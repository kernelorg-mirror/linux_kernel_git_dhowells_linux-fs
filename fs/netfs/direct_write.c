// SPDX-License-Identifier: GPL-2.0-or-later
/* Unbuffered and direct write support.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/uio.h>
#include "internal.h"

/*
 * Perform a read to a buffer from the server, slicing up the region to be read
 * according to the network rsize.
 */
static bool netfs_rmw_read_one(struct netfs_io_request *rreq, struct bvecq *bq)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	size_t len = 0;
	int ret = 0;

	for (int i = 0; i < bq->nr_slots; i++)
		len += bq->bv[i].bv_len;

	rreq->start		= bq->fpos;
	rreq->len		= len;
	stream->issue_from	= bq->fpos;
	stream->buffered	= len;

	do {
		struct netfs_io_subrequest *subreq;

		subreq = netfs_alloc_subrequest(rreq, NETFS_DOWNLOAD_FROM_SERVER);
		if (!subreq) {
			ret = -ENOMEM;
			break;
		}

		subreq->start	= stream->issue_from;
		subreq->len	= stream->buffered;

		spin_lock(&rreq->lock);
		list_add_tail(&subreq->rreq_link, &stream->subrequests);
		trace_netfs_sreq(subreq, netfs_sreq_trace_added);
		spin_unlock(&rreq->lock);

		netfs_stat(&netfs_n_rh_download);
		rreq->netfs_ops->issue_read(subreq);

		cond_resched();
	} while (stream->buffered > 0);

	return ret;
}

/*
 * Perform the read side of an RMW write.  We're supplied with a chain of one
 * or two buffers into which we should read directly.
 */
static ssize_t netfs_rmw_read(struct netfs_io_request *wreq, struct bvecq *bq)
{
	struct netfs_io_request *rreq;
	struct netfs_io_stream *stream;
	ssize_t ret;

	_enter("RMW:R=%x %llx", wreq->debug_id, bq->fpos);

	rreq = netfs_alloc_request(wreq->mapping, NULL, bq->fpos, 0, NETFS_RMW_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);
	stream = &rreq->io_streams[0];

	stream->dispatch_cursor.bvecq = bvecq_get(bq);
	stream->dispatch_cursor.slot = 0;
	stream->dispatch_cursor.offset = 0;

	bvecq_pos_set(&rreq->encrypt_cursor, &stream->dispatch_cursor);
	bvecq_pos_set(&rreq->bounce_copy, &stream->dispatch_cursor);
	bvecq_pos_set(&rreq->bounce_collect, &stream->dispatch_cursor);

	__set_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &rreq->flags);

	netfs_rmw_read_one(rreq, bq);
	if (bq->next)
		netfs_rmw_read_one(rreq, bq->next);

	ret = netfs_wait_for_read(rreq);
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	return ret;
}

/*
 * Read gaps at either end of the bounce buffer that need to be filled for an
 * RMW cycle.
 */
static ssize_t netfs_unbuffered_rmw(struct netfs_io_request *wreq,
				    struct netfs_io_subrequest *subreq,
				    unsigned long long to,
				    unsigned long long end)
{
	struct bvecq *before = NULL, *after = NULL;
	size_t bsize = wreq->crypto_bsize;
	int ret;

	_enter("%llx,%llx", to, end);

	/* Build a buffer chain to cover the gaps.  If we have two gaps, they
	 * must be discontiguous and so we will need two separate bvecqs for
	 * that; however, if the entire write spans at most two pages, just do
	 * one read for both gaps plus the middle.
	 */
	if (subreq->start < wreq->start) {
		before = bvecq_alloc_one(2, GFP_KERNEL);
		if (!before)
			return -ENOMEM;
		before->fpos = subreq->start;
		before->bv[0] = wreq->encrypt_cursor.bvecq->bv[wreq->encrypt_cursor.slot];
		before->bv[0].bv_offset += wreq->encrypt_cursor.offset;
		before->bv[0].bv_len = bsize;
		bvecq_filled_to(before, 1);
	}

	if (to == end && subreq->start + subreq->len < to) {
		size_t part = end - subreq->start;

		if (before && part <= 2 * PAGE_SIZE) {
			struct bvecq *bq;
			size_t page0 = PAGE_SIZE - before->bv[0].bv_offset;
			int slot;

			if (part <= page0) {
				before->bv[0].bv_len = part;
				bvecq_filled_to(before, 1);
				goto do_it;
			}

			bq = wreq->encrypt_cursor.bvecq;
			slot = wreq->encrypt_cursor.slot + 1;
			if (slot > bq->nr_slots) {
				bq = bq->next;
				slot = 0;
			}

			before->bv[0].bv_len = page0;
			before->bv[1] = bq->bv[slot];
			before->bv[1].bv_len = part - page0;
			bvecq_filled_to(before, 2);
			goto do_it;
		}

		after = bvecq_alloc_one(1, GFP_KERNEL);
		if (!after) {
			ret = -ENOMEM;
			goto out;
		}
		after->fpos = to - bsize;
		after->bv[0] = wreq->bounce_alloc.bvecq->bv[wreq->bounce_alloc.slot];
		after->bv[0].bv_offset = to & (PAGE_SIZE - 1);
		after->bv[0].bv_len = bsize;
		bvecq_filled_to(after, 1);
	}

	if (before && after) {
		before->next = after;
		after->prev = before;
		after->discontig = true;
	}

do_it:
	ret = netfs_rmw_read(wreq, before ?: after);

out:
	bvecq_put(before ?: after);
	return ret;
}

/*
 * Load data into the bounce buffer and encrypt it.
 */
static int netfs_unbuffered_load_bounce(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	unsigned long long to, end;
	ssize_t got;
	size_t amount = subreq->len;
	int ret;

	/* Expand the bounce buffer as needed. */
	to = round_up(subreq->start + subreq->len, wreq->crypto_bsize);
	end = round_up(wreq->start + wreq->len, wreq->crypto_bsize);

	if (wreq->bounce_alloc_to < to) {
		ret = bvecq_buffer_add_space(&wreq->bounce_alloc,
					     &wreq->bounce_alloc_to,
					     to, end, false, GFP_KERNEL);
		if (ret < 0)
			return ret;
	}

	/* Perform RMW if there are gaps to be filled. */
	if (stream->issue_from < wreq->start ||
	    (to == end && subreq->start + subreq->len < to)) {
		ret = netfs_unbuffered_rmw(wreq, subreq, to, end);
		if (ret < 0)
			return ret;
	}

	/* Copy in the data.  We need to work around any RMW gaps. */
	if (subreq->start < wreq->start + wreq->submitted)
		amount -= wreq->submitted;
	if (amount > wreq->len - wreq->submitted)
		amount = wreq->len - wreq->submitted;

	got = bvecq_copy_to_bvecq(&wreq->copy_cursor, &wreq->bounce_copy, amount);
	if (got != amount)
		return -EFAULT;

	/* And then encrypt the data in-place. */
	return netfs_encrypt(wreq, to, GFP_KERNEL);
}

/*
 * Prepare the buffer for an unbuffered/DIO write.
 */
int netfs_prepare_unbuffered_write_buffer(struct netfs_io_subrequest *subreq,
					  unsigned int max_segs, bool copy)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	ssize_t got;
	size_t len;
	int ret;

	len = subreq->len;
	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags) &&
	    len >= wreq->crypto_bsize)
		len = round_down(len, wreq->crypto_bsize);

	if (test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &wreq->flags)) {
		ret = netfs_unbuffered_load_bounce(subreq);
		if (ret < 0)
			return ret;
	}

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);

	if (copy) {
		got = bvecq_extract(&stream->dispatch_cursor, len, max_segs,
				    &subreq->content.bvecq);
		if (got < 0)
			return -ENOMEM;
		len = got;
	} else {
		bvecq_pos_set(&subreq->content, &stream->dispatch_cursor);

		len = bvecq_slice(&stream->dispatch_cursor, len, max_segs, &subreq->nr_segs);
	}

	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	// TODO: Wait here for completion of prev subreq

	stream->issue_from += subreq->len;
	stream->buffered   -= subreq->len;
	if (stream->buffered == 0)
		netfs_all_subreqs_queued(subreq->rreq);
	return 0;
}

/*
 * Perform the cleanup rituals after an unbuffered write is complete.
 */
static void netfs_unbuffered_write_done(struct netfs_io_request *wreq)
{
	struct netfs_inode *ictx = netfs_inode(wreq->inode);

	_enter("R=%x", wreq->debug_id);

	/* Okay, declare that all I/O is complete. */
	trace_netfs_rreq(wreq, netfs_rreq_trace_write_done);

	if (!wreq->error)
		netfs_update_i_size(ictx, &ictx->inode, wreq->start, wreq->transferred);

	if (wreq->origin == NETFS_DIO_WRITE &&
	    wreq->mapping->nrpages) {
		/* mmap may have got underfoot and we may now have folios
		 * locally covering the region we just wrote.  Attempt to
		 * discard the folios, but leave in place any modified locally.
		 * ->write_iter() is prevented from interfering by the DIO
		 * counter.
		 */
		pgoff_t first = wreq->start >> PAGE_SHIFT;
		pgoff_t last = (wreq->start + wreq->transferred - 1) >> PAGE_SHIFT;

		invalidate_inode_pages2_range(wreq->mapping, first, last);
	}

	if (wreq->origin == NETFS_DIO_WRITE)
		inode_dio_end(wreq->inode);

	_debug("finished");
	netfs_wake_rreq_flag(wreq, NETFS_RREQ_IN_PROGRESS, netfs_rreq_trace_wake_ip);
	/* As we cleared NETFS_RREQ_IN_PROGRESS, we acquired its ref. */

	if (wreq->iocb) {
		size_t written = umin(wreq->transferred, wreq->len);

		wreq->iocb->ki_pos += written;
		if (wreq->iocb->ki_complete) {
			trace_netfs_rreq(wreq, netfs_rreq_trace_ki_complete);
			wreq->iocb->ki_complete(wreq->iocb, wreq->error ?: written);
		}
		wreq->iocb = VFS_PTR_POISON;
	}

	netfs_clear_subrequests(wreq);
}

/*
 * Collect the subrequest results of unbuffered write subrequests.
 */
static void netfs_unbuffered_write_collect(struct netfs_io_request *wreq,
					   struct netfs_io_stream *stream,
					   struct netfs_io_subrequest *subreq)
{
	trace_netfs_collect_sreq(wreq, subreq);

	spin_lock(&wreq->lock);
	list_del_init(&subreq->rreq_link);
	spin_unlock(&wreq->lock);

	wreq->transferred += subreq->transferred;
	if (subreq->transferred < subreq->len) {
		bvecq_pos_unset(&stream->dispatch_cursor);
		bvecq_pos_transfer(&stream->dispatch_cursor, &subreq->dispatch_pos);
		bvecq_pos_advance(&stream->dispatch_cursor, subreq->transferred);
	}

	stream->collected_to = subreq->start + subreq->transferred;
	wreq->collected_to = stream->collected_to;
	netfs_put_subrequest(subreq, netfs_sreq_trace_put_done);

	trace_netfs_collect_stream(wreq, stream);
	trace_netfs_collect_state(wreq, wreq->collected_to, 0);
	/* TODO: Progressively clean up wreq->direct_bq */
}

/*
 * Write data to the server without going through the pagecache and without
 * writing it to the local cache.  We dispatch the subrequests serially and
 * wait for each to complete before dispatching the next, lest we leave a gap
 * in the data written due to a failure such as ENOSPC.  We could, however
 * attempt to do preparation such as content encryption for the next subreq
 * whilst the current is in progress.
 */
static int netfs_unbuffered_write(struct netfs_io_request *wreq)
{
	struct netfs_io_subrequest *subreq = NULL;
	struct netfs_io_stream *stream = &wreq->io_streams[0];
	int ret;

	_enter("%llx", wreq->len);

	stream->issue_from = wreq->start;
	stream->buffered = wreq->len;

	if (wreq->origin == NETFS_DIO_WRITE)
		inode_dio_begin(wreq->inode);


	for (;;) {
		bool retry = false;

		if (!subreq) {
			subreq = netfs_alloc_write_subreq(wreq, stream);
			if (!subreq)
				return -ENOMEM;
		}

		stream->issue_write(subreq);

		ret = netfs_wait_for_in_progress_subreq(wreq, subreq);
		if (ret < 0) {
			if (ret != -EAGAIN) {
				list_del_init(&subreq->rreq_link);
				ret = subreq->error;
				netfs_put_subrequest(subreq, netfs_sreq_trace_put_failed);
				subreq = NULL;
				goto failed;
			}
			retry = true;
		}

		if (!retry) {
			netfs_unbuffered_write_collect(wreq, stream, subreq);
			subreq = NULL;
			if (wreq->transferred >= wreq->len)
				break;
			if (!wreq->iocb && signal_pending(current)) {
				ret = wreq->transferred ? -EINTR : -ERESTARTSYS;
				trace_netfs_rreq(wreq, netfs_rreq_trace_intr);
				break;
			}
			continue;
		}

		/* We need to retry the last subrequest, so first wind back the
		 * buffer position.
		 */
		subreq->error = -EAGAIN;
		trace_netfs_sreq(subreq, netfs_sreq_trace_retry);

		bvecq_pos_unset(&subreq->content);
		bvecq_pos_unset(&stream->dispatch_cursor);
		bvecq_pos_transfer(&stream->dispatch_cursor, &subreq->dispatch_pos);

		stream->issue_from -= subreq->len - subreq->transferred;
		stream->buffered   += subreq->len - subreq->transferred;
		if (subreq->transferred > 0) {
			wreq->transferred  += subreq->transferred;
			bvecq_pos_advance(&stream->dispatch_cursor, subreq->transferred);
		}

		if (stream->source == NETFS_UPLOAD_TO_SERVER &&
		    wreq->netfs_ops->retry_request)
			wreq->netfs_ops->retry_request(wreq, stream);

		__clear_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
		__clear_bit(NETFS_SREQ_FAILED, &subreq->flags);
		__clear_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
		subreq->start		= stream->issue_from;
		subreq->len		= stream->buffered;
		subreq->transferred	= 0;
		subreq->retry_count	+= 1;

		netfs_get_subrequest(subreq, netfs_sreq_trace_get_resubmit);

		__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);
		netfs_stat(&netfs_n_wh_retry_write_subreq);
	}

failed:
	bvecq_pos_unset(&stream->dispatch_cursor);
	netfs_unbuffered_write_done(wreq);
	_leave(" = %d", ret);
	return ret;
}

static void netfs_unbuffered_write_async(struct work_struct *work)
{
	struct netfs_io_request *wreq = container_of(work, struct netfs_io_request, work);

	netfs_unbuffered_write(wreq);
	netfs_put_request(wreq, netfs_rreq_trace_put_complete);
}

/*
 * Perform an unbuffered write where we may have to do an RMW operation on an
 * encrypted file.  This can also be used for direct I/O writes.
 */
ssize_t netfs_unbuffered_write_iter_locked(struct kiocb *iocb, struct iov_iter *iter,
					   struct netfs_group *netfs_group)
{
	struct netfs_io_request *wreq;
	struct netfs_io_stream *stream;
	unsigned long long start = iocb->ki_pos;
	unsigned long long end = start + iov_iter_count(iter);
	ssize_t ret, n;
	size_t len = iov_iter_count(iter);
	bool async = !is_sync_kiocb(iocb);

	_enter("");

	_debug("uw %llx-%llx", start, end);

	wreq = netfs_create_write_req(iocb->ki_filp->f_mapping, iocb->ki_filp, start,
				      iocb->ki_flags & IOCB_DIRECT ?
				      NETFS_DIO_WRITE : NETFS_UNBUFFERED_WRITE);
	if (IS_ERR(wreq))
		return PTR_ERR(wreq);

	wreq->len = iov_iter_count(iter);
	wreq->submitted = 0;
	stream = &wreq->io_streams[0];
	stream->avail = true;
	trace_netfs_write(wreq, (iocb->ki_flags & IOCB_DIRECT ?
				 netfs_write_trace_dio_write :
				 netfs_write_trace_unbuffered_write));

	/* If we're going to do encryption or compression, we're going to need
	 * a bounce buffer.
	 */
	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags)) {
		__set_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &wreq->flags);
		__set_bit(NETFS_RREQ_CRYPT_IN_PLACE, &wreq->flags);
	}

	/* Transcribe the source buffer into a bvecq chain.  We need this for
	 * async writes because the source iterator but we also use it for
	 * unencrypted sync writes as it gets passed to the filesystem in this
	 * form.
	 *
	 * We extract as much of the buffer as we can manage, but this may
	 * shorten the request.
	 */
	n = netfs_extract_iter(iter, len, INT_MAX, iocb->ki_pos,
			       &wreq->load_cursor.bvecq, 0);
	if (n < 0) {
		ret = n;
		goto error_put;
	}
	wreq->len = n;
	_debug("dio-write %zx/%zx %u/%u",
	       n, len, wreq->load_cursor.bvecq->nr_slots,
	       wreq->load_cursor.bvecq->max_slots);

	/* Set up the bounce buffer if we need it.  Allow for padding the
	 * request out to the crypo block size and allocate at least one bvecq
	 * into it.
	 */
	if (test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &wreq->flags)) {
		size_t bsize = wreq->crypto_bsize;
		size_t gap;

		bvecq_pos_set(&wreq->copy_cursor, &wreq->load_cursor);

		wreq->bounce_alloc_to = round_down(wreq->start, bsize);
		atomic64_set(&wreq->encrypted_to, wreq->bounce_alloc_to);
		gap = wreq->start - wreq->bounce_alloc_to;

		stream->issue_from = wreq->bounce_alloc_to;
		stream->buffered = round_up(wreq->len + gap, bsize);

		ret = bvecq_buffer_init(&wreq->bounce_alloc, wreq->debug_id);
		if (ret < 0)
			goto error_put;

		/*   0--->
		 *  ~--+-------+-------+-------+-------+---~
		 *     :       |       |       |       |
		 *     :spent  |encrypt|copied |alloced|
		 *     :       |-ed    |       |       |
		 *  ~--+-------+-------+-------+-------+---~
		 *                                     ^bounce_alloc
		 *                             ^bounce_copy
		 *                     ^encrypt_cursor
		 *             ^dispatch_cursor
		 */
		bvecq_pos_set(&wreq->bounce_copy, &wreq->bounce_alloc);
		bvecq_pos_set(&wreq->encrypt_cursor, &wreq->bounce_alloc);
		bvecq_pos_set(&stream->dispatch_cursor, &wreq->bounce_alloc);

	} else {
		stream->buffered = ret;
		stream->issue_from = wreq->start;
		bvecq_pos_set(&stream->dispatch_cursor, &wreq->load_cursor);
	}

	/* Dispatch the write. */
	__set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);

	if (async) {
		INIT_WORK(&wreq->work, netfs_unbuffered_write_async);
		wreq->iocb = iocb;
		queue_work(system_dfl_wq, &wreq->work);
		ret = -EIOCBQUEUED;
	} else {
		ret = netfs_unbuffered_write(wreq);
		if (ret < 0) {
			_debug("begin = %zd", ret);
		} else {
			iocb->ki_pos += wreq->transferred;
			ret = wreq->transferred ?: wreq->error;
		}

		netfs_put_request(wreq, netfs_rreq_trace_put_complete);
	}

	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	return ret;

error_put:
	netfs_put_failed_request(wreq);
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_write_iter_locked);

/**
 * netfs_unbuffered_write_iter - Unbuffered write to a file
 * @iocb: IO state structure
 * @from: iov_iter with data to write
 *
 * Do an unbuffered write to a file, writing the data directly to the server
 * and not lodging the data in the pagecache.
 *
 * Return:
 * * Negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * Number of bytes written, even for truncated writes
 */
ssize_t netfs_unbuffered_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct netfs_inode *ictx = netfs_inode(inode);
	ssize_t ret;
	loff_t pos = iocb->ki_pos;
	unsigned long long end = pos + iov_iter_count(from) - 1;

	_enter("%llx,%zx,%llx", pos, iov_iter_count(from), i_size_read(inode));

	if (!iov_iter_count(from))
		return 0;

	trace_netfs_write_iter(iocb, from);
	netfs_stat(&netfs_n_wh_dio_write);

	ret = netfs_start_io_direct(inode);
	if (ret < 0)
		return ret;
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;
	ret = file_remove_privs(file);
	if (ret < 0)
		goto out;
	ret = file_update_time(file);
	if (ret < 0)
		goto out;
	if (iocb->ki_flags & IOCB_NOWAIT) {
		/* We could block if there are any pages in the range. */
		ret = -EAGAIN;
		if (filemap_range_has_page(mapping, pos, end))
			if (filemap_invalidate_inode(inode, true, pos, end))
				goto out;
	} else {
		ret = filemap_write_and_wait_range(mapping, pos, end);
		if (ret < 0)
			goto out;
	}

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	ret = filemap_invalidate_inode(inode, true, pos, end);
	if (ret < 0)
		goto out;
	end = iocb->ki_pos + iov_iter_count(from);
	spin_lock(&inode->i_lock);
	if (end > ictx->_zero_point)
		netfs_write_zero_point(inode, end);
	spin_unlock(&inode->i_lock);

	fscache_invalidate(netfs_i_cookie(ictx), NULL, i_size_read(inode),
			   FSCACHE_INVAL_DIO_WRITE);
	ret = netfs_unbuffered_write_iter_locked(iocb, from, NULL);
out:
	netfs_end_io_direct(inode);
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_write_iter);
