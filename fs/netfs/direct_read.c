// SPDX-License-Identifier: GPL-2.0-or-later
/* Direct I/O support.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/sched/mm.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/netfs.h>
#include "internal.h"

/*
 * If we did a direct read to a bounce buffer (say we needed to decrypt it),
 * copy the data obtained to the destination iterator if we need to (if we can,
 * we encrypt between buffers, but that requires correct alignment of the
 * output buffer).
 */
int netfs_dio_copy_bounce_to_dest(struct netfs_io_request *rreq, struct kiocb *iocb)
{
	unsigned long long dec_to = atomic64_read(&rreq->encrypted_to);
	unsigned long long end = rreq->start + rreq->len;

	_enter("%zx/%llx @%llx", rreq->transferred, rreq->len, rreq->copied_to);

	if (!iocb)
		iocb = rreq->iocb;

	if (!test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags) ||
	    !test_bit(NETFS_RREQ_CRYPT_IN_PLACE, &rreq->flags))
		return 0;

	/* Skip over any rounding to get to the data of interest. */
	if (dec_to < rreq->start)
		return 0;
	if (rreq->copied_to < rreq->start) {
		bvecq_pos_advance(&rreq->collect_cursor, rreq->start - rreq->copied_to);
		rreq->copied_to = rreq->start;
	}

	/* Now we can copy any data of interest we've just received. */
	if (rreq->copied_to >= dec_to)
		return 0;
	if (rreq->copied_to < end) {
		ssize_t copy;
		size_t part = umin(dec_to, end) - rreq->copied_to;

		copy = bvecq_copy_to_bvecq(&rreq->bounce_copy, &rreq->collect_cursor, part);
		if (copy < part) {
			if (!copy && rreq->copied_to == rreq->start) {
				trace_netfs_failure(rreq, NULL, -EFAULT, netfs_fail_dio_read_zero);
				return -EIO;
			}
			trace_netfs_failure(rreq, NULL, -EFAULT, netfs_fail_dio_read_short);
		}
	}

	_debug("xfer %zx/%llx @%llx", rreq->transferred, rreq->len, iocb->ki_pos);
	return 0;
}

/*
 * Prepare the buffer for the read RPC.  Limits are applied and the buffer may
 * be rounded down.  Bounce bufferage will be added if necessary.
 */
int netfs_prepare_unbuffered_read_buffer(struct netfs_io_subrequest *subreq,
					 unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	size_t len = subreq->len;
	int ret;

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);
	bvecq_pos_set(&subreq->content, &stream->dispatch_cursor);

	/* Limit encrypted reads so that we don't split an encryption block
	 * across two subrequests unless the filesystem doesn't support blocks
	 * that big.
	 */
	if (len > rreq->crypto_bsize &&
	    test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &rreq->flags)) {
		len = round_down(len, rreq->crypto_bsize);
		if (WARN_ON_ONCE(len == 0))
			return -EIO;
	}

	/* Expand the bounce buffer so that we've got something to read into. */
	if (test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags)) {
		ret = bvecq_buffer_add_space(&rreq->bounce_alloc,
					     &rreq->bounce_alloc_to,
					     subreq->start + len,
					     round_up(rreq->start + rreq->len,
						      rreq->crypto_bsize),
					     false, GFP_KERNEL);
		if (ret < 0)
			return ret;
	}

	len = bvecq_slice(&stream->dispatch_cursor, len, max_segs,
			  &subreq->nr_segs);

	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	stream->buffered   -= subreq->len;
	stream->issue_from += subreq->len;
	rreq->submitted = stream->issue_from;

	if (stream->buffered == 0)
		netfs_all_subreqs_queued(rreq);
	return 0;
}

/*
 * Perform a read to a buffer from the server, slicing up the region to be read
 * according to the network rsize.
 */
static void netfs_dispatch_unbuffered_reads(struct netfs_io_request *rreq)
{
	struct netfs_io_stream *stream = &rreq->io_streams[0];
	unsigned long long start = rreq->start;
	ssize_t size = rreq->len;
	size_t bsize = rreq->crypto_bsize;

	/* Pad out an encrypted transfer to the block size. */
	start = round_down(start, bsize);
	size += rreq->start - start;
	size = round_up(size, bsize);

	do {
		struct netfs_io_subrequest *subreq;

		subreq = netfs_alloc_read_subrequest(rreq, NETFS_DOWNLOAD_FROM_SERVER);
		if (!subreq) {
			/* Stash the error in the request if there's not
			 * already an error set.
			 */
			cmpxchg(&rreq->error, 0, -ENOMEM);
			break;
		}

		subreq->start	= stream->issue_from;
		subreq->len	= stream->buffered;

		netfs_stat(&netfs_n_rh_download);

		rreq->netfs_ops->issue_read(subreq);

		if (test_bit(NETFS_RREQ_PAUSE, &rreq->flags))
			netfs_wait_for_paused_read(rreq);
		if (test_bit(NETFS_RREQ_FAILED, &rreq->flags))
			break;
		cond_resched();
	} while (stream->buffered > 0);

	if (unlikely(stream->buffered > 0)) {
		netfs_all_subreqs_queued(rreq);
		netfs_wake_collector(rreq);
	}

	bvecq_pos_unset(&stream->dispatch_cursor);
}

/*
 * Perform a read to an application buffer, bypassing the pagecache and the
 * local disk cache.
 */
static ssize_t netfs_unbuffered_read(struct netfs_io_request *rreq, bool sync)
{
	ssize_t ret;

	_enter("R=%x %llx-%llx",
	       rreq->debug_id, rreq->start, rreq->start + rreq->len - 1);

	if (rreq->len == 0) {
		pr_err("Zero-sized read [R=%x]\n", rreq->debug_id);
		netfs_put_request(rreq, netfs_rreq_trace_put_discard);
		return -EIO;
	}

	// TODO: Use bounce buffer if requested

	inode_dio_begin(rreq->inode);
	netfs_dispatch_unbuffered_reads(rreq);

	/* The collector will get run, even if we don't manage to submit any
	 * subreqs, so we shouldn't call inode_dio_end() here.
	 */

	if (sync)
		ret = netfs_wait_for_read(rreq);
	else
		ret = -EIOCBQUEUED;

	_leave(" = %zd", ret);
	return ret;
}

/**
 * netfs_unbuffered_read_iter_locked - Perform an unbuffered or direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 *
 * Perform an unbuffered I/O or direct I/O from the file in @iocb to the
 * output buffer.  No use is made of the pagecache.
 *
 * The caller must hold any appropriate locks.
 */
ssize_t netfs_unbuffered_read_iter_locked(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_io_request *rreq;
	struct netfs_io_stream *stream;
	ssize_t ret;
	size_t orig_count = iov_iter_count(iter);
	bool sync = is_sync_kiocb(iocb);

	_enter("");

	if (!orig_count)
		return 0; /* Don't update atime */

	ret = kiocb_write_and_wait(iocb, orig_count);
	if (ret < 0)
		return ret;
	file_accessed(iocb->ki_filp);

	rreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   iocb->ki_pos, orig_count,
				   iocb->ki_flags & IOCB_DIRECT ?
				   NETFS_DIO_READ : NETFS_UNBUFFERED_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	netfs_stat(&netfs_n_rh_dio_read);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_dio_read);

	stream = &rreq->io_streams[0];

	/* If this is an async op, we have to keep track of the destination
	 * buffer for ourselves as the caller's iterator will be trashed when
	 * we return.
	 *
	 * Extract a buffer queue to represent as much of the output buffer as
	 * we can manage.  The fragments are extracted into a bvecq which will
	 * have sufficient nodes allocated to hold all the data, though this
	 * may end up truncated if ENOMEM is encountered.
	 */
	ret = netfs_extract_iter(iter, rreq->len, INT_MAX, iocb->ki_pos,
				 &rreq->collect_cursor.bvecq, 0);
	if (ret < 0)
		goto error_put;

	rreq->len = ret;

	/* If we're going to do decryption or decompression, we're going to
	 * need a bounce buffer.  If the output buffer is correctly aligned and
	 * correctly sized for the crypto algorithm, we get a free copy between
	 * buffers from the crypto; if misaligned, we decrypt in place in the
	 * bounce buffer and then copy.
	 */
	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &rreq->flags)) {
		if (!netfs_is_crypto_aligned(rreq, iter))
			__set_bit(NETFS_RREQ_CRYPT_IN_PLACE, &rreq->flags);
		__set_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags);
	}

	/* Set up the bounce buffer if we need it.  Allow for padding the
	 * request out to the crypo block size and allocate at least one bvecq
	 * into it.
	 */
	if (test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags)) {
		size_t bsize = rreq->crypto_bsize;
		size_t gap;

		rreq->bounce_alloc_to = round_down(rreq->start, bsize);
		gap = rreq->start - rreq->bounce_alloc_to;

		stream->issue_from = rreq->bounce_alloc_to;
		stream->buffered = round_up(rreq->len + gap, bsize);

		ret = bvecq_buffer_init(&rreq->bounce_alloc, rreq->debug_id);
		if (ret < 0)
			goto out;

		/*   0--->
		 *  ~--+-------+-------+-------+-------+---~
		 *     |       |       |       |       |
		 *     |copied |decrypt|reading|alloced|
		 *     |       |-ed    |       |       |
		 *  ~--+-------+-------+-------+-------+---~
		 *                                     ^bounce_alloc
		 *                             ^dispatch_cursor
		 *                     ^encrypt_cursor
		 *             ^bounce_copy
		 *     ^bounce_collect
		 */
		bvecq_pos_set(&stream->dispatch_cursor, &rreq->bounce_alloc);
		bvecq_pos_set(&rreq->encrypt_cursor, &rreq->bounce_alloc);
		bvecq_pos_set(&rreq->bounce_copy, &rreq->bounce_alloc);
		bvecq_pos_set(&rreq->bounce_collect, &rreq->bounce_alloc);

	} else {
		stream->buffered = ret;
		stream->issue_from = rreq->start;
		bvecq_pos_transfer(&stream->dispatch_cursor, &rreq->collect_cursor);
	}

	if (!sync) {
		rreq->iocb = iocb;
		__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &rreq->flags);
	}

	ret = netfs_unbuffered_read(rreq, sync);
	if (ret < 0)
		goto out; /* May be -EIOCBQUEUED */
	if (sync) {
		ret = netfs_dio_copy_bounce_to_dest(rreq, iocb);
		if (ret == 0) {
			iocb->ki_pos += rreq->transferred;
			ret = rreq->transferred;
		}
	}

out:
	netfs_put_request(rreq, netfs_rreq_trace_put_return);
	if (ret > 0)
		orig_count -= ret;
	return ret;

error_put:
	netfs_put_failed_request(rreq);
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_read_iter_locked);

/**
 * netfs_unbuffered_read_iter - Perform an unbuffered or direct I/O read
 * @iocb: The I/O control descriptor describing the read
 * @iter: The output buffer (also specifies read length)
 *
 * Perform an unbuffered I/O or direct I/O from the file in @iocb to the
 * output buffer.  No use is made of the pagecache.
 */
ssize_t netfs_unbuffered_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (!iter->count)
		return 0; /* Don't update atime */

	ret = netfs_start_io_direct(inode);
	if (ret == 0) {
		ret = netfs_unbuffered_read_iter_locked(iocb, iter);
		netfs_end_io_direct(inode);
	}
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_read_iter);
