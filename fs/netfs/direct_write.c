// SPDX-License-Identifier: GPL-2.0-or-later
/* Unbuffered and direct write support.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/uio.h>
#include "internal.h"

static void netfs_cleanup_dio_write(struct netfs_io_request *wreq)
{
	struct inode *inode = wreq->inode;
	unsigned long long end = wreq->start + wreq->len;

	if (!wreq->error &&
	    i_size_read(inode) < end) {
		if (wreq->netfs_ops->update_i_size)
			wreq->netfs_ops->update_i_size(inode, end);
		else
			i_size_write(inode, end);
	}
}

/*
 * Allocate a bunch of pages and add them into the xarray buffer starting at
 * the given index.
 */
static int netfs_alloc_buffer(struct xarray *xa, pgoff_t index, unsigned int nr_pages)
{
	struct page *page;
	unsigned int n;
	int ret = 0;
	LIST_HEAD(list);

	n = alloc_pages_bulk_list(GFP_NOIO, nr_pages, &list);
	if (n < nr_pages) {
		ret = -ENOMEM;
	}

	while ((page = list_first_entry_or_null(&list, struct page, lru))) {
		list_del(&page->lru);
		page->index = index;
		ret = xa_insert(xa, index++, page, GFP_NOIO);
		if (ret < 0)
			break;
	}

	while ((page = list_first_entry_or_null(&list, struct page, lru))) {
		list_del(&page->lru);
		__free_page(page);
	}
	return ret;
}

/*
 * Copy all of the data from the source iterator into folios in the destination
 * xarray.  We cannot step through and kmap the source iterator if it's an
 * iovec, so we have to step through the xarray and drop the RCU lock each
 * time.
 */
static int netfs_copy_iter_to_xarray(struct iov_iter *src, struct xarray *xa,
				     unsigned long long start)
{
	struct folio *folio;
	void *base;
	pgoff_t index = start / PAGE_SIZE;
	size_t len, copied, count = iov_iter_count(src);

	XA_STATE(xas, xa, index);

	_enter("%zx", count);

	if (!count)
		return -EIO;

	len = PAGE_SIZE - offset_in_page(start);
	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		size_t offset;

		if (xas_retry(&xas, folio))
			continue;

		/* There shouldn't be a need to call xas_pause() as no one else
		 * can see the xarray we're iterating over.
		 */
		rcu_read_unlock();

		offset = offset_in_folio(folio, start);
		_debug("folio %lx +%zx [%llx]", folio->index, offset, start);

		while (offset < folio_size(folio)) {
			len = min(count, len);

			base = kmap_local_folio(folio, offset);
			copied = copy_from_iter(base, len, src);
			kunmap_local(base);
			if (copied != len)
				goto out;
			count -= len;
			if (count == 0)
				goto out;

			start += len;
			offset += len;
			len = PAGE_SIZE;
		}

		rcu_read_lock();
	}

	rcu_read_unlock();
out:
	_leave(" = %zx", count);
	return count ? -EIO : 0;
}

/*
 * Perform an unbuffered write where we may have to do an RMW operation on an
 * encrypted file.  This can also be used for direct I/O writes.
 */
static ssize_t netfs_unbuffered_write_iter_locked(struct kiocb *iocb, struct iov_iter *iter,
						  struct netfs_group *netfs_group)
{
	struct netfs_io_request *wreq;
	struct netfs_inode *ctx = netfs_inode(file_inode(iocb->ki_filp));
	unsigned long long real_size = ctx->remote_i_size;
	unsigned long long start = iocb->ki_pos;
	unsigned long long end = start + iov_iter_count(iter);
	ssize_t ret, n;
	size_t min_bsize = 1UL << ctx->min_bshift;
	size_t bmask = min_bsize - 1;
	size_t gap_before = start & bmask;
	size_t gap_after = (min_bsize - end) & bmask;
	bool use_bounce, async = !is_sync_kiocb(iocb);
	enum {
		DIRECT_IO, COPY_TO_BOUNCE, ENC_TO_BOUNCE, COPY_THEN_ENC,
	} buffering;

	_enter("");

	/* The real size must be rounded out to the crypto block size plus
	 * any trailer we might want to attach.
	 */
	if (real_size && ctx->crypto_bshift) {
		size_t cmask = 1UL << ctx->crypto_bshift;

		if (real_size < ctx->crypto_trailer)
			return -EIO;
		if ((real_size - ctx->crypto_trailer) & cmask)
			return -EIO;
		real_size -= ctx->crypto_trailer;
	}

	/* We're going to need a bounce buffer if what we transmit is going to
	 * be different in some way to the source buffer, e.g. because it gets
	 * encrypted/compressed or because it needs expanding to a block size.
	 */
	use_bounce = test_bit(NETFS_ICTX_ENCRYPTED, &ctx->flags);
	if (gap_before || gap_after) {
		if (iocb->ki_flags & IOCB_DIRECT)
			return -EINVAL;
		use_bounce = true;
	}

	_debug("uw %llx-%llx +%zx,%zx", start, end, gap_before, gap_after);

	wreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   start, end - start,
				   iocb->ki_flags & IOCB_DIRECT ?
				   NETFS_DIO_WRITE : NETFS_UNBUFFERED_WRITE);
	if (IS_ERR(wreq))
		return PTR_ERR(wreq);

	if (use_bounce) {
		unsigned long long bstart = start - gap_before;
		unsigned long long bend = end + gap_after;
		pgoff_t first = bstart / PAGE_SIZE;
		pgoff_t last  = (bend - 1) / PAGE_SIZE;

		_debug("bounce %llx-%llx %lx-%lx", bstart, bend, first, last);

		ret = netfs_alloc_buffer(&wreq->bounce, first, last - first + 1);
		if (ret < 0)
			goto out;

		iov_iter_xarray(&wreq->io_iter, READ, &wreq->bounce,
				bstart, bend - bstart);

		if (gap_before || gap_after)
			async = false; /* We may have to repeat the RMW cycle */
	}

repeat_rmw_cycle:
	if (use_bounce) {
		/* If we're going to need to do an RMW cycle, fill in the gaps
		 * at the ends of the buffer.
		 */
		if (gap_before || gap_after) {
			struct iov_iter buffer = wreq->io_iter;

			if ((gap_before && start - gap_before < real_size) ||
			    (gap_after && end < real_size)) {
				ret = netfs_rmw_read(wreq, iocb->ki_filp,
						     start - gap_before, gap_before,
						     end, end < real_size ? gap_after : 0);
				if (ret < 0)
					goto out;
			}

			if (gap_before && start - gap_before >= real_size)
				iov_iter_zero(gap_before, &buffer);
			if (gap_after && end >= real_size) {
				iov_iter_advance(&buffer, end - start);
				iov_iter_zero(gap_after, &buffer);
			}
		}

		if (!test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags))
			buffering = COPY_TO_BOUNCE;
		else if (!gap_before && !gap_after && netfs_is_crypto_aligned(wreq, iter))
			buffering = ENC_TO_BOUNCE;
		else
			buffering = COPY_THEN_ENC;
	} else {
		/* If this is an async op and we're not using a bounce buffer,
		 * we have to save the source buffer as the iterator is only
		 * good until we return.  In such a case, extract an iterator
		 * to represent as much of the the output buffer as we can
		 * manage.  Note that the extraction might not be able to
		 * allocate a sufficiently large bvec array and may shorten the
		 * request.
		 */
		if (async || user_backed_iter(iter)) {
			n = netfs_extract_user_iter(iter, wreq->len, &wreq->iter, 0);
			if (n < 0) {
				ret = n;
				goto out;
			}
			wreq->direct_bv = (struct bio_vec *)wreq->iter.bvec;
			wreq->direct_bv_count = n;
			wreq->direct_bv_unpin = iov_iter_extract_will_pin(iter);
			wreq->len = iov_iter_count(&wreq->iter);
		} else {
			wreq->iter = *iter;
		}

		wreq->io_iter = wreq->iter;
		buffering = DIRECT_IO;
	}

	/* Copy the data into the bounce buffer and encrypt it. */
	if (buffering == COPY_TO_BOUNCE ||
	    buffering == COPY_THEN_ENC) {
		ret = netfs_copy_iter_to_xarray(iter, &wreq->bounce, wreq->start);
		if (ret < 0)
			goto out;
		wreq->iter = wreq->io_iter;
		wreq->start -= gap_before;
		wreq->len += gap_before + gap_after;
	}

	if (buffering == COPY_THEN_ENC ||
	    buffering == ENC_TO_BOUNCE) {
		if (!netfs_encrypt(wreq))
			goto out;
	}

	/* Dispatch the write. */
	__set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
	if (async)
		wreq->iocb = iocb;
	wreq->cleanup = netfs_cleanup_dio_write;
	ret = netfs_begin_write(wreq, is_sync_kiocb(iocb),
				iocb->ki_flags & IOCB_DIRECT ?
				netfs_write_trace_dio_write :
				netfs_write_trace_unbuffered_write);
	if (ret < 0) {
		_debug("begin = %zd", ret);
		goto out;
	}

	if (!async) {
		trace_netfs_rreq(wreq, netfs_rreq_trace_wait_ip);
		wait_on_bit(&wreq->flags, NETFS_RREQ_IN_PROGRESS,
			    TASK_UNINTERRUPTIBLE);

		/* See if the write failed due to a 3rd party race when doing
		 * an RMW on a partially modified block in an encrypted file.
		 */
		if (test_and_clear_bit(NETFS_RREQ_REPEAT_RMW, &wreq->flags)) {
			netfs_clear_subrequests(wreq, false);
			iov_iter_revert(iter, end - start);
			wreq->error = 0;
			wreq->start = start;
			wreq->len = end - start;
			wreq->transferred = 0;
			wreq->submitted = 0;
			goto repeat_rmw_cycle;
		}

		ret = wreq->error;
		_debug("waited = %zd", ret);
		if (ret == 0) {
			ret = wreq->transferred;
			iocb->ki_pos += ret;
		}
	} else {
		ret = -EIOCBQUEUED;
	}

out:
	netfs_put_request(wreq, false, netfs_rreq_trace_put_return);
	return ret;
}

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
	struct inode *inode = file->f_mapping->host;
	struct netfs_inode *ictx = netfs_inode(inode);
	unsigned long long end;
	ssize_t ret;

	_enter("%llx,%zx,%llx", iocb->ki_pos, iov_iter_count(from), i_size_read(inode));

	trace_netfs_write_iter(iocb, from);
	netfs_stat(&netfs_n_rh_dio_write);

	ret = netfs_start_io_direct(inode);
	if (ret < 0)
		return ret;
	ret = generic_write_checks(iocb, from);
	if (ret < 0)
		goto out;
	ret = file_remove_privs(file);
	if (ret < 0)
		goto out;
	ret = file_update_time(file);
	if (ret < 0)
		goto out;
	ret = kiocb_invalidate_pages(iocb, iov_iter_count(from));
	if (ret < 0)
		goto out;
	end = iocb->ki_pos + iov_iter_count(from);
	if (end > ictx->zero_point)
		ictx->zero_point = end;

	fscache_invalidate(netfs_i_cookie(ictx), NULL, i_size_read(inode),
			   FSCACHE_INVAL_DIO_WRITE);
	ret = netfs_unbuffered_write_iter_locked(iocb, from, NULL);
out:
	netfs_end_io_direct(inode);
	return ret;
}
EXPORT_SYMBOL(netfs_unbuffered_write_iter);
