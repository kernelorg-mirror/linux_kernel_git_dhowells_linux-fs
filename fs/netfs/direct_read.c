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
 * Copy all of the data from the folios in the source xarray into the
 * destination iterator.  We cannot step through and kmap the dest iterator if
 * it's an iovec, so we have to step through the xarray and drop the RCU lock
 * each time.
 */
static int netfs_copy_xarray_to_iter(struct netfs_io_request *rreq,
				     struct xarray *xa, struct iov_iter *dst,
				     unsigned long long start, size_t avail)
{
	struct folio *folio;
	void *base;
	pgoff_t index = start / PAGE_SIZE;
	size_t len, copied, count = min(avail, iov_iter_count(dst));

	XA_STATE(xas, xa, index);

	_enter("%zx", count);

	if (!count) {
		trace_netfs_failure(rreq, NULL, -EIO, netfs_fail_dio_read_zero);
		return -EIO;
	}

	len = PAGE_SIZE - offset_in_page(start);
	rcu_read_lock();
	xas_for_each(&xas, folio, ULONG_MAX) {
		size_t offset;

		if (xas_retry(&xas, folio))
			continue;

		/* There shouldn't be a need to call xas_pause() as no one else
		 * should be modifying the xarray we're iterating over.
		 * Really, we only need the RCU readlock to keep lockdep happy
		 * inside xas_for_each().
		 */
		rcu_read_unlock();

		offset = offset_in_folio(folio, start);
		kdebug("folio %lx +%zx [%llx]", folio->index, offset, start);

		while (offset < folio_size(folio)) {
			len = min(count, len);

			base = kmap_local_folio(folio, offset);
			copied = copy_to_iter(base, len, dst);
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
	return count ? -EFAULT : 0;
}

/*
 * If we did a direct read to a bounce buffer (say we needed to decrypt it),
 * copy the data obtained to the destination iterator.
 */
static int netfs_dio_copy_bounce_to_dest(struct netfs_io_request *rreq)
{
	struct iov_iter *dest_iter = &rreq->iter;
	struct kiocb *iocb = rreq->iocb;
	unsigned long long start = rreq->start;

	_enter("%zx/%zx @%llx", rreq->transferred, rreq->len, start);

	if (!test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags))
		return 0;

	if (start < iocb->ki_pos) {
		if (rreq->transferred <= iocb->ki_pos - start) {
			trace_netfs_failure(rreq, NULL, -EIO, netfs_fail_dio_read_short);
			return -EIO;
		}
		rreq->len = rreq->transferred;
		rreq->transferred -= iocb->ki_pos - start;
	}

	if (rreq->transferred > iov_iter_count(dest_iter))
		rreq->transferred = iov_iter_count(dest_iter);

	_debug("xfer %zx/%zx @%llx", rreq->transferred, rreq->len, iocb->ki_pos);
	return netfs_copy_xarray_to_iter(rreq, &rreq->bounce, dest_iter,
					 iocb->ki_pos, rreq->transferred);
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
static ssize_t netfs_unbuffered_read_iter_locked(struct kiocb *iocb, struct iov_iter *iter)
{
	struct netfs_io_request *rreq;
	struct netfs_inode *ctx;
	unsigned long long start, end;
	unsigned int min_bsize;
	pgoff_t first, last;
	ssize_t ret;
	size_t orig_count = iov_iter_count(iter);
	bool async = !is_sync_kiocb(iocb);

	_enter("");

	if (!orig_count)
		return 0; /* Don't update atime */

	ret = kiocb_write_and_wait(iocb, orig_count);
	if (ret < 0)
		return ret;
	file_accessed(iocb->ki_filp);

	rreq = netfs_alloc_request(iocb->ki_filp->f_mapping, iocb->ki_filp,
				   iocb->ki_pos, orig_count,
				   NETFS_DIO_READ);
	if (IS_ERR(rreq))
		return PTR_ERR(rreq);

	ctx = netfs_inode(rreq->inode);
	netfs_stat(&netfs_n_rh_dio_read);
	trace_netfs_read(rreq, rreq->start, rreq->len, netfs_read_trace_dio_read);

	/* If this is an async op, we have to keep track of the destination
	 * buffer for ourselves as the caller's iterator will be trashed when
	 * we return.
	 *
	 * In such a case, extract an iterator to represent as much of the the
	 * output buffer as we can manage.  Note that the extraction might not
	 * be able to allocate a sufficiently large bvec array and may shorten
	 * the request.
	 */
	if (user_backed_iter(iter)) {
		ret = netfs_extract_user_iter(iter, rreq->len, &rreq->iter, 0);
		if (ret < 0)
			goto out;
		rreq->direct_bv = (struct bio_vec *)rreq->iter.bvec;
		rreq->direct_bv_count = ret;
		rreq->direct_bv_unpin = iov_iter_extract_will_pin(iter);
		rreq->len = iov_iter_count(&rreq->iter);
	} else {
		rreq->iter = *iter;
		rreq->len = orig_count;
		rreq->direct_bv_unpin = false;
		iov_iter_advance(iter, orig_count);
	}

	/* If we're going to do decryption or decompression, we're going to
	 * need a bounce buffer - and if the data is misaligned for the crypto
	 * algorithm, we decrypt in place and then copy.
	 */
	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &rreq->flags)) {
		if (!netfs_is_crypto_aligned(rreq, iter))
			__set_bit(NETFS_RREQ_CRYPT_IN_PLACE, &rreq->flags);
		__set_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags);
	}

	/* If we're going to use a bounce buffer, we need to set it up.  We
	 * will then need to pad the request out to the minimum block size.
	 */
	if (test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &rreq->flags)) {
		min_bsize = 1ULL << ctx->min_bshift;
		start = round_down(rreq->start, min_bsize);
		end = min_t(unsigned long long,
			    round_up(rreq->start + rreq->len, min_bsize),
			    ctx->remote_i_size);

		rreq->start = start;
		rreq->len   = end - start;
		first = start / PAGE_SIZE;
		last  = (end - 1) / PAGE_SIZE;
		_debug("bounce %llx-%llx %lx-%lx",
		       rreq->start, end, first, last);

		ret = netfs_add_folios_to_buffer(&rreq->bounce, rreq->mapping,
						 first, last, GFP_KERNEL);
		if (ret < 0)
			goto out;
	}

	if (async)
		rreq->iocb = iocb;

	ret = netfs_begin_read(rreq, is_sync_kiocb(iocb));
	if (ret < 0)
		goto out; /* May be -EIOCBQUEUED */
	if (!async) {
		ret = netfs_dio_copy_bounce_to_dest(rreq);
		if (ret == 0) {
			iocb->ki_pos += rreq->transferred;
			ret = rreq->transferred;
		}
	}

out:
	netfs_put_request(rreq, false, netfs_rreq_trace_put_return);
	if (ret > 0)
		orig_count -= ret;
	if (ret != -EIOCBQUEUED)
		iov_iter_revert(iter, orig_count - iov_iter_count(iter));
	return ret;
}

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
