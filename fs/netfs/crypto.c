// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem content encryption support.
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include "internal.h"

/*
 * Populate a scatterlist from the next bufferage of an I/O iterator.
 */
static int netfs_bvecq_to_sglist(struct bvecq_pos *pos, size_t len,
				 struct scatterlist *sg, unsigned int n_sg)
{
	int nr = 0;

	do {
		const struct bio_vec *bv;
		size_t part;

		if (!bvecq_pos_nudge(pos))
			break;

		bv = &pos->bvecq->bv[pos->slot];
		part = min(bv->bv_len - pos->offset, len);

		sg_set_page(sg++, bv->bv_page, part, bv->bv_offset + pos->offset);
		nr++;
		pos->offset += part;
		len -= part;
	} while (nr < n_sg && len > 0);

	if (nr == 0)
		return -EFAULT;
	sg_mark_end(sg - 1);
	return nr;
}

/*
 * Start asynchronous encryption from the source folio in/into the bounce folio
 * (which may be the same folio).
 */
int netfs_encrypt_folio(struct netfs_io_request *wreq, struct folio *folio,
			unsigned long long start, size_t len, gfp_t gfp)
{
	struct netfs_inode *ictx = netfs_inode(wreq->inode);
	struct bvecq *bq = wreq->encrypt_cursor.bvecq;
	size_t offset = wreq->encrypt_cursor.offset;
	size_t bsize = wreq->crypto_bsize;
	int slot = wreq->encrypt_cursor.slot;
	int ret;

	_enter("");

	trace_netfs_rreq(wreq, netfs_rreq_trace_encrypt);

	do {
		struct scatterlist src_sg, dst_sg;

		if (offset >= bq->bv[slot].bv_len) {
			slot++;
			if (slot >= READ_ONCE(bq->nr_slots)) {
				if (!bq->next)
					break;
				bq = bq->next;
				slot = 0;
			}
			offset = 0;
		}

		trace_netfs_folio(folio, netfs_folio_trace_encrypt);
		trace_netfs_bounce(wreq, start, &bq->bv[slot],
				   netfs_folio_trace_encrypt);

		sg_init_table(&src_sg, 1);
		sg_init_table(&dst_sg, 1);
		sg_set_folio(&src_sg, folio, bsize, start - folio_pos(folio));
		sg_set_page(&dst_sg, bq->bv[slot].bv_page, bsize, offset);

		ret = ictx->ops->encrypt_block(wreq, start, &src_sg, &dst_sg, gfp);
		if (ret < 0)
			return ret;
		offset += bsize;
		start += bsize;
		len -= bsize;
	} while (len > 0);

	bvecq_pos_move(&wreq->encrypt_cursor, bq);
	wreq->encrypt_cursor.slot = slot;
	wreq->encrypt_cursor.offset = offset;
	return 0;
}

/*
 * Start asynchronous encryptions
 */
int netfs_encrypt(struct netfs_io_request *wreq, unsigned long long to, gfp_t gfp)
{
	struct netfs_inode *ictx = netfs_inode(wreq->inode);
	unsigned long long start = atomic64_read(&wreq->encrypted_to);
	size_t bsize = wreq->crypto_bsize;
	int ret;

	_enter("%llx,%llx", start, to);

	trace_netfs_rreq(wreq, netfs_rreq_trace_encrypt);

	while (start < to) {
		struct scatterlist sg;

		sg_init_table(&sg, 1);

		ret = netfs_bvecq_to_sglist(&wreq->encrypt_cursor, bsize, &sg, 1);
		if (ret < 0)
			goto error;

		ictx->ops->encrypt_block(wreq, start, &sg, &sg, gfp);
		start += bsize;
	}

	return true;

error:
	wreq->error = ret;
	return false;
}

/*
 * Decrypt a folio in the pagecache.  We arrange the minimum folio size such
 * that the crypto block size will never be larger than the size of the folios
 * we are using.
 */
void netfs_decrypt_folio(struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_inode *ictx = netfs_inode(rreq->inode);
	struct scatterlist sg;
	unsigned long long start = folio_pos(folio);
	size_t len = folio_size(folio);
	size_t bsize = rreq->crypto_bsize, off = 0;
	int ret;

	if (start >= rreq->i_size)
		return;
	trace_netfs_folio(folio, netfs_folio_trace_decrypt);

	len = umin(len, rreq->i_size - start);

	_debug("DECRYPT %llx-%llx", start, start + len - 1);

	do {
		sg_init_table(&sg, 1);
		sg_set_folio(&sg, folio, bsize, off);

		ret = ictx->ops->decrypt_block(rreq, start + off, bsize, &sg, 1, &sg, 1);
		if (ret < 0)
			goto error_failed;
		off += bsize;
	} while (off < len);

	return;

error_failed:
	trace_netfs_failure(rreq, NULL, ret, netfs_fail_decryption);
	rreq->error = ret;
	set_bit(NETFS_RREQ_FAILED, &rreq->flags);
	return;
}

/*
 * Decrypt the result of a DIO read request.
 */
void netfs_decrypt_dio(struct netfs_io_request *rreq)
{
	struct netfs_inode *ictx = netfs_inode(rreq->inode);
	unsigned long long start = atomic64_read(&rreq->encrypted_to);
	size_t processed = 0, bsize = rreq->crypto_bsize;
	size_t len = rreq->collected_to - start;
	int ret;

	trace_netfs_rreq(rreq, netfs_rreq_trace_decrypt);
	if (rreq->start >= rreq->i_size)
		return;

	len = round_down(len, bsize);

	_debug("DECRYPT %llx-%llx f=%lx", start, start + len - 1, rreq->flags);

	do {
		struct scatterlist source_sg[1], dest_sg[1];
		struct sg_table source = { .sgl = source_sg, };
		struct sg_table dest   = { .sgl = dest_sg, };

		sg_init_table(source_sg, 1);
		sg_init_table(dest_sg, 1);

		ret = bvecq_extract_to_sg(&rreq->bounce_collect, bsize,
					  &source, ARRAY_SIZE(source_sg));
		if (ret != bsize) {
			pr_err("Failed to extract buffer in netfs_decrypt_dio()\n");
			ret = -EIO;
			goto error;
		}

		ret = bvecq_extract_to_sg(&rreq->encrypt_cursor, bsize,
					  &dest, ARRAY_SIZE(dest_sg));
		if (ret != bsize) {
			pr_err("Failed to extract buffer in netfs_decrypt_dio()\n");
			ret = -EIO;
			goto error;
		}

		ret = ictx->ops->decrypt_block(rreq, start, bsize,
					       source_sg, source.nents,
					       dest_sg, dest.nents);
		if (ret < 0)
			goto error_failed;
		processed += bsize;
		start += bsize;
	} while (processed < len);

	atomic64_set(&rreq->encrypted_to, start);

	rreq->transferred = processed;
	return;

error_failed:
	trace_netfs_failure(rreq, NULL, ret, netfs_fail_decryption);
error:
	rreq->error = ret;
	__set_bit(NETFS_RREQ_FAILED, &rreq->flags);
	return;
}
