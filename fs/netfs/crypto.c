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
 * Encrypt from the source folio into the bounce page.
 */
void netfs_encrypt_folio(struct netfs_io_request *wreq,
			 struct folio *folio, size_t foff,
			 struct page *page, size_t poff,
			 size_t len)
{
	struct netfs_inode *ictx = netfs_inode(wreq->inode);
	size_t bsize = wreq->crypto_bsize, fend = foff + len;
	uoff_t start = folio_pos(folio);

	_enter("");

	trace_netfs_rreq(wreq, netfs_rreq_trace_encrypt);

	do {
		struct scatterlist src_sg, dst_sg;

		trace_netfs_folio(folio, netfs_folio_trace_encrypt);

		sg_init_table(&src_sg, 1);
		sg_init_table(&dst_sg, 1);
		sg_set_folio(&src_sg, folio, bsize, foff);
		sg_set_page(&dst_sg, page, bsize, poff);

		ictx->ops->encrypt_block(wreq, start, &src_sg, &dst_sg, wreq->gfp);
		start += bsize;
		foff += bsize;
		poff += bsize;
	} while (foff < fend);
}

/*
 * Start asynchronous encryptions
 */
int netfs_encrypt(struct netfs_io_request *wreq, uoff_t to, gfp_t gfp)
{
	struct netfs_inode *ictx = netfs_inode(wreq->inode);
	uoff_t start = atomic64_read(&wreq->encrypted_to);
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
