// SPDX-License-Identifier: GPL-2.0-or-later
/* Iterator helpers.
 *
 * Copyright (C) 2022 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/scatterlist.h>
#include <linux/netfs.h>
#include "internal.h"

/**
 * netfs_extract_iter - Extract virtually contiguous pages from an iterator into a bvecq
 * @orig: The original iterator
 * @max_len: Maximum number of bytes to extract
 * @max_pages: Maximum number of pages to extract
 * @fpos: Starting file position to label the bvecq with
 * @_bvecq_head: Where to cache the bvec queue
 * @extraction_flags: Flags to qualify the request
 *
 * Extract virtually contiguous page fragments from the source iterator up to
 * the given maxima and build bvec queue that refers to all of those bits.
 * This allows the original iterator to disposed of.
 *
 * @extraction_flags can have ITER_ALLOW_P2PDMA set to request peer-to-peer DMA be
 * allowed on the pages extracted.
 *
 * On success, the amount of data in the bvec is returned, the original
 * iterator will have been advanced by the amount extracted.
 *
 * The bvecq segments are marked with indications on how to get clean up the
 * extracted fragments.
 */
ssize_t netfs_extract_iter(struct iov_iter *orig, size_t max_len, size_t max_pages,
			   unsigned long long fpos, struct bvecq **_bvecq_head,
			   iov_iter_extraction_t extraction_flags)
{
	struct bvecq *bq_tail = NULL;
	ssize_t ret = 0;
	size_t extracted = 0;

	_enter("{%u,%zx},%zx", orig->iter_type, orig->count, max_len);

	if (max_len > orig->count)
		max_len = orig->count;
	if (WARN_ON_ONCE(!max_len || !max_pages))
		return 0;

	max_pages = iov_iter_npages(orig, max_pages);
	if (!max_pages)
		return 0;

	do {
		struct bvecq *bq;

		bq = bvecq_alloc_one(max_pages, GFP_NOFS);
		if (!bq) {
			ret = -ENOMEM;
			break;
		}
		if (user_backed_iter(orig))
			bq->mem_type = iov_iter_extract_will_pin(orig) ?
				BVECQ_MEM_GUP : BVECQ_MEM_PAGECACHE;
		bq->prev	= bq_tail;
		bq->fpos	= fpos + extracted;

		if (bq_tail)
			bq_tail->next = bq;
		else
			*_bvecq_head = bq;
		bq_tail = bq;

		if (max_len == 0)
			break;

		struct bio_vec *bv = bq->bv;
		do {
			struct page **pages;
			unsigned int slot = 0;
			ssize_t got;
			size_t offset;
			size_t space = bq->max_slots - bq->nr_slots;
			size_t bv_size = array_size(bq->max_slots, sizeof(*bv));
			size_t pg_size = array_size(space, sizeof(*pages));

			/* Put the page list at the end of the bvec list
			 * storage.  bvec elements are larger than page
			 * pointers, so as long as we work 0->last, we should
			 * be fine.
			 */
			pages = (void *)bv + bv_size - pg_size;

			got = iov_iter_extract_pages(orig, &pages, max_len,
						     space, extraction_flags, &offset);
			if (got < 0) {
				ret = got;
				goto out;
			}

			if (got == 0) {
				pr_err("extract_pages gave nothing from %zx, %zx\n",
				       extracted, max_len);
				ret = -EIO;
				goto out;
			}

			if (WARN(got > max_len,
				 "%s: extract_pages overrun %zx > %zx bytes\n",
				 __func__, got, max_len)) {
				ret = -EIO;
				break;
			}

			extracted += got;
			max_len -= got;

			do {
				size_t len = umin(got, PAGE_SIZE - offset);

				BUG_ON(slot >= bq->max_slots);

				bvec_set_page(&bq->bv[slot], *pages++, len, offset);
				slot++;
				got -= len;
				offset = 0;
			} while (got > 0);

			bvecq_filled_to(bq, slot);
		} while (max_len > 0 && !bvecq_is_full(bq));

		max_pages -= bq->nr_slots;
	} while (max_len > 0 && max_pages > 0);

out:
	return extracted ?: ret;
}
EXPORT_SYMBOL_GPL(netfs_extract_iter);
