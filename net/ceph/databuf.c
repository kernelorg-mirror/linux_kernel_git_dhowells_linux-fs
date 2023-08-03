// SPDX-License-Identifier: GPL-2.0
/* Data container
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/ceph/databuf.h>

/**
 * ceph_bvecq_reserve - Allocate extra space in the buffer
 * @enc: The encoding context to expand
 * @add_space: The amount of space to be added
 *
 * Preallocate sufficient pages for a data buffer object to be able to append
 * the specified amount of data without having to perform further allocation.
 *
 * Returns: 0 on success, -ENOMEM on error.
 */
int ceph_bvecq_reserve(struct ceph_encode *enc, size_t add_space)
{
	size_t capacity = enc->capacity;
	size_t new_size = enc->len + add_space;
	int ret;

	if (enc->capacity >= new_size)
		return 0;

	ret = bvecq_expand_buffer(&enc->dbuf, &capacity, new_size, enc->gfp, false);
	enc->capacity = capacity;
	if (ret < 0) {
		enc->nomem = true;
		return ret;
	}
	return 0;
}
EXPORT_SYMBOL(ceph_bvecq_reserve);

/**
 * ceph_bvecq_append - Append some data onto a buffer
 * @enc: The encoding context
 * @data: The data to append
 * @len: The length of the data
 *
 * Add some data onto the end of the encoding buffer's occupied region.  This
 * will expand the maximum size of the buffer if necessary.
 *
 * If ENOMEM is encountered, enc->nomem is set to true and all future appends
 * will do nothing.
 */
void ceph_bvecq_append(struct ceph_encode *enc, const void *data, size_t len)
{
	for (;;) {
		struct bvecq *bq;

		if (likely(len <= enc->space)) {
			size_t part = umin(part, enc->space);

			memcpy(enc->p, data, len);
			enc->p += len;
			enc->space -= len;
			enc->len += len;

			if (part >= len)
				return;
			data += part;
			len -= part;
		}

		if (enc->p)
			kunmap_local(enc->p);

		if (unlikely(enc->nomem))
			return;
		if (ceph_bvecq_reserve(enc, len) < 0) {
			enc->p = NULL;
			enc->nomem = true;
			return;
		}

		enc->slot++;
		bq = enc->bq;
		if (enc->slot >= bq->nr_slots) {
			bq = bq->next;
			enc->bq = bq;
			enc->slot = 0;
		}
		enc->space = bq->bv[enc->slot].bv_len;
		enc->p = kmap_local_bvecq(enc->bq, 0);
	}
}
EXPORT_SYMBOL(ceph_bvecq_append);

/**
 * ceph_bvecq_insert_frag - Allocate and insert a fragment into a buffer
 * @bq: The data buffer to modify
 * @index: The bio_vec slot to set
 * @len: The amount of data to set in the bio_vec
 * @gfp: Flags controlling the allocation
 *
 * Allocate a page fragment suitable for MSG_SPLICE_PAGES and insert it into
 * the buffer at the specified index.  This may indicate a whole page or it
 * may, in future, allocate a fragment of size @len from a page fragment
 * allocator.
 *
 * Return: 0 on success, -ENOMEM if insufficient memory.
 */
int ceph_bvecq_insert_frag(struct bvecq *bq, unsigned int index, size_t len, gfp_t gfp)
{
	struct page *page;

	page = alloc_page(gfp);
	if (!page)
		return -ENOMEM;

	bvec_set_page(&bq->bv[index], page, len, 0);
	if (bq->nr_slots == index)
		bq->nr_slots = index + 1;
	return 0;
}
EXPORT_SYMBOL(ceph_bvecq_insert_frag);
