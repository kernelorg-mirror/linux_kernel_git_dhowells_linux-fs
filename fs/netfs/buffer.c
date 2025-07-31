// SPDX-License-Identifier: GPL-2.0-only
/* Buffering helpers for bvec_queues
 *
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#include "internal.h"

void dump_bvecq(const struct bvecq *bq)
{
	int b = 0;

	for (; bq; bq = bq->next, b++) {
		printk("BQ[%u] %u/%u\n", b, bq->nr_segs, bq->max_segs);
		for (int s = 0; s < bq->nr_segs; s++) {
			const struct bio_vec *bv = &bq->bv[s];
			printk("BQ[%u:%u] %10lx %04x %04x %u\n",
			       b, s,
			       bv->bv_page ? page_to_pfn(bv->bv_page) : 0,
			       bv->bv_offset, bv->bv_len,
			       bv->bv_page ? page_count(bv->bv_page) : 0);
		}
	}
}

/**
 * netfs_alloc_bvecq_buffer - Allocate buffer space into a bvec queue
 * @size: Target size of the buffer.
 * @pre_slots: Number of preamble slots to set aside
 * @gfp: The allocation constraints.
 */
struct bvecq *netfs_alloc_bvecq_buffer(size_t size, unsigned int pre_slots, gfp_t gfp)
{
	struct bvecq *head = NULL, *tail = NULL, *p = NULL;
	size_t count = DIV_ROUND_UP(size, PAGE_SIZE);
	int max_segs = 32;

	_enter("%zx,%zx,%u", size, count, pre_slots);

	do {
		struct page **pages;
		int want, got;

		p = kzalloc(struct_size(p, bv, max_segs), gfp);
		if (!p)
			goto oom;
		if (tail) {
			tail->next = p;
			p->prev = tail;
		} else {
			head = p;
		}
		tail = p;
		pages = (struct page **)&p->bv[max_segs];
		pages -= max_segs - pre_slots;

		want = umin(count, max_segs - pre_slots);
		got = alloc_pages_bulk(gfp, want, pages);
		if (got < want) {
			for (int i = 0; i < got; i++)
				__free_page(pages[i]);
			goto oom;
		}

		tail->max_segs = max_segs;
		tail->nr_segs = pre_slots + got;
		for (int i = 0; i < got; i++) {
			int j = pre_slots + i;
			set_page_count(pages[i], 1);
			bvec_set_page(&tail->bv[j], pages[i], PAGE_SIZE, 0);
		}

		count -= got;
		pre_slots = 0;
	} while (count > 0);

	return head;
oom:
	netfs_free_bvecq_buffer(head);
	return NULL;
}
EXPORT_SYMBOL(netfs_alloc_bvecq_buffer);

/**
 * netfs_free_bvecq_buffer - Free a bvec queue
 * @bq: The start of the folio queue to free
 *
 * Free up a chain of bvecqs and the pages it points to.
 */
void netfs_free_bvecq_buffer(struct bvecq *bq)
{
	struct bvecq *next;

	for (; bq; bq = next) {
		for (int seg = 0; seg < bq->nr_segs; seg++)
			__free_page(bq->bv[seg].bv_page);
		next = bq->next;
		kfree(bq);
	}
}
EXPORT_SYMBOL(netfs_free_bvecq_buffer);
