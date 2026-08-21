// SPDX-License-Identifier: GPL-2.0-only
/* Read with PG_private_2 [DEPRECATED].
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/task_io_accounting_ops.h>
#include "internal.h"

/*
 * [DEPRECATED] Copy a folio to the cache with PG_private_2 set.
 */
static void netfs_pgpriv2_copy_folio(struct netfs_io_request *creq, struct folio *folio)
{
	struct netfs_io_stream *cache = &creq->io_streams[1];
	struct bvecq *queue;
	unsigned int slot;
	size_t dio_size = PAGE_SIZE;
	size_t fsize = folio_size(folio), flen = fsize;
	uoff_t fpos = folio_pos(folio), i_size;
	bool to_eof = false;

	_enter("");

	/* netfs_perform_write() may shift i_size around the page or from out
	 * of the page to beyond it, but cannot move i_size into or through the
	 * page since we have it locked.
	 */
	i_size = i_size_read(creq->inode);

	if (fpos >= i_size) {
		/* mmap beyond eof. */
		_debug("beyond eof");
		folio_end_private_2(folio);
		return;
	}

	if (fpos + fsize > creq->i_size)
		creq->i_size = i_size;

	if (flen > i_size - fpos) {
		flen = i_size - fpos;
		to_eof = true;
	} else if (flen == i_size - fpos) {
		to_eof = true;
	}

	flen = round_up(flen, dio_size);

	_debug("folio %zx %zx", flen, fsize);

	trace_netfs_folio(folio, netfs_folio_trace_store_copy);

	/* Institute a new bvec queue segment if the current one is full or if
	 * we encounter a discontiguity.  The discontiguity break is important
	 * when it comes to bulk unlocking folios by file range.
	 */
	queue = creq->load_cursor.bvecq;
	if (bvecq_is_full(queue) ||
	    (fpos != creq->last_end && creq->last_end > 0 && queue->nr_slots > 0)) {
		bvecq_buffer_append(&creq->load_cursor, creq->spare);
		creq->spare = NULL;

		queue = creq->load_cursor.bvecq;
	}

	/* Attach the folio to the rolling buffer. */
	slot = queue->nr_slots;
	bvec_set_folio(&queue->bv[slot], folio, fsize, 0);
	trace_netfs_bv_slot(queue, slot);
	slot++;
	bvecq_filled_to(queue, slot);
	creq->load_cursor.slot = slot;
	creq->load_cursor.offset = 0;
	creq->last_end = fpos + flen;

	bvecq_pos_nudge(&creq->dispatch_cursor);
	
	cache->submit_off = 0;
	cache->submit_len = flen;

	/* Attach the folio to one or more subrequests.  For a big folio, we
	 * could end up with thousands of subrequests if the wsize is small -
	 * but we might need to wait during the creation of subrequests for
	 * network resources (eg. SMB credits).
	 */
	do {
		ssize_t part;

		creq->dispatch_cursor.offset = cache->submit_off;

		atomic64_set(&cache->issued_to, fpos + cache->submit_off);
		part = netfs_advance_write(creq, cache, fpos + cache->submit_off,
					   cache->submit_len, to_eof);
		cache->submit_off += part;
		if (part > cache->submit_len)
			cache->submit_len = 0;
		else
			cache->submit_len -= part;
	} while (cache->submit_len > 0);

	bvecq_pos_step(&creq->dispatch_cursor);
	atomic64_set(&cache->issued_to, fpos + fsize);

	if (flen < fsize)
		netfs_issue_write(creq, cache);
}

/*
 * [DEPRECATED] Set up copying to the cache.
 */
static struct netfs_io_request *netfs_pgpriv2_begin_copy_to_cache(
	struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_io_request *creq;

	if (!fscache_resources_valid(&rreq->cache_resources))
		goto cancel;

	creq = netfs_create_write_req(rreq->mapping, NULL, folio_pos(folio),
				      NETFS_PGPRIV2_COPY_TO_CACHE);
	if (IS_ERR(creq))
		goto cancel;

	if (!creq->io_streams[1].avail)
		goto cancel_put;

	if (bvecq_buffer_init(&creq->load_cursor, creq->gfp, false) < 0)
		goto cancel_put;
	bvecq_pos_set(&creq->dispatch_cursor, &creq->load_cursor);
	bvecq_pos_set(&creq->collect_cursor, &creq->dispatch_cursor);

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &creq->flags);
	trace_netfs_copy2cache(rreq, creq);
	trace_netfs_write(creq, netfs_write_trace_copy_to_cache);
	netfs_stat(&netfs_n_wh_copy_to_cache);
	rreq->copy_to_cache = creq;
	return creq;

cancel_put:
	netfs_put_failed_request(creq);
cancel:
	rreq->copy_to_cache = ERR_PTR(-ENOBUFS);
	set_bit(NETFS_RREQ_CANCEL_CACHING, &rreq->flags);
	return ERR_PTR(-ENOBUFS);
}

/*
 * [DEPRECATED] Mark page as requiring copy-to-cache using PG_private_2 and add
 * it to the copy write request.  PG_private_2 should already be set on the
 * folio.
 */
void netfs_pgpriv2_copy_to_cache(struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_io_request *creq = rreq->copy_to_cache;

	if (!creq)
		creq = netfs_pgpriv2_begin_copy_to_cache(rreq, folio);
	if (IS_ERR(creq)) {
		set_bit(NETFS_RREQ_CANCEL_CACHING, &rreq->flags);
		netfs_cancel_copy_to_cache(rreq, folio);
		return;
	}

	if (!creq->spare) {
		creq->spare = bvecq_alloc_one(BVECQ_STD_SLOTS, creq->gfp, false);
		if (!creq->spare) {
			set_bit(NETFS_RREQ_CANCEL_CACHING, &creq->flags);
			return;
		}
	}

	trace_netfs_folio(folio, netfs_folio_trace_pgpriv2_copy);
	netfs_pgpriv2_copy_folio(creq, folio);
}

/*
 * [DEPRECATED] End writing to the cache, flushing out any outstanding writes.
 */
void netfs_pgpriv2_end_copy_to_cache(struct netfs_io_request *rreq)
{
	struct netfs_io_request *creq = rreq->copy_to_cache;

	if (IS_ERR_OR_NULL(creq))
		return;

	netfs_issue_write(creq, &creq->io_streams[1]);
	netfs_all_subreqs_queued(creq);
	trace_netfs_rreq(rreq, netfs_rreq_trace_end_copy_to_cache);
	if (list_empty_careful(&creq->io_streams[1].subrequests))
		netfs_wake_collector(creq);

	netfs_put_request(creq, netfs_rreq_trace_put_return);
	creq->copy_to_cache = NULL;
}

/*
 * [DEPRECATED] Remove the PG_private_2 mark from any folios we've finished
 * copying.
 */
bool netfs_pgpriv2_unlock_copied_folios(struct netfs_io_request *creq)
{
	struct bvecq *bq = creq->collect_cursor.bvecq;
	unsigned int slot;
	uoff_t collected_to = creq->collected_to;
	bool made_progress = false;

	slot = creq->collect_cursor.slot;

	for (;;) {
		struct folio *folio;
		uoff_t fpos, fend;
		size_t fsize, flen;

		if (!bvecq_acquire_slot(bq, slot)) {
			creq->collect_cursor.slot = slot;
			if (!bvecq_delete_spent(&creq->collect_cursor))
				goto out;
			bq   = creq->collect_cursor.bvecq;
			slot = creq->collect_cursor.slot;
		}

		folio = page_folio(bq->bv[slot].bv_page);
		if (WARN_ONCE(!folio_test_private_2(folio),
			      "R=%08x: folio %lx is not marked private_2\n",
			      creq->debug_id, folio->index))
			trace_netfs_folio(folio, netfs_folio_trace_not_under_wback);

		fpos = folio_pos(folio);
		fsize = folio_size(folio);
		flen = fsize;

		fend = min_t(uoff_t, fpos + flen, creq->i_size);

		trace_netfs_collect_folio(creq, folio);

		/* Unlock any folio we've transferred all of. */
		if (collected_to < fend)
			break;

		trace_netfs_folio(folio, netfs_folio_trace_end_copy);
		folio_end_private_2(folio);
		creq->cleaned_to = fpos + fsize;
		made_progress = true;

		/* Clean up the head segment.  If we clear an entire segment,
		 * then we can get rid of it provided it's not also the tail
		 * segment being filled by the issuer.
		 */
		bq->bv[slot].bv_page = NULL;
		slot++;

		if (fpos + fsize >= collected_to)
			break;
	}

	creq->collect_cursor.slot = slot;
out:
	return made_progress;
}
