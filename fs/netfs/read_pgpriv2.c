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

int netfs_prepare_pgpriv2_write_buffer(struct netfs_io_subrequest *subreq,
				       unsigned int max_segs, bool copy)
{
	struct netfs_io_request *creq = subreq->rreq;
	struct netfs_io_stream *stream = &creq->io_streams[1];
	ssize_t got;
	size_t len;

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);

	if (copy) {
		got = bvecq_extract(&stream->dispatch_cursor, subreq->len, max_segs,
				    &subreq->content.bvecq);
		if (got < 0)
			return -ENOMEM;
		len = got;
	} else {
		bvecq_pos_set(&subreq->content, &stream->dispatch_cursor);
		len = bvecq_slice(&stream->dispatch_cursor, subreq->len, max_segs,
				  &subreq->nr_segs);
	}

	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	// TODO: Wait here for completion of prev subreq

	stream->issue_from += subreq->len;
	stream->buffered   -= subreq->len;
	if (stream->buffered == 0)
		netfs_all_subreqs_queued(creq);
	return 0;
}

/*
 * [DEPRECATED] Copy a folio to the cache with PG_private_2 set.  Note that the
 * folio won't necessarily be contiguous with the previous one as there might
 * be a mixture of folios read from the cache and downloaded from the server
 * (or just zeroed).
 */
static void netfs_pgpriv2_copy_folio(struct netfs_io_request *creq, struct folio *folio)
{
	struct netfs_io_stream *cache = &creq->io_streams[1];
	struct bvecq *queue;
	unsigned int slot;
	size_t dio_size = PAGE_SIZE;
	size_t fsize = folio_size(folio), flen = fsize;
	loff_t fpos = folio_pos(folio), i_size;

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

	if (flen > i_size - fpos)
		flen = i_size - fpos;

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
		queue->fpos = fpos;
		if (fpos != creq->last_end)
			queue->discontig = true;
	}

	/* Attach the folio to the rolling buffer. */
	slot = queue->nr_slots;
	bvec_set_folio(&queue->bv[slot], folio, fsize, 0);
	trace_netfs_bv_slot(queue, slot);
	slot++;
	bvecq_filled_to(queue, slot);
	creq->load_cursor.slot = slot;
	creq->load_cursor.offset = 0;
	trace_netfs_wback(creq, folio, 0);

	cache->buffered += flen;
}

/*
 * [DEPRECATED] Set up copying to the cache.
 */
static struct netfs_io_request *netfs_pgpriv2_begin_copy_to_cache(
	struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_io_request *creq;
	struct netfs_io_stream *cache;

	if (!fscache_resources_valid(&rreq->cache_resources))
		goto cancel;

	creq = netfs_create_write_req(rreq->mapping, NULL, folio_pos(folio),
				      NETFS_PGPRIV2_COPY_TO_CACHE);
	if (IS_ERR(creq))
		goto cancel;

	cache = &creq->io_streams[1];
	if (!cache->avail)
		goto cancel_put;

	if (bvecq_buffer_init(&creq->load_cursor, GFP_KERNEL) < 0)
		goto cancel_put;

	bvecq_pos_set(&cache->dispatch_cursor, &creq->load_cursor);
	bvecq_pos_set(&creq->collect_cursor, &creq->load_cursor);

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
	clear_bit(NETFS_RREQ_FOLIO_COPY_TO_CACHE, &rreq->flags);
	return ERR_PTR(-ENOBUFS);
}

/*
 * [DEPRECATED] Mark page as requiring copy-to-cache using PG_private_2 and add
 * it to the copy write request.
 */
void netfs_pgpriv2_copy_to_cache(struct netfs_io_request *rreq, struct folio *folio)
{
	struct netfs_io_request *creq = rreq->copy_to_cache;

	if (!creq)
		creq = netfs_pgpriv2_begin_copy_to_cache(rreq, folio);
	if (IS_ERR(creq))
		return;

	if (!creq->spare) {
		creq->spare = bvecq_alloc_one(BVECQ_STD_SLOTS, GFP_NOFS);
		if (!creq->spare) {
			clear_bit(NETFS_RREQ_FOLIO_COPY_TO_CACHE, &creq->flags);
			return;
		}
	}

	trace_netfs_folio(folio, netfs_folio_trace_copy_to_cache);
	folio_start_private_2(folio);
	netfs_pgpriv2_copy_folio(creq, folio);
}

/*
 * Issue all pending writes on the cache stream.
 */
static int netfs_pgpriv2_issue_stream(struct netfs_io_request *wreq,
				      struct netfs_io_stream *stream)
{
	int ret;

	atomic64_set_release(&stream->issued_to, wreq->start);

	do {
		struct netfs_io_subrequest *subreq;

		subreq = netfs_alloc_write_subreq(wreq, stream);
		if (!subreq)
			return -ENOMEM;

		stream->issue_write(subreq);
		if (test_bit(NETFS_RREQ_SAW_ENOMEM, &wreq->flags))
			return -ENOMEM;

	} while (stream->buffered > 0);

	return ret;
}

/*
 * [DEPRECATED] End writing to the cache, flushing out any outstanding writes.
 */
void netfs_pgpriv2_end_copy_to_cache(struct netfs_io_request *rreq)
{
	struct netfs_io_request *creq = rreq->copy_to_cache;
	struct netfs_io_stream *stream = &creq->io_streams[1];

	if (IS_ERR_OR_NULL(creq))
		return;

	netfs_pgpriv2_issue_stream(creq, stream);
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
	unsigned long long collected_to = creq->collected_to;
	unsigned int slot;
	bool made_progress = false;

	slot = creq->collect_cursor.slot;

	for (;;) {
		struct folio *folio;
		unsigned long long fpos, fend;
		size_t fsize, flen;

		if (!bvecq_acquire_slot(bq, slot)) {
			if (!bvecq_delete_spent(&creq->collect_cursor, slot))
				return false;
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

		fend = min_t(unsigned long long, fpos + flen, creq->i_size);

		trace_netfs_collect_folio(creq, folio, fend, collected_to);

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
	return made_progress;
}
