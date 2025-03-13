// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem high-level (buffered) writeback.
 *
 * Copyright (C) 2024 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 *
 * To support network filesystems with local caching, we manage a situation
 * that can be envisioned like the following:
 *
 *               +---+---+-----+-----+---+----------+
 *    Folios:    |   |   |     |     |   |          |
 *               +---+---+-----+-----+---+----------+
 *
 *                 +------+------+     +----+----+
 *    Upload:      |      |      |.....|    |    |
 *  (Stream 0)     +------+------+     +----+----+
 *
 *               +------+------+------+------+------+
 *    Cache:     |      |      |      |      |      |
 *  (Stream 1)   +------+------+------+------+------+
 *
 * Where we have a sequence of folios of varying sizes that we need to overlay
 * with multiple parallel streams of I/O requests, where the I/O requests in a
 * stream may also be of various sizes (in cifs, for example, the sizes are
 * negotiated with the server; in something like ceph, they may represent the
 * sizes of storage objects).
 *
 * The sequence in each stream may contain gaps and noncontiguous subrequests
 * may be glued together into single vectored write RPCs.
 */

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include "internal.h"

#define NOTE_UPLOAD_AVAIL	0x001	/* Upload is available */
#define NOTE_CACHE_AVAIL	0x002	/* Local cache is available */
#define NOTE_CACHE_COPY		0x004	/* Copy folio to cache */
#define NOTE_UPLOAD		0x008	/* Upload folio to server */
#define NOTE_UPLOAD_STARTED	0x010	/* Upload started */
#define NOTE_STREAMW		0x020	/* Folio is from a streaming write */
#define NOTE_FLUSH_ANYWAY	0x040	/* Flush data, even if not hit estimated limit */

#define NOTES__KEEP_MASK (NOTE_UPLOAD_AVAIL | NOTE_CACHE_AVAIL | NOTE_UPLOAD_STARTED)

struct netfs_wb_params {
	uoff_t			fpos;
	unsigned int		notes;		/* Notes on applicability */

	/* When we're using a bounce buffer, the outer data window is all of
	 * the data we encrypted, rounded out to the largest alignment; the
	 * inner data window is all the data that got changed, rounded out to
	 * the smallest alignment.
	 *
	 * We have two alignments at play: the size of chunk which we encrypt
	 * in one go (typically 4KiB) and the local cache DIO size.
	 */
	unsigned int		inner_align;	/* Smallest alignment */
	unsigned int		inner_off;	/* Start of inner data window */
	unsigned int		inner_end;	/* End of inner data window */
	unsigned int		outer_align;	/* Largest alignment */
	unsigned int		outer_off;	/* Start of outer data window */
	unsigned int		outer_end;	/* End of outer data window */

	/* Bounce buffer page currently being divided up. */
	unsigned int		bounce_usage;	/* Amount of bounce page used */
	unsigned int		bounce_size;	/* Size of bounce page */
	struct page		*bounce_page;	/* Bounce page */

	struct netfs_write_estimate estimates[NR_IO_STREAMS];
};

static int netfs_prepare_write_single_buffer(struct netfs_io_subrequest *subreq,
					     unsigned int max_segs);

/*
 * Kill all dirty folios in the event of an unrecoverable error, starting with
 * a locked folio we've already obtained from writeback_iter().
 */
static void netfs_kill_dirty_pages(struct address_space *mapping,
				   struct writeback_control *wbc,
				   struct folio *folio)
{
	int error = 0;

	do {
		enum netfs_folio_trace why = netfs_folio_trace_kill;
		struct netfs_group *group = NULL;
		struct netfs_folio *finfo = NULL;
		void *priv;

		priv = folio_detach_private(folio);
		if (priv) {
			finfo = __netfs_folio_info(priv);
			if (finfo) {
				/* Kill folio from streaming write. */
				group = finfo->netfs_group;
				why = netfs_folio_trace_kill_s;
			} else {
				group = priv;
				if (group == NETFS_FOLIO_COPY_TO_CACHE) {
					/* Kill copy-to-cache folio */
					why = netfs_folio_trace_kill_cc;
					group = NULL;
				} else {
					/* Kill folio with group */
					why = netfs_folio_trace_kill_g;
				}
			}
		}

		trace_netfs_folio(folio, why);

		folio_start_writeback(folio);
		folio_unlock(folio);
		folio_end_writeback(folio);

		netfs_put_group(group);
		kfree(finfo);

	} while ((folio = writeback_iter(mapping, wbc, folio, &error)));
}

/*
 * Create a write request and set it up appropriately for the origin type.
 */
struct netfs_io_request *netfs_create_write_req(struct address_space *mapping,
						struct file *file,
						uoff_t start,
						void *netfs_priv2,
						enum netfs_io_origin origin)
{
	struct netfs_io_request *wreq;
	struct netfs_inode *ictx;
	bool is_cacheable = (origin == NETFS_WRITEBACK ||
			     origin == NETFS_WRITEBACK_SINGLE ||
			     origin == NETFS_PGPRIV2_COPY_TO_CACHE);

	wreq = netfs_alloc_request(mapping, file, start, 0, netfs_priv2, origin);
	if (IS_ERR(wreq))
		return wreq;

	_enter("R=%x", wreq->debug_id);

	ictx = netfs_inode(wreq->inode);
	if (is_cacheable)
		fscache_begin_write_operation(&wreq->cache_resources, netfs_i_cookie(ictx));
	if (test_bit(NETFS_ICTX_ENCRYPTED, &ictx->flags))
		__set_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &wreq->flags);

	wreq->cleaned_to = wreq->start;
	if (wreq->cache_resources.dio_size > 1)
		wreq->cache_coll_to = round_down(wreq->start, wreq->cache_resources.dio_size);

	wreq->io_streams[0].stream_nr		= 0;
	wreq->io_streams[0].source		= NETFS_UPLOAD_TO_SERVER;
	wreq->io_streams[0].applicable		= NOTE_UPLOAD;
	wreq->io_streams[0].estimate_write	= ictx->ops->estimate_write;
	wreq->io_streams[0].issue_write		= ictx->ops->issue_write;
	wreq->io_streams[0].collected_to	= start;
	wreq->io_streams[0].transferred		= 0;

	wreq->io_streams[1].stream_nr		= 1;
	wreq->io_streams[1].source		= NETFS_WRITE_TO_CACHE;
	wreq->io_streams[1].applicable		= NOTE_CACHE_COPY;
	wreq->io_streams[1].collected_to	= start;
	wreq->io_streams[1].transferred		= 0;
	if (fscache_resources_valid(&wreq->cache_resources)) {
		wreq->io_streams[1].avail	= true;
		wreq->io_streams[1].active	= true;
		wreq->io_streams[1].estimate_write = wreq->cache_resources.ops->estimate_write;
		wreq->io_streams[1].issue_write = wreq->cache_resources.ops->issue_write;
		wreq->io_streams[1].alignment	= wreq->cache_resources.dio_size;
	}

	return wreq;
}

/*
 * Allocate and prepare a write subrequest.  Will only return NULL if not
 * performing writeback; if performing writeback, mempools may be accessed and
 * the allocator may wait forever.
 */
struct netfs_io_subrequest *netfs_alloc_write_subreq(struct netfs_io_request *wreq,
						     struct netfs_io_stream *stream)
{
	struct netfs_io_subrequest *subreq;

	subreq = netfs_alloc_subrequest(wreq, stream->source);
	if (!subreq)
		return subreq;

	subreq->start		= stream->issue_from;
	subreq->len		= stream->buffered;
	subreq->stream_nr	= stream->stream_nr;

	_enter("R=%x[%x]", wreq->debug_id, subreq->debug_index);

	trace_netfs_sreq(subreq, netfs_sreq_trace_prepare);

	switch (stream->source) {
	case NETFS_UPLOAD_TO_SERVER:
		netfs_stat(&netfs_n_wh_upload);
		break;
	case NETFS_WRITE_TO_CACHE:
		netfs_stat(&netfs_n_wh_write);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}

	__set_bit(NETFS_SREQ_IN_PROGRESS, &subreq->flags);

	/* We add to the end of the list whilst the collector may be walking
	 * the list.  The collector only goes nextwards and uses the lock to
	 * remove entries off of the front.
	 */
	spin_lock(&wreq->lock);
	/* Write IN_PROGRESS before pointer to new subreq */
	list_add_tail_release(&subreq->rreq_link, &stream->subrequests);
	if (list_is_first(&subreq->rreq_link, &stream->subrequests) &&
	    stream->collected_to == 0)
		stream->collected_to = subreq->start;

	spin_unlock(&wreq->lock);
	return subreq;
}

/*
 * Advance the state of the amount of data buffered on a stream.
 */
static void netfs_advance_stream(struct netfs_io_request *wreq,
				 struct netfs_io_stream *stream,
				 struct netfs_io_subrequest *subreq)
{
	stream->issue_from += subreq->len;
	stream->buffered   -= subreq->len;
	if (stream->buffered == 0) {
		subreq->post_gap = stream->post_gap;
		stream->post_gap = 0;
		stream->buffering = false;
		bvecq_pos_unset(&stream->dispatch_cursor);
	}
	/* Order loading the queue before updating the issue_to point */
	atomic64_set_release(&stream->issued_to, stream->issue_from);
}

/*
 * Prepare the buffer for a buffered write.
 */
static int netfs_prepare_buffered_write_buffer(struct netfs_io_subrequest *subreq,
					       unsigned int max_segs)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];
	ssize_t len;

	_enter("%zx,{,%u,%u},%u",
	       subreq->len, stream->dispatch_cursor.slot, stream->dispatch_cursor.offset, max_segs);

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);
	bvecq_pos_set(&subreq->content, &stream->dispatch_cursor);

	if (unlikely(test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags)))
		/* Round the length down to the crypto block size. */
		subreq->len = round_down(subreq->len, wreq->crypto_bsize);

	len = bvecq_slice(&stream->dispatch_cursor, subreq->len, max_segs, &subreq->nr_segs);
	if (len < subreq->len) {
		subreq->len = len;
		trace_netfs_sreq(subreq, netfs_sreq_trace_limited);
	}

	netfs_advance_stream(wreq, stream, subreq);
	return 0;
}

/**
 * netfs_prepare_write_buffer - Get the buffer for a subrequest
 * @subreq: The subrequest to get the buffer for
 * @max_segs: Maximum number of segments in buffer (or INT_MAX)
 *
 * Extract a slice of buffer from the stream and attach it to the subrequest as
 * a bio_vec queue.  The maximum amount of data attached is set by
 * @subreq->len, but this may be shortened if @max_segs would be exceeded.
 */
int netfs_prepare_write_buffer(struct netfs_io_subrequest *subreq,
			       unsigned int max_segs)
{
	struct netfs_io_request *rreq = subreq->rreq;

	switch (rreq->origin) {
	case NETFS_WRITEBACK:
		if (test_bit(NETFS_RREQ_RETRYING, &rreq->flags))
			return netfs_prepare_write_retry_buffer(subreq, max_segs);
		return netfs_prepare_buffered_write_buffer(subreq, max_segs);

	case NETFS_UNBUFFERED_WRITE:
	case NETFS_DIO_WRITE:
		return netfs_prepare_unbuffered_write_buffer(subreq, max_segs);

	case NETFS_WRITEBACK_SINGLE:
		return netfs_prepare_write_single_buffer(subreq, max_segs);

	case NETFS_PGPRIV2_COPY_TO_CACHE:
		return netfs_prepare_pgpriv2_write_buffer(subreq, max_segs);

	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
}
EXPORT_SYMBOL(netfs_prepare_write_buffer);

/*
 * Issue writes for a stream.
 */
static void netfs_writeback_flush(struct netfs_io_request *wreq,
				  struct netfs_io_stream *stream,
				  struct netfs_wb_params *params)
{
	struct netfs_write_estimate *estimate = &params->estimates[stream->stream_nr];

	for (;;) {
		struct netfs_io_subrequest *subreq;
		int ret;

		if (test_bit(NETFS_RREQ_PAUSE, &wreq->flags))
			netfs_wait_for_paused_write(wreq);

		subreq = netfs_alloc_write_subreq(wreq, stream);
		/* subreq allocation in a writeback is backed by a mempool and
		 * will wait for an new one to come available.
		 */

		if (stream->source == NETFS_WRITE_TO_CACHE &&
		    unlikely(test_bit(NETFS_RREQ_CACHE_STOP, &wreq->flags))) {
			estimate->issue_at = ULLONG_MAX;
			estimate->max_segs = INT_MAX;
			__set_bit(NETFS_SREQ_CANCELLED, &subreq->flags);
			netfs_advance_stream(wreq, stream, subreq);
			netfs_write_subrequest_terminated(subreq, subreq->len);
			return;
		}

		ret = stream->issue_write(subreq);
		if (ret < 0) {
			/* Ownership of subreq was returned to us. */
			trace_netfs_sreq(subreq, netfs_sreq_trace_fail);
			bvecq_pos_advance(&stream->dispatch_cursor, subreq->len);
			netfs_advance_stream(wreq, stream, subreq);
			netfs_write_subrequest_terminated(subreq, ret);
		}
		/* We no longer own subreq. */

		if (stream->buffered == 0) {
			if (stream->stream_nr == 0)
				params->notes &= ~NOTE_UPLOAD_STARTED;
			return;
		}

		if (!(params->notes & NOTE_FLUSH_ANYWAY)) {
			estimate->issue_at = ULLONG_MAX;
			estimate->max_segs = INT_MAX;
			stream->estimate_write(wreq, stream, estimate);
			if (stream->issue_from + stream->buffered < estimate->issue_at &&
			    estimate->max_segs > 0)
				return;
		}
	}
}

/*
 * End the issuing of writes, let the collector know we're done.
 */
static void netfs_writeback_end(struct netfs_io_request *wreq,
				struct netfs_wb_params *params)
{
	bool needs_poke = true;

	params->notes |= NOTE_FLUSH_ANYWAY;

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (stream->buffering) {
			netfs_writeback_flush(wreq, stream, params);
			stream->buffering = false;
		}
	}

	netfs_all_subreqs_queued(wreq);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (!stream->active)
			continue;
		if (!list_empty(&stream->subrequests))
			needs_poke = false;
	}

	if (needs_poke)
		netfs_wake_collector(wreq);
}

/*
 * Add a single, physically contiguous segment of data to a writeback stream
 * and dispatch subrequests when we hit a discontiguity or have accumulated
 * sufficient data to hit the estimated dispatch point.
 */
static void netfs_writeback_add_seg_to_stream(struct netfs_io_request *wreq,
					      struct netfs_io_stream *stream,
					      struct netfs_wb_params *params,
					      uoff_t start, size_t len,
					      unsigned int post_gap)
{
	struct netfs_write_estimate *estimate = &params->estimates[stream->stream_nr];

	_enter("%llx,%zx", start, len);

	params->notes &= ~NOTE_FLUSH_ANYWAY;

	/* Flush if not contiguous with the previous slice. */
	if (stream->buffering && start != stream->last_end) {
		params->notes |= NOTE_FLUSH_ANYWAY;
		netfs_writeback_flush(wreq, stream, params);
		params->notes &= ~NOTE_FLUSH_ANYWAY;
	}

	/* Begin the assembly of a slice and get an estimate of how much we can
	 * accumulate before we have to flush.
	 */
	if (!stream->buffering) {
		stream->issue_from = start;
		bvecq_pos_set(&stream->dispatch_cursor, &wreq->load_cursor);
		stream->buffering = true;
		stream->buffered = 0;
		estimate->issue_at = ULLONG_MAX;
		estimate->max_segs = INT_MAX;
		stream->estimate_write(wreq, stream, estimate);
	}

	stream->buffered += len;
	stream->last_end = start + len;
	stream->post_gap = post_gap;
	estimate->max_segs--;

	_debug("[%u] %llx + %zx >= %llx, %u %x",
	       stream->stream_nr, stream->issue_from, stream->buffered,
	       estimate->issue_at, estimate->max_segs, params->notes);

	if (stream->issue_from + stream->buffered >= estimate->issue_at ||
	    estimate->max_segs <= 0)
		netfs_writeback_flush(wreq, stream, params);
}

/*
 * Add a folio directly to the writeback streams and dispatch subrequests as
 * needed.
 */
static void netfs_writeback_add_folio_to_stream(struct netfs_io_request *wreq,
						struct netfs_wb_params *params,
						struct folio *folio)
{
	size_t fsize = folio_size(folio);
	uoff_t fpos = params->fpos;

	/* Attach the folio to the rolling buffer. */
	bvecq_append_page(&wreq->load_cursor, &folio->page, 0, fsize, wreq->gfp, true);
	wreq->load_cursor.slot--;

	trace_netfs_bv_slot(wreq->load_cursor.bvecq, wreq->load_cursor.slot - 1);
	trace_netfs_wback(wreq, folio, params->notes);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];
		size_t off, end;

		if (!stream->active || !(params->notes & stream->applicable))
			continue;

		/* Select the appropriately sized chunk. */
		if (stream->source == NETFS_WRITE_TO_CACHE) {
			off = params->outer_off;
			end = params->outer_end;
		} else {
			off = params->inner_off;
			end = params->inner_end;
		}

		wreq->load_cursor.offset = off;
		netfs_writeback_add_seg_to_stream(wreq, stream, params, fpos + off, end - off,
						  fsize - end);
	}


	/* Advance the load cursor after copying to the dispatch cursor. */
	wreq->load_cursor.slot++;
	wreq->load_cursor.offset = 0;
}

/*
 * Process bounce buffering, including content encryption.
 */
static void netfs_writeback_fill_bounce(struct netfs_io_request *wreq,
					struct netfs_wb_params *params,
					struct folio *folio, size_t foff,
					struct page *page, size_t poff,
					size_t len)
{
	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags)) {
		netfs_encrypt_folio(wreq, folio, foff, page, poff, len);
	} else {
		struct iov_iter iov;
		struct bio_vec bv;
		size_t res;

		bvec_set_folio(&bv, folio, len, foff);
		iov_iter_bvec(&iov, ITER_SOURCE, &bv, 1, len);
		res = copy_page_from_iter(page, poff, len, &iov);
		WARN_ON_ONCE(res != len);
	}
}

/*
 * Add bounce bufferage to a stream.
 */
static void netfs_writeback_bounce_folio(struct netfs_io_request *wreq,
					 struct netfs_wb_params *params,
					 struct folio *folio)
{
	size_t foff = params->outer_off, fsize = folio_size(folio);

	while (foff < params->outer_end) {
		struct page *page;
		size_t poff, part;

		/* Allocate a bounce page if we don't have one.
		 * TODO: Consider allocating higher-order pages if crypto
		 * offload gets used.
		 */
		if (!params->bounce_page) {
			params->bounce_page = mempool_alloc(&netfs_page_pool,
							    wreq->gfp | __GFP_COMP);
			params->bounce_usage = 0;
			params->bounce_size = PAGE_SIZE;

			/* For the moment crypto_bsize _must_ be no larger than
			 * PAGE_SIZE.  If it is, we need to be able to allocate
			 * higher-order pages from the emergency pool, but
			 * that's for future consideration.
			 */
			BUG_ON(params->bounce_size < wreq->crypto_bsize);
		}

		page = params->bounce_page;
		poff = params->bounce_usage;
		part = min(params->bounce_size - poff, params->outer_end - foff);
		WARN_ON_ONCE((part & (wreq->crypto_bsize - 1)) != 0);

		bvecq_append_page(&wreq->load_cursor, params->bounce_page,
				  params->bounce_usage, part, GFP_NOFS, true);
		wreq->load_cursor.slot--;

		trace_netfs_bounce(wreq, params->fpos + foff,
				   &wreq->load_cursor.bvecq->bv[wreq->load_cursor.slot - 1],
				   netfs_folio_trace_encrypt);

		params->bounce_usage += part;
		if (params->bounce_usage >= params->bounce_size) {
			params->bounce_page = NULL;
			params->bounce_size = 0;
		} else {
			get_page(params->bounce_page);
		}

		netfs_writeback_fill_bounce(wreq, params, folio, foff, page, poff, part);

		for (int s = 0; s < NR_IO_STREAMS; s++) {
			struct netfs_io_stream *stream = &wreq->io_streams[s];
			size_t off, end, pend = foff + part, post_gap = 0;

			/* Select the appropriately sized chunk. */
			if (stream->source == NETFS_WRITE_TO_CACHE) {
				off = foff;
				end = pend;
			} else {
				off = params->inner_off;
				end = params->inner_end;
				if (pend <= foff || off >= pend)
					continue;
				if (off < foff)
					off = foff;
				if (pend > end)
					pend = end;
				if (off >= pend)
					continue;
			}

			if (pend >= end && end < fsize)
				post_gap = fsize - end;

			/* Pass the bounce pages along as soon as available
			 * without waiting for the full folio lest the folio is
			 * so large that the emergency pools can't supply us
			 * with sufficient bounce pages.
			 */
			netfs_writeback_add_seg_to_stream(wreq, stream, params,
							  params->fpos + off, pend - off,
							  post_gap);

		}

		foff += part;

		/* Advance the load cursor after copying to the dispatch cursor. */
		wreq->load_cursor.slot++;
		wreq->load_cursor.offset = 0;
	}
}

/*
 * Queue a folio for writeback.
 */
static void netfs_writeback_folio(struct netfs_io_request *wreq,
				  struct writeback_control *wbc,
				  struct folio *folio,
				  struct netfs_wb_params *params)
{
	struct netfs_writeback *wback;
	struct netfs_group *fgroup; /* TODO: Use this with ceph */
	struct netfs_folio *finfo;
	size_t fsize = folio_size(folio), fend = fsize, foff = 0;
	uoff_t fpos = folio_pos(folio), i_size;

	_enter("%x", params->notes);

	/* netfs_perform_write() may shift i_size around the folio or from out
	 * of the folio to beyond it, but cannot move i_size into or through
	 * the folio since we have it locked.
	 *
	 * Truncate could in theory move i_size into or before the folio, but
	 * it should take steps to prevent writeback from happening
	 * concurrently and should wait for any in-progress writebacks before
	 * proceeding.
	 */
	i_size = i_size_read(wreq->inode);

	params->fpos = fpos;
	if (fpos >= i_size) {
		/* mmap beyond eof. */
		_debug("beyond eof");
		folio_start_writeback(folio);
		folio_unlock(folio);
		netfs_folio_written_back(wreq, folio);
		netfs_put_group_many(wreq->group, wreq->nr_group_rel);
		wreq->nr_group_rel = 0;
		return;
	}

	if (fpos + fsize > wreq->i_size)
		wreq->i_size = i_size;

	fgroup = netfs_folio_group(folio);
	finfo = netfs_folio_info(folio);
	if (finfo) {
		foff = finfo->dirty_offset;
		fend = foff + finfo->dirty_len;
		params->notes |= NOTE_STREAMW;
	}

	if (fend > i_size - fpos) {
		fend = i_size - fpos;
		if (!(params->notes & NOTE_STREAMW))
			folio_zero_segment(folio, fend, fsize);
	}

	/* Account for cache and crypto alignments. */
	params->inner_off = round_down(foff, params->inner_align);
	params->inner_end = round_up  (fend, params->inner_align);
	params->outer_off = round_down(foff, params->outer_align);
	params->outer_end = round_up  (fend, params->outer_align);

	_debug("folio %zx %zx %zx", foff, fend - foff, fsize);

	/* Deal with discontinuities in the stream of dirty pages.  These can
	 * arise from a number of sources:
	 *
	 * (1) Intervening non-dirty pages from random-access writes, multiple
	 *     flushers writing back different parts simultaneously and manual
	 *     syncing.
	 *
	 * (2) Partially-written pages from write-streaming.
	 *
	 * (3) Pages that belong to a different write-back group (eg.  Ceph
	 *     snapshots).
	 *
	 * (4) Actually-clean pages that were marked for write to the cache
	 *     when they were read.  Note that these appear as a special
	 *     write-back group.
	 */
	if (fgroup == NETFS_FOLIO_COPY_TO_CACHE) {
		if (!(params->notes & NOTE_CACHE_AVAIL)) {
			trace_netfs_folio(folio, netfs_folio_trace_cancel_copy);
			goto cancel_folio;
		}
		params->notes |= NOTE_CACHE_COPY;
		trace_netfs_folio(folio, netfs_folio_trace_store_copy);
	} else if (fgroup != wreq->group) {
		/* We can't write this page to the server yet. */
		kdebug("wrong group %p != %p", fgroup, wreq->group);
		goto skip_folio;
	} else if (!(params->notes & (NOTE_UPLOAD_AVAIL | NOTE_CACHE_AVAIL))) {
		trace_netfs_folio(folio, netfs_folio_trace_cancel_store);
		goto cancel_folio_discard;
	} else {
		if (params->notes & NOTE_UPLOAD_STARTED) {
			params->notes |= NOTE_UPLOAD;
			trace_netfs_folio(folio, netfs_folio_trace_store_plus);
		} else {
			params->notes |= NOTE_UPLOAD | NOTE_UPLOAD_STARTED;
			trace_netfs_folio(folio, netfs_folio_trace_store);
		}
		if ((params->notes & NOTE_CACHE_AVAIL) &&
		    !(params->notes & NOTE_STREAMW))
			params->notes |= NOTE_CACHE_COPY;
	}

	folio_start_writeback(folio);
	folio_unlock(folio);

	/* Keep track of what we will need to unlock. */
	wback = wreq->writebacks_tail;
	if (!wback || fpos != wback->start + wback->len || wback->len > LONG_MAX) {
		wback = mempool_alloc(&netfs_writeback_pool, wreq->gfp);
		wback->next = NULL;
		wback->start = fpos;
		wback->len = fsize;

		if (wreq->writebacks)
			/* Order write of next after last write of len in old tail. */
			smp_store_release(&wreq->writebacks_tail->next, wback);
		else
			wreq->writebacks = wback;
		wreq->writebacks_tail = wback;
	} else {
		/* Order update of len after setting pointer. */
		smp_store_release(&wback->len, wback->len + fsize);
	}

	/* Flush any streams not being used for this folio. */
	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (!stream->active || !(params->notes & stream->applicable)) {
			if (stream->buffering) {
				params->notes |= NOTE_FLUSH_ANYWAY;
				netfs_writeback_flush(wreq, stream, params);
			}
			atomic64_set_release(&stream->issued_to, fpos + params->outer_end);
		}
	}

	/* Initiate or extend the dispatch of each selected stream.  At this
	 * point we may need to copy the data to a bounce buffer and push the
	 * bounce bits instead.
	 */
	if (unlikely(test_bit(NETFS_RREQ_USE_BOUNCE_BUFFER, &wreq->flags)))
		netfs_writeback_bounce_folio(wreq, params, folio);
	else
		netfs_writeback_add_folio_to_stream(wreq, params, folio);

out:
	_leave(" = %x", params->notes);
	return;

skip_folio:
	folio_redirty_for_writepage(wbc, folio);
	folio_unlock(folio);
	goto out;
cancel_folio_discard:
	netfs_put_group(fgroup);
cancel_folio:
	folio_detach_private(folio);
	kfree(finfo);
	folio_unlock(folio);
	folio_cancel_dirty(folio);
	goto out;
}

/**
 * netfs_writepages_group - Flush data from the pagecache for a file
 * @mapping: The file to flush from
 * @wbc: Details of what should be flushed
 * @group: The write grouping to flush (or NULL)
 * @netfs_priv2: Private data specific to the netfs (or NULL)
 *
 * Start asynchronous write back operations to flush dirty data belonging to a
 * particular group in a file's pagecache back to the server and to the local
 * cache.
 *
 * If not NULL, @netfs_priv2 will be set on wreq->netfs_priv2
 */
int netfs_writepages_group(struct address_space *mapping,
			   struct writeback_control *wbc,
			   struct netfs_group *group,
			   void *netfs_priv2)
{
	struct netfs_inode *ictx = netfs_inode(mapping->host);
	struct netfs_io_request *wreq = NULL;
	struct netfs_wb_params params = {};
	struct folio *folio;
	int error = 0;

	if (!netfs_wb_begin(ictx, wbc->sync_mode == WB_SYNC_NONE))
		return 0;

	/* Need the first folio to be able to set up the op. */
	folio = writeback_iter(mapping, wbc, NULL, &error);
	if (!folio)
		goto out;

	wreq = netfs_create_write_req(mapping, NULL, folio_pos(folio),
				      netfs_priv2, NETFS_WRITEBACK);
	if (IS_ERR(wreq)) {
		error = PTR_ERR(wreq);
		goto couldnt_start;
	}

	bvecq_buffer_init(&wreq->load_cursor, GFP_NOFS, true);

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &wreq->flags);
	wreq->group = netfs_get_group(group);

	trace_netfs_write(wreq, netfs_write_trace_writeback);
	netfs_stat(&netfs_n_wh_writepages);

	params.inner_align = 1;
	params.outer_align = 1;

	if (wreq->io_streams[1].avail) {
		params.notes |= NOTE_CACHE_AVAIL;
		params.outer_align = wreq->cache_resources.dio_size;
	}
	if (unlikely(test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags))) {
		params.inner_align = wreq->crypto_bsize;
		params.outer_align = max(params.outer_align, wreq->crypto_bsize);
	}

	do {
		_debug("wbiter %lx", folio->index);

		if (netfs_folio_group(folio) != NETFS_FOLIO_COPY_TO_CACHE &&
		    unlikely(!test_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags))) {
			set_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags);
			wreq->netfs_ops->begin_writeback(wreq);
			if (wreq->io_streams[0].avail) {
				params.notes |= NOTE_UPLOAD_AVAIL;
				/* Order setting the active flag after other fields. */
				smp_store_release(&wreq->io_streams[0].active, true);
			}
		}

		params.notes &= NOTES__KEEP_MASK;
		netfs_writeback_folio(wreq, wbc, folio, &params);
	} while ((folio = writeback_iter(mapping, wbc, folio, &error)));

	netfs_writeback_end(wreq, &params);

	bvecq_pos_unset(&wreq->load_cursor);
	for (int i = 0; i < NR_IO_STREAMS; i++)
		bvecq_pos_unset(&wreq->io_streams[i].dispatch_cursor);
	netfs_wake_collector(wreq);

	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	_leave(" = %d", error);
	return error;

couldnt_start:
	if (error == -ENOMEM) {
		folio_redirty_for_writepage(wbc, folio);
		folio_unlock(folio);
		folio = writeback_iter(mapping, wbc, folio, &error);
		WARN_ON_ONCE(folio != NULL);
	} else {
		netfs_kill_dirty_pages(mapping, wbc, folio);
	}
out:
	netfs_wb_end(ictx);
	_leave(" = %d", error);
	return error;
}
EXPORT_SYMBOL(netfs_writepages_group);

/**
 * netfs_writepages - Flush data from the pagecache for a file
 * @mapping: The file to flush from
 * @wbc: Details of what should be flushed
 *
 * Start asynchronous write back operations to flush dirty data in a file's
 * pagecache back to the server and to the local cache.
 */
int netfs_writepages(struct address_space *mapping,
		     struct writeback_control *wbc)
{
	return netfs_writepages_group(mapping, wbc, NULL, NULL);
}
EXPORT_SYMBOL(netfs_writepages);

/*
 * Prepare a buffer for a single monolithic write.
 */
static int netfs_prepare_write_single_buffer(struct netfs_io_subrequest *subreq,
					     unsigned int max_segs)
{
	struct netfs_io_request *wreq = subreq->rreq;
	struct netfs_io_stream *stream = &wreq->io_streams[subreq->stream_nr];

	bvecq_pos_set(&subreq->dispatch_pos, &stream->dispatch_cursor);
	bvecq_pos_set(&subreq->content, &subreq->dispatch_pos);

	stream->buffered   = 0;
	stream->issue_from = subreq->len;
	wreq->submitted    = subreq->len;
	netfs_all_subreqs_queued(wreq);
	return 0;
}

/**
 * netfs_writeback_single - Write back a monolithic payload
 * @mapping: The mapping to write from
 * @wbc: Hints from the VM
 * @iter: Buffer to write from
 * @len: Amount to write from buffer
 *
 * Write a monolithic, non-pagecache object back to the server and/or the
 * cache.  There's a maximum of one subrequest per stream.  The buffer should
 * be rounded out sufficiently that it can accommodate cache DIO rounding.
 *
 * This is normally only used to write to the cache (for AFS directories and
 * symlinks); it doesn't normally write to the server as well.  The filesystem
 * can override that by setting NETFS_RREQ_UPLOAD_TO_SERVER when the request is
 * initialised.
 *
 * Return: 0 if successful; 1 if skipped due to lock conflict and WB_SYNC_NONE;
 * or a negative error code.
 * the cache.  There's a maximum of one subrequest per stream.
 */
int netfs_writeback_single(struct address_space *mapping,
			   struct writeback_control *wbc,
			   struct iov_iter *iter, size_t len)
{
	struct netfs_io_request *wreq;
	struct netfs_inode *ictx = netfs_inode(mapping->host);
	size_t clen;
	int ret;

	_enter("%zx,%zx", iov_iter_count(iter), len);

	if (!len)
		return 0;

	if (!netfs_wb_begin(ictx, wbc->sync_mode == WB_SYNC_NONE)) {
		/* The VFS will have undirtied the inode. */
		netfs_single_mark_inode_dirty(&ictx->inode);
		return 1;
	}

	wreq = netfs_create_write_req(mapping, NULL, 0, NULL, NETFS_WRITEBACK_SINGLE);
	if (IS_ERR(wreq)) {
		ret = PTR_ERR(wreq);
		goto couldnt_start;
	}

	wreq->len = len;
	clen = len;
	if (wreq->cache_resources.dio_size > 1) {
		clen = round_up(len, wreq->cache_resources.dio_size);
		if (clen > iov_iter_count(iter)) {
			ret = -EIO;
			goto cleanup_free;
		}
	}

	ret = netfs_extract_iter(iter, clen, INT_MAX, &wreq->load_cursor.bvecq,
				 0, wreq->gfp);
	if (ret < 0)
		goto cleanup_free;
	if (ret < clen) {
		ret = -EIO;
		goto cleanup_free;
	}

	__set_bit(NETFS_RREQ_OFFLOAD_COLLECTION, &wreq->flags);
	trace_netfs_write(wreq, netfs_write_trace_writeback_single);
	netfs_stat(&netfs_n_wh_writepages);

	/* This normally just writes to the cache; if the filesystem wants to
	 * write to the server too, it must set UPLOAD_TO_SERVER in
	 * ->init_request().
	 */
	if (test_bit(NETFS_RREQ_UPLOAD_TO_SERVER, &wreq->flags))
		wreq->netfs_ops->begin_writeback(wreq);

	for (int s = 0; s < NR_IO_STREAMS; s++) {
		struct netfs_io_subrequest *subreq;
		struct netfs_io_stream *stream = &wreq->io_streams[s];

		if (!stream->avail)
			continue;

		stream->issue_from = 0;
		stream->buffered   = len;
		if (stream->source == NETFS_WRITE_TO_CACHE)
			stream->buffered = clen;

		subreq = netfs_alloc_write_subreq(wreq, stream);
		if (!subreq) {
			ret = -ENOMEM;
			break;
		}

		bvecq_pos_set(&stream->dispatch_cursor, &wreq->load_cursor);

		ret = stream->issue_write(subreq);
		if (ret < 0) {
			/* Ownership of subreq was returned to us. */
			trace_netfs_sreq(subreq, netfs_sreq_trace_fail);
			stream->buffered -= subreq->len;
			netfs_write_subrequest_terminated(subreq, ret);
			/* Punt the error to the collector. */
		}

		bvecq_pos_unset(&stream->dispatch_cursor);
	}

	wreq->submitted = wreq->len;
	netfs_all_subreqs_queued(wreq);
	netfs_wake_collector(wreq);

	/* TODO: Might want to be async here if WB_SYNC_NONE, but then need to
	 * wait before modifying.
	 */
	ret = netfs_wait_for_write(wreq);
	if (ret > 0)
		ret = 0;

	netfs_put_request(wreq, netfs_rreq_trace_put_return);
	_leave(" = %d", ret);
	return ret;

cleanup_free:
	netfs_put_failed_request(wreq);
couldnt_start:
	netfs_wb_end(ictx);
	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(netfs_writeback_single);
