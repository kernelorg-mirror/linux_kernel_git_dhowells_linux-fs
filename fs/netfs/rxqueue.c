// SPDX-License-Identifier: GPL-2.0-only
/* Receive buffer handling.  Move memory copy outside of the socket lock.
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/delay.h>
#include "internal.h"

/*
 * Get a ref on an Rx page.
 */
static void netfs_get_rx_page(struct bio_vec *bv)
{
	get_page(bv->bv_page);
}

/*
 * Drop a ref on an Rx page.
 */
static void netfs_put_rx_page(struct bio_vec *bv)
{
	put_page(bv->bv_page);
}

/*
 * netfs_alloc_rx_bvecq - Allocate a receive buffer.
 * nr_bv: Number of slots to allocate
 *
 * Allocate a receive buffer with the specified number of slots.  This function
 * will not fail, though it has no upper bound on the time taken to succeed.
 *
 * Return: The new buffer.
 */
struct bvecq *netfs_alloc_rx_bvecq(unsigned int nr_bv)
{
	struct bvecq *bq;

	for (;;) {
		bq = bvecq_alloc_one(nr_bv, GFP_NOFS, true);
		if (bq)
			return bq;
		msleep(50);
	}
}
EXPORT_SYMBOL(netfs_alloc_rx_bvecq);

/**
 * netfs_put_rx_bvecq - Put a receive buffer chain
 * @bq: The head buffer to put
 *
 * Put a ref on the first buffer segment in a bvecq chain and if that reaches
 * zero, destroy it, move on to the next buffer and repeat the put.
 */
void netfs_put_rx_bvecq(struct bvecq *bq)
{
	struct bvecq *next;

	for (; bq; bq = next) {
		if (!refcount_dec_and_test(&bq->ref))
			break;
		for (int seg = 0; seg < bq->nr_slots; seg++)
			if (bq->bv[seg].bv_page)
				netfs_put_rx_page(&bq->bv[seg]);
		next = bq->next;
		kfree(bq);
	}
}
EXPORT_SYMBOL(netfs_put_rx_bvecq);

/**
 * netfs_rxqueue_read_iter - Read data from a queue to an iterator
 * @rxq: The receive queue to read
 * @dest: The buffer to fill
 * @skip: The amount of data in the queue to skip over
 * @amount: The amount of data to read
 *
 * Copy data from the receive queue to an iterator.  The data doesn't have to
 * lie at the beginning of the buffer, but the initial unwanted data can be
 * skipped over.
 *
 * Note that this does not discard any data from the queue.
 *
 * Return: The amount of data copied.  0 is returned on failure or if @amount
 * is 0.
 */
size_t netfs_rxqueue_read_iter(const struct netfs_rxqueue *rxq,
			       struct iov_iter *dest, size_t skip, size_t amount)
{
	const struct bvecq *from = rxq->take_from;
	unsigned int slot = rxq->take_slot;
	size_t qsize = rxq->qsize, copied = 0;

	if (WARN(amount > iov_iter_count(dest),
		 "MSG=%x %zx > %zx",
		 rxq->msg_id, amount, iov_iter_count(dest)))
		amount = iov_iter_count(dest);

	if (skip > rxq->pdu_remain) {
		pr_warn("Rx over-skip %zx > %x\n", skip, rxq->pdu_remain);
		return 0;
	}
	if (amount > rxq->pdu_remain - skip) {
		pr_warn("Rx over-read %zx+%zx > %x\n",
			skip, amount, rxq->pdu_remain);
		amount = rxq->pdu_remain - skip;
		if (amount == 0)
			return 0;
	}
	if (amount > qsize)
		amount = qsize;

	skip += rxq->take_offset;

	while (copied < amount) {
		if (slot >= from->nr_slots) {
			slot = 0;
			from = from->next;
			if (!from)
				break;
		}

		const struct bio_vec *bv = &from->bv[slot];
		size_t blen = bv->bv_len;

		if (skip >= blen) {
			skip -= blen;
			slot++;
			continue;
		}

		size_t part = umin(blen - skip, amount - copied), got;

		trace_netfs_rxq_read(rxq, slot, skip, part, copied);

		got = copy_page_to_iter(bv->bv_page,
					bv->bv_offset + skip, part, dest);
		if (WARN_ON(got != part)) {
			bvecq_dump(rxq->take_from);
			return 0;
		}

		copied += part;
		skip = 0;
		slot++;
	}

	if (amount != copied)
		pr_warn("Failed to fully read %zx/%zx %x %pSR\n",
			copied, amount, rxq->qsize, __builtin_return_address(0));
	return copied;
}
EXPORT_SYMBOL(netfs_rxqueue_read_iter);

/**
 * netfs_rxqueue_read - Read data from a queue to a flat buffer
 * @rxq: The receive queue to read
 * @buffer: The buffer to fill
 * @skip: The amount of data in the queue to skip over
 * @amount: The amount of data to read
 *
 * Copy data from the receive queue to a flat buffer.  The data doesn't have to
 * lie at the beginning of the buffer, but the initial unwanted data can be
 * skipped over.
 *
 * Note that this does not discard any data from the queue.
 *
 * Return: The amount of data copied.  0 is returned on failure or if @amount
 * is 0.
 */
size_t netfs_rxqueue_read(const struct netfs_rxqueue *rxq,
			  void *buffer, size_t skip, size_t amount)
{
	struct iov_iter iter;
	struct kvec kv = { .iov_base = buffer, .iov_len = amount };

	iov_iter_kvec(&iter, ITER_DEST, &kv, 1, amount);
	return netfs_rxqueue_read_iter(rxq, &iter, skip, amount);
}
EXPORT_SYMBOL(netfs_rxqueue_read);

/**
 * netfs_rxqueue_discard - Discard data from a queue
 * @rxq: The receive queue to modify
 * @amount: The amount of data to discard
 *
 * Discard the specified amount of data from @rxq.  This may free pages and
 * bvecq segments.  In the event that the last bvecq is entirely cleared, it
 * will be refurbished and prepared for future refilling.
 */
void netfs_rxqueue_discard(struct netfs_rxqueue *rxq, size_t amount)
{
	struct bvecq *from = rxq->take_from, *dead;
	unsigned int offset = rxq->take_offset;
	unsigned int slot = rxq->take_slot;
	size_t qsize = rxq->qsize;

	if (amount > rxq->pdu_remain) {
		pr_warn("Rx over discard %zx > %x\n", amount, rxq->pdu_remain);
		amount = rxq->pdu_remain;
	}

	rxq->pdu_remain -= amount;

	for (;;) {
		if (slot >= from->nr_slots) {
			slot = 0;
			offset = 0;
			if (!from->next) {
				/* Refurbish the final bvecq.  add_to is NULL
				 * for a queue excerpt.
				 */
				if (!rxq->add_to) {
					netfs_put_rx_bvecq(from);
					from = NULL;
					break;
				}

				WARN_ON_ONCE(from != rxq->add_to);
				from->nr_slots = 0;
				rxq->add_to = from;
				break;
			}
			dead = from;
			from = dead->next;
			from->prev = NULL;
			dead->next = NULL;
			netfs_put_rx_bvecq(dead);
		}

		if (!amount)
			break;

		struct bio_vec *bv = &from->bv[slot];

		if (offset < bv->bv_len) {
			size_t part = umin(umin(bv->bv_len - offset, amount), qsize);
			offset += part;
			amount -= part;
			qsize -= part;
			if (offset < bv->bv_len)
				break;
		}

		if (!WARN_ON_ONCE(!bv->bv_page))
			netfs_put_rx_page(bv);
		bv->bv_page = NULL;
		bv->bv_offset = 0;
		bv->bv_len = 0;
		slot++;
		offset = 0;
	}

	if (amount > 0)
		pr_warn("Failed to fully discard %zx %zx %pSR\n",
			amount, qsize, __builtin_return_address(0));

	rxq->take_from = from;
	rxq->take_slot = slot;
	rxq->take_offset = offset;
	rxq->qsize = qsize;
}
EXPORT_SYMBOL(netfs_rxqueue_discard);

/**
 * netfs_rxqueue_count - Count the number of segs holding the specified data
 * @rxq: The receive queue to assess
 * @amount: The amount of data desired
 *
 * Count the number of segments in the receive queue that the requested amount
 * of data spans.
 *
 * Return: Segment count; 0 is returned if there is in sufficient data.
 */
unsigned int netfs_rxqueue_count(const struct netfs_rxqueue *rxq, size_t amount)
{
	const struct bvecq *from = rxq->take_from;
	unsigned int offset = rxq->take_offset;
	unsigned int count = 0;
	unsigned int slot = rxq->take_slot;

	while (amount > 0) {
		if (slot >= from->nr_slots) {
			if (WARN_ON_ONCE(!from->next))
				return 0;
			from = from->next;
			slot = 0;
			offset = 0;
		}

		const struct bio_vec *bv = &from->bv[slot];

		if (offset < bv->bv_len) {
			count++;
			if (bv->bv_len - offset >= amount)
				return count;
			amount -= bv->bv_len - offset;
		}

		slot++;
		offset = 0;
	}

	return count;
}
EXPORT_SYMBOL(netfs_rxqueue_count);

/*
 * Append (part of) a segment to a bvec queue and get/transfer a page count.
 * If we use up to the end of the source segment, we steal the page ref and
 * clear the segment.
 */
static void netfs_bvecq_append_seg(struct bvecq **pdestq, struct bio_vec *sv,
				   size_t offset, size_t len)
{
	struct bvecq *destq = *pdestq;
	struct bio_vec *dv;

	if (bvecq_is_full(destq)) {
		destq = destq->next;
		*pdestq = destq;
	}
	dv = &destq->bv[destq->nr_slots++];
	*dv = *sv;
	if (offset > 0) {
		dv->bv_offset += offset;
		dv->bv_len -= offset;
	}
	if (len < dv->bv_len) {
		dv->bv_len = len;
		netfs_get_rx_page(dv);
	} else {
		sv->bv_page = NULL;
		sv->bv_offset = 0;
		sv->bv_len = 0;
	}
}

/**
 * netfs_rxqueue_decant - Decant data segs to a private queue
 * @rxq: The receive queue to decant from
 * @amount: The amount of data received
 *
 * Decant data from the receive queue to a private queue.  This prevents the
 * receive queue keeping the buffers pinned.
 *
 * Return: A bvecq chain, with ref, holding the decanted data or NULL if out of
 * memory.
 */
struct bvecq *netfs_rxqueue_decant(struct netfs_rxqueue *rxq, size_t amount)
{
	struct bvecq *head_bq = NULL, *pbq, *destq;
	struct bvecq *from = rxq->take_from;
	unsigned int need_segs;
	unsigned int offset = rxq->take_offset;
	unsigned int slot = rxq->take_slot;
	size_t qsize = rxq->qsize;

	if (amount > rxq->pdu_remain) {
		pr_warn("Rx over decant %zx > %x\n",
			amount, rxq->pdu_remain);
		amount = rxq->pdu_remain;
	}

	/* Count the number of segments in the queue for this PDU and then
	 * allocate sufficient bvecq capacity to hold the whole PDU.
	 */
	need_segs = netfs_rxqueue_count(rxq, amount);
	while (need_segs > 0) {
		struct bvecq *b;
		unsigned int max_bv = (PAGE_SIZE - sizeof(*b)) / sizeof(b->bv[0]);
		unsigned int nr_bv = umin(need_segs, max_bv);

		need_segs -= nr_bv;
		b = netfs_alloc_rx_bvecq(nr_bv);
		if (!b)
			goto nomem;
		b->prev = pbq;
		if (head_bq)
			pbq->next = b;
		else
			head_bq = b;
		pbq = b;
	}

	rxq->pdu_remain -= amount;
	destq = head_bq;
	for (;;) {
		if (slot >= from->nr_slots) {
			struct bvecq *dead;

			slot = 0;
			offset = 0;
			if (!from->next) {
				/* Refurbish the final bvecq. */
				WARN_ON_ONCE(from != rxq->add_to);
				from->nr_slots = 0;
				rxq->add_to = from;
				break;
			}
			dead = from;
			from = dead->next;
			from->prev = NULL;
			dead->next = NULL;
			netfs_put_rx_bvecq(dead);
		}

		if (!amount)
			break;

		struct bio_vec *bv = &from->bv[slot];

		if (offset < bv->bv_len) {
			size_t part = umin(umin(bv->bv_len - offset, amount), qsize);
			netfs_bvecq_append_seg(&destq, bv, offset, part);
			offset += part;
			amount -= part;
			qsize -= part;
			if (offset < bv->bv_len)
				break;
		}

		if (WARN_ON_ONCE(bv->bv_page)) {
			netfs_put_rx_page(bv);
			bv->bv_page = NULL;
			bv->bv_offset = 0;
			bv->bv_len = 0;
		}
		slot++;
		offset = 0;
	}

	rxq->take_from = from;
	rxq->take_slot = slot;
	rxq->take_offset = offset;
	rxq->qsize = qsize;
	return head_bq;

nomem:
	netfs_put_rx_bvecq(head_bq);
	return NULL;
}
EXPORT_SYMBOL(netfs_rxqueue_decant);

/**
 * netfs_rxqueue_tcp_refill - Refill receive queue by TCP splice
 * @tcp_sock: The TCP socket to splice data from
 * @rxq: The Rx queue to splice into
 * @min_size: The amount of data we're interested in
 *
 * Refill the receive queue by splicing network receive buffer segments from a
 * TCP socket, but don't wait for data.  The caller must do any waiting
 * required.
 *
 * Note that whilst the peer may send PDUs in separate TCP packets, it's
 * possible that the local NIC may join them back together if doing receive
 * offload.
 */
int netfs_rxqueue_tcp_refill(struct socket *tcp_sock, struct netfs_rxqueue *rxq,
			     size_t min_size)
{
	struct bvecq *add_to = rxq->add_to;
	size_t qsize = rxq->qsize;
	int rc = 0;

	if (!rxq->refillable) {
		WARN_ON(min_size > qsize);
		return 0;
	}
	if (qsize >= min_size && min_size > 0)
		return 0;

	do {
		if (!add_to || bvecq_is_full(add_to)) {
			struct bvecq *b;
			unsigned int nr_bv = (2048 - sizeof(*add_to)) / sizeof(add_to->bv[0]);

			b = netfs_alloc_rx_bvecq(nr_bv);
			b->prev = add_to;
			if (!add_to)
				rxq->take_from = b;
			else
				add_to->next = b;
			add_to = b;
		}

		rc = netfs_tcp_splice_to_bvecq(tcp_sock, add_to, INT_MAX);
		//trace_smb3_tcp_splice(rc);
		if (rc < 0)
			break;

		qsize += rc;
		rc = 0;
	} while (qsize < min_size);

	rxq->add_to = add_to;
	rxq->qsize = qsize;
	return rc;
}
EXPORT_SYMBOL(netfs_rxqueue_tcp_refill);

/**
 * netfs_rxqueue_tcp_consume - Receive and discard data from a receive queue
 * @tcp_sock: The TCP socket that's the data source
 * @rxq: The Rx queue to discard from
 * @amount: The amount of data to discard
 *
 * Consume received data by receiving it if it's not already queued and then
 * discarding it.  This function does no waiting, so the caller must do the
 * waiting and repeatedly call it until the desired amount of data is consumed.
 */
int netfs_rxqueue_tcp_consume(struct socket *tcp_sock, struct netfs_rxqueue *rxq,
			      size_t amount)
{
	while (amount) {
		size_t part = umin(amount, rxq->qsize);
		int rc;

		amount -= part;
		netfs_rxqueue_discard(rxq, part);

		if (!amount)
			break;

		rc = netfs_rxqueue_tcp_refill(tcp_sock, rxq, 1);
		if (rc < 0)
			return rc;
	}
	return 0;
}
EXPORT_SYMBOL(netfs_rxqueue_tcp_consume);
