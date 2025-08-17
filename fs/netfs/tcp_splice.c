/* Splice from TCP to a bvecq
 *
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */
#include "internal.h"
#include <net/sock.h>
#include <net/rps.h>
#include <net/tcp.h>

static struct page *linear_to_page(struct page *page, unsigned int *len,
				   unsigned int *offset,
				   struct sock *sk)
{
	struct page_frag *pfrag = sk_page_frag(sk);

	if (!sk_page_frag_refill(sk, pfrag))
		return NULL;

	*len = min_t(unsigned int, *len, pfrag->size - pfrag->offset);

	memcpy(page_address(pfrag->page) + pfrag->offset,
	       page_address(page) + *offset, *len);
	*offset = pfrag->offset;
	pfrag->offset += *len;

	return pfrag->page;
}

static bool bvecq_can_coalesce(const struct bvecq *bvecq,
			       struct page *page,
			       unsigned int offset)
{
	const struct bio_vec *bv = &bvecq->bv[bvecq->nr_slots - 1];

	return bvecq->nr_slots > 0 &&
		bv->bv_page == page &&
		bv->bv_offset + bv->bv_len == offset;
}

/*
 * Add {page,offset,length} into bvecq, if it has more capacity available.
 */
static bool bvecq_add_page(struct bvecq *bvecq, struct page *page,
			   unsigned int *len, unsigned int offset, bool linear,
			   struct sock *sk)
{
	if (unlikely(bvecq_is_full(bvecq)))
		return true;

	if (linear) {
		page = linear_to_page(page, len, &offset, sk);
		if (!page)
			return true;
	}
	if (bvecq_can_coalesce(bvecq, page, offset)) {
		unsigned int old_len = bvecq->bv[bvecq->nr_slots - 1].bv_len;

		WRITE_ONCE(bvecq->bv[bvecq->nr_slots - 1].bv_len, old_len + *len);
		return false;
	}

	get_page(page);
	bvec_set_page(&bvecq->bv[bvecq->nr_slots], page, *len, offset);
	bvecq->nr_slots++;
	return false;
}

static bool bvecq_splice_segment(struct bvecq *bvecq,
				 struct page *page, unsigned int poff,
				 unsigned int plen, unsigned int *off,
				 unsigned int *len, bool linear,
				 struct sock *sk)
{
	if (!*len)
		return true;

	/* skip this segment if already processed */
	if (*off >= plen) {
		*off -= plen;
		return false;
	}

	/* ignore any bits we already processed */
	poff += *off;
	plen -= *off;
	*off = 0;

	/* TODO: Splice in large pages as single bio_vecs. */
	do {
		unsigned int flen = umin(*len, plen);

		if (bvecq_add_page(bvecq, page, &flen, poff, linear, sk))
			return true;
		poff += flen;
		plen -= flen;
		*len -= flen;
	} while (*len && plen);

	return false;
}

/*
 * Map linear and fragment data from the skb to spd. It reports true if the
 * pipe is full or if we already spliced the requested length.
 */
static bool bvecq_splice_bits_recursive(struct bvecq *bvecq, struct sk_buff *skb,
					unsigned int *offset, unsigned int *len,
					struct sock *sk)
{
	struct sk_buff *iter;
	int seg;

	/* map the linear part :
	 * If skb->head_frag is set, this 'linear' part is backed by a
	 * fragment, and if the head is not shared with any clones then
	 * we can avoid a copy since we own the head portion of this page.
	 */
	if (bvecq_splice_segment(bvecq, virt_to_page(skb->data),
				 (unsigned long) skb->data & (PAGE_SIZE - 1),
				 skb_headlen(skb), offset, len,
				 skb_head_is_locked(skb), sk))
		return true;

	/*
	 * then map the fragments
	 */
	if (!skb_frags_readable(skb))
		return false;

	for (seg = 0; seg < skb_shinfo(skb)->nr_frags; seg++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[seg];

		if (WARN_ON_ONCE(!skb_frag_page(f)))
			return false;

		if (bvecq_splice_segment(bvecq, skb_frag_page(f),
					 skb_frag_off(f), skb_frag_size(f),
					 offset, len, false, sk))
			return true;
	}

	skb_walk_frags(skb, iter) {
		if (*offset >= iter->len) {
			*offset -= iter->len;
			continue;
		}
		/* We only fail if the output has no room left, so no point in
		 * going over the frag_list for the error case.
		 */
		if (bvecq_splice_bits_recursive(bvecq, iter, offset, len, sk))
			return true;
	}

	return false;
}

/*
 * Map data from the skb to a pipe. Should handle both the linear part,
 * the fragments, and the frag list.
 */
static int tcp_splice_data_to_bvecq(read_descriptor_t *rd_desc, struct sk_buff *skb,
				    unsigned int offset, size_t len)
{
	struct bvecq *bvecq = rd_desc->arg.data;
	unsigned int tlen = umin(rd_desc->count, len);
	unsigned int used;

	bvecq_splice_bits_recursive(bvecq, skb, &offset, &tlen, skb->sk);
	used = len - tlen;
	rd_desc->count -= used;
	return used;
}

/**
 * netfs_tcp_splice_to_bvecq - splice data from TCP socket to a bvec queue
 * @sock: The socket to splice from
 * @bvecq: The bvec queue to splice to
 * @len: The number of bytes to splice
 *
 * Read pages from the given socket and transfer them into a bvec queue.  Data
 * segments are attached starting at the next available segment in the bvecq
 * (from bvecq->nr_slots+1 up to bvecq->max_slots) and may extend the last
 * segment used if contiguous with it.
 */
ssize_t netfs_tcp_splice_to_bvecq(struct socket *sock, struct bvecq *bvecq,
				  size_t len)
{
	read_descriptor_t rd_desc = {
		.arg.data = bvecq,
		.count	  = len,
	};
	struct sock *sk = sock->sk;
	ssize_t spliced = 0;
	long timeo;
	int ret = 0;

	sock_rps_record_flow(sk);
	if (unlikely(bvecq_is_full(bvecq)))
		return -ENOBUFS;

	lock_sock(sk);

	timeo = sock_rcvtimeo(sk, true /* non-blocking */);
	while (len) {
		ret = tcp_read_sock(sk, &rd_desc, tcp_splice_data_to_bvecq);
		if (ret < 0)
			break;
		if (!ret) {
			if (spliced)
				break;
			if (sock_flag(sk, SOCK_DONE))
				break;
			if (sk->sk_err) {
				ret = sock_error(sk);
				break;
			}
			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;
			if (sk->sk_state == TCP_CLOSE) {
				/*
				 * This occurs when user tries to read
				 * from never connected socket.
				 */
				ret = -ENOTCONN;
				break;
			}
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}
			/* if __tcp_splice_read() got nothing while we have
			 * an skb in receive queue, we do not want to loop.
			 * This might happen with URG data.
			 */
			if (!skb_queue_empty(&sk->sk_receive_queue))
				break;
			ret = sk_wait_data(sk, &timeo, NULL);
			if (ret < 0)
				break;
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}
			continue;
		}
		len -= ret;
		spliced += ret;

		if (!len || !timeo || bvecq_is_full(bvecq))
			break;
		release_sock(sk);
		lock_sock(sk);

		if (sk->sk_err || sk->sk_state == TCP_CLOSE ||
		    (sk->sk_shutdown & RCV_SHUTDOWN) ||
		    signal_pending(current))
			break;
	}

	release_sock(sk);
	return spliced ?: ret;
}
EXPORT_SYMBOL_GPL(netfs_tcp_splice_to_bvecq);
