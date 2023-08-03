/* SPDX-License-Identifier: GPL-2.0 */
/* Data container
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef __FS_CEPH_DATABUF_H
#define __FS_CEPH_DATABUF_H

#include <asm/byteorder.h>
#include <linux/refcount.h>
#include <linux/blk_types.h>
#include <linux/bvecq.h>
#include <linux/iov_iter.h>

#define kmap_local_bvecq(bq, slot) \
	bvec_kmap_partial(&bq->bv[slot], 0)

struct ceph_encode {
	struct bvecq	*dbuf;		/* Head of buffer */
	struct bvecq	*bq;		/* Current tail of buffer */
	u8		*p;		/* Mapped pointer */
	gfp_t		gfp;		/* Allocation constraints */
	unsigned int	len;		/* Total amount of data in buffer */
	unsigned int	capacity;	/* Current buffer capacity */
	unsigned int	space;		/* Space remaining in current slot */
	unsigned short	slot;		/* Current slot */
	bool		nomem;		/* ENOMEM hit */
};

static inline int ceph_start_encode(struct ceph_encode *enc, size_t size, gfp_t gfp)
{
	struct bvecq *bq = bvecq_alloc_buffer(size, gfp, false);
	if (!bq) {
		enc->nomem = true;
		enc->dbuf = NULL;
		enc->p = NULL;
		return -ENOMEM;
	}

	enc->dbuf	= bq;
	enc->bq		= bq;
	enc->p		= kmap_local_bvecq(enc->bq, 0);
	enc->gfp	= gfp;
	enc->len	= 0;
	enc->capacity	= size;
	enc->space	= enc->bq->bv[0].bv_len;
	enc->slot	= 0;
	enc->nomem	= false;
	return 0;
}

static inline int ceph_encode_error(const struct ceph_encode *enc)
{
	return enc->nomem ? -ENOMEM : 0;
}

static inline int ceph_end_encode(struct ceph_encode *enc)
{
	if (enc->p)
		kunmap_local(enc->p);
	bvecq_put(enc->dbuf);
	enc->dbuf = NULL;
	return enc->nomem ? -ENOMEM : 0;
}

static inline struct bvecq *ceph_alloc_frag(size_t size, gfp_t gfp)
{
	struct bvecq *bq, *p;

	/* Use frag allocator? */
	bq = bvecq_alloc_buffer(size, gfp, false);
	if (!bq)
		return NULL;

	/* We want to use bv_len to indicate how much of each page we've
	 * occupied.  We know each slot contains PAGE_SIZE memory.
	 */
	for (p = bq; p; p = p->next)
		for (int i = 0; i < p->nr_slots; i++)
			p->bv[i].bv_len = 0;
	return bq;
}

void ceph_bvecq_append(struct ceph_encode *enc, const void *data, size_t len);
int ceph_bvecq_reserve(struct ceph_encode *enc, size_t space);
int ceph_bvecq_insert_frag(struct bvecq *bq, unsigned int slot, size_t len, gfp_t gfp);

static inline void bvecq_trim(struct bvecq *bq, size_t size)
{
	/* Rejig the bv_len members to limit the overall size */
}

static inline size_t bvecq_len(const struct bvecq *bq)
{
	size_t n = 0;

	for (int slot = 0; slot < bq->nr_slots; slot++)
		n += bq->bv[slot].bv_len;
	return n;
}

static inline unsigned int bvecq_nr_slots(const struct bvecq *bq)
{
	return bq->nr_slots;
}

static inline struct page *bvecq_page(struct bvecq *bq, unsigned int slot)
{
	return bq->bv[slot].bv_page;
}

static inline void *ceph_map_enc_start(struct bvecq *bq)
{
	return bvec_virt(&bq->bv[0]) + bq->bv[0].bv_offset + bq->bv[0].bv_len;
}

static inline size_t ceph_map_enc_stop(struct bvecq *bq, void *p)
{
	size_t len = p - (bvec_virt(&bq->bv[0]) + bq->bv[0].bv_offset);

	bq->bv[0].bv_len = len;
	BUG_ON(bq->bv[0].bv_len > PAGE_SIZE);
	bvecq_trim(bq, len);
	return len;
}

static inline void *ceph_map_dec_start(struct bvecq *bq)
{
	return bvec_virt(&bq->bv[0]);
}

static inline void ceph_map_dec_stop(struct bvecq *bq, void *p)
{
	size_t len = p - bvec_virt(&bq->bv[0]);

	BUG_ON(len > bq->bv[0].bv_len);
}

static inline void ceph_bq_encode(struct ceph_encode *enc, const void *s, u32 len)
{
	return ceph_bvecq_append(enc, s, len);
}

static inline void ceph_bq_encode_64(struct ceph_encode *enc, u64 val)
{
	__le64 ev = cpu_to_le64(val);

	return ceph_bvecq_append(enc, &ev, sizeof(ev));
}
static inline void ceph_bq_encode_32(struct ceph_encode *enc, u32 val)
{
	__le32 ev = cpu_to_le32(val);

	return ceph_bvecq_append(enc, &ev, sizeof(ev));
}
static inline void ceph_bq_encode_16(struct ceph_encode *enc, u16 val)
{
	__le16 ev = cpu_to_le16(val);

	return ceph_bvecq_append(enc, &ev, sizeof(ev));
}
static inline void ceph_bq_encode_8(struct ceph_encode *enc, u8 val)
{
	return ceph_bvecq_append(enc, &val, sizeof(val));
}
static inline void ceph_bq_encode_string(struct ceph_encode *enc,
					const char *s, u32 len)
{
	ceph_bq_encode_32(enc, len);
	ceph_bvecq_append(enc, s, len);
}

static inline void ceph_bvecq_add_page(struct bvecq *bq, struct page *page,
				       unsigned int offset, unsigned int len)
{
	BUG_ON(bq->nr_slots >= bq->max_slots);
	bvec_set_page(&bq->bv[bq->nr_slots++], page, len, offset);
}

static inline void ceph_enc_added_data(struct ceph_encode *enc, size_t amount)
{
	enc->len += amount;
}

/*
 * Transfer the contents of one databuf to another, clearing the first.
 */
static inline void bvecq_transfer(struct bvecq *to, struct bvecq *from)
{
	BUG_ON(to->max_slots);
	BUG_ON(from->inline_bv);
	to->bv		= from->bv;
	to->nr_slots	= from->nr_slots;
	to->max_slots	= from->max_slots;

	from->bv = from->__bv;
	from->nr_slots = from->max_slots = 0;
}

static __always_inline
size_t bvecq_scan_for_nonzero(void *iter_from, size_t progress,
			      size_t len, void *priv, void *priv2)
{
	void *p;

	p = memchr_inv(iter_from, 0, len);
	return p ? p - iter_from : 0;
}

/*
 * Scan a buffer to see if it contains only zeros.
 */
static inline bool bvecq_is_all_zero(struct bvecq *bq, size_t count)
{
	struct iov_iter iter;

	iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 0, 0, count);

	return iterate_bvecq(&iter, count, NULL, NULL,
			     bvecq_scan_for_nonzero) == count;
}

/*
 * Copy data from a bvec queue to a buffer.
 */
static inline ssize_t bvecq_copy_to_buf(struct bvecq *bq, size_t bq_size, size_t offset,
					void *buf, size_t count)
{
	struct iov_iter iter;

	iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 0, 0, bq_size);
	iov_iter_advance(&iter, offset);

	if (copy_from_iter(buf, count, &iter) != count)
		return -EIO;
	return count;
}

static inline void bvec_set_bv(struct bio_vec *bv, const struct bio_vec *sbv,
			       unsigned int offset, unsigned int len)
{
	bv->bv_page	= sbv->bv_page;
	bv->bv_offset	= sbv->bv_offset + offset;
	bv->bv_len	= len;
}

#endif /* __FS_DATABUF_H */
