/* SPDX-License-Identifier: GPL-2.0 */
/* Implementation of a segmented queue of bio_vec[].
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _LINUX_BVECQ_H
#define _LINUX_BVECQ_H

#include <linux/bvec.h>

/*
 * The type of memory retention used by the elements in bvecq->bv[] and how to
 * clean it up.
 */
enum bvecq_mem {
	BVECQ_MEM_EXTERNAL,	/* Externally retained memory - no freeing */
	BVECQ_MEM_PAGECACHE,	/* Ref'd pagecache pages - must put */
	BVECQ_MEM_GUP,		/* Pinned memory from get_user_pages() - unpin */
	BVECQ_MEM_ALLOCED,	/* Memory alloc'd by bvecq - can be freed/pooled */
} __mode(byte);

/*
 * Segmented bio_vec queue.
 *
 * These can be linked together to form messages of indefinite length and
 * iterated over with an ITER_BVECQ iterator.  The list is non-circular; next
 * and prev are NULL at the ends.
 *
 * The bv pointer points to the bio_vec array; this may be __bv if allocated
 * together.  The caller is responsible for determining whether or not this is
 * the case as the array pointed to by bv may be follow on directly from the
 * bvecq by accident of allocation (ie. ->bv == ->__bv is *not* sufficient to
 * determine this).
 *
 * The file position and discontiguity flag allow non-contiguous data sets to
 * be chained together, but still teased apart without the need to convert the
 * info in the bio_vec back into a folio pointer.
 */
struct bvecq {
	struct bvecq	*next;		/* Next bvec in the list or NULL */
	struct bvecq	*prev;		/* Prev bvec in the list or NULL */
	unsigned long long fpos;	/* File position */
	refcount_t	ref;
	u32		priv;		/* Private data */
	u16		nr_slots;	/* Number of elements in bv[] used */
	u16		max_slots;	/* Number of elements allocated in bv[] */
	enum bvecq_mem	mem_type:3;	/* What sort of memory and how to free it */
	bool		inline_bv:1;	/* T if __bv[] is being used */
	bool		discontig:1;	/* T if not contiguous with previous bvecq */
	struct bio_vec	*bv;		/* Pointer to array of page fragments */
	struct bio_vec	__bv[];		/* Default array (if ->inline_bv) */
};

#if BITS_PER_LONG == 64
/* Number of slots in __bv[] for a bvecq in a 512-byte kmalloc block. */
#define BVECQ_STD_SLOTS		29	/* 2 words/slot; 32 slots; bvecq is 6 words (3 slots) */
#elif  BITS_PER_LONG == 32
/* Number of slots in __bv[] for a bvecq in a 256-byte kmalloc block. */
#define BVECQ_STD_SLOTS		18	/* 3 words/slot; 21 slots; bvecq is 9 words (3 slots) */
#else
#error BVECQ_STD_SLOTS undetermined
#endif

/*
 * Position in a bio_vec queue.  The bvecq holds a ref on the queue segment it
 * points to.
 */
struct bvecq_pos {
	struct bvecq		*bvecq;		/* The first bvecq */
	unsigned int		offset;		/* The offset within the starting slot */
	u16			slot;		/* The starting slot */
};

void bvecq_dump(const struct bvecq *bq);
struct bvecq *bvecq_alloc_one(size_t nr_slots, gfp_t gfp);
struct bvecq *bvecq_alloc_chain(size_t nr_slots, gfp_t gfp);
struct bvecq *bvecq_alloc_buffer2(size_t size, unsigned int pre_slots, gfp_t gfp);
void bvecq_put(struct bvecq *bq);
int bvecq_expand_buffer(struct bvecq **_buffer, size_t *_cur_size, ssize_t size, gfp_t gfp);
int bvecq_shorten_buffer(struct bvecq *bq, unsigned int slot, size_t size);
int bvecq_buffer_init(struct bvecq_pos *pos, gfp_t gfp);
void bvecq_buffer_append(struct bvecq_pos *pos, struct bvecq *bq);
void bvecq_pos_advance(struct bvecq_pos *pos, size_t amount);
ssize_t bvecq_zero(struct bvecq_pos *pos, size_t amount);
size_t bvecq_slice(struct bvecq_pos *pos, size_t max_size,
		   unsigned int max_slots, unsigned int *_nr_slots);
ssize_t bvecq_extract(struct bvecq_pos *pos, size_t max_size,
		      unsigned int max_slots, struct bvecq **to);
ssize_t bvecq_load_from_ra(struct bvecq_pos *pos, struct readahead_control *ractl);

/**
 * bvecq_alloc_buffer - Allocate a bvecq chain and populate with buffers
 * @size: Target size of the buffer (can be 0 for an empty buffer)
 * @gfp: The allocation constraints.
 *
 * Wrapper around %bvecq_alloc_buffer2().
 */
static inline struct bvecq *bvecq_alloc_buffer(size_t size, gfp_t gfp)
{
	return bvecq_alloc_buffer2(size, 0, gfp);
}

/**
 * bvecq_get - Get a ref on a bvecq
 * @bq: The bvecq to get a ref on
 */
static inline struct bvecq *bvecq_get(struct bvecq *bq)
{
	refcount_inc(&bq->ref);
	return bq;
}

/**
 * bvecq_is_full - Determine if a bvecq is full
 * @bvecq: The object to query
 *
 * Return: true if full; false if not.
 */
static inline bool bvecq_is_full(const struct bvecq *bvecq)
{
	return bvecq->nr_slots >= bvecq->max_slots;
}

/**
 * bvecq_filled_to - Release filled slots with release barrier
 * @bvecq: The object modified
 * @to: The latest slot filled + 1
 */
static inline void bvecq_filled_to(struct bvecq *bvecq, unsigned int to)
{
	/* Set the slot counter after filling the slot */
	smp_store_release(&bvecq->nr_slots, to);
}

/**
 * bvecq_nr_slots_acquire - Get the number of filled slots with acquire barrier
 * @bvecq: The object to query
 *
 * Return: The number of filled slots
 */
static inline unsigned int bvecq_nr_slots_acquire(const struct bvecq *bvecq)
{
	/* Read the slot counter before looking at the slot */
	return smp_load_acquire(&bvecq->nr_slots);
}

/**
 * bvecq_acquire_slot - Determine if a slot is valid with acquire barrier
 * @bvecq: The object to query
 * @slot: The next slot
 *
 * Return: true if valid; false if might not be valid
 */
static inline bool bvecq_acquire_slot(const struct bvecq *bvecq, unsigned int slot)
{
	/* Read the slot counter before looking at the slot */
	return slot < bvecq_nr_slots_acquire(bvecq);
}

/**
 * bvecq_pos_set - Set one position to be the same as another
 * @pos: The position object to set
 * @at: The source position.
 *
 * Set @pos to have the same position as @at.  This may take a ref on the
 * bvecq pointed to.
 */
static inline void bvecq_pos_set(struct bvecq_pos *pos, const struct bvecq_pos *at)
{
	*pos = *at;
	bvecq_get(pos->bvecq);
}

/**
 * bvecq_pos_unset - Unset a position
 * @pos: The position object to unset
 *
 * Unset @pos.  This does any needed ref cleanup.
 */
static inline void bvecq_pos_unset(struct bvecq_pos *pos)
{
	bvecq_put(pos->bvecq);
	pos->bvecq = NULL;
	pos->slot = 0;
	pos->offset = 0;
}

/**
 * bvecq_pos_transfer - Transfer one position to another, clearing the first
 * @pos: The position object to set
 * @from: The source position to clear.
 *
 * Set @pos to have the same position as @from and then clear @from.  This may
 * transfer a ref on the bvecq pointed to.
 */
static inline void bvecq_pos_transfer(struct bvecq_pos *pos, struct bvecq_pos *from)
{
	*pos = *from;
	from->bvecq = NULL;
	from->slot = 0;
	from->offset = 0;
}

/**
 * bvecq_pos_move - Update a position to a new bvecq
 * @pos: The position object to update.
 * @to: The new bvecq to point at.
 *
 * Update @pos to point to @to if it doesn't already do so.  This may
 * manipulate refs on the bvecqs pointed to.
 */
static inline void bvecq_pos_move(struct bvecq_pos *pos, struct bvecq *to)
{
	struct bvecq *old = pos->bvecq;

	if (old != to) {
		pos->bvecq = bvecq_get(to);
		bvecq_put(old);
	}
}

/**
 * bvecq_pos_nudge - Nudge a position onto the next segment if current used up
 * @pos: The position object to nudge.
 *
 * Update @pos to point to the next segment in the chain if we've used up the
 * current segment.  This may manipulate refs on the bvecqs pointed to.
 *
 * Return: true if found a new segment, false if hit the end.
 */
static inline bool bvecq_pos_nudge(struct bvecq_pos *pos)
{
	struct bvecq *bq = pos->bvecq;

	for (;;) {
		if (!bvecq_acquire_slot(bq, pos->slot)) {
			bq = bq->next;
			if (!bq)
				return false;
			bvecq_pos_move(pos, bq);
			pos->slot = 0;
			pos->offset = 0;
			continue;
		}
		if (pos->offset >= bq->bv[pos->slot].bv_len) {
			pos->slot++;
			pos->offset = 0;
			continue;
		}
		return true;
	}
}

/**
 * bvecq_pos_step - Step a position to the next slot if possible
 * @pos: The position object to step.
 *
 * Update @pos to point to the next slot in the queue if not at the end.  This
 * may manipulate refs on the bvecqs pointed to.
 *
 * Return: true if successful, false if was at the end.
 */
static inline bool bvecq_pos_step(struct bvecq_pos *pos)
{
	struct bvecq *bq = pos->bvecq;

	pos->slot++;
	pos->offset = 0;
	if (pos->slot <= bq->nr_slots)
		return true;
	if (!bq->next)
		return false;
	bvecq_pos_move(pos, bq->next);
	return true;
}

/**
 * bvecq_delete_spent - Delete the bvecq at the front if possible
 * @pos: The position object to update.
 * @slot: Current slot.
 *
 * Delete the used up bvecq at the front of the queue that @pos points to if it
 * is not the last node in the queue; if it is the last node in the queue, it
 * is kept so that the queue doesn't become detached from the other end.  This
 * may manipulate refs on the bvecqs pointed to.  It is also possible that the
 * producer will fill more slots in the current bvecq.
 *
 * Also, we have to be very careful: the consumer can catch the producer, which
 * could lead to us having nothing left in the queue, causing the front and
 * back pointers to end up on different tracks.  To avoid this, we must always
 * keep at least one segment in the queue.
 *
 * The caller must reload from @pos after calling this.
 *
 * Return: true if there's more available; false if not.
 */
static inline bool bvecq_delete_spent(struct bvecq_pos *pos, unsigned int slot)
{
	struct bvecq *spent = pos->bvecq;
	struct bvecq *next;

again:
	/* Read the contents of the queue node after the pointer to it. */
	next = smp_load_acquire(&spent->next);
	if (!next)
		return false; /* Nothing more to consume at the moment. */
	if (slot < bvecq_nr_slots_acquire(spent))
		return true; /* The producer added more. */
	next->prev = NULL;
	spent->next = NULL;
	bvecq_put(spent);
	pos->bvecq = next; /* We take spent's ref. */
	pos->slot = 0;
	pos->offset = 0;
	if (!bvecq_acquire_slot(next, 0)) {
		spent = next;
		slot = 0;
		goto again;
	}
	return true;
}

#endif /* _LINUX_BVECQ_H */
