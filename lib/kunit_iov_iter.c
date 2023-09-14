// SPDX-License-Identifier: GPL-2.0-only
/* I/O iterator tests.  This can only test kernel-backed iterator types.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <kunit/test.h>

MODULE_DESCRIPTION("iov_iter testing");
MODULE_AUTHOR("David Howells <dhowells@redhat.com>");
MODULE_LICENSE("GPL");

struct iov_kunit_range {
	int	page, from, to;
};

/*
 * Ranges that to use in tests where we have address/offset ranges to play
 * with (ie. KVEC) or where we have a single blob that we can copy
 * arbitrary chunks of (ie. XARRAY).
 */
static const struct iov_kunit_range kvec_test_ranges[] = {
	{ 0, 0x00002, 0x00002 }, /* Start with an empty range */
	{ 0, 0x00027, 0x03000 }, /* Midpage to page end */
	{ 0, 0x05193, 0x18794 }, /* Midpage to midpage */
	{ 0, 0x20000, 0x20000 }, /* Empty range in the middle */
	{ 0, 0x20000, 0x24000 }, /* Page start to page end */
	{ 0, 0x24000, 0x27001 }, /* Page end to midpage */
	{ 0, 0x29000, 0xffffb }, /* Page start to midpage */
	{ 0, 0xffffd, 0xffffe }, /* Almost contig to last, ending in same page */
	{ -1 }
};

/*
 * Ranges that to use in tests where we have a list of partial pages to
 * play with (ie. BVEC).
 */
static const struct iov_kunit_range bvec_test_ranges[] = {
	{ 0, 0x0002, 0x0002 }, /* Start with an empty range */
	{ 1, 0x0027, 0x0893 }, /* Random part of page */
	{ 2, 0x0193, 0x0794 }, /* Random part of page */
	{ 3, 0x0000, 0x1000 }, /* Full page */
	{ 4, 0x0000, 0x1000 }, /* Full page logically contig to last */
	{ 5, 0x0000, 0x1000 }, /* Full page logically contig to last */
	{ 6, 0x0000, 0x0ffb }, /* Part page logically contig to last */
	{ 6, 0x0ffd, 0x0ffe }, /* Part of prev page, but not quite contig */
	{ -1 }
};

/*
 * The pattern to fill with.
 */
static inline u8 pattern(unsigned long x)
{
	return x & 0xff;
}

static void iov_kunit_unmap(void *data)
{
	vunmap(data);
}

/*
 * Create a buffer out of some pages and return a vmap'd pointer to it.
 */
static void *__init iov_kunit_create_buffer(struct kunit *test,
					    struct page ***ppages,
					    size_t npages)
{
	struct page **pages;
	unsigned long got;
	void *buffer;

	pages = kunit_kcalloc(test, npages, sizeof(struct page *), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, pages);
	*ppages = pages;

	got = alloc_pages_bulk_array(GFP_KERNEL, npages, pages);
	if (got != npages) {
		release_pages(pages, got);
		KUNIT_ASSERT_EQ(test, got, npages);
	}

	buffer = vmap(pages, npages, VM_MAP | VM_MAP_PUT_PAGES, PAGE_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, buffer);

	kunit_add_action_or_reset(test, iov_kunit_unmap, buffer);
	return buffer;
}

/*
 * Build the reference pattern in the scratch buffer that we expect to see in
 * the iterator buffer (ie. the result of copy *to*).
 */
static void iov_kunit_build_to_reference_pattern(struct kunit *test, u8 *scratch,
						 size_t bufsize,
						 const struct iov_kunit_range *pr)
{
	int i, patt = 0;

	memset(scratch, 0, bufsize);
	for (; pr->page >= 0; pr++) {
		u8 *p = scratch + pr->page * PAGE_SIZE;
		for (i = pr->from; i < pr->to; i++)
			p[i] = pattern(patt++);
	}
}

/*
 * Build the reference pattern in the iterator buffer that we expect to see in
 * the scratch buffer (ie. the result of copy *from*).
 */
static void iov_kunit_build_from_reference_pattern(struct kunit *test, u8 *buffer,
						   size_t bufsize,
						   const struct iov_kunit_range *pr)
{
	size_t i = 0, j;

	memset(buffer, 0, bufsize);
	for (; pr->page >= 0; pr++) {
		size_t patt = pr->page * PAGE_SIZE;

		for (j = pr->from; j < pr->to; j++) {
			buffer[i++] = pattern(patt + j);
			if (i >= bufsize)
				return;
		}
	}
}

/*
 * Compare two kernel buffers to see that they're the same.
 */
static void iov_kunit_check_pattern(struct kunit *test, const u8 *buffer,
				    const u8 *scratch, size_t bufsize)
{
	size_t i;

	for (i = 0; i < bufsize; i++) {
		KUNIT_EXPECT_EQ_MSG(test, buffer[i], scratch[i], "at i=%x", i);
		if (buffer[i] != scratch[i])
			return;
	}
}

static void __init iov_kunit_load_kvec(struct kunit *test,
				       struct iov_iter *iter, int dir,
				       struct kvec *kvec, unsigned int kvmax,
				       void *buffer, size_t bufsize,
				       const struct iov_kunit_range *pr)
{
	size_t size = 0;
	int i;

	for (i = 0; i < kvmax; i++, pr++) {
		if (pr->page < 0)
			break;
		KUNIT_ASSERT_GE(test, pr->to, pr->from);
		KUNIT_ASSERT_LE(test, pr->to, bufsize);
		kvec[i].iov_base = buffer + pr->from;
		kvec[i].iov_len = pr->to - pr->from;
		size += pr->to - pr->from;
	}
	KUNIT_ASSERT_LE(test, size, bufsize);

	iov_iter_kvec(iter, dir, kvec, i, size);
}

/*
 * Test copying to a ITER_KVEC-type iterator.
 */
static void __init iov_kunit_copy_to_kvec(struct kunit *test)
{
	struct iov_iter iter;
	struct page **spages, **bpages;
	struct kvec kvec[8];
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	for (i = 0; i < bufsize; i++)
		scratch[i] = pattern(i);

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	memset(buffer, 0, bufsize);

	iov_kunit_load_kvec(test, &iter, READ, kvec, ARRAY_SIZE(kvec),
			    buffer, bufsize, kvec_test_ranges);
	size = iter.count;

	copied = copy_to_iter(scratch, size, &iter);

	KUNIT_EXPECT_EQ(test, copied, size);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_EXPECT_EQ(test, iter.nr_segs, 0);

	iov_kunit_build_to_reference_pattern(test, scratch, bufsize, kvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

/*
 * Test copying from a ITER_KVEC-type iterator.
 */
static void __init iov_kunit_copy_from_kvec(struct kunit *test)
{
	struct iov_iter iter;
	struct page **spages, **bpages;
	struct kvec kvec[8];
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	for (i = 0; i < bufsize; i++)
		buffer[i] = pattern(i);

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	memset(scratch, 0, bufsize);

	iov_kunit_load_kvec(test, &iter, WRITE, kvec, ARRAY_SIZE(kvec),
			    buffer, bufsize, kvec_test_ranges);
	size = min(iter.count, bufsize);

	copied = copy_from_iter(scratch, size, &iter);

	KUNIT_EXPECT_EQ(test, copied, size);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_EXPECT_EQ(test, iter.nr_segs, 0);

	iov_kunit_build_from_reference_pattern(test, buffer, bufsize, kvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

static void __init iov_kunit_load_bvec(struct kunit *test,
				       struct iov_iter *iter, int dir,
				       struct bio_vec *bvec, unsigned int bvmax,
				       struct page **pages, size_t npages,
				       size_t bufsize,
				       const struct iov_kunit_range *pr)
{
	struct page *can_merge = NULL, *page;
	size_t size = 0;
	int i;

	for (i = 0; i < bvmax; i++, pr++) {
		if (pr->page < 0)
			break;
		KUNIT_ASSERT_LT(test, pr->page, npages);
		KUNIT_ASSERT_LT(test, pr->page * PAGE_SIZE, bufsize);
		KUNIT_ASSERT_GE(test, pr->from, 0);
		KUNIT_ASSERT_GE(test, pr->to, pr->from);
		KUNIT_ASSERT_LE(test, pr->to, PAGE_SIZE);

		page = pages[pr->page];
		if (pr->from == 0 && pr->from != pr->to && page == can_merge) {
			i--;
			bvec[i].bv_len += pr->to;
		} else {
			bvec_set_page(&bvec[i], page, pr->to - pr->from, pr->from);
		}

		size += pr->to - pr->from;
		if ((pr->to & ~PAGE_MASK) == 0)
			can_merge = page + pr->to / PAGE_SIZE;
		else
			can_merge = NULL;
	}

	iov_iter_bvec(iter, dir, bvec, i, size);
}

/*
 * Test copying to a ITER_BVEC-type iterator.
 */
static void __init iov_kunit_copy_to_bvec(struct kunit *test)
{
	struct iov_iter iter;
	struct bio_vec bvec[8];
	struct page **spages, **bpages;
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	for (i = 0; i < bufsize; i++)
		scratch[i] = pattern(i);

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	memset(buffer, 0, bufsize);

	iov_kunit_load_bvec(test, &iter, READ, bvec, ARRAY_SIZE(bvec),
			    bpages, npages, bufsize, bvec_test_ranges);
	size = iter.count;

	copied = copy_to_iter(scratch, size, &iter);

	KUNIT_EXPECT_EQ(test, copied, size);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_EXPECT_EQ(test, iter.nr_segs, 0);

	iov_kunit_build_to_reference_pattern(test, scratch, bufsize, bvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

/*
 * Test copying from a ITER_BVEC-type iterator.
 */
static void __init iov_kunit_copy_from_bvec(struct kunit *test)
{
	struct iov_iter iter;
	struct bio_vec bvec[8];
	struct page **spages, **bpages;
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	for (i = 0; i < bufsize; i++)
		buffer[i] = pattern(i);

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	memset(scratch, 0, bufsize);

	iov_kunit_load_bvec(test, &iter, WRITE, bvec, ARRAY_SIZE(bvec),
			    bpages, npages, bufsize, bvec_test_ranges);
	size = iter.count;

	copied = copy_from_iter(scratch, size, &iter);

	KUNIT_EXPECT_EQ(test, copied, size);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_EXPECT_EQ(test, iter.nr_segs, 0);

	iov_kunit_build_from_reference_pattern(test, buffer, bufsize, bvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

static void iov_kunit_destroy_xarray(void *data)
{
	struct xarray *xarray = data;

	xa_destroy(xarray);
	kfree(xarray);
}

static void __init iov_kunit_load_xarray(struct kunit *test,
					 struct iov_iter *iter, int dir,
					 struct xarray *xarray,
					 struct page **pages, size_t npages)
{
	size_t size = 0;
	int i;

	for (i = 0; i < npages; i++) {
		void *x = xa_store(xarray, i, pages[i], GFP_KERNEL);

		KUNIT_ASSERT_FALSE(test, xa_is_err(x));
		size += PAGE_SIZE;
	}
	iov_iter_xarray(iter, dir, xarray, 0, size);
}

static struct xarray *iov_kunit_create_xarray(struct kunit *test)
{
	struct xarray *xarray;

	xarray = kzalloc(sizeof(struct xarray), GFP_KERNEL);
	xa_init(xarray);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, xarray);
	kunit_add_action_or_reset(test, iov_kunit_destroy_xarray, xarray);
	return xarray;
}

/*
 * Test copying to a ITER_XARRAY-type iterator.
 */
static void __init iov_kunit_copy_to_xarray(struct kunit *test)
{
	const struct iov_kunit_range *pr;
	struct iov_iter iter;
	struct xarray *xarray;
	struct page **spages, **bpages;
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	xarray = iov_kunit_create_xarray(test);

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	for (i = 0; i < bufsize; i++)
		scratch[i] = pattern(i);

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	memset(buffer, 0, bufsize);

	iov_kunit_load_xarray(test, &iter, READ, xarray, bpages, npages);

	i = 0;
	for (pr = kvec_test_ranges; pr->page >= 0; pr++) {
		size = pr->to - pr->from;
		KUNIT_ASSERT_LE(test, pr->to, bufsize);

		iov_iter_xarray(&iter, READ, xarray, pr->from, size);
		copied = copy_to_iter(scratch + i, size, &iter);

		KUNIT_EXPECT_EQ(test, copied, size);
		KUNIT_EXPECT_EQ(test, iter.count, 0);
		KUNIT_EXPECT_EQ(test, iter.iov_offset, size);
		i += size;
	}

	iov_kunit_build_to_reference_pattern(test, scratch, bufsize, kvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

/*
 * Test copying from a ITER_XARRAY-type iterator.
 */
static void __init iov_kunit_copy_from_xarray(struct kunit *test)
{
	const struct iov_kunit_range *pr;
	struct iov_iter iter;
	struct xarray *xarray;
	struct page **spages, **bpages;
	u8 *scratch, *buffer;
	size_t bufsize, npages, size, copied;
	int i;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	xarray = iov_kunit_create_xarray(test);

	buffer = iov_kunit_create_buffer(test, &bpages, npages);
	for (i = 0; i < bufsize; i++)
		buffer[i] = pattern(i);

	scratch = iov_kunit_create_buffer(test, &spages, npages);
	memset(scratch, 0, bufsize);

	iov_kunit_load_xarray(test, &iter, READ, xarray, bpages, npages);

	i = 0;
	for (pr = kvec_test_ranges; pr->page >= 0; pr++) {
		size = pr->to - pr->from;
		KUNIT_ASSERT_LE(test, pr->to, bufsize);

		iov_iter_xarray(&iter, WRITE, xarray, pr->from, size);
		copied = copy_from_iter(scratch + i, size, &iter);

		KUNIT_EXPECT_EQ(test, copied, size);
		KUNIT_EXPECT_EQ(test, iter.count, 0);
		KUNIT_EXPECT_EQ(test, iter.iov_offset, size);
		i += size;
	}

	iov_kunit_build_from_reference_pattern(test, buffer, bufsize, kvec_test_ranges);
	iov_kunit_check_pattern(test, buffer, scratch, bufsize);
	KUNIT_SUCCEED();
}

/*
 * Test the extraction of ITER_KVEC-type iterators.
 */
static void __init iov_kunit_extract_pages_kvec(struct kunit *test)
{
	const struct iov_kunit_range *pr;
	struct iov_iter iter;
	struct page **bpages, *pagelist[8], **pages = pagelist;
	struct kvec kvec[8];
	u8 *buffer;
	ssize_t len;
	size_t bufsize, size = 0, npages;
	int i, from;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	buffer = iov_kunit_create_buffer(test, &bpages, npages);

	iov_kunit_load_kvec(test, &iter, READ, kvec, ARRAY_SIZE(kvec),
			    buffer, bufsize, kvec_test_ranges);
	size = iter.count;

	pr = kvec_test_ranges;
	from = pr->from;
	do {
		size_t offset0 = LONG_MAX;

		for (i = 0; i < ARRAY_SIZE(pagelist); i++)
			pagelist[i] = (void *)POISON_POINTER_DELTA + 0x5a;

		len = iov_iter_extract_pages(&iter, &pages, 100 * 1024,
					     ARRAY_SIZE(pagelist), 0, &offset0);
		KUNIT_EXPECT_GE(test, len, 0);
		if (len < 0)
			break;
		KUNIT_EXPECT_GE(test, (ssize_t)offset0, 0);
		KUNIT_EXPECT_LT(test, offset0, PAGE_SIZE);
		KUNIT_EXPECT_LE(test, len, size);
		KUNIT_EXPECT_EQ(test, iter.count, size - len);
		size -= len;

		if (len == 0)
			break;

		for (i = 0; i < ARRAY_SIZE(pagelist); i++) {
			struct page *p;
			ssize_t part = min_t(ssize_t, len, PAGE_SIZE - offset0);
			int ix;

			KUNIT_ASSERT_GE(test, part, 0);
			while (from == pr->to) {
				pr++;
				from = pr->from;
				if (pr->page < 0)
					goto stop;
			}
			ix = from / PAGE_SIZE;
			KUNIT_ASSERT_LT(test, ix, npages);
			p = bpages[ix];
			KUNIT_EXPECT_PTR_EQ(test, pagelist[i], p);
			KUNIT_EXPECT_EQ(test, offset0, from % PAGE_SIZE);
			from += part;
			len -= part;
			KUNIT_ASSERT_GE(test, len, 0);
			if (len == 0)
				break;
			offset0 = 0;
		}

		if (test->status == KUNIT_FAILURE)
			break;
	} while (iov_iter_count(&iter) > 0);

stop:
	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_SUCCEED();
}

/*
 * Test the extraction of ITER_BVEC-type iterators.
 */
static void __init iov_kunit_extract_pages_bvec(struct kunit *test)
{
	const struct iov_kunit_range *pr;
	struct iov_iter iter;
	struct page **bpages, *pagelist[8], **pages = pagelist;
	struct bio_vec bvec[8];
	ssize_t len;
	size_t bufsize, size = 0, npages;
	int i, from;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	iov_kunit_create_buffer(test, &bpages, npages);
	iov_kunit_load_bvec(test, &iter, READ, bvec, ARRAY_SIZE(bvec),
			    bpages, npages, bufsize, bvec_test_ranges);
	size = iter.count;

	pr = bvec_test_ranges;
	from = pr->from;
	do {
		size_t offset0 = LONG_MAX;

		for (i = 0; i < ARRAY_SIZE(pagelist); i++)
			pagelist[i] = (void *)POISON_POINTER_DELTA + 0x5a;

		len = iov_iter_extract_pages(&iter, &pages, 100 * 1024,
					     ARRAY_SIZE(pagelist), 0, &offset0);
		KUNIT_EXPECT_GE(test, len, 0);
		if (len < 0)
			break;
		KUNIT_EXPECT_GE(test, (ssize_t)offset0, 0);
		KUNIT_EXPECT_LT(test, offset0, PAGE_SIZE);
		KUNIT_EXPECT_LE(test, len, size);
		KUNIT_EXPECT_EQ(test, iter.count, size - len);
		size -= len;

		if (len == 0)
			break;

		for (i = 0; i < ARRAY_SIZE(pagelist); i++) {
			struct page *p;
			ssize_t part = min_t(ssize_t, len, PAGE_SIZE - offset0);
			int ix;

			KUNIT_ASSERT_GE(test, part, 0);
			while (from == pr->to) {
				pr++;
				from = pr->from;
				if (pr->page < 0)
					goto stop;
			}
			ix = pr->page + from / PAGE_SIZE;
			KUNIT_ASSERT_LT(test, ix, npages);
			p = bpages[ix];
			KUNIT_EXPECT_PTR_EQ(test, pagelist[i], p);
			KUNIT_EXPECT_EQ(test, offset0, from % PAGE_SIZE);
			from += part;
			len -= part;
			KUNIT_ASSERT_GE(test, len, 0);
			if (len == 0)
				break;
			offset0 = 0;
		}

		if (test->status == KUNIT_FAILURE)
			break;
	} while (iov_iter_count(&iter) > 0);

stop:
	KUNIT_EXPECT_EQ(test, size, 0);
	KUNIT_EXPECT_EQ(test, iter.count, 0);
	KUNIT_SUCCEED();
}

/*
 * Test the extraction of ITER_XARRAY-type iterators.
 */
static void __init iov_kunit_extract_pages_xarray(struct kunit *test)
{
	const struct iov_kunit_range *pr;
	struct iov_iter iter;
	struct xarray *xarray;
	struct page **bpages, *pagelist[8], **pages = pagelist;
	ssize_t len;
	size_t bufsize, size = 0, npages;
	int i, from;

	bufsize = 0x100000;
	npages = bufsize / PAGE_SIZE;

	xarray = iov_kunit_create_xarray(test);

	iov_kunit_create_buffer(test, &bpages, npages);
	iov_kunit_load_xarray(test, &iter, READ, xarray, bpages, npages);

	for (pr = kvec_test_ranges; pr->page >= 0; pr++) {
		from = pr->from;
		size = pr->to - from;
		KUNIT_ASSERT_LE(test, pr->to, bufsize);

		iov_iter_xarray(&iter, WRITE, xarray, from, size);

		do {
			size_t offset0 = LONG_MAX;

			for (i = 0; i < ARRAY_SIZE(pagelist); i++)
				pagelist[i] = (void *)POISON_POINTER_DELTA + 0x5a;

			len = iov_iter_extract_pages(&iter, &pages, 100 * 1024,
						     ARRAY_SIZE(pagelist), 0, &offset0);
			KUNIT_EXPECT_GE(test, len, 0);
			if (len < 0)
				break;
			KUNIT_EXPECT_LE(test, len, size);
			KUNIT_EXPECT_EQ(test, iter.count, size - len);
			if (len == 0)
				break;
			size -= len;
			KUNIT_EXPECT_GE(test, (ssize_t)offset0, 0);
			KUNIT_EXPECT_LT(test, offset0, PAGE_SIZE);

			for (i = 0; i < ARRAY_SIZE(pagelist); i++) {
				struct page *p;
				ssize_t part = min_t(ssize_t, len, PAGE_SIZE - offset0);
				int ix;

				KUNIT_ASSERT_GE(test, part, 0);
				ix = from / PAGE_SIZE;
				KUNIT_ASSERT_LT(test, ix, npages);
				p = bpages[ix];
				KUNIT_EXPECT_PTR_EQ(test, pagelist[i], p);
				KUNIT_EXPECT_EQ(test, offset0, from % PAGE_SIZE);
				from += part;
				len -= part;
				KUNIT_ASSERT_GE(test, len, 0);
				if (len == 0)
					break;
				offset0 = 0;
			}

			if (test->status == KUNIT_FAILURE)
				goto stop;
		} while (iov_iter_count(&iter) > 0);

		KUNIT_EXPECT_EQ(test, size, 0);
		KUNIT_EXPECT_EQ(test, iter.count, 0);
		KUNIT_EXPECT_EQ(test, iter.iov_offset, pr->to - pr->from);
	}

stop:
	KUNIT_SUCCEED();
}

static struct kunit_case __refdata iov_kunit_cases[] = {
	KUNIT_CASE(iov_kunit_copy_to_kvec),
	KUNIT_CASE(iov_kunit_copy_from_kvec),
	KUNIT_CASE(iov_kunit_copy_to_bvec),
	KUNIT_CASE(iov_kunit_copy_from_bvec),
	KUNIT_CASE(iov_kunit_copy_to_xarray),
	KUNIT_CASE(iov_kunit_copy_from_xarray),
	KUNIT_CASE(iov_kunit_extract_pages_kvec),
	KUNIT_CASE(iov_kunit_extract_pages_bvec),
	KUNIT_CASE(iov_kunit_extract_pages_xarray),
	{}
};

static struct kunit_suite iov_kunit_suite = {
	.name = "iov_iter",
	.test_cases = iov_kunit_cases,
};

kunit_test_suites(&iov_kunit_suite);
