// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, SUSE LLC
 *
 * Authors: Enzo Matsumiya <ematsumiya@suse.de>
 *
 * This file implements I/O compression support for SMB2 messages (SMB 3.1.1 only).
 * See compress/ for implementation details of each algorithm.
 *
 * References:
 * MS-SMB2 "3.1.4.4 Compressing the Message"
 * MS-SMB2 "3.1.5.3 Decompressing the Chained Message"
 * MS-XCA - for details of the supported algorithms
 */
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/uio.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>

#include "cifsglob.h"
#include "../common/smb2pdu.h"
#include "cifsproto.h"
#include "smb2proto.h"

#include "../common/compress/lz77.h"
#include "compress.h"

/*
 * The heuristic_*() functions below try to determine data compressibility.
 *
 * Derived from fs/btrfs/compression.c, changing coding style, some parameters, and removing
 * unused parts.
 *
 * Read that file for better and more detailed explanation of the calculations.
 *
 * The algorithms are ran in a collected sample of the input (uncompressed) data.
 * The sample is formed of 2K reads in PAGE_SIZE intervals, with a maximum size of 4M.
 *
 * Parsing the sample goes from "low-hanging fruits" (fastest algorithms, likely compressible)
 * to "need more analysis" (likely uncompressible).
 */

struct bucket {
	unsigned int count;
};

static inline size_t pow4(size_t n)
{
	return n * n * n * n;
}

/*
 * has_low_entropy() - Compute Shannon entropy of the sampled data.
 * @bkt:	Bytes counts of the sample.
 * @slen:	Size of the sample.
 *
 * Return: true if the level (percentage of number of bits that would be required to
 *	   compress the data) is below the minimum threshold.
 *
 * Note:
 * There _is_ an entropy level here that's > 65 (minimum threshold) that would indicate a
 * possibility of compression, but compressing, or even further analysing, it would waste so much
 * resources that it's simply not worth it.
 *
 * Also Shannon entropy is the last computed heuristic; if we got this far and ended up
 * with uncertainty, just stay on the safe side and call it uncompressible.
 */
static bool has_low_entropy(struct bucket *bkt, size_t slen)
{
	const size_t threshold = 65, max_entropy = 8 * ilog2(16);
	size_t i, p, p2, len, sum = 0;

	len = ilog2(pow4(slen));

	for (i = 0; i < 256 && bkt[i].count > 0; i++) {
		p = bkt[i].count;
		p2 = ilog2(pow4(p));
		sum += p * (len - p2);
	}

	sum /= slen;

	return ((sum * 100 / max_entropy) <= threshold);
}

#define BYTE_DIST_BAD		0
#define BYTE_DIST_GOOD		1
#define BYTE_DIST_MAYBE		2
/*
 * calc_byte_distribution() - Compute byte distribution on the sampled data.
 * @bkt:	Byte counts of the sample.
 * @slen:	Size of the sample.
 *
 * Return:
 * BYTE_DIST_BAD:	A "hard no" for compression -- a computed uniform distribution of
 *			the bytes (e.g. random or encrypted data).
 * BYTE_DIST_GOOD:	High probability (normal (Gaussian) distribution) of the data being
 *			compressible.
 * BYTE_DIST_MAYBE:	When computed byte distribution resulted in "low > n < high"
 *			grounds.  has_low_entropy() should be used for a final decision.
 */
static int calc_byte_distribution(struct bucket *bkt, size_t slen)
{
	const size_t low = 64, high = 200, threshold = slen * 90 / 100;
	size_t sum = 0;
	int i;

	for (i = 0; i < low; i++)
		sum += bkt[i].count;

	if (sum > threshold)
		return BYTE_DIST_BAD;

	for (; i < high && bkt[i].count > 0; i++) {
		sum += bkt[i].count;
		if (sum > threshold)
			break;
	}

	if (i <= low)
		return BYTE_DIST_GOOD;

	if (i >= high)
		return BYTE_DIST_BAD;

	return BYTE_DIST_MAYBE;
}

static bool is_mostly_ascii(const struct bucket *bkt)
{
	size_t count = 0;
	int i;

	for (i = 0; i < 256; i++)
		if (bkt[i].count > 0)
			/* Too many non-ASCII (0-63) bytes. */
			if (++count > 64)
				return false;

	return true;
}

static bool has_repeated_data(const u8 *sample, size_t len)
{
	size_t s = len / 2;

	return (!memcmp(&sample[0], &sample[s], s));
}

static int cmp_bkt(const void *_a, const void *_b)
{
	const struct bucket *a = _a, *b = _b;

	/* Reverse sort. */
	if (a->count > b->count)
		return -1;

	return 1;
}

/*
 * Collect some 2K samples with 2K gaps between.
 */
static int collect_sample(const struct iov_iter *source, ssize_t max, u8 *sample)
{
	struct iov_iter iter = *source;
	size_t s = 0;

	while (iov_iter_count(&iter) >= SZ_2K) {
		size_t part = umin(umin(iov_iter_count(&iter), SZ_2K), max);
		size_t n;

		n = copy_from_iter(sample + s, part, &iter);
		if (n != part)
			return -EFAULT;

		s += n;
		max -= n;

		if (iov_iter_count(&iter) < PAGE_SIZE - SZ_2K)
			break;

		iov_iter_advance(&iter, SZ_2K);
	}

	return s;
}

/*
 * is_compressible() - Determines if a chunk of data is compressible.
 * @data: Iterator containing uncompressed data.
 *
 * Return: true if @data is compressible, false otherwise.
 *
 * Tests shows that this function is quite reliable in predicting data compressibility,
 * matching close to 1:1 with the behaviour of LZ77 compression success and failures.
 */
bool is_compressible(const struct iov_iter *data)
{
	const size_t read_size = SZ_2K, bkt_size = 256, max = SZ_4M;
	struct bucket *bkt = NULL;
	size_t len;
	u8 *sample;
	bool ret = false;
	int i;

	/* Preventive double check -- already checked in should_compress(). */
	len = iov_iter_count(data);
	if (unlikely(len < read_size))
		return ret;

	if (len - read_size > max)
		len = max;

	sample = kvzalloc(len, GFP_KERNEL);
	if (!sample) {
		WARN_ON_ONCE(1);

		return ret;
	}

	/* Sample 2K bytes per page of the uncompressed data. */
	i = collect_sample(data, len, sample);
	if (i <= 0) {
		WARN_ON_ONCE(1);

		goto out;
	}

	len = i;
	ret = true;

	if (has_repeated_data(sample, len))
		goto out;

	bkt = kzalloc_objs(*bkt, bkt_size);
	if (!bkt) {
		WARN_ON_ONCE(1);
		ret = false;

		goto out;
	}

	for (i = 0; i < len; i++)
		bkt[sample[i]].count++;

	if (is_mostly_ascii(bkt))
		goto out;

	/* Sort in descending order */
	sort(bkt, bkt_size, sizeof(*bkt), cmp_bkt, NULL);

	i = calc_byte_distribution(bkt, len);
	if (i != BYTE_DIST_MAYBE) {
		ret = !!i;

		goto out;
	}

	ret = has_low_entropy(bkt, len);
out:
	kvfree(sample);
	kfree(bkt);

	return ret;
}

/*
 * should_compress() - Determines if a request (write) or the response to a
 *		       request (read) should be compressed.
 * @tcon: tcon of the request is being sent to
 * @rqst: request to evaluate
 *
 * Return: true iff:
 * - compression was successfully negotiated with server
 * - server has enabled compression for the share
 * - it's a read or write request
 * - (write only) request length is >= SMB_COMPRESS_MIN_LEN
 * - (write only) is_compressible() returns 1
 *
 * Return false otherwise.
 */
bool should_compress(const struct cifs_tcon *tcon, const struct smb_rqst *rq)
{
	const struct smb2_hdr *shdr = rq->rq_iov->iov_base;

	if (unlikely(!tcon || !tcon->ses || !tcon->ses->server))
		return false;

	if (!tcon->ses->server->compression.enabled)
		return false;

	if (!(tcon->share_flags & SMB2_SHAREFLAG_COMPRESS_DATA))
		return false;

	if (shdr->Command == SMB2_WRITE) {
		const struct smb2_write_req *wreq = rq->rq_iov->iov_base;

		if (le32_to_cpu(wreq->Length) < SMB_COMPRESS_MIN_LEN)
			return false;

		return true;
	}

	return (shdr->Command == SMB2_READ);
}

/*
 * vmap the pages from a BVECQ-type iterator.
 */
static void *vmap_bvecq(struct iov_iter *iter, pgprot_t prot)
{
	struct page **pages = NULL;
	ssize_t size, offset;
	void *map;

	if (WARN_ON(!iov_iter_is_bvecq(iter)))
		return ERR_PTR(-EIO);

	size = iov_iter_extract_pages(iter, &pages, INT_MAX, INT_MAX, 0, &offset);
	if (size < 0)
		return ERR_PTR(size);

	if (size == 0 || offset > 0) {
		kvfree(pages);
		return ERR_PTR(-EIO);
	}

	map = vmap(pages, DIV_ROUND_UP(size, PAGE_SIZE), 0, prot);
	kvfree(pages);
	if (!map)
		return ERR_PTR(-ENOMEM);
	return map;
}

int smb_compress(struct TCP_Server_Info *server, struct iov_iter *iter,
		 struct bvecq **bq, unsigned int flags)
{
	struct smb2_compression_hdr *z_hdr;
	struct smb2_write_req *w_hdr;
	struct smb2_hdr *shdr;
	struct iov_iter tmp;
	struct bvecq *sbq = *bq, *dbq = NULL;
	void *src, *dst = NULL;
	u32 slen, dlen, hlen, datalen;
	int ret;

	/* We need contiguous buffers for the compression algorithm. */
	slen = iov_iter_count(iter);
	src = vmap_bvecq(iter, PAGE_KERNEL_RO);
	if (IS_ERR(src)) {
		ret = PTR_ERR(src);
		src = NULL;
		goto err_free;
	}

	shdr = src;
	hlen  = le16_to_cpu(shdr->StructureSize);
	w_hdr = src;
	hlen = le16_to_cpu(w_hdr->DataOffset);
	datalen = le32_to_cpu(w_hdr->Length);
	if (datalen != slen - hlen) {
		pr_warn("datalen %x != slen-hlen %x\n", datalen, slen - hlen);
		return -EMSGSIZE;
	}

	/*
	 * This is just overprovisioning, as the algorithm will error out if @dst reaches 7/8
	 * of @slen.
	 */
	dlen = smb_lz77_compressed_alloc_size(slen);
	dlen = sizeof(*z_hdr) + slen;
	dbq = bvecq_alloc_buffer(dlen, GFP_NOFS, flags & CIFS_WRITEBACK);
	if (!dbq) {
		ret = -ENOMEM;
		goto err_free;
	}

	iov_iter_bvec_queue(&tmp, ITER_DEST, dbq, 1, 0, dlen);
	dst = vmap_bvecq(&tmp, PAGE_KERNEL);
	if (IS_ERR(dst)) {
		ret = PTR_ERR(dst);
		dst = NULL;
		goto err_free;
	}
	z_hdr = dst;
	dst  += sizeof(*z_hdr) + hlen;
	dlen -= sizeof(*z_hdr) + hlen;

	ret = smb_lz77_compress(src + hlen, slen - hlen, dst, &dlen);
	if (ret)
		goto err_free;

	dlen += sizeof(*z_hdr) + hlen;
	dst -= hlen;
	memcpy(dst, src, hlen);

	z_hdr->ProtocolId			= SMB2_COMPRESSION_TRANSFORM_ID;
	z_hdr->OriginalCompressedSegmentSize	= cpu_to_le32(datalen);
	z_hdr->CompressionAlgorithm		= SMB3_COMPRESS_LZ77;
	z_hdr->Flags				= SMB2_COMPRESSION_FLAG_NONE;
	z_hdr->Offset				= cpu_to_le32(hlen);

	vunmap(z_hdr);
	vunmap(src);

	dbq->bv[0] = sbq->bv[0];
	memset(&sbq->bv[0], 0, sizeof(sbq->bv[0]));
	bvecq_shorten_buffer(dbq, 1, dlen);
	bvecq_dump(dbq);

	bvecq_put(sbq);
	*bq = dbq;
	return dlen;

err_free:
	vunmap(z_hdr);
	vunmap(src);
	bvecq_put(dbq);
	return ret;
}
