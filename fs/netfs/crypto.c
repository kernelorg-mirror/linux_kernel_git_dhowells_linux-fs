// SPDX-License-Identifier: GPL-2.0-only
/* Network filesystem content encryption support.
 *
 * Copyright (C) 2023 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include "internal.h"

/*
 * Populate a scatterlist from the next bufferage of an I/O iterator.
 */
static int netfs_iter_to_sglist(const struct iov_iter *iter, size_t len,
				struct scatterlist *sg, unsigned int n_sg)
{
	struct iov_iter tmp_iter = *iter;
	struct sg_table sgtable = { .sgl = sg };
	ssize_t ret;

	_enter("%zx/%zx", len, iov_iter_count(iter));

	sg_init_table(sg, n_sg);
	ret = extract_iter_to_sg(&tmp_iter, len, &sgtable, n_sg, 0);
	if (ret < 0)
		return ret;
	sg_mark_end(&sg[sgtable.nents - 1]);
	return sgtable.nents;
}

/*
 * Prepare a write request for writing.  We encrypt in/into the bounce buffer.
 */
bool netfs_encrypt(struct netfs_io_request *wreq)
{
	struct netfs_inode *ctx = netfs_inode(wreq->inode);
	struct scatterlist source_sg[16], dest_sg[16];
	unsigned int n_dest;
	size_t n, chunk, bsize = 1UL << ctx->crypto_bshift;
	loff_t pos;
	int ret;

	_enter("");

	trace_netfs_rreq(wreq, netfs_rreq_trace_encrypt);

	pos = wreq->start;
	n = wreq->len;
	_debug("ENCRYPT %llx-%llx", pos, pos + n - 1);

	for (; n > 0; n -= chunk, pos += chunk) {
		chunk = min(n, bsize);

		ret = netfs_iter_to_sglist(&wreq->io_iter, chunk,
					   dest_sg, ARRAY_SIZE(dest_sg));
		if (ret < 0)
			goto error;
		n_dest = ret;

		if (test_bit(NETFS_RREQ_CRYPT_IN_PLACE, &wreq->flags)) {
			ret = ctx->ops->encrypt_block(wreq, pos, chunk,
						      dest_sg, n_dest,
						      dest_sg, n_dest);
		} else {
			ret = netfs_iter_to_sglist(&wreq->iter, chunk,
						   source_sg, ARRAY_SIZE(source_sg));
			if (ret < 0)
				goto error;
			ret = ctx->ops->encrypt_block(wreq, pos, chunk,
						      source_sg, ret,
						      dest_sg, n_dest);
		}

		if (ret < 0)
			goto error_failed;
	}

	return true;

error_failed:
	trace_netfs_failure(wreq, NULL, ret, netfs_fail_encryption);
error:
	wreq->error = ret;
	return false;
}
