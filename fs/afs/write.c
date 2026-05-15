// SPDX-License-Identifier: GPL-2.0-or-later
/* handling of writes to regular files and writing back to the server
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/netfs.h>
#include <crypto/skcipher.h>
#include <crypto/sha2.h>
#include <trace/events/netfs.h>
#include "internal.h"

/*
 * completion of write to server
 */
static void afs_pages_written_back(struct afs_vnode *vnode, loff_t start, unsigned int len)
{
	_enter("{%llx:%llu},{%x @%llx}",
	       vnode->fid.vid, vnode->fid.vnode, len, start);

	afs_prune_wb_keys(vnode);
	_leave("");
}

/*
 * Find a key to use for the writeback.  We cached the keys used to author the
 * writes on the vnode.  wreq->netfs_priv2 will contain the last writeback key
 * record used or NULL and we need to start from there if it's set.
 * wreq->netfs_priv will be set to the key itself or NULL.
 */
static void afs_get_writeback_key(struct netfs_io_request *wreq)
{
	struct afs_wb_key *wbk, *old = wreq->netfs_priv2;
	struct afs_vnode *vnode = AFS_FS_I(wreq->inode);

	key_put(wreq->netfs_priv);
	wreq->netfs_priv = NULL;
	wreq->netfs_priv2 = NULL;

	spin_lock(&vnode->wb_lock);
	if (old)
		wbk = list_next_entry(old, vnode_link);
	else
		wbk = list_first_entry(&vnode->wb_keys, struct afs_wb_key, vnode_link);

	list_for_each_entry_from(wbk, &vnode->wb_keys, vnode_link) {
		_debug("wbk %u", key_serial(wbk->key));
		if (key_validate(wbk->key) == 0) {
			refcount_inc(&wbk->usage);
			wreq->netfs_priv = key_get(wbk->key);
			wreq->netfs_priv2 = wbk;
			_debug("USE WB KEY %u", key_serial(wbk->key));
			break;
		}
	}

	spin_unlock(&vnode->wb_lock);

	afs_put_wb_key(old);
}

static void afs_store_data_success(struct afs_operation *op)
{
	struct afs_vnode *vnode = op->file[0].vnode;

	op->ctime = op->file[0].scb.status.mtime_client;
	afs_vnode_commit_status(op, &op->file[0]);
	if (!afs_op_error(op)) {
		afs_pages_written_back(vnode, op->store.pos, op->store.size);
		afs_stat_v(vnode, n_stores);
		atomic_long_add(op->store.size, &afs_v2net(vnode)->n_store_bytes);
	}
}

static const struct afs_operation_ops afs_store_data_operation = {
	.issue_afs_rpc	= afs_fs_store_data,
	.issue_yfs_rpc	= yfs_fs_store_data,
	.success	= afs_store_data_success,
};

/*
 * Estimate the maximum size of a write we can send to the server.
 */
int afs_estimate_write(struct netfs_io_request *wreq,
		       struct netfs_io_stream *stream,
		       struct netfs_write_estimate *estimate)
{
	unsigned long long limit = ULLONG_MAX - stream->issue_from;
	unsigned long long max_len = 256 * 1024 * 1024;

	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags))
		max_len = 64 * 1024;

	//if (test_bit(NETFS_SREQ_RETRYING, &subreq->flags))
	//	max_len = 512 * 1024;

	estimate->issue_at = stream->issue_from + umin(max_len, limit);
	return 0;
}

/*
 * Add a trailer to adjust the write to a content-encrypted file.  We have to
 * round up the block with the EOF in it to the algo block size at a minimum;
 * we then tag on sufficient zeros to pad the server's file size to our file
 * size + 16 (or whatever the algo block size is).
 *
 * Note that *_len is already padded out to a full fscrypt block size.
 */
static int afs_add_content_encryption_trailer(struct afs_vnode *vnode,
					      struct netfs_io_request *wreq,
					      struct netfs_io_subrequest *subreq,
					      size_t *_len)
{
	struct bvecq *bq;
	unsigned long long remote_i_size, eof;
	size_t asize = wreq->crypto_asize; /* Algo block size */
	size_t tlen = asize;
	size_t len = *_len;

	kenter("%llx,%zx", subreq->start, len);

	eof = subreq->start + len;
	remote_i_size = netfs_read_remote_i_size(&vnode->netfs.inode);
	if (eof < remote_i_size) {
		kleave(" = 0");
		return 0;
	}

	/* If the target file size is at or beyond the end of this subreq, then
	 * we write all of it with a full-sized trailer.  Subsequent subreqs
	 * will overwrite the trailer, but as long as FS.StoreData is atomic
	 * and gets rolled back on failure, the file should never be seen in a
	 * state where it has a corrupt length.
	 */
	if (eof <= wreq->i_size)
		goto add_trailer;

	/* Reduce the length so that we don't write beyond the final algo
	 * block.  If i_size aligns with the algo block, then just add a whole
	 * trailer.
	 */
	eof = round_up(wreq->i_size, asize);
	*_len = eof - subreq->start;
	if (eof == wreq->i_size)
		goto add_trailer;

	/* Otherwise, just add sufficient zeros to pad from the end of the algo
	 * block to EOF + algo block size.
	 */
	tlen = asize - (eof - wreq->i_size);

add_trailer:
	for (bq = subreq->content.bvecq; bq->next; bq = bq->next)
		;
	if (bvecq_is_full(bq) || bq->mem_type == BVECQ_MEM_ALLOCED) {
		struct bvecq *p = bvecq_alloc_one(1, GFP_NOFS);

		if (!p) {
			kleave(" = -ENOMEM");
			return -ENOMEM;
		}
		p->fpos = eof;
		p->prev = bq;
		bq->next = p;
		bq = p;
	}
	bvec_set_page(&bq->bv[bq->nr_slots], ZERO_PAGE(0), PAGE_SIZE, 0);
	bq->nr_slots++;
	subreq->back_excess = asize;
	*_len += tlen;
	kleave(" = 0 [%zx]", *_len);
	return 0;
}

/*
 * Issue a subrequest to write to the server.
 */
static void afs_issue_write_worker(struct work_struct *work)
{
	struct netfs_io_subrequest *subreq = container_of(work, struct netfs_io_subrequest, work);
	struct netfs_io_request *wreq = subreq->rreq;
	struct afs_operation *op;
	struct afs_vnode *vnode = AFS_FS_I(wreq->inode);
	unsigned long long pos = subreq->start + subreq->transferred;
	size_t len = subreq->len - subreq->transferred;
	int ret = -ENOKEY;

	kenter("R=%x[%x],%s{%llx:%llu.%u},%llx,%zx",
	       wreq->debug_id, subreq->debug_index,
	       vnode->volume->name,
	       vnode->fid.vid,
	       vnode->fid.vnode,
	       vnode->fid.unique,
	       pos, len);

#if 0 // Error injection
	if (subreq->debug_index == 3)
		return netfs_write_subrequest_terminated(subreq, -ENOANO);

	if (!subreq->retry_count) {
		set_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
		return netfs_write_subrequest_terminated(subreq, -EAGAIN);
	}
#endif

	if (test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags)) {
		/* We need to include a fixed-length trailer if this is at the
		 * end of the file so that we can work out later how big the
		 * file is as we need to retain the entire end crypto block.
		 */
		ret = afs_add_content_encryption_trailer(vnode, wreq, subreq, &len);
		if (ret < 0)
			return netfs_write_subrequest_terminated(subreq, ret);
	}

	kdebug("-- content %zx --", len);
	bvecq_dump(subreq->content.bvecq);

	op = afs_alloc_operation(wreq->netfs_priv, vnode->volume);
	if (IS_ERR(op))
		return netfs_write_subrequest_terminated(subreq, -EAGAIN);

	afs_op_set_vnode(op, 0, vnode);
	op->file[0].dv_delta	= 1;
	op->file[0].modification = true;
	op->store.pos		= pos;
	op->store.size		= len;
	op->flags		|= AFS_OPERATION_UNINTR;
	op->ops			= &afs_store_data_operation;

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
	afs_begin_vnode_operation(op);

	op->store.i_size	= umax(pos + len, netfs_read_remote_i_size(&vnode->netfs.inode));
	op->mtime		= inode_get_mtime(&vnode->netfs.inode);

	iov_iter_bvec_queue(&op->store.write_iter, ITER_SOURCE, subreq->content.bvecq,
			    subreq->content.slot, subreq->content.offset, len);

	afs_wait_for_operation(op);
	ret = afs_put_operation(op);
	switch (ret) {
	case 0:
		__set_bit(NETFS_SREQ_MADE_PROGRESS, &subreq->flags);
		break;
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		/* If there are more keys we can try, use the retry algorithm
		 * to rotate the keys.
		 */
		if (wreq->netfs_priv2)
			set_bit(NETFS_SREQ_NEED_RETRY, &subreq->flags);
		break;
	}

	kdebug("excess %zx %x", subreq->len, subreq->back_excess);
	//subreq->len -= subreq->back_excess;
	kleave(" = %zd", ret < 0 ? ret : subreq->len);
	netfs_write_subrequest_terminated(subreq, ret < 0 ? ret : subreq->len);
}

void afs_issue_write(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *wreq = subreq->rreq;
	unsigned long long wsize = 256 * 1024 * 1024;
	bool enc = test_bit(NETFS_RREQ_CONTENT_ENCRYPTION, &wreq->flags);
	int ret;

	if (enc)
		wsize = 64 * 1024;
	if (subreq->len > wsize)
		subreq->len = wsize;
	ret = netfs_prepare_write_buffer(subreq, INT_MAX, enc);
	if (ret < 0)
		return netfs_write_subrequest_terminated(subreq, ret);

	subreq->work.func = afs_issue_write_worker;
	if (!queue_work(system_dfl_wq, &subreq->work))
		WARN_ON_ONCE(1);
}

/*
 * Writeback calls this when it finds a folio that needs uploading.  This isn't
 * called if writeback only has copy-to-cache to deal with.
 */
void afs_begin_writeback(struct netfs_io_request *wreq)
{
	if (S_ISREG(wreq->inode->i_mode))
		afs_get_writeback_key(wreq);

	wreq->io_streams[0].avail = true;
}

/*
 * Prepare to retry the writes in request.  Use this to try rotating the
 * available writeback keys.
 */
void afs_retry_request(struct netfs_io_request *wreq, struct netfs_io_stream *stream)
{
	struct netfs_io_subrequest *subreq =
		list_first_entry(&stream->subrequests,
				 struct netfs_io_subrequest, rreq_link);

	switch (wreq->origin) {
	case NETFS_READAHEAD:
	case NETFS_READPAGE:
	case NETFS_READ_GAPS:
	case NETFS_READ_SINGLE:
	case NETFS_READ_FOR_WRITE:
	case NETFS_UNBUFFERED_READ:
	case NETFS_DIO_READ:
		return;
	default:
		break;
	}

	switch (subreq->error) {
	case -EACCES:
	case -EPERM:
	case -ENOKEY:
	case -EKEYEXPIRED:
	case -EKEYREJECTED:
	case -EKEYREVOKED:
		afs_get_writeback_key(wreq);
		if (!wreq->netfs_priv)
			stream->failed = true;
		break;
	}
}

/*
 * write some of the pending data back to the server
 */
int afs_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct afs_vnode *vnode = AFS_FS_I(mapping->host);
	int ret;

	/* We have to be careful as we can end up racing with setattr()
	 * truncating the pagecache since the caller doesn't take a lock here
	 * to prevent it.
	 */
	if (wbc->sync_mode == WB_SYNC_ALL)
		down_read(&vnode->validate_lock);
	else if (!down_read_trylock(&vnode->validate_lock))
		return 0;

	ret = netfs_writepages(mapping, wbc);
	up_read(&vnode->validate_lock);
	return ret;
}

/*
 * flush any dirty pages for this process, and check for write errors.
 * - the return status from this call provides a reliable indication of
 *   whether any write errors occurred for this process.
 */
int afs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct afs_vnode *vnode = AFS_FS_I(file_inode(file));
	struct afs_file *af = file->private_data;
	int ret;

	_enter("{%llx:%llu},{n=%pD},%d",
	       vnode->fid.vid, vnode->fid.vnode, file,
	       datasync);

	ret = afs_validate(vnode, af->key);
	if (ret < 0)
		return ret;

	return file_write_and_wait_range(file, start, end);
}

/*
 * notification that a previously read-only page is about to become writable
 * - if it returns an error, the caller will deliver a bus error signal
 */
vm_fault_t afs_page_mkwrite(struct vm_fault *vmf)
{
	struct file *file = vmf->vma->vm_file;

	if (afs_validate(AFS_FS_I(file_inode(file)), afs_file_key(file)) < 0)
		return VM_FAULT_SIGBUS;
	return netfs_page_mkwrite(vmf, NULL);
}

/*
 * Prune the keys cached for writeback.  The caller must hold vnode->wb_lock.
 */
void afs_prune_wb_keys(struct afs_vnode *vnode)
{
	LIST_HEAD(graveyard);
	struct afs_wb_key *wbk, *tmp;

	/* Discard unused keys */
	spin_lock(&vnode->wb_lock);

	if (!mapping_tagged(&vnode->netfs.inode.i_data, PAGECACHE_TAG_WRITEBACK) &&
	    !mapping_tagged(&vnode->netfs.inode.i_data, PAGECACHE_TAG_DIRTY)) {
		list_for_each_entry_safe(wbk, tmp, &vnode->wb_keys, vnode_link) {
			if (refcount_read(&wbk->usage) == 1)
				list_move(&wbk->vnode_link, &graveyard);
		}
	}

	spin_unlock(&vnode->wb_lock);

	while (!list_empty(&graveyard)) {
		wbk = list_entry(graveyard.next, struct afs_wb_key, vnode_link);
		list_del(&wbk->vnode_link);
		afs_put_wb_key(wbk);
	}
}

static void netfs_dump_sg(const char *prefix, struct scatterlist *sg, unsigned int n_sg)
{
	unsigned int i;

	for (i = 0; i < n_sg; i++) {
		void *p = kmap_local_page(sg_page(sg));
		unsigned int l = min_t(size_t, sg->length, 16);

		printk("%s[%x] %10lx %04x %04x %*phN\n",
		       prefix, i, page_to_pfn(sg_page(sg)), sg->offset, sg->length,
		       l, p + sg->offset);
		kunmap_local(p);
		sg++;
	}
}

/*
 * Create a keyed symmetric cipher for use in content crypto ops.
 */
int afs_open_crypto(struct afs_vnode *vnode)
{
	struct crypto_skcipher *ci;
	struct sha256_ctx sha;
	int ret = 0;
	u8 key[SHA256_DIGEST_SIZE];

	afs_lock_for_io(vnode);
	if (vnode->content_ci)
		goto out;

	ci = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(ci)) {
		ret = PTR_ERR(ci);
		pr_err("Can't allocate cipher: %d\n", ret);
		goto out;
	}

	if (crypto_skcipher_ivsize(ci) > 16 &&
	    crypto_skcipher_blocksize(ci) > 16) {
		pr_err("iv wrong size: %u\n", crypto_skcipher_ivsize(ci));
		ret = -EINVAL;
		goto error_ci;
	}

	sha256_init(&sha);
	sha256_update(&sha, vnode->volume->cell->name, vnode->volume->cell->name_len);
	sha256_update(&sha, (u8 *)&vnode->fid, sizeof(vnode->fid));
	sha256_final(&sha, key);

	crypto_skcipher_set_flags(ci, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	ret = crypto_skcipher_setkey(ci, key, sizeof(key));
	if (ret < 0) {
		pr_err("Setkey failed: %d\n", ret);
		goto error_ci;
	}

	vnode->content_ci = ci;
	ret = 0;
out:
	afs_unlock_for_io(vnode);
	return ret;

error_ci:
	crypto_free_skcipher(ci);
	goto out;
}

/*
 * Encrypt part of a write for fscrypt.
 */
int afs_encrypt_block(struct netfs_io_request *wreq,
		       unsigned long long start,
		       struct scatterlist *src_sg,
		       struct scatterlist *dst_sg,
		       gfp_t gfp)
{
	struct skcipher_request *req;
	struct crypto_skcipher *ci = AFS_FS_I(wreq->inode)->content_ci;
	size_t len = wreq->crypto_bsize, reqsize, ivsize;
	int ret;
	u8 *iv;

	kenter("%llx", start);

	reqsize = round_up(sizeof(struct skcipher_request) +
			   crypto_skcipher_reqsize(ci),
			   CRYPTO_MINALIGN);
	ivsize = crypto_skcipher_ivsize(ci);

	netfs_dump_sg("SRC", src_sg, 1);

	req = kzalloc(reqsize + ivsize, gfp);
	if (!req)
		return -ENOMEM;

	iv = (void *)req + reqsize;
	*(__be64 *)iv = cpu_to_be64(start);

	skcipher_request_set_tfm(req, ci);
	skcipher_request_set_crypt(req, src_sg, dst_sg, len, iv);
	ret = crypto_skcipher_encrypt(req);
	if (ret < 0)
		pr_err("R=%x Encrypt %llx failed: %d\n",
		       wreq->debug_id, start, ret);

	netfs_dump_sg("ENC", dst_sg, 1);

	skcipher_request_free(req);
	return ret;
}

/*
 * Decrypt part of a read for fscrypt.  The caller reserved an extra
 * scatterlist element before each of source_sg and dest_sg for our purposes,
 * should we need them.
 */
int afs_decrypt_block(struct netfs_io_request *rreq,
		      unsigned long long start, size_t len,
		      struct scatterlist *src_sg, unsigned int n_src,
		      struct scatterlist *dst_sg, unsigned int n_dst)
{
	struct skcipher_request *req;
	struct crypto_skcipher *ci = AFS_FS_I(rreq->inode)->content_ci;
	size_t reqsize, ivsize;
	u8 *iv;
	int ret = -ENOMEM;
	DECLARE_CRYPTO_WAIT(wait);

	_enter("%llx,%zx", start, len);

	netfs_dump_sg("DEC", src_sg, n_src);

	reqsize = round_up(sizeof(struct skcipher_request) +
			   crypto_skcipher_reqsize(ci),
			   CRYPTO_MINALIGN);
	ivsize = crypto_skcipher_ivsize(ci);

	req = kzalloc(reqsize + ivsize, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	iv = (void *)req + reqsize;
	*(__be64 *)iv = cpu_to_be64(start);

	skcipher_request_set_tfm(req, ci);
	//skcipher_request_set_callback(
	//	req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
	//	crypto_req_done, &wait);
	skcipher_request_set_crypt(req, src_sg, dst_sg, len, iv);

	//ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
	ret = crypto_skcipher_decrypt(req);
	if (ret < 0)
		pr_err("Decrypt failed: %d\n", ret);

	netfs_dump_sg("DEC", dst_sg, n_dst);

	skcipher_request_free(req);
	_leave(" = %d", ret);
	return ret;
}
