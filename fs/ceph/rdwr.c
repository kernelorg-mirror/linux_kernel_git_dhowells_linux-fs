// SPDX-License-Identifier: GPL-2.0
/* Ceph netfs-based file read-write operations.
 *
 * There are a few funny things going on here.
 *
 * The page->private field is used to reference a struct ceph_snap_context for
 * _every_ dirty page.  This indicates which snapshot the page was logically
 * dirtied in, and thus which snap context needs to be associated with the osd
 * write during writeback.
 *
 * Similarly, struct ceph_inode_info maintains a set of counters to count dirty
 * pages on the inode.  In the absence of snapshots, i_wrbuffer_ref ==
 * i_wrbuffer_ref_head == the dirty page count.
 *
 * When a snapshot is taken (that is, when the client receives notification
 * that a snapshot was taken), each inode with caps and with dirty pages (dirty
 * pages implies there is a cap) gets a new ceph_cap_snap in the i_cap_snaps
 * list (which is sorted in ascending order, new snaps go to the tail).  The
 * i_wrbuffer_ref_head count is moved to capsnap->dirty. (Unless a sync write
 * is currently in progress.  In that case, the capsnap is said to be
 * "pending", new writes cannot start, and the capsnap isn't "finalized" until
 * the write completes (or fails) and a final size/mtime for the inode for that
 * snap can be settled upon.)  i_wrbuffer_ref_head is reset to 0.
 *
 * On writeback, we must submit writes to the osd IN SNAP ORDER.  So, we look
 * for the first capsnap in i_cap_snaps and write out pages in that snap
 * context _only_.  Then we move on to the next capsnap, eventually reaching
 * the "live" or "head" context (i.e., pages that are not yet snapped) and are
 * writing the most recently dirtied pages.
 *
 * Invalidate and so forth must take care to ensure the dirty page accounting
 * is preserved.
 *
 * Copyright (C) 2026 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#include <linux/ceph/ceph_debug.h>

#include <linux/backing-dev.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/folio_batch.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/signal.h>
#include <linux/iversion.h>
#include <linux/ktime.h>
#include <linux/netfs.h>
#include <trace/events/netfs.h>

#include "super.h"
#include "mds_client.h"
#include "cache.h"
#include "metric.h"
#include "crypto.h"
#include <linux/ceph/osd_client.h>
#include <linux/ceph/striper.h>

struct ceph_writeback_ctl
{
	loff_t i_size;
	u64 truncate_size;
	u32 truncate_seq;
	bool size_stable;
	bool head_snapc;
};

struct kmem_cache *ceph_io_request_cachep;
struct kmem_cache *ceph_io_subrequest_cachep;

static struct ceph_io_subrequest *ceph_sreq2io(struct netfs_io_subrequest *subreq)
{
	BUILD_BUG_ON(sizeof(struct ceph_io_request) > NETFS_DEF_IO_REQUEST_SIZE);
	BUILD_BUG_ON(sizeof(struct ceph_io_subrequest) > NETFS_DEF_IO_SUBREQUEST_SIZE);

	return container_of(subreq, struct ceph_io_subrequest, sreq);
}

/*
 * Get the snapc from the group attached to a request
 */
static struct ceph_snap_context *ceph_wreq_snapc(struct netfs_io_request *wreq)
{
	struct ceph_snap_context *snapc =
		container_of(wreq->group, struct ceph_snap_context, group);
	return snapc;
}

#if 0
static void ceph_put_many_snap_context(struct ceph_snap_context *sc, unsigned int nr)
{
	if (sc)
		netfs_put_group_many(&sc->group, nr);
}
#endif

/*
 * Handle the termination of a write to the server.
 */
static void ceph_netfs_write_callback(struct ceph_osd_request *req)
{
	struct netfs_io_subrequest *subreq = req->r_subreq;
	struct ceph_io_subrequest *csub = ceph_sreq2io(subreq);
	struct ceph_io_request *creq = csub->creq;
	struct inode *inode = creq->rreq.inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	struct ceph_client *cl = ceph_inode_to_client(inode);
	size_t wrote = req->r_result ? 0 : subreq->len;
	int err = req->r_result;

	trace_netfs_sreq(subreq, netfs_sreq_trace_io_progress);

	ceph_update_write_metrics(&fsc->mdsc->metric, req->r_start_latency,
				  req->r_end_latency, wrote, err);

	if (err) {
		doutc(cl, "sync_write osd write returned %d\n", err);
		/* Version changed! Must re-do the rmw cycle */
		if ((creq->rmw_assert_version && (err == -ERANGE || err == -EOVERFLOW)) ||
		    (!creq->rmw_assert_version && err == -EEXIST)) {
			/* We should only ever see this on a rmw */
			WARN_ON_ONCE(!test_bit(NETFS_RREQ_RMW, &ci->netfs.flags));

			/* The version should never go backward */
			WARN_ON_ONCE(err == -EOVERFLOW);

			/* FIXME: limit number of times we loop? */
			set_bit(NETFS_RREQ_REPEAT_RMW, &creq->rreq.flags);
			trace_netfs_sreq(subreq, netfs_sreq_trace_need_rmw);
		}
		ceph_set_error_write(ci);
	} else {
		ceph_clear_error_write(ci);
	}

	csub->req = NULL;
	ceph_osdc_put_request(req);
	netfs_write_subrequest_terminated(subreq, err ?: wrote);
}

/*
 * Estimate the maximum amount to accumulate before generating writes to the
 * server.  Use the end of the object for this as we would like be able to
 * generate sparse writes.
 */
static int ceph_estimate_write(struct netfs_io_request *wreq,
			       struct netfs_io_stream *stream,
			       struct netfs_write_estimate *estimate)
{
	struct ceph_inode_info *ci = ceph_inode(wreq->inode);
	size_t max_len;
	u64 objnum, objoff;

	/* Clamp the length to the next object boundary. */
	ceph_calc_file_object_mapping(&ci->i_layout, stream->issue_from,
				      ULLONG_MAX, &objnum, &objoff, &max_len);

	estimate->issue_at = stream->issue_from + max_len;
	return 0;
}

/*
 * Issue a subrequest to upload to the server.
 */
static int ceph_issue_write(struct netfs_io_subrequest *subreq)
{
	struct ceph_io_subrequest *csub = ceph_sreq2io(subreq);
	struct ceph_snap_context *snapc = ceph_wreq_snapc(subreq->rreq);
	struct ceph_osd_request *req;
	struct ceph_io_request *creq = csub->creq;
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(subreq->rreq->inode);
	struct ceph_osd_client *osdc = &fsc->client->osdc;
	struct inode *inode = subreq->rreq->inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct bvecq *buf_copy;
	unsigned long long len;
	unsigned int rmw = test_bit(NETFS_RREQ_RMW, &ci->netfs.flags) ? 1 : 0;
	u64 objnum, objoff;
	int ret;

	doutc(cl, "issue_write R=%08x[%x] ino %llx %lld~%zu -- %srmw\n",
	      subreq->rreq->debug_id, subreq->debug_index, ci->i_vino.ino,
	      subreq->start, subreq->len,
	      rmw ? "" : "no ");

	/* Clamp the length to the next object boundary. */
	ceph_calc_file_object_mapping(&ci->i_layout, subreq->start, subreq->len,
				      &objnum, &objoff, &subreq->len);

	len = umin(subreq->len, fsc->mount_options->wsize);

	req = ceph_osdc_new_request(osdc, &ci->i_layout, ci->i_vino,
				    subreq->start, &len,
				    rmw,	/* which: 0 or 1 */
				    rmw + 1,	/* num_ops: 1 or 2 */
				    CEPH_OSD_OP_WRITE,
				    CEPH_OSD_FLAG_WRITE,
				    snapc,
				    ci->i_truncate_seq,
				    ci->i_truncate_size, false);
	if (IS_ERR(req)) {
		netfs_write_subrequest_terminated(subreq, PTR_ERR(req));
		return 0;
	}

	/* Get the write buffer and copy the bvecq. */
	subreq->len = len;
	ret = netfs_prepare_write_buffer(subreq, INT_MAX);
	if (ret < 0)
		return ret;
	ret = bvecq_extract(&subreq->content, subreq->len, INT_MAX, &buf_copy,
			    creq->rreq.origin == NETFS_WRITEBACK);
	if (ret < 0)
		return ret;

	bvecq_pos_unset(&subreq->content);
	subreq->content.bvecq = buf_copy; /* Transfer extracted ref. */

	doutc(cl, "write op %lld~%zu\n", subreq->start, subreq->len);
	osd_req_op_extent_osd_bvecq(req, 0, subreq->content.bvecq, subreq->len);
	req->r_inode	= inode;
	req->r_mtime	= current_time(inode);
	req->r_callback	= ceph_netfs_write_callback;
	req->r_subreq	= subreq;
	csub->req	= req;

	/*
	 * If we're doing an RMW cycle, set up an assertion that the remote
	 * data hasn't changed.  If we don't have a version number, then the
	 * object doesn't exist yet.  Use an exclusive create instead of a
	 * version assertion in that case.
	 */
	if (rmw) {
		if (creq->rmw_assert_version) {
			osd_req_op_init(req, 0, CEPH_OSD_OP_ASSERT_VER, 0);
			req->r_ops[0].assert_ver.ver = creq->rmw_assert_version;
		} else {
			osd_req_op_init(req, 0, CEPH_OSD_OP_CREATE,
					CEPH_OSD_OP_FLAG_EXCL);
		}
	}

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
	ceph_osdc_start_request(osdc, req);
	return 0;
}

/*
 * Mark the caps as dirty
 */
static void ceph_netfs_post_modify(struct inode *inode, void *fs_priv)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap_flush **prealloc_cf = fs_priv;
	int dirty;

	spin_lock(&ci->i_ceph_lock);
	dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR, prealloc_cf);
	spin_unlock(&ci->i_ceph_lock);
	if (dirty)
		__mark_inode_dirty(inode, dirty);
}

static void ceph_netfs_expand_readahead(struct netfs_io_request *rreq)
{
	struct inode *inode = rreq->inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_layout *lo = &ci->i_layout;
	unsigned long max_pages = inode->i_sb->s_bdi->ra_pages;
	loff_t end = rreq->start + rreq->len, new_end;
	struct ceph_io_request *priv = container_of(rreq, struct ceph_io_request, rreq);
	unsigned long max_len;
	u32 blockoff;

	if (priv) {
		/* Readahead is disabled by posix_fadvise POSIX_FADV_RANDOM */
		if (priv->file_ra_disabled)
			max_pages = 0;
		else
			max_pages = priv->file_ra_pages;

	}

	/* Readahead is disabled */
	if (!max_pages)
		return;

	max_len = max_pages << PAGE_SHIFT;

	/*
	 * Try to expand the length forward by rounding up it to the next
	 * block, but do not exceed the file size, unless the original
	 * request already exceeds it.
	 */
	new_end = umin(round_up(end, lo->stripe_unit), rreq->i_size);
	if (new_end > end && new_end <= rreq->start + max_len)
		rreq->len = new_end - rreq->start;

	/* Try to expand the start downward */
	div_u64_rem(rreq->start, lo->stripe_unit, &blockoff);
	if (rreq->len + blockoff <= max_len) {
		rreq->start -= blockoff;
		rreq->len += blockoff;
	}
}

static void ceph_netfs_read_callback(struct ceph_osd_request *req)
{
	struct inode *inode = req->r_inode;
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	struct ceph_client *cl = fsc->client;
	struct ceph_osd_data *osd_data = osd_req_op_extent_osd_data(req, 0);
	struct netfs_io_subrequest *subreq = req->r_priv;
	struct ceph_osd_req_op *op = &req->r_ops[0];
	bool sparse = (op->op == CEPH_OSD_OP_SPARSE_READ);
	int err = req->r_result;

	ceph_update_read_metrics(&fsc->mdsc->metric, req->r_start_latency,
				 req->r_end_latency, osd_data->iter.count, err);

	doutc(cl, "result %d subreq->len=%zu i_size=%lld\n", req->r_result,
	      subreq->len, i_size_read(req->r_inode));

	/* no object means success but no data */
	if (err == -ENOENT)
		err = 0;
	else if (err == -EBLOCKLISTED)
		fsc->blocklisted = true;

	if (err >= 0) {
		if (sparse && err > 0)
			err = ceph_sparse_ext_map_end(op);
		if (err < subreq->len &&
		    subreq->rreq->origin != NETFS_DIO_READ)
			__set_bit(NETFS_SREQ_CLEAR_TAIL, &subreq->flags);
		if (IS_ENCRYPTED(inode) && err > 0) {
#if 0
			err = ceph_fscrypt_decrypt_extents(inode, osd_data->dbuf,
							   subreq->start,
							   op->extent.sparse_ext,
							   op->extent.sparse_ext_cnt);
			if (err > subreq->len)
				err = subreq->len;
#else
			pr_err("TODO: Content-decrypt currently disabled\n");
			err = -EOPNOTSUPP;
#endif
		}
	}

	if (err > 0) {
		subreq->transferred = err;
		err = 0;
	}

	subreq->error = err;
	trace_netfs_sreq(subreq, netfs_sreq_trace_io_progress);
	ceph_dec_osd_stopping_blocker(fsc->mdsc);
	netfs_read_subreq_terminated(subreq);
}

static void ceph_rmw_read_done(struct netfs_io_request *wreq, struct netfs_io_request *rreq)
{
	struct ceph_io_request *cwreq = container_of(wreq, struct ceph_io_request, rreq);
	struct ceph_io_request *crreq = container_of(rreq, struct ceph_io_request, rreq);

	cwreq->rmw_assert_version = crreq->rmw_assert_version;
}

static int ceph_netfs_issue_read_inline(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct inode *inode = rreq->inode;
	struct ceph_mds_reply_info_parsed *rinfo;
	struct ceph_mds_reply_info_in *iinfo;
	struct ceph_mds_request *req;
	struct ceph_mds_client *mdsc = ceph_sb_to_mdsc(inode->i_sb);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct iov_iter iter;
	ssize_t err = 0;
	size_t len, copied;
	int mode;

	__clear_bit(NETFS_SREQ_COPY_TO_CACHE, &subreq->flags);

	if (subreq->start >= inode->i_size) {
		__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
		goto out;
	}

	err = netfs_prepare_read_buffer(subreq, INT_MAX);
	if (err < 0)
		goto out;

	/* We need to fetch the inline data. */
	mode = ceph_try_to_choose_auth_mds(inode, CEPH_STAT_CAP_INLINE_DATA);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_GETATTR, mode);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}
	req->r_ino1 = ci->i_vino;
	req->r_args.getattr.mask = cpu_to_le32(CEPH_STAT_CAP_INLINE_DATA);
	req->r_num_caps = 2;

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	if (err < 0)
		goto out;

	rinfo = &req->r_reply_info;
	iinfo = &rinfo->targeti;
	if (iinfo->inline_version == CEPH_INLINE_NONE) {
		/* The data got uninlined */
		ceph_mdsc_put_request(req);
		return 1; /* Proceed as uninlined */
	}

	iov_iter_bvec_queue(&iter, ITER_DEST, subreq->content.bvecq,
			    subreq->content.slot, subreq->content.offset,
			    subreq->len);

	len = umin(iinfo->inline_len - subreq->start, subreq->len);
	copied = copy_to_iter(iinfo->inline_data + subreq->start, len, &iter);
	if (copied) {
		subreq->transferred += copied;
		if (copied == len)
			__set_bit(NETFS_SREQ_HIT_EOF, &subreq->flags);
		subreq->error = 0;
	} else {
		subreq->error = -EFAULT;
	}

	ceph_mdsc_put_request(req);
	err = 0;
out:
	netfs_read_subreq_terminated(subreq);
	return err;
}

static int ceph_netfs_issue_read(struct netfs_io_subrequest *subreq)
{
	struct netfs_io_request *rreq = subreq->rreq;
	struct inode *inode = rreq->inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	struct ceph_client *cl = fsc->client;
	struct ceph_osd_request *req = NULL;
	struct ceph_vino vino = ceph_vino(inode);
	bool sparse = IS_ENCRYPTED(inode) || ceph_test_mount_opt(fsc, SPARSEREAD);
	u64 objno, objoff, len, off = subreq->start;
	int err = 0, extent_cnt;

	err = ceph_inode_is_shutdown(inode);
	if (err <= 0)
		goto failed;

	if (ceph_has_inline_data(ci)) {
		err = ceph_netfs_issue_read_inline(subreq);
		if (err != 1)
			return err;
	}

	/* Truncate the extent at the end of the current block */
	ceph_calc_file_object_mapping(&ci->i_layout, subreq->start, subreq->len,
				      &objno, &objoff, &subreq->len);

	len = umin(subreq->len, fsc->mount_options->rsize);

	req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout, vino,
				    off, &len, 0, 1,
				    sparse ? CEPH_OSD_OP_SPARSE_READ : CEPH_OSD_OP_READ,
				    CEPH_OSD_FLAG_READ, /*  read_from_replica will be or'd in */
				    NULL, ci->i_truncate_seq, ci->i_truncate_size, false);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		req = NULL;
		goto failed;
	}

	subreq->len = len;
	err = netfs_prepare_read_buffer(subreq, INT_MAX);
	if (err < 0)
		goto failed;

	if (sparse) {
		extent_cnt = __ceph_sparse_read_ext_count(inode, len);
		err = ceph_alloc_sparse_ext_map(&req->r_ops[0], extent_cnt);
		if (err)
			goto failed;
	}

	doutc(cl, "%llx.%llx pos=%llu orig_len=%zu len=%llu\n",
	      ceph_vinop(inode), subreq->start, subreq->len, len);

	osd_req_op_extent_osd_bvecq(req, 0, subreq->content.bvecq, subreq->len);
	if (!ceph_inc_osd_stopping_blocker(fsc->mdsc)) {
		err = -EIO;
		goto failed;
	}

	req->r_callback = ceph_netfs_read_callback;
	req->r_priv = subreq;
	req->r_inode = inode;

	trace_netfs_sreq(subreq, netfs_sreq_trace_submit);

	ceph_osdc_start_request(req->r_osdc, req);
	ceph_osdc_put_request(req);
	doutc(cl, "%llx.%llx queued\n", ceph_vinop(inode));
	return 0;
failed:
	subreq->error = err;
	if (req)
		ceph_osdc_put_request(req);
	doutc(cl, "%llx.%llx result %d\n", ceph_vinop(inode), err);
	netfs_read_subreq_terminated(subreq);
	return 0;
}

static int ceph_init_request(struct netfs_io_request *rreq, struct file *file)
{
	struct ceph_io_request *priv = container_of(rreq, struct ceph_io_request, rreq);
	struct inode *inode = rreq->inode;
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	int got = 0, want = CEPH_CAP_FILE_CACHE;
	int ret = 0;

	rreq->rsize = 1024 * 1024;
	rreq->wsize = umin(i_blocksize(inode), fsc->mount_options->wsize);

	switch (rreq->origin) {
	case NETFS_READAHEAD:
		goto init_readahead;
	case NETFS_WRITEBACK:
	case NETFS_UNBUFFERED_WRITE:
	case NETFS_DIO_WRITE:
		if (S_ISREG(rreq->inode->i_mode))
			rreq->io_streams[0].avail = true;
		return 0;
	default:
		return 0;
	}

init_readahead:
	/*
	 * If we are doing readahead triggered by a read, fault-in or
	 * MADV/FADV_WILLNEED, someone higher up the stack must be holding the
	 * FILE_CACHE and/or LAZYIO caps.
	 */
	if (file) {
		priv->file_ra_pages = file->f_ra.ra_pages;
		priv->file_ra_disabled = file->f_mode & FMODE_RANDOM;
		rreq->netfs_priv = priv;
		return 0;
	}

	/*
	 * readahead callers do not necessarily hold Fcb caps
	 * (e.g. fadvise, madvise).
	 */
	ret = ceph_try_get_caps(inode, CEPH_CAP_FILE_RD, want, true, &got);
	if (ret < 0) {
		doutc(cl, "%llx.%llx, error getting cap\n", ceph_vinop(inode));
		goto out;
	}

	if (!(got & want)) {
		doutc(cl, "%llx.%llx, no cache cap\n", ceph_vinop(inode));
		ret = -EACCES;
		goto out;
	}
	if (ret > 0)
		priv->caps = got;
	else
		ret = -EACCES;
out:
	return ret;
}

static void ceph_netfs_free_request(struct netfs_io_request *rreq)
{
	struct ceph_io_request *creq = container_of(rreq, struct ceph_io_request, rreq);

	if (creq->caps)
		ceph_put_cap_refs(ceph_inode(rreq->inode), creq->caps);
}

const struct netfs_request_ops ceph_netfs_ops = {
	.init_request		= ceph_init_request,
	.free_request		= ceph_netfs_free_request,
	.expand_readahead	= ceph_netfs_expand_readahead,
	.issue_read		= ceph_netfs_issue_read,
	.rmw_read_done		= ceph_rmw_read_done,
	.post_modify		= ceph_netfs_post_modify,
	.estimate_write		= ceph_estimate_write,
	.issue_write		= ceph_issue_write,
};

/*
 * Get ref for the oldest snapc for an inode with dirty data... that is, the
 * only snap context we are allowed to write back.
 */
static struct ceph_snap_context *
ceph_get_oldest_context(struct inode *inode, struct ceph_writeback_ctl *ctl,
			struct ceph_snap_context *folio_snapc)
{
	struct ceph_snap_context *snapc = NULL;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap_snap *capsnap = NULL;
	struct ceph_client *cl = ceph_inode_to_client(inode);

	spin_lock(&ci->i_ceph_lock);
	list_for_each_entry(capsnap, &ci->i_cap_snaps, ci_item) {
		doutc(cl, " capsnap %p snapc %p has %d dirty pages\n",
		      capsnap, capsnap->context, capsnap->dirty_pages);
		if (!capsnap->dirty_pages)
			continue;

		/* get i_size, truncate_{seq,size} for folio_snapc? */
		if (snapc && capsnap->context != folio_snapc)
			continue;

		if (ctl) {
			if (capsnap->writing) {
				ctl->i_size = i_size_read(inode);
				ctl->size_stable = false;
			} else {
				ctl->i_size = capsnap->size;
				ctl->size_stable = true;
			}
			ctl->truncate_size = capsnap->truncate_size;
			ctl->truncate_seq = capsnap->truncate_seq;
			ctl->head_snapc = false;
		}

		if (snapc)
			break;

		snapc = ceph_get_snap_context(capsnap->context);
		if (!folio_snapc ||
		    folio_snapc == snapc ||
		    folio_snapc->seq > snapc->seq)
			break;
	}
	if (!snapc && ci->i_wrbuffer_ref_head) {
		snapc = ceph_get_snap_context(ci->i_head_snapc);
		doutc(cl, " head snapc %p has %d dirty pages\n", snapc,
		      ci->i_wrbuffer_ref_head);
		if (ctl) {
			ctl->i_size = i_size_read(inode);
			ctl->truncate_size = ci->i_truncate_size;
			ctl->truncate_seq = ci->i_truncate_seq;
			ctl->size_stable = false;
			ctl->head_snapc = true;
		}
	}
	spin_unlock(&ci->i_ceph_lock);
	return snapc;
}

/*
 * Flush dirty data.  We have to start with the oldest snap as that's the only
 * one we're allowed to write back.
 */
static int ceph_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct ceph_writeback_ctl ceph_wbc;
	struct ceph_snap_context *snapc;
	struct ceph_inode_info *ci = ceph_inode(mapping->host);
	loff_t actual_start = wbc->range_start, actual_end = wbc->range_end;
	int ret;

	do {
		snapc = ceph_get_oldest_context(mapping->host, &ceph_wbc, NULL);
		if (snapc == ci->i_head_snapc) {
			wbc->range_start = actual_start;
			wbc->range_end = actual_end;
		} else {
			/* Do not respect wbc->range_{start,end}.  Dirty pages
			 * in that range can be associated with newer snapc.
			 * They are not writeable until we write all dirty
			 * pages associated with an older snapc get written.
			 */
			wbc->range_start = 0;
			wbc->range_end = LLONG_MAX;
		}

		ret = netfs_writepages_group(mapping, wbc, &snapc->group, &ceph_wbc);
		ceph_put_snap_context(snapc);
		if (snapc == ci->i_head_snapc)
			break;
	} while (ret == 0 && wbc->nr_to_write > 0);

	return ret;
}

const struct address_space_operations ceph_aops = {
	.read_folio	= netfs_read_folio,
	.readahead	= netfs_readahead,
	.writepages	= ceph_writepages,
	.dirty_folio	= ceph_dirty_folio,
	.invalidate_folio = netfs_invalidate_folio,
	.release_folio	= netfs_release_folio,
	.direct_IO	= noop_direct_IO,
	.migrate_folio	= filemap_migrate_folio,
};

/*
 * Wrap generic_file_aio_read with checks for cap bits on the inode.
 * Atomically grab references, so that those bits are not released
 * back to the MDS mid-read.
 *
 * Hmm, the sync read case isn't actually async... should it be?
 */
ssize_t ceph_netfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *filp = iocb->ki_filp;
	struct inode *inode = file_inode(filp);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_info *fi = filp->private_data;
	struct ceph_client *cl = ceph_inode_to_client(inode);
	ssize_t ret;
	size_t len = iov_iter_count(to);
	bool dio = iocb->ki_flags & IOCB_DIRECT;
	int want = 0, got = 0;

	doutc(cl, "%llu~%zu trying to get caps on %p %llx.%llx\n",
	      iocb->ki_pos, len, inode, ceph_vinop(inode));

	if (ceph_inode_is_shutdown(inode))
		return -ESTALE;

	if (dio)
		ret = netfs_start_io_direct(inode);
	else
		ret = netfs_start_io_read(inode);
	if (ret < 0)
		return ret;

	if (!(fi->flags & CEPH_F_SYNC) && !dio)
		want |= CEPH_CAP_FILE_CACHE;
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want |= CEPH_CAP_FILE_LAZYIO;

	ret = ceph_get_caps(filp, CEPH_CAP_FILE_RD, want, -1, &got);
	if (ret < 0)
		goto out;

	if ((got & (CEPH_CAP_FILE_CACHE|CEPH_CAP_FILE_LAZYIO)) == 0 ||
	    dio ||
	    (fi->flags & CEPH_F_SYNC)) {
		doutc(cl, "sync %p %llx.%llx %llu~%zu got cap refs on %s\n",
		      inode, ceph_vinop(inode), iocb->ki_pos, len,
		      ceph_cap_string(got));

		ret = netfs_unbuffered_read_iter(iocb, to);
	} else {
		doutc(cl, "async %p %llx.%llx %llu~%zu got cap refs on %s\n",
		      inode, ceph_vinop(inode), iocb->ki_pos, len,
		      ceph_cap_string(got));
		ret = filemap_read(iocb, to, 0);
	}

	doutc(cl, "%p %llx.%llx dropping cap refs on %s = %zd\n",
	      inode, ceph_vinop(inode), ceph_cap_string(got), ret);
	ceph_put_cap_refs(ci, got);

out:
	if (dio)
		netfs_end_io_direct(inode);
	else
		netfs_end_io_read(inode);
	return ret;
}

/*
 * Get the most recent snap context in the list to which the inode subscribes.
 * This is the only one we are allowed to modify.  If a folio points to an
 * earlier snapshot, it must be flushed first.
 */
static struct ceph_snap_context *ceph_get_most_recent_snapc(struct inode *inode)
{
	struct ceph_snap_context *snapc;
	struct ceph_inode_info *ci = ceph_inode(inode);

	/* Get the snap this write is going to belong to. */
	spin_lock(&ci->i_ceph_lock);
	if (__ceph_have_pending_cap_snap(ci)) {
		struct ceph_cap_snap *capsnap =
			list_last_entry(&ci->i_cap_snaps,
					struct ceph_cap_snap, ci_item);

		snapc = ceph_get_snap_context(capsnap->context);
	} else {
		BUG_ON(!ci->i_head_snapc);
		snapc = ceph_get_snap_context(ci->i_head_snapc);
	}
	spin_unlock(&ci->i_ceph_lock);

	return snapc;
}

/*
 * Take cap references to avoid releasing caps to MDS mid-write.
 *
 * If we are synchronous, and write with an old snap context, the OSD
 * may return EOLDSNAPC.  In that case, retry the write.. _after_
 * dropping our cap refs and allowing the pending snap to logically
 * complete _before_ this write occurs.
 *
 * If we are near ENOSPC, write synchronously.
 */
ssize_t ceph_netfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct ceph_snap_context *snapc;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	struct ceph_file_info *fi = file->private_data;
	struct ceph_osd_client *osdc = &fsc->client->osdc;
	struct ceph_cap_flush *prealloc_cf;
	struct ceph_client *cl = fsc->client;
	ssize_t count, written = 0;
	loff_t limit = max(i_size_read(inode), fsc->max_file_size);
	loff_t pos;
	bool direct_lock = false;
	u64 pool_flags;
	u32 map_flags;
	int err, want = 0, got;

	if (ceph_inode_is_shutdown(inode))
		return -ESTALE;

	if (ceph_snap(inode) != CEPH_NOSNAP)
		return -EROFS;

	prealloc_cf = ceph_alloc_cap_flush();
	if (!prealloc_cf)
		return -ENOMEM;

	if ((iocb->ki_flags & (IOCB_DIRECT | IOCB_APPEND)) == IOCB_DIRECT)
		direct_lock = true;

retry_snap:
	if (direct_lock)
		netfs_start_io_direct(inode);
	else
		netfs_start_io_write(inode);

	if (iocb->ki_flags & IOCB_APPEND) {
		err = ceph_do_getattr(inode, CEPH_STAT_CAP_SIZE, false);
		if (err < 0)
			goto out;
	}

	err = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	pos = iocb->ki_pos;
	if (unlikely(pos >= limit)) {
		err = -EFBIG;
		goto out;
	} else {
		iov_iter_truncate(from, limit - pos);
	}

	count = iov_iter_count(from);
	if (ceph_quota_is_max_bytes_exceeded(inode, pos + count)) {
		err = -EDQUOT;
		goto out;
	}

	down_read(&osdc->lock);
	map_flags = osdc->osdmap->flags;
	pool_flags = ceph_pg_pool_flags(osdc->osdmap, ci->i_layout.pool_id);
	up_read(&osdc->lock);
	if ((map_flags & CEPH_OSDMAP_FULL) ||
	    (pool_flags & CEPH_POOL_FLAG_FULL)) {
		err = -ENOSPC;
		goto out;
	}

	err = file_remove_privs(file);
	if (err)
		goto out;

	doutc(cl, "%p %llx.%llx %llu~%zd getting caps. i_size %llu\n",
	      inode, ceph_vinop(inode), pos, count,
	      i_size_read(inode));
	if (!(fi->flags & CEPH_F_SYNC) && !direct_lock)
		want |= CEPH_CAP_FILE_BUFFER;
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want |= CEPH_CAP_FILE_LAZYIO;
	got = 0;
	err = ceph_get_caps(file, CEPH_CAP_FILE_WR, want, pos + count, &got);
	if (err < 0)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out_caps;

	inode_inc_iversion_raw(inode);

	doutc(cl, "%p %llx.%llx %llu~%zd got cap refs on %s\n",
	      inode, ceph_vinop(inode), pos, count, ceph_cap_string(got));

	/* Get the snap this write is going to belong to. */
	snapc = ceph_get_most_recent_snapc(inode);

	if ((got & (CEPH_CAP_FILE_BUFFER|CEPH_CAP_FILE_LAZYIO)) == 0 ||
	    (iocb->ki_flags & IOCB_DIRECT) || (fi->flags & CEPH_F_SYNC) ||
	    test_bit(CEPH_I_ERROR_WRITE_BIT, &ci->i_ceph_flags)) {
		struct iov_iter data;

		/* we might need to revert back to that point */
		data = *from;
		written = netfs_unbuffered_write_iter_locked(iocb, &data, &snapc->group);
		if (direct_lock)
			netfs_end_io_direct(inode);
		else
			netfs_end_io_write(inode);
		if (written > 0)
			iov_iter_advance(from, written);
		ceph_put_snap_context(snapc);
	} else {
		/*
		 * No need to acquire the i_truncate_mutex.  Because the MDS
		 * revokes Fwb caps before sending truncate message to us.  We
		 * can't get Fwb cap while there are pending vmtruncate.  So
		 * write and vmtruncate can not run at the same time
		 */
		written = netfs_perform_write(iocb, from, &snapc->group, &prealloc_cf);
		netfs_end_io_write(inode);
	}

	if (written >= 0) {
		int dirty;

		spin_lock(&ci->i_ceph_lock);
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR,
					       &prealloc_cf);
		spin_unlock(&ci->i_ceph_lock);
		if (dirty)
			__mark_inode_dirty(inode, dirty);
		if (ceph_quota_is_max_bytes_approaching(inode, iocb->ki_pos))
			ceph_check_caps(ci, CHECK_CAPS_FLUSH);
	}

	doutc(cl, "%p %llx.%llx %llu~%u  dropping cap refs on %s\n",
	      inode, ceph_vinop(inode), pos, (unsigned)count,
	      ceph_cap_string(got));
	ceph_put_cap_refs(ci, got);

	if (written == -EOLDSNAPC) {
		doutc(cl, "%p %llx.%llx %llu~%u" "got EOLDSNAPC, retrying\n",
		      inode, ceph_vinop(inode), pos, (unsigned)count);
		goto retry_snap;
	}

	if (written >= 0) {
		if ((map_flags & CEPH_OSDMAP_NEARFULL) ||
		    (pool_flags & CEPH_POOL_FLAG_NEARFULL))
			iocb->ki_flags |= IOCB_DSYNC;
		written = generic_write_sync(iocb, written);
	}

	goto out_unlocked;
out_caps:
	ceph_put_cap_refs(ci, got);
out:
	if (direct_lock)
		netfs_end_io_direct(inode);
	else
		netfs_end_io_write(inode);
out_unlocked:
	ceph_free_cap_flush(prealloc_cf);
	return written ? written : err;
}

vm_fault_t ceph_page_mkwrite(struct vm_fault *vmf)
{
	struct ceph_snap_context *snapc;
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_info *fi = vma->vm_file->private_data;
	struct ceph_cap_flush *prealloc_cf;
	struct folio *folio = page_folio(vmf->page);
	loff_t size = i_size_read(inode);
	loff_t off = folio_pos(folio);
	size_t len = folio_size(folio);
	int want, got, err;
	vm_fault_t ret = VM_FAULT_SIGBUS;

	if (ceph_inode_is_shutdown(inode))
		return ret;

	prealloc_cf = ceph_alloc_cap_flush();
	if (!prealloc_cf)
		return -ENOMEM;

	doutc(cl, "%llx.%llx %llu~%zd getting caps i_size %llu\n",
	      ceph_vinop(inode), off, len, size);
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_BUFFER | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_BUFFER;

	got = 0;
	err = ceph_get_caps(vma->vm_file, CEPH_CAP_FILE_WR, want, off + len, &got);
	if (err < 0)
		goto out_free;

	doutc(cl, "%llx.%llx %llu~%zd got cap refs on %s\n", ceph_vinop(inode),
	      off, len, ceph_cap_string(got));

	/* Get the snap this write is going to belong to. */
	snapc = ceph_get_most_recent_snapc(inode);

	ret = netfs_page_mkwrite(vmf, &snapc->group, &prealloc_cf);

	doutc(cl, "%llx.%llx %llu~%zd dropping cap refs on %s ret %x\n",
	      ceph_vinop(inode), off, len, ceph_cap_string(got), ret);
	ceph_put_cap_refs_async(ci, got);
out_free:
	ceph_free_cap_flush(prealloc_cf);
	if (err < 0)
		ret = vmf_error(err);
	return ret;
}
