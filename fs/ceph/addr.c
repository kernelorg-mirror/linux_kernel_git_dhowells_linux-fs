// SPDX-License-Identifier: GPL-2.0
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
#include "subvolume_metrics.h"
#include "crypto.h"
#include <linux/ceph/osd_client.h>
#include <linux/ceph/striper.h>

/*
 * Ceph address space ops.
 *
 * There are a few funny things going on here.
 *
 * The page->private field is used to reference a struct
 * ceph_snap_context for _every_ dirty page.  This indicates which
 * snapshot the page was logically dirtied in, and thus which snap
 * context needs to be associated with the osd write during writeback.
 *
 * Similarly, struct ceph_inode_info maintains a set of counters to
 * count dirty pages on the inode.  In the absence of snapshots,
 * i_wrbuffer_ref == i_wrbuffer_ref_head == the dirty page count.
 *
 * When a snapshot is taken (that is, when the client receives
 * notification that a snapshot was taken), each inode with caps and
 * with dirty pages (dirty pages implies there is a cap) gets a new
 * ceph_cap_snap in the i_cap_snaps list (which is sorted in ascending
 * order, new snaps go to the tail).  The i_wrbuffer_ref_head count is
 * moved to capsnap->dirty. (Unless a sync write is currently in
 * progress.  In that case, the capsnap is said to be "pending", new
 * writes cannot start, and the capsnap isn't "finalized" until the
 * write completes (or fails) and a final size/mtime for the inode for
 * that snap can be settled upon.)  i_wrbuffer_ref_head is reset to 0.
 *
 * On writeback, we must submit writes to the osd IN SNAP ORDER.  So,
 * we look for the first capsnap in i_cap_snaps and write out pages in
 * that snap context _only_.  Then we move on to the next capsnap,
 * eventually reaching the "live" or "head" context (i.e., pages that
 * are not yet snapped) and are writing the most recently dirtied
 * pages.
 *
 * Invalidate and so forth must take care to ensure the dirty page
 * accounting is preserved.
 */

/*
 * Dirty a page.  Optimistically adjust accounting, on the assumption
 * that we won't race with invalidate.  If we do, readjust.
 */
bool ceph_dirty_folio(struct address_space *mapping, struct folio *folio)
{
	struct inode *inode = mapping->host;
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct ceph_mds_client *mdsc = ceph_sb_to_mdsc(inode->i_sb);
	struct ceph_inode_info *ci;
	struct ceph_snap_context *snapc;
	struct netfs_group *group;

	if (folio_test_dirty(folio)) {
		doutc(cl, "%llx.%llx %p idx %lu -- already dirty\n",
		      ceph_vinop(inode), folio, folio->index);
		VM_BUG_ON_FOLIO(!folio_test_private(folio), folio);
		return false;
	}

	atomic64_inc(&mdsc->dirty_folios);

	ci = ceph_inode(inode);

	/* dirty the head */
	spin_lock(&ci->i_ceph_lock);
	if (__ceph_have_pending_cap_snap(ci)) {
		struct ceph_cap_snap *capsnap =
			list_last_entry(&ci->i_cap_snaps,
					struct ceph_cap_snap,
					ci_item);
		snapc = capsnap->context;
		capsnap->dirty_pages++;
	} else {
		snapc = ci->i_head_snapc;
		BUG_ON(!snapc);
		++ci->i_wrbuffer_ref_head;
	}

	/* Attach a reference to the snap/group to the folio. */
	group = netfs_folio_group(folio);
	if (group != &snapc->group) {
		netfs_set_group(folio, &snapc->group);
		if (group) {
			doutc(cl, "Different group %px != %px\n",
			      group, &snapc->group);
			netfs_put_group(group);
		}
	}

	if (ci->i_wrbuffer_ref == 0)
		ihold(inode);
	++ci->i_wrbuffer_ref;
	doutc(cl, "%llx.%llx %p idx %lu head %d/%d -> %d/%d "
	      "snapc %p seq %lld (%d snaps)\n",
	      ceph_vinop(inode), folio, folio->index,
	      ci->i_wrbuffer_ref-1, ci->i_wrbuffer_ref_head-1,
	      ci->i_wrbuffer_ref, ci->i_wrbuffer_ref_head,
	      snapc, snapc->seq, snapc->num_snaps);
	spin_unlock(&ci->i_ceph_lock);

	return netfs_dirty_folio(mapping, folio);
}

static void ceph_block_sigs(sigset_t *oldset)
{
	sigset_t mask;
	siginitsetinv(&mask, sigmask(SIGKILL));
	sigprocmask(SIG_BLOCK, &mask, oldset);
}

static void ceph_restore_sigs(sigset_t *oldset)
{
	sigprocmask(SIG_SETMASK, oldset, NULL);
}

/*
 * vm ops
 */
static vm_fault_t ceph_filemap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct ceph_file_info *fi = vma->vm_file->private_data;
	loff_t off = (loff_t)vmf->pgoff << PAGE_SHIFT;
	int want, got, err;
	sigset_t oldset;
	vm_fault_t ret = VM_FAULT_SIGBUS;

	if (ceph_inode_is_shutdown(inode))
		return ret;

	ceph_block_sigs(&oldset);

	doutc(cl, "%llx.%llx %llu trying to get caps\n",
	      ceph_vinop(inode), off);
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_CACHE | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_CACHE;

	got = 0;
	err = ceph_get_caps(vma->vm_file, CEPH_CAP_FILE_RD, want, -1, &got);
	if (err < 0)
		goto out_restore;

	doutc(cl, "%llx.%llx %llu got cap refs on %s\n", ceph_vinop(inode),
	      off, ceph_cap_string(got));

	if ((got & (CEPH_CAP_FILE_CACHE | CEPH_CAP_FILE_LAZYIO)) ||
	    !ceph_has_inline_data(ci)) {
		ret = filemap_fault(vmf);
		doutc(cl, "%llx.%llx %llu drop cap refs %s ret %x\n",
		      ceph_vinop(inode), off, ceph_cap_string(got), ret);
	} else
		err = -EAGAIN;

	ceph_put_cap_refs(ci, got);

	if (err != -EAGAIN)
		goto out_restore;

	/* read inline data */
	if (off >= PAGE_SIZE) {
		/* does not support inline data > PAGE_SIZE */
		ret = VM_FAULT_SIGBUS;
	} else {
		struct address_space *mapping = inode->i_mapping;
		struct page *page;

		filemap_invalidate_lock_shared(mapping);
		page = find_or_create_page(mapping, 0,
				mapping_gfp_constraint(mapping, ~__GFP_FS));
		if (!page) {
			ret = VM_FAULT_OOM;
			goto out_inline;
		}
		err = __ceph_do_getattr(inode, page,
					 CEPH_STAT_CAP_INLINE_DATA, true);
		if (err < 0 || off >= i_size_read(inode)) {
			unlock_page(page);
			put_page(page);
			ret = vmf_error(err);
			goto out_inline;
		}
		if (err < PAGE_SIZE)
			zero_user_segment(page, err, PAGE_SIZE);
		else
			flush_dcache_page(page);
		SetPageUptodate(page);
		vmf->page = page;
		ret = VM_FAULT_MAJOR | VM_FAULT_LOCKED;
out_inline:
		filemap_invalidate_unlock_shared(mapping);
		doutc(cl, "%llx.%llx %llu read inline data ret %x\n",
		      ceph_vinop(inode), off, ret);
	}
out_restore:
	ceph_restore_sigs(&oldset);
	if (err < 0)
		ret = vmf_error(err);

	return ret;
}

void ceph_fill_inline_data(struct inode *inode, struct page *locked_page,
			   char	*data, size_t len)
{
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	if (locked_page) {
		page = locked_page;
	} else {
		if (i_size_read(inode) == 0)
			return;
		page = find_or_create_page(mapping, 0,
					   mapping_gfp_constraint(mapping,
					   ~__GFP_FS));
		if (!page)
			return;
		if (PageUptodate(page)) {
			unlock_page(page);
			put_page(page);
			return;
		}
	}

	doutc(cl, "%p %llx.%llx len %zu locked_page %p\n", inode,
	      ceph_vinop(inode), len, locked_page);

	if (len > 0) {
		void *kaddr = kmap_atomic(page);
		memcpy(kaddr, data, len);
		kunmap_atomic(kaddr);
	}

	if (page != locked_page) {
		if (len < PAGE_SIZE)
			zero_user_segment(page, len, PAGE_SIZE);
		else
			flush_dcache_page(page);

		SetPageUptodate(page);
		unlock_page(page);
		put_page(page);
	}
}

int ceph_uninline_data(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(inode);
	struct ceph_client *cl = fsc->client;
	struct ceph_osd_request *req = NULL;
	struct ceph_cap_flush *prealloc_cf = NULL;
	struct folio *folio = NULL;
	struct ceph_snap_context *snapc = NULL;
	u64 inline_version = CEPH_INLINE_NONE;
	struct page *pages[1];
	int err = 0;
	u64 len;

	spin_lock(&ci->i_ceph_lock);
	inline_version = ci->i_inline_version;
	spin_unlock(&ci->i_ceph_lock);

	doutc(cl, "%llx.%llx inline_version %llu\n", ceph_vinop(inode),
	      inline_version);

	if (ceph_inode_is_shutdown(inode)) {
		err = -EIO;
		goto out;
	}

	if (inline_version == CEPH_INLINE_NONE)
		return 0;

	prealloc_cf = ceph_alloc_cap_flush();
	if (!prealloc_cf)
		return -ENOMEM;

	if (inline_version == 1) /* initial version, no data */
		goto out_uninline;

	down_read(&fsc->mdsc->snap_rwsem);
	spin_lock(&ci->i_ceph_lock);
	if (__ceph_have_pending_cap_snap(ci)) {
		struct ceph_cap_snap *capsnap =
				list_last_entry(&ci->i_cap_snaps,
						struct ceph_cap_snap,
						ci_item);
		snapc = ceph_get_snap_context(capsnap->context);
	} else {
		if (!ci->i_head_snapc) {
			ci->i_head_snapc = ceph_get_snap_context(
				ci->i_snap_realm->cached_context);
		}
		snapc = ceph_get_snap_context(ci->i_head_snapc);
	}
	spin_unlock(&ci->i_ceph_lock);
	up_read(&fsc->mdsc->snap_rwsem);

	folio = read_mapping_folio(inode->i_mapping, 0, file);
	if (IS_ERR(folio)) {
		err = PTR_ERR(folio);
		goto out;
	}

	folio_lock(folio);

	len = i_size_read(inode);
	if (len > folio_size(folio))
		len = folio_size(folio);

	req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout,
				    ceph_vino(inode), 0, &len, 0, 1,
				    CEPH_OSD_OP_CREATE, CEPH_OSD_FLAG_WRITE,
				    snapc, 0, 0, false);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out_unlock;
	}

	req->r_mtime = inode_get_mtime(inode);
	ceph_osdc_start_request(&fsc->client->osdc, req);
	err = ceph_osdc_wait_request(&fsc->client->osdc, req);
	ceph_osdc_put_request(req);
	if (err < 0)
		goto out_unlock;

	req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout,
				    ceph_vino(inode), 0, &len, 1, 3,
				    CEPH_OSD_OP_WRITE, CEPH_OSD_FLAG_WRITE,
				    snapc, ci->i_truncate_seq,
				    ci->i_truncate_size, false);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out_unlock;
	}

	pages[0] = folio_page(folio, 0);
	osd_req_op_extent_osd_data_pages(req, 1, pages, len, 0, false, false);

	{
		__le64 xattr_buf = cpu_to_le64(inline_version);
		err = osd_req_op_xattr_init(req, 0, CEPH_OSD_OP_CMPXATTR,
					    "inline_version", &xattr_buf,
					    sizeof(xattr_buf),
					    CEPH_OSD_CMPXATTR_OP_GT,
					    CEPH_OSD_CMPXATTR_MODE_U64);
		if (err)
			goto out_put_req;
	}

	{
		char xattr_buf[32];
		int xattr_len = snprintf(xattr_buf, sizeof(xattr_buf),
					 "%llu", inline_version);
		err = osd_req_op_xattr_init(req, 2, CEPH_OSD_OP_SETXATTR,
					    "inline_version",
					    xattr_buf, xattr_len, 0, 0);
		if (err)
			goto out_put_req;
	}

	req->r_mtime = inode_get_mtime(inode);
	ceph_osdc_start_request(&fsc->client->osdc, req);
	err = ceph_osdc_wait_request(&fsc->client->osdc, req);

	ceph_update_write_metrics(&fsc->mdsc->metric, req->r_start_latency,
				  req->r_end_latency, len, err);

out_uninline:
	if (!err) {
		int dirty;

		/* Set to CAP_INLINE_NONE and dirty the caps */
		down_read(&fsc->mdsc->snap_rwsem);
		spin_lock(&ci->i_ceph_lock);
		ci->i_inline_version = CEPH_INLINE_NONE;
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR, &prealloc_cf);
		spin_unlock(&ci->i_ceph_lock);
		up_read(&fsc->mdsc->snap_rwsem);
		if (dirty)
			__mark_inode_dirty(inode, dirty);
	}
out_put_req:
	ceph_osdc_put_request(req);
	if (err == -ECANCELED)
		err = 0;
out_unlock:
	if (folio) {
		folio_unlock(folio);
		folio_put(folio);
	}
out:
	ceph_put_snap_context(snapc);
	ceph_free_cap_flush(prealloc_cf);
	doutc(cl, "%llx.%llx inline_version %llu = %d\n",
	      ceph_vinop(inode), inline_version, err);
	return err;
}

static const struct vm_operations_struct ceph_vmops = {
	.fault		= ceph_filemap_fault,
	.page_mkwrite	= ceph_page_mkwrite,
};

int ceph_mmap_prepare(struct vm_area_desc *desc)
{
	struct address_space *mapping = desc->file->f_mapping;

	if (!mapping->a_ops->read_folio)
		return -ENOEXEC;
	desc->vm_ops = &ceph_vmops;
	return 0;
}

enum {
	POOL_READ	= 1,
	POOL_WRITE	= 2,
};

static int __ceph_pool_perm_get(struct ceph_inode_info *ci,
				s64 pool, struct ceph_string *pool_ns)
{
	struct ceph_fs_client *fsc = ceph_inode_to_fs_client(&ci->netfs.inode);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_client *cl = fsc->client;
	struct ceph_osd_request *rd_req = NULL, *wr_req = NULL;
	struct rb_node **p, *parent;
	struct ceph_pool_perm *perm;
	struct page **pages;
	size_t pool_ns_len;
	int err = 0, err2 = 0, have = 0;

	down_read(&mdsc->pool_perm_rwsem);
	p = &mdsc->pool_perm_tree.rb_node;
	while (*p) {
		perm = rb_entry(*p, struct ceph_pool_perm, node);
		if (pool < perm->pool)
			p = &(*p)->rb_left;
		else if (pool > perm->pool)
			p = &(*p)->rb_right;
		else {
			int ret = ceph_compare_string(pool_ns,
						perm->pool_ns,
						perm->pool_ns_len);
			if (ret < 0)
				p = &(*p)->rb_left;
			else if (ret > 0)
				p = &(*p)->rb_right;
			else {
				have = perm->perm;
				break;
			}
		}
	}
	up_read(&mdsc->pool_perm_rwsem);
	if (*p)
		goto out;

	if (pool_ns)
		doutc(cl, "pool %lld ns %.*s no perm cached\n", pool,
		      (int)pool_ns->len, pool_ns->str);
	else
		doutc(cl, "pool %lld no perm cached\n", pool);

	down_write(&mdsc->pool_perm_rwsem);
	p = &mdsc->pool_perm_tree.rb_node;
	parent = NULL;
	while (*p) {
		parent = *p;
		perm = rb_entry(parent, struct ceph_pool_perm, node);
		if (pool < perm->pool)
			p = &(*p)->rb_left;
		else if (pool > perm->pool)
			p = &(*p)->rb_right;
		else {
			int ret = ceph_compare_string(pool_ns,
						perm->pool_ns,
						perm->pool_ns_len);
			if (ret < 0)
				p = &(*p)->rb_left;
			else if (ret > 0)
				p = &(*p)->rb_right;
			else {
				have = perm->perm;
				break;
			}
		}
	}
	if (*p) {
		up_write(&mdsc->pool_perm_rwsem);
		goto out;
	}

	rd_req = ceph_osdc_alloc_request(&fsc->client->osdc, NULL,
					 1, false, GFP_NOFS);
	if (!rd_req) {
		err = -ENOMEM;
		goto out_unlock;
	}

	rd_req->r_flags = CEPH_OSD_FLAG_READ;
	osd_req_op_init(rd_req, 0, CEPH_OSD_OP_STAT, 0);
	rd_req->r_base_oloc.pool = pool;
	if (pool_ns)
		rd_req->r_base_oloc.pool_ns = ceph_get_string(pool_ns);
	ceph_oid_printf(&rd_req->r_base_oid, "%llx.00000000", ci->i_vino.ino);

	err = ceph_osdc_alloc_messages(rd_req, GFP_NOFS);
	if (err)
		goto out_unlock;

	wr_req = ceph_osdc_alloc_request(&fsc->client->osdc, NULL,
					 1, false, GFP_NOFS);
	if (!wr_req) {
		err = -ENOMEM;
		goto out_unlock;
	}

	wr_req->r_flags = CEPH_OSD_FLAG_WRITE;
	osd_req_op_init(wr_req, 0, CEPH_OSD_OP_CREATE, CEPH_OSD_OP_FLAG_EXCL);
	ceph_oloc_copy(&wr_req->r_base_oloc, &rd_req->r_base_oloc);
	ceph_oid_copy(&wr_req->r_base_oid, &rd_req->r_base_oid);

	err = ceph_osdc_alloc_messages(wr_req, GFP_NOFS);
	if (err)
		goto out_unlock;

	/* one page should be large enough for STAT data */
	pages = ceph_alloc_page_vector(1, GFP_KERNEL);
	if (IS_ERR(pages)) {
		err = PTR_ERR(pages);
		goto out_unlock;
	}

	osd_req_op_raw_data_in_pages(rd_req, 0, pages, PAGE_SIZE,
				     0, false, true);
	ceph_osdc_start_request(&fsc->client->osdc, rd_req);

	wr_req->r_mtime = inode_get_mtime(&ci->netfs.inode);
	ceph_osdc_start_request(&fsc->client->osdc, wr_req);

	err = ceph_osdc_wait_request(&fsc->client->osdc, rd_req);
	err2 = ceph_osdc_wait_request(&fsc->client->osdc, wr_req);

	if (err >= 0 || err == -ENOENT)
		have |= POOL_READ;
	else if (err != -EPERM) {
		if (err == -EBLOCKLISTED)
			fsc->blocklisted = true;
		goto out_unlock;
	}

	if (err2 == 0 || err2 == -EEXIST)
		have |= POOL_WRITE;
	else if (err2 != -EPERM) {
		if (err2 == -EBLOCKLISTED)
			fsc->blocklisted = true;
		err = err2;
		goto out_unlock;
	}

	pool_ns_len = pool_ns ? pool_ns->len : 0;
	perm = kmalloc_flex(*perm, pool_ns, pool_ns_len + 1, GFP_NOFS);
	if (!perm) {
		err = -ENOMEM;
		goto out_unlock;
	}

	perm->pool = pool;
	perm->perm = have;
	perm->pool_ns_len = pool_ns_len;
	if (pool_ns_len > 0)
		memcpy(perm->pool_ns, pool_ns->str, pool_ns_len);
	perm->pool_ns[pool_ns_len] = 0;

	rb_link_node(&perm->node, parent, p);
	rb_insert_color(&perm->node, &mdsc->pool_perm_tree);
	err = 0;
out_unlock:
	up_write(&mdsc->pool_perm_rwsem);

	ceph_osdc_put_request(rd_req);
	ceph_osdc_put_request(wr_req);
out:
	if (!err)
		err = have;
	if (pool_ns)
		doutc(cl, "pool %lld ns %.*s result = %d\n", pool,
		      (int)pool_ns->len, pool_ns->str, err);
	else
		doutc(cl, "pool %lld result = %d\n", pool, err);
	return err;
}

int ceph_pool_perm_check(struct inode *inode, int need)
{
	struct ceph_client *cl = ceph_inode_to_client(inode);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_string *pool_ns;
	s64 pool;
	int ret;
	unsigned long flags;

	/* Only need to do this for regular files */
	if (!S_ISREG(inode->i_mode))
		return 0;

	if (ci->i_vino.snap != CEPH_NOSNAP) {
		/*
		 * Pool permission check needs to write to the first object.
		 * But for snapshot, head of the first object may have already
		 * been deleted. Skip check to avoid creating orphan object.
		 */
		return 0;
	}

	if (ceph_test_mount_opt(ceph_inode_to_fs_client(inode),
				NOPOOLPERM))
		return 0;

	spin_lock(&ci->i_ceph_lock);
	flags = ci->i_ceph_flags;
	pool = ci->i_layout.pool_id;
	spin_unlock(&ci->i_ceph_lock);
check:
	if (flags & CEPH_I_POOL_PERM) {
		if ((need & CEPH_CAP_FILE_RD) && !(flags & CEPH_I_POOL_RD)) {
			doutc(cl, "pool %lld no read perm\n", pool);
			return -EPERM;
		}
		if ((need & CEPH_CAP_FILE_WR) && !(flags & CEPH_I_POOL_WR)) {
			doutc(cl, "pool %lld no write perm\n", pool);
			return -EPERM;
		}
		return 0;
	}

	pool_ns = ceph_try_get_string(ci->i_layout.pool_ns);
	ret = __ceph_pool_perm_get(ci, pool, pool_ns);
	ceph_put_string(pool_ns);
	if (ret < 0)
		return ret;

	spin_lock(&ci->i_ceph_lock);
	if (pool == ci->i_layout.pool_id &&
	    pool_ns == rcu_dereference_raw(ci->i_layout.pool_ns)) {
		set_bit(CEPH_I_POOL_PERM_BIT, &ci->i_ceph_flags);
		if (ret & POOL_READ)
			set_bit(CEPH_I_POOL_RD_BIT, &ci->i_ceph_flags);
		if (ret & POOL_WRITE)
			set_bit(CEPH_I_POOL_WR_BIT, &ci->i_ceph_flags);
	} else {
		pool = ci->i_layout.pool_id;
	}
	/* Re-read flags under the lock so check: sees the updated bits. */
	flags = ci->i_ceph_flags;
	spin_unlock(&ci->i_ceph_lock);
	goto check;
}

void ceph_pool_perm_destroy(struct ceph_mds_client *mdsc)
{
	struct ceph_pool_perm *perm;
	struct rb_node *n;

	while (!RB_EMPTY_ROOT(&mdsc->pool_perm_tree)) {
		n = rb_first(&mdsc->pool_perm_tree);
		perm = rb_entry(n, struct ceph_pool_perm, node);
		rb_erase(n, &mdsc->pool_perm_tree);
		kfree(perm);
	}
}
