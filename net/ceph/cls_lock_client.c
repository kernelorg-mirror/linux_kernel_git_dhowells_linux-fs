// SPDX-License-Identifier: GPL-2.0
#include <linux/ceph/ceph_debug.h>

#include <linux/types.h>
#include <linux/slab.h>

#include <linux/ceph/cls_lock_client.h>
#include <linux/ceph/decode.h>
#include <linux/ceph/libceph.h>

/**
 * ceph_cls_lock - grab rados lock for object
 * @osdc: OSD client instance
 * @oid: object to lock
 * @oloc: object to lock
 * @lock_name: the name of the lock
 * @type: lock type (CEPH_CLS_LOCK_EXCLUSIVE or CEPH_CLS_LOCK_SHARED)
 * @cookie: user-defined identifier for this instance of the lock
 * @tag: user-defined tag
 * @desc: user-defined lock description
 * @flags: lock flags
 *
 * All operations on the same lock should use the same tag.
 */
int ceph_cls_lock(struct ceph_osd_client *osdc,
		  struct ceph_object_id *oid,
		  struct ceph_object_locator *oloc,
		  char *lock_name, u8 type, char *cookie,
		  char *tag, char *desc, u8 flags)
{
	int lock_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	int tag_len = strlen(tag);
	int desc_len = strlen(desc);
	void *p, *end;
	struct bvecq *lock_op_req;
	struct timespec64 mtime;
	int ret;

	lock_op_buf_size = name_len + sizeof(__le32) +
			   cookie_len + sizeof(__le32) +
			   tag_len + sizeof(__le32) +
			   desc_len + sizeof(__le32) +
			   sizeof(struct ceph_timespec) +
			   /* flag and type */
			   sizeof(u8) + sizeof(u8) +
			   CEPH_ENCODING_START_BLK_LEN;
	if (lock_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	lock_op_req = ceph_alloc_frag(lock_op_buf_size, GFP_NOIO);
	if (!lock_op_req)
		return -ENOMEM;

	p = ceph_map_enc_start(lock_op_req);
	end = p + lock_op_buf_size;

	/* encode cls_lock_lock_op struct */
	ceph_start_encoding(&p, 1, 1,
			    lock_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_8(&p, type);
	ceph_encode_string(&p, end, cookie, cookie_len);
	ceph_encode_string(&p, end, tag, tag_len);
	ceph_encode_string(&p, end, desc, desc_len);
	/* only support infinite duration */
	memset(&mtime, 0, sizeof(mtime));
	ceph_encode_timespec64(p, &mtime);
	p += sizeof(struct ceph_timespec);
	ceph_encode_8(&p, flags);
	ceph_map_enc_stop(lock_op_req, p);

	dout("%s lock_name %s type %d cookie %s tag %s desc %s flags 0x%x\n",
	     __func__, lock_name, type, cookie, tag, desc, flags);
	ret = ceph_osdc_call(osdc, oid, oloc, "lock", "lock",
			     CEPH_OSD_FLAG_WRITE, lock_op_req,
			     lock_op_buf_size, NULL, NULL);

	dout("%s: status %d\n", __func__, ret);
	bvecq_put(lock_op_req);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_lock);

/**
 * ceph_cls_unlock - release rados lock for object
 * @osdc: OSD client instance
 * @oid: object to lock
 * @oloc: object to lock
 * @lock_name: the name of the lock
 * @cookie: user-defined identifier for this instance of the lock
 */
int ceph_cls_unlock(struct ceph_osd_client *osdc,
		    struct ceph_object_id *oid,
		    struct ceph_object_locator *oloc,
		    char *lock_name, char *cookie)
{
	int unlock_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	void *p, *end;
	struct bvecq *unlock_op_req;
	int ret;

	unlock_op_buf_size = name_len + sizeof(__le32) +
			     cookie_len + sizeof(__le32) +
			     CEPH_ENCODING_START_BLK_LEN;
	if (unlock_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	unlock_op_req = ceph_alloc_frag(unlock_op_buf_size, GFP_NOIO);
	if (!unlock_op_req)
		return -ENOMEM;

	p = ceph_map_enc_start(unlock_op_req);
	end = p + unlock_op_buf_size;

	/* encode cls_lock_unlock_op struct */
	ceph_start_encoding(&p, 1, 1,
			    unlock_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_string(&p, end, cookie, cookie_len);
	ceph_map_enc_stop(unlock_op_req, p);

	dout("%s lock_name %s cookie %s\n", __func__, lock_name, cookie);
	ret = ceph_osdc_call(osdc, oid, oloc, "lock", "unlock",
			     CEPH_OSD_FLAG_WRITE, unlock_op_req,
			     unlock_op_buf_size, NULL, NULL);

	dout("%s: status %d\n", __func__, ret);
	bvecq_put(unlock_op_req);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_unlock);

/**
 * ceph_cls_break_lock - release rados lock for object for specified client
 * @osdc: OSD client instance
 * @oid: object to lock
 * @oloc: object to lock
 * @lock_name: the name of the lock
 * @cookie: user-defined identifier for this instance of the lock
 * @locker: current lock owner
 */
int ceph_cls_break_lock(struct ceph_osd_client *osdc,
			struct ceph_object_id *oid,
			struct ceph_object_locator *oloc,
			char *lock_name, char *cookie,
			struct ceph_entity_name *locker)
{
	int break_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	struct bvecq *break_op_req;
	void *p, *end;
	int ret;

	break_op_buf_size = name_len + sizeof(__le32) +
			    cookie_len + sizeof(__le32) +
			    sizeof(u8) + sizeof(__le64) +
			    CEPH_ENCODING_START_BLK_LEN;
	if (break_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	break_op_req = ceph_alloc_frag(break_op_buf_size, GFP_NOIO);
	if (!break_op_req)
		return -ENOMEM;

	p = ceph_map_enc_start(break_op_req);
	end = p + break_op_buf_size;

	/* encode cls_lock_break_op struct */
	ceph_start_encoding(&p, 1, 1,
			    break_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_copy(&p, locker, sizeof(*locker));
	ceph_encode_string(&p, end, cookie, cookie_len);
	ceph_map_enc_stop(break_op_req, p);

	dout("%s lock_name %s cookie %s locker %s%llu\n", __func__, lock_name,
	     cookie, ENTITY_NAME(*locker));
	ret = ceph_osdc_call(osdc, oid, oloc, "lock", "break_lock",
			     CEPH_OSD_FLAG_WRITE, break_op_req,
			     break_op_buf_size, NULL, NULL);

	dout("%s: status %d\n", __func__, ret);
	bvecq_put(break_op_req);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_break_lock);

int ceph_cls_set_cookie(struct ceph_osd_client *osdc,
			struct ceph_object_id *oid,
			struct ceph_object_locator *oloc,
			char *lock_name, u8 type, char *old_cookie,
			char *tag, char *new_cookie)
{
	int cookie_op_buf_size;
	int name_len = strlen(lock_name);
	int old_cookie_len = strlen(old_cookie);
	int tag_len = strlen(tag);
	int new_cookie_len = strlen(new_cookie);
	void *p, *end;
	struct bvecq *cookie_op_req;
	int ret;

	cookie_op_buf_size = name_len + sizeof(__le32) +
			     old_cookie_len + sizeof(__le32) +
			     tag_len + sizeof(__le32) +
			     new_cookie_len + sizeof(__le32) +
			     sizeof(u8) + CEPH_ENCODING_START_BLK_LEN;
	if (cookie_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	cookie_op_req = ceph_alloc_frag(cookie_op_buf_size, GFP_NOIO);
	if (!cookie_op_req)
		return -ENOMEM;

	p = ceph_map_enc_start(cookie_op_req);
	end = p + cookie_op_buf_size;

	/* encode cls_lock_set_cookie_op struct */
	ceph_start_encoding(&p, 1, 1,
			    cookie_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_8(&p, type);
	ceph_encode_string(&p, end, old_cookie, old_cookie_len);
	ceph_encode_string(&p, end, tag, tag_len);
	ceph_encode_string(&p, end, new_cookie, new_cookie_len);
	ceph_map_enc_stop(cookie_op_req, p);

	dout("%s lock_name %s type %d old_cookie %s tag %s new_cookie %s\n",
	     __func__, lock_name, type, old_cookie, tag, new_cookie);
	ret = ceph_osdc_call(osdc, oid, oloc, "lock", "set_cookie",
			     CEPH_OSD_FLAG_WRITE, cookie_op_req,
			     cookie_op_buf_size, NULL, NULL);

	dout("%s: status %d\n", __func__, ret);
	bvecq_put(cookie_op_req);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_set_cookie);

void ceph_free_lockers(struct ceph_locker *lockers, u32 num_lockers)
{
	int i;

	for (i = 0; i < num_lockers; i++)
		kfree(lockers[i].id.cookie);
	kfree(lockers);
}
EXPORT_SYMBOL(ceph_free_lockers);

static int decode_locker(void **p, void *end, struct ceph_locker *locker)
{
	u8 struct_v;
	u32 len;
	char *s;
	int ret;

	ret = ceph_start_decoding(p, end, 1, "locker_id_t", &struct_v, &len);
	if (ret)
		return ret;

	ceph_decode_copy_safe(p, end, &locker->id.name,
			      sizeof(locker->id.name), bad);
	s = ceph_extract_encoded_string(p, end, NULL, GFP_NOIO);
	if (IS_ERR(s))
		return PTR_ERR(s);

	locker->id.cookie = s;

	ret = ceph_start_decoding(p, end, 1, "locker_info_t", &struct_v, &len);
	if (ret)
		return ret;

	/* skip expiration */
	ceph_decode_skip_n(p, end, sizeof(struct ceph_timespec), bad);

	ret = ceph_decode_entity_addr(p, end, &locker->info.addr);
	if (ret)
		return ret;

	/* skip description */
	ceph_decode_skip_string(p, end, bad);

	dout("%s %s%llu cookie %s addr %s\n", __func__,
	     ENTITY_NAME(locker->id.name), locker->id.cookie,
	     ceph_pr_addr(&locker->info.addr));
	return 0;

bad:
	return -EINVAL;
}

static int decode_lockers(void **p, void *end, u8 *type, char **tag,
			  struct ceph_locker **lockers, u32 *num_lockers)
{
	u8 struct_v;
	u32 struct_len;
	char *s;
	int i;
	int ret;

	ret = ceph_start_decoding(p, end, 1, "cls_lock_get_info_reply",
				  &struct_v, &struct_len);
	if (ret)
		return ret;

	ceph_decode_32_safe(p, end, *num_lockers, err_inval);
	*lockers = kzalloc_objs(**lockers, *num_lockers, GFP_NOIO);
	if (!*lockers)
		return -ENOMEM;

	for (i = 0; i < *num_lockers; i++) {
		ret = decode_locker(p, end, *lockers + i);
		if (ret)
			goto err_free_lockers;
	}

	ret = -EINVAL;
	ceph_decode_8_safe(p, end, *type, err_free_lockers);
	s = ceph_extract_encoded_string(p, end, NULL, GFP_NOIO);
	if (IS_ERR(s)) {
		ret = PTR_ERR(s);
		goto err_free_lockers;
	}

	*tag = s;
	return 0;

err_inval:
	return -EINVAL;

err_free_lockers:
	ceph_free_lockers(*lockers, *num_lockers);
	return ret;
}

/*
 * On success, the caller is responsible for:
 *
 *     kfree(tag);
 *     ceph_free_lockers(lockers, num_lockers);
 */
int ceph_cls_lock_info(struct ceph_osd_client *osdc,
		       struct ceph_object_id *oid,
		       struct ceph_object_locator *oloc,
		       char *lock_name, u8 *type, char **tag,
		       struct ceph_locker **lockers, u32 *num_lockers)
{
	struct bvecq *request, *reply;
	int get_info_op_buf_size;
	int name_len = strlen(lock_name);
	size_t reply_len = PAGE_SIZE;
	void *p, *end;
	int ret = -ENOMEM;

	get_info_op_buf_size = name_len + sizeof(__le32) +
			       CEPH_ENCODING_START_BLK_LEN;
	if (get_info_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	request = ceph_alloc_frag(get_info_op_buf_size, GFP_NOIO);
	if (!request)
		return -ENOMEM;

	reply = bvecq_alloc_buffer(reply_len, GFP_NOIO, false);
	if (!reply)
		goto out;

	p = ceph_map_enc_start(request);
	end = p + get_info_op_buf_size;

	/* encode cls_lock_get_info_op struct */
	ceph_start_encoding(&p, 1, 1,
			    get_info_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_map_enc_stop(request, p);

	dout("%s lock_name %s\n", __func__, lock_name);
	ret = ceph_osdc_call(osdc, oid, oloc, "lock", "get_info",
			     CEPH_OSD_FLAG_READ,
			     request, get_info_op_buf_size,
			     reply, &reply_len);

	dout("%s: status %d\n", __func__, ret);
	if (ret >= 0) {
		p = ceph_map_dec_start(reply);
		end = p + reply_len;

		ret = decode_lockers(&p, end, type, tag, lockers, num_lockers);
		ceph_map_dec_stop(reply, p);
	}

	bvecq_put(reply);
out:
	bvecq_put(request);
	return ret;
}
EXPORT_SYMBOL(ceph_cls_lock_info);

int ceph_cls_assert_locked(struct ceph_osd_request *req, int which,
			   char *lock_name, u8 type, char *cookie, char *tag)
{
	struct bvecq *dbuf;
	int assert_op_buf_size;
	int name_len = strlen(lock_name);
	int cookie_len = strlen(cookie);
	int tag_len = strlen(tag);
	void *p, *end;
	int ret;

	assert_op_buf_size = name_len + sizeof(__le32) +
			     cookie_len + sizeof(__le32) +
			     tag_len + sizeof(__le32) +
			     sizeof(u8) + CEPH_ENCODING_START_BLK_LEN;
	if (assert_op_buf_size > PAGE_SIZE)
		return -E2BIG;

	ret = osd_req_op_cls_init(req, which, "lock", "assert_locked");
	if (ret)
		return ret;

	dbuf = bvecq_alloc_buffer(assert_op_buf_size, GFP_NOIO, false);
	if (!dbuf)
		return -ENOMEM;

	p = kmap_local_bvecq(dbuf, 0);
	end = p + assert_op_buf_size;

	/* encode cls_lock_assert_op struct */
	ceph_start_encoding(&p, 1, 1,
			    assert_op_buf_size - CEPH_ENCODING_START_BLK_LEN);
	ceph_encode_string(&p, end, lock_name, name_len);
	ceph_encode_8(&p, type);
	ceph_encode_string(&p, end, cookie, cookie_len);
	ceph_encode_string(&p, end, tag, tag_len);
	kunmap(p);
	WARN_ON(p != end);

	osd_req_op_cls_request_bvecq(req, which, dbuf, assert_op_buf_size);
	return 0;
}
EXPORT_SYMBOL(ceph_cls_assert_locked);

