// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *   Jeremy Allison (jra@samba.org) 2006.
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/tcp.h>
#include <linux/bvec.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/processor.h>
#include <linux/mempool.h>
#include <linux/sched/signal.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/task_work.h>
#include <linux/iov_iter.h>
#include "rfc1002pdu.h"
#include "cifspdu.h"
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "smb2proto.h"
#include "smbdirect.h"
#include "compress.h"

/*
 * Allocate transmission buffers for a socket.  This memory will be allocated
 * from the netmem buffers.  It comes with a page ref that we need to drop.
 * The networking layer can pin it by getting its own ref.
 */
void *cifs_allocate_tx_buf(struct TCP_Server_Info *server, size_t size)
{
	void *p;

	mutex_lock(&server->tx_alloc_lock);
	p = page_frag_alloc_align(&server->tx_alloc, size, GFP_NOFS, 8);
	mutex_unlock(&server->tx_alloc_lock);
	return p;
}

void cifs_free_tx_buf(void *p)
{
	page_frag_free(p);
}

struct smb_message *smb_message_alloc(enum smb_command_trace cmd, gfp_t gfp)
{
	static atomic_t debug_ids;
	struct smb_message *smb;

	smb = mempool_alloc(&smb_message_pool, gfp);
	if (smb) {
		memset(smb, 0, sizeof(*smb));
		refcount_set(&smb->ref, 1);
		spin_lock_init(&smb->mid_lock);
		smb->debug_id	= atomic_inc_return(&debug_ids);
		smb->command_trace = cmd;
		smb->when_alloc	= jiffies;
		smb->pid	= current->pid;

		/*
		 * The default is for the mid to be synchronous, so the default
		 * callback just wakes up the current task.
		 */
		smb->callback		= cifs_wake_up_task;
		smb->mid_state		= MID_REQUEST_ALLOCATED;
		init_waitqueue_head(&smb->waitq);
		trace_smb3_message(smb->debug_id, 1, (enum smb_message_trace)cmd);
	}
	return smb;
}

void smb_see_message(struct smb_message *smb, enum smb_message_trace trace)
{
	trace_smb3_message(smb->debug_id, refcount_read(&smb->ref), trace);
}

void smb_get_message(struct smb_message *smb, enum smb_message_trace trace)
{
	int r;

	__refcount_inc(&smb->ref, &r);
	trace_smb3_message(smb->debug_id, r + 1, trace);
}

static void smb_free_message(struct smb_message *smb)
{
	trace_smb3_message(smb->debug_id, refcount_read(&smb->ref),
			   smb_message_trace_free);
	mempool_free(smb, &smb_message_pool);
}

/*
 * Drop a ref on a message.  This does not touch the chained messages.
 */
void smb_put_message(struct smb_message *smb, enum smb_message_trace trace)
{
	unsigned int debug_id = smb->debug_id;
	bool dead;
	int r;

	dead = __refcount_dec_and_test(&smb->ref, &r);
	trace_smb3_message(debug_id, r - 1, trace);
	if (dead)
		smb_free_message(smb);
}

/*
 * Dispose of a chain of compound messages.  This should only be called by the
 * caller of smb_send_recv_messages().
 */
void smb_put_messages(struct smb_message *smb)
{
	struct smb_message *next;

	for (; smb; smb = next) {
		unsigned int debug_id = smb->debug_id;
		bool dead;
		int r;

		next = smb->next;
		dead = __refcount_dec_and_test(&smb->ref, &r);
		trace_smb3_message(debug_id, r - 1, smb_message_trace_put_messages);
		if (dead)
			smb_free_message(smb);
	}
}

void
cifs_wake_up_task(struct TCP_Server_Info *server, struct smb_message *smb)
{
	if (smb->mid_state == MID_RESPONSE_RECEIVED)
		smb->mid_state = MID_RESPONSE_READY;
	smb_see_message(smb, smb_message_trace_see_wake_up_task);
	wake_up_all(&smb->waitq);
}

static void smb_clear_mid(struct TCP_Server_Info *server, struct smb_message *smb)
{
#ifdef CONFIG_CIFS_STATS2
	__le16 command = server->vals->lock_cmd;
	__u16 smb_cmd = le16_to_cpu(smb->command);
	unsigned long now;
	unsigned long roundtrip_time;
#endif

	if (smb->response && smb->wait_cancelled &&
	    (smb->mid_state == MID_RESPONSE_RECEIVED ||
	     smb->mid_state == MID_RESPONSE_READY) &&
	    server->ops->handle_cancelled_mid)
		server->ops->handle_cancelled_mid(smb, server);

	smb->mid_state = MID_FREE;
	atomic_dec(&mid_count);
	if (smb->large_buf)
		cifs_buf_release(smb->response);
	else
		cifs_small_buf_release(smb->response);
	if (smb->response_data)
		netfs_put_rx_bvecq(smb->response_data);
#ifdef CONFIG_CIFS_STATS2
	now = jiffies;
	if (now < smb->when_alloc)
		cifs_server_dbg(VFS, "Invalid mid allocation time\n");
	roundtrip_time = now - smb->when_alloc;

	if (smb_cmd < NUMBER_OF_SMB2_COMMANDS) {
		if (atomic_read(&server->num_cmds[smb_cmd]) == 0) {
			server->slowest_cmd[smb_cmd] = roundtrip_time;
			server->fastest_cmd[smb_cmd] = roundtrip_time;
		} else {
			if (server->slowest_cmd[smb_cmd] < roundtrip_time)
				server->slowest_cmd[smb_cmd] = roundtrip_time;
			else if (server->fastest_cmd[smb_cmd] > roundtrip_time)
				server->fastest_cmd[smb_cmd] = roundtrip_time;
		}
		cifs_stats_inc(&server->num_cmds[smb_cmd]);
		server->time_per_cmd[smb_cmd] += roundtrip_time;
	}
	/*
	 * commands taking longer than one second (default) can be indications
	 * that something is wrong, unless it is quite a slow link or a very
	 * busy server. Note that this calc is unlikely or impossible to wrap
	 * as long as slow_rsp_threshold is not set way above recommended max
	 * value (32767 ie 9 hours) and is generally harmless even if wrong
	 * since only affects debug counters - so leaving the calc as simple
	 * comparison rather than doing multiple conversions and overflow
	 * checks
	 */
	if ((slow_rsp_threshold != 0) &&
	    time_after(now, smb->when_alloc + (slow_rsp_threshold * HZ)) &&
	    (smb->command != command)) {
		/*
		 * smb2slowcmd[NUMBER_OF_SMB2_COMMANDS] counts by command
		 * NB: le16_to_cpu returns unsigned so can not be negative below
		 */
		if (smb_cmd < NUMBER_OF_SMB2_COMMANDS)
			cifs_stats_inc(&server->smb2slowcmd[smb_cmd]);

		trace_smb3_slow_rsp(smb_cmd, smb->mid, smb->pid,
				    smb->when_sent, smb->when_received);
		if (cifsFYI & CIFS_TIMER) {
			pr_debug("slow rsp: cmd %d mid %llu",
				 smb->command, smb->mid);
			cifs_info("A: 0x%lx S: 0x%lx R: 0x%lx\n",
				  now - smb->when_alloc,
				  now - smb->when_sent,
				  now - smb->when_received);
		}
	}
#endif
}

static bool discard_message(struct TCP_Server_Info *server, struct smb_message *smb)
{
	bool got_ref = false;

	spin_lock(&server->mid_queue_lock);

	if (!smb->deleted_from_q) {
		list_del_init(&smb->qhead);
		smb->deleted_from_q = true;
		got_ref = true;
	}

	spin_unlock(&server->mid_queue_lock);
	return got_ref;
}

static void smb_discard_messages(struct TCP_Server_Info *server, struct smb_message *head_smb)
{
	struct smb_message *smb, *next;

	for (smb = head_smb; smb; smb = next) {
		next = smb->next;
		if (discard_message(server, smb))
			smb_put_message(smb, smb_message_trace_put_discard_message);
	}
}

/*
 * smb_send_kvec - send an array of kvecs to the server
 * @server:	Server to send the data to
 * @smb_msg:	Message to send
 * @sent:	amount of data sent on socket is stored here
 *
 * Our basic "send data to server" function. Should be called with srv_mutex
 * held. The caller is responsible for handling the results.
 */
int
smb_send_kvec(struct TCP_Server_Info *server, struct msghdr *smb_msg,
	      size_t *sent)
{
	int rc = 0;
	int retries = 0;
	struct socket *ssocket = server->ssocket;

	*sent = 0;

	if (server->noblocksnd)
		smb_msg->msg_flags = MSG_DONTWAIT + MSG_NOSIGNAL;
	else
		smb_msg->msg_flags = MSG_NOSIGNAL;

	while (msg_data_left(smb_msg)) {
		/*
		 * If blocking send, we try 3 times, since each can block
		 * for 5 seconds. For nonblocking  we have to try more
		 * but wait increasing amounts of time allowing time for
		 * socket to clear.  The overall time we wait in either
		 * case to send on the socket is about 15 seconds.
		 * Similarly we wait for 15 seconds for a response from
		 * the server in SendReceive[2] for the server to send
		 * a response back for most types of requests (except
		 * SMB Write past end of file which can be slow, and
		 * blocking lock operations). NFS waits slightly longer
		 * than CIFS, but this can make it take longer for
		 * nonresponsive servers to be detected and 15 seconds
		 * is more than enough time for modern networks to
		 * send a packet.  In most cases if we fail to send
		 * after the retries we will kill the socket and
		 * reconnect which may clear the network problem.
		 *
		 * Even if regular signals are masked, EINTR might be
		 * propagated from sk_stream_wait_memory() to here when
		 * TIF_NOTIFY_SIGNAL is used for task work. For example,
		 * certain io_uring completions will use that. Treat
		 * having EINTR with pending task work the same as EAGAIN
		 * to avoid unnecessary reconnects.
		 */
		rc = sock_sendmsg(ssocket, smb_msg);
		if (rc == -EAGAIN || unlikely(rc == -EINTR && task_work_pending(current))) {
			retries++;
			if (retries >= 14 ||
			    (!server->noblocksnd && (retries > 2))) {
				cifs_server_dbg(VFS, "sends on sock %p stuck for 15 seconds\n",
					 ssocket);
				return -EAGAIN;
			}
			msleep(1 << retries);
			continue;
		}

		if (rc < 0)
			return rc;

		if (rc == 0) {
			/* should never happen, letting socket clear before
			   retrying is our only obvious option here */
			cifs_server_dbg(VFS, "tcp sent no data\n");
			msleep(500);
			continue;
		}

		/* send was at least partially successful */
		*sent += rc;
		retries = 0; /* in case we get ENOSPC on the next send */
	}
	return 0;
}

/*
 * smb_sendmsg - send a buffer to the socket
 * @server:	Server to send the data to
 * @iter:	The data to send (not advanced)
 * @sent:	The amount of data sent
 *
 * Our basic "send data to server" function. Should be called with srv_mutex
 * held. The caller is responsible for handling the results.
 */
static int smb_sendmsg(struct TCP_Server_Info *server, const struct iov_iter *iter,
		       size_t *sent)
{
	struct socket *ssocket = server->ssocket;
	struct msghdr msg = {
		/*
		 * MSG_SPLICE_PAGES causes tcp_sendmsg() to splice in the pages
		 * in the iterator rather than copying from them; MSG_EOR
		 * indicates that the last TCP packet we create should be
		 * marked no-append with regards to the next sendmsg.
		 */
		.msg_flags	= MSG_NOSIGNAL | MSG_SPLICE_PAGES | MSG_EOR,
		.msg_iter	= *iter,
	};
	int retries = 0;
	int rc = 0;

	*sent = 0;
	if (server->noblocksnd)
		msg.msg_flags = MSG_DONTWAIT;

	while (msg_data_left(&msg)) {
		/*
		 * If blocking send, we try 3 times, since each can block for 5
		 * seconds. For nonblocking we have to try more but wait
		 * increasing amounts of time allowing time for socket to
		 * clear.  The overall time we wait in either case to send on
		 * the socket is about 15 seconds.  Similarly we wait for 15
		 * seconds for a response from the server in SendReceive[2] for
		 * the server to send a response back for most types of
		 * requests (except SMB Write past end of file which can be
		 * slow, and blocking lock operations). NFS waits slightly
		 * longer than CIFS, but this can make it take longer for
		 * nonresponsive servers to be detected and 15 seconds is more
		 * than enough time for modern networks to send a packet.  In
		 * most cases if we fail to send after the retries we will kill
		 * the socket and reconnect which may clear the network
		 * problem.
		 */
		rc = sock_sendmsg(ssocket, &msg);
		if (rc == -EAGAIN) {
			retries++;
			if (retries >= 14 ||
			    (!server->noblocksnd && (retries > 2))) {
				cifs_server_dbg(VFS, "sends on sock %p stuck for 15 seconds\n",
					 ssocket);
				return -EAGAIN;
			}
			msleep(1 << retries);
			continue;
		}

		if (rc < 0)
			return rc;

		if (rc == 0) {
			/* should never happen, letting socket clear before
			   retrying is our only obvious option here */
			cifs_server_dbg(VFS, "tcp sent no data\n");
			msleep(500);
			continue;
		}

		*sent += rc;

		/* send was at least partially successful */
		retries = 0; /* in case we get ENOSPC on the next send */
	}
	return 0;
}

int
__smb_send_rqst(struct TCP_Server_Info *server, struct iov_iter *iter)
{
	struct socket *ssocket = server->ssocket;
	sigset_t mask, oldmask;
	size_t total_to_send = iov_iter_count(iter), sent = 0;
	int rc;

	cifs_in_send_inc(server);
	if (cifs_rdma_enabled(server)) {
		/* return -EAGAIN when connecting or reconnecting */
		rc = -EAGAIN;
		if (server->smbd_conn) {
			iov_iter_advance(iter, 4);
			rc = smbd_send(server, iter);
		}
		goto smbd_done;
	}

	rc = -EAGAIN;
	if (ssocket == NULL)
		goto out;

	rc = -ERESTARTSYS;
	if (fatal_signal_pending(current)) {
		cifs_dbg(FYI, "signal pending before send request\n");
		goto out;
	}

	/*
	 * We should not allow signals to interrupt the network send because
	 * any partial send will cause session reconnects thus increasing
	 * latency of system calls and overload a server with unnecessary
	 * requests.
	 */

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);

	cifs_dbg(FYI, "Sending smb: smb_len=%zu\n", iov_iter_count(iter));
	rc = smb_sendmsg(server, iter, &sent);

	sigprocmask(SIG_SETMASK, &oldmask, NULL);

	if (sent > 0) {
		/*
		 * If signal is pending but we have already sent the whole
		 * packet to the server we need to return success status to
		 * allow a corresponding mid entry to be kept in the pending
		 * requests queue thus allowing to handle responses from the
		 * server by the client.
		 *
		 * If only part of the packet has been sent there is no need to
		 * hide interrupt because the session will be reconnected
		 * anyway, so there won't be any response from the server to
		 * handle.
		 */
		if (signal_pending(current)) {
			cifs_dbg(FYI, "signal is pending after attempt to send\n");
			rc = -ERESTARTSYS;
		}

		/*
		 * If we have only sent part of an SMB then the next SMB could
		 * be taken as the remainder of this one. We need to kill the
		 * socket so the server throws away the partial SMB
		 */
		if (sent != total_to_send) {
			cifs_dbg(FYI, "partial send (wanted=%zu sent=%zu): terminating session\n",
				 total_to_send, sent);
			cifs_signal_cifsd_for_reconnect(server, false);
			trace_smb3_partial_send_reconnect(server->current_mid,
							  server->conn_id, server->hostname);
		}
	}
smbd_done:
	/*
	 * there's hardly any use for the layers above to know the
	 * actual error code here. All they should do at this point is
	 * to retry the connection and hope it goes away.
	 */
	if (rc < 0 && rc != -EINTR && rc != -EAGAIN) {
		cifs_server_dbg(VFS, "Error %d sending data on socket to server\n",
			 rc);
		rc = -ECONNABORTED;
		cifs_signal_cifsd_for_reconnect(server, false);
	} else if (rc > 0)
		rc = 0;
out:
	cifs_in_send_dec(server);
	return rc;
}

static size_t smb3_copy_data_iter(void *iter_from, size_t progress, size_t len,
				  void *priv, void *priv2)
{
	struct iov_iter *iter = priv;
	return copy_to_iter(iter_from, len, iter) == len ? 0 : len;
}

/*
 * Copy the data into a buffer that we can use for encryption in place and also
 * pass to sendmsg() with MSG_SPLICE_PAGES.  This avoids a lot of copies in TCP
 * at the expense of doing it upfront here.  A spare slot is left in the bvec
 * queue at the front for the header(s).
 *
 * TODO: In future, the buffers should be allocated by the marshalling code.
 */
static int smb_copy_data_into_buffer(struct TCP_Server_Info *server,
				     struct smb_message *head_smb,
				     struct iov_iter *iter, struct bvecq **_bq,
				     unsigned int flags)
{
	struct smb_message *smb;
	struct bvecq *bq;
	size_t total_len = 0, offset = 0;
	int rc;

	for (smb = head_smb; smb; smb = smb->next) {
		total_len = ALIGN8(total_len);
		total_len += smb->total_len;
	}

	if (total_len <= PAGE_SIZE / 2) {
		/* TODO: Choose algo-based alignment. */
		unsigned int align = (flags & CIFS_TRANSFORM_REQ) ? 32 : 1;
		size_t alen = (flags & CIFS_TRANSFORM_REQ) ?
			round_up(total_len, align) : total_len;

		bq = bvecq_alloc_chain(2, GFP_NOFS, head_smb->writeback);
		if (!bq)
			return -ENOMEM;
		mutex_lock(&server->tx_alloc_lock);
		void *p = page_frag_alloc_align(&server->tx_alloc, alen,
						GFP_NOFS, align);
		mutex_unlock(&server->tx_alloc_lock);
		if (!p) {
			bvecq_put(bq);
			return -ENOMEM;
		}
		bvec_set_virt(&bq->bv[1], p, total_len);
		bq->nr_slots = 2;
		bq->mem_type = BVECQ_MEM_PAGECACHE;
	} else {
		bq = bvecq_alloc_buffer2(total_len, 1, GFP_NOFS, head_smb->writeback);
		if (!bq)
			return -ENOMEM;
	}

	iov_iter_bvec_queue(iter, ITER_DEST, bq, 1, 0, total_len);

	for (smb = head_smb; smb; smb = smb->next) {
		size_t size = iov_iter_count(&smb->rqst.rq_iter);
		size_t got;

		if (offset & 7) {
			unsigned int tmp = offset;
			offset = ALIGN8(offset);
			iov_iter_zero(offset - tmp, iter);
		}

		for (int i = 0; i < smb->rqst.rq_nvec; i++) {
			size_t len = smb->rqst.rq_iov[i].iov_len;
			got = copy_to_iter(smb->rqst.rq_iov[i].iov_base, len, iter);
			if (got != len) {
				rc = smb_EIO2(smb_eio_trace_tx_copy_to_buf, got, size);
				goto error;
			}
			offset += len;
		}

		got = iterate_and_advance_kernel(&smb->rqst.rq_iter,
						 size, iter, NULL,
						 smb3_copy_data_iter);
		if (got != size) {
			rc = smb_EIO2(smb_eio_trace_tx_copy_iter_to_buf, got, size);
			goto error;
		}

		offset += size;
	}

	if (WARN_ONCE(offset != total_len,
		      "offset=%zx total_len=%zx\n", offset, total_len)) {
		rc = smb_EIO2(smb_eio_trace_tx_miscopy_to_buf, offset, total_len);
		goto error;
	}

	iov_iter_bvec_queue(iter, ITER_DEST, bq, 1, 0, total_len);
	*_bq = bq;
	return 0;
error:
	bvecq_put(bq);
	*_bq = NULL;
	return rc;
}

static int
smb_send_rqst(struct TCP_Server_Info *server, struct smb_message *head_smb, int flags)
{
	struct iov_iter iter;
	struct bvecq *bq;
	u32 content_len;
	int rc;

	if ((flags & CIFS_TRANSFORM_REQ) &&
	    !server->ops->init_transform_rq) {
		cifs_server_dbg(VFS, "Encryption requested but transform callback is missing\n");
		return smb_EIO(smb_eio_trace_tx_need_transform);
	}

	rc = smb_copy_data_into_buffer(server, head_smb, &iter, &bq, flags);
	if (rc)
		return rc;
	content_len = iov_iter_count(&iter);

	{
		struct smb2_transform_hdr *tr_hdr;
		unsigned int hdr_len = 4, troff = 0;
		__le32 *rfc1002;
		void *hdr_blob;

		if (flags & CIFS_TRANSFORM_REQ) {
			troff = hdr_len;
			hdr_len += sizeof(*tr_hdr);
		}

		/* TODO: Allocate netmem here */
		rc = -ENOMEM;
		mutex_lock(&server->tx_alloc_lock);
		hdr_blob = page_frag_alloc(&server->tx_alloc, hdr_len, GFP_NOFS);
		mutex_unlock(&server->tx_alloc_lock);
		if (!hdr_blob)
			goto error;
		bvec_set_virt(&bq->bv[0], hdr_blob, hdr_len);

		if (flags & CIFS_COMPRESS_REQ) {
			struct smb2_write_req *whdr = bvec_virt(&bq->bv[1]);
			size_t doff = le16_to_cpu(whdr->DataOffset);

			iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 1, doff,
					    content_len - doff);

			if (is_compressible(&iter)) {
				iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 1, 0,
						    content_len);

				rc = smb_compress(server, &iter, &bq, flags);
				if (rc > 0) {
					content_len = rc;
				} else if (rc == -EMSGSIZE) {
					/* Fall back to uncompressed. */
				} else {
					if (rc == 0)
						rc = smb_EIO(smb_eio_trace_tx_compress_failed);
					goto error;
				}
			}
		}

		if (flags & CIFS_TRANSFORM_REQ) {
			iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 0, 0,
					    hdr_len + content_len);
			iov_iter_advance(&iter, troff);
			tr_hdr = hdr_blob + troff;

			rc = server->ops->init_transform_rq(server, head_smb, tr_hdr, &iter);
			if (rc)
				goto error;
			content_len += sizeof(*tr_hdr);
		} else {
			bvec_set_virt(&bq->bv[0], hdr_blob, hdr_len);
		}

		/* Set the RFC1002 header at the front. */
		rfc1002 = hdr_blob;
		*rfc1002 = cpu_to_be32(RFC1002_SESSION_MESSAGE << 24 | content_len);

		iov_iter_bvec_queue(&iter, ITER_SOURCE, bq, 0, 0, 4 + content_len);
	}
	rc = __smb_send_rqst(server, &iter);
error:
	bvecq_put(bq);
	return rc;
}

static int
wait_for_free_credits(struct TCP_Server_Info *server, const int num_credits,
		      const int timeout, const int flags,
		      unsigned int *instance)
{
	long rc;
	int *credits;
	int optype;
	long int t;
	int scredits, in_flight;

	if (timeout < 0)
		t = MAX_JIFFY_OFFSET;
	else
		t = msecs_to_jiffies(timeout);

	optype = flags & CIFS_OP_MASK;

	*instance = 0;

	credits = server->ops->get_credits_field(server, optype);
	/* Since an echo is already inflight, no need to wait to send another */
	if (*credits <= 0 && optype == CIFS_ECHO_OP)
		return -EAGAIN;

	spin_lock(&server->req_lock);
	if ((flags & CIFS_TIMEOUT_MASK) == CIFS_NON_BLOCKING) {
		/* oplock breaks must not be held up */
		server->in_flight++;
		if (server->in_flight > server->max_in_flight)
			server->max_in_flight = server->in_flight;
		*credits -= 1;
		*instance = server->reconnect_instance;
		scredits = *credits;
		in_flight = server->in_flight;
		spin_unlock(&server->req_lock);

		trace_smb3_nblk_credits(server->current_mid,
				server->conn_id, server->hostname, scredits, -1, in_flight);
		cifs_dbg(FYI, "%s: remove %u credits total=%d\n",
				__func__, 1, scredits);

		return 0;
	}

	while (1) {
		spin_unlock(&server->req_lock);

		spin_lock(&server->srv_lock);
		if (server->tcpStatus == CifsExiting) {
			spin_unlock(&server->srv_lock);
			return -ENOENT;
		}
		spin_unlock(&server->srv_lock);

		spin_lock(&server->req_lock);
		if (*credits < num_credits) {
			scredits = *credits;
			spin_unlock(&server->req_lock);

			cifs_num_waiters_inc(server);
			rc = wait_event_killable_timeout(server->request_q,
				has_credits(server, credits, num_credits), t);
			cifs_num_waiters_dec(server);
			if (!rc) {
				spin_lock(&server->req_lock);
				scredits = *credits;
				in_flight = server->in_flight;
				spin_unlock(&server->req_lock);

				trace_smb3_credit_timeout(server->current_mid,
						server->conn_id, server->hostname, scredits,
						num_credits, in_flight);
				cifs_server_dbg(VFS, "wait timed out after %d ms\n",
						timeout);
				return -EBUSY;
			}
			if (rc == -ERESTARTSYS)
				return -ERESTARTSYS;
			spin_lock(&server->req_lock);
		} else {
			/*
			 * For normal commands, reserve the last MAX_COMPOUND
			 * credits to compound requests.
			 * Otherwise these compounds could be permanently
			 * starved for credits by single-credit requests.
			 *
			 * To prevent spinning CPU, block this thread until
			 * there are >MAX_COMPOUND credits available.
			 * But only do this is we already have a lot of
			 * credits in flight to avoid triggering this check
			 * for servers that are slow to hand out credits on
			 * new sessions.
			 */
			if (!optype && num_credits == 1 &&
			    server->in_flight > 2 * MAX_COMPOUND &&
			    *credits <= MAX_COMPOUND) {
				spin_unlock(&server->req_lock);

				cifs_num_waiters_inc(server);
				rc = wait_event_killable_timeout(
					server->request_q,
					has_credits(server, credits,
						    MAX_COMPOUND + 1),
					t);
				cifs_num_waiters_dec(server);
				if (!rc) {
					spin_lock(&server->req_lock);
					scredits = *credits;
					in_flight = server->in_flight;
					spin_unlock(&server->req_lock);

					trace_smb3_credit_timeout(
							server->current_mid,
							server->conn_id, server->hostname,
							scredits, num_credits, in_flight);
					cifs_server_dbg(VFS, "wait timed out after %d ms\n",
							timeout);
					return -EBUSY;
				}
				if (rc == -ERESTARTSYS)
					return -ERESTARTSYS;
				spin_lock(&server->req_lock);
				continue;
			}

			/*
			 * Can not count locking commands against total
			 * as they are allowed to block on server.
			 */

			/* update # of requests on the wire to server */
			if ((flags & CIFS_TIMEOUT_MASK) != CIFS_BLOCKING_OP) {
				*credits -= num_credits;
				server->in_flight += num_credits;
				if (server->in_flight > server->max_in_flight)
					server->max_in_flight = server->in_flight;
				*instance = server->reconnect_instance;
			}
			scredits = *credits;
			in_flight = server->in_flight;
			spin_unlock(&server->req_lock);

			trace_smb3_waitff_credits(server->current_mid,
					server->conn_id, server->hostname, scredits,
					-(num_credits), in_flight);
			cifs_dbg(FYI, "%s: remove %u credits total=%d\n",
					__func__, num_credits, scredits);
			break;
		}
	}
	return 0;
}

int wait_for_free_request(struct TCP_Server_Info *server, const int flags,
			  unsigned int *instance)
{
	return wait_for_free_credits(server, 1, -1, flags,
				     instance);
}

static int
wait_for_compound_request(struct TCP_Server_Info *server, int num,
			  const int flags, unsigned int *instance)
{
	int *credits;
	int scredits, in_flight;

	credits = server->ops->get_credits_field(server, flags & CIFS_OP_MASK);

	spin_lock(&server->req_lock);
	scredits = *credits;
	in_flight = server->in_flight;

	if (*credits < num) {
		/*
		 * If the server is tight on resources or just gives us less
		 * credits for other reasons (e.g. requests are coming out of
		 * order and the server delays granting more credits until it
		 * processes a missing mid) and we exhausted most available
		 * credits there may be situations when we try to send
		 * a compound request but we don't have enough credits. At this
		 * point the client needs to decide if it should wait for
		 * additional credits or fail the request. If at least one
		 * request is in flight there is a high probability that the
		 * server will return enough credits to satisfy this compound
		 * request.
		 *
		 * Return immediately if no requests in flight since we will be
		 * stuck on waiting for credits.
		 */
		if (server->in_flight == 0) {
			spin_unlock(&server->req_lock);
			trace_smb3_insufficient_credits(server->current_mid,
					server->conn_id, server->hostname, scredits,
					num, in_flight);
			cifs_dbg(FYI, "%s: %d requests in flight, needed %d total=%d\n",
					__func__, in_flight, num, scredits);
			return -EDEADLK;
		}
	}
	spin_unlock(&server->req_lock);

	return wait_for_free_credits(server, num, 60000, flags,
				     instance);
}

int
cifs_wait_mtu_credits(struct TCP_Server_Info *server, size_t size,
		      size_t *num, struct cifs_credits *credits)
{
	*num = size;
	credits->value = 0;
	credits->instance = server->reconnect_instance;
	return 0;
}

int wait_for_response(struct TCP_Server_Info *server, struct smb_message *smb)
{
	unsigned int sleep_state = TASK_KILLABLE;
	int error;

	if (smb->sr_flags & CIFS_INTERRUPTIBLE_WAIT)
		sleep_state = TASK_INTERRUPTIBLE;

	error = wait_event_state(smb->waitq,
				 smb->mid_state != MID_REQUEST_SUBMITTED &&
				 smb->mid_state != MID_RESPONSE_RECEIVED,
				 (sleep_state | TASK_FREEZABLE_UNSAFE));
	if (error < 0)
		return -ERESTARTSYS;

	return 0;
}

/*
 * Send a SMB request and set the callback function in the mid to handle
 * the result. Caller is responsible for dealing with timeouts.
 */
int
cifs_call_async(struct TCP_Server_Info *server, struct smb_message *smb,
		const int flags, const struct cifs_credits *exist_credits)
{
	struct cifs_credits credits = { .value = 0, .instance = 0 };
	unsigned int instance;
	int optype;
	int rc;

	if (WARN_ON_ONCE(smb->next))
		return smb_EIO(smb_eio_trace_tx_chained_async);

	optype = flags & CIFS_OP_MASK;

	if ((flags & CIFS_HAS_CREDITS) == 0) {
		rc = wait_for_free_request(server, flags, &instance);
		if (rc)
			return rc;
		credits.value = 1;
		credits.instance = instance;
	} else
		instance = exist_credits->instance;

	cifs_server_lock(server);

	/*
	 * We can't use credits obtained from the previous session to send this
	 * request. Check if there were reconnects after we obtained credits and
	 * return -EAGAIN in such cases to let callers handle it.
	 */
	if (instance != server->reconnect_instance) {
		cifs_server_unlock(server);
		add_credits_and_wake_if(server, &credits, optype);
		return -EAGAIN;
	}

	rc = server->ops->setup_async_request(server, smb);
	if (rc) {
		cifs_server_unlock(server);
		add_credits_and_wake_if(server, &credits, optype);
		return rc;
	}

	smb->sr_flags = flags;
	smb->mid_state = MID_REQUEST_SUBMITTED;

	/* put it on the pending_mid_q */
	smb_get_message(smb, smb_message_trace_get_call_async);
	spin_lock(&server->mid_queue_lock);
	list_add_tail(&smb->qhead, &server->pending_mid_q);
	spin_unlock(&server->mid_queue_lock);

	/*
	 * Need to store the time in mid before calling I/O. For call_async,
	 * I/O response may come back and free the mid entry on another thread.
	 */
	cifs_save_when_sent(smb);
	rc = smb_send_rqst(server, smb, flags);

	if (rc < 0) {
		revert_current_mid(server, smb->credits_consumed);
		server->sequence_number -= 2;
		if (discard_message(server, smb))
			smb_put_message(smb, smb_message_trace_put_discard_message);
	}

	cifs_server_unlock(server);

	if (rc == 0)
		return 0;

	add_credits_and_wake_if(server, &credits, optype);
	return rc;
}

int cifs_sync_mid_result(struct smb_message *smb, struct TCP_Server_Info *server)
{
	int rc = 0;

	cifs_dbg(FYI, "%s: cmd=%d mid=%llu state=%d\n",
		 __func__, le16_to_cpu(smb->command), smb->mid, smb->mid_state);

	spin_lock(&server->mid_queue_lock);
	switch (smb->mid_state) {
	case MID_RESPONSE_READY:
		spin_unlock(&server->mid_queue_lock);
		return rc;
	case MID_RETRY_NEEDED:
		rc = -EAGAIN;
		break;
	case MID_RESPONSE_MALFORMED:
		rc = smb_EIO(smb_eio_trace_rx_sync_mid_malformed);
		break;
	case MID_SHUTDOWN:
		rc = -EHOSTDOWN;
		break;
	case MID_RC:
		rc = smb->mid_rc;
		break;
	default:
		if (smb->deleted_from_q == false) {
			list_del_init(&smb->qhead);
			smb->deleted_from_q = true;
		}
		spin_unlock(&server->mid_queue_lock);
		cifs_server_dbg(VFS, "%s: invalid mid state mid=%llu state=%d\n",
			 __func__, smb->mid, smb->mid_state);
		rc = smb_EIO1(smb_eio_trace_rx_sync_mid_invalid, smb->mid_state);
		goto sync_mid_done;
	}
	spin_unlock(&server->mid_queue_lock);

sync_mid_done:
	smb_clear_mid(server, smb);
	return rc;
}

static void
cifs_compound_callback(struct TCP_Server_Info *server, struct smb_message *smb)
{
	if (server) {
		struct cifs_credits credits = {
			.value = 1,
			.instance = server->reconnect_instance,
		};

		if (!is_smb1(server))
			credits.value = server->ops->get_credits(smb);

		add_credits(server, &credits, smb->optype);
	}

	if (smb->mid_state == MID_RESPONSE_RECEIVED)
		smb->mid_state = MID_RESPONSE_READY;
}

static void
cifs_compound_last_callback(struct TCP_Server_Info *server, struct smb_message *smb)
{
	cifs_compound_callback(server, smb);
	cifs_wake_up_task(server, smb);
}

static void
cifs_cancelled_callback(struct TCP_Server_Info *server, struct smb_message *smb)
{
	cifs_compound_callback(server, smb);
}

/*
 * cifs_pick_channel - pick an eligible channel for network operations
 *
 * @ses: session reference
 *
 * Select an eligible channel (not terminating and not marked as needing
 * reconnect), preferring the least loaded one. If no eligible channel is
 * found, fall back to the primary channel (index 0).
 *
 * Return: TCP_Server_Info pointer for the chosen channel, or NULL if @ses is
 * NULL.
 */
struct TCP_Server_Info *cifs_pick_channel(struct cifs_ses *ses)
{
	uint index = 0;
	unsigned int min_in_flight = UINT_MAX;
	struct TCP_Server_Info *server = NULL;
	int i, start, cur;

	if (!ses)
		return NULL;

	spin_lock(&ses->chan_lock);
	start = atomic_inc_return(&ses->chan_seq);
	for (i = 0; i < ses->chan_count; i++) {
		cur = (start + i) % ses->chan_count;
		server = ses->chans[cur].server;
		if (!server || server->terminate)
			continue;

		if (CIFS_CHAN_NEEDS_RECONNECT(ses, cur))
			continue;

		/*
		 * strictly speaking, we should pick up req_lock to read
		 * server->in_flight. But it shouldn't matter much here if we
		 * race while reading this data. The worst that can happen is
		 * that we could use a channel that's not least loaded. Avoiding
		 * taking the lock could help reduce wait time, which is
		 * important for this function
		 */
		if (server->in_flight < min_in_flight) {
			min_in_flight = server->in_flight;
			index = cur;
		}
	}

	server = ses->chans[index].server;
	spin_unlock(&ses->chan_lock);

	return server;
}

/*
 * Send a single message or a string of messages as a compound.
 */
static int smb_send_recv_messages(const unsigned int xid, struct cifs_ses *ses,
				  struct TCP_Server_Info *server,
				  struct smb_message *head_smb, const int flags)
{
	unsigned int instance;
	int nr_reqs, i, optype, rc = 0;

	if (!ses || !ses->server || !server) {
		cifs_dbg(VFS, "Null session\n");
		return smb_EIO(smb_eio_trace_null_pointers);
	}

	optype = flags & CIFS_OP_MASK;

	/* TODO: Stitch together the messages in a compound. */
	nr_reqs = 0;
	for (struct smb_message *smb = head_smb; smb; smb = smb->next)
		nr_reqs++;

	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsExiting) {
		spin_unlock(&server->srv_lock);
		return -ENOENT;
	}
	spin_unlock(&server->srv_lock);

	/*
	 * Wait for all the requests to become available.
	 * This approach still leaves the possibility to be stuck waiting for
	 * credits if the server doesn't grant credits to the outstanding
	 * requests and if the client is completely idle, not generating any
	 * other requests.
	 * This can be handled by the eventual session reconnect.
	 */
	rc = wait_for_compound_request(server, nr_reqs, flags, &instance);
	if (rc)
		return rc;

	for (struct smb_message *smb = head_smb; smb; smb = smb->next) {
		smb->credits.value	= 1;
		smb->credits.instance	= instance;
	}

	/*
	 * Make sure that we sign in the same order that we send on this socket
	 * and avoid races inside tcp sendmsg code that could cause corruption
	 * of smb data.
	 */

	cifs_server_lock(server);

	/*
	 * All the parts of the compound chain belong obtained credits from the
	 * same session. We can not use credits obtained from the previous
	 * session to send this request. Check if there were reconnects after
	 * we obtained credits and return -EAGAIN in such cases to let callers
	 * handle it.
	 */
	if (instance != server->reconnect_instance) {
		cifs_server_unlock(server);
		for (struct smb_message *smb = head_smb; smb; smb = smb->next)
			add_credits(server, &smb->credits, optype);
		return -EAGAIN;
	}

	i = 0;
	for (struct smb_message *smb = head_smb; smb; smb = smb->next) {
		smb->optype = optype;
		/*
		 * Invoke callback for every part of the compound chain
		 * to calculate credits properly. Wake up this thread only when
		 * the last element is received.
		 */
		if (smb->next)
			smb->callback = cifs_compound_callback;
		else
			smb->callback = cifs_compound_last_callback;

		rc = server->ops->setup_request(ses, server, smb);
		if (rc) {
			revert_current_mid(server, i);
			smb_discard_messages(server, head_smb);
			cifs_server_unlock(server);

			/* Update # of requests on wire to server */
			for (struct smb_message *smb = head_smb; smb; smb = smb->next)
				add_credits(server, &smb->credits, optype);
			return rc;
		}

		smb->mid_state = MID_REQUEST_SUBMITTED;
	}

	rc = smb_send_rqst(server, head_smb, flags);

	for (struct smb_message *smb = head_smb; smb; smb = smb->next)
		cifs_save_when_sent(smb);

	if (rc < 0) {
		revert_current_mid(server, nr_reqs);
		server->sequence_number -= 2;
	}

	cifs_server_unlock(server);

	/*
	 * If sending failed for some reason or it is an oplock break that we
	 * will not receive a response to - return credits back
	 */
	if (rc < 0 || (flags & CIFS_NO_SRV_RSP)) {
		for (struct smb_message *smb = head_smb; smb; smb = smb->next)
			add_credits(server, &smb->credits, optype);
		goto out;
	}

	/*
	 * At this point the request is passed to the network stack - we assume
	 * that any credits taken from the server structure on the client have
	 * been spent and we can't return them back. Once we receive responses
	 * we will collect credits granted by the server in the mid callbacks
	 * and add those credits to the server structure.
	 */

	/*
	 * Compounding is never used during session establish.
	 */
	spin_lock(&ses->ses_lock);
	if ((ses->ses_status == SES_NEW) || (optype & CIFS_NEG_OP) || (optype & CIFS_SESS_OP)) {
		spin_unlock(&ses->ses_lock);

		if (WARN_ON_ONCE(head_smb->next))
			return -EINVAL;

		cifs_server_lock(server);
		smb311_update_preauth_hash(ses, server, head_smb, false);
		cifs_server_unlock(server);
	} else {
		spin_unlock(&ses->ses_lock);
	}

	for (struct smb_message *smb = head_smb; smb; smb = smb->next) {
		if (!smb->next) {
			rc = wait_for_response(server, smb);
			if (rc != 0)
				break;
		}
	}
	if (rc != 0) {
		for (struct smb_message *smb = head_smb; smb; smb = smb->next) {
			cifs_server_dbg(FYI, "Cancelling wait for mid %llu cmd: %d\n",
					smb->mid, le32_to_cpu(smb->command));
			send_cancel(ses, server, smb, xid);
			spin_lock(&smb->mid_lock);
			smb->wait_cancelled = true;
			if (smb->mid_state == MID_REQUEST_SUBMITTED ||
			    smb->mid_state == MID_RESPONSE_RECEIVED) {
				smb->callback = cifs_cancelled_callback;
				smb->cancelled = true;
				smb->credits.value = 0;
			}
			spin_unlock(&smb->mid_lock);
		}
	}

	for (struct smb_message *smb = head_smb; smb; smb = smb->next) {
		if (rc < 0)
			goto out;

		rc = cifs_sync_mid_result(smb, server);
		if (rc != 0) {
			/* mark this mid as cancelled to not free it below */
			smb->cancelled = true;
			goto out;
		}

		if (!smb->response ||
		    smb->mid_state != MID_RESPONSE_READY) {
			rc = smb_EIO1(smb_eio_trace_rx_mid_unready, smb->mid_state);
			cifs_dbg(FYI, "Bad MID state?\n");
			goto out;
		}

		rc = server->ops->check_receive(smb, server,
						flags & CIFS_LOG_ERROR);
	}

	/*
	 * Compounding is never used during session establish.
	 */
	spin_lock(&ses->ses_lock);
	if ((ses->ses_status == SES_NEW) || (optype & CIFS_NEG_OP) || (optype & CIFS_SESS_OP)) {
		spin_unlock(&ses->ses_lock);
		cifs_server_lock(server);
		smb311_update_preauth_hash(ses, server, head_smb, true);
		cifs_server_unlock(server);
	} else {
		spin_unlock(&ses->ses_lock);
	}

out:
	/*
	 * This will dequeue all mids. After this it is important that the
	 * demultiplex_thread will not process any of these mids any further.
	 * This is prevented above by using a noop callback that will not
	 * wake this thread except for the very last PDU.
	 */
	for (struct smb_message *smb = head_smb; smb; smb = smb->next)
		if (!smb->cancelled)
			discard_message(server, smb);

	return rc;
}

int
compound_send_recv(const unsigned int xid, struct cifs_ses *ses,
		   struct TCP_Server_Info *server,
		   const int flags, const int num_rqst, struct smb_rqst *rqst,
		   int *resp_buf_type, struct kvec *resp_iov)
{
	struct smb_message *head_smb = NULL, **ppsmb = &head_smb, *smb;
	int rc = -ENOMEM;

	if (!ses || !ses->server || !server) {
		cifs_dbg(VFS, "Null session\n");
		return smb_EIO(smb_eio_trace_null_pointers);
	}

	for (int i = 0; i < num_rqst; i++) {
		struct smb_rqst *rq = &rqst[i];
		void *request = rq->rq_iov[0].iov_base;
		struct smb2_hdr *hdr = request;
		enum smb_command_trace cmd = smb_command_trace_unknown;

		if (!is_smb1(server))
			cmd = le32_to_cpu(hdr->Command);

		smb = smb_message_alloc(cmd, GFP_NOFS);
		if (!smb)
			goto error;

		*ppsmb = smb;
		ppsmb = &smb->next;
		smb->request		= request;
		smb->rqst		= *rq;
		smb->sr_flags		= flags;

		if (is_smb1(server)) {
			smb->command = 0;
			smb->command_trace = smb1_command_trace_unknown;
		}

		for (int j = 0; j < rq->rq_nvec; j++)
			smb->total_len += rq->rq_iov[j].iov_len;
		smb->total_len += iov_iter_count(&rq->rq_iter);
	}

	rc = smb_send_recv_messages(xid, ses, server, head_smb, flags);

	smb = head_smb;
	for (int i = 0; i < num_rqst; i++) {
		if (smb->response && !(flags & CIFS_NO_RSP_BUF)) {
			resp_iov[i].iov_base = smb->response;
			resp_iov[i].iov_len  = smb->resp_len;
			smb->response = NULL;

			if (smb->large_buf)
				resp_buf_type[i] = CIFS_LARGE_BUFFER;
			else
				resp_buf_type[i] = CIFS_SMALL_BUFFER;
		} else {
			resp_iov[i].iov_base	= NULL;
			resp_buf_type[i]	= 0;
			resp_buf_type[i]	= CIFS_NO_BUFFER;
		}
		smb = smb->next;
	}

error:
	smb_put_messages(head_smb);
	return rc;
}

int
cifs_send_recv(const unsigned int xid, struct cifs_ses *ses,
	       struct TCP_Server_Info *server,
	       struct smb_rqst *rqst, int *resp_buf_type, const int flags,
	       struct kvec *resp_iov)
{
	return compound_send_recv(xid, ses, server, flags, 1,
				  rqst, resp_buf_type, resp_iov);
}
