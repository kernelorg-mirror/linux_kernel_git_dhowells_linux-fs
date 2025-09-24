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
#include "cifsglob.h"
#include "cifsproto.h"
#include "smb1proto.h"
#include "smb2proto.h"
#include "cifs_debug.h"
#include "smbdirect.h"
#include "compress.h"

/* Max number of iovectors we can use off the stack when sending requests. */
#define CIFS_MAX_IOV_SIZE 8

static struct smb_message *
alloc_mid(const struct smb_hdr *shdr, struct TCP_Server_Info *server)
{
	struct smb_message *smb;

	if (server == NULL) {
		cifs_dbg(VFS, "%s: null TCP session\n", __func__);
		return NULL;
	}

	smb = mempool_alloc(&smb_message_pool, GFP_NOFS);
	memset(smb, 0, sizeof(struct smb_message));
	refcount_set(&smb->ref, 1);
	spin_lock_init(&smb->mid_lock);
	smb->mid	= le16_to_cpu(shdr->Mid);
	smb->pid	= current->pid;
	smb->command	= cpu_to_le16(shdr->Command);
	cifs_dbg(FYI, "For smb_command %d\n", shdr->Command);
	/* easier to use jiffies */
	/* when mid allocated can be before when sent */
	smb->when_alloc	= jiffies;

	/*
	 * The default is for the mid to be synchronous, so the
	 * default callback just wakes up the current task.
	 */
	get_task_struct(current);
	smb->creator = current;
	smb->callback = cifs_wake_up_task;
	smb->callback_data = current;

	atomic_inc(&mid_count);
	smb->mid_state = MID_REQUEST_ALLOCATED;
	return smb;
}

static int allocate_mid(struct cifs_ses *ses, struct smb_hdr *in_buf,
			struct smb_message **ppmidQ)
{
	spin_lock(&ses->ses_lock);
	if (ses->ses_status == SES_NEW) {
		if ((in_buf->Command != SMB_COM_SESSION_SETUP_ANDX) &&
			(in_buf->Command != SMB_COM_NEGOTIATE)) {
			spin_unlock(&ses->ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are setting up session */
	}

	if (ses->ses_status == SES_EXITING) {
		/* check if SMB session is bad because we are setting it up */
		if (in_buf->Command != SMB_COM_LOGOFF_ANDX) {
			spin_unlock(&ses->ses_lock);
			return -EAGAIN;
		}
		/* else ok - we are shutting down session */
	}
	spin_unlock(&ses->ses_lock);

	*ppmidQ = alloc_mid(in_buf, ses->server);
	if (*ppmidQ == NULL)
		return -ENOMEM;
	spin_lock(&ses->server->mid_queue_lock);
	list_add_tail(&(*ppmidQ)->qhead, &ses->server->pending_mid_q);
	spin_unlock(&ses->server->mid_queue_lock);
	return 0;
}

struct smb_message *
cifs_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct smb_message *smb;

	/* enable signing if server requires it */
	if (server->sign)
		hdr->Flags2 |= SMBFLG2_SECURITY_SIGNATURE;

	smb = alloc_mid(hdr, server);
	if (smb == NULL)
		return ERR_PTR(-ENOMEM);

	rc = cifs_sign_rqst(rqst, server, &smb->sequence_number);
	if (rc) {
		release_mid(server, smb);
		return ERR_PTR(rc);
	}

	return smb;
}

/*
 *
 * Send an SMB Request.  No response info (other than return code)
 * needs to be parsed.
 *
 * flags indicate the type of request buffer and how long to wait
 * and whether to log NT STATUS code (error) before mapping it to POSIX error
 *
 */
int
SendReceiveNoRsp(const unsigned int xid, struct cifs_ses *ses,
		 char *in_buf, unsigned int in_len, int flags)
{
	int rc;
	struct kvec iov[1];
	struct kvec rsp_iov;
	int resp_buf_type;

	iov[0].iov_base = in_buf;
	iov[0].iov_len = in_len;
	flags |= CIFS_NO_RSP_BUF;
	rc = SendReceive2(xid, ses, iov, 1, &resp_buf_type, flags, &rsp_iov);
	cifs_dbg(NOISY, "SendRcvNoRsp flags %d rc %d\n", flags, rc);

	return rc;
}

int
cifs_check_receive(struct smb_message *smb, struct TCP_Server_Info *server,
		   bool log_error)
{
	dump_smb(smb->response, min_t(u32, 92, smb->resp_len));

	/* convert the length into a more usable form */
	if (server->sign && !smb->sig_checked) {
		int rc;

		/* FIXME: add code to kill session */
		rc = cifs_verify_signature(smb, server, smb->sequence_number);
		if (rc) {
			cifs_server_dbg(VFS, "SMB signature verification returned error = %d\n",
				 rc);

			if (!(server->sec_mode & SECMODE_SIGN_REQUIRED)) {
				cifs_reconnect(server, true);
				return rc;
			}
		}
	}

	/* BB special case reconnect tid and uid here? */
	return map_and_check_smb_error(server, smb, log_error);
}

struct smb_message *
cifs_setup_request(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb_hdr *hdr = (struct smb_hdr *)rqst->rq_iov[0].iov_base;
	struct smb_message *smb;

	rc = allocate_mid(ses, hdr, &smb);
	if (rc)
		return ERR_PTR(rc);
	rc = cifs_sign_rqst(rqst, server, &smb->sequence_number);
	if (rc) {
		delete_mid(server, smb);
		return ERR_PTR(rc);
	}
	return smb;
}

int
SendReceive2(const unsigned int xid, struct cifs_ses *ses,
	     struct kvec *iov, int n_vec, int *resp_buf_type /* ret */,
	     const int flags, struct kvec *resp_iov)
{
	struct smb_rqst rqst = {
		.rq_iov = iov,
		.rq_nvec = n_vec,
	};

	return cifs_send_recv(xid, ses, ses->server,
			      &rqst, resp_buf_type, flags, resp_iov);
}

int
SendReceive(const unsigned int xid, struct cifs_ses *ses,
	    struct smb_hdr *in_buf, unsigned int in_len,
	    struct smb_hdr *out_buf, int *pbytes_returned, const int flags)
{
	struct TCP_Server_Info *server;
	struct kvec resp_iov = {};
	struct kvec iov = { .iov_base = in_buf, .iov_len = in_len };
	struct smb_rqst rqst = { .rq_iov = &iov, .rq_nvec = 1 };
	int resp_buf_type;
	int rc = 0;

	if (WARN_ON_ONCE(in_len > 0xffffff))
		return smb_EIO1(smb_eio_trace_tx_too_long, in_len);
	if (ses == NULL) {
		cifs_dbg(VFS, "Null smb session\n");
		return smb_EIO(smb_eio_trace_null_pointers);
	}
	server = ses->server;
	if (server == NULL) {
		cifs_dbg(VFS, "Null tcp session\n");
		return smb_EIO(smb_eio_trace_null_pointers);
	}

	/* Ensure that we do not send more than 50 overlapping requests
	   to the same server. We may make this configurable later or
	   use ses->maxReq */

	if (in_len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE) {
		cifs_server_dbg(VFS, "Invalid length, greater than maximum frame, %d\n",
				in_len);
		return smb_EIO1(smb_eio_trace_tx_too_long, in_len);
	}

	rc = cifs_send_recv(xid, ses, ses->server,
			    &rqst, &resp_buf_type, flags, &resp_iov);
	if (rc < 0)
		goto out;

	if (out_buf) {
		/* Use smbCalcSize() for both single- and multi-part T2 responses,
		 * both here and in coalesce_t2().
		 */
		unsigned int copy_len;
		if (WARN_ON_ONCE(!resp_iov.iov_base)) {
			rc = -EIO;
			goto out;
		}
		copy_len = smbCalcSize(resp_iov.iov_base);
		if (copy_len > CIFSMaxBufSize + MAX_CIFS_HDR_SIZE) {
			cifs_dbg(VFS, "response size %u exceeds buffer\n",
				 copy_len);
			rc = -ENOBUFS;
			goto out;
		}
		*pbytes_returned = copy_len;
		memcpy(out_buf, resp_iov.iov_base, copy_len);
	}

out:
	free_rsp_buf(resp_buf_type, resp_iov.iov_base);
	return rc;
}

struct smb1_reassembly_section {
	u32	asm_off;	/* Offset within reassembled PDU */
	u16	asm_dis;	/* Offset within reassembly section */
	u16	asm_cnt;	/* Filled amount of reassembly section */
	u16	asm_len;	/* Fully reassembled length */
	u16	seg_off;	/* Segment offset within PDU */
	u16	seg_len;	/* Segment len */
	char	type;
};

struct smb1_reassembly {
	u16	area_offset;
	struct smb1_reassembly_section params, data;
};

/*
 * Check the basic structure of a trans2-class message.
 *
 *  | SMB1 hdr
 *  | Trans2 resp hdr	} Accounted in WCT
 *  | Setup words[]	}
 *  | BCC
 *  | Padding/Reserved2	} Accounted in BCC
 *  | content[]		}
 */
static bool smb1_trans2_check(const union smb1_response_hdr *h,
			      const struct cifs_receive *recv,
			      struct smb1_reassembly *t2)
{
	const struct trans2_resp *t2_rsp = &h->trans2.t2_rsp;
	const struct smb_hdr *shdr = &h->trans2.hdr;
	unsigned int expected_bcc;
	unsigned int area_offset = recv->hdr_len;
	unsigned int area_len = get_bcc(shdr);
	unsigned int area_top = area_offset + area_len;

	t2->area_offset    = area_offset;
	t2->params.asm_len = get_unaligned_le16(&t2_rsp->TotalParameterCount);
	t2->params.asm_dis = get_unaligned_le16(&t2_rsp->ParameterDisplacement);
	t2->params.seg_len = get_unaligned_le16(&t2_rsp->ParameterCount);
	t2->params.seg_off = get_unaligned_le16(&t2_rsp->ParameterOffset);
	t2->data.asm_len   = get_unaligned_le16(&t2_rsp->TotalDataCount);
	t2->data.asm_dis   = get_unaligned_le16(&t2_rsp->DataDisplacement);
	t2->data.seg_len   = get_unaligned_le16(&t2_rsp->DataCount);
	t2->data.seg_off   = get_unaligned_le16(&t2_rsp->DataOffset);

	t2->params.asm_off = 0;
	t2->params.asm_cnt = 0;
	t2->params.type    = 'P';
	t2->data.asm_off   = 0;
	t2->data.asm_cnt   = 0;
	t2->data.type      = 'D';

	if (t2->params.seg_len + t2->data.seg_len > area_len)
		goto bad;

	if (t2->params.seg_len > 0) {
		if (t2->params.seg_off < t2->area_offset ||
		    t2->params.seg_off + t2->params.seg_len > area_top ||
		    t2->params.asm_dis + t2->params.seg_len > t2->params.asm_len)
			goto bad;
	}

	if (t2->data.seg_len > 0) {
		if (t2->data.seg_off < t2->area_offset ||
		    t2->data.seg_off + t2->data.seg_len > area_top ||
		    t2->data.asm_dis + t2->data.seg_len > t2->data.asm_len)
			goto bad;
	}
	if (t2->data.seg_len > 0 &&
	    t2->params.seg_len > 0) {
		/* Must not overlap. */
		if (t2->params.seg_off == t2->data.seg_off)
			goto bad;
		if (t2->params.seg_off < t2->data.seg_off &&
		    t2->params.seg_off + t2->params.seg_len > t2->data.seg_off)
			goto bad;
		if (t2->data.seg_off < t2->params.seg_off &&
		    t2->data.seg_off + t2->data.seg_len > t2->params.seg_off)
			goto bad;
	}
	expected_bcc = t2->params.asm_len + t2->data.asm_len;
	if (expected_bcc > USHRT_MAX) {
		cifs_dbg(FYI, "trans2: Expected BCC too large (%u)\n", expected_bcc);
		return false;
	}
	if (t2->data.asm_len > CIFSMaxBufSize) {
		cifs_dbg(VFS, "trans2: TotalDataSize %u is over maximum buffer %u\n",
			 t2->data.asm_len, CIFSMaxBufSize);
		return false;
	}
	return true;

bad:
	cifs_dbg(FYI, "trans2: Bad resp layout: area %x-%x\n",
		 t2->area_offset, area_top);
	cifs_dbg(FYI, "trans2: Params: len=%x/%x off=%x dis=%x\n",
		 t2->params.seg_len, t2->params.asm_len,
		 t2->params.seg_off, t2->params.asm_dis);
	cifs_dbg(FYI, "trans2: Data: len=%x/%x off=%x dis=%x\n",
		 t2->data.seg_len, t2->data.asm_len,
		 t2->data.seg_off, t2->data.asm_dis);
	return false;
}

/*
 * Check follow-on messages for a Trans2 message.
 */
static int smb1_trans2_check2(struct TCP_Server_Info *server,
			      struct smb_message *smb,
			      struct cifs_receive *recv,
			      struct smb1_reassembly *t2)
{
	union smb1_response_hdr *target_h = smb->response;
	struct smb_t2_rsp *target = &target_h->trans2;
	int remaining_params, remaining_data;
	unsigned int total_params, total_data;

	total_params       = get_unaligned_le16(&target->t2_rsp.TotalParameterCount);
	total_data         = get_unaligned_le16(&target->t2_rsp.TotalDataCount);
	t2->params.asm_cnt = get_unaligned_le16(&target->t2_rsp.ParameterCount);
	t2->data.asm_cnt   = get_unaligned_le16(&target->t2_rsp.DataCount);

	cifs_dbg(FYI, "trans2: params=%x/%x/%x data=%x/%x/%x\n",
		 t2->params.seg_len, t2->params.asm_cnt, t2->params.asm_len,
		 t2->data.seg_len,   t2->data.asm_cnt,   t2->data.asm_len);

	if (t2->params.asm_len != total_params)
		cifs_dbg(FYI, "trans2: Inconsistent TotalParameterCount %u!=%u\n",
			 t2->params.asm_len, total_params);

	if (t2->data.asm_len != total_data)
		cifs_dbg(FYI, "trans2: Inconsistent TotalDataCount %u!=%u\n",
			 t2->params.asm_len, total_data);

	remaining_params = t2->params.asm_len - t2->params.asm_cnt;
	remaining_data   = t2->data.asm_len   - t2->data.asm_cnt;

	if (remaining_params < 0 || remaining_data < 0) {
		pr_warn("trans2: Server sent too much: params=%u/%u data=%u/%u\n",
			t2->params.asm_cnt, t2->params.asm_len,
			t2->data.asm_cnt, t2->data.asm_len);
		return -EPROTO;
	}

	if (t2->params.seg_len > remaining_params ||
	    t2->data.seg_len   > remaining_data) {
		pr_warn("trans2: Excessive addition: params=%u/%u/%u data=%u/%u/%u\n",
			t2->params.seg_len, t2->params.asm_cnt, t2->params.asm_len,
			t2->data.seg_len,   t2->data.asm_cnt,   t2->data.asm_len);
		return -EPROTO;
	}

	return 0;
}

/*
 * Allocate an appropriately sized buffer for a reassembled Trans2 reply.
 */
static int smb1_trans2_alloc(struct TCP_Server_Info *server,
			     struct smb_message *smb,
			     struct cifs_receive *recv,
			     struct smb1_reassembly *t2)
{
	union smb1_response_hdr *h = recv->response;
	struct trans2_resp *rsp = &h->trans2.t2_rsp;
	struct smb_hdr *shdr = &h->trans2.hdr;
	unsigned int reasm_len;
	u16 bcc;

	reasm_len  = t2->area_offset;
	/* Might need 1 byte of padding before the params */
	reasm_len += t2->params.asm_len;
	/* Might need 2 bytes of padding before the data */
	reasm_len += t2->data.asm_len;

	if (reasm_len <= MAX_CIFS_SMALL_BUFFER_SIZE) {
		/* Stick with the small buffer we're already using. */
		smb->response = server->smallbuf;
		smb->resp_len = reasm_len;
		server->smallbuf = NULL;
	} else if (reasm_len <= CIFSMaxBufSize + MAX_SMB2_HDR_SIZE) {
		/* Switch to a large buffer. */
		smb->response = server->bigbuf;
		smb->resp_len = reasm_len;
		smb->large_buf = true;
		memcpy(server->bigbuf, server->smallbuf, recv->extracted);
		server->bigbuf = NULL;
		recv->resp_buf_type = CIFS_LARGE_BUFFER;
	} else {
		/* Too big - could decant into a list of pages. */
		smb->error = -EMSGSIZE;
		cifs_dbg(FYI, "%s: Message too big\n", __func__);
		return -EMSGSIZE;
	}

	h = smb->response;
	shdr = &h->trans2.hdr;
	rsp = &h->trans2.t2_rsp;

	/* Fix up the BCC to the anticipated full amount. */
	bcc = t2->params.asm_len + t2->data.asm_len;
	put_bcc(bcc, shdr);

	/* Lay out the parameter and data blocks appropriately. */
	rsp->ParameterOffset = cpu_to_le16(recv->hdr_len);
	rsp->DataOffset      = cpu_to_le16(recv->hdr_len + t2->params.asm_len);

	recv->msg_len = reasm_len;
	return 0;
}

static bool smb1_trans2_extract(struct smb_message *smb,
				struct cifs_receive *recv,
				struct smb1_reassembly_section *a,
				struct netfs_rxqueue *rxq)
{
	size_t got;

	if (a->seg_len == 0)
		return true;

	got = netfs_rxqueue_read(rxq, smb->response + a->asm_off,
				 a->seg_off, a->seg_len);
	if (got != a->seg_len) {
		cifs_dbg(FYI, "trans2: copy_from_iter failed (%u bytes)\n",
			 rxq->qsize);
		return false;
	}
	return true;
}

/*
 * Receive a Trans2-class message.  These are potentially multipart and may
 * need assembly.
 *
 * Returns 0 if the message is complete (for good or bad), 1 if further data is
 * expected and a negative error code otherwise.
 */
static int smb1_trans2_receive(struct TCP_Server_Info *server,
			       struct smb_message *smb,
			       struct cifs_receive *recv,
			       struct netfs_rxqueue *rxq)
{
	union smb1_response_hdr *target_h;
	union smb1_response_hdr *h = recv->response;
	struct smb1_reassembly t2;
	struct trans2_resp *target;
	int rc;

	if (server->sign) {
		rc = cifs_verify_trans_signature(server, recv, rxq,
						 smb->sequence_number);
		if (rc < 0) {
			cifs_dbg(FYI, "Signature check failed\n");
		}
		smb->sig_checked = true;
	}

	if (h->hdr.Status.CifsError != 0 &&
	    h->hdr.WordCount == 0) {
		smb->response = server->smallbuf;
		smb->resp_len = recv->msg_len;
		server->smallbuf = NULL;
		return 0;
	}

	if (!smb1_trans2_check(h, recv, &t2)) {
		cifs_dbg(FYI, "Invalid transact2 layout\n");
		return -EINVAL;
	}

	if (t2.params.seg_len < t2.params.asm_len ||
	    t2.data.seg_len   < t2.data.asm_len) {
		smb->multiRsp = true;
		cifs_dbg(FYI, "Trans2 incomplete (%u/%u, %u/%u), check next response\n",
			 t2.params.seg_len, t2.params.asm_len,
			 t2.data.seg_len, t2.data.asm_len);
	}

	if (!smb->response) {
		rc = smb1_trans2_alloc(server, smb, recv, &t2);
		if (rc < 0)
			return rc;
	} else {
		/* Check follow-on message. */
		rc = smb1_trans2_check2(server, smb, recv, &t2);
		if (rc < 0)
			return rc;
	}

	/* Perform the reassembly. */
	target_h = smb->response;
	target = &target_h->trans2.t2_rsp;
	t2.params.asm_off = le16_to_cpup(&target->ParameterOffset) + t2.params.asm_dis;
	t2.data.asm_off   = le16_to_cpup(&target->DataOffset)      + t2.data.asm_dis;

	if (!smb1_trans2_extract(smb, recv, &t2.params, rxq) ||
	    !smb1_trans2_extract(smb, recv, &t2.data,   rxq))
		return smb_EIO(smb_eio_trace_rx_trans2_extract);

	t2.params.asm_cnt += t2.params.seg_len;
	t2.data.asm_cnt   += t2.data.seg_len;
	target->ParameterCount = cpu_to_le16(t2.params.asm_cnt);
	target->DataCount      = cpu_to_le16(t2.data.asm_cnt);

	/* All parts received or packet is malformed. */
	if (t2.params.asm_cnt == t2.params.asm_len &&
	    t2.data.asm_cnt   == t2.data.asm_len) {
		smb->multiEnd = true;
		return 0;
	}
	return 1;
}

/*
 * Check the size of the response header and extract the data area size.
 */
static bool smb1_check_response(struct cifs_receive *recv)
{
	const union smb1_response_hdr *h = recv->response;
	const struct smb_hdr *shdr = &h->hdr;
	unsigned bcc;

	if (shdr->Status.CifsError != 0)
		return true;

	/* Assume, by default, that the data area is beyond the BCC-covered area. */
	bcc = get_bcc(shdr);
	if (recv->extracted + bcc < recv->msg_len) {
		recv->data_offset = recv->extracted + bcc;
		recv->data_len = recv->msg_len;
	}

	switch (shdr->Command) {
		/* Trivial responses with WCT=0 and BCC=0 */
	case SMB_COM_CREATE_DIRECTORY:
	case SMB_COM_DELETE_DIRECTORY:
	case SMB_COM_CLOSE:
	case SMB_COM_FLUSH:
	case SMB_COM_DELETE:
	case SMB_COM_RENAME:
	case SMB_COM_SETATTR:
	case SMB_COM_FIND_CLOSE2:
	case SMB_COM_TREE_DISCONNECT:
	case SMB_COM_NT_RENAME:
		if (recv->hdr_len < sizeof(struct smb_hdr) + 2)
			goto too_short;
		break;
		/* Trivial AndX responses with WCT=2 and BCC=0 */
	case SMB_COM_LOCKING_ANDX:
		if (recv->hdr_len < sizeof(struct smb_hdr) + 6)
			goto too_short;
		break;
	case SMB_COM_QUERY_INFORMATION:
		if (recv->hdr_len < sizeof(struct smb_com_query_information_rsp))
			goto too_short;
		break;
	case SMB_COM_COPY:
		if (recv->hdr_len < sizeof(struct smb_com_copy_rsp))
			goto too_short;
		break;
	case SMB_COM_ECHO:
		if (recv->hdr_len < sizeof(struct smb_com_echo_rsp))
			goto too_short;
		break;
	case SMB_COM_OPEN_ANDX:
	case SMB_COM_NT_CREATE_ANDX:
		if (recv->hdr_len < sizeof(struct smb_com_open_rsp))
			goto too_short;
		break;
	case SMB_COM_READ_ANDX:
		if (recv->hdr_len < sizeof(struct smb_com_read_rsp))
			goto too_short;
		recv->data_offset = le16_to_cpu(h->read.DataOffset);
		recv->data_len    = le16_to_cpu(h->read.DataLengthHigh) << 16;
		recv->data_len   += le16_to_cpu(h->read.DataLength);
		break;
	case SMB_COM_WRITE_ANDX:
		if (recv->hdr_len < sizeof(struct smb_com_write_rsp))
			goto too_short;
		break;
	case SMB_COM_NEGOTIATE:
		if (recv->hdr_len < offsetof(struct smb_negotiate_rsp, ByteCount))
			goto too_short;
		break;
	case SMB_COM_SESSION_SETUP_ANDX:
		if (recv->hdr_len < sizeof(struct smb1_old_session_rsp))
			goto too_short;
		break;
	case SMB_COM_LOGOFF_ANDX:
		if (recv->hdr_len < sizeof(struct smb_com_logoff_andx_rsp))
			goto too_short;
		break;
	case SMB_COM_TREE_CONNECT_ANDX:
		if (recv->hdr_len < sizeof(struct smb_com_tconx_rsp))
			goto too_short;
		break;
	case SMB_COM_TRANSACTION2:
		if (recv->hdr_len < sizeof(struct smb_t2_rsp))
			goto too_short;
		break;
	case SMB_COM_NT_TRANSACT:
		if (recv->hdr_len < sizeof(struct smb_com_ntransact_rsp))
			goto too_short;
		break;
	case SMB_COM_TRANSACTION2_SECONDARY:
	case SMB_COM_NT_TRANSACT_SECONDARY:
	case SMB_COM_NT_CANCEL:
	default:
		cifs_dbg(VFS, "Unsupported command reply (%x)\n", shdr->Command);
		break;
	}

	return true;
too_short:
	cifs_dbg(VFS, "Header too short (%x) for command (%x)\n",
		 recv->hdr_len, shdr->Command);
	return false;
}

static bool
check_smb_hdr(struct cifs_receive *recv)
{
	union smb1_response_hdr *h = recv->response;
	struct smb_hdr *smb = &h->hdr;

	/* does it have the right SMB "signature" ? */
	if (*(__le32 *) smb->Protocol != SMB1_PROTO_NUMBER) {
		cifs_dbg(VFS, "Bad protocol string signature header 0x%x\n",
			 *(unsigned int *)smb->Protocol);
		return false;
	}

	/* if it's a response then accept */
	if (smb->Flags & SMBFLG_RESPONSE)
		return true;

	/* only one valid case where server sends us request */
	if (smb->Command == SMB_COM_LOCKING_ANDX)
		return true;

	/*
	 * Windows NT server returns error response (e.g. STATUS_DELETE_PENDING
	 * or STATUS_OBJECT_NAME_NOT_FOUND or ERRDOS/ERRbadfile or any other)
	 * for some TRANS2 requests without the RESPONSE flag set in header.
	 */
	if (smb->Command == SMB_COM_TRANSACTION2 && smb->Status.CifsError != 0)
		return true;

	cifs_dbg(VFS, "Server sent request, not response. mid=%u\n",
		 le16_to_cpu(smb->Mid));
	return false;
}

/*
 * Try and fix up a message that's too short even to contain a full BCC word
 * and nothing else after the header.
 */
static int smb1_fix_up_short_header(struct cifs_receive *recv)
{
	union smb1_response_hdr *h = recv->response;

	cifs_dbg(FYI, "%s: rfc1002 len: 0x%x\n", __func__, recv->msg_len);

	if (recv->msg_len < sizeof(struct smb_hdr) - 1) {
		cifs_dbg(VFS, "Length less than smb header size\n");
		return smb_EIO1(smb_eio_trace_rx_too_short, recv->msg_len);
	}

	if (h->hdr.Status.CifsError != 0) {
		/* It's an error return (some error cases do not return wct and
		 * bcc).
		 */
		goto reset_wct_and_bcc;
	}

	if (recv->msg_len == sizeof(struct smb_hdr) + 1 &&
	    h->hdr.WordCount == 0) {
		/* Need to work around a bug in two servers here */
		/* First, check if the part of bcc they sent was zero */
		if (h->trivial_rsp.short_bcc == 0) {
			/* some servers return only half of bcc
			 * on simple responses (wct, bcc both zero)
			 * in particular have seen this on
			 * ulogoffX and FindClose. This leaves
			 * one byte of bcc potentially uninitialized
			 */
			goto reset_wct_and_bcc;
		}
		cifs_dbg(VFS, "rcvd invalid byte count (bcc)\n");
		return smb_EIO1(smb_eio_trace_rx_inv_bcc, h->trivial_rsp.short_bcc);
	}

	cifs_dbg(VFS, "Length less than smb header size\n");
	return smb_EIO2(smb_eio_trace_rx_too_short,
			recv->msg_len, le16_to_cpu(h->hdr.WordCount));

reset_wct_and_bcc:
	h->trivial_rsp.hdr.WordCount = 0;
	h->trivial_rsp.bcc = 0;
	recv->msg_len   = sizeof(h->trivial_rsp);
	recv->hdr_len   = recv->msg_len;
	recv->extracted = recv->msg_len;
	return 0;
}

int
checkSMB(const struct TCP_Server_Info *server, struct cifs_receive *recv)
{
	union smb1_response_hdr *h = recv->response;
	struct smb_hdr *smb = &h->hdr;

	cifs_dbg(FYI, "checkSMB rfc1002 len: 0x%x\n", recv->msg_len);

	/* otherwise, there is enough to get to the BCC */
	if (!smb1_check_response(recv))
		return smb_EIO2(smb_eio_trace_rx_check_rsp,
				h->hdr.Command,
				(le16_to_cpu(h->hdr.WordCount) << 16) |
				h->trivial_rsp.short_bcc);

	recv->calc_len = smbCalcSize(smb);
	if (recv->msg_len != recv->calc_len) {
		__u16 mid = le16_to_cpu(smb->Mid);
		/* check if bcc wrapped around for large read responses */
		if ((recv->msg_len > 64 * 1024) &&
		    (recv->msg_len > recv->calc_len)) {
			/* check if lengths match mod 64K */
			if ((recv->msg_len & 0xFFFF) == (recv->calc_len & 0xFFFF))
				return 0; /* bcc wrapped */
		}
		cifs_dbg(FYI, "Calculated size %u vs length %u mismatch for mid=%u\n",
			 recv->calc_len, recv->msg_len, mid);

		if (recv->msg_len < recv->calc_len) {
			cifs_dbg(VFS, "RFC1001 size %u smaller than SMB for mid=%u\n",
				 recv->msg_len, mid);
			return smb_EIO2(smb_eio_trace_rx_calc_len_too_big,
					recv->msg_len, recv->calc_len);
		} else if (recv->msg_len > recv->calc_len + 512) {
			/*
			 * Some servers (Windows XP in particular) send more
			 * data than the lengths in the SMB packet would
			 * indicate on certain calls (byte range locks and
			 * trans2 find first calls in particular). While the
			 * client can handle such a frame by ignoring the
			 * trailing data, we choose limit the amount of extra
			 * data to 512 bytes.
			 */
			cifs_dbg(VFS, "RFC1001 size %u more than 512 bytes larger than SMB for mid=%u\n",
				 recv->msg_len, mid);
			return smb_EIO2(smb_eio_trace_rx_overlong,
					recv->msg_len, recv->calc_len + 512);
		}
	}
	return 0;
}

/*
 * Copy data directly into prepared buffers.
 *
 * Ideally, we'd wait for sufficient data to be present in the queue before
 * doing this, but that causes a performance loss as we don't receive data and
 * copy in parallel.
 */
static void smb1_copy_to_prepped_buffers(struct TCP_Server_Info *server,
					 struct smb_message *smb,
					 struct netfs_rxqueue *rxq,
					 struct cifs_receive *recv)
{
	const union smb1_response_hdr *h = recv->response;
	struct iov_iter dest = smb->response_iter;
	unsigned int to_copy, skip;
	int rc;

	switch (h->hdr.Command) {
	case SMB_COM_READ_ANDX:
		to_copy = recv->data_len;
		skip = recv->data_offset;
		break;
	default:
		cifs_dbg(FYI, "%s: Non-Read copy\n", __func__);
		return;
	}

	if (skip < recv->hdr_len) {
		if (skip != 0) {
			cifs_dbg(FYI, "%s: Read.DataOffset too small\n", __func__);
			return;
		}
		skip = recv->hdr_len;
	}
	if (skip > recv->msg_len) {
		cifs_dbg(FYI, "%s: Read.DataOffset beyond end\n", __func__);
		return;
	}
	if (to_copy > recv->msg_len - skip) {
		cifs_dbg(FYI, "%s: Read.DataLength beyond end\n", __func__);
		return;
	}

	if (!rxq->refillable) {
		size_t got;

		got = netfs_rxqueue_read_iter(rxq, &dest, 0, to_copy);
		if (got > 0)
			netfs_rxqueue_discard(rxq, got);
		recv->extracted += got;
		if (got < to_copy) {
			cifs_dbg(VFS, "Copy to buffer was short %zu/%u\n",
				 got, to_copy);
			recv->malformed = true;
		}
		return;
	}

	while (to_copy) {
		size_t got, part = umin(to_copy, rxq->qsize);

		got = netfs_rxqueue_read_iter(rxq, &dest, 0, part);
		if (got > 0) {
			recv->extracted += got;
			to_copy -= got;
			netfs_rxqueue_discard(rxq, got);
		}
		if (!to_copy)
			break;
		if (got < part) {
			cifs_dbg(VFS, "Copy to buffer was short %zu/%zu\n",
				 part, to_copy + part);
			recv->malformed = true;
			return;
		}

		rc = smb_rxqueue_refill(server, rxq, 1);
		if (rc < 0) {
			recv->malformed = true;
			return;
		}
		if (!rxq->qsize || !rxq->pdu_remain)
			break;
	}
}

/*
 * Parse an SMB1 message that's at least partially extracted.  For successful
 * reads, the data part is still in the receive queue or even not yet received.
 */
static void smb1_parse_one_message(struct TCP_Server_Info *server,
				   struct cifs_receive *recv,
				   struct netfs_rxqueue *rxq)
{
	union smb1_response_hdr *h = recv->response;
	struct smb_message *smb;
	struct smb_hdr *shdr = &h->hdr;
	int rc;

	smb = cifs_find_mid(server, shdr);
	if (!smb) {
		cifs_dbg(VFS, "%s: Unqueued mid (%x)\n",
			 __func__, le16_to_cpu(shdr->Mid));
		rxq->msg_id = 0;
	} else {
		rxq->msg_id = 0; /* TODO: smb->debug_id */
	}

	/* No session expiry check. */
	/* No status pending check. */
	/* SMB1 does not use credits. */

	if (cifs_is_network_name_deleted(&h->hdr, server))
		return;

	if (shdr->Status.CifsError != 0)
		recv->error = map_smb_to_linux_error(shdr, false);

	if (smb) {
		size_t resp_len = 0;

		/* handle_mid */
		smb->status		= shdr->Status.CifsError;
		smb->error		= recv->error;
		smb->credits_received	= smb->credits_consumed;
		smb->resp_data_len	= recv->data_len;
		smb->resp_data_offset	= recv->data_offset;

		trace_smb3_reply(smb, recv);

		if (h->hdr.Command == SMB_COM_TRANSACTION2 &&
		    !recv->malformed) {
			/* Handle multipart trans2-class messages. */
			rc = smb1_trans2_receive(server, smb, recv, rxq);
			if (rc == 1) {
				release_mid(server, smb);
				return; /* Multipart, incomplete. */
			}
			if (rc < 0)
				recv->malformed = true;
			smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
			goto extracted;
		}

		/* For a successful Read, we grab everthing up to the base of
		 * the read region, but no more.  This may include padding.
		 */
		resp_len = recv->msg_len;
		if (smb->status != 0)
			smb->copy_to_bufs = false;
		if (smb->copy_to_bufs) {
			resp_len = recv->data_offset;

			rc = smb_rxqueue_refill(server, rxq, recv->data_offset);
			if (rc < 0) {
				recv->malformed = true;
				goto extracted;
			}
		}

		if (resp_len <= MAX_CIFS_SMALL_BUFFER_SIZE) {
			server->smallbuf = NULL;
		} else if (resp_len <= CIFSMaxBufSize + MAX_SMB2_HDR_SIZE) {
			memcpy(server->bigbuf, server->smallbuf, recv->extracted);
			recv->response = server->bigbuf;
			server->bigbuf = NULL;
			recv->resp_buf_type = CIFS_LARGE_BUFFER;
			h = recv->response;
			shdr = &h->hdr;
		} else {
			/* Too big - should parse directly from iterator. */
			smb->error = -EMSGSIZE;
			cifs_dbg(FYI, "%s: Message too big\n", __func__);
		}

		smb->response = recv->response;
		smb->resp_len = resp_len;

		if (recv->extracted < recv->msg_len) {
			size_t part = resp_len - recv->extracted, got;

			got = netfs_rxqueue_read(rxq, recv->response + recv->extracted,
						 recv->extracted, part);
			recv->extracted += got;
			netfs_rxqueue_discard(rxq, recv->extracted);

			if (WARN_ON(got != part)) {
				smb->error = smb_EIO2(smb_eio_trace_rx_b_read_short,
						      got, part);
				smb->resp_len = recv->extracted;
				recv->malformed = true;
			} else if (smb->copy_to_bufs) {
				smb1_copy_to_prepped_buffers(server, smb, rxq,
							     recv);
			} else if (rxq->pdu_remain) {
				iov_iter_bvec_queue(&smb->response_iter, ITER_SOURCE,
						    rxq->take_from, rxq->take_slot,
						    rxq->take_offset, rxq->pdu_remain);
				smb->response_data = rxq->take_from;
				refcount_inc(&smb->response_data->ref);
			}
		} else {
			netfs_rxqueue_discard(rxq, recv->extracted);
		}

	extracted:
		dequeue_mid(server, smb, recv->malformed);
		mid_execute_callback(server, smb);

		release_mid(server, smb);
	} else if (smb1_is_valid_oplock_break(h, recv->msg_len, server)) {
		cifs_dbg(FYI, "Received oplock break\n");
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
	} else {
		cifs_server_dbg(VFS, "No task to wake, unknown frame received! NumMids %d\n",
				atomic_read(&mid_count));
		cifs_dump_mem("Received Data is: ", h, HEADER_SIZE(server));
#ifdef CONFIG_CIFS_DEBUG2
		cifs_dump_detail(server, recv);
		cifs_dump_mids(server);
#endif /* CIFS_DEBUG2 */
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
	}
}

/*
 * Receive and parse a received SMB1 PDU.
 *
 * At this point all the data has been read, any transformation unapplied,
 * decompression performed and some of it is stored in the receive queue
 * (excerpt) without either the rfc1002, transform or compression headers,
 * though some may yet to be received.
 */
static void smb1_parse_pdu(struct TCP_Server_Info *server,
			   struct netfs_rxqueue *rxq)
{
	union smb1_response_hdr *h;
	struct smb_hdr *shdr;
	unsigned int advance_get, part, got;
	int rc;

	server->lstrp = jiffies;

	struct cifs_receive recv = {
		.resp_buf_type	= CIFS_SMALL_BUFFER,
		.response	= server->smallbuf,
		.msg_len	= rxq->pdu_remain,
	};
	h = recv.response;
	shdr = &h->hdr;

	/* We try to grab the header if we can, plus the BCC field, assuming it
	 * to be trivially placed (ie. WCT==0).
	 *
	 * Now, it's possible for buggy servers to return less than the size of
	 * the header in certain cases, such as error cases, so we grab what
	 * there is of it and then fix up the short header.
	 */
	advance_get = umin(sizeof(h->trivial_rsp), rxq->pdu_remain);

	rc = smb_rxqueue_refill(server, rxq, advance_get);
	if (rc < 0)
		goto failed;

	got = netfs_rxqueue_read(rxq, recv.response, 0, advance_get);
	if (got != advance_get) {
		cifs_server_dbg(VFS, "SMB response too short (%u bytes)\n",
				rxq->qsize);
		goto failed;
	}
	recv.extracted = advance_get;

	/* Validate the header and fix up the message if it's too small due to
	 * known server bugs.
	 */
	recv.hdr_len = umin(sizeof(*shdr), recv.msg_len);
	if (recv.msg_len < sizeof(h->trivial_rsp)) {
		rc = smb1_fix_up_short_header(&recv);
		if (rc < 0)
			goto bad;
	}

	if (!check_smb_hdr(&recv))
		goto bad;

	/* Get the rest of the command-specific response header plus the BCC. */
	recv.hdr_len += h->hdr.WordCount * 2 + 2;
	if (recv.hdr_len > sizeof(*h)) {
		cifs_dbg(VFS, "%s: can't read BCC due to invalid WordCount(%u)\n",
			 __func__, h->hdr.WordCount);
		goto bad;
	}

	/* If it's a successful read, then wait for the header. */
	if (shdr->Command == SMB_COM_READ_ANDX &&
	    shdr->Status.CifsError == 0)
		advance_get = recv.hdr_len;
	else
		advance_get = recv.msg_len;

	rc = smb_rxqueue_refill(server, rxq, advance_get);
	if (rc < 0)
		goto failed;

	part = recv.hdr_len - recv.extracted;
	got = netfs_rxqueue_read(rxq, (void *)recv.response + recv.extracted,
				 recv.extracted, part);
	if (got != part) {
		cifs_server_dbg(VFS, "rxqueue_read failed (%u bytes)\n",
				rxq->qsize);
		goto failed;
	}
	recv.extracted += got;

	/*
	 * We've got the MID and the BCC.  Now check to see if the rest of the
	 * header is OK.  Note that we've only extracted up to and including
	 * the BCC at this point; everything else is either in the receive
	 * queue or still pending (i.e. for the data in a Read).
	 */
	rc = checkSMB(server, &recv);
	if (rc) {
		recv.malformed = true;
		goto bad;
	}

	smb1_parse_one_message(server, &recv, rxq);

discard:
	WARN(rxq->pdu_remain > 0, "pdu_remain=%x", rxq->pdu_remain);
	smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
	return;

bad:
	/*
	 * 48 bytes is enough to display the header and a little bit into the
	 * payload for debugging purposes.
	 */
	cifs_dump_mem("Bad SMB: ", h, umin(recv.msg_len, 48));
failed:
	set_bit(SMB_SERVER_NEED_RECONNECT, &server->flags);
	goto discard;
}

/*
 * Receive and parse an SMB1 PDU.  We need to wait for data to come in until we
 * have enough and then we have to reverse transformations and perform
 * decompression before we can fully parse the message contents.
 */
int smb1_receive_pdu(struct TCP_Server_Info *server, unsigned int pdu_len)
{
	/* There are no transformations in SMB1. */
	smb1_parse_pdu(server, &server->rx_queue);
	return 0;
}
