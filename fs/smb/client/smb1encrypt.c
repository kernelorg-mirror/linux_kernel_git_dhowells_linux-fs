// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Encryption and hashing operations relating to NTLM, NTLMv2.  See MS-NLMP
 *   for more detailed information
 *
 *   Copyright (C) International Business Machines  Corp., 2005,2013
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 */

#include <linux/fips.h>
#include <linux/iov_iter.h>
#include <crypto/md5.h>
#include <crypto/utils.h>
#include "cifsproto.h"
#include "smb1proto.h"
#include "cifs_debug.h"

static size_t cifs_md5_step(void *iter_base, size_t progress, size_t len,
			    void *priv, void *priv2)
{
	struct md5_ctx *ctx = priv;

	md5_update(ctx, iter_base, len);
	return 0;
}

static int cifs_md5_iter(struct iov_iter *iter, size_t maxsize,
			 struct md5_ctx *ctx)
{
	size_t did;

	did = iterate_and_advance_kernel(iter, maxsize, ctx, NULL,
					 cifs_md5_step);
	if (did != maxsize)
		return smb_EIO2(smb_eio_trace_md5_iter, did, maxsize);
	return 0;
}

/*
 * Calculate and return the CIFS signature based on the mac key and SMB PDU.
 * The 16 byte signature must be allocated by the caller. Note we only use the
 * 1st eight bytes and that the smb header signature field on input contains
 * the sequence number before this function is called. Also, this function
 * should be called with the server->srv_mutex held.
 */
static int cifs_calc_signature(struct smb_rqst *rqst,
			struct TCP_Server_Info *server, char *signature)
{
	struct md5_ctx ctx;

	if (!rqst->rq_iov || !signature || !server)
		return -EINVAL;
	if (fips_enabled) {
		cifs_dbg(VFS,
			 "MD5 signature support is disabled due to FIPS\n");
		return -EOPNOTSUPP;
	}

	md5_init(&ctx);
	md5_update(&ctx, server->session_key.response, server->session_key.len);

	return __cifs_calc_signature(
		rqst, server, signature,
		&(struct cifs_calc_sig_ctx){ .md5 = &ctx });
}

/* must be called with server->srv_mutex held */
int cifs_sign_rqst(struct smb_rqst *rqst, struct TCP_Server_Info *server,
		   __u32 *pexpected_response_sequence_number)
{
	int rc = 0;
	char smb_signature[20];
	struct smb_hdr *cifs_pdu = (struct smb_hdr *)rqst->rq_iov[0].iov_base;

	if ((cifs_pdu == NULL) || (server == NULL))
		return -EINVAL;

	spin_lock(&server->srv_lock);
	if (!(cifs_pdu->Flags2 & SMBFLG2_SECURITY_SIGNATURE) ||
	    server->tcpStatus == CifsNeedNegotiate) {
		spin_unlock(&server->srv_lock);
		return rc;
	}
	spin_unlock(&server->srv_lock);

	if (!server->session_estab) {
		memcpy(cifs_pdu->Signature.SecuritySignature, "BSRSPYL", 8);
		return rc;
	}

	cifs_pdu->Signature.Sequence.SequenceNumber =
				cpu_to_le32(server->sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	*pexpected_response_sequence_number = ++server->sequence_number;
	++server->sequence_number;

	rc = cifs_calc_signature(rqst, server, smb_signature);
	if (rc)
		memset(cifs_pdu->Signature.SecuritySignature, 0, 8);
	else
		memcpy(cifs_pdu->Signature.SecuritySignature, smb_signature, 8);

	return rc;
}

int cifs_verify_signature(struct smb_rqst *rqst,
			  struct TCP_Server_Info *server,
			  __u32 expected_sequence_number)
{
	unsigned int rc;
	char server_response_sig[8];
	char what_we_think_sig_should_be[20];
	struct smb_hdr *cifs_pdu = (struct smb_hdr *)rqst->rq_iov[0].iov_base;

	if (cifs_pdu == NULL || server == NULL)
		return -EINVAL;

	if (!server->session_estab)
		return 0;

	if (cifs_pdu->Command == SMB_COM_LOCKING_ANDX) {
		struct smb_com_lock_req *pSMB =
			(struct smb_com_lock_req *)cifs_pdu;
		if (pSMB->LockType & LOCKING_ANDX_OPLOCK_RELEASE)
			return 0;
	}

	/* BB what if signatures are supposed to be on for session but
	   server does not send one? BB */

	/* Do not need to verify session setups with signature "BSRSPYL "  */
	if (memcmp(cifs_pdu->Signature.SecuritySignature, "BSRSPYL ", 8) == 0)
		cifs_dbg(FYI, "dummy signature received for smb command 0x%x\n",
			 cifs_pdu->Command);

	/* save off the original signature so we can modify the smb and check
		its signature against what the server sent */
	memcpy(server_response_sig, cifs_pdu->Signature.SecuritySignature, 8);

	cifs_pdu->Signature.Sequence.SequenceNumber =
					cpu_to_le32(expected_sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	cifs_server_lock(server);
	rc = cifs_calc_signature(rqst, server, what_we_think_sig_should_be);
	cifs_server_unlock(server);

	if (rc)
		return rc;

/*	cifs_dump_mem("what we think it should be: ",
		      what_we_think_sig_should_be, 16); */

	if (crypto_memneq(server_response_sig, what_we_think_sig_should_be, 8))
		return -EACCES;
	else
		return 0;

}

/*
 * Calculate and return the CIFS signature based on the mac key and SMB PDU.
 * The 16 byte signature must be allocated by the caller. Note we only use the
 * 1st eight bytes and that the smb header signature field on input contains
 * the sequence number before this function is called. Also, this function
 * should be called with the server->srv_mutex held.
 */
static int cifs_calc_trans_signature(struct TCP_Server_Info *server,
				     struct cifs_receive *recv,
				     struct iov_iter *message,
				     char *signature)
{
	struct iov_iter iter;
	struct md5_ctx ctx;
	struct kvec kv[1] = {
		[0].iov_len  = recv->extracted,
		[0].iov_base = recv->response,
	};
	size_t did;
	int rc;

	md5_init(&ctx);
	md5_update(&ctx, server->session_key.response, server->session_key.len);

	iov_iter_kvec(&iter, ITER_SOURCE, kv, 3, recv->extracted);

	did = iterate_kvec(&iter, recv->extracted, &ctx, NULL, cifs_md5_step);
	if (did != recv->extracted)
		return smb_EIO2(smb_eio_trace_md5_iter, did, recv->extracted);

	iter = *message;
	rc = cifs_md5_iter(&iter, recv->msg_len - recv->extracted, &ctx);
	if (rc < 0)
		return rc;

	md5_final(&ctx, signature);
	return 0;
}

/*
 * Verify the signature on a Trans/Trans2/NTTrans packet that's incompletely
 * extracted from the Rx queue.  We need to do this in the I/O thread unless we
 * want to punt the entire reassembly process to cifs_check_receive() as
 * reassembly will corrupt the signatures.
 */
int cifs_verify_trans_signature(struct TCP_Server_Info *server,
				struct cifs_receive *recv,
				struct netfs_rxqueue *rxq,
				__u32 expected_sequence_number)
{
	union smb1_response_hdr *h = recv->response;
	struct iov_iter iter;
	struct smb_hdr *cifs_pdu = &h->hdr;
	char what_we_think_sig_should_be[20];
	char server_response_sig[8];
	int rc;

	/* BB what if signatures are supposed to be on for session but
	   server does not send one? BB */

	/* Do not need to verify session setups with signature "BSRSPYL "  */
	if (memcmp(cifs_pdu->Signature.SecuritySignature, "BSRSPYL ", 8) == 0)
		cifs_dbg(FYI, "dummy signature received for smb command 0x%x\n",
			 cifs_pdu->Command);

	/* save off the original signature so we can modify the smb and check
		its signature against what the server sent */
	memcpy(server_response_sig, cifs_pdu->Signature.SecuritySignature, 8);
	cifs_pdu->Signature.Sequence.SequenceNumber =
					cpu_to_le32(expected_sequence_number);
	cifs_pdu->Signature.Sequence.Reserved = 0;

	iov_iter_bvec_queue(&iter, ITER_SOURCE, rxq->take_from,
			    rxq->take_slot, rxq->take_offset,
			    umin(rxq->qsize, rxq->pdu_remain));

	cifs_server_lock(server);
	rc = cifs_calc_trans_signature(server, recv, &iter,
				       what_we_think_sig_should_be);
	cifs_server_unlock(server);

	if (rc)
		return rc;

	if (memcmp(server_response_sig, what_we_think_sig_should_be, 8) != 0)
		return -EACCES;
	return 0;
}
