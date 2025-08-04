// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002, 2011
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Jeremy Allison (jra@samba.org) 2006
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/uaccess.h>
#include <asm/processor.h>
#include <linux/mempool.h>
#include <linux/highmem.h>
#include <linux/iov_iter.h>
#include <crypto/aead.h>
#include <crypto/aes-cbc-macs.h>
#include <crypto/sha2.h>
#include <crypto/utils.h>
#include "cifsglob.h"
#include "cifsproto.h"
#include "smb2proto.h"
#include "cifs_debug.h"
#include "../common/smb2status.h"
#include "smb2glob.h"

static void smb2_parse_pdu(struct TCP_Server_Info *server,
			   struct netfs_rxqueue *rxq);

static
int smb3_get_sign_key(__u64 ses_id, struct TCP_Server_Info *server, u8 *key)
{
	struct cifs_chan *chan;
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses = NULL;
	int i;
	int rc = 0;
	bool is_binding = false;

	spin_lock(&cifs_tcp_ses_lock);

	/* If server is a channel, select the primary channel */
	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;

	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (ses->Suid == ses_id)
			goto found;
	}
	trace_smb3_ses_not_found(ses_id);
	cifs_server_dbg(FYI, "%s: Could not find session 0x%llx\n",
			__func__, ses_id);
	rc = -ENOENT;
	goto out;

found:
	spin_lock(&ses->ses_lock);
	spin_lock(&ses->chan_lock);

	is_binding = (cifs_chan_needs_reconnect(ses, server) &&
		      ses->ses_status == SES_GOOD);
	if (is_binding) {
		/*
		 * If we are in the process of binding a new channel
		 * to an existing session, use the master connection
		 * session key
		 */
		memcpy(key, ses->smb3signingkey, SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->chan_lock);
		spin_unlock(&ses->ses_lock);
		goto out;
	}

	/*
	 * Otherwise, use the channel key.
	 */

	for (i = 0; i < ses->chan_count; i++) {
		chan = ses->chans + i;
		if (chan->server == server) {
			memcpy(key, chan->signkey, SMB3_SIGN_KEY_SIZE);
			spin_unlock(&ses->chan_lock);
			spin_unlock(&ses->ses_lock);
			goto out;
		}
	}
	spin_unlock(&ses->chan_lock);
	spin_unlock(&ses->ses_lock);

	cifs_dbg(VFS,
		 "%s: Could not find channel signing key for session 0x%llx\n",
		 __func__, ses_id);
	rc = -ENOENT;

out:
	spin_unlock(&cifs_tcp_ses_lock);
	return rc;
}

static struct cifs_ses *
smb2_find_smb_ses_unlocked(struct TCP_Server_Info *server, __u64 ses_id)
{
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses;

	/* If server is a channel, select the primary channel */
	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;

	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (ses->Suid != ses_id)
			continue;

		spin_lock(&ses->ses_lock);
		if (ses->ses_status == SES_EXITING) {
			spin_unlock(&ses->ses_lock);
			continue;
		}
		cifs_smb_ses_inc_refcount(ses);
		spin_unlock(&ses->ses_lock);
		return ses;
	}

	return NULL;
}

static int smb2_get_sign_key(struct TCP_Server_Info *server,
			     __u64 ses_id, u8 *key)
{
	struct cifs_ses *ses;
	int rc = -ENOENT;

	if (SERVER_IS_CHAN(server))
		server = server->primary_server;

	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &server->smb_ses_list, smb_ses_list) {
		if (ses->Suid != ses_id)
			continue;

		rc = 0;
		spin_lock(&ses->ses_lock);
		switch (ses->ses_status) {
		case SES_EXITING: /* SMB2_LOGOFF */
		case SES_GOOD:
			if (likely(ses->auth_key.response)) {
				memcpy(key, ses->auth_key.response,
				       SMB2_NTLMV2_SESSKEY_SIZE);
			} else {
				rc = smb_EIO(smb_eio_trace_no_auth_key);
			}
			break;
		default:
			rc = -EAGAIN;
			break;
		}
		spin_unlock(&ses->ses_lock);
		break;
	}
	spin_unlock(&cifs_tcp_ses_lock);
	return rc;
}

static struct cifs_tcon *
smb2_find_smb_sess_tcon_unlocked(struct cifs_ses *ses, __u32  tid)
{
	struct cifs_tcon *tcon;

	list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
		if (tcon->tid != tid)
			continue;
		spin_lock(&tcon->tc_lock);
		++tcon->tc_count;
		spin_unlock(&tcon->tc_lock);
		trace_smb3_tcon_ref(tcon->debug_id, tcon->tc_count,
				    netfs_trace_tcon_ref_get_find_sess_tcon);
		return tcon;
	}

	return NULL;
}

/*
 * Obtain tcon corresponding to the tid in the given
 * cifs_ses
 */

struct cifs_tcon *
smb2_find_smb_tcon(struct TCP_Server_Info *server, __u64 ses_id, __u32  tid)
{
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;

	spin_lock(&cifs_tcp_ses_lock);
	ses = smb2_find_smb_ses_unlocked(server, ses_id);
	if (!ses) {
		spin_unlock(&cifs_tcp_ses_lock);
		return NULL;
	}
	tcon = smb2_find_smb_sess_tcon_unlocked(ses, tid);
	spin_unlock(&cifs_tcp_ses_lock);
	/* tcon already has a ref to ses, so we don't need ses anymore */
	cifs_put_smb_ses(ses);

	return tcon;
}

static int
smb2_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	int rc;
	unsigned char smb2_signature[SMB2_HMACSHA256_SIZE];
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct hmac_sha256_ctx hmac_ctx;
	struct smb_rqst drqst;
	__u64 sid = le64_to_cpu(shdr->SessionId);
	u8 key[SMB2_NTLMV2_SESSKEY_SIZE];

	rc = smb2_get_sign_key(server, sid, key);
	if (unlikely(rc)) {
		cifs_server_dbg(FYI, "%s: [sesid=0x%llx] couldn't find signing key: %d\n",
				__func__, sid, rc);
		return rc;
	}

	memset(smb2_signature, 0x0, SMB2_HMACSHA256_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	hmac_sha256_init_usingrawkey(&hmac_ctx, key, sizeof(key));

	/*
	 * For SMB2+, __cifs_calc_signature() expects to sign only the actual
	 * data, that is, iov[0] should not contain a rfc1002 length.
	 *
	 * Sign the rfc1002 length prior to passing the data (iov[1-N]) down to
	 * __cifs_calc_signature().
	 */
	drqst = *rqst;
	if (drqst.rq_nvec >= 2 && iov[0].iov_len == 4) {
		hmac_sha256_update(&hmac_ctx, iov[0].iov_base, iov[0].iov_len);
		drqst.rq_iov++;
		drqst.rq_nvec--;
	}

	rc = __cifs_calc_signature(
		&drqst, server, smb2_signature,
		&(struct cifs_calc_sig_ctx){ .hmac = &hmac_ctx });
	if (!rc)
		memcpy(shdr->Signature, smb2_signature, SMB2_SIGNATURE_SIZE);

	return rc;
}

static void generate_key(struct cifs_ses *ses, struct kvec label,
			 struct kvec context, __u8 *key, unsigned int key_size,
			 unsigned int full_key_size)
{
	unsigned char zero = 0x0;
	__u8 i[4] = {0, 0, 0, 1};
	__u8 L128[4] = {0, 0, 0, 128};
	__u8 L256[4] = {0, 0, 1, 0};
	unsigned char prfhash[SMB2_HMACSHA256_SIZE];
	struct TCP_Server_Info *server = ses->server;
	struct hmac_sha256_ctx hmac_ctx;

	memset(prfhash, 0x0, SMB2_HMACSHA256_SIZE);
	memset(key, 0x0, key_size);

	hmac_sha256_init_usingrawkey(&hmac_ctx, ses->auth_key.response,
				     full_key_size);
	hmac_sha256_update(&hmac_ctx, i, 4);
	hmac_sha256_update(&hmac_ctx, label.iov_base, label.iov_len);
	hmac_sha256_update(&hmac_ctx, &zero, 1);
	hmac_sha256_update(&hmac_ctx, context.iov_base, context.iov_len);

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		hmac_sha256_update(&hmac_ctx, L256, 4);
	} else {
		hmac_sha256_update(&hmac_ctx, L128, 4);
	}
	hmac_sha256_final(&hmac_ctx, prfhash);

	memcpy(key, prfhash, key_size);
}

struct derivation {
	struct kvec label;
	struct kvec context;
};

struct derivation_triplet {
	struct derivation signing;
	struct derivation encryption;
	struct derivation decryption;
};

static int
generate_smb3signingkey(struct cifs_ses *ses,
			struct TCP_Server_Info *server,
			const struct derivation_triplet *ptriplet)
{
	unsigned int full_key_size = SMB2_NTLMV2_SESSKEY_SIZE;
	bool is_binding = false;
	int chan_index = 0;

	spin_lock(&ses->ses_lock);
	spin_lock(&ses->chan_lock);
	is_binding = (cifs_chan_needs_reconnect(ses, server) &&
		      ses->ses_status == SES_GOOD);

	chan_index = cifs_ses_get_chan_index(ses, server);
	if (chan_index == CIFS_INVAL_CHAN_INDEX) {
		spin_unlock(&ses->chan_lock);
		spin_unlock(&ses->ses_lock);

		return -EINVAL;
	}

	spin_unlock(&ses->chan_lock);
	spin_unlock(&ses->ses_lock);

	/*
	 * All channels use the same encryption/decryption keys but
	 * they have their own signing key.
	 *
	 * When we generate the keys, check if it is for a new channel
	 * (binding) in which case we only need to generate a signing
	 * key and store it in the channel as to not overwrite the
	 * master connection signing key stored in the session
	 */

	if (is_binding) {
		generate_key(ses, ptriplet->signing.label,
			     ptriplet->signing.context,
			     ses->chans[chan_index].signkey, SMB3_SIGN_KEY_SIZE,
			     SMB2_NTLMV2_SESSKEY_SIZE);
	} else {
		generate_key(ses, ptriplet->signing.label,
			     ptriplet->signing.context, ses->smb3signingkey,
			     SMB3_SIGN_KEY_SIZE, SMB2_NTLMV2_SESSKEY_SIZE);

		/*
		 * Per MS-SMB2 3.2.5.3.1, signing key always uses Session.SessionKey
		 * (first 16 bytes). Encryption/decryption keys use
		 * Session.FullSessionKey when dialect is 3.1.1 and cipher is
		 * AES-256-CCM or AES-256-GCM, otherwise Session.SessionKey.
		 */

		if (server->dialect == SMB311_PROT_ID &&
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_CCM ||
		     server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			full_key_size = ses->auth_key.len;

		/* safe to access primary channel, since it will never go away */
		spin_lock(&ses->chan_lock);
		memcpy(ses->chans[chan_index].signkey, ses->smb3signingkey,
		       SMB3_SIGN_KEY_SIZE);
		spin_unlock(&ses->chan_lock);

		generate_key(ses, ptriplet->encryption.label,
			     ptriplet->encryption.context,
			     ses->smb3encryptionkey, SMB3_ENC_DEC_KEY_SIZE,
			     full_key_size);

		generate_key(ses, ptriplet->decryption.label,
			     ptriplet->decryption.context,
			     ses->smb3decryptionkey, SMB3_ENC_DEC_KEY_SIZE,
			     full_key_size);
	}

#ifdef CONFIG_CIFS_DEBUG_DUMP_KEYS
	cifs_dbg(VFS, "%s: dumping generated AES session keys\n", __func__);
	/*
	 * The session id is opaque in terms of endianness, so we can't
	 * print it as a long long. we dump it as we got it on the wire
	 */
	cifs_dbg(VFS, "Session Id    %*ph\n", (int)sizeof(ses->Suid),
			&ses->Suid);
	cifs_dbg(VFS, "Cipher type   %d\n", server->cipher_type);
	cifs_dbg(VFS, "Session Key   %*ph\n",
		 (int)ses->auth_key.len, ses->auth_key.response);
	cifs_dbg(VFS, "Signing Key   %*ph\n",
		 SMB3_SIGN_KEY_SIZE, ses->smb3signingkey);
	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM)) {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM256_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	} else {
		cifs_dbg(VFS, "ServerIn Key  %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3encryptionkey);
		cifs_dbg(VFS, "ServerOut Key %*ph\n",
				SMB3_GCM128_CRYPTKEY_SIZE, ses->smb3decryptionkey);
	}
#endif
	return 0;
}

int
generate_smb30signingkey(struct cifs_ses *ses,
			 struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMB2AESCMAC";
	d->label.iov_len = 12;
	d->context.iov_base = "SmbSign";
	d->context.iov_len = 8;

	d = &triplet.encryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerIn ";
	d->context.iov_len = 10;

	d = &triplet.decryption;
	d->label.iov_base = "SMB2AESCCM";
	d->label.iov_len = 11;
	d->context.iov_base = "ServerOut";
	d->context.iov_len = 10;

	return generate_smb3signingkey(ses, server, &triplet);
}

int
generate_smb311signingkey(struct cifs_ses *ses,
			  struct TCP_Server_Info *server)

{
	struct derivation_triplet triplet;
	struct derivation *d;

	d = &triplet.signing;
	d->label.iov_base = "SMBSigningKey";
	d->label.iov_len = 14;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.encryption;
	d->label.iov_base = "SMBC2SCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	d = &triplet.decryption;
	d->label.iov_base = "SMBS2CCipherKey";
	d->label.iov_len = 16;
	d->context.iov_base = ses->preauth_sha_hash;
	d->context.iov_len = 64;

	return generate_smb3signingkey(ses, server, &triplet);
}

static int
smb3_calc_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	int rc;
	unsigned char smb3_signature[SMB2_CMACAES_SIZE];
	struct kvec *iov = rqst->rq_iov;
	struct smb2_hdr *shdr = (struct smb2_hdr *)iov[0].iov_base;
	struct aes_cmac_key cmac_key __cleanup(aes_cmac_zeroize_key);
	struct aes_cmac_ctx cmac_ctx __cleanup(aes_cmac_zeroize_ctx);
	struct smb_rqst drqst;
	u8 key[SMB3_SIGN_KEY_SIZE];

	if (server->vals->protocol_id <= SMB21_PROT_ID)
		return smb2_calc_signature(rqst, server);

	rc = smb3_get_sign_key(le64_to_cpu(shdr->SessionId), server, key);
	if (unlikely(rc)) {
		cifs_server_dbg(FYI, "%s: Could not get signing key\n", __func__);
		return rc;
	}

	memset(smb3_signature, 0x0, SMB2_CMACAES_SIZE);
	memset(shdr->Signature, 0x0, SMB2_SIGNATURE_SIZE);

	rc = aes_cmac_preparekey(&cmac_key, key, SMB2_CMACAES_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Could not set key for cmac aes\n", __func__);
		return rc;
	}

	aes_cmac_init(&cmac_ctx, &cmac_key);

	/*
	 * For SMB2+, __cifs_calc_signature() expects to sign only the actual
	 * data, that is, iov[0] should not contain a rfc1002 length.
	 *
	 * Sign the rfc1002 length prior to passing the data (iov[1-N]) down to
	 * __cifs_calc_signature().
	 */
	drqst = *rqst;
	if (drqst.rq_nvec >= 2 && iov[0].iov_len == 4) {
		aes_cmac_update(&cmac_ctx, iov[0].iov_base, iov[0].iov_len);
		drqst.rq_iov++;
		drqst.rq_nvec--;
	}

	rc = __cifs_calc_signature(
		&drqst, server, smb3_signature,
		&(struct cifs_calc_sig_ctx){ .cmac = &cmac_ctx });
	if (!rc)
		memcpy(shdr->Signature, smb3_signature, SMB2_SIGNATURE_SIZE);
	return rc;
}

/* must be called with server->srv_mutex held */
static int
smb2_sign_rqst(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	struct smb2_hdr *shdr;
	struct smb2_sess_setup_req *ssr;
	bool is_binding;
	bool is_signed;

	shdr = (struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	ssr = (struct smb2_sess_setup_req *)shdr;

	is_binding = shdr->Command == SMB2_SESSION_SETUP &&
		(ssr->Flags & SMB2_SESSION_REQ_FLAG_BINDING);
	is_signed = shdr->Flags & SMB2_FLAGS_SIGNED;

	if (!is_signed)
		return 0;
	spin_lock(&server->srv_lock);
	if (server->ops->need_neg &&
	    server->ops->need_neg(server)) {
		spin_unlock(&server->srv_lock);
		return 0;
	}
	spin_unlock(&server->srv_lock);
	if (!is_binding && !server->session_estab) {
		strscpy(shdr->Signature, "BSRSPYL");
		return 0;
	}

	return smb3_calc_signature(rqst, server);
}

int
smb2_verify_signature(struct smb_rqst *rqst, struct TCP_Server_Info *server)
{
	int rc;
	char server_response_sig[SMB2_SIGNATURE_SIZE];
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;

	if ((shdr->Command == SMB2_NEGOTIATE) ||
	    (shdr->Command == SMB2_SESSION_SETUP) ||
	    (shdr->Command == SMB2_OPLOCK_BREAK) ||
	    server->ignore_signature ||
	    (!server->session_estab))
		return 0;

	/*
	 * BB what if signatures are supposed to be on for session but
	 * server does not send one? BB
	 */

	/* Do not need to verify session setups with signature "BSRSPYL " */
	if (memcmp(shdr->Signature, "BSRSPYL ", 8) == 0)
		cifs_dbg(FYI, "dummy signature received for smb command 0x%x\n",
			 shdr->Command);

	/*
	 * Save off the original signature so we can modify the smb and check
	 * our calculated signature against what the server sent.
	 */
	memcpy(server_response_sig, shdr->Signature, SMB2_SIGNATURE_SIZE);

	memset(shdr->Signature, 0, SMB2_SIGNATURE_SIZE);

	rc = smb3_calc_signature(rqst, server);

	if (rc)
		return rc;

	if (crypto_memneq(server_response_sig, shdr->Signature,
			  SMB2_SIGNATURE_SIZE)) {
		cifs_dbg(VFS, "sign fail cmd 0x%x message id 0x%llx\n",
			shdr->Command, shdr->MessageId);
		return -EACCES;
	} else
		return 0;
}

/*
 * Set message id for the request. Should be called after wait_for_free_request
 * and when srv_mutex is held.
 */
static inline void
smb2_seq_num_into_buf(struct TCP_Server_Info *server,
		      struct smb2_hdr *shdr)
{
	unsigned int i, num = le16_to_cpu(shdr->CreditCharge);

	shdr->MessageId = get_next_mid64(server);
	/* skip message numbers according to CreditCharge field */
	for (i = 1; i < num; i++)
		get_next_mid(server);
}

static struct smb_message *
smb2_mid_entry_alloc(const struct smb2_hdr *shdr,
		     struct TCP_Server_Info *server)
{
	struct smb_message *smb;
	unsigned int credits = le16_to_cpu(shdr->CreditCharge);

	if (server == NULL) {
		cifs_dbg(VFS, "Null TCP session in smb2_mid_entry_alloc\n");
		return NULL;
	}

	smb = mempool_alloc(&smb_message_pool, GFP_NOFS);
	memset(smb, 0, sizeof(*smb));
	refcount_set(&smb->ref, 1);
	spin_lock_init(&smb->mid_lock);
	smb->mid = le64_to_cpu(shdr->MessageId);
	smb->credits_consumed = credits > 0 ? credits : 1;
	smb->pid = current->pid;
	smb->command = shdr->Command; /* Always LE */
	smb->when_alloc = jiffies;

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
	trace_smb3_cmd_enter(le32_to_cpu(shdr->Id.SyncId.TreeId),
			     le64_to_cpu(shdr->SessionId),
			     le16_to_cpu(shdr->Command), smb->mid);
	return smb;
}

static int
smb2_get_mid_entry(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb2_hdr *shdr, struct smb_message **smb)
{
	switch (READ_ONCE(server->tcpStatus)) {
	case CifsExiting:
		return -ENOENT;
	case CifsNeedReconnect:
		cifs_dbg(FYI, "tcp session dead - return to caller to retry\n");
		return -EAGAIN;
	case CifsNeedNegotiate:
		if (shdr->Command != SMB2_NEGOTIATE)
			return -EAGAIN;
		break;
	default:
		break;
	}

	switch (READ_ONCE(ses->ses_status)) {
	case SES_NEW:
		if (shdr->Command != SMB2_SESSION_SETUP &&
		    shdr->Command != SMB2_NEGOTIATE)
			return -EAGAIN;
			/* else ok - we are setting up session */
		break;
	case SES_EXITING:
		if (shdr->Command != SMB2_LOGOFF)
			return -EAGAIN;
		/* else ok - we are shutting down the session */
		break;
	default:
		break;
	}

	*smb = smb2_mid_entry_alloc(shdr, server);
	if (*smb == NULL)
		return -ENOMEM;
	spin_lock(&server->mid_queue_lock);
	list_add_tail(&(*smb)->qhead, &server->pending_mid_q);
	spin_unlock(&server->mid_queue_lock);

	return 0;
}

int
smb2_check_receive(struct smb_message *smb, struct TCP_Server_Info *server,
		   bool log_error)
{
	unsigned int len = smb->resp_len;
	struct kvec iov[1];
	struct smb_rqst rqst = { .rq_iov = iov,
				 .rq_nvec = 1 };

	iov[0].iov_base = (char *)smb->response;
	iov[0].iov_len = len;

	dump_smb(smb->response, min_t(u32, 80, len));
	/* convert the length into a more usable form */
	if (len > 24 && server->sign && !smb->decrypted) {
		int rc;

		rc = smb2_verify_signature(&rqst, server);
		if (rc)
			cifs_server_dbg(VFS, "SMB signature verification returned error = %d\n",
					rc);
	}

	return map_smb2_to_linux_error(smb->response, log_error);
}

struct smb_message *
smb2_setup_request(struct cifs_ses *ses, struct TCP_Server_Info *server,
		   struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct smb_message *smb;

	smb2_seq_num_into_buf(server, shdr);

	rc = smb2_get_mid_entry(ses, server, shdr, &smb);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(rc);
	}

	rc = smb2_sign_rqst(rqst, server);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		delete_mid(server, smb);
		return ERR_PTR(rc);
	}

	return smb;
}

struct smb_message *
smb2_setup_async_request(struct TCP_Server_Info *server, struct smb_rqst *rqst)
{
	int rc;
	struct smb2_hdr *shdr =
			(struct smb2_hdr *)rqst->rq_iov[0].iov_base;
	struct smb_message *smb;

	spin_lock(&server->srv_lock);
	if (server->tcpStatus == CifsNeedNegotiate &&
	   shdr->Command != SMB2_NEGOTIATE) {
		spin_unlock(&server->srv_lock);
		return ERR_PTR(-EAGAIN);
	}
	spin_unlock(&server->srv_lock);

	smb2_seq_num_into_buf(server, shdr);

	smb = smb2_mid_entry_alloc(shdr, server);
	if (smb == NULL) {
		revert_current_mid_from_hdr(server, shdr);
		return ERR_PTR(-ENOMEM);
	}

	rc = smb2_sign_rqst(rqst, server);
	if (rc) {
		revert_current_mid_from_hdr(server, shdr);
		release_mid(server, smb);
		return ERR_PTR(rc);
	}

	return smb;
}

int
smb3_crypto_aead_allocate(struct TCP_Server_Info *server)
{
	struct crypto_aead *tfm;

	if (!server->secmech.enc) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			cifs_server_dbg(VFS, "%s: Failed alloc encrypt aead\n",
				 __func__);
			return PTR_ERR(tfm);
		}
		server->secmech.enc = tfm;
	}

	if (!server->secmech.dec) {
		if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
		    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
			tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
		else
			tfm = crypto_alloc_aead("ccm(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			crypto_free_aead(server->secmech.enc);
			server->secmech.enc = NULL;
			cifs_server_dbg(VFS, "%s: Failed to alloc decrypt aead\n",
				 __func__);
			return PTR_ERR(tfm);
		}
		server->secmech.dec = tfm;
	}

	return 0;
}

/*
 * Allocate the context info needed for the encryption operation, along with a
 * scatterlist to point to the buffer.
 */
static void *smb2_aead_req_alloc_new(struct crypto_aead *tfm, const struct iov_iter *iter,
				 u8 **iv,
				 struct aead_request **req, struct sg_table *sgt,
				 unsigned int *num_sgs, size_t *sensitive_size)
{
	unsigned int req_size = sizeof(**req) + crypto_aead_reqsize(tfm);
	unsigned int iv_size = crypto_aead_ivsize(tfm);
	unsigned int len;
	u8 *p;

	*num_sgs = iov_iter_npages(iter, INT_MAX);

	len = iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += array_size(*num_sgs + 2, sizeof(struct scatterlist));
	*sensitive_size = len;

	p = kvzalloc(len, GFP_NOFS);
	if (!p)
		return ERR_PTR(-ENOMEM);

	*iv = (u8 *)PTR_ALIGN(p, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
						crypto_tfm_ctx_alignment());
	sgt->sgl = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
						   __alignof__(struct scatterlist));
	return p;
}

/*
 * Set up for doing a crypto operation, building a scatterlist from the
 * supplied iterator.
 */
static void *smb2_get_aead_req_new(struct crypto_aead *tfm, const struct iov_iter *iter,
				   const u8 *sig, u8 **iv,
				   struct aead_request **req, struct scatterlist **sgl,
				   size_t *sensitive_size)
{
	struct sg_table sgtable = {};
	struct iov_iter tmp = *iter;
	unsigned int num_sgs;
	ssize_t rc;
	void *p;

	p = smb2_aead_req_alloc_new(tfm, iter, iv, req, &sgtable,
				    &num_sgs, sensitive_size);
	if (IS_ERR(p))
		return ERR_CAST(p);

	sg_init_marker(sgtable.sgl, num_sgs + 2);

	rc = extract_iter_to_sg(&tmp, iov_iter_count(iter), &sgtable, num_sgs, 0);
	sgtable.orig_nents = sgtable.nents + 1;
	if (rc < 0)
		return ERR_PTR(rc);

	cifs_sg_set_buf(&sgtable, sig, SMB2_SIGNATURE_SIZE);
	sg_mark_end(&sgtable.sgl[sgtable.nents - 1]);
	*sgl = sgtable.sgl;
	return p;
}

/*
 * Encrypt the message in the buffer described by the iterator.
 * On success return encrypted data in iov[1-N] and pages, leave iov[0]
 * untouched.
 */
static int
encrypt_message(struct TCP_Server_Info *server,
		struct smb2_transform_hdr *tr_hdr,
		struct iov_iter *iter, struct crypto_aead *tfm)
{
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 20;
	int rc = 0;
	struct scatterlist *sg;
	u8 key[SMB3_ENC_DEC_KEY_SIZE];
	struct aead_request *req;
	u8 *iv;
	DECLARE_CRYPTO_WAIT(wait);
	unsigned int crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);
	void *creq;
	size_t sensitive_size;

	rc = smb2_get_enc_key(server, le64_to_cpu(tr_hdr->SessionId), 1, key);
	if (rc) {
		cifs_server_dbg(FYI, "%s: Could not get encryption key. sid: 0x%llx\n",
				__func__, le64_to_cpu(tr_hdr->SessionId));
		return rc;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM256_CRYPTKEY_SIZE);
	else
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM128_CRYPTKEY_SIZE);

	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set aead key %d\n", __func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set authsize %d\n", __func__, rc);
		return rc;
	}

	creq = smb2_get_aead_req_new(tfm, iter, tr_hdr->Signature, &iv, &req, &sg,
				     &sensitive_size);
	if (IS_ERR(creq))
		return PTR_ERR(creq);

	if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
	    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		memcpy(iv, (char *)tr_hdr->Nonce, SMB3_AES_GCM_NONCE);
	else {
		iv[0] = 3;
		memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES_CCM_NONCE);
	}

	aead_request_set_tfm(req, tfm);
	aead_request_set_crypt(req, sg, sg, crypt_len, iv);
	aead_request_set_ad(req, assoc_data_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	rc = crypto_wait_req(crypto_aead_encrypt(req), &wait);

	kvfree_sensitive(creq, sensitive_size);
	return rc;
}

static void
fill_transform_hdr(struct smb2_transform_hdr *tr_hdr, unsigned int orig_len,
		   const struct smb_rqst *old_rq, __le16 cipher_type)
{
	struct smb2_hdr *shdr = (struct smb2_hdr *)old_rq->rq_iov[0].iov_base;

	*tr_hdr = (struct smb2_transform_hdr){
		.ProtocolId		= SMB2_TRANSFORM_PROTO_NUM,
		.OriginalMessageSize	= cpu_to_le32(orig_len),
		.Flags			= cpu_to_le16(0x01),
		.SessionId		= shdr->SessionId,
	};
	if ((cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
	    (cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		get_random_bytes(&tr_hdr->Nonce, SMB3_AES_GCM_NONCE);
	else
		get_random_bytes(&tr_hdr->Nonce, SMB3_AES_CCM_NONCE);
}

/*
 * This function encrypts the content in the buffer described by the iterator
 * and fills in the transform header.  The source request buffers are provided
 * for reference.
 */
int
smb3_init_transform_rq(struct TCP_Server_Info *server,
		       int num_rqst, const struct smb_rqst *rqst,
		       struct smb2_transform_hdr *tr_hdr,
		       struct iov_iter *iter)
{
	size_t orig_len = iov_iter_count(iter) - sizeof(*tr_hdr);
	int rc;

	fill_transform_hdr(tr_hdr, orig_len, rqst, server->cipher_type);

	iov_iter_advance(iter, offsetof(struct smb2_transform_hdr, Nonce));

	rc = encrypt_message(server, tr_hdr, iter, server->secmech.enc);
	cifs_dbg(FYI, "Encrypt message returned %d\n", rc);
	return rc;
}

/*
 * Decrypt the PDU in the iterator.  The PDU begins with the transform header.
 */
static int decrypt_pdu(struct TCP_Server_Info *server,
		       struct smb2_transform_hdr *tr_hdr,
		       struct netfs_rxqueue *rxq)
{
	DECLARE_CRYPTO_WAIT(wait);
	struct aead_request *req;
	struct crypto_aead *tfm = server->secmech.dec;
	struct scatterlist *sg;
	struct iov_iter iter;
	unsigned int assoc_data_len = sizeof(struct smb2_transform_hdr) - 20;
	unsigned int crypt_len;
	size_t sensitive_size;
	void *creq;
	int rc = 0;
	u8 sign[SMB2_SIGNATURE_SIZE] = {};
	u8 key[SMB3_ENC_DEC_KEY_SIZE];
	u8 *iv;

	crypt_len = le32_to_cpu(tr_hdr->OriginalMessageSize);

	rc = smb2_get_enc_key(server, le64_to_cpu(tr_hdr->SessionId), 0, key);
	if (rc) {
		cifs_server_dbg(FYI, "%s: Could not get decryption key. sid: 0x%llx\n",
				__func__, le64_to_cpu(tr_hdr->SessionId));
		return rc;
	}

	if ((server->cipher_type == SMB2_ENCRYPTION_AES256_CCM) ||
		(server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM256_CRYPTKEY_SIZE);
	else
		rc = crypto_aead_setkey(tfm, key, SMB3_GCM128_CRYPTKEY_SIZE);

	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set aead key %d\n", __func__, rc);
		return rc;
	}

	rc = crypto_aead_setauthsize(tfm, SMB2_SIGNATURE_SIZE);
	if (rc) {
		cifs_server_dbg(VFS, "%s: Failed to set authsize %d\n", __func__, rc);
		return rc;
	}

	netfs_rxqueue_discard(rxq, offsetof(struct smb2_transform_hdr, Nonce));

	iov_iter_bvec_queue(&iter, ITER_DEST, rxq->take_from, rxq->take_slot,
			    rxq->take_offset, rxq->pdu_remain);

	creq = smb2_get_aead_req_new(tfm, &iter, sign, &iv, &req, &sg,
				     &sensitive_size);
	if (IS_ERR(creq))
		return PTR_ERR(creq);

	memcpy(sign, &tr_hdr->Signature, SMB2_SIGNATURE_SIZE);
	crypt_len += SMB2_SIGNATURE_SIZE;

	if ((server->cipher_type == SMB2_ENCRYPTION_AES128_GCM) ||
	    (server->cipher_type == SMB2_ENCRYPTION_AES256_GCM))
		memcpy(iv, (char *)tr_hdr->Nonce, SMB3_AES_GCM_NONCE);
	else {
		iv[0] = 3;
		memcpy(iv + 1, (char *)tr_hdr->Nonce, SMB3_AES_CCM_NONCE);
	}

	aead_request_set_tfm(req, tfm);
	aead_request_set_crypt(req, sg, sg, crypt_len, iv);
	aead_request_set_ad(req, assoc_data_len);

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	rc = crypto_wait_req(crypto_aead_decrypt(req), &wait);

	netfs_rxqueue_discard(rxq, sizeof(*tr_hdr) - offsetof(struct smb2_transform_hdr, Nonce));

	kvfree_sensitive(creq, sensitive_size);
	return rc;
}

struct smb2_decrypt_work {
	struct work_struct	decrypt;
	struct TCP_Server_Info	*server;
	struct netfs_rxqueue	rx_subset;
};

static void smb2_decrypt_offload(struct work_struct *work)
{
	struct smb2_transform_hdr tr_hdr;
	struct smb2_decrypt_work *dw =
		container_of(work, struct smb2_decrypt_work, decrypt);
	struct netfs_rxqueue *rxq = &dw->rx_subset;
	int rc;

	if (netfs_rxqueue_read(rxq, &tr_hdr, 0, sizeof(tr_hdr)) != sizeof(tr_hdr))
		goto out;

	rc = decrypt_pdu(dw->server, &tr_hdr, rxq);
	if (rc < 0) {
		cifs_dbg(VFS, "error decrypting rc=%d\n", rc);
		goto out;
	}

	smb2_parse_pdu(dw->server, rxq);
out:
	netfs_put_rx_bvecq(rxq->take_from);
	kfree(dw);
}

static bool smb3_offload_decrypt(struct TCP_Server_Info *server,
				 struct smb2_transform_hdr *tr_hdr,
				 struct netfs_rxqueue *rxq)
{
	struct smb2_decrypt_work *dw;
	struct bvecq *head_bq;
	size_t remain = rxq->pdu_remain;

	dw = kzalloc(sizeof(struct smb2_decrypt_work), GFP_KERNEL);
	if (!dw)
		return false;
	INIT_WORK(&dw->decrypt, smb2_decrypt_offload);
	dw->server = server;

	head_bq = netfs_rxqueue_decant(rxq, remain);
	if (!head_bq) {
		kfree(dw);
		return -ENOMEM;
	}

	dw->rx_subset.take_from		= head_bq;
	dw->rx_subset.add_to		= NULL;
	dw->rx_subset.take_slot		= 0;
	dw->rx_subset.take_offset	= 0;
	dw->rx_subset.refillable	= false;
	dw->rx_subset.qsize		= remain;
	dw->rx_subset.pdu_remain	= remain;

	queue_work(decrypt_wq, &dw->decrypt);
	return true;
}

/*
 * Reverse the transformation the sender made to a PDU we just received, such
 * as decrypting it.  The PDU body is currently in residence upon the server
 * receive queue.
 */
static int smb3_reverse_transform(struct TCP_Server_Info *server,
				  struct netfs_rxqueue *rxq)
{
	struct smb2_transform_hdr tr_hdr;
	unsigned int orig_len;
	size_t got;
	int rc;

	if (!server->secmech.dec) {
		cifs_server_dbg(VFS, "%s: Decryption TFM not allocated\n", __func__);
		return -EIO;
	}

	rc = smb_rxqueue_refill(server, rxq, rxq->pdu_remain);
	if (rc < 0)
		return rc;

	got = netfs_rxqueue_read(rxq, &tr_hdr, 0, sizeof(tr_hdr));
	if (got != sizeof(tr_hdr)) {
		cifs_server_dbg(VFS, "Too short for transform header (%u)\n",
				rxq->pdu_remain);
		return -EIO;
	}

	orig_len = le32_to_cpu(tr_hdr.OriginalMessageSize);
	if (orig_len > rxq->pdu_remain - sizeof(tr_hdr)) {
		cifs_server_dbg(VFS, "Transform message is broken\n");
		return -EIO;
	}

	/*
	 * For large reads, offload to different thread for better performance,
	 * use more cores decrypting which can be expensive
	 */
	if (server->min_offload && server->in_flight > 1 &&
	    rxq->pdu_remain >= server->min_offload &&
	    smb3_offload_decrypt(server, &tr_hdr, rxq))
		return 0;

	rxq->refillable = false;
	decrypt_pdu(server, &tr_hdr, rxq);
	smb2_parse_pdu(server, rxq);
	return 0;
}

/*
 * Copy data directly into prepared buffers.
 *
 * Ideally, we'd wait for sufficient data to be present in the queue before
 * doing this, but that causes a performance loss as we don't receive data and
 * copy in parallel.
 */
static void smb2_copy_to_prepped_buffers(struct TCP_Server_Info *server,
					 struct smb_message *smb,
					 struct netfs_rxqueue *rxq,
					 struct cifs_receive *recv)
{
	const union smb2_response_hdr *h = recv->response;
	struct iov_iter dest = smb->response_iter;
	unsigned int to_copy, skip;
	int rc;

	switch (smb->command) {
	case SMB2_READ:
		to_copy = recv->data_len;
		skip = recv->data_offset;

		switch (h->read.Flags) {
		case SMB2_READFLAG_RESPONSE_NONE:
			break;
		case SMB2_READFLAG_RESPONSE_RDMA_TRANSFORM:
			if (to_copy)
				cifs_dbg(FYI, "%s: Read.DataLength != 0 for RDMA\n", __func__);
			return;
		default:
			cifs_dbg(FYI, "%s: Unknown Read.Flags value (%x)\n",
				 __func__, le32_to_cpu(h->read.Flags));
			recv->malformed = true;
			return;
		}
		skip -= recv->extracted;
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

		got = netfs_rxqueue_read_iter(rxq, &smb->response_iter, 0, to_copy);
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
 * Parse an SMB2/3 message that's at least partially extracted.  For successful
 * reads, the data part is still in the receive queue or even not yet received.
 */
static void smb2_parse_one_message(struct TCP_Server_Info *server,
				   struct cifs_receive *recv,
				   struct netfs_rxqueue *rxq)
{
	union smb2_response_hdr *h = recv->response;
	struct smb_message *smb;
	struct smb2_hdr *shdr = &h->hdr;
	int rc;

	smb = smb2_find_mid(server, shdr, false);
	if (!smb) {
		cifs_dbg(VFS, "%s: Unqueued mid (%llx)\n",
			 __func__, le64_to_cpu(shdr->MessageId));
		rxq->msg_id = 0;
	} else {
		rxq->msg_id = 0; /* TODO: smb->debug_id */
	}

	/*
	 * We know that we received enough to get to the MID as we checked the
	 * pdu_length earlier. Now check to see if the rest of the header is OK
	 * and determine the general layout of the message.
	 *
	 * 48 bytes is enough to display the header and a little bit into the
	 * payload for debugging purposes.
	 */
	rc = smb2_check_message(server, recv);
	if (rc) {
		cifs_dump_mem("Bad SMB: ", h, umin(recv->extracted, 48));
		recv->malformed = true;
		recv->error = -EPROTO;
	}

	/* Check the status codes for server/connection-level information. */
	switch (shdr->Status) {
	case 0:
		trace_smb3_cmd_done(le32_to_cpu(shdr->Id.SyncId.TreeId),
			      le64_to_cpu(shdr->SessionId),
			      le16_to_cpu(shdr->Command),
			      le64_to_cpu(shdr->MessageId));
		break;
	case STATUS_NETWORK_SESSION_EXPIRED:
	case STATUS_USER_SESSION_DELETED:
		trace_smb3_ses_expired(le32_to_cpu(shdr->Id.SyncId.TreeId),
				       le64_to_cpu(shdr->SessionId),
				       le16_to_cpu(shdr->Command),
				       le64_to_cpu(shdr->MessageId));
		cifs_dbg(FYI, "Session expired or deleted\n");
		set_bit(SMB_SERVER_NEED_RECONNECT, &server->flags);
		release_mid(server, smb);
		return;
	case STATUS_PENDING:
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
		smb2_status_pending(shdr, server);
		release_mid(server, smb);
		return;
	case STATUS_IO_TIMEOUT:
		int iotimo = atomic_inc_return(&server->num_io_timeout);
		if (iotimo > MAX_STATUS_IO_TIMEOUT) {
			cifs_server_dbg(VFS,
					"Number of request timeouts exceeded %d. Reconnecting",
					MAX_STATUS_IO_TIMEOUT);

			set_bit(SMB_SERVER_SESSION_RECONNECT, &server->flags);
			set_bit(SMB_SERVER_NEED_RECONNECT, &server->flags);
			atomic_set(&server->num_io_timeout, 0);
		}
		break;
	case STATUS_NETWORK_NAME_DELETED:
		cifs_server_dbg(FYI, "Share deleted. Reconnect needed");
		smb2_network_name_is_deleted(shdr, server);
		break;
	default:
		recv->error = map_smb2_to_linux_error(shdr, false);
		if (recv->error) {
			cifs_dbg(FYI, "%s: server returned error %d\n",
				 __func__, recv->error);
			/* normal error on read response */
		}
		break;
	}

	if (smb) {
		size_t resp_len;

		/* handle_mid */
		smb->status		= shdr->Status;
		smb->error		= recv->error;
		smb->credits_received	= le16_to_cpu(shdr->CreditRequest);
		smb->resp_data_len	= recv->data_len;
		smb->resp_data_offset	= recv->data_offset;

		trace_smb3_reply(smb, recv);

		/* For a successful Read, we only grab the header. */
		resp_len = recv->msg_len;
		if (smb->status != 0)
			smb->copy_to_bufs = false;
		if (smb->copy_to_bufs)
			resp_len = recv->hdr_len;

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
				smb->error = -EIO;
				smb->resp_len = recv->extracted;
				recv->malformed = true;
			} else if (smb->copy_to_bufs) {
				smb2_copy_to_prepped_buffers(server, smb, rxq,
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

		dequeue_mid(server, smb, recv->malformed);
		mid_execute_callback(server, smb);

		release_mid(server, smb);
	} else if (shdr->Command == cpu_to_le32(SMB2_OPLOCK_BREAK)) {
		smb2_is_valid_oplock_break(server, h);
		smb2_add_credits_from_hdr(shdr, server);
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
		cifs_dbg(FYI, "Received oplock break\n");
	} else {
		cifs_server_dbg(VFS, "No task to wake, unknown frame received! NumMids %d\n",
				atomic_read(&mid_count));
		cifs_dump_mem("Received Data is: ", h, HEADER_SIZE(server));
		smb2_add_credits_from_hdr(shdr, server);
#ifdef CONFIG_CIFS_DEBUG2
		smb2_dump_detail(server, recv);
		smb2_dump_mids(server);
#endif /* CIFS_DEBUG2 */
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
	}
}

/*
 * Receive and parse a received SMB2/3 PDU.
 *
 * At this point all the data has been read, any transformation unapplied,
 * decompression performed and some of it is stored in the receive queue
 * (excerpt) without either the rfc1002, transform or compression headers,
 * though some may yet to be received.
 */
static void smb2_parse_pdu(struct TCP_Server_Info *server,
			   struct netfs_rxqueue *rxq)
{
	u32 next_command, ssize2, next_len;
	int rc;

	server->lstrp = jiffies;

	do {
		union smb2_response_hdr *h;
		struct smb2_hdr *shdr;
		size_t want, got;

		while (!allocate_buffers(server))
			if (server->tcpStatus == CifsExiting)
				return;

		struct cifs_receive recv = {
			.resp_buf_type	= CIFS_SMALL_BUFFER,
			.response	= server->smallbuf,
			.msg_len	= rxq->pdu_remain,
			.hdr_len	= sizeof(*shdr) + sizeof(h->StructureSize2),
		};
		h = recv.response;
		shdr = &h->hdr;

		rc = smb_rxqueue_refill(server, rxq, recv.hdr_len);
		if (rc < 0)
			goto failed;

		got = netfs_rxqueue_read(rxq, recv.response, 0, recv.hdr_len);
		if (got != recv.hdr_len) {
			cifs_server_dbg(VFS, "SMB response too short (%u bytes)\n",
					rxq->qsize);
			goto failed;
		}
		recv.extracted = recv.hdr_len;

		switch (shdr->ProtocolId) {
		case SMB2_PROTO_NUMBER:
			break;
		case SMB2_TRANSFORM_PROTO_NUM:
		case SMB2_COMPRESSION_TRANSFORM_ID:
		default:
			cifs_server_dbg(VFS, "SMB unsupported ProtocolId (%x)\n",
					le32_to_cpu(shdr->ProtocolId));
			goto failed;
		}

		/* Extract message from a compound. */
		next_command = le32_to_cpu(shdr->NextCommand);
		next_len = 0;
		if (next_command) {
			if (next_command < sizeof(*shdr) + 4 ||
			    next_command + sizeof(*shdr) >= rxq->pdu_remain ||
			    (next_command & 0x7)) {
				cifs_dbg(VFS, "%s: malformed response (next_command=%u)\n",
					 __func__, next_command);
				goto failed;
			}
			next_len = rxq->pdu_remain - next_command;
			rxq->pdu_remain = next_command;
			recv.msg_len = next_command;
		}

		/* Get the rest of the command-specific response header. */
		ssize2 = le16_to_cpu(h->StructureSize2);
		ssize2 &= ~SMB2_STRUCT_HAS_DYNAMIC_PART;
		if (ssize2 < 4 ||
		    ssize2 > sizeof(*h) - sizeof(h->hdr)) {
			cifs_dbg(VFS, "%s: malformed response (structsize2=%u)\n",
				 __func__, ssize2);
			goto failed;
		}
		ssize2 -= sizeof(h->StructureSize2);

		/* If it's not a successful read, then wait for the entire message. */
		if (le16_to_cpu(shdr->Command) != SMB2_READ ||
		    shdr->Status != 0)
			want = recv.msg_len;
		else
			want = recv.hdr_len + ssize2;

		rc = smb_rxqueue_refill(server, rxq, want);
		if (rc < 0)
			goto failed;

		got = netfs_rxqueue_read(rxq, &h->pdu + 1, recv.hdr_len, ssize2);
		if (got != ssize2) {
			cifs_server_dbg(VFS, "SMB response too short (%u bytes)\n",
					rxq->qsize);
			goto failed;
		}
		recv.hdr_len += ssize2;
		recv.extracted += ssize2;

		smb2_parse_one_message(server, &recv, rxq);

		WARN(rxq->pdu_remain > 0, "MSG=%08x pdu_remain=%x",
		     rxq->msg_id, rxq->pdu_remain);
		smb_rxqueue_consume(server, rxq, rxq->pdu_remain);
		rxq->pdu_remain = next_len;
	} while (next_command);
	return;

failed:
	set_bit(SMB_SERVER_NEED_RECONNECT, &server->flags);
}

/*
 * Receive and parse an SMB2/3 PDU.  We need to wait for data to come in until
 * we have enough and then we have to reverse transformations and perform
 * decompression before we can fully parse the message contents.
 */
int smb2_receive_pdu(struct TCP_Server_Info *server, unsigned int pdu_len)
{
	struct netfs_rxqueue *rxq = &server->rx_queue;
	__le32 protocol_id;
	size_t got;
	int rc;

	rc = smb_rxqueue_refill(server, rxq, sizeof(struct smb2_pdu));
	if (rc < 0)
		return rc;

	got = netfs_rxqueue_read(rxq, &protocol_id, 0, sizeof(protocol_id));
	if (got != sizeof(protocol_id)) {
		cifs_dbg(VFS, "%s: Couldn't extract ProtocolId\n", __func__);
		set_bit(SMB_SERVER_NEED_RECONNECT, &server->flags);
		return -EIO;
	}

	/* Reverse any transformation made to the content.  We set up an
	 * iterator to define the buffer, but anyone looking at the buffer
	 * *should not* assume that they can simply poke around in it as it may
	 * be assembled from raw network packet Rx buffers.
	 */
	if (protocol_id == SMB2_TRANSFORM_PROTO_NUM)
		return smb3_reverse_transform(server, rxq);
	smb2_parse_pdu(server, rxq);
	return 0;
}
