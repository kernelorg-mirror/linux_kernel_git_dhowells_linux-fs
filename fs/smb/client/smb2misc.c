// SPDX-License-Identifier: LGPL-2.1
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2011
 *                 Etersoft, 2012
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *              Pavel Shilovsky (pshilovsky@samba.org) 2012
 *
 */
#include <crypto/sha2.h>
#include <linux/ctype.h>
#include "cifsglob.h"
#include "cifsproto.h"
#include "smb2proto.h"
#include "cifs_debug.h"
#include "cifs_unicode.h"
#include "../common/smb2status.h"
#include "smb2glob.h"
#include "nterr.h"
#include "cached_dir.h"

static int
check_smb2_hdr(const struct smb2_hdr *shdr, __u64 mid)
{
	__u64 wire_mid = le64_to_cpu(shdr->MessageId);

	/*
	 * Make sure that this really is an SMB, that it is a response,
	 * and that the message ids match.
	 */
	if ((shdr->ProtocolId == SMB2_PROTO_NUMBER) &&
	    (mid == wire_mid)) {
		if (shdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
			return 0;
		else {
			/* only one valid case where server sends us request */
			if (shdr->Command == SMB2_OPLOCK_BREAK)
				return 0;
			else
				cifs_dbg(VFS, "Received Request not response\n");
		}
	} else { /* bad signature or mid */
		if (shdr->ProtocolId != SMB2_PROTO_NUMBER)
			cifs_dbg(VFS, "Bad protocol string signature header %x\n",
				 le32_to_cpu(shdr->ProtocolId));
		if (mid != wire_mid)
			cifs_dbg(VFS, "Mids do not match: %llu and %llu\n",
				 mid, wire_mid);
	}
	cifs_dbg(VFS, "Bad SMB detected. The Mid=%llu\n", wire_mid);
	return 1;
}

/*
 *  The following table defines the expected "StructureSize" of SMB2 responses
 *  in order by SMB2 command.  This is similar to "wct" in SMB/CIFS responses.
 *
 *  Note that commands are defined in smb2pdu.h in le16 but the array below is
 *  indexed by command in host byte order
 */
static const u16 smb2_rsp_struct_sizes[NUMBER_OF_SMB2_COMMANDS] = {
	[SMB2_NEGOTIATE]	= 65,
	[SMB2_SESSION_SETUP]	= 9,
	[SMB2_LOGOFF]		= 4,
	[SMB2_TREE_CONNECT]	= 16,
	[SMB2_TREE_DISCONNECT]	= 4,
	[SMB2_CREATE]		= 89,
	[SMB2_CLOSE]		= 60,
	[SMB2_FLUSH]		= 4,
	[SMB2_READ]		= 17,
	[SMB2_WRITE]		= 17,
	[SMB2_LOCK]		= 4,
	[SMB2_IOCTL]		= 49,
	/* BB CHECK this ... not listed in documentation */
	[SMB2_CANCEL]		= 0,
	[SMB2_ECHO]		= 4,
	[SMB2_QUERY_DIRECTORY]	= 9,
	[SMB2_CHANGE_NOTIFY]	= 9,
	[SMB2_QUERY_INFO]	= 9,
	[SMB2_SET_INFO]		= 2,
	[SMB2_OPLOCK_BREAK]	= 24, /* BB FIXME can also be 44 for lease break */
};

#define SMB311_NEGPROT_BASE_SIZE (sizeof(struct smb2_hdr) + sizeof(struct smb2_negotiate_rsp))

static __u32 get_neg_ctxt_len(const struct smb2_negotiate_rsp *pneg_rsp,
			      __u32 len, __u32 non_ctxlen)
{
	__u16 neg_count;
	__u32 nc_offset, size_of_pad_before_neg_ctxts;

	/* Negotiate contexts are only valid for latest dialect SMB3.11 */
	neg_count = le16_to_cpu(pneg_rsp->NegotiateContextCount);
	if ((neg_count == 0) ||
	   (pneg_rsp->DialectRevision != cpu_to_le16(SMB311_PROT_ID)))
		return 0;

	/*
	 * if SPNEGO blob present (ie the RFC2478 GSS info which indicates
	 * which security mechanisms the server supports) make sure that
	 * the negotiate contexts start after it
	 */
	nc_offset = le32_to_cpu(pneg_rsp->NegotiateContextOffset);
	/*
	 * non_ctxlen is at least shdr->StructureSize + pdu->StructureSize2
	 * and the latter is 1 byte bigger than the fix-sized area of the
	 * NEGOTIATE response
	 */
	if (nc_offset + 1 < non_ctxlen) {
		pr_warn_once("Invalid negotiate context offset %d\n", nc_offset);
		return 0;
	} else if (nc_offset + 1 == non_ctxlen) {
		cifs_dbg(FYI, "no SPNEGO security blob in negprot rsp\n");
		size_of_pad_before_neg_ctxts = 0;
	} else if (non_ctxlen == SMB311_NEGPROT_BASE_SIZE + 1)
		/* has padding, but no SPNEGO blob */
		size_of_pad_before_neg_ctxts = nc_offset - non_ctxlen + 1;
	else
		size_of_pad_before_neg_ctxts = nc_offset - non_ctxlen;

	/* Verify that at least minimal negotiate contexts fit within frame */
	if (len < nc_offset + (neg_count * sizeof(struct smb2_neg_context))) {
		pr_warn_once("negotiate context goes beyond end\n");
		return 0;
	}

	cifs_dbg(FYI, "length of negcontexts %d pad %d\n",
		len - nc_offset, size_of_pad_before_neg_ctxts);

	/* length of negcontexts including pad from end of sec blob to them */
	return (len - nc_offset) + size_of_pad_before_neg_ctxts;
}

/*
 * Check the sizes of various parts of the message and retrieve the data area
 * offset and length if there is one.
 */
int
smb2_check_message(struct TCP_Server_Info *server, struct cifs_receive *recv)
{
	union smb2_response_hdr *h = recv->response;
	struct smb2_hdr *shdr = &h->hdr;
	const unsigned int len = recv->msg_len;
	int hdr_size = sizeof(struct smb2_hdr);
	int pdu_size = sizeof(struct smb2_pdu);
	__u32 calc_len; /* calculated length */
	__u64 mid;
        u16 command;
	u16 ssize2 = le16_to_cpu(h->StructureSize2);

	/*
	 * Add function to do table lookup of StructureSize by command
	 * ie Validate the wct via smb2_struct_sizes table above
	 */
	mid = le64_to_cpu(shdr->MessageId);
	if (check_smb2_hdr(shdr, mid))
		return 1;

	if (shdr->StructureSize != SMB2_HEADER_STRUCTURE_SIZE) {
		cifs_dbg(VFS, "Invalid structure size %u\n",
			 le16_to_cpu(shdr->StructureSize));
		return 1;
	}

	command = le16_to_cpu(shdr->Command);
	if (command >= NUMBER_OF_SMB2_COMMANDS) {
		cifs_dbg(VFS, "Invalid SMB2 command %d\n", command);
		return 1;
	}

	if (len < pdu_size) {
		if ((len >= hdr_size)
		    && (shdr->Status != 0)) {
			h->StructureSize2 = 0;
			/*
			 * As with SMB/CIFS, on some error cases servers may
			 * not return wct properly
			 */
			return 0;
		} else {
			cifs_dbg(VFS, "Length less than SMB header size\n");
		}
		return 1;
	}
	if (len > CIFSMaxBufSize + MAX_SMB2_HDR_SIZE &&
	    command != SMB2_READ_HE) {
		cifs_dbg(VFS, "SMB length (%u) greater than maximum (%u), mid=%llu\n",
			 len, CIFSMaxBufSize + MAX_SMB2_HDR_SIZE, mid);
		return 1;
	}

	if (ssize2 != smb2_rsp_struct_sizes[command]) {
		if (command != SMB2_OPLOCK_BREAK_HE &&
		    (shdr->Status == 0 || ssize2 != SMB2_ERROR_STRUCTURE_SIZE2)) {
			/* error packets have 9 byte structure size */
			cifs_dbg(VFS, "Invalid response size %u for command %d\n",
				 ssize2, command);
			return 1;
		} else if (command == SMB2_OPLOCK_BREAK_HE
			   && (shdr->Status == 0)
			   && (ssize2 != 44)
			   && (ssize2 != 36)) {
			/* special case for SMB2.1 lease break message */
			cifs_dbg(VFS, "Invalid response size %d for oplock break\n",
				 ssize2);
			return 1;
		}
	}

	smb2_calc_size(recv);

	/* For SMB2_IOCTL, OutputOffset and OutputLength are optional, so might
	 * be 0, and not a real miscalculation */
	if (command == SMB2_IOCTL_HE && calc_len == 0)
		return 0;

	if (command == SMB2_NEGOTIATE_HE)
		calc_len += get_neg_ctxt_len(&h->neg, len, calc_len);

	if (len != calc_len) {
		/* create failed on symlink */
		if (command == SMB2_CREATE_HE &&
		    shdr->Status == STATUS_STOPPED_ON_SYMLINK &&
		    len > calc_len)
			return 0;
		/* Windows 7 server returns 24 bytes more */
		if (calc_len + 24 == len && command == SMB2_OPLOCK_BREAK_HE)
			return 0;
		/*
		 * Server can return one byte more due to implied bcc[0].
		 * Allow it only when there is no data area; if data_length > 0
		 * the +1 gap indicates an overreported data length rather than
		 * the bcc[0] omission.
		 */
		if (calc_len == len + 1)
			return 0;

		/*
		 * Some windows servers (win2016) will pad also the final
		 * PDU in a compound to 8 bytes.
		 */
		if (ALIGN8(calc_len) == len)
			return 0;

		/*
		 * MacOS server pads after SMB2.1 write response with 3 bytes
		 * of junk. Other servers match RFC1001 len to actual
		 * SMB2/SMB3 frame length (header + smb2 response specific data)
		 * Some windows servers also pad up to 8 bytes when compounding.
		 */
		if (calc_len < len)
			return 0;

		/* Only log a message if len was really miscalculated */
		if (unlikely(cifsFYI))
			cifs_dbg(FYI, "Server response too short: calculated "
				 "length %u doesn't match read length %u (cmd=%d, mid=%llu)\n",
				 calc_len, len, command, mid);
		else
			pr_warn("Server response too short: calculated length "
				"%u doesn't match read length %u (cmd=%d, mid=%llu)\n",
				calc_len, len, command, mid);

		return 1;
	}
	return 0;
}

/*
 * The size of the variable area depends on the offset and length fields
 * located in different fields for various SMB2 responses. SMB2 responses
 * with no variable length info, show an offset of zero for the offset field.
 */
static const bool has_smb2_data_area[NUMBER_OF_SMB2_COMMANDS] = {
	[SMB2_NEGOTIATE_HE]		= true,
	[SMB2_SESSION_SETUP_HE]		= true,
	[SMB2_LOGOFF_HE]		= false,
	[SMB2_TREE_CONNECT_HE]		= false,
	[SMB2_TREE_DISCONNECT_HE]	= false,
	[SMB2_CREATE_HE]		= true,
	[SMB2_CLOSE_HE]			= false,
	[SMB2_FLUSH_HE]			= false,
	[SMB2_READ_HE]			= true,
	[SMB2_WRITE_HE]			= false,
	[SMB2_LOCK_HE]			= false,
	[SMB2_IOCTL_HE]			= true,
	[SMB2_CANCEL_HE]		= false, /* BB CHECK this not listed in documentation */
	[SMB2_ECHO_HE]			= false,
	[SMB2_QUERY_DIRECTORY_HE]	= true,
	[SMB2_CHANGE_NOTIFY_HE]		= true,
	[SMB2_QUERY_INFO_HE]		= true,
	[SMB2_SET_INFO_HE]		= false,
	[SMB2_OPLOCK_BREAK_HE]		= false,
};

/*
 * Returns the pointer to the beginning of the data area. Length of the data
 * area and the offset to it (from the beginning of the smb are also returned.
 */
char *
smb2_get_data_area_len(struct cifs_receive *recv)
{
	const union smb2_response_hdr *h = recv->response;
	const struct smb2_hdr *shdr = &h->hdr;
	u16 command = le16_to_cpu(shdr->Command);
	int off, len;

	recv->data_offset = 0;
	recv->data_len = 0;

	/* error responses do not have data area */
	if (shdr->Status && shdr->Status != STATUS_MORE_PROCESSING_REQUIRED &&
	    h->StructureSize2 == SMB2_ERROR_STRUCTURE_SIZE2_LE)
		return NULL;

	/*
	 * Following commands have data areas so we have to get the location
	 * of the data buffer offset and data buffer length for the particular
	 * command.
	 */
	switch (command) {
	case SMB2_NEGOTIATE_HE:
		off = le16_to_cpu(h->neg.SecurityBufferOffset);
		len = le16_to_cpu(h->neg.SecurityBufferLength);
		break;
	case SMB2_SESSION_SETUP_HE:
		off = le16_to_cpu(h->sess.SecurityBufferOffset);
		len = le16_to_cpu(h->sess.SecurityBufferLength);
		break;
	case SMB2_CREATE_HE:
		off = le32_to_cpu(h->create.CreateContextsOffset);
		len = le32_to_cpu(h->create.CreateContextsLength);
		break;
	case SMB2_QUERY_INFO_HE:
		off = le16_to_cpu(h->qinfo.OutputBufferOffset);
		len = le32_to_cpu(h->qinfo.OutputBufferLength);
		break;
	case SMB2_READ_HE:
		/* TODO: is this a bug ? */
		off = h->read.DataOffset;
		len = le32_to_cpu(h->read.DataLength);
		if (off == 0) {
			/*
			 * win2k8 sometimes sends an offset of 0 when
			 * the read is beyond the EOF. Treat it as if
			 * the data starts just after the header.
			 */
			cifs_dbg(FYI, "%s: data offset (%u) inside read response header\n",
				 __func__, off);
			off = sizeof(h->read);
		}
		break;
	case SMB2_QUERY_DIRECTORY_HE:
		off = le16_to_cpu(h->qdir.OutputBufferOffset);
		len = le32_to_cpu(h->qdir.OutputBufferLength);
		break;
	case SMB2_IOCTL_HE:
		off = le32_to_cpu(h->ioctl.OutputOffset);
		len = le32_to_cpu(h->ioctl.OutputCount);
		break;
	case SMB2_CHANGE_NOTIFY_HE:
		off = le16_to_cpu(h->change.OutputBufferOffset);
		len = le32_to_cpu(h->change.OutputBufferLength);
		break;
	default:
		cifs_dbg(VFS, "no length check for command %d\n", le16_to_cpu(shdr->Command));
		break;
	}

	/*
	 * Invalid length or offset probably means data area is invalid, but
	 * we have little choice but to ignore the data area in this case.
	 */
	if (unlikely(off < 0 || len < 0)) {
		cifs_dbg(VFS, "%s: invalid data area (off=%d len=%d)\n",
			 __func__, off, len);
		off = 0;
		len = 0;
	} else if (off == 0) {
		len = 0;
	}

	/* return pointer to beginning of data area, ie offset from SMB start */
	if (off > 0 && len > 0) {
		recv->data_offset = off;
		recv->data_len = len;
		return (char *)shdr + off;
	}
	return NULL;
}

/*
 * Calculate the size of the SMB message based on the fixed header, fixed
 * parameter area, and variable data area.
 *
 * If have_data is not NULL, it is set when a non-empty data area is found.
 * If data_area_overlap is not NULL, it is set when the data area overlaps
 * the fixed area.
 */
void
smb2_calc_size(struct cifs_receive *recv)
{
	const union smb2_response_hdr *h = recv->response;
	const struct smb2_hdr *shdr = &h->hdr;
	u16 command = le16_to_cpu(shdr->Command);

	recv->calc_len = recv->hdr_len;
	WARN_ON_ONCE(!recv->calc_len);

	if (command >= ARRAY_SIZE(has_smb2_data_area) ||
	    has_smb2_data_area[command] == false)
		goto calc_size_exit;

	smb2_get_data_area_len(recv);
	cifs_dbg(FYI, "SMB2 data length %d offset %d\n",
		 recv->data_len, recv->data_offset);

	if (recv->data_len > 0) {
		/* Check to make sure that data area begins after fixed area. */
		if (recv->data_offset < recv->hdr_len) {
			cifs_dbg(VFS, "data area offset %d overlaps SMB2 header %d\n",
				 recv->data_offset, recv->hdr_len);
			recv->data_offset = 0;
			recv->data_len = 0;
			goto calc_size_exit;
		}
		recv->calc_len = recv->data_offset + recv->data_len;
	}
calc_size_exit:
	cifs_dbg(FYI, "SMB2 len %d\n", recv->calc_len);
}

/* Note: caller must free return buffer */
__le16 *
cifs_convert_path_to_utf16(const char *from, struct cifs_sb_info *cifs_sb)
{
	const char *start_of_path;
	int len;

	/* Windows doesn't allow paths beginning with \ */
	if (from[0] == '\\')
		start_of_path = from + 1;

	/* SMB311 POSIX extensions paths do not include leading slash */
	else if (cifs_sb_master_tlink(cifs_sb) &&
		 cifs_sb_master_tcon(cifs_sb)->posix_extensions &&
		 (from[0] == '/')) {
		start_of_path = from + 1;
	} else
		start_of_path = from;

	return cifs_strndup_to_utf16(start_of_path, PATH_MAX, &len,
				     cifs_sb->local_nls, cifs_remap(cifs_sb));
}

__le32 smb2_get_lease_state(struct cifsInodeInfo *cinode, unsigned int oplock)
{
	unsigned int sbflags = cifs_sb_flags(CIFS_SB(cinode));
	__le32 lease = 0;

	if ((oplock & CIFS_CACHE_WRITE_FLG) || (sbflags & CIFS_MOUNT_RW_CACHE))
		lease |= SMB2_LEASE_WRITE_CACHING_LE;
	if (oplock & CIFS_CACHE_HANDLE_FLG)
		lease |= SMB2_LEASE_HANDLE_CACHING_LE;
	if ((oplock & CIFS_CACHE_READ_FLG) || (sbflags & CIFS_MOUNT_RO_CACHE))
		lease |= SMB2_LEASE_READ_CACHING_LE;
	return lease;
}

struct smb2_lease_break_work {
	struct work_struct lease_break;
	struct tcon_link *tlink;
	__u8 lease_key[16];
	__le32 lease_state;
};

static void
cifs_ses_oplock_break(struct work_struct *work)
{
	struct smb2_lease_break_work *lw = container_of(work,
				struct smb2_lease_break_work, lease_break);
	int rc = 0;

	rc = SMB2_lease_break(0, tlink_tcon(lw->tlink), lw->lease_key,
			      lw->lease_state);

	cifs_dbg(FYI, "Lease release rc %d\n", rc);
	cifs_put_tlink(lw->tlink);
	kfree(lw);
}

static void
smb2_queue_pending_open_break(struct tcon_link *tlink, __u8 *lease_key,
			      __le32 new_lease_state)
{
	struct smb2_lease_break_work *lw;

	lw = kmalloc_obj(struct smb2_lease_break_work);
	if (!lw) {
		cifs_put_tlink(tlink);
		return;
	}

	INIT_WORK(&lw->lease_break, cifs_ses_oplock_break);
	lw->tlink = tlink;
	lw->lease_state = new_lease_state;
	memcpy(lw->lease_key, lease_key, SMB2_LEASE_KEY_SIZE);
	queue_work(cifsiod_wq, &lw->lease_break);
}

static bool
smb2_tcon_has_lease(struct cifs_tcon *tcon, struct smb2_lease_break *rsp)
{
	__u8 lease_state;
	struct cifsFileInfo *cfile;
	struct cifsInodeInfo *cinode;
	int ack_req = le32_to_cpu(rsp->Flags &
				  SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED);

	lease_state = le32_to_cpu(rsp->NewLeaseState);

	list_for_each_entry(cfile, &tcon->openFileList, tlist) {
		cinode = CIFS_I(d_inode(cfile->dentry));

		if (memcmp(cinode->lease_key, rsp->LeaseKey,
							SMB2_LEASE_KEY_SIZE))
			continue;

		cifs_dbg(FYI, "found in the open list\n");
		cifs_dbg(FYI, "lease key match, lease break 0x%x\n",
			 lease_state);

		if (ack_req)
			cfile->oplock_break_cancelled = false;
		else
			cfile->oplock_break_cancelled = true;

		set_bit(CIFS_INODE_PENDING_OPLOCK_BREAK, &cinode->flags);

		cfile->oplock_epoch = le16_to_cpu(rsp->Epoch);
		cfile->oplock_level = lease_state;

		cifs_queue_oplock_break(cfile);
		return true;
	}

	return false;
}

static struct cifs_pending_open *
smb2_tcon_find_pending_open_lease(struct cifs_tcon *tcon,
				  struct smb2_lease_break *rsp)
{
	__u8 lease_state = le32_to_cpu(rsp->NewLeaseState);
	int ack_req = le32_to_cpu(rsp->Flags &
				  SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED);
	struct cifs_pending_open *open;
	struct cifs_pending_open *found = NULL;

	list_for_each_entry(open, &tcon->pending_opens, olist) {
		if (memcmp(open->lease_key, rsp->LeaseKey,
			   SMB2_LEASE_KEY_SIZE))
			continue;

		if (!found && ack_req) {
			found = open;
		}

		cifs_dbg(FYI, "found in the pending open list\n");
		cifs_dbg(FYI, "lease key match, lease break 0x%x\n",
			 lease_state);

		open->oplock = lease_state;
	}

	return found;
}

static void
smb2_is_valid_lease_break(struct TCP_Server_Info *server,
			  union smb2_response_hdr *h)
{
	struct smb2_lease_break *rsp = &h->lease;
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifs_pending_open *open;

	/* Trace receipt of lease break request from server */
	trace_smb3_lease_break_enter(le32_to_cpu(rsp->CurrentLeaseState),
		le32_to_cpu(rsp->Flags),
		le16_to_cpu(rsp->Epoch),
		le32_to_cpu(rsp->hdr.Id.SyncId.TreeId),
		le64_to_cpu(rsp->hdr.SessionId),
		*((u64 *)rsp->LeaseKey),
		*((u64 *)&rsp->LeaseKey[8]));

	cifs_dbg(FYI, "Checking for lease break\n");

	/* If server is a channel, select the primary channel */
	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;

	/* look up tcon based on tid & uid */
	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (cifs_ses_exiting(ses))
			continue;
		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {
			spin_lock(&tcon->open_file_lock);
			cifs_stats_inc(
				       &tcon->stats.cifs_stats.num_oplock_brks);
			if (smb2_tcon_has_lease(tcon, rsp)) {
				spin_unlock(&tcon->open_file_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				return;
			}
			open = smb2_tcon_find_pending_open_lease(tcon,
								 rsp);
			if (open) {
				__u8 lease_key[SMB2_LEASE_KEY_SIZE];
				struct tcon_link *tlink;

				tlink = cifs_get_tlink(open->tlink);
				memcpy(lease_key, open->lease_key,
				       SMB2_LEASE_KEY_SIZE);
				spin_unlock(&tcon->open_file_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				smb2_queue_pending_open_break(tlink,
							      lease_key,
							      rsp->NewLeaseState);
				return;
			}
			spin_unlock(&tcon->open_file_lock);

			if (cached_dir_lease_break(tcon, rsp->LeaseKey)) {
				spin_unlock(&cifs_tcp_ses_lock);
				return;
			}
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);
	cifs_dbg(FYI, "Can not process lease break - no lease matched\n");
	trace_smb3_lease_not_found(le32_to_cpu(rsp->CurrentLeaseState),
					   le32_to_cpu(rsp->Flags),
					   le16_to_cpu(rsp->Epoch),
					   le32_to_cpu(rsp->hdr.Id.SyncId.TreeId),
					   le64_to_cpu(rsp->hdr.SessionId),
					   *((u64 *)rsp->LeaseKey),
					   *((u64 *)&rsp->LeaseKey[8]));

}

void
smb2_is_valid_oplock_break(struct TCP_Server_Info *server,
			   union smb2_response_hdr *h)
{
	struct smb2_oplock_break *rsp = &h->oplock;
	struct TCP_Server_Info *pserver;
	struct cifs_ses *ses;
	struct cifs_tcon *tcon;
	struct cifsInodeInfo *cinode;
	struct cifsFileInfo *cfile;
	u16 ssize2 = le16_to_cpu(h->StructureSize2);

	cifs_dbg(FYI, "Checking for oplock break\n");

	if (ssize2 != smb2_rsp_struct_sizes[SMB2_OPLOCK_BREAK_HE]) {
		if (ssize2 == 44)
			return smb2_is_valid_lease_break(server, h);
		WARN(1, "Invalid oplock break 0x%x\n", ssize2);
		return;
	}

	cifs_dbg(FYI, "oplock level 0x%x\n", rsp->OplockLevel);

	/* If server is a channel, select the primary channel */
	pserver = SERVER_IS_CHAN(server) ? server->primary_server : server;

	/* look up tcon based on tid & uid */
	spin_lock(&cifs_tcp_ses_lock);
	list_for_each_entry(ses, &pserver->smb_ses_list, smb_ses_list) {
		if (cifs_ses_exiting(ses))
			continue;
		list_for_each_entry(tcon, &ses->tcon_list, tcon_list) {

			spin_lock(&tcon->open_file_lock);
			list_for_each_entry(cfile, &tcon->openFileList, tlist) {
				if (rsp->PersistentFid !=
				    cfile->fid.persistent_fid ||
				    rsp->VolatileFid !=
				    cfile->fid.volatile_fid)
					continue;

				cifs_dbg(FYI, "file id match, oplock break\n");
				cifs_stats_inc(
				    &tcon->stats.cifs_stats.num_oplock_brks);
				cinode = CIFS_I(d_inode(cfile->dentry));
				spin_lock(&cfile->file_info_lock);
				if (!CIFS_CACHE_WRITE(cinode) &&
				    rsp->OplockLevel == SMB2_OPLOCK_LEVEL_NONE)
					cfile->oplock_break_cancelled = true;
				else
					cfile->oplock_break_cancelled = false;

				set_bit(CIFS_INODE_PENDING_OPLOCK_BREAK,
					&cinode->flags);

				cfile->oplock_epoch = 0;
				cfile->oplock_level = rsp->OplockLevel;

				spin_unlock(&cfile->file_info_lock);

				cifs_queue_oplock_break(cfile);

				spin_unlock(&tcon->open_file_lock);
				spin_unlock(&cifs_tcp_ses_lock);
				return;
			}
			spin_unlock(&tcon->open_file_lock);
		}
	}
	spin_unlock(&cifs_tcp_ses_lock);
	cifs_dbg(FYI, "No file id matched, oplock break ignored\n");
	trace_smb3_oplock_not_found(0 /* no xid */, rsp->PersistentFid,
				  le32_to_cpu(rsp->hdr.Id.SyncId.TreeId),
				  le64_to_cpu(rsp->hdr.SessionId));
	return;
}

void
smb2_cancelled_close_fid(struct work_struct *work)
{
	struct close_cancelled_open *cancelled = container_of(work,
					struct close_cancelled_open, work);
	struct cifs_tcon *tcon = cancelled->tcon;
	int rc;

	if (cancelled->mid)
		cifs_tcon_dbg(VFS, "Close unmatched open for MID:%llu\n",
			      cancelled->mid);
	else
		cifs_tcon_dbg(VFS, "Close interrupted close\n");

	rc = SMB2_close(0, tcon, cancelled->fid.persistent_fid,
			cancelled->fid.volatile_fid);
	if (rc)
		cifs_tcon_dbg(VFS, "Close cancelled mid failed rc:%d\n", rc);

	cifs_put_tcon(tcon, netfs_trace_tcon_ref_put_cancelled_close_fid);
	kfree(cancelled);
}

/*
 * Caller should already has an extra reference to @tcon
 * This function is used to queue work to close a handle to prevent leaks
 * on the server.
 * We handle two cases. If an open was interrupted after we sent the
 * SMB2_CREATE to the server but before we processed the reply, and second
 * if a close was interrupted before we sent the SMB2_CLOSE to the server.
 */
static int
__smb2_handle_cancelled_cmd(struct cifs_tcon *tcon, __u16 cmd, __u64 mid,
			    __u64 persistent_fid, __u64 volatile_fid)
{
	struct close_cancelled_open *cancelled;

	cancelled = kzalloc_obj(*cancelled);
	if (!cancelled)
		return -ENOMEM;

	cancelled->fid.persistent_fid = persistent_fid;
	cancelled->fid.volatile_fid = volatile_fid;
	cancelled->tcon = tcon;
	cancelled->cmd = cmd;
	cancelled->mid = mid;
	INIT_WORK(&cancelled->work, smb2_cancelled_close_fid);
	WARN_ON(queue_work(cifsiod_wq, &cancelled->work) == false);

	return 0;
}

int
smb2_handle_cancelled_close(struct cifs_tcon *tcon, __u64 persistent_fid,
			    __u64 volatile_fid)
{
	int rc;

	cifs_dbg(FYI, "%s: tc_count=%d\n", __func__, tcon->tc_count);
	spin_lock(&tcon->tc_lock);
	if (tcon->tc_count <= 0) {
		struct TCP_Server_Info *server = NULL;

		trace_smb3_tcon_ref(tcon->debug_id, tcon->tc_count,
				    netfs_trace_tcon_ref_see_cancelled_close);
		WARN_ONCE(tcon->tc_count < 0, "tcon refcount is negative");
		spin_unlock(&tcon->tc_lock);

		if (tcon->ses) {
			server = tcon->ses->server;
			cifs_server_dbg(FYI,
					"tid=0x%x: tcon is closing, skipping async close retry of fid %llu %llu\n",
					tcon->tid, persistent_fid, volatile_fid);
		}

		return 0;
	}
	tcon->tc_count++;
	trace_smb3_tcon_ref(tcon->debug_id, tcon->tc_count,
			    netfs_trace_tcon_ref_get_cancelled_close);
	spin_unlock(&tcon->tc_lock);

	rc = __smb2_handle_cancelled_cmd(tcon, SMB2_CLOSE_HE, 0,
					 persistent_fid, volatile_fid);
	if (rc)
		cifs_put_tcon(tcon, netfs_trace_tcon_ref_put_cancelled_close);

	return rc;
}

int
smb2_handle_cancelled_mid(struct smb_message *smb, struct TCP_Server_Info *server)
{
	struct smb2_hdr *hdr = smb->response;
	struct smb2_create_rsp *rsp = smb->response;
	struct cifs_tcon *tcon;
	int rc;

	if ((smb->optype & CIFS_CP_CREATE_CLOSE_OP) || hdr->Command != SMB2_CREATE ||
	    hdr->Status != STATUS_SUCCESS)
		return 0;

	tcon = smb2_find_smb_tcon(server, le64_to_cpu(hdr->SessionId),
				  le32_to_cpu(hdr->Id.SyncId.TreeId));
	if (!tcon)
		return -ENOENT;

	rc = __smb2_handle_cancelled_cmd(tcon,
					 le16_to_cpu(hdr->Command),
					 le64_to_cpu(hdr->MessageId),
					 rsp->PersistentFileId,
					 rsp->VolatileFileId);
	if (rc)
		cifs_put_tcon(tcon, netfs_trace_tcon_ref_put_cancelled_mid);

	return rc;
}

/**
 * smb311_update_preauth_hash - update @ses hash with the packet data in @iov
 *
 * Assumes @iov does not contain the rfc1002 length and iov[0] has the
 * SMB2 header.
 *
 * @ses:	server session structure
 * @server:	pointer to server info
 * @iov:	array containing the SMB request we will send to the server
 * @nvec:	number of array entries for the iov
 */
void
smb311_update_preauth_hash(struct cifs_ses *ses, struct TCP_Server_Info *server,
			   struct kvec *iov, int nvec)
{
	int i;
	struct smb2_hdr *hdr;
	struct sha512_ctx sha_ctx;

	hdr = (struct smb2_hdr *)iov[0].iov_base;
	/* neg prot are always taken */
	if (hdr->Command == SMB2_NEGOTIATE)
		goto ok;

	/*
	 * If we process a command which wasn't a negprot it means the
	 * neg prot was already done, so the server dialect was set
	 * and we can test it. Preauth requires 3.1.1 for now.
	 */
	if (server->dialect != SMB311_PROT_ID)
		return;

	if (hdr->Command != SMB2_SESSION_SETUP)
		return;

	/* skip last sess setup response */
	if ((hdr->Flags & SMB2_FLAGS_SERVER_TO_REDIR)
	    && (hdr->Status == NT_STATUS_OK
		|| (hdr->Status !=
		    cpu_to_le32(NT_STATUS_MORE_PROCESSING_REQUIRED))))
		return;

ok:
	sha512_init(&sha_ctx);
	sha512_update(&sha_ctx, ses->preauth_sha_hash, SMB2_PREAUTH_HASH_SIZE);
	for (i = 0; i < nvec; i++)
		sha512_update(&sha_ctx, iov[i].iov_base, iov[i].iov_len);
	sha512_final(&sha_ctx, ses->preauth_sha_hash);
}
