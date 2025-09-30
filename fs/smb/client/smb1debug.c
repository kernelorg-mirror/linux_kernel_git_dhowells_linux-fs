// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *   Copyright (C) International Business Machines  Corp., 2000,2005
 *
 *   Modified by Steve French (sfrench@us.ibm.com)
 */
#include "cifsproto.h"
#include "smb1proto.h"
#include "cifs_debug.h"

#ifdef CONFIG_CIFS_DEBUG2
void cifs_dump_detail(struct TCP_Server_Info *server, const struct cifs_receive *recv)
{
	const union smb1_response_hdr *h = recv->response;
	const struct smb_hdr *smb = &h->hdr;

	cifs_dbg(VFS, "Cmd: %d Err: 0x%x Flags: 0x%x Flgs2: 0x%x Mid: %d Pid: %d Wct: %d\n",
		 smb->Command, smb->Status.CifsError, smb->Flags,
		 smb->Flags2, smb->Mid, smb->Pid, smb->WordCount);
	if (recv->malformed)
		cifs_dbg(VFS, "smb buf %p len %u\n", smb, recv->calc_len);
}

void cifs_dump_mids(struct TCP_Server_Info *server)
{
	struct smb_message *smb;

	if (server == NULL)
		return;

	cifs_dbg(VFS, "Dump pending requests:\n");
	spin_lock(&server->mid_queue_lock);
	list_for_each_entry(smb, &server->pending_mid_q, qhead) {
		struct cifs_receive recv = {
			.response	= smb->response,
			.msg_len	= smb->resp_len,
			.error		= smb->error,
			.data_len	= smb->resp_data_len,
			.data_offset	= smb->resp_data_offset,
		};

		cifs_dbg(VFS, "State: %d Cmd: %d Pid: %d Cbdata: %p Mid %llu\n",
			 smb->mid_state,
			 le16_to_cpu(smb->command),
			 smb->pid,
			 smb->callback_data,
			 smb->mid);
#ifdef CONFIG_CIFS_STATS2
		cifs_dbg(VFS, "IsLarge: %d buf: %p time rcv: %ld now: %ld\n",
			 smb->large_buf,
			 smb->response,
			 smb->when_received,
			 jiffies);
#endif /* STATS2 */
		cifs_dbg(VFS, "IsMult: %d IsEnd: %d\n",
			 smb->multiRsp, smb->multiEnd);
		if (recv.response) {
			cifs_dump_detail(server, &recv);
			cifs_dump_mem("existing buf: ", recv.response, 62);
		}
	}
	spin_unlock(&server->mid_queue_lock);
}

#endif /* CONFIG_CIFS_DEBUG2 */
