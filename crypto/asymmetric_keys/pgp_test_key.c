// SPDX-License-Identifier: GPL-2.0
/* Testing module to load key from trusted PGP message
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PGPtest: "fmt
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/verification.h>
#include <keys/user-type.h>
#include <keys/system_keyring.h>
#include <crypto/pgp.h>

#include "pgp_parser.h"

MODULE_LICENSE("GPL");

struct pgp_test_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_literal_data_parameters params;
	const void *content;
};

static int pgp_test_parse_data(struct pgp_parse_context *context,
			       enum pgp_packet_tag type,
			       u8 headerlen,
			       const u8 *data,
			       size_t datalen)
{
	struct pgp_test_parse_context *ctx =
		container_of(context, struct pgp_test_parse_context, pgp);
	int ret;

	kenter("");

	ret = pgp_parse_literal_data(data, datalen, &ctx->params);
	if (ret == 0)
		ctx->content = data + ctx->params.content_offset;
	return ret;
}

/*
 * Instantiate a PGP wrapped and validated key.
 */
static int pgp_test_instantiate(struct key *key,
				struct key_preparsed_payload *prep)
{
	struct pgp_test_parse_context p;
	const void *saved_prep_data;
	size_t saved_prep_datalen;
	const struct cred *cred = current_cred();
	int ret;

	kenter("");

	memset(&p, 0, sizeof(p));
	p.pgp.types_of_interest = (1 << PGP_PKT_LITERAL_DATA);
	p.pgp.process_packet = pgp_test_parse_data;
	ret = pgp_parse_packets(prep->data, prep->datalen, &p.pgp);
	if (ret < 0) {
		kleave(" = %d [parse]", ret);
		return ret;
	}

	if (!p.params.content_len) {
		kleave(" = -ENODATA [no literal data");
		return -ENODATA;
	}

	ret = verify_pgp_signature(p.content, p.params.content_len,
				   prep->data, prep->datalen, NULL,
				   VERIFYING_UNSPECIFIED_SIGNATURE, NULL, NULL);
	if (ret < 0 && cred->session_keyring) {
		ret = verify_pgp_signature(p.content, p.params.content_len,
					   prep->data, prep->datalen,
					   cred->session_keyring,
					   VERIFYING_UNSPECIFIED_SIGNATURE,
					   NULL, NULL);
		if (ret < 0)
			goto error;

		pr_warn("PGP message doesn't chain back to a trusted key\n");
	}

	saved_prep_data = prep->data;
	saved_prep_datalen = prep->datalen;
	prep->data = p.content;
	prep->datalen = p.params.content_len;
	ret = generic_key_instantiate(key, prep);
	prep->data = saved_prep_data;
	prep->datalen = saved_prep_datalen;
error:
	kleave(" = %d", ret);
	return ret;
}

/*
 * user defined keys take an arbitrary string as the description and an
 * arbitrary blob of data as the payload
 */
static struct key_type key_type_pgp_test = {
	.name			= "pgp_test",
	.instantiate		= pgp_test_instantiate,
	.revoke			= user_revoke,
	.destroy		= user_destroy,
	.describe		= user_describe,
	.read			= user_read,
};

/*
 * Module stuff
 */
static int __init pgp_key_init(void)
{
	return register_key_type(&key_type_pgp_test);
}

static void __exit pgp_key_cleanup(void)
{
	unregister_key_type(&key_type_pgp_test);
}

module_init(pgp_key_init);
module_exit(pgp_key_cleanup);
