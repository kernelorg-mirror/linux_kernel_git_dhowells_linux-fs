// SPDX-License-Identifier: GPL-2.0
/* Instantiate a public key crypto key from PGP format data [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PGP: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mpi.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/hash.h>
#include <crypto/public_key.h>

#include "pgp_parser.h"

#define MAX_MPI 5
#define KEYCTL_SUPPORTS_ENCDEC \
	(KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_DECRYPT)
#define KEYCTL_SUPPORTS_SIGVER (KEYCTL_SUPPORTS_SIGN | KEYCTL_SUPPORTS_VERIFY)

MODULE_LICENSE("GPL");

const char *pgp_to_public_key_algo[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= "rsa",
	[PGP_PUBKEY_RSA_ENC_ONLY]	= "rsa",
	[PGP_PUBKEY_RSA_SIG_ONLY]	= "rsa",
	[PGP_PUBKEY_ELGAMAL]		= NULL,
	[PGP_PUBKEY_DSA]		= NULL,
};

static const int pgp_key_algo_p_num_mpi[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= 2,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= 2,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= 2,
	[PGP_PUBKEY_ELGAMAL]		= 3,
	[PGP_PUBKEY_DSA]		= 4,
};

static const u8 pgp_public_key_capabilities[PGP_PUBKEY__LAST] = {
	[PGP_PUBKEY_RSA_ENC_OR_SIG]	= KEYCTL_SUPPORTS_ENCDEC |
					  KEYCTL_SUPPORTS_SIGVER,
	[PGP_PUBKEY_RSA_ENC_ONLY]	= KEYCTL_SUPPORTS_ENCDEC,
	[PGP_PUBKEY_RSA_SIG_ONLY]	= KEYCTL_SUPPORTS_SIGVER,
	[PGP_PUBKEY_ELGAMAL]		= 0,
	[PGP_PUBKEY_DSA]		= 0,
};

static inline void digest_putc(struct shash_desc *digest, uint8_t ch)
{
	crypto_shash_update(digest, &ch, 1);
}

struct pgp_key_data_parse_context {
	struct pgp_parse_context pgp;
	struct public_key *pub;
	u8 raw_fingerprint[HASH_MAX_DIGESTSIZE];
	size_t raw_fingerprint_len;
	const char *user_id;
	size_t user_id_len;
};

/*
 * Calculate the public key ID (RFC4880 12.2)
 */
static int pgp_calc_pkey_keyid(struct shash_desc *digest,
			       struct pgp_parse_pubkey *pgp,
			       struct public_key *pub)
{
	unsigned int nb[MAX_MPI];
	unsigned int nn[MAX_MPI];
	unsigned int n;
	size_t keylen = pub->keylen;
	u8 *key_ptr = pub->key;
	u8 *pp[MAX_MPI];
	u32 a32;
	int npkey = pgp_key_algo_p_num_mpi[pgp->pubkey_algo];
	int i, ret;

	kenter("");

	n = (pgp->version < PGP_KEY_VERSION_4) ? 8 : 6;
	for (i = 0; i < npkey; i++) {
		ret = mpi_key_length(key_ptr, keylen, nb + i, nn + i);
		if (ret < 0)
			return ret;

		if (keylen < 2 + nn[i])
			break;

		pp[i] = key_ptr + 2;
		key_ptr += 2 + nn[i];
		keylen -= 2 + nn[i];
		n += 2 + nn[i];
	}

	if (keylen != 0) {
		pr_debug("excess %zu\n", keylen);
		return -EBADMSG;
	}

	digest_putc(digest, 0x99);     /* ctb */
	digest_putc(digest, n >> 8);   /* 16-bit header length */
	digest_putc(digest, n);
	digest_putc(digest, pgp->version);

	a32 = pgp->creation_time;
	digest_putc(digest, a32 >> 24);
	digest_putc(digest, a32 >> 16);
	digest_putc(digest, a32 >>  8);
	digest_putc(digest, a32 >>  0);

	if (pgp->version < PGP_KEY_VERSION_4) {
		u16 a16;

		if (pgp->expires_at)
			a16 = (pgp->expires_at - pgp->creation_time) / 86400UL;
		else
			a16 = 0;
		digest_putc(digest, a16 >> 8);
		digest_putc(digest, a16 >> 0);
	}

	digest_putc(digest, pgp->pubkey_algo);

	for (i = 0; i < npkey; i++) {
		digest_putc(digest, nb[i] >> 8);
		digest_putc(digest, nb[i]);
		crypto_shash_update(digest, pp[i], nn[i]);
	}
	ret = 0;

	kleave(" = %d", ret);
	return ret;
}

/*
 * Calculate the public key ID fingerprint
 */
static int pgp_generate_fingerprint(struct pgp_key_data_parse_context *ctx,
				    struct pgp_parse_pubkey *pgp,
				    struct public_key *pub)
{
	struct crypto_shash *tfm;
	struct shash_desc *digest;
	char fingerprint[HASH_MAX_DIGESTSIZE * 2 + 1] = { 0 };
	size_t offset;
	int ret;

	ret = -ENOMEM;
	tfm = crypto_alloc_shash(pgp->version < PGP_KEY_VERSION_4 ?
				 "md5" : "sha1", 0, 0);
	if (!tfm)
		goto cleanup;

	digest = kmalloc(sizeof(*digest) + crypto_shash_descsize(tfm),
			 GFP_KERNEL);
	if (!digest)
		goto cleanup_tfm;

	digest->tfm = tfm;
	crypto_shash_set_flags(digest->tfm, CRYPTO_TFM_REQ_MAY_SLEEP);
	ret = crypto_shash_init(digest);
	if (ret < 0)
		goto cleanup_hash;

	ret = pgp_calc_pkey_keyid(digest, pgp, pub);
	if (ret < 0)
		goto cleanup_hash;

	ctx->raw_fingerprint_len = crypto_shash_digestsize(tfm);

	ret = crypto_shash_final(digest, ctx->raw_fingerprint);
	if (ret < 0)
		goto cleanup_hash;

	offset = ctx->raw_fingerprint_len - 8;
	pr_debug("offset %lu/%lu\n", offset, ctx->raw_fingerprint_len);

	bin2hex(fingerprint, ctx->raw_fingerprint, ctx->raw_fingerprint_len);
	pr_debug("fingerprint %s\n", fingerprint);

	ret = 0;
cleanup_hash:
	kfree(digest);
cleanup_tfm:
	crypto_free_shash(tfm);
cleanup:
	kleave(" = %d", ret);
	return ret;
}

/*
 * Extract a public key or public subkey from the PGP stream.
 */
static int pgp_process_public_key(struct pgp_parse_context *context,
				  enum pgp_packet_tag type,
				  u8 headerlen,
				  const u8 *data,
				  size_t datalen)
{
	const char *algo;
	struct pgp_key_data_parse_context *ctx =
		container_of(context, struct pgp_key_data_parse_context, pgp);
	struct pgp_parse_pubkey pgp;
	struct public_key *pub;
	u8 capabilities;
	int ret;

	kenter(",%u,%u,,%zu", type, headerlen, datalen);

	if (type == PGP_PKT_USER_ID) {
		if (!ctx->user_id_len) {
			ctx->user_id = data;
			ctx->user_id_len = datalen;
		}
		kleave(" = 0 [user ID]");
		return 0;
	}

	if (ctx->raw_fingerprint_len) {
		kleave(" = -ENOKEY [already]");
		return -EBADMSG;
	}

	pub = kzalloc(sizeof(struct public_key), GFP_KERNEL);
	if (!pub)
		return -ENOMEM;
	pub->id_type = "PGP";

	ret = pgp_parse_public_key(&data, &datalen, &pgp);
	if (ret < 0)
		goto cleanup;

	if (pgp.pubkey_algo >= PGP_PUBKEY__LAST)
		goto cleanup_unsupported_pkey_algo;
	algo = pgp_to_public_key_algo[pgp.pubkey_algo];
	if (!algo)
		goto cleanup_unsupported_pkey_algo;

	pub->pkey_algo = algo;

	/*
	 * It's the public half of a key, so that only gives us encrypt and
	 * verify capabilities.
	 */
	capabilities = pgp_public_key_capabilities[pgp.pubkey_algo] &
		       (KEYCTL_SUPPORTS_ENCRYPT | KEYCTL_SUPPORTS_VERIFY);
	/*
	 * Capabilities are not stored anymore in the public key, store only
	 * those that allow signature verification.
	 */
	if (!(capabilities & KEYCTL_SUPPORTS_VERIFY))
		goto cleanup_unsupported_pkey_algo;

	pub->key = kmemdup(data, datalen, GFP_KERNEL);
	if (!pub->key)
		goto cleanup_nomem;

	pub->keylen = datalen;

	ret = pgp_generate_fingerprint(ctx, &pgp, pub);
	if (ret < 0)
		goto cleanup;

	ctx->pub = pub;
	kleave(" = 0 [use]");
	return 0;

cleanup_unsupported_pkey_algo:
	pr_debug("Unsupported public key algorithm %u\n",
		 pgp.pubkey_algo);
	ret = -ENOPKG;
	goto cleanup;
cleanup_nomem:
	ret = -ENOMEM;
	goto cleanup;
cleanup:
	pr_devel("cleanup");
	public_key_free(pub);
	kleave(" = %d", ret);
	return ret;
}

static struct asymmetric_key_ids *pgp_key_generate_id(
					struct pgp_key_data_parse_context *ctx)
{
	struct asymmetric_key_ids *kids;
	struct asymmetric_key_id *kid;

	kids = kzalloc(sizeof(struct asymmetric_key_ids), GFP_KERNEL);
	if (!kids)
		return kids;

	kid = asymmetric_key_generate_id(ctx->raw_fingerprint,
					 ctx->raw_fingerprint_len, NULL, 0);
	if (IS_ERR(kid))
		goto error;

	kids->id[0] = kid;
	kids->id[1] = kmemdup(kid, sizeof(*kid) + ctx->raw_fingerprint_len,
			      GFP_KERNEL);
	if (!kids->id[1])
		goto error;

	return kids;
error:
	kfree(kids->id[0]);
	kfree(kids);

	return NULL;
}

/*
 * Attempt to parse the instantiation data blob for a key as a PGP packet
 * message holding a key.
 */
static int pgp_key_parse(struct key_preparsed_payload *prep)
{
	struct pgp_key_data_parse_context ctx;
	int ret;

	kenter("");

	memset(&ctx, 0, sizeof(ctx));
	ctx.pgp.types_of_interest = (1 << PGP_PKT_PUBLIC_KEY) |
				    (1 << PGP_PKT_USER_ID);
	ctx.pgp.process_packet = pgp_process_public_key;

	ret = pgp_parse_packets(prep->data, prep->datalen, &ctx.pgp);
	if (ret < 0)
		goto error;

	if (ctx.user_id && ctx.user_id_len > 0) {
		/*
		 * Propose a description for the key (user ID without the
		 * comment).
		 */
		size_t ulen = ctx.user_id_len;
		const char *p;

		p = memchr(ctx.user_id, '(', ulen);
		if (p) {
			/* Remove the comment */
			do {
				p--;
			} while (*p == ' ' && p > ctx.user_id);
			if (*p != ' ')
				p++;
			ulen = p - ctx.user_id;
		}

		if (ulen > 255 - 9)
			ulen = 255 - 9;
		prep->description = kmalloc(ulen + 1 + 8 + 1, GFP_KERNEL);
		ret = -ENOMEM;
		if (!prep->description)
			goto error;
		memcpy(prep->description, ctx.user_id, ulen);
		prep->description[ulen] = ' ';
		bin2hex(prep->description + ulen + 1,
			ctx.raw_fingerprint + ctx.raw_fingerprint_len - 4, 4);
		prep->description[ulen + 9] = 0;
		pr_debug("desc '%s'\n", prep->description);
	}

	/* We're pinning the module by being linked against it */
	__module_get(public_key_subtype.owner);
	prep->payload.data[asym_subtype] = &public_key_subtype;
	prep->payload.data[asym_key_ids] = pgp_key_generate_id(&ctx);
	prep->payload.data[asym_crypto] = ctx.pub;
	prep->quotalen = 100;
	return 0;

error:
	public_key_free(ctx.pub);
	return ret;
}

static struct asymmetric_key_parser pgp_key_parser = {
	.owner		= THIS_MODULE,
	.name		= "pgp",
	.parse		= pgp_key_parse,
};

/*
 * Module stuff
 */
static int __init pgp_key_init(void)
{
	return register_asymmetric_key_parser(&pgp_key_parser);
}

static void __exit pgp_key_exit(void)
{
	unregister_asymmetric_key_parser(&pgp_key_parser);
}

module_init(pgp_key_init);
module_exit(pgp_key_exit);
