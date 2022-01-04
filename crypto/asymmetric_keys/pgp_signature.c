// SPDX-License-Identifier: GPL-2.0-or-later
/* PGP public key signature verification [RFC 4880]
 *
 * Copyright (C) 2011 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) "PGPSIG: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mpi.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/key.h>
#include <linux/err.h>
#include <keys/asymmetric-type.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <crypto/pgp.h>

#include "pgp_parser.h"

static const struct {
	enum hash_algo algo : 8;
} pgp_pubkey_hash[PGP_HASH__LAST] = {
	[PGP_HASH_MD5].algo		= HASH_ALGO_MD5,
	[PGP_HASH_SHA1].algo		= HASH_ALGO_SHA1,
	[PGP_HASH_RIPE_MD_160].algo	= HASH_ALGO_RIPE_MD_160,
	[PGP_HASH_SHA256].algo		= HASH_ALGO_SHA256,
	[PGP_HASH_SHA384].algo		= HASH_ALGO_SHA384,
	[PGP_HASH_SHA512].algo		= HASH_ALGO_SHA512,
	[PGP_HASH_SHA224].algo		= HASH_ALGO_SHA224,
};

struct pgp_current_pkt {
	enum pgp_packet_tag type;
	u8 headerlen;
	const u8 *data;
	size_t datalen;
};

struct pgp_sig_verify {
	enum pgp_signature_version sig_version : 8;
	struct public_key_signature *sig;
	u8 signed_hash_msw[2];
	struct shash_desc *hash;
	struct pgp_current_pkt pkt;
};

/*
 * Find a key in the given keyring by issuer and authority.
 */
static struct key *pgp_request_asymmetric_key(struct pgp_sig_verify *ctx,
					      struct key *keyring)
{
	struct key *key;
	__be32 *issuer32;
	char id[20];

	issuer32 = (__be32 *)ctx->sig->auth_ids[0]->data;
	snprintf(id, sizeof(id), "id:%08x%08x", be32_to_cpu(issuer32[0]),
		 be32_to_cpu(issuer32[1]));

	kenter(",,%s", id);

	pr_debug("Look up key: \"%s\"\n", id);

	key = find_asymmetric_key(keyring, ctx->sig->auth_ids[0],
				  ctx->sig->auth_ids[1], NULL, true);
	if (IS_ERR(key)) {
		pr_debug("Request for public key '%08x%08x' err %ld\n",
			 issuer32[0], issuer32[1], PTR_ERR(key));

		switch (PTR_ERR(key)) {
			/* Hide some search errors */
		case -EACCES:
		case -ENOTDIR:
		case -EAGAIN:
			kleave(" = -ENOKEY");
			return ERR_PTR(-ENOKEY);
		default:
			kleave(" = %ld", PTR_ERR(key));
			return ERR_CAST(key);
		}
	}

	kleave(" = 0 [%x]", key_serial(key));
	return key;
}

struct pgp_sig_parse_context {
	struct pgp_parse_context pgp;
	struct pgp_sig_parameters params;
	struct pgp_current_pkt pkt;
};

static int pgp_parse_signature(struct pgp_parse_context *context,
			       enum pgp_packet_tag type,
			       u8 headerlen,
			       const u8 *data,
			       size_t datalen)
{
	struct pgp_sig_parse_context *ctx =
		container_of(context, struct pgp_sig_parse_context, pgp);
	struct pgp_sig_parameters tmp_params;
	struct pgp_current_pkt tmp_pkt = { type, headerlen, data, datalen};
	int ret;

	ret = pgp_parse_sig_params(&data, &datalen, &tmp_params);
	if (ret < 0)
		return ret;

	if (tmp_params.signature_type != PGP_SIG_BINARY_DOCUMENT_SIG &&
	    tmp_params.signature_type != PGP_SIG_STANDALONE_SIG &&
	    tmp_params.signature_type != PGP_SIG_POSTITIVE_CERT_OF_UID_PUBKEY)
		return 0;

	memcpy(&ctx->params, &tmp_params, sizeof(tmp_params));
	memcpy(&ctx->pkt, &tmp_pkt, sizeof(tmp_pkt));
	return 0;
}

/**
 * pgp_sig_parse - Begin the process of verifying a signature
 * @sigdata: Signature blob
 * @siglen: Length of signature blob
 *
 * This involves allocating the hash into which first the data and then the
 * metadata will be put, and parsing the signature to get the issuer ID from
 * which the key used to verify the signature will be searched.
 *
 * Return: a PGP sig context pointer on success, an error pointer on error
 */
struct pgp_sig_verify *pgp_sig_parse(const u8 *sigdata, size_t siglen)
{
	struct pgp_sig_parse_context p;
	struct pgp_sig_verify *ctx;
	struct crypto_shash *tfm;
	const char *pkey_algo;
	size_t digest_size, desc_size;
	int ret;

	kenter(",,%zu", siglen);

	p.pgp.types_of_interest = (1 << PGP_PKT_SIGNATURE);
	p.pgp.process_packet = pgp_parse_signature;
	p.pkt.data = NULL;
	ret = pgp_parse_packets(sigdata, siglen, &p.pgp);
	if (ret < 0) {
		kleave(" = ERR_PTR [bad pkt]");
		return ERR_PTR(ret);
	}

	if (!p.pkt.data) {
		kleave(" = ERR_PTR [no pkt]");
		return ERR_PTR(-ENOENT);
	}

	/* Check the signature itself for usefulness */
	if (p.params.pubkey_algo >= PGP_PUBKEY__LAST)
		goto unsupported_pkey_algo;
	pkey_algo = pgp_to_public_key_algo[p.params.pubkey_algo];
	if (!pkey_algo)
		goto unsupported_pkey_algo;

	if (p.params.hash_algo >= PGP_HASH__LAST ||
	    !pgp_hash_algorithms[p.params.hash_algo]) {
		pr_debug("Unsupported hash algorithm %u\n",
			 p.params.hash_algo);
		kleave(" = -ENOPKG [unsupp hash algo]");
		return ERR_PTR(-ENOPKG);
	}

	pr_debug("Signature generated with %s hash\n",
		 pgp_hash_algorithms[p.params.hash_algo]);

	/* Allocate the hashing algorithm we're going to need and find out how
	 * big the hash operational data will be.
	 */
	tfm = crypto_alloc_shash(pgp_hash_algorithms[p.params.hash_algo], 0, 0);
	if (IS_ERR(tfm)) {
		ret = (PTR_ERR(tfm) == -ENOENT ? -ENOPKG : PTR_ERR(tfm));
		kleave(" = %d", ret);
		return ERR_PTR(ret);
	}

	desc_size = crypto_shash_descsize(tfm);
	digest_size = crypto_shash_digestsize(tfm);

	/* We allocate the hash operational data storage on the end of our
	 * context data.
	 */
	ctx = kzalloc(sizeof(*ctx) + sizeof(struct shash_desc) + desc_size,
		      GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto error_have_shash;
	}

	ctx->sig = kzalloc(sizeof(*ctx->sig), GFP_KERNEL);
	if (!ctx->sig) {
		ret = -ENOMEM;
		goto error_have_ctx;
	}

	ctx->sig->auth_ids[0] = asymmetric_key_generate_id(p.params.issuer.id,
					sizeof(p.params.issuer.id), "", 0);
	if (IS_ERR(ctx->sig->auth_ids[0])) {
		ret = -ENOMEM;
		goto error_have_ctx_sig;
	}

	ctx->sig->encoding	= "pkcs1";
	ctx->sig->pkey_algo	= pkey_algo;
	ctx->sig->hash_algo	= pgp_hash_algorithms[p.params.hash_algo];
	ctx->sig->digest_size	= digest_size;
	ctx->hash		= (struct shash_desc *)((void *)ctx +
				  sizeof(*ctx));
	ctx->hash->tfm		= tfm;
	ctx->sig_version	= p.params.version;

	memcpy(&ctx->pkt, &p.pkt, sizeof(p.pkt));

	ret = crypto_shash_init(ctx->hash);
	if (ret < 0)
		goto error_have_auth_ids;

	kleave(" = %p", ctx);
	return ctx;

error_have_auth_ids:
	kfree(ctx->sig->auth_ids[0]);
error_have_ctx_sig:
	kfree(ctx->sig);
error_have_ctx:
	kfree(ctx);
error_have_shash:
	crypto_free_shash(tfm);
	kleave(" = %d", ret);
	return ERR_PTR(ret);

unsupported_pkey_algo:
	pr_debug("Unsupported public key algorithm %u\n",
		 p.params.pubkey_algo);
	kleave(" = -ENOPKG [unsupp pk algo]");
	return ERR_PTR(-ENOPKG);
}

/*
 * Load data into the hash
 */
int pgp_sig_add_data(struct pgp_sig_verify *ctx, const void *data,
		     size_t datalen)
{
	return crypto_shash_update(ctx->hash, data, datalen);
}

/*
 * Extract required metadata from the signature packet and add what we need to
 * the hash; finalise the hash.
 */
static int pgp_digest_signature(struct pgp_sig_verify *ctx)
{
	enum pgp_signature_version version;
	unsigned int nbytes, nbytes_alloc;
	enum pgp_packet_tag type = ctx->pkt.type;
	const u8 *data = ctx->pkt.data;
	size_t datalen = ctx->pkt.datalen;
	int ret;

	kenter(",%u,,%zu", type, datalen);

	if (ctx->sig->digest) {
		kleave(" = 0 [digest found]");
		return 0;
	}

	version = *data;
	if (version == PGP_SIG_VERSION_3) {
		/* We just include an excerpt of the metadata from a V3
		 * signature.
		 */
		crypto_shash_update(ctx->hash, data + 2, 5);
		data += sizeof(struct pgp_signature_v3_packet);
		datalen -= sizeof(struct pgp_signature_v3_packet);
	} else if (version == PGP_SIG_VERSION_4) {
		/* We add the whole metadata header and some of the hashed data
		 * for a V4 signature, plus a trailer.
		 */
		size_t hashedsz, unhashedsz;
		u8 trailer[6];

		hashedsz = 4 + 2 + (data[4] << 8) + data[5];
		crypto_shash_update(ctx->hash, data, hashedsz);

		trailer[0] = version;
		trailer[1] = 0xffU;
		trailer[2] = hashedsz >> 24;
		trailer[3] = hashedsz >> 16;
		trailer[4] = hashedsz >> 8;
		trailer[5] = hashedsz;

		crypto_shash_update(ctx->hash, trailer, 6);
		data += hashedsz;
		datalen -= hashedsz;

		unhashedsz = 2 + (data[0] << 8) + data[1];
		data += unhashedsz;
		datalen -= unhashedsz;
	}

	if (datalen <= 2) {
		kleave(" = -EBADMSG");
		return -EBADMSG;
	}

	/* There's a quick check on the hash available. */
	ctx->signed_hash_msw[0] = *data++;
	ctx->signed_hash_msw[1] = *data++;
	datalen -= 2;

	/* And then the cryptographic data, which we'll need for the
	 * algorithm.
	 */
	ret = mpi_key_length(data, datalen, NULL, &nbytes);
	if (ret < 0) {
		kleave(" = -EBADMSG [key length]");
		return ret;
	}

	if (datalen != nbytes + 2) {
		kleave(" = -EBADMSG [size mismatch]");
		return -EBADMSG;
	}

	nbytes_alloc = DIV_ROUND_UP(nbytes, 8) * 8;

	ctx->sig->s = kzalloc(nbytes_alloc, GFP_KERNEL);
	if (!ctx->sig->s) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy(ctx->sig->s + nbytes_alloc - nbytes, data + 2, nbytes);
	ctx->sig->s_size = nbytes_alloc;

	ctx->sig->digest = kmalloc(ctx->sig->digest_size, GFP_KERNEL);
	if (!ctx->sig->digest) {
		ret = -ENOMEM;
		goto out;
	}

	ret = crypto_shash_final(ctx->hash, ctx->sig->digest);
	if (ret < 0)
		goto out;

	pr_debug("hash: %*phN\n", ctx->sig->digest_size, ctx->sig->digest);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * pgp_sig_get_digest - Finalize digest calculation
 * @ctx: PGP sig verification context to use
 * @buf: Buffer digest is written to
 * @len: Buffer length
 * @hash_algo: Digest algorithm
 *
 * Copy the calculated digest, length and algorithm to the destinations provided
 * by the caller.
 *
 * Return: 0 on success, a negative value on error
 */
int pgp_sig_get_digest(struct pgp_sig_verify *ctx, const u8 **buf, u32 *len,
		       enum hash_algo *hash_algo)
{
	int ret, i;

	kenter("");

	ret = pgp_digest_signature(ctx);
	if (ret < 0)
		goto out;

	i = match_string(hash_algo_name, HASH_ALGO__LAST,
			 ctx->sig->hash_algo);
	if (i < 0) {
		ret = -ENOENT;
		goto out;
	}

	*hash_algo = i;
	*buf = ctx->sig->digest;
	*len = ctx->sig->digest_size;
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * pgp_sig_verify - Verify the PGP signature
 * @ctx: PGP sig verification context to use
 * @keyring: Keyring containing the key for signature verification
 *
 * Search the key to be used for signature verification, and verify the PGP
 * signature.
 *
 * Return: 0 if the signature is valid, a negative value otherwise
 */
int pgp_sig_verify(struct pgp_sig_verify *ctx, struct key *keyring)
{
	const struct public_key *pub;
	struct key *key;
	int ret;

	kenter("");

	ret = pgp_digest_signature(ctx);
	if (ret < 0)
		goto out;

	if (ctx->sig->digest[0] != ctx->signed_hash_msw[0] ||
	    ctx->sig->digest[1] != ctx->signed_hash_msw[1]) {
		pr_err("Hash (%02x%02x) mismatch against quick check (%02x%02x)\n",
		       ctx->sig->digest[0], ctx->sig->digest[1],
		       ctx->signed_hash_msw[0], ctx->signed_hash_msw[1]);
		ret = -EKEYREJECTED;
		goto out;
	}

	/* Now we need to find a key to use */
	key = pgp_request_asymmetric_key(ctx, keyring);
	if (IS_ERR(key)) {
		ret = PTR_ERR(key);
		goto out;
	}

	pub = key->payload.data[asym_crypto];

	if (strcmp(ctx->sig->pkey_algo, pub->pkey_algo)) {
		ret = -EKEYREJECTED;
		goto out_key;
	}

	ret = verify_signature(key, ctx->sig);
out_key:
	key_put(key);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * pgp_sig_verify_cancel - End the PGP signature verification
 * @ctx: PGP sig verification context to use
 * @keep_sig: Don't deallocate the signature
 *
 * Free the memory used for the signature verification.
 */
void pgp_sig_verify_cancel(struct pgp_sig_verify *ctx, bool keep_sig)
{
	kenter("");

	crypto_free_shash(ctx->hash->tfm);
	if (!keep_sig)
		public_key_signature_free(ctx->sig);

	kfree(ctx);

	kleave("");
}

/**
 * pgp_sig_get_sig - Return the PGP signature
 * @ctx: PGP sig verification context to use
 *
 * Finalize the signature by calculating the digest if not already done. Then,
 * return the PGP signature to the caller.
 *
 * Return: the PGP signature if successfully finalized, an error pointer
 * otherwise
 */
struct public_key_signature *pgp_sig_get_sig(struct pgp_sig_verify *ctx)
{
	int ret;

	ret = pgp_digest_signature(ctx);
	if (ret < 0)
		return ERR_PTR(-ENOENT);

	return ctx->sig;
}

/**
 * pgp_sig_get_version - Return the PGP signature version
 * @ctx: PGP sig verification context to use
 *
 * Return the version of the PGP signature to the caller.
 *
 * Return: the PGP signature version
 */
u8 pgp_sig_get_version(struct pgp_sig_verify *ctx)
{
	return ctx->sig_version;
}
