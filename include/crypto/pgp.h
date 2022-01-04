/* SPDX-License-Identifier: GPL-2.0+ */
/* PGP signature processing
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef _CRYPTO_PGP_H
#define _CRYPTO_PGP_H

#include <crypto/hash_info.h>

struct key;
struct pgp_sig_verify;

/*
 * pgp_signature.c
 */
extern struct pgp_sig_verify *pgp_sig_parse(const u8 *sigdata, size_t siglen);
extern int pgp_sig_add_data(struct pgp_sig_verify *ctx,
			    const void *data, size_t datalen);
extern int pgp_sig_get_digest(struct pgp_sig_verify *ctx, const u8 **buf,
			      u32 *len, enum hash_algo *hash_algo);
extern int pgp_sig_verify(struct pgp_sig_verify *ctx, struct key *keyring);
extern void pgp_sig_verify_cancel(struct pgp_sig_verify *ctx, bool keep_sig);
extern struct public_key_signature *pgp_sig_get_sig(struct pgp_sig_verify *ctx);
extern u8 pgp_sig_get_version(struct pgp_sig_verify *ctx);

#endif /* _CRYPTO_PGP_H */
