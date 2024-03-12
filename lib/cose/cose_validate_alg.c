/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"
#include "private-lib-cose.h"

aws_lws_cose_sig_alg_t *
aws_lws_cose_val_alg_create(struct aws_lws_context *cx, aws_lws_cose_key_t *ck,
		        cose_param_t cose_alg, int op)
{
	aws_lws_cose_sig_alg_t *alg = aws_lws_zalloc(sizeof(*alg), __func__);
	struct aws_lws_gencrypto_keyelem *ke;
	enum aws_lws_genhmac_types ghm;
	enum aws_lws_genhash_types gh;
	const char *crv;

	if (!alg)
		return NULL;

	alg->cose_alg = cose_alg;
	alg->cose_key = ck;

	switch (cose_alg) {

	/* ECDSA algs */

	case LWSCOSE_WKAECDSA_ALG_ES256: /* ECDSA w/ SHA-256 */
		crv = "P-256";
		gh = LWS_GENHASH_TYPE_SHA256;
		alg->keybits = 256;
		goto ecdsa;
	case LWSCOSE_WKAECDSA_ALG_ES384: /* ECDSA w/ SHA-384 */
		crv = "P-384";
		gh = LWS_GENHASH_TYPE_SHA384;
		alg->keybits = 384;
		goto ecdsa;
	case LWSCOSE_WKAECDSA_ALG_ES512: /* ECDSA w/ SHA-512 */
		crv = "P-521";
		gh = LWS_GENHASH_TYPE_SHA512;
		alg->keybits = 521;
ecdsa:

		/* the key is good for this? */

		if (aws_lws_cose_key_checks(ck, LWSCOSE_WKKTV_EC2, cose_alg,
					op, crv))
			goto bail_ecdsa;

		if (aws_lws_genhash_init(&alg->hash_ctx, gh))
			goto bail_ecdsa;

		if (aws_lws_genecdsa_create(&alg->u.ecdsactx, cx, aws_lws_ec_curves)) {
			aws_lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			goto bail_ecdsa1;
		}

		if (aws_lws_genecdsa_set_key(&alg->u.ecdsactx, ck->e)) {
			aws_lwsl_notice("%s: ec key import fail\n", __func__);
			goto bail_ecdsa2;
		}

		break;

	/* HMAC algs */

	case LWSCOSE_WKAHMAC_256_64:
		ghm = LWS_GENHMAC_TYPE_SHA256;
		alg->keybits = 64;
		goto hmac;
	case LWSCOSE_WKAHMAC_256_256:
		ghm = LWS_GENHMAC_TYPE_SHA256;
		alg->keybits = 256;
		goto hmac;
	case LWSCOSE_WKAHMAC_384_384:
		ghm = LWS_GENHMAC_TYPE_SHA384;
		alg->keybits = 384;
		goto hmac;
	case LWSCOSE_WKAHMAC_512_512:
		ghm = LWS_GENHMAC_TYPE_SHA512;
		alg->keybits = 512;

hmac:
		if (aws_lws_cose_key_checks(ck, LWSCOSE_WKKTV_SYMMETRIC,
					cose_alg, op, NULL))
			goto bail_hmac;

		ke = &ck->e[LWS_GENCRYPTO_OCT_KEYEL_K];
		if (aws_lws_genhmac_init(&alg->u.hmacctx, ghm, ke->buf, ke->len))
			goto bail_hmac;

		break;

	/* RSASSA algs */

	case LWSCOSE_WKARSA_ALG_RS256:
		gh = LWS_GENHASH_TYPE_SHA256;
		goto rsassa;

	case LWSCOSE_WKARSA_ALG_RS384:
		gh = LWS_GENHASH_TYPE_SHA384;
		goto rsassa;

	case LWSCOSE_WKARSA_ALG_RS512:
		gh = LWS_GENHASH_TYPE_SHA512;

rsassa:
		if (aws_lws_cose_key_checks(ck, LWSCOSE_WKKTV_RSA, cose_alg,
					op, NULL))
			goto bail_hmac;
		alg->keybits = (int)ck->e[LWS_GENCRYPTO_RSA_KEYEL_N].len * 8;

		if (aws_lws_genhash_init(&alg->hash_ctx, gh))
			goto bail_ecdsa;

		if (aws_lws_genrsa_create(&alg->u.rsactx, ck->e, cx,
				      LGRSAM_PKCS1_1_5, gh)) {
			aws_lwsl_notice("%s: aws_lws_genrsa_create fail\n", __func__);
			goto bail_ecdsa1;
		}
		break;

	default:
		aws_lwsl_warn("%s: unsupported alg %lld\n", __func__,
				(long long)cose_alg);
		goto bail_hmac;
	}

	return alg;

bail_ecdsa2:
	aws_lws_genec_destroy(&alg->u.ecdsactx);
bail_ecdsa1:
	aws_lws_genhash_destroy(&alg->hash_ctx, NULL);
bail_ecdsa:
	aws_lws_free(alg);

	aws_lwsl_notice("%s: failed\n", __func__);

	return NULL;

bail_hmac:
	aws_lws_free(alg);

	return NULL;
}

int
aws_lws_cose_val_alg_hash(aws_lws_cose_sig_alg_t *alg, const uint8_t *in, size_t in_len)
{
#if defined(VERBOSE)
	aws_lwsl_hexdump_warn(in, in_len);
#endif

	switch (alg->cose_alg) {
	case LWSCOSE_WKAHMAC_256_64:
	case LWSCOSE_WKAHMAC_256_256:
	case LWSCOSE_WKAHMAC_384_384:
	case LWSCOSE_WKAHMAC_512_512:
		return aws_lws_genhmac_update(&alg->u.hmacctx, in, in_len);
	}

	return aws_lws_genhash_update(&alg->hash_ctx, in, in_len);
}

void
aws_lws_cose_val_alg_destroy(struct aws_lws_cose_validate_context *cps,
			 aws_lws_cose_sig_alg_t **_alg, const uint8_t *against,
			 size_t against_len)
{
	uint8_t digest[LWS_GENHASH_LARGEST];
	aws_lws_cose_sig_alg_t *alg = *_alg;
	aws_lws_cose_validate_res_t *res;
	size_t hs, shs;
	int keybits;
	uint8_t ht;

	aws_lws_dll2_remove(&alg->list);
	ht = alg->hash_ctx.type;
	keybits = alg->keybits;

	res = aws_lws_zalloc(sizeof(*res), __func__);
	if (res) {

		res->cose_key = alg->cose_key;
		res->cose_alg = alg->cose_alg;
		res->result = -999;

		aws_lws_dll2_add_tail(&res->list, &cps->results);
	}

	switch (alg->cose_alg) {
	case LWSCOSE_WKAECDSA_ALG_ES256: /* ECDSA w/ SHA-256 */
	case LWSCOSE_WKAECDSA_ALG_ES384: /* ECDSA w/ SHA-384 */
	case LWSCOSE_WKAECDSA_ALG_ES512: /* ECDSA w/ SHA-512 */
		hs = aws_lws_genhash_size(alg->hash_ctx.type);
		aws_lws_genhash_destroy(&alg->hash_ctx, digest);

		aws_lwsl_notice("%d %d %d\n", (int)hs, (int)keybits, (int)against_len);

		if (res && against)
			res->result = aws_lws_genecdsa_hash_sig_verify_jws(
						&alg->u.ecdsactx, digest, ht,
						keybits, against, against_len);
		aws_lws_genec_destroy(&alg->u.ecdsactx);
		break;

	case LWSCOSE_WKAHMAC_256_64:
	case LWSCOSE_WKAHMAC_256_256:
	case LWSCOSE_WKAHMAC_384_384:
	case LWSCOSE_WKAHMAC_512_512:
		shs = hs = aws_lws_genhmac_size(alg->u.hmacctx.type);
		if (alg->cose_alg == LWSCOSE_WKAHMAC_256_64)
			shs = 8;

		if (aws_lws_genhmac_destroy(&alg->u.hmacctx, digest)) {
			aws_lwsl_err("%s: destroy failed\n", __func__);
			break;
		}

		if (cps->mac_pos != shs) {
			aws_lwsl_warn("%s: mac wrong size\n", __func__);
			/* we can't compare it, leave it at fail */
			break;
		}
		if (res && against) {
			res->result = aws_lws_timingsafe_bcmp(digest, cps->mac,
								(uint32_t)shs);
			if (res->result)
				aws_lwsl_warn("%s: hash mismatch\n", __func__);
		}
		break;

	case LWSCOSE_WKARSA_ALG_RS256:
	case LWSCOSE_WKARSA_ALG_RS384:
	case LWSCOSE_WKARSA_ALG_RS512:

		if (!aws_lws_genhash_destroy(&alg->hash_ctx, digest) &&
		    !alg->failed &&
		    aws_lws_genrsa_hash_sig_verify(&alg->u.rsactx, digest,
					 alg->hash_ctx.type,
					 against, against_len) >= 0) {
			if (res)
				res->result = 0;
		} else
			aws_lwsl_err("%s: lws_genrsa_hash_verify\n", __func__);

		aws_lws_genrsa_destroy(&alg->u.rsactx);
		break;
	}

	aws_lws_free_set_NULL(*_alg);
}
