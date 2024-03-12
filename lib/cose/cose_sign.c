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

struct aws_lws_cose_sign_context *
aws_lws_cose_sign_create(const aws_lws_cose_sign_create_info_t *info)
{
	struct aws_lws_cose_sign_context *csc;

	/* you have to have prepared a cbor output context for us to use */
	assert(info->lec);
	/* you have to provide at least one key in a cose_keyset */
	assert(info->keyset);
	/* you have to provide an aws_lws_context (for crypto random) */
	assert(info->cx);

	if (info->sigtype == SIGTYPE_MAC) {
		aws_lwsl_err("%s: only mac0 supported for signing\n", __func__);
		return NULL;
	}

	csc = aws_lws_zalloc(sizeof(*csc), __func__);
	if (!csc)
		return NULL;

	csc->info = *info;

	return csc;
}

int
aws_lws_cose_sign_add(struct aws_lws_cose_sign_context *csc, cose_param_t alg,
		  const aws_lws_cose_key_t *ck)
{
	aws_lws_cose_sig_alg_t *si = aws_lws_cose_sign_alg_create(csc->info.cx, ck, alg,
							  LWSCOSE_WKKO_SIGN);

	if (!si)
		return 1;

	aws_lws_dll2_add_tail(&si->list, &csc->algs);

	return 0;
}

static signed char cose_tags[] = {
	0,
	LWSCOAP_CONTENTFORMAT_COSE_SIGN,
	LWSCOAP_CONTENTFORMAT_COSE_SIGN1,
	LWSCOAP_CONTENTFORMAT_COSE_SIGN,
	LWSCOAP_CONTENTFORMAT_COSE_MAC,
	LWSCOAP_CONTENTFORMAT_COSE_MAC0
};

static void
aws_lws_cose_sign_hashing(struct aws_lws_cose_sign_context *csc,
		      const uint8_t *in, size_t in_len)
{
	//aws_lwsl_hexdump_warn(in, in_len);

	assert(in_len);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, tp,
				   aws_lws_dll2_get_head(&csc->algs)) {
		aws_lws_cose_sig_alg_t *alg = aws_lws_container_of(p,
						aws_lws_cose_sig_alg_t, list);

		if (aws_lws_cose_sign_alg_hash(alg, in, in_len))
			alg->failed = 1;
	} aws_lws_end_foreach_dll_safe(p, tp);
}

/*
 * These chunks may be payload or application AAD being emitted into the
 * signed object somewhere else.  But we do not emit them ourselves here
 * (since other non-emitted things are also hashed by us) and so can always
 * deal with the whole in_len in one step.
 */

enum aws_lws_lec_pctx_ret
aws_lws_cose_sign_payload_chunk(struct aws_lws_cose_sign_context *csc,
			    const uint8_t *in, size_t in_len)
{
	uint8_t lbuf[MAX_BLOBBED_PARAMS], lb[9];
	const struct aws_lws_gencrypto_keyelem *ke;
	enum aws_lws_lec_pctx_ret ret;
	aws_lws_lec_pctx_t lec, lec1;
	aws_lws_cose_sig_alg_t *alg;
	uint8_t c;
	size_t s;

	switch (csc->tli) {
	case ST_UNKNOWN:
		/*
		 * We need to figure out what signing structure we need to use,
		 * given the algorithms that are in it.  So let's have a look
		 * and decide.
		 */

		if (!csc->algs.count) {
			aws_lwsl_err("%s: must add at least one signature\n", __func__);
			return 1;
		}

		csc->type = SIGTYPE_MULTI;
		alg = aws_lws_container_of(csc->algs.head, aws_lws_cose_sig_alg_t, list);

		switch (alg->cose_alg) {
		case LWSCOSE_WKAHMAC_256_64:
		case LWSCOSE_WKAHMAC_256_256:
		case LWSCOSE_WKAHMAC_384_384:
		case LWSCOSE_WKAHMAC_512_512:
//			if (csc->info.sigtype == SIGTYPE_MAC0)
				csc->type = SIGTYPE_MAC0;
//			else
//				csc->type = SIGTYPE_MAC;
			break;
		}

		if (csc->algs.count == 1) {
			if (!csc->info.sigtype && csc->type == SIGTYPE_MAC) {
			    if (csc->info.flags & LCSC_FL_ADD_CBOR_PREFER_MAC0)
				csc->type = SIGTYPE_MAC0;
			} else
				if (!csc->info.sigtype ||
				    csc->info.sigtype == SIGTYPE_SINGLE) /* ie, if no hint */
					csc->type = SIGTYPE_SINGLE;
		}

		aws_lwsl_notice("%s: decided on type %d\n", __func__, csc->type);

		/*
		 * Start emitting the appropriate tag if that's requested
		 */

		if (csc->info.flags & LCSC_FL_ADD_CBOR_TAG) {
			ret = aws_lws_lec_printf(csc->info.lec, "%t(",
					       cose_tags[csc->type]);

			if (ret != LWS_LECPCTX_RET_FINISHED)
				return ret;
		}

		/* The */
		c = 0;
		switch (csc->type) {
		case SIGTYPE_MAC0:
		case SIGTYPE_MULTI:
		case SIGTYPE_SINGLE:
			c = 0x84;
			break;
		case SIGTYPE_MAC:
			c = 0x85;
			break;
		default:
			break;
		}

		/* The outer array */
		csc->info.lec->scratch[csc->info.lec->scratch_len++] = c;

		/*
		 * Then, let's start hashing with the sigtype constant part
		 */

		aws_lws_cose_sign_hashing(csc, sig_mctx[csc->type],
					   sig_mctx_len[csc->type]);

		csc->tli = ST_OUTER_PROTECTED;
		csc->subsequent = 0;

		/* fallthru */

	case ST_OUTER_PROTECTED:

		/*
		 * We need to list and emit any outer protected data as a map
		 * into its own buffer, then emit that into the output as a bstr
		 */

		switch (csc->type) {
		case SIGTYPE_SINGLE:
		case SIGTYPE_MAC0:
			alg = aws_lws_container_of(csc->algs.head,
					       aws_lws_cose_sig_alg_t, list);

			aws_lws_lec_init(&lec, lbuf, sizeof(lbuf));

			/* we know it will fit */
			aws_lws_lec_printf(&lec, "{1:%lld}",
					     (long long)alg->cose_alg);
			aws_lws_lec_scratch(&lec);

			if (!csc->subsequent) {
				aws_lws_lec_init(&lec1, lb, sizeof(lb));
				aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0,
						lec.used);
				aws_lws_cose_sign_hashing(csc, lec1.scratch,
							   lec1.scratch_len);
				aws_lws_cose_sign_hashing(csc, lec.start, lec.used);
				ret = aws_lws_lec_printf(csc->info.lec, "%.*b",
						     (int)lec.used, lec.start);

				if (ret != LWS_LECPCTX_RET_FINISHED)
					return ret;
				csc->subsequent = 1;
			}
			break;
		case SIGTYPE_MAC:
		case SIGTYPE_MULTI:
			aws_lws_lec_init(&lec, lbuf, sizeof(lbuf));
			aws_lws_lec_int(&lec, LWS_CBOR_MAJTYP_BSTR, 0, 0);
			aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_BSTR, 0, 0);
			aws_lws_lec_scratch(&lec);
			lec.used = aws_lws_ptr_diff_size_t(lec.buf, lec.start);
			aws_lws_cose_sign_hashing(csc, lec.start,
						   lec.used);
			break;
		default:
			lec.used = 0;
			break;
		}

		csc->tli = ST_OUTER_UNPROTECTED;

		/* fallthru */

	case ST_OUTER_UNPROTECTED:

		/*
		 * We need to list and emit any outer unprotected data, as
		 * an inline cbor map
		 */

		switch (csc->type) {
		case SIGTYPE_SINGLE:
		case SIGTYPE_MAC0:
			alg = aws_lws_container_of(csc->algs.head,
					       aws_lws_cose_sig_alg_t, list);
			ke = &alg->cose_key->meta[COSEKEY_META_KID];
			if (ke->len) {
				ret = aws_lws_lec_printf(csc->info.lec, "{%d:%.*b}",
						     LWSCOSE_WKL_KID,
						     (int)ke->len, ke->buf);

				if (ret != LWS_LECPCTX_RET_FINISHED)
					return ret;
			}
			/* hack for no extra data */

			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0, 0);
			aws_lws_cose_sign_hashing(csc, lec1.scratch,
						   lec1.scratch_len);
			break;
		case SIGTYPE_MAC:
		case SIGTYPE_MULTI:

			aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_BSTR, 0, 0);

			/*
			 * For cose-sign, we need to feed each sig alg its alg-
			 * specific protected data into the hash before letting
			 * all the hashes see the payload
			 */

			aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, tp,
						   aws_lws_dll2_get_head(&csc->algs)) {
				alg = aws_lws_container_of(p, aws_lws_cose_sig_alg_t, list);

				aws_lws_lec_init(&lec, lbuf, sizeof(lbuf));

				/* we know it will fit */
				aws_lws_lec_printf(&lec, "{1:%lld}",
						     (long long)alg->cose_alg);

				aws_lws_lec_init(&lec1, lb, sizeof(lb));
				aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0,
						lec.used);

				// aws_lwsl_hexdump_warn(lec1.scratch, lec1.scratch_len);
				// aws_lwsl_hexdump_warn(lec.start, lec.used);
				if (aws_lws_cose_sign_alg_hash(alg, lec1.scratch,
							   lec1.scratch_len))
					alg->failed = 1;
				if (aws_lws_cose_sign_alg_hash(alg, lec.start,
							   lec.used))
					alg->failed = 1;

			} aws_lws_end_foreach_dll_safe(p, tp);

			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0, 0);
			aws_lws_cose_sign_hashing(csc, lec1.scratch,
						   lec1.scratch_len);

			break;
		default:
			ret = aws_lws_lec_printf(csc->info.lec, "{}");
			if (ret != LWS_LECPCTX_RET_FINISHED)
				return ret;
			break;
		}

		csc->tli = ST_OUTER_PAYLOAD;
		csc->subsequent = 0;

		/* Prepare the payload BSTR */

		aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_BSTR, 0,
					   csc->info.inline_payload_len);

		aws_lws_lec_init(&lec1, lb, sizeof(lb));
		aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0,
			    csc->info.inline_payload_len);
		aws_lws_cose_sign_hashing(csc, lec1.scratch,
					   lec1.scratch_len);

		aws_lws_lec_scratch(csc->info.lec);

		csc->rem_pay = csc->info.inline_payload_len;

		/* fallthru */

	case ST_OUTER_PAYLOAD:

		if (csc->along) {
			in += csc->along;
			in_len -= csc->along;
		}

		aws_lws_lec_scratch(csc->info.lec);

		if (csc->rem_pay) {

			aws_lws_cose_sign_hashing(csc, in, in_len);

			/*
			 * in / in_len is the payload chunk
			 */

			s = aws_lws_ptr_diff_size_t(csc->info.lec->end,
						csc->info.lec->buf);
			if (s > (size_t)csc->rem_pay)
				s = (size_t)csc->rem_pay;
			if (s > in_len)
				s = in_len;

			memcpy(csc->info.lec->buf, in, s);
			csc->info.lec->buf += s;
			csc->info.lec->used = aws_lws_ptr_diff_size_t(
					csc->info.lec->buf,
					csc->info.lec->start);
			csc->rem_pay -= s;

			csc->along = s;

			return LWS_LECPCTX_RET_AGAIN;
		}

		/* finished with rem_pay */

		if (csc->type == SIGTYPE_MULTI) {

			csc->alg = aws_lws_container_of(csc->algs.head,
						aws_lws_cose_sig_alg_t, list);
			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_ARRAY, 0,
				    csc->algs.count);
			aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_ARRAY, 0,
					csc->algs.count);
			csc->tli = ST_INNER_PROTECTED;
			goto inner_protected;
		}
		csc->tli = ST_OUTER_SIGN1_SIGNATURE;
		csc->along = 0;

		/* fallthru */

	case ST_OUTER_SIGN1_SIGNATURE:

		alg = aws_lws_container_of(aws_lws_dll2_get_head(&csc->algs),
				       aws_lws_cose_sig_alg_t, list);

		if (!alg->completed)
			aws_lws_cose_sign_alg_complete(alg);
		if (alg->failed)
			return LWS_LECPCTX_RET_FAIL;

		ret = aws_lws_lec_printf(csc->info.lec, "%.*b",
				     (int)alg->rhash_len, alg->rhash);
		if (ret != LWS_LECPCTX_RET_FINISHED)
				return ret;

		if (csc->type == SIGTYPE_MAC) {
			csc->alg = aws_lws_container_of(csc->algs.head,
						aws_lws_cose_sig_alg_t, list);
			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_ARRAY, 0,
				    csc->algs.count);
			aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_ARRAY, 0,
					csc->algs.count);
			csc->tli = ST_INNER_PROTECTED;
			goto inner_protected;
		}

		break;

	case ST_INNER_PROTECTED:
inner_protected:

		/*
		 * We need to list and emit any outer protected data as a map
		 * into its own buffer, then emit that into the output as a bstr
		 */

		switch (csc->type) {
		case SIGTYPE_MAC:
		case SIGTYPE_MULTI:
			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_ARRAY, 0, 3);

			aws_lws_lec_int(csc->info.lec, LWS_CBOR_MAJTYP_ARRAY, 0, 3);

			aws_lws_lec_init(&lec, lbuf, sizeof(lbuf));

			/* we know it will fit */
			aws_lws_lec_printf(&lec, "{1:%lld}",
					     (long long)csc->alg->cose_alg);

			aws_lws_lec_init(&lec1, lb, sizeof(lb));
			aws_lws_lec_int(&lec1, LWS_CBOR_MAJTYP_BSTR, 0,
					lec.used);
			aws_lws_lec_printf(csc->info.lec, "{1:%lld}",
					     (long long)csc->alg->cose_alg);
			break;
		default:
			lec.used = 0;
			break;
		}


		csc->tli = ST_INNER_UNPROTECTED;

		/* fallthru */

	case ST_INNER_UNPROTECTED:

		switch (csc->type) {
		case SIGTYPE_MULTI:
			alg = aws_lws_container_of(csc->algs.head,
					       aws_lws_cose_sig_alg_t, list);
			ke = &alg->cose_key->meta[COSEKEY_META_KID];
			if (ke->len) {
				ret = aws_lws_lec_printf(csc->info.lec, "{%d:%.*b}",
						     LWSCOSE_WKL_KID,
						     (int)ke->len, ke->buf);

				if (ret != LWS_LECPCTX_RET_FINISHED)
					return ret;
			}
			break;
		default:
			ret = aws_lws_lec_printf(csc->info.lec, "{}");
			if (ret != LWS_LECPCTX_RET_FINISHED)
				return ret;
			break;
		}

		aws_lws_cose_sign_alg_complete(csc->alg);
		if (csc->alg->failed)
			return LWS_LECPCTX_RET_FAIL;
		csc->tli = ST_INNER_SIGNATURE;

		/* fallthru */

	case ST_INNER_SIGNATURE:

		ret = aws_lws_lec_printf(csc->info.lec, "%.*b",
				     (int)csc->alg->rhash_len, csc->alg->rhash);
		if (ret != LWS_LECPCTX_RET_FINISHED)
			return ret;

		if (csc->alg->list.next) {
			csc->alg = (aws_lws_cose_sig_alg_t *)csc->alg->list.next;
			csc->tli = ST_INNER_PROTECTED;
		}
		break;

	}

	return 0;
}

void
aws_lws_cose_sign_destroy(struct aws_lws_cose_sign_context **_csc)
{
	struct aws_lws_cose_sign_context *csc = *_csc;

	if (!csc)
		return;

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, tp,
				   aws_lws_dll2_get_head(&csc->algs)) {
		aws_lws_cose_sig_alg_t *alg = aws_lws_container_of(p,
						aws_lws_cose_sig_alg_t, list);

		aws_lws_dll2_remove(p);
		aws_lws_cose_sign_alg_destroy(&alg);
	} aws_lws_end_foreach_dll_safe(p, tp);

	aws_lws_free_set_NULL(*_csc);
}
