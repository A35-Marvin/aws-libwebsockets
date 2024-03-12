/*
 * lws-crypto-jws
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <sys/types.h>
#include <fcntl.h>

#define MAX_SIZE (4 * 1024 * 1024)
char temp[MAX_SIZE], compact[MAX_SIZE];

int main(int argc, const char **argv)
{
	int n, sign = 0, result = 0,
	    logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	char *in;
	struct aws_lws_context_creation_info info;
	struct aws_lws_jws_map map;
	int temp_len = sizeof(temp);
	struct aws_lws_context *context;
	struct aws_lws_jose jose;
	struct aws_lws_jwk jwk;
	struct aws_lws_jws jws;
	const char *p;

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS JWS example tool\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	aws_lws_jose_init(&jose);
	aws_lws_jws_init(&jws, &jwk, context);

	/* if signing, set the ciphers */

	if ((p = aws_lws_cmdline_option(argc, argv, "-s"))) {

		if (aws_lws_gencrypto_jws_alg_to_definition(p, &jose.alg)) {
			aws_lwsl_err("format: -s \"<jws cipher alg>\", eg, "
				 "-e \"RS256\"\n");

			return 1;
		}

		/* create JOSE header, also needed for output */

		if (aws_lws_jws_alloc_element(&jws.map, LJWS_JOSE,
				      aws_lws_concat_temp(temp, temp_len),
				      &temp_len, strlen(p) + 10, 0)) {
			aws_lwsl_err("%s: temp space too small\n", __func__);
			return 1;
		}

		jws.map.len[LJWS_JOSE] = (uint32_t)
				aws_lws_snprintf((char *)jws.map.buf[LJWS_JOSE],
					     (unsigned int)temp_len, "{\"alg\":\"%s\"}", p);
		sign = 1;
	}

	in = aws_lws_concat_temp(temp, temp_len);
	n = (int)read(0, in, (unsigned int)temp_len);
	if (n < 0) {
		aws_lwsl_err("Problem reading from stdin\n");
		return 1;
	}
	temp_len -= n;

	/* grab the key */

	if ((p = aws_lws_cmdline_option(argc, argv, "-k"))) {
		if (aws_lws_jwk_load(&jwk, p, NULL, NULL)) {
			aws_lwsl_err("%s: problem loading JWK %s\n", __func__, p);

			return 1;
		}
	} else {
		aws_lwsl_err("-k <jwk file> is required\n");

		return 1;
	}
	if (sign) {

		/* add the plaintext from stdin to the map and a b64 version */

		jws.map.buf[LJWS_PYLD] = in;
		jws.map.len[LJWS_PYLD] = (unsigned int)n;

		if (aws_lws_jws_encode_b64_element(&jws.map_b64, LJWS_PYLD,
					       aws_lws_concat_temp(temp, temp_len),
					       &temp_len, jws.map.buf[LJWS_PYLD],
					       jws.map.len[LJWS_PYLD]))
			goto bail1;

		/* add the b64 JOSE header to the b64 map */

		if (aws_lws_jws_encode_b64_element(&jws.map_b64, LJWS_JOSE,
					       aws_lws_concat_temp(temp, temp_len),
					       &temp_len, jws.map.buf[LJWS_JOSE],
					       jws.map.len[LJWS_JOSE]))
			goto bail1;

		/* prepare the space for the b64 signature in the map */

		if (aws_lws_jws_alloc_element(&jws.map_b64, LJWS_SIG,
				      aws_lws_concat_temp(temp, temp_len),
				      &temp_len, (unsigned int)aws_lws_base64_size(
					 LWS_JWE_LIMIT_KEY_ELEMENT_BYTES), 0)) {
			aws_lwsl_err("%s: temp space too small\n", __func__);
			goto bail1;
		}

	

		/* sign the plaintext */

		n = aws_lws_jws_sign_from_b64(&jose, &jws,
					  (char *)jws.map_b64.buf[LJWS_SIG],
					  jws.map_b64.len[LJWS_SIG]);
		if (n < 0) {
			aws_lwsl_err("%s: failed signing test packet\n", __func__);
			goto bail1;
		}
		/* set the actual b64 signature size */
		jws.map_b64.len[LJWS_SIG] = (uint32_t)n;

		if (aws_lws_cmdline_option(argc, argv, "-f"))
			/* create the flattened representation */
			n = aws_lws_jws_write_flattened_json(&jws, compact, sizeof(compact));
		else
			/* create the compact JWS representation */
			n = aws_lws_jws_write_compact(&jws, compact, sizeof(compact));
		if (n < 0) {
			aws_lwsl_notice("%s: write_compact failed\n", __func__);
			goto bail1;
		}

		/* dump the compact JWS representation on stdout */

		if (write(1, compact,
#if defined(WIN32)
				(unsigned int)
#endif
				strlen(compact))  < 0) {
			aws_lwsl_err("Write stdout failed\n");
			goto bail1;
		}

	} else {
		/* perform the verify directly on the compact representation */

		if (aws_lws_cmdline_option(argc, argv, "-f")) {
			if (aws_lws_jws_sig_confirm_json(in, (unsigned int)n, &jws, &jwk, context,
					aws_lws_concat_temp(temp, temp_len),
					&temp_len) < 0) {
				aws_lwsl_notice("%s: confirm rsa sig failed\n",
					    __func__);
				aws_lwsl_hexdump_notice(jws.map.buf[LJWS_JOSE], jws.map.len[LJWS_JOSE]);
				aws_lwsl_hexdump_notice(jws.map.buf[LJWS_PYLD], jws.map.len[LJWS_PYLD]);
				aws_lwsl_hexdump_notice(jws.map.buf[LJWS_SIG], jws.map.len[LJWS_SIG]);

				aws_lwsl_hexdump_notice(jws.map_b64.buf[LJWS_JOSE], jws.map_b64.len[LJWS_JOSE]);
				aws_lwsl_hexdump_notice(jws.map_b64.buf[LJWS_PYLD], jws.map_b64.len[LJWS_PYLD]);
				aws_lwsl_hexdump_notice(jws.map_b64.buf[LJWS_SIG], jws.map_b64.len[LJWS_SIG]);
				goto bail1;
			}
		} else {
			if (aws_lws_jws_sig_confirm_compact_b64(in,
					aws_lws_concat_used(temp, (unsigned int)temp_len),
					&map, &jwk, context,
					aws_lws_concat_temp(temp, temp_len),
					&temp_len) < 0) {
				aws_lwsl_notice("%s: confirm rsa sig failed\n",
					    __func__);
				goto bail1;
			}
		}

		aws_lwsl_notice("VALID\n");

		/* dump the verifed plaintext and return 0 */

		if (write(1, jws.map.buf[LJWS_PYLD], jws.map.len[LJWS_PYLD]) < 0) {
			aws_lwsl_err("Write stdout failed\n");
			goto bail1;
		}
	}

	result = 0;

bail1:
	aws_lws_jws_destroy(&jws);
	aws_lws_jwk_destroy(&jwk);

	aws_lws_context_destroy(context);

	return result;
}
