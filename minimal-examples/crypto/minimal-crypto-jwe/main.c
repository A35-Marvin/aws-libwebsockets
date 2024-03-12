/*
 * lws-crypto-jwe
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <sys/types.h>
#include <fcntl.h>

/*
 * handles escapes and line wrapping suitable for use
 * defining a C char array ( -c option )
 */

static void
format_c(const char *key)
{
	const char *k = key;
	int seq = 0;

	while (*k) {
		if (*k == '{') {
			putchar('\"');
			putchar('{');
			putchar('\"');
			putchar('\n');
			putchar('\t');
			putchar('\"');
			k++;
			seq = 0;
			continue;
		}
		if (*k == '}') {
			putchar('\"');
			putchar('\n');
			putchar('\"');
			putchar('}');
			putchar('\"');
			putchar('\n');
			k++;
			seq = 0;
			continue;
		}
		if (*k == '\"') {
			putchar('\\');
			putchar('\"');
			seq += 2;
			k++;
			continue;
		}
		if (*k == ',') {
			putchar(',');
			putchar('\"');
			putchar('\n');
			putchar('\t');
			putchar('\"');
			k++;
			seq = 0;
			continue;
		}
		putchar(*k);
		seq++;
		if (seq >= 60) {
			putchar('\"');
			putchar('\n');
			putchar('\t');
			putchar(' ');
			putchar('\"');
			seq = 1;
		}
		k++;
	}
}

#define MAX_SIZE (4 * 1024 * 1024)
	char temp[MAX_SIZE], compact[MAX_SIZE];

int main(int argc, const char **argv)
{
	int n, enc = 0, result = 0,
	    logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	char *in;
	struct aws_lws_context_creation_info info;
	int temp_len = sizeof(temp);
	struct aws_lws_context *context;
	struct aws_lws_jwe jwe;
	const char *p;

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS JWE example tool\n");

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

	aws_lws_jwe_init(&jwe, context);

	/* if encrypting, set the ciphers */

	if ((p = aws_lws_cmdline_option(argc, argv, "-e"))) {
		char *sp = strchr(p, ' ');

		if (!sp) {
			aws_lwsl_err("format: -e \"<cek cipher alg> "
				 "<payload enc alg>\", eg, "
				 "-e \"RSA1_5 A128CBC-HS256\"\n");

			return 1;
		}
		*sp = '\0';
		if (aws_lws_gencrypto_jwe_alg_to_definition(p, &jwe.jose.alg)) {
			aws_lwsl_err("Unknown cipher alg %s\n", p);
			return 1;
		}
		if (aws_lws_gencrypto_jwe_enc_to_definition(sp + 1, &jwe.jose.enc_alg)) {
			aws_lwsl_err("Unknown payload enc alg %s\n", sp + 1);
			return 1;
		}

		/* create JOSE header, also needed for output */

		if (aws_lws_jws_alloc_element(&jwe.jws.map, LJWS_JOSE,
					  aws_lws_concat_temp(temp, temp_len),
					  &temp_len, strlen(p) +
					  strlen(sp + 1) + 32, 0)) {
			aws_lwsl_err("%s: temp space too small\n", __func__);
			return 1;
		}

		jwe.jws.map.len[LJWS_JOSE] = (uint32_t)aws_lws_snprintf(
				(char *)jwe.jws.map.buf[LJWS_JOSE], (unsigned int)temp_len,
				"{\"alg\":\"%s\",\"enc\":\"%s\"}", p, sp + 1);

		enc = 1;
	}

	in = aws_lws_concat_temp(temp, temp_len);
	n = (int)read(0, in, (unsigned int)temp_len);
	if (n < 0) {
		aws_lwsl_err("Problem reading from stdin\n");
		return 1;
	}

	/* account for padding as well */

	temp_len -= (int)aws_lws_gencrypto_padded_length(LWS_AES_CBC_BLOCKLEN, (unsigned int)n);

	/* grab the key */

	if ((p = aws_lws_cmdline_option(argc, argv, "-k"))) {
		if (aws_lws_jwk_load(&jwe.jwk, p, NULL, NULL)) {
			aws_lwsl_err("%s: problem loading JWK %s\n", __func__, p);

			return 1;
		}
	} else {
		aws_lwsl_err("-k <jwk file> is required\n");

		return 1;
	}

	if (enc) {

		/* point CTXT to the plaintext we read from stdin */

		jwe.jws.map.buf[LJWE_CTXT] = in;
		jwe.jws.map.len[LJWE_CTXT] = (uint32_t)n;

		/*
		 * Create a random CEK and set EKEY to it
		 * CEK size is determined by hash / hmac size
		 */

		n = aws_lws_gencrypto_bits_to_bytes(jwe.jose.enc_alg->keybits_fixed);
		if (aws_lws_jws_randomize_element(context, &jwe.jws.map, LJWE_EKEY,
					      aws_lws_concat_temp(temp, temp_len),
					      &temp_len, (unsigned int)n,
					      LWS_JWE_LIMIT_KEY_ELEMENT_BYTES)) {
			aws_lwsl_err("Problem getting random\n");
			goto bail1;
		}

		/* perform the encryption of the CEK and the plaintext */

		n = aws_lws_jwe_encrypt(&jwe, aws_lws_concat_temp(temp, temp_len),
				    &temp_len);
		if (n < 0) {
			aws_lwsl_err("%s: aws_lws_jwe_encrypt failed\n", __func__);
			goto bail1;
		}
		if (aws_lws_cmdline_option(argc, argv, "-f"))
			/* output the JWE in flattened form */
			n = aws_lws_jwe_render_flattened(&jwe, compact,
						     sizeof(compact));
		else
			/* output the JWE in compact form */
			n = aws_lws_jwe_render_compact(&jwe, compact,
						   sizeof(compact));

		if (n < 0) {
			aws_lwsl_err("%s: aws_lws_jwe_render failed: %d\n",
				 __func__, n);
			goto bail1;
		}

		if (aws_lws_cmdline_option(argc, argv, "-c"))
			format_c(compact);
		else
			if (write(1, compact,
#if defined(WIN32)
					(unsigned int)
#endif
					strlen(compact)) < 0) {
				aws_lwsl_err("Write stdout failed\n");
				goto bail1;
			}
	} else {
		if (aws_lws_cmdline_option(argc, argv, "-f")) {
			if (aws_lws_jwe_json_parse(&jwe, (uint8_t *)in, n,
					       aws_lws_concat_temp(temp, temp_len),
					       &temp_len)) {
				aws_lwsl_err("%s: aws_lws_jwe_json_parse failed\n",
								 __func__);
				goto bail1;
			}
		} else
			/*
			 * converts a compact serialization to b64 + decoded maps
			 * held in jws
			 */
			if (aws_lws_jws_compact_decode(in, n, &jwe.jws.map,
						   &jwe.jws.map_b64,
						   aws_lws_concat_temp(temp, temp_len),
						   &temp_len) != 5) {
				aws_lwsl_err("%s: aws_lws_jws_compact_decode failed\n",
					 __func__);
				goto bail1;
			}

		/*
		 * Do the crypto according to what we parsed into the jose
		 * (information on the ciphers) and the jws (plaintext and
		 * signature info)
		 */

		n = aws_lws_jwe_auth_and_decrypt(&jwe,
					     aws_lws_concat_temp(temp, temp_len),
					     &temp_len);
		if (n < 0) {
			aws_lwsl_err("%s: aws_lws_jwe_auth_and_decrypt failed\n",
				 __func__);
			goto bail1;
		}

		/* if it's valid, dump the plaintext and return 0 */

		if (write(1, jwe.jws.map.buf[LJWE_CTXT],
			     jwe.jws.map.len[LJWE_CTXT]) < 0) {
			aws_lwsl_err("Write stdout failed\n");
			goto bail1;
		}
	}

	result = 0;

bail1:

	aws_lws_jwe_destroy(&jwe);

	aws_lws_context_destroy(context);

	return result;
}
