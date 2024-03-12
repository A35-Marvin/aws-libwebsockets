 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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
 *
 *  This is included from private-lib-core.h if LWS_WITH_TLS
 */

struct aws_lws_context_per_thread;
struct aws_lws_tls_ops {
	int (*fake_POLLIN_for_buffered)(struct aws_lws_context_per_thread *pt);
};

struct aws_lws_context_tls {
	char alpn_discovered[32];
	const char *alpn_default;
	time_t last_cert_check_s;
	struct aws_lws_dll2_owner cc_owner;
	int count_client_contexts;
};

struct aws_lws_pt_tls {
	struct aws_lws_dll2_owner dll_pending_tls_owner;
};

struct aws_lws_tls_ss_pieces;

struct alpn_ctx {
	uint8_t data[23];
	uint8_t len;
};

struct aws_lws_vhost_tls {
	aws_lws_tls_ctx *ssl_ctx;
	aws_lws_tls_ctx *ssl_client_ctx;
	struct aws_lws_tls_client_reuse *tcr;
	const char *alpn;
	struct aws_lws_tls_ss_pieces *ss; /* for acme tls certs */
	char *alloc_cert_path;
	char *key_path;
#if defined(LWS_WITH_MBEDTLS)
	aws_lws_tls_x509 *x509_client_CA;
#endif
	char ecdh_curve[16];
	struct alpn_ctx alpn_ctx;

	int use_ssl;
	int allow_non_ssl_on_ssl_port;
	int ssl_info_event_mask;

#if defined(LWS_WITH_MBEDTLS)
	uint32_t tls_session_cache_ttl;
#endif

	unsigned int user_supplied_ssl_ctx:1;
	unsigned int skipped_certs:1;
};

struct aws_lws_lws_tls {
	aws_lws_tls_conn		*ssl;
	aws_lws_tls_bio		*client_bio;
#if defined(LWS_TLS_SYNTHESIZE_CB)
	aws_lws_sorted_usec_list_t	sul_cb_synth;
#endif
#if !defined(LWS_WITH_MBEDTLS) && defined(LWS_WITH_TLS_JIT_TRUST)
	/* mbedtls has this in the wrapper, since no wsi ptr at validation */
	aws_lws_tls_kid_chain_t	kid_chain;
#endif
	struct aws_lws_dll2		dll_pending_tls;
	char			err_helper[32];
	unsigned int		use_ssl;
	unsigned int		redirect_to_https:1;
};


void
aws_lws_context_init_alpn(struct aws_lws_vhost *vhost);
int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_capable_read(struct aws_lws *wsi, unsigned char *buf, size_t len);
int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_capable_write(struct aws_lws *wsi, unsigned char *buf, size_t len);
int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_pending(struct aws_lws *wsi);
int LWS_WARN_UNUSED_RESULT
aws_lws_server_socket_service_ssl(struct aws_lws *new_wsi, aws_lws_sockfd_type accept_fd,
				char is_pollin);

void
aws_lws_sess_cache_synth_cb(aws_lws_sorted_usec_list_t *sul);

int
aws_lws_ssl_close(struct aws_lws *wsi);
void
aws_lws_ssl_SSL_CTX_destroy(struct aws_lws_vhost *vhost);
void
aws_lws_ssl_context_destroy(struct aws_lws_context *context);
void
aws___lws_ssl_remove_wsi_from_buffered_list(struct aws_lws *wsi);
LWS_VISIBLE void
aws_lws_ssl_remove_wsi_from_buffered_list(struct aws_lws *wsi);
int
aws_lws_ssl_client_bio_create(struct aws_lws *wsi);

int
aws_lws_ssl_client_connect2(struct aws_lws *wsi, char *errbuf, size_t len);
int
aws_lws_tls_fake_POLLIN_for_buffered(struct aws_lws_context_per_thread *pt);
int
aws_lws_gate_accepts(struct aws_lws_context *context, int on);
void
aws_lws_ssl_bind_passphrase(aws_lws_tls_ctx *ssl_ctx, int is_client,
			const struct aws_lws_context_creation_info *info);
void
aws_lws_ssl_info_callback(const aws_lws_tls_conn *ssl, int where, int ret);
int
aws_lws_tls_server_certs_load(struct aws_lws_vhost *vhost, struct aws_lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len);
enum aws_lws_tls_extant
aws_lws_tls_generic_cert_checks(struct aws_lws_vhost *vhost, const char *cert,
			    const char *private_key);
#if defined(LWS_WITH_SERVER)
 int
 aws_lws_context_init_server_ssl(const struct aws_lws_context_creation_info *info,
			     struct aws_lws_vhost *vhost);
 void
 aws_lws_tls_acme_sni_cert_destroy(struct aws_lws_vhost *vhost);
#else
 #define aws_lws_context_init_server_ssl(_a, _b) (0)
 #define aws_lws_tls_acme_sni_cert_destroy(_a)
#endif

void
aws_lws_ssl_destroy(struct aws_lws_vhost *vhost);

/*
* aws_lws_tls_ abstract backend implementations
*/

int
aws_lws_tls_server_client_cert_verify_config(struct aws_lws_vhost *vh);
int
aws_lws_tls_server_vhost_backend_init(const struct aws_lws_context_creation_info *info,
			  struct aws_lws_vhost *vhost, struct aws_lws *wsi);
int
aws_lws_tls_server_new_nonblocking(struct aws_lws *wsi, aws_lws_sockfd_type accept_fd);

enum aws_lws_ssl_capable_status
aws_lws_tls_server_accept(struct aws_lws *wsi);

enum aws_lws_ssl_capable_status
aws_lws_tls_server_abort_connection(struct aws_lws *wsi);

enum aws_lws_ssl_capable_status
aws___lws_tls_shutdown(struct aws_lws *wsi);

enum aws_lws_ssl_capable_status
aws_lws_tls_client_connect(struct aws_lws *wsi, char *errbuf, size_t len);
int
aws_lws_tls_client_confirm_peer_cert(struct aws_lws *wsi, char *ebuf, size_t ebuf_len);
int
aws_lws_tls_client_create_vhost_context(struct aws_lws_vhost *vh,
			    const struct aws_lws_context_creation_info *info,
			    const char *cipher_list,
			    const char *ca_filepath,
			    const void *ca_mem,
			    unsigned int ca_mem_len,
			    const char *cert_filepath,
			    const void *cert_mem,
			    unsigned int cert_mem_len,
			    const char *private_key_filepath,
			    const void *key_mem,
			    unsigned int key_mem_len);


aws_lws_tls_ctx *
aws_lws_tls_ctx_from_wsi(struct aws_lws *wsi);
int
aws_lws_ssl_get_error(struct aws_lws *wsi, int n);

int
aws_lws_context_init_client_ssl(const struct aws_lws_context_creation_info *info,
		    struct aws_lws_vhost *vhost);

void
aws_lws_ssl_info_callback(const aws_lws_tls_conn *ssl, int where, int ret);

int
aws_lws_tls_fake_POLLIN_for_buffered(struct aws_lws_context_per_thread *pt);
