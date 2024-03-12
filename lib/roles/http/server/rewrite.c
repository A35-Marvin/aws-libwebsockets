#include "private-lib-core.h"

#if defined(LWS_WITH_HUBBUB)

struct aws_lws_rewrite *
aws_lws_rewrite_create(struct aws_lws *wsi, hubbub_callback_t cb, const char *from,
		   const char *to)
{
	struct aws_lws_rewrite *r = aws_lws_malloc(sizeof(*r), "rewrite");

	if (!r) {
		aws_lwsl_err("OOM\n");
		return NULL;
	}

	if (hubbub_parser_create("UTF-8", false, &r->parser) != HUBBUB_OK) {
		aws_lws_free(r);

		return NULL;
	}
	r->from = from;
	r->from_len = strlen(from);
	r->to = to;
	r->to_len = strlen(to);
	r->params.token_handler.handler = cb;
	r->wsi = wsi;
	r->params.token_handler.pw = (void *)r;
	if (hubbub_parser_setopt(r->parser, HUBBUB_PARSER_TOKEN_HANDLER,
				 &r->params) != HUBBUB_OK) {
		aws_lws_free(r);

		return NULL;
	}

	return r;
}

int
aws_lws_rewrite_parse(struct aws_lws_rewrite *r,
		  const unsigned char *in, int in_len)
{
	if (r && hubbub_parser_parse_chunk(r->parser, in, in_len) != HUBBUB_OK)
		return -1;

	return 0;
}

void
aws_lws_rewrite_destroy(struct aws_lws_rewrite *r)
{
	hubbub_parser_destroy(r->parser);
	aws_lws_free(r);
}

#endif
