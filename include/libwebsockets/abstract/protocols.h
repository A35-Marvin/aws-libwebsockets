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
 */

/*
 * Information about how this protocol handles multiple use of connections.
 *
 * .flags of 0 indicates each connection must start with a fresh transport.
 *
 * Flags can be used to indicate the protocol itself supports different
 * kinds of multiple use.  However the actual use or not of these may depend on
 * negotiation with the remote peer.
 *
 * LWS_AP_FLAG_PIPELINE_TRANSACTIONS:	other instances can be queued on one
 *					with an existing connection and get a
 *					chance to "hot take over" the existing
 *					transport in turn, like h1 keepalive
 *					pipelining
 *
 * LWS_AP_FLAG_MUXABLE_STREAM:	an existing connection can absorb more child
 *				connections and mux them as separate child
 *				streams ongoing, like h2
 */

enum {
	LWS_AP_FLAG_PIPELINE_TRANSACTIONS			= (1 << 0),
	LWS_AP_FLAG_MUXABLE_STREAM				= (1 << 1),
};

typedef struct aws_lws_abs_protocol {
	const char	*name;
	int		alloc;
	int		flags;

	int		(*create)(const struct aws_lws_abs *ai);
	void		(*destroy)(aws_lws_abs_protocol_inst_t **d);
	int		(*compare)(aws_lws_abs_t *abs1, aws_lws_abs_t *abs2);

	/* events the transport invokes (handled by abstract protocol) */

	int		(*accept)(aws_lws_abs_protocol_inst_t *d);
	int		(*rx)(aws_lws_abs_protocol_inst_t *d, const uint8_t *b, size_t l);
	int		(*writeable)(aws_lws_abs_protocol_inst_t *d, size_t budget);
	int		(*closed)(aws_lws_abs_protocol_inst_t *d);
	int		(*heartbeat)(aws_lws_abs_protocol_inst_t *d);

	/* as parent, we get a notification a new child / queue entry
	 * bound to us... this is the parent aws_lws_abs_t as arg */
	int		(*child_bind)(aws_lws_abs_t *abs);
} aws_lws_abs_protocol_t;

/**
 * aws_lws_abs_protocol_get_by_name() - returns a pointer to the named protocol ops
 *
 * \param name: the name of the abstract protocol
 *
 * Returns a pointer to the named protocol ops struct if available, otherwise
 * NULL.
 */
LWS_VISIBLE LWS_EXTERN const aws_lws_abs_protocol_t *
aws_lws_abs_protocol_get_by_name(const char *name);

/*
 * bring in public api pieces from protocols
 */

#include <libwebsockets/abstract/protocols/smtp.h>

