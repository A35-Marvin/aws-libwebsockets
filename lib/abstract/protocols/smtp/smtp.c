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

#include "private-lib-core.h"
#include "private-lib-abstract.h"

/** enum aws_lwsgs_smtp_states - where we are in SMTP protocol sequence */
typedef enum aws_lwsgs_smtp_states {
	LGSSMTP_IDLE,		/**< awaiting new email */
	LGSSMTP_CONNECTING,	/**< opening tcp connection to MTA */
	LGSSMTP_CONNECTED,	/**< tcp connection to MTA is connected */
		/* (server sends greeting) */
	LGSSMTP_SENT_HELO,	/**< sent the HELO */

	LGSSMTP_SENT_FROM,	/**< sent FROM */
	LGSSMTP_SENT_TO,	/**< sent TO */
	LGSSMTP_SENT_DATA,	/**< sent DATA request */
	LGSSMTP_SENT_BODY,	/**< sent the email body */

		/*
		 * (server sends, eg, "250 Ok: queued as 12345")
		 * at this point we can return to LGSSMTP_SENT_HELO and send a
		 * new email, or continue below to QUIT, or just wait
		 */

	LGSSMTP_SENT_QUIT,	/**< sent the session quit */

	/* (server sends, eg, "221 Bye" and closes the connection) */
} aws_lwsgs_smtp_states_t;

/** abstract protocol instance data */

typedef struct aws_lws_smtp_client_protocol {
	const struct aws_lws_abs	*abs;
	aws_lwsgs_smtp_states_t	estate;

	aws_lws_smtp_email_t	*e;	/* the email we are trying to send */
	const char		*helo;

	unsigned char		send_pending:1;
} aws_lws_smtpcp_t;

static const short retcodes[] = {
	0,	/* idle */
	0,	/* connecting */
	220,	/* connected */
	250,	/* helo */
	250,	/* from */
	250,	/* to */
	354,	/* data */
	250,	/* body */
	221,	/* quit */
};

static void
aws_lws_smtpc_state_transition(aws_lws_smtpcp_t *c, aws_lwsgs_smtp_states_t s)
{
	aws_lwsl_debug("%s: cli %p: state %d -> %d\n", __func__, c, c->estate, s);
	c->estate = s;
}

static aws_lws_smtp_email_t *
aws_lws_smtpc_get_email(aws_lws_smtpcp_t *c)
{
	const aws_lws_token_map_t *tm;

	/* ... the email we want to send */
	tm = aws_lws_abs_get_token(c->abs->ap_tokens, LTMI_PSMTP_V_LWS_SMTP_EMAIL_T);
	if (!tm) {
		assert(0);

		return NULL;
	}

	return (aws_lws_smtp_email_t *)tm->u.value;
}

/*
 * Called when something happened so that we know now the final disposition of
 * the email send attempt, for good or ill.
 *
 * Inform the owner via the done callback and set up the next queued one if any.
 *
 * Returns nonzero if we queued a new one
 */

static int
aws_lws_smtpc_email_disposition(aws_lws_smtpcp_t *c, int disp, const void *buf,
			    size_t len)
{
	aws_lws_smtpcp_t *ch;
	aws_lws_abs_t *ach;
	aws_lws_dll2_t *d;

	aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_HELO);

	/* lifetime of the email object is handled by done callback */
	c->e->done(c->e, c->e->data, disp, buf, len);
	c->e = NULL;

	/* this may not be the time to try to send anything else... */

	if (disp == LWS_SMTP_DISPOSITION_FAILED_DESTROY)
		return 0;

	/* ... otherwise... do we have another queued? */

	d = aws_lws_dll2_get_tail(&c->abs->children_owner);
	if (!d)
		return 0;

	ach = aws_lws_container_of(d, aws_lws_abs_t, bound);
	ch = (aws_lws_smtpcp_t *)ach->api;

	c->e = aws_lws_smtpc_get_email(ch);

	/* since we took it on, remove it from the queue */
	aws_lws_dll2_remove(d);

	return 1;
}

/*
 * we became connected
 */

static int
aws_lws_smtpc_abs_accept(aws_lws_abs_protocol_inst_t *api)
{
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)api;

	/* we have become connected in the tcp sense */

	aws_lws_smtpc_state_transition(c, LGSSMTP_CONNECTED);

	/*
	 * From the accept(), the next thing that should happen is the SMTP
	 * server sends its greeting like "220 smtp2.example.com ESMTP Postfix",
	 * we'll hear about it in the rx callback, or time out
	 */

	c->abs->at->set_timeout(c->abs->ati,
				PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE, 3);

	return 0;
}

static int
aws_lws_smtpc_abs_rx(aws_lws_abs_protocol_inst_t *api, const uint8_t *buf, size_t len)
{
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)api;
	char dotstar[96], at[5];
	int n;

	c->abs->at->set_timeout(c->abs->ati, NO_PENDING_TIMEOUT, 0);

	aws_lws_strncpy(at, (const char *)buf, sizeof(at));
	n = atoi(at);

	switch (c->estate) {
	case LGSSMTP_CONNECTED:
		if (n != 220) {
			/*
			 * The server did not properly greet us... we can't
			 * even get started, so fail the transport connection
			 * (and anything queued on it)
			 */

			aws_lws_strnncpy(dotstar, (const char *)buf, len, sizeof(dotstar));
			aws_lwsl_err("%s: server: %s\n", __func__, dotstar);

			return 1;
		}
		break;

	case LGSSMTP_SENT_BODY:
		/*
		 * We finished one way or another... let's prepare to send a
		 * new one... or wait until server hangs up on us
		 */
		if (!aws_lws_smtpc_email_disposition(c,
					n == 250 ? LWS_SMTP_DISPOSITION_SENT :
						   LWS_SMTP_DISPOSITION_FAILED,
					"destroyed", 0))
			return 0; /* become idle */

		break; /* ask to send */

	case LGSSMTP_SENT_QUIT:
		aws_lwsl_debug("%s: done\n", __func__);
		aws_lws_smtpc_state_transition(c, LGSSMTP_IDLE);

		return 1;

	default:
		if (n != retcodes[c->estate]) {
			aws_lws_strnncpy(dotstar, buf, len, sizeof(dotstar));
			aws_lwsl_notice("%s: bad response: %d (state %d) %s\n",
				    __func__, n, c->estate, dotstar);

			aws_lws_smtpc_email_disposition(c,
					LWS_SMTP_DISPOSITION_FAILED, buf, len);

			return 0;
		}
		break;
	}

	c->send_pending = 1;
	c->abs->at->ask_for_writeable(c->abs->ati);

	return 0;
}

static int
aws_lws_smtpc_abs_writeable(aws_lws_abs_protocol_inst_t *api, size_t budget)
{
	char b[256 + LWS_PRE], *p = b + LWS_PRE;
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)api;
	int n;

	if (!c->send_pending || !c->e)
		return 0;

	c->send_pending = 0;

	aws_lwsl_debug("%s: writing response for state %d\n", __func__, c->estate);

	switch (c->estate) {
	case LGSSMTP_CONNECTED:
		n = aws_lws_snprintf(p, sizeof(b) - LWS_PRE, "HELO %s\n", c->helo);
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_HELO);
		break;

	case LGSSMTP_SENT_HELO:
		n = aws_lws_snprintf(p, sizeof(b) - LWS_PRE, "MAIL FROM: <%s>\n",
				 c->e->from);
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_FROM);
		break;

	case LGSSMTP_SENT_FROM:
		n = aws_lws_snprintf(p, sizeof(b) - LWS_PRE,
				 "RCPT TO: <%s>\n", c->e->to);
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_TO);
		break;

	case LGSSMTP_SENT_TO:
		n = aws_lws_snprintf(p, sizeof(b) - LWS_PRE, "DATA\n");
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_DATA);
		break;

	case LGSSMTP_SENT_DATA:
		p = (char *)&c->e[1];
		n = strlen(p);
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_BODY);
		break;

	case LGSSMTP_SENT_BODY:
		n = aws_lws_snprintf(p, sizeof(b) - LWS_PRE, "quit\n");
		aws_lws_smtpc_state_transition(c, LGSSMTP_SENT_QUIT);
		break;

	case LGSSMTP_SENT_QUIT:
		return 0;

	default:
		return 0;
	}

	//puts(p);
	c->abs->at->tx(c->abs->ati, (uint8_t *)p, n);

	return 0;
}

static int
aws_lws_smtpc_abs_closed(aws_lws_abs_protocol_inst_t *api)
{
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)api;

	if (c)
		aws_lws_smtpc_state_transition(c, LGSSMTP_IDLE);

	return 0;
}

/*
 * Creating for initial transport and for piggybacking on another transport
 * both get created here the same.  But piggybackers have ai->bound attached.
 */

static int
aws_lws_smtpc_create(const aws_lws_abs_t *ai)
{
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)ai->api;

	memset(c, 0, sizeof(*c));

	c->abs = ai;
	c->e = aws_lws_smtpc_get_email(c);

	aws_lws_smtpc_state_transition(c, aws_lws_dll2_is_detached(&ai->bound) ?
					LGSSMTP_CONNECTING : LGSSMTP_IDLE);

	/* If we are initiating the transport, we will get an accept() next...
	 *
	 * If we are piggybacking, the parent will get a .child_bind() after
	 * this to give it a chance to act on us joining (eg, it was completely
	 * idle and we joined).
	 */

	return 0;
}

static void
aws_lws_smtpc_destroy(aws_lws_abs_protocol_inst_t **_c)
{
	aws_lws_smtpcp_t *c = (aws_lws_smtpcp_t *)*_c;

	if (!c)
		return;

	/* so if we are still holding on to c->e, we have failed to send it */
	if (c->e)
		aws_lws_smtpc_email_disposition(c,
			LWS_SMTP_DISPOSITION_FAILED_DESTROY, "destroyed", 0);

	*_c = NULL;
}

static int
aws_lws_smtpc_compare(aws_lws_abs_t *abs1, aws_lws_abs_t *abs2)
{
	return 0;
}

static int
aws_lws_smtpc_child_bind(aws_lws_abs_t *abs)
{
	return 0;
}

/* events the transport invokes (handled by abstract protocol) */

const aws_lws_abs_protocol_t aws_lws_abs_protocol_smtp = {
	.name		= "smtp",
	.alloc		= sizeof(aws_lws_smtpcp_t),
	.flags		= LWSABSPR_FLAG_PIPELINE,

	.create		= aws_lws_smtpc_create,
	.destroy	= aws_lws_smtpc_destroy,
	.compare	= aws_lws_smtpc_compare,

	.accept		= aws_lws_smtpc_abs_accept,
	.rx		= aws_lws_smtpc_abs_rx,
	.writeable	= aws_lws_smtpc_abs_writeable,
	.closed		= aws_lws_smtpc_abs_closed,
	.heartbeat	= NULL,

	.child_bind	= aws_lws_smtpc_child_bind,
};
