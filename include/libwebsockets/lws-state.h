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

struct aws_lws_state_notify_link;
struct aws_lws_state_manager;

#if defined(LWS_WITH_SYS_STATE)

typedef int (*aws_lws_state_notify_t)(struct aws_lws_state_manager *mgr,
				  struct aws_lws_state_notify_link *link,
				  int current, int target);

typedef struct aws_lws_state_notify_link {
	aws_lws_dll2_t		list;
	aws_lws_state_notify_t	notify_cb;
	const char		*name;
} aws_lws_state_notify_link_t;

typedef struct aws_lws_state_manager {
	aws_lws_dll2_owner_t	notify_list;
	struct aws_lws_context	*context;
	void			*parent;
#if defined(LWS_WITH_SYS_SMD)
	aws_lws_smd_class_t		smd_class;
#endif
	/**< optional opaque pointer to owning object... useful to make such
	 * a pointer available to a notification callback.  Ignored by lws */
	const char		**state_names;
	const char		*name;
	int			state;
} aws_lws_state_manager_t;

/**
 * aws_lws_state_reg_notifier() - add dep handler for state notifications
 *
 * \param context: the aws_lws_context
 * \param nl: the handler to add to the notifier linked-list
 *
 * Add \p notify_link to the context's list of notification handlers for system
 * state changes.  The handlers can defeat or take over responsibility for
 * retrying the change after they have initiated some dependency.
 */

LWS_EXTERN LWS_VISIBLE void
aws_lws_state_reg_notifier(aws_lws_state_manager_t *mgr, aws_lws_state_notify_link_t *nl);

/**
 * aws_lws_state_reg_deregister() - deregister a notifier
 *
 * \param nl: notification hardler to deregister
 *
 * Remove a notification handler from its state manager
 */

LWS_EXTERN LWS_VISIBLE void
aws_lws_state_reg_deregister(aws_lws_state_notify_link_t *nl);

/**
 * aws_lws_state_reg_notifier_list() - add dep handlers for state notifications
 *
 * \param context: the aws_lws_context
 * \param nl: list of notification handlers
 *
 * Add a NULL-terminated list of notification handler pointers to a notification
 * manager object
 */

LWS_EXTERN LWS_VISIBLE void
aws_lws_state_reg_notifier_list(aws_lws_state_manager_t *mgr,
			    aws_lws_state_notify_link_t * const *nl);

/**
 * aws_lws_state_transition_steps() - move to state via starting any deps
 *
 * \param mgr: the state manager object
 * \param target: the state we wish to move to
 *
 * Advance state by state towards state \p target.  At each state, notifiers
 * may veto the change and be triggered to perform dependencies, stopping the
 * advance towards the target state.
 */
LWS_EXTERN LWS_VISIBLE int
aws_lws_state_transition_steps(aws_lws_state_manager_t *mgr, int target);

/**
 * aws_lws_state_transition() - move to state via starting any deps
 *
 * \param mgr: the state manager object
 * \param target: the state we wish to move to
 *
 * Jump to state target atomically.  Notifiers may veto it.
 */
LWS_EXTERN LWS_VISIBLE int
aws_lws_state_transition(aws_lws_state_manager_t *mgr, int target);

#else

#endif
