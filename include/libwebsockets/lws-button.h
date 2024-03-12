/*
 * Generic button ops
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 * Leverages the lws generic gpio pieces to bind gpio buttons to smd events
 */

#if !defined(__LWS_BUTTON_H__)
#define __LWS_BUTTON_H__

typedef uint16_t aws_lws_button_idx_t;

/* actual minimum may be 1 x RTOS tick depending on platform */
#define LWS_BUTTON_MON_TIMER_MS 5

typedef void (*aws_lws_button_cb_t)(void *opaque, aws_lws_button_idx_t idx, int state);

/* These are specified in ms but the granularity is LWS_BUTTON_MON_TIMER_MS,
 * which may have been rounded up to an RTOS tick depending on platform */

enum {
	LWSBTNRGMFLAG_CLASSIFY_DOUBLECLICK = (1 << 0)
};

typedef struct aws_lws_button_regime {
	uint16_t			ms_min_down;
	uint16_t			ms_min_down_longpress;
	uint16_t			ms_up_settle;
	uint16_t			ms_doubleclick_grace;
	uint16_t			ms_repeat_down;
	uint8_t				flags;
	/**< when double-click classification is enabled, clicks are delayed
	 * by ms_min_down + ms_doubleclick_grace to wait and see if it will
	 * become a double-click.  Set LWSBTNRGMFLAG_CLASSIFY_DOUBLECLICK to
	 * enable it or leave that bit at 0 to get faster single-click
	 * classification.
	 */
} aws_lws_button_regime_t;

/*
 * This is the const part of the button controller, describing the static
 * bindings to gpio, and aws_lws_smd event name information
 */

typedef struct aws_lws_button_map {
	aws__lws_plat_gpio_t		gpio;
	const char			*smd_interaction_name;
	const aws_lws_button_regime_t	*regime;
	/**< a default regime is applied if this is left NULL */
} aws_lws_button_map_t;

typedef struct aws_lws_button_controller {
	const char			*smd_bc_name;
	const aws_lws_gpio_ops_t		*gpio_ops;
	const aws_lws_button_map_t		*button_map;
	aws_lws_button_idx_t		active_state_bitmap;
	uint8_t				count_buttons;
} aws_lws_button_controller_t;

struct aws_lws_button_state; /* opaque */

/**
 * aws_lws_button_controller_create() - instantiate a button controller
 *
 * \param ctx: the aws_lws_context
 * \param controller: the static controller definition
 *
 * Instantiates a button controller from a static definition of the buttons
 * and their smd names, and active levels, and binds it to a gpio implementation
 */

LWS_VISIBLE LWS_EXTERN struct aws_lws_button_state *
aws_lws_button_controller_create(struct aws_lws_context *ctx,
			     const aws_lws_button_controller_t *controller);

/**
 * aws_lws_button_controller_destroy() - destroys a button controller
 *
 * \param bcs: button controller state previously created
 *
 * Disables all buttons and then destroys and frees a previously created
 * button controller.
 */

LWS_VISIBLE LWS_EXTERN void
aws_lws_button_controller_destroy(struct aws_lws_button_state *bcs);


LWS_VISIBLE LWS_EXTERN aws_lws_button_idx_t
aws_lws_button_get_bit(struct aws_lws_button_state *bcs, const char *name);

/*
 * aws_lws_button_enable() - enable and disable buttons
 */

LWS_VISIBLE LWS_EXTERN void
aws_lws_button_enable(struct aws_lws_button_state *bcs,
		  aws_lws_button_idx_t _reset, aws_lws_button_idx_t _set);

#endif

