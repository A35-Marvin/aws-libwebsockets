/*
 * lws abstract display
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
 */

#include <libwebsockets.h>

static void
sul_autodim_cb(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_display_state_t *lds = aws_lws_container_of(sul, aws_lws_display_state_t,
						    sul_autodim);
	int next_ms = -1;

	/* we fire both to dim and to blank... if already in dim state, blank */

	switch (lds->state) {
	case LWSDISPS_BECOMING_ACTIVE:
		aws_lws_display_state_set_brightness(lds, lds->disp->bl_active);
		lds->state = LWSDISPS_ACTIVE;
		next_ms = lds->autodim_ms;
		break;

	case LWSDISPS_ACTIVE:
		/* active -> autodimmed */
		lds->state = LWSDISPS_AUTODIMMED;
		next_ms = lds->off_ms;
		aws_lws_display_state_set_brightness(lds, lds->disp->bl_dim);
		break;

	case LWSDISPS_AUTODIMMED:
		/* dimmed -> OFF */
		aws_lws_display_state_set_brightness(lds, &aws_lws_pwmseq_static_off);
		lds->state = LWSDISPS_GOING_OFF;
		next_ms = 600;
		break;

	case LWSDISPS_GOING_OFF:
		/* off dimming completed, actual display OFF */
		aws_lws_display_state_off(lds);
		return;

	default:
		return;
	}

	if (next_ms >= 0)
		aws_lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 next_ms * LWS_US_PER_MS);
}

void
aws_lws_display_state_init(aws_lws_display_state_t *lds, struct aws_lws_context *ctx,
		       int dim_ms, int off_ms, struct aws_lws_led_state *bl_lcs,
		       const aws_lws_display_t *disp)
{
	memset(lds, 0, sizeof(*lds));

	lds->disp = disp;
	lds->ctx = ctx;
	lds->autodim_ms = dim_ms;
	lds->off_ms = off_ms;
	lds->bl_lcs = bl_lcs;
	lds->state = LWSDISPS_OFF;

	aws_lws_led_transition(lds->bl_lcs, "backlight", &aws_lws_pwmseq_static_off,
						     &aws_lws_pwmseq_static_on);

	disp->init(disp);
}

void
aws_lws_display_state_set_brightness(aws_lws_display_state_t *lds,
				 const aws_lws_led_sequence_def_t *pwmseq)
{
	aws_lws_led_transition(lds->bl_lcs, "backlight", pwmseq,
			   lds->disp->bl_transition);
}

void
aws_lws_display_state_active(aws_lws_display_state_t *lds)
{
	int waiting_ms;

	if (lds->state == LWSDISPS_OFF) {
		/* power us up */
		lds->disp->power(lds->disp, 1);
		lds->state = LWSDISPS_BECOMING_ACTIVE;
		waiting_ms = lds->disp->latency_wake_ms;
	} else {

		if (lds->state != LWSDISPS_ACTIVE)
			aws_lws_display_state_set_brightness(lds,
						lds->disp->bl_active);

		lds->state = LWSDISPS_ACTIVE;
		waiting_ms = lds->autodim_ms;
	}

	/* reset the autodim timer */
	if (waiting_ms >= 0)
		aws_lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 waiting_ms * LWS_US_PER_MS);

}

void
aws_lws_display_state_off(aws_lws_display_state_t *lds)
{
	lds->disp->power(lds->disp, 0);
	aws_lws_sul_cancel(&lds->sul_autodim);
	lds->state = LWSDISPS_OFF;
}
