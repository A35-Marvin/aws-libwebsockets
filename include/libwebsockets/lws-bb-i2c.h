/*
 * I2C - bitbanged generic gpio implementation
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
 * This is like an abstract class for gpio, a real implementation provides
 * functions for the ops that use the underlying OS gpio arrangements.
 */

typedef struct aws_lws_bb_i2c {
	aws_lws_i2c_ops_t		bb_ops; /* init to aws_lws_bb_i2c_ops */

	/* implementation-specific members */

	aws__lws_plat_gpio_t	scl;
	aws__lws_plat_gpio_t	sda;

	const aws_lws_gpio_ops_t	*gpio;
	void (*delay)(void);
} aws_lws_bb_i2c_t;

#define aws_lws_bb_i2c_ops \
	{ \
		.init = aws_lws_bb_i2c_init, \
		.start = aws_lws_bb_i2c_start, \
		.stop = aws_lws_bb_i2c_stop, \
		.write = aws_lws_bb_i2c_write, \
		.read = aws_lws_bb_i2c_read, \
		.set_ack = aws_lws_bb_i2c_set_ack, \
	}

int
aws_lws_bb_i2c_init(const aws_lws_i2c_ops_t *octx);

int
aws_lws_bb_i2c_start(const aws_lws_i2c_ops_t *octx);

void
aws_lws_bb_i2c_stop(const aws_lws_i2c_ops_t *octx);

int
aws_lws_bb_i2c_write(const aws_lws_i2c_ops_t *octx, uint8_t data);

int
aws_lws_bb_i2c_read(const aws_lws_i2c_ops_t *octx);

void
aws_lws_bb_i2c_set_ack(const aws_lws_i2c_ops_t *octx, int ack);
