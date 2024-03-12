/*
 * lws abstract display implementation for ssd1306 on i2c
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

#if !defined(__LWS_DISPLAY_SSD1306_I2C_H__)
#define __LWS_DISPLAY_SSD1306_I2C_H__

/*
 * D/C# pin on SSD1306 sets the I2C device ads
 * from these two options (7-bit address)
 */

#define SSD1306_I2C7_ADS1		0x3c
#define SSD1306_I2C7_ADS2		0x3d

typedef struct aws_lws_display_ssd1306 {

	aws_lws_display_t		disp; /* use aws_lws_display_ssd1306_ops to set ops */
	const aws_lws_i2c_ops_t	*i2c;	      /* i2c ops */

	const aws_lws_gpio_ops_t	*gpio;	      /* NULL or gpio ops */
	aws__lws_plat_gpio_t	reset_gpio;   /* if gpio ops, nReset gpio # */

	uint8_t			i2c7_address; /* one of SSD1306_I2C7_ADS... */

} aws_lws_display_ssd1306_t;

int
aws_lws_display_ssd1306_i2c_init(const struct aws_lws_display *disp);
int
aws_lws_display_ssd1306_i2c_contrast(const struct aws_lws_display *disp, uint8_t b);
int
aws_lws_display_ssd1306_i2c_blit(const struct aws_lws_display *disp, const uint8_t *src,
                             aws_lws_display_scalar x, aws_lws_display_scalar y,
                             aws_lws_display_scalar w, aws_lws_display_scalar h);
int
aws_lws_display_ssd1306_i2c_power(const struct aws_lws_display *disp, int state);

#define aws_lws_display_ssd1306_ops \
	.init = aws_lws_display_ssd1306_i2c_init, \
	.contrast = aws_lws_display_ssd1306_i2c_contrast, \
	.blit = aws_lws_display_ssd1306_i2c_blit, \
	.power = aws_lws_display_ssd1306_i2c_power
#endif
