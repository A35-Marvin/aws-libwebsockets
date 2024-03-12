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

/** \defgroup form-parsing  Form Parsing
 * \ingroup http
 * ##POSTed form parsing functions
 *
 * These aws_lws_spa (stateful post arguments) apis let you parse and urldecode
 * POSTed form arguments, both using simple urlencoded and multipart transfer
 * encoding.
 *
 * It's capable of handling file uploads as well a named input parsing,
 * and the apis are the same for both form upload styles.
 *
 * You feed it a list of parameter names and it creates pointers to the
 * urldecoded arguments: file upload parameters pass the file data in chunks to
 * a user-supplied callback as they come.
 *
 * Since it's stateful, it handles the incoming data needing more than one
 * POST_BODY callback and has no limit on uploaded file size.
 */
///@{

/** enum aws_lws_spa_fileupload_states */
enum aws_lws_spa_fileupload_states {
	LWS_UFS_CONTENT,
	/**< a chunk of file content has arrived */
	LWS_UFS_FINAL_CONTENT,
	/**< the last chunk (possibly zero length) of file content has arrived */
	LWS_UFS_OPEN,
	/**< a new file is starting to arrive */
	LWS_UFS_CLOSE
	/**< the file decode stuff is being destroyed */
};

/**
 * aws_lws_spa_fileupload_cb() - callback to receive file upload data
 *
 * \param data: opt_data pointer set in aws_lws_spa_create
 * \param name: name of the form field being uploaded
 * \param filename: original filename from client
 * \param buf: start of data to receive
 * \param len: length of data to receive
 * \param state: information about how this call relates to file
 *
 * Notice name and filename shouldn't be trusted, as they are passed from
 * HTTP provided by the client.
 */
typedef int (*aws_lws_spa_fileupload_cb)(void *data, const char *name,
				     const char *filename, char *buf, int len,
				     enum aws_lws_spa_fileupload_states state);

/** struct aws_lws_spa - opaque urldecode parser capable of handling multipart
 *			and file uploads */
struct aws_lws_spa;

/**
 * aws_lws_spa_create() - create urldecode parser
 *
 * \param wsi: lws connection (used to find Content Type)
 * \param param_names: array of form parameter names, like "username"
 * \param count_params: count of param_names
 * \param max_storage: total amount of form parameter values we can store
 * \param opt_cb: NULL, or callback to receive file upload data.
 * \param opt_data: NULL, or user pointer provided to opt_cb.
 *
 * Creates a urldecode parser and initializes it.
 *
 * It's recommended to use the newer api, aws_lws_spa_create_via_info()
 * instead.
 *
 * opt_cb can be NULL if you just want normal name=value parsing, however
 * if one or more entries in your form are bulk data (file transfer), you
 * can provide this callback and filter on the name callback parameter to
 * treat that urldecoded data separately.  The callback should return -1
 * in case of fatal error, and 0 if OK.
 */
LWS_VISIBLE LWS_EXTERN struct aws_lws_spa *
aws_lws_spa_create(struct aws_lws *wsi, const char * const *param_names,
	       int count_params, int max_storage, aws_lws_spa_fileupload_cb opt_cb,
	       void *opt_data);

typedef struct aws_lws_spa_create_info {
	const char * const *param_names; /* array of form parameter names, like "username" */
	int count_params; /* count of param_names */
	int max_storage; /* total amount of form parameter values we can store */
	aws_lws_spa_fileupload_cb opt_cb; /* NULL, or callback to receive file upload data. */
	void *opt_data; /* NULL, or user pointer provided to opt_cb. */
	size_t param_names_stride; /* 0 if param_names is an array of char *.
					Else stride to next char * */
	struct aws_lwsac **ac;	/* NULL, or pointer to aws_lwsac * to contain all
				   related heap allocations */
	size_t ac_chunk_size;	/* 0 for default, or ac chunk size */
} aws_lws_spa_create_info_t;

/**
 * aws_lws_spa_create_via_info() - create urldecode parser
 *
 * \param wsi: lws connection (used to find Content Type)
 * \param info: pointer to struct defining the arguments
 *
 * Creates a urldecode parser and initializes it.
 *
 * opt_cb can be NULL if you just want normal name=value parsing, however
 * if one or more entries in your form are bulk data (file transfer), you
 * can provide this callback and filter on the name callback parameter to
 * treat that urldecoded data separately.  The callback should return -1
 * in case of fatal error, and 0 if OK.
 */
LWS_VISIBLE LWS_EXTERN struct aws_lws_spa *
aws_lws_spa_create_via_info(struct aws_lws *wsi, const aws_lws_spa_create_info_t *info);

/**
 * aws_lws_spa_process() - parses a chunk of input data
 *
 * \param spa: the parser object previously created
 * \param in: incoming urlencoded data
 * \param len: count of bytes valid at \p in
 */
LWS_VISIBLE LWS_EXTERN int
aws_lws_spa_process(struct aws_lws_spa *spa, const char *in, int len);

/**
 * aws_lws_spa_finalize() - indicate incoming data completed
 *
 * \param spa: the parser object previously created
 */
LWS_VISIBLE LWS_EXTERN int
aws_lws_spa_finalize(struct aws_lws_spa *spa);

/**
 * aws_lws_spa_get_length() - return length of parameter value
 *
 * \param spa: the parser object previously created
 * \param n: parameter ordinal to return length of value for
 */
LWS_VISIBLE LWS_EXTERN int
aws_lws_spa_get_length(struct aws_lws_spa *spa, int n);

/**
 * aws_lws_spa_get_string() - return pointer to parameter value
 * \param spa: the parser object previously created
 * \param n: parameter ordinal to return pointer to value for
 */
LWS_VISIBLE LWS_EXTERN const char *
aws_lws_spa_get_string(struct aws_lws_spa *spa, int n);

/**
 * aws_lws_spa_destroy() - destroy parser object
 *
 * \param spa: the parser object previously created
 */
LWS_VISIBLE LWS_EXTERN int
aws_lws_spa_destroy(struct aws_lws_spa *spa);
///@}
