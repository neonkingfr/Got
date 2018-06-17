/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Utilities for dealing with filesystem paths. */

#define GOT_DEFAULT_FILE_MODE	(S_IRUSR|S_IWUSR | S_IRGRP | S_IROTH)
#define GOT_DEFAULT_DIR_MODE	(S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH)

/* Determine whether a path is an absolute path. */
int got_path_is_absolute(const char *);

/*
 * Return an absolute version of a relative path.
 * The result is allocated with malloc(3).
 */
char *got_path_get_absolute(const char *);

/* 
 * Normalize a path for internal processing.
 * The result is allocated with malloc(3).
 */
char *got_path_normalize(const char *);
