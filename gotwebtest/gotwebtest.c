/*
 * Copyright (c) 2020 Tracey Emery <tracey@traceyemery.net>
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

#include <sys/queue.h>
#include <sys/socket.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../gotwebd/proc.h"
#include "../gotwebd/gotwebd.h"

#include "got_error.h"

int	 main(int, char**);
__dead static void usage(void);

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s -q 'querystring'\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const struct got_error	*error = NULL;
	struct querystring	*qs = NULL;
	char		*qst = NULL;
	int		 ch, q = 0;

	while ((ch = getopt(argc, argv, "q")) != -1) {
		switch (ch) {
		case('q'):
			q = 1;
			qst = strdup(argv[2]);
			if (qst == NULL)
				errx(1, "%s: strdup", __func__);
			break;
		default:
			usage();
			break;
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (!q) {
		usage();
		return 0;
	}

	error = init_querystring(&qs);
	if (error)
		printf("%s\n", error->msg);

	error = parse_querystring(&qs, qst);

	error = gotweb_tests(qs);

	free_querystring(qs);
	free(qst);

	return 0;
}
