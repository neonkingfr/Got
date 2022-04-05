/*
 * Copyright (c) 2016, 2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_path.h"
#include "got_error.h"

#include "proc.h"
#include "gotwebd.h"

static const struct querystring_keys querystring_keys[] = {
	{ "action",	GW_ACTION },
	{ "commit",	GW_COMMIT },
	{ "file",	GW_FILE },
	{ "folder",	GW_FOLDER },
	{ "headref",	GW_HEADREF },
	{ "page",	GW_PAGE },
	{ "path",	GW_PATH },
	{ "prev",	GW_PREV },
	{ "prev_prev",	GW_PREV_PREV },
};

static const struct action_keys action_keys[] = {
	{ "blame",	GW_BLAME },
	{ "blob",	GW_BLOB },
	{ "briefs",	GW_BRIEFS },
	{ "commits",	GW_COMMITS },
	{ "diff",	GW_DIFF },
	{ "error",	GW_ERR },
	{ "index",	GW_INDEX },
	{ "summary",	GW_SUMMARY },
	{ "tag",	GW_TAG },
	{ "tags",	GW_TAGS },
	{ "tree",	GW_TREE },
};

static const struct got_error *gotweb_init_querystring(struct querystring **);
static const struct got_error *gotweb_parse_querystring(struct querystring **,
    char *);
static const struct got_error *gotweb_assign_querystring(struct querystring **,
    char *, char *);
static const struct got_error *gotweb_render_content_type(struct request *,
    uint8_t *);
static const struct got_error *gotweb_render_header(struct request *,
    struct server *, struct querystring *);
static const struct got_error *gotweb_render_footer(struct request *,
    struct server *);
static const struct got_error *gotweb_render_index(struct request *,
    struct server *);
static const struct got_error *gotweb_escape_html(char **, const char *);
static const struct got_error *gotweb_init_gw_dir(struct gw_dir **,
    const char *);
static const struct got_error *gotweb_load_got_path(struct server *,
    struct gw_dir *);
static const struct got_error *gotweb_get_repo_description(char **,
    struct server *, char *);
static const struct got_error *gotweb_get_clone_url(char **, struct server *,
    char *);

void	 gotweb_free_querystring(struct querystring *);

struct server *gotweb_get_server(uint8_t *, uint8_t *);

extern int cgi_inflight;

enum gw_ref_tm {
	TM_DIFF,
	TM_LONG,
};

enum gw_tags_type {
	TAGBRIEF,
	TAGFULL,
};

FILE *
gotweb_opentemp(int priv_fd)
{
	int fd;
	FILE *f;

	fd = dup(priv_fd);
	if (fd < 0)
		return NULL;

	f = fdopen(fd, "w+");
	if (f == NULL) {
		close(fd);
		return NULL;
	}

	return f;
}

void
gotweb_process_request(struct request *c)
{
	const struct got_error *error = NULL;
	struct querystring *qs = NULL;
	struct server *srv;
	FILE *f = NULL;
	uint8_t err[] = "gotwebd experienced an error: ";
	int erre = 0;

	/* get the gotwebd server */
	srv = gotweb_get_server(c->document_root, c->http_host);
	if (srv == NULL) {
		log_warnx("%s: error server is NULL", __func__);
		goto err;
	}
	/* open our privileged fd */
	f = gotweb_opentemp(c->priv_fd);
	if (f == NULL) {
		log_warnx("%s: error opening temp file", __func__);
		goto err;
	}
	/* parse our querystring */
	if (strlen(c->querystring) != 0) {
		error = gotweb_init_querystring(&qs);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}

		error = gotweb_parse_querystring(&qs, c->querystring);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
	}

	/* render top of page */
	if (qs != NULL && qs->action == GW_BLOB) {
		gotweb_render_content_type(c, "text/text");
		/* got_render_blob; */
		fcgi_gen_response(c, "render blob here");
	} else
		gotweb_render_content_type(c, "text/html");
	gotweb_render_header(c, srv, qs);

	if (qs != NULL) {
		switch(qs->action) {
		default:
			break;
		}
	} else
		gotweb_render_index(c, srv);

	goto done;
err:
	/*
	 * we don't care if errors are pretty
	 * for example, if srv == NULL, how can we render anything other
	 * than the text error?
	 */
	erre = 1;
	gotweb_render_content_type(c, "text/text");
	fcgi_gen_response(c, err);
	if (error)
		fcgi_gen_response(c, (uint8_t *)error->msg);
	else
		fcgi_gen_response(c, "see daemon logs for details");
done:
	if (f != NULL)
		fclose(f);

	if (srv != NULL && erre == 0)
		gotweb_render_footer(c, srv);

	gotweb_free_querystring(qs);
	cgi_inflight--;
	c->inflight_fds_accounted = 1;
}

struct server *
gotweb_get_server(uint8_t *document_root,
    uint8_t *subdomain)
{
	struct server *srv = NULL;

	/* check against document_root first */
	if (strlen(document_root) > 0)
		TAILQ_FOREACH(srv, gotwebd_env->servers, entry)
			if (strcmp(srv->name, document_root) == 0)
				goto done;

	/* check against subdomain next */
	if (strlen(subdomain) > 0)
		TAILQ_FOREACH(srv, gotwebd_env->servers, entry)
			if (strcmp(srv->name, subdomain) == 0)
				goto done;

	/* if those fail, send first server */
	TAILQ_FOREACH(srv, gotwebd_env->servers, entry)
		if (srv != NULL)
			goto done;

done:
	return srv;

};

static const struct got_error *
gotweb_init_querystring(struct querystring **qs)
{
	const struct got_error *error = NULL;

	*qs = malloc(sizeof(**qs));
	if (*qs == NULL)
		return got_error_from_errno2("%s: malloc", __func__);

	(*qs)->commit = NULL;
	(*qs)->file = NULL;
	(*qs)->folder = NULL;
	(*qs)->headref = NULL;
	(*qs)->path = NULL;
	(*qs)->prev = NULL;
	(*qs)->prev_prev = NULL;

	return error;
}

static const struct got_error *
gotweb_parse_querystring(struct querystring **qs, char *qst)
{
	const struct got_error *error = NULL;
	char *tok1 = NULL, *tok1_pair = NULL, *tok1_end = NULL;
	char *tok2 = NULL, *tok2_pair = NULL, *tok2_end = NULL;

	if (qst == NULL)
		return error;

	tok1 = strdup(qst);
	if (tok1 == NULL)
		return got_error_from_errno2("%s: strdup", __func__);

	tok1_pair = tok1;
	tok1_end = tok1;

	while (tok1_pair != NULL) {
		strsep(&tok1_end, "&");

		tok2 = strdup(tok1_pair);
		if (tok2 == NULL) {
			free(tok1);
			return got_error_from_errno2("%s: strdup", __func__);
		}

		tok2_pair = tok2;
		tok2_end = tok2;

		while (tok2_pair != NULL) {
			strsep(&tok2_end, "=");
			if (tok2_end) {
				error = gotweb_assign_querystring(qs, tok2_pair,
				    tok2_end);
				if (error)
					goto err;
			}
			tok2_pair = tok2_end;
		}
		free(tok2);
		tok1_pair = tok1_end;
	}
	free(tok1);
	return error;
err:
	free(tok2);
	free(tok1);
	return error;
}

static const struct got_error *
gotweb_assign_querystring(struct querystring **qs, char *key, char *value)
{
	const struct got_error *error = NULL;
	const char *errstr;
	int a_cnt, el_cnt;

	for (el_cnt = 0; el_cnt < GW_QSELEM__MAX; el_cnt++) {
		if (strcmp(key, querystring_keys[el_cnt].name) != 0)
			continue;

		switch (querystring_keys[el_cnt].element) {
		case GW_ACTION:
			for (a_cnt = 0; a_cnt < GW_ACTIONS__MAX; a_cnt++) {
				if (strcmp(value, action_keys[a_cnt].name) != 0)
					continue;
				(*qs)->action = action_keys[a_cnt].action;
				break;
			}
			break;
		case GW_COMMIT:
			(*qs)->commit = strdup(value);
			if ((*qs)->commit == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_FILE:
			(*qs)->file = strdup(value);
			if ((*qs)->file == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_FOLDER:
			(*qs)->folder = strdup(value);
			if ((*qs)->folder == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_HEADREF:
			(*qs)->headref = strdup(value);
			if ((*qs)->headref == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_PAGE:
			(*qs)->page = strtonum(value, INT64_MIN, INT64_MAX,
			    &errstr);
			if (errstr) {
				error = got_error_from_errno3("%s: strtonum %s",
				    __func__, errstr);
				goto done;
			}
			break;
		case GW_PATH:
			(*qs)->path = strdup(value);
			if ((*qs)->path == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_PREV:
			(*qs)->prev = strdup(value);
			if ((*qs)->prev == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case GW_PREV_PREV:
			(*qs)->prev_prev = strdup(value);
			if ((*qs)->prev_prev == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		default:
			break;
		}
	}
done:
	return error;
}

void
gotweb_free_querystring(struct querystring *qs)
{
	if (qs != NULL) {
		free(qs->commit);
		free(qs->file);
		free(qs->folder);
		free(qs->headref);
		free(qs->path);
		free(qs->prev);
		free(qs->prev_prev);
	}
	free(qs);
}

static const struct got_error *
gotweb_render_content_type(struct request *c, uint8_t *type)
{
	const struct got_error *error = NULL;
	char *h = NULL;

	if (asprintf(&h, "Content-type: %s\r\n\r\n", type) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}

	fcgi_gen_response(c, h);
done:
	free(h);

	return error;
}

static const struct got_error *
gotweb_render_header(struct request *c, struct server *srv,
    struct querystring *qs)
{
	const struct got_error *error = NULL;
	char *title = NULL, *droot = NULL, *css = NULL, *gotlink = NULL;
	char *gotimg = NULL, *sitelink = NULL;

	if (strlen(c->document_root) > 0) {
		if (asprintf(&droot, "/%s/", c->document_root) == -1) {
			error = got_error_from_errno2("%s: asprintf", __func__);
			goto done;
		}
	} else {
		if (asprintf(&droot, "/") == -1) {
			error = got_error_from_errno2("%s: asprintf", __func__);
			goto done;
		}
	}

	if (asprintf(&title, "<title>%s</title>\n", srv->site_name) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&css,
	    "<link rel='stylesheet' type='text/css' href='%s%s'/>\n",
	    droot, srv->custom_css) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&gotlink, "<a href='%s' target='_sotd'>\n",
	    srv->logo_url) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&gotimg, "<img src='%s%s' alt='logo' id='logo'/></a>\n",
	    droot, srv->logo) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&sitelink, "<a href='/%s' alt='sitelink'>%s</a>\n",
	    c->document_root, srv->site_link) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}

	fcgi_gen_response(c, "<!DOCTYPE html>\n<head>\n");
	fcgi_gen_response(c, title);
	fcgi_gen_response(c, "<meta name='viewport' "
	    "content='initial-scale=.75, user-scalable=yes'/>\n");
	fcgi_gen_response(c, "<meta charset='utf-8'/>\n");
	fcgi_gen_response(c, "<meta name='msapplication-TileColor' "
	    "content='#da532c'/>\n");
	fcgi_gen_response(c, "<meta name='theme-color' content='#ffffff'/>\n");
	fcgi_gen_response(c, "<link rel='apple-touch-icon' sizes='180x180' "
	    "href='/apple-touch-icon.png'/>\n");
	fcgi_gen_response(c, "<link rel='icon' type='image/png' sizes='32x32' "
	    "href='/favicon-32x32.png'/>\n");
	fcgi_gen_response(c, "<link rel='icon' type='image/png' sizes='16x16' "
	    "href='/favicon-16x16.png'/>\n");
	fcgi_gen_response(c, "<link rel='manifest' "
	    "href='/site.webmanifest'/>\n");
	fcgi_gen_response(c, "<link rel='mask-icon' "
	    "href='/safari-pinned-tab.svg'/>\n");
	fcgi_gen_response(c, css);
	fcgi_gen_response(c, "</head>\n<body>\n<div id='gw_body'>\n");
	fcgi_gen_response(c, "<div id='header'>\n<div id='got_link'>\n");
	fcgi_gen_response(c, gotlink);
	fcgi_gen_response(c, gotimg);
	fcgi_gen_response(c, "</div>\n</div>\n");
	fcgi_gen_response(c, "<div id='site_path'>\n<div id='site_link'>\n");
	fcgi_gen_response(c, sitelink);
	if (qs != NULL) {
		if (qs->path != NULL) {
			fcgi_gen_response(c, " / ");
			fcgi_gen_response(c, qs->path);
		}
		if (qs->action) {
			fcgi_gen_response(c, " / ");
			switch(qs->action) {
			case(GW_BLAME):
				fcgi_gen_response(c, "blame");
				break;
			case(GW_BRIEFS):
				fcgi_gen_response(c, "briefs");
				break;
			case(GW_COMMITS):
				fcgi_gen_response(c, "commits");
				break;
			case(GW_DIFF):
				fcgi_gen_response(c, "diff");
				break;
			case(GW_SUMMARY):
				fcgi_gen_response(c, "summary");
				break;
			case(GW_TAG):
				fcgi_gen_response(c, "tag");
				break;
			case(GW_TAGS):
				fcgi_gen_response(c, "tags");
				break;
			case(GW_TREE):
				fcgi_gen_response(c, "tree");
				break;
			default:
				break;
			}
		}

	}
	fcgi_gen_response(c, "</div>\n</div>\n<div id='content'>\n");
done:
	free(title);
	free(droot);
	free(css);
	free(gotlink);
	free(gotimg);
	free(sitelink);

	return error;
}

static const struct got_error *
gotweb_render_footer(struct request *c, struct server *srv)
{
	const struct got_error *error = NULL;
	char *siteowner = NULL;

	fcgi_gen_response(c, "<div id='site_owner_wrapper'>\n");
	fcgi_gen_response(c, "<div id='site_owner'>\n");
	if (srv->show_site_owner) {
		error = gotweb_escape_html(&siteowner, srv->site_owner);
		if (error)
			goto done;
		fcgi_gen_response(c, siteowner);
	} else
		fcgi_gen_response(c, "&nbsp;");
	fcgi_gen_response(c, "\n</div>\n</div>\n</body>\n</html>");
done:
	fcgi_create_end_record(c);
	free(siteowner);

	return error;
}

static const struct got_error *
gotweb_render_index(struct request *c, struct server *srv)
{
	const struct got_error *error = NULL;
	DIR *d;
	struct dirent **sd_dent;
	struct gw_dir *gw_dir;
	struct stat st;
	unsigned int d_cnt, d_i;

	char *test = NULL; int t = 0;

	fcgi_gen_response(c, "<div id='index_header'>\n");
	fcgi_gen_response(c, "<div id='index_header_project'>Project</div>\n");
	if (srv->show_repo_description)
		fcgi_gen_response(c, "<div id='index_header_description'>"
		    "Description</div>\n");
	if (srv->show_repo_owner)
		fcgi_gen_response(c, "<div id='index_header_owner'>"
		    "Owner</div>\n");
	if (srv->show_repo_age)
		fcgi_gen_response(c, "<div id='index_header_age'>"
		    "Last Change</div>\n</div>\n");

	d = opendir(srv->repos_path);
	if (d == NULL) {
		error = got_error_from_errno2("opendir", srv->repos_path);
		return error;
	}

	d_cnt = scandir(srv->repos_path, &sd_dent, NULL, alphasort);
	if (d_cnt == -1) {
		error = got_error_from_errno2("scandir", srv->repos_path);
		goto done;
	}

	for (d_i = 0; d_i < d_cnt; d_i++) {
		if (srv->max_repos > 0 && (d_i - 2) == srv->max_repos)
			break; /* account for parent and self */

		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0)
			continue;

		error = gotweb_init_gw_dir(&gw_dir, sd_dent[d_i]->d_name);
		if (error)
			goto done;

		error = gotweb_load_got_path(srv, gw_dir);
		if (error && error->code == GOT_ERR_NOT_GIT_REPO) {
			error = NULL;
			continue;
		}
		else if (error)
			goto done;

		if (lstat(gw_dir->path, &st) == 0 && S_ISDIR(st.st_mode) &&
		    !got_path_dir_is_empty(gw_dir->path)) {
			srv->gw_trans->repos_total++;
			goto render;
		} else
			continue;
render:
		/* test output for thread */
		asprintf(&test, "repo: %d<br />", ++t);
		fcgi_gen_response(c, test);
		free(test);
		test = NULL;
	}

done:
	fcgi_gen_response(c, "</div>");
	if (d && closedir(d) == -1 && error == NULL)
		error = got_error_from_errno("closedir");
	return error;
}

static const struct got_error *
gotweb_escape_html(char **escaped_html, const char *orig_html)
{
	const struct got_error *error = NULL;
	struct escape_pair {
		char c;
		const char *s;
	} esc[] = {
		{ '>', "&gt;" },
		{ '<', "&lt;" },
		{ '&', "&amp;" },
		{ '"', "&quot;" },
		{ '\'', "&apos;" },
		{ '\n', "<br />" },
	};
	size_t orig_len, len;
	int i, j, x;

	orig_len = strlen(orig_html);
	len = orig_len;
	for (i = 0; i < orig_len; i++) {
		for (j = 0; j < nitems(esc); j++) {
			if (orig_html[i] != esc[j].c)
				continue;
			len += strlen(esc[j].s) - 1 /* escaped char */;
		}
	}

	*escaped_html = calloc(len + 1 /* NUL */, sizeof(**escaped_html));
	if (*escaped_html == NULL)
		return got_error_from_errno("calloc");

	x = 0;
	for (i = 0; i < orig_len; i++) {
		int escaped = 0;
		for (j = 0; j < nitems(esc); j++) {
			if (orig_html[i] != esc[j].c)
				continue;

			if (strlcat(*escaped_html, esc[j].s, len + 1)
			    >= len + 1) {
				error = got_error(GOT_ERR_NO_SPACE);
				goto done;
			}
			x += strlen(esc[j].s);
			escaped = 1;
			break;
		}
		if (!escaped) {
			(*escaped_html)[x] = orig_html[i];
			x++;
		}
	}
done:
	if (error) {
		free(*escaped_html);
		*escaped_html = NULL;
	} else {
		(*escaped_html)[x] = '\0';
	}

	return error;
}

static const struct got_error *
gotweb_load_got_path(struct server *srv, struct gw_dir *gw_dir)
{
	const struct got_error *error = NULL;
	DIR *dt;
	char *dir_test;
	int opened = 0;

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, gw_dir->name,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
	} else {
		gw_dir->path = strdup(dir_test);
		if (gw_dir->path == NULL) {
			opened = 1;
			error = got_error_from_errno("strdup");
			goto errored;
		}
		opened = 1;
		goto done;
	}

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, gw_dir->name,
	    GOTWEB_GOT_DIR) == -1) {
		dir_test = NULL;
		error = got_error_from_errno("asprintf");
		goto errored;
	}

	dt = opendir(dir_test);
	if (dt == NULL)
		free(dir_test);
	else {
		opened = 1;
		error = got_error(GOT_ERR_NOT_GIT_REPO);
		goto errored;
	}

	if (asprintf(&dir_test, "%s/%s", srv->repos_path, gw_dir->name) == -1) {
		error = got_error_from_errno("asprintf");
		dir_test = NULL;
		goto errored;
	}

	gw_dir->path = strdup(dir_test);
	if (gw_dir->path == NULL) {
		opened = 1;
		error = got_error_from_errno("strdup");
		goto errored;
	}

	dt = opendir(dir_test);
	if (dt == NULL) {
		error = got_error_path(gw_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto errored;
	} else
		opened = 1;
done:
	error = gotweb_get_repo_description(&gw_dir->description, srv,
	    gw_dir->path);
	if (error)
		goto errored;
	error = got_get_repo_owner(&gw_dir->owner, srv, gw_dir->path);
	if (error)
		goto errored;
	error = got_get_repo_age(&gw_dir->age, srv, gw_dir->path,
	    NULL, TM_DIFF);
	if (error)
		goto errored;
	error = gotweb_get_clone_url(&gw_dir->url, srv, gw_dir->path);
errored:
	free(dir_test);
	if (opened)
		if (dt && closedir(dt) == -1 && error == NULL)
			error = got_error_from_errno("closedir");
	return error;
}

static const struct got_error *
gotweb_init_gw_dir(struct gw_dir **gw_dir, const char *dir)
{
	const struct got_error *error;

	*gw_dir = malloc(sizeof(**gw_dir));
	if (*gw_dir == NULL)
		return got_error_from_errno("malloc");

	if (asprintf(&(*gw_dir)->name, "%s", dir) == -1) {
		error = got_error_from_errno("asprintf");
		free(*gw_dir);
		*gw_dir = NULL;
		return error;
	}

	return NULL;
}

static const struct got_error *
gotweb_get_repo_description(char **description, struct server *srv, char *dir)
{
	const struct got_error *error = NULL;
	FILE *f = NULL;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*description = NULL;
	if (srv->show_repo_description == 0)
		return NULL;

	if (asprintf(&d_file, "%s/description", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "r");
	if (f == NULL) {
		if (errno == ENOENT || errno == EACCES)
			return NULL;
		error = got_error_from_errno2("fopen", d_file);
		goto done;
	}

	if (fseek(f, 0, SEEK_END) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	len = ftell(f);
	if (len == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	*description = calloc(len + 1, sizeof(**description));
	if (*description == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	n = fread(*description, 1, len, f);
	if (n == 0 && ferror(f))
		error = got_ferror(f, GOT_ERR_IO);
done:
	if (f != NULL && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return error;
}

static const struct got_error *
gotweb_get_clone_url(char **url, struct server *srv, char *dir)
{
	const struct got_error *error = NULL;
	FILE *f;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*url = NULL;

	if (srv->show_repo_cloneurl == 0)
		return NULL;

	if (asprintf(&d_file, "%s/cloneurl", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "r");
	if (f == NULL) {
		if (errno != ENOENT && errno != EACCES)
			error = got_error_from_errno2("fopen", d_file);
		goto done;
	}

	if (fseek(f, 0, SEEK_END) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	len = ftell(f);
	if (len == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	*url = calloc(len + 1, sizeof(**url));
	if (*url == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	n = fread(*url, 1, len, f);
	if (n == 0 && ferror(f))
		error = got_ferror(f, GOT_ERR_IO);
done:
	if (f && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return NULL;
}

const struct got_error *
gotweb_get_time_str(char **repo_age, time_t committer_time, int ref_tm)
{
	struct tm tm;
	time_t diff_time;
	char *years = "years ago", *months = "months ago";
	char *weeks = "weeks ago", *days = "days ago", *hours = "hours ago";
	char *minutes = "minutes ago", *seconds = "seconds ago";
	char *now = "right now";
	char *s;
	char datebuf[29];

	*repo_age = NULL;

	switch (ref_tm) {
	case TM_DIFF:
		diff_time = time(NULL) - committer_time;
		if (diff_time > 60 * 60 * 24 * 365 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 365), years) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * (365 / 12) * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / (365 / 12)),
			    months) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * 7 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 7), weeks) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24), days) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60), hours) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 2) {
			if (asprintf(repo_age, "%lld %s", (diff_time / 60),
			    minutes) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 2) {
			if (asprintf(repo_age, "%lld %s", diff_time,
			    seconds) == -1)
				return got_error_from_errno("asprintf");
		} else {
			if (asprintf(repo_age, "%s", now) == -1)
				return got_error_from_errno("asprintf");
		}
		break;
	case TM_LONG:
		if (gmtime_r(&committer_time, &tm) == NULL)
			return got_error_from_errno("gmtime_r");

		s = asctime_r(&tm, datebuf);
		if (s == NULL)
			return got_error_from_errno("asctime_r");

		if (asprintf(repo_age, "%s UTC", datebuf) == -1)
			return got_error_from_errno("asprintf");
		break;
	}
	return NULL;
}