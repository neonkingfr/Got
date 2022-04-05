/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/socket.h>
#include <sys/stat.h>

#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"

#include "proc.h"
#include "gotwebd.h"

static const struct got_error *got_init_repo_commit(struct repo_commit **);
static const struct got_error *got_init_repo_tag(struct repo_tag **);
static const struct got_error *got_get_repo_commit(struct request *,
    struct repo_commit *, struct got_commit_object *, struct got_reflist_head *,
    struct got_object_id *);
static const struct got_error *got_gotweb_opentemp(FILE **, int *, int *);
static const struct got_error *got_gotweb_flushtemp(FILE *, int);
static const struct got_error *got_blame_cb(void *, int, int,
    struct got_object_id *);

static int
isbinary(const uint8_t *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (buf[i] == 0)
			return 1;
	return 0;
}


static const struct got_error *
got_gotweb_flushtemp(FILE *f, int fd)
{
	if (fseek(f, 0, SEEK_SET) == -1)
		return got_error_from_errno("fseek");

	if (ftruncate(fd, 0) == -1)
		return got_error_from_errno("ftruncate");

	if (fsync(fd) == -1)
		return got_error_from_errno("fsync");

	if (f && fclose(f) == EOF)
		return got_error_from_errno("fclose");

	if (fd != -1 && close(fd) != -1)
		return got_error_from_errno("close");

	return NULL;
}

static const struct got_error *
got_gotweb_opentemp(FILE **f, int *priv_fd, int *fd)
{
	const struct got_error *error = NULL;

	*fd = dup(*priv_fd);

	if (*fd < 0)
		return NULL;

	*f = fdopen(*fd, "w+");
	if (*f == NULL) {
		close(*fd);
		error = got_error(GOT_ERR_PRIVSEP_NO_FD);
	}

	return error;
}

const struct got_error *
got_tests(struct querystring *qs)
{
	const struct got_error *error = NULL;

	printf("hello test world\n");

	return error;
}

const struct got_error *
got_get_repo_owner(char **owner, struct request *c, char *dir)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	const char *gitconfig_owner;

	*owner = NULL;

	if (srv->show_repo_owner == 0)
		return NULL;

	gitconfig_owner = got_repo_get_gitconfig_owner(repo);
	if (gitconfig_owner) {
		*owner = strdup(gitconfig_owner);
		if (*owner == NULL)
			return got_error_from_errno("strdup");
	}
	return error;
}

const struct got_error *
got_get_repo_age(char **repo_age, struct request *c, char *dir,
    const char *refname, int ref_tm)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	time_t committer_time = 0, cmp_time = 0;

	*repo_age = NULL;
	TAILQ_INIT(&refs);

	if (srv->show_repo_age == 0)
		return NULL;

	error = got_ref_list(&refs, repo, "refs/heads",
	    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	/*
	 * Find the youngest branch tip in the repository, or the age of
	 * the a specific branch tip if a name was provided by the caller.
	 */
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id = NULL;

		if (refname && strcmp(got_ref_get_name(re->ref), refname) != 0)
			continue;

		error = got_ref_resolve(&id, repo, re->ref);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
		free(id);
		if (error)
			goto done;

		committer_time =
		    got_object_commit_get_committer_time(commit);
		got_object_commit_close(commit);
		if (cmp_time < committer_time)
			cmp_time = committer_time;

		if (refname)
			break;
	}

	if (cmp_time != 0) {
		committer_time = cmp_time;
		error = gotweb_get_time_str(repo_age, committer_time, ref_tm);
	}
done:
	got_ref_list_free(&refs);
	return error;
}

static const struct got_error *
got_get_repo_commit(struct request *c, struct repo_commit *repo_commit,
    struct got_commit_object *commit, struct got_reflist_head *refs,
    struct got_object_id *id)
{
	const struct got_error *error = NULL;
	struct got_reflist_entry *re;
	struct got_object_id *id2 = NULL;
	struct got_object_qid *parent_id;
	struct transport *t = c->t;
	struct querystring *qs = c->t->qs;
	char *commit_msg = NULL, *commit_msg0;

	TAILQ_FOREACH(re, refs, entry) {
		char *s;
		const char *name;
		struct got_tag_object *tag = NULL;
		struct got_object_id *ref_id;
		int cmp;

		if (got_ref_is_symbolic(re->ref))
			continue;

		name = got_ref_get_name(re->ref);
		if (strncmp(name, "refs/", 5) == 0)
			name += 5;
		if (strncmp(name, "got/", 4) == 0)
			continue;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0) {
			name += 8;
			s = strstr(name, "/" GOT_REF_HEAD);
			if (s != NULL && s[strlen(s)] == '\0')
				continue;
		}
		error = got_ref_resolve(&ref_id, t->repo, re->ref);
		if (error)
			return error;
		if (strncmp(name, "tags/", 5) == 0) {
			error = got_object_open_as_tag(&tag, t->repo, ref_id);
			if (error) {
				if (error->code != GOT_ERR_OBJ_TYPE) {
					free(ref_id);
					continue;
				}
				/*
				 * Ref points at something other
				 * than a tag.
				 */
				error = NULL;
				tag = NULL;
			}
		}
		cmp = got_object_id_cmp(tag ?
		    got_object_tag_get_object_id(tag) : ref_id, id);
		free(ref_id);
		if (tag)
			got_object_tag_close(tag);
		if (cmp != 0)
			continue;
		s = repo_commit->refs_str;
		if (asprintf(&repo_commit->refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			error = got_error_from_errno("asprintf");
			free(s);
			repo_commit->refs_str = NULL;
			return error;
		}
		free(s);
	}

	error = got_object_id_str(&repo_commit->commit_id, id);
	if (error)
		return error;

	error = got_object_id_str(&repo_commit->tree_id,
	    got_object_commit_get_tree_id(commit));
	if (error)
		return error;

	if (qs->action == DIFF) {
		parent_id = STAILQ_FIRST(
		    got_object_commit_get_parent_ids(commit));
		if (parent_id != NULL) {
			id2 = got_object_id_dup(parent_id->id);
			error = got_object_id_str(&repo_commit->parent_id, id2);
			if (error)
				return error;
			free(id2);
		} else {
			repo_commit->parent_id = strdup("/dev/null");
			if (repo_commit->parent_id == NULL) {
				error = got_error_from_errno("strdup");
				return error;
			}
		}
	}

	repo_commit->committer_time =
	    got_object_commit_get_committer_time(commit);

	repo_commit->author =
	    strdup(got_object_commit_get_author(commit));
	if (repo_commit->author == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	repo_commit->committer =
	    strdup(got_object_commit_get_committer(commit));
	if (repo_commit->committer == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	error = got_object_commit_get_logmsg(&commit_msg0, commit);
	if (error)
		return error;

	commit_msg = commit_msg0;
	while (*commit_msg == '\n')
		commit_msg++;

	repo_commit->commit_msg = strdup(commit_msg);
	if (repo_commit->commit_msg == NULL)
		error = got_error_from_errno("strdup");
	free(commit_msg0);
	return error;
}

const struct got_error *
got_get_repo_commits(struct request *c, int limit)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reference *ref;
	struct repo_commit *repo_commit = NULL, *rs = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *in_repo_path = NULL, *repo_path = NULL;
	int chk_next = 0, chk_multi = 0, commit_found = 0, c_cnt = 0;

	TAILQ_INIT(&refs);

	if (asprintf(&repo_path, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1)
		return got_error_from_errno("asprintf");

	error = got_init_repo_commit(&repo_commit);
	if (error)
		return error;

	/*
	 * XXX: jumping directly to a commit id via
	 * got_repo_match_object_id_prefix significantly improves performance,
	 * but does not allow us to create a PREVIOUS button, since commits can
	 * only be itereated forward. So, we have to build the queue from the
	 * headref and match, which slows down page loading on large repos, when
	 * looking at old commits. Some kind of better caching must be
	 * investigated.
	 */
	error = got_ref_open(&ref, repo, qs->headref, 0);
	if (error)
		goto err;
	error = got_ref_resolve(&id, repo, ref);
	got_ref_close(ref);
	if (error)
		goto err;

	error = got_repo_map_path(&in_repo_path, repo, repo_path);
	if (error)
		goto err;

	if (in_repo_path) {
		repo_commit->path = strdup(in_repo_path);
		if (repo_commit->path == NULL) {
			error = got_error_from_errno("strdup");
			goto err;
		}
	}

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto err;

	error = got_commit_graph_open(&graph, repo_commit->path, 0);
	if (error)
		goto err;

	error = got_commit_graph_iter_start(graph, id, repo, NULL, NULL);
	if (error)
		goto err;

	for (;;) {
		error = got_commit_graph_iter_next(&id, graph, repo, NULL,
		    NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			goto done;
		}
		if (id == NULL)
			goto err;

		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
			goto err;

		struct repo_commit *new_repo_commit = NULL;
		error = got_init_repo_commit(&new_repo_commit);
		if (error)
			goto err;

		TAILQ_INSERT_TAIL(&t->repo_commits, new_repo_commit, entry);

		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto err;

		error = got_get_repo_commit(c, new_repo_commit, commit,
		    &refs, id);
		if (error)
			goto err;

		free(id);
		id = NULL;

		if (limit == 1 && chk_multi == 0 &&
		    srv->max_commits_display != 1)
			commit_found = 1;
		else {
			chk_multi = 1;

			if (qs->commit != NULL) {
				if (strcmp(qs->commit,
				    new_repo_commit->commit_id) == 0)
					commit_found = 1;

			} else
				commit_found = 1;

			/*
			 * check for one more commit before breaking,
			 * so we know whether to navigate through briefs
			 * commits and summary
			 */
			if (chk_next && (qs->action == BRIEFS ||
			    qs->action == COMMITS || qs->action == SUMMARY)) {
				t->next_id = strdup(new_repo_commit->commit_id);
				if (t->next_id == NULL) {
					error = got_error_from_errno("strdup");
					goto err;
				}
				if (commit) {
					got_object_commit_close(commit);
					commit = NULL;
				}
				if (t->next_id == NULL) {
					error = got_error_from_errno("strdup");
					goto err;
				}
				TAILQ_REMOVE(&t->repo_commits, new_repo_commit,
				    entry);
				gotweb_free_repo_commit(new_repo_commit);
				goto done;
			}
		}
		got_ref_list_free(&refs);
		if (commit_found && (error || (limit && --limit == 0))) {
			if (chk_multi == 0)
				break;
			chk_next = 1;
		}
		if (commit) {
			got_object_commit_close(commit);
			commit = NULL;
		}
	}
done:
	/*
	 * we have tailq populated, so find previous commit id
	 * for navigation through briefs and commits
	 */
	if (t->prev_id == NULL && qs->commit != NULL &&
	    (qs->action == BRIEFS || qs->action == COMMITS)) {
		commit_found = 0;
		TAILQ_FOREACH_REVERSE(rs, &t->repo_commits, repo_commits_head,
		    entry) {
			if (commit_found == 0 &&
			    strcmp(qs->commit, rs->commit_id) != 0) {
				continue;
			} else
				commit_found = 1;
			if (c_cnt == srv->max_commits_display ||
			    rs == TAILQ_FIRST(&t->repo_commits)) {
				t->prev_id = strdup(rs->commit_id);
				if (t->prev_id == NULL)
					error = got_error_from_errno("strdup");
				break;
			}
			c_cnt++;
		}
	}
err:
	gotweb_free_repo_commit(repo_commit);
	if (commit)
		got_object_commit_close(commit);
	if (graph)
		got_commit_graph_close(graph);
	got_ref_list_free(&refs);
	free(repo_path);
	free(id);
	return error;
}

const struct got_error *
got_get_repo_tags(struct request *c, int limit)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reference *ref;
	struct got_reflist_entry *re;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	struct got_tag_object *tag = NULL;
	struct repo_tag *rt = NULL, *trt = NULL;
	char *in_repo_path = NULL, *repo_path = NULL, *id_str = NULL;
	char *commit_msg = NULL, *commit_msg0 = NULL;
	int chk_next = 0, chk_multi = 1, commit_found = 0, c_cnt = 0;

	TAILQ_INIT(&refs);

	if (asprintf(&repo_path, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1)
		return got_error_from_errno("asprintf");

	if (error)
		return error;

	if (qs->commit == NULL && qs->action == TAGS) {
		error = got_ref_open(&ref, repo, qs->headref, 0);
		if (error)
			goto err;
		error = got_ref_resolve(&id, repo, ref);
		got_ref_close(ref);
		if (error)
			goto err;
	} else if (qs->commit == NULL && qs->action == TAG) {
		error = got_error_msg(GOT_ERR_EOF, "commit id missing");
		goto err;
	} else {
		error = got_repo_match_object_id_prefix(&id, qs->commit,
		    GOT_OBJ_TYPE_COMMIT, repo);
		if (error)
			goto err;
	}

	if (qs->action != SUMMARY && qs->action != TAGS) {
		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
			goto err;
		error = got_object_commit_get_logmsg(&commit_msg0, commit);
		if (error)
			goto err;
		if (commit) {
			got_object_commit_close(commit);
			commit = NULL;
		}
	}

	error = got_repo_map_path(&in_repo_path, repo, repo_path);
	if (error)
		goto err;

	error = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_tags,
	   repo);
	if (error)
		goto err;

	if (limit == 1)
		chk_multi = 0;

	/*
	 * XXX: again, see previous message about caching
	 */

	TAILQ_FOREACH(re, &refs, entry) {
		struct repo_tag *new_repo_tag = NULL;
		error = got_init_repo_tag(&new_repo_tag);
		if (error)
			goto err;

		TAILQ_INSERT_TAIL(&t->repo_tags, new_repo_tag, entry);

		new_repo_tag->tag_name = strdup(got_ref_get_name(re->ref));
		if (new_repo_tag->tag_name == NULL) {
			error = got_error_from_errno("strdup");
			goto err;
		}

		error = got_ref_resolve(&id, repo, re->ref);
		if (error)
			goto done;

		error = got_object_open_as_tag(&tag, repo, id);
		if (error) {
			if (error->code != GOT_ERR_OBJ_TYPE) {
				free(id);
				id = NULL;
				goto done;
			}
			/* "lightweight" tag */
			error = got_object_open_as_commit(&commit, repo, id);
			if (error) {
				free(id);
				id = NULL;
				goto done;
			}
			new_repo_tag->tagger =
			    strdup(got_object_commit_get_committer(commit));
			if (new_repo_tag->tagger == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			new_repo_tag->tagger_time =
			    got_object_commit_get_committer_time(commit);
			error = got_object_id_str(&id_str, id);
			if (error)
				goto err;
			free(id);
			id = NULL;
		} else {
			free(id);
			id = NULL;
			new_repo_tag->tagger =
			    strdup(got_object_tag_get_tagger(tag));
			if (new_repo_tag->tagger == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			new_repo_tag->tagger_time =
			    got_object_tag_get_tagger_time(tag);
			error = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
			if (error)
				goto err;
		}

		new_repo_tag->commit_id = strdup(id_str);
		if (new_repo_tag->commit_id == NULL)
			goto err;

		if (commit_found == 0 && qs->commit != NULL &&
		    strncmp(id_str, qs->commit, strlen(id_str)) != 0)
			continue;
		else
			commit_found = 1;

		t->tag_count++;

		/*
		 * check for one more commit before breaking,
		 * so we know whether to navigate through briefs
		 * commits and summary
		 */
		if (chk_next) {
			t->next_id = strdup(new_repo_tag->commit_id);
			if (t->next_id == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			if (commit) {
				got_object_commit_close(commit);
				commit = NULL;
			}
			if (t->next_id == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			TAILQ_REMOVE(&t->repo_tags, new_repo_tag, entry);
			gotweb_free_repo_tag(new_repo_tag);
			goto done;
		}

		if (commit) {
			error = got_object_commit_get_logmsg(&new_repo_tag->
			    tag_commit, commit);
			if (error)
				goto done;
			got_object_commit_close(commit);
			commit = NULL;
		} else {
			new_repo_tag->tag_commit =
			    strdup(got_object_tag_get_message(tag));
			if (new_repo_tag->tag_commit == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}

		while (*new_repo_tag->tag_commit == '\n')
			new_repo_tag->tag_commit++;

		if (qs->action != SUMMARY && qs->action != TAGS) {
			commit_msg = commit_msg0;
			while (*commit_msg == '\n')
				commit_msg++;

			new_repo_tag->commit_msg = strdup(commit_msg);
			if (new_repo_tag->commit_msg == NULL) {
				error = got_error_from_errno("strdup");
				free(commit_msg0);
				goto err;
			}
			free(commit_msg0);
		}

		if (limit && --limit == 0) {
			if (chk_multi == 0)
				break;
			chk_next = 1;
		}
		free(id);
		id = NULL;
	}

done:
	/*
	 * we have tailq populated, so find previous commit id
	 * for navigation through briefs and commits
	 */
	if (t->tag_count == 0) {
		TAILQ_FOREACH_SAFE(rt, &t->repo_tags, entry, trt) {
			TAILQ_REMOVE(&t->repo_tags, rt, entry);
			gotweb_free_repo_tag(rt);
		}
	}
	if (t->tag_count > 0 && t->prev_id == NULL && qs->commit != NULL) {
		commit_found = 0;
		TAILQ_FOREACH_REVERSE(rt, &t->repo_tags, repo_tags_head,
		    entry) {
			if (commit_found == 0 &&
			    strcmp(qs->commit, rt->commit_id) != 0) {
				continue;
			} else
				commit_found = 1;
			if (c_cnt == srv->max_commits_display ||
			    rt == TAILQ_FIRST(&t->repo_tags)) {
				t->prev_id = strdup(rt->commit_id);
				if (t->prev_id == NULL)
					error = got_error_from_errno("strdup");
				break;
			}
			c_cnt++;
		}
	}
err:
	if (commit)
		got_object_commit_close(commit);
	got_ref_list_free(&refs);
	free(repo_path);
	free(id);
	return error;
}

const struct got_error *
got_output_repo_tree(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_commit *rc = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_reflist_head refs;
	struct got_tree_object *tree = NULL;
	struct repo_dir *repo_dir = t->repo_dir;
	char *label1 = NULL, *label2 = NULL, *id_str = NULL, *class = NULL;
	char *path = NULL, *in_repo_path = NULL, *build_folder = NULL;
	int nentries, i, class_flip = 0;

	TAILQ_INIT(&refs);

	rc = TAILQ_FIRST(&t->repo_commits);

	if (qs->folder != NULL) {
		path = strdup(qs->folder);
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		error = got_repo_map_path(&in_repo_path, repo, repo_dir->path);
		if (error)
			goto done;
		free(path);
		path = in_repo_path;
	}

	error = got_repo_match_object_id(&id2, &label2, rc->commit_id,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&id1, repo, id2, path);
	if (error)
		goto done;

	error = got_object_open_as_tree(&tree, repo, id1);
	if (error)
		goto done;

	nentries = got_object_tree_get_nentries(tree);

	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		char *modestr = "", *name = NULL;
		mode_t mode;

		te = got_object_tree_get_entry(tree, i);

		error = got_object_id_str(&id_str, got_tree_entry_get_id(te));
		if (error)
			goto done;

		mode = got_tree_entry_get_mode(te);
		if (got_object_tree_entry_is_submodule(te))
			modestr = "$";
		else if (S_ISLNK(mode))
			modestr = "@";
		else if (S_ISDIR(mode))
			modestr = "/";
		else if (mode & S_IXUSR)
			modestr = "*";

		if (class_flip == 0) {
			class = "back_lightgray";
			class_flip = 1;
		} else {
			class = "back_white";
			class_flip = 0;
		}

		name = strdup(got_tree_entry_get_name(te));
		if (S_ISDIR(mode)) {
			if (asprintf(&build_folder, "%s/%s",
			    qs->folder ? qs->folder : "",
			    got_tree_entry_get_name(te)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if (fcgi_gen_response(c,
			    "<div id='tree_wrapper'>\n") == -1)
			goto done;

			if (fcgi_gen_response(c, "<div id='tree_line' "
			    "class='") == -1)
				goto done;
			if (fcgi_gen_response(c, class) == -1)
				goto done;
			if (fcgi_gen_response(c, "'>") == -1)
				goto done;

			if (fcgi_gen_response(c, "<a class='diff_directory' "
			    "href='?index_page=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->index_page_str) == -1)
				goto done;
			if (fcgi_gen_response(c, "&path=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->path) == -1)
				goto done;
			if (fcgi_gen_response(c, "&action=tree") == -1)
				goto done;
			if (fcgi_gen_response(c, "&commit=") == -1)
				goto done;
			if (fcgi_gen_response(c, rc->commit_id) == -1)
				goto done;
			if (fcgi_gen_response(c, "&folder=") == -1)
				goto done;
			if (fcgi_gen_response(c, build_folder) == -1)
				goto done;
			if (fcgi_gen_response(c, "'>") == -1)
				goto done;
			if (fcgi_gen_response(c, name) == -1)
				goto done;
			if (fcgi_gen_response(c, modestr) == -1)
				goto done;
			if (fcgi_gen_response(c, "</a>") == -1)
				goto done;

			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;

			if (fcgi_gen_response(c, "<div id='tree_line_blank' "
			    "class='") == -1)
				goto done;
			if (fcgi_gen_response(c, class) == -1)
				goto done;
			if (fcgi_gen_response(c, "'>") == -1)
				goto done;
			if (fcgi_gen_response(c, "&nbsp;") == -1)
				goto done;
			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;

			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;

		} else {
			name = strdup(got_tree_entry_get_name(te));

			if (fcgi_gen_response(c,
			    "<div id='tree_wrapper'>\n") == -1)
			goto done;
			if (fcgi_gen_response(c, "<div id='tree_line' "
			    "class='") == -1)
				goto done;
			if (fcgi_gen_response(c, class) == -1)
				goto done;
			if (fcgi_gen_response(c, "'>") == -1)
				goto done;

			if (fcgi_gen_response(c,
			    "<a href='?index_page=") == -1)
				goto done;

			if (fcgi_gen_response(c, qs->index_page_str) == -1)
				goto done;

			if (fcgi_gen_response(c, "&path=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->path) == -1)
				goto done;

			if (fcgi_gen_response(c, "&action=blob") == -1)
				goto done;

			if (fcgi_gen_response(c, "&commit=") == -1)
				goto done;
			if (fcgi_gen_response(c, rc->commit_id) == -1)
				goto done;

			if (fcgi_gen_response(c, "&folder=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->folder) == -1)
				goto done;

			if (fcgi_gen_response(c, "&file=") == -1)
				goto done;
			if (fcgi_gen_response(c, name) == -1)
				goto done;

			if (fcgi_gen_response(c, "'>") == -1)
				goto done;
			if (fcgi_gen_response(c, name) == -1)
				goto done;
			if (fcgi_gen_response(c, modestr) == -1)
				goto done;

			if (fcgi_gen_response(c, "</a>") == -1)
				goto done;

			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;

			if (fcgi_gen_response(c, "<div id='tree_line_blank' "
			    "class='") == -1)
				goto done;
			if (fcgi_gen_response(c, class) == -1)
				goto done;
			if (fcgi_gen_response(c, "'>") == -1)
				goto done;

			if (fcgi_gen_response(c,
			    "<a href='?index_page=") == -1)
				goto done;

			if (fcgi_gen_response(c, qs->index_page_str) == -1)
				goto done;

			if (fcgi_gen_response(c, "&path=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->path) == -1)
				goto done;

			if (fcgi_gen_response(c, "&action=blob") == -1)
				goto done;

			if (fcgi_gen_response(c, "&commit=") == -1)
				goto done;
			if (fcgi_gen_response(c, rc->commit_id) == -1)
				goto done;

			if (fcgi_gen_response(c, "&folder=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->folder) == -1)
				goto done;

			if (fcgi_gen_response(c, "&file=") == -1)
				goto done;
			if (fcgi_gen_response(c, name) == -1)
				goto done;

			if (fcgi_gen_response(c, "'>") == -1)
				goto done;

			if (fcgi_gen_response(c, "blob") == -1)
				goto done;
			if (fcgi_gen_response(c, "</a>\n") == -1)
				goto done;

			if (fcgi_gen_response(c, " | \n") == -1)
				goto done;

			if (fcgi_gen_response(c,
			    "<a href='?index_page=") == -1)
				goto done;

			if (fcgi_gen_response(c, qs->index_page_str) == -1)
				goto done;

			if (fcgi_gen_response(c, "&path=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->path) == -1)
				goto done;

			if (fcgi_gen_response(c, "&action=blame") == -1)
				goto done;

			if (fcgi_gen_response(c, "&commit=") == -1)
				goto done;
			if (fcgi_gen_response(c, rc->commit_id) == -1)
				goto done;

			if (fcgi_gen_response(c, "&folder=") == -1)
				goto done;
			if (fcgi_gen_response(c, qs->folder) == -1)
				goto done;

			if (fcgi_gen_response(c, "&file=") == -1)
				goto done;
			if (fcgi_gen_response(c, name) == -1)
				goto done;

			if (fcgi_gen_response(c, "'>") == -1)
				goto done;

			if (fcgi_gen_response(c, "blame") == -1)
				goto done;
			if (fcgi_gen_response(c, "</a>\n") == -1)
				goto done;

			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;
			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;
		}
		free(id_str);
		id_str = NULL;
		free(build_folder);
		build_folder = NULL;
		free(name);
		name = NULL;
	}
done:
	got_ref_list_free(&refs);
	free(label1);
	free(label2);
	free(id1);
	free(id2);
	return error;
}

const struct got_error *
got_output_file_blob(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = c->t->qs;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_reflist_head refs;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	int obj_type, set_mime = 0, type = 0;
	char *buf_output = NULL;
	size_t len, hdrlen;
	const uint8_t *buf;

	TAILQ_INIT(&refs);

	if (asprintf(&path, "%s%s%s", qs->folder ? qs->folder : "",
	    qs->folder ? "/" : "", qs->file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, qs->commit,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit_id, in_repo_path);
	if (error)
		goto done;

	if (obj_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, BUF);
	if (error)
		goto done;
	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		error = got_object_blob_read_block(&len, blob);
		if (error)
			goto done;
		buf = got_object_blob_get_read_buf(blob);

		/*
		 * Skip blob object header first time around,
		 * which also contains a zero byte.
		 */
		buf += hdrlen;
		if (set_mime == 0) {
			if (isbinary(buf, len - hdrlen)) {
				error = gotweb_render_content_type_file(c,
				    "application/octet-stream",
				    qs->file);
				if (error) {
					log_warnx("%s: %s", __func__,
					    error->msg);
					goto done;
				}
				type = 0;
			} else {
				error = gotweb_render_content_type(c,
				  "text/text");
				if (error) {
					log_warnx("%s: %s", __func__,
					    error->msg);
					goto done;
				}
				type = 1;
			}
		}
		set_mime = 1;
		if (type) {
			buf_output = calloc(len - hdrlen + 1,
			    sizeof(*buf_output));
			if (buf_output == NULL) {
				error = got_error_from_errno("calloc");
				goto done;
			}
			memcpy(buf_output, buf, len - hdrlen);
			fcgi_gen_response(c, buf_output);
			free(buf_output);
			buf_output = NULL;
		} else
			fcgi_gen_binary_response(c, buf, len - hdrlen);

		hdrlen = 0;
	} while (len != 0);
done:
	free(buf_output);
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);
	if (blob)
		got_object_blob_close(blob);
	return error;
}

struct blame_line {
	int annotated;
	char *id_str;
	char *committer;
	char datebuf[11]; /* YYYY-MM-DD + NUL */
};

struct blame_cb_args {
	struct blame_line *lines;
	int nlines;
	int nlines_prec;
	int lineno_cur;
	off_t *line_offsets;
	FILE *f;
	struct got_repository *repo;
	struct request *c;
};

static const struct got_error *
got_blame_cb(void *arg, int nlines, int lineno, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct blame_cb_args *a = arg;
	struct blame_line *bline;
	struct request *c = a->c;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *line = NULL;
	size_t linesize = 0;
	struct got_commit_object *commit = NULL;
	off_t offset;
	struct tm tm;
	time_t committer_time;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	if (lineno == -1)
		return NULL; /* no change in this commit */

	/* Annotate this line. */
	bline = &a->lines[lineno - 1];
	if (bline->annotated)
		return NULL;
	err = got_object_id_str(&bline->id_str, id);
	if (err)
		return err;

	err = got_object_open_as_commit(&commit, a->repo, id);
	if (err)
		goto done;

	bline->committer = strdup(got_object_commit_get_committer(commit));
	if (bline->committer == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (gmtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(bline->datebuf, sizeof(bline->datebuf), "%G-%m-%d",
	    &tm) == 0) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}
	bline->annotated = 1;

	/* Print lines annotated so far. */
	bline = &a->lines[a->lineno_cur - 1];
	if (!bline->annotated)
		goto done;

	offset = a->line_offsets[a->lineno_cur - 1];
	if (fseeko(a->f, offset, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	while (bline->annotated) {
		int out_buff_size = 100;
		char *smallerthan, *at, *nl, *committer;
		char out_buff[out_buff_size];
		size_t len;

		if (getline(&line, &linesize, a->f) == -1) {
			if (ferror(a->f))
				err = got_error_from_errno("getline");
			break;
		}

		committer = bline->committer;
		smallerthan = strchr(committer, '<');
		if (smallerthan && smallerthan[1] != '\0')
			committer = smallerthan + 1;
		at = strchr(committer, '@');
		if (at)
			*at = '\0';
		len = strlen(committer);
		if (len >= 9)
			committer[8] = '\0';

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';

		if (fcgi_gen_response(c, "<div id='blame_wrapper'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div id='blame_number'>") == -1)
			goto done;
		if (snprintf(out_buff, strlen(out_buff), "%.*d", a->nlines_prec,
		    a->lineno_cur) < 0)
			goto done;
		if (fcgi_gen_response(c, out_buff) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div id='blame_hash'>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=diff&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, bline->id_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (snprintf(out_buff, 10, "%.8s", bline->id_str) < 0)
			goto done;
		if (fcgi_gen_response(c, out_buff) == -1)
			goto done;
		if (fcgi_gen_response(c, "</a></div>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div id='blame_date'>") == -1)
			goto done;
		if (fcgi_gen_response(c, bline->datebuf) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div id='blame_author'>") == -1)
			goto done;
		if (fcgi_gen_response(c, committer) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div id='blame_code'>") == -1)
			goto done;
		if (fcgi_gen_response(c, line) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;
		a->lineno_cur++;
		bline = &a->lines[a->lineno_cur - 1];
	}
done:
	if (commit)
		got_object_commit_close(commit);
	free(line);
	return err;
}

const struct got_error *
got_output_file_blame(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = c->t->qs;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_reflist_head refs;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	struct blame_cb_args bca;
	int i, obj_type, fd;
	off_t filesize;

	TAILQ_INIT(&refs);

	error = got_gotweb_opentemp(&bca.f, &c->priv_fd, &fd);
	if (error)
		goto done;

	if (asprintf(&path, "%s%s%s", qs->folder ? qs->folder : "",
	    qs->folder ? "/" : "", qs->file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, qs->commit,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit_id, in_repo_path);
	if (error)
		goto done;

	if (obj_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, BUF);
	if (error)
		goto done;

	error = got_object_blob_dump_to_file(&filesize, &bca.nlines,
	    &bca.line_offsets, bca.f, blob);
	if (error || bca.nlines == 0)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (bca.line_offsets[bca.nlines - 1] == filesize)
		bca.nlines--;

	bca.lines = calloc(bca.nlines, sizeof(*bca.lines));
	if (bca.lines == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}
	bca.lineno_cur = 1;
	bca.nlines_prec = 0;
	i = bca.nlines;
	while (i > 0) {
		i /= 10;
		bca.nlines_prec++;
	}
	bca.repo = repo;
	bca.c = c;

	error = got_blame(in_repo_path, commit_id, repo, got_blame_cb, &bca,
	    NULL, NULL);

	error = got_gotweb_flushtemp(bca.f, fd);
done:
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);

	if (blob) {
		free(bca.line_offsets);
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
		free(bca.lines);
	}
	if (blob)
		got_object_blob_close(blob);
	return error;
}

const struct got_error *
got_output_repo_diff(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct repo_commit *rc = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_reflist_head refs;
	FILE *f = NULL;
	char *label1 = NULL, *label2 = NULL, *line = NULL, *color = NULL;
	char *newline, *eline = NULL;
	int obj_type, fd;
	size_t linesize = 0;
	ssize_t linelen;
	int wrlen = 0;

	TAILQ_INIT(&refs);

	error = got_gotweb_opentemp(&f, &c->priv_fd, &fd);
	if (error)
		return error;

	rc = TAILQ_FIRST(&t->repo_commits);

	if (rc->parent_id != NULL &&
	    strncmp(rc->parent_id, "/dev/null", 9) != 0) {
		error = got_repo_match_object_id(&id1, &label1,
		    rc->parent_id, GOT_OBJ_TYPE_ANY,
		    &refs, repo);
		if (error)
			goto done;
	}

	error = got_repo_match_object_id(&id2, &label2, rc->commit_id,
	    GOT_OBJ_TYPE_ANY, &refs, repo);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, id2);
	if (error)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(NULL, NULL, id1, id2,
		    NULL, NULL, 3, 0, 0, repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(NULL, NULL, id1, id2, NULL,
		   "", "", 3, 0, 0, repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(NULL, NULL, id1, id2, NULL,
		    3, 0, 0, repo, f);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}
	if (error)
		goto done;

	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		color = NULL;
		if (strncmp(line, "-", 1) == 0)
			color = "diff_minus";
		else if (strncmp(line, "+", 1) == 0)
			color = "diff_plus";
		else if (strncmp(line, "@@", 2) == 0)
			color = "diff_chunk_header";
		else if (strncmp(line, "@@", 2) == 0)
			color = "diff_chunk_header";
		else if (strncmp(line, "commit +", 8) == 0)
			color = "diff_meta";
		else if (strncmp(line, "commit -", 8) == 0)
			color = "diff_meta";
		else if (strncmp(line, "blob +", 6) == 0)
			color = "diff_meta";
		else if (strncmp(line, "blob -", 6) == 0)
			color = "diff_meta";
		else if (strncmp(line, "file +", 6) == 0)
			color = "diff_meta";
		else if (strncmp(line, "file -", 6) == 0)
			color = "diff_meta";
		else if (strncmp(line, "from:", 5) == 0)
			color = "diff_author";
		else if (strncmp(line, "via:", 4) == 0)
			color = "diff_author";
		else if (strncmp(line, "date:", 5) == 0)
			color = "diff_date";
		if (fcgi_gen_response(c, "<div id='diff_line' class='") == -1)
			goto done;
		if (fcgi_gen_response(c, color ? color : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		newline = strchr(line, '\n');
		if (newline)
			*newline = '\0';

		error = gotweb_escape_html(&eline, line);
		if (error)
			goto done;
		if (fcgi_gen_response(c, eline) == -1)
			goto done;
		free(eline);
		eline = NULL;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (linelen > 0)
			wrlen = wrlen + linelen;
	}
	if (linelen == -1 && ferror(f)) {
		error = got_error_from_errno("getline");
		got_gotweb_flushtemp(f, fd);
		goto done;
	}
	error = got_gotweb_flushtemp(f, fd);
done:
	got_ref_list_free(&refs);
	free(line);
	free(eline);
	free(label1);
	free(label2);
	free(id1);
	free(id2);
	return error;
}

static const struct got_error *
got_init_repo_commit(struct repo_commit **rc)
{
	const struct got_error *error = NULL;

	*rc = calloc(1, sizeof(**rc));
	if (*rc == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	(*rc)->path = NULL;
	(*rc)->refs_str = NULL;
	(*rc)->commit_id = NULL;
	(*rc)->committer = NULL;
	(*rc)->author = NULL;
	(*rc)->parent_id = NULL;
	(*rc)->tree_id = NULL;
	(*rc)->commit_msg = NULL;

	return error;
}

static const struct got_error *
got_init_repo_tag(struct repo_tag **rt)
{
	const struct got_error *error = NULL;

	*rt = calloc(1, sizeof(**rt));
	if (*rt == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	(*rt)->commit_id = NULL;
	(*rt)->tag_name = NULL;
	(*rt)->tag_commit = NULL;
	(*rt)->commit_msg = NULL;
	(*rt)->tagger = NULL;

	return error;
}
