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
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_opentemp.h"

#include "proc.h"
#include "gotwebd.h"

static const struct got_error *got_init_repo_commit(struct repo_commit **);
static const struct got_error *got_get_repo_commit(struct request *,
    struct repo_commit *, struct got_commit_object *, struct got_reflist_head *,
    struct got_object_id *);

const struct got_error *
got_tests(struct querystring *qs)
{
	const struct got_error *error = NULL;

	printf("hello test world\n");

	return error;
}

const struct got_error *
got_get_repo_owner(char **owner, struct server *srv, char *dir)
{
	const struct got_error *error = NULL;
	struct got_repository *repo;
	const char *gitconfig_owner;

	*owner = NULL;

	if (srv->show_repo_owner == 0)
		return NULL;

	error = got_repo_open(&repo, dir, NULL);
	if (error)
		return error;
	gitconfig_owner = got_repo_get_gitconfig_owner(repo);
	if (gitconfig_owner) {
		*owner = strdup(gitconfig_owner);
		if (*owner == NULL)
			return got_error_from_errno("strdup");
	}
	error = got_repo_close(repo);
	return error;
}

const struct got_error *
got_get_repo_age(char **repo_age, struct server *srv, char *dir,
    const char *refname, int ref_tm)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	time_t committer_time = 0, cmp_time = 0;

	*repo_age = NULL;
	TAILQ_INIT(&refs);

	if (srv->show_repo_age == 0)
		return NULL;

	error = got_repo_open(&repo, dir, NULL);
	if (error)
		return error;

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
	got_repo_close(repo);
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
			error = got_object_open_as_tag(&tag, t->repo,
			    ref_id);
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
		parent_id = SIMPLEQ_FIRST(
		    got_object_commit_get_parent_ids(commit));
		if (parent_id != NULL) {
			id2 = got_object_id_dup(parent_id->id);
			free (parent_id);
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
	struct got_repository *repo = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct repo_commit *repo_commit = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = c->t->repo_dir;
	char *in_repo_path = NULL, *repo_path = NULL;
	int chk_next = 0, chk_multi = 0;

	TAILQ_INIT(&refs);

	if (asprintf(&repo_path, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1)
		return got_error_from_errno("asprintf");

	error = got_init_repo_commit(&repo_commit);
	if (error)
		return error;

	error = got_repo_open(&repo, repo_path, NULL);
	if (error)
		return error;

	c->t->repo = repo;

	if (qs->commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, t->headref, 0);
		if (error)
			return error;
		t->last_commit = 1;
		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			return error;
	} else {
		struct got_reference *ref;

		error = got_ref_open(&ref, repo, qs->commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id, repo, ref);
			got_ref_close(ref);
			if (error)
				return error;
			error = got_object_get_type(&obj_type, repo, id);
			if (error)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id);
				if (error)
					goto done;
				if (got_object_tag_get_object_type(tag) !=
				    GOT_OBJ_TYPE_COMMIT) {
					got_object_tag_close(tag);
					error = got_error(GOT_ERR_OBJ_TYPE);
					goto done;
				}
				free(id);
				id = got_object_id_dup(
				    got_object_tag_get_object_id(tag));
				if (id == NULL)
					error = got_error_from_errno(
					    "got_object_id_dup");
				got_object_tag_close(tag);
				if (error)
					goto done;
			} else if (obj_type != GOT_OBJ_TYPE_COMMIT) {
				error = got_error(GOT_ERR_OBJ_TYPE);
				goto done;
			}
		}
		error = got_repo_match_object_id_prefix(&id, qs->commit,
		    GOT_OBJ_TYPE_COMMIT, repo);
		if (error)
			goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, repo_path);
	if (error)
		goto done;

	if (in_repo_path) {
		repo_commit->path = strdup(in_repo_path);
		if (repo_commit->path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = got_commit_graph_open(&graph, repo_commit->path, 0);
	if (error)
		goto done;

	error = got_commit_graph_iter_start(graph, id, repo, NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		error = got_commit_graph_iter_next(&id, graph, repo, NULL,
		    NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			goto done;
		}
		if (id == NULL)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
			goto done;
		if (limit == 1 && chk_multi == 0 &&
		    srv->max_commits_display != 1) {
			error = got_get_repo_commit(c, repo_commit, commit,
			    &refs, id);
			if (error)
				goto done;
		} else {
			chk_multi = 1;
			struct repo_commit *new_repo_commit = NULL;
			error = got_init_repo_commit(&new_repo_commit);
			if (error)
				goto done;
			error = got_ref_list(&refs, repo, NULL,
			    got_ref_cmp_by_name, NULL);
			if (error)
				goto done;

			error = got_get_repo_commit(c, new_repo_commit, commit,
			    &refs, id);
			if (error)
				goto done;

			got_ref_list_free(&refs);

			/*
			 * we have a commit_id now, so copy it to next_prev_id
			 * for navigation through briefs and commits
			 */
			if (t->prev_id == NULL && t->last_commit == 0 &&
			    (qs->action == BRIEFS || qs->action == COMMITS ||
			     qs->action == SUMMARY)) {
				t->prev_id =
				    strdup(new_repo_commit->commit_id);
				if (t->prev_id == NULL) {
					error = got_error_from_errno("strdup");
					goto done;
				}
			}

			/*
			 * check for one more commit before breaking,
			 * so we know whether to navicate through gw_briefs
			 * gw_commits and gw_summary
			 */
			if (chk_next && (qs->action == BRIEFS ||
			    qs->action == COMMITS || qs->action == SUMMARY)) {
				t->next_id = strdup(new_repo_commit->commit_id);
				if (t->next_id == NULL)
					error = got_error_from_errno("strdup");
				goto done;
			}

			TAILQ_INSERT_TAIL(&t->repo_commits, new_repo_commit,
			    entry);
		}
		if (error || (limit && --limit == 0)) {
			if (chk_multi == 0)
				break;
			chk_next = 1;
		}
		if (commit != NULL)
			got_object_commit_close(commit);
	}
done:
	if (commit != NULL)
		got_object_commit_close(commit);
	if (graph)
		got_commit_graph_close(graph);
	got_ref_list_free(&refs);
	free(id);
	free(repo_path);
	free(in_repo_path);
	error = got_repo_close(repo);
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
