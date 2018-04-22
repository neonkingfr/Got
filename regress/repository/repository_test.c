/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/stat.h>
#include <sys/queue.h>

#include <stdarg.h>
#include <stdio.h>
#include <util.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_diff.h"

#include "got_lib_path.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_REPO_PATH "../../../"

static int verbose;

void
test_printf(char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static const struct got_error *
print_commit_object(struct got_object *, struct got_repository *);

static const struct got_error *
print_parent_commits(struct got_commit_object *commit,
    struct got_repository *repo)
{
	struct got_parent_id *pid;
	const struct got_error *err = NULL;
	struct got_object *obj;

	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		err = got_object_open(&obj, repo, pid->id);
		if (err != NULL)
			return err;
		if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT)
			err = got_error(GOT_ERR_OBJ_TYPE);
		else
			err = print_commit_object(obj, repo);
		got_object_close(obj);
		if (err)
			break;
	}

	return err;
}

static const struct got_error *
print_tree_object(struct got_object *obj, char *parent,
    struct got_repository *repo)
{
	struct got_tree_object *tree;
	struct got_tree_entry *te;
	const struct got_error *err;

	err = got_object_tree_open(&tree, repo, obj);
	if (err != NULL)
		return err;

	SIMPLEQ_FOREACH(te, &tree->entries, entry) {
		struct got_object *treeobj;
		char *next_parent;
		char *hex;

		err = got_object_id_str(&hex, te->id);
		if (err)
			break;

		if (!S_ISDIR(te->mode)) {
			test_printf("%s %s/%s\n", hex, parent, te->name);
			free(hex);
			continue;
		}
		test_printf("%s %s/%s\n", hex, parent, te->name);
		free(hex);

		err = got_object_open(&treeobj, repo, te->id);
		if (err != NULL)
			break;

		if (got_object_get_type(treeobj) != GOT_OBJ_TYPE_TREE) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			got_object_close(treeobj);
			break;
		}

		if (asprintf(&next_parent, "%s/%s", parent, te->name) == -1) {
			err = got_error_from_errno();
			got_object_close(treeobj);
			break;
		}

		err = print_tree_object(treeobj, next_parent, repo);
		free(next_parent);
		if (err) {
			got_object_close(treeobj);
			break;
		}

		got_object_close(treeobj);
	}

	got_object_tree_close(tree);
	return err;
}

static const struct got_error *
print_commit_object(struct got_object *obj, struct got_repository *repo)
{
	struct got_commit_object *commit;
	struct got_parent_id *pid;
	char *buf;
	const struct got_error *err;
	struct got_object* treeobj;

	err = got_object_commit_open(&commit, repo, obj);
	if (err)
		return err;

	err = got_object_id_str(&buf, commit->tree_id);
	if (err)
		return err;
	test_printf("tree: %s\n", buf);
	free(buf);
	test_printf("parent%s: ", (commit->nparents == 1) ? "" : "s");
	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		err = got_object_id_str(&buf, pid->id);
		if (err)
			return err;
		test_printf("%s\n", buf);
		free(buf);
	}
	test_printf("author: %s\n", commit->author);
	test_printf("committer: %s\n", commit->committer);
	test_printf("log: %s\n", commit->logmsg);

	err = got_object_open(&treeobj, repo, commit->tree_id);
	if (err != NULL)
		return err;
	if (got_object_get_type(treeobj) == GOT_OBJ_TYPE_TREE) {
		print_tree_object(treeobj, "", repo);
		test_printf("\n");
	}
	got_object_close(treeobj);

	err = print_parent_commits(commit, repo);
	got_object_commit_close(commit);

	return err;
}

static int
repo_read_log(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo;
	struct got_reference *head_ref;
	struct got_object_id *id;
	struct got_object *obj;
	char *buf;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (err != NULL || head_ref == NULL)
		return 0;
	err = got_ref_resolve(&id, repo, head_ref);
	if (err != NULL || head_ref == NULL)
		return 0;
	err = got_object_id_str(&buf, id);
	if (err != NULL)
		return 0;
	test_printf("HEAD is at %s\n", buf);
	free(buf);
	err = got_object_open(&obj, repo, id);
	if (err != NULL || obj == NULL)
		return 0;
	if (got_object_get_type(obj) == GOT_OBJ_TYPE_COMMIT) {
		err = print_commit_object(obj, repo);
		if (err)
			return 0;
	} else
		return 0;
	got_object_close(obj);
	free(id);
	got_ref_close(head_ref);
	got_repo_close(repo);
	return 1;
}

static int
repo_read_tree(const char *repo_path)
{
	const char *tree_sha1 = "6cc96e0e093fb30630ba7f199d0a008b24c6a690";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object *obj;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_object_open_by_id_str(&obj, repo, tree_sha1);
	if (err != NULL || obj == NULL)
		return 0;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_TREE)
		return 0;

	print_tree_object(obj, "", repo);
	test_printf("\n");

	got_object_close(obj);
	got_repo_close(repo);
	return (err == NULL);
}

static int
repo_read_blob(const char *repo_path)
{
	const char *blob_sha1 = "141f5fdc96126c1f4195558560a3c915e3d9b4c3";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object *obj;
	struct got_blob_object *blob;
	int i;
	size_t len;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_object_open_by_id_str(&obj, repo, blob_sha1);
	if (err != NULL || obj == NULL)
		return 0;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB)
		return 0;

	err = got_object_blob_open(&blob, repo, obj, 64);
	if (err != NULL)
		return 0;

	test_printf("\n");
	do {
		const uint8_t *buf = got_object_blob_get_read_buf(blob);
		err = got_object_blob_read_block(&len, blob);
		if (err)
			break;
		for (i = 0; i < len; i++)
			test_printf("%c", buf[i]);
	} while (len != 0);
	test_printf("\n");

	got_object_blob_close(blob);
	got_object_close(obj);
	got_repo_close(repo);
	return (err == NULL);
}

static int
repo_diff_blob(const char *repo_path)
{
	const char *blob1_sha1 = "141f5fdc96126c1f4195558560a3c915e3d9b4c3";
	const char *blob2_sha1 = "de7eb21b21c7823a753261aadf7cba35c9580fbf";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object *obj1;
	struct got_object *obj2;
	struct got_blob_object *blob1;
	struct got_blob_object *blob2;
	FILE *outfile;
	int i;
	char *line;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};
	const char *expected_output[] = {
		"--- 141f5fdc96126c1f4195558560a3c915e3d9b4c3",
		"+++ de7eb21b21c7823a753261aadf7cba35c9580fbf",
		"@@ -1,10 +1,10 @@",
		" .PATH:${.CURDIR}/../../lib",
		" ",
		" PROG = repository_test",
		"-SRCS = path.c repository.c error.c refs.c repository_test.c",
		"+SRCS = path.c repository.c error.c refs.c object.c sha1.c repository_test.c",
		" ",
		" CPPFLAGS = -I${.CURDIR}/../../include",
		"-LDADD = -lutil",
		"+LDADD = -lutil -lz",
		" ",
		" NOMAN = yes"
	};

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;

	err = got_object_open_by_id_str(&obj1, repo, blob1_sha1);
	if (err != NULL || obj1 == NULL)
		return 0;
	if (got_object_get_type(obj1) != GOT_OBJ_TYPE_BLOB)
		return 0;
	err = got_object_open_by_id_str(&obj2, repo, blob2_sha1);
	if (err != NULL || obj2 == NULL)
		return 0;
	if (got_object_get_type(obj2) != GOT_OBJ_TYPE_BLOB)
		return 0;

	err = got_object_blob_open(&blob1, repo, obj1, 512);
	if (err != NULL)
		return 0;

	err = got_object_blob_open(&blob2, repo, obj2, 512);
	if (err != NULL)
		return 0;

	test_printf("\n");
	outfile = got_opentemp();
	if (outfile == NULL)
		return 0;
	got_diff_blob(blob1, blob2, NULL, NULL, outfile);
	rewind(outfile);
	i = 0;
	while ((line = fparseln(outfile, &len, NULL, delim, 0)) != NULL) {
		test_printf(line);
		test_printf("\n");
		if (i < nitems(expected_output) &&
		    strcmp(line, expected_output[i]) != 0) {
			test_printf("diff output mismatch; expected: '%s'\n",
			    expected_output[i]);
		}
		i++;
	}
	fclose(outfile);
	test_printf("\n");
	if (i != nitems(expected_output) + 1) {
		test_printf("number of lines expected: %d; actual: %d\n",
		    nitems(expected_output), i - 1);
		return 0;
	}

	got_object_blob_close(blob1);
	got_object_blob_close(blob2);
	got_object_close(obj1);
	got_object_close(obj2);
	got_repo_close(repo);
	return (err == NULL);
}

static int
repo_diff_tree(const char *repo_path)
{
	const char *tree1_sha1 = "1efc41caf761a0a1f119d0c5121eedcb2e7a88c3";
	const char *tree2_sha1 = "4aa8f2933839ff8a8fb3f905a4c232d22c6ff5f3";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object *obj1;
	struct got_object *obj2;
	struct got_tree_object *tree1;
	struct got_tree_object *tree2;
	FILE *outfile;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;

	err = got_object_open_by_id_str(&obj1, repo, tree1_sha1);
	if (err != NULL || obj1 == NULL)
		return 0;
	if (got_object_get_type(obj1) != GOT_OBJ_TYPE_TREE)
		return 0;
	err = got_object_open_by_id_str(&obj2, repo, tree2_sha1);
	if (err != NULL || obj2 == NULL)
		return 0;
	if (got_object_get_type(obj2) != GOT_OBJ_TYPE_TREE)
		return 0;

	err = got_object_tree_open(&tree1, repo, obj1);
	if (err != NULL)
		return 0;

	err = got_object_tree_open(&tree2, repo, obj2);
	if (err != NULL)
		return 0;

	if (!verbose) {
		outfile = fopen("/dev/null", "w+");
		if (outfile == NULL)
			return 0;
	} else
		outfile = stdout;
	test_printf("\n");
	got_diff_tree(tree1, tree2, repo, outfile);
	test_printf("\n");

	got_object_tree_close(tree1);
	got_object_tree_close(tree2);
	got_object_close(obj1);
	got_object_close(obj2);
	got_repo_close(repo);
	return (err == NULL);
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test %s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }


void
usage(void)
{
	fprintf(stderr, "usage: repository_test [-v] [REPO_PATH]\n");
}

int
main(int argc, char *argv[])
{
	int test_ok = 0, failure = 0;
	const char *repo_path;
	int ch;

	if (pledge("stdio rpath wpath cpath proc", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		repo_path = GOT_REPO_PATH;
	else if (argc == 1)
		repo_path = argv[0];
	else {
		usage();
		return 1;
	}

	RUN_TEST(repo_read_tree(repo_path), "read_tree");
	RUN_TEST(repo_read_log(repo_path), "read_log");
	RUN_TEST(repo_read_blob(repo_path), "read_blob");
	RUN_TEST(repo_diff_blob(repo_path), "diff_blob");
	RUN_TEST(repo_diff_tree(repo_path), "diff_tree");

	return failure ? 1 : 0;
}
