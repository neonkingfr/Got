#!/bin/sh
#
# Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

. ./common.sh

function test_blame_basic {
	local testroot=`test_init blame_basic`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret="$?"
	if [ "$ret" != "0" ]; then
		test_done "$testroot" "$ret"
		return 1
	fi

	echo 1 > $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 1" > /dev/null)
	local commit1=`git_show_head $testroot/repo`

	echo 2 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 2" > /dev/null)
	local commit2=`git_show_head $testroot/repo`

	echo 3 >> $testroot/wt/alpha
	(cd $testroot/wt && got commit -m "change 3" > /dev/null)
	local commit3=`git_show_head $testroot/repo`

	(cd $testroot/wt && got blame alpha > $testroot/stdout)

	local short_commit1=`trim_obj_id 32 $commit1`
	local short_commit2=`trim_obj_id 32 $commit2`
	local short_commit3=`trim_obj_id 32 $commit3`

	echo "$short_commit1 1" > $testroot/stdout.expected
	echo "$short_commit2 2" >> $testroot/stdout.expected
	echo "$short_commit3 3" >> $testroot/stdout.expected

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret="$?"
	if [ "$ret" != "0" ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi

	test_done "$testroot" "$ret"
}

run_test test_blame_basic