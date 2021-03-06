#!/bin/sh
#
# Copyright (c) 2022 Omar Polo <op@openbsd.org>
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

test_patch_simple_add_file() {
	local testroot=`test_init patch_simple_add_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- /dev/null
+++ eta
@@ -0,0 +1 @@
+eta
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo "A  eta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo eta > $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
	fi
	test_done $testroot $ret
}

test_patch_simple_rm_file() {
	local testroot=`test_init patch_simple_rm_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ /dev/null
@@ -1 +0,0 @@
-alpha
EOF

	echo "D  alpha" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	if [ -f $testroot/wt/alpha ]; then
		ret=1
		echo "alpha still exists!"
	fi
	test_done $testroot $ret
}

test_patch_simple_edit_file() {
	local testroot=`test_init patch_simple_edit_file`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1 @@
-alpha
+alpha is my favourite character
EOF

	echo "M  alpha" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo 'alpha is my favourite character' > $testroot/wt/alpha.expected
	cmp -s $testroot/wt/alpha.expected $testroot/wt/alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/alpha.expected $testroot/wt/alpha
	fi
	test_done $testroot $ret
}

test_patch_prepend_line() {
	local testroot=`test_init patch_prepend_line`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
+hatsuseno
 alpha
EOF

	echo "M  alpha" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo hatsuseno > $testroot/wt/alpha.expected
	echo alpha    >> $testroot/wt/alpha.expected
	cmp -s $testroot/wt/alpha.expected $testroot/wt/alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/alpha.expected $testroot/wt/alpha
	fi
	test_done $testroot $ret
}

test_patch_replace_line() {
	local testroot=`test_init patch_replace_line`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	jot 10 > $testroot/wt/numbers
	(cd $testroot/wt/ && got add numbers && got ci -m 'add numbers') \
		>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- numbers
+++ numbers
@@ -3,7 +3,7 @@
 3
 4
 5
-6
+foo
 7
 8
 9
EOF

	echo "M  numbers" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	jot 10 | sed 's/6/foo/' > $testroot/wt/numbers.expected
	cmp -s $testroot/wt/numbers.expected $testroot/wt/numbers
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/numbers.expected $testroot/wt/numbers
	fi
	test_done $testroot $ret
}

test_patch_multiple_hunks() {
	local testroot=`test_init patch_replace_multiple_hunks`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	jot 100 > $testroot/wt/numbers
	(cd $testroot/wt/ && got add numbers && got ci -m 'add numbers') \
		>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- numbers
+++ numbers
@@ -3,7 +3,7 @@
 3
 4
 5
-6
+foo
 7
 8
 9
@@ -57,7 +57,7 @@
 57
 58
 59
-60
+foo foo
 61
 62
 63
@@ -98,3 +98,6 @@
 98
 99
 100
+101
+102
+...
EOF

	echo "M  numbers" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	jot 100 | sed -e 's/^6$/foo/' -e 's/^60$/foo foo/' \
		> $testroot/wt/numbers.expected
	echo "101" >> $testroot/wt/numbers.expected
	echo "102" >> $testroot/wt/numbers.expected
	echo "..." >> $testroot/wt/numbers.expected

	cmp -s $testroot/wt/numbers.expected $testroot/wt/numbers
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/numbers.expected $testroot/wt/numbers
	fi
	test_done $testroot $ret
}

test_patch_multiple_files() {
	local testroot=`test_init patch_multiple_files`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha	Mon Mar  7 19:02:07 2022
+++ alpha	Mon Mar  7 19:01:53 2022
@@ -1 +1,3 @@
+new
 alpha
+available
--- beta	Mon Mar  7 19:02:11 2022
+++ beta	Mon Mar  7 19:01:46 2022
@@ -1 +1,3 @@
 beta
+was
+improved
--- gamma/delta	Mon Mar  7 19:02:17 2022
+++ gamma/delta	Mon Mar  7 19:01:37 2022
@@ -1 +1 @@
-delta
+delta new
EOF

	echo "M  alpha" > $testroot/stdout.expected
	echo "M  beta" >> $testroot/stdout.expected
	echo "M  gamma/delta" >> $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	printf 'new\nalpha\navailable\n' > $testroot/wt/alpha.expected
	printf 'beta\nwas\nimproved\n' > $testroot/wt/beta.expected
	printf 'delta new\n' > $testroot/wt/gamma/delta.expected

	for f in alpha beta gamma/delta; do
		cmp -s $testroot/wt/$f.expected $testroot/wt/$f
		ret=$?
		if [ $ret -ne 0 ]; then
			diff -u $testroot/wt/$f.expected $testroot/wt/$f
			test_done $testroot $ret
			return 1
		fi
	done

	test_done $testroot 0
}

test_patch_dont_apply() {
	local testroot=`test_init patch_dont_apply`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	jot 100 > $testroot/wt/numbers
	(cd $testroot/wt && got add numbers && got commit -m 'add numbers') \
		>/dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
+hatsuseno
 alpha something
--- numbers
+++ /dev/null
@@ -1,9 +0,0 @@
-1
-2
-3
-4
-5
-6
-7
-8
-9
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout 2> /dev/null
	ret=$?
	if [ $ret -eq 0 ]; then # should fail
		test_done $testroot 1
		return 1
	fi

	cat <<EOF > $testroot/stdout.expected
#  alpha
@@ -1,1 +1,2 @@ hunk failed to apply
#  numbers
@@ -1,9 +0,0 @@ hunk failed to apply
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done $testroot $ret
}

test_patch_malformed() {
	local testroot=`test_init patch_malformed`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	# missing "@@"
	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2
+hatsuseno
 alpha
EOF

	echo -n > $testroot/stdout.expected
	echo "got: malformed patch" > $testroot/stderr.expected

	(cd $testroot/wt && got patch patch) \
		 > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got managed to apply an invalid patch"
		test_done $testroot 1
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done $testroot $ret
		return 1
	fi

	# wrong first character
	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
+hatsuseno
alpha
EOF

	(cd $testroot/wt && got patch patch) \
		 > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "got managed to apply an invalid patch"
		test_done $testroot 1
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done $testroot $ret
		return 1
	fi

	test_done $testroot $ret
}

test_patch_no_patch() {
	local testroot=`test_init patch_no_patch`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
hello world!
...

some other nonsense
...

there's no patch in here!
EOF

	echo -n > $testroot/stdout.expected
	echo "got: no patch found" > $testroot/stderr.expected

	(cd $testroot/wt && got patch patch) \
		 > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then # should fail
		test_done $testroot 1
		return 1
	fi
	
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done $testroot $ret
		return 1
	fi

	test_done $testroot $ret
}

test_patch_equals_for_context() {
	local testroot=`test_init patch_prepend_line`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
+hatsuseno
=alpha
EOF

	echo "M  alpha" > $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo hatsuseno > $testroot/wt/alpha.expected
	echo alpha    >> $testroot/wt/alpha.expected
	cmp -s $testroot/wt/alpha.expected $testroot/wt/alpha
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/alpha.expected $testroot/wt/alpha
	fi
	test_done $testroot $ret
}

test_patch_rename() {
	local testroot=`test_init patch_rename`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
diff --git a/alpha b/eta
--- a/alpha
+++ b/eta
@@ -0,0 +0,0 @@
EOF

	echo 'D  alpha' > $testroot/stdout.expected
	echo 'A  eta'  >> $testroot/stdout.expected

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	if [ -f $testroot/wt/alpha ]; then
		echo "alpha was not removed" >&2
		test_done $testroot 1
		return 1
	fi
	if [ ! -f $testroot/wt/eta ]; then
		echo "eta was not created" >&2
		test_done $testroot 1
		return 1
	fi

	echo alpha > $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
		test_done $testroot $ret
		return 1
	fi

	# revert the changes and try again with a rename + edit
	(cd $testroot/wt && got revert alpha eta) > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi
	rm $testroot/wt/eta

	cat <<EOF > $testroot/wt/patch
diff --git a/alpha b/eta
--- a/alpha
+++ b/eta
@@ -1 +1,2 @@
 alpha
+but now is eta
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	if [ -f $testroot/wt/alpha ]; then
		echo "alpha was not removed" >&2
		test_done $testroot 1
		return 1
	fi
	if [ ! -f $testroot/wt/eta ]; then
		echo "eta was not created" >&2
		test_done $testroot 1
		return 1
	fi

	echo alpha > $testroot/wt/eta.expected
	echo 'but now is eta' >> $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
	fi
	test_done $testroot $ret
}

test_patch_illegal_status() {
	local testroot=`test_init patch_illegal_status`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	# try to patch an obstructed file, add a versioned one, edit a
	# non existent file and an unversioned one, and remove a
	# non existent file.
	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
 alpha
+was edited
--- /dev/null
+++ beta
@@ -0,0 +1 @@
+beta
--- iota
+++ iota
@@ -1 +1 @@
-iota
+IOTA
--- kappa
+++ kappa
@@ -1 +1 @@
-kappa
+KAPPA
--- lambda
+++ /dev/null
@@ -1 +0,0 @@
-lambda
EOF

	echo kappa > $testroot/wt/kappa
	rm $testroot/wt/alpha
	mkdir $testroot/wt/alpha

	(cd $testroot/wt && got patch patch) > $testroot/stdout \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "edited a missing file" >&2
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/stdout.expected
#  alpha
#  beta
#  iota
#  kappa
#  lambda
EOF

	cat <<EOF > $testroot/stderr.expected
got: alpha: file has unexpected status
got: beta: file has unexpected status
got: iota: No such file or directory
got: kappa: file has unexpected status
got: lambda: No such file or directory
got: patch failed to apply
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got status) > $testroot/stdout
	cat <<EOF > $testroot/stdout.expected
~  alpha
?  kappa
?  patch
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done $testroot $ret
}

test_patch_nop() {
	local testroot=`test_init patch_nop`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1 @@
-alpha
+cafe alpha
--- beta
+++ /dev/null
@@ -1 +0,0 @@
-beta
diff --git a/gamma/delta b/gamma/delta.new
--- gamma/delta
+++ gamma/delta.new
@@ -1 +1 @@
-delta
+delta updated and renamed!
EOF

	(cd $testroot/wt && got patch -n patch)
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	# remove the patch to avoid the ? entry
	rm $testroot/wt/patch

	(cd $testroot/wt && got status) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo -n > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done $testroot $ret
}

test_patch_preserve_perm() {
	local testroot=`test_init patch_preserve_perm`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	chmod +x $testroot/wt/alpha
	(cd $testroot/wt && got commit -m 'alpha executable') > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha
+++ alpha
@@ -1 +1,2 @@
 alpha
+was edited
EOF

	(cd $testroot/wt && got patch patch) > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	if [ ! -x $testroot/wt/alpha ]; then
		echo "alpha is no more executable!" >&2
		test_done $testroot 1
		return 1
	fi
	test_done $testroot 0
}

test_patch_create_dirs() {
	local testroot=`test_init patch_create_dirs`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- /dev/null
+++ iota/kappa/lambda
@@ -0,0 +1 @@
+lambda
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo 'A  iota/kappa/lambda' >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	if [ ! -f $testroot/wt/iota/kappa/lambda ]; then
		echo "file not created!" >&2
		test_done $testroot $ret
		return 1
	fi
	test_done $testroot 0
}

test_patch_with_offset() {
	local testroot=`test_init patch_with_offset`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- numbers
+++ numbers
@@ -47,7 +47,7 @@
 47
 48
 49
-50
+midway tru it!
 51
 52
 53
@@ -87,7 +87,7 @@
 87
 88
 89
-90
+almost there!
 91
 92
 93
EOF

	jot 100 > $testroot/wt/numbers
	ed $testroot/wt/numbers <<EOF > /dev/null 2> /dev/null
1,10d
50r !jot 20
w
q
EOF

	(cd $testroot/wt && got add numbers && got commit -m '+numbers') \
		> /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot/wt $ret
		return 1
	fi

	cat <<EOF > $testroot/stdout.expected
M  numbers
@@ -47,7 +47,7 @@ applied with offset -10
@@ -87,7 +87,7 @@ applied with offset 10
EOF

	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done $testroot $ret
}

test_patch_prefer_new_path() {
	local testroot=`test_init patch_orig`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- alpha.orig
+++ alpha
@@ -1 +1,2 @@
 alpha
+was edited
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo 'M  alpha' > $testroot/stdout.expected	
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
	fi
	test_done $testroot $ret
}

test_patch_no_newline() {
	local testroot=`test_init patch_no_newline`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- /dev/null
+++ eta
@@ -0,0 +1 @@
+eta
\ No newline at end of file
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo "A  eta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo -n eta > $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got commit -m 'add eta') > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- eta
+++ eta
@@ -1 +1 @@
-eta
\ No newline at end of file
+ETA
\ No newline at end of file
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo "M  eta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo -n ETA > $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got commit -m 'edit eta') > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- eta
+++ eta
@@ -1 +1 @@
-ETA
\ No newline at end of file
+eta
EOF

	(cd $testroot/wt && got patch patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo "M  eta" > $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	echo eta > $testroot/wt/eta.expected
	cmp -s $testroot/wt/eta.expected $testroot/wt/eta
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/wt/eta.expected $testroot/wt/eta
	fi
	test_done $testroot $ret
}

test_patch_strip() {
	local testroot=`test_init patch_strip`

	got checkout $testroot/repo $testroot/wt > /dev/null
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	cat <<EOF > $testroot/wt/patch
--- foo/bar/alpha.orig
+++ foo/bar/alpha
@@ -1 +1 @@
-alpha
+ALPHA
EOF

	(cd $testroot/wt && got patch -p2 patch) > $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	echo "M  alpha" >> $testroot/stdout.expected
	cmp -s $testroot/stdout.expected $testroot/stdout
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stdout.expected $testroot/stdout
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got revert alpha) > /dev/null 2>&1
	ret=$?
	if [ $ret -ne 0 ]; then
		test_done $testroot $ret
		return 1
	fi

	(cd $testroot/wt && got patch -p3 patch) \
		2> $testroot/stderr
	ret=$?
	if [ $ret -eq 0 ]; then
		echo "stripped more components than available!"
		test_done $testroot 1
		return 1
	fi

	cat <<EOF > $testroot/stderr.expected
got: can't strip 1 path-components from foo/bar/alpha: bad path
EOF

	cmp -s $testroot/stderr.expected $testroot/stderr
	ret=$?
	if [ $ret -ne 0 ]; then
		diff -u $testroot/stderr.expected $testroot/stderr
	fi
	test_done $testroot 0
}

test_parseargs "$@"
run_test test_patch_simple_add_file
run_test test_patch_simple_rm_file
run_test test_patch_simple_edit_file
run_test test_patch_prepend_line
run_test test_patch_replace_line
run_test test_patch_multiple_hunks
run_test test_patch_multiple_files
run_test test_patch_dont_apply
run_test test_patch_malformed
run_test test_patch_no_patch
run_test test_patch_equals_for_context
run_test test_patch_rename
run_test test_patch_illegal_status
run_test test_patch_nop
run_test test_patch_preserve_perm
run_test test_patch_create_dirs
run_test test_patch_with_offset
run_test test_patch_prefer_new_path
run_test test_patch_no_newline
run_test test_patch_strip
