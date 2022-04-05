.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotwebd

.include "../got-version.mk"

PROG=		gotwebtest
SRCS=		gotwebtest.c got_operations.c utils.c \
		blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		utf8.c inflate.c buf.c rcsutil.c diff3.c \
		lockfile.c deflate.c object_create.c delta_cache.c \
		gotconfig.c diff_main.c diff_atomize_text.c diff_myers.c \
		diff_output.c diff_output_plain.c diff_output_unidiff.c \
		diff_output_edscript.c diff_patience.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${CURDIR}/../gotwebd

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lc_p
.else
LDADD = -lutil -lz
.endif
DPADD = ${LIBZ} ${LIBUTIL}

NOMAN = Yes

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

dist:
	mkdir ../got-${GOT_VERSION}/got
	cp ${SRCS} ${MAN} ../got-${GOT_VERSION}/got

.include <bsd.prog.mk>
