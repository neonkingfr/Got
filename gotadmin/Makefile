.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		gotadmin
SRCS=		gotadmin.c \
		deflate.c delta.c delta_cache.c deltify.c error.c gotconfig.c \
		inflate.c lockfile.c object.c object_cache.c object_create.c \
		object_idset.c object_parse.c opentemp.c pack.c pack_create.c \
		path.c privsep.c reference.c repository.c repository_admin.c \
		worktree_open.c sha1.c bloom.c murmurhash2.c ratelimit.c
MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p
.else
LDADD = -lutil -lz -lm
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
