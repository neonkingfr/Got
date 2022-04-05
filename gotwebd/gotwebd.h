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

#include <netinet/in.h>
#include <net/if.h>

#include <limits.h>
#include <stdio.h>

#ifdef DEBUG
#define dprintf(x...)   do { log_debug(x); } while(0)
#else
#define dprintf(x...)
#endif /* DEBUG */

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/* GOTWEBD DEFAULTS */
#define GOTWEBD_CONF		 "/etc/gotwebd.conf"

#define GOTWEBD_USER		 "www"

#define GOTWEBD_MAXCLIENTS	 1024
#define GOTWEBD_MAXTEXT		 511
#define GOTWEBD_MAXNAME		 64
#define GOTWEBD_MAXPORT		 6
#define GOTWEBD_NUMPROC		 3
#define GOTWEBD_MAXIFACE	 16

/* GOTWEB DEFAULTS */
#define MAX_QUERYSTRING		 2048
#define MAX_DOCUMENT_ROOT	 255

#define GOTWEB_GOT_DIR		 ".got"
#define GOTWEB_GIT_DIR		 ".git"

#define D_HTTPD_CHROOT		 "/var/www"
#define D_UNIX_SOCKET		 "/run/gotweb.sock"
#define D_FCGI_PORT		 "9000"
#define D_GOTPATH		 "/got/public"
#define D_SITENAME		 "Gotweb"
#define D_SITEOWNER		 "Got Owner"
#define D_SITELINK		 "Repos"
#define D_GOTLOGO		 "got.png"
#define D_GOTURL		 "https://gameoftrees.org"
#define D_GOTWEBCSS		 "gotweb.css"

#define D_SHOWROWNER		 1
#define D_SHOWSOWNER		 1
#define D_SHOWAGE		 1
#define D_SHOWDESC		 1
#define D_SHOWURL		 1
#define D_MAXREPO		 0
#define D_MAXREPODISP		 25
#define D_MAXSLCOMMDISP		 10
#define D_MAXCOMMITDISP		 25

#define TIMEOUT_DEFAULT		 120

#define FCGI_CONTENT_SIZE	 65535
#define FCGI_PADDING_SIZE	 255
#define FCGI_RECORD_SIZE	 \
    (sizeof(struct fcgi_record_header) + FCGI_CONTENT_SIZE + FCGI_PADDING_SIZE)

#define FCGI_ALIGNMENT		 8
#define FCGI_ALIGN(n)		 \
    (((n) + (FCGI_ALIGNMENT - 1)) & ~(FCGI_ALIGNMENT - 1))

#define FD_RESERVE		 5
#define FD_NEEDED		 6

#define FCGI_BEGIN_REQUEST	 1
#define FCGI_ABORT_REQUEST	 2
#define FCGI_END_REQUEST	 3
#define FCGI_PARAMS		 4
#define FCGI_STDIN		 5
#define FCGI_STDOUT		 6
#define FCGI_STDERR		 7
#define FCGI_DATA		 8
#define FCGI_GET_VALUES		 9
#define FCGI_GET_VALUES_RESULT	10
#define FCGI_UNKNOWN_TYPE	11
#define FCGI_MAXTYPE		(FCGI_UNKNOWN_TYPE)

#define FCGI_REQUEST_COMPLETE	0
#define FCGI_CANT_MPX_CONN	1
#define FCGI_OVERLOADED		2
#define FCGI_UNKNOWN_ROLE	3

enum imsg_type {
	IMSG_CFG_SRV = IMSG_PROC_MAX,
	IMSG_CFG_SOCK,
	IMSG_CFG_FD,
	IMSG_CFG_DONE,
	IMSG_CTL_START,
};

struct env_val {
	SLIST_ENTRY(env_val)	 entry;
	char			*val;
};
SLIST_HEAD(env_head, env_val);

struct fcgi_record_header {
	uint8_t		version;
	uint8_t		type;
	uint16_t	id;
	uint16_t	content_len;
	uint8_t		padding_len;
	uint8_t		reserved;
}__packed;

struct fcgi_response {
	TAILQ_ENTRY(fcgi_response)	entry;
	uint8_t				data[FCGI_RECORD_SIZE];
	size_t				data_pos;
	size_t				data_len;
};

struct repo_dir {
	char			*name;
	char			*owner;
	char			*description;
	char			*url;
	char			*age;
	char			*path;
};

struct repo_tag {
	TAILQ_ENTRY(repo_tag)	 entry;
	char			*commit_id;
	char			*tag_name;
	char			*tag_commit;
	char			*tagger;
	time_t			 tagger_time;
};

struct repo_commit {
	TAILQ_ENTRY(repo_commit)	 entry;
	char			*path;
	char			*refs_str;
	char			*commit_id; /* id_str1 */
	char			*parent_id; /* id_str2 */
	char			*tree_id;
	char			*author;
	char			*committer;
	char			*commit_msg;
	time_t			 committer_time;
};

struct got_repository;
struct transport {
	TAILQ_HEAD(repo_commits_head, repo_commit)	 repo_commits;
	TAILQ_HEAD(repo_tags_head, repo_tag)		 repo_tags;
	struct got_repository	*repo;
	struct repo_dir		*repo_dir;
	struct querystring	*qs;
	const char		*headref;
	char			*next_id;
	char			*prev_id;
	unsigned int		 repos_total;
	unsigned int		 next_disp;
	unsigned int		 prev_disp;
	unsigned int		 tag_count;
};

struct request {
	struct socket			*sock;
	struct server			*srv;
	struct transport		*t;
	struct event			 ev;
	struct event			 tmo;

	uint16_t			 id;
	int				 fd;
	int				 priv_fd;

	uint8_t				 buf[FCGI_RECORD_SIZE];
	size_t				 buf_pos;
	size_t				 buf_len;

	char				 querystring[MAX_QUERYSTRING];
	char				 http_host[GOTWEBD_MAXTEXT];
	char				 document_root[MAX_DOCUMENT_ROOT];

	struct env_head			 env;
	int				 env_count;

	uint8_t				 request_started;
};

struct fcgi_begin_request_body {
	uint16_t	role;
	uint8_t		flags;
	uint8_t		reserved[5];
}__packed;

struct fcgi_end_request_body {
	uint32_t	app_status;
	uint8_t		protocol_status;
	uint8_t		reserved[3];
}__packed;

struct address {
	TAILQ_ENTRY(address)	 entry;
	struct sockaddr_storage	 ss;
	int			 ipproto;
	int			 prefixlen;
	in_port_t		 port;
	char			 ifname[IFNAMSIZ];
};
TAILQ_HEAD(addresslist, address);

struct server {
	TAILQ_ENTRY(server)	 entry;
	struct addresslist	*al;

	char		 name[GOTWEBD_MAXTEXT];

	char		 repos_path[PATH_MAX];
	char		 site_name[GOTWEBD_MAXNAME];
	char		 site_owner[GOTWEBD_MAXNAME];
	char		 site_link[GOTWEBD_MAXTEXT];
	char		 logo[GOTWEBD_MAXTEXT];
	char		 logo_url[GOTWEBD_MAXTEXT];
	char		 custom_css[PATH_MAX];

	size_t		 max_repos;
	size_t		 max_repos_display;
	size_t		 max_commits_display;

	int		 show_site_owner;
	int		 show_repo_owner;
	int		 show_repo_age;
	int		 show_repo_description;
	int		 show_repo_cloneurl;

	int		 unix_socket;
	char		 unix_socket_name[PATH_MAX];

	int		 fcgi_socket;
	char		 fcgi_socket_bind[GOTWEBD_MAXTEXT];
	in_port_t	 fcgi_socket_port;
};
TAILQ_HEAD(serverlist, server);

enum client_action {
	CLIENT_CONNECT,
	CLIENT_DISCONNECT,
};

enum sock_type {
	UNIX,
	FCGI,
};

struct priv_fd {
	TAILQ_ENTRY(priv_fd)	 entry;
	int			 sock_id;
	int			 fd;
};
TAILQ_HEAD(priv_fds, priv_fd);

struct socket_conf {
	struct addresslist	*al;

	char		 name[GOTWEBD_MAXTEXT];
	char		 srv_name[GOTWEBD_MAXTEXT];

	int		 id;
	int		 child_id;
	int		 parent_id;

	int		 ipv4;
	int		 ipv6;

	int		 type;
	char		 unix_socket_name[PATH_MAX];
	in_port_t	 fcgi_socket_port;
};

struct socket {
	TAILQ_ENTRY(socket)	 entry;
	struct socket_conf	 conf;

	int		  fd;
	int		  priv_fd;

	struct event	  evt;
	struct event	  ev;
	struct event	  pause;

	int		  client_status;
};
TAILQ_HEAD(socketlist, socket);

struct gotwebd {
	struct serverlist	*servers;
	struct socketlist	*sockets;
	struct priv_fds		*priv_fds;

	struct privsep	*gotwebd_ps;
	const char	*gotwebd_conffile;

	int		 gotwebd_debug;
	int		 gotwebd_verbose;
	int		 gotwebd_noaction;

	uint16_t	 prefork_gotwebd;
	int		 gotwebd_reload;

	int		 server_cnt;

	char		 httpd_chroot[PATH_MAX];

	int		 unix_socket;
	char		 unix_socket_name[PATH_MAX];

	int		 fcgi_socket;
	char		 fcgi_socket_bind[GOTWEBD_MAXTEXT];
	in_port_t	 fcgi_socket_port;
};

struct querystring {
	uint8_t		 action;
	char		*commit;
	char		*file;
	char		*folder;
	char		*headref;
	unsigned int	 index_page;
	char		*index_page_str;
	char		*path;
};

struct querystring_keys {
	const char	*name;
	int		 element;
};

struct action_keys {
	const char	*name;
	int		 action;
};

enum querystring_elements {
	ACTION,
	COMMIT,
	RFILE,
	FOLDER,
	HEADREF,
	INDEX_PAGE,
	PATH,
	QSELEM__MAX,
};

enum query_actions {
	BLAME,
	BLOB,
	BRIEFS,
	COMMITS,
	DIFF,
	ERR,
	INDEX,
	SUMMARY,
	TAG,
	TAGS,
	TREE,
	ACTIONS__MAX,
};

extern struct gotwebd	*gotwebd_env;

/* sockets.c */
void sockets(struct privsep *, struct privsep_proc *);
void sockets_shutdown(void);
void sockets_parse_sockets(struct gotwebd *);
void sockets_socket_accept(int, short, void *);
int sockets_privinit(struct gotwebd *, struct socket *);

/* gotweb.c */
const struct got_error *gotweb_get_time_str(char **, time_t, int);
const struct got_error *gotweb_init_transport(struct transport **);
const struct got_error *gotweb_escape_html(char **, const char *);
void gotweb_free_repo_commit(struct repo_commit *);
void gotweb_free_repo_tag(struct repo_tag *);
void gotweb_process_request(struct request *);
void gotweb_free_transport(struct transport *);

/* parse.y */
int parse_config(const char *, struct gotwebd *);
int cmdline_symset(char *);

/* fcgi.c */
void fcgi_request(int, short, void *);
void fcgi_timeout(int, short, void *);
void fcgi_cleanup_request(struct request *);
void fcgi_create_end_record(struct request *);
void dump_fcgi_record(const char *, struct fcgi_record_header *);
int fcgi_gen_response(struct request *, char *);

/* got_operations.c */
const struct got_error *got_tests(struct querystring *);
const struct got_error *got_get_repo_owner(char **, struct request *, char *);
const struct got_error *got_get_repo_age(char **, struct request *, char *,
    const char *, int);
const struct got_error *got_get_repo_commits(struct request *, int);
const struct got_error *got_get_repo_tags(struct request *, int);
const struct got_error *got_output_diff(struct request *);

/* config.c */
int config_setserver(struct gotwebd *, struct server *);
int config_getserver(struct gotwebd *, struct imsg *);
int config_setsock(struct gotwebd *, struct socket *);
int config_getsock(struct gotwebd *, struct imsg *);
int config_setfd(struct gotwebd *, struct priv_fd *);
int config_getfd(struct gotwebd *, struct imsg *);
int config_getcfg(struct gotwebd *, struct imsg *);
int config_init(struct gotwebd *);
