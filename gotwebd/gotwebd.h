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
#include <pthread.h>
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
	IMSG_GET_INFO_GOTWEBD_REQUEST = IMSG_PROC_MAX,
	IMSG_GET_INFO_GOTWEBD_DATA,
	IMSG_GET_INFO_GOTWEBD_END_DATA,

	IMSG_GET_INFO_GOTWEB_REQUEST,
	IMSG_GET_INFO_GOTWEB_REQUEST_ROOT,
	IMSG_GET_INFO_GOTWEB_DATA,
	IMSG_GET_INFO_GOTWEB_END_DATA,

	IMSG_CFG_SRV,
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
TAILQ_HEAD(fcgi_response_head, fcgi_response);

struct request {
	LIST_ENTRY(request)		 entry;
	struct socket			*sock;
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

	struct fcgi_response_head	 response_head;
	struct env_head			 env;
	int				 env_count;

	pthread_t			 thread;

	uint8_t				 request_started;
};

LIST_HEAD(requests_head, request);

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

struct transport {
	/* TAILQ_HEAD(headers, gw_header)	 gw_headers; */
	struct querystring	*qs;
	char			*next_id;
	char			*next_prev_id;
	char			*prev_id;
	char			*prev_prev_id;
	char			*commit_id;
	unsigned int		 repos_total;
	unsigned int		 next_disp;
	unsigned int		 prev_disp;
};

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
	CLIENT_END,
	CLIENT_START,
	CLIENT_FINISH,
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
	struct requests_head	 requests;
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
	unsigned int	 page;
	char		*path;
	char		*prev;
	char		*prev_prev;
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
	PAGE,
	PATH,
	PREV,
	PREV_PREV,
	QSELEM__MAX,
};

enum query_actions {
	INDEX,
	BLAME,
	BLOB,
	BRIEFS,
	COMMITS,
	DIFF,
	ERR,
	SUMMARY,
	TAG,
	TAGS,
	TREE,
	ACTIONS__MAX,
};

struct repo_dir {
	char			*name;
	char			*owner;
	char			*description;
	char			*url;
	char			*age;
	char			*path;
};

extern struct gotwebd	*gotwebd_env;

/* gotwebd.c */
void	 socket_rlimit(int);

/* sockets.c */
void	 sockets(struct privsep *, struct privsep_proc *);
void	 sockets_shutdown(void);
void	 sockets_purge(struct gotwebd *);
void	 sockets_parse_sockets(struct gotwebd *);
void	 sockets_socket_accept(int, short, void *);
int	 sockets_privinit(struct gotwebd *, struct socket *);

/* gotweb.c */
void	 gotweb_process_request(struct request *);
void	 gotweb_free_transport(struct transport *);
const struct got_error	*gotweb_get_time_str(char **, time_t, int);
const struct got_error	*gotweb_init_transport(struct transport **);

/* parse.y */
int	 parse_config(const char *, struct gotwebd *);
int	 cmdline_symset(char *);

/* fcgi.c */
void	 fcgi_request(int, short, void *);
void	 fcgi_add_response(struct request *, struct fcgi_response *);
void	 fcgi_timeout(int, short, void *);
void	 fcgi_cleanup_request(struct request *);
void	 fcgi_create_end_record(struct request *);
void	 dump_fcgi_record(const char *, struct fcgi_record_header *);
int	 fcgi_gen_response(struct request *, char *);

/* got_operations.c */
const struct got_error	*got_tests(struct querystring *);
const struct got_error	*got_get_repo_owner(char **, struct server *, char *);
const struct got_error	*got_get_repo_age(char **, struct server *, char *,
    const char *, int);

/* config.c */
int	 config_setserver(struct gotwebd *, struct server *);
int	 config_getserver(struct gotwebd *, struct imsg *);
int	 config_setsock(struct gotwebd *, struct socket *);
int	 config_getsock(struct gotwebd *, struct imsg *);
int	 config_setfd(struct gotwebd *, struct priv_fd *);
int	 config_getfd(struct gotwebd *, struct imsg *);
int	 config_getcfg(struct gotwebd *, struct imsg *);
int	 config_init(struct gotwebd *);
int	 config_setreset(struct gotwebd *, unsigned int);
int	 config_getreset(struct gotwebd *, struct imsg *);

void	 config_purge(struct gotwebd *, unsigned int);
