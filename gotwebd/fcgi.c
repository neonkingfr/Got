/*
 * Copyright (c) 2020-2021 Tracey Emery <tracey@traceyemery.net>
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

#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proc.h"
#include "gotwebd.h"

size_t	 fcgi_parse_record(uint8_t *, size_t, struct request *);
void	 fcgi_parse_begin_request(uint8_t *, uint16_t, struct request *,
	    uint16_t);
void	 fcgi_parse_params(uint8_t *, uint16_t, struct request *, uint16_t);

void	 fcgi_create_end_record(struct request *);
void	 fcgi_cleanup_request(struct request *);

void	 dump_fcgi_record(const char *, struct fcgi_record_header *);
void	 dump_fcgi_record_header(const char *, struct fcgi_record_header *);
void	 dump_fcgi_begin_request_body(const char *,
	    struct fcgi_begin_request_body *);
void	 dump_fcgi_end_request_body(const char *,
	    struct fcgi_end_request_body *);

extern int	 cgi_inflight;

void
fcgi_request(int fd, short events, void *arg)
{
	struct request *c = arg;
	ssize_t n;
	size_t parsed = 0;

	n = read(fd, c->buf + c->buf_pos + c->buf_len,
	    FCGI_RECORD_SIZE - c->buf_pos-c->buf_len);

	switch (n) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			return;
		default:
			goto fail;
		}
		break;

	case 0:
		log_debug("closed connection");
		goto fail;
	default:
		break;
	}

	c->buf_len += n;

	/*
	 * Parse the records as they are received. Per the FastCGI
	 * specification, the server need only receive the FastCGI
	 * parameter records in full; it is free to begin execution
	 * at that point, which is what happens here.
	 */
	do {
		parsed = fcgi_parse_record(c->buf + c->buf_pos, c->buf_len, c);
		c->buf_pos += parsed;
		c->buf_len -= parsed;
	} while (parsed > 0 && c->buf_len > 0);

	/* Make space for further reads */
	if (c->buf_len > 0) {
		bcopy(c->buf + c->buf_pos, c->buf, c->buf_len);
		c->buf_pos = 0;
	}
	return;
fail:
	fcgi_cleanup_request(c);
}

size_t
fcgi_parse_record(uint8_t *buf, size_t n, struct request *c)
{
	struct fcgi_record_header *h;

	if (n < sizeof(struct fcgi_record_header))
		 return 0;

	h = (struct fcgi_record_header*) buf;

	dump_fcgi_record("", h);

	if (n < sizeof(struct fcgi_record_header) + ntohs(h->content_len)
	    + h->padding_len)
		 return 0;

	if (h->version != 1)
		log_warn("wrong version");

	switch (h->type) {
	case FCGI_BEGIN_REQUEST:
		fcgi_parse_begin_request(buf +
		    sizeof(struct fcgi_record_header),
		    ntohs(h->content_len), c, ntohs(h->id));
		break;
	case FCGI_PARAMS:
		fcgi_parse_params(buf + sizeof(struct fcgi_record_header),
		    ntohs(h->content_len), c, ntohs(h->id));
		break;
	case FCGI_STDIN:
		fcgi_create_end_record(c);
		break;
	case FCGI_ABORT_REQUEST:
		fcgi_create_end_record(c);
		fcgi_cleanup_request(c);
		break;
	default:
		log_warn("unimplemented type %d", h->type);
		break;
	}

	return (sizeof(struct fcgi_record_header) + ntohs(h->content_len)
	    + h->padding_len);
}

void
fcgi_parse_begin_request(uint8_t *buf, uint16_t n,
    struct request *c, uint16_t id)
{
	/* XXX -- FCGI_CANT_MPX_CONN */
	if (c->request_started) {
		log_warn("unexpected FCGI_BEGIN_REQUEST, ignoring");
		return;
	}

	if (n != sizeof(struct fcgi_begin_request_body)) {
		log_warn("wrong size %d != %lu", n,
		    sizeof(struct fcgi_begin_request_body));
		return;
	}

	c->request_started = 1;

	c->id = id;
	SLIST_INIT(&c->env);
	c->env_count = 0;
}

void
fcgi_parse_params(uint8_t *buf, uint16_t n, struct request *c, uint16_t id)
{
	struct env_val *env_entry;
	uint32_t name_len, val_len;
	uint8_t *sd, *dr_buf;

	if (!c->request_started) {
		log_warn("FCGI_PARAMS without FCGI_BEGIN_REQUEST, ignoring");
		return;
	}

	if (c->id != id) {
		log_warn("unexpected id, ignoring");
		return;
	}

	if (n == 0) {
		gotweb_process_request(c);
		return;
	}

	while (n > 0) {
		if (buf[0] >> 7 == 0) {
			name_len = buf[0];
			n--;
			buf++;
		} else {
			if (n > 3) {
				name_len = ((buf[0] & 0x7f) << 24) +
				    (buf[1] << 16) + (buf[2] << 8) + buf[3];
				n -= 4;
				buf += 4;
			} else
				return;
		}

		if (n > 0) {
			if (buf[0] >> 7 == 0) {
				val_len = buf[0];
				n--;
				buf++;
			} else {
				if (n > 3) {
					val_len = ((buf[0] & 0x7f) << 24) +
					    (buf[1] << 16) + (buf[2] << 8) +
					     buf[3];
					n -= 4;
					buf += 4;
				} else
					return;
			}
		} else
			return;

		if (n < name_len + val_len)
			return;

		if ((env_entry = malloc(sizeof(struct env_val))) == NULL) {
			log_warn("cannot allocate env_entry");
			return;
		}

		if ((env_entry->val = calloc(sizeof(char), name_len + val_len +
		    2)) == NULL) {
			log_warn("cannot allocate env_entry->val");
			free(env_entry);
			return;
		}

		bcopy(buf, env_entry->val, name_len);
		buf += name_len;
		n -= name_len;

		env_entry->val[name_len] = '\0';
		if (val_len < MAX_QUERYSTRING && strcmp(env_entry->val,
		    "QUERY_STRING") == 0 && c->querystring[0] == '\0') {
			bcopy(buf, c->querystring, val_len);
			c->querystring[val_len] = '\0';
		}
		if (val_len < GOTWEBD_MAXTEXT && strcmp(env_entry->val,
		    "HTTP_HOST") == 0 && c->http_host[0] == '\0') {

			/*
			 * lazily get subdomain
			 * will only get domain if no subdomain exists
			 * this can still work if gotweb server name is the same
			 */
			sd = strchr(buf, '.');
			if (sd)
				*sd = '\0';

			bcopy(buf, c->http_host, val_len);
			c->http_host[val_len] = '\0';
		}
		if (val_len < MAX_DOCUMENT_ROOT && strcmp(env_entry->val,
		    "DOCUMENT_ROOT") == 0 && c->document_root[0] == '\0') {

			/* drop first char, as it's always / */
			dr_buf = &buf[1];

			bcopy(dr_buf, c->document_root, val_len - 1);
			c->document_root[val_len] = '\0';
		}
		env_entry->val[name_len] = '=';

		bcopy(buf, (env_entry->val) + name_len + 1, val_len);
		buf += val_len;
		n -= val_len;

		SLIST_INSERT_HEAD(&c->env, env_entry, entry);
		log_debug("env[%d], %s", c->env_count, env_entry->val);
		c->env_count++;
	}
}

void
fcgi_response(int fd, short events, void *arg)
{
	struct request *c;
	struct fcgi_record_header *header;
	struct fcgi_response *resp;
	ssize_t n;

	c = arg;

	while ((resp = TAILQ_FIRST(&c->response_head))) {
		header = (struct fcgi_record_header*) resp->data;
		dump_fcgi_record("resp ", header);
		n = write(fd, resp->data + resp->data_pos, resp->data_len);
		if (n == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return;
			fcgi_cleanup_request(c);
			return;
		}
		resp->data_pos += n;
		resp->data_len -= n;
		if (resp->data_len == 0) {
			TAILQ_REMOVE(&c->response_head, resp, entry);
			free(resp);
		}
	}

	if (TAILQ_EMPTY(&c->response_head)) {
		if (c->gotweb_flags == GOT_DONE)
			fcgi_cleanup_request(c);
		else
			event_del(&c->resp_ev);
	}
}

void
fcgi_timeout(int fd, short events, void *arg)
{
	fcgi_cleanup_request((struct request*) arg);
}

void
fcgi_gen_response(struct request *c, char *data)
{
	struct fcgi_response *resp;
	struct fcgi_record_header *header;
	ssize_t n = 0;
	int i, j;

	if ((resp = calloc(1, sizeof(struct fcgi_response))) == NULL) {
		log_warn("cannot malloc fcgi_response");
		return;
	}

	header = (struct fcgi_record_header*) resp->data;
	header->version = 1;
	header->type = FCGI_STDOUT;
	header->id = htons(c->id);
	header->padding_len = 0;
	header->reserved = 0;

	for (i = 0; i < strlen(data); i++) {
		resp->data[i+8] = data[i];
		n++;
	}

	j = i;

	header->content_len = htons(n);
	resp->data_pos = 0;
	resp->data_len = n + sizeof(struct fcgi_record_header);
	fcgi_add_response(c, resp);
}

void
fcgi_add_response(struct request *c, struct fcgi_response *resp)
{
	struct fcgi_record_header *header;
	size_t padded_len;

	header = (struct fcgi_record_header*)resp->data;

	/* The FastCGI spec suggests to align the output buffer */
	padded_len = FCGI_ALIGN(resp->data_len);
	if (padded_len > resp->data_len) {
		/* There should always be FCGI_PADDING_SIZE bytes left */
		if (padded_len > FCGI_RECORD_SIZE)
			log_warn("response too long");
		header->padding_len = padded_len - resp->data_len;
		resp->data_len = padded_len;
	}

	TAILQ_INSERT_TAIL(&c->response_head, resp, entry);
	event_add(&c->resp_ev, NULL);
}

void
fcgi_create_end_record(struct request *c)
{
	struct fcgi_response *resp;
	struct fcgi_record_header *header;
	struct fcgi_end_request_body *end_request;

	if ((resp = calloc(1, sizeof(struct fcgi_response))) == NULL) {
		log_warn("cannot malloc fcgi_response");
		return;
	}
	header = (struct fcgi_record_header*) resp->data;
	header->version = 1;
	header->type = FCGI_END_REQUEST;
	header->id = htons(c->id);
	header->content_len = htons(sizeof(struct
	    fcgi_end_request_body));
	header->padding_len = 0;
	header->reserved = 0;
	end_request = (struct fcgi_end_request_body *) (resp->data +
	    sizeof(struct fcgi_record_header));
	end_request->app_status = htonl(0); /* script_status */
	end_request->protocol_status = FCGI_REQUEST_COMPLETE;
	end_request->reserved[0] = 0;
	end_request->reserved[1] = 0;
	end_request->reserved[2] = 0;
	resp->data_pos = 0;
	resp->data_len = sizeof(struct fcgi_end_request_body) +
	    sizeof(struct fcgi_record_header);
	fcgi_add_response(c, resp);
}

void
fcgi_cleanup_request(struct request *c)
{
	struct fcgi_response *resp;

	evtimer_del(&c->tmo);
	if (event_initialized(&c->ev))
		event_del(&c->ev);
	if (event_initialized(&c->resp_ev))
		event_del(&c->resp_ev);
	close(c->fd);

	while ((resp = TAILQ_FIRST(&c->response_head))) {
		TAILQ_REMOVE(&c->response_head, resp, entry);
		free(resp);
	}

	LIST_REMOVE(c, entry);

	if (! c->inflight_fds_accounted)
		cgi_inflight--;
	free(c);
}

void
dump_fcgi_record(const char *p, struct fcgi_record_header *h)
{
	dump_fcgi_record_header(p, h);

	if (h->type == FCGI_BEGIN_REQUEST)
		dump_fcgi_begin_request_body(p,
		    (struct fcgi_begin_request_body *)(h + 1));
	else if (h->type == FCGI_END_REQUEST)
		dump_fcgi_end_request_body(p,
		    (struct fcgi_end_request_body *)(h + 1));
}

void
dump_fcgi_record_header(const char* p, struct fcgi_record_header *h)
{
	log_debug("%sversion:         %d", p, h->version);
	log_debug("%stype:            %d", p, h->type);
	log_debug("%srequestId:       %d", p, ntohs(h->id));
	log_debug("%scontentLength:   %d", p, ntohs(h->content_len));
	log_debug("%spaddingLength:   %d", p, h->padding_len);
	log_debug("%sreserved:        %d", p, h->reserved);
}

void
dump_fcgi_begin_request_body(const char *p, struct fcgi_begin_request_body *b)
{
	log_debug("%srole             %d", p, ntohs(b->role));
	log_debug("%sflags            %d", p, b->flags);
}

void
dump_fcgi_end_request_body(const char *p, struct fcgi_end_request_body *b)
{
	log_debug("%sappStatus:       %d", p, ntohl(b->app_status));
	log_debug("%sprotocolStatus:  %d", p, b->protocol_status);
}
