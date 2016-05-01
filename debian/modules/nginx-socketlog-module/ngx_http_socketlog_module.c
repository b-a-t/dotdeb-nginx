
/*
 * Copyright (C) 2012 Valery Kholodkov
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#define NGX_SOCKETLOG_OFF			0
#define NGX_SOCKETLOG_ON			1

#define NGX_SOCKETLOG_FACILITY_LOCAL7		23
#define NGX_SOCKETLOG_SEVERITY_INFO		6

typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);

struct ngx_http_log_op_s {
    size_t			len;
    ngx_http_log_op_getlen_pt	getlen;
    ngx_http_log_op_run_pt	run;
    uintptr_t			data;
};

typedef struct {
    ngx_str_t			name;
#if defined nginx_version && nginx_version >= 7018
    ngx_array_t			*flushes;
#endif
    ngx_array_t			*ops;		/* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    ngx_str_t			value;
    ngx_array_t			*lengths;
    ngx_array_t			*values;
} ngx_http_log_tag_template_t;

typedef struct {
    ngx_array_t			formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t			combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;

typedef struct {
    ngx_str_t			name;
    ngx_uint_t			number;
} ngx_syslog_facility_t;

typedef ngx_syslog_facility_t ngx_syslog_severity_t;

typedef struct {
    ngx_str_t			name;
    struct sockaddr		*sockaddr;
    socklen_t			socklen;
    ngx_msec_t			write_timeout;
    ngx_msec_t			connect_timeout;
    ngx_msec_t			reconnect_timeout;
    ngx_msec_t			flush_timeout;

    ngx_bufs_t			bufs;
} ngx_socketlog_peer_conf_t;

typedef struct {
    ngx_array_t			*peers;
} ngx_socketlog_conf_t;

typedef struct {
    ngx_socketlog_peer_conf_t	*conf;
    ngx_peer_connection_t	conn;
    ngx_event_t			flush_timer;
    ngx_event_t			reconnect_timer;
    ngx_log_t			*log;
    ngx_pool_t			*pool;

    ngx_chain_t			*busy;
    ngx_chain_t			*free;

    ngx_uint_t			discarded;
    ngx_uint_t			reconnect_timeout;

    unsigned			connecting:1;
    unsigned			flush_timer_set:1;
} ngx_socketlog_peer_t;

typedef struct {
    ngx_str_t			peer_name;
    ngx_uint_t			peer_idx;
    ngx_http_log_fmt_t		*format;
    ngx_uint_t			bare:1;
} ngx_http_socketlog_t;

typedef struct {
    ngx_array_t			*logs;		/* array of ngx_http_socketlog_t */
    unsigned			enabled;
    ngx_http_log_tag_template_t	*tag;
    ngx_uint_t			facility;
    ngx_uint_t			severity;
} ngx_http_socketlog_conf_t;

static ngx_array_t ngx_socketlog_peers;

static void ngx_socketlog_reconnect_peer(ngx_socketlog_peer_t *p);
static void ngx_http_socketlog_append(ngx_socketlog_peer_t *p, u_char *buf, size_t len);
static void ngx_http_socketlog_send(ngx_socketlog_peer_t *p);
static void ngx_socketlog_flush_handler(ngx_event_t*);

static char *ngx_http_socketlog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_socketlog_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_socketlog_set_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_socketlog_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_socketlog_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_socketlog_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static void *ngx_socketlog_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_socketlog_init(ngx_conf_t *cf);
static ngx_int_t ngx_socketlog_init_process(ngx_cycle_t *cycle);

static ngx_command_t ngx_http_socketlog_commands[] = {

    { ngx_string("access_socketlog"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
			|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1234,
      ngx_http_socketlog_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("socketlog_priority"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_http_socketlog_set_priority,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("socketlog_tag"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_socketlog_set_tag,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_socketlog_conf_t, tag),
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_socketlog_module_ctx = {
    NULL,				/* preconfiguration */
    ngx_http_socketlog_init,		/* postconfiguration */

    NULL,				/* create main configuration */
    NULL,				/* init main configuration */

    NULL,				/* create server configuration */
    NULL,				/* merge server configuration */

    ngx_http_socketlog_create_loc_conf,	/* create location configration */
    ngx_http_socketlog_merge_loc_conf	/* merge location configration */
};

extern ngx_module_t ngx_http_log_module;

ngx_module_t  ngx_http_socketlog_module = {
    NGX_MODULE_V1,
    &ngx_http_socketlog_module_ctx,	/* module context */
    ngx_http_socketlog_commands,	/* module directives */
    NGX_HTTP_MODULE,			/* module type */
    NULL,				/* init master */
    NULL,				/* init module */
    NULL,				/* init process */
    NULL,				/* init thread */
    NULL,				/* exit thread */
    NULL,				/* exit process */
    NULL,				/* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_command_t  ngx_socketlog_commands[] = {

    { ngx_string("socketlog"),
      NGX_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_socketlog_command,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_core_module_t  ngx_socketlog_module_ctx = {
    ngx_string("socketlog"),
    ngx_socketlog_create_conf,
    NULL
};

ngx_module_t  ngx_core_socketlog_module = {
    NGX_MODULE_V1,
    &ngx_socketlog_module_ctx,		/* module context */
    ngx_socketlog_commands,		/* module directives */
    NGX_CORE_MODULE,			/* module type */
    NULL,				/* init master */
    NULL,				/* init module */
    ngx_socketlog_init_process,		/* init process */
    NULL,				/* init thread */
    NULL,				/* exit thread */
    NULL,				/* exit process */
    NULL,				/* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_syslog_facility_t ngx_syslog_facilities[] = {
    { ngx_string("kern"),	0 },
    { ngx_string("user"),	1 },
    { ngx_string("mail"),	2 },
    { ngx_string("daemon"),	3 },
    { ngx_string("auth"),	4 },
    { ngx_string("intern"),	5 },
    { ngx_string("lpr"),	6 },
    { ngx_string("news"),	7 },
    { ngx_string("uucp"),	8 },
    { ngx_string("clock"),	9 },
    { ngx_string("authpriv"),	10 },
    { ngx_string("ftp"),	11 },
    { ngx_string("ntp"),	12 },
    { ngx_string("audit"),	13 },
    { ngx_string("alert"),	14 },
    { ngx_string("cron"),	15 },
    { ngx_string("local0"),	16 },
    { ngx_string("local1"),	17 },
    { ngx_string("local2"),	18 },
    { ngx_string("local3"),	19 },
    { ngx_string("local4"),	20 },
    { ngx_string("local5"),	21 },
    { ngx_string("local6"),	22 },
    { ngx_string("local7"),	23 },
    { ngx_null_string, 0 }
};

static ngx_syslog_severity_t ngx_syslog_severities[] = {
    { ngx_string("emerg"),	0 },
    { ngx_string("alert"),	1 },
    { ngx_string("crit"),	2 },
    { ngx_string("err"),	3 },
    { ngx_string("warning"),	4 },
    { ngx_string("notice"),	5 },
    { ngx_string("info"),	6 },
    { ngx_string("debug"),	7 },
    { ngx_null_string, 0 }
};

/*
 * See RFC 3164 chapter 4.1.2
 */
static char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

ngx_int_t
ngx_http_socketlog_handler(ngx_http_request_t *r)
{
    u_char			*line, *p;
    size_t			len;
    ngx_uint_t			i, l, pri;
    ngx_str_t			tag;
    ngx_http_socketlog_t	*log;
    ngx_http_log_op_t		*op;
    ngx_http_socketlog_conf_t	*slcf;
    time_t			time;
    ngx_tm_t			tm;
    ngx_socketlog_peer_t	**peer;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
		   "http socketlog handler");

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_socketlog_module);

    if(slcf->enabled == NGX_SOCKETLOG_OFF) {
	return NGX_OK;
    }

    if(slcf->logs == NULL) {
	return NGX_OK;
    }

    if(slcf->tag != NULL) {
	if(slcf->tag->lengths == NULL) {
	    tag = slcf->tag->value;
	}
	else {
	    if (ngx_http_script_run(r, &tag, slcf->tag->lengths->elts, 0, slcf->tag->values->elts)
	      == NULL) {
		return NGX_ERROR;
	    }
	}
    }
    else {
	tag.data = (u_char*)"nginx";
	tag.len = sizeof("nginx") - 1;
    }

    time = ngx_time();
//    ngx_gmtime(time, &tm);
    /* emulate localtime() */
    ngx_gmtime(time + ngx_cached_time->gmtoff * 60, &tm);


    log = slcf->logs->elts;
    pri = slcf->facility * 8 + slcf->severity;
    if(pri > 255) {
	pri = NGX_SOCKETLOG_FACILITY_LOCAL7 * 8 + NGX_SOCKETLOG_SEVERITY_INFO;
    }

    for (l = 0; l < slcf->logs->nelts; l++) {
#if defined nginx_version && nginx_version >= 7018
	ngx_http_script_flush_no_cacheable_variables(r, log[l].format->flushes);
#endif

	len = 0;
	op = log[l].format->ops->elts;
	for (i = 0; i < log[l].format->ops->nelts; i++) {
	    if (op[i].len == 0) {
		len += op[i].getlen(r, op[i].data);
	    }
	    else {
		len += op[i].len;
	    }
	}

	len += sizeof("<255>") - 1 + sizeof("Jan 31 00:00:00") - 1 + 1 + ngx_cycle->hostname.len + 1
	    + tag.len + 2 + 1;

#if defined nginx_version && nginx_version >= 7003
	line = ngx_pnalloc(r->pool, len);
#else
	line = ngx_palloc(r->pool, len);
#endif
	if (line == NULL) {
	    return NGX_ERROR;
	}

	/*
	 * BSD syslog message header (see RFC 3164)
	 */
	if(!log[l].bare) {
	    p = ngx_sprintf(line, "<%ui>%s %2d %02d:%02d:%02d %V %V: ", pri, months[tm.ngx_tm_mon - 1], tm.ngx_tm_mday,
		tm.ngx_tm_hour, tm.ngx_tm_min, tm.ngx_tm_sec, &ngx_cycle->hostname, &tag);
	}
	else {
	    p = line;
	}

	for(i = 0; i < log[l].format->ops->nelts; i++) {
	    p = op[i].run(r, p, &op[i]);
	}

	*p++ = '\n';

	peer = ngx_socketlog_peers.elts;

	peer += log[l].peer_idx;

	ngx_http_socketlog_append(*peer, line, p - line);
    }

    return NGX_OK;
}

static u_char*
ngx_socketlog_buf_append(ngx_buf_t *buf, u_char *p, size_t *len)
{
    size_t remaining = buf->end - buf->last;

    if(remaining > *len) {
	remaining = *len;
    }

    buf->last = ngx_copy(buf->last, p, remaining);
    *len -= remaining;

    return p + remaining;
}

static void
ngx_http_socketlog_append(ngx_socketlog_peer_t *peer, u_char *buf, size_t len)
{
    u_char *p;
    ngx_chain_t *last, *q;
    size_t remaining;
    ngx_uint_t num_busy = 0;
    ngx_connection_t *c;

    /*
     * Find last busy buffer
     */
    last = peer->busy;

    while(last != NULL && last->next != NULL) {
	last = last->next;
    }

    /*
     * See if message fits into remaining space
     */
    remaining = (last != NULL ? last->buf->end - last->buf->last : 0);

    q = peer->free;

    while(remaining <= len && q != NULL) {
	remaining += (q->buf->end - q->buf->last);
	q = q->next;
    }

    /*
     * No memory for this message, discard it
     */
    if(remaining < len) {
	peer->discarded++;
	return;
    }

    /*
     * Append message to the buffers
     */
    if(last != NULL) {
	p = ngx_socketlog_buf_append(last->buf, buf, &len);
    }
    else {
	p = buf;
    }

    while(peer->free != NULL && len != 0) {
	q = peer->free;

	p = ngx_socketlog_buf_append(q->buf, p, &len);

	peer->free = peer->free->next;

	q->next = NULL;

	if(last == NULL) {
	    peer->busy = q;
	}
	else {
	    last->next = q;
	}
	last = q;
    }

    q = peer->busy;

    while(q != NULL) {
	num_busy++;
	q = q->next;
    }

    if(!peer->flush_timer_set) {
	peer->flush_timer.handler = ngx_socketlog_flush_handler;
	peer->flush_timer.data = peer;
	peer->flush_timer.log = peer->conn.log;

	ngx_add_timer(&peer->flush_timer, peer->conf->flush_timeout);

	peer->flush_timer_set = 1;
    }

    if(num_busy >= 2) {
	c = peer->conn.connection;
	/*
	 * Send it if write channel is not suspended
	 */
	if(c != NULL && !(c->buffered & NGX_HTTP_WRITE_BUFFERED)) {
	    ngx_http_socketlog_send(peer);
	}
    }
}

static void
ngx_http_socketlog_send(ngx_socketlog_peer_t *p)
{
    ngx_chain_t				*written;
    ngx_connection_t			*c;
//    ngx_socketlog_peer_t		*peer;
    ngx_chain_t				*dummy = NULL;

    c = p->conn.connection;

    if(c == NULL || c->fd == -1) {
	return;
    }

    if(!c->write->ready) {
	return;
    }

    if(p->flush_timer_set) {
	ngx_del_timer(&p->flush_timer);
	p->flush_timer_set = 0;
    }

//    peer = c->data;

    if(p->busy != NULL) {
	written = c->send_chain(c, p->busy, 0);

	if(written == NGX_CHAIN_ERROR) {
	    ngx_log_error(NGX_LOG_ERR, c->log, 0,
			  "socketlog write error");
	    ngx_close_connection(c);
	    return;
	}


#if defined nginx_version && nginx_version >= 1001004
	ngx_chain_update_chains(p->pool, &p->free, &p->busy, &dummy, 0);
#else
	ngx_chain_update_chains(&p->free, &p->busy, &dummy, 0);
#endif

	if(written != NULL) {

	    c->buffered |= NGX_HTTP_WRITE_BUFFERED;

	    if(!c->write->ready && !c->write->timer_set) {
		ngx_add_timer(c->write, p->conf->write_timeout);
	    }

	    if(ngx_handle_write_event(c->write, 0) != NGX_OK) {
		ngx_close_connection(c);
	    }
	    return;
	}
	else {

	    c->buffered &= ~NGX_HTTP_WRITE_BUFFERED;

	    if(c->write->timer_set) {
		ngx_del_timer(c->write);
	    }
	}
    }
}

static void ngx_socketlog_connected_handler(ngx_socketlog_peer_t *peer)
{
    ngx_connection_t			*c;

    c = peer->conn.connection;

    ngx_del_timer(c->read);

    /*
     * Once the connection has been established, we need to
     * reset the reconnect timeout to it's initial value
     */
    peer->reconnect_timeout = peer->conf->reconnect_timeout;

    if(peer->discarded != 0) {
	ngx_log_error(NGX_LOG_ERR, peer->log, 0,
	    "socketlog peer \"%V\" discarded %ui messages",
	    &peer->conf->name, peer->discarded);

	peer->discarded = 0;
    }
}

static void ngx_socketlog_read_handler(ngx_event_t *rev)
{
    ngx_connection_t			*c;
    ngx_socketlog_peer_t		*peer;

    int					n;
    char				buf[1];
    ngx_err_t				err;

    c = rev->data;
    peer = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
		   "socketlog read handler");

    if(rev->timedout || c->error || c->close) {
	if(rev->timedout) {
	    ngx_log_error(NGX_LOG_ERR, rev->log, NGX_ETIMEDOUT,
			  "socketlog peer timed out");
	}

	if(rev->error) {
	    ngx_log_error(NGX_LOG_ERR, rev->log, 0,
			  "socketlog peer connection error");
	}

	ngx_close_connection(c);

	if(!c->close) {
	    ngx_socketlog_reconnect_peer(peer);
	}
	return;
    }

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

	if(!ev->pending_eof) {
	    goto no_error;
	}

	rev->eof = 1;
	c->error = 1;

	if(ev->kq_errno) {
	    ev->error = 1;
	}

	goto reconnect;
    }
#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, rev->log, err,
		   "socketlog recv(): %d", n);

    if(n > 0) {
	goto no_error;
    }

    if(n == -1) {
	if(err == NGX_EAGAIN) {
	    goto no_error;
	}

	rev->error = 1;

    }
    else {
	err = 0;
    }

    rev->eof = 1;
    c->error = 1;

    ngx_log_error(NGX_LOG_INFO, rev->log, err,
		  "socketlog connection error");

#if (NGX_HAVE_KQUEUE)
reconnect:
#endif
    ngx_close_connection(c);
    ngx_socketlog_reconnect_peer(peer);
    return;

no_error:
    if(peer->connecting) {
	ngx_socketlog_connected_handler(peer);
	peer->connecting = 0;
    }
}

static void ngx_socketlog_write_handler(ngx_event_t *wev)
{
    ngx_connection_t			*c;
    ngx_socketlog_peer_t		*peer;

    c = wev->data;
    peer = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, wev->log, 0,
		   "socketlog write handler");

    if(wev->timedout || c->error || c->close) {
	if(wev->timedout) {
	    ngx_log_error(NGX_LOG_ERR, wev->log, NGX_ETIMEDOUT,
			  "socketlog peer timed out");
	}

	if(wev->error) {
	    ngx_log_error(NGX_LOG_ERR, wev->log, 0,
			  "socketlog peer connection error");
	}

	ngx_close_connection(c);

	if(!c->close) {
	    ngx_socketlog_reconnect_peer(peer);
	}
	return;
    }

    if(peer->connecting) {
	ngx_socketlog_connected_handler(peer);
	peer->connecting = 0;
    }

    if(c->write->timer_set) {
	ngx_del_timer(c->write);
    }

    ngx_http_socketlog_send(peer);
}

static void ngx_socketlog_flush_handler(ngx_event_t *ev)
{
    ngx_socketlog_peer_t		*peer = ev->data;
    ngx_connection_t			*c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, peer->log, 0,
		   "socketlog flush handler, set read handler");

    peer->flush_timer_set = 0;

    c = peer->conn.connection;

    if(c == NULL || c->fd == -1) {
	return;
    }

    c->read->handler = ngx_socketlog_read_handler;

    ngx_http_socketlog_send(peer);
}

static ngx_int_t ngx_socketlog_connect_peer(ngx_socketlog_peer_t *peer)
{
    ngx_int_t		    rc;

    ngx_log_error(NGX_LOG_INFO, peer->log, 0,
		  "socketlog connect peer \"%V\"", &peer->conf->name);

    peer->conn.sockaddr = peer->conf->sockaddr;
    peer->conn.socklen = peer->conf->socklen;
    peer->conn.name = &peer->conf->name;
    peer->conn.get = ngx_event_get_peer;
    peer->conn.log = peer->log;
    peer->conn.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&peer->conn);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
	if(peer->conn.connection) {
	    ngx_close_connection(peer->conn.connection);
	}

	return NGX_ERROR;
    }

    peer->conn.connection->data = peer;
    peer->conn.connection->pool = peer->pool;

    peer->conn.connection->read->handler = ngx_socketlog_read_handler;
    peer->conn.connection->write->handler = ngx_socketlog_write_handler;
    peer->conn.connection->buffered = 0;

    ngx_add_timer(peer->conn.connection->read, peer->conf->connect_timeout);

    peer->connecting = 1;

    return NGX_OK;
}

static void ngx_socketlog_connect_handler(ngx_event_t *ev)
{
    ngx_int_t		    rc;
    ngx_socketlog_peer_t    *peer = ev->data;

    rc = ngx_socketlog_connect_peer(peer);

    if(rc != NGX_OK) {
	ngx_socketlog_reconnect_peer(peer);
    }
}

static void ngx_socketlog_reconnect_peer(ngx_socketlog_peer_t *p)
{
    p->conn.connection = NULL;

    p->reconnect_timer.handler = ngx_socketlog_connect_handler;
    p->reconnect_timer.data = p;
    p->reconnect_timer.log = p->conn.log;

    ngx_add_timer(&p->reconnect_timer, p->reconnect_timeout);

    p->reconnect_timeout *= 2;

    if(p->discarded != 0) {
	ngx_log_error(NGX_LOG_ERR, p->log, 0,
	    "socketlog peer \"%V\" discarded %ui messages",
	    &p->conf->name, p->discarded);

	p->discarded = 0;
    }
}

static void *
ngx_http_socketlog_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_socketlog_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_socketlog_conf_t));
    if (conf == NULL) {
	return NGX_CONF_ERROR;
    }
    conf->facility = NGX_CONF_UNSET_UINT;
    conf->severity = NGX_CONF_UNSET_UINT;
//    conf->enabled = NGX_SOCKETLOG_OFF;

    return conf;
}

static char *
ngx_http_socketlog_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_socketlog_conf_t *prev = parent;
    ngx_http_socketlog_conf_t *conf = child;

    if(conf->tag == NULL) {
	conf->tag = prev->tag;
    }

    ngx_conf_merge_uint_value(conf->facility,
			      prev->facility, NGX_SOCKETLOG_FACILITY_LOCAL7);
    ngx_conf_merge_uint_value(conf->severity,
			      prev->severity, NGX_SOCKETLOG_SEVERITY_INFO);

    if(conf->logs) {
	return NGX_CONF_OK;
    }

    if(conf->enabled == NGX_SOCKETLOG_ON) {
	return NGX_CONF_OK;
    }

    conf->logs = prev->logs;
    conf->enabled = prev->enabled;

    return NGX_CONF_OK;
}

static void *
ngx_socketlog_create_conf(ngx_cycle_t *cycle)
{
    ngx_socketlog_conf_t  *slcf;

    slcf = ngx_pcalloc(cycle->pool, sizeof(ngx_socketlog_conf_t));
    if(slcf == NULL) {
	return NULL;
    }

    return slcf;
}

static ngx_int_t
ngx_http_socketlog_find_peer_by_name(ngx_conf_t *cf, ngx_str_t *name)
{
    ngx_socketlog_conf_t	 *slcf;
    ngx_socketlog_peer_conf_t	 *pc;
    ngx_uint_t			 i;

    slcf = (ngx_socketlog_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_socketlog_module);

    pc = slcf->peers->elts;

    for(i = 0; i < slcf->peers->nelts; i++) {
	if(pc[i].name.len == name->len
	  && ngx_strncmp(pc[i].name.data, name->data, name->len) == 0) {
	    return i;
	}
    }

    return NGX_DECLINED;
}

static char *
ngx_http_socketlog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_socketlog_conf_t	 *slcf = conf;

    ngx_uint_t			 i;
    ngx_str_t			 *value, name;
    ngx_http_socketlog_t	 *log;
    ngx_http_log_fmt_t		 *fmt;
    ngx_http_log_main_conf_t	 *lmcf;
    ngx_int_t			 rc;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
	slcf->enabled = NGX_SOCKETLOG_OFF;
	return NGX_CONF_OK;
    }
    slcf->enabled = NGX_SOCKETLOG_ON;

    if (slcf->logs == NULL) {
	slcf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_http_socketlog_t));
	if (slcf->logs == NULL) {
	    return NGX_CONF_ERROR;
	}
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if(lmcf == NULL) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			   "socketlog module requires log module to be compiled in");
	return NGX_CONF_ERROR;
    }

    log = ngx_array_push(slcf->logs);
    if (log == NULL) {
	return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_http_socketlog_t));

    log->peer_name = value[1];

    rc = ngx_http_socketlog_find_peer_by_name(cf, &log->peer_name);

    if(rc == NGX_DECLINED) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			   "socketlog peer %V is not defined", &log->peer_name);
	return NGX_CONF_ERROR;
    }

    log->peer_idx = rc;

    log->bare = 0;

    if (cf->args->nelts >= 3) {
	name = value[2];

	if (ngx_strcmp(name.data, "combined") == 0) {
	    lmcf->combined_used = 1;
	}
    }
    else {
	name.len = sizeof("combined") - 1;
	name.data = (u_char *) "combined";
	lmcf->combined_used = 1;
    }

    if (cf->args->nelts >= 4) {
      if (ngx_strcmp(value[3].data, "bare") == 0) {
	log->bare = 1;
      }
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
	if (fmt[i].name.len == name.len
	  && ngx_strcasecmp(fmt[i].name.data, name.data) == 0) {
	    log->format = &fmt[i];
	    goto done;
	}
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;

done:
    return NGX_CONF_OK;
}

static char *
ngx_http_socketlog_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t			 *value;
    ngx_socketlog_conf_t	 *slcf;
    ngx_url_t			 u;
    ngx_socketlog_peer_conf_t	 *peer;

    slcf = (ngx_socketlog_conf_t *) ngx_get_conf(cf->cycle->conf_ctx, ngx_core_socketlog_module);

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[2];
    u.default_port = 514;
    u.no_resolve = 0;

    if(ngx_parse_url(cf->pool, &u) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &u.host, u.err);
	return NGX_CONF_ERROR;
    }

    if(slcf->peers == NULL) {
	slcf->peers = ngx_array_create(cf->pool, 2, sizeof(ngx_socketlog_peer_conf_t));
	if (slcf->peers == NULL) {
	    return NGX_CONF_ERROR;
	}
    }

    peer = ngx_array_push(slcf->peers);
    if(peer == NULL) {
	return NGX_CONF_ERROR;
    }

    peer->name = value[1];
    peer->sockaddr = u.addrs[0].sockaddr;
    peer->socklen = u.addrs[0].socklen;

    peer->write_timeout = 30000;
    peer->connect_timeout = 30000;
    peer->reconnect_timeout = 5000;
    peer->flush_timeout = 2000;

    peer->bufs.num = 200;
    peer->bufs.size = 2048;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_socketlog_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t	 *cmcf;
    ngx_http_handler_pt		 *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
	return NGX_ERROR;
    }

    *h = ngx_http_socketlog_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_socketlog_init_process(ngx_cycle_t *cycle)
{
    ngx_int_t				rc;
    ngx_socketlog_conf_t		*slcf;
    ngx_uint_t				i;
    ngx_socketlog_peer_conf_t		*pc;
    ngx_socketlog_peer_t		*peer, **ppeer;

    slcf = (ngx_socketlog_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_socketlog_module);

    if(slcf->peers == NULL || slcf->peers->nelts == 0) {
	return NGX_OK;
    }

    rc = ngx_array_init(&ngx_socketlog_peers, cycle->pool,
	slcf->peers->nelts, sizeof(ngx_socketlog_peer_t*));

    if(rc != NGX_OK) {
	return rc;
    }

    pc = slcf->peers->elts;

    for(i = 0; i < slcf->peers->nelts; i++) {
	ppeer = ngx_array_push(&ngx_socketlog_peers);

	if(ppeer == NULL) {
	    return NGX_ERROR;
	}

	peer = ngx_pcalloc(cycle->pool, sizeof(ngx_socketlog_peer_t));

	if(peer == NULL) {
	    return NGX_ERROR;
	}

	peer->free = ngx_create_chain_of_bufs(cycle->pool, &pc[i].bufs);

	if(peer->free == NULL) {
	    return NGX_ERROR;
	}

	*ppeer = peer;

	peer->pool = cycle->pool;
	peer->conf = &pc[i];
	peer->log = cycle->log;

	peer->reconnect_timeout = pc[i].reconnect_timeout;

	ngx_socketlog_connect_peer(peer);
    }

    return NGX_OK;
}

static char *
ngx_http_socketlog_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_socketlog_conf_t	*slcf = conf;
    ngx_str_t			*value;
    ngx_syslog_facility_t	*f;
    ngx_syslog_severity_t	*s;

    value = cf->args->elts;

    f = ngx_syslog_facilities;

    while(f->name.data != NULL) {
        if(ngx_strncmp(f->name.data, value[1].data, f->name.len) == 0)
            break;
        f++;
    }

    if(f->name.data != NULL) {
        slcf->facility = f->number;
    }
    else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown facility \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        s = ngx_syslog_severities;

        while(s->name.data != NULL) {
            if(ngx_strncmp(s->name.data, value[2].data, s->name.len) == 0)
                break;
            s++;
        }

        if(s->name.data != NULL) {
            slcf->severity = s->number;
        }
        else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown severity \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_socketlog_set_tag(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t			n;
    ngx_str_t			*value;
    ngx_http_script_compile_t	sc;
    ngx_http_log_tag_template_t	**field, *h;

    field = (ngx_http_log_tag_template_t**) (((u_char*)conf) + cmd->offset);

    value = cf->args->elts;

    if (*field == NULL) {
        *field = ngx_palloc(cf->pool, sizeof(ngx_http_log_tag_template_t));
        if (*field == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = *field;

    h->value = value[1];
    h->lengths = NULL;
    h->values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);

    if (n > 0) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &value[1];
        sc.lengths = &h->lengths;
        sc.values = &h->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
