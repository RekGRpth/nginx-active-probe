/**
 * @file   ngx_http_active_probe_module.c
 * @brief  Active probe modular for Nginx.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define DEFAULT_SERVER_PORT           5688
#define DEFAULT_PROBE_INTERVAL        300
#define DEFAULT_PROBE_CONNECT_TIMEOUT 600

#define NGX_ACTIVE_PROBE_ICMP    0
#define NGX_ACTIVE_PROBE_TCP     1 
#define NGX_ACTIVE_PROBE_UDP     2
#define NGX_ACTIVE_PROBE_HTTP    3 
#define NGX_ACTIVE_PROBE_HTTPS   4 
#define NGX_ACTIVE_PROBE_DNS     5

/**
 *This module provided directive: active_probe url interval=100 timeout=300 port=8080 protocol=TCP.
 *
 */
typedef struct ngx_http_active_probe_srv_conf_s ngx_http_active_probe_srv_conf_t;
static char *ngx_http_active_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_active_probe_timer_handler(ngx_event_t *ev);
static void ngx_http_active_probe_timeout_handler(ngx_event_t *ev);
static void * ngx_http_active_probe_create_main_conf(ngx_conf_t *cf);
static void * ngx_http_active_probe_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_active_probe_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_active_probe_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_active_probe_peek_one_byte(ngx_connection_t *c);
static void ngx_http_active_probe_clear_event(ngx_http_active_probe_srv_conf_t *apscf);

typedef struct {
    ngx_array_t      active_probes;
} ngx_http_active_probe_main_conf_t;

typedef struct ngx_http_active_probe_srv_conf_s {
    ngx_pool_t                     *pool;
    ngx_str_t                       name;
    ngx_msec_t                      interval;
    ngx_msec_t                      timeout;
    ngx_uint_t                      protocol;
    in_port_t                       port;
    ngx_uint_t                      no_port;
    ngx_addr_t                     *addrs;
    ngx_uint_t                      naddrs;
    ngx_event_t                     probe_timer;
    ngx_event_t                     timeout_timer;
    ngx_peer_connection_t           pc;
    ngx_http_upstream_srv_conf_t   *upstream;
} ngx_http_active_probe_srv_conf_t;

static ngx_command_t ngx_http_active_probe_commands[] = {

    { ngx_string("active_probe"), /* directive */
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE, /* ups context and takes
                                            1,2,3,4 arguments*/
      ngx_http_active_probe,            /* configuration setup function */
      0,                                /* No offset. Only one context is supported. */
      0,                                /* No offset when storing the module configuration on struct. */
      NULL},

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_active_probe_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    ngx_http_active_probe_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_active_probe_create_srv_conf, /* create server configuration */
    ngx_http_active_probe_merge_srv_conf, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_active_probe_module = {
    NGX_MODULE_V1,
    &ngx_http_active_probe_module_ctx, /* module context */
    ngx_http_active_probe_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    ngx_http_active_probe_init_process, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

/**
 * Configuration setup function that installs the content handler.
 */
static char *ngx_http_active_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_active_probe_main_conf_t *apmcf;
    ngx_http_active_probe_srv_conf_t  *apscf;
    ngx_str_t                         *value, s;
    ngx_uint_t                         i, port, protocol;
    ngx_url_t                          u;
    ngx_msec_t                         interval, timeout;

    apmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_active_probe_module);
    if (apmcf == NULL) {
        return NGX_CONF_ERROR;
    }

    apscf = ngx_array_push(&apmcf->active_probes);
    if (apscf == NULL) {
        return NGX_CONF_ERROR;
    }

    apscf->upstream = (ngx_http_upstream_srv_conf_t *)conf;
    /* Install the hello world handler. */
    value = cf->args->elts;
    interval = DEFAULT_PROBE_INTERVAL; 
    timeout = DEFAULT_PROBE_CONNECT_TIMEOUT;
    port = DEFAULT_SERVER_PORT;
    protocol = NGX_ACTIVE_PROBE_ICMP;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR || interval == 0) {
                goto invalid_parameter;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "port=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            port = ngx_atoi(s.data, s.len);
            if (port == (ngx_uint_t) NGX_ERROR || port == 0) {
                goto invalid_parameter;
            }
            continue;
       }

       if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
           s.len = value[i].len - 8;
           s.data = value[i].data + 8;

           timeout = ngx_atoi(s.data, s.len);
           if (timeout == (ngx_msec_t) NGX_ERROR || timeout == 0) {
               goto invalid_parameter;
           }
           continue;
       }

       if (ngx_strncmp(value[i].data, "protocol=", 9) == 0) {
           s.len = value[i].len - 9;
           s.data = value[i].data + 9;
            
           if (ngx_strncmp(s.data,  (u_char *)"ICMP", 4) == 0) {
               protocol = NGX_ACTIVE_PROBE_ICMP;
           } else if (ngx_strncasecmp(s.data,  (u_char *)"TCP", 3) == 0) {
               protocol = NGX_ACTIVE_PROBE_TCP;
           } else if (ngx_strncasecmp(s.data,  (u_char *)"UDP", 3) == 0) {
               protocol = NGX_ACTIVE_PROBE_UDP;
           } else if (ngx_strncasecmp(s.data,  (u_char *)"HTTP", 4) == 0) {
               protocol = NGX_ACTIVE_PROBE_HTTP;
           } else if (ngx_strncasecmp(s.data,  (u_char *)"HTTPS", 5) == 0) {
               protocol = NGX_ACTIVE_PROBE_HTTPS;
           } else if (ngx_strncasecmp(s.data,  (u_char *)"DNS", 3) == 0) {
               protocol = NGX_ACTIVE_PROBE_DNS;
           } else {
               goto invalid_parameter;
           }
           continue;
       }

       goto invalid_parameter;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = DEFAULT_SERVER_PORT;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    apscf->name = u.url;
    apscf->naddrs = u.naddrs;
    apscf->addrs = u.addrs;
    apscf->port = port;
    apscf->interval = interval;
    apscf->timeout = timeout;
    apscf->protocol = protocol;
    return NGX_CONF_OK;

invalid_parameter:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "invalid parameter \"%V\"", &value[i]);
    return NGX_CONF_ERROR;
}

static void *
ngx_http_active_probe_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_active_probe_srv_conf_t *apscf;

    apscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_active_probe_srv_conf_t));
    if (apscf == NULL) {
        return NULL;
    }

    apscf->interval = NGX_CONF_UNSET_UINT;
    apscf->timeout = NGX_CONF_UNSET_UINT;
    apscf->port = NGX_CONF_UNSET;
    apscf->protocol = NGX_CONF_UNSET_UINT;
    apscf->no_port = NGX_CONF_UNSET_UINT;
    apscf->upstream = NGX_CONF_UNSET_PTR;
    apscf->addrs = NGX_CONF_UNSET_PTR;
    apscf->naddrs = NGX_CONF_UNSET_UINT;

    return apscf;
}

static char *
ngx_http_active_probe_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_active_probe_srv_conf_t *prev = parent;
    ngx_http_active_probe_srv_conf_t *conf = child;
    ngx_conf_merge_ptr_value(conf->upstream, prev->upstream, NULL);
    ngx_conf_merge_uint_value(conf->interval, prev->interval, DEFAULT_PROBE_INTERVAL);
    ngx_conf_merge_uint_value(conf->timeout, prev->timeout, DEFAULT_PROBE_CONNECT_TIMEOUT);
    ngx_conf_merge_uint_value(conf->port, prev->port, DEFAULT_SERVER_PORT);
    ngx_conf_merge_uint_value(conf->no_port, prev->no_port, 1);

    return NGX_CONF_OK;
}

static void *
ngx_http_active_probe_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_active_probe_main_conf_t *apmcf;

    apmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_active_probe_main_conf_t));
    if (apmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&apmcf->active_probes, cf->pool, 4,
                    sizeof(ngx_http_active_probe_srv_conf_t))
            != NGX_OK) {
        return NULL;
    }

    return apmcf;
}

static void ngx_http_active_probe_recv_handler(ngx_event_t *ev)
{
    ngx_connection_t                    *c;
    c = ev->data;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "active probe recv handler.");
    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        return;
    }
    return;
}

static void ngx_http_active_probe_send_handler(ngx_event_t *ev) 
{
    ngx_connection_t                    *c;
    ngx_http_active_probe_srv_conf_t    *apscf;
    ngx_http_upstream_srv_conf_t        *upstream;

    c = ev->data;
    apscf = c->data;

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "active probe send.");
    upstream = apscf->upstream;
    if (upstream == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "no upstream is set.");
        return;
    }
    /*loop all the peers and send them to the receiver*/

    return;
}

static void ngx_http_active_probe_clear_event(ngx_http_active_probe_srv_conf_t *apscf)
{
    ngx_connection_t                    *c;

    if (apscf == NULL || apscf->addrs == NULL || apscf->naddrs == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "no valid data");
        return;   
    }

    c = apscf->pc.connection;
    if (c) {
        ngx_close_connection(c);
        apscf->pc.connection = NULL;
    }

    if (apscf->timeout_timer.timer_set) {
        ngx_del_timer(&apscf->timeout_timer);
    }

    return;
}

static void ngx_http_active_probe_timeout_handler(ngx_event_t *ev)
{
    ngx_connection_t                    *c;
    ngx_http_active_probe_srv_conf_t    *apscf;

    apscf = ev->data;
    if (apscf == NULL || apscf->addrs == NULL || apscf->naddrs == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "no valid data");
        return;   
    }

    c = apscf->pc.connection;
    if (c) {
        c->error = 1;
    }
    ngx_http_active_probe_clear_event(apscf);
    return;
}

static ngx_int_t
ngx_http_active_probe_peek_one_byte(ngx_connection_t *c)
{
    char                            buf[1];
    ngx_int_t                       n;
    ngx_err_t                       err;

    n = recv(c->fd, buf, 1, MSG_PEEK);
    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, err,
                   "http check upstream recv(): %i, fd: %d",
                   n, c->fd);

    if (n == 1 || (n == -1 && err == NGX_EAGAIN)) {
        return NGX_OK;
    } else {
        return NGX_ERROR;
    }
}

/*timer handler*/
static void ngx_http_active_probe_timer_handler(ngx_event_t *ev)
{
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_http_active_probe_srv_conf_t    *apscf;

    apscf = ev->data;
    if (apscf == NULL || apscf->addrs == NULL || apscf->naddrs == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "no valid data");
        return;   
    }

    ngx_add_timer(ev, apscf->interval);

    if (apscf->pc.connection != NULL) {
        c = apscf->pc.connection;
        if ((rc = ngx_http_active_probe_peek_one_byte(c)) == NGX_OK) {
            goto connection_done;
        } else {
            ngx_close_connection(c);
            apscf->pc.connection = NULL;
        }
    }
    ngx_memzero(&apscf->pc, sizeof(ngx_peer_connection_t));

    apscf->pc.sockaddr = apscf->addrs[0].sockaddr;
    apscf->pc.socklen = apscf->addrs[0].socklen;
    apscf->pc.name = &apscf->name;

    apscf->pc.get = ngx_event_get_peer;
    apscf->pc.log = ev->log;
    apscf->pc.log_error = NGX_ERROR_ERR;
    apscf->pc.cached = 0;
    apscf->pc.connection = NULL;

    rc = ngx_event_connect_peer(&apscf->pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED || rc == NGX_BUSY) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ngx_cycle->log, 0, "connect to server %V error.", apscf->name);
        return;
    }

    /* NGX_OK or NGX_AGAIN */
    c = apscf->pc.connection;
    c->data = apscf;
    c->log = apscf->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->pool = apscf->pool;

connection_done:
    c->write->handler = ngx_http_active_probe_send_handler;
    c->read->handler = ngx_http_active_probe_recv_handler;
    ngx_add_timer(&apscf->timeout_timer, apscf->timeout);

    if (rc == NGX_OK) {
        c->write->handler(c->write);
    }
    return;
}

static ngx_int_t
ngx_http_active_probe_init_process(ngx_cycle_t *cycle)
{
    ngx_http_active_probe_main_conf_t *apmcf;
    ngx_http_active_probe_srv_conf_t  *apscf;
    ngx_event_t *probe_timer, *timeout_timer;
    ngx_uint_t  i;
    ngx_uint_t  refresh_in;

    if (ngx_process != NGX_PROCESS_WORKER || ngx_worker != 0) {
        /*only works in the worker 0 prcess.*/
        return NGX_OK;
    }

    apmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_active_probe_module);
    if (apmcf == NULL) {
        return NGX_OK;
    }

    apscf = apmcf->active_probes.elts;
    for (i=0; i < apmcf->active_probes.nelts; i ++) {
        if (apscf[i].addrs == NULL || apscf[i].naddrs == 0) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cycle->log, 0,
                          "no address for host %V", apscf->name);
            continue;
        }
        /*set up the timer for service*/
        apscf[i].pool = ngx_create_pool(ngx_pagesize, cycle->log);
        probe_timer = &apscf[i].probe_timer;
        probe_timer->handler = ngx_http_active_probe_timer_handler;
        probe_timer->log = cycle->log;
        probe_timer->data = &apscf[i];

        timeout_timer = &apscf[i].timeout_timer;
        timeout_timer->handler = ngx_http_active_probe_timeout_handler;
        timeout_timer->log = cycle->log;
        timeout_timer->data = &apscf[i];

        refresh_in = ngx_random() % 1000;
        /*log*/
        ngx_add_timer(probe_timer, refresh_in);
    }

    return NGX_OK;
}

