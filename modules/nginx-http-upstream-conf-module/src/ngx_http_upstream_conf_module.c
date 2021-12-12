
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_upstream_conf_op.h"


static ngx_http_upstream_srv_conf_t *
ngx_http_upstream_conf_get_zone(ngx_http_request_t *r, ngx_http_upstream_conf_op_t *op);
static ngx_int_t
ngx_http_upstream_conf_create_response_buf(ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, size_t size, ngx_int_t verbose);
static ngx_int_t
ngx_http_upstream_conf_handler(ngx_http_request_t *r);
static char *
ngx_http_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_upstream_conf_commands[] = {
    {
        ngx_string("upstream_conf"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_upstream_conf,
        0,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t ngx_http_upstream_conf_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
};


ngx_module_t ngx_http_upstream_conf_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_conf_module_ctx, /* module context */
    ngx_http_upstream_conf_commands,    /* module directives */
    NGX_HTTP_MODULE,                  /* module type */
    NULL,                             /* init master */
    NULL,                             /* init module */
    NULL,                             /* init process */
    NULL,                             /* init thread */
    NULL,                             /* exit thread */
    NULL,                             /* exit process */
    NULL,                             /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_upstream_srv_conf_t *
ngx_http_upstream_conf_get_zone(ngx_http_request_t *r, ngx_http_upstream_conf_op_t *op)
{
    ngx_uint_t                      i;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf  = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        if (uscf->shm_zone != NULL &&
            uscf->shm_zone->shm.name.len == op->upstream.len &&
            ngx_strncmp(uscf->shm_zone->shm.name.data, op->upstream.data, op->upstream.len) == 0)
        {
            return uscf;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_upstream_conf_create_response_buf(ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *backup;

    ngx_http_upstream_rr_peers_rlock(peers);
    b->last = ngx_snprintf(b->last, size, "{\"%V\" : {\"peers\" : [ ", peers->name);
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        size = b->end - b->last;
        if (verbose) {
            b->last = ngx_snprintf(b->last, size,
                    "{\"server\" : \"%V\", \"name\" : \"%V\", \"weight\" : %d, \"max_conns\" : %d, \"connections\" : %d, "
                    "\"fails\" : %d, \"max_fails\" : %d, \"down\" : %d, \"backup\" : false, \"fake\" : %s},",
                    &peer->server, &peer->name, peer->weight, peer->max_conns, peer->conns, peer->fails, peer->max_fails,
                    peer->down, peer->fake ? "true": "false");
        } else {
            b->last = ngx_snprintf(b->last, size,
                    "{\"server\" : \"%V\", \"name\" : \"%V\"},", &peer->server, &peer->name);
        }
    }

    backup = peers->next;
    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {
            size = b->end - b->last;
            if (verbose) {
                b->last = ngx_snprintf(b->last, size,
                        "{\"server\" : \"%V\", \"name\" : \"%V\", \"weight\" : %d, \"max_conns\" : %d, \"connections\" : %d, "
                        "\"fails\" : %d, \"max_fails\" : %d, \"down\" : %d, \"backup\" : true, \"fake\" : %s},",
                        &peer->server, &peer->name, peer->weight, peer->max_conns, peer->conns, peer->fails, peer->max_fails,
                        peer->down, peer->fake ? "true": "false");
            } else {
                b->last = ngx_snprintf(b->last, size,
                        "{\"server\" : \"%V\", \"name\" : \"%V\"},", &peer->server, &peer->name);
            }
        }
    }
    b->last--;
    size = b->end - b->last;
    b->last = ngx_snprintf(b->last, size, " ]}}");

    ngx_http_upstream_rr_peers_unlock(peers);
    return NGX_OK;
}

static size_t
ngx_http_upstream_peers_dump_size(ngx_http_request_t *r, ngx_http_upstream_rr_peers_t *peers)
{
    ngx_int_t                       max_conns;
    u_char                          flag[64];
    size_t                          len, flen;
    ngx_http_upstream_rr_peer_t    *peer;
    ngx_http_upstream_rr_peers_t   *backup;

    ngx_http_upstream_rr_peers_rlock(peers);

    len = sizeof("{\"\" : {\"peers\" : [  ]}}") - 1 + peers->name->len;
    for (peer = peers->peer; peer != NULL; peer = peer->next) {
        ngx_memset(flag, 0x00, 64);
        max_conns = 0;
        max_conns =  peer->max_conns;
        flen = ngx_snprintf(flag, 64, "%d%d%d%d%d%d",
            peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down) - flag;

        len += sizeof("{\"server\" : \"\", \"name\" : \"\", \"weight\" : , \"max_conns\" : , \"connections\" : , "
                      "\"fails\" : , \"max_fails\" : , \"down\" : , \"backup\" : false, \"fake\" : false},") - 1 +
                      peer->server.len + peer->name.len + flen;
    }

    backup = peers->next;
    if (backup != NULL) {
        for (peer = backup->peer; peer != NULL; peer = peer->next) {
            ngx_memset(flag, 0x00, 64);
            max_conns = 0;
            max_conns =  peer->max_conns;
            flen = ngx_snprintf(flag, 64, "%d%d%d%d%d%d",
                peer->weight, max_conns, peer->conns, peer->fails, peer->max_fails, peer->down) - flag;

            len += sizeof("{\"server\" : \"\", \"name\" : \"\", \"weight\" : , \"max_conns\" : , \"connections\" : , "
                          "\"fails\" : , \"max_fails\" : , \"down\" : , \"backup\" : true, \"fake\" : false},") - 1 +
                          peer->server.len + peer->name.len + flen;
        }
    }
    len--;

    ngx_http_upstream_rr_peers_unlock(peers);
    return len;
}

static ngx_int_t
ngx_http_upstream_conf_handler(ngx_http_request_t *r)
{
    size_t                          size;
    ngx_int_t                       rc;
    ngx_chain_t                     out;
    ngx_http_upstream_conf_op_t       op;
    ngx_buf_t                      *b;
    ngx_http_upstream_srv_conf_t   *uscf;
    ngx_slab_pool_t                *shpool;

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_http_upstream_conf_build_op(r, &op);
    if (rc != NGX_OK) {
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }

    uscf = ngx_http_upstream_conf_get_zone(r, &op);
    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream is not found. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_NOT_FOUND;
    }

    shpool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);

    rc = ngx_http_upstream_conf_op(r, &op, shpool, uscf);
    if (rc != NGX_OK) {
        ngx_shmtx_unlock(&shpool->mutex);
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }
    ngx_shmtx_unlock(&shpool->mutex);

    size = ngx_http_upstream_peers_dump_size(r,(ngx_http_upstream_rr_peers_t *)uscf->peer.data);

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_upstream_conf_create_response_buf((ngx_http_upstream_rr_peers_t *)uscf->peer.data, b, size, op.verbose);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to create a response. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_upstream_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upstream_conf_handler;

    return NGX_CONF_OK;
}
