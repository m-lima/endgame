#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <endgame.h>

#include <limits.h>
#include <stdio.h>

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r);
static void *ngx_http_endgame_create_conf(ngx_conf_t *cf);
static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static char *ngx_http_endgame_set_session_name(ngx_conf_t *cf, void *post,
                                               void *data);

typedef struct {
  ngx_flag_t enable;
  ngx_str_t session_name;
  Key session_secret;
  time_t session_ttl;
  ngx_str_t session_domain;
  ngx_str_t header_prefix;
} ngx_http_endgame_conf_t;

static ngx_conf_post_t ngx_http_endgame_set_session_name_post = {
    ngx_http_endgame_set_session_name};

static ngx_command_t ngx_http_endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, enable), NULL},
    {ngx_string("endgame_session_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_name),
     &ngx_http_endgame_set_session_name_post},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_domain), NULL},
    {ngx_string("endgame_session_ttl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_ttl), NULL},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_domain), NULL},
    ngx_null_command};

static ngx_http_module_t ngx_http_endgame_module_ctx = {
    NULL,                         /* preconfiguration */
    ngx_http_endgame_init,        /* postconfiguration */
    NULL,                         /* create main configuration */
    NULL,                         /* init main configuration */
    NULL,                         /* create server configuration */
    NULL,                         /* merge server configuration */
    ngx_http_endgame_create_conf, /* create location configuration */
    ngx_http_endgame_merge_conf,  /* merge location configuration */
};

ngx_module_t ngx_http_endgame_module = {
    NGX_MODULE_V1,
    &ngx_http_endgame_module_ctx, /* module context */
    ngx_http_endgame_commands,    /* module directives */
    NGX_HTTP_MODULE,              /* module type */
    NULL,                         /* init master */
    NULL,                         /* init module */
    NULL,                         /* init process */
    NULL,                         /* init thread */
    NULL,                         /* exit thread */
    NULL,                         /* exit process */
    NULL,                         /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf) {
  ngx_http_core_main_conf_t *cmcf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  ngx_http_handler_pt *h =
      ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_endgame_handler;

  ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "Initialized endgame");

  return NGX_OK;
}

static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r) {
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "endgaaaaayyme");

  ngx_table_elt_t *cookie;
  ngx_str_t value;

  ngx_http_endgame_conf_t *egcf =
      ngx_http_get_module_loc_conf(r, ngx_http_endgame_module);

  if (!egcf->enable) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "declined");
    return NGX_DECLINED;
  }

  cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                             &egcf->session_name, &value);

  if (cookie == NULL || value.len == 0) {
    return NGX_HTTP_UNAUTHORIZED;
  }

  CSlice src = {.ptr = value.data, .len = value.len};
  RustSlice email = endgame_rust_slice_null(),
            given = endgame_rust_slice_null(),
            family = endgame_rust_slice_null();

  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "cookie: '%*s'", src.len,
                src.ptr);
  CSlice error = endgame_decrypt(&egcf->session_secret, src, egcf->session_ttl,
                                 &email, &given, &family);
  if (error.ptr != NULL) {
    ngx_str_t msg = {.data = (u_char *)error.ptr, .len = error.len};
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to decrypt cookie: \"%V\"", &msg);
    return NGX_HTTP_UNAUTHORIZED;
  }

  if (email.ptr == NULL) {
    endgame_rust_slice_free(&given);
    endgame_rust_slice_free(&family);
    return NGX_HTTP_UNAUTHORIZED;
  }

  return NGX_DECLINED;
}

static void *ngx_http_endgame_create_conf(ngx_conf_t *cf) {
  ngx_http_endgame_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_endgame_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->enable = NGX_CONF_UNSET;

  return conf;
}

static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child) {
  ngx_http_endgame_conf_t *prev = parent;
  ngx_http_endgame_conf_t *conf = child;

  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_str_value(conf->session_name, prev->session_name, "endgame");
  ngx_conf_merge_sec_value(conf->session_ttl, prev->session_ttl, 60 * 60);
  ngx_conf_merge_str_value(conf->header_prefix, prev->header_prefix, "X-User-");

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_set_session_name(ngx_conf_t *cf, void *post,
                                               void *data) {
  ngx_str_t *str = data;

  if (str->data == NULL || str->len == 0) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "endgame_session_name cannot be empty");
    return NGX_CONF_ERROR;
  }

  CSlice trimmed =
      endgame_c_slice_trim((CSlice){.ptr = str->data, .len = str->len});

  if (trimmed.len == 0) {
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "endgame_session_name cannot be white spaces");
    return NGX_CONF_ERROR;
  }

  str->data = (uint8_t *)trimmed.ptr;
  str->len = trimmed.len;

  ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "endgame_session_name '%V'", str);

  return NGX_CONF_OK;
}
