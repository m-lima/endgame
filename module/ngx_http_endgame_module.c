#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <endgame.h>

#include <limits.h>
#include <stdio.h>

typedef struct {
  ngx_flag_t enable;
} ngx_http_auth_pam_loc_conf_t;

static ngx_command_t ngx_http_endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_auth_pam_loc_conf_t, enable), NULL},
    ngx_null_command};

static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r) {
  ngx_table_elt_t *cookie;
  ngx_str_t name = ngx_string("endgame"), value;

  cookie =
      ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &name, &value);

  if (cookie == NULL || value.len == 0) {
    return NGX_HTTP_UNAUTHORIZED;
  }

  Key key = {.bytes = {0}};
  CSlice src = {.ptr = value.data, .len = value.len};
  RustSlice email = endgame_rust_slice_null(),
            given = endgame_rust_slice_null(),
            family = endgame_rust_slice_null();

  CSlice error = endgame_decrypt(&key, src, 3600, &email, &given, &family);
  if (error.ptr != NULL) {
    ngx_str_t msg = {.data = (u_char *)error.ptr, .len = error.len};
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to decrypt cookie: \"%V\"", &msg);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (email.ptr == NULL) {
    endgame_rust_slice_free(&given);
    endgame_rust_slice_free(&family);
    return NGX_HTTP_UNAUTHORIZED;
  }

  return NGX_DECLINED;
}

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_endgame_handler;

  return NGX_OK;
}

static ngx_http_module_t ngx_http_endgame_module_ctx = {
    NULL,                  /* preconfiguration */
    ngx_http_endgame_init, /* postconfiguration */
    NULL,                  /* create main configuration */
    NULL,                  /* init main configuration */
    NULL,                  /* create server configuration */
    NULL,                  /* merge server configuration */
    NULL,                  /* create location configuration */
    NULL                   /* merge location configuration */
};

// Module definition
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
