#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <endgame.h>

#include <limits.h>
#include <stdio.h>

enum endgame_mode_e;
typedef enum endgame_mode_e endgame_mode_t;
struct ngx_http_endgame_conf_s;
typedef struct ngx_http_endgame_conf_s ngx_http_endgame_conf_t;

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_endgame_callback(ngx_http_request_t *r,
                                           ngx_http_endgame_conf_t *egcf);
static void *ngx_http_endgame_create_conf(ngx_conf_t *cf);
static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child);

static char *endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *endgame_conf_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char *endgame_conf_set_nonempty_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static char *endgame_conf_set_session_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf);

static ngx_int_t endgame_handle_unauthed(ngx_http_request_t *r,
                                         ngx_http_endgame_conf_t *egcf);
static ngx_table_elt_t *endgame_header_find(ngx_list_part_t *part,
                                            ngx_str_t name);
static ngx_int_t endgame_ngx_str_t_eq(ngx_str_t left, ngx_str_t right);
static ngx_int_t endgame_redirect_login(ngx_http_request_t *r,
                                        ngx_http_endgame_conf_t *egcf);
static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    RustSlice header_value);
static ngx_str_t endgame_take_rust_slice(ngx_pool_t *pool, RustSlice *slice);

enum endgame_mode_e { UNSET = -1, DISABLED = 0, ENABLED = 1, CALLBACK = 2 };

struct ngx_http_endgame_conf_s {
  endgame_mode_t mode;
  ngx_flag_t auto_login;
  ngx_str_t login_control_header;
  ngx_str_t session_name;
  Key session_key;
  ngx_flag_t session_key_set;
  time_t session_ttl;
  ngx_str_t session_domain;
  ngx_str_t discovery_url;
  ngx_str_t client_id;
  ngx_str_t client_secret;
  ngx_str_t callback_url;
  uint64_t oidc_id;
};

static ngx_command_t ngx_http_endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     endgame_conf_set_mode, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, mode), NULL},
    {ngx_string("endgame_auto_login"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, auto_login), NULL},
    {ngx_string("endgame_login_control_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, login_control_header), NULL},
    {ngx_string("endgame_session_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_name), NULL},
    {ngx_string("endgame_session_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     endgame_conf_set_session_key, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_key), NULL},
    {ngx_string("endgame_session_ttl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_ttl), NULL},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_domain), NULL},
    {ngx_string("endgame_discovery_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, discovery_url), NULL},
    {ngx_string("endgame_client_id"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, client_id), NULL},
    {ngx_string("endgame_client_secret"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, client_secret), NULL},
    {ngx_string("endgame_callback_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, callback_url), NULL},
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

  return NGX_OK;
}

static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r) {
  ngx_http_endgame_conf_t *egcf =
      ngx_http_get_module_loc_conf(r, ngx_http_endgame_module);

  switch (egcf->mode) {
  case CALLBACK:
    return ngx_http_endgame_callback(r, egcf);
  case ENABLED:
    break;
  default:
    return NGX_DECLINED;
  }

  ngx_table_elt_t *cookie;
  ngx_str_t value;

  cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                             &egcf->session_name, &value);

  if (cookie == NULL || value.len == 0) {
    return endgame_handle_unauthed(r, egcf);
  }

  RustSlice email = endgame_rust_slice_null(),
            given = endgame_rust_slice_null(),
            family = endgame_rust_slice_null();

  Error error = endgame_token_decrypt(
      egcf->session_key, value, egcf->session_ttl, &email, &given, &family);
  if (error.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to decrypt cookie: '%V'", &error);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  if (email.ptr == NULL || email.len == 0) {
    endgame_rust_slice_free(&email);
    endgame_rust_slice_free(&given);
    endgame_rust_slice_free(&family);
    return endgame_handle_unauthed(r, egcf);
  }

  ngx_int_t result;
  result = endgame_set_header(r, (ngx_str_t)ngx_string("X-Email"), email);
  if (result != NGX_OK) {
    endgame_rust_slice_free(&given);
    endgame_rust_slice_free(&family);
    return result;
  }

  result = endgame_set_header(r, (ngx_str_t)ngx_string("X-Given-Name"), given);
  if (result != NGX_OK) {
    endgame_rust_slice_free(&family);
    return result;
  }

  result =
      endgame_set_header(r, (ngx_str_t)ngx_string("X-Family-Name"), family);
  if (result != NGX_OK) {
    return result;
  }

  return NGX_DECLINED;
}

static ngx_int_t ngx_http_endgame_callback(ngx_http_request_t *r,
                                           ngx_http_endgame_conf_t *egcf) {
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Args: '%V'", &r->args);
  return NGX_HTTP_INSUFFICIENT_STORAGE;
}

static ngx_str_t endgame_take_rust_slice(ngx_pool_t *pool, RustSlice *slice) {
  ngx_str_t output = {.data = ngx_pnalloc(pool, slice->len), .len = slice->len};
  if (output.data != NULL) {
    ngx_memcpy(output.data, slice->ptr, slice->len);
  }
  endgame_rust_slice_free(slice);
  return output;
}

static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    RustSlice header_value) {
  // Disable the header first thing
  ngx_table_elt_t *header =
      endgame_header_find(&r->headers_in.headers.part, header_name);
  if (header != NULL) {
    header->hash = 0;
  }

  // If the incoming value is null, stop here
  if (header_value.ptr == NULL || header_value.len == 0) {
    endgame_rust_slice_free(&header_value);
    return NGX_OK;
  }

  // Copy the rust string into a ngx_str_t
  ngx_str_t header_value_str = endgame_take_rust_slice(r->pool, &header_value);
  if (header_value_str.data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "Could not allocate `%V` string", &header_name);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  // If the header already existed, copy the value in, enable, and stop here
  if (header != NULL) {
    header->hash = 1;
    header->value = header_value_str;
    return NGX_OK;
  }

  header = ngx_list_push(&r->headers_in.headers);
  if (header == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "Could not allocate `%V` header", &header_name);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  header->hash = 1;
  header->key = header_name;
  header->value = header_value_str;

  return NGX_OK;
}

static ngx_int_t endgame_handle_unauthed(ngx_http_request_t *r,
                                         ngx_http_endgame_conf_t *egcf) {
  ngx_table_elt_t *maybe_header = endgame_header_find(
      &r->headers_in.headers.part, egcf->login_control_header);

  // Endgame-Login: never
  // Endgame-Login: always
  if (egcf->auto_login) {
    if (maybe_header != NULL &&
        !endgame_ngx_str_t_eq(maybe_header->value,
                              (ngx_str_t)ngx_string("never"))) {
      return endgame_redirect_login(r, egcf);
    }
  } else {
    if (maybe_header != NULL &&
        endgame_ngx_str_t_eq(maybe_header->value,
                             (ngx_str_t)ngx_string("always"))) {
      return endgame_redirect_login(r, egcf);
    }
  }
  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_table_elt_t *endgame_header_find(ngx_list_part_t *part,
                                            ngx_str_t name) {
  if (name.data == NULL) {
    return NULL;
  }

  ngx_table_elt_t *h = part->elts;

  for (ngx_uint_t i = 0;; i++) {
    // Need to got to the next block
    if (i >= part->nelts) {
      if (part->next == NULL) {
        break;
      }
      part = part->next;
      h = part->elts;
      i = 0;
    }

    ngx_str_t key = h[i].key;
    if (endgame_ngx_str_t_eq(key, name)) {
      return &h[i];
    }
  }

  return NULL;
}

static ngx_int_t endgame_ngx_str_t_eq(ngx_str_t left, ngx_str_t right) {
  if (left.data == NULL || right.data == NULL) {
    return left.data == right.data;
  }

  return left.len == right.len &&
         (left.data == right.data ||
          ngx_strncasecmp(left.data, right.data, left.len) == 0);
}

static ngx_int_t endgame_redirect_login(ngx_http_request_t *r,
                                        ngx_http_endgame_conf_t *egcf) {
  RustSlice location = endgame_rust_slice_null();

  Error error = endgame_oidc_get_url(egcf->session_key, egcf->oidc_id,
                                     r->headers_in.host->value, r->unparsed_uri,
                                     &location);

  if (error.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to get auth url: '%V'", &error);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  ngx_table_elt_t *loc = ngx_list_push(&r->headers_out.headers);
  if (loc == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  loc->hash = 1;
  ngx_str_set(&loc->key, "Location");
  loc->value = endgame_take_rust_slice(r->pool, &location);
  return NGX_HTTP_MOVED_TEMPORARILY;
}

static void *ngx_http_endgame_create_conf(ngx_conf_t *cf) {
  ngx_http_endgame_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_endgame_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->mode = UNSET;
  conf->auto_login = NGX_CONF_UNSET;
  conf->session_ttl = NGX_CONF_UNSET;

  return conf;
}

static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child) {
  ngx_http_endgame_conf_t *prev = parent;
  ngx_http_endgame_conf_t *conf = child;

  if (prev->mode == CALLBACK) {
    return "cannot have an endgame callback as a parent";
  }

  if (conf->mode == UNSET) {
    conf->mode = (prev->mode == UNSET) ? DISABLED : prev->mode;
  }

  ngx_conf_merge_value(conf->auto_login, prev->auto_login, 0);
  ngx_conf_merge_str_value(conf->login_control_header,
                           prev->login_control_header, "Endgame-Login");
  ngx_conf_merge_str_value(conf->session_name, prev->session_name, "endgame");
  ngx_conf_merge_sec_value(conf->session_ttl, prev->session_ttl, 60 * 60);
  ngx_conf_merge_str_value(conf->session_domain, prev->session_domain, "");
  ngx_conf_merge_str_value(conf->discovery_url, prev->discovery_url, "");
  ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
  ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
  ngx_conf_merge_str_value(conf->callback_url, prev->callback_url, "");

  if (!conf->session_key_set) {
    if (prev->session_key_set) {
      conf->session_key = prev->session_key;
      conf->session_key_set = 1;
    } else if (conf->mode == ENABLED || conf->mode == CALLBACK) {
      return "missing endame_session_key";
    }
  }

  Error error = endgame_oidc_discover(conf->discovery_url, conf->client_id,
                                      conf->client_secret, conf->callback_url,
                                      &conf->oidc_id);
  if (error.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to call OIDC discover: '%V'",
                  &error);
    return "endgame discovery could not be called";
  }

  if (conf->oidc_id == 0) {
    return "endgame discovery not initialized";
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->session_key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  arg += 1;

  if (endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("on"))) {
    egcf->mode = ENABLED;
  } else if (endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("off"))) {
    egcf->mode = DISABLED;
  } else if (endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("callback"))) {
    egcf->mode = CALLBACK;
  } else {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "unexpected value: '%V'", arg);
    return "should be 'on', 'off', or 'callback'";
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf) {
  ngx_str_t *field = (ngx_str_t *)((char *)conf + cmd->offset);

  if (field->data) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  arg += 1;

  if (arg->data == NULL || arg->len == 0) {
    return "is empty";
  }

  endgame_ngx_str_t_trim(arg);

  *field = *arg;

  return NGX_CONF_OK;
}

static char *endgame_conf_set_nonempty_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
  char *out = endgame_conf_set_str(cf, cmd, conf);
  if (out) {
    return out;
  }

  ngx_str_t *field = (ngx_str_t *)((char *)conf + cmd->offset);

  if (field->len == 0) {
    return "is just whitespaces";
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_session_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                          void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->session_key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  ngx_str_t *kind = arg + 1;
  ngx_str_t *value = arg + 2;

  if (endgame_ngx_str_t_eq(*kind, (ngx_str_t)ngx_string("raw"))) {
    if (value->len != 44 || value->data[43] != '=' || value->data[42] == '=') {
      return "is not a 32-byte key";
    }

    ngx_str_t decoded = {.data = egcf->session_key.bytes};
    // Using the actual destination for decrypting
    // Here we know that it should fit, and we leave the decoding to set the
    // `len` field
    if (ngx_decode_base64(&decoded, value) == NGX_ERROR) {
      return "is not valid base64";
    }

    if (decoded.len != 32) {
      return "is not a decoded 32-byte key";
    }

    egcf->session_key_set = 1;
  } else if (endgame_ngx_str_t_eq(*kind, (ngx_str_t)ngx_string("file"))) {
    Error error = endgame_load_key(*value, &egcf->session_key);
    if (error.data != NULL) {
      ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to load key: '%V'",
                    &error);
      return "does not point to a valid key";
    }

  } else {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "unexpected value: '%V'", kind);
    return "should be 'raw' or 'file'";
  }

  egcf->session_key_set = 1;
  return NGX_CONF_OK;
}
