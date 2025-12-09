#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <endgame.h>

#include <limits.h>
#include <stdio.h>

struct ngx_http_endgame_conf_s;
typedef struct ngx_http_endgame_conf_s ngx_http_endgame_conf_t;

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r);
static void *ngx_http_endgame_create_conf(ngx_conf_t *cf);
static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child);
static char *ngx_http_endgame_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                      void *conf);
static char *ngx_http_endgame_set_nonempty_str(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf);
static char *ngx_http_endgame_set_session_key(ngx_conf_t *cf,
                                              ngx_command_t *cmd, void *conf);

static ngx_int_t endgame_handle_unauthed(ngx_http_request_t *r,
                                         ngx_http_endgame_conf_t *egcf);
static ngx_table_elt_t *endgame_find_header(ngx_list_part_t *part,
                                            ngx_str_t name);
static ngx_int_t endgame_login_control_header_matches(
    ngx_http_request_t *r, ngx_http_endgame_conf_t *egcf, ngx_str_t value);
static ngx_int_t endgame_redirect_login(ngx_http_request_t *r,
                                        ngx_http_endgame_conf_t *egcf);
static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    RustSlice header_value);

struct ngx_http_endgame_conf_s {
  ngx_flag_t enable;
  ngx_flag_t auto_login;
  ngx_str_t login_control_header;
  ngx_str_t session_name;
  Key session_key;
  ngx_flag_t session_key_set;
  time_t session_ttl;
  ngx_str_t session_domain;
};

static ngx_command_t ngx_http_endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, enable), NULL},
    {ngx_string("endgame_auto_login"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, auto_login), NULL},
    {ngx_string("endgame_login_control_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, login_control_header), NULL},
    {ngx_string("endgame_session_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_name), NULL},
    {ngx_string("endgame_session_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     ngx_http_endgame_set_session_key, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_key), NULL},
    {ngx_string("endgame_session_ttl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_ttl), NULL},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_set_str, NGX_HTTP_LOC_CONF_OFFSET,
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

  return NGX_OK;
}

static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r) {

  ngx_table_elt_t *cookie;
  ngx_str_t value;

  ngx_http_endgame_conf_t *egcf =
      ngx_http_get_module_loc_conf(r, ngx_http_endgame_module);

  if (!egcf->enable) {
    return NGX_DECLINED;
  }

  cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
                                             &egcf->session_name, &value);

  if (cookie == NULL || value.len == 0) {
    return endgame_handle_unauthed(r, egcf);
  }

  RustSlice email = endgame_rust_slice_null(),
            given = endgame_rust_slice_null(),
            family = endgame_rust_slice_null();

  Error error = endgame_decrypt(egcf->session_key, value, egcf->session_ttl,
                                &email, &given, &family);
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

static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    RustSlice header_value) {
  // Disable the header first thing
  ngx_table_elt_t *header =
      endgame_find_header(&r->headers_in.headers.part, header_name);
  if (header != NULL) {
    header->hash = 0;
  }

  // If the incoming value is null, stop here
  if (header_value.ptr == NULL || header_value.len == 0) {
    endgame_rust_slice_free(&header_value);
    return NGX_OK;
  }

  // Copy the rust string into a ngx_str_t
  ngx_str_t header_value_str = {.data = ngx_pnalloc(r->pool, header_value.len),
                                .len = header_value.len};
  if (header_value_str.data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "Could not allocate `%V` string", &header_name);
    endgame_rust_slice_free(&header_value);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_memcpy(header_value_str.data, header_value.ptr, header_value.len);
  endgame_rust_slice_free(&header_value);

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
  // Endgame-Login: never
  // Endgame-Login: always
  if (egcf->auto_login) {
    if (!endgame_login_control_header_matches(r, egcf,
                                              (ngx_str_t)ngx_string("never"))) {
      return endgame_redirect_login(r, egcf);
    }
  } else {
    if (endgame_login_control_header_matches(r, egcf,
                                             (ngx_str_t)ngx_string("always"))) {
      return endgame_redirect_login(r, egcf);
    }
  }
  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_table_elt_t *endgame_find_header(ngx_list_part_t *part,
                                            ngx_str_t name) {

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
    if (key.data != NULL && key.len == name.len &&
        ngx_strncasecmp(key.data, name.data, key.len) == 0) {
      return &h[i];
    }
  }

  return NULL;
}

static ngx_int_t endgame_login_control_header_matches(
    ngx_http_request_t *r, ngx_http_endgame_conf_t *egcf, ngx_str_t value) {
  ngx_table_elt_t *maybe_header = endgame_find_header(
      &r->headers_in.headers.part, egcf->login_control_header);

  return maybe_header != NULL && maybe_header->value.data != NULL &&
         maybe_header->value.len == value.len &&
         (ngx_strncasecmp(maybe_header->value.data, value.data, value.len) ==
          0);
}

static ngx_int_t endgame_redirect_login(ngx_http_request_t *r,
                                        ngx_http_endgame_conf_t *egcf) {
  ngx_table_elt_t *loc = ngx_list_push(&r->headers_out.headers);
  if (loc == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  loc->hash = 1;
  ngx_str_set(&loc->key, "Location");
  // TODO: Need to do the actual redirection here
  loc->value = egcf->login_control_header;
  return NGX_HTTP_MOVED_TEMPORARILY;
}

static void *ngx_http_endgame_create_conf(ngx_conf_t *cf) {
  ngx_http_endgame_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_endgame_conf_t));
  if (conf == NULL) {
    return NGX_CONF_ERROR;
  }

  conf->enable = NGX_CONF_UNSET;
  conf->auto_login = NGX_CONF_UNSET;
  conf->session_ttl = NGX_CONF_UNSET;

  return conf;
}

static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child) {
  ngx_http_endgame_conf_t *prev = parent;
  ngx_http_endgame_conf_t *conf = child;

  ngx_conf_merge_value(conf->enable, prev->enable, 0);
  ngx_conf_merge_value(conf->auto_login, prev->auto_login, 0);
  ngx_conf_merge_str_value(conf->login_control_header,
                           prev->login_control_header, "Endgame-Login");
  ngx_conf_merge_str_value(conf->session_name, prev->session_name, "endgame");
  ngx_conf_merge_sec_value(conf->session_ttl, prev->session_ttl, 60 * 60);
  ngx_conf_merge_str_value(conf->session_domain, prev->session_domain, "");

  if (!conf->session_key_set) {
    if (prev->session_key_set) {
      conf->session_key = prev->session_key;
      conf->session_key_set = 1;
    } else if (conf->enable) {
      return "missing endame_session_key";
    }
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
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

static char *ngx_http_endgame_set_nonempty_str(ngx_conf_t *cf,
                                               ngx_command_t *cmd, void *conf) {
  char *out = ngx_http_endgame_set_str(cf, cmd, conf);
  if (out) {
    return out;
  }

  ngx_str_t *field = (ngx_str_t *)((char *)conf + cmd->offset);

  if (field->len == 0) {
    return "is just whitespaces";
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_set_session_key(ngx_conf_t *cf,
                                              ngx_command_t *cmd, void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->session_key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  ngx_str_t *kind = arg + 1;
  ngx_str_t *value = arg + 2;

  if (kind->len == 3 &&
      ngx_strncasecmp((uint8_t *)"raw", kind->data, kind->len) == 0) {
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
  } else if (kind->len == 4 &&
             ngx_strncasecmp((uint8_t *)"file", kind->data, kind->len) == 0) {
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
