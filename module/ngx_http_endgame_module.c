#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// TODO
// #include <endgame.h>
#include "../include/endgame.h"

#include <limits.h>
#include <stdio.h>
#include <unistd.h>

enum ngx_http_endgame_mode_e;
typedef enum ngx_http_endgame_mode_e ngx_http_endgame_mode_t;
struct ngx_http_endgame_conf_s;
typedef struct ngx_http_endgame_conf_s ngx_http_endgame_conf_t;

static ngx_int_t ngx_http_endgame_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_endgame_init_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_endgame_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_endgame_callback(ngx_http_request_t *r,
                                           ngx_http_endgame_conf_t *egcf);
static void ngx_http_endgame_finalizer(ngx_event_t *ev);
static void *ngx_http_endgame_create_conf(ngx_conf_t *cf);
static char *ngx_http_endgame_merge_conf(ngx_conf_t *cf, void *parent,
                                         void *child);

static char *ngx_http_endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                            void *conf);
static char *ngx_http_endgame_conf_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static char *ngx_http_endgame_conf_set_nonempty_str(ngx_conf_t *cf,
                                                    ngx_command_t *cmd,
                                                    void *conf);
static char *ngx_http_endgame_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static char *ngx_http_endgame_conf_set_discovery_url(ngx_conf_t *cf,
                                                     ngx_command_t *cmd,
                                                     void *conf);
static char *ngx_http_endgame_conf_set_whitelist(ngx_conf_t *cf,
                                                 ngx_command_t *cmd,
                                                 void *conf);

static ngx_int_t
ngx_http_endgame_handle_unauthed(ngx_http_request_t *r,
                                 ngx_http_endgame_conf_t *egcf);
static ngx_int_t
ngx_http_endgame_handle_redirect_login(ngx_http_request_t *r,
                                       ngx_http_endgame_conf_t *egcf);

static ngx_table_elt_t *ngx_http_endgame_header_find(ngx_list_part_t *part,
                                                     ngx_str_t name);
static ngx_int_t ngx_http_endgame_ngx_str_t_eq(ngx_str_t left, ngx_str_t right);
static ngx_int_t ngx_http_endgame_set_header(ngx_http_request_t *r,
                                             ngx_str_t header_name,
                                             ngx_str_t header_value);
static ngx_int_t ngx_http_endgame_set_location_header(ngx_http_request_t *r,
                                                      ngx_str_t header_value);
static ngx_int_t ngx_http_endgame_set_cookie_header(ngx_http_request_t *r,
                                                    ngx_str_t header_value);

static int ngx_http_endgame_pipe[2];
static ngx_connection_t *ngx_http_endgame_dummy_conn = NULL;

enum ngx_http_endgame_mode_e {
  UNSET = -1,
  DISABLED = 0,
  ENABLED = 1,
  CALLBACK = 2,
};

#define UNUSED_ID (size_t)-1

// TODO: Not all locations require all configs
// TODO: Callbacks (CB) must match the endpoint (EP) config. Right now, we have
// no guarantee of that
// TODO: Group a set of configs into a single entry (key, client_*, callback)
// and possibly merge all of these into a single pointer
struct ngx_http_endgame_conf_s {
  ngx_http_endgame_mode_t mode;   /* All: Master switch */
  Key key;                        /* All: Encryption key */
  ngx_flag_t auto_login;          /* EP: Should it try to login or return 401 */
  ngx_str_t login_control_header; /* EP: Override header for `auto_login` */
  ngx_str_t session_name;         /* All: Sesion name in cookie */
  time_t session_ttl;             /* CB: TTL for the session cookie */
  ngx_str_t session_domain;       /* CB: Domain for the session cookie */
  ngx_str_t client_id;            /* All: OIDC client ID */
  ngx_str_t client_secret;        /* CB: OIDC client secret */
  ngx_str_t callback_url;         /* All: OIDC callback endpoint */
  ngx_array_t *whitelist;         /* EP: Optional list of allowed users */

  // Internal
  ngx_flag_t key_set; /* If the key was set */
  size_t oidc_id;     /* Id for fetched OIDC config */
};

static ngx_command_t ngx_http_endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_http_endgame_conf_set_mode, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, mode), NULL},
    {ngx_string("endgame_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     ngx_http_endgame_conf_set_key, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, key), NULL},
    {ngx_string("endgame_auto_login"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, auto_login), NULL},
    {ngx_string("endgame_login_control_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, login_control_header), NULL},
    {ngx_string("endgame_session_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_name), NULL},
    {ngx_string("endgame_session_ttl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_ttl), NULL},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, session_domain), NULL},
    {ngx_string("endgame_discovery_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_discovery_url, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, oidc_id), NULL},
    {ngx_string("endgame_client_id"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, client_id), NULL},
    {ngx_string("endgame_client_secret"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, client_secret), NULL},
    {ngx_string("endgame_callback_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_http_endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, callback_url), NULL},
    {ngx_string("endgame_whitelist"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_1MORE,
     ngx_http_endgame_conf_set_whitelist, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(ngx_http_endgame_conf_t, whitelist), NULL},
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
    &ngx_http_endgame_module_ctx,  /* module context */
    ngx_http_endgame_commands,     /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_endgame_init_process, /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
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

static ngx_int_t ngx_http_endgame_init_process(ngx_cycle_t *cycle) {
  if (pipe(ngx_http_endgame_pipe) == -1) {
    return NGX_ERROR;
  }

  // Set non-blocking on the read end
  ngx_nonblocking(ngx_http_endgame_pipe[0]);

  // Create dummy connection for the Event Loop
  ngx_http_endgame_dummy_conn =
      ngx_get_connection(ngx_http_endgame_pipe[0], cycle->log);
  if (ngx_http_endgame_dummy_conn == NULL)
    return NGX_ERROR;

  ngx_http_endgame_dummy_conn->data = NULL;

  ngx_event_t *rev = ngx_http_endgame_dummy_conn->read;
  rev->handler = ngx_http_endgame_finalizer;
  rev->log = cycle->log;

  // Add read-end of pipe to epoll/kqueue
  if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
    return NGX_ERROR;
  }

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
    return ngx_http_endgame_handle_unauthed(r, egcf);
  }

  ngx_str_t email, given, family;
  Error error =
      endgame_token_decrypt(egcf->key, value, &email, &given, &family, r->pool);
  if (error.msg.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to decrypt cookie: '%V'", &error.msg);
  }
  if (error.status != NGX_OK) {
    return error.status;
  }

  if (email.data == NULL) {
    return ngx_http_endgame_handle_unauthed(r, egcf);
  }

  if (egcf->whitelist != NULL) {
    ngx_str_t *whitelisted = egcf->whitelist->elts;
    for (ngx_uint_t i = 0; i < egcf->whitelist->nelts; ++i) {
      if (ngx_http_endgame_ngx_str_t_eq(email, whitelisted[i])) {
        return NGX_DECLINED;
      }
    }
    return NGX_HTTP_FORBIDDEN;
  }

  ngx_int_t result;
  result =
      ngx_http_endgame_set_header(r, (ngx_str_t)ngx_string("X-Email"), email);
  if (result != NGX_OK) {
    return result;
  }

  result = ngx_http_endgame_set_header(r, (ngx_str_t)ngx_string("X-Given-Name"),
                                       given);
  if (result != NGX_OK) {
    return result;
  }

  result = ngx_http_endgame_set_header(
      r, (ngx_str_t)ngx_string("X-Family-Name"), family);
  if (result != NGX_OK) {
    return result;
  }

  return NGX_DECLINED;
}

static ngx_int_t ngx_http_endgame_callback(ngx_http_request_t *r,
                                           ngx_http_endgame_conf_t *egcf) {
  Error error = endgame_auth_exchange_token(
      r->args, egcf->key, egcf->oidc_id, egcf->client_id, egcf->client_secret,
      egcf->callback_url, egcf->session_name, egcf->session_domain,
      egcf->session_ttl, r, ngx_http_endgame_pipe[1], r->pool);
  if (error.msg.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to get auth url: '%V'", &error.msg);
  }
  if (error.status != NGX_OK) {
    return error.status;
  }

  r->main->count++;
  return NGX_DONE;
}

static void ngx_http_endgame_finalizer(ngx_event_t *ev) {
  static LoginResult result;
  static size_t b;

  for (;;) {
    for (;;) {
      ssize_t n = read(ngx_http_endgame_pipe[0], ((uint8_t *)&result) + b,
                       sizeof(LoginResult) - b);

      if (n == 0) {
        ngx_log_error(NGX_LOG_CRIT, ev->log, 0, "endgame pipe closed");
        ngx_abort();
      }

      if (n == -1) {
        if (ngx_errno == NGX_EAGAIN) {
          return;
        }
        ngx_log_error(NGX_LOG_CRIT, ev->log, 0, "failed to read from pipe: %d",
                      ngx_errno);
        ngx_abort();
      }

      b += n;

      if (b == sizeof(LoginResult)) {
        break;
      }
    }

    b = 0;
    ngx_http_request_t *r = (ngx_http_request_t *)result.request;

    if (result.status != NGX_OK) {
      ngx_http_finalize_request(r, result.status);
      continue;
    }

    if (result.cookie.data == NULL) {
      ngx_http_finalize_request(r, NGX_HTTP_UNAUTHORIZED);
      return;
    }

    ngx_int_t status;
    status = ngx_http_endgame_set_cookie_header(r, result.cookie);
    if (status != NGX_OK) {
      ngx_http_finalize_request(r, status);
      continue;
    }

    if (result.redirect.data == NULL) {
      ngx_http_finalize_request(r, NGX_HTTP_OK);
      continue;
    }

    status = ngx_http_endgame_set_location_header(r, result.redirect);
    if (status != NGX_OK) {
      ngx_http_finalize_request(r, status);
      continue;
    }

    ngx_http_finalize_request(r, NGX_HTTP_MOVED_TEMPORARILY);
  }
}

static ngx_int_t ngx_http_endgame_set_header(ngx_http_request_t *r,
                                             ngx_str_t header_name,
                                             ngx_str_t header_value) {
  // Disable the header first thing
  ngx_table_elt_t *header =
      ngx_http_endgame_header_find(&r->headers_in.headers.part, header_name);
  if (header != NULL) {
    header->hash = 0;
  }

  // If the incoming value is null, stop here
  if (header_value.data == NULL || header_value.len == 0) {
    return NGX_OK;
  }

  // If the header already existed, copy the value in, enable, and stop here
  if (header != NULL) {
    header->hash = 1;
    header->value = header_value;
    return NGX_OK;
  }

  header = ngx_list_push(&r->headers_in.headers);
  if (header == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "could not allocate `%V` header", &header_name);
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  header->hash = 1;
  header->key = header_name;
  header->value = header_value;

  return NGX_OK;
}

static ngx_int_t ngx_http_endgame_set_location_header(ngx_http_request_t *r,
                                                      ngx_str_t location) {
  ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to allocate memory for the location header");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  h->hash = 1;
  ngx_str_set(&h->key, "Location");
  h->value = location;
  r->headers_out.location = h;

  return NGX_OK;
}

static ngx_int_t ngx_http_endgame_set_cookie_header(ngx_http_request_t *r,
                                                    ngx_str_t cookie) {
  ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
  if (h == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to allocate memory for the cookie header");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  h->hash = 1;
  ngx_str_set(&h->key, "Set-Cookie");
  h->value = cookie;

  return NGX_OK;
}

static ngx_int_t
ngx_http_endgame_handle_unauthed(ngx_http_request_t *r,
                                 ngx_http_endgame_conf_t *egcf) {
  ngx_table_elt_t *maybe_header = ngx_http_endgame_header_find(
      &r->headers_in.headers.part, egcf->login_control_header);

  // Endgame-Login: never
  // Endgame-Login: always
  if (egcf->auto_login) {
    if (maybe_header != NULL &&
        !ngx_http_endgame_ngx_str_t_eq(maybe_header->value,
                                       (ngx_str_t)ngx_string("never"))) {
      return ngx_http_endgame_handle_redirect_login(r, egcf);
    }
  } else {
    if (maybe_header != NULL &&
        ngx_http_endgame_ngx_str_t_eq(maybe_header->value,
                                      (ngx_str_t)ngx_string("always"))) {
      return ngx_http_endgame_handle_redirect_login(r, egcf);
    }
  }
  return NGX_HTTP_UNAUTHORIZED;
}

static ngx_table_elt_t *ngx_http_endgame_header_find(ngx_list_part_t *part,
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
    if (ngx_http_endgame_ngx_str_t_eq(key, name)) {
      return &h[i];
    }
  }

  return NULL;
}

static ngx_int_t ngx_http_endgame_ngx_str_t_eq(ngx_str_t left,
                                               ngx_str_t right) {
  if (left.data == NULL || right.data == NULL) {
    return left.data == right.data;
  }

  return left.len == right.len &&
         (left.data == right.data ||
          ngx_strncasecmp(left.data, right.data, left.len) == 0);
}

static ngx_int_t
ngx_http_endgame_handle_redirect_login(ngx_http_request_t *r,
                                       ngx_http_endgame_conf_t *egcf) {
  ngx_str_t location;
  Error error = endgame_auth_redirect_login_url(
      egcf->key, egcf->oidc_id, egcf->client_id, egcf->callback_url,
      r->headers_in.host->value, r->unparsed_uri, &location, r->pool);
  if (error.msg.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to get auth url: '%V'", &error.msg);
  }
  if (error.status != NGX_OK) {
    return error.status;
  }

  ngx_int_t status = ngx_http_endgame_set_location_header(r, location);
  if (status != NGX_OK) {
    return status;
  }
  return NGX_HTTP_MOVED_TEMPORARILY;
}

static void *ngx_http_endgame_create_conf(ngx_conf_t *cf) {
  ngx_http_endgame_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_endgame_conf_t));
  if (conf == NULL) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                  "failed to create configuration context");
    return NGX_CONF_ERROR;
  }

  conf->mode = UNSET;
  conf->auto_login = NGX_CONF_UNSET;
  conf->session_ttl = NGX_CONF_UNSET;
  conf->oidc_id = UNUSED_ID;
  conf->whitelist = NGX_CONF_UNSET_PTR;

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
  ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
  ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
  ngx_conf_merge_str_value(conf->callback_url, prev->callback_url, "");
  ngx_conf_merge_ptr_value(conf->whitelist, prev->whitelist, NULL);

  if (!conf->key_set) {
    if (prev->key_set) {
      conf->key = prev->key;
      conf->key_set = 1;
    }
  }

  if (conf->oidc_id == UNUSED_ID) {
    if (prev->oidc_id != UNUSED_ID) {
      conf->oidc_id = prev->oidc_id;
    }
  }

  if (conf->mode == ENABLED || conf->mode == CALLBACK) {
#define check_missing($name)                                                   \
  if (conf->$name.len == 0)                                                    \
    return "missing endgame_$name";
    check_missing(session_name);
    check_missing(client_id);
    check_missing(client_secret);
    check_missing(callback_url);
#undef check_missing
    if (!conf->key_set) {
      return "missing endame_key";
    }
    if (conf->oidc_id == UNUSED_ID) {
      return "endgame discovery not initialized";
    }
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                            void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  arg += 1;

  if (ngx_http_endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("on"))) {
    egcf->mode = ENABLED;
  } else if (ngx_http_endgame_ngx_str_t_eq(*arg,
                                           (ngx_str_t)ngx_string("off"))) {
    egcf->mode = DISABLED;
  } else if (ngx_http_endgame_ngx_str_t_eq(*arg,
                                           (ngx_str_t)ngx_string("callback"))) {
    egcf->mode = CALLBACK;
  } else {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "unexpected value: '%V'", arg);
    return "should be 'on', 'off', or 'callback'";
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_conf_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
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

static char *ngx_http_endgame_conf_set_nonempty_str(ngx_conf_t *cf,
                                                    ngx_command_t *cmd,
                                                    void *conf) {
  char *out = ngx_http_endgame_conf_set_str(cf, cmd, conf);
  if (out) {
    return out;
  }

  ngx_str_t *field = (ngx_str_t *)((char *)conf + cmd->offset);

  if (field->len == 0) {
    return "is just whitespaces";
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  ngx_str_t *kind = arg + 1;
  ngx_str_t *value = arg + 2;

  if (ngx_http_endgame_ngx_str_t_eq(*kind, (ngx_str_t)ngx_string("raw"))) {
    if (value->len != 44 || value->data[43] != '=' || value->data[42] == '=') {
      return "is not a 32-byte key";
    }

    ngx_str_t decoded = {.data = egcf->key.bytes};
    // Using the actual destination for decrypting
    // Here we know that it should fit, and we leave the decoding to set the
    // `len` field
    if (ngx_decode_base64(&decoded, value) == NGX_ERROR) {
      return "is not valid base64";
    }

    if (decoded.len != 32) {
      return "is not a decoded 32-byte key";
    }

    egcf->key_set = 1;
  } else if (ngx_http_endgame_ngx_str_t_eq(*kind,
                                           (ngx_str_t)ngx_string("file"))) {
    char *error = endgame_conf_load_key(*value, &egcf->key);
    if (error != NULL) {
      return error;
    }
  } else {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "unexpected value: '%V'", kind);
    return "should be 'raw' or 'file'";
  }

  egcf->key_set = 1;
  return NGX_CONF_OK;
}

static char *ngx_http_endgame_conf_set_discovery_url(ngx_conf_t *cf,
                                                     ngx_command_t *cmd,
                                                     void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  if (egcf->oidc_id != UNUSED_ID) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  arg += 1;

  char *error = endgame_conf_oidc_discover(*arg, &egcf->oidc_id);
  if (error != NULL) {
    return error;
  }

  if (egcf->oidc_id == UNUSED_ID) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                  "cannot have more than usize::MAX configurations");
    return "has overflowed the number of OIDC configurations";
  }

  return NGX_CONF_OK;
}

static char *ngx_http_endgame_conf_set_whitelist(ngx_conf_t *cf,
                                                 ngx_command_t *cmd,
                                                 void *conf) {
  ngx_http_endgame_conf_t *egcf = conf;

  ngx_str_t *arg = cf->args->elts;

  if (egcf->whitelist != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }

  // Capture `endgame_whitelist off`
  if (ngx_http_endgame_ngx_str_t_eq(arg[1], (ngx_str_t)ngx_string("off"))) {

    // `off` must be alone
    if (cf->args->nelts > 2) {
      return "must be 'off' or a list of emails, not both";
    }

    egcf->whitelist = NULL;
    return NGX_CONF_OK;
  }

  egcf->whitelist =
      ngx_array_create(cf->pool, cf->args->nelts - 1, sizeof(ngx_str_t));
  if (egcf->whitelist == NULL) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to allocate whitelist");
    return NGX_CONF_ERROR;
  }

  // Add values that are not whitestrings
  for (ngx_uint_t i = 1; i < cf->args->nelts; ++i) {
    ngx_str_t value = arg[i];

    // Trim it
    endgame_ngx_str_t_trim(&value);

    // If `off` is anywhere, this is invalid
    if (ngx_http_endgame_ngx_str_t_eq(value, (ngx_str_t)ngx_string("off"))) {
      return "must be 'off' or a list of emails, not both";
    }

    if (value.len == 0) {
      continue;
    }

    ngx_str_t *s = ngx_array_push(egcf->whitelist);
    if (s == NULL) {
      ngx_log_error(NGX_LOG_ERR, cf->log, 0, "failed to insert into whitelist");
      return NGX_CONF_ERROR;
    }

    *s = value;
  }

  if (egcf->whitelist->nelts == 0) {
    egcf->whitelist = NULL;
  }

  return NGX_CONF_OK;
}
