#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <endgame.h>

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

enum endgame_mode_e;
typedef enum endgame_mode_e endgame_mode_t;
struct endgame_conf_s;
typedef struct endgame_conf_s endgame_conf_t;
struct endgame_redirect_s;
typedef struct endgame_redirect_s endgame_redirect_t;
struct endgame_ctx_s;
typedef struct endgame_ctx_s endgame_ctx_t;

static ngx_int_t endgame_preinit(ngx_conf_t *cf);
static ngx_int_t endgame_init(ngx_conf_t *cf);
static ngx_int_t endgame_init_process(ngx_cycle_t *cycle);
static ngx_int_t endgame_handler(ngx_http_request_t *r);
static ngx_int_t endgame_logout(ngx_http_request_t *r, endgame_conf_t *egcf);
static ngx_int_t endgame_callback(ngx_http_request_t *r, endgame_conf_t *egcf);
static void endgame_finalizer(ngx_event_t *ev);
static void *endgame_create_conf(ngx_conf_t *cf);
static char *endgame_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static char *endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf);
static char *endgame_conf_set_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char *endgame_conf_set_nonempty_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                           void *conf);
static char *endgame_conf_set_loaded_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                         void *conf);
static char *endgame_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf);
static char *endgame_conf_set_whitelist(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf);
static char *endgame_conf_set_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf);

static ngx_int_t endgame_handle_unauthed(ngx_http_request_t *r,
                                         endgame_conf_t *egcf);
static ngx_int_t endgame_handle_redirect_login(ngx_http_request_t *r,
                                               endgame_conf_t *egcf,
                                               bool select_account);

static ngx_int_t endgame_get_var(ngx_http_request_t *r,
                                 ngx_http_variable_value_t *v, uintptr_t data);

static ngx_table_elt_t *endgame_header_find(ngx_list_part_t *part,
                                            ngx_str_t name);
static ngx_int_t endgame_ngx_str_t_eq(ngx_str_t left, ngx_str_t right);
static ngx_int_t endgame_ngx_str_t_starts_with(ngx_str_t string,
                                               ngx_str_t prefix);
static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    ngx_str_t header_value);
static ngx_int_t extract_here(ngx_http_request_t *r, ngx_str_t *location);
static ngx_str_t get_redirect(ngx_http_request_t *r, endgame_conf_t *egcf);
static ngx_int_t endgame_set_location_header(ngx_http_request_t *r,
                                             ngx_str_t header_value);
static ngx_int_t endgame_set_cookie_header(ngx_http_request_t *r,
                                           ngx_str_t header_value);

static int endgame_pipe[2];
static ngx_connection_t *endgame_dummy_conn = NULL;

enum endgame_mode_e {
  UNSET = -1,
  DISABLED = 0,
  ENABLED = 1,
  CALLBACK = 2,
  RESET = 3,
  LOGOUT = 4,
};

#define UNUSED_REF (size_t)-1

struct endgame_conf_oidc_ref_s {
  size_t id;
  uint32_t signature;
};

struct endgame_redirect_s {
  ngx_str_t header;
  ngx_str_t location;
};

struct endgame_ctx_s {
  ngx_str_t email;
  ngx_str_t given;
  ngx_str_t family;
  ngx_str_t picture;
};

struct endgame_conf_s {
  endgame_mode_t mode; // Master switch

  ngx_flag_t auto_login;          // Should it try to login or return 401
  ngx_str_t login_control_header; // Override header for `auto_login`
  endgame_redirect_t redirect;    // Where to redirect to after login
  ngx_array_t *whitelist;         // Optional list of allowed users

  // Temporary
  EndgameKey key;                // Encryption key
  ngx_flag_t key_set;            // If the key was set
  ngx_str_t discovery_url;       // Discovery URL for OIDC endpoints
  ngx_str_t session_name;        // Sesion name in cookie
  time_t session_ttl;            // TTL for the session cookie
  ngx_str_t session_domain;      // Domain for the session cookie
  ngx_str_t client_id;           // OIDC client ID
  ngx_str_t client_secret;       // OIDC client secret
  ngx_str_t client_callback_url; // OIDC callback endpoint

  // Internal
  EndgameKey master_key; // Used for dencrypting the state
  EndgameOidc oidc_ref;  // Id for fetched OIDC config
};

static ngx_http_variable_t endgame_vars[] = {
    {ngx_string("endgame_email"), NULL, endgame_get_var, 0,
     NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("endgame_given_name"), NULL, endgame_get_var, 1,
     NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("endgame_family_name"), NULL, endgame_get_var, 2,
     NGX_HTTP_VAR_NOCACHEABLE, 0},
    {ngx_string("endgame_picture"), NULL, endgame_get_var, 3,
     NGX_HTTP_VAR_NOCACHEABLE, 0},
    ngx_http_null_variable};

static ngx_command_t endgame_commands[] = {
    {ngx_string("endgame"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     endgame_conf_set_mode, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, mode), NULL},

    {ngx_string("endgame_auto_login"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
     ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, auto_login), NULL},
    {ngx_string("endgame_login_control_header"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, login_control_header), NULL},
    {ngx_string("endgame_redirect"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE12,
     endgame_conf_set_redirect, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, redirect), NULL},
    {ngx_string("endgame_whitelist"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_1MORE,
     endgame_conf_set_whitelist, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, whitelist), NULL},

    {ngx_string("endgame_key"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     endgame_conf_set_key, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, key), NULL},
    {ngx_string("endgame_discovery_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, discovery_url), NULL},
    {ngx_string("endgame_session_name"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, session_name), NULL},
    {ngx_string("endgame_session_ttl"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     ngx_conf_set_sec_slot, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, session_ttl), NULL},
    {ngx_string("endgame_session_domain"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, session_domain), NULL},
    {ngx_string("endgame_client_id"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     endgame_conf_set_loaded_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, client_id), NULL},
    {ngx_string("endgame_client_secret"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE2,
     endgame_conf_set_loaded_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, client_secret), NULL},
    {ngx_string("endgame_client_callback_url"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
         NGX_CONF_TAKE1,
     endgame_conf_set_nonempty_str, NGX_HTTP_LOC_CONF_OFFSET,
     offsetof(endgame_conf_t, client_callback_url), NULL},

    ngx_null_command};

static ngx_http_module_t endgame_module_ctx = {
    endgame_preinit,     /* preconfiguration */
    endgame_init,        /* postconfiguration */
    NULL,                /* create main configuration */
    NULL,                /* init main configuration */
    NULL,                /* create server configuration */
    NULL,                /* merge server configuration */
    endgame_create_conf, /* create location configuration */
    endgame_merge_conf,  /* merge location configuration */
};

ngx_module_t ngx_http_endgame_module = {
    NGX_MODULE_V1,
    &endgame_module_ctx,  /* module context */
    endgame_commands,     /* module directives */
    NGX_HTTP_MODULE,      /* module type */
    NULL,                 /* init master */
    NULL,                 /* init module */
    endgame_init_process, /* init process */
    NULL,                 /* init thread */
    NULL,                 /* exit thread */
    NULL,                 /* exit process */
    NULL,                 /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t endgame_preinit(ngx_conf_t *cf) {
  endgame_conf_clear();

  ngx_http_variable_t *var, *v;

  for (v = endgame_vars; v->name.len; ++v) {
    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      return NGX_ERROR;
    }
    var->get_handler = v->get_handler;
    var->data = v->data;
  }

  return NGX_OK;
}

static ngx_int_t endgame_init(ngx_conf_t *cf) {
  ngx_http_core_main_conf_t *cmcf =
      ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

  ngx_http_handler_pt *h =
      ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = endgame_handler;

  return NGX_OK;
}

static ngx_int_t endgame_init_process(ngx_cycle_t *cycle) {
  if (pipe(endgame_pipe) == -1) {
    return NGX_ERROR;
  }

  // Set non-blocking on the read end
  ngx_nonblocking(endgame_pipe[0]);

  // Create dummy connection for the Event Loop
  endgame_dummy_conn = ngx_get_connection(endgame_pipe[0], cycle->log);
  if (endgame_dummy_conn == NULL)
    return NGX_ERROR;

  endgame_dummy_conn->data = NULL;

  ngx_event_t *rev = endgame_dummy_conn->read;
  rev->handler = endgame_finalizer;
  rev->log = cycle->log;

  // Add read-end of pipe to epoll/kqueue
  if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
    return NGX_ERROR;
  }

  return NGX_OK;
}

static ngx_int_t endgame_handler(ngx_http_request_t *r) {
  endgame_conf_t *egcf =
      ngx_http_get_module_loc_conf(r, ngx_http_endgame_module);

  switch (egcf->mode) {
  case LOGOUT:
    return endgame_logout(r, egcf);
  case RESET:
    return endgame_handle_redirect_login(r, egcf, true);
  case CALLBACK:
    return endgame_callback(r, egcf);
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

  endgame_ctx_t *ctx = ngx_palloc(r->pool, sizeof(endgame_ctx_t));
  if (ctx == NULL) {
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }
  ngx_http_set_ctx(r, ctx, ngx_http_endgame_module);

  EndgameError error =
      endgame_token_decrypt(egcf->key, value, &ctx->email, &ctx->given,
                            &ctx->family, &ctx->picture, r->pool);
  if (error.msg.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to decrypt cookie: '%V'", &error.msg);
  }
  if (error.status != NGX_OK) {
    return error.status;
  }

  if (ctx->email.data == NULL) {
    return endgame_handle_unauthed(r, egcf);
  }

  if (egcf->whitelist != NULL) {
    ngx_str_t *whitelisted = egcf->whitelist->elts;
    for (ngx_uint_t i = 0; i < egcf->whitelist->nelts; ++i) {
      if (endgame_ngx_str_t_eq(ctx->email, whitelisted[i])) {
        goto whitelisted;
      }
    }
    return NGX_HTTP_FORBIDDEN;
  whitelisted:;
  }

  ngx_int_t result;
  result = endgame_set_header(r, (ngx_str_t)ngx_string("X-Email"), ctx->email);
  if (result != NGX_OK) {
    return result;
  }

  result =
      endgame_set_header(r, (ngx_str_t)ngx_string("X-Given-Name"), ctx->given);
  if (result != NGX_OK) {
    return result;
  }

  result = endgame_set_header(r, (ngx_str_t)ngx_string("X-Family-Name"),
                              ctx->family);
  if (result != NGX_OK) {
    return result;
  }

  result =
      endgame_set_header(r, (ngx_str_t)ngx_string("X-Picture"), ctx->picture);
  if (result != NGX_OK) {
    return result;
  }

  return NGX_DECLINED;
}

static ngx_int_t endgame_logout(ngx_http_request_t *r, endgame_conf_t *egcf) {
  ngx_str_t cookie_killer;

  size_t len =
      sizeof("=;Path=/;Domain=;Max-Age=0;Secure;HttpOnly;SameSite=lax") +
      egcf->session_name.len + egcf->session_domain.len;
  cookie_killer.data = ngx_pnalloc(r->pool, len);
  if (cookie_killer.data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "could not allocate cookie clearing value");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  u_char *end = ngx_snprintf(
      cookie_killer.data, len,
      "%V=;Path=/;Domain=%V;Max-Age=0;Secure;HttpOnly;SameSite=lax",
      &egcf->session_name, &egcf->session_domain);
  cookie_killer.len = end - cookie_killer.data;

  ngx_int_t status = endgame_set_cookie_header(r, cookie_killer);
  if (status != NGX_OK) {
    return status;
  }

  ngx_str_t redirect = get_redirect(r, egcf);
  if (redirect.data == NULL) {
    return NGX_DECLINED;
  }

  status = endgame_set_location_header(r, redirect);
  if (status != NGX_OK) {
    return status;
  }
  return NGX_HTTP_MOVED_TEMPORARILY;
}

static ngx_int_t endgame_callback(ngx_http_request_t *r, endgame_conf_t *egcf) {
  EndgameError error = endgame_auth_exchange_token(egcf->master_key, r->args, r,
                                                   endgame_pipe[1], r->pool);
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

static void endgame_finalizer(ngx_event_t *ev) {
  static EndgameResult result;
  static size_t b;

  for (;;) {
    for (;;) {
      ssize_t n = read(endgame_pipe[0], ((uint8_t *)&result) + b,
                       sizeof(EndgameResult) - b);

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

      if (b == sizeof(EndgameResult)) {
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
    status = endgame_set_cookie_header(r, result.cookie);
    if (status != NGX_OK) {
      ngx_http_finalize_request(r, status);
      continue;
    }

    if (result.redirect.data == NULL) {
      ngx_http_finalize_request(r, NGX_HTTP_OK);
      continue;
    }

    status = endgame_set_location_header(r, result.redirect);
    if (status != NGX_OK) {
      ngx_http_finalize_request(r, status);
      continue;
    }

    ngx_http_finalize_request(r, NGX_HTTP_MOVED_TEMPORARILY);
  }
}

static ngx_int_t endgame_set_header(ngx_http_request_t *r,
                                    ngx_str_t header_name,
                                    ngx_str_t header_value) {
  // Disable the header first thing
  ngx_table_elt_t *header =
      endgame_header_find(&r->headers_in.headers.part, header_name);
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

static ngx_int_t endgame_set_location_header(ngx_http_request_t *r,
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

static ngx_int_t endgame_set_cookie_header(ngx_http_request_t *r,
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

static ngx_int_t endgame_handle_unauthed(ngx_http_request_t *r,
                                         endgame_conf_t *egcf) {
  ngx_table_elt_t *maybe_header = endgame_header_find(
      &r->headers_in.headers.part, egcf->login_control_header);

#define header_is(wanted_value)                                                \
  (maybe_header != NULL &&                                                     \
   endgame_ngx_str_t_eq(maybe_header->value,                                   \
                        (ngx_str_t)ngx_string(wanted_value)))

  // Endgame-AutoLogin: never
  // Endgame-AutoLogin: always
  if (egcf->auto_login) {
    if (header_is("never")) {
      return NGX_HTTP_UNAUTHORIZED;
    }
    return endgame_handle_redirect_login(r, egcf, false);
  } else {
    if (header_is("always")) {
      return endgame_handle_redirect_login(r, egcf, false);
    }
    return NGX_HTTP_UNAUTHORIZED;
  }
#undef header_is
}

static ngx_int_t endgame_get_var(ngx_http_request_t *r,
                                 ngx_http_variable_value_t *v, uintptr_t data) {
  endgame_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_endgame_module);

  if (ctx == NULL) {
    v->not_found = 1;
    return NGX_OK;
  }

  ngx_str_t *target;
  switch (data) {
  case 0:
    target = &ctx->email;
    break;
  case 1:
    target = &ctx->given;
    break;
  case 2:
    target = &ctx->family;
    break;
  case 3:
    target = &ctx->picture;
    break;
  default:
    v->not_found = 1;
    return NGX_OK;
  }

  if (target->data != NULL) {
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = target->len;
    v->data = target->data;
  } else {
    v->not_found = 1;
  }

  return NGX_OK;
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

static ngx_int_t endgame_ngx_str_t_starts_with(ngx_str_t string,
                                               ngx_str_t prefix) {
  if (string.data == NULL || prefix.data == NULL) {
    return false;
  }

  return string.len >= prefix.len &&
         ngx_strncasecmp(string.data, prefix.data, prefix.len) == 0;
}

static ngx_int_t extract_here(ngx_http_request_t *r, ngx_str_t *location) {
  size_t len = r->unparsed_uri.len + 1;

  location->data = ngx_pnalloc(r->pool, len);
  if (location->data == NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "could not allocate redirect value");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  u_char *p = location->data;
  *p++ = '/';
  p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);
  location->len = p - location->data;

  return NGX_OK;
}

static ngx_str_t get_redirect(ngx_http_request_t *r, endgame_conf_t *egcf) {
  ngx_str_t redirect;
  if (ngx_http_arg(r, egcf->redirect.header.data, egcf->redirect.header.len,
                   &redirect) == NGX_OK) {
  } else if (egcf->redirect.location.data != NULL) {
    redirect = egcf->redirect.location;
  } else {
    ngx_str_null(&redirect);
  }

  return redirect;
}

static ngx_int_t endgame_handle_redirect_login(ngx_http_request_t *r,
                                               endgame_conf_t *egcf,
                                               bool select_account) {
  ngx_str_t redirect = get_redirect(r, egcf);
  if (redirect.data == NULL) {
    ngx_int_t result = extract_here(r, &redirect);
    if (result != NGX_OK) {
      return result;
    }
  }

  ngx_str_t location;
  EndgameError error = endgame_auth_redirect_login_url(
      egcf->master_key, egcf->oidc_ref, redirect, select_account, &location,
      r->pool);
  if (error.msg.data != NULL) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "failed to get auth url: '%V'", &error.msg);
  }
  if (error.status != NGX_OK) {
    return error.status;
  }

  ngx_int_t status = endgame_set_location_header(r, location);
  if (status != NGX_OK) {
    return status;
  }
  return NGX_HTTP_MOVED_TEMPORARILY;
}

static void *endgame_create_conf(ngx_conf_t *cf) {
  endgame_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(endgame_conf_t));
  if (conf == NULL) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                  "failed to create configuration context");
    return NGX_CONF_ERROR;
  }

  conf->mode = UNSET;

  conf->auto_login = NGX_CONF_UNSET;
  conf->whitelist = NGX_CONF_UNSET_PTR;

  conf->session_ttl = NGX_CONF_UNSET;

  conf->master_key = endgame_conf_random_key();
  conf->oidc_ref.id = UNUSED_REF;

  return conf;
}

static char *endgame_merge_conf(ngx_conf_t *cf, void *parent, void *child) {
  endgame_conf_t *prev = parent;
  endgame_conf_t *conf = child;

  if (prev->mode == LOGOUT) {
    return "cannot have a logout as a parent";
  }

  if (prev->mode == RESET) {
    return "cannot have a reset as a parent";
  }

  if (prev->mode == CALLBACK) {
    return "cannot have a callback as a parent";
  }

  if (conf->mode == UNSET) {
    conf->mode = (prev->mode == UNSET) ? DISABLED : prev->mode;
  }

  ngx_conf_merge_value(conf->auto_login, prev->auto_login, 1);
  ngx_conf_merge_str_value(conf->login_control_header,
                           prev->login_control_header, "Endgame-AutoLogin");
  ngx_conf_merge_ptr_value(conf->whitelist, prev->whitelist, NULL);

  if (conf->redirect.header.data == NULL) {
    if (prev->redirect.header.data) {
      conf->redirect.header = prev->redirect.header;
      conf->redirect.location = prev->redirect.location;
    } else {
      ngx_str_set(&conf->redirect.header, "redirect");
      ngx_str_null(&conf->redirect.location);
    }
  }

  if (!conf->key_set) {
    if (prev->key_set) {
      conf->key = prev->key;
      conf->key_set = 1;
    }
  }

  ngx_conf_merge_str_value(conf->discovery_url, prev->discovery_url, "");
  ngx_conf_merge_str_value(conf->session_name, prev->session_name, "endgame");
  ngx_conf_merge_sec_value(conf->session_ttl, prev->session_ttl, 60 * 60);
  ngx_conf_merge_str_value(conf->session_domain, prev->session_domain, "");
  ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
  ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
  ngx_conf_merge_str_value(conf->client_callback_url, prev->client_callback_url,
                           "");

  conf->master_key = prev->master_key;

  if (conf->mode == DISABLED) {
    return NGX_CONF_OK;
  }

#define check_missing(name)                                                    \
  if (conf->name.len == 0)                                                     \
    return "is missing endgame_" #name;
  if (!conf->key_set) {
    return "is missing endgame_key";
  }
  check_missing(discovery_url);
  check_missing(client_id);
  check_missing(client_secret);
  check_missing(client_callback_url);
#undef check_missing

  char *error = endgame_conf_push(
      conf->key, conf->discovery_url, conf->session_name, conf->session_ttl,
      conf->session_domain, conf->client_id, conf->client_secret,
      conf->client_callback_url, &conf->oidc_ref);
  if (error != NULL) {
    return error;
  }

  if (conf->oidc_ref.id == UNUSED_REF) {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                  "cannot have more than usize::MAX configurations");
    return "has overflowed the number of OIDC configurations";
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd,
                                   void *conf) {
  endgame_conf_t *egcf = conf;

  if (egcf->mode != UNSET) {
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
  } else if (endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("reset"))) {
    egcf->mode = RESET;
  } else if (endgame_ngx_str_t_eq(*arg, (ngx_str_t)ngx_string("logout"))) {
    egcf->mode = LOGOUT;
  } else {
    ngx_log_error(NGX_LOG_ERR, cf->log, 0, "unexpected value: '%V'", arg);
    return "should be 'on', 'off', 'callback', 'reset', or 'logout'";
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
    return "is just whitespace";
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_loaded_str(ngx_conf_t *cf, ngx_command_t *cmd,
                                         void *conf) {
  ngx_str_t *field = (ngx_str_t *)((char *)conf + cmd->offset);
  if (field->data) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  ngx_str_t *kind = arg + 1;
  ngx_str_t *value = arg + 2;

  char *error = endgame_conf_load_string(*kind, *value, field, cf->pool);
  if (error != NULL) {
    return error;
  }

  return NGX_CONF_OK;
}

static char *endgame_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd,
                                  void *conf) {
  endgame_conf_t *egcf = conf;

  if (egcf->key_set) {
    return "is duplicate";
  }

  ngx_str_t *arg = cf->args->elts;
  ngx_str_t *kind = arg + 1;
  ngx_str_t *value = arg + 2;

  if (endgame_ngx_str_t_eq(*kind, (ngx_str_t)ngx_string("raw"))) {
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
  } else if (endgame_ngx_str_t_eq(*kind, (ngx_str_t)ngx_string("file"))) {
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

static char *endgame_conf_set_whitelist(ngx_conf_t *cf, ngx_command_t *cmd,
                                        void *conf) {
  endgame_conf_t *egcf = conf;

  ngx_str_t *arg = cf->args->elts;

  if (egcf->whitelist != NGX_CONF_UNSET_PTR) {
    return "is duplicate";
  }

  // Capture `endgame_whitelist off`
  if (endgame_ngx_str_t_eq(arg[1], (ngx_str_t)ngx_string("off"))) {

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
    if (endgame_ngx_str_t_eq(value, (ngx_str_t)ngx_string("off"))) {
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

static char *endgame_conf_set_redirect(ngx_conf_t *cf, ngx_command_t *cmd,
                                       void *conf) {
  endgame_conf_t *egcf = conf;

  ngx_str_t *arg = cf->args->elts;

  if (egcf->redirect.header.data) {
    return "is duplicate";
  }

  ngx_str_t value = arg[1];

  endgame_ngx_str_t_trim(&value);

  if (value.len == 0) {
    return "is just whitespace";
  }

  egcf->redirect.header = value;

  if (cf->args->nelts == 3) {
    ngx_str_t value = arg[2];

    endgame_ngx_str_t_trim(&value);

    if (value.len == 0) {
      return "default location is just whitespace";
    }

    if (value.data[0] != '/' && !endgame_ngx_str_t_starts_with(
                                    value, (ngx_str_t)ngx_string("https://"))) {
      return "does not start with '/' or 'https://'";
    }

    egcf->redirect.location = value;
  } else {
    ngx_str_null(&egcf->redirect.location);
  }

  return NGX_CONF_OK;
}
