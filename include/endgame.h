#pragma once

#include <stdint.h>
#include <ngx_string.h>

typedef struct RustSlice {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} RustSlice;

typedef struct Key {
  uint8_t bytes[32];
} Key;

typedef struct Error {
  uint16_t status;
  ngx_str_t msg;
} Error;

typedef struct LoginResult {
  const void *request;
  uint16_t status;
  struct RustSlice cookie;
  struct RustSlice redirect;
} LoginResult;

void endgame_ngx_str_t_trim(ngx_str_t *string);

struct RustSlice endgame_rust_slice_null(void);

void endgame_rust_slice_free(struct RustSlice *self);

char *endgame_conf_load_key(ngx_str_t path, struct Key *key);

char *endgame_conf_oidc_discover(ngx_str_t discovery_url, size_t *oidc_id);

struct Error endgame_auth_redirect_login_url(struct Key key,
                                             size_t oidc_id,
                                             ngx_str_t client_id,
                                             ngx_str_t callback_url,
                                             ngx_str_t redirect_host,
                                             ngx_str_t redirect_path,
                                             struct RustSlice *login_url);

struct Error endgame_auth_exchange_token(ngx_str_t query,
                                         struct Key key,
                                         size_t oidc_id,
                                         ngx_str_t client_id,
                                         ngx_str_t client_secret,
                                         ngx_str_t callback_url,
                                         ngx_str_t session_name,
                                         ngx_str_t session_domain,
                                         int64_t session_ttl,
                                         const void *request,
                                         int pipe);

struct Error endgame_token_decrypt(struct Key key,
                                   ngx_str_t src,
                                   uint64_t max_age_secs,
                                   struct RustSlice *email,
                                   struct RustSlice *given_name,
                                   struct RustSlice *family_name);
