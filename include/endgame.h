#pragma once

#include <stdint.h>
#include <ngx_string.h>

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
  ngx_str_t cookie;
  ngx_str_t redirect;
} LoginResult;

void endgame_ngx_str_t_trim(ngx_str_t *string);

char *endgame_conf_load_key(ngx_str_t path, struct Key *key);

char *endgame_conf_oidc_discover(ngx_str_t discovery_url, size_t *oidc_id);

struct Error endgame_auth_redirect_login_url(struct Key key,
                                             size_t oidc_id,
                                             ngx_str_t client_id,
                                             ngx_str_t callback_url,
                                             ngx_str_t redirect_host,
                                             ngx_str_t redirect_path,
                                             ngx_str_t *login_url,
                                             void *pool);

struct Error endgame_auth_exchange_token(ngx_str_t query,
                                         struct Key key,
                                         size_t oidc_id,
                                         ngx_str_t client_id,
                                         ngx_str_t client_secret,
                                         ngx_str_t callback_url,
                                         ngx_str_t session_name,
                                         ngx_str_t session_domain,
                                         uint64_t session_ttl,
                                         const void *request,
                                         int pipe,
                                         void *pool);

struct Error endgame_token_decrypt(struct Key key,
                                   ngx_str_t src,
                                   ngx_str_t *email,
                                   ngx_str_t *given_name,
                                   ngx_str_t *family_name,
                                   void *pool);
