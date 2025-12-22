#pragma once

#include <stdint.h>
#include <ngx_string.h>

typedef struct Error {
  size_t len;
  const uint8_t *data;
} Error;

typedef struct Key {
  uint8_t bytes[32];
} Key;

typedef struct RustSlice {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} RustSlice;

struct Error endgame_load_key(ngx_str_t path, struct Key *key);

struct Error endgame_token_decrypt(struct Key key,
                                   ngx_str_t src,
                                   uint64_t max_age_secs,
                                   struct RustSlice *email,
                                   struct RustSlice *given_name,
                                   struct RustSlice *family_name);

struct Error endgame_oidc_discover(ngx_str_t discovery_url,
                                   ngx_str_t client_id,
                                   ngx_str_t client_secret,
                                   ngx_str_t callback_url,
                                   uint64_t *oidc_id);

struct Error endgame_oidc_get_url(struct Key key,
                                  uint64_t id,
                                  ngx_str_t redirect_host,
                                  ngx_str_t redirect_uri,
                                  struct RustSlice *auth_url);

void endgame_ngx_str_t_trim(ngx_str_t *string);

struct RustSlice endgame_rust_slice_null(void);

void endgame_rust_slice_free(struct RustSlice *self);
