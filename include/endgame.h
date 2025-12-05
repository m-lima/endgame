#pragma once

#include <stdint.h>
#include <ngx_string.h>

typedef struct Error {
  size_t len;
  const uint8_t *data;
} Error;

typedef uint8_t Key[32];

typedef struct RustSlice {
  uint8_t *ptr;
  size_t len;
  size_t cap;
} RustSlice;

struct Error endgame_decrypt(Key key,
                             ngx_str_t src,
                             uint64_t max_age_secs,
                             struct RustSlice *email,
                             struct RustSlice *given_name,
                             struct RustSlice *family_name);

struct Error endgame_load_key(ngx_str_t path, Key *key);

void endgame_ngx_str_t_trim(ngx_str_t *string);

struct RustSlice endgame_rust_slice_null(void);

void endgame_rust_slice_free(struct RustSlice *self);
