#pragma once

#include <stdint.h>

typedef struct RustSlice {
  const uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} RustSlice;

typedef struct RustSlice RustError;

typedef struct KeyBase64 {
  uint8_t bytes[176];
} KeyBase64;

typedef struct Key {
  uint8_t bytes[32];
} Key;

typedef struct CSlice {
  const uint8_t *ptr;
  uintptr_t len;
} CSlice;

typedef struct CSlice Error;

RustError endgame_base64_into_key(struct KeyBase64 self, struct Key *dst);

struct CSlice endgame_c_slice_new(const uint8_t *ptr, uintptr_t len);

struct CSlice endgame_c_slice_trim(struct CSlice self);

struct RustSlice endgame_rust_slice_null(void);

struct CSlice endgame_rust_slice_as_c_slice(struct RustSlice self);

void endgame_rust_slice_free(struct RustSlice *self);

Error endgame_encrypt(const struct Key *key,
                      struct CSlice email,
                      struct CSlice given_name,
                      struct CSlice family_name,
                      struct RustSlice *dst);

Error endgame_decrypt(const struct Key *key,
                      struct CSlice src,
                      uint64_t max_age_secs,
                      struct RustSlice *email,
                      struct RustSlice *given_name,
                      struct RustSlice *family_name);
