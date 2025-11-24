#pragma once

#include <stdint.h>

typedef struct CSlice {
  const uint8_t *ptr;
  uintptr_t len;
} CSlice;

typedef struct RustSlice {
  const uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} RustSlice;

typedef struct CSlice Error;

typedef struct Key {
  uint8_t bytes[32];
} Key;

typedef struct RustSlice RustError;

#if defined(ENDGAME_BASE64)
typedef struct KeyBase64 {
  uint8_t bytes[176];
} KeyBase64;
#endif

struct CSlice endgame_c_slice_new(const uint8_t *ptr, uintptr_t len);

struct RustSlice endgame_rust_slice_null(void);

struct CSlice endgame_rust_slice_as_c_slice(struct RustSlice self);

void endgame_rust_slice_free(struct RustSlice *self);

Error endgame_encrypt_raw(const struct Key *key, struct CSlice src, struct RustSlice *dst);

Error endgame_decrypt_raw(const struct Key *key, struct CSlice src, struct RustSlice *dst);

#if defined(ENDGAME_BASE64)
RustError endgame_base64_into_key(struct KeyBase64 self, struct Key *dst);
#endif
