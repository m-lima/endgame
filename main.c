#include <endgame.h>
#include <limits.h>
#include <stdio.h>

int uintptr_t_to_int(uintptr_t i) {
  if (i > INT_MAX) {
    return INT_MAX;
  } else {
    return i;
  }
}

int main() {
  const uint8_t payload[16] = "0123456789abcdef";
  // CSlice decrypted;
  // Key key;
  // RustSlice encrypted;
  // CSlice error;

  // decrypted = endgame_c_slice_new(&payload[0], 16);
  CSlice decrypted = endgame_c_slice_new(&payload[0], 16);

  printf("Original:  %.*s\n", uintptr_t_to_int(decrypted.len), decrypted.ptr);

  Key key = {.bytes = {0}};

  printf("Key:      ");
  for (int i = 0; i < 32; ++i) {
    printf(" %d", key.bytes[i]);
  }
  printf("\n");

  RustSlice encrypted = endgame_rust_slice_null();
  Error error = endgame_encrypt_raw(&key, decrypted, &encrypted);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return -1;
  }
  printf("Encrypted:");
  for (int i = 0; i < encrypted.len; ++i) {
    printf(" %d", encrypted.ptr[i]);
  }
  printf("\n");

  CSlice param = {.ptr = encrypted.ptr, .len = encrypted.len};

  RustSlice recovered = endgame_rust_slice_null();
  error = endgame_decrypt_raw(&key, param, &recovered);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return -1;
  }
  printf("Recovered: %.*s\n", uintptr_t_to_int(recovered.len), recovered.ptr);

  printf("Pointers:  (%p %lu %lu) (%p %lu %lu)\n", encrypted.ptr, encrypted.len,
         encrypted.cap, recovered.ptr, recovered.len, recovered.cap);
  endgame_rust_slice_free(&encrypted);
  endgame_rust_slice_free(&recovered);
  printf("Pointers:  (%p %lu %lu) (%p %lu %lu)\n", encrypted.ptr, encrypted.len,
         encrypted.cap, recovered.ptr, recovered.len, recovered.cap);

  return 0;
}
