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

int test_raw(Key key) {
  const uint8_t payload[16] = "0123456789abcdef";
  CSlice decrypted = endgame_c_slice_new(&payload[0], 16);

  printf("Original:  %.*s\n", uintptr_t_to_int(decrypted.len), decrypted.ptr);

  RustSlice encrypted = endgame_rust_slice_null();
  Error error = endgame_encrypt_raw(&key, decrypted, &encrypted);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return 1;
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
    return 1;
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

int test_header(Key key) {
  CSlice in_email = endgame_c_slice_new("", 0);
  CSlice in_given = endgame_c_slice_new(NULL, 0);
  CSlice in_family = endgame_c_slice_new("family", 6);

  printf("In Email:   %.*s\n", uintptr_t_to_int(in_email.len), in_email.ptr);
  printf("In Given:   %.*s\n", uintptr_t_to_int(in_given.len), in_given.ptr);
  printf("In Family:  %.*s\n", uintptr_t_to_int(in_family.len), in_family.ptr);

  RustSlice encrypted = endgame_rust_slice_null();
  Error error =
      endgame_encrypt_header(&key, in_email, in_given, in_family, &encrypted);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return 1;
  }
  printf("Encrypted: ");
  for (int i = 0; i < encrypted.len; ++i) {
    printf(" %d", encrypted.ptr[i]);
  }
  printf("\n");

  CSlice param = {.ptr = encrypted.ptr, .len = encrypted.len};

  uint64_t timestamp;
  RustSlice out_email = endgame_rust_slice_null();
  RustSlice out_given = endgame_rust_slice_null();
  RustSlice out_family = endgame_rust_slice_null();
  error = endgame_decrypt_header(&key, param, &timestamp, &out_email,
                                 &out_given, &out_family);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return 1;
  }
  printf("Timestamp:  %lu\n", timestamp);
  printf("Out Email:  %.*s\n", uintptr_t_to_int(out_email.len), out_email.ptr);
  printf("Out Given:  %.*s\n", uintptr_t_to_int(out_given.len), out_given.ptr);
  printf("Out Family: %.*s\n", uintptr_t_to_int(out_family.len),
         out_family.ptr);

  endgame_rust_slice_free(&encrypted);
  endgame_rust_slice_free(&out_email);
  endgame_rust_slice_free(&out_given);
  endgame_rust_slice_free(&out_family);

  return 0;
}

int main() {
  int errors = 0;

  Key key = {.bytes = {0}};

  printf("Key:      ");
  for (int i = 0; i < 32; ++i) {
    printf(" %d", key.bytes[i]);
  }
  printf("\n");

  printf("Testing raw\n");
  errors += test_raw(key);

  printf("Testing header\n");
  errors += test_header(key);

  return errors;
}
