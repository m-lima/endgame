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

int test_header(Key key) {
  CSlice in_email = endgame_c_slice_new("email", 5);
  CSlice in_given = endgame_c_slice_new(NULL, 0);
  CSlice in_family = endgame_c_slice_new("  family	", 9);

  printf("In Email:   %.*s\n", uintptr_t_to_int(in_email.len), in_email.ptr);
  printf("In Given:   %.*s\n", uintptr_t_to_int(in_given.len), in_given.ptr);
  printf("In Family:  %.*s\n", uintptr_t_to_int(in_family.len), in_family.ptr);

  RustSlice encrypted = endgame_rust_slice_null();
  Error error =
      endgame_encrypt(&key, in_email, in_given, in_family, &encrypted);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return 1;
  }

  printf("Encrypted:  %.*s\n", uintptr_t_to_int(encrypted.len), encrypted.ptr);

  CSlice param = {.ptr = encrypted.ptr, .len = encrypted.len};

  RustSlice out_email = endgame_rust_slice_null();
  RustSlice out_given = endgame_rust_slice_null();
  RustSlice out_family = endgame_rust_slice_null();
  error = endgame_decrypt(&key, param, 30, &out_email, &out_given, &out_family);
  if (error.ptr != NULL) {
    printf("Error: %.*s\n", uintptr_t_to_int(error.len), error.ptr);
    return 1;
  }
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

  printf("Key:");
  for (int i = 0; i < 32; ++i) {
    printf(" %d", key.bytes[i]);
  }
  printf("\n");

  printf("Testing header\n");
  errors += test_header(key);

  return errors;
}
