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
  CSlice decrypted = endgame_c_slice_new(&payload[0], 16);

  printf("Original:  %.*s\n", uintptr_t_to_int(decrypted.len), decrypted.ptr);

  Key key = {.bytes = {0}};

  printf("Key:      ");
  for (int i = 0; i < 32; ++i) {
    printf(" %d", key.bytes[i]);
  }
  printf("\n");

  RustSlice encrypted = endgame_encrypt_raw(&key, decrypted);

  printf("Encrypted:");
  for (int i = 0; i < encrypted.len; ++i) {
    printf(" %d", encrypted.ptr[i]);
  }
  printf("\n");

  CSlice param = {.ptr = encrypted.ptr, .len = encrypted.len};

  RustSlice recovered = endgame_decrypt_raw(&key, param);
  printf("Recovered: %.*s\n", uintptr_t_to_int(recovered.len), recovered.ptr);

  return 0;
}
