// clang -fsanitize=fuzzer,address -o fuzzer fuzzer.c ./libcheck_password.so
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PREFIX "fuzz!"

extern int check_password(const char* input);  // From libcheck_password.so

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char* buf = calloc(size + 1, 1);           // Allocate and null out size + 1 bytes of memory.
    memcpy(buf, data, size);                   // Copy in the fuzz data to the buffer so that it is null-terminated.

    check_password(buf);                       // Call the target function with the fuzz data.

    free(buf);                                 // Free the buffer to avoid memory exhaustion.
    return 0;                                  // End the fuzz iteration.
}
