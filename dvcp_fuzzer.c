// clang -fsanitize=fuzzer,address -fno-omit-frame-pointer -fno-optimize-sibling-calls -O0 -g -o dvcp_fuzzer dvcp_fuzzer.c -L. -ldvcp -Wl,-rpath,.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int parse_dvcp_buffer(const uint8_t *buffer, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 7) return 0;

    parse_dvcp_buffer(data, size);
    return 0;
}
