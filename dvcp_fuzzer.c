// dvcp_fuzzer.c
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint8_t *g_last_input = NULL;
size_t g_last_input_size = 0;

extern int parse_dvcp_buffer(const uint8_t *buffer, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 7) return 0;

    g_last_input = data;
    g_last_input_size = size;

    parse_dvcp_buffer(data, size);
    return 0;
}
