#include "debug.h"

#include "hex.h"
#include "types.h"
#include <stdio.h>

void
print_hex_dump(void const* data, size_t byte_len) {
    for(size_t i = 0; i < byte_len; ++i) {
       char cs[2];
       byte_to_2hex_chars(((u8 const*)data)[i], cs);
       putchar(cs[0]);
       putchar(cs[1]);
    }
}

