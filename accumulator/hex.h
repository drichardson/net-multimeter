#pragma once

#include "types.h"

static inline void byte_to_2hex_chars(u8 b, char *p) {
    static char const nibble_to_char[16] ={
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F'
    };
    p[0] = nibble_to_char[b >> 4];
    p[1] = nibble_to_char[b & 0x0f];
}

