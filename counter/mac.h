#pragma once

#include "hex.h"
#include <stdio.h>

#define MAC_ADDRESS_STRING_LEN 17

inline void
mac_address_to_string(u8 const (*p)[6], char* buf, size_t buflen) { 
    byte_to_2hex_chars((*p)[0], buf);
    buf[2] = ':';
    byte_to_2hex_chars((*p)[1], buf+3);
    buf[5] = ':';
    byte_to_2hex_chars((*p)[2], buf+6);
    buf[8] = ':';
    byte_to_2hex_chars((*p)[3], buf+9);
    buf[11] = ':';
    byte_to_2hex_chars((*p)[4], buf+12);
    buf[14] = ':';
    byte_to_2hex_chars((*p)[5], buf+15);
}

