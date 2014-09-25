#pragma once

#include "types.h"

inline u16 u8s_to_u16(u8 const (*u)[2]) {
    u16 r0 = (*u)[0], r1 = (*u)[1];
    return (r0 << 8) | r1;
}

inline u32 u8s_to_u32(u8 const (*u)[4]) {
    u32 r0 = (*u)[0], r1 = (*u)[1], r2 = (*u)[2], r3 = (*u)[4];
    return (r0 << 24) | (r1 << 16) | (r2 << 8) | r3;
}

