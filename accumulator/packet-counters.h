#pragma once

#include "types.h"
#include <sys/time.h>

void packet_counters_init(packet_counters*);
void packet_counters_process(packet_counters*);
void packet_counters_destroy(packet_counters*);
