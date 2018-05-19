#include "util.h"
#include <time.h>

unsigned long get_tick_count()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}