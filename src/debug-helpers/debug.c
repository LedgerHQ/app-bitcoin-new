#include <stdio.h>
#include <stdarg.h>
#include "printf.h"

void debug_write(const char *buf)
{
  asm volatile (
     "movs r0, #0x04\n"
     "movs r1, %0\n"
     "svc      0xab\n"
     :: "r"(buf) : "r0", "r1"
  );
}


int semihosted_printf(const char *format, ...) {
    char buf[128+1];

    va_list args;
    va_start(args, format);

    int ret = vsnprintf(buf, sizeof(buf) - 1, format, args);

    va_end(args);

    if (ret > 0) {
      buf[ret] = 0;
      debug_write(buf);
    }

    return ret;
}
