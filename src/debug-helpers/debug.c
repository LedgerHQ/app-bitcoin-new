#include <stdio.h>
#include <stdarg.h>
#include "printf.h"

void debug_write(const char *buf) {
    asm volatile(
        "movs r0, #0x04\n"
        "movs r1, %0\n"
        "svc      0xab\n" ::"r"(buf)
        : "r0", "r1");
}

int semihosted_printf(const char *format, ...) {
    char buf[128 + 1];

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

// Returns the current stack pointer
static unsigned int __attribute__((noinline)) get_stack_pointer() {
    int stack_top = 0;
    // Returning an address on the stack is unusual, so we disable the warning
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreturn-stack-address"
    return (unsigned int) &stack_top;
#pragma GCC diagnostic pop
}

void print_stack_pointer(const char *file, int line, const char *func_name) {
    PRINTF("STACK (%s) %s:%d: %08x\n", func_name, file, line, get_stack_pointer());
}