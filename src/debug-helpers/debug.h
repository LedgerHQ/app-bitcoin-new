#pragma once

void debug_write(const char *buf);

int semihosted_printf(const char *format, ...);

void print_stack_pointer(const char *file, int line, const char *func_name);

// Helper macro
#ifdef HAVE_PRINT_STACK_POINTER
#define PRINT_STACK_POINTER() print_stack_pointer(__FILE__, __LINE__, __func__)
#else
#define PRINT_STACK_POINTER()
#endif