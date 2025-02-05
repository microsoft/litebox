typedef unsigned char       uint8_t;
typedef   signed char        int8_t;
typedef unsigned short     uint16_t;
typedef   signed short      int16_t;
typedef unsigned int       uint32_t;
typedef   signed int        int32_t;
typedef unsigned long long uint64_t;
typedef   signed long long  int64_t;
typedef unsigned long        size_t;
typedef   signed long       ssize_t;
typedef unsigned long     uintptr_t;
typedef   signed long      intptr_t;

typedef struct desc_struct {
} desc_struct_t;

typedef struct x86_hw_tss {
} x86_hw_tss_t;

#define GDT_ENTRIES			32

#include "sandbox_driver/include/snp-sandbox.h"