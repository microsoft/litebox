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

typedef uint8_t u8;
typedef uint8_t __u8;
typedef uint16_t u16;
typedef uint16_t __u16;
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint64_t u64;
typedef uint64_t __u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define __packed __attribute__((packed))

#define __AC(X,Y) (X##Y)
#define _AC(X,Y) __AC(X,Y)
#define _UL(x) (_AC(x, UL))
#define _ULL(x) (_AC(x, ULL))
#define UL(x) (_UL(x))
#define ULL(x) (_ULL(x))
#define BIT(nr) (UL(1) << (nr))
#define BIT_ULL(nr) (ULL(1) << (nr))

#define PAGE_SIZE 4096
