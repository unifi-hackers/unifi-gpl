#ifndef _ASM_M32R_STRING_H
#define _ASM_M32R_STRING_H

/* $Id: //depot/sw/releases/7.3_AP/linux/kernels/mips-linux-2.6.15/include/asm-m32r/string.h#1 $ */

#define  __HAVE_ARCH_STRLEN
extern size_t strlen(const char * s);

#define  __HAVE_ARCH_MEMCPY
extern void *memcpy(void *__to, __const__ void *__from, size_t __n);

#define  __HAVE_ARCH_MEMSET
extern void *memset(void *__s, int __c, size_t __count);

#endif  /* _ASM_M32R_STRING_H */
