#ifndef _ASM_M32R_DMA_H
#define _ASM_M32R_DMA_H

/* $Id: //depot/sw/releases/7.3_AP/linux/kernels/mips-linux-2.6.15/include/asm-m32r/dma.h#1 $ */

#include <asm/io.h>

/*
 * The maximum address that we can perform a DMA transfer
 * to on this platform
 */
#define MAX_DMA_ADDRESS      (PAGE_OFFSET+0x20000000)

#endif /* _ASM_M32R_DMA_H */
