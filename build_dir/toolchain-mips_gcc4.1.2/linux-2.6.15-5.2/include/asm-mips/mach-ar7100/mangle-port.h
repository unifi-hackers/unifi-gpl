#ifndef __ASM_MACH_AR7100_MANGLE_PORT_H
#define __ASM_MACH_AR7100_MANGLE_PORT_H

#define __swizzle_addr_b(port)	((port) ^ 3)
#define __swizzle_addr_w(port)	((port) ^ 2)
#define __swizzle_addr_l(port)	(port)
#define __swizzle_addr_q(port)	(port)

#endif /* __ASM_MACH_AR7100_MANGLE_PORT_H */
