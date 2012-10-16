/*
 *             High performance packet classification 
 *                     <http://www.hipac.org>
 *
 * (c) 2004-2005   MARA Systems AB <http://www.marasystems.com>
 *                 +-----------------------------+
 *                 |       Michael Bellion       |
 *                 |  <michael@marasystems.com>  |
 *                 +-----------------------------+
 *
 * (c) 2002-2003   hipac core team <nf@hipac.org>:
 *     +---------------------------+--------------------------+
 *     |      Michael Bellion      |       Thomas Heinz       |
 *     |   <mbellion@hipac.org>    |   <creatix@hipac.org>    |
 *     +---------------------------+--------------------------+
 *
 * Licenced under the GNU General Public Licence, version 2.
 */


#ifndef _MODE_H
#define _MODE_H

#include <linux/stddef.h> // offsetof
#include <asm/page.h>

/* maximal number of bytes allocatable by mini_alloc */
#define MINI_ALLOC_MAX 131072


/*
 * NEVER use big_alloc and big_free. Use hp_alloc and hp_free instead.
 * The only exceptions to this rule is the implementation of hp_alloc,
 * hp_realloc and hp_free.
 *
 * mini_alloc and mini_free can be used for small (<= MINI_ALLOC_MAX bytes)
 * data structures if one wants to avoid the overhead of hp_alloc and hp_free
 */

static inline unsigned
big_alloc_size(unsigned size)
{
	return size == 0 ? 0 : (((size - 1) + PAGE_SIZE) & ~(PAGE_SIZE - 1));
}


#ifdef __KERNEL__
/*
 * Kernel space
 */
#include <linux/config.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>    // ULONG_MAX
#include <linux/compiler.h>  // likely, unlikely
#include <linux/smp.h>       // smp_num_cpus, cpu_number_map, smp_processor_id
#include <linux/rcupdate.h>  // Read Copy Update: sychronize_rcu
#include <linux/cache.h>     // __cacheline_aligned
#include <linux/netfilter.h> // NF_ACCEPT, NF_DROP
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/version.h>

#define assert(as)           do {} while (0)
#define printf(str, args...) printk(str , ## args)

static inline unsigned
mini_alloc_size(unsigned size)
{
	unsigned int s;
#define CACHE(x) if (size <= x) { s = x; goto found;}
#include <linux/kmalloc_sizes.h>
	return 0;
found:
	return s;
}

/* for small amounts of memory only (up to 128 KB) */
static inline void *
mini_alloc(unsigned size)
{
	if (size > 0 && size <= MINI_ALLOC_MAX) {
		return kmalloc(size, GFP_KERNEL);
	}
	return NULL;
}

static inline void
mini_free(void *p)
{
	kfree(p);
}

/* memory is allocated in amounts of multiples of PAGE_SIZE */
static inline void *
big_alloc(unsigned size)
{
	return vmalloc(size);
}

static inline void
big_free(void *p)
{
	vfree(p);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
#define synchronize_rcu(x)    synchronize_kernel(x)
#endif

/* dirty hack to make stuff work with uml (otherwise high_physmem and end_vm
   are not defined) */
#ifdef  CONFIG_UML_NET
#  undef  TOP
#  ifdef  CONFIG_HOST_2G_2G
#    define TOP 0x80000000
#  else
#    define TOP 0xc0000000
#  endif
#  undef  SIZE
#  define SIZE  ((CONFIG_NEST_LEVEL + CONFIG_KERNEL_HALF_GIGS) * 0x20000000)
#  undef  START
#  define START (TOP - SIZE)
#  undef  VMALLOC_OFFSET
#  define VMALLOC_OFFSET (8 * 1024 * 1024)
#  undef  VMALLOC_START
#  define VMALLOC_START (((unsigned long) (START + 32 * 1024 * 1024) + \
 	VMALLOC_OFFSET) & ~(VMALLOC_OFFSET - 1))
static unsigned long high_physmem = START + 32 * 1024 * 1024;
static unsigned long end_vm       = VMALLOC_START + 32 * 1024 * 1024;
#endif  /* CONFIG_UML_NET */




#else /* __KERNEL__ */
/*
 * User space
 */
#include <features.h>
#if defined(__GLIBC__) && __GLIBC__ == 2
#  include <asm/types.h>
#else /* libc5 */
#  include <linux/types.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>  // ULONG_MAX
#include <assert.h>
#include <malloc.h>

/* no assertions if not debugging */
#ifndef DEBUG
#  undef  assert
#  define assert(as) do {} while (0)
#endif

/* locking unnecessary in user space */
#define synchronize_rcu(x)    do {} while (0)

/* printk compatibility */
#define KERN_EMERG    "KERN_EMERG: "
#define KERN_ALERT    "KERN_ALERT: "
#define KERN_CRIT     "KERN_CRIT: "
#define KERN_ERR      "KERN_ERR: "
#define KERN_WARNING  "KERN_WARNING: "
#define KERN_NOTICE   "KERN_NOTICE: "
#define KERN_INFO     "KERN_INFO: "
#define KERN_DEBUG    "KERN_DEBUG: "
#define printk(str, args...) printf(str , ## args)

/* netfilter verdict compatibility */
#define NF_DROP   0
#define NF_ACCEPT 1

/* macro to annotate likely branch directions which results in the
   blocks being reordered appropriately */
#if __GNUC__ == 2 && __GNUC_MINOR__ < 96
#  define __builtin_expect(x, expected_value) (x)
#  define likely(x)   __builtin_expect((x), 1)
#  define unlikely(x) __builtin_expect((x), 0)
#endif

static inline unsigned
mini_alloc_size(unsigned size)
{
	unsigned int s;
#define CACHE(x) if (size <= x) { s = x; goto found;}
	CACHE(32);
	CACHE(64);
	CACHE(96);
	CACHE(128);
	CACHE(192);
	CACHE(256);
	CACHE(512);
	CACHE(1024);
	CACHE(2048);
	CACHE(4096);
	CACHE(8192);
	CACHE(16384);
	CACHE(32768);
	CACHE(65536);
	CACHE(131072);
	return 0;
found:
	return s;
}

/* for small amounts of memory only (up to 128 KB) */
static inline void *
mini_alloc(unsigned size)
{
	return malloc(mini_alloc_size(size));
}

static inline void
mini_free(void *p)
{
	free(p);
}

/* memory is allocated in amounts of multiples of PAGE_SIZE */
static inline void *
big_alloc(unsigned size)
{
	return malloc(big_alloc_size(size));
}

static inline void
big_free(void *p)
{
	free(p);
}

#endif /* __KERNEL__ */

#endif
