
/*
 * Prom setup file for ar7240
 */

#include <linux/init.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/bootmem.h>

#include <asm/bootinfo.h>
#include <asm/addrspace.h>

#include "ar7240.h"

static char cfg_cmdline[CL_SIZE] = CONFIG_CMDLINE;
static char* cmdargs[CL_SIZE] = {};
static int cmdargc = 0;

static int cmd2args(char* cmd) {
	int c = 0;
	char* p = cmd;

	if (!cmd) return c;

	cmdargs[c] = cmd;
	++c;
	while ((p = strchr(p, ' '))) {
		*p = 0;
		p++;
		cmdargs[c] = p;
		++c;
	}
	return c;
}

static int overwritecmd(char* opt) {
	int i;
	char* end;

	if (!opt) return 0;

	end = strchr(opt, '=');
	for (i = 0; i < cmdargc; i++) {
		if (cmdargs[i] && !strncmp(cmdargs[i], opt, end ? (end - opt) : strlen(opt))) {
			cmdargs[i] = 0;
			return 1;
		}
	}
	return 1;
}

#define AR71XX_MEM_SIZE_MIN     0x00200000
#define AR71XX_MEM_SIZE_MAX     0x10000000

/**
 * borrowed from OpenWRT arch/mips/ar71xx/setup.c
 */
static void __init ar71xx_detect_mem_size(void)
{
	unsigned long size;

	for (size = AR71XX_MEM_SIZE_MIN; size < AR71XX_MEM_SIZE_MAX;
			size <<= 1) {
		if (!memcmp(ar71xx_detect_mem_size,
				ar71xx_detect_mem_size + size, 1024))
			break;
	}

	add_memory_region(0, size, BOOT_MEM_RAM);
}

extern void Uart16550Put(unsigned char byte);

void __init prom_putchar(char c)
{
	Uart16550Put((unsigned char)c);
}

void __init prom_init(void)
{
	int i;
	int argc = fw_arg0;
	char **arg = (char**) fw_arg1;
	/*
	 * if user passes kernel args, overwrite the configured one
	 */
	if (argc > 1) {
		cmdargc = cmd2args(cfg_cmdline);
		arcs_cmdline[0] = '\0';
#ifdef DEBUG
		printk("Boot loader cmdline:\n");
		for (i = 1; i < argc; i++)
			printk("\t%s\n", arg[i]);

		printk("Kernel cmdline:\n");
		for (i = 0; i < cmdargc; i++)
			printk("\t%s\n", cmdargs[i]);
#endif
		/*
		 * arg[0] is "g", the rest is boot parameters
		 */
		for (i = 1; i < argc; i++) {
			if (strlen(arcs_cmdline) + strlen(arg[i]) + 1
					>= sizeof(arcs_cmdline))
				break;
			if (overwritecmd(arg[i])) {
				strcat(arcs_cmdline, arg[i]);
				strcat(arcs_cmdline, " ");
			}
		}
		for (i = 0; i < cmdargc; i++) {
			if (cmdargs[i]) {
				if (strlen(arcs_cmdline) + strlen(cmdargs[i]) + 1
						>= sizeof(arcs_cmdline))
					break;
				strcat(arcs_cmdline, cmdargs[i]);
				strcat(arcs_cmdline, " ");
			}
		}
	}
	mips_machgroup = MACH_GROUP_AR7240;
	mips_machtype  = MACH_ATHEROS_AR7240;

	ar71xx_detect_mem_size();
}

void __init prom_free_prom_memory(void)
{
}
