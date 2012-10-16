/* Shared library add-on to iptables to add TARPIT target support */
#include <stdio.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>

static void TARPIT_help(void)
{
	fputs(
"TARPIT takes no options\n"
"\n", stdout);
}

static struct option TARPIT_opts[] = {
	{ 0 }
};

static int TARPIT_parse(int c, char **argv, int invert, unsigned int *flags,
			const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void TARPIT_final_check(unsigned int flags)
{
}

static void TARPIT_print(const void *ip, const struct xt_entry_target *target,
			int numeric)
{
}

static void TARPIT_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target tarpit_target = {
	.family		= AF_INET,
	.name		= "TARPIT",
	.version	= IPTABLES_VERSION,
	.size		= XT_ALIGN(0),
	.userspacesize	= XT_ALIGN(0),
	.help		= TARPIT_help,
	.parse		= TARPIT_parse,
	.final_check	= TARPIT_final_check,
	.print		= TARPIT_print,
	.save		= TARPIT_save,
	.extra_opts	= TARPIT_opts
};

void _init(void)
{
	xtables_register_target(&tarpit_target);
}
