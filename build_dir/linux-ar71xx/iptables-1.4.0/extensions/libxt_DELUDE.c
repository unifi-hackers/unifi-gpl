/*
 *	DELUDE target for iptables
 *	Copyright © CC Computer Consultants GmbH, 2006 - 2007
 *	Contact: Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either version
 *	2 or 3 as published by the Free Software Foundation.
 */
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>

static void delude_tg_help(void)
{
	printf("DELUDE takes no options\n");
	return;
}

static int delude_tg_parse(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_target **target)
{
	return 0;
}

static void delude_tg_check(unsigned int flags)
{
	return;
}

static struct xtables_target delude_tg_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "DELUDE",
	.family        = AF_INET,
	.size          = XT_ALIGN(0),
	.userspacesize = XT_ALIGN(0),
	.help          = delude_tg_help,
	.parse         = delude_tg_parse,
	.final_check   = delude_tg_check,
};

void _init(void)
{
	xtables_register_target(&delude_tg_reg);
	return;
}
