/*
 *	CHAOS target for iptables
 *	Copyright © CC Computer Consultants GmbH, 2006 - 2007
 *	Contact: Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either version
 *	2 or 3 as published by the Free Software Foundation.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_CHAOS.h>

enum {
	F_DELUDE = 1 << 0,
	F_TARPIT = 1 << 1,
};

static const struct option chaos_tg_opts[] = {
	{.name = "delude", .has_arg = false, .val = 'd'},
	{.name = "tarpit", .has_arg = false, .val = 't'},
	{},
};

static void chaos_tg_help(void)
{
	printf(
		"CHAOS target v%s options:\n"
		"  --delude     Enable DELUDE processing for TCP\n"
		"  --tarpit     Enable TARPIT processing for TCP\n",
		IPTABLES_VERSION);
	return;
}

static int chaos_tg_parse(int c, char **argv, int invert, unsigned int *flags,
    const void *entry, struct xt_entry_target **target)
{
	struct xt_chaos_target_info *info = (void *)((*target)->data);
	switch (c) {
		case 'd':
			info->variant = XTCHAOS_DELUDE;
			*flags |= F_DELUDE;
			return true;
		case 't':
			info->variant = XTCHAOS_TARPIT;
			*flags |= F_TARPIT;
			return true;
	}
	return false;
}

static void chaos_tg_check(unsigned int flags)
{
	if ((flags & (F_DELUDE | F_TARPIT)) == (F_DELUDE | F_TARPIT))
		/* If flags == 0x03, both were specified, which should not be. */
		exit_error(PARAMETER_PROBLEM,
		           "CHAOS: only one of --tarpit or --delude "
		           "may be specified");
	return;
}

static void chaos_tg_print(const void *ip,
    const struct xt_entry_target *target, int numeric)
{
	const struct xt_chaos_target_info *info = (const void *)target->data;
	switch (info->variant) {
		case XTCHAOS_DELUDE:
			printf("DELUDE ");
			break;
		case XTCHAOS_TARPIT:
			printf("TARPIT ");
			break;
	}
	return;
}

static void chaos_tg_save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_chaos_target_info *info = (const void *)target->data;
	switch (info->variant) {
		case XTCHAOS_DELUDE:
			printf("--delude ");
			break;
		case XTCHAOS_TARPIT:
			printf("--tarpit ");
			break;
	}
	return;
}

static struct xtables_target chaos_tg_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "CHAOS",
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_chaos_target_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_chaos_target_info)),
	.help          = chaos_tg_help,
	.parse         = chaos_tg_parse,
	.final_check   = chaos_tg_check,
	.print         = chaos_tg_print,
	.save          = chaos_tg_save,
	.extra_opts    = chaos_tg_opts,
};

void _init(void)
{
	xtables_register_target(&chaos_tg_reg);
	return;
}
