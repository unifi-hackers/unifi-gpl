/*
 *	portscan match for iptables
 *	Copyright © CC Computer Consultants GmbH, 2006 - 2007
 *	Contact: Jan Engelhardt <jengelh@computergmbh.de>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License; either version
 *	2 or 3 as published by the Free Software Foundation.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <iptables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_portscan.h>

static const struct option portscan_mt_opts[] = {
	{.name = "stealth", .has_arg = false, .val = 'x'},
	{.name = "synscan", .has_arg = false, .val = 's'},
	{.name = "cnscan",  .has_arg = false, .val = 'c'},
	{.name = "grscan",  .has_arg = false, .val = 'g'},
	{},
};

static void portscan_mt_help(void)
{
	printf(
		"portscan match v%s options:\n"
		"(Combining them will make them match by OR-logic)\n"
		"  --stealth    Match TCP Stealth packets\n"
		"  --synscan    Match TCP SYN scans\n"
		"  --cnscan     Match TCP Connect scans\n"
		"  --grscan     Match Banner Grabbing scans\n",
		IPTABLES_VERSION);
	return;
}

static int portscan_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
	struct xt_portscan_match_info *info = (void *)((*match)->data);

	switch (c) {
		case 'c':
			info->match_cn = true;
			return true;
		case 'g':
			info->match_gr = true;
			return true;
		case 's':
			info->match_syn = true;
			return true;
		case 'x':
			info->match_stealth = true;
			return true;
	}
	return false;
}

static void portscan_mt_check(unsigned int flags)
{
	return;
}

static void portscan_mt_print(const void *ip,
    const struct xt_entry_match *match, int numeric)
{
	const struct xt_portscan_match_info *info = (const void *)(match->data);
	const char *s = "";

	printf("portscan ");
	if (info->match_stealth) {
		printf("STEALTH");
		s = ",";
	}
	if (info->match_syn) {
		printf("%sSYNSCAN", s);
		s = ",";
	}
	if (info->match_cn) {
		printf("%sCNSCAN", s);
		s = ",";
	}
	if (info->match_gr)
		printf("%sGRSCAN", s);
	printf(" ");
	return;
}

static void portscan_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_portscan_match_info *info = (const void *)(match->data);

	if (info->match_stealth)
		printf("--stealth ");
	if (info->match_syn)
		printf("--synscan ");
	if (info->match_cn)
		printf("--cnscan ");
	if (info->match_gr)
		printf("--grscan ");
	return;
}

static struct xtables_match portscan_mt_reg = {
	.version       = IPTABLES_VERSION,
	.name          = "portscan",
	.family        = AF_INET,
	.size          = XT_ALIGN(sizeof(struct xt_portscan_match_info)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_portscan_match_info)),
	.help          = portscan_mt_help,
	.parse         = portscan_mt_parse,
	.final_check   = portscan_mt_check,
	.print         = portscan_mt_print,
	.save          = portscan_mt_save,
	.extra_opts    = portscan_mt_opts,
};

void _init(void)
{
	xtables_register_match(&portscan_mt_reg);
	return;
}
