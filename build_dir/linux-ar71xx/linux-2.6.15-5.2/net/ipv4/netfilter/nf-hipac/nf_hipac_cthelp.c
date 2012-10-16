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


#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include "nfhp_mod.h"

static int
__init init(void)
{
	need_ip_conntrack();
	if (nfhp_register_cthelp(THIS_MODULE)) {
		return -EINVAL;
	}
	return 0;
}

static void
__exit fini(void)
{
	nfhp_unregister_cthelp(THIS_MODULE);
}

module_init(init);
module_exit(fini);
MODULE_AUTHOR("Michael Bellion and Thomas Heinz");
MODULE_DESCRIPTION("nf-HiPAC - connection tracking dependency helper module");
MODULE_LICENSE("GPL");
