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


#ifndef _NFHP_MOD_H
#define _NFHP_MOD_H

#include <linux/module.h>
#include <asm/semaphore.h>

/* hipac data structures for INPUT, FORWARD and OUTPUT hook and the
   corresponding netfilter hook ops */
extern void *hipac_input;
extern struct nf_hook_ops input_op;

extern void *hipac_forward;
extern struct nf_hook_ops forward_op;

extern void *hipac_output;
extern struct nf_hook_ops output_op;

/* netlink mutex */
extern struct semaphore nlhp_lock;

int
nfhp_register_cthelp(struct module *nfhp_cthelp_module);

void
nfhp_unregister_cthelp(struct module *nfhp_cthelp_module);

#endif
