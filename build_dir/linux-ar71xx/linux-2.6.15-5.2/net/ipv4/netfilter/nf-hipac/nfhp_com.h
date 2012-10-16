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


#ifndef _NFHP_COM_H
#define _NFHP_COM_H

#ifdef __KERNEL__
#  include <linux/if.h>
#  include <linux/in.h>
#  include <linux/types.h>
#endif
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netlink.h>
#include "hipac.h"


/* a similar line will hopefully make its way into netlink.h */
#define NETLINK_NFHIPAC	    26
#define NLHP_PROTO          NETLINK_NFHIPAC
#define NLHP_TYPE           0xFADE

/* dimension id's */
enum {
	DIMID_STATE,
	DIMID_SRC_IP,
	DIMID_DEST_IP,
	DIMID_INIFACE,
	DIMID_OUTIFACE,
	DIMID_PROTO,
	DIMID_FRAGMENT,
	DIMID_DPORT,
	DIMID_SPORT,
	DIMID_SYN,
	DIMID_ICMP_TYPE,
	DIMID_TTL,
	NUMBER_OF_DIM
};

/* bit types */
#define BIT_STATE       BIT_U16
#define BIT_SRC_IP      BIT_U32
#define BIT_DEST_IP     BIT_U32
#define BIT_INIFACE     BIT_U16
#define BIT_OUTIFACE    BIT_U16
#define BIT_PROTO       BIT_U16
#define BIT_FRAGMENT    BIT_U16
#define BIT_DPORT       BIT_U16
#define BIT_SPORT       BIT_U16
#define BIT_SYN         BIT_U16
#define BIT_ICMP_TYPE   BIT_U16
#define BIT_TTL         BIT_U16

/* origin bits */
#define NFHP_ORIGIN_INPUT   0x1
#define NFHP_ORIGIN_FORWARD 0x2
#define NFHP_ORIGIN_OUTPUT  0x4

/* hipac_error and nfhipac_error together form the netlink error messages */
typedef enum
{
	NFHE_INDEX   = HE_NEXT_ERROR,      // Unable to retrieve unused ifindex
	NFHE_NOMSG   = HE_NEXT_ERROR - 1,  // Incorrect message format
	NFHE_CMD     = HE_NEXT_ERROR - 2,  // Invalid command
	NFHE_LABEL   = HE_NEXT_ERROR - 3,  // Empty chain label
	NFHE_NLABEL  = HE_NEXT_ERROR - 4,  // Empty new chain label
	NFHE_POLICY  = HE_NEXT_ERROR - 5,  // Invalid policy
	NFHE_ACTION  = HE_NEXT_ERROR - 6,  // Invalid action
	NFHE_NMCT    = HE_NEXT_ERROR - 7,  // Invalid native match count
	NFHE_IEOFF   = HE_NEXT_ERROR - 8,  // Invalid target_offset/next_offset
	                                   // in ipt_entry
	NFHE_SORT    = HE_NEXT_ERROR - 9,  // Native matches not sorted or 
	                                   // dimid duplicate
        NFHE_MINT    = HE_NEXT_ERROR - 10, // Invalid interval in native match
	NFHE_DEVA    = HE_NEXT_ERROR - 11, // Native interface match but no 
                                           // corresponding interface name
	NFHE_DEVB    = HE_NEXT_ERROR - 12, // Interface name but no corres-
	                                   // ponding native interface match
	NFHE_FRAG    = HE_NEXT_ERROR - 13, // Invalid fragment match
	NFHE_PROTO   = HE_NEXT_ERROR - 14, // Invalid protocol match
        NFHE_SYN     = HE_NEXT_ERROR - 15, // Invalid syn match
	NFHE_STATE   = HE_NEXT_ERROR - 16, // Invalid state match
	NFHE_TCP     = HE_NEXT_ERROR - 17, // tcp match dependency failure
	NFHE_TCPUDP  = HE_NEXT_ERROR - 18, // tcp or udp match dependency failure
	NFHE_ICMP    = HE_NEXT_ERROR - 19, // icmp match dependency failure
	NFHE_CMPMIS  = HE_NEXT_ERROR - 20, // Missing cmp_len array
	NFHE_CMPSH   = HE_NEXT_ERROR - 21, // cmp_len array too short
	NFHE_CMPLA   = HE_NEXT_ERROR - 22, // cmp_len array contains a value
	                                   // larger than the corresponding
	                                   // ipt match/target size
	NFHE_ORIGIN  = HE_NEXT_ERROR - 23, // Illegal combination of matches
                                           // (no valid origin)
	NFHE_IPTMSZ  = HE_NEXT_ERROR - 24, // Invalid ipt match size
	NFHE_IPTMCH  = HE_NEXT_ERROR - 25, // checkentry fails for ipt match
	NFHE_IPTTMI  = HE_NEXT_ERROR - 26, // Missing ipt target
	NFHE_IPTTSZ  = HE_NEXT_ERROR - 27, // Invalid ipt target size
	NFHE_IPTTCH  = HE_NEXT_ERROR - 28, // checkentry fails for ipt target
	NFHE_TOFF    = HE_NEXT_ERROR - 29, // Invalid target_offset
	NFHE_CHAINE  = HE_NEXT_ERROR - 30, // Empty chain name
	NFHE_CHAINL  = HE_NEXT_ERROR - 31, // Chain name too long
	NFHE_CT      = HE_NEXT_ERROR - 32, // Kernel does not have support for 
	                                   // connection tracking, please recompile
	NFHE_CTHELP  = HE_NEXT_ERROR - 33, // Unable to load connection tracking
	                                   // helper module (nf_hipac_cthelp.o)
	NFHE_ILL     = HE_NEXT_ERROR - 34, // Illegal condition
	NFHE_IMPL    = HE_NEXT_ERROR - 35, // Feature not yet implemented
	NFHE_SYSOFF  = HE_NEXT_ERROR - 36  // - offset for system errno's -
} nfhipac_error;

/* errno is positive */
#define ERRNO_TO_NFHE(e) (NFHE_SYSOFF - e)
#define NFHE_TO_ERRNO(e) (NFHE_SYSOFF - e)

/* connection tracking states */
typedef enum
{
	NFHP_STATE_ESTABLISHED,
	NFHP_STATE_RELATED,
	NFHP_STATE_NEW,
	NFHP_STATE_INVALID,
	NFHP_STATE_UNTRACKED,
	NFHP_STATE_NUM_VALID = NFHP_STATE_INVALID
} nfhp_state;

/* netlink commands */
#define CMD_NONE           0
#define CMD_MIN            1
#define CMD_APPEND         1
#define CMD_INSERT         2
#define CMD_DELETE_RULE    3
#define CMD_DELETE_POS     4 
#define CMD_REPLACE        5
#define CMD_FLUSH          6
#define CMD_NEW_CHAIN      7
#define CMD_DELETE_CHAIN   8
#define CMD_RENAME_CHAIN   9
#define CMD_SET_POLICY    10
#define CMD_LIST          11
#define CMD_MAX           11

struct nfhp_rule
{
	char indev[IFNAMSIZ];
	char outdev[IFNAMSIZ];
	struct hipac_rule r;
	struct hipac_match m[NUMBER_OF_DIM];  // == r.first_match
	/* we cannot use aligned(__alignof__(u_int64_t)) instead of
	   aligned(8) because of incompatibilities in gcc versions */
	struct ipt_entry e[0] __attribute__((aligned(8)));
};

struct nfhp_chain
{
	char label[HIPAC_CHAIN_NAME_MAX_LEN];
	char newlabel[HIPAC_CHAIN_NAME_MAX_LEN];
	u_int8_t policy;
};

/* universal macros which can be used for USER <-> KERNEL (both directions) */
#define HAS_IPT_MATCH(r)      ((r)->match_offset > 0)
#define HAS_IPT_TARGET(r)     ((r)->action == TARGET_EXEC)
#define HAS_CHAIN_TARGET(r)   ((r)->action == TARGET_CHAIN)
#define NEXT_IPT_MATCH(m)     ((struct ipt_entry_match *)          \
			       ((char *) (m) + (m)->u.match_size))


/*
 * netlink communication: USER -> KERNEL
 */

/* command sent to kernel; only the necessary parts (depending on the command
   type) must be filled in;

  this is how a nfhp_cmd really looks like:
  --------------------------------------------
  |              nfhp_cmd struct             |
  |------------------------------------------|
  |                ipt_entry                 |
  |------------------------------------------|
  |             ipt_entry_match 1            |
  |------------------------------------------|
  |                  . . .                   |
  |------------------------------------------|
  |             ipt_entry_match m            |
  |------------------------------------------|
  |             ipt_entry_target             |
  |                    or                    |
  |                chain label               |
  |------------------------------------------|
  |          cmp_len array of size m         |
  |  or m + 1 if ipt_entry_target available  |
  --------------------------------------------

  ipt_entry, ipt_entry_matches, ipt_entry_target / chain label and cmp_len are
  optional; here are the rules defining their presence:
  1) if the rule action is TARGET_EXEC there is an ipt_entry_target
  2) if the rule action is TARGET_CHAIN there is a chain label
  3) if there is an ipt_entry_match or ipt_entry_target or chain label there
     is an ipt_entry
  4) if there is an ipt_entry and cmd is CMD_DELETE_RULE there is cmp_len

  => the smallest command simply consists of the nfhp_cmd struct

  struct nfhp_cmd contains an embedded struct hipac_rule; set its member
  match_offset to a value > 0 if there is at least one ipt_entry_match;
  otherwise it must be 0; you don't have to specify the following members:
                           size, origin, target_offset

  if ipt_entry exists you only have to specify the following members:
                           target_offset, next_offset

  note: - the iptables_matches and the iptables_target must be aligned with
          the IPT_ALIGN macro
*/
struct nfhp_cmd
{
	u_int32_t cmd;
	struct nfhp_chain chain;
	struct nfhp_rule rule;
};

/* macros to access nfhp_cmd; hr is a pointer to the embedded hipac_rule */
#define HAS_IPT_ENTRY(hr)      (HAS_IPT_MATCH(hr) || HAS_IPT_TARGET(hr) || \
			        HAS_CHAIN_TARGET(hr))
#define HAS_CMP_LEN(cmd, hr)   ((cmd) == CMD_DELETE_RULE && \
				(HAS_IPT_MATCH(hr) || HAS_IPT_TARGET(hr)))
#define NFHP_RULE(hr)          ((struct nfhp_rule *)              \
			        ((char *) (hr) - (unsigned long)  \
			 	 (&((struct nfhp_rule *) 0)->r)))
#define IPT_ENTRY(hr)          (NFHP_RULE(hr)->e)
#define FIRST_IPT_MATCH_IE(hr) ((struct ipt_entry_match *) \
				NFHP_RULE(hr)->e->elems)
#define IPT_ENTRY_END(hr)      FIRST_IPT_MATCH_IE(hr)
#define IPT_TARGET_IE(hr)      ((struct ipt_entry_target *)        \
			        ((char *) NFHP_RULE(hr)->e +       \
				 NFHP_RULE(hr)->e->target_offset))
#define IPT_MATCH_END_IE(r)    ((struct ipt_entry_match *) IPT_TARGET_IE(r))
#define CHAIN_TARGET_IE(hr)    ((char *) IPT_TARGET_IE(hr))
#define CMP_LEN(hr)            ((u16 *) ((char *) IPT_ENTRY(hr) +     \
					 IPT_ENTRY(hr)->next_offset))



/*
 * netlink communication: KERNEL -> USER
 */

/*
  in reply to a CMD_LIST command the kernel sends a series of packets to
  the userspace; each packet is filled as much as possible so that the
  number of packets being transfered is reduced to a minimum;
  in case of an error which can happen sometime during the
  transmission a packet containing the error number is sent (int32_t);
  the data sent to the userspace is organized in the following way:
  |struct nfhp_list_chain (chain 1)|rule 1|padding|...|rule n_1|padding|
  |                   .   .   .   .                                    |
  |struct nfhp_list_chain (chain k)|rule 1|padding|...|rule n_k|padding|
  the rules are of the type struct nfhp_rule;
  
  this is how a nfhp_list_rule really looks like:
  --------------------------------------------
  |           nfhp_list_rule struct          |
  |------------------------------------------|
  |               hipac_match 1              |
  |------------------------------------------|
  |                  . . .                   |
  |------------------------------------------|
  |               hipac_match n              |
  |------------------------------------------|
  |             ipt_entry_match 1            |
  |------------------------------------------|
  |                  . . .                   |
  |------------------------------------------|
  |             ipt_entry_match m            |
  |------------------------------------------|
  |             ipt_entry_target             |
  |                    or                    |
  |                chain label               |
  --------------------------------------------

  the number of hipac_matches depends on native_mct (member of hipac_rule);
  there is neither ipt_entry nor cmp_len;

  IMPORTANT: - there might be a padding between two consecutive rules
               in order to meet the alignment requirements for rules which
	       contain 64 bit members; so you have to use the IPT_ALIGN
               macro to jump to the next rule; note that there is no padding
               after a chain because it contains 64 bit members which
	       enforce the strictest alignment on the system
*/
struct nfhp_list_chain
{
	char label[HIPAC_CHAIN_NAME_MAX_LEN];
	u_int8_t policy;
	u_int32_t rule_num;
};

struct nfhp_list_rule
{
        char indev[IFNAMSIZ];
        char outdev[IFNAMSIZ];
        struct hipac_rule r;
};

/* these macros together with the universal macros can be used to access
   nfhp_list_rule */
#define FIRST_IPT_MATCH(r) ((struct ipt_entry_match *)          \
			    ((char *) (r) + (r)->match_offset))
#define IPT_TARGET(r)      ((struct ipt_entry_target *)          \
			    ((char *) (r) + (r)->target_offset))
#define IPT_MATCH_END(r)   ((struct ipt_entry_match *) IPT_TARGET(r))
#define CHAIN_TARGET(r)    ((char *) IPT_TARGET(r))

#endif
