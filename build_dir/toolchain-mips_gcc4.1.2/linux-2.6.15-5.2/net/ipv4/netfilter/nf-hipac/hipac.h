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


#ifndef _HIPAC_H
#define _HIPAC_H

#include "mode.h"

/* values of bittype in specification header */
#define BIT_U16  0
#define BIT_U32  1

/* maximum length of a hipac chain name (including terminating '\0') */
#define HIPAC_CHAIN_NAME_MAX_LEN 32

/* representation of the match [left, right] associated with a dimension id;
   [left, right] must not be a wildcard match */
struct hipac_match
{
        unsigned dimid  : 5;
	unsigned invert : 1;
        __u32 left;
        __u32 right;
	char next_match[0];
};

struct hipac_rule
{
	__u32 pos;
	char  cmp_start[0];
	__u32 size;
	__u32 origin;
	__u8  action;
	__u8  native_mct;
	__u16 match_offset;
	__u32 target_offset;
	struct hipac_match first_match[0];
};

struct hipac_chain_info
{
	char *label;
	__u8 policy;
	__u8 is_internal_chain;
	__u32 rule_num;
	struct list_head *chain_head;
};



/* return values of function based match executor */
typedef enum
{
	MATCH_YES,
	MATCH_NO,
	MATCH_HOTDROP
} hipac_match_t;


/* hipac_rule action value; TARGET_DUMMY is reserved for internal usage only;
   the function based target exectutor may return TARGET_ACCEPT, TARGET_DROP
   or TARGET_NONE */
typedef enum
{
	TARGET_DROP = NF_DROP,
	TARGET_ACCEPT = NF_ACCEPT,
	TARGET_NONE = (NF_ACCEPT > NF_DROP ? NF_ACCEPT + 1 : NF_DROP + 1),
	TARGET_RETURN,
	TARGET_DUMMY,
	TARGET_EXEC,
	TARGET_CHAIN
} hipac_target_t;


/* function based match and target executor function types */
typedef hipac_match_t (* hipac_match_exec_t) (const void *packet,
					      void *first_match, void *end);
typedef hipac_target_t (* hipac_target_exec_t) (const void *packet,
						void *target);


/* dimension extractor function type */
typedef __u32 (* hipac_extract_t) (const void *packet, int *hotdrop);


/* equality function type */
typedef int (* hipac_eq_exec_t) (const struct hipac_rule *r1,
				 const struct hipac_rule *r2);


/* constructor/destructor function type */
typedef void (* hipac_copy_constructor_t) (const struct hipac_rule *r_org,
					   struct hipac_rule *r_new);
typedef void (* hipac_destroy_exec_t) (struct hipac_rule *r);


/* hipac error codes */
typedef enum
{
	HE_OK                        =  0,
	HE_IMPOSSIBLE_CONDITION      = -1,
	HE_LOW_MEMORY                = -2,
	HE_CHAIN_EXISTS              = -3,
    	HE_CHAIN_NOT_EXISTENT        = -4,
	HE_CHAIN_IS_EMPTY            = -5,
	HE_CHAIN_NOT_EMPTY           = -6,
	HE_CHAIN_IS_USERDEFINED      = -7,
	HE_CHAIN_IS_CONNECTED        = -8,
	HE_CHAIN_IS_REFERENCED       = -9,
	HE_CHAIN_NOT_NATIVE          = -10,
	HE_CHAIN_IS_NATIVE           = -11,
	HE_RULE_NOT_EXISTENT         = -12,
	HE_RULE_ORIGIN_MISMATCH      = -13,
	HE_RULE_PREFIX_MISMATCH      = -14,
	HE_LOOP_DETECTED             = -15,
	HE_REC_LIMIT                 = -16,
	HE_TARGET_CHAIN_NOT_EXISTENT = -17,
	HE_TARGET_CHAIN_IS_NATIVE    = -18,
	HE_NATIVE_CHAIN_EXISTS       = -19,
	HE_NEXT_ERROR                = -100  // shouldn't be changed
} hipac_error;



/* return maximum key of a dimension with the given bittype */
static inline __u32
hipac_maxkey(__u8 bittype)
{
	if (bittype == BIT_U16)
		return 0xffff;
	return 0xffffffff;
}


/* init hipac data structures;
   MUST be called once at the beginning in order to let the other
   operations work properly!
   dimid_to_bittype: assigns dimids to bit types. 
                     i-th element of the array contains the bit type
		     of dimension id i
   extract:          functions to extract certain fields from a packet. 
                     the function at position i of the array returns
		     the entry in a packet that corresponds to 
		     dimension id i (i.e. the source ip of the packet)
   len:              length of the dim2btype and extract array
   copycon:          constructor function
   destroy:          destructor function
   match:            match executor function
   target:           target executor function
   eq:               equality function to compare rules
   maxmem:           maximum allowed memory consumption  
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */  
hipac_error
hipac_init(const __u8 dimid_to_bittype[], const hipac_extract_t extract[],
	   const __u8 len, hipac_copy_constructor_t copycon,
	   hipac_destroy_exec_t destroy, hipac_match_exec_t match,
	   hipac_target_exec_t target, hipac_eq_exec_t eq, 
	   const __u64 maxmem);


/* free all hipac data structures;
   MUST be called once in the end
   attention: make sure there are no external accesses to hipac 
              data structures taking place anymore!                   */
void
hipac_exit(void);


/* return new hipac data structure
   name:        name of the public chain
   name_intern: name of the internal dimtree chain
   policy:      initial policy
   origin:      bitvector uniq to this data structure
   hipac:       pointer to a pointer to the resulting hipac data
                structure. use as first argument to hipac_match()
   possible errors: HE_LOW_MEMORY, HE_NATIVE_CHAIN_EXISTS,
                    HE_CHAIN_EXISTS, HE_IMPOSSIBLE_CONDITION          */
hipac_error
hipac_new(const char *name, const char* name_intern, const __u8 policy, 
	  const __u32 origin, void **hipac);  


/* set maximum amount of memory the hipac data structures are 
   allowed to occupy. return LOW_MEMORY if 'mem' is lower than
   currently allocated memory
   possible errors: HE_LOW_MEMORY                                     */  
hipac_error
hipac_set_maxmem(const __u64 mem);


/* get maximum amount of memory the hipac data structures are 
   allowed to occupy.                                                 */  
__u64
hipac_get_maxmem(void);


/* set policy of chain with name 'name' to 'policy'.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_USERDEFINED,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error 
hipac_set_policy(const char *name, const __u8 policy);


/* get policy of chain with name 'name' and write it to 'result'.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_USERDEFINED,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_policy(const char *name, __u8 *result);


/* create new user-defined chain with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_EXISTS, 
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_new_chain(const char* name);


/* delete all rules in chain with name 'name'.
   if 'name' is NULL all rules in all chains are deleted
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_flush_chain(const char *name);


/* delete user-defined chain with name 'name'.
   if 'name' is NULL delete all chains that are empty 
   and not referenced from other chains.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_NATIVE,
                    HE_CHAIN_NOT_EMPTY, HE_CHAIN_IS_REFERENCED        */   
hipac_error
hipac_delete_chain(const char *name);


/* rename chain with name 'name' to 'new_name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_EXISTS, 
                    HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_NATIVE,
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_rename_chain(const char *name, const char *new_name);


/* get an array of hipac_chain_info structs containing required infos
   for a rule listing of chain with name 'name'. if 'name' is NULL
   return infos for all chains. 'len' specifies the length of the
   returned struct hipac_chain_info array.
   attention: don't forget to free the struct hipac_chain_info array
              after the rule listing via hipac_free_chain_infos()!
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_chain_infos(const char *name, struct hipac_chain_info **inf,
		      __u32 *len);


/* free array of hipac_chain_info structs that has been allocated
   before via hipac_get_chain_infos(). 
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_free_chain_infos(struct hipac_chain_info *inf);


/* get next hipac_rule 'next' of previous hipac_rule 'prev'.
   with this function you can walk over the chain during rule listing.
   to get the first hipac_rule of a chain, set 'prev' to NULL.
   when the end of the chain is reached or the chain is empty the
   hipac_error HE_RULE_NOT_EXISTENT is returned.
   attention: during rule listing of a chain hipac_get_next_rule() 
              must always be called until finally HE_RULE_NOT_EXISTENT 
	      is returned!
   possible errors: HE_LOW_MEMORY, HE_RULE_NOT_EXISTENT,
                    IMPOSSIBLE_CONDITION                              */
hipac_error
hipac_get_next_rule(const struct hipac_chain_info *inf,
		    struct hipac_rule *prev,
		    struct hipac_rule **next);


/* append hipac_rule 'rule' to chain with name 'name'.
   'rule->pos' is set to the position of the last rule
   in the chain + 1.  
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT, 
                    HE_LOOP_DETECTED, HE_REC_LIMIT,
		    HE_RULE_ORIGIN_MISMATCH, HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_TARGET_CHAIN_IS_NATIVE, 
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_append(const char *name, const struct hipac_rule *rule);


/* insert hipac_rule 'rule' at position 'rule->pos' into chain
   with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_LOOP_DETECTED, HE_REC_LIMIT,
		    HE_RULE_ORIGIN_MISMATCH, HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_TARGET_CHAIN_IS_NATIVE, 
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_insert(const char *name, const struct hipac_rule *rule);


/* delete hipac_rule with position 'pos' from chain with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT, 
                    HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
hipac_error
hipac_delete_pos(const char *name, const __u32 pos);


/* find the first rule in chain with name 'name' that equals to
   hipac_rule 'rule' and delete it.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT, 
                    HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
hipac_error
hipac_delete(const char *name, const struct hipac_rule *rule);


/* replace rule with position 'rule->pos' in chain with name 'name'
   with hipac_rule 'rule'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_RULE_NOT_EXISTENT, HE_LOOP_DETECTED,
		    HE_REC_LIMIT, HE_RULE_ORIGIN_MISMATCH,
		    HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_TARGET_CHAIN_IS_NATIVE, 
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_replace(const char *name, const struct hipac_rule *rule);


/* match packet and return the terminal packet action which is either
   TARGET_ACCEPT or TARGET_DROP; note that this is the only function
   that may be used in parallel with other functions of the hipac API */
hipac_target_t
hipac_match(void *hipac, const void *packet);



/*
 * hipac statistics: data structures
 */

/* rlp statistics
   total_mem_tight:       current overall memory consumption in bytes
                          in terms of how much has been requested
   total_mem_real:        current overall memory consumption in bytes
                          in terms of how much has actually been
                          allocated
   rlp_mem_tight:         current memory consumption in bytes of all
                          rlps (not including termrule blocks) in
                          terms of how much has been requested
   rlp_mem_real:          current memory consumption in bytes of all
                          rlps (not including termrule blocks) in
                          terms of how much has actually been
			  allocated
   termrule_mem_tight:    current memory consumption in bytes of all
                          termrule blocks in terms of how much has
			  been requested
   termrule_mem_real:     current memory consumption in bytes of all
                          termrule blocks in terms of how much has
			  actually been allocated
   rlp_num:               number of rlps
   rlp_dimid_num:         mapping with [i] containing the number of
                          rlps in dimension i
   rlp_depth_num:         mapping with [i] containing the number of
                          rlps in depth i
   termrule_num:          number of termrule blocks
   termrule_ptr_num:      number of entries in all termrule blocks
   keys_num:              number of keys in all rlps
   rlp_dimid_keys_stat:   array of distributions with [i][j]
                          containing the number of rlps in
			  dimension i with 2^(i - 1) <= keys < 2^i
   termptr_num:           number of terminal pointers (of all rlps)
   termptr_dimid_num:     mapping with [i] containing the number of
                          terminal pointers in dimension i
   termptr_depth_num:     mapping with [i] containing the number of
                          terminal pointers in depth i
   nontermptr_num:        number of non-terminal pointers (of all
                          rlps)
   nontermptr_dimid_num:  mapping with [i] containing the number of
                          non-terminal pointers in dimension i
   nontermptr_depth_num:  mapping with [i] containing the number of
                          non-terminal pointers in depth i
   dt_elem_num:           number of elementary interval structures
   dt_elem_ptr_num:       number of rules in all elementary interval
                          structures
   dt_elem_stat:          distribution with [i] containing the number
                          of elementary interval structures with
			  2^(i - 1) <= rules < 2^i                    */
struct hipac_rlp_stat
{
	__u64 total_mem_tight;
	__u64 total_mem_real;
	__u64 rlp_mem_tight;
	__u64 rlp_mem_real;
	__u64 termrule_mem_tight;
	__u64 termrule_mem_real;
	__u32 rlp_num;
	__u32 rlp_dimid_num[16];
	__u32 rlp_depth_num[16];
	__u32 termrule_num;
	__u32 termrule_ptr_num;
	__u32 keys_num;
	__u32 rlp_dimid_keys_stat[16][18];
	__u32 termptr_num;
	__u32 termptr_dimid_num[16];
	__u32 termptr_depth_num[16];
	__u32 nontermptr_num;
	__u32 nontermptr_dimid_num[16];
	__u32 nontermptr_depth_num[16];
	__u32 dt_elem_num;
	__u32 dt_elem_ptr_num;
	__u32 dt_elem_stat[16];
};

/* dimtree statistics
   chain_mem_tight:         current memory consumption in bytes of
                            a dimtree chain including the rules in
                            terms of how much has been requested
   chain_mem_real:          current memory consumption in bytes of
                            a dimtree chain including the rules in
                            terms of how much has actually been
                            allocated
   rule_num:                number of dimtree rules
   rules_with_exec_matches: number of dimtree rules containing at
                            least one function based match
   rules_with_exec_target:  number of dimtree rules containing
                            a function based target
   rules_same_pos_stat:     distribution with [i] containing number
                            of dimtree rule series of length
                            >= 2^(i - 1) and < 2^i where all rules
                            share the same position 
   dt_match_stat:           mapping with [i] containing the number
                            of dimtree rules having i non-wildcard
                            matches                                   */
struct hipac_dimtree_stat
{
	__u64 chain_mem_tight;
	__u64 chain_mem_real;
	__u32 rule_num;
	__u32 rules_with_exec_matches;
	__u32 rules_with_exec_target;
	__u32 rules_same_pos_stat[16];
	__u32 dt_match_stat[16];
};

/* hipac memory statistics
   total_mem_tight:             current overall memory consumption in
                                bytes in terms of how much has been
                                requested
   total_mem_real:              current overall memory consumption in
                                bytes in terms of how much has
                                actually been allocated
   memhash_elem_num:            number of objects for which memory
                                has been requested
   memhash_len:                 number of buckets in the memory hash
   memhash_smallest_bucket_len: number of objects in the smallest
                                bucket of the memory hash
   memhash_biggest_bucket_len:  number of objects in the biggest
                                bucket of the memory hash
   memhash_bucket_stat:         distribution with [i] containing the
                                number of buckets with
                                2^(i - 1) <= objects < 2^i            */
struct hipac_mem_stat
{
	__u64 total_mem_tight;
	__u64 total_mem_real;
	__u32 memhash_elem_num;
	__u32 memhash_len;
	__u32 memhash_smallest_bucket_len;
	__u32 memhash_biggest_bucket_len;
	__u32 memhash_bucket_stat[16];
	
};


/* hipac chain statistics
   mem_tight:     current memory consumption in bytes of all
                  hipac chains including the rules in terms of 
		  how much has been requested
   mem_real:      current memory consumption in bytes of all
                  hipac chains including the rules in terms of
		  how much has actually been allocated
   chain_num:     number of chains
   rule_num:      number of rules in all chains
   paths_stat:    distribution with [i] containing the number of 
                  chains with 2^(i - 1) <= paths < 2^i
   incoming_stat: distribution with [i] containing the number of
                  chains with 2^(i - 1) <= incoming edges < 2^i
   outgoing_stat: distribution with [i] containing the number of
                  chains with 2^(i - 1) <= outgoing edges < 2^i       */
struct hipac_chain_stat
{	
	__u64 mem_tight;
	__u64 mem_real;
	__u32 chain_num;
	__u32 rule_num;
	__u32 prefix_stat[16];
	__u32 incoming_stat[16];
	__u32 outgoing_stat[16];
};


/* hipac rule statistics
   rule_num:          number of rules 
   exec_match_num:    number of rules with exec_matches
   exec_target_num:   number of rules with exec_target
   jump_target_num:   number of rules with jump target
   return_target_num: number of rules with return target
   hipac_match_stat:  mapping with [i] containing the number
                      of rules with i hipac_matches
   inv_rules_stat:    mapping with [i] containing the number
                      of rules with i inversion flags                 */
struct hipac_rule_stat
{
	__u32 rule_num;
	__u32 exec_match_num;
	__u32 exec_target_num;
	__u32 jump_target_num;
	__u32 return_target_num;
	__u32 hipac_match_stat[16];
	__u32 inv_rules_stat[16];
};


/* hipac user statistics
   total_mem_tight: current memory consumption in bytes in terms 
                    of how much has been requested
   total_mem_real:  current memory consumption in bytes in terms
                    of how much has actually been allocated
   chain_num:       number of chains
   rule_num:        number of rules in all chains                     */
struct hipac_user_stat
{
	__u64 total_mem_tight;
	__u64 total_mem_real;	
	__u32 chain_num;
	__u32 rule_num;
};



/*
 * hipac statistics: functions
 */

/* get rlp statistics, i.e. the statistics of the internal
   rlp representation of all rules reachable from the root chain
   represented by the 'hipac' pointer
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_rlp_stat(void *hipac, struct hipac_rlp_stat *stat);


/* get dimtree statistics, i.e. the statistics of the internal
   chain representation of all rules reachable from the root chain
   represented by the 'hipac' pointer
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_dimtree_stat(void *hipac, struct hipac_dimtree_stat *stat);


/* get hipac memory statistics
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_mem_stat(struct hipac_mem_stat *stat);


/* get hipac chain statistics
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_chain_stat(struct hipac_chain_stat *stat);


/* get hipac rule statistics
   returned statistics constains all rules of those chains that are
   reachable from the root chain represented by the 'hipac' pointer
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_rule_stat(void *hipac, struct hipac_rule_stat *stat);


/* get hipac user statistics
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_user_stat(struct hipac_user_stat *stat);

#ifdef DEBUG
/* per object debugging: selection is done by an externally defined variable
   hipac_debug which is a bit vector of DEBUG_* */
#  define DEBUG_HIPAC   0x01
#  define DEBUG_DIMTREE 0x02
#  define DEBUG_RLP     0x04
#  define DEBUG_IHASH   0x08
#  define DEBUG_GLOBAL  0x10
   extern unsigned hipac_debug;

hipac_error
hipac_get_dt_rule_ptrs(const char *name, const __u32 pos, void **res);

__u8
dt_rules_have_same_position(void *hipac, void *dt_start, void *dt_rule);
#endif

#endif
