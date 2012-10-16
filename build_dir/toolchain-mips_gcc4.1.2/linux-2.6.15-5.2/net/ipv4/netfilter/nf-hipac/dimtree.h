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


#ifndef _DIMTREE_H
#define _DIMTREE_H

#include "global.h"
#include "rlp.h"

/* upper bound for matches of the given bit type */
#define MAXKEY(bittype) \
((bittype) == BIT_U16 ? 0xffff : 0xffffffff)

/* used to distinguish a rule from an elementary interval */
#define RT_RULE 0
#define RT_ELEM 1


/* header for dimtree rules and elementary intervals */
struct dt_rule_elem_spec
{
	unsigned rlp    : 1; // must be 0	
	unsigned rtype  : 1; // {RT_RULE, RT_ELEM}
};

/* header for dimtree rules */
struct dt_rule_spec
{
	unsigned rlp    :  1; // must be 0	
	unsigned rtype  :  1; // must be RT_RULE
	unsigned action :  4; // packet action
	unsigned pos    : 26; // position of the rule in the chain
};

/* dt_match represents the native interval match [left, right] associated
   with dimension dimid whereby [left, right] may not be a wildcard match */
struct dt_match
{
        __u8 dimid;
        __u32 left, right;
	char next_match[0];
};

/* dt_rule is an entry in the dt_chain; at the end of the struct we have
   dt_match_len >= 0 dt_matches
   if the rule has a function based target then exec_target points to the
   target's data which is handled by target_fn;
   the rule's exec_match pointer block references >= 0 blocks each of >= 1
   function based matches, called fblocks;
   the (2 * i)-th pointer of exec_match points to the beginning of the i-th
   fblock;
   the (2 * i + 1)-th pointer of exec_match points to the end of the i-th
   fblock;
   the start and end pointers are handed to match_fn */
struct dt_rule
{
        struct dt_rule_spec spec;
	struct list_head head;
	struct ptrblock *exec_match;
	void *exec_target;
	__u32 exec_target_size;
	__u8 deleted;
	__u8 dt_match_len;
	struct dt_match first_dt_match[0];
};

#define IS_RULE(r) (!IS_RLP(r) &&                                         \
		    ((struct dt_rule_elem_spec *) (r))->rtype == RT_RULE)
#define HAS_EXEC_MATCH(r)  ((r)->exec_match != NULL)
#define IS_TARGET_DUMMY(r) ((r)->spec.action == TARGET_DUMMY)
#define IS_TARGET_NONE(r)  ((r)->spec.action == TARGET_NONE)
#define IS_TARGET_EXEC(r)  ((r)->spec.action == TARGET_EXEC)
#define IS_TARGET_TERM(r)  ((r)->spec.action == TARGET_ACCEPT || \
			    (r)->spec.action == TARGET_DROP)
#define IS_RULE_TERM(r)    (IS_TARGET_TERM(r) && !HAS_EXEC_MATCH(r))

/* return the size of a dt_rule with dt_match_len dt_matches */
static inline __u32
dt_rule_size(__u8 dt_match_len)
{
	return (sizeof(struct dt_rule) + 
		dt_match_len * sizeof(struct dt_match));
}

/* head of the list of rules */
struct dt_chain
{
	struct list_head head;
	char name[HIPAC_CHAIN_NAME_MAX_LEN];
	struct dt_rule *first; // optimization of dimtree_chain_fix
	__u32 len;
};



/* header for elementary intervals */
struct dt_elem_spec
{
	unsigned rlp     : 1; // must be 0
	unsigned rtype   : 1; // must be RT_ELEM
	unsigned newspec : 1; // indicates whether the elementary interval is
	                      // contained in newspec
};

/* elementary interval */
struct dt_elem
{
	struct dt_elem_spec spec;
	/* terminating target (TARGET_ACCEPT, TARGET_DROP) without function
	   based matches */
	struct dt_rule *term_rule;
	/* block of non-terminating rules (function based matches or no
	   terminal target) whose position is < term_rule->spec.pos */
	struct ptrblock ntm_rules;
};

#define IS_ELEM(e) (!IS_RLP(e) &&                                         \
		    ((struct dt_rule_elem_spec *) (e))->rtype == RT_ELEM)



struct dimtree
{
	__u32 origin;
        struct gen_spec *top;
	struct gen_spec *top_new;    // new not yet active top level structure
	int need_commit;             // 1 if top_new is valid
        struct dt_chain *chain;
};



/* create new dimtree and store it in *newdt; chain_name is copied to
   dt->chain->name; memory for newdt is allocated within dimtree_new;
   origin is a bit vector where exactly one bit is set; it is used to
   uniquely define the "origin property" of newdt; dummy and policy
   define the base ruleset; dummy must have TARGET_DUMMY as target,
   policy must be a terminal rule without any dt_matches;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
dimtree_new(struct dimtree **newdt, __u32 origin, const char *chain_name,
	    struct dt_rule *dummy, struct dt_rule *policy);

/* free memory for dt and all embedded structures; make sure that no packet
   matching occurs on dt any more */
void
dimtree_free(struct dimtree *dt);

/* remove all rules except the first and the last one from dt->chain and
   free them; set dt->top to the last rule in the chain */
void
dimtree_flush(struct dimtree *dt);

const char *
dimtree_get_chain_name(const struct dimtree *dt);

/* insert rule into the dt_chain and the rlps; inc indicates whether all
   rule positions >= rule->spec.pos should be incremented by 1;
   if commit is not 0 then the top level structure in dt is replaced by the
   new one and the old rlps and elementary intervals are freed;
   in case of a fault all newly created rlps and elementary intervals
   are freed; origin is a bit vector describing the allowed dimtrees
   into which rule may be inserted; if rule must not be inserted into dt
   it is anyway inserted into dt->chain (so take care to remove it from
   there);
   NOTICE: if commit is not 0 it is assumed that this operation is the
           first one (at all or directly after a previously committed
           operation or series of operations (-> dimtree_commit))
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION,
                    HE_RULE_ORIGIN_MISMATCH */
hipac_error
dimtree_insert(struct dimtree *dt, struct dt_rule *rule, __u32 origin,
	       int inc, int commit);

/* delete rule from rlp, _NOT_ from the dt_chain; 'rule' must point to a
   rule in dt->chain; if commit is not 0 then the top level structure in dt
   is replaced by the new one and the old rlps and elementary intervals
   are freed; in case of a fault all newly created rlps and elementary
   intervals are freed;
   NOTICE: if commit is not 0 it is assumed that this operation is the
           first one (at all or directly after a previously committed
           operation or series of operations (-> dimtree_commit))
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
dimtree_delete(struct dimtree *dt, struct dt_rule *rule, int commit);

/* called at the end of a successful series of dimtree_insert and/or
   dimtree_delete operation(s) to make the result visible, i.e. set dt->top
   to dt->top_new for each dimtree dt in dt_block and free the old rlps
   and elementary intervals */
void
dimtree_commit(struct ptrblock *dt_block);

/* called at the end of an unsuccessful series of dimtree_insert and/or
   dimtree_delete operation(s) to undo the changes, i.e. set dt->top_new
   to NULL and need_commit to 0 for each dimtree dt in dt_block and free the
   new rlps and elementary intervals */
void
dimtree_failed(struct ptrblock *dt_block);

#ifdef DEBUG
int
rule_occur(struct gen_spec *g, struct dt_rule *rule, int print);
#endif

/* remove all rules between start and the rule(s) r with position end_pos inc.
   start and r themselves; the positions of the rules behind r are not
   changed */
static inline void
dimtree_chain_delete(struct dimtree *dt, struct dt_rule *start, __u32 end_pos)
{
	struct dt_rule *rule;
       	struct list_head *lh;

	if (unlikely(dt == NULL || start == NULL ||
		     start->spec.pos > end_pos)) {
		ARG_MSG;
		return;
	}

	assert(dt->need_commit == 0);
	if (start->head.prev == &dt->chain->head) {
		/* start is the first element => dt->chain->first stays
		   NULL until dimtree_chain_fix has been called */
		dt->chain->first = NULL;
	} else if (dt->chain->first != NULL &&
		   dt->chain->first->spec.pos >= start->spec.pos) {
		dt->chain->first = list_entry(start->head.prev,
					      struct dt_rule, head);
	}
	for (lh = &start->head, rule = start; lh != &dt->chain->head &&
		     rule->spec.pos <= end_pos;) {
		lh = lh->next;
		list_del(lh->prev);
#ifdef DEBUG
		if (rule_occur(dt->top, rule, 1)) {
			ERR("rule present in original structure");
			return;
		}
#endif
		if (rule->exec_match != NULL) {
			ptrblock_free(rule->exec_match);
		}
		hp_free(rule);
		dt->chain->len--;
		rule = list_entry(lh, struct dt_rule, head);
	}
}

/* iterate over the dt_chain in dt and tighten the position numbers */
void
dimtree_chain_fix(struct ptrblock *dt_block);

#ifdef DEBUG
/* matching algorithm used for correctness checks; the returned ptrblock
   contains the rules matching the packet ordered after their positions;
   the last rule should always have TARGET_ACCEPT or TARGET_DROP as action
   and may not contain exec_matches */
struct ptrblock *
hipac_match_debug(struct dimtree *dt, const void *packet);
#endif

#endif
