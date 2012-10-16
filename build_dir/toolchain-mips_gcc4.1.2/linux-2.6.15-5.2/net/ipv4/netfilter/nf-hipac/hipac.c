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


#include "hipac.h"
#include "global.h"
#include "ihash.h"
#include "dimtree.h"


static struct hipac_chain *current_chain = NULL;
static struct ihash* chain_hash = NULL;
static struct ptrblock* native_dts = NULL;

__u8 *dim2btype;
__u8 d2blen;
hipac_extract_t *extract_fn;
static hipac_copy_constructor_t copy_fn;
static hipac_destroy_exec_t destroy_fn;
hipac_match_exec_t match_fn;
hipac_target_exec_t target_fn;
static hipac_eq_exec_t eq_fn;



/* 
 * Some helpful defines in order to make code more readable
 */

#define DONT_COMMIT    0
#define COMMIT         1
#define DONT_INC       0
#define INC            1
#define DONT_ADD       0
#define ADD            1
#define ORIGIN_ALL     0xffff

#define CHAIN_IS_REFERENCED(chain) ((chain)->ref_count != 0)
#define CHAIN_NOT_CONNECTED(chain) ((chain)->start == NULL)
#define IS_ROOT_CHAIN(chain)       ((chain)->dimtree != NULL)
#define IS_NOT_JUMP_RULE(rule)     ((rule)->r.action != TARGET_CHAIN)
#define IS_JUMP_RULE(rule)         ((rule)->r.action == TARGET_CHAIN)

#define P_ELEM(x, i)         (STRBLOCK_ITH(x, i, struct path *))
#define P_ELEM_DIMTREE(x, i) (STRBLOCK_ITH(x, i, struct path *)->dimtree)
#define P_ELEM_PREV(x, i)    (STRBLOCK_ITH(x, i, struct path *)->prev)
#define P_ELEM_RULE(x, i)    (STRBLOCK_ITH(x, i, struct path *)->rule)


#define CHAIN_HASH_LEN         16
#define CHAIN_HASH_AVR_BUCKET   3
#define HIPAC_REC_LIMIT        10


#ifdef DEBUG
#       define LOW_MEM(args...) do { NOTICE(args); return HE_LOW_MEMORY; \
                                   } while (0)
#       define CHECK_ERROR(func) \
                if (error == HE_LOW_MEMORY) { \
	                NOTICE(func " returned LOW_MEMORY error!"); \
        } else if (error == HE_IMPOSSIBLE_CONDITION) {  \
	        ERR(func " returned IMPOSSIBLE_CONDITION error!"); \
	}

        static inline hipac_error
	strblock_append_check(struct strblock **b, const void *s, __u32 size){
		__u32 i;
		if (*b)
			for (i = 0; i < (*b)->len; i++){
				if (!(memcmp(STRBLOCK_ITH(*b, i, void *), 
					     s, size)))
					IMPOSSIBLE_CONDITION(
						"already in strblock");
			}
		return strblock_append(b, s, size);
	}

#else
#       define LOW_MEM(args...) return HE_LOW_MEMORY
#       define CHECK_ERROR(func) \
                if (error == HE_IMPOSSIBLE_CONDITION) {  \
                        ERR(func " returned IMPOSSIBLE_CONDITION error!"); \
                }

        static inline hipac_error
	strblock_append_check(struct strblock **b, const void *s, __u32 size){
		return strblock_append(b, s, size);
	}
#endif




/* element in strblock next_chain in struct hipac_chain
   means that current chain contains 'count' >= 1 rules 
   that jump to chain 'chain'                                         */
struct next_chain_elem
{
	__u32 count;
	struct hipac_chain *chain;
};


/* the combined rule of all the chain_rules on the path
   from a ROOT_CHAIN to the current chain                             */
struct prefix_rule
{
	__u32 origin;
	struct ptrblock *exec_matches;
	__u8  native_mct;
	struct hipac_match first_match[0];
};


/* the path from a ROOT_CHAIN to the current chain;
   dimtree:   the dimtree corresponding to the ROOT of that path
   prev:      the previous chain_rule on that path
   rule:      the combined rule of all the chain_rules on that path   */
struct path
{
	struct dimtree *dimtree;
	struct chain_rule *prev;
	struct prefix_rule *rule;
};


/* hipac_chain is the 'head' of the doubly linked list of chain_rules;
   name:           the name of the chain
   ref_count:      the number of rules that jump to this chain
   next_chains:    block of next_chain_elem structs; each chain that is
                   jumped to from a rule in this chain has its own 
		   next_chain_elem in this block with its 'count' field set to
		   the number of rules that jump to that chain
   paths:          block of all the paths from any ROOT_CHAIN to this chain
   start:          contains pointers to dt_rules that mark the beginning
                   of this chain in the internal dt_chain
   end:            the same for the ending of the chain
   dimtree:        points to a dimtree if chain is a ROOT_CHAIN,
                   otherwise it's NULL                                */
struct hipac_chain
{
	struct list_head head;
	char name[HIPAC_CHAIN_NAME_MAX_LEN];
	__u32 list_pos;
	__u32 ref_count;
	struct strblock *next_chains; 
	struct strblock *paths;
	struct ptrblock *start;
	struct ptrblock *end;   
	struct dimtree *dimtree;
};

/* chain_rule is contained in a cyclic doubly linked list of rules where the
   'head' of the list is of type struct hipac_chain;
   dtr:  contains pointers to dt_rules in the internal dt_chain that correspond
         to this chain_rule                                           */
struct chain_rule
{
	struct list_head head;
	struct ptrblock *dtr;
	struct hipac_rule r;
};





/* 
 * Several functions to free certain structs.
 * The functions recursively free all other data structures that
 * are pointed to from within the structs.  
 */

static inline void
dt_rule_free(struct dt_rule *rule)
{
	if (rule->exec_match)
		ptrblock_free(rule->exec_match);
	hp_free(rule);
}

static inline void
hipac_rule_free(struct hipac_rule *rule)
{
	destroy_fn(rule);
	hp_free(rule);
}

static inline void
chain_rule_free(struct chain_rule *rule)
{
	if (rule->dtr)
		ptrblock_free(rule->dtr);
	hp_free(rule);
}

static inline void
chain_rule_destroy(struct chain_rule *rule)
{
	if (rule->dtr)
		ptrblock_free(rule->dtr);
	destroy_fn(&rule->r);
	hp_free(rule);
}

static inline void
prefix_rule_free(struct prefix_rule *p)
{
	if (p->exec_matches)
		ptrblock_free(p->exec_matches);
	hp_free(p);
}

static inline void
path_free(struct path *p)
{
	if (p->rule)
		prefix_rule_free(p->rule);
	hp_free(p);
}

static inline void
paths_free(struct strblock *paths)
{
	__u32 i;
	for (i = 0; i < paths->len; i++)
		prefix_rule_free(P_ELEM_RULE(paths, i));
	strblock_free(paths);
}

/* End of free functions */








/*
 * chain_hash_* functions
 */


/* insert 'chain' into the global hash of all chains ('chain_hash') 
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
chain_hash_insert(struct hipac_chain* chain)
{
	return ihash_insert(&chain_hash, chain->name, chain);//IS_THIS_CORRECT?
}



/* remove 'chain' from the global hash of all chains ('chain_hash')
   the removed chain is not freed                                     */
static inline void
chain_hash_remove(struct hipac_chain* chain)
{
	if (current_chain && current_chain == chain)
		current_chain = NULL;
	ihash_delete(chain_hash, chain->name, NULL);
}



/* replace 'org' with 'new' in global hash of all chains
   the replaced chain is not freed                                    */
static inline hipac_error
chain_hash_replace(struct hipac_chain *org, struct hipac_chain *new)
{
	if (current_chain && current_chain == org)
		current_chain = NULL;
	return ihash_replace(&chain_hash, org->name, NULL, new->name, new);
}



/* lookup 'chain' with name 'name' in global 'chain_hash',
   the hash of all chains. 
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION    */
static inline hipac_error
chain_hash_lookup(const char* name, struct hipac_chain **chain)
{
	if (unlikely(!name || !chain))
		ARG_ERR;
	if ((current_chain) &&
	    (!strcmp(name, current_chain->name))){
		*chain = current_chain;
		return HE_OK;
	}
	*chain = (struct hipac_chain*) ihash_lookup(chain_hash, name);
	if (*chain != NULL) {
		current_chain = *chain;
		return HE_OK;
	}
	return HE_CHAIN_NOT_EXISTENT;
}


/* End of chain_hash_* functions */





/* get previous dt_rules of the internal dt_rule representations of
   chain_rule 'rule'.
   if previous chain_rule 'prev' is not a jump rule return pointer to 
   'prev->dtr' and set 'free_needed' to 0. otherwise a new ptrblock
   with pointers to the previous dt_rules has to be computed from the
   'chain->end' block of the chain 'prev' is pointing to and 
   'free_needed' is set to 1.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
get_prev_dt_rules(const struct hipac_chain *chain, 
		  const struct chain_rule *rule, 
		  __u8 *free_needed, struct ptrblock **p)
{			     
	struct chain_rule *prev;
	
	if (unlikely(CHAIN_NOT_CONNECTED(chain)))
		return HE_IMPOSSIBLE_CONDITION;
	
	if (unlikely(rule->head.prev == &chain->head)){
		*p = chain->start;
		*free_needed = 0;
		return HE_OK;
	}
	
	prev = list_entry(rule->head.prev, struct chain_rule, head);
	*free_needed = IS_JUMP_RULE(prev);
	if (!(*free_needed)){
		*p = prev->dtr;
	} else {
		struct hipac_chain *c = NULL;
		hipac_error error;
		__u32 i;
		chain_hash_lookup((void *) &prev->r 
				  + prev->r.target_offset, &c);
		*p = NULL;
		for (i = 0; i < c->paths->len; i++){
			if (prev == P_ELEM_PREV(c->paths, i)){
				if ((error = 
				     ptrblock_append(p, c->end->p[i]))){
					CHECK_ERROR("ptrblock_append");
					if (*p)
						ptrblock_free(*p);
					*p = NULL;
					return error;
				}
			}
		}
	}
	return HE_OK;
}



/* get next dt_rules of the internal dt_rule representations of 
   chain_rule 'rule'.
   if next chain_rule 'next' is not a jump rule return pointer to
   'next->dtr' and set 'free_needed' to 0. otherwise a new ptrblock
   with pointers to the next dt_rules has to be computed from the
   'chain->start' block of the chain 'next' is pointing to and 
   'free_needed' is set to 1. 
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
get_next_dt_rules(const struct hipac_chain *chain, 
		  const struct chain_rule *rule, 
		  __u8 *free_needed, struct ptrblock **p)
{			     
	struct chain_rule *next;
	
	if (unlikely(CHAIN_NOT_CONNECTED(chain)))
		return HE_IMPOSSIBLE_CONDITION;
	
	if (unlikely(rule->head.next == &chain->head)){
		*p = chain->end;
		*free_needed = 0;
		return HE_OK;
	}
	
	next = list_entry(rule->head.next, struct chain_rule, head);
	*free_needed = IS_JUMP_RULE(next);
	if (!(*free_needed)){
		*p = next->dtr;
	} else {
		struct hipac_chain *c = NULL;
		hipac_error error;
		__u32 i;
		chain_hash_lookup((void *) &next->r + 
				  next->r.target_offset, &c);
		*p = NULL;
		for (i = 0; i < c->paths->len; i++){
			if (next == P_ELEM_PREV(c->paths, i)){
				if ((error = 
				     ptrblock_append(p, c->start->p[i]))){
					CHECK_ERROR("ptrblock_append");
					if (*p)
						ptrblock_free(*p);
					*p = NULL;
					return error;
				}
			}
		}
	}
	return HE_OK;
}





/*
 * chain_* functions
 */


/* create new hipac_chain with name 'name' and initialize all fields 
   in struct hipac_chain 'result'. 'list_pos' is used to initialize
   the list_pos member of 'result'
   hipac_chain 'result' is not inserted into 'chain_hash'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_EXISTS,
                    HE_IMPOSSIBLE_CONDITION                           */
static inline hipac_error
chain_new(const char *name, struct hipac_chain **result, __u32 list_pos)
{	
	struct hipac_chain *chain;
	hipac_error error;

	if (unlikely(!name || !result))
		ARG_ERR;
	
	if (unlikely(!(error = chain_hash_lookup(name, &chain))))
		return HE_CHAIN_EXISTS;
		
	*result = chain = hp_alloc(sizeof(*chain), ADD);
	if (!chain)
		LOW_MEM("chain alloc failed!");
	INIT_LIST_HEAD(&chain->head);
	strncpy(chain->name, name, HIPAC_CHAIN_NAME_MAX_LEN);
	chain->name[HIPAC_CHAIN_NAME_MAX_LEN - 1] = '\0';
	chain->list_pos = list_pos;
	chain->ref_count = 0;
	chain->next_chains = NULL;
	chain->paths = NULL;
	chain->start = NULL;
	chain->end = NULL;
	chain->dimtree = NULL;
	return HE_OK;
}



/* free hipac_chain 'chain' and recursively all other data 
   structures that are pointed to from within this struct.
   also free all rules in this chain.
   attention: make sure 'chain' is NOT in the global 
              'chain_hash' anymore!                                   */
static inline void
chain_free(struct hipac_chain* chain)
{
	struct list_head *lh;
	struct chain_rule *rule;
	
	if (unlikely(!chain)){
		ARG_MSG;
		return;
	}
	
	lh = chain->head.next;
	while (lh != &chain->head) {
		rule = list_entry(lh, struct chain_rule, head);
		lh = lh->next;
		list_del(lh->prev);
		chain_rule_destroy(rule);
	} 
	if (chain->next_chains)
		strblock_free(chain->next_chains);
	if (chain->paths)
		paths_free(chain->paths);
	if (chain->start)
		ptrblock_free(chain->start);
	if (chain->end)
		ptrblock_free(chain->end);
       	hp_free(chain);
}



/* flush hipac_chain 'chain'
   free all rules in this chain and all other data structures
   that are pointed to from within this struct.                       */
static inline void
chain_flush(struct hipac_chain* chain)
{
	struct list_head *lh;
	struct chain_rule *rule;
	
	if (unlikely(!chain)){
		ARG_MSG;
		return;
	}
	
	lh = chain->head.next;
	while (lh != &chain->head) {
		rule = list_entry(lh, struct chain_rule, head);
		lh = lh->next;
		list_del(lh->prev);
		chain_rule_destroy(rule);
	}
	if (chain->next_chains){
		strblock_free(chain->next_chains);
		chain->next_chains = NULL;
	}
	if (chain->paths){
		paths_free(chain->paths);
		chain->paths = NULL;
	}
	if (chain->start){
		ptrblock_free(chain->start);
		chain->start = NULL;
	}
	if (chain->end){
		ptrblock_free(chain->end);
		chain->end = NULL;
	}
	chain->ref_count = 0;
	
}



/* insert chain_rule 'rule' into 'chain' at position rule->r.pos;
   if chain is empty, rule->r.pos is set to 1;
   if rule->r.pos is larger than maxpos, rule->r.pos is set to maxpos;
   'do_inc': when not 0 the pos field of all rules with 
             pos >= rule->r.pos is incremented by 1                   */
static inline void
chain_insert(struct hipac_chain* chain, struct chain_rule *rule,
	     const __u8 do_inc)
{
	struct list_head *lh;
	__u32 rulepos;
	struct chain_rule *curule;
	
	if (unlikely(!chain || !rule)){
		ARG_MSG;
		return;
	}

	if (list_empty(&chain->head)) {
		list_add(&rule->head, &chain->head);
		rule->r.pos = 1;
		return;
	}

	if (rule->r.pos == 0)
		rule->r.pos = 1;

	lh = chain->head.prev;
	rulepos = rule->r.pos;
	curule = list_entry(lh, struct chain_rule, head);
	
	if (rulepos > curule->r.pos) {
		list_add_tail(&rule->head, &chain->head);
		rule->r.pos = curule->r.pos + 1;
		return;
	}

	if (do_inc) {
		do {
			curule->r.pos++;
			lh = lh->prev;
			curule = list_entry(lh, struct chain_rule, head);
		} while (lh != &chain->head && curule->r.pos >= rulepos);
	} else {
		do {
			lh = lh->prev;
			curule = list_entry(lh, struct chain_rule, head);
		} while (lh != &chain->head && curule->r.pos >= rulepos);
	}

	if (lh == &chain->head) {
		assert(rulepos == 1);
		assert(!do_inc || 
		       list_entry(chain->head.next,
				  struct chain_rule, head)->r.pos == 2);
		assert(do_inc ||
		       list_entry(chain->head.next,
				  struct chain_rule, head)->r.pos == 1);
		
		list_add(&rule->head, &chain->head);
	} else {
		assert(curule->r.pos < rulepos);
		assert(!do_inc ||
		       list_entry(curule->head.next,
				  struct chain_rule,
				  head)->r.pos == rulepos + 1);
		assert(do_inc ||
		       list_entry(curule->head.next,
				  struct chain_rule,
				  head)->r.pos == rulepos);
		
		list_add(&rule->head, &curule->head);
	}
}



/* delete and all rules in 'chain' with position == 'rulepos';
   attention: you must NOT call chain_delete with an empty chain!
              does not free the rules!                                */
static void
chain_delete(const struct hipac_chain* chain, const __u32 rulepos)
{
       	struct chain_rule *current_rule;
	
	if (unlikely(!chain)){
		ARG_MSG;
		return;
	}
	current_rule = list_entry(chain->head.prev, struct chain_rule, head);
	
	while (current_rule->r.pos > rulepos) {
		current_rule->r.pos--;
		current_rule = list_entry(current_rule->head.prev, 
					  struct chain_rule, head);
	}	
       	list_del(&current_rule->head);
}



/* find rule in hipac_chain 'chain' that equals hipac_rule 'rule'.
   possible errors: HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
static inline hipac_error
chain_find_rule(const struct hipac_chain *chain, const struct hipac_rule *rule,
		struct chain_rule **result)
{
	struct list_head *lh;
	struct chain_rule *currule;

	if (!chain || !rule || !result)
		ARG_ERR;
			
	list_for_each(lh, &chain->head) {
		currule = list_entry(lh, struct chain_rule, head);
		if (eq_fn(rule, &currule->r)){
			*result = currule;
			return HE_OK;
		}
	}
	return HE_RULE_NOT_EXISTENT;
}



/* find rule in hipac_chain 'chain' with position 'pos'
   possible errors: HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
static inline hipac_error
chain_find_rule_with_pos(const struct hipac_chain *chain, const __u32 pos,
			 struct chain_rule **result)
{
	struct list_head *lh;
	struct chain_rule *currule;

	if (!chain || !result)
		ARG_ERR;
			
	list_for_each(lh, &chain->head) {
		currule = list_entry(lh, struct chain_rule, head);
		if (currule->r.pos == pos){
			*result = currule;
			return HE_OK;
		}
	}
	return HE_RULE_NOT_EXISTENT;
}


/* End of chain_* functions */






/* build chain_rule 'result' from hipac_rule 'rule'.        
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
hipac_error
build_chain_rule_from_hipac_rule(const struct hipac_rule *rule, 
				 struct chain_rule **result)
{
	if (unlikely(!rule || !result))
		ARG_ERR;

	*result = hp_alloc(sizeof(**result) - sizeof(struct hipac_rule)
	                   + rule->size, ADD);
	if (!(*result))
		LOW_MEM("chain_rule alloc failed!");
	
	(*result)->dtr = NULL;
	copy_fn(rule, &(*result)->r);
       	return HE_OK;
}



/* build hipac_rule 'result' from dt_rule 'dt_rule'.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
hipac_error
build_hipac_rule_from_dt_rule(const struct dt_rule *dt_rule,
			      struct hipac_rule **result)
{
	__u32 size, exec_match_size = 0;
	__u32 i;

	if (unlikely(!dt_rule || !result))
		ARG_ERR;

	size = sizeof(**result) 
		+ dt_rule->dt_match_len * sizeof(struct hipac_match)
		+ dt_rule->exec_target_size;
	
	if (dt_rule->exec_match){
		for (i = 0; i < dt_rule->exec_match->len; i += 2){ 
			exec_match_size += (void *) 
				dt_rule->exec_match->p[i + 1]
				- dt_rule->exec_match->p[i];
		}
	}
	size += exec_match_size;

	*result = hp_alloc(size, ADD);
	if (!(*result))
		LOW_MEM("hipac_rule alloc failed!");
	
	(*result)->pos = dt_rule->spec.pos;
	(*result)->size = size;
	(*result)->origin = 0;
	(*result)->action = dt_rule->spec.action;
	(*result)->native_mct = dt_rule->dt_match_len;
	if (dt_rule->exec_match)
		(*result)->match_offset = sizeof(**result)
			+ dt_rule->dt_match_len * sizeof(struct hipac_match);
	else (*result)->match_offset = 0;
	(*result)->target_offset = sizeof(**result)
		+ dt_rule->dt_match_len * sizeof(struct hipac_match)
		+ exec_match_size;
	
	for (i = 0; i < dt_rule->dt_match_len; i++){
		(*result)->first_match[i].dimid =
			dt_rule->first_dt_match[i].dimid;
		(*result)->first_match[i].invert = 0;
		(*result)->first_match[i].left =
			dt_rule->first_dt_match[i].left;
		(*result)->first_match[i].right =
			dt_rule->first_dt_match[i].right;
	}
	if (dt_rule->exec_match){
		void *pos = (void *) (*result) + (*result)->match_offset;
		for (i = 0; i < dt_rule->exec_match->len; i += 2){ 
			size = dt_rule->exec_match->p[i + 1]
				- dt_rule->exec_match->p[i];
			memcpy(pos, dt_rule->exec_match->p[i], size);
			pos += size;
		}
	}
	if (dt_rule->exec_target_size){
		memcpy((void *) (*result) + (*result)->target_offset, 
		       dt_rule->exec_target, dt_rule->exec_target_size);
	}
	return HE_OK;
}



/* if hipac_rule 'r' contains exec_matches, add a pointer to the beginning
   and a pointer to the end of that exec_matches to the ptrblock '*p'  
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
add_exec_matches(struct ptrblock **p, const struct hipac_rule *r)
{
       	hipac_error error;

	if (unlikely(!p || !r))
		ARG_ERR;

	if (r->match_offset == 0)
		return HE_OK;
	
	if ((error = ptrblock_append(p, (void *) r + r->match_offset))){
		CHECK_ERROR("ptrblock_append");
		return error;
	}
	if ((error = ptrblock_append(p, (void *) r + r->target_offset))){
		CHECK_ERROR("ptrblock_append");
		ptrblock_delete_tail(p);
		return error;
	}
	return HE_OK;
}



/* build new dt_rule from prefix_rule and/or hipac_rule.
   prefix_rule and/or hipac_rule can be NULL.
   pos:      the position of the new dt_rule; is written to result->spec.pos
   action:   the action of the new dt_rule;   is written to result->spec.action
   the exec_matches from prefix and hipac_rule are merged into
   result->exec_match.
   if the hipac_rule contains a exec_target it is written to 
   result->exec_target.
   attention: does NOT copy the native matches, this must be done externally!
              allocs space for prefix->native_mct + rule->native_mct matches!
              when merging the native matches externally, remember to do a
              'hipac_realloc' when prefix and rule contain the same dimids!
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
build_dt_rule(struct prefix_rule *prefix, const struct hipac_rule *rule, 
	      const __u32 pos, const __u32 action, struct dt_rule **result)
{
	hipac_error error;
	struct dt_rule *new_dt_rule;
	__u8 mct = 0;

	if (unlikely(!result))
		ARG_ERR;
	
	if (prefix)
		mct += prefix->native_mct;
	if (rule) 
		mct += rule->native_mct;
	
	new_dt_rule = hp_alloc(dt_rule_size(mct), ADD);
	if (!new_dt_rule)
		LOW_MEM("dt_rule alloc failed!");
	new_dt_rule->spec.rlp = 0;
	new_dt_rule->spec.rtype = RT_RULE;
	new_dt_rule->spec.action = action;
	new_dt_rule->spec.pos = pos;
	new_dt_rule->exec_match = NULL;
	new_dt_rule->exec_target = NULL;
	new_dt_rule->exec_target_size = 0;
	new_dt_rule->deleted = 0;
	
	if (prefix){
		if ((error = ptrblock_clone(prefix->exec_matches, 
					    &new_dt_rule->exec_match))){
			dt_rule_free(new_dt_rule);
			CHECK_ERROR("ptrblock_clone");
			return error;
		}
	}
	if (rule){
		if ((error = add_exec_matches(&new_dt_rule->exec_match,
						  rule))){
			dt_rule_free(new_dt_rule);
			CHECK_ERROR("add_exec_matches");
			return error;
		}
	}
	if (action == TARGET_EXEC){
		new_dt_rule->exec_target = (void *) rule + rule->target_offset;
		new_dt_rule->exec_target_size = ((void *) rule + rule->size)
			- ((void *) rule + rule->target_offset);
	}
	new_dt_rule->dt_match_len = mct;
	*result = new_dt_rule;
	return HE_OK;
}



/* Remove last element from strblock 'paths' and also free the data
   structures that are pointed to from within this element            */
static inline void
paths_delete_tail(struct strblock **paths)
{
	struct prefix_rule *p = P_ELEM_RULE(*paths, (*paths)->len - 1);
	if (p)
		prefix_rule_free(p);
	strblock_delete_tail(paths);
}



/* Remove element with position 'pos' from strblock 'paths' and also free
   the data structures that are pointed to from within this element.  */
static inline void
paths_delete_pos(struct strblock **paths, __u32 pos)
{
	struct prefix_rule *p = P_ELEM_RULE(*paths, pos);
	if (p)
		prefix_rule_free(p);
	strblock_delete_pos(paths, pos);
}


/* count number of negations/inverted matches in hipac_match array    */
static inline __u8
count_inv_matches(const struct hipac_match *first_match, const __u8 match_cnt)
{
	__u8 i, result = 0;
	for (i = 0; i < match_cnt; i++)
		if (first_match[i].invert)
			result++;
	return result;
}	 



/* count number of negations/inverted matches in both rules, but
   without counting matches in the same dimid twice                   */
static inline __u8
count_inv_matches_2(const struct hipac_rule *hipac_rule, 
		    const struct prefix_rule *prefix_rule)
{
	__u8 i, j, result = 0;

	for (i = 0, j = 0; i < prefix_rule->native_mct; i++){
			while ((j < hipac_rule->native_mct)
			       && (hipac_rule->first_match[j].dimid 
				   < prefix_rule->first_match[i].dimid)){
				if (hipac_rule->first_match[j].invert)
					result++;
				j++;
			}
			if ((j < hipac_rule->native_mct)
			    && (hipac_rule->first_match[j].dimid 
				== prefix_rule->first_match[i].dimid)){
				if (hipac_rule->first_match[j].invert)
					result++;
				j++;
				continue;
			}
			if (prefix_rule->first_match[i].invert)
				result++;
	}
	while (j < hipac_rule->native_mct){
		if (hipac_rule->first_match[j].invert)
			result++;	
		j++;
	}	
	return result;
}	 



/* merge hipac_match 's' into dt_match 'new' while keeping negation
   in mind.                                                           */
static inline void
merge_dimension(struct hipac_match *s, struct dt_match *new,
		__u32 inv, __u16 *inv_match, __u8 *not_valid)
{
	if (!(s->invert)){
		new->dimid = s->dimid;
		new->left = s->left;
		new->right = s->right;
		return;
	}
	if (inv & (1 << *inv_match)){
		if (s->right < 
		    MAXKEY(dim2btype[s->dimid])){
			new->dimid = s->dimid;
			new->left = s->right + 1;
			new->right = MAXKEY(dim2btype[s->dimid]);
			(*inv_match)++;
		} else {
			*not_valid = 1;
		}
	} else {
		if (s->left){	
			new->dimid = s->dimid;
			new->left = 0;
			new->right = s->left - 1;
			(*inv_match)++;
		} else {
			*not_valid = 1;
		}
	}
}



/* insert new dt_rule(s) at position 'pos' into dimtree 'path->dimtree'.
   the new dt_rule is created from information found in 'path->rule'
   and 'rule'. if 'path->rule' or 'rule' contain negation solve this by
   adding several new dt_rules to the dimtree. append the (first) new 
   dt_rule to the 'rule->dtr' pointer block.
   if commit is not 0 commit the changes.
   in case of an error undo all changes.
   attention: in case of an error already inserted rules are not removed
              from the internal dimtree chain. those rules have to be
	      removed externally.  
   possible errors: HE_LOW_MEMORY, HE_RULE_ORIGIN_MISMATCH,
                    HE_RULE_PREFIX_MISMATCH, HE_IMPOSSIBLE_CONDITION  */
hipac_error
insert_into_dt(const struct path *path,
	       struct chain_rule *rule,
	       const __u32 pos, const __u8 commit)
{
	struct dt_rule *new_dt_rule;
	hipac_error error;
       	__u32 i, j, inv;
	__u8 first = 1;
	__u8 num;
	struct dt_match *new;
	__u32 mct = 0;
	
	if (unlikely(!path || !path->rule || !rule))
		ARG_ERR;

	num = count_inv_matches_2(&rule->r, path->rule);
	
	mct = rule->r.native_mct + path->rule->native_mct;
	
	if (!(num)){
		__u32 new_mct = 0;
		struct hipac_match *p = path->rule->first_match;
		struct hipac_match *r = rule->r.first_match;
		

		if ((error = build_dt_rule(path->rule, &rule->r, pos, 
					   rule->r.action, &new_dt_rule))){
			CHECK_ERROR("build_dt_rule");
			return error;
		}

		new = new_dt_rule->first_dt_match;

		for (i = 0, j = 0; i < path->rule->native_mct; i++){
			while ((j < rule->r.native_mct)
			       && (r[j].dimid < p[i].dimid)){
				new[new_mct].dimid = r[j].dimid;
				new[new_mct].left = r[j].left;
				new[new_mct].right = r[j].right;
				j++;
				new_mct++;
				
			}
			if ((j < rule->r.native_mct)
			    && (r[j].dimid == p[i].dimid)){
				if (p[i].invert){
					if (!(r[j].right < p[i].left
					      || r[j].left > p[i].right)){
						dt_rule_free(new_dt_rule);
						return HE_RULE_PREFIX_MISMATCH;
					}
				} else if (r[j].left < p[i].left
					   || r[j].right > p[i].right){
					dt_rule_free(new_dt_rule);
					return HE_RULE_PREFIX_MISMATCH;
				}
				new[new_mct].dimid = r[j].dimid;
				new[new_mct].left = r[j].left;
				new[new_mct].right = r[j].right;
				j++;
				new_mct++;
				continue;
			}
			new[new_mct].dimid = p[i].dimid;
			new[new_mct].left = p[i].left;
			new[new_mct].right = p[i].right;
			new_mct++;
		}
		
		while (j < rule->r.native_mct){
			new[new_mct].dimid = r[j].dimid;
			new[new_mct].left = r[j].left;
			new[new_mct].right = r[j].right;
			j++;
			new_mct++;
		}
  	
		if (new_mct < mct){
			new_dt_rule->dt_match_len = new_mct;
			new_dt_rule = hp_realloc(new_dt_rule, 
						 dt_rule_size(new_mct));
			if (!new_dt_rule){
				dt_rule_free(new_dt_rule);
				IMPOSSIBLE_CONDITION("new_dt_rule is NULL");
			}
		}
		
		if ((error = ptrblock_append(&rule->dtr,
					     (void *) new_dt_rule))){
			CHECK_ERROR("ptrblock_append");
			dt_rule_free(new_dt_rule);
			return error;
		}
		if ((error = dimtree_insert(path->dimtree, new_dt_rule,
					    rule->r.origin, INC, commit))){
			CHECK_ERROR("dimtree_insert");
			return error;
		}
		return HE_OK;
	} 
	//else we have a rule containing negation
	
       	for (inv = 0; inv < (1 << num); inv++){
		__u16 j;
		__u8 not_valid = 0;
		__u16 inv_match = 0;
		__u32 new_mct = 0;
		struct hipac_match *p = path->rule->first_match;
		struct hipac_match *r = rule->r.first_match;
	
		if ((error = build_dt_rule(path->rule, &rule->r, pos, 
					   rule->r.action, &new_dt_rule))){
			CHECK_ERROR("build_dt_rule");
			if (!first)
				dimtree_failed(native_dts);
			return error;
		}
		
		new = new_dt_rule->first_dt_match;

		for (i = 0, j = 0; i < path->rule->native_mct; i++){
			while ((j < rule->r.native_mct)
			       && (r[j].dimid < p[i].dimid)){
				merge_dimension(&r[j], &new[new_mct], inv, 
						&inv_match, &not_valid);
				if (not_valid)
					break;
				j++;
				new_mct++;
			}
			if (not_valid)
				break;
			if ((j < rule->r.native_mct)
			    && (r[j].dimid == p[i].dimid)){
				if (!r[j].invert && !p[i].invert){
					if (r[j].left < p[i].left
					    || r[j].right > p[i].right){
						dt_rule_free(new_dt_rule);
						if (!first)
							dimtree_failed(
								native_dts);
						return HE_RULE_PREFIX_MISMATCH;
					}
				} else if (r[j].invert && !p[i].invert){
					dt_rule_free(new_dt_rule);
					if (!first)
						dimtree_failed(native_dts);
					return HE_RULE_PREFIX_MISMATCH;
				} else if (!r[j].invert && p[i].invert){
					if (!(r[j].right < p[i].left
					      || r[j].left > p[i].right)){
						dt_rule_free(new_dt_rule);
						if (!first)
							dimtree_failed(
								native_dts);
						return HE_RULE_PREFIX_MISMATCH;
					}
				} else if(r[j].invert && p[i].invert){
					if (r[j].left > p[i].left
					    || r[j].right < p[i].right){
						dt_rule_free(new_dt_rule);
						if (!first)
							dimtree_failed(
								native_dts);
						return HE_RULE_PREFIX_MISMATCH;
					}
				}

				merge_dimension(&r[j], &new[new_mct], inv, 
						&inv_match, &not_valid);
				if (not_valid)
					break;
				j++;
				new_mct++;
				continue;
				
			}
			merge_dimension(&p[i], &new[new_mct], inv, 
					&inv_match, &not_valid);
			if (not_valid)
				break;
			new_mct++;
		}
		if (not_valid){
			dt_rule_free(new_dt_rule);
			continue;
		}
		while (j < rule->r.native_mct){
			merge_dimension(&r[j], &new[new_mct], inv, 
					&inv_match, &not_valid);
			if (not_valid)
				break;
			j++;
			new_mct++;
		}			
		if (not_valid){
			dt_rule_free(new_dt_rule);
			continue;
		}
		
		if (new_mct < mct){
			new_dt_rule->dt_match_len = new_mct;
			new_dt_rule = hp_realloc(new_dt_rule, 
						 dt_rule_size(new_mct));
			if (!new_dt_rule){
				dt_rule_free(new_dt_rule);
				IMPOSSIBLE_CONDITION("new_dt_rule is NULL");
			}
		}

		if (first){
			if ((error = ptrblock_append(&rule->dtr,
						     (void *) new_dt_rule))){
				CHECK_ERROR("ptrblock_append");
				dt_rule_free(new_dt_rule);
				return error;
			}
		}
		if ((error = dimtree_insert(path->dimtree, new_dt_rule,
					    rule->r.origin, first, 
					    DONT_COMMIT))){
			CHECK_ERROR("dimtree_insert");
			return error;
		}
		if (first)
			first = 0;
	}	
	if (commit)
		dimtree_commit(native_dts);
	return HE_OK;
}	



/* detect loop in hipac_chains.
   if any rule in hipac_chain 'chain' (or recursively in any other
   hipac_chain any rule in 'chain' jumps to) jumps to hipac_chain 'org'
   a loop is detected.
   possible errors: HE_LOOP_DETECTED, HE_REC_LIMIT                    */
hipac_error
detect_loop(const struct hipac_chain *chain, 
	    const struct hipac_chain *org, __u32 depth)
{
	if (unlikely(!chain || !org))
		ARG_ERR;
	
	if (depth > HIPAC_REC_LIMIT)
		return HE_REC_LIMIT;

	if (chain->next_chains){
		__u32 i;
		hipac_error error;
		struct hipac_chain *next;
		for (i = 0; i < chain->next_chains->len; i++){
			next = STRBLOCK_ITH(chain->next_chains, i,
					    struct next_chain_elem *)->chain;
			if (next == org)
				return HE_LOOP_DETECTED;
			if ((error = detect_loop(next, org, depth + 1)))
				return error;
		}
	}
	return HE_OK;
}



/* add new path to the paths block of hipac_chain 'chain'.
   the new path is computed from the path 'path' and the chain_rule 'rule'.
   possible errors: HE_LOW_MEMORY, HE_RULE_PREFIX_MISMATCH, 
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
add_path(struct hipac_chain *chain, const struct path *path,
	 struct chain_rule *rule)
{
	hipac_error error;
	struct path *new_path;
	struct prefix_rule *new_prefix;
	struct hipac_match *r, *p, *new;
	__u8 mct, i, j = 0, new_mct = 0;

	if (!chain || !path || !path->rule || !rule)
		ARG_ERR;
	
	mct = rule->r.native_mct + path->rule->native_mct;
	
	new_prefix = hp_alloc(sizeof(*new_prefix) 
			      + mct * sizeof(struct hipac_match), ADD);
	if (!new_prefix){
		LOW_MEM("new_prefix alloc failed!");
	}
	new_path = hp_alloc(sizeof(*new_path), ADD);
	if (!new_path){
		hp_free(new_prefix);
		LOW_MEM("new_path alloc failed!");
	}

	new_path->dimtree = path->dimtree;
	new_path->prev = rule;
	new_path->rule = new_prefix;
	
	new_prefix->origin = path->rule->origin & rule->r.origin;
	new_prefix->exec_matches = NULL;
	if ((error = ptrblock_clone(path->rule->exec_matches, 
				    &new_prefix->exec_matches))){
		CHECK_ERROR("ptrblock_clone");
		path_free(new_path);
		return error;
	}
	if ((error = add_exec_matches(&new_prefix->exec_matches, 
				      &rule->r))){
		CHECK_ERROR("add_exec_matches");
		path_free(new_path);
		return error;
	}
	r = rule->r.first_match;
	p = path->rule->first_match;
	new = new_prefix->first_match;
	
	for (i = 0; i < path->rule->native_mct; i++){
		while ((j < rule->r.native_mct)
		       && (r[j].dimid < p[i].dimid)){
			new[new_mct].dimid = r[j].dimid;
			new[new_mct].invert = r[j].invert;
			new[new_mct].left = r[j].left;
			new[new_mct].right = r[j].right;
			j++;
			new_mct++;
		}
		if ((j < rule->r.native_mct)
		    && (r[j].dimid == p[i].dimid)){
			if (!r[j].invert && !p[i].invert){
				if (r[j].left < p[i].left
				    || r[j].right > p[i].right){
					path_free(new_path);
					return HE_RULE_PREFIX_MISMATCH;
				}
			} else if (r[j].invert && !p[i].invert){
				path_free(new_path);
				return HE_RULE_PREFIX_MISMATCH;
			} else if (!r[j].invert && p[i].invert){
				if (!(r[j].right < p[i].left
				      || r[j].left > p[i].right)){
					path_free(new_path);
					return HE_RULE_PREFIX_MISMATCH;
				}
			} else if(r[j].invert && p[i].invert){
				if (r[j].left > p[i].left
				    || r[j].right < p[i].right){
					path_free(new_path);
					return HE_RULE_PREFIX_MISMATCH;
				}
			}
			
			new[new_mct].dimid = r[j].dimid;
			new[new_mct].invert = r[j].invert;
			new[new_mct].left = r[j].left;
			new[new_mct].right = r[j].right;
			j++;
			new_mct++;
			continue;
		}
		new[new_mct].dimid = p[i].dimid;
		new[new_mct].invert = p[i].invert;
		new[new_mct].left = p[i].left;
		new[new_mct].right = p[i].right;
		new_mct++;
	}

	while (j < rule->r.native_mct){
		new[new_mct].dimid = r[j].dimid;
		new[new_mct].invert = r[j].invert;
		new[new_mct].left = r[j].left;
		new[new_mct].right = r[j].right;
		j++;
		new_mct++;
	}
	
	if (new_mct < mct){
		new_prefix = hp_realloc(new_prefix, sizeof(*new_prefix)
					+ new_mct
					* sizeof(struct hipac_match));
		if (!new_prefix){
			path_free(new_path);
			IMPOSSIBLE_CONDITION("new_prefix is NULL");
		}
		new_path->rule = new_prefix;
	}

	new_prefix->native_mct = new_mct;
	
	if ((error = strblock_append_check(&chain->paths, new_path, 
					   sizeof(*new_path)))){
		CHECK_ERROR("strblock_append");
		path_free(new_path);
		return error;
	}
	hp_free(new_path);
	return HE_OK;

}



/* add a dt_rule marking the beginning of the hipac_chain 'chain'
   in the internal dimtree chain to 'path->dimtree' and add a pointer
   to that new dt_rule to the 'chain->start' ptrblock.
   the dt_rule is added with TARGET_DUMMY, so that it is not inserted
   into the internal dimtree only into the internal dimtree chain.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
add_chain_start(struct hipac_chain *chain, const struct path *path,
		const __u32 pos)
{
	hipac_error error;
	struct dt_rule *start;

	if ((error = build_dt_rule(NULL, NULL, pos, 
				   TARGET_DUMMY, &start))){
		CHECK_ERROR("build_dt_rule");
		return error;
	}
	if ((error = ptrblock_append(&chain->start, start))){
		CHECK_ERROR("ptrblock_append");
		dt_rule_free(start);
		return error;
	}
	if ((error = dimtree_insert(path->dimtree, start, 
				    ORIGIN_ALL, INC, DONT_COMMIT))){
		CHECK_ERROR("dimtree_insert");
		ptrblock_delete_tail(&chain->start);
		dt_rule_free(start);
		return error;
	}
	return HE_OK;
}



/* add a dt_rule marking the end of the hipac_chain 'chain'
   in the internal dimtree chain to 'path->dimtree' and add a pointer
   to that new dt_rule to the 'chain->end' ptrblock.
   the dt_rule added to the internal dimtree corresponds to 'path->rule'.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
hipac_error
add_chain_end(struct hipac_chain *chain, struct path *path,
	      const __u32 pos)
{
	struct dt_rule *new_dt_rule;
	hipac_error error;
       	__u32 i;
	__u8 first = 1;
	__u8 num;
     	struct hipac_match *old;
	struct dt_match *new;
		
		
	num = count_inv_matches((struct hipac_match *) path->rule->first_match,
				path->rule->native_mct);

	if (!(num)){
		if ((error = build_dt_rule(path->rule, NULL, pos, 
					   TARGET_NONE, &new_dt_rule))){
			CHECK_ERROR("build_dt_rule");
			return error;
		}
		for (i = 0; i < path->rule->native_mct; i++){
			new_dt_rule->first_dt_match[i].dimid = 
				path->rule->first_match[i].dimid;
			new_dt_rule->first_dt_match[i].left = 
				path->rule->first_match[i].left;
			new_dt_rule->first_dt_match[i].right = 
				path->rule->first_match[i].right;
		}
		if ((error = ptrblock_append(&chain->end,
					     (void *) new_dt_rule))){
			CHECK_ERROR("ptrblock_append");
			dt_rule_free(new_dt_rule);
			return error;
		}
		if ((error = dimtree_insert(path->dimtree, new_dt_rule, 
					    ORIGIN_ALL, INC, DONT_COMMIT))){
			CHECK_ERROR("dimtree_insert");
			return error;
		}
		return HE_OK;
	} 
	//else we have a rule containing negation
	
       	for (i = 0; i < (1 << num); i++){
		__u16 j;
		__u8 not_valid = 0;
		__u16 inv_match = 0;
	
	
		if ((error = build_dt_rule(path->rule, NULL, pos, 
					   TARGET_NONE, &new_dt_rule))){
			CHECK_ERROR("build_dt_rule");
			if (!first)
				dimtree_failed(native_dts);
			return error;
		}
		old = path->rule->first_match;
		new = new_dt_rule->first_dt_match;
		for (j = 0; j < path->rule->native_mct; j++){
			if (!(old[j].invert)){
				new[j].dimid = old[j].dimid;
				new[j].left = old[j].left;
				new[j].right = old[j].right;
				continue;
			}
			if (i & (1 << inv_match)){
				if (old[j].right < 
				    MAXKEY(dim2btype[old[j].dimid])){
					new[j].dimid = old[j].dimid;
					new[j].left = old[j].right + 1;
					new[j].right = 
						MAXKEY(dim2btype[new[j].dimid]);
				} else {
					not_valid = 1;
					break;
				}
			} else {
				if (old[j].left){
					new[j].dimid = old[j].dimid;
					new[j].left = 0;
					new[j].right = old[j].left - 1;
				} else {
					not_valid = 1;
					break;
				}
			}
			inv_match++;
		}
		if (not_valid){
			dt_rule_free(new_dt_rule);
			continue;
		}	
		if (first){
			if ((error = ptrblock_append(&chain->end,
						     (void *) new_dt_rule))){
				CHECK_ERROR("ptrblock_append");
				dt_rule_free(new_dt_rule);
				return error;
			}
		}
		if ((error = dimtree_insert(path->dimtree, new_dt_rule,
					    ORIGIN_ALL, first, DONT_COMMIT))){
			CHECK_ERROR("dimtree_insert");
			return error;
		}
		if (first)
			first = 0;
	}
	return HE_OK;
}



/* add hipac_chain 'to' to the next_chain block of hipac_chain 'from'.
   if 'from' already contains a reference to hipac_chain 'to' then the
   corresponding count field is incremented by 1, otherwise a new
   next_chain_elem with its count field set to 1 is added to the
   next_chain block.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
add_next_chain(struct hipac_chain *from, struct hipac_chain *to)
{
	hipac_error error;
	struct next_chain_elem *nc;

	if (from->next_chains){
		__u32 i;
		for (i = 0; i < from->next_chains->len; i++){
			nc = STRBLOCK_ITH(from->next_chains, i,
					  struct next_chain_elem *);
			if (nc->chain == to){
				nc->count++;
				return HE_OK;
			}
		}
	}

	nc = hp_alloc(sizeof(*nc), ADD);
	if (!nc)
		LOW_MEM("next_chain alloc failed!");
	nc->count = 1;
	nc->chain = to;
	error = strblock_append_check(&from->next_chains, nc, sizeof(*nc));
	hp_free(nc);
	CHECK_ERROR("strblock_append");
     	return error;
}



/* remove one reference to hipac_chain 'to' from the next_chain block
   of hipac_chain 'from'.                                             */
static inline void
delete_next_chain(struct hipac_chain *from, const struct hipac_chain *to)
{
     	struct next_chain_elem *nc;
	
	if (from->next_chains){
		__u32 i;
		for (i = 0; i < from->next_chains->len; i++){
			nc = STRBLOCK_ITH(from->next_chains, i,
					  struct next_chain_elem *);
			if (nc->chain == to){
				if (nc->count > 1){
					nc->count--;
				} else {
					strblock_delete_pos(&from->next_chains,
							    i);
				}
				break;
			}
		}
	}
}



/* recursively insert jump rule 'rule' into hipac data structures
   and dimtrees. in case of an error changes must be undone 
   externally via delete_jump_from_hipac_layer(),
   delete_dt_rules_from_dt_chains() and dimtree_chain_fix().
   attention: in case of an success does NOT commit the changes.
              don't forget to eventually commit the modifications
	      externally via dimtree_commit().
   possible errors: HE_LOW_MEMORY, HE_LOOP_DETECTED, HE_REC_LIMIT,
                    HE_RULE_ORIGIN_MISMATCH, HE_RULE_RREFIX_MISMATCH,
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
insert_jump_rec(const struct hipac_chain *org, const struct ptrblock *next,
		const struct path *path, const __u32 ins_num,
		struct chain_rule *rule, __u32 depth)
{
	hipac_error error;
	struct list_head *lh;
	struct chain_rule *currule;
	struct path *new_path;
	struct hipac_chain *chain = NULL;
	__u32 i;
       
	if (depth > HIPAC_REC_LIMIT)
		return HE_REC_LIMIT;

	chain_hash_lookup((void *) &rule->r + rule->r.target_offset, &chain);
		
	if (org == chain)
		return HE_LOOP_DETECTED;
	
	for (i = 0; i < ins_num; i++){
		if ((error = add_path(chain, path + i, rule))){
			CHECK_ERROR("add_path");
			for (; i > 0; i--){
				paths_delete_tail(&chain->paths);
				ptrblock_delete_tail(&chain->start);
			}
			return error;
		}
		if ((error = add_chain_start(chain, 
					     P_ELEM(chain->paths,
						    chain->paths->len - 1),
					     ((struct dt_rule *)
					      next->p[i])->spec.pos))){
			CHECK_ERROR("add_chain_start");
			paths_delete_tail(&chain->paths);
			for (; i > 0; i--){
				paths_delete_tail(&chain->paths);
				ptrblock_delete_tail(&chain->start);
			}
			return error;
		}
	}

	new_path = P_ELEM(chain->paths, chain->paths->len - ins_num);
		
	list_for_each(lh, &chain->head){
		currule = list_entry(lh, struct chain_rule, head);
		if (IS_JUMP_RULE(currule)){
			if ((error = insert_jump_rec(org, next,
						     new_path, ins_num,
						     currule, depth + 1))){
				CHECK_ERROR("insert_jump_rec");
				return error;
			}
		} else for (i = 0; i < ins_num; i++){
				if ((error = insert_into_dt(new_path + i, currule,
							    ((struct dt_rule *)
							     next->p[i])->spec.pos, 
							    DONT_COMMIT))){
					CHECK_ERROR("insert_into_dt");
					return error;
				}
		}
	}   
	for (i = 0; i < ins_num; i++){
		if ((error = add_chain_end(chain, new_path + i, 
					   ((struct dt_rule *) 
					    next->p[i])->spec.pos))){
			CHECK_ERROR("add_chain_end");
			return error;
		}
	}
		
	return HE_OK;
}	



/* delete all entries in the hipac layer data structures corresponding to
   jump rule 'rule'. all entries in hipac_chain path, start and end blocks
   pointing to dt_rules with positions > prev and < next are deleted.
   attention: be sure that those rules have been deleted from the dimtrees
              before and that those changes have been commited. there must NOT
	      be any intervall in any dimtree anymore pointing to one of those
	      rules! BUT the corresponding dt_rules must NOT yet have been
	      deleted from the internal dimtree chains!               */
static void
delete_jump_from_hipac_layer(const struct hipac_chain *org,
			     const struct ptrblock *prev, 
			     const struct ptrblock *next,
			     const struct chain_rule *rule)
{
	struct list_head *lh;
	struct hipac_chain *chain = NULL;
	struct chain_rule *currule;
	__u32 i, j , finished = 0, del_num = 0;
	
	chain_hash_lookup((void *) &rule->r + rule->r.target_offset, 
			  &chain);
	
	if (!chain->start)
		return;
	
	for (i = chain->start->len; i > 0; i--){
		for (j = 0; j < prev->len; j++){
			if (!chain->paths){
				finished = 1;
				break;
			}
			if ((P_ELEM_DIMTREE(chain->paths, i - 1)
			     == P_ELEM_DIMTREE(org->paths, j))
			    && (((struct dt_rule *)
				 chain->start->p[i - 1])->spec.pos
				> ((struct dt_rule *) prev->p[j])->spec.pos)
			    && (((struct dt_rule *) 
				 chain->start->p[i - 1])->spec.pos
				< ((struct dt_rule *) next->p[j])->spec.pos)){
				
				chain->start->p[i - 1] = NULL;
				paths_delete_pos(&chain->paths, i - 1);
				del_num++;
				break;
			}
		}
		if (finished)
			break;
	}

	if (!del_num)
		return;
	
	ptrblock_delete_multi(&chain->end, chain->start);
		
	list_for_each(lh, &chain->head){
		currule = list_entry(lh, 
				     struct chain_rule, head);
		if (IS_JUMP_RULE(currule)){
			delete_jump_from_hipac_layer(org, prev, next, currule);
		} else {
			if (!currule->dtr)
				break;
			if (chain->end
			    && chain->end->len == currule->dtr->len)
				break;
			ptrblock_delete_multi(&currule->dtr, chain->start);
		}
	}		
	
	for (i = chain->start->len; i > 0; i--){
		if (!chain->start->p[i - 1])
			ptrblock_delete_pos(&chain->start, i - 1);
	}
}							   
							   

      
/* delete all dt_rules between prev and next from the internal dimtrees.
   all rules with positions > prev and < next are deleted.
   in case of an error undo all made changes.
   attention: does NOT commit the changes. don't forget to eventually commit
              the modifications externally via dimtree_commit().
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
delete_dt_rules_from_dimtrees(const struct hipac_chain *chain,
			      const struct ptrblock *prev,
			      const struct ptrblock *next)
{
	hipac_error error;
	__u32 i;
	struct dt_rule *rule;
	
	if (!chain || !prev || !next)
		ARG_ERR;
	
	for (i = 0; i < prev->len; i++){
		rule = list_entry(((struct dt_rule *) prev->p[i])->head.next, 
				  struct dt_rule, head);
		
		while (rule->spec.pos == 
		       ((struct dt_rule *) prev->p[i])->spec.pos){
			rule = list_entry(rule->head.next, 
					  struct dt_rule, head);
		}
		while (rule != ((struct dt_rule *) next->p[i])){
			if ((error = dimtree_delete(P_ELEM_DIMTREE(chain->paths,
								   i),
						    rule, DONT_COMMIT))){
				CHECK_ERROR("dimtree_delete");
				return error;
			}
			rule = list_entry(rule->head.next,
					  struct dt_rule, head);
		}
	}
	return HE_OK;
}



/* delete all dt_rules between prev and next from the internal dimtree chains.
   all rules with positions > prev and < next are deleted.
   attention: be sure that those rules have been deleted from the dimtrees
              before and that those changes have been commited. there must NOT
	      be any intervall in any dimtree anymore pointing to one of those
	      rules!                                                  */
static inline void
delete_dt_rules_from_dt_chains(const struct hipac_chain *chain,
			       const struct ptrblock *prev,
			       const struct ptrblock *next)
{
	__u32 i, end_pos;
	struct dt_rule *start;
	
	if (!chain || !prev || !next)
		ARG_MSG;
	
	for (i = 0; i < prev->len; i++){
		end_pos = ((struct dt_rule *) next->p[i])->spec.pos - 1;
		if (((struct dt_rule *) prev->p[i])->spec.pos == end_pos){
			continue;
		}
		start = list_entry(((struct dt_rule *) prev->p[i])->head.next, 
				   struct dt_rule, head);
		while (start->spec.pos == 
		       ((struct dt_rule *) prev->p[i])->spec.pos){
			start = list_entry(start->head.next, 
					   struct dt_rule, head);
		}
		dimtree_chain_delete(P_ELEM_DIMTREE(chain->paths, i), start, 
				     end_pos);
	}
}



/* insert chain_rule 'rule' into hipac_chain 'chain' and 
   commit the changes. in case of an error undo all made changes.
   possible errors: HE_LOW_MEMORY, HE_LOOP_DETECTED, HE_REC_LIMIT,
                    HE_RULE_ORIGIN_MISMATCH, HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_IS_NATIVE, 
		    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_IMPOSSIBLE_CONDITION                           */
static inline hipac_error
insert(struct hipac_chain *chain, struct chain_rule *rule)
{
     	hipac_error error;
	struct ptrblock *prev, *next;
	__u8 prev_free, next_free;
	
	if (CHAIN_NOT_CONNECTED(chain)){
		if (IS_JUMP_RULE(rule)){
			struct hipac_chain *target_chain;
			if ((error = chain_hash_lookup((void *) &rule->r 
						       + rule->r.target_offset,
						       &target_chain))){
				chain_rule_free(rule);
				return HE_TARGET_CHAIN_NOT_EXISTENT;
			}
			if (target_chain == chain){
				chain_rule_free(rule);
				return HE_LOOP_DETECTED;
			}
			if (IS_ROOT_CHAIN(target_chain)){
				chain_rule_free(rule);
				return HE_TARGET_CHAIN_IS_NATIVE;
			}
			if ((error = detect_loop(target_chain, chain, 1))){
				chain_rule_free(rule);
				return error;
			}
			if ((error = add_next_chain(chain, target_chain))){
				chain_rule_free(rule);
				return error;
			}
			target_chain->ref_count++;
		}
		chain_insert(chain, rule, INC);
		return HE_OK;
	}

	chain_insert(chain, rule, INC);
	if ((error = get_prev_dt_rules(chain, rule, &prev_free, &prev))){
		CHECK_ERROR("get_prev_dt_rules");
		chain_delete(chain, rule->r.pos);
		chain_rule_free(rule);
		return error;
	}
	if ((error = get_next_dt_rules(chain, rule, &next_free, &next))){
		CHECK_ERROR("get_next_dt_rules");
		chain_delete(chain, rule->r.pos);
		chain_rule_free(rule);
		if (prev_free)
			ptrblock_free(prev);
		return error;
	}


	if (likely(IS_NOT_JUMP_RULE(rule))){
		__u32 i;
		__u8 commit = DONT_COMMIT;
		if (next->len == 1)
			commit = COMMIT;
		for (i = 0; i < next->len; i++){
			if ((error = 
			     insert_into_dt(P_ELEM(chain->paths, i), rule,
					    ((struct dt_rule *) 
					     next->p[i])->spec.pos, commit))){
				CHECK_ERROR("insert_into_dt");
				dimtree_failed(native_dts);
				delete_dt_rules_from_dt_chains(chain, 
							       prev, next);
				dimtree_chain_fix(native_dts);
				chain_delete(chain, rule->r.pos);
				chain_rule_free(rule);
				if (prev_free)
					ptrblock_free(prev);
				if (next_free)
					ptrblock_free(next);
				return error;
			}
		}
		if (!commit)
			dimtree_commit(native_dts);
	} else {
		struct hipac_chain *target_chain;
		if ((error = chain_hash_lookup((void *) &rule->r 
					       + rule->r.target_offset,
					       &target_chain))){
			CHECK_ERROR("chain_hash_lookup");
			chain_delete(chain, rule->r.pos);
			chain_rule_free(rule);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return HE_TARGET_CHAIN_NOT_EXISTENT;
		}
		if (target_chain == chain){
			chain_delete(chain, rule->r.pos);
			chain_rule_free(rule);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return HE_LOOP_DETECTED;
		}
		if (IS_ROOT_CHAIN(target_chain)){
			chain_delete(chain, rule->r.pos);
			chain_rule_free(rule);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return HE_TARGET_CHAIN_IS_NATIVE;
		}
		if ((error = add_next_chain(chain, target_chain))){
			CHECK_ERROR("add_next_chain");
			chain_delete(chain, rule->r.pos);
			chain_rule_free(rule);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return error;
		}
		if ((error = insert_jump_rec(chain, next, 
					     P_ELEM(chain->paths, 0),
					     chain->paths->len, rule, 1))){
			CHECK_ERROR("insert_jump_rec");
			dimtree_failed(native_dts);
			delete_jump_from_hipac_layer(chain, prev, next, rule);
			delete_dt_rules_from_dt_chains(chain, prev, next);
			dimtree_chain_fix(native_dts);
			delete_next_chain(chain, target_chain);
			chain_delete(chain, rule->r.pos);
			chain_rule_free(rule);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return error;
		}
		dimtree_commit(native_dts);
		target_chain->ref_count++;
	}
      	if (prev_free)
		ptrblock_free(prev);
	if (next_free)
		ptrblock_free(next);
	return HE_OK;
}



/* delete chain_rule 'rule' from hipac_chain 'chain' and commit
   the changes. all representations of that rule in the internal 
   dimtrees are removed. 
   in case of an error undo all made changes.
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION            */
static inline hipac_error
delete(struct hipac_chain* chain, struct chain_rule* rule)
{
	hipac_error error;
	__u8 inv;
	
	if (unlikely(CHAIN_NOT_CONNECTED(chain))){
		if (unlikely(IS_JUMP_RULE(rule))){
			struct hipac_chain *target_chain = NULL;
			chain_hash_lookup((void *) &rule->r 
					  + rule->r.target_offset,
					  &target_chain);
			delete_next_chain(chain, target_chain);
			target_chain->ref_count--;
		}
		chain_delete(chain, rule->r.pos);
		chain_rule_destroy(rule);
		return HE_OK;
	}
	
	inv = count_inv_matches(rule->r.first_match, 
				rule->r.native_mct);
	
	if (likely(!inv && IS_NOT_JUMP_RULE(rule))){
      		__u32 i;
		__u8 commit = 0;
		if (rule->dtr->len == 1){
			commit = 1;
		}
		for (i = 0; i < rule->dtr->len; i++){
			if ((error = 
			     dimtree_delete(P_ELEM_DIMTREE(chain->paths, i),
					    (struct dt_rule *) rule->dtr->p[i],
					    commit))){
				CHECK_ERROR("dimtree_delete");
				if (!commit)
					dimtree_failed(native_dts);
				return error;
			}
		}
		if (!commit)
			dimtree_commit(native_dts);
		for (i = 0; i < rule->dtr->len; i++){
			dimtree_chain_delete(P_ELEM_DIMTREE(chain->paths, i),
					     (struct dt_rule *) rule->dtr->p[i],
					     ((struct dt_rule *) 
					      rule->dtr->p[i])->spec.pos);
		}
	} else {
		struct ptrblock *prev, *next;
		__u8 prev_free, next_free;
		
		if ((error = get_prev_dt_rules(chain, rule, 
					       &prev_free, &prev))){
			CHECK_ERROR("get_prev_dt_rules");
			return error;
		}
		if ((error = get_next_dt_rules(chain, rule, 
					       &next_free, &next))){
			CHECK_ERROR("get_next_dt_rules");
			if (prev_free)
				ptrblock_free(prev);
			return error;
		}
		if ((error = delete_dt_rules_from_dimtrees(chain, 
							   prev, next))){
			CHECK_ERROR("delete_dt_rules_from_dimtrees");
			dimtree_failed(native_dts);
			if (prev_free)
				ptrblock_free(prev);
			if (next_free)
				ptrblock_free(next);
			return error;
		}
		dimtree_commit(native_dts);
		if (unlikely(IS_JUMP_RULE(rule))){
			struct hipac_chain *target_chain = NULL;
			chain_hash_lookup((void *) &rule->r + rule->r.target_offset,
					  &target_chain);
			delete_next_chain(chain, target_chain);
			target_chain->ref_count--;
			delete_jump_from_hipac_layer(chain, prev, next, rule);
		}
		delete_dt_rules_from_dt_chains(chain, prev, next);
		if (prev_free)
			ptrblock_free(prev);
		if (next_free)
			ptrblock_free(next);
	}
	dimtree_chain_fix(native_dts);
	chain_delete(chain, rule->r.pos);
	chain_rule_destroy(rule);
	return HE_OK;
}



/* replace chain_rule 'old_rule' in hipac_chain 'chain' with 
   chain_rule 'new_rule' and commit the changes.
   in case of an error undo all made changes.
   possible errors: HE_LOW_MEMORY, HE_LOOP_DETECTED, HE_REC_LIMIT,
                    HE_RULE_ORIGIN_MISMATCH, HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_IS_NATIVE,
                    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_IMPOSSIBLE_CONDITION                           */
static inline hipac_error
replace(struct hipac_chain *chain, struct chain_rule *old_rule,
	struct chain_rule *new_rule)
{
     	hipac_error error;
	struct ptrblock *prev_old, *prev_new, *next_old, *next_new;
	__u8 prev_free_old, prev_free_new, next_free_old, next_free_new;
	struct hipac_chain *target_chain = NULL;
	
	if (CHAIN_NOT_CONNECTED(chain)){
		if (IS_JUMP_RULE(new_rule)){
			if ((error = 
			     chain_hash_lookup((void *) &new_rule->r 
					       + new_rule->r.target_offset,
					       &target_chain))){
				chain_rule_free(new_rule);
				return HE_TARGET_CHAIN_NOT_EXISTENT;
			}
			if (target_chain == chain){
				chain_rule_free(new_rule);
				return HE_LOOP_DETECTED;
			}
			if (IS_ROOT_CHAIN(target_chain)){
				chain_rule_free(new_rule);
				return HE_TARGET_CHAIN_IS_NATIVE;
			}
			if ((error = detect_loop(target_chain, chain, 1))){
				chain_rule_free(new_rule);
				return error;
			}
			if ((error = add_next_chain(chain, target_chain))){
				chain_rule_free(new_rule);
				return error;
			}
			target_chain->ref_count++;
		}
		if (IS_JUMP_RULE(old_rule)){
			chain_hash_lookup((void *) &old_rule->r 
					  + old_rule->r.target_offset,
					  &target_chain);
			delete_next_chain(chain, target_chain);
			target_chain->ref_count--;
		}
		chain_delete(chain, old_rule->r.pos);
		chain_rule_destroy(old_rule);
		chain_insert(chain, new_rule, INC);
		return HE_OK;
	}

	if ((error = get_prev_dt_rules(chain, old_rule, 
				       &prev_free_new, &prev_new))){
		CHECK_ERROR("get_prev_dt_rules");
		chain_rule_free(new_rule);
		return error;
	}
	if ((error = get_next_dt_rules(chain, old_rule, 
				       &next_free_old, &next_old))){
		CHECK_ERROR("get_next_dt_rules");
		chain_rule_free(new_rule);
		if (prev_free_new)
			ptrblock_free(prev_new);
		return error;
	}
	if ((error = delete_dt_rules_from_dimtrees(chain, 
						   prev_new, next_old))){
		CHECK_ERROR("delete_dt_rules_from_dimtrees");
		dimtree_failed(native_dts);
		chain_rule_free(new_rule);
		if (prev_free_new)
			ptrblock_free(prev_new);
		if (next_free_old)
			ptrblock_free(next_old);
		return error;
	}
	
	chain_insert(chain, new_rule, INC);
	
	if ((error = get_next_dt_rules(chain, new_rule, 
				       &next_free_new, &next_new))){
		CHECK_ERROR("get_next_dt_rules");
		chain_delete(chain, new_rule->r.pos);
		chain_rule_free(new_rule);
		dimtree_failed(native_dts);
		if (prev_free_new)
			ptrblock_free(prev_new);
		if (next_free_old)
			ptrblock_free(next_old);
		return error;
	}	

	if (likely(IS_NOT_JUMP_RULE(new_rule))){
		__u32 i;
		for (i = 0; i < next_new->len; i++){
			if ((error = insert_into_dt(P_ELEM(chain->paths, i),
						    new_rule, 
						    ((struct dt_rule *)
						     next_new->p[i])->spec.pos, 
						    DONT_COMMIT))){
				CHECK_ERROR("insert_into_dt");
				dimtree_failed(native_dts);
				delete_dt_rules_from_dt_chains(chain, 
							       prev_new, 
							       next_new);
				dimtree_chain_fix(native_dts);
				chain_delete(chain, new_rule->r.pos);
				chain_rule_free(new_rule);
				if (prev_free_new)
					ptrblock_free(prev_new);
				if (next_free_old)
					ptrblock_free(next_old);
				if (next_free_new)
					ptrblock_free(next_new);
				return error;
			}
		}
		if ((error = get_prev_dt_rules(chain, old_rule, 
				       &prev_free_old, &prev_old))){
			CHECK_ERROR("get_prev_dt_rules");
			dimtree_failed(native_dts);
			delete_dt_rules_from_dt_chains(chain, prev_new, 
						       next_new);
			dimtree_chain_fix(native_dts);
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return error;
		}
	} else {
		if ((error = chain_hash_lookup((void *) &new_rule->r 
					       + new_rule->r.target_offset,
					       &target_chain))){
			CHECK_ERROR("chain_hash_lookup");
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			dimtree_failed(native_dts);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return HE_TARGET_CHAIN_NOT_EXISTENT;
		}
		if (target_chain == chain){
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			dimtree_failed(native_dts);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return HE_LOOP_DETECTED;
		}
		if (IS_ROOT_CHAIN(target_chain)){
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			dimtree_failed(native_dts);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return HE_TARGET_CHAIN_IS_NATIVE;
		}
		if ((error = add_next_chain(chain, target_chain))){
			CHECK_ERROR("add_next_chain");
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			dimtree_failed(native_dts);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return error;
		}
		if ((error = insert_jump_rec(chain, next_new, 
					     P_ELEM(chain->paths, 0),
					     chain->paths->len, new_rule, 1))){
			CHECK_ERROR("insert_jump_rec");
			dimtree_failed(native_dts);
			delete_jump_from_hipac_layer(chain, prev_new, 
						     next_new, new_rule);
			delete_dt_rules_from_dt_chains(chain, prev_new, 
						       next_new);
			dimtree_chain_fix(native_dts);
			delete_next_chain(chain, target_chain);
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return error;
		}
		if ((error = get_prev_dt_rules(chain, old_rule, 
					       &prev_free_old, &prev_old))){
			CHECK_ERROR("get_prev_dt_rules");
			dimtree_failed(native_dts);
			delete_jump_from_hipac_layer(chain, prev_new, 
						     next_new, new_rule);
			delete_dt_rules_from_dt_chains(chain, prev_new, 
						       next_new);
			dimtree_chain_fix(native_dts);
			delete_next_chain(chain, target_chain);
			chain_delete(chain, new_rule->r.pos);
			chain_rule_free(new_rule);
			if (prev_free_new)
				ptrblock_free(prev_new);
			if (next_free_old)
				ptrblock_free(next_old);
			if (next_free_new)
				ptrblock_free(next_new);
			return error;
		}
		target_chain->ref_count++;
	}
	dimtree_commit(native_dts);
	
	if (likely(IS_JUMP_RULE(old_rule))){
		chain_hash_lookup((void *) &old_rule->r 
				  + old_rule->r.target_offset,
				  &target_chain);
		delete_next_chain(chain, target_chain);
		target_chain->ref_count--;
		delete_jump_from_hipac_layer(chain, prev_old, next_old, 
					     old_rule);
	}
	delete_dt_rules_from_dt_chains(chain, prev_old, next_old);
	dimtree_chain_fix(native_dts);
	chain_delete(chain, old_rule->r.pos);
	chain_rule_destroy(old_rule);
	if (prev_free_old)
		ptrblock_free(prev_old);
	if (prev_free_new)
		ptrblock_free(prev_new);
	if (next_free_old)
		ptrblock_free(next_old);
	if (next_free_new)
		ptrblock_free(next_new);
	return HE_OK;
}





/*
 * hipac_* functions
 */


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
	   const __u64 maxmem)
{
        
	if (unlikely(!dimid_to_bittype || !extract || !copycon || !destroy ||
		     !match || !target || !eq ))
	ARG_ERR;
	
	mem_max = maxmem;
	d2blen = len;
	current_chain = NULL;
	chain_hash = NULL;
	native_dts = NULL;
	dim2btype = hp_alloc(len, ADD);
	if (!dim2btype)
		LOW_MEM("dim2btype alloc failed!");
	extract_fn = hp_alloc(len * sizeof(void *), ADD);
	if (!extract_fn){
		hp_free(dim2btype);
		LOW_MEM("extract_fn alloc failed!");
	}
	chain_hash = ihash_new(CHAIN_HASH_LEN, ADD, CHAIN_HASH_AVR_BUCKET,
			       ihash_func_str, eq_str);
	if (!chain_hash){
		hp_free(dim2btype);
		hp_free(extract_fn);
		LOW_MEM("ihash_new failed!");
	}
	memcpy(dim2btype, dimid_to_bittype, len);
	memcpy(extract_fn, extract, len * sizeof(void *));
	copy_fn = copycon;
	destroy_fn = destroy;
	match_fn = match;
	target_fn = target;
	eq_fn = eq;
	return HE_OK;
}



/* free all hipac data structures;
   MUST be called once in the end
   attention: make sure there are no external accesses to hipac
              data structures taking place anymore!                   */
void
hipac_exit(void)
{
	if (native_dts){
		__u8 i;
		for(i = 0; i < native_dts->len; i++){
			dimtree_free((struct dimtree*) native_dts->p[i]);
		}
		ptrblock_free(native_dts);
	} 
	hp_free(dim2btype);
	hp_free(extract_fn);
	IHASH_VAL_ITERATE(chain_hash, struct hipac_chain *, chain_free);
	ihash_free(chain_hash);
	hp_mem_exit();
}



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
	  const __u32 origin, void **hipac)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct dt_rule *start, *end;
	struct prefix_rule *prefix_rule;
	struct path *new_path;
	__u32 i, j, list_pos = 0;

	if (unlikely(!name || !name_intern || !hipac))
		ARG_ERR;

	for (i = 0; i < chain_hash->len; i++) {
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			struct hipac_chain *c;
			c = chain_hash->bucket[i]->kv[j].val;
			if (c->dimtree && list_pos <= c->list_pos) {
				list_pos = c->list_pos + 1;
			}
		}
	}
	
	if (native_dts){
		__u32 i = 0;
		for (i = 0; i < native_dts->len; i++)
			if (!strcmp(((struct dimtree *)native_dts->p[i])
				    ->chain->name, name_intern))
				return HE_NATIVE_CHAIN_EXISTS;
	}

	if ((error = chain_new(name, &chain, list_pos))){
		CHECK_ERROR("chain_new");
		return error;
	}

	if ((error = build_dt_rule(NULL, NULL, 0, TARGET_DUMMY, &start))){
		CHECK_ERROR("build_dt_rule");
		chain_free(chain);
		return error;
	}

	if ((error = ptrblock_append(&chain->start, start))){
		CHECK_ERROR("ptrblock_append");
		chain_free(chain);
		dt_rule_free(start);
		return error;
	}
	if ((error = build_dt_rule(NULL, NULL, 1, policy, &end))){
		CHECK_ERROR("build_dt_rule");
		chain_free(chain);
		dt_rule_free(start);
		return error;
	}
	
        if ((error = ptrblock_append(&chain->end, end))){
		CHECK_ERROR("ptrblock_append");
		chain_free(chain);
		dt_rule_free(start);
		dt_rule_free(end);
		return error;
	}
	if ((error = dimtree_new((struct dimtree **)hipac, 
				 origin, name_intern,
				 start, end))){
		CHECK_ERROR("dimtree_new");
		chain_free(chain);
		dt_rule_free(start);
		dt_rule_free(end);
		return error;
	}

	if ((error = ptrblock_append(&native_dts, 
				     *(struct dimtree**) hipac))){
		CHECK_ERROR("ptrblock_append");
		dimtree_free(*(struct dimtree**) hipac);
		chain_free(chain);
		return error;
	}

	prefix_rule = hp_alloc(sizeof(*prefix_rule), ADD);
	if (!prefix_rule){
		dimtree_free(*(struct dimtree**) hipac);
		chain_free(chain);
		ptrblock_delete_tail(&native_dts);
		LOW_MEM("prefix rule alloc failed");
	}
	new_path = hp_alloc(sizeof(*new_path), ADD);
	if (!new_path){
		hp_free(prefix_rule);
		dimtree_free(*(struct dimtree**) hipac);
		chain_free(chain);
		ptrblock_delete_tail(&native_dts);
		LOW_MEM("new_path alloc failed");
	}
	new_path->dimtree = *(struct dimtree**) hipac;
	new_path->prev = NULL;
	new_path->rule = prefix_rule;
	prefix_rule->origin = ORIGIN_ALL;
	prefix_rule->exec_matches = NULL;
	prefix_rule->native_mct = 0;
	if ((error = strblock_append_check(&chain->paths, new_path, 
					   sizeof(*new_path)))){
		CHECK_ERROR("strblock_append");
		path_free(new_path);
		dimtree_free(*(struct dimtree**) hipac);
		chain_free(chain);
		ptrblock_delete_tail(&native_dts);
		return error;
	}
	hp_free(new_path);

	if ((error = chain_hash_insert(chain))){
		CHECK_ERROR("chain_hash_insert");
		chain_free(chain);
		dimtree_free(*(struct dimtree**) hipac);
		ptrblock_delete_tail(&native_dts);
		return error;
	}
	chain->dimtree = *(struct dimtree**) hipac;
	return HE_OK;
}



/* set maximum amount of memory the hipac data structures are 
   allowed to occupy. return LOW_MEMORY if 'mem' is lower than
   currently allocated memory
   possible errors: HE_LOW_MEMORY                                     */  
hipac_error
hipac_set_maxmem(const __u64 mem)
{
	if (mem_current_real > mem){
		LOW_MEM();
	}
	mem_max = mem;
	return HE_OK;
}



/* get maximum amount of memory the hipac data structures are 
   allowed to occupy.                                                 */  
__u64
hipac_get_maxmem(void)
{
	return mem_max;
}



/* set policy of chain with name 'name' to 'policy'.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_USERDEFINED,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_set_policy(const char *name, const __u8 policy)
{
	hipac_error error;
	struct hipac_chain *chain;
	
        if (unlikely(!name))
		ARG_ERR;
	if ((error = chain_hash_lookup(name, &chain))){
		CHECK_ERROR("chain_hash_lookup");
		return error;
	}
	if (!chain->dimtree)
		return HE_CHAIN_IS_USERDEFINED;
	((struct dt_rule *)(chain->end->p[0]))->spec.action = policy;
	return HE_OK;
}



/* get policy of chain with name 'name' and write it to 'result'.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_USERDEFINED,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_policy(const char *name, __u8 *result)
{
	hipac_error error;
	struct hipac_chain *chain;
	
	if (unlikely(!name || !result))
		ARG_ERR;
	if ((error = chain_hash_lookup(name, &chain))){
		CHECK_ERROR("chain_hash_lookup");
		return error;
	}
	if (!chain->dimtree)
		return HE_CHAIN_IS_USERDEFINED;
	*result = ((struct dt_rule *)(chain->end->p[0]))->spec.action;
	return HE_OK;
}



/* create new user-defined chain with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_EXISTS, 
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_new_chain(const char* name)
{
	hipac_error error;
	struct hipac_chain *chain;
	__u32 i, j, list_pos;

	if (unlikely(!name))
		ARG_ERR;
	
	list_pos = chain_hash->elem_ct - (native_dts ? native_dts->len : 0);
	if ((error = chain_new(name, &chain, list_pos))){
		CHECK_ERROR("chain_new");
		return error;
	}
	if ((error = chain_hash_insert(chain))){
		CHECK_ERROR("chain_hash_insert");
		chain_free(chain);
		return error;
	}
	for (i = 0; i < chain_hash->len; i++) {
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			struct hipac_chain *c;
			c = chain_hash->bucket[i]->kv[j].val;
			if (c->dimtree) {
				continue;
			}
			if (strcmp(c->name, name) > 0) {
				if (c->list_pos < list_pos) {
					list_pos = c->list_pos;
				}
				c->list_pos++;
			}
		}
	}
	chain->list_pos = list_pos;

	return HE_OK;
}



/* delete all rules in chain with name 'name'.
   if 'name' is NULL all rules in all chains are deleted.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_IMPOSSIBLE_CONDITION                           */
hipac_error 
hipac_flush_chain(const char *name)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct list_head *lh;
	struct chain_rule *rule;
	struct next_chain_elem *n_elem;
	__u32 i, j;
	
	if (!name){
		//flushing all chains	
		for (i = 0; i < chain_hash->len; i++) {
			if (chain_hash->bucket[i] == NULL) {
				continue;
			}
			for (j = 0; j < chain_hash->bucket[i]->len; j++) {
				chain = chain_hash->bucket[i]->kv[j].val;
				if (chain->dimtree){
					dimtree_flush(chain->dimtree);
					lh = chain->head.next;
					while (lh != &chain->head) {
						rule = list_entry(
							lh, struct chain_rule,
							head);
						lh = lh->next;
						list_del(lh->prev);
						chain_rule_destroy(rule);
					}
					if (chain->next_chains){
						strblock_free(
							chain->next_chains);
						chain->next_chains = NULL;
					}
				} else {
					chain_flush(chain);
				}
			}                                                         
		}
		return HE_OK;
	}

	if ((error = chain_hash_lookup(name, &chain)))
		return error;


	if (unlikely(CHAIN_NOT_CONNECTED(chain))){			
		if (chain->next_chains){
			for (i = 0; i < chain->next_chains->len; i++){
				n_elem = STRBLOCK_ITH(chain->next_chains, i,
						      struct next_chain_elem *);
				n_elem->chain->ref_count -= n_elem->count;
			}
			strblock_free(chain->next_chains);
			chain->next_chains = NULL;
		}
		lh = chain->head.next;
		while (lh != &chain->head) {
			rule = list_entry(lh, struct chain_rule, head);
			lh = lh->next;
			list_del(lh->prev);
			chain_rule_destroy(rule);
		}
		return HE_OK;
	}

	
	if (!chain->dimtree){
		if ((error = delete_dt_rules_from_dimtrees(chain, 
							   chain->start,
							   chain->end))){
			CHECK_ERROR("delete_dt_rules_from_dimtrees");
			dimtree_failed(native_dts);
			return error;
		}
		dimtree_commit(native_dts);
	}
	
	if (chain->next_chains){
		for (i = 0; i < chain->next_chains->len; i++){
			n_elem = STRBLOCK_ITH(chain->next_chains, i,
					      struct next_chain_elem *);
			n_elem->chain->ref_count -= n_elem->count;
		}
		strblock_free(chain->next_chains);
		chain->next_chains = NULL;
	}

	lh = chain->head.next;
	while (lh != &chain->head) {
		rule = list_entry(lh, struct chain_rule, head);
		lh = lh->next;
		list_del(lh->prev);
		if (IS_JUMP_RULE(rule)){
			delete_jump_from_hipac_layer(chain, chain->start,
						     chain->end, rule);
		}
		chain_rule_destroy(rule);
	}
	
	if (chain->dimtree){
		dimtree_flush(chain->dimtree);
	} else {
		delete_dt_rules_from_dt_chains(chain, 
					       chain->start, chain->end);
		dimtree_chain_fix(native_dts);
	}
	return HE_OK;
}



/* delete user-defined chain with name 'name'.
   if 'name' is NULL delete all chains that are empty 
   and not referenced from other chains.
   possible errors: HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_NATIVE,
                    HE_CHAIN_NOT_EMPTY, HE_CHAIN_IS_REFERENCED        */   
hipac_error
hipac_delete_chain(const char *name)
{
	hipac_error error;
	struct hipac_chain *chain;
	__u32 i, j;
	
	if (!name){
		//delete all empty and not referenced user-defined chains
		for (i = 0; i < chain_hash->len; i++) {
			if (chain_hash->bucket[i] == NULL) {
				continue;
			}
			for (j = 0; j < chain_hash->bucket[i]->len;) {
				__u32 k, l;
				chain = chain_hash->bucket[i]->kv[j].val;
				if (chain->dimtree
				    || !list_empty(&chain->head)
				    || CHAIN_IS_REFERENCED(chain)) {
					j++;
					continue;
				}
				chain_hash_remove(chain);
				for (k = 0; k < chain_hash->len; k++) {
					if (!chain_hash->bucket[k]) {
						continue;
					}
					for (l = 0; l < chain_hash->
						     bucket[k]->len; l++) {
						struct hipac_chain *c;
						c = chain_hash->bucket[k]->
							kv[l].val;
						if (!c->dimtree &&
						    c->list_pos >
						    chain->list_pos) {
							c->list_pos--;
						}
					}
				}
				chain_free(chain);
			}                                                         
		}
		return HE_OK;
	}

	if ((error = chain_hash_lookup(name, &chain)))
		return HE_CHAIN_NOT_EXISTENT;

	if (chain->dimtree)
		return HE_CHAIN_IS_NATIVE;
	
	if (!list_empty(&chain->head))
		return HE_CHAIN_NOT_EMPTY;

	if (CHAIN_IS_REFERENCED(chain))
		return HE_CHAIN_IS_REFERENCED;
	
	chain_hash_remove(chain);
	for (i = 0; i < chain_hash->len; i++) {
		struct hipac_chain *c;
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			c = chain_hash->bucket[i]->kv[j].val;
			if (!c->dimtree && c->list_pos > chain->list_pos) {
				c->list_pos--;
			}
		}                                                         
	}
	chain_free(chain);
	return HE_OK;
}



/* rename chain with name 'name' to 'new_name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_EXISTS, 
                    HE_CHAIN_NOT_EXISTENT, HE_CHAIN_IS_NATIVE,
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_rename_chain(const char *name, const char *new_name)
{
	hipac_error error;
	struct hipac_chain *old_chain, *new_chain;
	struct list_head *lh;
	struct chain_rule *rule;
	int new_is_larger;
	char *old;
	__u32 i, j, k, list_pos;

	if (unlikely(!name || !new_name))
		ARG_ERR;
	
	if ((!(error = chain_hash_lookup(new_name, &old_chain))))
		return HE_CHAIN_EXISTS;

	if ((error = chain_hash_lookup(name, &old_chain)))
		return error;
	
	if (old_chain->dimtree)
		return HE_CHAIN_IS_NATIVE;

	new_chain = hp_alloc(sizeof(*new_chain), ADD);
	if (!new_chain)
		return HE_LOW_MEMORY;

	memcpy(new_chain, old_chain, sizeof(*new_chain));

	strncpy(new_chain->name, new_name, HIPAC_CHAIN_NAME_MAX_LEN);
	new_chain->name[HIPAC_CHAIN_NAME_MAX_LEN - 1] = '\0';

	if ((error = chain_hash_replace(old_chain, new_chain))) {
		CHECK_ERROR("chain_hash_replace");
		hp_free(new_chain);
		return error;
	}
	current_chain = NULL;
	
	if (list_empty(&old_chain->head)) {
		INIT_LIST_HEAD(&new_chain->head);
	} else {
		lh = old_chain->head.next;
		list_del(&old_chain->head);
		list_add_tail(&new_chain->head, lh);
	}
	
	new_is_larger = (strcmp(new_name, name) > 0);
	list_pos = old_chain->list_pos;
	if (!CHAIN_IS_REFERENCED(old_chain)) {
		for (i = 0; i < chain_hash->len; i++) {
			struct hipac_chain *chain;
			if (chain_hash->bucket[i] == NULL) {
				continue;
			}
			for (j = 0; j < chain_hash->bucket[i]->len; j++) {
				chain = chain_hash->bucket[i]->kv[j].val;
				if (chain->dimtree)
					continue;
				if (new_is_larger) {
					if (chain->list_pos >
					    old_chain->list_pos &&
					    strcmp(chain->name,
						   new_name) < 0) {
						if (list_pos <
						    chain->list_pos) {
							list_pos = chain->
								list_pos;
						}
						chain->list_pos--;
					}
				} else {
					if (chain->list_pos <
					    old_chain->list_pos &&
					    strcmp(chain->name,
						   new_name) > 0) {
						if (list_pos >
						    chain->list_pos) {
							list_pos = chain->
								list_pos;
						}
						chain->list_pos++;
					}
				}
			}
		}
		new_chain->list_pos = list_pos;
		hp_free(old_chain);
		return HE_OK;
	}
	
	for (i = 0; i < chain_hash->len; i++) {
		struct hipac_chain *chain, **next;
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			chain = chain_hash->bucket[i]->kv[j].val;

			if (chain->next_chains){
				for (k = 0; k < chain->next_chains->len; k++){
					next = &STRBLOCK_ITH(
						chain->next_chains, k,
						struct next_chain_elem *)
						->chain;
					if (*next == old_chain)
						*next = new_chain;
				}
			}

			list_for_each(lh, &chain->head) {
				rule = list_entry(lh, struct chain_rule, head);
				if (IS_JUMP_RULE(rule)){
					old = (void *) &rule->r 
						+ rule->r.target_offset;
					if (!strcmp(old, name)){
						strncpy(old, new_name,
						    HIPAC_CHAIN_NAME_MAX_LEN);
						old[HIPAC_CHAIN_NAME_MAX_LEN
						    - 1] = '\0';
					}
				}
			}	

			if (chain->dimtree)
				continue;
				
			if (new_is_larger) {
				if (chain->list_pos > old_chain->list_pos &&
				    strcmp(chain->name, new_name) < 0) {
					if (list_pos < chain->list_pos) {
						list_pos = chain->list_pos;
					}
					chain->list_pos--;
				}
			} else {
				if (chain->list_pos < old_chain->list_pos &&
				    strcmp(chain->name, new_name) > 0) {
					if (list_pos > chain->list_pos) {
						list_pos = chain->list_pos;
					}
					chain->list_pos++;
				}
			}
		}
	}
	new_chain->list_pos = list_pos;
	hp_free(old_chain);
	return HE_OK;
}



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
		      __u32 *len)
{
	hipac_error error;
	struct hipac_chain *chain;

	if (unlikely(!inf || !len))
		ARG_ERR;
	
	if (!name){
		__u32 i, j, e;
		*len = chain_hash->elem_ct;
		*inf = hp_alloc(*len * sizeof(**inf), ADD);
		if (!(*inf)){
			LOW_MEM("hipac_chain_info alloc failed!");
		}
		for (i = 0; i < chain_hash->len; i++) {
		        if (!chain_hash->bucket[i])
				continue;
			for (j = 0; j < chain_hash->bucket[i]->len; j++) {
				chain = chain_hash->bucket[i]->kv[j].val;
				if (chain->dimtree) {
					e = chain->list_pos;
					(*inf)[e].policy = ((struct dt_rule *)
							    (chain->end->p[0]))
						->spec.action;
				} else {
					e = chain->list_pos +
						(native_dts ?
						 native_dts->len : 0);
					(*inf)[e].policy = 0;
				}
				(*inf)[e].label = chain->name;
				(*inf)[e].is_internal_chain = 0;
				if (list_empty(&chain->head)){
					(*inf)[e].rule_num = 0;
				} else {
					(*inf)[e].rule_num =
						list_entry(chain->head.prev,
							   struct chain_rule, 
							   head)->r.pos;
				}
				(*inf)[e].chain_head = &chain->head;
			}                                                       
		}
		return HE_OK;
	}
		

	if ((error = chain_hash_lookup(name, &chain))){
		// it's not a user-defined chain
		// check if it's a internal dimtree chain
		__u32 i;
		struct dimtree *dt;
		if (!native_dts) 
			return  HE_CHAIN_NOT_EXISTENT;
		for (i = 0; i < native_dts->len; i++){
			dt = (struct dimtree *) native_dts->p[i];
			if (!strcmp(name, dt->chain->name)){
				*len = 1;
				*inf = hp_alloc(sizeof(**inf), ADD);
				if (!(*inf))
					LOW_MEM();
				(*inf)[0].label = dt->chain->name;
				(*inf)[0].policy = 
					list_entry(dt->chain->head.prev,
						   struct dt_rule, 
						   head)->spec.action;
				(*inf)[0].is_internal_chain = 1;
				(*inf)[0].rule_num = dt->chain->len;
				(*inf)[0].chain_head = &dt->chain->head;
				return HE_OK;
			}
		}
		return HE_CHAIN_NOT_EXISTENT;
	}
	
	*len = 1;
	*inf = hp_alloc(sizeof(**inf), ADD);
	if (!(*inf))
		LOW_MEM("hipac_chain_info alloc failed!");
	(*inf)[0].label = chain->name;
	if (chain->dimtree)
		(*inf)[0].policy = ((struct dt_rule *)
				    (chain->end->p[0]))->spec.action;
	else (*inf)[0].policy = 0;
	(*inf)[0].is_internal_chain = 0;
	if (list_empty(&chain->head)){
		(*inf)[0].rule_num = 0;
	} else {
		(*inf)[0].rule_num = list_entry(
			chain->head.prev,
			struct chain_rule, head)->r.pos;
	} 
	(*inf)[0].chain_head = &chain->head;
	return HE_OK;
}



/* free array of hipac_chain_info structs that has been allocated
   before via hipac_get_chain_infos(). 
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_free_chain_infos(struct hipac_chain_info *inf)
{
	if (unlikely(!inf))
		ARG_ERR;
	hp_free(inf);
	return HE_OK;
}



/* get next hipac_rule 'next' of previous hipac_rule 'prev'.
   with this function you can walk over the chain during rule listing.
   to get the first hipac_rule of a chain, set 'prev_rule' to NULL.
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
		    struct hipac_rule **next)
{
	hipac_error error;
	static struct dt_rule *dt_rule = NULL;

	if (unlikely(!inf || !next))
		ARG_ERR;

	if (unlikely(!prev)){
		if (!inf->is_internal_chain){
			if (unlikely(list_empty(inf->chain_head))){
				*next = NULL;
				return HE_RULE_NOT_EXISTENT;
			} else {
				*next = &list_entry(inf->chain_head->next,
						    struct chain_rule, 
						    head)->r;
			}
		} else {
			if (dt_rule)
				IMPOSSIBLE_CONDITION("dt_rule is defined!");
			dt_rule = list_entry(inf->chain_head->next,
					     struct dt_rule, head);
			if ((error = build_hipac_rule_from_dt_rule(dt_rule, 
								   next))){
				CHECK_ERROR("build_hipac_rule_from_dt_rule");
				dt_rule = NULL;
				*next = NULL;
				return error;
			}
		}
		return HE_OK;
	}
       
	if (!inf->is_internal_chain){
		struct chain_rule *prev_chain_rule;
		prev_chain_rule = list_entry(prev, 
					     struct chain_rule, r);
		if (prev_chain_rule->head.next == inf->chain_head){
			*next = NULL;
			return HE_RULE_NOT_EXISTENT;
		}
		*next = &list_entry(prev_chain_rule->head.next,
				    struct chain_rule, head)->r;
	} else {
		hp_free(prev);
		if (!dt_rule)
			IMPOSSIBLE_CONDITION("dt_rule not defined!");
		if (dt_rule->head.next == inf->chain_head){
			dt_rule = NULL;
			*next = NULL;
			return HE_RULE_NOT_EXISTENT;
		}
		dt_rule = list_entry(dt_rule->head.next,
				     struct dt_rule, head);
		if ((error = build_hipac_rule_from_dt_rule(dt_rule, 
							   next))){
			CHECK_ERROR("build_hipac_rule_from_dt_rule");
			dt_rule = NULL;
			*next = NULL;
			return error;
		}
	}
	return HE_OK;
}


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
hipac_append(const char *name, const struct hipac_rule *rule)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *new_rule;
	
	if (unlikely(!name || !rule))
		ARG_ERR;
	
	if ((error = chain_hash_lookup(name, &chain)))
		return error;

	if (unlikely(error = build_chain_rule_from_hipac_rule(rule, &new_rule)))
		return error;

	new_rule->r.pos = (list_empty(&chain->head)) ?
		1 : (list_entry(chain->head.prev,
				struct chain_rule, head)->r.pos + 1);
	return insert(chain, new_rule);
}	



/* insert hipac_rule 'rule' at position 'rule->pos' into chain
   with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT,
                    HE_LOOP_DETECTED, HE_REC_LIMIT,
		    HE_RULE_ORIGIN_MISMATCH, HE_RULE_PREFIX_MISMATCH,
		    HE_TARGET_CHAIN_NOT_EXISTENT,
		    HE_TARGET_CHAIN_IS_NATIVE, 
		    HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_insert(const char *name, const struct hipac_rule *rule)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *new_rule;

	if (unlikely(!name || !rule))
		ARG_ERR;

	if ((error = chain_hash_lookup(name, &chain)))
		return error;

	if (unlikely(error = build_chain_rule_from_hipac_rule(rule, &new_rule)))
		return error;

	return insert(chain, new_rule);
}



/* delete hipac_rule with position 'pos' from chain with name 'name'.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT, 
                    HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
hipac_error
hipac_delete_pos(const char *name, const __u32 pos)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *del_rule;
	
	if (unlikely(!name))
		ARG_ERR;
	
	if ((error = chain_hash_lookup(name, &chain)))
		return error;
	
	if ((error = chain_find_rule_with_pos(chain, pos, &del_rule)))
		return error;

	return delete(chain, del_rule);
}



/* find the first rule in chain with name 'name' that equals to
   hipac_rule 'rule' and delete it.
   possible errors: HE_LOW_MEMORY, HE_CHAIN_NOT_EXISTENT, 
                    HE_RULE_NOT_EXISTENT, HE_IMPOSSIBLE_CONDITION     */
hipac_error
hipac_delete(const char *name, const struct hipac_rule *rule)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *del_rule;

	if (unlikely(!name || !rule))
		ARG_ERR;
	
	if ((error = chain_hash_lookup(name, &chain)))
		return error;
	
	if ((error = chain_find_rule(chain, rule, &del_rule)))
		return error;
	
	return delete(chain, del_rule);
}



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
hipac_replace(const char *name, const struct hipac_rule *rule)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *del_rule, *new_rule;
		
	if (unlikely(!name || !rule))
		ARG_ERR;
	
	if ((error = chain_hash_lookup(name, &chain)))
		return error;
	
	if ((error = chain_find_rule_with_pos(chain, rule->pos, 
						      &del_rule)))
		return error;
	
	if (unlikely(error = build_chain_rule_from_hipac_rule(rule, &new_rule)))
		return error;
	
	return replace(chain, del_rule, new_rule);
}





/*
 * hipac statistic functions
 */



/* get hipac chain statistics
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_chain_stat(struct hipac_chain_stat *stat)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct prefix_rule *prefix;
	struct list_head *lh;
	struct chain_rule *rule;
	__u32 i, j, k;
	
	if (unlikely(!stat))
		ARG_ERR;
	
	stat->mem_tight = 0;
	stat->mem_real = 0;
	stat->chain_num = chain_hash->elem_ct;
	stat->rule_num = 0;
	stat_distribution_init(stat->prefix_stat, 16);
	stat_distribution_init(stat->incoming_stat, 16);
	stat_distribution_init(stat->outgoing_stat, 16);
	
	for (i = 0; i < chain_hash->len; i++) {
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			chain = chain_hash->bucket[i]->kv[j].val;
			if ((error = hp_size(chain, 
					     &stat->mem_real,
					     &stat->mem_tight)))
				return error;
			if ((error = hp_size(chain->next_chains, 
					     &stat->mem_real,
					     &stat->mem_tight)))
				return error;
			if ((error = hp_size(chain->paths, 
					     &stat->mem_real,
					     &stat->mem_tight)))
				return error;
			if (chain->paths){
				for (k = 0; k < chain->paths->len; k++){
					prefix = P_ELEM_RULE(chain->paths, k);
					if ((error = 
					     hp_size(prefix, 
						     &stat->mem_real,
						     &stat->mem_tight)))
					       	return error;
					if (prefix
					    && (error = 
						hp_size(prefix->exec_matches, 
							&stat->mem_real,
							&stat->mem_tight)))
						return error;
				}
			}
			if ((error = hp_size(chain->start, 
					     &stat->mem_real,
					     &stat->mem_tight)))
				return error;
			if ((error = hp_size(chain->end, 
					     &stat->mem_real,
					     &stat->mem_tight)))
				return error;

			if (!list_empty(&chain->head)){
				stat->rule_num += 
					list_entry(chain->head.prev,
						   struct chain_rule, 
						   head)->r.pos;
			}   
			
			if (chain->paths)
				stat_distribution_add(stat->prefix_stat, 16, 
						      chain->paths->len);
			else stat_distribution_add(stat->prefix_stat, 16, 0);
			stat_distribution_add(stat->incoming_stat, 16,
					      chain->ref_count);
			if (chain->next_chains)
				stat_distribution_add(stat->outgoing_stat, 16,
						      chain->next_chains->len);
			else stat_distribution_add(stat->outgoing_stat, 16, 0);
			
			list_for_each(lh, &chain->head) {
				rule = list_entry(lh, struct chain_rule, head);
				if ((error = hp_size(rule, 
						     &stat->mem_real,
						     &stat->mem_tight)))
					return error;
				if ((error = hp_size(rule->dtr, 
						     &stat->mem_real,
						     &stat->mem_tight)))
					return error;
			}
		}
	}
	return HE_OK;
}



/* get hipac rule statistics
   returned statistic constains all rules of those chains that are
   reachable from the root chain represented by the 'hipac' pointer.
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_rule_stat(void *hipac, struct hipac_rule_stat *stat)
{
	struct hipac_chain *chain;
	struct list_head *lh;
	struct chain_rule *rule;
	__u32 i, j, k, inv;
	__u8 found;
	
	if (unlikely(!hipac || !stat))
		ARG_ERR;
	
	stat->rule_num = 0;
	stat->exec_match_num = 0;
	stat->exec_target_num = 0;
	stat->jump_target_num = 0;
	stat->return_target_num = 0;
	stat_distribution_init(stat->hipac_match_stat, 16);
	stat_distribution_init(stat->inv_rules_stat, 16);
	
	for (i = 0; i < chain_hash->len; i++) {
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			chain = chain_hash->bucket[i]->kv[j].val;
			found = 0;
			if (chain->paths){
				for (k = 0; k < chain->paths->len; k++){
					if (hipac ==
					    P_ELEM_DIMTREE(chain->paths, k)){
						found = 1;
						break;
					}
				}
			}
			if (!found)
				continue;
			if (!list_empty(&chain->head)){
				stat->rule_num += 
					list_entry(chain->head.prev,
						   struct chain_rule, 
						   head)->r.pos;
			}   
			
			list_for_each(lh, &chain->head) {
				rule = list_entry(lh, struct chain_rule, head);
				if (rule->r.match_offset)
					stat->exec_match_num++;
				if (rule->r.action == TARGET_EXEC)
					stat->exec_target_num++;
				if (rule->r.action == TARGET_CHAIN)
					stat->jump_target_num++;
				if (rule->r.action == TARGET_RETURN)
					stat->return_target_num++;
				stat->hipac_match_stat[rule->r.native_mct]++;
				inv = count_inv_matches(rule->r.first_match, 
							rule->r.native_mct);
				stat->inv_rules_stat[inv]++;
			}
		}
	}
	return HE_OK;
}
	


/* get hipac user statistics
   possible errors: HE_IMPOSSIBLE_CONDITION                           */
hipac_error
hipac_get_user_stat(struct hipac_user_stat *stat)
{
	struct hipac_chain *chain;
	__u32 i, j;
	
	if (unlikely(!stat))
		ARG_ERR;

	stat->total_mem_tight = mem_current_tight;
	stat->total_mem_real = mem_current_real;
	stat->chain_num = chain_hash->elem_ct;
	stat->rule_num = 0;
	
	for (i = 0; i < chain_hash->len; i++) {
		if (chain_hash->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < chain_hash->bucket[i]->len; j++) {
			chain = chain_hash->bucket[i]->kv[j].val;
			if (!list_empty(&chain->head)){
				stat->rule_num += 
					list_entry(chain->head.prev,
						   struct chain_rule, 
						   head)->r.pos;
			}                 
		}
	}
	return HE_OK;
}



#ifdef DEBUG
hipac_error
hipac_get_dt_rule_ptrs(const char *name, const __u32 pos, 
		       void **res)
{
	hipac_error error;
	struct hipac_chain *chain;
	struct chain_rule *rule;
	
	if (unlikely(!name || !res))
		ARG_ERR;
	
	if ((error = chain_hash_lookup(name, &chain)))
		return error;
       
	if (list_empty(&chain->head)){
		*res = chain->end;
		return HE_OK;
	}
	rule = list_entry(chain->head.prev, struct chain_rule, head);
	if (pos > rule->r.pos){
		if (pos == rule->r.pos + 1){
			*res = chain->end;
			return HE_OK;
		} else {
			return HE_RULE_NOT_EXISTENT;
		}
	}

	if (unlikely(error = chain_find_rule_with_pos(chain, pos, &rule)))
		return error;

	*res = rule->dtr;
	return HE_OK;
}



__u8
dt_rules_have_same_position(void *hipac, void *dt_start, void *dt_rule)
{
	struct dt_rule *rule = (struct dt_rule *) dt_start;
	
	if (!hipac || !dt_start || !dt_rule){
		 ARG_MSG;
		 return 0;
	}
	if (rule->head.prev != &((struct dimtree *) hipac)->chain->head) {
	        if (rule->spec.pos ==
		    list_entry(rule->head.prev, struct dt_rule, head)
		    ->spec.pos){
			ERR("previous rule with same position found");
			return 0;
		}
	}
	while (rule->spec.pos == ((struct dt_rule *) dt_rule)->spec.pos) {
		if (rule == dt_rule)
			return 1;
		if (rule->head.next == 
		    &((struct dimtree *) hipac)->chain->head)
			return 0;
		rule = list_entry(rule->head.next, struct dt_rule, head);
	}
	return 0;
}


#endif



/* End of hipac_* functions */
