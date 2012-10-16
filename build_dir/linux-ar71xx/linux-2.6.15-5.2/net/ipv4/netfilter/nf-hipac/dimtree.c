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


#include "global.h"
#include "ihash.h"
#include "rlp.h"
#include "dimtree.h"

#define HAS_DT_MATCH(rule)      ((rule)->dt_match_len > 0)
#define ITH_DT_MATCH(rule, i)   ((rule)->first_dt_match + (i))
#define LAST_DT_MATCH(rule)     ITH_DT_MATCH(rule, (rule)->dt_match_len - 1)
#define LEN(array)              (sizeof(array) / sizeof(*(array)))

/*
 * newspec keeps track of the rlps and elementary intervals that have been
 * newly allocated during a series of dimtree operations;
 * orgspec keeps track of the rlps and elementary intervals that can be
 * freed after the series of dimtree operations has been successfully finished
 */
static struct ptrlist orgspec = {LIST_HEAD_INIT(orgspec.head), 0};
static struct ihash *newspec  = NULL;



static inline void
elem_free(struct dt_elem *e)
{
	if (unlikely(e == NULL)) {
		ARG_MSG;
		return;
	}
	hp_free(e);
}


/* free s which can be an elemtary interval or a rlp */
static inline void
rlp_elem_free(struct gen_spec *s)
{
	if (unlikely(s == NULL)) {
		ARG_MSG;
		return;
	}
	if (IS_RLP(s)) {
		rlp_free((struct rlp_spec *) s);
	} else {
		/* s must be elemtary interval */
		assert(IS_ELEM(s));
		elem_free((struct dt_elem *) s);
	}
}

/* set newspec bit of s which can be an elementary interval or a rlp to 0 */
static inline void
rlp_elem_newspec_set(struct gen_spec *s, int newspec_set)
{
	if (unlikely(s == NULL)) {
		ARG_MSG;
		return;
	}
	if (IS_RLP(s)) {
		((struct rlp_spec *) s)->newspec = !!newspec_set;
	} else {
		/* s must be elemtary interval */
		assert(IS_ELEM(s));
		((struct dt_elem_spec *) s)->newspec = !!newspec_set;
	}
}

/* call rlp_elem_free for each member of orgspec and empty orgspec */
static inline void
orgspec_dofree(void)
{
	struct list_head *lh;
	struct ptrlist_entry* e;

	for (lh = orgspec.head.next; lh != &orgspec.head;) {
		e = list_entry(lh, struct ptrlist_entry, head);
		lh = lh->next;
		assert((IS_RLP(e->p) &&
			!((struct rlp_spec *) e->p)->newspec) ||
		       (IS_ELEM(e->p) &&
			!((struct dt_elem_spec *) e->p)->newspec));
		rlp_elem_free(e->p);
		mini_free(e);
	}
	INIT_LIST_HEAD(&orgspec.head);
	orgspec.len = 0;
}

/* call rlp_elem_free for each member of newspec and empty newspec */
static inline void
newspec_dofree(void)
{
	if (unlikely(newspec == NULL)) {
		return;
	}
	IHASH_KEY_ITERATE(newspec, struct gen_spec *, rlp_elem_free);
	ihash_free(newspec);
	newspec = NULL;
}

/* add s to orgspec;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
static inline hipac_error
orgspec_add(struct gen_spec *s)
{
	if (unlikely(s == NULL)) {
		ARG_ERR;
	}
	assert((IS_RLP(s) && !((struct rlp_spec *) s)->newspec) ||
	       (IS_ELEM(s) && !((struct dt_elem_spec *) s)->newspec));
#ifdef DEBUG
	return ptrlist_add(&orgspec, s, 1);
#else
	return ptrlist_add(&orgspec, s, 0);
#endif
}

/* empty orgspec */
static inline void
orgspec_flush(void)
{
	ptrlist_flush(&orgspec);
}

/* empty newspec; if newspec_reset is not 0 the newspec bit is set
   to 0 for each element of newspec */
static inline void
newspec_flush(int newspec_reset)
{
	if (unlikely(newspec == NULL)) {
		return;
	}
	if (newspec_reset) {
		IHASH_KEY_ITERATE(newspec, struct gen_spec *,
				  rlp_elem_newspec_set, 0);
	}
	ihash_free(newspec);
	newspec = NULL;
}


/*
 * history operations
 */

static void
history_undo(void)
{
	newspec_dofree();
	orgspec_flush();
}

static void
history_commit(int newspec_set)
{
	orgspec_dofree();
	newspec_flush(newspec_set);
}

#ifdef DEBUG
/* return 1 if orgspec and newspec are empty and 0 otherwise */
static int
history_is_empty(void)
{
	return newspec == NULL && list_empty(&orgspec.head);
}
#endif

/* s is a new rlp or elementary interval layer which does __not__
   replace another */
static hipac_error
history_new(struct gen_spec *s, int newspec_set)
{
	int stat;

	if (unlikely(s == NULL)) {
		ARG_ERR;
	}

	assert((IS_RLP(s) || IS_ELEM(s)));
	if (unlikely(newspec == NULL)) {
		newspec = ihash_new(INITIAL_NEWSPEC_LEN, 0,
				    NEWSPEC_AVRG_ELEM_PER_BUCKET,
				    ihash_func_val, eq_val);
		if (newspec == NULL) {
			return HE_LOW_MEMORY;
		}
	}
	stat = ihash_insert(&newspec, s, NULL);
	if (stat < 0) {
		return stat;
	}
	if (newspec_set) {
		rlp_elem_newspec_set(s, 1);
	}
	return stat;
}

static hipac_error
history_replace(struct gen_spec *old, struct gen_spec *new, int newspec_set)
{
	int stat;

	if (unlikely(old == NULL || new == NULL)) {
		ARG_ERR;
	}

	assert((IS_RLP(old) && IS_RLP(new)) ||
	       (IS_ELEM(old) && IS_ELEM(new)));
	assert(newspec_set ||
	       (IS_RLP(old) && !((struct rlp_spec *) old)->newspec) ||
	       (IS_ELEM(old) && !((struct dt_elem_spec *) old)->newspec));
	assert(newspec_set ||
	       (IS_RLP(new) && !((struct rlp_spec *) new)->newspec) ||
	       (IS_ELEM(new) && !((struct dt_elem_spec *) new)->newspec));
	if (unlikely(newspec == NULL)) {
		if (newspec_set &&
		    ((IS_RLP(old) &&
		      ((struct rlp_spec *) old)->newspec) ||
		     (IS_ELEM(old) &&
		      ((struct dt_elem_spec *) old)->newspec))) {
			IMPOSSIBLE_CONDITION("old must be contained in new"
					     "spec but newspec is empty");
		}
		newspec = ihash_new(INITIAL_NEWSPEC_LEN, 0,
				    NEWSPEC_AVRG_ELEM_PER_BUCKET,
				    ihash_func_val, eq_val);
		if (newspec == NULL) {
			return HE_LOW_MEMORY;
		}
	}
	if (newspec_set &&
	    ((IS_RLP(old) && ((struct rlp_spec *) old)->newspec) ||
	     (IS_ELEM(old) && ((struct dt_elem_spec *) old)->newspec))) {
		
		stat = ihash_replace(&newspec, old, NULL, new, NULL);
		if (stat == HE_OK) {
			rlp_elem_newspec_set(new, 1);
			rlp_elem_free(old);
		}
	} else {
		stat = orgspec_add(old);
		if (stat < 0) {
			return stat;
		}
		stat = ihash_insert(&newspec, new, NULL);
		if (stat < 0) {
			return stat;
		}
		if (newspec_set) {
			rlp_elem_newspec_set(new, 1);
		}
	}
	return stat;
}

/* s is an obsolete rlp or elementary interval layer */
static hipac_error
history_obsolete(struct gen_spec *s, int newspec_set)
{
	if (unlikely(s == NULL)) {
		ARG_ERR;
	}

	assert((IS_RLP(s) || IS_ELEM(s)));
	assert(newspec_set ||
	       (IS_RLP(s) && !((struct rlp_spec *) s)->newspec) ||
	       (IS_ELEM(s) && !((struct dt_elem_spec *) s)->newspec));
	if (unlikely(newspec == NULL && newspec_set &&
		     ((IS_RLP(s) && ((struct rlp_spec *) s)->newspec) ||
		      (IS_ELEM(s) && ((struct dt_elem_spec *) s)->newspec)))) {
		IMPOSSIBLE_CONDITION("s is obsolete, newspec_set is not 0 and"
				     " the newspec bit of s is set __but__ s "
				     "is not contained in newspec");
	}
	if (newspec_set &&
	    ((IS_RLP(s) && ((struct rlp_spec *) s)->newspec) ||
	     (IS_ELEM(s) && ((struct dt_elem_spec *) s)->newspec))) {
		if (ihash_delete(newspec, s, NULL) < 0) {
			IMPOSSIBLE_CONDITION("unable to remove s from "
					     "newspec");
		}
		rlp_elem_free(s);
		return HE_OK;
	}
	return orgspec_add(s);
}

/* hp_realloc can result in a pointer becoming invalid; this function is used
   to apply this fact to the history */
static void
history_del_invalid(struct gen_spec *s)
{
	if (unlikely(s == NULL)) {
		ARG_MSG;
		return;
	}
	if (ihash_delete(newspec, s, NULL) < 0) {
		ERR("unable to remove invalid pointer from newspec");
	}
}



/*
 * termrule operations
 */

/* insert 'rule' in 'term' in sorted order (sorted after pointer addresses);
   'term' must be sorted before */
static inline hipac_error
termrule_insert(struct ptrblock **term, struct dt_rule *rule)
{
	__u32 i;

	if (unlikely(term == NULL || rule == NULL)) {
		ARG_ERR;
	}

	if (*term == NULL) {
		*term = ptrblock_new(rule, 1);
		if (*term == NULL) {
			return HE_LOW_MEMORY;
		}
		return HE_OK;
	}

#ifdef BIT32_ARCH
	for (i = 0; i < (*term)->len && 
		     (__u32) (*term)->p[i] < (__u32) rule; i++);
#else
	for (i = 0; i < (*term)->len && 
		     (__u64) (*term)->p[i] < (__u64) rule; i++);
#endif
	if (i < (*term)->len && (*term)->p[i] == rule) {
		IMPOSSIBLE_CONDITION("rule is already contained in term");
	}
	return ptrblock_insert(term, rule, i);
}

/* delete 'rule' from 'term' which must be in sorted order (sorted after
   pointer addresses) */
static inline hipac_error
termrule_delete(struct ptrblock **term, const struct dt_rule *rule)
{
	__u32 i;

	if (unlikely(term == NULL || rule == NULL)) {
		ARG_ERR;
	}
	if (*term == NULL) {
		/* rule is not in term */
		return HE_OK;
	}

#ifdef BIT32_ARCH
	for (i = 0; i < (*term)->len && 
		     (__u32) (*term)->p[i] < (__u32) rule; i++);
#else
	for (i = 0; i < (*term)->len && 
		     (__u64) (*term)->p[i] < (__u64) rule; i++);
#endif
	
	if (i >= (*term)->len || (*term)->p[i] != rule) {
		/* rule is not in term */
		return HE_OK;
	}
	return ptrblock_delete_pos(term, i);
}

/* delete those rules from 'term' whose match boundaries in dimension 'dimid'
   lie completely within ['left', 'right'] */
static inline hipac_error
termrule_delete_ovl(struct ptrblock **term, __u32 left, __u32 right,
		    __u8 dimid)
{
	__u32 i, curleft, curight;
	struct dt_match *match;
	int stat;

	if (unlikely(term == NULL || left > right ||
		     left > MAXKEY(dim2btype[dimid]) ||
		     right > MAXKEY(dim2btype[dimid]))) {
		ARG_ERR;
	}
	if (*term == NULL) {
		return HE_OK;
	}

       	for (i = 0; i < (*term)->len;) {
		match = HAS_DT_MATCH((struct dt_rule *) (*term)->p[i]) ?
			LAST_DT_MATCH((struct dt_rule *) (*term)->p[i]) : NULL;
		if (match != NULL && match->dimid == dimid) {
			assert(match->left > 0 ||
			       match->right < MAXKEY(dim2btype[dimid]));
			curleft = match->left;
			curight = match->right;
		} else {
			curleft = 0;
			curight = MAXKEY(dim2btype[dimid]);
		}
		if (curleft >= left && curight <= right) {
			stat = ptrblock_delete_pos(term, i);
			if (stat < 0) {
				return stat;
			}
			if (*term == NULL) {
				return HE_OK;
			}
		} else {
			i++;
		}
	}
	return HE_OK;
}

/* returns 1 if there is a rule in 'term' whose last match m produces the
   interval represented by 'right' and dimid(m) == 'dimid' */
static inline int
termrule_exists(const struct ptrblock *term, __u8 dimid, __u32 right)
{
	struct dt_match *match;
	struct dt_rule **rule;
	__u32 i;
	
	if (unlikely(right > MAXKEY(dim2btype[dimid]))) {
		ARG_MSG;
		return 0;
	}
	if (term == NULL) {
		return 0;
	}

	rule = (struct dt_rule **) term->p;
	for (i = 0; i < term->len; i++) {
		match = HAS_DT_MATCH(*rule) ? LAST_DT_MATCH(*rule) : NULL;
		if (match != NULL && match->dimid == dimid &&
		    (match->right == right ||
		     (match->left > 0 && match->left - 1 == right))) {
			return 1;
		}
		rule++;
	}
	return 0;
}

/* return 1 if 'rule' terminates in the elementary interval described by 
   'right' resp. 'wildcard' and 'dimid'; otherwise 0 is returned */
static inline int
rule_term(const struct dt_rule *rule, __u32 right, __u8 wildcard, __u8 dimid)
{
	__u32 lbound, ubound;
	const struct dt_match *match;
	__u8 match_wc, match_nwc1, match_nwc2;

	if (unlikely(rule == NULL || (wildcard && !HAS_WILDCARD_DIM(dimid)))) {
		ARG_MSG;
		return 0;
	}

	match = HAS_DT_MATCH(rule) ? LAST_DT_MATCH(rule) : NULL;
	if (match != NULL && match->dimid == dimid) {
		assert(match->left > 0 ||
		       match->right < MAXKEY(dim2btype[dimid]));
		lbound = match->left;
		ubound = match->right;
	} else if (match == NULL || match->dimid < dimid) {
		lbound = 0;
		ubound = MAXKEY(dim2btype[dimid]);
	} else {
		return 0;
	}
	
	match_wc   = wildcard && (match == NULL || match->dimid < dimid);
	
	match_nwc1 = !wildcard && HAS_WILDCARD_DIM(dimid) &&
		match != NULL && match->dimid == dimid && ubound >= right &&
		lbound <= right;
	
	match_nwc2 = !wildcard && !HAS_WILDCARD_DIM(dimid) &&
		ubound >= right && lbound <= right;
	
	return match_wc || match_nwc1 || match_nwc2;
}

/* store the subset of rules from 'term' that terminate in the elemtary
   interval represented by 'right' resp. 'wildcard' in dimension 'dimid'
   in 'subterm' */
static inline hipac_error
termrule_subset(const struct ptrblock *term, struct ptrblock **subterm,
		__u32 right, __u8 wildcard, __u8 dimid)
{
	struct dt_rule **rule;
	int stat;
	__u32 i;

	if (unlikely(subterm == NULL)) {
		ARG_ERR;
	}

	*subterm = NULL;
	if (term == NULL) {
		return HE_OK;
	}

	rule = (struct dt_rule **) term->p;
	for (i = 0; i < term->len; i++, rule++) {
		if (rule_term(*rule, right, wildcard, dimid)) {
			stat = ptrblock_insert(
				subterm, *rule, *subterm == NULL ? 0 :
				(*subterm)->len);
			if (stat < 0) {
				if (*subterm != NULL) {
					ptrblock_free(*subterm);
				}
				*subterm = NULL;
				return stat;
			}
		}
	}
	return HE_OK;
}

/* merge 'tmpterm' into 'term' so that there are no duplicates;
   'tmpterm' is freed even if termrule_merge fails */
static inline hipac_error
termrule_merge(struct ptrblock **term, struct ptrlist *tmpterm)
{
	struct ptrlist_entry *e;
	struct list_head *lh;
	int stat;
	__u32 i;
	
	if (unlikely(term == NULL || tmpterm == NULL)) {
		ARG_ERR;
	}

	if (ptrlist_is_empty(tmpterm)) {
		ptrlist_free(tmpterm);
		return HE_OK;
	}

	for (lh = tmpterm->head.next, i = 0; lh != &tmpterm->head;) {
		e = list_entry(lh, struct ptrlist_entry, head);
#ifdef BIT32_ARCH
		for (; *term != NULL && i < (*term)->len &&
			     (__u32) (*term)->p[i] < (__u32) e->p; i++);
#else
		for (; *term != NULL && i < (*term)->len &&
			     (__u64) (*term)->p[i] < (__u64) e->p; i++);
#endif
		if (*term == NULL || i == (*term)->len) {
			/* append rest of tmpterm to term */
			do {
				stat = ptrblock_insert(
					term, e->p, *term == NULL ? 0 :
					(*term)->len);
				if (stat < 0) {
					goto error;
				}
				lh = lh->next;
				ptrlist_free_entry(e);
				e = list_entry(lh, struct ptrlist_entry, head);
			} while (lh != &tmpterm->head);
			break;
		}
		if (e->p != (*term)->p[i]) {
			stat = ptrblock_insert(term, e->p, i++);
			if (stat < 0) {
				goto error;
			}
		}
		lh = lh->next;
		ptrlist_free_entry(e);
	}
	ptrlist_free(tmpterm);
	return HE_OK;

 error:
	ptrlist_free(tmpterm);
	return stat;
}

/* remove all elements of 'delterm' from 'term'; 'delterm' must be completely
   contained in 'term' */
static inline hipac_error
termrule_cut(struct ptrblock **term, struct ptrblock *delterm)
{
	__u32 i, j;
	int stat;
	
	if (unlikely(term == NULL)) {
		ARG_ERR;
	}

	if (delterm == NULL) {
		return HE_OK;
	}
	if (unlikely(*term == NULL)) {
		IMPOSSIBLE_CONDITION("unable to cut elements from empty "
				     "termrule block");
	}

	for (i = 0, j = 0; *term != NULL && i < (*term)->len &&
		     j < delterm->len; j++) {
#ifdef BIT32_ARCH
		for (; i < (*term)->len &&
			     (__u32) (*term)->p[i] < (__u32) delterm->p[j];
		     i++);
#else
		for (; i < (*term)->len &&
			     (__u64) (*term)->p[i] < (__u64) delterm->p[j];
		     i++);
#endif
		if (i >= (*term)->len || (*term)->p[i] != delterm->p[j]) {
			goto error;
		}
		stat = ptrblock_delete_pos(term, i);
		if (stat < 0) {
			return stat;
		}
	}
	if (j >= delterm->len) {
		return HE_OK;
	}

 error:
	IMPOSSIBLE_CONDITION("delterm contains elements which are not "
			     "contained in term");
}

/* return the terminal rule (terminal target + no function based matches)
   from 'term' which dominates the elementary interval represented by 'right'
   resp. 'wildcard' in the dimension specified by 'dimid' and which does not
   equal 'rule' */
static inline struct dt_rule *
termrule_find_best_term(const struct ptrblock *term,
			const struct dt_rule *rule,
			__u32 right, __u8 wildcard, __u8 dimid)
{
	struct dt_rule *best = NULL;
	__u32 nextpos = (__u32) ULONG_MAX;
	struct dt_rule *tr;
	__u32 i;

	if (unlikely(term == NULL || rule == NULL ||
		     right > MAXKEY(dim2btype[dimid]) ||
		     (wildcard && !HAS_WILDCARD_DIM(dimid)))) {
		ARG_MSG;
		return NULL;
	}
	
	for (i = 0; i < term->len; i++) {
		tr = term->p[i];
		if (!IS_RULE_TERM(tr) || tr == rule) {
			continue;
		}
		if (rule_term(tr, right, wildcard, dimid) &&
		    tr->spec.pos < nextpos) {
			nextpos = tr->spec.pos;
			best = tr;
		}
	}
	return best;
}

/* return the number(*) of non-terminal rules (non-terminal target or function
   based matches) in 'term' not equal to 'rule' which terminate in the
   elementary interval represented by 'right' resp. 'wildcard' in the
   dimension specified by 'dimid' and whose position is < term_rule->spec.pos
   if term_rule != NULL; if there is exactly one such non-terminal rule it is
   stored in 'ntm_rule';
   (*) the return value ret is 0, 1 or 2; ret == 0 || ret == 1 means there are
       exactly ret non-terminal rules; ret == 2 means there are >= 2
       non-terminal rules */
static inline __u32
termrule_num_ntm(struct dt_rule **ntm_rule, const struct ptrblock *term,
		 const struct dt_rule *term_rule, const struct dt_rule *rule,
		 __u32 right, __u8 wildcard, __u8 dimid)
{
	__u32 num = 0;
	struct dt_rule *tr;
	__u32 i;

	if (unlikely(ntm_rule == NULL || term == NULL || rule == NULL ||
		     right > MAXKEY(dim2btype[dimid]) ||
		     (wildcard && !HAS_WILDCARD_DIM(dimid)))) {
		ARG_MSG;
		return 0;
	}
	
	*ntm_rule = NULL;
	for (i = 0; i < term->len; i++) {
		tr = term->p[i];
		if (IS_RULE_TERM(tr) || tr == rule ||
		    (term_rule != NULL &&
		     tr->spec.pos >= term_rule->spec.pos)) {
			continue;
		}
		if (rule_term(tr, right, wildcard, dimid)) {
			*ntm_rule = tr;
			if (++num == 2) {
				/* there are at least 2 non-terminal rules
				   => stop searching */
				*ntm_rule = NULL;
				return num;
			}
		}
	}
	if (num > 1) {
		*ntm_rule = NULL;
	}
	return num;
}

/* store all non-terminating rules (non-terminal target or function based
   matches) from 'term' not equal to rule in 'e' which terminate in the
   elementary interval represented by 'right' resp. 'wildcard' in the
   dimension specified by 'dimid' and whose position is < max_rule->spec.pos
   if max_rule != NULL and > min_rule->spec.pos if min_rule != NULL;
   the rules are stored in e->ntm_rules in sorted order (sorted after their
   positions) */
static inline hipac_error
termrule_insert_ntm(struct dt_elem **e, const struct ptrblock *term,
		    const struct dt_rule *min_rule,
		    const struct dt_rule *max_rule,
		    const struct dt_rule *rule,
		    __u32 right, __u8 wildcard, __u8 dimid)
{
	struct dt_rule *tr;
	__u32 i, j, stat;

	if (unlikely(e == NULL || *e == NULL || term == NULL ||
		     right > MAXKEY(dim2btype[dimid]) ||
		     (wildcard && !HAS_WILDCARD_DIM(dimid)))) {
		ARG_ERR;
	}
	
	for (i = 0; i < term->len; i++) {
		tr = term->p[i];
		if (IS_RULE_TERM(tr) || tr == rule ||
		    (min_rule != NULL &&
		     (tr->spec.pos <= min_rule->spec.pos)) ||
		    (max_rule != NULL &&
		     (tr->spec.pos >= max_rule->spec.pos))) {
			continue;
		}
		if (rule_term(tr, right, wildcard, dimid)) {
			for (j = 0; j < (*e)->ntm_rules.len &&
				     ((struct dt_rule *)
				      (*e)->ntm_rules.p[j])->spec.pos <
				     tr->spec.pos; j++);
			stat = ptrblock_insert_embed((void **) e,
						     offsetof(struct dt_elem,
							      ntm_rules),
						     tr, j);
			if (stat < 0) {
				return stat;
			}
		}
	}
	return HE_OK;
}



/*
 * tmp_termrule operations
 */

static inline struct ptrlist *
tmp_termrule_new(void)
{
	return ptrlist_new();
}

static inline void
tmp_termrule_free(struct ptrlist *tmpterm)
{
	return ptrlist_free(tmpterm);
}

/* merge 'term' into 'tmpterm' so that there are no duplicates */
static inline hipac_error
tmp_termrule_merge(struct ptrlist *tmpterm, struct ptrblock *term)
{
	struct ptrlist_entry *e;
	struct list_head *lh;
	int stat;
	__u32 i;
	
	if (unlikely(tmpterm == NULL)) {
		ARG_ERR;
	}

	if (term == NULL) {
		return HE_OK;
	}

	for (i = 0, lh = tmpterm->head.next; i < term->len; i++) {
#ifdef BIT32_ARCH
		for (; lh != &tmpterm->head &&
			     (__u32) list_entry(lh, struct ptrlist_entry,
						head)->p <
			     (__u32) term->p[i]; lh = lh->next);
#else
		for (; lh != &tmpterm->head &&
			     (__u64) list_entry(lh, struct ptrlist_entry,
						head)->p <
			     (__u64) term->p[i]; lh = lh->next);
#endif
		if (lh == &tmpterm->head) {
			/* append rest of term to tmpterm */
			for (; i < term->len; i++) {
				stat = ptrlist_add(tmpterm, term->p[i], 0);
				if (stat < 0) {
					return stat;
				}
			}
			break;
		}
		e = list_entry(lh, struct ptrlist_entry, head);
		if (e->p != term->p[i]) {
			e = ptrlist_new_entry(term->p[i]);
			if (e == NULL) {
				return HE_LOW_MEMORY;
			}
			list_add_tail(&e->head, lh);
			tmpterm->len++;
		}
	}
	return HE_OK;
}



/*
 * elementary interval operations
 */

/* create new elementary interval layer with ntm_len non-terminal rules
   which are stored in ntm_rules sorted after their positions */
static inline struct dt_elem *
elem_new(struct dt_rule *term_rule, struct dt_rule *ntm_rules[], __u32 ntm_len)
{
	struct dt_elem *e;
	__u32 i;

	if (unlikely(ntm_len == 0 || ntm_rules == NULL || *ntm_rules == NULL ||
		     (termrule == NULL && ntm_len <= 1))) {
		ARG_MSG;
		return NULL;
	}

	e = hp_alloc(sizeof(*e) + ntm_len * sizeof(*e->ntm_rules.p), 1);
	if (e == NULL) {
		return NULL;
	}
	e->spec.rlp = 0;
	e->spec.rtype = RT_ELEM;
	e->spec.newspec = 0;
	e->term_rule = term_rule;
	e->ntm_rules.len = ntm_len;
	for (i = 0; i < ntm_len; i++) {
		e->ntm_rules.p[i] = ntm_rules[i];
	}
	return e;
}

/* create new elementary interval layer with 0 non-terminal rules; notice that
   the resulting elementary interval is not valid because it __must__ contain
   at least one non-terminal rule */
static inline struct dt_elem *
elem_new_empty(struct dt_rule *term_rule)
{
	struct dt_elem *e;
	
	e = hp_alloc(sizeof(*e), 1);
	if (e == NULL) {
		return NULL;
	}
	e->spec.rlp = 0;
	e->spec.rtype = RT_ELEM;
	e->spec.newspec = 0;
	e->term_rule = term_rule;
	e->ntm_rules.len = 0;
	return e;
}

static inline int
elem_eq(const struct dt_elem *e1, const struct dt_elem *e2)
{
	if (e1 == NULL || e2 == NULL || !IS_ELEM(e1) || !IS_ELEM(e2)) {
		ARG_MSG;
		return 0;
	}
	if (e1->term_rule != e2->term_rule ||
	    !ptrblock_eq(&e1->ntm_rules, &e2->ntm_rules)) {
		return 0;
	}
	return 1;
}

static inline hipac_error
elem_clone(struct dt_elem *e, struct dt_elem **clone)
{
	if (e == NULL || clone == NULL) {
		ARG_ERR;
	}

	*clone = hp_alloc(sizeof(*e) + e->ntm_rules.len *
			  sizeof(*e->ntm_rules.p), 1);
	if (*clone == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*clone, e, sizeof(*e) + e->ntm_rules.len *
	       sizeof(*e->ntm_rules.p));
	return HE_OK;
}

/* forward declaration */
static int 
rlp_eq_rec(const struct rlp_spec *spec1, const struct rlp_spec *spec2);

/* return 1 if g1 and g2 are equal and rules;
   return 2 if g1 and g2 are equal and elementary intervals;
   return 3 if g1 and g2 are equal and rlps;
   return 0 otherwise */
static inline int
rlp_rule_elem_eq(const struct gen_spec *g1, const struct gen_spec *g2)
{
	if (g1 == NULL || g2 == NULL ||
	    (IS_RULE(g1) && IS_RULE(g2))) {
		return g1 == g2;
	} else if (IS_ELEM(g1) && IS_ELEM(g2)) {
		struct dt_elem *e1 = (struct dt_elem *) g1;
		struct dt_elem *e2 = (struct dt_elem *) g2;

		if (e1->ntm_rules.len != e2->ntm_rules.len) {
			return 0;
		}
		return elem_eq(e1, e2) ? 2 : 0;
	} else if (IS_RLP(g1) && IS_RLP(g2)) {
		struct rlp_spec *b1 = (struct rlp_spec *) g1;
		struct rlp_spec *b2 = (struct rlp_spec *) g2;

		return (rlp_spec_eq(b1, b2) && rlp_eq_rec(b1, b2)) ? 3 : 0;
	}
	return 0;
}

/* insert rule into rule_elem which can be a rule or an elementary interval
   layer; the result which can be a rule or an elementary interval layer
   is directly written to rule_elem */
static inline hipac_error
rule_elem_insert(struct dt_rule_elem_spec **rule_elem, struct dt_rule *rule,
		 int newspec_set)
{
	int stat;

	if (unlikely(rule_elem == NULL || rule == NULL)) {
		ARG_ERR;
	}

	if (*rule_elem == NULL) {
		*rule_elem = (struct dt_rule_elem_spec *) rule;
		return HE_OK;
	}

	assert(IS_RULE(*rule_elem) || IS_ELEM(*rule_elem));
	assert(!IS_ELEM(*rule_elem) ||
	       ((struct dt_elem *) *rule_elem)->ntm_rules.len > 0);
	assert(!IS_ELEM(*rule_elem) ||
	       ((struct dt_elem *) *rule_elem)->term_rule != NULL ||
	       ((struct dt_elem *) *rule_elem)->ntm_rules.len > 1);

	if (IS_RULE(*rule_elem)) {
		struct dt_rule *r = (struct dt_rule *) *rule_elem;
		
		if (IS_RULE_TERM(rule) && IS_RULE_TERM(r)) {
			if (rule->spec.pos < r->spec.pos) {
				*rule_elem = (struct dt_rule_elem_spec *) rule;
			}
			return HE_OK;
		
		} else if (!IS_RULE_TERM(rule) && !IS_RULE_TERM(r)) {
			struct dt_rule *ntm[2];
			struct dt_elem *e;
			if (r->spec.pos < rule->spec.pos) {
				ntm[0] = r;
				ntm[1] = rule;
			} else {
				ntm[0] = rule;
				ntm[1] = r;
			}
			e = elem_new(NULL, ntm, sizeof(ntm) / sizeof(*ntm));
			if (e == NULL) {
				return HE_LOW_MEMORY;
			}
			stat = history_new((struct gen_spec *) e, newspec_set);
			if (stat < 0) {
				elem_free(e);
				return stat;
			}
			*rule_elem = (struct dt_rule_elem_spec *) e;
			return HE_OK;
			
		} else {
			struct dt_rule *term_rule, *ntm_rule;
			struct dt_elem *e;
			if (IS_RULE_TERM(rule)) {
				term_rule = rule;
				ntm_rule = r;
			} else {
				term_rule = r;
				ntm_rule = rule;
			}
			if (term_rule->spec.pos < ntm_rule->spec.pos) {
				*rule_elem = (struct dt_rule_elem_spec *)
					term_rule;
				return HE_OK;
			}
			e = elem_new(term_rule, &ntm_rule, 1);
			if (e == NULL) {
				return HE_LOW_MEMORY;
			}
			stat = history_new((struct gen_spec *) e, newspec_set);
			if (stat < 0) {
				elem_free(e);
				return stat;
			}
			*rule_elem = (struct dt_rule_elem_spec *) e;
			return HE_OK;
		}
	} else {
		/* IS_ELEM(*rule_elem) */
		struct dt_elem *e = (struct dt_elem *) *rule_elem;
		__u32 i;
		
		if (e->term_rule != NULL && 
		    rule->spec.pos > e->term_rule->spec.pos) {
			/* rule is never matched */
			return HE_OK;
		}
		if (IS_RULE_TERM(rule)) {
			/* find still matching rules if any */
			if (((struct dt_rule *) e->ntm_rules.p[0])->spec.pos >
			    rule->spec.pos) {
				stat = history_obsolete((struct gen_spec *) e,
							newspec_set);
				if (stat < 0) {
					return stat;
				}
				*rule_elem = (struct dt_rule_elem_spec *) rule;
				return HE_OK;
			}
			e->term_rule = rule;
			i = e->ntm_rules.len;
			do {
				i--;
				if (((struct dt_rule *)
				     e->ntm_rules.p[i])->spec.pos <
				    rule->spec.pos) {
					break;
				}
			} while (i > 0);
			assert(((struct dt_rule *)
				e->ntm_rules.p[i])->spec.pos < rule->spec.pos);
			if (i < e->ntm_rules.len - 1) {
				struct dt_elem *e2;
				e2 = hp_realloc(e, sizeof(*e) + (i + 1) *
						sizeof(*e->ntm_rules.p));
				if (e2 == NULL) {
					/* this should never happen as we
					   shrink e */
					return HE_LOW_MEMORY;
				}
				if (e != e2) {
					history_del_invalid(
						(struct gen_spec *) e);
					stat = history_new(
						(struct gen_spec *) e2,
						newspec_set);
					if (stat < 0) {
						elem_free(e2);
						return stat;
					}
				}
				e2->ntm_rules.len = i + 1;
				*rule_elem = (struct dt_rule_elem_spec *) e2;
			}
			return HE_OK;

		} else {
			/* !IS_RULE_TERM(rule) */
			for (i = 0; i < e->ntm_rules.len &&
				     ((struct dt_rule *)
				      e->ntm_rules.p[i])->spec.pos <
				     rule->spec.pos; i++);
			stat = ptrblock_insert_embed((void **) rule_elem,
						     offsetof(struct dt_elem,
							      ntm_rules),
						     rule, i);
			if (stat < 0) {
				return stat;
			}
			if (e != (struct dt_elem *) *rule_elem) {
				history_del_invalid((struct gen_spec *) e);
				stat = history_new((struct gen_spec *)
						   *rule_elem, newspec_set);
				if (stat < 0) {
					elem_free((struct dt_elem *)
						  *rule_elem);
					return stat;
				}
			}
			return HE_OK;
		}
	}
}

/* delete rule from rule_elem which can be a rule or an elementary interval
   layer; if rule is not contained in rule_elem nothing happens;
   the result which can be a rule or an elementary interval layer is directly
   written to rule_elem; term, right, wildcard and dimid must be given to
   find the next best rule(s) if necessary */
static inline hipac_error
rule_elem_delete(struct dt_rule_elem_spec **rule_elem,
		 const struct dt_rule *rule, const struct ptrblock *term,
		 __u32 right, __u8 wildcard, __u8 dimid, int newspec_set)
{
	int stat;

	if (unlikely(rule_elem == NULL || rule == NULL || term == NULL ||
		     right > MAXKEY(dim2btype[dimid]) ||
		     (wildcard && !HAS_WILDCARD_DIM(dimid)))) {
		ARG_ERR;
	}

	if (*rule_elem == NULL) {
		/* rule is not contained in rule_elem */
		return HE_OK;
	}

	assert(IS_RULE(*rule_elem) || IS_ELEM(*rule_elem));
	assert(!IS_ELEM(*rule_elem) ||
	       ((struct dt_elem *) *rule_elem)->ntm_rules.len > 0);
	assert(!IS_ELEM(*rule_elem) ||
	       ((struct dt_elem *) *rule_elem)->term_rule != NULL ||
	       ((struct dt_elem *) *rule_elem)->ntm_rules.len > 1);

	if (IS_RULE(*rule_elem)) {
		struct dt_rule *r = (struct dt_rule *) *rule_elem;
		struct dt_rule *term_rule, *ntm_rule = NULL;
		__u32 ntm_num;

		if (r != rule) {
			/* rule is not contained in rule_elem */
			return HE_OK;
		}

		/* in fact it would suffice to call termrule_find_best_term
		   only if IS_RULE_TERM(r) */
		term_rule = termrule_find_best_term(term, rule, right,
						    wildcard, dimid);
		ntm_num = termrule_num_ntm(&ntm_rule, term, term_rule, rule,
					   right, wildcard, dimid);
		if (term_rule == NULL && ntm_num <= 1) {
			*rule_elem = (struct dt_rule_elem_spec *) ntm_rule;
			return HE_OK;
		} else if (term_rule != NULL && ntm_num == 0) {
			*rule_elem = (struct dt_rule_elem_spec *) term_rule;
			return HE_OK;
		} else {
			struct dt_elem *e = elem_new_empty(term_rule);
			if (e == NULL) {
				return HE_LOW_MEMORY;
			}
			stat = termrule_insert_ntm(&e, term, NULL, term_rule,
						   rule, right, wildcard,
						   dimid);
			if (stat < 0) {
				hp_free(e);
				return stat;
			}
			assert(e->ntm_rules.len > 0);
			stat = history_new((struct gen_spec *) e, newspec_set);
			if (stat < 0) {
				elem_free(e);
				return stat;
			}
			*rule_elem = (struct dt_rule_elem_spec *) e;
			return HE_OK;
		}
	} else {
		/* IS_ELEM(*rule_elem) */
		struct dt_elem *e = (struct dt_elem *) *rule_elem;
		__u32 i;
		
		if (e->term_rule == rule) {
			struct dt_rule *term_rule;
			term_rule = termrule_find_best_term(
				term, rule, right, wildcard, dimid);
			stat = termrule_insert_ntm(
				(struct dt_elem **) rule_elem, term,
				e->ntm_rules.p[e->ntm_rules.len - 1],
				term_rule, rule, right, wildcard, dimid);
			if (stat < 0) {
				/* we only care about rule_elem if its address
				   has changed; otherwise rule_elem is 
				   handled by the history */
				if (e != (struct dt_elem *) *rule_elem) {
					history_del_invalid((struct gen_spec *)
							    e);
					elem_free((struct dt_elem *)
						  *rule_elem);
				}
				return stat;
			}
			if (e != (struct dt_elem *) *rule_elem) {
				history_del_invalid((struct gen_spec *) e);
				stat = history_new((struct gen_spec *)
						   *rule_elem, newspec_set);
				if (stat < 0) {
					elem_free((struct dt_elem *)
						  *rule_elem);
					return stat;
				}
			}
			e = (struct dt_elem *) *rule_elem;
			if (term_rule == NULL && e->ntm_rules.len == 1) {
				struct dt_rule_elem_spec *ntm =
					e->ntm_rules.p[0];
				stat = history_obsolete((struct gen_spec *) e,
							newspec_set);
				if (stat < 0) {
					return stat;
				}
				*rule_elem = ntm;
				return HE_OK;
			}
			e->term_rule = term_rule;
			return HE_OK;
		} else {
			for (i = 0; i < e->ntm_rules.len &&
				     ((struct dt_rule *)
				      e->ntm_rules.p[i])->spec.pos <
				     rule->spec.pos; i++);
			if (i >= e->ntm_rules.len ||
			    e->ntm_rules.p[i] != rule) {
				/* rule is not contained in rule_elem */
				return HE_OK;
			}
			if (e->ntm_rules.len == 1) {
				struct dt_rule_elem_spec *tm =
					(struct dt_rule_elem_spec *)
					e->term_rule;
				stat = history_obsolete((struct gen_spec *) e,
							newspec_set);
				if (stat < 0) {
					return stat;
				}
				*rule_elem = tm;
				return HE_OK;
			} else if (e->term_rule == NULL &&
				   e->ntm_rules.len == 2) {
				struct dt_rule_elem_spec *ntm =
					(struct dt_rule_elem_spec *)
					e->ntm_rules.p[(i + 1) % 2];
				stat = history_obsolete((struct gen_spec *) e,
							newspec_set);
				if (stat < 0) {
					return stat;
				}
				*rule_elem = ntm;
				return HE_OK;
			} else {
				stat = ptrblock_delete_pos_embed(
					(void **) rule_elem,
					offsetof(struct dt_elem, ntm_rules),
					i);
				if (stat < 0) {
					return stat;
				}
				if (e != (struct dt_elem *) *rule_elem) {
					history_del_invalid(
						(struct gen_spec *) e);
					stat = history_new((struct gen_spec *)
							   *rule_elem,
							   newspec_set);
					if (stat < 0) {
						elem_free((struct dt_elem *)
							  *rule_elem);
						return stat;
					}
				}
				return HE_OK;
			}
		}
	}
}



/*
 * recursive rlp operations
 */

/* necessary forward declaration */
static hipac_error
rlp_clone_rec(const struct rlp_spec *spec, struct rlp_spec **clone,
	      int newspec_set);

static inline hipac_error
rlp_clone_help(struct gen_spec **g, int newspec_set)
{
	int stat = HE_OK;

	if (*g == NULL) {
		return HE_OK;
	}
	if (IS_RLP(*g)) {
		stat = rlp_clone_rec((struct rlp_spec *) *g,
				     (struct rlp_spec **) g,
				     newspec_set);
		if (stat < 0) {
			return stat;
		}
	} else if (IS_ELEM(*g)) {
		struct dt_elem *clone;
		stat = elem_clone((struct dt_elem *) *g, &clone);
		if (stat < 0) {
			return stat;
		}
		stat = history_new((struct gen_spec *) clone,
				   newspec_set);
		if (stat < 0) {
			elem_free(clone);
			return stat;
		}
		*g = (struct gen_spec *) clone;
	}
	return HE_OK;
}

/* clone spec including the elementary interval layers recursively and call
   history_new for each clone;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
static hipac_error
rlp_clone_rec(const struct rlp_spec *spec, struct rlp_spec **clone,
	      int newspec_set)
{
	struct gen_spec **nextspec = NULL;
	__u32 size;
	int stat;
	__u16 n;
       
	if (unlikely(spec == NULL || clone == NULL)) {
		ARG_ERR;
	}
	
	size = rlp_size(spec);
	*clone = hp_alloc(size, 1);
	if (*clone == NULL) {
		return HE_LOW_MEMORY;
	}
	
	memcpy(*clone, spec, size);
	stat = ptrblock_clone(*termrule(spec), termrule(*clone));
	if (stat < 0) {
		hp_free(*clone);
		return stat;
	}
	
	stat = history_new((struct gen_spec *) *clone, newspec_set);
	if (stat < 0) {
		hp_free(*termrule(*clone));
		hp_free(*clone);
		return stat;
	}
	
	nextspec = rlp_nextspec(*clone);
	assert(nextspec != NULL);
	
	for (n = 0; n < (*clone)->num; n++) {
		stat = rlp_clone_help(nextspec + n, newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	
	if (HAS_WILDCARD_SPEC(*clone)) {
		stat = rlp_clone_help(WILDCARD(*clone), newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

/* necessary forward declaration */
static hipac_error
rlp_free_rec(struct rlp_spec *spec, int newspec_set, int direct_free);

static inline hipac_error
rlp_free_help(struct gen_spec *g, int newspec_set, int direct_free)
{
	int stat;

	if (g == NULL) {
		return HE_OK;
	}
	if (IS_RLP(g)) {
		stat = rlp_free_rec((struct rlp_spec *) g, newspec_set,
				    direct_free);
		if (stat < 0) {
			return stat;
		}
	} else if (IS_ELEM(g)) {
		if (direct_free) {
			rlp_elem_free(g);
		} else {
			stat = history_obsolete(g, newspec_set);
			if (stat < 0) {
				return stat;
			}
		}
	}
	return HE_OK;
}

/* 'free' spec including the elementary interval layers recursively;
   if direct_free is 0 'free' means to call history_obsolete for each element;
   otherwise the elements are directly freed by rlp_elem_free;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
static hipac_error
rlp_free_rec(struct rlp_spec *spec, int newspec_set, int direct_free)
{
	struct gen_spec **nextspec = NULL;
	int stat;
	__u16 n;
	
	if (unlikely(spec == NULL)) {
		ARG_ERR;
	}
	
	nextspec = rlp_nextspec(spec);
	assert(nextspec != NULL);
	
	for (n = 0; n < spec->num; n++) {
		stat = rlp_free_help(*(nextspec + n), newspec_set,
				     direct_free);
		if (stat < 0) {
			return stat;
		}
	}

	if (HAS_WILDCARD_SPEC(spec)) {
		stat = rlp_free_help(*WILDCARD(spec), newspec_set,
				     direct_free);
		if (stat < 0) {
			return stat;
		}
	}

	if (direct_free) {
		rlp_elem_free((struct gen_spec *) spec);
		return HE_OK;
	}
	return history_obsolete((struct gen_spec *) spec, newspec_set);
}

/* return 1 if spec1 and spec2 are recursively equal; the headers spec1 and
   spec2 are assumed to be equal */
static int
rlp_eq_rec(const struct rlp_spec *spec1, const struct rlp_spec *spec2)
{
	struct gen_spec **nextspec1 = NULL, **nextspec2 = NULL;
	__u16 n;
	
	if (unlikely(spec1 == NULL || spec2 == NULL)) {
		ARG_ERR;
	}

	assert(IS_RLP(spec1));
	assert(IS_RLP(spec2));
	assert(rlp_spec_eq(spec1, spec2));

	if (!ptrblock_eq(*termrule(spec1), *termrule(spec2))) {
		return 0;
	}
	nextspec1 = rlp_nextspec(spec1);
	assert(nextspec1 != NULL);
	nextspec2 = rlp_nextspec(spec2);
	assert(nextspec2 != NULL);

	/* we don't need to compare the keys of spec1 and spec2 because for
	   each corresponding rlp pair the termrule blocks are compared
	   which means that if rlp_eq_rec finally returns 1 the same rules
	   terminate in the subtree rooted by the top level rlp spec1 and in
	   the subtree rooted by the top level rlp spec2; since all leaves
	   of the subtrees are terminal (NULL, rule or elementary interval
	   layer) we can conclude that there is no other rule except those in
	   the termrule blocks that have created keys in the rlps */
	for (n = 0; n < spec1->num; n++) {
		if (!rlp_rule_elem_eq(*(nextspec1 + n), *(nextspec2 + n))) {
			return 0;
		}
	}

	if (HAS_WILDCARD_SPEC(spec1) &&
	    !rlp_rule_elem_eq(*WILDCARD(spec1), *WILDCARD(spec2))) {
		return 0;
	}
	return 1;
}



/*
 * internal dimtree operations
 */

static inline hipac_error
rlp_clone_ifneeded(struct rlp_spec *b, struct rlp_spec **newb,
		     int newspec_set)
{
	int stat;

	if (unlikely(b == NULL || newb == NULL)) {
		ARG_ERR;
	}

	if (b->newspec == 0) {
		/* we must clone because b is visible for packet matching */
		stat = rlp_clone(b, newb);
		if (stat < 0) {
			return stat;
		}
		stat = history_replace((struct gen_spec *) b,
				       (struct gen_spec *) *newb, newspec_set);
		if (stat < 0) {
			rlp_free(*newb);
			return stat;
		}
	} else {
		/* b can be modified directly */
		*newb = b;
	}
	return HE_OK;
}

static inline hipac_error
elem_clone_ifneeded(struct dt_elem *e, struct dt_elem **newe,
		    int newspec_set)
{
	int stat;

	if (unlikely(e == NULL || newe == NULL)) {
		ARG_ERR;
	}

	if (e->spec.newspec == 0) {
		/* we must clone because e is visible for packet matching */
		stat = elem_clone(e, newe);
		if (stat < 0) {
			return stat;
		}
		stat = history_replace((struct gen_spec *) e,
				       (struct gen_spec *) *newe, newspec_set);
		if (stat < 0) {
			elem_free(*newe);
			return stat;
		}
	} else {
		/* e can be modified directly */
		*newe = e;
	}
	return HE_OK;
}

#ifdef DEBUG
static void
print_elem(struct dt_elem *e)
{
	int i;

	DPRINT(DEBUG_DIMTREE, "term_rule: %p, ntm_rules:", e->term_rule);
	if (e->ntm_rules.len == 0) {
		DPRINT(DEBUG_DIMTREE, " <none> => BUG");
		return;
	}
	for (i = 0; i < e->ntm_rules.len; i++) {
		DPRINT(DEBUG_DIMTREE, " %p", e->ntm_rules.p[i]);
	}
}

static void
print_rlp(struct rlp_spec *rlp)
{
	__u32 key = 0;
	struct locate_inf inf;
	int i;

	if (rlp == NULL) {
		DPRINT(DEBUG_DIMTREE, "rlp: %p (this might not be what you "
		       "expected)\n", rlp);
		return;
	}
	if (!IS_RLP(rlp)) {
		DPRINT(DEBUG_DIMTREE, "rlp: %p is __NOT__ a rlp => FATAL "
		       "ERROR\n", rlp);
		return;
	}
	DPRINT(DEBUG_DIMTREE, "rlp: %p  -  bittype: %d, dimid: %d, "
	       "newspec: %d, num: %d\n", rlp, rlp->bittype, rlp->dimid,
	       rlp->newspec, rlp->num);
	DPRINT(DEBUG_DIMTREE, "   content:");
	if (HAS_WILDCARD_DIM(rlp->dimid)) {
		if (*WILDCARD(rlp) != NULL && IS_RULE(*WILDCARD(rlp))) {
			DPRINT(DEBUG_DIMTREE, " (wc, %p: rule)",
			       *WILDCARD(rlp));
		} else if (*WILDCARD(rlp) != NULL && IS_ELEM(*WILDCARD(rlp))) {
			DPRINT(DEBUG_DIMTREE, " (wc, %p: ", *WILDCARD(rlp));
			print_elem((struct dt_elem *) *WILDCARD(rlp));
			DPRINT(DEBUG_DIMTREE, ")");
		} else {
			DPRINT(DEBUG_DIMTREE, " (wc, %p)", *WILDCARD(rlp));
		}
	}
	do {
		if (rlp_locate(rlp, &inf, key) < 0) {
			DPRINT(DEBUG_DIMTREE, "\n%s: no memory for locate "
			       "info\n", __FUNCTION__);
			return;
		}
		if (*inf.nextspec != NULL && IS_RULE(*inf.nextspec)) {
			DPRINT(DEBUG_DIMTREE, " (%u, %p: rule)", inf.key,
			       *inf.nextspec);
		} else if (*inf.nextspec != NULL && 
			   IS_ELEM(*inf.nextspec)) {
			DPRINT(DEBUG_DIMTREE, " (%u, %p: ", inf.key,
			       *inf.nextspec);
			print_elem((struct dt_elem *) *inf.nextspec);
			DPRINT(DEBUG_DIMTREE, ")");
		} else {
			DPRINT(DEBUG_DIMTREE, " (%u, %p)", inf.key,
			       *inf.nextspec);
		}
		key = inf.key + 1;
	} while (inf.key < MAXKEY(dim2btype[rlp->dimid]));
	DPRINT(DEBUG_DIMTREE, "\n   term:");
	if (*termrule(rlp) == NULL) {
		DPRINT(DEBUG_DIMTREE, " <empty>\n");
	} else {
		for (i = 0; i < (*termrule(rlp))->len; i++) {
			DPRINT(DEBUG_DIMTREE, " %p", (*termrule(rlp))->p[i]);
		}
		DPRINT(DEBUG_DIMTREE, "\n");
	}
}
#endif

static inline hipac_error
segment_insert_help(struct locate_inf *inf, __u8 *ins_num,
		    struct gen_spec* new_nextspec[], int newspec_set)
{
	int stat;

	if (*inf->nextspec == NULL || IS_RULE(*inf->nextspec)) {
		new_nextspec[*ins_num] = *inf->nextspec;
	} else if (IS_ELEM(*inf->nextspec)) {
		struct dt_elem *e;
		stat = elem_clone((struct dt_elem *) *inf->nextspec, &e);
		if (stat < 0) {
			return stat;
		}
		stat = history_new((struct gen_spec *) e, newspec_set);
		if (stat < 0) {
			elem_free(e);
			return stat;
		}
		new_nextspec[*ins_num] = (struct gen_spec *) e;
	} else {
		assert(IS_RLP(*inf->nextspec));
		stat = rlp_clone_rec(
			(struct rlp_spec *) *inf->nextspec,
			(struct rlp_spec **) &new_nextspec[*ins_num],
			newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	(*ins_num)++;
	return HE_OK;
}

/* segment [left, right] is inserted into spec which causes at most two new
   elementary intervals being created; for every new elementary interval
   the neighbour interval is cloned recursively */
static inline hipac_error
segment_insert(struct rlp_spec **spec, __u32 left, __u32 right,
	       int newspec_set)
{  	
	__u8 ins_num = 0;
	struct gen_spec* new_nextspec[2];
	struct locate_inf inf;
	__u32 new_key[2];
	int stat;

	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: left: %u, right: %u, newspec_set: %d\n",
	       __FUNCTION__, left, right, newspec_set);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if (left > 0) {
		stat = rlp_locate(*spec, &inf, left - 1);
		if (stat < 0) {
			return stat;
		}
		if (inf.key != left - 1) {
			new_key[ins_num] = left - 1;
			stat = segment_insert_help(&inf, &ins_num,
						   new_nextspec, newspec_set);
			if (stat < 0) {
				return stat;
			}
		}
	}
	
	stat = rlp_locate(*spec, &inf, right);
	if (stat < 0) {
		return stat;
	}
	if (inf.key != right) {
		new_key[ins_num] = right;
		stat = segment_insert_help(&inf, &ins_num, new_nextspec,
					   newspec_set);
		if (stat < 0) {
			return stat;
		}
	}

	if (ins_num > 0) {
		struct rlp_spec *b;
		assert(ins_num == 1 || new_key[0] != new_key[1]);
		if (ins_num == 1) {
			DPRINT(DEBUG_DIMTREE, "new key: %u\n", new_key[0]);
		} else {
			DPRINT(DEBUG_DIMTREE, "new keys: %u, %u\n", new_key[0],
			       new_key[1]);
		}
		stat = rlp_insert(*spec, ins_num, new_key, new_nextspec, &b);
		if (stat < 0) {
			return stat;
		}
		stat = history_replace((struct gen_spec *) *spec,
				       (struct gen_spec *) b, newspec_set);
		if (stat < 0) {
			rlp_free(b);
			return stat;
		}
		*spec = b;
#ifdef DEBUG
		print_rlp(*spec);
#endif
	} else {
		/* we clone the rlp anyway if necessary */
		struct rlp_spec *b;
		stat = rlp_clone_ifneeded(*spec, &b, newspec_set);
		if (stat < 0) {
			return stat;
		}
		*spec = b;
	}
	return HE_OK;
}

/* forward declaration */
static hipac_error
dimtree_insrec(struct rlp_spec **spec, struct dt_rule *rule,
	       __u8 match_num, int newspec_set);

static hipac_error
dimtree_insrec_null(struct rlp_spec **spec, struct dt_rule *rule,
		    __u8 match_num, int newspec_set)
{
	const struct dt_match *match = ITH_DT_MATCH(rule, match_num);
	__u8 bittype = dim2btype[match->dimid];
	struct gen_spec *nextspec[] = {NULL};
	__u32 key = MAXKEY(bittype);
	struct locate_inf inf;
	int stat;

	/* create new rlp that defaults to policy and insert match
	   recursively */
	assert(spec != NULL && *spec == NULL);
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, match: "
	       "(dimid: %d, left: %u, right: %u)\n", __FUNCTION__, match_num,
	       newspec_set, match->dimid, match->left, match->right);
	DPRINT(DEBUG_DIMTREE, "%s: new rlp: bittype: %d, dimid: %d, key: "
	       "%u, nextspec: %p\n", __FUNCTION__, bittype, match->dimid, key,
	       *nextspec);
	*spec = rlp_new(bittype, match->dimid, 1, &key, nextspec);
	if (*spec == NULL) {
		return HE_LOW_MEMORY;
	}
	stat = history_new((struct gen_spec *) *spec, newspec_set);
	if (stat < 0) {
		rlp_free(*spec);
		return stat;
	}

	/* match must be non-wildcard */
	assert(match->left > 0 || match->right < MAXKEY((*spec)->bittype));
	stat = segment_insert(spec, match->left, match->right, newspec_set);
	if (stat < 0) {
		return stat;
	}
	stat = rlp_locate(*spec, &inf, match->right);
	if (stat < 0) {
		return stat;
	}
	if (match_num == rule->dt_match_len - 1) {
		/* final match of rule -> insert rule into termrule block */
		struct ptrblock **term = termrule(*spec);
		stat = termrule_insert(term, rule);
		if (stat < 0) {
			return stat;
		}
		*inf.nextspec = (struct gen_spec *) rule;
	} else {
		/* before final match -> insert next match by recursion */
		stat = dimtree_insrec_null((struct rlp_spec **)
					   inf.nextspec, rule, match_num + 1,
					   newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_insrec_rule_elem(struct dt_rule_elem_spec **spec, struct dt_rule *rule,
			 __u8 match_num, struct ptrblock *term_prop,
			 int newspec_set)
{
	struct dt_match *match = ITH_DT_MATCH(rule, match_num);
	__u8 bittype = dim2btype[match->dimid];
	__u32 key = MAXKEY(bittype);
	struct gen_spec *nextspec[1];
	struct rlp_spec *newspec;
	struct ptrblock **term;
	struct locate_inf inf;
	int stat;

	assert(spec != NULL);
	assert(*spec != NULL);
	assert(IS_RULE(*spec) || IS_ELEM(*spec));
	assert(match->left > 0 || match->right < MAXKEY(bittype));

	/* create new rlp and insert match recursively; term_prop propagates
	   through all dimension while remaining in each dimension as
	   termrule block; if anything goes wrong before term_prop is
	   attached to newspec term_prop will be freed; later it is treated
	   by the history */
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, match: "
	       "(dimid: %d, left: %u, right: %u)\n", __FUNCTION__, match_num,
	       newspec_set, match->dimid, match->left, match->right);
	if (HAS_WILDCARD_DIM(match->dimid)) {
		nextspec[0] = NULL;
		DPRINT(DEBUG_DIMTREE, "%s: new rlp: bittype: %d, dimid: %d,"
		       " key: %u, nextspec: %p\n", __FUNCTION__, bittype,
		       match->dimid, key, *nextspec);
		newspec = rlp_new(bittype, match->dimid, 1, &key, nextspec);
		if (newspec == NULL) {
			if (term_prop != NULL) {
				ptrblock_free(term_prop);
			}
			return HE_LOW_MEMORY;
		}
		*WILDCARD(newspec) = (struct gen_spec *) *spec;
	} else {
		nextspec[0] = (struct gen_spec *) *spec;
		DPRINT(DEBUG_DIMTREE, "%s: new rlp: bittype: %d, dimid: %d,"
		       " key: %u, nextspec: %p\n", __FUNCTION__, bittype,
		       match->dimid, key, *nextspec);
		newspec = rlp_new(bittype, match->dimid, 1, &key, nextspec);
		if (newspec == NULL) {
			if (term_prop != NULL) {
				ptrblock_free(term_prop);
			}
			return HE_LOW_MEMORY;
		}
	}
	stat = history_new((struct gen_spec *) newspec, newspec_set);
	if (stat < 0) {
		rlp_free(newspec);
		if (term_prop != NULL) {
			ptrblock_free(term_prop);
		}
		return stat;
	}
	stat = segment_insert(&newspec, match->left, match->right,
			      newspec_set);
	if (stat < 0) {
		if (term_prop != NULL) {
			ptrblock_free(term_prop);
		}
		return stat;
	}
	/* attach term_prop to newspec -> if anything goes wrong from now on
	   term_prop must not be freed here */
	term = termrule(newspec);
	*term = term_prop;
	stat = rlp_locate(newspec, &inf, match->right);
	if (stat < 0) {
		return stat;
	}
       
	if (match_num == rule->dt_match_len - 1) {
		/* final match of rule -> insert rule into termrule block */
		stat = termrule_insert(term, rule);
		if (stat < 0) {
			return stat;
		}
		if (HAS_WILDCARD_DIM(match->dimid)) {
			assert(*inf.nextspec == NULL);
			*inf.nextspec = (struct gen_spec *) rule;
		} else {
			stat = rule_elem_insert((struct dt_rule_elem_spec **)
						inf.nextspec, rule,
						newspec_set);
			if (stat < 0) {
				return stat;
			}
		}
	} else {
		/* before final match -> insert next match by recursion */
		if (*inf.nextspec == NULL) {
                        stat = dimtree_insrec_null((struct rlp_spec **)
						   inf.nextspec, rule,
						   match_num + 1, newspec_set);
			if (stat < 0) {
				return stat;
			}
                } else {
			struct ptrblock *term_prop_clone = NULL;
			if (term_prop != NULL) {
				stat = ptrblock_clone(term_prop,
						      &term_prop_clone);
				if (stat < 0) {
					return stat;
				}
			}
			stat = dimtree_insrec_rule_elem(
				(struct dt_rule_elem_spec **) inf.nextspec,
				rule, match_num + 1, term_prop_clone,
				newspec_set);
			if (stat < 0) {
				return stat;
			}
		}
	}
	/* newspec is a rlp (not struct dt_rule_elem_spec *); the cast is
	   anyway necessary because of spec */
	*spec = (struct dt_rule_elem_spec *) newspec;
	return HE_OK;
}

static inline hipac_error
dimtree_insrec_curdimid_sm_help(struct rlp_spec *spec, struct gen_spec **g,
				struct dt_rule *rule, __u8 match_num,
				__u32 right, __u8 wildcard, int newspec_set,
				int do_cut)
{
	int stat;

	if (*g == NULL) {
		/* insert rule into policy interval */
		stat = dimtree_insrec_null((struct rlp_spec **) g, rule,
					   match_num, newspec_set);
		if (stat < 0) {
			return stat;
		}
	} else if (IS_RLP(*g)) {
		/* non-terminal case */
		struct rlp_spec *b = (struct rlp_spec *) *g;

		/* we don't have to clone if dimtree_insrec_curdimid_eq is
		   called by dimtree_insrec because segment_insert clones
		   the rlp anyway if necessary */
		if ((b->dimid != ITH_DT_MATCH(rule, match_num)->dimid)) {
			stat = rlp_clone_ifneeded(b, &b, newspec_set);
			if (stat < 0) {
				return stat;
			}
		}
		stat = dimtree_insrec(&b, rule, match_num, newspec_set);
		if (stat < 0) {
			return stat;
		}
		*g = (struct gen_spec *) b;
	} else {
		/* the rules that terminate in g will propagate to termrule
		   blocks in below dimensions */
		struct dt_rule_elem_spec **re;
		struct ptrblock *term_prop;
		assert(IS_ELEM(*g) || IS_RULE(*g));
		stat = termrule_subset(*termrule(spec), &term_prop, right,
				       wildcard, spec->dimid);
		if (stat < 0) {
			return stat;
		}
		if (do_cut && *termrule(spec) != NULL && term_prop != NULL) {
			/* remove all rules in term_prop from current
			   termrule block */
			stat = termrule_cut(termrule(spec), term_prop);
			if (stat < 0) {
				ptrblock_free(term_prop);
				return stat;
			}
		}

		re = (struct dt_rule_elem_spec **) g;
		if (IS_ELEM(*re)) {
			struct dt_elem *e;
			stat = elem_clone_ifneeded((struct dt_elem *) *re, &e,
						   newspec_set);
			if (stat < 0) {
				if (term_prop != NULL) {
					ptrblock_free(term_prop);
				}
				return stat;
			}
			*re = (struct dt_rule_elem_spec *) e;
		}
		stat = dimtree_insrec_rule_elem(re, rule, match_num,
						term_prop, newspec_set);
		if (stat < 0) {
			/* term_prop was freed by
			   dimtree_insrec_rule_elem */
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_insrec_curdimid_sm(struct rlp_spec **spec, struct dt_rule *rule,
			   __u8 match_num, int newspec_set)
{
	__u32 key = 0;
	__u32 maxkey = MAXKEY((*spec)->bittype);
	struct locate_inf inf;
	int stat;

	assert(spec != NULL);
	assert(*spec != NULL);
	assert(IS_RLP(*spec));
	assert(match_num < rule->dt_match_len);
	/* insert it into every elementary interval respectively the wildcard
	   pointer */
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d\n",
	       __FUNCTION__, match_num, newspec_set);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if (HAS_WILDCARD_SPEC(*spec)) {
		return dimtree_insrec_curdimid_sm_help(
			*spec, WILDCARD(*spec), rule, match_num, 0, 1,
			newspec_set, 1);
	}

	do {
		stat = rlp_locate(*spec, &inf, key);
		if (stat < 0) {
			return stat;
		}
		key  = inf.key + 1;
		stat = dimtree_insrec_curdimid_sm_help(
			*spec, inf.nextspec, rule, match_num, inf.key, 0,
			newspec_set, 0);
		if (stat < 0) {
			return stat;
		}
	} while (inf.key < maxkey);
	
	if (*termrule(*spec) != NULL) {
		/* by inserting rule into every elementary interval the
		   dimension becomes completely nonterminating */
		ptrblock_free(*termrule(*spec));
		*termrule(*spec) = NULL;
	}
	return HE_OK;
}

/* necessary forward declaration */
static hipac_error
dimtree_insrec_curdimid_eq_tm(struct rlp_spec **spec, struct dt_rule *rule,
			      __u32 left, __u32 right, int newspec_set);

static inline hipac_error
dimtree_insrec_curdimid_eq_tm_help(struct gen_spec **g, struct dt_rule *rule,
				   struct ptrblock **term, __u8 *ins_termrule,
				   int newspec_set)
{
	int stat;

	if (*g != NULL && IS_RLP(*g)) {
		/* non-terminal case */
		struct rlp_spec *b;

		stat = rlp_clone_ifneeded((struct rlp_spec *) *g, &b,
					  newspec_set);
		if (stat < 0) {
			return stat;
		}
		stat = dimtree_insrec_curdimid_eq_tm(
			&b, rule, 0, MAXKEY(b->bittype), newspec_set);
		if (stat < 0) {
			return stat;
		}
		*g = (struct gen_spec *) b;
	} else {
		/* beyond final match of rule -> insert rule into
		   termrule block if not already inserted */
		struct dt_rule_elem_spec **re;
		if (*ins_termrule) {
			stat = termrule_insert(term, rule);
			if (stat < 0) {
				return stat;
			}
			*ins_termrule = 0;
		}
		
		re = (struct dt_rule_elem_spec **) g;
		if (*re != NULL && IS_ELEM(*re)) {
			struct dt_elem *e;
			stat = elem_clone_ifneeded((struct dt_elem *) *re, &e,
						   newspec_set);
			if (stat < 0) {
				return stat;
			}
			*re = (struct dt_rule_elem_spec *) e;
		}
		stat = rule_elem_insert(re, rule, newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_insrec_curdimid_eq_tm(struct rlp_spec **spec, struct dt_rule *rule,
			      __u32 left, __u32 right, int newspec_set)
{
	__u8 ins_termrule = 1;
	struct ptrblock **term = termrule(*spec);
	struct locate_inf inf;
	__u32 key = left;
	int stat;

	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: left: %u, right: %u, newspec_set: %d\n",
	       __FUNCTION__, left, right, newspec_set);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if (HAS_WILDCARD_SPEC(*spec) && left == 0 &&
	    right == MAXKEY((*spec)->bittype)) {
		/* insert wildcard match into wildcard dimension */
		return dimtree_insrec_curdimid_eq_tm_help(
			WILDCARD(*spec), rule, term, &ins_termrule,
			newspec_set);
	}

	/* iterate over every elementary interval between left and right
	   and check if rule is better than the current or recurse if
	   elementary interval is non-terminating */
	do {
		stat = rlp_locate(*spec, &inf, key);
		if (stat < 0) {
			return stat;
		}
		key  = inf.key + 1;
		stat = dimtree_insrec_curdimid_eq_tm_help(
			inf.nextspec, rule, term, &ins_termrule,
			newspec_set);
		if (stat < 0) {
			return stat;
		}
	} while (inf.key < right);
	return HE_OK;
}

static hipac_error
dimtree_insrec_curdimid_eq(struct rlp_spec **spec, struct dt_rule *rule,
			   const struct dt_match *match, __u8 match_num,
			   int newspec_set)
{
	__u32 key = match->left;
	struct locate_inf inf;
	int stat;

	/* match must be non-wildcard */
	assert(match->left > 0 || match->right < MAXKEY((*spec)->bittype));
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, match: "
	       "(dimid: %d, left: %u, right: %u)\n", __FUNCTION__, match_num,
	       newspec_set, match->dimid, match->left, match->right);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	stat = segment_insert(spec, match->left, match->right, newspec_set);
	if (stat < 0) {
		return stat;
	}

	/* insert match and iterate over every overlapped interval */
	if (match_num == rule->dt_match_len - 1) {
		/* final match of rule */
		stat = dimtree_insrec_curdimid_eq_tm(
			spec, rule, match->left, match->right, newspec_set);
		if (stat < 0) {
			return stat;
		}
	} else {
		/* before final match of rule */
		do {
			stat = rlp_locate(*spec, &inf, key);
			if (stat < 0) {
				return stat;
			}
			key = inf.key + 1;
			
			if (*inf.nextspec == NULL) {
				/* insert rule into policy interval */
				stat = dimtree_insrec_null(
					(struct rlp_spec **) inf.nextspec,
					rule, match_num + 1, newspec_set);
				if (stat < 0) {
					return stat;
				}
			} else if (IS_RLP(*inf.nextspec)) {
				/* non-terminal case */
				struct rlp_spec *b = (struct rlp_spec *)
					*inf.nextspec;
				
				/* we don't have to clone if
				   dimtree_insrec_curdimid_eq is called by
				   dimtree_insrec because segment_insert
				   clones the rlp anyway if necessary */
				if (b->dimid !=
				    ITH_DT_MATCH(rule, match_num + 1)->dimid) {
					stat = rlp_clone_ifneeded(
						(struct rlp_spec *)
						*inf.nextspec, &b,
						newspec_set);
					if (stat < 0) {
						return stat;
					}
				}
				stat = dimtree_insrec(
					&b, rule, match_num + 1, newspec_set);
				if (stat < 0) {
					return stat;
				}
				*inf.nextspec = (struct gen_spec *) b;
			} else {
				/* the rules that terminate in the current
				   elementary interval will propagate to
				   termrule blocks in below dimensions */
				struct dt_rule_elem_spec **re;
				struct ptrblock *term_prop;
				stat = termrule_subset(
					*termrule(*spec), &term_prop, inf.key,
					0, (*spec)->dimid);
				if (stat < 0) {
					if (term_prop != NULL) {
						ptrblock_free(term_prop);
					}
					return stat;
				}
				re = (struct dt_rule_elem_spec **)
					inf.nextspec;
				if (IS_ELEM(*re)) {
					struct dt_elem *e;
					stat = elem_clone_ifneeded(
						(struct dt_elem *) *re, &e,
						newspec_set);
					if (stat < 0) {
						if (term_prop != NULL) {
							ptrblock_free(
							      term_prop);
						}
						return stat;
					}
					*re = (struct dt_rule_elem_spec *) e;
				}
				stat = dimtree_insrec_rule_elem(
					re, rule, match_num + 1, term_prop,
					newspec_set);
				if (stat < 0) {
					/* term_prop was freed by
					   dimtree_insrec_rule_elem */
					return stat;
				}
			}
		} while (inf.key < match->right);

		/* as the rule continues we can be sure that every terminating
		   rule whose match in the current dimension is completely
		   overlapped by match can be removed from the termrule block;
		   we possibly forget to remove rules with partially overlapped
		   matches but this does NOT cause any harm and the case should
		   be very rare */
		stat = termrule_delete_ovl(termrule(*spec), match->left,
					   match->right, (*spec)->dimid);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_insrec_curdimid_gr(struct rlp_spec **spec, struct dt_rule *rule,
			   const struct dt_match *match, __u8 match_num,
			   int newspec_set)
{
	__u8 bittype = dim2btype[match->dimid];
	__u32 key = MAXKEY(bittype);	
	struct gen_spec *nextspec[1];
	struct rlp_spec *newspec;
	int stat;

	/* create missing dimension and insert current match by recursion */
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, match: "
	       "(dimid: %d, left: %u, right: %u)\n", __FUNCTION__, match_num,
	       newspec_set, match->dimid, match->left, match->right);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if (HAS_WILDCARD_DIM(match->dimid)) {
		nextspec[0] = NULL;
		DPRINT(DEBUG_DIMTREE, "%s: new rlp: bittype: %d, dimid: %d,"
		       " key: %u, nextspec: %p\n", __FUNCTION__, bittype,
		       match->dimid, key, *nextspec);
		newspec = rlp_new(bittype, match->dimid, 1, &key, nextspec);
		if (newspec == NULL) {
			return HE_LOW_MEMORY;
		}
		*WILDCARD(newspec) = (struct gen_spec *) *spec;
	} else {
		nextspec[0] = (struct gen_spec *) *spec;
		DPRINT(DEBUG_DIMTREE, "%s: new rlp: bittype: %d, dimid: %d,"
		       " key: %u, nextspec: %p\n", __FUNCTION__, bittype,
		       match->dimid, key, *nextspec);
		newspec = rlp_new(bittype, match->dimid, 1, &key, nextspec);
		if (newspec == NULL) {
			return HE_LOW_MEMORY;
		}
	}
	stat = history_new((struct gen_spec *) newspec, newspec_set);
	if (stat < 0) {
		rlp_free(newspec);
		return stat;
	}
	*spec = newspec;
	return dimtree_insrec(spec, rule, match_num, newspec_set);
}

static hipac_error
dimtree_insrec(struct rlp_spec **spec, struct dt_rule *rule,
	       __u8 match_num, int newspec_set)
{
	struct dt_match *match;

	/* spec non-terminating	*/
	assert(spec != NULL);
	assert(*spec != NULL);
	assert(IS_RLP(*spec));

	/* rule is not finished yet */
	assert(match_num < rule->dt_match_len);

	match = ITH_DT_MATCH(rule, match_num);

	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, match: "
	       "(dimid: %d,  left: %u, right: %u)\n", __FUNCTION__, match_num,
	       newspec_set, match->dimid, match->left, match->right);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if ((*spec)->dimid < match->dimid) {
		/* match in current dimension treated as wildcard because there
		   is no match for the current dimension */
		return dimtree_insrec_curdimid_sm(spec, rule, match_num,
						  newspec_set);
	} else if ((*spec)->dimid == match->dimid) {
		/* there is a match in the current dimension which is per
		   default no wildcard */
		return dimtree_insrec_curdimid_eq(spec, rule, match,
						  match_num, newspec_set);
		
	} else {
		/* the dimension of the current match has not yet been
		   created */
		return dimtree_insrec_curdimid_gr(spec, rule, match,
						  match_num, newspec_set);
	}
}

static inline hipac_error
segment_delete_help(struct rlp_spec *spec, struct locate_inf *bound1,
		    __u32 lkey, __u32 dkey, __u32 del_key[], __u8 *del_num,
		    int newspec_set)
{
	struct gen_spec *current1, *current2;
	struct locate_inf bound2;
	int stat;

	stat = rlp_locate(spec, &bound2, lkey);
	if (stat < 0) {
		return stat;
	}
	current1 = *bound1->nextspec;
	current2 = *bound2.nextspec;
	switch (rlp_rule_elem_eq(current1, current2)) {
	    case 1:
		    if (current1 == NULL ||
			!termrule_exists(*termrule(spec), spec->dimid, dkey)) {
			    del_key[(*del_num)++] = dkey;
		    }
		    break;
	    case 2:
		    if (!termrule_exists(*termrule(spec), spec->dimid, dkey)) {
			    history_obsolete(current1, newspec_set);
			    del_key[(*del_num)++] = dkey;
		    }
		    break;
	    case 3:
		    del_key[(*del_num)++] = dkey;
		    stat = rlp_free_rec((struct rlp_spec *) current1,
					newspec_set, 0);
		    if (stat < 0) {
			    return stat;
		    }
		    break;
	    default:
		    break;
	}
	return HE_OK;
}

/* segment [left, right] is deleted from spec if the neighbours of left and
   right point to the same spec; at most two elementary intervals can be
   deleted */
static inline hipac_error
segment_delete(struct rlp_spec **spec, __u32 left, __u32 right,
	       int newspec_set)
{
	__u8 del_num = 0;
	__u32 maxkey = MAXKEY((*spec)->bittype);
	__u32 del_key[2] = {0, 0};
	struct locate_inf bound1;
	int stat;
	
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: left: %u, right: %u, newspec_set: %d\n",
	       __FUNCTION__, left, right, newspec_set);
#ifdef DEBUG
	print_rlp(*spec);
#endif
	if (left > 0) {
		stat = rlp_locate(*spec, &bound1, left - 1);
		if (stat < 0) {
			return stat;
		}
		assert(bound1.key == left - 1);
		stat = segment_delete_help(*spec, &bound1, left, left - 1,
					   del_key, &del_num, newspec_set);
		if (stat < 0) {
			return stat;
		}
	}

	if (right < maxkey) {
		stat = rlp_locate(*spec, &bound1, right);
		if (stat < 0) {
			return stat;
		}
		assert(bound1.key == right);
		stat = segment_delete_help(*spec, &bound1, right + 1, right,
					   del_key, &del_num, newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	
	if (del_num > 0) {
		struct rlp_spec *b;
		assert(del_num == 1 || del_key[0] < del_key[1]);
		if (del_num == 1) {
			DPRINT(DEBUG_DIMTREE, "del key: %u\n", del_key[0]);
		} else {
			DPRINT(DEBUG_DIMTREE, "del keys: %u, %u\n",
			       del_key[0], del_key[1]);
		}
		stat = rlp_delete(*spec, del_num, del_key, &b);
		if (stat < 0) {
			return stat;
		}
		stat = history_replace((struct gen_spec *) *spec,
				       (struct gen_spec *) b, newspec_set);
		if (stat < 0) {
			rlp_free(b);
			return stat;
		}
		*spec = b;
	}
	return HE_OK;
}

/* forward declaration needed for dimtree_delrec_interval */
static hipac_error
dimtree_delrec(struct rlp_spec **spec, const struct dt_rule *rule,
	       __u8 match_num, struct ptrlist *term_prop, int newspec_set);

static inline hipac_error
dimtree_delrec_interval(struct gen_spec **spec, const struct dt_rule *rule,
			__u8 match_num, struct ptrlist *tmpterm,
			struct ptrblock **term, __u32 right, __u8 wildcard,
			__u8 dimid, int newspec_set)
{
	int stat;

	assert(*spec != NULL);
	if (IS_RLP(*spec)) {
		/* non-terminal case */
		struct rlp_spec *b;

		stat = rlp_clone_ifneeded((struct rlp_spec *) *spec, &b,
					  newspec_set);
		if (stat < 0) {
			return stat;
		}
		stat = dimtree_delrec(&b, rule, match_num, tmpterm,
				      newspec_set);
		if (stat < 0) {
			return stat;
		}
		*spec = (struct gen_spec *) b;
	} else {
		struct dt_rule_elem_spec **re =
			(struct dt_rule_elem_spec **) spec;

		if (IS_ELEM(*re)) {
			struct dt_elem *e;
			stat = elem_clone_ifneeded((struct dt_elem *) *re, &e,
						   newspec_set);
			if (stat < 0) {
				return stat;
			}
			*re = (struct dt_rule_elem_spec *) e;
		}
		stat = rule_elem_delete(re, rule, *term, right, wildcard,
					dimid, newspec_set);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_delrec(struct rlp_spec **spec, const struct dt_rule *rule,
	       __u8 match_num, struct ptrlist *term_prop, int newspec_set)
{	
	/* current match is initialized as wildcard */
	__u32 left   = 0;	
	__u32 key    = 0;
	__u32 maxkey = MAXKEY((*spec)->bittype);
	__u8 match_is_wildcard = 1;

	/* collects all terminating specs from the below dimension */
	struct ptrlist *tmpterm;
	struct ptrblock **term;
	struct locate_inf inf;
	int stat;
	
#ifdef DEBUG
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	if (match_num < rule->dt_match_len) {
		const struct dt_match *match = ITH_DT_MATCH(rule, match_num);
		DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, "
		       "le: %p, match: (dimid: %d, left: %u, right: %u)\n",
		       __FUNCTION__, match_num, newspec_set, rule,
		       match->dimid, match->left, match->right);
	} else {
		DPRINT(DEBUG_DIMTREE, "%s: match_num: %d, newspec_set: %d, "
		       "rule: %p, match: <none>\n", __FUNCTION__, match_num,
		       newspec_set, rule);
	}
	print_rlp(*spec);
#endif
	tmpterm = tmp_termrule_new();
	if (tmpterm == NULL) {
		return HE_LOW_MEMORY;
	}
	term = termrule(*spec);

	/* dimtree_delrec is never called for terminal cases */
	assert(*spec != NULL);
	assert(IS_RLP(*spec));

	if (match_num < rule->dt_match_len) {
		/* rule is not finished yet */
		const struct dt_match *match = ITH_DT_MATCH(rule, match_num);
		
		if ((*spec)->dimid == match->dimid) {
			/* match must be non-wildcard */
			assert(match->left > 0 ||
			       match->right < MAXKEY((*spec)->bittype));
			key = left = match->left;
			maxkey = match->right;
			match_is_wildcard = 0;
			match_num++;
		}
	}
	
	if (HAS_WILDCARD_SPEC(*spec) && match_is_wildcard) {
		assert(*WILDCARD(*spec) != NULL);
		stat = dimtree_delrec_interval(
			WILDCARD(*spec), rule, match_num, tmpterm, term,
			0, 1, (*spec)->dimid, newspec_set);
		if (stat < 0) {
			goto error;
		}
	} else {
		do {
			stat = rlp_locate(*spec, &inf, key);
			if (stat < 0) {
				goto error;
			}
			key = inf.key + 1;
			assert(*inf.nextspec != NULL);
			stat = dimtree_delrec_interval(
				inf.nextspec, rule, match_num, tmpterm, term,
				inf.key, 0, (*spec)->dimid, newspec_set);
			if (stat < 0) {
				goto error;
			}
		} while (inf.key < maxkey);
	}
		
	/* delete rule from termrule block if it is there */
	stat = termrule_delete(term, rule);
	if (stat < 0) {
		goto error;
	}

	/* merge temporary termrule list with termrule block */
	stat = termrule_merge(term, tmpterm);
	if (stat < 0) {
		return stat;
	}

	if (!match_is_wildcard) {
		/* remove surrounding elementary intervals represented by left
		   and maxkey if necessary */
		stat = segment_delete(spec, left, maxkey, newspec_set);
		if (stat < 0) {
			/* tmpterm is already freed */
			return stat;
		}
		term = termrule(*spec);
	}
	
	if ((*spec)->num == 1) {
		/* spec is empty => drop it */
		struct gen_spec *nextspec;

		if (HAS_WILDCARD_SPEC(*spec)) {
			assert((stat = rlp_locate(*spec, &inf, 0),
				stat < 0 ? 1 : *inf.nextspec == NULL));
			nextspec = *WILDCARD(*spec);
		} else {
			stat = rlp_locate(*spec, &inf, 0);
			if (stat < 0) {
				/* tmpterm is already freed */
				return stat;
			}
			nextspec = *inf.nextspec;
		}
		
		if (*term != NULL && term_prop != NULL) {
			stat = tmp_termrule_merge(term_prop, *term);
			if (stat < 0) {
				/* tmpterm is already freed */
				return stat;
			}
		}
		stat = history_obsolete((struct gen_spec *) *spec,
					newspec_set);
		if (stat < 0) {
			/* tmpterm is already freed */
			return stat;
		}

		if (nextspec == NULL || IS_RULE(nextspec)) {
			*spec = (struct rlp_spec *) nextspec;
		} else if (IS_RLP(nextspec)) {
			struct rlp_spec *b;

			stat = rlp_clone_ifneeded((struct rlp_spec *)
						  nextspec, &b, newspec_set);
			if (stat < 0) {
				return stat;
			}
			*spec = (struct rlp_spec *) b;
		} else {
			struct dt_elem *e;
			assert(IS_ELEM(nextspec));
			stat = elem_clone_ifneeded((struct dt_elem *)
						   nextspec, &e, newspec_set);
			if (stat < 0) {
				return stat;
			}
			*spec = (struct rlp_spec *) e;
		}
	}
	return HE_OK;

 error:
	tmp_termrule_free(tmpterm);
	return stat;
}



/*
 * public dimtree operations
 */

hipac_error
dimtree_new(struct dimtree **newdt, __u32 origin, const char *chain_name,
	    struct dt_rule *dummy, struct dt_rule *policy)
{
	struct dt_chain *chain;

	if (unlikely(newdt == NULL || chain_name == NULL || dummy == NULL ||
		     policy == NULL || dummy->spec.action != TARGET_DUMMY ||
		     !IS_RULE_TERM(policy) || policy->dt_match_len != 0)) {
		ARG_ERR;
	}
	*newdt = hp_alloc(sizeof(**newdt), 1);
	if (*newdt == NULL) {
		return HE_LOW_MEMORY;
	}
	chain = hp_alloc(sizeof(*chain), 1);
	if (chain == NULL) {
		hp_free(*newdt);
		*newdt = NULL;
		return HE_LOW_MEMORY;
	}
	INIT_LIST_HEAD(&chain->head);
	strncpy(chain->name, chain_name, sizeof(chain->name));
	chain->name[sizeof(chain->name) - 1] = '\0';
	chain->first = policy;
	chain->len = 2;
	list_add(&policy->head, &chain->head);
	list_add(&dummy->head, &chain->head);

	(*newdt)->origin = origin;
        (*newdt)->top = (struct gen_spec *) policy;
	(*newdt)->top_new = NULL;
        (*newdt)->need_commit = 0;
	(*newdt)->chain = chain;
	return HE_OK;
}

void
dimtree_free(struct dimtree *dt)
{
	struct list_head *lh;
	struct dt_rule *rule;

	if (unlikely(dt == NULL)) {
		ARG_MSG;
		return;
	}
	if (dt->top != NULL) {
		if (IS_RLP(dt->top)) {
			rlp_free_rec((struct rlp_spec *) dt->top, 0, 1);
		} else if (IS_ELEM(dt->top)) {
			elem_free((struct dt_elem *) dt->top);
		}
	}
	for (lh = dt->chain->head.next; lh != &dt->chain->head;) {
		rule = list_entry(lh, struct dt_rule, head);
		lh = lh->next;
		if (rule->exec_match != NULL) {
			ptrblock_free(rule->exec_match);
		}
		hp_free(rule);
	}
	hp_free(dt->chain);
	hp_free(dt);
}

void
dimtree_flush(struct dimtree *dt)
{
	struct gen_spec *top;
	struct list_head *lh;
	struct dt_rule *rule;

	if (unlikely(dt == NULL)) {
		ARG_MSG;
		return;
	}
	assert(dt->chain->len >= 2);
	assert(list_entry(dt->chain->head.next,
			  struct dt_rule, head)->spec.action == TARGET_DUMMY);
	top = dt->top;
	dt->top = (struct gen_spec *) list_entry(dt->chain->head.prev,
						 struct dt_rule, head);
	((struct dt_rule *) dt->top)->spec.pos = 1;
	dt->need_commit = 0;
	synchronize_rcu();
	if (top != NULL) {
		if (IS_RLP(top)) {
			rlp_free_rec((struct rlp_spec *) top, 0, 1);
		} else  if (IS_ELEM(top)) {
			elem_free((struct dt_elem *) top);
		}
	}
	for (lh = dt->chain->head.next->next; lh != dt->chain->head.prev;) {
		rule = list_entry(lh, struct dt_rule, head);
		lh = lh->next;
		list_del(lh->prev);
		if (rule->exec_match != NULL) {
			ptrblock_free(rule->exec_match);
		}
		hp_free(rule);
	}
	dt->chain->first = list_entry(dt->chain->head.prev, struct dt_rule,
				      head);
	dt->chain->len = 2;
}

const char *
dimtree_get_chain_name(const struct dimtree *dt)
{
	if (unlikely(dt == NULL)) {
		ARG_MSG;
		return NULL;
	}
	return dt->chain->name;
}

static hipac_error
dimtree_insert_intern(struct dimtree *dt, struct dt_rule *rule, __u32 origin,
		      int inc, int insert_chain, int commit)
{
	struct gen_spec *top;
	struct list_head *lh;
	struct dt_rule *r;
	int stat;
	
	if (unlikely(dt == NULL || rule == NULL ||
		     rule->spec.pos <= 0 ||
		     rule->spec.pos >
		     list_entry(dt->chain->head.prev,
				struct dt_rule, head)->spec.pos ||
		     (IS_TARGET_DUMMY(rule) && !insert_chain))) {
		ARG_ERR;
	}
	
	/* insert rule into dt_chain */
	assert(!rule->deleted);
	if (insert_chain) {
		if (likely(inc)) {
			for (lh = dt->chain->head.prev; lh != &dt->chain->head;
			     lh = lh->prev) {
				r = list_entry(lh, struct dt_rule, head);
				if (r->spec.pos < rule->spec.pos) {
					break;
				}
				r->spec.pos++;
			}
			list_add(&rule->head, lh);
		} else {
			__u32 maxpos = list_entry(dt->chain->head.prev,
						  struct dt_rule,
						  head)->spec.pos;
			if (((maxpos + 1) * rule->spec.pos) / dt->chain->len <
			    dt->chain->len >> 1) {
				list_for_each (lh, &dt->chain->head) {
					r = list_entry(lh, struct dt_rule,
						       head);
					if (r->spec.pos > rule->spec.pos) {
						break;
					}
				}
				list_add_tail(&rule->head, lh);
			} else {
				for (lh = dt->chain->head.prev;
				     lh != &dt->chain->head; lh = lh->prev) {
					r = list_entry(lh, struct dt_rule,
						       head);
					if (r->spec.pos <= rule->spec.pos) {
						break;
					}
				}
				list_add(&rule->head, lh);
			}
		}
		dt->chain->len++;
		if (IS_TARGET_DUMMY(rule)) {
			return HE_OK;
		}
	}

	/* origin check */
	if (!(dt->origin & origin)) {
		return HE_RULE_ORIGIN_MISMATCH;
	}

	if (!dt->need_commit) {
		/* first operation in a series => clone top level structure
		   if necessary */
		if (dt->top == NULL) {
			top = NULL;
		} else if (IS_RLP(dt->top)) {
			stat = rlp_clone((struct rlp_spec *) dt->top,
					 (struct rlp_spec **) &top);
			if (stat < 0) {
				return stat;
			}
			stat = history_replace(dt->top, top, !commit);
			if (stat < 0) {
				rlp_free((struct rlp_spec *) top);
				history_undo();
				return stat;
			}
		} else if (IS_ELEM(dt->top)) {
			stat = elem_clone((struct dt_elem *) dt->top,
					  (struct dt_elem **) &top);
			if (stat < 0) {
				return stat;
			}
			stat = history_replace(dt->top, top, !commit);
			if (stat < 0) {
				elem_free((struct dt_elem *) top);
				history_undo();
				return stat;
			}
		} else {
			assert(IS_RULE(dt->top));
			top = dt->top;
		}
	} else {
		top = dt->top_new;
	}

	/* insert rule into rlp */
	if (rule->dt_match_len == 0) {
		/* rule has no native matches at all */
		if (top != NULL && IS_RLP(top)) {
			stat = dimtree_insrec_curdimid_eq_tm(
				(struct rlp_spec **) &top, rule, 0,
				MAXKEY(dim2btype[((struct rlp_spec *)
						  top)->dimid]), !commit);
		} else {
			stat = rule_elem_insert((struct dt_rule_elem_spec **)
						&top, rule, !commit);
		}
	} else {
		/* rule has at least one native match */
		if (top == NULL) {
			stat = dimtree_insrec_null((struct rlp_spec **) &top,
						   rule, 0, !commit);
		} else if (IS_RLP(top)) {
			stat = dimtree_insrec((struct rlp_spec **) &top,
					      rule, 0, !commit);
		} else {
			/* construct termrule block containing all
			   non TARGET_DUMMY rules except the inserted rule
			   from dt->chain */
			struct ptrblock *term_prop = NULL;
			struct list_head *lh;
			struct dt_rule *r;
			
			stat = HE_OK;
			list_for_each (lh, &dt->chain->head) {
				r = list_entry(lh, struct dt_rule, head);
				if (r->spec.action == TARGET_DUMMY ||
				    r == rule || r->deleted) {
					continue;
				}
				assert(r->dt_match_len == 0);
				stat = termrule_insert(&term_prop, r);
				if (stat < 0) {
					if (term_prop != NULL) {
						ptrblock_free(term_prop);
					}
					break;
				}
			}
			if (stat == HE_OK) {
				stat = dimtree_insrec_rule_elem(
					(struct dt_rule_elem_spec **) &top,
					rule, 0, term_prop, !commit);
			}
		}
	}
	if (stat < 0) {
		history_undo();
		dt->top_new = NULL;
		return stat;
	}
	if (commit) {
#ifdef DEBUG
		if (rule_occur(dt->top, rule, 1)) {
			DPRINT(DEBUG_DIMTREE, "rule present in original"
			       "structure\n");
			return HE_IMPOSSIBLE_CONDITION;
		}
#endif
		dt->top = top;
		dt->top_new = NULL;
		synchronize_rcu();
		history_commit(0);
		assert(history_is_empty());
	} else {
		assert((IS_RULE(top) && IS_RULE(dt->top)) ||
		       !history_is_empty());
		dt->need_commit = 1;
		dt->top_new = top;
	}
	return HE_OK;
}

#ifdef DEBUG
void
dt_rule_print(const struct dt_rule *rule);
#endif

hipac_error
dimtree_insert(struct dimtree *dt, struct dt_rule *rule, __u32 origin,
	       int inc, int commit)
{
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: origin: %X, inc: %d, commit: %d\n",
	       __FUNCTION__, origin, inc, commit);
	DPRINT(DEBUG_DIMTREE, "dt: origin: %X, need_commit: %u,"
	       " chain: %s (len: %u)\n", dt->origin, dt->need_commit,
	       dt->chain->name, dt->chain->len);
#ifdef DEBUG
	if (dt->top_new == NULL) {
		if (dt->top != NULL) {
			if (IS_RLP(dt->top)) {
				print_rlp((struct rlp_spec *) dt->top);
			} else if (IS_ELEM(dt->top)) {
				print_elem((struct dt_elem *) dt->top);
				DPRINT(DEBUG_DIMTREE, "\n");
			} else {
				DPRINT(DEBUG_DIMTREE, "top level rule: %p\n",
				       dt->top);
			}
		}
	} else {
		if (IS_RLP(dt->top_new)) {
			print_rlp((struct rlp_spec *) dt->top_new);
		} else if (IS_ELEM(dt->top_new)) {
				print_elem((struct dt_elem *) dt->top_new);
				DPRINT(DEBUG_DIMTREE, "\n");
		} else {
			DPRINT(DEBUG_DIMTREE, "top level rule: %p\n",
			       dt->top_new);
		}
	}
	if (hipac_debug & DEBUG_DIMTREE) {
		dt_rule_print(rule);
	}
#endif
	return dimtree_insert_intern(dt, rule, origin, inc, 1, commit);
}

static struct dt_rule *
dimtree_delete_find_best_term(struct dimtree *dt,
			      const struct dt_rule *term_rule, __u32 *ntm_num)
{
	struct list_head *lh;
	struct dt_rule *cr;
	
	if (unlikely(dt == NULL || term_rule == NULL || ntm_num == NULL)) {
		ARG_MSG;
		return NULL;
	}

	*ntm_num = 0;
	for (lh = term_rule->head.next; lh != &dt->chain->head;
	     lh = lh->next) {
		cr = list_entry(lh, struct dt_rule, head);
		if (cr->deleted) {
			continue;
		}
		if (IS_RULE_TERM(cr)) {
			return cr;
		} else if (cr->spec.action != TARGET_DUMMY) {
			(*ntm_num)++;
		}
	}
	return NULL;
}

/* from and to are exclusive */
static hipac_error
dimtree_delete_insert_ntm(struct dimtree *dt, struct dt_elem **e,
			  const struct dt_rule *from, const struct dt_rule *to)
{
	struct list_head *lh;
	struct dt_rule *cr;
	int stat;
	
	if (unlikely(dt == NULL || e == NULL || *e == NULL || to == NULL)) {
		ARG_ERR;
	}

	for (lh = (from == NULL ? dt->chain->head.next : from->head.next);
	     lh != &to->head; lh = lh->next) {
		cr = list_entry(lh, struct dt_rule, head);
		if (cr->deleted || cr->spec.action == TARGET_DUMMY) {
			continue;
		}
		assert(cr->spec.pos < to->spec.pos);
		assert(!IS_RULE_TERM(cr));
		stat = ptrblock_insert_embed((void **) e,
					     offsetof(struct dt_elem,
						      ntm_rules), cr,
					     (*e)->ntm_rules.len);
		if (stat < 0) {
			return stat;
		}
	}
	return HE_OK;
}

static hipac_error
dimtree_delete_rule_elem(struct dt_rule_elem_spec **rule_elem,
			 const struct dt_rule *rule, struct dimtree *dt,
			 int newspec_set)
{
	struct dt_elem *e;
	int stat;
	__u32 i;
	
	if (IS_RULE(*rule_elem)) {
		struct dt_rule *r = (struct dt_rule *) *rule_elem;
		struct dt_rule *term_rule;
		__u32 ntm_num;
		
		if (r != rule) {
			/* deleted rule must have a higher position than r */
			return HE_OK;
		}
		term_rule = dimtree_delete_find_best_term(dt, rule, &ntm_num);
		if (term_rule == NULL) {
			IMPOSSIBLE_CONDITION("attempt to delete the only "
					     "terminal rule");
		}
		if (ntm_num == 0) {
			*rule_elem = (struct dt_rule_elem_spec *) term_rule;
			return HE_OK;
		} else {
			struct dt_elem *e = elem_new_empty(term_rule);
			if (e == NULL) {
				return HE_LOW_MEMORY;
			}
			stat = dimtree_delete_insert_ntm(dt, &e, rule,
							 term_rule);
			if (stat < 0) {
				elem_free(e);
				return stat;
			}
			assert(e->ntm_rules.len > 0);
			stat = history_new((struct gen_spec *) e, newspec_set);
			if (stat < 0) {
				elem_free(e);
				return stat;
			}
			*rule_elem = (struct dt_rule_elem_spec *) e;
			return HE_OK;
		}
	}

	assert(IS_ELEM(*rule_elem));
	e = (struct dt_elem *) *rule_elem;
	assert(e->term_rule != NULL);
	if (IS_RULE_TERM(rule)) {
		struct dt_rule *term_rule;
		__u32 ntm_num;

		if (e->term_rule != rule) {
			/* deleted rule must have a higher position than
			   e->term_rule */
			assert(rule->spec.pos > e->term_rule->spec.pos);
			return HE_OK;
		}
		term_rule = dimtree_delete_find_best_term(dt, rule, &ntm_num);
		if (term_rule == NULL) {
			IMPOSSIBLE_CONDITION("attempt to delete the only "
					     "terminal rule");
		}
		stat = dimtree_delete_insert_ntm(
			 dt, (struct dt_elem **) rule_elem, rule, term_rule);
		if (stat < 0) {
			/* we only care about rule_elem if its address has
			   changed; otherwise rule_elem is handled by the
			   history */
			if (e != (struct dt_elem *) *rule_elem) {
				history_del_invalid((struct gen_spec *) e);
				elem_free((struct dt_elem *) *rule_elem);
			}
			return stat;
		}
		if (e != (struct dt_elem *) *rule_elem) {
			history_del_invalid((struct gen_spec *) e);
			stat = history_new((struct gen_spec *)
					   *rule_elem, newspec_set);
			if (stat < 0) {
				elem_free((struct dt_elem *) *rule_elem);
				return stat;
			}
		}
		(*(struct dt_elem **) rule_elem)->term_rule = term_rule;
		return HE_OK;
	} else {
		for (i = 0; i < e->ntm_rules.len &&
			     ((struct dt_rule *)
			      e->ntm_rules.p[i])->spec.pos <
			     rule->spec.pos; i++);
		if (i >= e->ntm_rules.len || e->ntm_rules.p[i] != rule) {
			/* deleted rule must have a higher position than
			   e->ntm_rules.p[e->ntm_rules.len - 1] */
			return HE_OK;
		}
		if (e->ntm_rules.len == 1) {
			struct dt_rule_elem_spec *tm =
				(struct dt_rule_elem_spec *)
				e->term_rule;
			stat = history_obsolete((struct gen_spec *) e,
						newspec_set);
			if (stat < 0) {
				return stat;
			}
			*rule_elem = tm;
			return HE_OK;
		} else {
			stat = ptrblock_delete_pos_embed(
				 (void **) rule_elem,
				 offsetof(struct dt_elem, ntm_rules),
				 i);
			if (stat < 0) {
				/* we only care about rule_elem if its address
				   has changed; otherwise rule_elem is 
				   handled by the history */
				if (e != (struct dt_elem *) *rule_elem) {
					history_del_invalid((struct gen_spec *)
							    e);
					elem_free((struct dt_elem *)
						  *rule_elem);
				}
				return stat;
			}
			if (e != (struct dt_elem *) *rule_elem) {
				history_del_invalid((struct gen_spec *) e);
				stat = history_new((struct gen_spec *)
						   *rule_elem, newspec_set);
				if (stat < 0) {
					elem_free((struct dt_elem *)
						  *rule_elem);
					return stat;
				}
			}
			return HE_OK;
		}
	}
}

hipac_error
dimtree_delete(struct dimtree *dt, struct dt_rule *rule, int commit)
{
	struct gen_spec *top;
	int stat;

	if (unlikely(dt == NULL || rule == NULL || rule->deleted ||
		     rule == list_entry(dt->chain->head.next,
					struct dt_rule, head) ||
		     rule == list_entry(dt->chain->head.prev,
					struct dt_rule, head))) {
		ARG_ERR;
	}

	assert(dt->top != NULL);
	DPRINT(DEBUG_DIMTREE,
	       "----------------------------------------------------------\n");
	DPRINT(DEBUG_DIMTREE, "%s: commit: %d\n", __FUNCTION__, commit);
	DPRINT(DEBUG_DIMTREE, "dt: origin: %X, need_commit: %u,"
	       " chain: %s (len: %u)\n", dt->origin, dt->need_commit,
	       dt->chain->name, dt->chain->len);
#ifdef DEBUG
	if (dt->top_new == NULL) {
		if (dt->top != NULL) {
			if (IS_RLP(dt->top)) {
				print_rlp((struct rlp_spec *) dt->top);
			} else if (IS_ELEM(dt->top)) {
				print_elem((struct dt_elem *) dt->top);
				DPRINT(DEBUG_DIMTREE, "\n");
			} else {
				DPRINT(DEBUG_DIMTREE, "top level rule: %p\n",
				       dt->top);
			}
		}
	} else {
		if (IS_RLP(dt->top_new)) {
			print_rlp((struct rlp_spec *) dt->top_new);
		} else if (IS_ELEM(dt->top_new)) {
				print_elem((struct dt_elem *) dt->top_new);
				DPRINT(DEBUG_DIMTREE, "\n");
		} else {
			DPRINT(DEBUG_DIMTREE, "top level rule: %p\n",
			       dt->top_new);
		}
	}
	if (hipac_debug & DEBUG_DIMTREE) {
		dt_rule_print(rule);
	}
#endif

	if (!dt->need_commit) {
		/* first operation in a series => clone top level structure
		   if necessary */
		if (IS_RLP(dt->top)) {
			stat = rlp_clone((struct rlp_spec *) dt->top,
					 (struct rlp_spec **) &top);
			if (stat < 0) {
				return stat;
			}
			stat = history_replace(dt->top, top, !commit);
			if (stat < 0) {
				rlp_free((struct rlp_spec *) top);
				history_undo();
				return stat;
			}
		} else if (IS_ELEM(dt->top)) {
			stat = elem_clone((struct dt_elem *) dt->top,
					  (struct dt_elem **) &top);
			if (stat < 0) {
				return stat;
			}
			stat = history_replace(dt->top, top, !commit);
			if (stat < 0) {
				elem_free((struct dt_elem *) top);
				history_undo();
				return stat;
			}
		} else {
			assert(IS_RULE(dt->top));
			top = dt->top;
		}
	} else {
		top = dt->top_new;
	}

	/* delete rule from rlp / elementary interval */
	if (IS_RLP(top)) {
		stat = dimtree_delrec((struct rlp_spec **) &top, rule,
				      0, NULL, !commit);
	} else {
		stat = dimtree_delete_rule_elem((struct dt_rule_elem_spec **)
						&top, rule, dt, !commit);
	}
	if (stat < 0) {
		history_undo();
		return stat;
	}
	
	if (commit) {
#ifdef DEBUG
		if (dt->top != NULL && IS_RLP(dt->top) &&
		    !rule_occur(dt->top, rule, 0)) {
			/* this check only works if the top level structure is
			   a rlp */
			DPRINT(DEBUG_DIMTREE, "rule %p not present in "
			       "original rlp\n", rule);
			return HE_IMPOSSIBLE_CONDITION;
		}
#endif
		dt->top = top;
		dt->top_new = NULL;
		synchronize_rcu();
		history_commit(0);
		assert(history_is_empty());
	} else {
		assert((IS_RULE(top) && IS_RULE(dt->top)) ||
		       !history_is_empty());
		dt->need_commit = 1;
		dt->top_new = top;
		rule->deleted = 1;
	}
	return HE_OK;
}

void
dimtree_commit(struct ptrblock *dt_block)
{
	struct dimtree *dt;
	__u32 i;
	
	if (unlikely(dt_block == NULL)) {
		ARG_MSG;
		return;
	}

	for (i = 0; i < dt_block->len; i++) {
		dt = (struct dimtree *) dt_block->p[i];
		if (dt->need_commit) {
			dt->top = dt->top_new;
			dt->top_new = NULL;
			dt->need_commit = 0;
		}
	}
	synchronize_rcu();
	history_commit(1);
	assert(history_is_empty());
}

void
dimtree_failed(struct ptrblock *dt_block)
{
	struct list_head *lh;
	struct dimtree *dt;
	__u32 i;
	
	if (unlikely(dt_block == NULL)) {
		ARG_MSG;
		return;
	}

	for (i = 0; i < dt_block->len; i++) {
		dt = (struct dimtree *) dt_block->p[i];
		if (dt->need_commit) {
			dt->need_commit = 0;
			dt->top_new = NULL;
			list_for_each (lh, &dt->chain->head) {
				list_entry(lh, struct dt_rule,
					   head)->deleted = 0;
			}
		}
		assert(dt->need_commit || dt->top_new == NULL);
	}
	history_undo();
}

void
dimtree_chain_fix(struct ptrblock *dt_block)
{
	struct list_head *lh;
	struct dt_rule *rule;
	__u32 i, prevpos_new, prevpos_org;
	struct dimtree *dt;
	
	if (unlikely(dt_block == NULL)) {
		ARG_MSG;
		return;
	}
	
	for (i = 0; i < dt_block->len; i++) {
		dt = (struct dimtree *) dt_block->p[i];
		assert(!list_empty(&dt->chain->head));
		if (dt->chain->first == NULL) {
			lh = dt->chain->head.next;
			prevpos_org = list_entry(lh, struct dt_rule,
						 head)->spec.pos;
			prevpos_new = list_entry(lh, struct dt_rule,
						 head)->spec.pos = 0;
			lh = lh->next;
		} else {
			lh = dt->chain->first->head.next;
			prevpos_org = prevpos_new = dt->chain->first->spec.pos;
		}
		dt->chain->first = list_entry(dt->chain->head.prev,
					      struct dt_rule, head);
		for (; lh != &dt->chain->head; lh = lh->next) {
			rule = list_entry(lh, struct dt_rule, head);
			if (unlikely(rule->spec.pos == prevpos_org)) {
				rule->spec.pos = prevpos_new;
			} else {
				prevpos_org = rule->spec.pos;
				rule->spec.pos = ++prevpos_new;
			}
		}
	}
}

static hipac_error
hipac_get_rlp_stat_rec(struct gen_spec *g, struct hipac_rlp_stat *stat,
		       __u8 depth, __u8 parent_dimid)
{
	struct gen_spec **nextspec = NULL;
	struct rlp_spec *rlp;
	int ret;
	__u16 n;

	if (g == NULL) {
		return HE_OK;
	}
	if (IS_RULE(g) || IS_ELEM(g)) {
		if (depth < 1) {
			return HE_OK;
		}
		stat->termptr_num++;
		if (parent_dimid >= LEN(stat->termptr_dimid_num)) {
			IMPOSSIBLE_CONDITION("termptr_dimid_num too small");
		}
		stat->termptr_dimid_num[parent_dimid]++;
		if (depth - 1 >= LEN(stat->termptr_depth_num)) {
			IMPOSSIBLE_CONDITION("termptr_depth_num too small");
		}
		stat->termptr_depth_num[depth - 1]++;
		if (IS_ELEM(g)) {
			struct dt_elem *e = (struct dt_elem *) g;
			__u32 ptr_num;
			stat->dt_elem_num++;
			ptr_num = e->ntm_rules.len +
				(e->term_rule == NULL ? 0 : 1);
			stat->dt_elem_ptr_num += ptr_num;
			stat_distribution_add(stat->dt_elem_stat,
					      LEN(stat->dt_elem_stat),
					      ptr_num);
		}
		return HE_OK;
	}
	
	/* rlp statistics */
	rlp = (struct rlp_spec *) g;
	if (hp_size(rlp, &stat->rlp_mem_real, &stat->rlp_mem_tight) < 0) {
		return HE_IMPOSSIBLE_CONDITION;
	}
	if (hp_size(*termrule(rlp), &stat->termrule_mem_real,
		    &stat->termrule_mem_tight) < 0) {
		return HE_IMPOSSIBLE_CONDITION;
	}
	stat->rlp_num++;
	if (rlp->dimid >= LEN(stat->rlp_dimid_num)) {
		IMPOSSIBLE_CONDITION("rlp_dimid_num too small");
	}
	stat->rlp_dimid_num[rlp->dimid]++;
	if (depth >= LEN(stat->rlp_depth_num)) {
		IMPOSSIBLE_CONDITION("rlp_depth_num too small");
	}
	stat->rlp_depth_num[depth]++;
	if (*termrule(rlp) != NULL) {
		stat->termrule_num++;
		stat->termrule_ptr_num += (*termrule(rlp))->len;
	}
	stat->keys_num += rlp->num;
       	if (rlp->dimid >= LEN(stat->rlp_dimid_keys_stat)) {
		IMPOSSIBLE_CONDITION("rlp_dimid_keys_stat too small");
	}
	stat_distribution_add(stat->rlp_dimid_keys_stat[rlp->dimid],
			      LEN(*stat->rlp_dimid_keys_stat), rlp->num);
	if (depth > 0) {
		stat->nontermptr_num++;
		if (parent_dimid >= LEN(stat->nontermptr_dimid_num)) {
			IMPOSSIBLE_CONDITION("nontermptr_dimid_num too small");
		}
		stat->nontermptr_dimid_num[parent_dimid]++;
		if (depth - 1 >= LEN(stat->nontermptr_depth_num)) {
			IMPOSSIBLE_CONDITION("nontermptr_depth_num too small");
		}
		stat->nontermptr_depth_num[depth - 1]++;
	}

	/* recursion */
	nextspec = rlp_nextspec(rlp);
	assert(nextspec != NULL);
	
	for (n = 0; n < rlp->num; n++) {
		ret = hipac_get_rlp_stat_rec(*(nextspec + n), stat,
					     depth + 1, rlp->dimid);
		if (ret < 0) {
			return ret;
		}
	}
	if (HAS_WILDCARD_SPEC(rlp)) {
		ret = hipac_get_rlp_stat_rec(*WILDCARD(rlp), stat,
					     depth + 1, rlp->dimid);
		if (ret < 0) {
			return ret;
		}
	}
	return HE_OK;
}

hipac_error
hipac_get_rlp_stat(void *hipac, struct hipac_rlp_stat *stat)
{
	struct dimtree *dt = hipac;

	if (dt == NULL || stat == NULL) {
		ARG_ERR;
	}

	memset(stat, 0, sizeof(*stat));
	stat->total_mem_tight = mem_current_tight;
	stat->total_mem_real = mem_current_real;
	if (dt->top == NULL) {
		IMPOSSIBLE_CONDITION("top level rlp NULL");
	}
	return hipac_get_rlp_stat_rec(dt->top, stat, 0, 0);
}

hipac_error
hipac_get_dimtree_stat(void *hipac, struct hipac_dimtree_stat *stat)
{
	struct dimtree *dt = hipac;
	struct list_head *lh;
	struct dt_rule *r;
	__u32 pos, num;

	if (dt == NULL || stat == NULL) {
		ARG_ERR;
	}

	memset(stat, 0, sizeof(*stat));
	if (hp_size(dt->chain, &stat->chain_mem_real,
		    &stat->chain_mem_tight) < 0) {
		return HE_IMPOSSIBLE_CONDITION;
	}
	stat->rule_num = dt->chain->len;
	pos = num = 0;
	list_for_each (lh, &dt->chain->head) {
		r = list_entry(lh, struct dt_rule, head);
		if (r->spec.pos == pos) {
			num++;
		} else {
			if (num > 1) {
				stat_distribution_add(
				      stat->rules_same_pos_stat,
				      LEN(stat->rules_same_pos_stat), num);
			}
			num = 1;
			pos = r->spec.pos;
		}
		if (hp_size(r, &stat->chain_mem_real,
			    &stat->chain_mem_tight) < 0) {
			return HE_IMPOSSIBLE_CONDITION;
		}
		if (HAS_EXEC_MATCH(r)) {
			stat->rules_with_exec_matches++;
		}
		if (IS_TARGET_EXEC(r)) {
			stat->rules_with_exec_target++;
		}
		if (r->dt_match_len >= LEN(stat->dt_match_stat)) {
			IMPOSSIBLE_CONDITION("dt_match_stat too small");
		}
		stat->dt_match_stat[r->dt_match_len]++;
	}
	if (num > 1) {
		stat_distribution_add(stat->rules_same_pos_stat,
				      LEN(stat->rules_same_pos_stat), num);
	}
	return HE_OK;
}



/*
 * hipac matching algorithm
 */


#ifdef SINGLE_PATH

/* match packet against the rlp in dt and return the terminal action
   (TARGET_ACCEPT or TARGET_DROP) of the highest priority terminal rule or
   the policy if there is no such rule */
hipac_target_t
hipac_match(void *hipac, const void *packet)
{
	struct dt_rule *rule;
	struct gen_spec *t;
	__u8 action, i, j;
	int hotdrop = 0;

	t = ((struct dimtree *) hipac)->top;
	assert(t != NULL);
	assert(packet != NULL);

 	while (!hotdrop && IS_RLP(t)) {
		t = ((struct rlp_spec *) t)->locate((struct rlp_spec *) t,
						    packet, &hotdrop);
	}
	if (hotdrop)
		return TARGET_DROP;

	if (likely(IS_RULE(t))) {
		assert(IS_RULE_TERM((struct dt_rule *) t));
		return ((struct dt_rule *) t)->spec.action;
	}
	
	/* initialization required to prevent compiler warning */
	action = 0;

	assert(IS_ELEM(t));
	assert(((struct dt_elem *) t)->term_rule != NULL);
	assert(IS_RULE_TERM(((struct dt_elem *) t)->term_rule));
	assert(((struct dt_elem *) t)->ntm_rules.p != NULL);
	for (i = 0; i < ((struct dt_elem *) t)->ntm_rules.len; i++) {
		rule = ((struct dt_elem *) t)->ntm_rules.p[i];
		if (HAS_EXEC_MATCH(rule)) {
			assert(!(rule->exec_match->len & 1));
			assert(rule->exec_match->len >= 2);
			for (j = 0; j < rule->exec_match->len; j += 2) {
				action = match_fn(packet, 
						  rule->exec_match->p[j],
						  rule->exec_match->p[j + 1]);
				if (action != MATCH_YES) {
					break;
				}
			}
			if (action == MATCH_NO) {
				continue;
			}
			if (action == MATCH_HOTDROP) {
				return TARGET_DROP;
			}
		}
		action = IS_TARGET_EXEC(rule) ?
			target_fn(packet, rule->exec_target) 
			: rule->spec.action;
		if (action != TARGET_NONE) {
			assert(action == TARGET_ACCEPT ||
			       action == TARGET_DROP);
			return action;
		}
	}

	/* terminal rule or policy matches */
	return ((struct dt_elem *) t)->term_rule->spec.action;
}

#  ifdef DEBUG

/*
 * debugging version of hipac_match (single path)
 */

/* return the matched rules in order - for verification purposes only */
struct ptrblock *
hipac_match_debug(struct dimtree *hipac, const void *packet)
{
	struct ptrblock *b = NULL;
	struct dt_rule *rule;
	struct gen_spec *t;
	__u8 action, i, j;
	int hotdrop = 0;

	t = ((struct dimtree *) hipac)->top;
	assert(t != NULL);
	assert(packet != NULL);

	while (!hotdrop && IS_RLP(t)) {
		t = ((struct rlp_spec *) t)->locate((struct rlp_spec *) t,
						    packet, &hotdrop);
	}
	if (hotdrop)
		return b;

	if (likely(IS_RULE(t))) {
		assert(IS_RULE_TERM((struct dt_rule *) t));
		if (ptrblock_append(&b, t) < 0) {
			ERR("ptrblock_append failed");
		}
		return b;
	}
	
	/* initialization required to prevent compiler warning */
	action = 0;

	assert(IS_ELEM(t));
	assert(((struct dt_elem *) t)->term_rule != NULL);
	assert(IS_RULE_TERM(((struct dt_elem *) t)->term_rule));
	assert(((struct dt_elem *) t)->ntm_rules.p != NULL);
	for (i = 0; i < ((struct dt_elem *) t)->ntm_rules.len; i++) {
		rule = ((struct dt_elem *) t)->ntm_rules.p[i];
		if (HAS_EXEC_MATCH(rule)) {
			assert(!(rule->exec_match->len & 1));
			assert(rule->exec_match->len >= 2);
			for (j = 0; j < rule->exec_match->len; j += 2) {
				action = match_fn(packet, 
						  rule->exec_match->p[j],
						  rule->exec_match->p[j + 1]);
				if (action != MATCH_YES) {
					break;
				}
			}
			if (action == MATCH_NO) {
				continue;
			}
			if (action == MATCH_HOTDROP) {
				return b;
			}
		}
		if (ptrblock_append(&b, rule) < 0) {
			ERR("ptrblock_append failed");
			return b;
		}
		action = IS_TARGET_EXEC(rule) ?
			target_fn(packet, rule->exec_target) 
			: rule->spec.action;
		if (action != TARGET_NONE){
			assert(action == TARGET_ACCEPT ||
			       action == TARGET_DROP);
			return b;
		}
	}

	/* terminal rule or policy matches */
	if (ptrblock_append(&b, ((struct dt_elem *) t)->term_rule) < 0) {
		ERR("ptrblock_append failed");
	}
	return b;
}

#  endif   // DEBUG

#else      // SINGLE_PATH

static inline hipac_target_t
match_packet(const struct dimtree *dt, const void *packet,
	     struct dt_rule *rule)
{
	__u32 i;

	if (HAS_EXEC_MATCH(rule)) {
		assert(!(rule->exec_match->len & 1));
		assert(rule->exec_match->len >= 2);
		for (i = 0; i < rule->exec_match->len; i += 2) {
			switch (match_fn(packet, rule->exec_match->p[i],
					 rule->exec_match->p[i + 1])) {
			    case MATCH_YES:
				    break;

			    case MATCH_NO:
				    return TARGET_NONE;

			    case MATCH_HOTDROP: 
				    return TARGET_DROP;
			}
		}
	}
	return IS_TARGET_EXEC(rule) ?
		target_fn(packet, rule->exec_target) : rule->spec.action;
}


/* match packet against the rlp in dt and return the terminal action
   (TARGET_ACCEPT or TARGET_DROP) of the highest priority terminal rule or
   the policy if there is no such rule */
hipac_target_t
hipac_match(void *hipac, const void *packet)
{
#       define NUM_LEAVES 4
	/* UINT_MAX - 1 is required because of
	   if (likely(term_pos < nonterm_pos)) {...} optimization */
	__u32 term_pos = UINT_MAX - 1;
	__u32 nonterm_pos = UINT_MAX;
	struct dt_rule *term_rule = NULL;
	struct dt_rule_elem_spec *rule_elem[NUM_LEAVES];
	struct dt_rule **ntm_rule[NUM_LEAVES];
	struct dt_rule **ntm_end[NUM_LEAVES];
	struct gen_spec *t;
	__u32 ntm_next_pos, new_next;
	__u8 ntm_rule_sz, ntm_cur_ind;
	__u8 action, i, len, max;
	int hotdrop = 0;
	
	max = 1;
	i = len = 0;
	rule_elem[0] = (struct dt_rule_elem_spec *) 
		((struct dimtree *) hipac)->top;
	assert(packet != NULL);
	assert(rule_elem[0] != NULL);
	assert(!IS_RULE(rule_elem[0]) ||
	       IS_RULE_TERM(((struct dt_rule *) rule_elem[0])));
	assert(!IS_ELEM(rule_elem[0]) ||
	       (IS_RULE_TERM(((struct dt_elem *) rule_elem[0])->term_rule) &&
		((struct dt_elem *) rule_elem[0])->ntm_rules.len > 0));
	
	do {
		t = (struct gen_spec *) rule_elem[i++];
		while (!hotdrop && t && IS_RLP(t)) {
			t = ((struct rlp_spec *) t)->locate(
				(struct rlp_spec *) t, packet, &hotdrop,
				(struct gen_spec **) rule_elem, &max);
		};
		if (hotdrop)
			return TARGET_DROP;
		assert(max <= NUM_LEAVES);
		if (unlikely(t == NULL)) {
			continue;
		}
		rule_elem[len++] = (struct dt_rule_elem_spec *) t;
		if (likely(IS_RULE(t))) {
			if (likely(IS_RULE_TERM((struct dt_rule *) t))) {
				if (((struct dt_rule *) t)->spec.pos <
				    term_pos) {
					term_rule = (struct dt_rule *) t;
					term_pos = term_rule->spec.pos;
				}
			} else if (((struct dt_rule *) t)->spec.pos <
				   nonterm_pos) {
				nonterm_pos = ((struct dt_rule *)
					       t)->spec.pos;
			}
		} else {
			if (((struct dt_elem *) t)->term_rule != NULL &&
			    ((struct dt_elem *) t)->term_rule->spec.pos <
			    term_pos) {
				term_rule = ((struct dt_elem *)
					     t)->term_rule;
				term_pos = term_rule->spec.pos;
				assert(IS_RULE_TERM(term_rule));
			}
			assert(((struct dt_elem *) t)->ntm_rules.len > 0);
			if (((struct dt_rule *)
			     ((struct dt_elem *) t)->ntm_rules.p[0])->spec.pos
			    < nonterm_pos) {
				nonterm_pos = ((struct dt_rule *)
					       ((struct dt_elem *)
						t)->ntm_rules.p[0])->spec.pos;
			}
		}
	} while (i < max);
		
	/* optimization for the ideal case that no non-terminal rules
	   (function based matches or no terminal target) exist */
	if (likely(term_pos < nonterm_pos)) {
		assert(term_rule != NULL);
		action = term_rule->spec.action;
		return action;
	}

	/* initialize ntm_rule, ntm_end, ntm_rule_sz, ntm_cur_ind and
	   ntm_next_pos now that term_pos is given */
	ntm_rule_sz = ntm_cur_ind = 0;
	ntm_next_pos = UINT_MAX;
	for (i = 0; i < len; i++) {
		assert(rule_elem[i] != NULL);
		if (likely(IS_RULE(rule_elem[i]))) {
			struct dt_rule **r = (struct dt_rule **) &rule_elem[i];
			__u32 pos = (*r)->spec.pos;
			if (!IS_RULE_TERM(*r) && pos < term_pos) {
				if (pos == nonterm_pos) {
					ntm_cur_ind = ntm_rule_sz;
				} else if (pos < ntm_next_pos) {
					ntm_next_pos = pos;
				}
				ntm_rule[ntm_rule_sz] = r;
				ntm_end[ntm_rule_sz++] = r;
			}
		} else {
			struct dt_elem *e = (struct dt_elem *) rule_elem[i];
			__u32 pos = ((struct dt_rule *)
				     *e->ntm_rules.p)->spec.pos;
			if (pos < term_pos) {
				if (pos == nonterm_pos) {
					ntm_cur_ind = ntm_rule_sz;
				} else if (pos < ntm_next_pos) {
					ntm_next_pos = pos;
				}
				ntm_rule[ntm_rule_sz] =
					(struct dt_rule **) e->ntm_rules.p;
				ntm_end[ntm_rule_sz++] = (struct dt_rule **)
					&e->ntm_rules.p[e->ntm_rules.len - 1];
			}
		}
	}
	assert(ntm_rule_sz > 0);
	
	/* process non-terminal rules in order up to term_pos */
	ntm_next_pos = ntm_next_pos < term_pos ? ntm_next_pos : term_pos;
	while (ntm_rule_sz > 0 &&
	       (*ntm_rule[ntm_cur_ind])->spec.pos < ntm_next_pos) {
		
		/* match packet against current block of rules */
		for (; (ntm_rule[ntm_cur_ind] <= ntm_end[ntm_cur_ind] &&
			(*ntm_rule[ntm_cur_ind])->spec.pos < ntm_next_pos);
		     ntm_rule[ntm_cur_ind]++) {

			switch (action =
				match_packet((struct dimtree *) hipac, packet,
					     *ntm_rule[ntm_cur_ind])) {

			    case TARGET_NONE:
				    break;
			    default:
				    assert(action == TARGET_ACCEPT ||
					   action == TARGET_DROP);
				    return action;
			}
		}

		/* remove current block of rules if no rule is left that may
		   be matched */
		if (ntm_rule[ntm_cur_ind] > ntm_end[ntm_cur_ind] ||
		    (*ntm_rule[ntm_cur_ind])->spec.pos >= term_pos) {
			ntm_rule_sz--;
			assert(ntm_cur_ind <= ntm_rule_sz);
			ntm_rule[ntm_cur_ind] = ntm_rule[ntm_rule_sz];
			ntm_end[ntm_cur_ind] = ntm_end[ntm_rule_sz];
		}

		/* set ntm_cur_ind and ntm_next_pos for next run */
		new_next = term_pos;
		for (i = 0; i < ntm_rule_sz; i++) {
			if ((*ntm_rule[i])->spec.pos == ntm_next_pos) {
				ntm_cur_ind = i;
			} else if ((*ntm_rule[i])->spec.pos < new_next) {
				new_next = (*ntm_rule[i])->spec.pos;
			}
		}
		ntm_next_pos = new_next;
	}
	
	/* terminal rule or policy matches */
	assert(term_rule != NULL);
	action = term_rule->spec.action;
	return action;
}

#  ifdef DEBUG

/*
 * debugging version of hipac_match (multi path)
 */

/* for verification purposes only */
static inline hipac_target_t
match_packet_debug(struct ptrblock **b, const struct dimtree *dt,
		   const void *packet, struct dt_rule *rule)
{
	__u32 i;

	if (HAS_EXEC_MATCH(rule)) {
		assert(!(rule->exec_match->len & 1));
		assert(rule->exec_match->len >= 2);
		for (i = 0; i < rule->exec_match->len; i += 2) {
			switch (match_fn(packet, rule->exec_match->p[i],
					 rule->exec_match->p[i + 1])) {
			    case MATCH_YES:
				    break;

			    case MATCH_NO:
				    return TARGET_NONE;

			    case MATCH_HOTDROP: 
				    return TARGET_DROP;
			}
		}
	}
	if (ptrblock_append(b, rule) < 0) {
		ERR("ptrblock_append failed");
	}
	return IS_TARGET_EXEC(rule) ?
		target_fn(packet, rule->exec_target) : rule->spec.action;
}

/* return the matched rules in order - for verification purposes only */
struct ptrblock *
hipac_match_debug(struct dimtree *hipac, const void *packet)
{
#       define NUM_LEAVES 4
	struct ptrblock *b = NULL;
	/* UINT_MAX - 1 is required because of
	   if (likely(term_pos < nonterm_pos)) {...} optimization */
	__u32 term_pos = UINT_MAX - 1;
	__u32 nonterm_pos = UINT_MAX;
	struct dt_rule *term_rule = NULL;
	struct dt_rule_elem_spec *rule_elem[NUM_LEAVES];
	struct dt_rule **ntm_rule[NUM_LEAVES];
	struct dt_rule **ntm_end[NUM_LEAVES];
	struct gen_spec *t;
	__u32 ntm_next_pos, new_next;
	__u8 ntm_rule_sz, ntm_cur_ind;
	__u8 action, i, len, max;
	int hotdrop = 0;

	max = 1;
	i = len = 0;
	rule_elem[0] = (struct dt_rule_elem_spec *) 
		((struct dimtree *) hipac)->top;
	assert(packet != NULL);
	assert(rule_elem[0] != NULL);
	assert(!IS_RULE(rule_elem[0]) ||
	       IS_RULE_TERM(((struct dt_rule *) rule_elem[0])));
	assert(!IS_ELEM(rule_elem[0]) ||
	       (IS_RULE_TERM(((struct dt_elem *) rule_elem[0])->term_rule) &&
		((struct dt_elem *) rule_elem[0])->ntm_rules.len > 0));
 
       	do {
		t = (struct gen_spec *) rule_elem[i++];
		while (!hotdrop && t && IS_RLP(t)) {
			t = ((struct rlp_spec *) t)->locate(
				(struct rlp_spec *) t, packet, &hotdrop,
				(struct gen_spec **) rule_elem, &max);
		};
		if (hotdrop)
			return b;
		assert(max <= NUM_LEAVES);
		if (unlikely(t == NULL)) {
			continue;
		}
		rule_elem[len++] = (struct dt_rule_elem_spec *) t;
		if (likely(IS_RULE(t))) {
			if (likely(IS_RULE_TERM((struct dt_rule *) t))) {
				if (((struct dt_rule *) t)->spec.pos <
				    term_pos) {
					term_rule = (struct dt_rule *) t;
					term_pos = term_rule->spec.pos;
				}
			} else if (((struct dt_rule *) t)->spec.pos <
				   nonterm_pos) {
				nonterm_pos = ((struct dt_rule *)
					       t)->spec.pos;
			}
		} else {
			if (((struct dt_elem *) t)->term_rule != NULL &&
			    ((struct dt_elem *) t)->term_rule->spec.pos <
			    term_pos) {
				term_rule = ((struct dt_elem *)
					     t)->term_rule;
				term_pos = term_rule->spec.pos;
				assert(IS_RULE_TERM(term_rule));
			}
			assert(((struct dt_elem *) t)->ntm_rules.len > 0);
			if (((struct dt_rule *)
			     ((struct dt_elem *) t)->ntm_rules.p[0])->spec.pos
			    < nonterm_pos) {
				nonterm_pos = ((struct dt_rule *)
					       ((struct dt_elem *)
						t)->ntm_rules.p[0])->spec.pos;
			}
		}
	} while (i < max);
		
	/* optimization for the ideal case that no non-terminal rules
	   (function based matches or no terminal target) exist */
	if (likely(term_pos < nonterm_pos)) {
		assert(term_rule != NULL);
		if (ptrblock_append(&b, term_rule) < 0) {
			ERR("ptrblock_append failed");
		}
		return b;
	}

	/* initialize ntm_rule, ntm_end, ntm_rule_sz, ntm_cur_ind and
	   ntm_next_pos now that term_pos is given */
	ntm_rule_sz = ntm_cur_ind = 0;
	ntm_next_pos = UINT_MAX;
	for (i = 0; i < len; i++) {
		assert(rule_elem[i] != NULL);
		if (likely(IS_RULE(rule_elem[i]))) {
			struct dt_rule **r = (struct dt_rule **) &rule_elem[i];
			__u32 pos = (*r)->spec.pos;
			if (!IS_RULE_TERM(*r) && pos < term_pos) {
				if (pos == nonterm_pos) {
					ntm_cur_ind = ntm_rule_sz;
				} else if (pos < ntm_next_pos) {
					ntm_next_pos = pos;
				}
				ntm_rule[ntm_rule_sz] = r;
				ntm_end[ntm_rule_sz++] = r;
			}
		} else {
			struct dt_elem *e = (struct dt_elem *) rule_elem[i];
			__u32 pos = ((struct dt_rule *)
				     *e->ntm_rules.p)->spec.pos;
			if (pos < term_pos) {
				if (pos == nonterm_pos) {
					ntm_cur_ind = ntm_rule_sz;
				} else if (pos < ntm_next_pos) {
					ntm_next_pos = pos;
				}
				ntm_rule[ntm_rule_sz] =
					(struct dt_rule **) e->ntm_rules.p;
				ntm_end[ntm_rule_sz++] = (struct dt_rule **)
					&e->ntm_rules.p[e->ntm_rules.len - 1];
			}
		}
	}
	assert(ntm_rule_sz > 0);
	
	/* process non-terminal rules in order up to term_pos */
	ntm_next_pos = ntm_next_pos < term_pos ? ntm_next_pos : term_pos;
	while (ntm_rule_sz > 0 &&
	       (*ntm_rule[ntm_cur_ind])->spec.pos < ntm_next_pos) {
		
		/* match packet against current block of rules */
		for (; (ntm_rule[ntm_cur_ind] <= ntm_end[ntm_cur_ind] &&
			(*ntm_rule[ntm_cur_ind])->spec.pos < ntm_next_pos);
		     ntm_rule[ntm_cur_ind]++) {

			switch (action =
				match_packet_debug(&b,
						   (struct dimtree *) hipac,
						   packet, 
						   *ntm_rule[ntm_cur_ind])) {

			    case TARGET_NONE:
				    break;
			    default:
				    assert(action == TARGET_ACCEPT ||
					   action == TARGET_DROP);
				    return b;
			}
		}

		/* remove current block of rules if no rule is left that may
		   be matched */
		if (ntm_rule[ntm_cur_ind] > ntm_end[ntm_cur_ind] ||
		    (*ntm_rule[ntm_cur_ind])->spec.pos >= term_pos) {
			ntm_rule_sz--;
			assert(ntm_cur_ind <= ntm_rule_sz);
			ntm_rule[ntm_cur_ind] = ntm_rule[ntm_rule_sz];
			ntm_end[ntm_cur_ind] = ntm_end[ntm_rule_sz];
		}

		/* set ntm_cur_ind and ntm_next_pos for next run */
		new_next = term_pos;
		for (i = 0; i < ntm_rule_sz; i++) {
			if ((*ntm_rule[i])->spec.pos == ntm_next_pos) {
				ntm_cur_ind = i;
			} else if ((*ntm_rule[i])->spec.pos < new_next) {
				new_next = (*ntm_rule[i])->spec.pos;
			}
		}
		ntm_next_pos = new_next;
	}

	/* terminal rule or policy matches */
	assert(term_rule != NULL);
	if (ptrblock_append(&b, term_rule) < 0) {
		ERR("ptrblock_append failed");
	}
	return b;
}

#  endif  // DEBUG

#endif    // SINGLE_PATH
