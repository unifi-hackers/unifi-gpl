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
 * Licenced under the GNU General Public Licence, version 2.
 */


#ifndef _RLP_H
#define _RLP_H

#include "global.h"


/* rlp header */
struct rlp_spec
{
	unsigned rlp       :  1; // rlp identifier (must be 1)
	unsigned bittype   :  1; // {BIT_U16, BIT_U32}
	unsigned dimid     :  5; // dimension id
	unsigned newspec   :  1; // indicates whether the rlp is contained
                              	 // in newspec
	unsigned num       : 24; // number of elements in the rlp

#ifdef SINGLE_PATH
	struct gen_spec * (*locate)(const struct rlp_spec *spec,
				    const void *packet, int *hotdrop);
#else
	struct gen_spec * (*locate)(const struct rlp_spec *spec,
				    const void *packet, int *hotdrop,
				    struct gen_spec **nodes, __u8 *nodes_len);
#endif
};

/* rlp header test */
#define IS_RLP(r) (((struct gen_spec *) (r))->rlp)

/* test whether rlp has a wildcard pointer */
#ifdef SINGLE_PATH
#  define HAS_WILDCARD_SPEC(spec) 0
#  define HAS_WILDCARD_DIM(dimid) 0
#else
#  define HAS_WILDCARD_SPEC(spec) ((spec)->dimid == 1 || (spec)->dimid == 2)
#  define HAS_WILDCARD_DIM(dimid) ((dimid) == 1 || (dimid) == 2)
#endif

/* wildcard pointer to the next rlp spec */
#define WILDCARD(r) ((struct gen_spec **) ((__u8 *) (r) +            \
					   sizeof(struct rlp_spec)))

/* key and nextspec pointer found by rlp_locate */
struct locate_inf
{
	__u32 key;
	struct gen_spec **nextspec;
};


/* return address of termrule pointer */
struct ptrblock **
termrule(const struct rlp_spec *spec);

/* return new rlp with ins_num (1 or 2) elements inserted; the elements
   are (key[i], nextspec[i]) where 0 <= i < ins_num; if ins_num == 2 then
   key[1] > key[0] */
struct rlp_spec *
rlp_new(__u8 bittype, __u8 dimid, __u8 ins_num, const __u32 key[],
	struct gen_spec *nextspec[]);

/* return the size of the rlp */
__u32
rlp_size(const struct rlp_spec *spec);

/* return array of spec->num nextspec pointers;
   NOTE: this abstraction breaks as soon as the RLP solving data structure does
         not contain a contiguous array of nextspec pointers */
struct gen_spec **
rlp_nextspec(const struct rlp_spec *spec);

static inline void
rlp_free(struct rlp_spec *spec)
{
	struct ptrblock *term;
	
	if (spec == NULL) {
		ARG_MSG;
		return;
	}
	term = *termrule(spec);
	if (term != NULL) {
		ptrblock_free(term);
	}
	hp_free(spec);
}

static inline int
rlp_spec_eq(const struct rlp_spec *spec1, const struct rlp_spec *spec2)
{
	if (spec1 == NULL || spec2 == NULL || !IS_RLP(spec1) ||
	    !IS_RLP(spec2)) {
		ARG_MSG;
		return 0;
	}
	return spec1->bittype == spec2->bittype &&
		spec1->dimid == spec2->dimid &&
		spec1->num == spec2->num;
}

/* clone rlp (not recursively);
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
rlp_clone(const struct rlp_spec *spec, struct rlp_spec **clone);

/* insert (key[i], nextspec[i]) into the rlp where 0 <= i < ins_num <= 2
   and store the new rlp in result; if ins_num == 2 then key[1] must
   be > key[0];
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
rlp_insert(const struct rlp_spec *spec, __u8 ins_num, const __u32 key[],
	   struct gen_spec *nextspec[], struct rlp_spec **result);

/* delete (key[i], nextspec[i]) from the rlp where 0 <= i < del_num <= 2
   and nextspec[i] is associated with key[i] and store the new rlp in
   result; if del_num == 2 then key[1] must be > key[0];
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
rlp_delete(const struct rlp_spec *spec, __u8 del_num, const __u32 key[],
	   struct rlp_spec **result);

/* return (key', nextspec) where key' = min{k : k >= key} and nextspec
   is associated with key';
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
rlp_locate(const struct rlp_spec *spec, struct locate_inf *inf, __u32 key);

#endif
