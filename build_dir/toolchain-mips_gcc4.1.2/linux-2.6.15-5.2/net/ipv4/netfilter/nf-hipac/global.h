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


#ifndef _GLOBAL_H
#define _GLOBAL_H

#include "mode.h"
#include "hipac.h"  // hipac_error

#define INITIAL_MEMHASH_LEN          64
#define MEMHASH_AVRG_ELEM_PER_BUCKET 15
#define INITIAL_NEWSPEC_LEN          1024
#define NEWSPEC_AVRG_ELEM_PER_BUCKET 3

#ifdef DEBUG
#  define DPRINT(type, str, args...) if ((type) & hipac_debug)  \
                                          printk(str , ## args)
#else
#  define DPRINT(type, str, args...) do {} while (0)
#endif

/* the single space before the last ',' is vital to make this macro work the
   expected way because of some idiosyncrasy of gcc */
#ifdef DEBUG
#  define MSG(type, str, args...)                                           \
   printk(type "%-15s : %-30s : %6d :   " str "\n", __FILE__, __FUNCTION__, \
	  __LINE__ , ## args)
#else
#  define MSG(type, str, args...)                             \
   printk(type "%s:%s:%d: " str "\n", __FILE__, __FUNCTION__, \
	  __LINE__ , ## args)
#endif

#define ERR(str, args...)    MSG(KERN_ERR, str , ## args)
#define WARN(str, args...)   MSG(KERN_WARNING, str , ## args)
#define NOTICE(str, args...) MSG(KERN_NOTICE, str , ## args)
#define DBG(str, args...)    MSG(KERN_DEBUG, str , ## args)
#define ARG_MSG              MSG(KERN_ERR, "function arguments invalid")

#define ARG_ERR                                      \
do {                                                 \
	MSG(KERN_ERR, "function arguments invalid"); \
	return HE_IMPOSSIBLE_CONDITION;              \
} while (0)

#define IMPOSSIBLE_CONDITION(str, args...) \
do {                                       \
	MSG(KERN_ERR, str , ## args);      \
	return HE_IMPOSSIBLE_CONDITION;    \
} while (0)



/* generic header for dimtree rules, elementary intervals and rlps */
struct gen_spec
{
	unsigned rlp : 1;
};

/* dimid to bittype array */
extern __u8 *dim2btype;

/* match executor function */
extern hipac_match_exec_t match_fn;

/* target executor function */
extern hipac_target_exec_t target_fn;

/* dimension extractor function */
extern hipac_extract_t *extract_fn;



/*
 * memory management wrappers
 */

/* upper bound for memory consumption in bytes */
extern __u64 mem_max;

/* current memory consumption in bytes in terms of how much
   has been requested */
extern __u64 mem_current_tight;

/* current memory consumption in bytes in terms of how much
   has actually been allocated */
extern __u64 mem_current_real;

/* do_add indicates whether mem_current_tight and mem_current_real 
   should be updated or not */
void *
hp_alloc(__u32 size, int do_add);

void
hp_free(void *p);

void *
hp_realloc(void *p, __u32 newsize);

/* add the number of bytes requested for p to *size_tight and the number
   of bytes allocated for p to *size_real; if p is NULL, size_tight and
   size_real are not modified;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
hp_size(void *p, __u64 *size_real, __u64 *size_tight);

/* internal memhash is freed; if it is not empty a warning is printed */
void
hp_mem_exit(void);



/*
 * statistical distributions
 */

/* initialize statistical distribution dist of length len, i.e. set it to 0 */
static inline void
stat_distribution_init(__u32 dist[], __u32 len)
{
	if (unlikely(dist == NULL || len == 0)) {
		ARG_MSG;
		return;
	}
	memset(dist, 0, len * sizeof(*dist));
}

/* dist is an array of length len representing a statistical distribution;
   val is added to dist */
void
stat_distribution_add(__u32 dist[], __u32 len, __u32 val);



/*
 * pointer block
 */
struct ptrblock
{
	__u32 len;
	void *p[0];
};

/* return new pointer block with p as the only element; do_add indicates
   whether mem_current_tight and mem_current_real should be updated or not */
struct ptrblock *
ptrblock_new(void *p, int do_add);

static inline void
ptrblock_free(struct ptrblock *b)
{
	hp_free(b);
}

static inline __u32
ptrblock_size(const struct ptrblock *b)
{
	if (unlikely(b == NULL)) {
		ARG_MSG;
		return 0;
	}
	return sizeof(*b) + b->len * sizeof(*b->p);
}

/* returns 1 if b1 and b2 are equal and 0 otherwise; b1->len or b2->len might
   be 0 in order allow equality test on embedded ptrblocks */
int
ptrblock_eq(const struct ptrblock *b1, const struct ptrblock *b2);

/* clone b and store the result in clone; the memory for clone is allocated
   via hp_alloc if necessary and do_add is 1; b might be NULL;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_clone(struct ptrblock *b, struct ptrblock **clone);

/* insert p into b at position pos; if *b is NULL and pos is 0
   ptrblock_new(p, 1) is called and the result is assigned to b;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_insert(struct ptrblock **b, void *p, __u32 pos);

/* insert p into (struct ptrblock *) ((char *) *o + ptrblock_offset)
   at position pos; o is assumed to end after the embedded ptrblock;
   hp_realloc is used to resize o;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_insert_embed(void **o, __u32 ptrblock_offset, void *p, __u32 pos);

/* append p to b; if *b is NULL ptrblock_new(p, 1) is called and the result
   is assigned to b;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_append(struct ptrblock **b, void *p);

/* delete pointer at position pos in b; if b contains only one element and
   pos is 0 then *b is freed and NULL is assigned to *b;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete_pos(struct ptrblock **b, __u32 pos);

/* delete pointer at position pos in
   (struct ptrblock *) ((char *) *o + ptrblock_offset); o is assumed to end
   after the embedded ptrblock; hp_realloc is used to resize o;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete_pos_embed(void **o, __u32 ptrblock_offset, __u32 pos);

/* delete p in b; if p is the only element in b then *b is freed and NULL
   is assigned to *b;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete(struct ptrblock **b, void *p);

/* delete trailing pointer in b; if b contains only one element then *b is
   freed and NULL is assigned to *b;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete_tail(struct ptrblock **b);

/* for all mark->p[i] == NULL: delete the pointer at the position i fom b;
   if b is empty after the delete operation NULL is assigned to *b;
   note that mark->len must be >= (*b)->len;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete_multi(struct ptrblock **b, const struct ptrblock *mark);

/* similar to ptrblock_delete_multi: the pointers in b which are NULL are
   deleted;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrblock_delete_null(struct ptrblock **b);



/*
 * block of structs
 */
struct strblock
{
	__u32 len, size;
	char d[0];
};

#define STRBLOCK_ITH(b, i, cast) ((cast) ((b)->d + (i) * (b)->size))

/* return new struct block with s as the only element; size is the size of 
   the struct pointed to by s in bytes; do_add indicates whether
   mem_current_tight and mem_current_real should be updated or not */
struct strblock *
strblock_new(const void *s, __u32 size, int do_add);

static inline void
strblock_free(struct strblock *b)
{
	hp_free(b);
}

static inline __u32
strblock_size(const struct strblock *b)
{
	if (unlikely(b == NULL)) {
		ARG_MSG;
		return 0;
	}
	return sizeof(*b) + b->len * b->size;
}

/* returns 1 if b1 and b2 are equal and 0 otherwise; eq is an equality test
   function for the embedded structs; eq(a, b) returns 1 if a equals to b
   and 0 otherwise */
int
strblock_eq(const struct strblock *b1, const struct strblock *b2,
	    int (* eq) (void *, void *));

/* clone b and store the result in clone; the memory for clone is allocated
   via hp_alloc if necessary and do_add is 1; b might be NULL;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
strblock_clone(struct strblock *b, struct strblock **clone);

/* insert struct s into b at position pos; if *b is NULL and pos is 0
   strblock_new(s, size, 1) is called and the result is assigned to b;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
strblock_insert(struct strblock **b, const void *s, __u32 size, __u32 pos);

/* append struct s to b; if *b is NULL then strblock_new(s, size, 1) is
   called and the result is assigned to b;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
strblock_append(struct strblock **b, const void *s, __u32 size);

/* delete struct at position pos in b; if b contains only one element and
   pos is 0 then *b is freed and NULL is assigned to *b;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
strblock_delete_pos(struct strblock **b, __u32 pos);

/* delete trailing struct in b; if b contains only one element then *b is
   freed and NULL is assigned to *b;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
strblock_delete_tail(struct strblock **b);



/*
 * pointer list
 */
struct ptrlist
{
	struct list_head head;
	__u32 len;
};

struct ptrlist_entry
{
	struct list_head head;
	void *p;
};

/* return new empty pointer list or NULL if allocation fails */
struct ptrlist *
ptrlist_new(void);

/* return new pointer list entry containing p or NULL if allocation fails */
struct ptrlist_entry *
ptrlist_new_entry(void *p);

/* free all entries from the pointer list l */
void
ptrlist_flush(struct ptrlist *l);

/* free all entries from the pointer list l and l itself */
void
ptrlist_free(struct ptrlist *l);

/* free ptrlist entry */
static inline void
ptrlist_free_entry(struct ptrlist_entry *e)
{
	if (unlikely(e == NULL)) {
		ARG_MSG;
		return;
	}
	list_del(&e->head);
	mini_free(e);
}

/* return 1 if l is empty and 0 otherwise */
static inline int
ptrlist_is_empty(const struct ptrlist *l)
{
	if (unlikely(l == NULL)) {
		ARG_MSG;
		return 0;
	}
	assert((l->len != 0 || l->head.next == &l->head) &&
	       (l->head.next != &l->head || l->len == 0));
	return l->len == 0;
}

/* add a new pointer list entry containing p to l; if check_dup is not 0 
   the new entry is only added if p is not already contained in a list
   entry;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ptrlist_add(struct ptrlist *l, void *p, int check_dup);

#endif
