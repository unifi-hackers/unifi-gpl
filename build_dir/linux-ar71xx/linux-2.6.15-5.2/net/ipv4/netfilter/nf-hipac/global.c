/*
 *             High performance packet classification 
 *                     <http://www.hipac.org>
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

#define LEN(array) (sizeof(array) / sizeof(*(array)))


__u64 mem_max = 0;
__u64 mem_current_tight = 0;
__u64 mem_current_real = 0;
static struct ihash *memhash = NULL;


void *
hp_alloc(__u32 size, int do_add)
{
	__u32 sz_real;
	void *p;

	if (unlikely(size == 0 || size >= 0x80000000)) {
		ARG_MSG;
		return NULL;
	}
	if (unlikely(memhash == NULL)) {
		memhash = ihash_new(INITIAL_MEMHASH_LEN, 1,
				    MEMHASH_AVRG_ELEM_PER_BUCKET,
				    ihash_func_val, eq_val);
		if (memhash == NULL) {
			ERR("unable to create memhash");
			return NULL;
		}
	}
	if (size <= PAGE_SIZE) {
		sz_real = mini_alloc_size(size);
		if (unlikely(do_add && mem_current_real + sz_real > mem_max)) {
			goto mem_max_reached;
		}
		p = mini_alloc(size);
	} else {
		sz_real = big_alloc_size(size);
		if (unlikely(do_add && mem_current_real + sz_real > mem_max)) {
			goto mem_max_reached;
		}
		p = big_alloc(size);
	}
	if (p == NULL) {
		return NULL;
	}
	if (ihash_insert(&memhash, p,
			 val_to_ptr(((!!do_add) << 31) | size)) < 0) {
		if (size <= PAGE_SIZE) {
			mini_free(p);
		} else {
			big_free(p);
		}
		return NULL;
	}
	if (do_add) {
		mem_current_tight += size;
		mem_current_real += sz_real;
	}
	return p;
	
 mem_max_reached:
	return NULL;
}

void
hp_free(void *p)
{
	__u32 size, sz_real, do_add;
	void *inf;

	if (unlikely(p == NULL)) {
		ARG_MSG;
		return;
	}
	if (unlikely(memhash == NULL)) {
		ERR("hp_free called before hp_alloc");
		return;
	}
	inf = ihash_lookup_val(memhash, p);
	if (unlikely(inf == NULL)) {
		ERR("pointer %p not in memhash", p);
		return;
	}
	size = ptr_to_val(inf);
	do_add = size & 0x80000000;
	size &= 0x7FFFFFFF;
	if (size <= PAGE_SIZE) {
		mini_free(p);
		if (unlikely(ihash_delete(memhash, p, NULL) < 0)) {
			goto hashdel_failed;
		}
		if (!do_add) {
			return;
		}
		sz_real = mini_alloc_size(size);
	} else {
		big_free(p);
		if (unlikely(ihash_delete(memhash, p, NULL) < 0)) {
			goto hashdel_failed;
		}
		if (!do_add) {
			return;
		}
		sz_real = big_alloc_size(size);
	}
	mem_current_tight -= size;
	mem_current_real -= sz_real;
	return;

 hashdel_failed:
	ERR("memhash delete failed");
	return;
}

void *
hp_realloc(void *p, __u32 newsize)
{
	__u32 sz, sz_real, newsz_real, do_add;
	void *inf, *newp;

	if (unlikely(newsize == 0 || newsize >= 0x80000000 || p == NULL)) {
		ARG_MSG;
		return NULL;
	}
	if (unlikely(memhash == NULL)) {
		ERR("hp_realloc called before hp_alloc");
		return NULL;
	}
	inf = ihash_lookup_val(memhash, p);
	if (unlikely(inf == NULL)) {
		ERR("pointer %p not in memhash\n", p);
		return NULL;
	}
	sz = ptr_to_val(inf);
	do_add = sz & 0x80000000;
	sz &= 0x7FFFFFFF;
	sz_real = sz <= PAGE_SIZE ? mini_alloc_size(sz) : big_alloc_size(sz);
	if (newsize <= PAGE_SIZE) {
		newsz_real = mini_alloc_size(newsize);
		if (sz_real == newsz_real) {
			goto only_size_change;
		}
		if (unlikely(do_add && mem_current_real + newsz_real >
			     mem_max + sz_real)) {
			if (newsize <= sz) {
				goto only_size_change;
			}
			goto mem_max_reached;
		}
		newp = mini_alloc(newsize);
	} else {
		newsz_real = big_alloc_size(newsize);
		if (sz_real == newsz_real) {
			goto only_size_change;
		}
		if (unlikely(do_add && mem_current_real + newsz_real >
			     mem_max + sz_real)) {
			if (newsize <= sz) {
				goto only_size_change;
			}
			goto mem_max_reached;
		}
		newp = big_alloc(newsize);
	}
	if (newp == NULL) {
		if (newsize <= sz) {
			goto only_size_change;
		}
		return NULL;
	}
	if (unlikely(ihash_replace(&memhash, p, NULL, newp,
				   val_to_ptr(((!!do_add) << 31) |
					      newsize)) < 0)) {
		if (newsize <= PAGE_SIZE) {
			mini_free(newp);
		} else {
			big_free(newp);
		}
		if (newsize <= sz) {
			goto only_size_change;
		}
		return NULL;
	}
	memcpy(newp, p, sz < newsize ? sz : newsize);
	if (sz <= PAGE_SIZE) {
		mini_free(p);
	} else {
		big_free(p);
	}
	if (do_add) {
		mem_current_tight += newsize;
		mem_current_tight -= sz;
		mem_current_real += newsz_real;
		mem_current_real -= sz_real;
	}
	return newp;

 mem_max_reached:
	return NULL;

 only_size_change:
	if (unlikely(ihash_replace(&memhash, p, NULL, p,
				   val_to_ptr(((!!do_add) << 31) |
					      newsize)) < 0)) {
		ERR("unable to replace memhash entry");
		return NULL;
	}
	if (do_add) {
		mem_current_tight += newsize;
		mem_current_tight -= sz;
	} 
	return p;
}

hipac_error
hp_size(void *p, __u64 *size_real, __u64 *size_tight)
{
	void *inf;
	__u32 size;
	
	if (unlikely(size_real == NULL || size_tight == NULL)) {
		ARG_ERR;
	}
	if (unlikely(p == NULL)) {
		return HE_OK;
	}
	inf = ihash_lookup_val(memhash, p);
	if (unlikely(inf == NULL)) {
		IMPOSSIBLE_CONDITION("size request for unkown pointer");
	}
	size = ((__u32) ptr_to_val(inf)) & 0x7FFFFFFF;
	*size_tight += size;
	*size_real += size <= PAGE_SIZE ? mini_alloc_size(size) :
		big_alloc_size(size);
	return HE_OK;
}

void
hp_mem_exit(void)
{
	if (unlikely(memhash == NULL)) {
		return;
	}
	if (unlikely(memhash->elem_ct != 0)) {
		WARN("memhash still contains unfreed pointers");
	}
	if (unlikely(mem_current_tight != 0)) {
		WARN("mem_current_tight is not 0");
	}
	if (unlikely(mem_current_real != 0)) {
		WARN("mem_current_real is not 0");
	}
	ihash_free(memhash);
	memhash = NULL;
}

hipac_error
hipac_get_mem_stat(struct hipac_mem_stat *stat)
{
	struct ihash_stat istat;

	if (stat == NULL) {
		ARG_ERR;
	}
	if (sizeof(istat.bucket_dist) != sizeof(stat->memhash_bucket_stat)) {
		IMPOSSIBLE_CONDITION("struct ihash_stat and struct "
				     "hipac_mem_stat incompatible");
	}
	if (ihash_stat(memhash, &istat) < 0) {
		IMPOSSIBLE_CONDITION("ihash_stat failed");
	}
	
	stat->total_mem_tight = mem_current_tight;
	stat->total_mem_real = mem_current_real;
	stat->memhash_elem_num = istat.elem_ct;
	stat->memhash_len = istat.bucket_len;
	stat->memhash_smallest_bucket_len = istat.small_bucket_len;
	stat->memhash_biggest_bucket_len = istat.big_bucket_len;
	memcpy(stat->memhash_bucket_stat, istat.bucket_dist,
	       sizeof(istat.bucket_dist));
	return HE_OK;
}



/*
 * statistical distributions
 */

void
stat_distribution_add(__u32 dist[], __u32 len, __u32 val)
{
	__u32 i;

	if (unlikely(dist == NULL || len == 0)) {
		ARG_MSG;
		return;
	}
	
	for (i = 0; i < len - 1; i++) {
		if (val <= (1 << i) - 1) {
			dist[i]++;
			return;
		}
	}
	dist[i]++;
}



/*
 * pointer block
 */

struct ptrblock *
ptrblock_new(void *p, int do_add)
{
	struct ptrblock *new;
	
	if (unlikely(p == NULL)) {
		ARG_MSG;
		return NULL;
	}
	new = hp_alloc(sizeof(*new) + sizeof(*new->p), do_add);
	if (new == NULL) {
		return NULL;
	}
	new->len = 1;
	new->p[0] = p;
	return new;
}

int
ptrblock_eq(const struct ptrblock *b1, const struct ptrblock *b2)
{
	__u32 i;
	
	if (b1 == b2) {
		return 1;
	}
	if (b1 == NULL || b2 == NULL || b1->len != b2->len) {
		return 0;
	}
	/* b1->len == 0 is valid if b1 and b2 are embedded ptrblocks */
	for (i = 0; i < b1->len; i++) {
		if (b1->p[i] != b2->p[i]) {
			return 0;
		}
	}
	return 1;
}

hipac_error
ptrblock_clone(struct ptrblock *b, struct ptrblock **clone)
{
	__u32 sz;

	if (unlikely(clone == NULL)) {
		ARG_ERR;
	}

	if (b == NULL) {
		*clone = NULL;
		return HE_OK;
	}
	sz = ptrblock_size(b);
	*clone = hp_alloc(sz, 1);
	if (*clone == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*clone, b, sz);
	return HE_OK;
}

hipac_error
ptrblock_insert(struct ptrblock **b, void *p, __u32 pos)
{
	struct ptrblock *new;

	if (unlikely(p == NULL || b == NULL || (*b == NULL && pos > 0) ||
		     (*b != NULL && pos > (*b)->len))) {
		ARG_ERR;
	}

	if (*b == NULL) {
		new = ptrblock_new(p, 1);
		if (new == NULL) {
			return HE_LOW_MEMORY;
		}
		*b = new;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + ((*b)->len + 1) * sizeof(*(*b)->p));
	if (new == NULL) {
		return HE_LOW_MEMORY;
	}
	if (new->len > pos) {
		memmove(&new->p[pos + 1], &new->p[pos], (new->len - pos) *
			sizeof(*new->p));
	}
	new->len++;
	new->p[pos] = p;
	*b = new;
	return HE_OK;
}

hipac_error
ptrblock_insert_embed(void **o, __u32 ptrblock_offset, void *p, __u32 pos)
{
	struct ptrblock *b;
	void *new;

	if (unlikely(o == NULL || *o == NULL || p == NULL ||
		     pos > ((struct ptrblock *)
			    ((char *) *o + ptrblock_offset))->len)) {
		ARG_ERR;
	}
	b = (struct ptrblock *) ((char *) *o + ptrblock_offset);
	new = hp_realloc(*o, ptrblock_offset + sizeof(*b) +
			 (b->len + 1) * sizeof(*b->p));
	if (new == NULL) {
		return HE_LOW_MEMORY;
	}
	b = (struct ptrblock *) ((char *) new + ptrblock_offset);
	if (b->len > pos) {
		memmove(&b->p[pos + 1], &b->p[pos], (b->len - pos) *
			sizeof(*b->p));
	}
	b->len++;
	b->p[pos] = p;
	*o = new;
	return HE_OK;
}

hipac_error
ptrblock_append(struct ptrblock **b, void *p)
{
	struct ptrblock *new;

	if (unlikely(p == NULL || b == NULL)) {
		ARG_ERR;
	}

	if (*b == NULL) {
		new = ptrblock_new(p, 1);
		if (new == NULL) {
			return HE_LOW_MEMORY;
		}
		*b = new;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + ((*b)->len + 1) * sizeof(*(*b)->p));
	if (new == NULL) {
		return HE_LOW_MEMORY;
	}
#ifdef DEBUG
	{
		__u32 i;
		for (i = 0; i < new->len; i++) {
			if (new->p[i] == p) {
				IMPOSSIBLE_CONDITION("ptrblock contains "
						     "duplicated pointer");
			}
		}
	}
#endif
	new->p[new->len++] = p;
	*b = new;
	return HE_OK;
}

hipac_error
ptrblock_delete_pos(struct ptrblock **b, __u32 pos)
{
	struct ptrblock *new;

	if (unlikely(b == NULL || *b == NULL || pos >= (*b)->len)) {
		ARG_ERR;
	}

	if ((*b)->len == 1) {
		ptrblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	(*b)->len--;
	if ((*b)->len > pos) {
		memmove(&(*b)->p[pos], &(*b)->p[pos + 1],
			((*b)->len - pos) * sizeof(*(*b)->p));
	}
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * sizeof(*(*b)->p));
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}

hipac_error
ptrblock_delete_pos_embed(void **o, __u32 ptrblock_offset, __u32 pos)
{
	struct ptrblock *new;
	struct ptrblock *b;

	if (unlikely(o == NULL || *o == NULL ||
		     pos >= ((struct ptrblock *)
			     ((char *) *o + ptrblock_offset))->len)) {
		ARG_ERR;
	}
	b = (struct ptrblock *) ((char *) *o + ptrblock_offset);
	b->len--;
	if (b->len > pos) {
		memmove(&b->p[pos], &b->p[pos + 1],
			(b->len - pos) * sizeof(*b->p));
	}
	new = hp_realloc(*o, ptrblock_offset + sizeof(*b) +
			 b->len * sizeof(*b->p));
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*o = new;
	}
	return HE_OK;
}

hipac_error
ptrblock_delete(struct ptrblock **b, void *p)
{
	__u32 i;

	if (unlikely(b == NULL || *b == NULL)) {
		ARG_ERR;
	}
	for (i = 0; i < (*b)->len; i++) {
		if ((*b)->p[i] == p) {
			return ptrblock_delete_pos(b, i);
		}
	}
	IMPOSSIBLE_CONDITION("pointer %p not in ptrblock", p);
}

hipac_error
ptrblock_delete_tail(struct ptrblock **b)
{
	struct ptrblock *new;

	if (unlikely(b == NULL || *b == NULL)) {
		ARG_ERR;
	}

	if ((*b)->len == 1) {
		ptrblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	(*b)->len--;
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * sizeof(*(*b)->p));
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}

hipac_error
ptrblock_delete_multi(struct ptrblock **b, const struct ptrblock *mark)
{
	struct ptrblock *new;
	__u32 first, last, i;

	if (unlikely(b == NULL || mark == NULL ||
		     (*b != NULL && mark->len < (*b)->len))) {
		ARG_ERR;
	}

	if (*b == NULL) {
		return HE_OK;
	}
	for (first = 0; first < (*b)->len && mark->p[first] != NULL; first++);
	if (first == (*b)->len) {
		/* nothing to delete */
		return HE_OK;
	}
	for (last = first + 1, i = 0; last < (*b)->len; last++) {
		if (mark->p[last] != NULL) {
			continue;
		}
		if (last > first + 1) {
			memmove(&(*b)->p[first - i], &(*b)->p[first + 1],
				(last - first - 1) * sizeof(*(*b)->p));
		}
		i++;
		first = last;
	}
	if ((*b)->len > first + 1) {
		memmove(&(*b)->p[first - i], &(*b)->p[first + 1],
			((*b)->len - first - 1) * sizeof(*(*b)->p));
	}
	(*b)->len -= i + 1;
	if ((*b)->len == 0) {
		ptrblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * sizeof(*(*b)->p));
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}

hipac_error
ptrblock_delete_null(struct ptrblock **b)
{
	struct ptrblock *new;
	__u32 first, last, i;

	if (unlikely(b == NULL)) {
		ARG_ERR;
	}

	if (*b == NULL) {
		return HE_OK;
	}
	for (first = 0; first < (*b)->len && (*b)->p[first] != NULL; first++);
	if (first == (*b)->len) {
		/* nothing to delete */
		return HE_OK;
	}
	for (last = first + 1, i = 0; last < (*b)->len; last++) {
		if ((*b)->p[last] != NULL) {
			continue;
		}
		if (last > first + 1) {
			memmove(&(*b)->p[first - i], &(*b)->p[first + 1],
				(last - first - 1) * sizeof(*(*b)->p));
		}
		i++;
		first = last;
	}
	if ((*b)->len > first + 1) {
		memmove(&(*b)->p[first - i], &(*b)->p[first + 1],
			((*b)->len - first - 1) * sizeof(*(*b)->p));
	}
	(*b)->len -= i + 1;
	if ((*b)->len == 0) {
		ptrblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * sizeof(*(*b)->p));
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}



/*
 * block of structs
 */
struct strblock *
strblock_new(const void *s, __u32 size, int do_add)
{
	struct strblock *new;
	
	if (unlikely(s == NULL || size == 0)) {
		ARG_MSG;
		return NULL;
	}
	new = hp_alloc(sizeof(*new) + size, do_add);
	if (new == NULL) {
		return NULL;
	}
	new->len = 1;
	new->size = size;
	memcpy(new->d, s, size);
	return new;
}

int
strblock_eq(const struct strblock *b1, const struct strblock *b2,
	    int (* eq) (void *, void *))
{
	__u32 i;

	if (b1 == b2) {
		return 1;
	}
	if (b1 == NULL || b2 == NULL || b1->len != b2->len ||
	    b1->size != b2->size) {
		return 0;
	}
	assert(b1->len > 0);
	for (i = 0; i < b1->len; i++) {
		if (!eq(STRBLOCK_ITH(b1, i, void *),
			STRBLOCK_ITH(b2, i, void *))) {
			return 0;
		}
	}
	return 1;
}

hipac_error
strblock_clone(struct strblock *b, struct strblock **clone)
{
	__u32 sz;

	if (unlikely(clone == NULL)) {
		ARG_ERR;
	}

	if (b == NULL) {
		*clone = NULL;
		return HE_OK;
	}
	sz = strblock_size(b);
	*clone = hp_alloc(sz, 1);
	if (*clone == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*clone, b, sz);
	return HE_OK;
}

hipac_error
strblock_insert(struct strblock **b, const void *s, __u32 size, __u32 pos)
{
	struct strblock *new;

	if (unlikely(s == NULL || b == NULL ||
		     (*b == NULL && (pos > 0 || size == 0)) ||
		     (*b != NULL && (pos > (*b)->len ||
				     (*b)->size != size)))) {
		ARG_ERR;
	}

	if (*b == NULL) {
		new = strblock_new(s, size, 1);
		if (new == NULL) {
			return HE_LOW_MEMORY;
		}
		*b = new;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + ((*b)->len + 1) * size);
	if (new == NULL) {
		return HE_LOW_MEMORY;
	}
	if (new->len > pos) {
		memmove(STRBLOCK_ITH(new, pos + 1, void *),
			STRBLOCK_ITH(new, pos, void *),
			(new->len - pos) * size);
	}
	new->len++;
	memcpy(STRBLOCK_ITH(new, pos, void *), s, size);
	*b = new;
	return HE_OK;
}

hipac_error
strblock_append(struct strblock **b, const void *s, __u32 size)
{
	struct strblock *new;

	if (unlikely(s == NULL || b == NULL || (*b == NULL && size == 0) ||
		     (*b != NULL && (*b)->size != size))) {
		ARG_ERR;
	}

	if (*b == NULL) {
		new = strblock_new(s, size, 1);
		if (new == NULL) {
			return HE_LOW_MEMORY;
		}
		*b = new;
		return HE_OK;
	}
	new = hp_realloc(*b, sizeof(**b) + ((*b)->len + 1) * size);
	if (new == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(STRBLOCK_ITH(new, new->len, void *), s, size);
	new->len++;
	*b = new;
	return HE_OK;
}

hipac_error
strblock_delete_pos(struct strblock **b, __u32 pos)
{
	struct strblock *new;

	if (unlikely(b == NULL || *b == NULL || pos >= (*b)->len)) {
		ARG_ERR;
	}

	if ((*b)->len == 1) {
		strblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	(*b)->len--;
	if ((*b)->len > pos) {
		memmove(STRBLOCK_ITH(*b, pos, void *),
			STRBLOCK_ITH(*b, pos + 1, void *),
			((*b)->len - pos) * (*b)->size);
	}
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * (*b)->size);
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}

hipac_error
strblock_delete_tail(struct strblock **b)
{
	struct strblock *new;

	if (unlikely(b == NULL || *b == NULL)) {
		ARG_ERR;
	}

	if ((*b)->len == 1) {
		strblock_free(*b);
		*b = NULL;
		return HE_OK;
	}
	(*b)->len--;
	new = hp_realloc(*b, sizeof(**b) + (*b)->len * (*b)->size);
	if (new == NULL) {
		WARN("hp_realloc returns NULL although less memory was "
		     "requested");
	} else {
		*b = new;
	}
	return HE_OK;
}



/*
 * pointer list
 */

struct ptrlist *
ptrlist_new(void)
{
	struct ptrlist *new;

	new = mini_alloc(sizeof(*new));
	if (new == NULL) {
		return NULL;
	}
	new->len = 0;
	INIT_LIST_HEAD(&new->head);
	return new;
}

struct ptrlist_entry *
ptrlist_new_entry(void *p)
{
	struct ptrlist_entry *new;

	new = mini_alloc(sizeof(*new));
	if (new == NULL) {
		return NULL;
	}
	new->p = p;
	return new;
}

void
ptrlist_flush(struct ptrlist *l)
{
	struct list_head *lh;

	if (unlikely(l == NULL)) {
		ARG_MSG;
		return;
	}
	for (lh = l->head.next; lh != &l->head;) {
		lh = lh->next;
		mini_free(list_entry(lh->prev, struct ptrlist_entry, head));
	}
	INIT_LIST_HEAD(&l->head);
	l->len = 0;
}

void
ptrlist_free(struct ptrlist *l)
{
	struct list_head *lh;

	if (unlikely(l == NULL)) {
		ARG_MSG;
		return;
	}
	for (lh = l->head.next; lh != &l->head;) {
		lh = lh->next;
		mini_free(list_entry(lh->prev, struct ptrlist_entry, head));
	}
	mini_free(l);
}

hipac_error
ptrlist_add(struct ptrlist *l, void *p, int check_dup)
{
	struct list_head *lh;
	struct ptrlist_entry* e;

	if (unlikely(l == NULL || p == NULL)) {
		ARG_ERR;
	}
	if (unlikely(check_dup)) {
		list_for_each(lh, &l->head) {
			e = list_entry(lh, struct ptrlist_entry, head);
			if (e->p == p) {
				IMPOSSIBLE_CONDITION("pointer %p already in "
						     "ptrlist", p);
			}
		}
	}
	e = mini_alloc(sizeof(*e));
	if (e == NULL) {
		return HE_LOW_MEMORY;
	}
	e->p = p;
	list_add_tail(&e->head, &l->head);
	l->len++;
	return HE_OK;
}
