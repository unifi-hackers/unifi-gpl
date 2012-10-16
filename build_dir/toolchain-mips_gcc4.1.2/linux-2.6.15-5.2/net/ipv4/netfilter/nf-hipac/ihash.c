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

#define MAX_BUCKETS_MINI_ALLOC    (MINI_ALLOC_MAX / sizeof(void *))
#define INC_POSSIBLE(ihash, len)  (!(ihash)->use_mini_alloc ||     \
				   (len) <= MAX_BUCKETS_MINI_ALLOC)
#define BUCKET_SIZE(len)          (sizeof(struct ihash_bucket) + (len) * \
				   sizeof(struct ihash_keyval))
#define LEN(array)                (sizeof(array) / sizeof(*(array)))


int
eq_val(const void *key1, const void *key2)
{
	return key1 == key2;
}

__u32
ihash_func_val(const void *key)
{
#ifdef BIT32_ARCH
	/* 32 bit mix function */
	__u32 h = (__u32) key;
	
	h += ~(h << 15);
	h ^=  (h >> 10);
	h +=  (h << 3);
	h ^=  (h >> 6);
	h += ~(h << 11);
	h ^=  (h >> 16);
#else
	/* 64 bit mix function */
	__u64 h = (__u64) key;

	h += ~(h << 32);
	h ^=  (h >> 22);
	h += ~(h << 13);
	h ^=  (h >> 8);
	h +=  (h << 3);
	h ^=  (h >> 15);
	h += ~(h << 27);
	h ^=  (h >> 31);
#endif
	return h;
}

int
eq_str(const void *key1, const void *key2)
{
	return !strcmp(key1, key2);
}

__u32
ihash_func_str(const void *key)
{
	__u32 high, h = 0;
	const char *c = key;

	if (unlikely(key == NULL)) {
		ERR("key is NULL");
		return 0;
	}
	for (; *c != '\0'; c++) {
		/* CRC variant */
		high = h & 0xf8000000;
		h <<= 5;
		h ^= high >> 27;
		h ^= *c;
	}
	return h;
}

static inline __u32
near_pow2(__u32 n)
{
	if (n == 0 || n > 0x80000000) {
		return 1;
	}
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return ++n;
}

struct ihash *
ihash_new(__u32 len, int use_mini_alloc, __u32 avrg_elem_per_bucket,
	  ihash_func_t hash_fn, eq_t eq_fn)
{
	struct ihash *h;
	struct ihash_bucket **b;
	__u32 i;

	if (unlikely(hash_fn == NULL || eq_fn == NULL)) {
		ARG_MSG;
		return NULL;
	}
	h = mini_alloc(sizeof(*h));
	if (h == NULL) {
		return NULL;
	}
	if (use_mini_alloc && len > MAX_BUCKETS_MINI_ALLOC) {
		len = MAX_BUCKETS_MINI_ALLOC;
	} else {
		len = near_pow2(len);
	}
	b = use_mini_alloc ? mini_alloc(len * sizeof(*b)) :
		hp_alloc(len * sizeof(*b), 1);
	if (b == NULL) {
		mini_free(h);
		return NULL;
	}
	h->hash_fn = hash_fn;
	h->eq_fn = eq_fn;
	h->use_mini_alloc = use_mini_alloc;
	h->avrg_elem_per_bucket = avrg_elem_per_bucket;
	h->len = len;
	h->elem_ct = 0;
	h->bucket = b;
	/* strictly speaking memset(b, 0, len * sizeof(*b)) would be wrong
	   here because there are architectures where the machine
	   representation of the NULL pointer is not 0x0 */
	for (i = 0; i < len; i++) {
		b[i] = NULL;
	}
	return h;
}

void
ihash_free(struct ihash *h)
{
	__u32 i;

	if (unlikely(h == NULL)) {
		ARG_MSG;
		return;
	}
	for (i = 0; i < h->len; i++) {
		if (h->bucket[i] != NULL) {
			mini_free(h->bucket[i]);
		}
	}
	if (h->use_mini_alloc) {
		mini_free(h->bucket);
	} else {
		hp_free(h->bucket);
	}
	mini_free(h);
}

/* return values:  0 : ok
                  -1 : low memory
                  -2 : bucket cannot be enlarged further */
static inline int
insert(struct ihash *h, void *key, void *val)
{
	struct ihash_bucket *b;
	__u32 i;

	i = HASH(h->hash_fn, key, h->len);
	if (h->bucket[i] == NULL) {
		/* first element in bucket */
		b = mini_alloc(BUCKET_SIZE(1));
		if (b == NULL) {
			return -1;
		}
		b->len = 1;
		b->kv[0].key = key;
		b->kv[0].val = val;
		h->elem_ct++;
		h->bucket[i] = b;
		return 0;
	}
	if (unlikely(BUCKET_SIZE(h->bucket[i]->len + 1) > MINI_ALLOC_MAX)) {
		/* bucket cannot be enlarged further */
		return -2;
	}
	if (unlikely(mini_alloc_size(BUCKET_SIZE(h->bucket[i]->len)) !=
		     mini_alloc_size(BUCKET_SIZE(h->bucket[i]->len + 1)))) {
		/* bucket must be enlarged */
		b = mini_alloc(BUCKET_SIZE(h->bucket[i]->len + 1));
		if (b == NULL) {
			return -1;
		}
		b->len = h->bucket[i]->len + 1;
		b->kv[0].key = key;
		b->kv[0].val = val;
		memcpy(&b->kv[1], &h->bucket[i]->kv[0],
		       h->bucket[i]->len * sizeof(*b->kv));
		h->elem_ct++;
		mini_free(h->bucket[i]);
		h->bucket[i] = b;
		return 0;
	}

	h->bucket[i]->kv[h->bucket[i]->len].key = key;
	h->bucket[i]->kv[h->bucket[i]->len].val = val;
	h->bucket[i]->len++;
	h->elem_ct++;
	return 0;
}

/* return values like insert */
static inline int
rehash(struct ihash *h_old, struct ihash *h_new)
{
	__u32 i, j;
	int stat;

	for (i = 0; i < h_old->len; i++) {
		if (h_old->bucket[i] == NULL) {
			continue;
		}
		for (j = 0; j < h_old->bucket[i]->len; j++) {
			stat = insert(
				h_new, h_old->bucket[i]->kv[j].key,
				h_old->bucket[i]->kv[j].val);
			if (stat < 0) {
				return stat;
			}
		}
	}
	return 0;
}

hipac_error
ihash_insert(struct ihash **h, void *key, void *val)
{
	int shift = 1;
	int do_inc = 0;
	int stat;
	__u32 len;
	
	if (unlikely(h == NULL || *h == NULL || key == NULL)) {
		ARG_ERR;
	}
	len = (*h)->len;
	while (1) {
		if (unlikely((do_inc || (*h)->elem_ct >=
			      len * (*h)->avrg_elem_per_bucket) &&
			     INC_POSSIBLE(*h, len << shift))) {
			/* increase hash table */
			struct ihash *new;
			
			new = ihash_new(len << shift, (*h)->use_mini_alloc,
					(*h)->avrg_elem_per_bucket,
					(*h)->hash_fn, (*h)->eq_fn);
			if (new == NULL) {
				return HE_LOW_MEMORY;
			}
			stat = rehash(*h, new);
			if (stat < 0) {
				ihash_free(new);
				if (stat == -2 &&
				    INC_POSSIBLE(*h, len << ++shift)) {
					WARN("ihash bucket full after rehash "
					     "-> try again with more buckets");
					continue;
				}
				return HE_LOW_MEMORY;
			}
			ihash_free(*h);
			*h = new;
			do_inc = 0;
		}
		stat = insert(*h, key, val);
		if (stat < 0) {
			if (stat == -2 &&
			    (((*h)->elem_ct <
			      len * (*h)->avrg_elem_per_bucket &&
			      INC_POSSIBLE(*h, len << shift)) ||
			     INC_POSSIBLE(*h, len << ++shift))) {
				WARN("ihash bucket full after rehash -> try "
				     "again with more buckets");
				do_inc = 1;
				continue;
			}
			return HE_LOW_MEMORY;
		}
		return HE_OK;
	}
}

static inline void
delete(struct ihash *h, int i, int j, void **val)
{
	struct ihash_bucket *b;
	
	if (unlikely(mini_alloc_size(BUCKET_SIZE(h->bucket[i]->len)) !=
		     mini_alloc_size(BUCKET_SIZE(h->bucket[i]->len - 1)))) {
		/* shrink bucket */
		b = mini_alloc(BUCKET_SIZE(h->bucket[i]->len - 1));
		if (b != NULL) {
			b->len = h->bucket[i]->len - 1;
			if (j > 0) {
				memcpy(b->kv, h->bucket[i]->kv,
				       j * sizeof(*b->kv));
			}
			if (h->bucket[i]->len > j + 1) {
				memcpy(&b->kv[j], &h->bucket[i]->kv[j+1],
				       (h->bucket[i]->len - j - 1) *
				       sizeof(*b->kv));
			}
			if (val != NULL) {
				*val = h->bucket[i]->kv[j].val;
			}
			mini_free(h->bucket[i]);
			h->bucket[i] = b;
			h->elem_ct--;
			return;
		} else {
			WARN("unable to shrink ihash bucket");
		}
	}
	
 	if (val != NULL) {
		*val = h->bucket[i]->kv[j].val;
	}
	if (h->bucket[i]->len > j + 1) {
		memmove(&h->bucket[i]->kv[j], &h->bucket[i]->kv[j + 1],
			(h->bucket[i]->len - j - 1) * sizeof(*b->kv));
	}
	h->bucket[i]->len--;
	h->elem_ct--;
}

hipac_error
ihash_delete(struct ihash *h, const void *key, void **val)
{
	int i, j;

	if (unlikely(h == NULL || key == NULL)) {
		ARG_ERR;
	}
	i = HASH(h->hash_fn, key, h->len);
	if (unlikely(h->bucket[i] == NULL)) {
		goto not_contained;
	}
	for (j = h->bucket[i]->len - 1; j >= 0; j--) {
		if (h->eq_fn(h->bucket[i]->kv[j].key, key)) {
			delete(h, i, j, val);
			return HE_OK;
		}
	}
	
 not_contained:
	IMPOSSIBLE_CONDITION("key not contained in ihash");
}

hipac_error
ihash_replace(struct ihash **h, const void *oldkey, void **oldval,
	      void *newkey, void *newval)
{
	int i, j, stat;
	
	if (unlikely(h == NULL || *h == NULL || oldkey == NULL ||
		     newkey == NULL)) {
		ARG_ERR;
	}
	i = HASH((*h)->hash_fn, oldkey, (*h)->len);
	if (unlikely((*h)->bucket[i] == NULL)) {
		goto not_contained;
	}
	if (i != HASH((*h)->hash_fn, newkey, (*h)->len)) {
		stat = ihash_insert(h, newkey, newval);
		if (unlikely(stat < 0)) {
			if (stat != HE_LOW_MEMORY) {
				IMPOSSIBLE_CONDITION("ihash insert failed for"
						     " another reason than "
						     "low memory");
			}
			return stat;
		}
		/* a rehash might have occured so i must be recomputed */
		i = HASH((*h)->hash_fn, oldkey, (*h)->len);
		for (j = (*h)->bucket[i]->len - 1; j >= 0; j--) {
			if ((*h)->eq_fn((*h)->bucket[i]->kv[j].key, oldkey)) {
				delete(*h, i, j, oldval);
				return HE_OK;
			}
		}
		/* oldkey is not contained in h */
		i = HASH((*h)->hash_fn, newkey, (*h)->len);
		for (j = (*h)->bucket[i]->len - 1; j >= 0; j--) {
			if ((*h)->eq_fn((*h)->bucket[i]->kv[j].key, newkey)) {
				delete(*h, i, j, NULL);
				goto not_contained;
			}
		}
		IMPOSSIBLE_CONDITION("newkey not contained in ihash although "
				     "it has been inserted");
	}
	for (j = (*h)->bucket[i]->len - 1; j >= 0; j--) {
		if ((*h)->eq_fn((*h)->bucket[i]->kv[j].key, oldkey)) {
			if (oldval != NULL) {
				*oldval = (*h)->bucket[i]->kv[j].val;
			}
			(*h)->bucket[i]->kv[j].key = newkey;
			(*h)->bucket[i]->kv[j].val = newval;
			return HE_OK;
		}
	}

 not_contained:
	IMPOSSIBLE_CONDITION("oldkey not contained in ihash");
}

hipac_error
ihash_stat(struct ihash *h, struct ihash_stat *stat)
{
	__u32 i;

	if (unlikely(h == NULL || stat == NULL)) {
		ARG_ERR;
	}

	stat->elem_ct = h->elem_ct;
	stat->bucket_len = h->len;
	stat->small_bucket_len = 0xffffffff;
	stat->big_bucket_len = 0;
	stat_distribution_init(stat->bucket_dist, LEN(stat->bucket_dist));

	for (i = 0; i < h->len; i++) {
		if (h->bucket[i] == NULL) {
			stat->small_bucket_len = 0;
			stat_distribution_add(stat->bucket_dist,
					      LEN(stat->bucket_dist), 0);
			continue;
		}
		if (h->bucket[i]->len < stat->small_bucket_len) {
			stat->small_bucket_len = h->bucket[i]->len;
		}
		if (h->bucket[i]->len > stat->big_bucket_len) {
			stat->big_bucket_len = h->bucket[i]->len;
		}
		stat_distribution_add(stat->bucket_dist,
				      LEN(stat->bucket_dist),
				      h->bucket[i]->len);
	}
	return HE_OK;
}
