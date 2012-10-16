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


#ifndef _IHASH_H
#define _IHASH_H

#include "mode.h"
#include "global.h"  // hipac_error and error message macros

#define HASH(fn, key, len) (fn(key) & ((len) - 1))

typedef __u32 (*ihash_func_t) (const void *key);
typedef int (*eq_t) (const void *key1, const void *key2);

struct ihash_keyval
{
	void *key, *val;
};

struct ihash_bucket
{
	__u32 len;
	struct ihash_keyval kv[0];
};

struct ihash
{
	ihash_func_t hash_fn;
	eq_t eq_fn;
	int use_mini_alloc;
	__u32 len, elem_ct, avrg_elem_per_bucket;
	struct ihash_bucket **bucket;
};

struct ihash_stat
{
	__u32 elem_ct;
	__u32 bucket_len, small_bucket_len, big_bucket_len;
	/* bucket_dist[i] (0 <= i <= 14) contains the number of buckets
	   with <= 2^i - 1 (and >= 2^(i-1) if i > 0) elements; 
	   bucket_dist[15] contains the number of buckets with >= 2^14
	   elements */
	__u32 bucket_dist[16];
};


/* equality and hash function for strings as keys */
int
eq_str(const void *key1, const void *key2);

__u32
ihash_func_str(const void *key);


/* equality and hash function for values as keys */
int
eq_val(const void *key1, const void *key2);

__u32
ihash_func_val(const void *key);

/* if the value of the (key, val) pair is not a pointer but a value ptr_to_val
   and val_to_ptr serve as a conversion functions */
static inline __u64
ptr_to_val(const void *p)
{
#ifdef BIT32_ARCH
	return (__u32) p;
#else
	return (__u64) p;
#endif
}

static inline void *
val_to_ptr(__u64 v)
{
#ifdef BIT32_ARCH
	return (void *) (__u32) v;
#else
	return (void *) v;
#endif
}


/* create new hash table with len' buckets whereby len' is the nearest power
   of two >= len; if use_mini_alloc is not 0 then mini_alloc is used to
   allcate the bucket pointer array, otherwise hp_alloc is used;
   avrg_elem_per_bucket indicates how many elements per bucket are allowed
   at maximum assuming that they are equally distributed; in the case
   use_mini_alloc is not 0 and the bucket pointer array cannot be further
   enlarged the average number of elements per bucket may be larger */
struct ihash *
ihash_new(__u32 len, int use_mini_alloc, __u32 avrg_elem_per_bucket,
	  ihash_func_t hash_fn, eq_t eq_fn);

void
ihash_free(struct ihash *h);

/* key must not be contained in h (this is not checked);
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ihash_insert(struct ihash **h, void *key, void *val);

/* delete key and the corresponding value v from h; v stored in *val if val
   is not NULL; key must be contained in h;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ihash_delete(struct ihash *h, const void *key, void **val);

/* replace oldkey and the corresponding value v by newkey and newval; v is
   stored in *oldval if oldval is not NULL; oldkey must be contained in h;
   possible errors: HE_LOW_MEMORY, HE_IMPOSSIBLE_CONDITION */
hipac_error
ihash_replace(struct ihash **h, const void *oldkey, void **oldval,
	      void *newkey, void *newval);

/* compute statistical info about h;
   possible errors: HE_IMPOSSIBLE_CONDITION */
hipac_error
ihash_stat(struct ihash *h, struct ihash_stat *stat);

/* generic lookup function */
static inline void *
ihash_lookup(const struct ihash *h, const void *key)
{
	__u32 i;
	struct ihash_keyval *kv, *end;

	if (unlikely(h == NULL || key == NULL)) {
		ARG_MSG;
		return NULL;
	}
	i = HASH(h->hash_fn, key, h->len);
	if (h->bucket[i] == NULL) {
		return NULL;
	}
	end = h->bucket[i]->kv + h->bucket[i]->len;
	for (kv = h->bucket[i]->kv; kv < end; kv++) {
		if (h->eq_fn(kv->key, key)) {
			return kv->val;
		}
	}
	return NULL;
}

/* optimized lookup function if keys are values */
static inline void *
ihash_lookup_val(const struct ihash *h, const void *key)
{
	__u32 i;
	struct ihash_keyval *kv, *end;

	if (unlikely(h == NULL || key == NULL)) {
		ARG_MSG;
		return NULL;
	}
	i = HASH(ihash_func_val, key, h->len);
	if (h->bucket[i] == NULL) {
		return NULL;
	}
	end = h->bucket[i]->kv + h->bucket[i]->len;
	for (kv = h->bucket[i]->kv; kv < end; kv++) {
		if (kv->key == key) {
			return kv->val;
		}
	}
	return NULL;
}

/* optimized lookup function if keys are strings */
static inline void *
ihash_lookup_str(const struct ihash *h, const void *key)
{
	__u32 i;
	struct ihash_keyval *kv, *end;

	if (unlikely(h == NULL || key == NULL)) {
		ARG_MSG;
		return NULL;
	}
	i = HASH(ihash_func_str, key, h->len);
	if (i < 0 || i >= h->len || h->bucket[i] == NULL) {
		return NULL;
	}
	end = h->bucket[i]->kv + h->bucket[i]->len;
	for (kv = h->bucket[i]->kv; kv < end; kv++) {
		if (!strcmp(kv->key, key)) {
			return kv->val;
		}
	}
	return NULL;
}

/* call fn(key) for all keys of h */
#define IHASH_KEY_ITERATE(h, cast, fn, args...)                           \
do {                                                                      \
	__u32 i, j;                                                       \
                                                                          \
	if (unlikely((h) == NULL)) {                                      \
		ARG_MSG;                                                  \
		break;                                                    \
	}                                                                 \
	for (i = 0; i < (h)->len; i++) {                                  \
                if ((h)->bucket[i] == NULL) {                             \
                        continue;                                         \
                }                                                         \
		for (j = 0; j < (h)->bucket[i]->len; j++) {               \
			(fn)((cast) (h)->bucket[i]->kv[j].key , ## args); \
		}                                                         \
	}                                                                 \
} while (0)

/* call fn(val) for all values of h */
#define IHASH_VAL_ITERATE(h, cast, fn, args...)                           \
do {                                                                      \
	__u32 i, j;                                                       \
                                                                          \
	if (unlikely((h) == NULL)) {                                      \
		ARG_MSG;                                                  \
		break;                                                    \
	}                                                                 \
	for (i = 0; i < (h)->len; i++) {                                  \
                if ((h)->bucket[i] == NULL) {                             \
                        continue;                                         \
                }                                                         \
		for (j = 0; j < (h)->bucket[i]->len; j++) {               \
			(fn)((cast) (h)->bucket[i]->kv[j].val , ## args); \
		}                                                         \
	}                                                                 \
} while (0)

/* use the following macros to iterate over all (key, val) pairs in hash:
   IHASH_FOR_EACH(hash, key, val) {
           // do something with key, val
           IHASH_FOR_EACH_END;
   }
   IHASH_FOR_EACH_KEY and IHASH_FOR_EACH_VAL are used similarly */
#define IHASH_FOR_EACH(h, hkey, hval)                                     \
{                                                                         \
	__u32 _ihash_i, _ihash_j;                                         \
	for (_ihash_i = 0; _ihash_i < (h)->len; _ihash_i++) {             \
		if ((h)->bucket[_ihash_i] == NULL) {                      \
			continue;                                         \
		}                                                         \
		for (_ihash_j = 0; _ihash_j < (h)->bucket[_ihash_i]->len; \
		     _ihash_j++) {                                        \
			(hkey) = (h)->bucket[_ihash_i]->kv[_ihash_j].key; \
			(hval) = (h)->bucket[_ihash_i]->kv[_ihash_j].val;

#define IHASH_FOR_EACH_KEY(h, hkey)                                       \
{                                                                         \
	__u32 _ihash_i, _ihash_j;                                         \
	for (_ihash_i = 0; _ihash_i < (h)->len; _ihash_i++) {             \
		if ((h)->bucket[_ihash_i] == NULL) {                      \
			continue;                                         \
		}                                                         \
		for (_ihash_j = 0; _ihash_j < (h)->bucket[_ihash_i]->len; \
		     _ihash_j++) {                                        \
			(hkey) = (h)->bucket[_ihash_i]->kv[_ihash_j].key;

#define IHASH_FOR_EACH_VAL(h, hval)                                       \
{                                                                         \
	__u32 _ihash_i, _ihash_j;                                         \
	for (_ihash_i = 0; _ihash_i < (h)->len; _ihash_i++) {             \
		if ((h)->bucket[_ihash_i] == NULL) {                      \
			continue;                                         \
		}                                                         \
		for (_ihash_j = 0; _ihash_j < (h)->bucket[_ihash_i]->len; \
		     _ihash_j++) {                                        \
			(hval) = (h)->bucket[_ihash_i]->kv[_ihash_j].val;

#define IHASH_FOR_EACH_END }}} do {} while (0)

#endif
