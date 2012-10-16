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


#include "global.h"
#include "rlp.h"

#define KEYSIZE(bittype) (1 << ((bittype) + 1))
#define PTR_ALIGN(v)         (((v) + (__alignof__(void *) - 1)) & \
			      (~(__alignof__(void *) - 1)))
#define FIRST_KEY(spec)     ((void *) (spec) + sizeof(*(spec)) +           \
			     HAS_WILDCARD_SPEC(spec) * sizeof(void *))
#define FIRST_NEXTSPEC(spec) (FIRST_KEY(spec) +                              \
			      PTR_ALIGN((spec)->num * KEYSIZE((spec)->bittype)))


/*
 * optimized locate functions
 */

static struct gen_spec *
#ifdef SINGLE_PATH
u16_locate(const struct rlp_spec *spec, const void *packet, int *hotdrop)
#else
u16_locate(const struct rlp_spec *spec, const void *packet, int *hotdrop,
	   struct gen_spec **nodes, __u8 *nodes_len)
#endif
{
	const __u16 key = extract_fn[spec->dimid](packet, hotdrop);
	const __u16 *part = (void *) spec + sizeof(*spec);
	__u16 left = 0;
	__u16 right = spec->num - 1;
	__u16 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			return *(struct gen_spec **)
				((void *) part + PTR_ALIGN(spec->num << 1) +
				 pos * sizeof(void *));
		}
	}

	/* should never be reached */
	assert(1 == 0);
	return NULL;
}

#ifdef SINGLE_PATH
static struct gen_spec *
u32_locate(const struct rlp_spec *spec, const void *packet, int *hotdrop)
{
	const __u32 key = extract_fn[spec->dimid](packet, hotdrop);
	const __u32 *part = (void *) spec + sizeof(*spec);
	__u32 left = 0;
	__u32 right = spec->num - 1;
	__u32 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			return *(struct gen_spec **)
				((void *) part + PTR_ALIGN(spec->num << 2) +
				 pos * sizeof(void *));
		}
	}

	/* should never be reached */
	assert(1 == 0);
	return NULL;
}
#else
static struct gen_spec *
u32_locate(const struct rlp_spec *spec, const void *packet, int *hotdrop,
	   struct gen_spec **nodes, __u8 *nodes_len)
{
	const __u32 key = extract_fn[spec->dimid](packet, hotdrop);
	const __u32 *part = (void *) spec + sizeof(*spec) +
		HAS_WILDCARD_SPEC(spec) * sizeof(void *);
	__u32 left = 0;
	__u32 right = spec->num - 1;
	__u32 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			if (HAS_WILDCARD_SPEC(spec) && *((void **) part - 1)
				&& !(*hotdrop)) {
				nodes[(*nodes_len)++] = *((void **) part - 1);
			}
			return *(struct gen_spec **)
				((void *) part + PTR_ALIGN(spec->num << 2) +
				 pos * sizeof(void *));
		}
	}

	/* should never be reached */
	assert(1 == 0);
	return NULL;
}
#endif // SINGLE_PATH



/*
 * lookup helper
 */

static inline int
u16_key_exists(const struct rlp_spec *spec, __u32 key, struct locate_inf *inf,
	       __u32 *position)
{
	const __u16 *part = FIRST_KEY(spec);
	__u16 left = 0;
	__u16 right = spec->num - 1;
	__u16 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			if (inf != NULL) {
				inf->key = part[pos];
				inf->nextspec = FIRST_NEXTSPEC(spec) +
					pos * sizeof(void *);
			}
			if (position != NULL) {
				*position = pos;
			}
			return part[pos] == key;
		}
	}

	/* should never be reached */
	assert(1 == 0);
	return 0;
}

static inline int
u32_key_exists(const struct rlp_spec *spec, __u32 key, struct locate_inf *inf,
	       __u32 *position)
{
	const __u32 *part = FIRST_KEY(spec);
	__u32 left = 0;
	__u32 right = spec->num - 1;
	__u32 pos;

	while (left <= right) {
		pos = (left + right) >> 1;
		if (part[pos] < key) {
			left = pos + 1;
		} else if (pos && part[pos - 1] >= key) {
			right = pos - 1;
		} else {
			if (inf != NULL) {
				inf->key = part[pos];
				inf->nextspec = FIRST_NEXTSPEC(spec) +
					pos * sizeof(void *);
			}
			if (position != NULL) {
				*position = pos;
			}
			return part[pos] == key;
		}
	}

	/* should never be reached */
	assert(1 == 0);
	return 0;
}



/*
 * interface functions
 */

struct ptrblock **
termrule(const struct rlp_spec *spec)
{
	if (unlikely(spec == NULL)) {
		ARG_MSG;
		return NULL;
	}

	return (struct ptrblock **)
		(FIRST_NEXTSPEC(spec) + spec->num * sizeof(void *));
}

struct rlp_spec *
rlp_new(__u8 bittype, __u8 dimid, __u8 ins_num, const __u32 key[],
	struct gen_spec *nextspec[])
{
	struct rlp_spec *new_rlp;

	if (unlikely(bittype > BIT_U32 || key == NULL || nextspec == NULL ||
		     !(ins_num == 1 || ins_num == 2) ||
		     (ins_num == 1 && key[0] != hipac_maxkey(bittype)) ||
		     (ins_num == 2 && (key[0] >= key[1] ||
				       key[1] != hipac_maxkey(bittype))))) {
		ARG_MSG;
		return NULL;
	}

	new_rlp = hp_alloc(sizeof(*new_rlp) +
			   HAS_WILDCARD_DIM(dimid) * sizeof(void *) +
			   PTR_ALIGN(ins_num * KEYSIZE(bittype)) +
			   (ins_num + 1) * sizeof(void *), 1);
	if (new_rlp == NULL) {
		return NULL;
	}
	new_rlp->rlp = 1;
	new_rlp->bittype = bittype;
	new_rlp->dimid = dimid;
	new_rlp->newspec = 0;
	new_rlp->num = ins_num;
	*termrule(new_rlp) = NULL;
	if (HAS_WILDCARD_DIM(dimid)) {
		*WILDCARD(new_rlp) = NULL;
	}

	switch (bittype) {
	case BIT_U16: {
		__u16 *k = FIRST_KEY(new_rlp);
		struct gen_spec **s = FIRST_NEXTSPEC(new_rlp);
		new_rlp->locate = u16_locate;
		k[0] = key[0];
		s[0] = nextspec[0];
		if (ins_num == 2) {
			k[1] = key[1];
			s[1] = nextspec[1];
		}
		break;
	}
	case BIT_U32: {
		__u32 *k = FIRST_KEY(new_rlp);
		struct gen_spec **s = FIRST_NEXTSPEC(new_rlp);
		new_rlp->locate = u32_locate;
		k[0] = key[0];
		s[0] = nextspec[0];
		if (ins_num == 2) {
			k[1] = key[1];
			s[1] = nextspec[1];
		}
		break;
	}
	}
	return new_rlp;
}

__u32
rlp_size(const struct rlp_spec *spec)
{
	if (unlikely(spec == NULL)) {
		ARG_MSG;
		return 0;
	}

	return sizeof(*spec) +
		HAS_WILDCARD_SPEC(spec) * sizeof(void *) +
		PTR_ALIGN(spec->num * KEYSIZE(spec->bittype)) +
		(spec->num + 1) * sizeof(void *);
}

struct gen_spec **
rlp_nextspec(const struct rlp_spec *spec)
{
	if (unlikely(spec == NULL)) {
		ARG_MSG;
		return NULL;
	}

	return FIRST_NEXTSPEC(spec);
}

hipac_error
rlp_clone(const struct rlp_spec *spec, struct rlp_spec **clone)
{
	hipac_error stat;
	__u32 size;
	
	if (unlikely(spec == NULL || clone == NULL)) {
		ARG_ERR;
	}
     
	size = rlp_size(spec);
	*clone = hp_alloc(size, 1);
	if (*clone == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*clone, spec, size);
	(*clone)->newspec = 0;
	stat = ptrblock_clone(*termrule(spec), termrule(*clone));
	if (stat < 0) {
		hp_free(*clone);
		*clone = NULL;
		return stat;
	}
	return HE_OK;
}

hipac_error
rlp_insert(const struct rlp_spec *spec, __u8 ins_num, const __u32 key[],
	   struct gen_spec *nextspec[], struct rlp_spec **result)
{
	void *first_ksrc, *ksrc, *kdst, *nsrc, *ndst;
	struct gen_spec *lnspec[2];
	__u32 pos[2], lkey[2];
	__u32 i, ksize, nsize;
	hipac_error stat;

	if (unlikely(spec == NULL || key == NULL || nextspec == NULL ||
		     result == NULL || !(ins_num == 1 || ins_num == 2) ||
		     (ins_num == 1 &&
		      key[0] >= hipac_maxkey(spec->bittype)) ||
		     (ins_num == 2 &&
		      (key[0] >= key[1] ||
		       key[1] >= hipac_maxkey(spec->bittype))))) {
		ARG_ERR;
	}

	switch (spec->bittype) {
	case BIT_U16: {
		__u8 ct = 0;
		if (!u16_key_exists(spec, key[0], NULL, &pos[0])) {
			lkey[ct] = key[0];
			lnspec[ct++] = nextspec[0];
		}
		if (ins_num == 2 &&
		    !u16_key_exists(spec, key[1], NULL, &pos[ct])) {
			assert(ct == 0 || pos[0] <= pos[1]);
			lkey[ct] = key[1];
			lnspec[ct++] = nextspec[1];
		}
		ins_num = ct;
		break;
	}
	case BIT_U32: {
		__u8 ct = 0;
		if (!u32_key_exists(spec, key[0], NULL, &pos[0])) {
			lkey[ct] = key[0];
			lnspec[ct++] = nextspec[0];
		}
		if (ins_num == 2 &&
		    !u32_key_exists(spec, key[1], NULL, &pos[ct])) {
			assert(ct == 0 || pos[0] <= pos[1]);
			lkey[ct] = key[1];
			lnspec[ct++] = nextspec[1];
		}
		ins_num = ct;
		break;
	}
	}

	/* ins_num can be 0, 1 or 2 here */
	*result = hp_alloc(sizeof(**result) +
			   HAS_WILDCARD_SPEC(spec) * sizeof(void *) +
			   PTR_ALIGN((spec->num + ins_num) *
				 KEYSIZE(spec->bittype)) +
			   (spec->num + ins_num + 1) * sizeof(void *), 1);
	if (*result == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*result, spec, sizeof(*spec) +
	       HAS_WILDCARD_SPEC(spec) * sizeof(void *));
	(*result)->newspec = 0;
	(*result)->num += ins_num;
	stat = ptrblock_clone(*termrule(spec), termrule(*result));
	if (stat < 0) {
		hp_free(*result);
		*result = NULL;
		return stat;
	}

	first_ksrc = FIRST_KEY(spec);
	ksrc = first_ksrc;
	kdst = FIRST_KEY(*result);
	nsrc = FIRST_NEXTSPEC(spec);
	ndst = FIRST_NEXTSPEC(*result);
	for (i = 0; i < ins_num; i++) {
		ksize = (first_ksrc + pos[i] * KEYSIZE(spec->bittype)) - ksrc;
		nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);
		if (ksize > 0) {
			memcpy(kdst, ksrc, ksize);
			memcpy(ndst, nsrc, nsize);
		}
		ksrc += ksize;
		kdst += ksize;
		nsrc += nsize;
		ndst += nsize;
		switch (spec->bittype) {
		case BIT_U16:
			*(__u16 *) kdst = lkey[i];
			break;
		case BIT_U32:
			*(__u32 *) kdst = lkey[i];
			break;
		}
		*(struct gen_spec **) ndst = lnspec[i];
		kdst += KEYSIZE(spec->bittype);
		ndst += sizeof(void *);
	}
	ksize = (spec->num - (ins_num == 0 ? 0 : pos[ins_num - 1])) *
		KEYSIZE(spec->bittype);
	assert(ksize > 0);
	nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);
	memcpy(kdst, ksrc, ksize);
	memcpy(ndst, nsrc, nsize);
	return HE_OK;
}

hipac_error
rlp_delete(const struct rlp_spec *spec, __u8 del_num, const __u32 key[],
	   struct rlp_spec **result)
{
	void *first_ksrc, *ksrc, *kdst, *nsrc, *ndst;
	__u32 i, ksize, nsize;
	hipac_error stat;
	__u32 pos[2];

	if (unlikely(spec == NULL || key == NULL || result == NULL ||
		     del_num >= spec->num || !(del_num == 1 || del_num == 2) ||
		     (del_num == 1 &&
		      key[0] >= hipac_maxkey(spec->bittype)) ||
		     (del_num == 2 &&
		      (key[0] >= key[1] ||
		       key[1] >= hipac_maxkey(spec->bittype))))) {
		ARG_ERR;
	}

	switch (spec->bittype) {
	case BIT_U16:
		if (!u16_key_exists(spec, key[0], NULL, &pos[0])) {
			ARG_ERR;
		}
		if (del_num == 2 &&
		    !u16_key_exists(spec, key[1], NULL, &pos[1])) {
			ARG_ERR;
		}
		break;
	case BIT_U32:
		if (!u32_key_exists(spec, key[0], NULL, &pos[0])) {
			ARG_ERR;
		}
		if (del_num == 2 &&
		    !u32_key_exists(spec, key[1], NULL, &pos[1])) {
			ARG_ERR;
		}
		break;
	}

	*result = hp_alloc(sizeof(**result) +
			   HAS_WILDCARD_SPEC(spec) * sizeof(void *) +
			   PTR_ALIGN((spec->num - del_num) *
				 KEYSIZE(spec->bittype)) +
			   (spec->num - del_num + 1) * sizeof(void *), 1);
	if (*result == NULL) {
		return HE_LOW_MEMORY;
	}
	memcpy(*result, spec, sizeof(*spec) +
	       HAS_WILDCARD_SPEC(spec) * sizeof(void *));
	(*result)->newspec = 0;
	(*result)->num -= del_num;
	stat = ptrblock_clone(*termrule(spec), termrule(*result));
	if (stat < 0) {
		hp_free(*result);
		*result = NULL;
		return stat;
	}

	first_ksrc = FIRST_KEY(spec);
	ksrc = first_ksrc;
	kdst = FIRST_KEY(*result);
	nsrc = FIRST_NEXTSPEC(spec);
	ndst = FIRST_NEXTSPEC(*result);
	for (i = 0; i < del_num; i++) {
		ksize = (first_ksrc + pos[i] * KEYSIZE(spec->bittype)) - ksrc;
		nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);
		if (ksize > 0) {
			memcpy(kdst, ksrc, ksize);
			memcpy(ndst, nsrc, nsize);
		}
		ksrc += ksize + KEYSIZE(spec->bittype);
		kdst += ksize;
		nsrc += nsize + sizeof(void *);
		ndst += nsize;
	}
	ksize = (spec->num - pos[del_num - 1] - 1) * KEYSIZE(spec->bittype);
	assert(ksize > 0);
	nsize = (ksize / KEYSIZE(spec->bittype)) * sizeof(void *);
	memcpy(kdst, ksrc, ksize);
	memcpy(ndst, nsrc, nsize);
	return HE_OK;
}

hipac_error
rlp_locate(const struct rlp_spec *spec, struct locate_inf *inf, __u32 key)
{
	if (unlikely(spec == NULL || inf == NULL)) {
		ARG_ERR;
	}

	switch (spec->bittype) {
	case BIT_U16:
		u16_key_exists(spec, key, inf, NULL);
		break;
	case BIT_U32:
		u32_key_exists(spec, key, inf, NULL);
		break;
	}
	return HE_OK;
}
