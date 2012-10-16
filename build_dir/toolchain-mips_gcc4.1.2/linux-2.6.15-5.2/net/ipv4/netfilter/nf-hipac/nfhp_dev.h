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


#ifndef _NF_HIPAC_DEV_H
#define _NF_HIPAC_DEV_H

#define NF_HIPAC_MAX_UP_INTERFACES 255

struct nf_hipac_dev_ifindex_map_t
{
	u16 len;
	struct
	{
		u16 ifindex;
		u16 vindex;
	} map[NF_HIPAC_MAX_UP_INTERFACES];
};

/* mapping from interface index to virtual interface index */
extern struct nf_hipac_dev_ifindex_map_t nf_hipac_dev_ifindex_map;

/* call init during module initialization; if something fails a negative 
   errno is returned, otherwise 0 is returned */
int
nf_hipac_dev_init(void);

/* call exit during module finalization */
void
nf_hipac_dev_exit(void);

/* copies the device name corresponding to vindex to ifname which should
   be at least IFNAMSIZ bytes large and return 0;
   if vindex cannot be found a value < 0 is returned */
int
nf_hipac_dev_lookup_ifname(int vindex, char ifname[]);

/* return the corresponding virtual interface index if the interface is
   already known; otherwise the interface is added to the list of known
   non-existing interfaces and a new virtual interface index is returned;
   if something fails a nfhipac_error is returned */
int
nf_hipac_dev_get_vindex(const char *ifname);

/* return virtual interface index corresponding to ifindex */
static inline u16
nf_hipac_dev_ifindex_to_vindex(u16 ifindex)
{
	u16 i;
	for (i = 0; i < nf_hipac_dev_ifindex_map.len; i++) 
		if (nf_hipac_dev_ifindex_map.map[i].ifindex == ifindex)
			return nf_hipac_dev_ifindex_map.map[i].vindex;
	return 0;
}

#endif
