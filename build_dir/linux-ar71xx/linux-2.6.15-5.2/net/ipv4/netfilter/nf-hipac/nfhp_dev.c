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


#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/notifier.h>
#include "nfhp_com.h"
#include "nfhp_dev.h"


#define IFNAME_MAP_INIT_LEN 31

struct ifname_map_t
{
	u32 len;
	u32 size;
	struct
	{
		char *ifname;
		u16 vindex;
	} map[0];
};

static struct ifname_map_t *ifname_map;
static char (*ifnames)[IFNAMSIZ];
struct nf_hipac_dev_ifindex_map_t nf_hipac_dev_ifindex_map
__attribute__((aligned(SMP_CACHE_BYTES)));

static spinlock_t dev_lock = SPIN_LOCK_UNLOCKED;

static int
init_data(void)
{
	ifname_map = kmalloc(sizeof(ifname_map) + IFNAME_MAP_INIT_LEN *
			     sizeof(*ifname_map->map), GFP_KERNEL);
	if (ifname_map == NULL) {
		return -ENOMEM;
	}

	ifnames = kmalloc(IFNAME_MAP_INIT_LEN * sizeof(*ifnames), GFP_KERNEL);
	if (ifnames == NULL) {
		kfree(ifname_map);
		return -ENOMEM;
	}
	memset(&nf_hipac_dev_ifindex_map, 0, sizeof(nf_hipac_dev_ifindex_map));
	memset(ifname_map, 0, sizeof(ifname_map) + IFNAME_MAP_INIT_LEN *
	       sizeof(*ifname_map->map));
	memset(ifnames, 0, IFNAME_MAP_INIT_LEN * sizeof(*ifnames));
	ifname_map->size = IFNAME_MAP_INIT_LEN;
	return 0;
}

static void
free_data(void)
{
	if (ifname_map != NULL) {
		kfree(ifname_map);
		ifname_map = NULL;
	}

	if (ifnames != NULL) {
		kfree(ifnames);
		ifnames = NULL;
	}
}

static void
ifindex_map_add_replace(u16 ifindex, u16 vindex)
{
	u16 i;
	for (i = 0; i < nf_hipac_dev_ifindex_map.len; i++) {
		if (nf_hipac_dev_ifindex_map.map[i].ifindex == ifindex) {
			nf_hipac_dev_ifindex_map.map[i].vindex = vindex;
			return;
		}
	}
	for (i = 0; i < nf_hipac_dev_ifindex_map.len; i++) {
		if (nf_hipac_dev_ifindex_map.map[i].ifindex == 0) {
			nf_hipac_dev_ifindex_map.map[i].ifindex = ifindex;
			nf_hipac_dev_ifindex_map.map[i].vindex = vindex;
			return;
		}
	}
	if (nf_hipac_dev_ifindex_map.len < NF_HIPAC_MAX_UP_INTERFACES) {
		nf_hipac_dev_ifindex_map.map[nf_hipac_dev_ifindex_map.len]
			.ifindex = ifindex;
		nf_hipac_dev_ifindex_map.map[nf_hipac_dev_ifindex_map.len]
			.vindex = vindex;
		nf_hipac_dev_ifindex_map.len++;
	} else {
		printk(KERN_ERR "NF_HiPAC: too much interfaces UP at the "
		       "same time. Please increase NF_HIPAC_MAX_UP_INTERFACES "
		       "in nf_hipac_dev.h and recompile!");
	}
	return;
}

static void
ifindex_map_del(u16 ifindex)
{
	u16 i;
	for (i = 0; i < nf_hipac_dev_ifindex_map.len; i++) {
		if (nf_hipac_dev_ifindex_map.map[i].ifindex == ifindex) {
			nf_hipac_dev_ifindex_map.map[i].ifindex = 0;
			nf_hipac_dev_ifindex_map.map[i].vindex = 0;
			return;
		}
	}
	return;
}

int
ifname_map_lookup_vindex(const char *ifname)
{
	u16 pos;
	int cmp;
	u32 start = 1;
	u32 stop = ifname_map->len;

	while (stop >= start) {
		pos = ((start + stop) >> 1) - 1;
		cmp = strcmp(ifname_map->map[pos].ifname, ifname);
		if (cmp < 0) {
			start = pos + 2;
		} else if (cmp > 0) {
			stop = pos;
		} else {
			return ifname_map->map[pos].vindex;
		}
	}
	return -1;
}

int
nf_hipac_dev_lookup_ifname(int vindex, char ifname[])
{
	if (vindex < 1 || vindex > ifname_map->len)
		return -1;
	strlcpy(ifname, ifnames[vindex - 1], IFNAMSIZ);
	return 0;
}

int
nf_hipac_dev_get_vindex(const char *ifname)
{
	u32 max = 0;
	u32 start = 1;
	u16 pos;
	u32 stop;
	int cmp;
	struct net_device *dev;

	if (unlikely(ifname_map->len == 0)) {
		strlcpy(ifnames[0], ifname, sizeof(*ifnames));
		dev = dev_get_by_name(ifname);
		spin_lock_bh(&dev_lock);
		ifname_map->len = 1;
		ifname_map->map[0].ifname = ifnames[0];
		ifname_map->map[0].vindex = 1;
		if (dev) {
			if (dev->flags & IFF_UP)
				ifindex_map_add_replace(dev->ifindex, 1);
			dev_put(dev);
		}
		spin_unlock_bh(&dev_lock);
		return 1;
	}

	stop = ifname_map->len;
	while (stop >= start) {
		pos = ((start + stop) >> 1) - 1;
		cmp = strcmp(ifname_map->map[pos].ifname, ifname);
		if (cmp < 0) {
			start = pos + 2;
		} else if (cmp > 0) {
			stop = pos;
			max = pos + 1;
		} else {
			return ifname_map->map[pos].vindex;
		}
	}
	if (max == 0) {
		/* max has not been touched (otherwise it must be >= 1)
		   => new ifname is "maximal" */
		pos = ifname_map->len;
	} else {
		pos = max - 1;
	}

	if (ifname_map->len == 65535) {
		return NFHE_INDEX;
	}

	/* new vindex required -> do reallocations first if necessary */
	if (unlikely(ifname_map->len == ifname_map->size)) {
		u32 newsize = ((ifname_map->size + 1) << 1) - 1;
		struct ifname_map_t *new_ifname_map;
		char (*new_ifnames)[IFNAMSIZ];
		new_ifname_map = kmalloc(sizeof(new_ifname_map) + newsize *
					 sizeof(*new_ifname_map->map),
					 GFP_KERNEL);
		if (new_ifname_map == NULL) {
			return HE_LOW_MEMORY;
		}
		new_ifnames = kmalloc(newsize * sizeof(*new_ifnames),
				      GFP_KERNEL);
		if (new_ifnames == NULL) {
			kfree(new_ifname_map);
			return HE_LOW_MEMORY;
		}
		memcpy(new_ifname_map, ifname_map, sizeof(new_ifname_map) +
		       ifname_map->size * sizeof(*new_ifname_map->map));
		new_ifname_map->size = newsize;
		memcpy(new_ifnames, ifnames,
		       ifname_map->size * sizeof(*new_ifnames));
		strlcpy(new_ifnames[ifname_map->len], ifname,
			sizeof(*new_ifnames));
		dev = dev_get_by_name(ifname);
		spin_lock_bh(&dev_lock);
		kfree(ifname_map);
		kfree(ifnames);
		ifname_map = new_ifname_map;
		ifnames = new_ifnames;
	} else {
		strlcpy(ifnames[ifname_map->len], ifname, sizeof(*ifnames));
		dev = dev_get_by_name(ifname);
		spin_lock_bh(&dev_lock);
	}
	
	if (pos < ifname_map->len) {
		memmove(&ifname_map->map[pos + 1], &ifname_map->map[pos],
			(ifname_map->len - pos) * sizeof(*ifname_map->map));
	}
	ifname_map->map[pos].ifname = ifnames[ifname_map->len];
	ifname_map->map[pos].vindex = ++ifname_map->len;
	if (dev) {
		if (dev->flags & IFF_UP)
			ifindex_map_add_replace(dev->ifindex, ifname_map->len);
		dev_put(dev);
	}
	spin_unlock_bh(&dev_lock);
	return ifname_map->len;
}

static int
nf_hipac_dev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	int vindex;
	struct net_device *dev = ptr;
	switch (event) {
	case NETDEV_UP:
		spin_lock_bh(&dev_lock);
		vindex = ifname_map_lookup_vindex(dev->name);
		if (vindex > 0) {
			// interface is in ruleset => add to ifindex_map
			ifindex_map_add_replace(dev->ifindex, vindex);
		}
		spin_unlock_bh(&dev_lock);
		break;
		
	case NETDEV_DOWN:
		spin_lock_bh(&dev_lock);
		ifindex_map_del(dev->ifindex);
		spin_unlock_bh(&dev_lock);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block nf_hipac_dev_notifier = {
        .notifier_call  = nf_hipac_dev_event,
};

int
nf_hipac_dev_init(void)
{
	int stat;

	stat = init_data();
	if (stat < 0) {
		return stat;
	}
	stat = register_netdevice_notifier(&nf_hipac_dev_notifier);
	if (stat < 0) {
		free_data();
		return stat;
	}
	return 0;
}

void
nf_hipac_dev_exit(void)
{
	unregister_netdevice_notifier(&nf_hipac_dev_notifier);
	free_data();
}
