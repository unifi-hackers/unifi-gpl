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


#include <linux/module.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/completion.h>
#include "nfhp_mod.h"
#include "nfhp_com.h"
#include "nfhp_dev.h"
#include "nfhp_proc.h"
#include "hipac.h"

#define MAX(a, b)  ((a) >= (b) ? (a) : (b))
#define MIN(a, b)  ((a) >= (b) ? (b) : (a))
#define SKB_LEN(s) (((s)->end - (s)->tail) - NLMSG_LENGTH(0))

/* hook match functions */
static nf_hookfn input_match;
static nf_hookfn forward_match;
static nf_hookfn output_match;

/* hipac data structures for INPUT, FORWARD and OUPUT hook plus
   their corresponding netfilter ops */
void *hipac_input   = NULL;
void *hipac_forward = NULL;
void *hipac_output  = NULL;
struct nf_hook_ops input_op =
{
	.hook           = input_match,
	.owner          = THIS_MODULE,
	.pf             = PF_INET,
	.hooknum        = NF_IP_LOCAL_IN,
	.priority       = NF_IP_PRI_FILTER - 1,
};
struct nf_hook_ops forward_op =
{
	.hook           = forward_match,
	.owner          = THIS_MODULE,
	.pf             = PF_INET,
	.hooknum        = NF_IP_FORWARD,
	.priority       = NF_IP_PRI_FILTER - 1,
};
struct nf_hook_ops output_op  =
{
	.hook           = output_match,
	.owner          = THIS_MODULE,
	.pf             = PF_INET,
	.hooknum        = NF_IP_LOCAL_OUT,
	.priority       = NF_IP_PRI_FILTER - 1,
};

/* used to serialize hipac modifications caused by netlink commands and
   the interface handling module */
DECLARE_MUTEX(nlhp_lock);

static struct sock *nfhp_sock = NULL;

/* connection tracking dependency helper module */
static DECLARE_MUTEX(cthelp_lock);
static struct module *nfhp_cthelp_module = NULL;

DECLARE_COMPLETION(thread_comp);
static int threadID = 0;
DECLARE_WAIT_QUEUE_HEAD(thread_wait);

/* latest hipac_get_chain_info snapshot */
struct list_info
{
	struct hipac_chain_info *inf;
	u32 len;
};
static struct list_info linfo = {NULL, 0};

struct packet
{
	int hook;
	struct sk_buff **skbuff;
	const struct net_device *indev, *outdev;
};



/*
 * dimension extractor functions
 */

static u32
get_state(const void *pkt, int *hotdrop)
{
#ifdef CONFIG_IP_NF_CONNTRACK
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	unsigned int result;
        enum ip_conntrack_info ctinfo;
	if (skb->nfct == &ip_conntrack_untracked.ct_general)
		result = NFHP_STATE_UNTRACKED;
	else if (!ip_conntrack_get(skb, &ctinfo))
			result = NFHP_STATE_INVALID;
	else	result = ctinfo % NFHP_STATE_NUM_VALID;
	return result;
#else
	return 0;
#endif
}

static u32
get_src_ip(const void *pkt, int *hotdrop)
{
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	return ntohl(skb->nh.iph->saddr);
}

static u32
get_dst_ip(const void *pkt, int *hotdrop)
{
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	return ntohl(skb->nh.iph->daddr);
}

static u32
get_iniface(const void *pkt, int *hotdrop)
{
	return nf_hipac_dev_ifindex_to_vindex(((struct packet*) pkt)
					      ->indev->ifindex);
}

static u32
get_outiface(const void *pkt, int *hotdrop)
{
	return nf_hipac_dev_ifindex_to_vindex(((struct packet*)	pkt)
					      ->outdev->ifindex);
}

static u32
get_proto(const void *pkt, int *hotdrop)
{
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	return skb->nh.iph->protocol;
}

static u32
get_fragment(const void *pkt, int *hotdrop)
{
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	int offset = ntohs(skb->nh.iph->frag_off) & IP_OFFSET;
	if (unlikely(offset)) {
		if (unlikely(offset == 1 &&
			     skb->nh.iph->protocol == IPPROTO_TCP)) {
			printk(KERN_NOTICE "Dropping evil TCP offset=1 "
			       "fragment.\n");
			*hotdrop = 1;
		}
		return 1;
	}
	return 0;
}

static u32
get_dport(const void *pkt, int *hotdrop)
{
	struct udphdr _udph, *uh;
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	uh = skb_header_pointer(skb, skb->nh.iph->ihl*4, 
				sizeof(_udph), &_udph);
	if (unlikely(uh == NULL)) {
		/* We've been asked to examine this packet, and we
		   can't.  Hence, no choice but to drop. */
		*hotdrop = 1;
		return 0;
	}
	return ntohs(uh->dest);
}

static u32
get_sport(const void *pkt, int *hotdrop)
{
	struct udphdr _udph, *uh;
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	uh = skb_header_pointer(skb, skb->nh.iph->ihl*4, 
				sizeof(_udph), &_udph);
	if (unlikely(uh == NULL)) {
		*hotdrop = 1;
		return 0;
	}
	return ntohs(uh->source);
}

static u32
get_syn(const void *pkt, int *hotdrop)
{
	struct tcphdr _tcph, *th;
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	th = skb_header_pointer(skb, skb->nh.iph->ihl*4,
				sizeof(_tcph), &_tcph);
	if (unlikely(th == NULL)) {
		*hotdrop = 1;
		return 0;
	}
	return !(th->syn && !th->ack && !th->fin && !th->rst);
}

static u32
get_icmptypes(const void *pkt, int *hotdrop)
{
	struct icmphdr _icmph, *ic;
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	ic = skb_header_pointer(skb, skb->nh.iph->ihl*4,
				sizeof(_icmph), &_icmph);
	if (unlikely(ic == NULL)) {
		*hotdrop = 1;
		return 0;
	}
	return (ic->type << 8) + ic->code;
}

static u32
get_ttl(const void *pkt, int *hotdrop)
{
	const struct sk_buff *skb = *((struct packet *) pkt)->skbuff;
	return skb->nh.iph->ttl;
}


/*
 * conntrack dependency management
 */

#ifdef CONNTRACK_MODULE          /* conntrack built as module */

int
nfhp_register_cthelp(struct module *cthelp)
{
	int ret;

	ret = down_interruptible(&cthelp_lock);
	if (ret != 0) {
		return ret;
	}
	if (nfhp_cthelp_module != NULL) {
		printk(KERN_ERR "nfhp_register_cthelp: module already "
		       "registered\n");
		ret = -EINVAL;
	}
	nfhp_cthelp_module = cthelp;
	up(&cthelp_lock);
	return ret;
}

void
nfhp_unregister_cthelp(struct module *cthelp)
{
	 down(&cthelp_lock);
	 if (nfhp_cthelp_module != cthelp) {
		 printk(KERN_ERR "nfhp_unregister_cthelp: unregistered "
			"module tries to unregister\n");
		 up(&cthelp_lock);
		 return;
	 }
	 nfhp_cthelp_module = NULL;
	 up(&cthelp_lock);
}

static inline int
cthelp_use(void)
{
	int ret;

	/* check whether the conntrack dependency helper is registered */
	ret = down_interruptible(&cthelp_lock);
	if (ret < 0) {
		return ERRNO_TO_NFHE(-ret);
	}
	if (nfhp_cthelp_module != NULL) {
		try_module_get(nfhp_cthelp_module);
		up(&cthelp_lock);
		return 0;
	}

	/* try to load the module */
	up(&cthelp_lock);
	request_module("nf_hipac_cthelp");
	
	/* did we succeed? */
	ret = down_interruptible(&cthelp_lock);
	if (ret < 0) {
		return ERRNO_TO_NFHE(-ret);
	}
	if (nfhp_cthelp_module != NULL) {
		try_module_get(nfhp_cthelp_module);
		up(&cthelp_lock);
		return 0;
	}
	up(&cthelp_lock);
	return NFHE_CTHELP;
}

static inline void
cthelp_unuse(void)
{
	if (nfhp_cthelp_module == NULL) {
		printk(KERN_ERR "%s: conntrack dependency helper "
		       "module not registered\n", __FUNCTION__);
		return;
	}
	module_put(nfhp_cthelp_module);
}

#else                  /* conntrack built in or not available */

int
nfhp_register_cthelp(struct module *cthelp)
{
}

void
nfhp_unregister_cthelp(struct module *cthelp)
{
}

static inline int
cthelp_use(void)
{
#ifdef CONFIG_IP_NF_CONNTRACK
	return 0;
#else
	return NFHE_CT;
#endif
}

static inline void
cthelp_unuse(void)
{
}

#endif


/*
 * functions and data structures necessary for hipac initialization
 */

/* dimension id to bit type mapping */
static const u8 dim2btype[] =
{
	[DIMID_STATE]      = BIT_STATE,
	[DIMID_SRC_IP]     = BIT_SRC_IP,
	[DIMID_DEST_IP]    = BIT_DEST_IP,
	[DIMID_INIFACE]    = BIT_INIFACE,
	[DIMID_OUTIFACE]   = BIT_OUTIFACE,
	[DIMID_PROTO]      = BIT_PROTO,
	[DIMID_FRAGMENT]   = BIT_FRAGMENT,
	[DIMID_DPORT]      = BIT_DPORT,
	[DIMID_SPORT]      = BIT_SPORT,
	[DIMID_SYN]        = BIT_SYN,
	[DIMID_ICMP_TYPE]  = BIT_ICMP_TYPE,
	[DIMID_TTL]        = BIT_TTL
};

/* dimension extractor functions */
static const hipac_extract_t extract[] =
{
	[DIMID_STATE]      = get_state,
	[DIMID_SRC_IP]     = get_src_ip,
	[DIMID_DEST_IP]    = get_dst_ip,
	[DIMID_INIFACE]    = get_iniface,
	[DIMID_OUTIFACE]   = get_outiface,
	[DIMID_PROTO]      = get_proto,
	[DIMID_FRAGMENT]   = get_fragment,
	[DIMID_DPORT]      = get_dport,
	[DIMID_SPORT]      = get_sport,
	[DIMID_SYN]        = get_syn,
	[DIMID_ICMP_TYPE]  = get_icmptypes,
	[DIMID_TTL]        = get_ttl,
};

/* iptables_match executor */
static hipac_match_t
hipac_match_exec(const void *packet, void *first_match, void *end)
{
	const struct packet *p = packet;
	hipac_match_t match = MATCH_YES;
	struct ipt_entry_match *m = first_match;
	int hotdrop = 0;
	struct iphdr *ip = (*p->skbuff)->nh.iph;
	u16 offset = ntohs(ip->frag_off) & IP_OFFSET;

	for (; m < (struct ipt_entry_match *) end; m = NEXT_IPT_MATCH(m)) {
		if (!m->u.kernel.match->match(*p->skbuff, p->indev,
					      p->outdev, m->data,
					      offset, &hotdrop)) {
			match = MATCH_NO;
			break;
		}
	}
	if (hotdrop) {
		return MATCH_HOTDROP;
	}
	return match;
}

/* iptables_target executor */
static hipac_target_t
hipac_target_exec(const void *packet, void *target)
{
	const struct packet *p = packet;
	struct ipt_entry_target *t = target;
	hipac_target_t ht;

	ht = t->u.kernel.target->target(p->skbuff, p->indev, p->outdev, 
					p->hook, t->data, NULL);
	if (ht == IPT_CONTINUE) {
		return TARGET_NONE;
	}
	return ht;
}

/* equality test - rnl is the hipac_rule in netlink format which implies
   that it contains ipt_entry and cmp_len if the rule has an ipt_entry_match
   or ipt_entry_target or chain label; rhp is in hipac format which means
   that it does not contain ipt_entry and cmp_len */
static int
hipac_eq_exec(const struct hipac_rule *rnl, const struct hipac_rule *rhp)
{
	u32 cmp_len_ind = 0;
	u16 *cmp_len;

	if (rnl == rhp) {
		printk(KERN_ERR "%s: rnl == rhp error\n", __FUNCTION__);
		return 0;
	}
	if (rnl == NULL || rhp == NULL || rnl->size != rhp->size ||
	    rnl->native_mct != rhp->native_mct ||
	    memcmp(rnl->cmp_start, rhp->cmp_start,
		   sizeof(*rnl) - offsetof(struct hipac_rule, cmp_start) +
		   rnl->native_mct * sizeof(*rnl->first_match))) {
		return 0;
	}
	cmp_len = CMP_LEN(rnl);
	if (HAS_IPT_MATCH(rnl)) {
		struct ipt_entry_match *mnl, *mhp, *endhp;
		mnl = FIRST_IPT_MATCH_IE(rnl);
		mhp = FIRST_IPT_MATCH(rhp);
		endhp = IPT_MATCH_END(rhp);
		for (; mhp < endhp;
		     mnl = NEXT_IPT_MATCH(mnl), mhp = NEXT_IPT_MATCH(mhp),
		     cmp_len_ind++) {
			if (strncmp(mnl->u.user.name,
				    mhp->u.kernel.match->name,
				    sizeof(mnl->u.user.name)) ||
			    mnl->u.match_size != mhp->u.match_size ||
			    memcmp(&mnl->data, &mhp->data,
				   cmp_len[cmp_len_ind])) {
				return 0;
			}
		}
	}
	if (HAS_IPT_TARGET(rnl)) {
		struct ipt_entry_target *tnl, *thp;
		tnl = IPT_TARGET_IE(rnl);
		thp = IPT_TARGET(rhp);
		if (strncmp(tnl->u.user.name, thp->u.kernel.target->name,
			    sizeof(tnl->u.user.name)) ||
		    tnl->u.target_size != thp->u.target_size ||
		    memcmp(&tnl->data, &thp->data,
			   cmp_len[cmp_len_ind])) {
			return 0;
		}
	} else if (HAS_CHAIN_TARGET(rnl)) {
		char *tnl, *thp;
		tnl = CHAIN_TARGET_IE(rnl);
		thp = CHAIN_TARGET(rhp);
		/* strlen(tnl) < HIPAC_CHAIN_NAME_MAX_LEN */
		if (strcmp(tnl, thp)) {
			return 0;
		}
	}
	return 1;
}

/* r is constructed by copying rnl to the exclusion of ipt_entry and
   cmp_len (if present); rnl->size already states the size of r _but_
   rnl may be smaller than rnl->size if it has a chain target */
static void
hipac_copy_constructor(const struct hipac_rule *rnl, struct hipac_rule *r)
{
	if (HAS_IPT_ENTRY(rnl)) {
		u32 size = rnl->size;
		if (HAS_CHAIN_TARGET(rnl)) {
			size -= HIPAC_CHAIN_NAME_MAX_LEN -
				strlen(CHAIN_TARGET_IE(rnl)) - 1;
		}
		memcpy(r, rnl, sizeof(*rnl) + rnl->native_mct *
		       sizeof(*rnl->first_match));
		if (HAS_IPT_MATCH(rnl)) {
			memcpy(FIRST_IPT_MATCH(r), IPT_ENTRY_END(rnl),
			       size - rnl->match_offset);
		} else {
			memcpy(IPT_TARGET(r), IPT_ENTRY_END(rnl),
			       size - rnl->target_offset);
		}
	} else {
		memcpy(r, rnl, rnl->size);
	}
}

/* destructor for iptables matches/target */
static void
hipac_destroy_exec(struct hipac_rule *r)
{
	int i;

	if (r == NULL) {
		return;
	}
	for (i = 0; i < r->native_mct &&
		     r->first_match[i].dimid < DIMID_STATE; i++);
	if (i < r->native_mct && r->first_match[i].dimid == DIMID_STATE) {
		cthelp_unuse();
	}
	if (HAS_IPT_MATCH(r)) {
		struct ipt_entry_match *m, *end;
		m = FIRST_IPT_MATCH(r);
		end = IPT_MATCH_END(r);
		for (; m < end; m = NEXT_IPT_MATCH(m)) {
			if (m->u.kernel.match->destroy) {
				m->u.kernel.match->destroy(
					m->data, m->u.match_size - sizeof(*m));
			}
			module_put(m->u.kernel.match->me);
		}
	}
	if (HAS_IPT_TARGET(r)) {
		struct ipt_entry_target *t;
		t = IPT_TARGET(r);
		if (t->u.kernel.target->destroy) {
			t->u.kernel.target->destroy(
				t->data, t->u.target_size - sizeof(*t));
		}
		module_put(t->u.kernel.target->me);
	}
}

/* destructor for iptables matches/target (rnl is the hipac_rule in
   netlink format) */
static void
hipac_destroy_exec_nl(struct hipac_rule *rnl)
{
	int i;

	if (rnl == NULL) {
		return;
	}
	for (i = 0; i < rnl->native_mct &&
		     rnl->first_match[i].dimid < DIMID_STATE; i++);
	if (i < rnl->native_mct && rnl->first_match[i].dimid == DIMID_STATE) {
		cthelp_unuse();
	}
	if (HAS_IPT_MATCH(rnl)) {
		struct ipt_entry_match *m, *end;
		m = FIRST_IPT_MATCH_IE(rnl);
		end = IPT_MATCH_END_IE(rnl);
		for (; m < end; m = NEXT_IPT_MATCH(m)) {
			if (m->u.kernel.match->destroy) {
				m->u.kernel.match->destroy(
					m->data, m->u.match_size - sizeof(*m));
			}
			module_put(m->u.kernel.match->me);
		}
	}
	if (HAS_IPT_TARGET(rnl)) {
		struct ipt_entry_target *t;
		t = IPT_TARGET_IE(rnl);
		if (t->u.kernel.target->destroy) {
			t->u.kernel.target->destroy(
				t->data, t->u.target_size - sizeof(*t));
		}
		module_put(t->u.kernel.target->me);
	}
}

static unsigned int
input_match(unsigned int hooknum,
	    struct sk_buff **skb,
	    const struct net_device *in,
	    const struct net_device *out,
	    int (*okfn) (struct sk_buff *))
{
	const struct packet pkt = {hooknum, skb, in, out};
	return hipac_match(hipac_input, &pkt);
}

static unsigned int
forward_match(unsigned int hooknum,
	      struct sk_buff **skb,
	      const struct net_device *in,
	      const struct net_device *out,
	      int (*okfn) (struct sk_buff *))
{
	const struct packet pkt = {hooknum, skb, in, out};
	return hipac_match(hipac_forward, &pkt);
}

static unsigned int
output_match(unsigned int hooknum,
	     struct sk_buff **skb,
	     const struct net_device *in,
	     const struct net_device *out,
	     int (*okfn) (struct sk_buff *))
{
	const struct packet pkt = {hooknum, skb, in, out};

	/* root is playing with raw sockets. */
	if (unlikely((*skb)->len < sizeof(struct iphdr) ||
		     ((*skb)->nh.iph->ihl << 2) < sizeof(struct iphdr))) {
		return NF_ACCEPT;
	}
	return hipac_match(hipac_output, &pkt);
}


/*
 * kernel-user netlink communication
 */

static inline void *
nlhp_list_rule(struct nfhp_list_rule *r, struct hipac_rule *rule, int *len)
{
	int size = IPT_ALIGN(offsetof(struct nfhp_list_rule, r) + rule->size);
	u32 i;

	if (*len < size) {
		return NULL;
	}
	r->indev[0] = '\0';
	r->outdev[0] = '\0';
	memcpy(&r->r, rule, rule->size);
	
	/* fill in interface names if necessary */
	for (i = 0; i < r->r.native_mct; i++) {
		switch (r->r.first_match[i].dimid) {
		case DIMID_INIFACE:
			if (nf_hipac_dev_lookup_ifname(
				    r->r.first_match[i].left,
				    r->indev) < 0) {
				printk(KERN_ERR "%s: interface name look"
				       "up failed\n", __FUNCTION__);
			}
			break;
		case DIMID_OUTIFACE:
			if (nf_hipac_dev_lookup_ifname(
				    r->r.first_match[i].left,
				    r->outdev) < 0) {
				printk(KERN_ERR "%s: interface name look"
				       "up failed\n", __FUNCTION__);
			}
			break;
		}
	}

	/* prepare iptables matches/target for userspace */
	if (HAS_IPT_MATCH(&r->r)) {
		struct ipt_entry_match *m, *end;
		m = FIRST_IPT_MATCH(&r->r);
		end = IPT_MATCH_END(&r->r);
		for (; m < end; m = NEXT_IPT_MATCH(m)) {
			strncpy(m->u.user.name, m->u.kernel.match->name,
				sizeof(m->u.user.name));
		}
	}
	if (HAS_IPT_TARGET(&r->r)) {
		struct ipt_entry_target *t;
		t = IPT_TARGET(&r->r);
		strncpy(t->u.user.name, t->u.kernel.target->name,
			sizeof(t->u.user.name));
	}

	*len -= size;
	return (char *) r + size;
}

static inline void *
nlhp_list_chain(struct nfhp_list_chain *c, int pos, int *len)
{
	if (*len < sizeof(*c)) {
		return NULL;
	}
	strncpy(c->label, linfo.inf[pos].label, sizeof(c->label));
	c->label[sizeof(c->label) - 1] = '\0';
	c->policy = linfo.inf[pos].policy;
	c->rule_num = linfo.inf[pos].rule_num;
	*len -= sizeof(*c);
	return c + 1;
}

static inline int
nlhp_list_next_rule(struct hipac_rule *prev, struct hipac_rule **rule, int pos)
{
	int stat;

	stat = hipac_get_next_rule(&linfo.inf[pos], prev, rule);
	switch (stat) {
	case HE_OK:
		return 0;
	case HE_RULE_NOT_EXISTENT:
		*rule = NULL;
		return 0;
	default:
		if (unlikely(stat > 0)) {
			/* this should never happen */
			printk(KERN_ERR "%s: hipac_get_next_rule returned "
			       "status > 0\n", __FUNCTION__);
			stat = -stat;
		}
		return stat;
	}
}

/* callback function for CMD_LIST command */
static int
nlhp_list(struct sk_buff *skb, struct netlink_callback *cb)
{
	static u32 pos;
	static struct hipac_rule *rule;
	struct nlmsghdr *nlh;
	int len, total, stat;
	void *data;

	total = skb_tailroom(skb) - NLMSG_SPACE(0);
	switch (cb->args[0]) {
	    case 0:
		    /* first callback in the series */
		    pos = 0;
		    rule = NULL;
		    data = NLMSG_DATA(skb->data);
		    len = total;
		    cb->args[0] = 1;
		    break;
	    case 1:
		    /* pos, rule represent the current state */
		    data = NLMSG_DATA(skb->data);
		    len = total;
		    break;
	    default:
		    return 0;
	}

	while (1) {
		if (rule == NULL) {
			/* send chain info */
			data = nlhp_list_chain(data, pos, &len);
			if (data == NULL) {
				/* skb full - chain sent next time */
				break;
			}
			stat = nlhp_list_next_rule(NULL, &rule, pos);
			if (stat < 0) {
				/* rule listing aborted due to error */
				return stat;
			}
		} else {
			/* send next rule */
			data = nlhp_list_rule(data, rule, &len);
			if (data == NULL) {
				/* skb full - rule sent next time */
				break;
			}
			stat = nlhp_list_next_rule(rule, &rule, pos);
			if (stat < 0) {
				/* rule listing aborted due to error */
				return stat;
			}
		}
		if (rule == NULL) {
			if (++pos == linfo.len) {
				/* we are done */
				cb->args[0] = 2;
				break;
			}
		}
	}
	nlh = NLMSG_PUT(skb, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq,
			NLHP_TYPE, total - len);
	nlh->nlmsg_flags |= NLM_F_MULTI;
	return NLMSG_SPACE(total - len);

nlmsg_failure:
        skb_trim(skb, skb->tail - skb->data);
        return NFHE_ILL;
}

static int
nlhp_done(struct netlink_callback *cb)
{
	up(&nlhp_lock);
	return 0;
}

static void
nlhp_send_reply(struct sk_buff *skb, struct nlmsghdr *nlh, int err)
{
	struct sk_buff *r_skb;
	struct nlmsghdr *r_nlh;

	r_skb = alloc_skb(NLMSG_SPACE(sizeof(int32_t)), GFP_KERNEL);
	if (r_skb == NULL) {
		return;
	}

	r_nlh = NLMSG_PUT(r_skb, NETLINK_CB(skb).pid, nlh->nlmsg_seq, 
			  NLMSG_ERROR, sizeof(int32_t));
	*(int32_t *) NLMSG_DATA(r_nlh) = err;
	if (!NLMSG_OK(r_nlh, NLMSG_LENGTH(sizeof(int32_t)))) {
		printk(KERN_ERR "netlink message not ok\n");
		return;
	}
	if (netlink_unicast(nfhp_sock, r_skb, NETLINK_CB(skb).pid,
			    MSG_DONTWAIT) <= 0) {
		printk(KERN_ERR "netlink_unicast failed\n");
		return;
	}
	return;
nlmsg_failure:
	printk(KERN_ERR "NLMSG_PUT failed\n");
	kfree(r_skb);
}

static int
do_cmd(struct sk_buff *skb, int msg_len);

static inline int
nlhp_chk_user_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;

	if (skb->len < sizeof(struct nlmsghdr) ||
	    nlh->nlmsg_len < sizeof(struct nlmsghdr) ||
	    skb->len < nlh->nlmsg_len ||
	    nlh->nlmsg_pid <= 0 ||
	    nlh->nlmsg_type != NLHP_TYPE ||
	    nlh->nlmsg_flags & NLM_F_MULTI ||
	    !(nlh->nlmsg_flags & NLM_F_REQUEST) ||
	    !(nlh->nlmsg_flags & NLM_F_ACK)) {
		nlhp_send_reply(skb, nlh, NFHE_NOMSG);
		return 1;
	}
	if (nlh->nlmsg_flags & MSG_TRUNC) {
		nlhp_send_reply(skb, nlh, ERRNO_TO_NFHE(ECOMM));
		return 1;
	}
	if (security_netlink_recv(skb)) {
		nlhp_send_reply(skb, nlh, ERRNO_TO_NFHE(EPERM));
		return 1;
	}
	return do_cmd(skb, skb->len - NLMSG_LENGTH(0));
}

static void
nlhp_data_ready(struct sock *sk, int len)
{
	wake_up_interruptible(&thread_wait);
}

static int
nlhp_thread_func(void *data)
{
	struct sk_buff *skb;

	daemonize("nf_hipac");
	allow_signal(SIGTERM);
	while (1) {
 		if (wait_event_interruptible(
			    thread_wait,
			    (skb = skb_dequeue(&nfhp_sock->sk_receive_queue))
			    != NULL)
		    || down_interruptible(&nlhp_lock)) {
			complete_and_exit(&thread_comp, 0);
		}
		if (nlhp_chk_user_skb(skb)) {
			/* in the other case nlhp_done releases
			   the lock */
			up(&nlhp_lock);
		}
		kfree_skb(skb);
	}
	return 0;
}


/*
 * request handling
 */

static int
cmd_check_init_native_matches(struct nfhp_rule *rule, int inc_modct,
			      int *inc_cthelp)
{
	u32 dimbitv = 0;
	u8 frag_match = 0;
	u16 proto_match = 0;
	struct ipt_entry *e = NULL;
	struct hipac_rule *r = &rule->r;
	int i, ifindex, stat;
	u8 dimid, inv, devbf;
	u32 left, right;
	
	devbf = (rule->indev[0] != '\0');
	devbf |= (rule->outdev[0] != '\0') << 1;
	if (HAS_IPT_ENTRY(r)) {
		/* as nf-hipac does not care about ipt_entry we just fill in
		   the info needed by the existing modules */
		e = IPT_ENTRY(r);
		memset(&e->ip, 0, sizeof(e->ip));
		if (devbf & 1) {
			strncpy(e->ip.iniface, rule->indev,
				sizeof(e->ip.iniface));
			memset(e->ip.iniface_mask, 0xff,
			       strlen(rule->indev) + 1);
		}
		if (devbf & 2) {
			strncpy(e->ip.outiface, rule->outdev,
				sizeof(e->ip.outiface));
			memset(e->ip.outiface_mask, 0xff,
			       strlen(rule->outdev) + 1);
		}
		e->nfcache = 0;
		e->comefrom = 0;
		memset(&e->counters, 0, sizeof(e->counters));
	}
	for (i = 0; i < r->native_mct; i++) {
		r->first_match[i].invert = !!r->first_match[i].invert;
		dimid = r->first_match[i].dimid;
		inv = r->first_match[i].invert;
		left = r->first_match[i].left;
		right = r->first_match[i].right;
		if (i > 0 && dimid <= r->first_match[i - 1].dimid) {
			return NFHE_SORT;
		}
		if (left > right || right > hipac_maxkey(dim2btype[dimid]) ||
		    (left == 0 && right == hipac_maxkey(dim2btype[dimid]))) {
			return NFHE_MINT;
		}
		dimbitv |= 1 << dimid;
		switch (dimid) {
		case DIMID_INIFACE:
			if (!(devbf & 1)) {
				return NFHE_DEVA;
			}
			ifindex = nf_hipac_dev_get_vindex(rule->indev);
			if (ifindex < 0) {
				return ifindex;
			}
			r->first_match[i].left = ifindex;
			r->first_match[i].right = ifindex;
			if (e != NULL && inv) {
				e->ip.invflags |= IPT_INV_VIA_IN;
			}
			devbf &= 0xfe;
			r->origin &= NFHP_ORIGIN_INPUT |
				NFHP_ORIGIN_FORWARD;
			break;
		case DIMID_OUTIFACE:
			if (!(devbf & 2)) {
				return NFHE_DEVA;
			}
			ifindex = nf_hipac_dev_get_vindex(rule->outdev);
			if (ifindex < 0) {
				return ifindex;
			}
			r->first_match[i].left = ifindex;
			r->first_match[i].right = ifindex;
			if (e != NULL && inv) {
				e->ip.invflags |= IPT_INV_VIA_OUT;
			}
			devbf &= 0xfd;
			r->origin &= NFHP_ORIGIN_OUTPUT |
				NFHP_ORIGIN_FORWARD;
			break;
		case DIMID_PROTO:
			if (!inv && left == right) {
				proto_match = left;
			}
			if (e != NULL) {
				e->ip.proto = r->first_match[i].left;
				/* iptables does not support protocol
				   ranges; treating a range match as
				   inverted point match avoids illegal use
				   of iptables matches */
				if (inv || left != right) {
					e->ip.invflags |= IPT_INV_PROTO;
				}
			}
			break;
		case DIMID_FRAGMENT:
			if (inv || (left != right && left == 0)) {
				return NFHE_FRAG;
			}
			if (e != NULL) {
				e->ip.flags = IPT_F_FRAG;
			}
			if (left > 0) {
				r->first_match[i].left = 1;
				r->first_match[i].right =
					hipac_maxkey(dim2btype[dimid]);
			} else {
				frag_match = 1;
				if (e != NULL) {
					e->ip.invflags |= IPT_INV_FRAG;
				}
			}
			break;
		case DIMID_SYN:
			if (inv || (left != right && left == 0)) {
				return NFHE_SYN;
			}
			if (left > 0) {
				r->first_match[i].left = 1;
				r->first_match[i].right =
					hipac_maxkey(dim2btype[dimid]);
			}
			break;
		case DIMID_STATE:
			if (left > NFHP_STATE_UNTRACKED) {
				return NFHE_STATE;
			}
			if (inc_modct) {
				stat = cthelp_use();
				if (stat < 0) {
					return stat;
				}
				(*inc_cthelp)++;
			}
			break;
		}
	}
	if (devbf != 0) {
		return NFHE_DEVB;
	}

	/* check inter-match dependencies */
	if (dimbitv & (1 << DIMID_SYN)) {
		if (proto_match != IPPROTO_TCP || !frag_match ||
		    dimbitv & (1 << DIMID_ICMP_TYPE)) {
			return NFHE_TCP;
		}
	} else if (dimbitv & (1 << DIMID_DPORT) ||
		   dimbitv & (1 << DIMID_SPORT)) {
		if ((proto_match != IPPROTO_UDP && proto_match != IPPROTO_TCP) || !frag_match ||
		    dimbitv & (1 << DIMID_ICMP_TYPE)) {
			return NFHE_TCPUDP;
		}
	} else if (dimbitv & (1 << DIMID_ICMP_TYPE) &&
		   (proto_match != IPPROTO_ICMP || !frag_match)) {
		return NFHE_ICMP;
	}
	return 0;
}

static int
init_ipt_match(struct ipt_entry_match *m, char *table,
	       const struct ipt_ip *ip, unsigned int hook)
{
	struct ipt_match *match;
	int ret = 0;
	
	match = ipt_find_match(m->u.user.name, m->u.user.revision);
	if (!match)
                return ERRNO_TO_NFHE(ENOENT);
	m->u.kernel.match = match;
	if (m->u.kernel.match->checkentry
	    && !m->u.kernel.match->checkentry(table, ip, m->data,
					      m->u.match_size - sizeof(*m),
					      hook)) {
		module_put(m->u.kernel.match->me);
		ret = NFHE_IPTMCH;
	}
	return ret;
}

static int
init_ipt_target(struct ipt_entry_target *t, char *table,
		const struct ipt_entry *e, unsigned int hook)
{
	struct ipt_target *target;
	int ret = 0;
	
	target = ipt_find_target(t->u.user.name, t->u.user.revision);
	if (!target)
                return ERRNO_TO_NFHE(ENOENT);
	t->u.kernel.target = target;
	if (t->u.kernel.target->checkentry
	    && !t->u.kernel.target->checkentry(table, e, t->data,
					       t->u.target_size - sizeof(*t),
					       hook)) {
		module_put(t->u.kernel.target->me);
		ret = NFHE_IPTTCH;
	}
	return ret;
}

static inline u32
origin_to_hookmask(u32 origin)
{
	return (origin & NFHP_ORIGIN_INPUT ? 1 << NF_IP_LOCAL_IN : 0) |
	       (origin & NFHP_ORIGIN_FORWARD ? 1 << NF_IP_FORWARD : 0) |
	       (origin & NFHP_ORIGIN_OUTPUT ? 1 << NF_IP_LOCAL_OUT : 0);
}

static int
cmd_check_init_ipt_matches(struct hipac_rule *r, int len, u16 **cmp,
			   int *cmp_len, int inc_modct, int *num_done)
{
	struct ipt_entry_match *match;
	int stat;
	
	match = FIRST_IPT_MATCH_IE(r);
	while (len >= sizeof(*match) && len >= match->u.match_size) {
		if (match->u.match_size != IPT_ALIGN(match->u.match_size)) {
			return NFHE_IPTMSZ;
		}
		if (*cmp != NULL) {
			if (*cmp_len < sizeof(**cmp)) {
				return NFHE_CMPSH;
			}
			if (**cmp > match->u.match_size - sizeof(*match)) {
				return NFHE_CMPLA;
			}
		}

		/* this is really ugly but we have to hardcode the maximum
		   allowed origin bit vector since the actual origin of this
		   rule might change after another rule has been inserted;
		   in order to dynamically handle this setting a module would
		   be required to be asked for its maximum allowed origin bit
		   vector */
		if (!strcmp(match->u.user.name, "owner")) {
			r->origin &= NFHP_ORIGIN_OUTPUT;
		} else if (!strcmp(match->u.user.name, "owner-socketlookup")) {
			r->origin &= NFHP_ORIGIN_INPUT | NFHP_ORIGIN_OUTPUT;
		}
		if (r->origin == 0) {
			return NFHE_ORIGIN;
		}
		
		if (inc_modct) {
			if (r->action == TARGET_CHAIN) {
				/* TEMPORARY FIX: since hipac currently treats
				     jump rules in a way that leads to problems
				     with stateful ipt_matches we restrict
				     ourselves to certain known stateless
				     ipt_matches; if you absolutely need a jump
				     rule with another stateless ipt_match you
				     are free to add its name here after but
				     make sure that it is __really__
				     stateless */
				if (strcmp(match->u.user.name, "ah") &&
				    strcmp(match->u.user.name, "dscp") &&
				    strcmp(match->u.user.name, "ecn") &&
				    strcmp(match->u.user.name, "esp") &&
				    strcmp(match->u.user.name, "length") &&
				    strcmp(match->u.user.name, "owner") &&
				    strcmp(match->u.user.name, "pkttype") &&
				    strcmp(match->u.user.name, "tcpmss") &&
				    strcmp(match->u.user.name, "tos") &&
				    strcmp(match->u.user.name, "unclean")) {
					return NFHE_IMPL;
				}
			}
			stat = init_ipt_match(match, "filter",
					      &IPT_ENTRY(r)->ip,
					      origin_to_hookmask(r->origin));
			if (stat < 0) {
				return stat;
			}
		}
		(*num_done)++;
		len -= match->u.match_size;
		match = NEXT_IPT_MATCH(match);
		if (*cmp != NULL) {
			(*cmp_len) -= sizeof(**cmp);
			(*cmp)++;
		}
	}
	if (len > 0) {
		return NFHE_TOFF;
	}
	return 0;
}

static int
cmd_check_init_ipt_target(struct hipac_rule *r, int len, u16 *cmp,
			  int cmp_len, int inc_modct, int *done)
{
	struct ipt_entry_target *target;
	int stat;
	
	target = IPT_TARGET_IE(r);
	if (len < sizeof(*target) || len < target->u.target_size ||
	    target->u.target_size != IPT_ALIGN(target->u.target_size)) {
		return NFHE_IPTTSZ;
	}
	if (cmp != NULL) {
		if (cmp_len < sizeof(*cmp)) {
			return NFHE_CMPSH;
		}
		if (*cmp > target->u.target_size - sizeof(*target)) {
			return NFHE_CMPLA;
		}
	}

	/* this is really ugly but we have to hardcode the maximum allowed
	   origin bit vector since the actual origin of this rule might
	   change after another rule has been inserted;
	   in order to dynamically handle this setting a module would be 
	   required to be asked for its maximum allowed origin bit vector */
	if (!strcmp(target->u.user.name, "MIRROR")) {
		r->origin &= NFHP_ORIGIN_FORWARD | NFHP_ORIGIN_INPUT;
	} else if (!strcmp(target->u.user.name, "TCPMSS")) {
		r->origin &= NFHP_ORIGIN_FORWARD | NFHP_ORIGIN_OUTPUT;
	} else if (!strcmp(target->u.user.name, "TARPIT")) {
		r->origin &= NFHP_ORIGIN_FORWARD | NFHP_ORIGIN_INPUT;
	}
	if (r->origin == 0) {
		return NFHE_ORIGIN;
	}

	if (inc_modct) {
		stat = init_ipt_target(target, "filter", IPT_ENTRY(r),
				       origin_to_hookmask(r->origin));
		if (stat < 0) {
			return stat;
		}
	}
	(*done)++;
	len -= target->u.target_size;
	if (len > 0) {
		/* netlink message contains unnecessary padding between the
		   end of the ipt target and the beginning of the cmp_len
		   array */
		r->size -= len;
	}
	return 0;
}

static void
cmd_cleanup(struct hipac_rule *r, int inc_cthelp, int num_matches, int target)
{
	struct ipt_entry_match *m;
	struct ipt_entry_target *t;
	int i;

	if (inc_cthelp) {
		cthelp_unuse();
	}
	for (m = FIRST_IPT_MATCH_IE(r), i = 0; i < num_matches;
	     m = NEXT_IPT_MATCH(m), i++) {
		if (m->u.kernel.match->destroy) {
			m->u.kernel.match->destroy(m->data, m->u.match_size -
						   sizeof(*m));
		}
		module_put(m->u.kernel.match->me);
	}
	if (target) {
		t = IPT_TARGET_IE(r);
		if (t->u.kernel.target->destroy) {
			t->u.kernel.target->destroy(
				t->data, t->u.target_size - sizeof(*t));
		}
		module_put(t->u.kernel.target->me);
	}
}

static int
cmd_check_init(struct nfhp_cmd *cmd, int msg_len)
{
	u16 *cmp = NULL;
	int inc_cthelp = 0, num_matches = 0, target = 0, cmp_len = 0;
	int stat, len, inc_modct;
	struct hipac_rule *r;
	u32 c;
	
	if (msg_len < sizeof(*cmd)) {
		return NFHE_NOMSG;
	}

	/* basic checks */
	c = cmd->cmd;
	inc_modct = (c == CMD_APPEND || c == CMD_INSERT || c == CMD_REPLACE);
	if (c < CMD_MIN || c > CMD_MAX) {
		return NFHE_CMD;
	}
	cmd->chain.label[HIPAC_CHAIN_NAME_MAX_LEN - 1] = '\0';
	cmd->chain.newlabel[HIPAC_CHAIN_NAME_MAX_LEN - 1] = '\0';
	if (cmd->chain.label[0] == '\0' &&
	    !(c == CMD_FLUSH ||  c == CMD_DELETE_CHAIN || c == CMD_LIST)) {
		return NFHE_LABEL;
	}
	if (c == CMD_RENAME_CHAIN && cmd->chain.newlabel[0] == '\0') {
		return NFHE_NLABEL;
	}
	if (c == CMD_SET_POLICY && cmd->chain.policy != TARGET_ACCEPT &&
	    cmd->chain.policy != TARGET_DROP) {
		return NFHE_POLICY;
	}
	if (!(c == CMD_APPEND || c == CMD_INSERT || c == CMD_DELETE_RULE ||
	      c == CMD_REPLACE)) {
		/* we are finished since cmd->rule is irrelevant;
		   if c == CMD_DELETE_POS then cmd->rule.r.pos is verified
		   by hipac */
		return 0;
	}

	/* rule checks */
	r = &cmd->rule.r;
	cmd->rule.indev[IFNAMSIZ - 1] = '\0';
	cmd->rule.outdev[IFNAMSIZ - 1] = '\0';
	r->origin = NFHP_ORIGIN_INPUT | NFHP_ORIGIN_FORWARD |
		NFHP_ORIGIN_OUTPUT;
	/* TEMPORARY FIX: TARGET_RETURN is not yet implemented */
	if (r->action == TARGET_RETURN) {
		return NFHE_IMPL;
	}
	if (!(r->action == TARGET_ACCEPT || r->action == TARGET_DROP ||
	      r->action == TARGET_NONE || r->action == TARGET_RETURN ||
	      r->action == TARGET_EXEC || r->action == TARGET_CHAIN)) {
		return NFHE_ACTION;
	}
	if (r->native_mct > NUMBER_OF_DIM) {
		return NFHE_NMCT;
	}
	if (HAS_IPT_ENTRY(r)) {
		struct ipt_entry *e = IPT_ENTRY(r);
		if (e->target_offset > e->next_offset ||
		    e->target_offset < sizeof(*e) ||
		    offsetof(struct nfhp_cmd, rule.e) + 
		    e->next_offset > msg_len) {
			return NFHE_IEOFF;
		}
		/* assume target_offset/next_offset are correct; if they prove
		   to be wrong we reject the packet anyway;
		   the values are chosen to be correct for the target of 
		   hipac_copy_constructor */
		if (HAS_IPT_MATCH(r)) {
			r->match_offset = IPT_ALIGN(sizeof(*r) +
						    r->native_mct *
						    sizeof(*r->first_match));
			r->target_offset = (e->target_offset - sizeof(*e)) +
				r->match_offset;
		} else {
			if (e->target_offset != sizeof(*e)) {
				return NFHE_IEOFF;
			}
			r->match_offset = 0;
			if (HAS_CHAIN_TARGET(r)) {
				r->target_offset = sizeof(*r) + r->native_mct *
					sizeof(*r->first_match);
			} else {
				r->target_offset =
					IPT_ALIGN(sizeof(*r) +
						  r->native_mct *
						  sizeof(*r->first_match));
			}
		}
		r->size = (e->next_offset - sizeof(*e)) + r->target_offset;
	} else {
		/* no iptables matches/target, no chain target */
		r->size = sizeof(*r) + r->native_mct * sizeof(*r->first_match);
		r->match_offset = r->target_offset = 0;
	}

       	/* check the native matches */
	stat = cmd_check_init_native_matches(&cmd->rule, inc_modct,
					     &inc_cthelp);
	if (stat < 0) {
		goto error;
	}

	/* set maximum size of cmp_len based on r->size */
	if (HAS_CMP_LEN(c, r)) {
		cmp = CMP_LEN(r);
		cmp_len = msg_len - ((char *) cmp - (char *) cmd);
		if (cmp_len <= 0) {
			stat = NFHE_CMPMIS;
			goto error;
		}
	}

	/* check and initialize ipt matches */
	if (HAS_IPT_MATCH(r)) {
		len = r->target_offset - r->match_offset;
		stat = cmd_check_init_ipt_matches(r, len, &cmp, &cmp_len,
						  inc_modct, &num_matches);
		if (stat < 0) {
			goto error;
		}
	}

	/* check and initialize ipt target / chain target */
	if (HAS_IPT_TARGET(r)) {
		len = r->size - r->target_offset;
		if (len <= 0) {
			stat = NFHE_IPTTMI;
			goto error;
		}
		stat = cmd_check_init_ipt_target(r, len, cmp, cmp_len,
						 inc_modct, &target);
		if (stat < 0) {
			goto error;
		}
	} else if (HAS_CHAIN_TARGET(r)) {
		char *chain = CHAIN_TARGET_IE(r);
		u32 real_len;
		len = r->size - r->target_offset;
		if (len <= 0 || chain[0] == '\0') {
			stat = NFHE_CHAINE;
			goto error;
		}
		real_len = strnlen(chain, len);
		if (len > HIPAC_CHAIN_NAME_MAX_LEN || real_len == len) {
			stat = NFHE_CHAINL;
			goto error;
		}
		/* we have to reserve HIPAC_CHAIN_NAME_MAX_LEN bytes for
		   the chain label */
		r->size += HIPAC_CHAIN_NAME_MAX_LEN - len;
	}

	/* rule _syntactically_ correct; it might still be invalid because
	   of a violation of the hipac semantics */
	return 0;

 error:
	cmd_cleanup(r, inc_cthelp, num_matches, target);
	return stat;
}

static int
do_cmd(struct sk_buff *skb, int msg_len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;
	struct nfhp_cmd *cmd = (struct nfhp_cmd *) NLMSG_DATA(nlh);
	char *chain_label;
	int stat;

	stat = cmd_check_init(cmd, msg_len);
	if (stat < 0) {
		nlhp_send_reply(skb, nlh, stat);
		return 1;
	}
	if (cmd->chain.label[0] == '\0') {
		chain_label = NULL;
	} else {
		chain_label = cmd->chain.label;
	}

	switch (cmd->cmd) {
	    case CMD_APPEND:
		    stat = hipac_append(chain_label, &cmd->rule.r);
		    if (stat != HE_OK) {
			    hipac_destroy_exec_nl(&cmd->rule.r);
		    }
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_INSERT:
		    stat = hipac_insert(chain_label, &cmd->rule.r);
		    if (stat != HE_OK) {
			    hipac_destroy_exec_nl(&cmd->rule.r);
		    }
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_DELETE_RULE:
		    stat = hipac_delete(chain_label, &cmd->rule.r);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_DELETE_POS:
		    stat = hipac_delete_pos(chain_label, cmd->rule.r.pos);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_REPLACE:
		    stat = hipac_replace(chain_label, &cmd->rule.r);
		    if (stat != HE_OK) {
			    hipac_destroy_exec_nl(&cmd->rule.r);
		    }
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_FLUSH:
		    stat = hipac_flush_chain(chain_label);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_NEW_CHAIN:
		    stat = hipac_new_chain(chain_label);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_DELETE_CHAIN:
		    stat = hipac_delete_chain(chain_label);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_RENAME_CHAIN:
		    stat = hipac_rename_chain(chain_label,
					      cmd->chain.newlabel);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_SET_POLICY:
		    stat = hipac_set_policy(chain_label, cmd->chain.policy);
		    nlhp_send_reply(skb, nlh, stat);
		    break;
	    case CMD_LIST:
	    {
		    if (linfo.inf != NULL) {
			    if (hipac_free_chain_infos(linfo.inf) != HE_OK) {
				    /* this should never happen */
				    printk(KERN_ERR "%s: hipac_free_chain_info"
					   " failed\n", __FUNCTION__);
			    }
			    linfo.inf = NULL;
			    linfo.len = 0;
		    }
		    stat = hipac_get_chain_infos(chain_label, &linfo.inf,
						 &linfo.len);
		    if (stat < 0) {
			    linfo.inf = NULL;
			    linfo.len = 0;
			    nlhp_send_reply(skb, nlh, stat);
			    return 1;
		    }
		    if (netlink_dump_start(nfhp_sock, skb, nlh, nlhp_list,
					   nlhp_done) != 0) {
			    printk(KERN_ERR "netlink_dump_start failed\n");
			    return 1;
		    }
		    /* nlhp_done will or already has released nlhp_lock so
		       don't release it again */
		    return 0;
	    }
	    default:
		    printk(KERN_ERR "invalid command type although "
			   "cmd_check_init reported a valid command\n");
		    nlhp_send_reply(skb, nlh, NFHE_NOMSG);
		    break;
	}
	return 1;
}


/*
 * initialization, finalization
 */

static int
__init init(void)
{
	struct sysinfo sys;
	u64 total_mem;
	int ret;

	si_meminfo(&sys);
	total_mem = (u64) sys.totalram << PAGE_SHIFT;

	/* initialize hipac layer */
	if (hipac_init(dim2btype, extract,
		       sizeof(dim2btype) / sizeof(*dim2btype),
		       hipac_copy_constructor, hipac_destroy_exec,
		       hipac_match_exec, hipac_target_exec, hipac_eq_exec,
		       total_mem >> 1) != HE_OK) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "initialize hipac algorithm\n");
		return -ENOMEM;
	}
	if (hipac_new("INPUT", "__/INPUT_INTERN\\__", TARGET_ACCEPT,
		      NFHP_ORIGIN_INPUT, &hipac_input) != HE_OK) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "create hipac data structure for input hook\n");
		ret = -ENOMEM;
		goto cleanup_hipac;
	}
	if (hipac_new("FORWARD", "__/FORWARD_INTERN\\__", TARGET_ACCEPT,
		      NFHP_ORIGIN_FORWARD, &hipac_forward) != HE_OK) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "create hipac data structure for forward hook\n");
		ret = -ENOMEM;
		goto cleanup_hipac;
	}
	if (hipac_new("OUTPUT", "__/OUTPUT_INTERN\\__", TARGET_ACCEPT,
		      NFHP_ORIGIN_OUTPUT, &hipac_output) != HE_OK) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "create hipac data structure for output hook\n");
		ret = -ENOMEM;
		goto cleanup_hipac;
	}

	/* register to netfilter */
	if ((ret = nf_register_hook(&input_op)) < 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "register input hook\n");
		goto cleanup_hipac;
	}
	if ((ret = nf_register_hook(&forward_op)) < 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "register forward hook\n");
		goto cleanup_input;
	}
	if ((ret = nf_register_hook(&output_op)) < 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "register output hook\n");
		goto cleanup_forward;
	}

	/* initialize interface manager */
	if ((ret = nf_hipac_dev_init()) != 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "initialize device management\n");
		goto cleanup_output;
	}

	/* initialize proc interface */
	hpproc_init(total_mem);

	/* enable netlink user communication */
	nfhp_sock = netlink_kernel_create(NLHP_PROTO, 0, nlhp_data_ready, THIS_MODULE);
	if (nfhp_sock == NULL) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "create kernel netlink socket\n");
		ret = -ENOMEM;
		goto cleanup_hpproc;
	}

	/* start kernel thread */
	threadID = kernel_thread(nlhp_thread_func, NULL, CLONE_KERNEL);
	if (threadID == 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "start kernel thread\n");
		ret = -EIO;
		goto cleanup_netlink;
	}

	printk(KERN_INFO "nf_hipac: (C) 2002-2003 HIPAC core team "
	       "(Michael Bellion, Thomas Heinz)\n");
	printk(KERN_INFO "nf_hipac: (C) 2004-2005 MARA Systems AB "
	       "(Michael Bellion)\n");
	return 0;

cleanup_netlink:
	if (nfhp_sock == NULL ||
	    nfhp_sock->sk_socket == NULL) {
		/* this should never happen */
		printk(KERN_ERR "nfhp_sock is broken\n");
	} else {
		sock_release(nfhp_sock->sk_socket);
	}
cleanup_hpproc:
	hpproc_exit();
	nf_hipac_dev_exit();
cleanup_output:
	nf_unregister_hook(&output_op);
cleanup_forward:
	nf_unregister_hook(&forward_op);
cleanup_input:
	nf_unregister_hook(&input_op);
cleanup_hipac:
	hipac_exit();
	return ret;	
}

static void
__exit fini(void)
{
	/* wait for ongoing netlink or proc operations to finish */
	down(&nlhp_lock);
	kill_proc(threadID, SIGTERM, 1);
	wait_for_completion(&thread_comp);
	if (nfhp_sock == NULL ||
	    nfhp_sock->sk_socket == NULL) {
		/* this should never happen */
		printk(KERN_ERR "nfhp_sock is broken\n");
	} else {
		sock_release(nfhp_sock->sk_socket);
	}
	if (linfo.inf != NULL &&
	    hipac_free_chain_infos(linfo.inf) != HE_OK) {
			/* this should never happen */
			printk(KERN_ERR "%s: hipac_free_chain_info"
			       " failed\n", __FUNCTION__);
	}
	hpproc_exit();
	nf_hipac_dev_exit();
	nf_unregister_hook(&input_op);
	nf_unregister_hook(&forward_op);
	nf_unregister_hook(&output_op);
	hipac_exit();
	up(&nlhp_lock);
}


module_init(init);
module_exit(fini);
MODULE_AUTHOR("Michael Bellion and Thomas Heinz");
MODULE_DESCRIPTION("NF-HIPAC - netfilter high performance "
		   "packet classification");
MODULE_LICENSE("GPL");

EXPORT_SYMBOL(nfhp_register_cthelp);
EXPORT_SYMBOL(nfhp_unregister_cthelp);

