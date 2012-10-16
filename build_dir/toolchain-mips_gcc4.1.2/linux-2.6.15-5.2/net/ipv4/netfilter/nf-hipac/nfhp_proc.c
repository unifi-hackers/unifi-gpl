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
#include <linux/types.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "nfhp_mod.h"
#include "hipac.h"

#define BT_I "rlp_input"
#define BT_F "rlp_forward"
#define BT_O "rlp_output"
#define DT_I "dimtree_input"
#define DT_F "dimtree_forward"
#define DT_O "dimtree_output"
#define HP_I "hipac_rules_input"
#define HP_F "hipac_rules_forward"
#define HP_O "hipac_rules_output"
#define HP_C "hipac_chains"
#define MEM  "mem"
#define INF  "info"

#define INF_M    S_IRUGO | S_IWUSR
#define OTH_M    S_IRUSR

struct proc_data
{
	char *text;
	void *stat;
	u32 len, valid_len;
	rwlock_t lock;
	void *hipac;
	char *hipac_name;
};

struct nfhp_proc_entry
{
	const char *name;
	struct proc_dir_entry *entry;
	struct proc_dir_entry *parent;
	mode_t mode;
	read_proc_t *read_fn;
	write_proc_t *write_fn;
	void *hipac;
	char *hipac_name;
	u32 text_mem_required;
	u32 stat_mem_required;
};
static struct proc_dir_entry *nfhipac_dir, *stat_dir;
static const char proc_nfhipac_dir[] = "nf-hipac";
static const char proc_stat_dir[]    = "statistics";

static write_proc_t info_write;
static read_proc_t info_read;
static read_proc_t mem_read;
static read_proc_t rlp_read;
static read_proc_t dimtree_read;
static read_proc_t hipac_r_read;
static read_proc_t hipac_c_read;

/* the non constant members are initialized by init_nfhp_proc() */
static struct nfhp_proc_entry nfhp_proc[] =
{
	{ INF,   NULL, NULL, INF_M, info_read,    info_write, NULL, NULL,
	  1000,  sizeof(struct hipac_user_stat)    },

	{ MEM,   NULL, NULL, OTH_M, mem_read,     NULL,       NULL, NULL,
	  2000,  sizeof(struct hipac_mem_stat)     },

	{ BT_I,  NULL, NULL, OTH_M, rlp_read,     NULL,       NULL, "INPUT",
	  25000, sizeof(struct hipac_rlp_stat)     },

	{ BT_F,  NULL, NULL, OTH_M, rlp_read,     NULL,       NULL, "FORWARD",
	  25000, sizeof(struct hipac_rlp_stat)     },

	{ BT_O,  NULL, NULL, OTH_M, rlp_read,     NULL,       NULL, "OUTPUT",
	  25000, sizeof(struct hipac_rlp_stat)     },

	{ DT_I,  NULL, NULL, OTH_M, dimtree_read, NULL,       NULL, "INPUT",
	  3000,  sizeof(struct hipac_dimtree_stat) },

	{ DT_F,  NULL, NULL, OTH_M, dimtree_read, NULL,       NULL, "FORWARD",
	  3000,  sizeof(struct hipac_dimtree_stat) },

	{ DT_O,  NULL, NULL, OTH_M, dimtree_read, NULL,       NULL, "OUTPUT",
	  3000,  sizeof(struct hipac_dimtree_stat) },

	{ HP_I,  NULL, NULL, OTH_M, hipac_r_read, NULL,       NULL, "INPUT",
	  3000,  sizeof(struct hipac_rule_stat)    },

	{ HP_F,  NULL, NULL, OTH_M, hipac_r_read, NULL,       NULL, "FORWARD",
	  3000,  sizeof(struct hipac_rule_stat)    },

	{ HP_O,  NULL, NULL, OTH_M, hipac_r_read, NULL,       NULL, "OUTPUT",
	  3000,  sizeof(struct hipac_rule_stat)    },

	{ HP_C,  NULL, NULL, OTH_M, hipac_c_read, NULL,       NULL, NULL,
	  4000,  sizeof(struct hipac_chain_stat)   }
};

static const char indent_spc[] = "    ";
static u64 nfhp_total_mem = 0;



/*
 * helpers
 */

static inline void
init_nfhp_proc(struct proc_dir_entry *nfhipac_dir,
	       struct proc_dir_entry *stat_dir)
{
	int i;

	for (i = 0; i < sizeof(nfhp_proc) / sizeof(*nfhp_proc); i++) {
		if (nfhp_proc[i].write_fn == info_write) {
			nfhp_proc[i].parent = nfhipac_dir;
		} else {
			nfhp_proc[i].parent = stat_dir;
		}
		if (nfhp_proc[i].hipac_name == NULL) {
			continue;
		}
		if (strcmp(nfhp_proc[i].hipac_name, "INPUT") == 0) {
			nfhp_proc[i].hipac = hipac_input;
		} else if (strcmp(nfhp_proc[i].hipac_name, "FORWARD") == 0) {
			nfhp_proc[i].hipac = hipac_forward;
		} else {
			nfhp_proc[i].hipac = hipac_output;
		}
	}
}

static inline int
init_data(struct proc_data *data, const struct nfhp_proc_entry *e)
{
	data->text = kmalloc(e->text_mem_required, GFP_KERNEL);
	if (data->text == NULL) {
		return -1;
	}
	data->stat = kmalloc(e->stat_mem_required, GFP_KERNEL);
	if (data->stat == NULL) {
		kfree(data->text);
		return -1;
	}
	data->len = e->text_mem_required;
	data->valid_len = 0;
	data->lock = RW_LOCK_UNLOCKED;
	data->hipac = e->hipac;
	data->hipac_name = e->hipac_name;
	return 0;
}

static inline void
free_data(struct proc_data *data)
{
	if (data == NULL) {
		return;
	}
	if (data->text != NULL) {
		kfree(data->text);
	}
	if (data->stat != NULL) {
		kfree(data->stat);
	}
	kfree(data);
}

static inline void
print_inline(struct proc_data *data, int indent)
{
	int i;

	for (i = 0; i < indent; i++) {
		data->valid_len += sprintf(data->text + data->valid_len,
					   indent_spc);
	}
}

static int
print_desc(struct proc_data *data, int indent, const char *desc)
{
	if (data->len < data->valid_len + indent * strlen(indent_spc) +
	    strlen(desc)) {
		/* this should never happen */
		printk(KERN_ERR "%s: too little memory reserved\n",
		       __FUNCTION__);
		return -1;
	}
	print_inline(data, indent);
	data->valid_len += sprintf(data->text + data->valid_len, desc);
	return 0;
}

static int
print_scalar(struct proc_data *data, int indent, const char *desc, u64 val)
{
	if (data->len < data->valid_len + indent * strlen(indent_spc) +
	    strlen(desc) + 22) {
		/* this should never happen */
		printk(KERN_ERR "%s: too little memory reserved\n",
		       __FUNCTION__);
		return -1;
	}
	print_inline(data, indent);
	data->valid_len += sprintf(data->text + data->valid_len, desc);
	data->valid_len += sprintf(data->text + data->valid_len,
				   " %9llu\n", val);
	return 0;
}

static int
print_map(struct proc_data *data, int indent, const char *desc,
	  u32 map[], int len)
{
	int i, empty = 1;

	if (data->len < data->valid_len + (1 + len) * indent *
	    strlen(indent_spc) + strlen(desc) + 1 + len * 25) {
		/* this should never happen */
		printk(KERN_ERR "%s: too little memory reserved\n",
		       __FUNCTION__);
		return -1;
	}
	for (i = 0; i < len; i++) {
		if (map[i] == 0) {
			continue;
		}
		if (empty) {
			empty = 0;
			print_inline(data, indent);
			data->valid_len += sprintf(data->text +
						   data->valid_len, desc);
			data->valid_len += sprintf(data->text +
						   data->valid_len, "\n");
		}
		print_inline(data, indent);
		data->valid_len += sprintf(data->text + data->valid_len,
					   "  %2u: %9u\n", i, map[i]);
	}
	return 0;
}

static int
print_dist(struct proc_data *data, int indent, const char *desc,
	   u32 dist[], u32 len)
{
	int i, empty = 1;

	if (data->len < data->valid_len + (1 + len) * indent *
	    strlen(indent_spc) + strlen(desc) + 1 + (len - 1) * 39 + 38) {
		/* this should never happen */
		printk(KERN_ERR "%s: too little memory reserved\n",
		       __FUNCTION__);
		return -1;
	}
	if (len == 0) {
		return 0;
	}
	for (i = 0; i < len - 1; i++) {
		if (dist[i] == 0) {
			continue;
		}
		if (empty) {
			empty = 0;
			print_inline(data, indent);
			data->valid_len += sprintf(data->text +
						   data->valid_len, desc);
			data->valid_len += sprintf(data->text +
						   data->valid_len, "\n");
		}
		print_inline(data, indent);
		data->valid_len +=
			sprintf(data->text + data->valid_len,
				"  [%9u, %9u]: %9u\n",
				i == 0 ? 0 : 1 << (i - 1), (1 << i) - 1,
				dist[i]);
	}
	if (dist[i] == 0) {
		return 0;
	}
	if (empty) {
		print_inline(data, indent);
		data->valid_len += sprintf(data->text + data->valid_len, desc);
		data->valid_len += sprintf(data->text + data->valid_len, "\n");
	}
	print_inline(data, indent);
	data->valid_len += sprintf(data->text + data->valid_len,
				   "  [%9u,  infinity[: %9u\n", 1 << (i - 1),
				   dist[i]);
	return 0;
}

static int
write_stat(char *buf, char **start, off_t off, int count, int *eof,
	   struct proc_data *d)
{
	int len = d->valid_len - off;

	if (len <= 0) {
		*eof = 1;
		return 0;
	}
	if (len <= count) {
		*eof = 1;
	} else {
		len = count;
	}
	read_lock(&d->lock);
	memcpy(buf, d->text + off, len);
	read_unlock(&d->lock);
	*start = buf;
	return len;
}



/*
 * i/o functions
 */

static int
info_write(struct file *file, const char *buffer, unsigned long count,
	   void *data)
{
	static const char nfhp_first[] = "nf-hipac-first\n";
	static const char ipt_first[]  = "iptables-first\n";
	static char buf[32] = {0};
	int len = count > sizeof(buf) - 1 ? sizeof(buf) - 1 : count;
	u64 new_max_mem;
	int ret;
	
	if (copy_from_user(buf, buffer, len)) {
		return -EFAULT;
        }

	/* strings don't have to contain \n at the end */
	if (!(count == sizeof(nfhp_first) - 1 ||
	      count == sizeof(ipt_first) - 1 ||
	      count == sizeof(nfhp_first) - 2 ||
	      count == sizeof(ipt_first) - 2)) {
		if (count >= 9 && !(count == 10 && buf[9] != '\n')) {
			/* input definitely too large */
			return -EINVAL;
		}

		/* interpret as number */
		new_max_mem = simple_strtoul(buf, NULL, 10) << 20;
		if (new_max_mem > nfhp_total_mem) {
			new_max_mem = nfhp_total_mem;
		}
		if (new_max_mem == hipac_get_maxmem()) {
			return len;
		}
		down(&nlhp_lock);
		switch (hipac_set_maxmem(new_max_mem)) {
		    case HE_LOW_MEMORY:
			    up(&nlhp_lock);
			    printk(KERN_NOTICE "nf_hipac: actual memory "
				   "consumption larger than memory bound "
				   "written to " INF "\n");
			    return -EINVAL;
		    case HE_OK:
			    up(&nlhp_lock);
			    return len;
		    default:
			    /* this should never happen */
			    up(&nlhp_lock);
			    printk(KERN_ERR "%s: unexpected return value\n",
				   __FUNCTION__);
			    return -EINVAL;
		}
	}

	/* change order */
	if (strncmp(buf, nfhp_first, len) == 0) {
		if (input_op.priority >= NF_IP_PRI_FILTER) {
			nf_unregister_hook(&input_op);
			nf_unregister_hook(&forward_op);
			nf_unregister_hook(&output_op);
			input_op.priority = forward_op.priority =
				output_op.priority = NF_IP_PRI_FILTER - 1;
			goto hook_register;
		}
	} else if (strncmp(buf, ipt_first, len) == 0) {
		if (input_op.priority <= NF_IP_PRI_FILTER) {
			nf_unregister_hook(&input_op);
			nf_unregister_hook(&forward_op);
			nf_unregister_hook(&output_op);
			input_op.priority = forward_op.priority =
				output_op.priority = NF_IP_PRI_FILTER + 1;
			goto hook_register;
		}
	}
	return len;

hook_register:
	if ((ret = nf_register_hook(&input_op)) < 0) {
		printk(KERN_ERR "nf_hipac: initialization failed: unable to "
		       "register input hook\n");
		goto cleanup;
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
	return len;
cleanup_forward:
	nf_unregister_hook(&forward_op);
cleanup_input:
	nf_unregister_hook(&input_op);
cleanup:
	return ret;	
}

/*
  the statistics are being rebuilt if the proc entry is read from its
  beginning; if you modify the ruleset while at the same time reading
  a proc file with a pager strange things might happen to your pager
  output ;-)
  nonetheless this is the best we can do ... at least I think so :-)
*/

#define NEED_REBUILD (off == 0 || d->valid_len == 0)
#define LEN(x)       (sizeof(x) / sizeof(*(x)))
#define EXEC(fn)            \
do {                        \
	if (fn < 0) {       \
                goto error; \
	}                   \
} while (0)

static int
info_read(char *page, char **start, off_t off, int count, int *eof,
	  void *data)
{
	struct proc_data *d = data;
	struct hipac_user_stat *stat = d->stat;

	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_user_stat(stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_user_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_scalar(d, 0, "maximum memory bound:    ",
			  hipac_get_maxmem()));
	EXEC(print_scalar(d, 0, "total memory (used):     ",
			  stat->total_mem_tight));
	EXEC(print_scalar(d, 0, "total memory (allocated):",
			  stat->total_mem_real));
	EXEC(print_scalar(d, 0, "total number of chains:  ",
			  stat->chain_num));
	EXEC(print_scalar(d, 0, "total number of rules:   ",
			  stat->rule_num));
	if (input_op.priority < NF_IP_PRI_FILTER) {
		EXEC(print_desc(d, 0, "nf-hipac is invoked before "
				"iptables\n"));
	} else {
		EXEC(print_desc(d, 0, "iptables is invoked before "
				"nf-hipac\n"));
	}
#ifdef SINGLE_PATH
	EXEC(print_desc(d, 0, "compiled with SINGLE_PATH optimization\n"));
#else
	EXEC(print_desc(d, 0, "compiled without SINGLE_PATH optimization\n"));
#endif
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

static int
mem_read(char *page, char **start, off_t off, int count, int *eof,
	 void *data)
{
	struct proc_data *d = data;
	struct hipac_mem_stat *stat = d->stat;

	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_mem_stat(stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_mem_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_scalar(d, 0, "total memory (used):     ",
			  stat->total_mem_tight));
	EXEC(print_scalar(d, 0, "total memory (allocated):",
			  stat->total_mem_real));
	EXEC(print_desc(d, 0, "memhash:\n"));
	EXEC(print_scalar(d, 1, "number of entries:                    ",
			  stat->memhash_elem_num));
	EXEC(print_scalar(d, 1, "number of buckets:                    ",
			  stat->memhash_len));
	EXEC(print_scalar(d, 1, "number of entries in smallest bucket: ",
			  stat->memhash_smallest_bucket_len));
	EXEC(print_scalar(d, 1, "number of entries in largest bucket:  ",
			  stat->memhash_biggest_bucket_len));
	EXEC(print_dist(d, 1, "number of buckets with [x, y] entries:",
			stat->memhash_bucket_stat,
			LEN(stat->memhash_bucket_stat)));
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

static int
rlp_read(char *page, char **start, off_t off, int count, int *eof,
	 void *data)
{
	static char buf[100] = {0};
	struct proc_data *d = data;
	struct hipac_rlp_stat *stat = d->stat;
	int i;
	
	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_rlp_stat(d->hipac, stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_rlp_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_desc(d, 0, "root chain: "));
	EXEC(print_desc(d, 0, d->hipac_name));
	EXEC(print_desc(d, 0, "\n"));
	EXEC(print_scalar(d, 0, "total memory (used):             ",
			  stat->total_mem_tight));
	EXEC(print_scalar(d, 0, "total memory (allocated):        ",
			  stat->total_mem_real));
	EXEC(print_scalar(d, 1, "rlp memory (used):          ",
			  stat->rlp_mem_tight));
	EXEC(print_scalar(d, 1, "rlp memory (allocated):     ",
			  stat->rlp_mem_real));
	EXEC(print_scalar(d, 1, "termrule memory (used):     ",
			  stat->termrule_mem_tight));
	EXEC(print_scalar(d, 1, "termrule memory (allocated):",
			  stat->termrule_mem_real));
	EXEC(print_scalar(d, 0, "number of rlps:                  ",
			  stat->rlp_num));
	EXEC(print_map(d, 1, "number of rlps in dimid x:",
		       stat->rlp_dimid_num, LEN(stat->rlp_dimid_num)));
	EXEC(print_map(d, 1, "number of rlps in depth x:",
		       stat->rlp_depth_num, LEN(stat->rlp_depth_num)));
	EXEC(print_scalar(d, 0, "number of termrule blocks:       ",
			  stat->termrule_num));
	EXEC(print_scalar(d, 0, "total number of termrule entries:",
			  stat->termrule_ptr_num));
	EXEC(print_scalar(d, 0, "number of keys:                  ",
			  stat->keys_num));
	for (i = 0; i < LEN(stat->rlp_dimid_keys_stat); i++) {
		if (snprintf(buf, sizeof(buf) - 1, "number of rlps in dimid"
			     " %d with [x, y] keys:", i) < 0) {
			printk(KERN_ERR "%s: static buffer too small\n",
			       __FUNCTION__);
			break;
		}
		EXEC(print_dist(d, 1, buf, stat->rlp_dimid_keys_stat[i],
				LEN(*stat->rlp_dimid_keys_stat)));
	}
	EXEC(print_scalar(d, 0, "number of terminal pointers:     ",
			  stat->termptr_num));
	EXEC(print_map(d, 1, "number of terminal pointers in dimid x:",
		       stat->termptr_dimid_num,
		       LEN(stat->termptr_dimid_num)));
	EXEC(print_map(d, 1, "number of terminal pointers in depth x:",
		       stat->termptr_depth_num,
		       LEN(stat->termptr_depth_num)));
	EXEC(print_scalar(d, 0, "number of non-terminal pointers: ",
			  stat->nontermptr_num));
	EXEC(print_map(d, 1, "number of non-terminal pointers in dimid x:",
		       stat->nontermptr_dimid_num,
		       LEN(stat->nontermptr_dimid_num)));
	EXEC(print_map(d, 1, "number of non-terminal pointers in depth x:",
		       stat->nontermptr_depth_num,
		       LEN(stat->nontermptr_depth_num)));
	EXEC(print_scalar(d, 0, "number of dt_elem structs:       ",
			  stat->dt_elem_num));
	EXEC(print_scalar(d, 1, "total number of dt_elem entries:"
			  "      ", stat->dt_elem_ptr_num));
	EXEC(print_dist(d, 1, "number of dt_elem structs with [x, y] entries:",
			stat->dt_elem_stat, LEN(stat->dt_elem_stat)));
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

static int
dimtree_read(char *page, char **start, off_t off, int count, int *eof,
	     void *data)
{
	struct proc_data *d = data;
	struct hipac_dimtree_stat *stat = d->stat;

	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_dimtree_stat(d->hipac, stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_dimtree_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_desc(d, 0, "root chain: "));
	EXEC(print_desc(d, 0, d->hipac_name));
	EXEC(print_desc(d, 0, "\n"));
	EXEC(print_scalar(d, 0, "chain memory (used):           ",
			  stat->chain_mem_tight));
	EXEC(print_scalar(d, 0, "chain memory (allocated):      ",
			  stat->chain_mem_real));
	EXEC(print_scalar(d, 0, "number of rules:               ",
			  stat->rule_num));
	EXEC(print_scalar(d, 1, "number of rules with ipt matches:      "
			  "            ", stat->rules_with_exec_matches));
	EXEC(print_scalar(d, 1, "number of rules with ipt target:       "
			  "            ", stat->rules_with_exec_target));
	EXEC(print_dist(d, 1, "number of \"same pos rules\" series of "
			"length [x, y]:", stat->rules_same_pos_stat,
			LEN(stat->rules_same_pos_stat)));
	EXEC(print_map(d, 0, "number of rules with x dt_matches:",
		       stat->dt_match_stat, LEN(stat->dt_match_stat)));
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

static int
hipac_r_read(char *page, char **start, off_t off, int count, int *eof,
	     void *data)
{
	struct proc_data *d = data;
	struct hipac_rule_stat *stat = d->stat;

	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_rule_stat(d->hipac, stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_rule_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_desc(d, 0, "root chain: "));
	EXEC(print_desc(d, 0, d->hipac_name));
	EXEC(print_desc(d, 0, "\n"));
	EXEC(print_scalar(d, 0, "number of rules:                        ",
			  stat->rule_num));
	EXEC(print_scalar(d, 1, "number of rules with ipt matches:  ",
			  stat->exec_match_num));
	EXEC(print_scalar(d, 1, "number of rules with ipt target:   ",
			  stat->exec_target_num));
	EXEC(print_scalar(d, 1, "number of rules with jump target:  ",
			  stat->jump_target_num));
	EXEC(print_scalar(d, 1, "number of rules with return target:",
			  stat->return_target_num));
	EXEC(print_map(d, 0, "number of rules with x hipac_matches:   ",
		       stat->hipac_match_stat, LEN(stat->hipac_match_stat)));
	EXEC(print_map(d, 0, "number of rules with x inverted matches:",
		       stat->inv_rules_stat, LEN(stat->inv_rules_stat)));
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

static int
hipac_c_read(char *page, char **start, off_t off, int count, int *eof,
	     void *data)
{
	struct proc_data *d = data;
	struct hipac_chain_stat *stat = d->stat;

	if (!NEED_REBUILD) {
		return write_stat(page, start, off, count, eof, d);
	}

	/* (re)compute statistics */
	down(&nlhp_lock);
	if (hipac_get_chain_stat(stat) != HE_OK) {
		/* this should never happen */
		up(&nlhp_lock);
		printk(KERN_ERR "%s: hipac_get_chain_stat failed\n",
		       __FUNCTION__);
		*eof = 1;
		return 0;
	}
	up(&nlhp_lock);

	/* (re)build text */
	write_lock(&d->lock);
	d->valid_len = 0;
	EXEC(print_scalar(d, 0, "chain memory (used):     ", stat->mem_tight));
	EXEC(print_scalar(d, 0, "chain memory (allocated):", stat->mem_real));
	EXEC(print_scalar(d, 0, "number of chains:        ", stat->chain_num));
	EXEC(print_scalar(d, 0, "number of rules:         ", stat->rule_num));
	EXEC(print_dist(d, 1, "number of chains with [x, y] prefixes:     ",
			stat->prefix_stat, LEN(stat->prefix_stat)));
	EXEC(print_dist(d, 1, "number of chains with [x, y] incoming arcs:",
			stat->incoming_stat, LEN(stat->incoming_stat)));
	EXEC(print_dist(d, 1, "number of chains with [x, y] outgoing arcs:",
			stat->outgoing_stat, LEN(stat->outgoing_stat)));
	write_unlock(&d->lock);
	return write_stat(page, start, off, count, eof, d);

 error:
	write_unlock(&d->lock);
	*eof = 1;
	return 0;
}

void
hpproc_init(u64 total_mem)
{
	struct proc_data *data;
	int i, j;

	nfhp_total_mem = total_mem;

	/* create proc directories */
	nfhipac_dir = proc_mkdir(proc_nfhipac_dir, proc_net);
	if (nfhipac_dir == NULL) {
		printk(KERN_NOTICE "nf_hipac: unable to create proc "
		       "directory\n");
		return;
	}
	nfhipac_dir->owner = THIS_MODULE;
	stat_dir = proc_mkdir(proc_stat_dir, nfhipac_dir);
	if (stat_dir == NULL) {
		printk(KERN_NOTICE "nf_hipac: unable to create proc "
		       "directory\n");
		goto cleanup_nfhipac_dir;
	}
	stat_dir->owner = THIS_MODULE;

	/* create statistics entries */
	init_nfhp_proc(nfhipac_dir, stat_dir);
	for (i = 0; i < sizeof(nfhp_proc) / sizeof(*nfhp_proc); i++) {
		data = kmalloc(sizeof(*data), GFP_KERNEL);
		if (data == NULL) {
			printk(KERN_NOTICE "nf_hipac: unable to create "
			       "proc infrastructure because of low memory\n");
			goto cleanup;
		}
		if (init_data(data, &nfhp_proc[i]) < 0) {
			printk(KERN_NOTICE "nf_hipac: unable to create "
			       "proc infrastructure because of low memory\n");
			goto cleanup;
		}
		nfhp_proc[i].entry = create_proc_entry(nfhp_proc[i].name,
						       nfhp_proc[i].mode,
						       nfhp_proc[i].parent);
		if (nfhp_proc[i].entry == NULL) {
			printk(KERN_NOTICE "nf_hipac: unable to create proc "
			       "entry\n");
			goto cleanup;
		}
		nfhp_proc[i].entry->owner = THIS_MODULE;
		nfhp_proc[i].entry->data = data;
		nfhp_proc[i].entry->read_proc = nfhp_proc[i].read_fn;
		nfhp_proc[i].entry->write_proc = nfhp_proc[i].write_fn;
	}
	return;

 cleanup:
	for (j = 0; j <= i; j++)
		remove_proc_entry(nfhp_proc[j].name, nfhp_proc[i].parent);
	remove_proc_entry(proc_stat_dir, nfhipac_dir);
 cleanup_nfhipac_dir:
	remove_proc_entry(proc_nfhipac_dir, proc_net);
	return;
}

void
hpproc_exit(void)
{
	int i;

	for (i = 0; i < sizeof(nfhp_proc) / sizeof(*nfhp_proc); i++)
		remove_proc_entry(nfhp_proc[i].name, nfhp_proc[i].parent);
	remove_proc_entry(proc_stat_dir, nfhipac_dir);
	remove_proc_entry(proc_nfhipac_dir, proc_net);
}
