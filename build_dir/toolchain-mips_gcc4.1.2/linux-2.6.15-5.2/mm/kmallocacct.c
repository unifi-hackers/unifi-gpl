#include	<linux/config.h>
#include	<linux/seq_file.h>
#include	<linux/kallsyms.h>

struct kma_caller {
	const void *caller;
	long total, net, slack, allocs, frees;
};

struct kma_list {
	int callerhash;
	const void *address;
};

#define MAX_CALLER_TABLE 1024
#define MAX_ALLOC_TRACK 32768

#define kma_hash(address, size) (((u32)address / (u32)size) % size)

static struct kma_list kma_alloc[MAX_ALLOC_TRACK];
static struct kma_caller kma_caller[MAX_CALLER_TABLE];

static int kma_callers;
static int kma_lost_callers, kma_lost_allocs, kma_unknown_frees;
static int kma_total, kma_net, kma_slack, kma_allocs, kma_frees;
static spinlock_t kma_lock = SPIN_LOCK_UNLOCKED;

void __kmalloc_account(const void *caller, const void *addr, int size, int
req)
{
	int i, hasha, hashc;
	unsigned long flags;

	spin_lock_irqsave(&kma_lock, flags);
	if(req >= 0) /* kmalloc */
	{
		/* find callers slot */
		hashc = kma_hash(caller, MAX_CALLER_TABLE);
		for (i = 0; i < MAX_CALLER_TABLE; i++) {
			if (!kma_caller[hashc].caller ||
			    kma_caller[hashc].caller == caller)
				break;
			hashc = (hashc + 1) % MAX_CALLER_TABLE;
		}

		if (!kma_caller[hashc].caller)
			kma_callers++;

		if (i < MAX_CALLER_TABLE) {
			/* update callers stats */
			kma_caller[hashc].caller = caller;
			kma_caller[hashc].total += size;
			kma_caller[hashc].net += size;
			kma_caller[hashc].slack += size - req;
			kma_caller[hashc].allocs++;

			/* add malloc to list */
			hasha = kma_hash(addr, MAX_ALLOC_TRACK);
			for (i = 0; i < MAX_ALLOC_TRACK; i++) {
				if (!kma_alloc[hasha].callerhash)
					break;
				hasha = (hasha + 1) % MAX_ALLOC_TRACK;
			}

			if(i < MAX_ALLOC_TRACK) {
				kma_alloc[hasha].callerhash = hashc;
				kma_alloc[hasha].address = addr;
			}
			else
				kma_lost_allocs++;
		}
		else {
			kma_lost_callers++;
			kma_lost_allocs++;
		}

		kma_total += size;
		kma_net += size;
		kma_slack += size - req;
		kma_allocs++;
	}
	else { /* kfree */
		hasha = kma_hash(addr, MAX_ALLOC_TRACK);
		for (i = 0; i < MAX_ALLOC_TRACK ; i++) {
			if (kma_alloc[hasha].address == addr)
				break;
			hasha = (hasha + 1) % MAX_ALLOC_TRACK;
		}

		if (i < MAX_ALLOC_TRACK) {
			hashc = kma_alloc[hasha].callerhash;
			kma_alloc[hasha].callerhash = 0;
			kma_caller[hashc].net -= size;
			kma_caller[hashc].frees++;
		}
		else
			kma_unknown_frees++;

		kma_net -= size;
		kma_frees++;
	}
	spin_unlock_irqrestore(&kma_lock, flags);
}

static void *as_start(struct seq_file *m, loff_t *pos)
{
	int i;
	loff_t n = *pos;

	if (!n) {
		seq_printf(m, "total bytes allocated: %8d\n", kma_total);
		seq_printf(m, "slack bytes allocated: %8d\n", kma_slack);
		seq_printf(m, "net bytes allocated:   %8d\n", kma_net);
		seq_printf(m, "number of allocs:      %8d\n", kma_allocs);
		seq_printf(m, "number of frees:       %8d\n", kma_frees);
		seq_printf(m, "number of callers:     %8d\n", kma_callers);
		seq_printf(m, "lost callers:          %8d\n",
			   kma_lost_callers);
		seq_printf(m, "lost allocs:           %8d\n",
			   kma_lost_allocs);
		seq_printf(m, "unknown frees:         %8d\n",
			   kma_unknown_frees);
		seq_puts(m, "\n   total    slack      net alloc/free  caller\n");
	}

	for (i = 0; i < MAX_CALLER_TABLE; i++) {
		if(kma_caller[i].caller)
			n--;
		if(n < 0)
			return (void *)(i+1);
	}

	return 0;
}

static void *as_next(struct seq_file *m, void *p, loff_t *pos)
{
	int n = (int)p-1, i;
	++*pos;

	for (i = n + 1; i < MAX_CALLER_TABLE; i++)
		if(kma_caller[i].caller)
			return (void *)(i+1);

	return 0;
}

static void as_stop(struct seq_file *m, void *p)
{

}

static int as_show(struct seq_file *m, void *p)
{
	int n = (int)p-1;
	struct kma_caller *c;
#ifdef CONFIG_KALLSYMS
	char *modname;
	const char *name;
	unsigned long offset = 0, size;
	char namebuf[128];

	c = &kma_caller[n];
	name = kallsyms_lookup((int)c->caller, &size, &offset, &modname,
			       namebuf);
	seq_printf(m, "%8ld %8ld %8ld %5d/%-5d %s+0x%lx\n",
		   c->total, c->slack, c->net, c->allocs, c->frees,
		   name, offset);
#else
	c = &kma_caller[n];
	seq_printf(m, "%8d %8d %8d %5d/%-5d %p\n",
		   c->total, c->slack, c->net, c->allocs, c->frees, c->caller);
#endif

	return 0;
}

void check_memleak(const void *startAddr, const void *endAddr)
{
    int i;
    struct kma_caller *c;

    for (i = 0; i < MAX_CALLER_TABLE; i++) {
        if(kma_caller[i].frees != kma_caller[i].allocs)
        {
            if( (void *)startAddr <= (void*)(kma_caller[i].caller) && (void *)(kma_caller[i].caller) <= (void *)endAddr)
            {
#ifdef CONFIG_KALLSYMS
                    char *modname;
                    const char *name;
                    unsigned long offset = 0, size;
                    char namebuf[128];

                    c = &kma_caller[i];
                    name = kallsyms_lookup((int)c->caller, &size, &offset, &modname,
                                   namebuf);
                    printk("%8ld %8ld %8ld %5d/%-5d %s+0x%lx\n",
                           c->total, c->slack, c->net, c->allocs, c->frees,
                           name, offset);
#else
                    c = &kma_caller[n];
                    printk("%8d %8d %8d %5d/%-5d %p\n",
                           c->total, c->slack, c->net, c->allocs, c->frees, c->caller);
#endif
            }
        }
    }
}

struct seq_operations kmalloc_account_op = {
	.start	= as_start,
	.next	= as_next,
	.stop	= as_stop,
	.show	= as_show,
};

