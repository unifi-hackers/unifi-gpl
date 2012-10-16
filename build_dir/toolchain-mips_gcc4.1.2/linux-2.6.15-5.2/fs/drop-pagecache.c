/*
 * Implement the manual drop-all-pagecache function
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/writeback.h>
#include <linux/sysctl.h>
#include <linux/gfp.h>
#include <linux/timer.h>
#include <linux/workqueue.h>

#define CACHE_CLEANUP_TIMEOUT (4 * HZ)

static struct timer_list cache_cleanup_timer = {  .function = NULL  };

static struct work_struct drop_cache_workq;

static void drop_pagecache_sb(struct super_block *sb)
{
	struct inode *inode;

	spin_lock(&inode_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_WILL_FREE))
			continue;
		invalidate_inode_pages(inode->i_mapping);
	}
	spin_unlock(&inode_lock);
}

void drop_pagecache(void)
{
	struct super_block *sb;

	spin_lock(&sb_lock);
restart:
	list_for_each_entry(sb, &super_blocks, s_list) {
		sb->s_count++;
		spin_unlock(&sb_lock);
		down_read(&sb->s_umount);
		if (sb->s_root)
			drop_pagecache_sb(sb);
		up_read(&sb->s_umount);
		spin_lock(&sb_lock);
		if (__put_super_and_need_restart(sb))
			goto restart;
	}
	spin_unlock(&sb_lock);
}

static void drop_slab(void)
{
	int nr_objects;

	do {
		nr_objects = shrink_slab(1000, GFP_KERNEL, 1000);
	} while (nr_objects > 10);
}

static void drop_caches_timer_handler(void)
{
        schedule_work(&drop_cache_workq);
}

static void drop_caches(void *arg)
{
        drop_pagecache();
        drop_slab();
        mod_timer(&cache_cleanup_timer, (jiffies + CACHE_CLEANUP_TIMEOUT));
}

int drop_pagecache_sysctl_handler(ctl_table *table, int write,
	struct file *file, void __user *buffer, size_t *length, loff_t *ppos)
{

        if (cache_cleanup_timer.function == NULL)
        {
            init_timer(&cache_cleanup_timer);
            INIT_WORK(&drop_cache_workq, (void *)drop_caches, NULL);
            cache_cleanup_timer.data = (void *) NULL;
            cache_cleanup_timer.function = (void *)drop_caches_timer_handler;
            cache_cleanup_timer.expires = (jiffies + CACHE_CLEANUP_TIMEOUT);
            add_timer(&cache_cleanup_timer);
        }
        else
            *length = 0;
/*
	if (write) {
		drop_pagecache();
		drop_slab();
	} else {
		*length = 0;
	}
*/
	return 0;
}
