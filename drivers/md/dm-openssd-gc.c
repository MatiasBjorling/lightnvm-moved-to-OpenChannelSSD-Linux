#include "dm-openssd.h"
#include "dm-openssd-hint.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

void openssd_gc_cb(unsigned long data)
{
	struct openssd *os = (void*) data;
	queue_work(os->kgc_wq, &os->gc_ws);
	mod_timer(&os->gc_timer, jiffies + msecs_to_jiffies(os->config.gc_time));
}

static void __erase_block(struct nvm_block *block)
{
	// Perform device erase
}

/* the block with highest number of invalid pages, will be in the beginning of the list */
static struct nvm_block* block_max_invalid(struct nvm_block *a,
					   struct nvm_block *b)
{
	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return a;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? b : a;
}

/* linearly find the block with highest number of invalid pages 
 * requires pool->lock */
static struct nvm_block* block_prio_find_max(struct nvm_pool *pool)
{
	struct list_head *list = &pool->prio_list;
	struct nvm_block *block, *max;

	BUG_ON(list_empty(list));

	max = list_first_entry(list, struct nvm_block, prio);
	list_for_each_entry(block, list, prio)
		max = block_max_invalid(max, block);
	/*DMINFO("GC max: return block with max invalid %d %d",
	 max->nr_invalid_pages, max->next_page);*/

	return max;
}

/* Move data away from flash block to be erased. Additionally update the l to p and p to l
 * mappings.
 */
static void openssd_move_valid_pages(struct openssd *os, struct nvm_block *block)
{
	struct bio *src_bio;
	struct page *page;
	struct nvm_block* victim_block;
	int slot = -1;
	sector_t p_addr, l_addr, dst_addr;
	int i;
	struct bio_vec *bv;
	void *gc_private = NULL;

	if (bitmap_full(block->invalid_pages, os->nr_host_pages_in_blk))
		return;

	while ((slot = find_next_zero_bit(block->invalid_pages, os->nr_host_pages_in_blk, slot + 1)) < os->nr_host_pages_in_blk) {
		/* Perform read */
		p_addr = block_to_addr(block) + slot;

		/* TODO: check for memory failure */
		src_bio = bio_alloc(GFP_NOIO, 1);

		src_bio->bi_bdev = os->dev->bdev;
		src_bio->bi_sector = p_addr * NR_PHY_IN_LOG;
		page = mempool_alloc(os->page_pool, GFP_NOIO);

		/* TODO: check return value */
		bio_add_page(src_bio, page, EXPOSED_PAGE_SIZE, 0);

		openssd_submit_bio(os, block, READ, src_bio, 1);

		/* Perform write */
		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		l_addr = os->lookup_ptol(os, p_addr);
		//DMDEBUG("move page p_addr=%ld l_addr=%ld (map[%ld]=%ld)", p_addr, l_addr, l_addr, os->trans_map[l_addr].addr);

		if (os->begin_gc_private)
			gc_private = os->begin_gc_private(l_addr, p_addr, block);

		dst_addr = openssd_alloc_addr(os, l_addr, &victim_block, 1, gc_private);

		if (os->end_gc_private)
			os->end_gc_private(gc_private);

		/* Write using regular write machanism */
		bio_for_each_segment(bv, src_bio, i) {
			unsigned int size = openssd_handle_buffered_write(dst_addr, victim_block, bv);
			if (size % NR_HOST_PAGES_IN_FLASH_PAGE == 0)
				openssd_submit_write(os, dst_addr, victim_block, size);
		}

		bio_put(src_bio);
		mempool_free(page, os->page_pool);
	}
	BUG_ON(!bitmap_full(block->invalid_pages, os->nr_host_pages_in_blk));
}

/* Push erase condition to automatically be executed when block goes to zero.
 * Only GC should do this */
void openssd_block_release(struct kref *ref)
{
	struct nvm_block *block = container_of(ref, struct nvm_block, ref_count);

	__erase_block(block);

	nvm_pool_put_block(block);
}

void openssd_gc_collect(struct work_struct *work)
{
	struct openssd *os = container_of(work, struct openssd, gc_ws);
	struct nvm_pool *pool;
	struct nvm_block *block;
	unsigned int nr_blocks_need;
	int pid, pid_start;

	block = NULL;
	/* Iterate the pools once to look for pool that has a block to be freed. */
	pid_start = os->next_collect_pool % os->nr_pools;
	for (pid = 0; pid < os->nr_pools; pid++) {
		pool = &os->pools[(pid + pid_start) % os->nr_pools];

		/* DMDEBUG("pool_id=%d nr_blocks_need %d pool->nr_free_blocks %d", pid, nr_blocks_need, pool->nr_free_blocks); */
		nr_blocks_need = pool->nr_blocks / 10;

		/*DMINFO("pool_id=%d nr_blocks_need %d pool->nr_free_blocks %d",
		 * pid, nr_blocks_need, pool->nr_free_blocks);*/
		//printk("i need %u %u\n", nr_blocks_need, pool->nr_free_blocks);
		spin_lock(&pool->lock);
		while (nr_blocks_need > pool->nr_free_blocks) {

			if (list_empty(&pool->prio_list))
				break;

			block = block_prio_find_max(pool);

			/* this should never happen. Its just here for an extra check */
			if (!block->nr_invalid_pages)
				break;

			list_del(&block->prio);
			spin_unlock(&pool->lock);

			/* this should never happen. Anyway, lets check for it.*/
			BUG_ON(!block_is_full(block));

			/* take the lock. But also make sure that we haven't messed up the
			 * gc routine, by removing the global gc lock. */
			BUG_ON(!atomic_inc_return(&block->gc_running));

			/* rewrite to have moves outside lock. i.e. so we can
			 * prepare multiple pages in parallel on the attached
			 * device. */
			DMDEBUG("moving block addr %ld", block_to_addr(block));
			openssd_move_valid_pages(os, block);

			kref_put(&block->ref_count, openssd_block_release);

			spin_lock(&pool->lock);
		}
		spin_unlock(&pool->lock);
		//DMERR("Freed %u blocks", i);
	}

	os->next_collect_pool++;
}

void openssd_gc_kick_wait(struct openssd *os)
{
	queue_work(os->kgc_wq, &os->gc_ws);
	flush_workqueue(os->kgc_wq);
}
