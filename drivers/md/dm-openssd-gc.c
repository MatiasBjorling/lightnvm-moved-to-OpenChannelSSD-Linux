#include "dm-openssd.h"
#include "dm-openssd-hint.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

static void queue_pool_gc(struct nvm_pool *pool)
{
	struct openssd *os = pool->os;
	queue_work(os->kgc_wq, &pool->gc_ws);
}

void openssd_gc_cb(unsigned long data)
{
	struct openssd *os = (void*) data;
//	struct nvm_pool *pool;
//	int i;
//	ssd_for_each_pool(os, pool, i)
//		queue_pool_gc(pool);
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
 * requires pool->gc_lock */
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
	struct nvm_addr src;
	struct bio *src_bio;
	struct page *page;
	sector_t l_addr;
	int slot = -1;
	void *gc_private = NULL;

	if (bitmap_full(block->invalid_pages, os->nr_host_pages_in_blk)) {
		printk("o0\n");
		return;
	}

	printk("o1\n");
	while ((slot = find_next_zero_bit(block->invalid_pages, os->nr_host_pages_in_blk, slot + 1)) < os->nr_host_pages_in_blk) {
		/* Perform read */
		src.addr = block_to_addr(block) + slot;
		src.block = block;

		/* TODO: check for memory failure */
		src_bio = bio_alloc(GFP_NOIO, 1);
		src_bio->bi_bdev = os->dev->bdev;
		src_bio->bi_sector = src.addr * NR_PHY_IN_LOG;

		page = mempool_alloc(os->page_pool, GFP_NOIO);

		/* TODO: check return value */
		if (!bio_add_page(src_bio, page, EXPOSED_PAGE_SIZE, 0))
			DMERR("Could not add page");

		openssd_submit_bio(os, &src, READ, src_bio, 1);

		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		l_addr = os->lookup_ptol(os, src.addr);
		/* remap src_bio to write the logical addr to new physical
		 * place */
		src_bio->bi_sector = l_addr;

		//DMDEBUG("move page p_addr=%ld l_addr=%ld (map[%ld]=%ld)", p_addr, l_addr, l_addr, os->trans_map[l_addr].addr);

		if (os->begin_gc_private)
			gc_private = os->begin_gc_private(l_addr, src.addr, block);

		openssd_write_execute_bio(os, src_bio, 1, NULL);

		if (os->end_gc_private)
			os->end_gc_private(gc_private);

		bio_put(src_bio);
		mempool_free(page, os->page_pool);
	}
	BUG_ON(!bitmap_full(block->invalid_pages, os->nr_host_pages_in_blk));
	printk("o2\n");
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
	struct nvm_pool *pool = container_of(work, struct nvm_pool, gc_ws);
	struct openssd *os = pool->os;
	struct nvm_block *block;
	unsigned int nr_blocks_need;

	/* DMDEBUG("pool_id=%d nr_blocks_need %d pool->nr_free_blocks %d", pid, nr_blocks_need, pool->nr_free_blocks); */
	nr_blocks_need = pool->nr_blocks / 10;
	/*DMINFO("pool_id=%d nr_blocks_need %d pool->nr_free_blocks %d",
	 * pid, nr_blocks_need, pool->nr_free_blocks);*/
	//printk("i need %u %u\n", nr_blocks_need, pool->nr_free_blocks);
	spin_lock(&pool->gc_lock);
	if (list_empty(&pool->prio_list)) {
		spin_unlock(&pool->gc_lock);
		return;
	}

	while (nr_blocks_need > pool->nr_free_blocks) {
		block = block_prio_find_max(pool);

		/* this should never happen. Its just here for an extra check */
		if (!block->nr_invalid_pages) {
			printk("o\n");
			break;
		}

		list_del(&block->prio);
		spin_unlock(&pool->gc_lock);

		/* this should never happen. Anyway, lets check for it.*/
		BUG_ON(!block_is_full(block));

		/* take the lock. But also make sure that we haven't messed up the
		 * gc routine, by removing the global gc lock. */
		BUG_ON(atomic_inc_return(&block->gc_running) != 1);

		/* rewrite to have moves outside lock. i.e. so we can
		 * prepare multiple pages in parallel on the attached
		 * device. */
		DMDEBUG("moving block addr %ld", block_to_addr(block));
		openssd_move_valid_pages(os, block);

		kref_put(&block->ref_count, openssd_block_release);

		spin_lock(&pool->gc_lock);
	}
	spin_unlock(&pool->gc_lock);
	//DMERR("Freed %u blocks", i);

	os->next_collect_pool++;

	queue_work(os->kbiod_wq, &os->deferred_ws);
}

void openssd_gc_kick(struct nvm_pool *pool)
{
	BUG_ON(!pool);
	queue_pool_gc(pool);
}
