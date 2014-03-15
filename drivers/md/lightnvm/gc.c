#include "lightnvm.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

static void queue_pool_gc(struct nvm_pool *pool)
{
	struct nvmd *nvmd = pool->nvmd;
	queue_work(nvmd->kbiod_wq, &pool->gc_ws);
}

void nvm_gc_cb(unsigned long data)
{
	struct nvmd *nvmd = (struct nvmd *)data;
	struct nvm_pool *pool;
	int i;

/*	nvm_for_each_pool(nvmd, pool, i)
		queue_pool_gc(pool);
*/
	mod_timer(&nvmd->gc_timer,
			jiffies + msecs_to_jiffies(nvmd->config.gc_time));
}

static void __erase_block(struct nvm_block *block)
{
	/* TODO: Perform device flash erase */
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct nvm_block *block_max_invalid(struct nvm_block *a,
					   struct nvm_block *b)
{
	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return a;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? b : a;
}

/* linearly find the block with highest number of invalid pages
 * requires pool->gc_lock */
static struct nvm_block *block_prio_find_max(struct nvm_pool *pool)
{
	struct list_head *list = &pool->prio_list;
	struct nvm_block *block, *max;

	BUG_ON(list_empty(list));

	max = list_first_entry(list, struct nvm_block, prio);
	list_for_each_entry(block, list, prio)
		max = block_max_invalid(max, block);

	return max;
}

/* Move data away from flash block to be erased. Additionally update the
 * l to p and p to l mappings. */
static void nvm_move_valid_pages(struct nvmd *nvmd, struct nvm_block *block)
{
	struct nvm_addr src;
	struct nvm_rev_addr *rev;
	struct bio *src_bio;
	struct page *page;
	int slot;
	void *gc_private = NULL;
	DECLARE_COMPLETION(sync);

	if (bitmap_full(block->invalid_pages, nvmd->nr_host_pages_in_blk))
		return;

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   nvmd->nr_host_pages_in_blk)) <
						nvmd->nr_host_pages_in_blk) {
		/* Perform read */
		src.addr = block_to_addr(block) + slot;
		src.block = block;

		/* TODO: check for memory failure */
		src_bio = bio_alloc(GFP_NOIO, 1);
		src_bio->bi_bdev = nvmd->dev->bdev;
		src_bio->bi_sector = src.addr * NR_PHY_IN_LOG;

		page = mempool_alloc(nvmd->page_pool, GFP_NOIO);

		/* TODO: check return value */
		if (!bio_add_page(src_bio, page, EXPOSED_PAGE_SIZE, 0))
			DMERR("Could not add page");

		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		rev = nvmd->type->lookup_ptol(nvmd, src.addr);

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON)
			continue;

		/* unlocked by nvm_submit_bio nvm_endio */
		nvm_lock_addr(nvmd, rev->addr);

		init_completion(&sync);
		nvm_submit_bio(nvmd, &src, rev->addr, READ, src_bio, NULL,
								&sync, NULL);
		wait_for_completion(&sync);

		src_bio->bi_sector = rev->addr * NR_PHY_IN_LOG;

		gc_private = NULL;
		if (nvmd->type->begin_gc)
			gc_private = nvmd->type->begin_gc(nvmd,
							rev->addr, src.addr,
									block);

		init_completion(&sync);
		nvm_write_bio(nvmd, src_bio, 1, gc_private, &sync,
							rev->trans_map, 1);
		wait_for_completion(&sync);

		if (nvmd->type->end_gc)
			nvmd->type->end_gc(nvmd, gc_private);

		bio_put(src_bio);
		mempool_free(page, nvmd->page_pool);
	}
	WARN_ON(!bitmap_full(block->invalid_pages, nvmd->nr_host_pages_in_blk));
}

void nvm_gc_collect(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, gc_ws);
	struct nvmd *nvmd = pool->nvmd;
	struct nvm_block *block;
	unsigned int nr_blocks_need;

	nr_blocks_need = pool->nr_blocks / 10;

	if (nr_blocks_need < nvmd->nr_aps)
		nr_blocks_need = nvmd->nr_aps;

	spin_lock(&pool->gc_lock);
	spin_lock(&pool->lock);
	while (nr_blocks_need > pool->nr_free_blocks &&
						!list_empty(&pool->prio_list)) {
		block = block_prio_find_max(pool);

		if (!block->nr_invalid_pages) {
			DMERR("No invalid pages\n");
			break;
		}

		list_del_init(&block->prio);

		BUG_ON(!block_is_full(block));
		BUG_ON(atomic_inc_return(&block->gc_running) != 1);

		queue_work(nvmd->kgc_wq, &block->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&pool->lock);
	spin_unlock(&pool->gc_lock);
	nvmd->next_collect_pool++;

	queue_work(nvmd->kbiod_wq, &nvmd->deferred_ws);
}

void nvm_gc_block(struct work_struct *work)
{
	struct nvm_block *block = container_of(work, struct nvm_block, ws_gc);
	struct nvmd *nvmd = block->pool->nvmd;

	/* TODO: move outside lock to allow multiple pages
	 * in parallel to be erased. */
	nvm_move_valid_pages(nvmd, block);
	__erase_block(block);
	nvm_pool_put_block(block);
}

void nvm_gc_kick(struct nvmd *nvmd)
{
	struct nvm_pool *pool;
	unsigned int i;
	BUG_ON(!nvmd);

	nvm_for_each_pool(nvmd, pool, i)
		queue_pool_gc(pool);
}
