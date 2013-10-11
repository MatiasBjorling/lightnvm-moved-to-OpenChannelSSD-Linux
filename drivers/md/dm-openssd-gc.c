#include <linux/percpu-refcount.h>

#include "dm-openssd.h"

static void __erase_block(struct openssd_pool_block *block)
{
	// Perform device erase
}

/* the block with highest number of invalid pages, will be in the beginning of the list */
static int block_prio_sort_cmp(void *priv, struct list_head *lh_a, struct list_head *lh_b)
{
	struct openssd_pool_block *a = list_entry(lh_a, struct openssd_pool_block, prio);
	struct openssd_pool_block *b = list_entry(lh_b, struct openssd_pool_block, prio);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return 0;

	return a->nr_invalid_pages < b->nr_invalid_pages;
}

/* Move data away from flash block to be erased. Additionally update the l to p and p to l
 * mappings.
 */
static void openssd_move_valid_pages(struct openssd *os, struct openssd_pool_block *block)
{
	struct bio *src_bio;
	struct page *page;
	struct openssd_pool_block* victim_block;
	int slot = -1;
	sector_t physical_addr, logical_addr, dest_addr;
	int i;
	struct bio_vec *bv;

	if (bitmap_full(block->invalid_pages, NR_HOST_PAGES_IN_BLOCK))
		return;

	page = alloc_page(GFP_NOIO);
	while ((slot = find_next_zero_bit(block->invalid_pages, NR_HOST_PAGES_IN_BLOCK, slot + 1)) < NR_HOST_PAGES_IN_BLOCK) {
		// Perform read
		physical_addr = block_to_addr(block) + slot;
		DMINFO("move page physical_addr=%ld", physical_addr);
		src_bio = bio_alloc(GFP_NOIO, 1); // handle mem error

		bio_get(src_bio);

		src_bio->bi_bdev = os->dev->bdev;
		src_bio->bi_sector = physical_addr * NR_PHY_IN_LOG;
		bio_add_page(src_bio, page, EXPOSED_PAGE_SIZE, 0);

		openssd_submit_bio(os, block, READ, src_bio, 1);

		// Perform write

		// We use the physical address to go to the logical page addr, and then update its mapping
		// to its new place.
		logical_addr = os->lookup_ptol(os, physical_addr);
		DMINFO("move page physical_addr=%ld logical_addr=%ld (trans_map[%ld]=%ld)", physical_addr, logical_addr, logical_addr, os->trans_map[logical_addr].addr);
		// Doesn't handle shadow addresses yet.
		dest_addr = os->map_ltop(os, logical_addr, &victim_block, (void*)NULL);

		/* Write using regular write machanism */
		bio_for_each_segment(bv, src_bio, i) {
			unsigned int size = openssd_handle_buffered_write(dest_addr, victim_block, bv);
			if (size % NR_HOST_PAGES_IN_FLASH_PAGE == 0)
				openssd_submit_write(os, dest_addr, victim_block, size);
		}
	}
	__free_page(page);
	bitmap_fill(block->invalid_pages, NR_HOST_PAGES_IN_BLOCK);
}

/* Push erase condition to automatically be executed when block goes to zero.
 * Only GC should do this */
void openssd_block_release(struct percpu_ref *ref)
{
	struct openssd_pool_block *block;

	block = container_of(ref, struct openssd_pool_block, ref_count);

	DMINFO("erasing block");
	__erase_block(block);
	openssd_pool_put_block(block);
}

void openssd_gc_collect(struct openssd *os)
{
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	unsigned int nr_blocks_need;
	int pid, pid_start;
	int max_collect = round_up(os->nr_pools, 2);

	if (!spin_trylock(&os->gc_lock))
		return;

	while (max_collect) {
		block = NULL;
		/* Iterate the pools once to look for pool that has a block to be freed. */
		pid = os->next_collect_pool % os->nr_pools;
		pid_start = pid;
		do {
			pool = &os->pools[pid];

			nr_blocks_need = pool->nr_blocks;
			do_div(nr_blocks_need, GC_LIMIT_INVERSE);

			//DMINFO("pool_id=%d nr_blocks_need %d pool->nr_free_blocks %d", pid, nr_blocks_need, pool->nr_free_blocks);
			if (nr_blocks_need >= pool->nr_free_blocks) {
				list_sort(NULL, &pool->prio_list, block_prio_sort_cmp);
				block = list_first_entry(&pool->prio_list, struct openssd_pool_block, prio);
				//DMINFO("block->id=%d addr=%ld block->nr_invalid_pages=%d block->invalid_pages=%x%x", block->id, block_to_addr(block), block->nr_invalid_pages, block->invalid_pages[0], block->invalid_pages[1]);

				if (block->nr_invalid_pages != 0 &&
					block_is_full(block)) {
					/* rewrite to have moves outside lock. i.e. so we can prepare multiple pages
					 * in parallel on the attached device. */
					DMINFO("move pages");
					openssd_move_valid_pages(os, block);

					/* We activate ref counting and make put take action. */
					percpu_ref_kill(&block->ref_count);
					/* When block hits zero refs, its added back to 
					 * the empty pool */
					openssd_put_block(block);

					break;
				}
			}

			pid++;
			pid %= os->nr_pools;
		} while (pid_start != pid);

		os->next_collect_pool++;
		max_collect--;
	}
	spin_unlock(&os->gc_lock);
}
