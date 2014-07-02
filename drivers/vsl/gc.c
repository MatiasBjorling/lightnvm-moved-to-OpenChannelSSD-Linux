#include <linux/openvsl.h>
#include "vsl.h"

/* Run only GC if less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 10

static void queue_pool_gc(struct vsl_pool *pool)
{
	struct vsl_stor *s = pool->s;

	queue_work(s->krqd_wq, &pool->gc_ws);
}

void vsl_gc_cb(unsigned long data)
{
	struct vsl_stor *s = (struct vsl_stor *)data;
	struct vsl_pool *pool;
	int i;

	vsl_for_each_pool(s, pool, i)
		queue_pool_gc(pool);

	mod_timer(&s->gc_timer,
			jiffies + msecs_to_jiffies(s->config.gc_time));
}

static void __erase_block(struct vsl_block *block)
{
	/* TODO: Perform device flash erase */
}

/* the block with highest number of invalid pages, will be in the beginning
 * of the list */
static struct vsl_block *block_max_invalid(struct vsl_block *a,
					   struct vsl_block *b)
{
	BUG_ON(!a || !b);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return a;

	return (a->nr_invalid_pages < b->nr_invalid_pages) ? b : a;
}

/* linearly find the block with highest number of invalid pages
 * requires pool->lock */
static struct vsl_block *block_prio_find_max(struct vsl_pool *pool)
{
	struct list_head *list = &pool->prio_list;
	struct vsl_block *block, *max;

	BUG_ON(list_empty(list));

	max = list_first_entry(list, struct vsl_block, prio);
	list_for_each_entry(block, list, prio)
		max = block_max_invalid(max, block);

	return max;
}

/* Move data away from flash block to be erased. Additionally update the
 * l to p and p to l mappings. */
static void vsl_move_valid_pages(struct vsl_stor *s, struct vsl_block *block)
{
	struct vsl_dev *dev = s->dev;
	struct request_queue *q = dev->q;
	struct vsl_addr src;
	struct vsl_rev_addr *rev;
	struct bio *src_bio;
	struct request *src_rq, *dst_rq;
	struct page *page;
	int slot;
	DECLARE_COMPLETION(sync);

	if (bitmap_full(block->invalid_pages, s->nr_host_pages_in_blk))
		return;

	while ((slot = find_first_zero_bit(block->invalid_pages,
					   s->nr_host_pages_in_blk)) <
						s->nr_host_pages_in_blk) {
		/* Perform read */
		src.addr = block_to_addr(block) + slot;
		src.block = block;

		BUG_ON(src.addr >= s->nr_pages);

		src_bio = bio_alloc(GFP_NOIO, 1);
		if (!src_bio)
			pr_err("vsl: failed to alloc gc bio request");
		src_bio->bi_iter.bi_sector = src.addr * NR_PHY_IN_LOG;
		page = mempool_alloc(s->page_pool, GFP_NOIO);

		/* TODO: may fail with EXP_PG_SIZE > PAGE_SIZE */
		bio_add_page(src_bio, page, EXPOSED_PAGE_SIZE, 0);

		src_rq = blk_mq_alloc_request(q, READ, GFP_KERNEL, false);
		if (!src_rq)
			pr_err("vsl: failed to alloc gc request");

		blk_init_request_from_bio(src_rq, src_bio);

		/* We take the reverse lock here, and make sure that we only
		 * release it when we have locked its logical address. If
		 * another write on the same logical address is
		 * occuring, we just let it stall the pipeline.
		 *
		 * We do this for both the read and write. Fixing it after each
		 * IO.
		 */
		spin_lock(&s->rev_lock);
		/* We use the physical address to go to the logical page addr,
		 * and then update its mapping to its new place. */
		rev = &s->rev_trans_map[src.addr];

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		/* unlocked by vsl_submit_bio vsl_endio */
		__vsl_lock_addr(s, rev->addr, 1);
		spin_unlock(&s->rev_lock);

		init_completion(&sync);
		vsl_submit_rq(s, src_rq, &src, rev->addr,
							&sync, rev->trans_map);
		wait_for_completion(&sync);

		blk_put_request(src_rq);
		dst_rq = blk_mq_alloc_request(q, WRITE, GFP_KERNEL, false);

		blk_init_request_from_bio(dst_rq, src_bio);

		/* ok, now fix the write and make sure that it haven't been
		 * moved in the meantime. */
		spin_lock(&s->rev_lock);

		/* already updated by previous regular write */
		if (rev->addr == LTOP_POISON) {
			spin_unlock(&s->rev_lock);
			goto overwritten;
		}

		src_bio->bi_iter.bi_sector = rev->addr * NR_PHY_IN_LOG;

		/* again, unlocked by vsl_endio */
		__vsl_lock_addr(s, rev->addr, 1);
		spin_unlock(&s->rev_lock);


		init_completion(&sync);
		__vsl_write_rq(s, src_rq, 1, NULL, &sync, rev->trans_map);
		wait_for_completion(&sync);

overwritten:
		blk_put_request(dst_rq);
		bio_put(src_bio);
		mempool_free(page, s->page_pool);
	}
	WARN_ON(!bitmap_full(block->invalid_pages, s->nr_host_pages_in_blk));
}

void vsl_gc_collect(struct work_struct *work)
{
	struct vsl_pool *pool = container_of(work, struct vsl_pool, gc_ws);
	struct vsl_stor *s = pool->s;
	struct vsl_block *block;
	unsigned int nr_blocks_need;

	nr_blocks_need = pool->nr_blocks / 10;

	if (nr_blocks_need < s->nr_aps)
		nr_blocks_need = s->nr_aps;

	spin_lock(&pool->lock);
	while (nr_blocks_need > pool->nr_free_blocks &&
						!list_empty(&pool->prio_list)) {
		block = block_prio_find_max(pool);

		if (!block->nr_invalid_pages) {
			spin_unlock(&pool->lock);
			show_pool(pool);
			spin_lock(&pool->lock);
			pr_err("No invalid pages");
			break;
		}

		list_del_init(&block->prio);

		BUG_ON(!block_is_full(block));
		BUG_ON(atomic_inc_return(&block->gc_running) != 1);

		queue_work(s->kgc_wq, &block->ws_gc);

		nr_blocks_need--;
	}
	spin_unlock(&pool->lock);
	s->next_collect_pool++;

	/* TODO: Hint that request queue can be started again */
}

void vsl_gc_block(struct work_struct *work)
{
	struct vsl_block *block = container_of(work, struct vsl_block, ws_gc);
	struct vsl_stor *s = block->pool->s;

	/* TODO: move outside lock to allow multiple pages
	 * in parallel to be erased. */
	vsl_move_valid_pages(s, block);
	__erase_block(block);
	vsl_pool_put_block(block);
}

void vsl_gc_kick(struct vsl_stor *s)
{
	struct vsl_pool *pool;
	unsigned int i;

	BUG_ON(!s);

	vsl_for_each_pool(s, pool, i)
		queue_pool_gc(pool);
}
