#include "vsl.h"

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append point, we store it within the
 * used_list. We then move it back when its free to be used by another append
 * point.
 *
 * The newly claimed block is always added to the back of used_list. As we
 * assume that the start of used list is the oldest block, and therefore
 * more likely to contain invalidated pages.
 */
struct vsl_block *vsl_pool_get_block(struct vsl_pool *pool, int is_gc)
{
	struct vsl_stor *s;
	struct vsl_block *block = NULL;
	unsigned long flags;

	BUG_ON(!pool);

	s = pool->s;
	spin_lock_irqsave(&pool->lock, flags);

	if (list_empty(&pool->free_list)) {
		pr_err_ratelimited("Pool have no free pages available");
		__show_pool(pool);
		spin_unlock_irqrestore(&pool->lock, flags);
		goto out;
	}

	while (!is_gc && pool->nr_free_blocks < s->nr_aps) {
		spin_unlock_irqrestore(&pool->lock, flags);
		goto out;
	}

	block = list_first_entry(&pool->free_list, struct vsl_block, list);
	list_move_tail(&block->list, &pool->used_list);

	pool->nr_free_blocks--;

	spin_unlock_irqrestore(&pool->lock, flags);

	vsl_reset_block(block);

out:
	return block;
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void vsl_pool_put_block(struct vsl_block *block)
{
	struct vsl_pool *pool = block->pool;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);

	list_move_tail(&block->list, &pool->free_list);
	pool->nr_free_blocks++;

	spin_unlock_irqrestore(&pool->lock, flags);
}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We assume that there is no data and doesn't take a ref */
struct vsl_addr *vsl_lookup_ltop(struct vsl_stor *s, sector_t l_addr)
{
	struct vsl_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < s->nr_pages));

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	gp = &s->trans_map[l_addr];

	p->addr = gp->addr;
	p->block = gp->block;

	/* if it has not been written, p is initialized to 0. */
	if (p->block) {
		/* during gc, the mapping will be updated accordently. We
		 * therefore stop submitting new reads to the address, until it
		 * is copied to the new place. */
		if (atomic_read(&p->block->gc_running))
			goto err;
	}

	return p;
err:
	mempool_free(p, s->addr_pool);
	return NULL;

}

static inline unsigned int vsl_rq_sectors(const struct request *rq)
{
	/*TODO: remove hardcoding, query vsl_dev for setting*/
	return blk_rq_bytes(rq) >> 9;
}

static struct vsl_ap *__vsl_get_ap_rr(struct vsl_stor *s, int is_gc)
{
	if (!is_gc) {
		/*TODO: Factor out fnc and dependent vsl_stor var (latter to
		  custom, per-target struct)*/
		return get_next_ap(s);
	} else {
		/* during GC, we don't care about RR, instead we want to make
		 * sure that we maintain evenness between the block pools. */
		unsigned int i;
		struct vsl_pool *pool, *max_free;

		max_free = &s->pools[0];
		/* prevent GC-ing pool from devouring pages of a pool with
		 * little free blocks. We don't take the lock as we only need an
		 * estimate. */
		vsl_for_each_pool(s, pool, i) {
			if (pool->nr_free_blocks > max_free->nr_free_blocks)
				max_free = pool;
		}

		return &s->aps[max_free->id];
	}
}

/*read/write RQ has locked addr range already*/

static struct vsl_block *vsl_map_block_rr(struct vsl_stor *s, sector_t l_addr,
					int is_gc)
{
	struct vsl_ap *ap = NULL;
	struct vsl_block *block;

	ap = __vsl_get_ap_rr(s, is_gc);

	spin_lock(&ap->lock);
	block = s->type->pool_get_blk(ap->pool, is_gc);
	spin_unlock(&ap->lock);
	return block; /*NULL iff. no free blocks*/
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns vsl_addr with the physical address and block. Remember to return to
 * s->addr_cache when request is finished.
 */
static struct vsl_addr *vsl_map_page_rr(struct vsl_stor *s, sector_t l_addr,
					int is_gc)
{
	struct vsl_ap *ap = NULL;
	struct vsl_pool *pool = NULL;
	struct vsl_block *p_block = NULL;
	sector_t p_addr;
	struct vsl_addr *p = NULL;

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	ap = __vsl_get_ap_rr(s, is_gc);
	pool = ap->pool;

	spin_lock(&ap->lock);

	p_block = ap->cur;
	p_addr = vsl_alloc_phys_addr(p_block);

	if (p_addr == LTOP_EMPTY) {
		p_block = s->type->pool_get_blk(pool, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = vsl_alloc_phys_addr(ap->gc_cur);
				if (p_addr == LTOP_EMPTY) {
					p_block = s->type->pool_get_blk(pool, 1);
					ap->gc_cur = p_block;
					ap->gc_cur->ap = ap;
					if (!p_block) {
						show_all_pools(ap->parent);
						pr_err("vsl: no more blocks");
						goto finished;
					} else {
						p_addr =
						vsl_alloc_phys_addr(ap->gc_cur);
					}
				}
				p_block = ap->gc_cur;
			}
			goto finished;
		}

		vsl_set_ap_cur(ap, p_block);
		p_addr = vsl_alloc_phys_addr(p_block);
	}

finished:
	if (p_addr == LTOP_EMPTY) {
		mempool_free(p, s->addr_pool);
		return NULL;
	}

	p->addr = p_addr;
	p->block = p_block;

	if (!p_block)
		WARN_ON(is_gc);

	spin_unlock(&ap->lock);
	if (p)
		vsl_update_map(s, l_addr, p, is_gc);
	return p;
}

/* none target type, round robin, page-based FTL, and cost-based GC */
struct vsl_target_type vsl_target_rrpc = {
	.name		= "rrpc",
	.version	= {1, 0, 0},
	.lookup_ltop	= vsl_lookup_ltop,
	.map_page	= vsl_map_page_rr,
	.map_block	= vsl_map_block_rr,

	.write_rq	= vsl_write_rq,
	.read_rq	= vsl_read_rq,

	.pool_get_blk	= vsl_pool_get_block,
	.pool_put_blk	= vsl_pool_put_block,
};

/* none target type, round robin, block-based FTL, and cost-based GC */
struct vsl_target_type vsl_target_rrbc = {
	.name		= "rrbc",
	.version	= {1, 0, 0},
	.lookup_ltop	= vsl_lookup_ltop,
	.map_page	= NULL,
	.map_block	= vsl_map_block_rr,

	/*rewrite these to support multi-page writes*/
	.write_rq	= vsl_write_rq,
	.read_rq	= vsl_read_rq,

	.pool_get_blk	= vsl_pool_get_block,
	.pool_put_blk	= vsl_pool_put_block,
};
