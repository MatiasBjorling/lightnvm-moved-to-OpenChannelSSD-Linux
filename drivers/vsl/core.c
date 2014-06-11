#include "vsl.h"

/* requires lock on the translation map used */
void invalidate_block_page(struct vsl_stor *s, struct vsl_addr *p)
{
	unsigned int page_offset;
	struct vsl_block *block = p->block;

	page_offset = p->addr % s->nr_host_pages_in_blk;
	spin_lock(&block->lock);
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
	spin_unlock(&block->lock);
}

void vsl_update_map(struct vsl_stor *s, sector_t l_addr, struct vsl_addr *p,
					int is_gc, struct vsl_addr *trans_map)
{
	struct vsl_addr *gp;
	struct vsl_rev_addr *rev;

	BUG_ON(l_addr >= s->nr_pages);
	BUG_ON(p->addr >= s->nr_pages);

	gp = &trans_map[l_addr];
	spin_lock(&s->rev_lock);
	if (gp->block) {
		invalidate_block_page(s, gp);
		s->rev_trans_map[gp->addr].addr = LTOP_POISON;
	}

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &s->rev_trans_map[p->addr];
	rev->addr = l_addr;
	rev->trans_map = trans_map;
	spin_unlock(&s->rev_lock);
}

/* requires pool->lock taken */
inline void vsl_reset_block(struct vsl_block *block)
{
	struct vsl_stor *s = block->pool->s;

	BUG_ON(!block);

	spin_lock(&block->lock);
	bitmap_zero(block->invalid_pages, s->nr_host_pages_in_blk);
	block->ap = NULL;
	block->next_page = 0;
	block->next_offset = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->gc_running, 0);
	atomic_set(&block->data_size, 0);
	atomic_set(&block->data_cmnt_size, 0);
	spin_unlock(&block->lock);
}

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append point, we store it within the
 * used_list. We then move it back when its free to be used by another append
 * point.
 *
 * The newly acclaimed block is always added to the back of user_list. As we
 * assume that the start of used list is the oldest block, and therefore higher
 * probability of invalidated pages.
 */
struct vsl_block *vsl_pool_get_block(struct vsl_pool *pool, int is_gc)
{
	struct vsl_stor *s = pool->s;
	struct vsl_block *block = NULL;

	BUG_ON(!pool);

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		pr_err_ratelimited("Pool have no free pages available");
		spin_unlock(&pool->lock);
		show_pool(pool);
		return NULL;
	}

	while (!is_gc && pool->nr_free_blocks < s->nr_aps) {
		spin_unlock(&pool->lock);
		return NULL;
	}

	block = list_first_entry(&pool->free_list, struct vsl_block, list);
	list_move_tail(&block->list, &pool->used_list);

	pool->nr_free_blocks--;

	spin_unlock(&pool->lock);

	vsl_reset_block(block);

	block->data = mempool_alloc(s->block_page_pool, GFP_ATOMIC);
	BUG_ON(!block->data);

	return block;
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void vsl_pool_put_block(struct vsl_block *block)
{
	struct vsl_pool *pool = block->pool;

	spin_lock(&pool->lock);

	list_move_tail(&block->list, &pool->free_list);
	pool->nr_free_blocks++;

	spin_unlock(&pool->lock);
}

static sector_t __vsl_alloc_phys_addr(struct vsl_block *block,
							vsl_page_special_fn ps)
{
	struct vsl_stor *s;
	sector_t addr = LTOP_EMPTY;

	BUG_ON(!block);

	s = block->pool->s;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;

	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		if (ps && !ps(s, block->next_page + 1))
			goto out;

		block->next_offset = 0;
		block->next_page++;
	}

	addr = block_to_addr(block) +
			(block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) +
			block->next_offset;
	block->next_offset++;

	if (s->type->alloc_phys_addr)
		s->type->alloc_phys_addr(s, block);

out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t vsl_alloc_phys_addr_special(struct vsl_block *block,
						vsl_page_special_fn ps)
{
	return __vsl_alloc_phys_addr(block, ps);
}

sector_t vsl_alloc_phys_addr(struct vsl_block *block)
{
	return __vsl_alloc_phys_addr(block, NULL);
}

/* requires ap->lock taken */
void vsl_set_ap_cur(struct vsl_ap *ap, struct vsl_block *block)
{
	BUG_ON(!ap);
	BUG_ON(!block);

	if (ap->cur) {
		spin_lock(&ap->cur->lock);
		WARN_ON(!block_is_full(ap->cur));
		spin_unlock(&ap->cur->lock);
		ap->cur->ap = NULL;
	}
	ap->cur = block;
	ap->cur->ap = ap;
}

/* requires ap->lock held */
struct vsl_addr *vsl_alloc_addr_from_ap(struct vsl_ap *ap, int is_gc)
{
	struct vsl_stor *s = ap->parent;
	struct vsl_block *p_block;
	struct vsl_pool *pool;
	struct vsl_addr *p;
	sector_t p_addr;

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	p_block = ap->cur;
	pool = p_block->pool;
	p_addr = vsl_alloc_phys_addr(p_block);

	if (p_addr == LTOP_EMPTY) {
		p_block = vsl_pool_get_block(pool, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = vsl_alloc_phys_addr(ap->gc_cur);
				if (p_addr == LTOP_EMPTY) {
					p_block = vsl_pool_get_block(pool, 1);
					ap->gc_cur = p_block;
					ap->gc_cur->ap = ap;
					if (!p_block) {
						show_all_pools(ap->parent);
						DMERR("No more blocks");
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
	p->private = NULL;

	if (!p_block)
		WARN_ON(is_gc);

	return p;
}

void vsl_erase_block(struct vsl_block *block)
{
	/* Send erase command to device. */
}

struct vsl_addr *vsl_lookup_ltop_map(struct vsl_stor *s, sector_t l_addr,
				     struct vsl_addr *map, void *private)
{
	struct vsl_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < s->nr_pages));

	p = mempool_alloc(s->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	gp = &map[l_addr];

	p->addr = gp->addr;
	p->block = gp->block;

	/* if it has not been written, p is inited to 0. */
	if (p->block) {
		/* during gc, the mapping will be updated accordently. We
		 * therefore stop submitting new reads to the address, until it
		 * is copied to the new place. */
		if (atomic_read(&p->block->gc_running))
			goto err;
	}

	p->private = private;

	return p;
err:
	mempool_free(p, s->addr_pool);
	return NULL;

}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We assume that there is no data and doesn't take a ref */
struct vsl_addr *vsl_lookup_ltop(struct vsl_stor *s, sector_t l_addr)
{
	return vsl_lookup_ltop_map(s, l_addr, s->trans_map, NULL);
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns vsl_addr with the physical address and block. Remember to return to
 * s->addr_cache when request is finished.
 */
struct vsl_addr *vsl_map_ltop_rr(struct vsl_stor *s, sector_t l_addr, int is_gc,
				 struct vsl_addr *trans_map, void *private)
{
	struct vsl_ap *ap;
	struct vsl_addr *p;
	int i = 0;


	if (!is_gc) {
		ap = get_next_ap(s);
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

		ap = &s->aps[max_free->id];
	}

	spin_lock(&ap->lock);
	p = vsl_alloc_addr_from_ap(ap, is_gc);
	spin_unlock(&ap->lock);

	if (p)
		vsl_update_map(s, l_addr, p, is_gc, trans_map);

	return p;
}

static void vsl_endio(struct request *rq, int err)
{
	struct per_rq_data *pb;
	struct vsl_stor *s;
	struct vsl_ap *ap;
	struct vsl_pool *pool;
	struct vsl_addr *p;
	struct vsl_block *block;
	struct timespec end_tv, diff_tv;
	unsigned long diff, dev_wait, total_wait = 0;
	unsigned int data_cnt;

	pb = get_per_rq_data(rq);
	p = pb->addr;
	block = p->block;
	ap = pb->ap;
	s = ap->parent;
	pool = ap->pool;

	vsl_unlock_addr(s, pb->l_addr);

	if (rq_data_dir(rq) == WRITE) {
		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == s->nr_host_pages_in_blk) {
			mempool_free(block->data, s->block_page_pool);
			block->data = NULL;

			spin_lock(&pool->lock);
			list_add_tail(&block->prio, &pool->prio_list);
			spin_unlock(&pool->lock);
		}

		/* physical waits if hardware doesn't have a real backend */
		dev_wait = ap->t_write;
	} else {
		dev_wait = ap->t_read;
	}


	if (s->type->endio)
		s->type->endio(s, rq, pb, &dev_wait);

	if (!(s->config.flags & NVM_OPT_NO_WAITS) && dev_wait) {
wait_longer:
		getnstimeofday(&end_tv);
		diff_tv = timespec_sub(end_tv, pb->start_tv);
		diff = timespec_to_ns(&diff_tv) / 1000;
		if (dev_wait > diff) {
			total_wait = dev_wait - diff;
			WARN_ON(total_wait > 1500);
			if (total_wait > 10)
				udelay(5);
			goto wait_longer;
		}
	}

	if (s->config.flags & NVM_OPT_POOL_SERIALIZE) {
		/* we need this. updating pool current only by waiting_bios
		 * worker leaves a windows where current is bio thats was
		 * already ended */
		spin_lock(&pool->waiting_lock);
		pool->cur_bio = NULL;
		spin_unlock(&pool->waiting_lock);

		queue_work(s->kbiod_wq, &pool->waiting_ws);
	}

	/* Finish up */
	exit_pbd(pb, rq);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->orig_bio)
		bio_endio(pb->orig_bio, err);

	if (pb->event) {
		complete(pb->event);
		/* all submitted requests allocate their own addr,
		 * except GC reads */
		if (rq_data_dir(rq) == READ)
			goto free_pb;
	}

	mempool_free(pb->addr, s->addr_pool);
free_pb:
	free_pbd(s, pb);
}

static void vsl_end_write_rq(struct request *rq, int err)
{
	/* FIXME: Implement error handling of writes */
	vsl_endio(bio, err);

	/* separate bio is allocated on write. Remember to free it */
	bio_put(bio);
}

static void vsl_rq_zero_end(struct request *rq)
{
	/* TODO: fill rq with zeroes */
	blk_mq_complete_request(rq);
}

/* remember to lock l_add before calling vsl_submit_rq */
void vsl_submit_rq(struct vsl_stor *s, struct vsl_addr *p, sector_t l_addr,
			int rw, struct bio *bio,
			struct bio *orig_bio,
			struct completion *sync,
			struct vsl_addr *trans_map)
{
	struct vsl_block *block = p->block;
	struct vsl_ap *ap = block_to_ap(s, block);
	struct vsl_pool *pool = ap->pool;
	struct per_rq_data *pb;

	pb = get_per_rq_data(s->nvq, rq);
	pb->ap = ap;
	pb->addr = p;
	pb->l_addr = l_addr;
	pb->event = sync;
	pb->orig_bio = orig_bio;
	pb->trans_map = trans_map;

	if (blk_rq_dir(rq) == WRITE)
		bio->bi_end_io = vsl_end_write_bio;
	else
		bio->bi_end_io = vsl_end_read_bio;

	/* We allow counting to be semi-accurate as theres
	 * no lock for accounting. */
	ap->io_accesses[rq_data_dir(rq)]++;

/*	if (s->config.flags & NVM_OPT_POOL_SERIALIZE) {
		spin_lock(&pool->waiting_lock);
		s->type->bio_wait_add(&pool->waiting_bios, bio, p->private);

		if (atomic_inc_return(&pool->is_active) != 1) {
			atomic_dec(&pool->is_active);
			spin_unlock(&pool->waiting_lock);
			return;
		}

		bio = bio_list_peek(&pool->waiting_bios);

		/* we're not the only bio waiting */ /*
		if (!bio) {
			atomic_dec(&pool->is_active);
			spin_unlock(&pool->waiting_lock);
			return;
		}

		/* we're the only bio waiting. queue relevant worker*/ /*
		queue_work(s->kbiod_wq, &pool->waiting_ws);
		spin_unlock(&pool->waiting_lock);
		return;
	}*/ 

	submit_bio(bio->bi_rw, bio);
}

int vsl_read_rq(struct vsl_stor *s, struct request *rq)
{
	struct vsl_addr *p;
	sector_t l_addr;

	l_addr = blk_rq_pos(rq) / NR_PHY_IN_LOG;

	vsl_lock_addr(s, l_addr);

	p = s->type->lookup_ltop(s, l_addr);

	if (!p) {
		vsl_unlock_addr(s, l_addr);
		vsl_gc_kick(s);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	rq->sector = p->addr * NR_PHY_IN_LOG +
					(blk_rq_sectors(rq) % NR_PHY_IN_LOG);

	if (!p->block) {
		rq->sector = 0;
		vsl_rq_zero_end(rq);
		mempool_free(p, s->addr_pool);
		vsl_unlock_addr(s, l_addr);
		goto finished;
	}

	vsl_submit_rq(s, p, l_addr, READ, bio, NULL, NULL, s->trans_map);
finished:
	return BLK_MQ_RQ_QUEUE_OK;
}

struct bio *vsl_write_init_bio(struct vsl_stor *s, struct request *rq,
						struct vsl_addr *p)
{
	struct request *rq;
	int i, size;

	rq = blk_mq_alloc_request(s->q);
	if (!rq)
		return BLK_MQ_RQ_QUEUE_ERROR;

	rq->sector = p->addr * NR_PHY_IN_LOG;

	size = vsl_bv_copy(p, bio_iovec(bio));
	for (i = 0; i < NR_HOST_PAGES_IN_FLASH_PAGE; i++) {
		unsigned int idx = size - NR_HOST_PAGES_IN_FLASH_PAGE + i;
		bio_add_page(issue_bio, &p->block->data[idx], PAGE_SIZE, 0);
	}
	return issue_bio;
}

/* Assumes that l_addr is locked with vsl_lock_addr() */
int __vsl_write_rq(struct vsl_stor *s,
		  struct request *rq, int is_gc,
		  void *private, struct completion *sync,
		  struct vsl_addr *trans_map, unsigned int complete_bio)
{
	struct vsl_addr *p;
	struct bio *issue_bio;
	sector_t l_addr = blk_rq_sectors(rq) / NR_PHY_IN_LOG;

	p = s->type->map_ltop(s, l_addr, is_gc, trans_map, private);
	if (!p) {
		BUG_ON(is_gc);
		vsl_unlock_addr(s, l_addr);
		vsl_gc_kick(s);

		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	issue_bio = vsl_write_init_bio(s, bio, p);
	if (complete_bio)
		vsl_submit_rq(s, p, l_addr, WRITE, issue_bio, bio, sync,
								trans_map);
	else
		vsl_submit_rq(s, p, l_addri WRITE, issue_bio, NULL, sync,
								trans_map);

	return BLK_MQ_RQ_QUEUE_OK;
}

int vsl_write_rq(struct vsl_stor *s, struct request *rq)
{

}
