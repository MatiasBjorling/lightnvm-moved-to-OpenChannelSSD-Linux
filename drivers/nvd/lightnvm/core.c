#include "lightnvm.h"

/* requires lock on the translation map used */
void invalidate_block_page(struct nvmd *nvmd, struct nvm_addr *p)
{
	unsigned int page_offset;
	struct nvm_block *block = p->block;

	page_offset = p->addr % nvmd->nr_host_pages_in_blk;
	spin_lock(&block->lock);
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
	spin_unlock(&block->lock);
}

void nvm_update_map(struct nvmd *nvmd, sector_t l_addr, struct nvm_addr *p,
					int is_gc, struct nvm_addr *trans_map)
{
	struct nvm_addr *gp;
	struct nvm_rev_addr *rev;

	BUG_ON(l_addr >= nvmd->nr_pages);
	BUG_ON(p->addr >= nvmd->nr_pages);

	gp = &trans_map[l_addr];
	spin_lock(&nvmd->rev_lock);
	if (gp->block) {
		invalidate_block_page(nvmd, gp);
		nvmd->rev_trans_map[gp->addr].addr = LTOP_POISON;
	}

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &nvmd->rev_trans_map[p->addr];
	rev->addr = l_addr;
	rev->trans_map = trans_map;
	spin_unlock(&nvmd->rev_lock);
}

/* requires pool->lock taken */
inline void nvm_reset_block(struct nvm_block *block)
{
	struct nvmd *nvmd = block->pool->nvmd;

	BUG_ON(!block);

	spin_lock(&block->lock);
	bitmap_zero(block->invalid_pages, nvmd->nr_host_pages_in_blk);
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
struct nvm_block *nvm_pool_get_block(struct nvm_pool *pool, int is_gc)
{
	struct nvmd *nvmd = pool->nvmd;
	struct nvm_block *block = NULL;

	BUG_ON(!pool);

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		pr_err_ratelimited("Pool have no free pages available");
		spin_unlock(&pool->lock);
		show_pool(pool);
		return NULL;
	}

	while (!is_gc && pool->nr_free_blocks < nvmd->nr_aps) {
		spin_unlock(&pool->lock);
		return NULL;
	}

	block = list_first_entry(&pool->free_list, struct nvm_block, list);
	list_move_tail(&block->list, &pool->used_list);

	pool->nr_free_blocks--;

	spin_unlock(&pool->lock);

	nvm_reset_block(block);

	block->data = mempool_alloc(nvmd->block_page_pool, GFP_ATOMIC);
	BUG_ON(!block->data);

	return block;
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby
 * provide simple (naive) wear-leveling.
 */
void nvm_pool_put_block(struct nvm_block *block)
{
	struct nvm_pool *pool = block->pool;

	spin_lock(&pool->lock);

	list_move_tail(&block->list, &pool->free_list);
	pool->nr_free_blocks++;

	spin_unlock(&pool->lock);
}

static sector_t __nvm_alloc_phys_addr(struct nvm_block *block,
							nvm_page_special_fn ps)
{
	struct nvmd *nvmd;
	sector_t addr = LTOP_EMPTY;

	BUG_ON(!block);

	nvmd = block->pool->nvmd;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;

	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		if (ps && !ps(nvmd, block->next_page + 1))
			goto out;

		block->next_offset = 0;
		block->next_page++;
	}

	addr = block_to_addr(block) +
			(block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) +
			block->next_offset;
	block->next_offset++;

	if (nvmd->type->alloc_phys_addr)
		nvmd->type->alloc_phys_addr(nvmd, block);

out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t nvm_alloc_phys_addr_special(struct nvm_block *block,
						nvm_page_special_fn ps)
{
	return __nvm_alloc_phys_addr(block, ps);
}

sector_t nvm_alloc_phys_addr(struct nvm_block *block)
{
	return __nvm_alloc_phys_addr(block, NULL);
}

/* requires ap->lock taken */
void nvm_set_ap_cur(struct nvm_ap *ap, struct nvm_block *block)
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
struct nvm_addr *nvm_alloc_addr_from_ap(struct nvm_ap *ap, int is_gc)
{
	struct nvmd *nvmd = ap->parent;
	struct nvm_block *p_block;
	struct nvm_pool *pool;
	struct nvm_addr *p;
	sector_t p_addr;

	p = mempool_alloc(nvmd->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	p_block = ap->cur;
	pool = p_block->pool;
	p_addr = nvm_alloc_phys_addr(p_block);

	if (p_addr == LTOP_EMPTY) {
		p_block = nvm_pool_get_block(pool, 0);

		if (!p_block) {
			if (is_gc) {
				p_addr = nvm_alloc_phys_addr(ap->gc_cur);
				if (p_addr == LTOP_EMPTY) {
					p_block = nvm_pool_get_block(pool, 1);
					ap->gc_cur = p_block;
					ap->gc_cur->ap = ap;
					if (!p_block) {
						show_all_pools(ap->parent);
						DMERR("No more blocks");
						goto finished;
					} else {
						p_addr =
						nvm_alloc_phys_addr(ap->gc_cur);
					}
				}
				p_block = ap->gc_cur;
			}
			goto finished;
		}

		nvm_set_ap_cur(ap, p_block);
		p_addr = nvm_alloc_phys_addr(p_block);
	}

finished:
	if (p_addr == LTOP_EMPTY) {
		mempool_free(p, nvmd->addr_pool);
		return NULL;
	}

	p->addr = p_addr;
	p->block = p_block;
	p->private = NULL;

	if (!p_block)
		WARN_ON(is_gc);

	return p;
}

void nvm_erase_block(struct nvm_block *block)
{
	/* Send erase command to device. */
}

struct nvm_addr *nvm_lookup_ltop_map(struct nvmd *nvmd, sector_t l_addr,
				     struct nvm_addr *map, void *private)
{
	struct nvm_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < nvmd->nr_pages));

	p = mempool_alloc(nvmd->addr_pool, GFP_ATOMIC);
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
	mempool_free(p, nvmd->addr_pool);
	return NULL;

}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We assume that there is no data and doesn't take a ref */
struct nvm_addr *nvm_lookup_ltop(struct nvmd *nvmd, sector_t l_addr)
{
	return nvm_lookup_ltop_map(nvmd, l_addr, nvmd->trans_map, NULL);
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for
 * the next write to the disk.
 *
 * Returns nvm_addr with the physical address and block. Remember to return to
 * nvmd->addr_cache when request is finished.
 */
struct nvm_addr *nvm_map_ltop_rr(struct nvmd *nvmd, sector_t l_addr, int is_gc,
				 struct nvm_addr *trans_map, void *private)
{
	struct nvm_ap *ap;
	struct nvm_addr *p;
	int i = 0;


	if (!is_gc) {
		ap = get_next_ap(nvmd);
	} else {
		/* during GC, we don't care about RR, instead we want to make
		 * sure that we maintain evenness between the block pools. */
		unsigned int i;
		struct nvm_pool *pool, *max_free;

		max_free = &nvmd->pools[0];
		/* prevent GC-ing pool from devouring pages of a pool with
		 * little free blocks. We don't take the lock as we only need an
		 * estimate. */
		nvm_for_each_pool(nvmd, pool, i) {
			if (pool->nr_free_blocks > max_free->nr_free_blocks)
				max_free = pool;
		}

		ap = &nvmd->aps[max_free->id];
	}

	spin_lock(&ap->lock);
	p = nvm_alloc_addr_from_ap(ap, is_gc);
	spin_unlock(&ap->lock);

	if (p)
		nvm_update_map(nvmd, l_addr, p, is_gc, trans_map);

	return p;
}

static void nvm_endio(struct request *rq, int err)
{
	struct per_rq_data *pb;
	struct nvmd *nvmd;
	struct nvm_ap *ap;
	struct nvm_pool *pool;
	struct nvm_addr *p;
	struct nvm_block *block;
	struct timespec end_tv, diff_tv;
	unsigned long diff, dev_wait, total_wait = 0;
	unsigned int data_cnt;

	pb = get_per_rq_data(rq);
	p = pb->addr;
	block = p->block;
	ap = pb->ap;
	nvmd = ap->parent;
	pool = ap->pool;

	nvm_unlock_addr(nvmd, pb->l_addr);

	if (rq_data_dir(rq) == WRITE) {
		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == nvmd->nr_host_pages_in_blk) {
			mempool_free(block->data, nvmd->block_page_pool);
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


	if (nvmd->type->endio)
		nvmd->type->endio(nvmd, rq, pb, &dev_wait);

	if (!(nvmd->config.flags & NVM_OPT_NO_WAITS) && dev_wait) {
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

	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE) {
		/* we need this. updating pool current only by waiting_bios
		 * worker leaves a windows where current is bio thats was
		 * already ended */
		spin_lock(&pool->waiting_lock);
		pool->cur_bio = NULL;
		spin_unlock(&pool->waiting_lock);

		queue_work(nvmd->kbiod_wq, &pool->waiting_ws);
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

	mempool_free(pb->addr, nvmd->addr_pool);
free_pb:
	free_pbd(nvmd, pb);
}

static void nvm_end_write_rq(struct request *rq, int err)
{
	/* FIXME: Implement error handling of writes */
	nvm_endio(bio, err);

	/* separate bio is allocated on write. Remember to free it */
	bio_put(bio);
}

static void nvm_rq_zero_end(struct request *rq)
{
	/* TODO: fill rq with zeroes */
	blk_mq_complete_request(rq);
}

/* remember to lock l_add before calling nvm_submit_rq */
void nvm_submit_rq(struct nvmd *nvmd, struct nvm_addr *p, sector_t l_addr,
			int rw, struct bio *bio,
			struct bio *orig_bio,
			struct completion *sync,
			struct nvm_addr *trans_map)
{
	struct nvm_block *block = p->block;
	struct nvm_ap *ap = block_to_ap(nvmd, block);
	struct nvm_pool *pool = ap->pool;
	struct per_rq_data *pb;

	pb = get_per_rq_data(nvmd->nvq, rq);
	pb->ap = ap;
	pb->addr = p;
	pb->l_addr = l_addr;
	pb->event = sync;
	pb->orig_bio = orig_bio;
	pb->trans_map = trans_map;

	if (blk_rq_dir(rq) == WRITE)
		bio->bi_end_io = nvm_end_write_bio;
	else
		bio->bi_end_io = nvm_end_read_bio;

	/* We allow counting to be semi-accurate as theres
	 * no lock for accounting. */
	ap->io_accesses[rq_data_dir(rq)]++;

/*	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE) {
		spin_lock(&pool->waiting_lock);
		nvmd->type->bio_wait_add(&pool->waiting_bios, bio, p->private);

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
		queue_work(nvmd->kbiod_wq, &pool->waiting_ws);
		spin_unlock(&pool->waiting_lock);
		return;
	}*/ 

	submit_bio(bio->bi_rw, bio);
}
int nvm_read_rq(struct nvmd *nvmd, struct request *rq)
{
	struct nvm_addr *p;
	sector_t l_addr;

	l_addr = blk_rq_pos(rq) / NR_PHY_IN_LOG;

	nvm_lock_addr(nvmd, l_addr);

	p = nvmd->type->lookup_ltop(nvmd, l_addr);

	if (!p) {
		nvm_unlock_addr(nvmd, l_addr);
		nvm_gc_kick(nvmd);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	rq->sector = p->addr * NR_PHY_IN_LOG +
					(blk_rq_sectors(rq) % NR_PHY_IN_LOG);

	if (!p->block) {
		rq->sector = 0;
		nvm_rq_zero_end(rq);
		mempool_free(p, nvmd->addr_pool);
		nvm_unlock_addr(nvmd, l_addr);
		goto finished;
	}

	nvm_submit_rq(nvmd, p, l_addr, READ, bio, NULL, NULL, nvmd->trans_map);
finished:
	return BLK_MQ_RQ_QUEUE_OK;
}

struct bio *nvm_write_init_bio(struct nvmd *nvmd, struct request *rq,
						struct nvm_addr *p)
{
	struct request *rq;
	int i, size;

	rq = blk_mq_alloc_request(nvmd->q);
	if (!rq)
		return BLK_MQ_RQ_QUEUE_ERROR;

	rq->sector = p->addr * NR_PHY_IN_LOG;

	size = nvm_bv_copy(p, bio_iovec(bio));
	for (i = 0; i < NR_HOST_PAGES_IN_FLASH_PAGE; i++) {
		unsigned int idx = size - NR_HOST_PAGES_IN_FLASH_PAGE + i;
		bio_add_page(issue_bio, &p->block->data[idx], PAGE_SIZE, 0);
	}
	return issue_bio;
}

/* Assumes that l_addr is locked with nvm_lock_addr() */
int nvm_write_rq(struct nvmd *nvmd,
		  struct request *rq, int is_gc,
		  void *private, struct completion *sync,
		  struct nvm_addr *trans_map, unsigned int complete_bio)
{
	struct nvm_addr *p;
	struct bio *issue_bio;
	sector_t l_addr = blk_rq_sectors(rq) / NR_PHY_IN_LOG;

	p = nvmd->type->map_ltop(nvmd, l_addr, is_gc, trans_map, private);
	if (!p) {
		BUG_ON(is_gc);
		nvm_unlock_addr(nvmd, l_addr);
		nvm_gc_kick(nvmd);

		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	issue_bio = nvm_write_init_bio(nvmd, bio, p);
	if (complete_bio)
		nvm_submit_rq(nvmd, p, l_addr, WRITE, issue_bio, bio, sync,
								trans_map);
	else
		nvm_submit_rq(nvmd, p, l_addr, WRITE, issue_bio, NULL, sync,
								trans_map);

	return BLK_MQ_RQ_QUEUE_OK;
}

void nvm_rq_wait_add(struct bio_list *bl, struct bio *bio, void *p_private)
{
	bio_list_add(bl, bio);
}

