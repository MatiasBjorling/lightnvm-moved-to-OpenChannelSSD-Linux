#include "lightnvm.h"
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/time.h>
#include <linux/percpu_ida.h>

static void show_pool(struct nvm_pool *pool)
{
	struct list_head *head, *cur;
	unsigned int free_cnt = 0, used_cnt = 0, prio_cnt = 0;

	spin_lock(&pool->lock);
	list_for_each_safe(head, cur, &pool->free_list)
		free_cnt++;
	list_for_each_safe(head, cur, &pool->used_list)
		used_cnt++;
	list_for_each_safe(head, cur, &pool->prio_list)
		prio_cnt++;
	spin_unlock(&pool->lock);

	DMERR("Pool %d info %u %u %u", pool->id,
			free_cnt, used_cnt, prio_cnt);
}

static void show_all_pools(struct nvmd *nvmd)
{
	struct nvm_pool *pool;
	unsigned int i;

	nvm_for_each_pool(nvmd, pool, i)
		show_pool(pool);
}

static struct per_bio_data *alloc_decorate_per_bio_data(struct nvmd *nvmd, struct bio *bio)
{
	struct per_bio_data *pb = mempool_alloc(nvmd->per_bio_pool, GFP_NOIO);

	if (!pb) {
		DMERR("Couldn't allocate per_bio_data");
		return NULL;
	}

	pb->bi_end_io = bio->bi_end_io;
	pb->bi_private = bio->bi_private;

	bio->bi_private = pb;

	return pb;
}

static void dedecorate_bio(struct per_bio_data *pb, struct bio *bio)
{
	bio->bi_private = pb->bi_private;
	bio->bi_end_io = pb->bi_end_io;
}

static void free_per_bio_data(struct nvmd *nvmd, struct per_bio_data *pb)
{
	mempool_free(pb, nvmd->per_bio_pool);
}

/* deferred bios are used when no available nvm pages. Allowing GC to execute
 * and resubmit bios */
void nvm_defer_bio(struct nvmd *nvmd, struct bio *bio, void *private)
{
	spin_lock(&nvmd->deferred_lock);
	bio_list_add(&nvmd->deferred_bios, bio);
	spin_unlock(&nvmd->deferred_lock);
}

void nvm_deferred_bio_submit(struct work_struct *work)
{
	struct nvmd *nvmd = container_of(work, struct nvmd, deferred_ws);
	struct bio *bio;

	spin_lock(&nvmd->deferred_lock);
	bio = bio_list_get(&nvmd->deferred_bios);
	spin_unlock(&nvmd->deferred_lock);

	while (bio) {
		struct bio *next = bio->bi_next;
		bio->bi_next = NULL;
		if (bio_data_dir(bio) == WRITE)
			nvmd->type->write_bio(nvmd, bio);
		else
			nvmd->type->read_bio(nvmd, bio);
		bio = next;
	}
}

/* delayed bios are used for making pool accesses sequential */
void nvm_delayed_bio_submit(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, waiting_ws);
	struct bio *bio;
	struct per_bio_data *pb;

	spin_lock(&pool->waiting_lock);
	bio = bio_list_pop(&pool->waiting_bios);

	pool->cur_bio = bio;
	if (!bio) {
		atomic_dec(&pool->is_active);
		spin_unlock(&pool->waiting_lock);
		return;
	}

	spin_unlock(&pool->waiting_lock);

	/* setup timings to track end timings accordently */
	pb = bio->bi_private;
	getnstimeofday(&pb->start_tv);

	submit_bio(bio->bi_rw, bio);
}

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

int nvm_update_map(struct nvmd *nvmd, sector_t l_addr, struct nvm_addr *p,
					int is_gc, struct nvm_addr *trans_map)
{
	struct nvm_addr *gp;
	struct nvm_rev_addr *rev;

	BUG_ON(l_addr >= nvmd->nr_pages);
	BUG_ON(p->addr >= nvmd->nr_pages);

	spin_lock(&nvmd->trans_lock);
	gp = &trans_map[l_addr];

	if (gp->block) {
		invalidate_block_page(nvmd, gp);
		nvmd->rev_trans_map[gp->addr].addr = LTOP_POISON;
	}

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &nvmd->rev_trans_map[p->addr];
	rev->addr = l_addr;
	rev->trans_map = trans_map;
	spin_unlock(&nvmd->trans_lock);

	return 0;
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
	kref_init(&block->ref_count);
	spin_unlock(&block->lock);
}

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append point, we store it within the used_list.
 * We then move it back when its free to be used by another append point.
 *
 * The newly acclaimed block is always added to the back of user_list. As we assume
 * that the start of used list is the oldest block, and therefore higher probability
 * of invalidated pages.
 */
struct nvm_block *nvm_pool_get_block(struct nvm_pool *pool, int is_gc) {
	struct nvmd *nvmd = pool->nvmd;
	struct nvm_block *block = NULL;

	BUG_ON(!pool);

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		DMERR_LIMIT("Pool have no free pages available");
		spin_unlock(&pool->lock);
		show_pool(pool);
		return NULL;
	}

	while(!is_gc && pool->nr_free_blocks <= nvmd->nr_pools * 2) {
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
 * free list. We add it last to allow round-robin use of all pages. Thereby provide
 * simple (naive) wear-leveling.
 */
void nvm_pool_put_block(struct nvm_block *block)
{
	struct nvm_pool *pool = block->pool;

	spin_lock(&pool->lock);

	list_move_tail(&block->list, &pool->free_list);
	pool->nr_free_blocks++;
	pool->nr_gc_blocks--;

	spin_unlock(&pool->lock);

}

static sector_t __nvm_alloc_phys_addr(struct nvm_block *block, int req_fast)
{
	struct nvmd *nvmd;
	sector_t addr = LTOP_EMPTY;

	BUG_ON(!block);

	nvmd = block->pool->nvmd;

	spin_lock(&block->lock);

	if (block_is_full(block)){
		goto out;
	}

	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		if (req_fast && !page_is_fast(nvmd, block->next_page + 1))
			goto out;

		block->next_offset = 0;
		block->next_page++;
	}

	addr = block_to_addr(block) +
	       (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) + block->next_offset;
	block->next_offset++;

	if (nvmd->type->alloc_phys_addr)
		nvmd->type->alloc_phys_addr(nvmd, block);
out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t nvm_alloc_phys_addr(struct nvm_block *block)
{
	return __nvm_alloc_phys_addr(block, 0);
}

struct nvm_addr *nvm_alloc_phys_fastest_addr(struct nvmd *nvmd)
{
	struct nvm_ap *ap;
	struct nvm_addr *p;
	struct nvm_block *block = NULL;
	sector_t p_addr = LTOP_EMPTY;
	int i;

	p = mempool_alloc(nvmd->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;
	memset(p, 0, sizeof(struct nvm_addr));

	for (i = 0; i < nvmd->nr_pools; i++) {
		ap = get_next_ap(nvmd);
		block = ap->cur;

		p_addr = __nvm_alloc_phys_addr(block, 1);

		if (p_addr != LTOP_EMPTY)
			break;
	}

	if (p_addr == LTOP_EMPTY) {
		mempool_free(p, nvmd->per_bio_pool);
		return NULL;
	}

	p->addr = p_addr;
	p->block = block;
	return p;
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

struct nvm_rev_addr *nvm_lookup_ptol(struct nvmd *nvmd, sector_t p_addr)
{
	struct nvm_rev_addr *rev;
	spin_lock(&nvmd->trans_lock);
	rev = &nvmd->rev_trans_map[p_addr];
	spin_unlock(&nvmd->trans_lock);
	return rev;
}

/* requires ap->lock held */
struct nvm_addr *nvm_alloc_addr_from_ap(struct nvm_ap *ap, int is_gc)
{
	struct nvmd *nvmd = ap->parent;
	struct nvm_block *p_block;
	struct nvm_pool *pool;
	struct nvm_addr *p;
	sector_t p_addr = LTOP_EMPTY;

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

static void nvm_fill_bio_and_end(struct bio *bio)
{
	zero_fill_bio(bio);
	bio_endio(bio, 0);
}

struct nvm_addr *nvm_lookup_ltop_map(struct nvmd *nvmd, sector_t l_addr,
				     struct nvm_addr *map, void *private)
{
	struct nvm_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < nvmd->nr_pages));

	p = mempool_alloc(nvmd->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	spin_lock(&nvmd->trans_lock);
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

		if (!kref_get_unless_zero(&p->block->ref_count))
			goto err;
	}

	p->private = private;

	spin_unlock(&nvmd->trans_lock);
	return p;
err:
	spin_unlock(&nvmd->trans_lock);
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
 * Retrieve the mapping using the active append point. Then update the ap for the
 * next write to the disk.
 *
 * Returns nvm_addr with the physical address and block. Remember to return to
 * nvmd->addr_cache when bio is finished.
 */
struct nvm_addr *nvm_map_ltop_rr(struct nvmd *nvmd, sector_t l_addr, int is_gc,
				 struct nvm_addr *trans_map, void *private)
{
	struct nvm_ap *ap;
	struct nvm_addr *p;
	int ret, i = 0;

	ap = get_next_ap(nvmd);

	if (is_gc) {
		/* prevent GC-ing pool from devouring pages of pool with little free blocks*/
		spin_lock(&ap->pool->lock);
		while(ap->pool->nr_free_blocks <= nvmd->nr_pools * 2 &&
						ap->pool->id != (is_gc-1)) {
			spin_unlock(&ap->pool->lock);

			i++;
			if (i == nvmd->nr_pools * 2) {
				DMERR("Pool %d has to write GC data to pool %d"
						"which is too low on free pages",
							is_gc-1, ap->pool->id);
				spin_lock(&ap->pool->lock);
				break;
			}

			ap = get_next_ap(nvmd);
			spin_lock(&ap->pool->lock);
		}
		spin_unlock(&ap->pool->lock);
	}
	spin_lock(&ap->lock);
	p = nvm_alloc_addr_from_ap(ap, is_gc);
	spin_unlock(&ap->lock);

	if (p) {
		ret = nvm_update_map(nvmd, l_addr, p, is_gc, trans_map);

		if (ret) {
			DMERR("Cant update map");
			BUG_ON(!is_gc);

			invalidate_block_page(nvmd, p);

			return (struct nvm_addr *)LTOP_POISON;
		}
	}

	return p;
}

static void nvm_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb;
	struct nvmd *nvmd;
	struct nvm_ap *ap;
	struct nvm_pool *pool;
	struct nvm_addr *p;
	struct nvm_block *block;
	struct timespec end_tv, diff_tv;
	unsigned long diff, dev_wait, total_wait = 0;
	unsigned int data_cnt;

	pb = get_per_bio_data(bio);
	p = pb->addr;
	block = p->block;
	ap = pb->ap;
	nvmd = ap->parent;
	pool = ap->pool;

	if (bio_data_dir(bio) == WRITE) {
		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == nvmd->nr_host_pages_in_blk) {
			mempool_free(block->data, nvmd->block_page_pool);
			block->data = NULL;

			spin_lock(&pool->gc_lock);
			list_add_tail(&block->prio, &pool->prio_list);
			spin_unlock(&pool->gc_lock);
		}
		
		nvm_unlock_addr(nvmd, nvmd->type->get_inflight(nvmd, pb->trans_map), pb->l_addr);

		/* physical waits if hardware doesn't have a real backend */
		dev_wait = ap->t_write;
	} else {
		dev_wait = ap->t_read;
		spin_lock(&nvmd->trans_lock);
		kref_put(&block->ref_count, nvm_block_release);
		spin_unlock(&nvmd->trans_lock);
	}

	if (nvmd->type->endio)
		nvmd->type->endio(nvmd, bio, pb, &dev_wait);

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
		/* we need this. updating pool current only by waiting_bios worker
		   leaves a windows where current is bio thats was already ended */ 
		spin_lock(&pool->waiting_lock);
		pool->cur_bio = NULL;
		spin_unlock(&pool->waiting_lock);

		queue_work(pool->kbiod_wq, &pool->waiting_ws);
	}


	/* Finish up */
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->orig_bio){
		bio_endio(pb->orig_bio, err);
	}

	if (pb->event) {
		complete(pb->event);
		/* all submitted bios allocate their own addr, except GC reads*/
		if (bio_data_dir(bio) == READ)
			goto free_pb;
	}

	mempool_free(pb->addr, nvmd->addr_pool);
free_pb:
	free_per_bio_data(nvmd, pb);
}

static void nvm_end_read_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of reads
	 * Remember that bio->bi_end_io is overwritten during bio_split()
	 */
	nvm_endio(bio, err);
}

static void nvm_end_write_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of writes */
	nvm_endio(bio, err);

	/* separate bio is allocated on write. Remember to free it */
	bio_put(bio);
}

int nvm_read_bio(struct nvmd *nvmd, struct bio *bio)
{
	struct nvm_addr *p;
	sector_t l_addr;

	l_addr = bio->bi_sector / NR_PHY_IN_LOG;

	p = nvmd->type->lookup_ltop(nvmd, l_addr);

	if (!p) {
		nvm_defer_bio(nvmd, bio, NULL);
		nvm_gc_kick(nvmd);
		goto finished;
	}

	bio->bi_sector = p->addr * NR_PHY_IN_LOG +
					(bio->bi_sector % NR_PHY_IN_LOG);

	if (!p->block) {
		bio->bi_sector = 0;
		nvm_fill_bio_and_end(bio);
		mempool_free(p, nvmd->addr_pool);
		goto finished;
	}

	nvm_submit_bio(nvmd, p, l_addr, READ, bio, NULL, NULL, NULL);
finished:
	return DM_MAPIO_SUBMITTED;
}

int nvm_bv_copy(struct nvm_addr *p, struct bio_vec *bv)
{
	struct nvmd *nvmd = p->block->pool->nvmd;
	sector_t p_addr = p->addr;
	struct nvm_block *block = p->block;
	unsigned int idx;
	void *src_p, *dst_p;

	idx = p_addr % nvmd->nr_host_pages_in_blk;
	src_p = kmap_atomic(bv->bv_page);
	dst_p = kmap_atomic(&block->data[idx]);
	memcpy(dst_p, src_p, bv->bv_len);

	kunmap_atomic(dst_p);
	kunmap_atomic(src_p);

	return atomic_inc_return(&block->data_size);
}

struct bio *nvm_write_init_bio(struct nvmd *nvmd, struct bio *bio,
						struct nvm_addr *p)
{
	struct bio *issue_bio;
	int i, size;

	/* FIXME */
	issue_bio = bio_alloc(GFP_NOIO, NR_HOST_PAGES_IN_FLASH_PAGE);
	issue_bio->bi_bdev = nvmd->dev->bdev;
	issue_bio->bi_sector = p->addr * NR_PHY_IN_LOG;

	size = nvm_bv_copy(p, bio_iovec(bio));
	for (i = 0; i < NR_HOST_PAGES_IN_FLASH_PAGE; i++) {
		unsigned int idx = size - NR_HOST_PAGES_IN_FLASH_PAGE + i;
		bio_add_page(issue_bio, &p->block->data[idx], PAGE_SIZE, 0);
	}
	return issue_bio;
}

int nvm_write_execute_bio(struct nvmd *nvmd, struct bio *bio, int is_gc,
		void *private, struct completion *sync,
		struct nvm_addr *trans_map, unsigned int complete_bio)
{
	struct nvm_addr *p;
	struct bio *issue_bio;
	sector_t l_addr;

	l_addr = bio->bi_sector / NR_PHY_IN_LOG;

	p = nvmd->type->map_ltop(nvmd, l_addr, is_gc, trans_map, private);

	if (p) {
		if ((unsigned long)p == LTOP_POISON) {
			BUG_ON(!is_gc);
			DMERR("GC write might overwrite ongoing regular write to same l_addr. abort");
			if(sync)
				complete(sync);
			return NVM_WRITE_GC_ABORT;
		}

		nvm_lock_addr(nvmd, nvmd->type->get_inflight(nvmd, trans_map), l_addr);

		issue_bio = nvm_write_init_bio(nvmd, bio, p);
		if (complete_bio)
			nvm_submit_bio(nvmd, p, l_addr, WRITE, issue_bio, bio,
									sync, trans_map);
		else
			nvm_submit_bio(nvmd, p, l_addr, WRITE, issue_bio, NULL,
									sync, trans_map);
	} else {
		BUG_ON(is_gc);
		nvmd->type->defer_bio(nvmd, bio, trans_map);
		nvm_gc_kick(nvmd);

		return NVM_WRITE_DEFERRED;
	}

	return NVM_WRITE_SUCCESS;
}

int nvm_write_bio(struct nvmd *nvmd, struct bio *bio)
{
	nvm_write_execute_bio(nvmd, bio, 0, NULL, NULL, nvmd->trans_map, 1);
	return DM_MAPIO_SUBMITTED;
}

void nvm_bio_wait_add(struct bio_list *bl, struct bio *bio, void *p_private)
{
	bio_list_add(bl, bio);
}

struct nvm_inflight* nvm_get_inflight(struct nvmd *nvmd, struct nvm_addr *trans_map) 
{
	BUG_ON(trans_map != nvmd->trans_map);
	return nvmd->inflight;
}

void nvm_submit_bio(struct nvmd *nvmd, struct nvm_addr *p, sector_t l_addr,
			int rw, struct bio *bio,
			struct bio *orig_bio, 
			struct completion *sync,
			struct nvm_addr *trans_map)
{
	struct nvm_block *block = p->block;
	struct nvm_ap *ap = block_to_ap(nvmd, block);
	struct nvm_pool *pool = ap->pool;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(nvmd, bio);
	pb->ap = ap;
	pb->addr = p;
	pb->l_addr = l_addr;
	pb->event = sync;
	pb->orig_bio = orig_bio;
	pb->trans_map = trans_map;

	/* is set prematurely because we need it if bio is defered */
	bio->bi_rw |= rw;
	if (sync)
		bio->bi_rw |= REQ_SYNC;

	if (rw == WRITE)
		bio->bi_end_io = nvm_end_write_bio;
	else
		bio->bi_end_io = nvm_end_read_bio;

	/* We allow counting to be semi-accurate as theres
	 * no lock for accounting. */
	ap->io_accesses[bio_data_dir(bio)]++;

	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE) {
		spin_lock(&pool->waiting_lock);
		nvmd->type->bio_wait_add(&pool->waiting_bios, bio, p->private);

		if (atomic_inc_return(&pool->is_active) != 1) {
			atomic_dec(&pool->is_active);
			spin_unlock(&pool->waiting_lock);
			return;
		}

		bio = bio_list_peek(&pool->waiting_bios);

		/* we're not the only bio waiting */
		if (!bio) {
			atomic_dec(&pool->is_active);
			spin_unlock(&pool->waiting_lock);
			return;
		}

		/* we're the only bio waiting. queue relevant worker*/
		queue_work(pool->kbiod_wq, &pool->waiting_ws);
		spin_unlock(&pool->waiting_lock);
		return;
	}

	submit_bio(bio->bi_rw, bio);
}
