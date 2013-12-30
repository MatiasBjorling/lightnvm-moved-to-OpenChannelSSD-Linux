#include "dm-openssd.h"

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

	DMERR("Pool info %u %u %u %p",
			free_cnt, used_cnt, prio_cnt, pool);
}

static void show_all_pools(struct nvmd *nvmd)
{
	struct nvm_pool *pool;
	unsigned int i;

	ssd_for_each_pool(nvmd, pool, i) {
		show_pool(pool);
	}
}

static inline struct per_bio_data *get_per_bio_data(struct bio *bio)
{
	struct per_bio_data *pbd = bio->bi_private;
	return pbd;
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

void nvm_defer_bio(struct nvmd *nvmd, struct bio *bio)
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
			nvmd->write_bio(nvmd, bio);
		else
			nvmd->read_bio(nvmd, bio);
		bio = next;
	}
}

void __nvm_submit_bio(struct bio *bio, unsigned int sync);

void nvm_delayed_bio_submit(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, waiting_ws);
	struct bio *bio;
	unsigned int sync;

	spin_lock(&pool->waiting_lock);
	bio = bio_list_pop(&pool->waiting_bios);
	spin_unlock(&pool->waiting_lock);

	sync = bio->bi_rw & REQ_SYNC;
	__nvm_submit_bio(bio, sync);
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

void nvm_update_map(struct nvmd *nvmd, sector_t l_addr, struct nvm_addr *p)
{
	struct nvm_addr *gp;

	BUG_ON(l_addr >= nvmd->nr_pages);
	BUG_ON(p->addr >= nvmd->nr_pages);

	spin_lock(&nvmd->trans_lock);
	gp = &nvmd->trans_map[l_addr];

	while (atomic_inc_return(&gp->inflight) != 1) {
		atomic_dec(&gp->inflight);
		spin_unlock(&nvmd->trans_lock);
		schedule();
		spin_lock(&nvmd->trans_lock);
	}

	if (gp->block) {
		invalidate_block_page(nvmd, gp);
		nvmd->rev_trans_map[gp->addr] = LTOP_POISON;
	}


	gp->addr = p->addr;
	gp->block = p->block;

	nvmd->rev_trans_map[p->addr] = l_addr;
	spin_unlock(&nvmd->trans_lock);
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

	if (nvmd->alloc_phys_addr)
		nvmd->alloc_phys_addr(nvmd, block);
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
		if (!block_is_full(ap->cur))
			DMERR("Block isn't full - %u %u", ap->cur->next_page, ap->cur->next_offset);
		spin_unlock(&ap->cur->lock);
		ap->cur->ap = NULL;
	}
	ap->cur = block;
	ap->cur->ap = ap;
}

sector_t nvm_lookup_ptol(struct nvmd *nvmd, sector_t p_addr)
{
	sector_t l_addr;
	spin_lock(&nvmd->trans_lock);
	l_addr = nvmd->rev_trans_map[p_addr];
	spin_unlock(&nvmd->trans_lock);
	return l_addr;
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
						struct nvm_addr *map)
{
	struct nvm_addr *gp, *p;

	BUG_ON(!(l_addr >= 0 && l_addr < nvmd->nr_pages));

	p = mempool_alloc(nvmd->addr_pool, GFP_ATOMIC);
	if (!p)
		return NULL;

	spin_lock(&nvmd->trans_lock);
	gp = &map[l_addr];

	if (atomic_read(&gp->inflight) == 1)
		goto err;

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
	return nvm_lookup_ltop_map(nvmd, l_addr, nvmd->trans_map);
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
								void *private)
{
	struct nvm_ap *ap;
	struct nvm_addr *p;

	ap = get_next_ap(nvmd);

	spin_lock(&ap->lock);
	p = nvm_alloc_addr_from_ap(ap, is_gc);
	spin_unlock(&ap->lock);
	if (p != NULL){
		nvm_update_map(nvmd, l_addr, p);
	}

	return p;
}

static void nvm_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb;
	struct bio *deferred_bio;
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
		/* mark addr landed (persisted) */
		struct nvm_addr *gp = &nvmd->trans_map[pb->l_addr];
		atomic_dec(&gp->inflight);

		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == nvmd->nr_host_pages_in_blk) {
			mempool_free(block->data, nvmd->block_page_pool);
			block->data = NULL;

			spin_lock(&pool->gc_lock);
			list_add_tail(&block->prio, &pool->prio_list);
			spin_unlock(&pool->gc_lock);
		}

		/* physical waits if hardware doesn't have a real backend */
		dev_wait = ap->t_write;
	} else {
		dev_wait = ap->t_read;
		spin_lock(&nvmd->trans_lock);
		kref_put(&block->ref_count, nvm_block_release);
		spin_unlock(&nvmd->trans_lock);
	}

	nvm_delay_endio_hint(nvmd, bio, pb, &dev_wait);

	if (!(nvmd->config.flags & NVM_OPT_NO_WAITS) && dev_wait) {
		getnstimeofday(&end_tv);
		diff_tv = timespec_sub(end_tv, pb->start_tv);
		diff = timespec_to_ns(&diff_tv) / 1000;
		if (dev_wait > diff) {
			total_wait = dev_wait - diff;
			if (total_wait > 50)
				udelay(total_wait);
		}
	}

	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE) {
		spin_lock(&pool->waiting_lock);
		deferred_bio = bio_list_peek(&pool->waiting_bios);
		spin_unlock(&pool->waiting_lock);
		if (deferred_bio)
			queue_work(nvmd->kbiod_wq, &pool->waiting_ws);
		else
			atomic_dec(&pool->is_active);
	}

	/* Finish up */
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->orig_bio){
		bio_endio(pb->orig_bio, err);
	}

	if (pb->sync)
		complete(&pb->event);

	/* all submitted bios allocate their own addr, except GC reads*/
	if(!(pb->sync && bio_data_dir(bio) == READ)) 
		mempool_free(pb->addr, nvmd->addr_pool);

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

static int nvm_handle_buffered_read(struct nvmd *nvmd, struct bio *bio, struct nvm_addr *phys)
{
	struct nvm_ap *ap;
	struct nvm_block *block;
	struct bio_vec *bv;
	int i, j, pool_idx = phys->addr / (nvmd->nr_pages / nvmd->nr_pools);
	int data_idx = phys->addr % (nvmd->nr_host_pages_in_blk);
	void *src_p, *dst_p;
	sector_t addr;

	for (i = 0; i < nvmd->nr_aps_per_pool; i++) {
		ap = &nvmd->aps[(pool_idx * nvmd->nr_aps_per_pool) + i];
		block = ap->cur;
		addr = block_to_addr(block) + block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE;

		// if this is the first page in a the ap buffer
		if (addr == phys->addr) {
			bio_for_each_segment(bv, bio, j) {
				dst_p = kmap_atomic(bv->bv_page);
				src_p = kmap_atomic(&block->data[data_idx]);

				memcpy(dst_p, src_p, bv->bv_len);
				kunmap_atomic(dst_p);
				kunmap_atomic(src_p);
				break;
			}
			bio_endio(bio, 0);

			return 1;
		}
	}

	return 0;
}

int nvm_read_bio(struct nvmd *nvmd, struct bio *bio)
{
	struct nvm_addr *p;
	sector_t l_addr;

	l_addr = bio->bi_sector / NR_PHY_IN_LOG;
	p = nvmd->lookup_ltop(nvmd, l_addr);

	if (!p) {
		nvm_defer_bio(nvmd, bio);
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

	/* When physical page contains several logical pages, we may need to
	 * read from buffer. Check if so, and if page is cached in ap, read from
	 * there */
	if (NR_HOST_PAGES_IN_FLASH_PAGE > 1
				&& nvm_handle_buffered_read(nvmd, bio, p)) {
		mempool_free(p, nvmd->addr_pool);
		goto finished;
	}

	//printk("phys_addr: %lu blockid %u bio addr: %lu bi_sectors: %u\n", phys->addr, phys->block->id, bio->bi_sector, bio_sectors(bio));
	nvm_submit_bio(nvmd, p, l_addr, READ, bio, 0, NULL);
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

	//FIXME: can fail
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

void nvm_write_execute_bio(struct nvmd *nvmd, struct bio *bio, int is_gc,
		void *private)
{
	struct nvm_addr *p;
	struct bio *issue_bio;
	sector_t l_addr;

	l_addr = bio->bi_sector / NR_PHY_IN_LOG;
	p = nvmd->map_ltop(nvmd, l_addr, is_gc, private);

	if (p) {
		issue_bio = nvm_write_init_bio(nvmd, bio, p);
		nvm_submit_bio(nvmd, p, l_addr, WRITE, issue_bio, is_gc, bio);
	} else {
		BUG_ON(is_gc);
		nvm_defer_bio(nvmd, bio);
		nvm_gc_kick(nvmd);
	}
}

int nvm_write_bio(struct nvmd *nvmd, struct bio *bio)
{
	nvm_write_execute_bio(nvmd, bio, 0, NULL);
	return DM_MAPIO_SUBMITTED;
}

void __nvm_submit_bio(struct bio *bio, unsigned int sync)
{
	if (sync) {
		struct per_bio_data *pb = get_per_bio_data(bio);
		init_completion(&pb->event);
		submit_bio(bio->bi_rw, bio);
		wait_for_completion_io(&pb->event);
	} else {
		submit_bio(bio->bi_rw, bio);
	}
}

void nvm_submit_bio(struct nvmd *nvmd, struct nvm_addr *p, sector_t l_addr,
			int rw, struct bio *bio, int sync, struct bio *orig_bio)
{
	struct nvm_block *block = p->block;
	struct nvm_ap *ap = block_to_ap(nvmd, block);
	struct nvm_pool *pool = ap->pool;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(nvmd, bio);
	pb->ap = ap;
	pb->addr = p;
	pb->l_addr = l_addr;
	pb->sync = sync;
	pb->orig_bio = orig_bio;

	/* is set prematurely because we need it for deferred bios */
	bio->bi_rw |= rw;
	if (sync)
		bio->bi_rw |= REQ_SYNC;

	/* setup timings - remember overhead. */
	getnstimeofday(&pb->start_tv);

	if (rw == WRITE)
		bio->bi_end_io = nvm_end_write_bio;
	else {
		bio->bi_end_io = nvm_end_read_bio;
	}

	// We allow counting to be semi-accurate as theres no locking for accounting.
	ap->io_accesses[bio_data_dir(bio)]++;

	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE) {
		if (atomic_inc_return(&pool->is_active) != 1) {
			atomic_dec(&pool->is_active);
			spin_lock(&pool->waiting_lock);
			ap->io_delayed++;
			bio_list_add(&pool->waiting_bios, bio);
			spin_unlock(&pool->waiting_lock);
		}
		else
			__nvm_submit_bio(bio, sync);
	} else
		__nvm_submit_bio(bio, sync);

}
