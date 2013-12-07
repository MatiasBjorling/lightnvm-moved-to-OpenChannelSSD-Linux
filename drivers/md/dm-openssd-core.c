#include "dm-openssd.h"

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
		nvmd->write_bio(nvmd, bio);
		bio = next;
	}
}

void __nvm_submit_bio(struct bio *bio);

void nvm_delayed_bio_submit(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, waiting_ws);
	struct bio *bio;

	spin_lock(&pool->waiting_lock);
	bio = bio_list_pop(&pool->waiting_bios);
	spin_unlock(&pool->waiting_lock);

	__nvm_submit_bio(bio);
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

struct nvm_addr *nvm_update_map(struct nvmd *nvmd, sector_t l_addr,
				    sector_t p_addr, struct nvm_block *p_block)
{
	struct nvm_addr *p;

	BUG_ON(l_addr >= nvmd->nr_pages);
	BUG_ON(p_addr >= nvmd->nr_pages);

	spin_lock(&nvmd->trans_lock);
	p = &nvmd->trans_map[l_addr];

	while (atomic_inc_return(&p->inflight) != 1) {
		atomic_dec(&p->inflight);
		DMERR("w");
		udelay(100);
	}

	if (p->block)
		invalidate_block_page(nvmd, p);

	p->addr = p_addr;
	p->block = p_block;

	nvmd->rev_trans_map[p_addr] = l_addr;
	spin_unlock(&nvmd->trans_lock);

	return p;
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
	struct list_head *head, *i;
	unsigned int free_cnt = 0, used_cnt = 0, prio_cnt = 0;

	BUG_ON(!pool);

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		list_for_each_safe(head, i, &pool->free_list)
			free_cnt++;
		list_for_each_safe(head, i, &pool->used_list)
			used_cnt++;
		list_for_each_safe(head, i, &pool->prio_list)
			prio_cnt++;

		spin_unlock(&pool->lock);
		DMERR_LIMIT("Pool have no free pages available %u %u %u %p",
				free_cnt, used_cnt, prio_cnt, pool);
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

	if (block_is_full(block))
		goto out;

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

sector_t nvm_alloc_phys_fastest_addr(struct nvmd *nvmd, struct
                nvm_block **ret_victim_block)
{
	struct nvm_ap *ap;
	struct nvm_block *block = NULL;
	sector_t addr = LTOP_EMPTY;
	int i;

	for (i = 0; i < nvmd->nr_pools; i++) {
		ap = get_next_ap(nvmd);
		block = ap->cur;

		addr = __nvm_alloc_phys_addr(block, 1);

		if (addr != LTOP_EMPTY)
			break;
	}

	if (addr == LTOP_EMPTY)
		return LTOP_EMPTY;

	(*ret_victim_block) = block;
	return addr;
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

sector_t nvm_lookup_ptol(struct nvmd *nvmd, sector_t physical_addr)
{
	sector_t addr;
	spin_lock(&nvmd->trans_lock);
	addr = nvmd->rev_trans_map[physical_addr];
	spin_unlock(&nvmd->trans_lock);
	return addr;
}

sector_t nvm_alloc_addr_from_ap(struct nvm_ap *ap,
				struct nvm_block **ret_victim_block, int is_gc)
{
	struct nvm_block *block;
	struct nvm_pool *pool;
	sector_t p_addr;

	spin_lock(&ap->lock);

	block = ap->cur;
	pool = block->pool;
	p_addr = nvm_alloc_phys_addr(block);

	if (p_addr == LTOP_EMPTY) {
		block = nvm_pool_get_block(pool, 0);

		if (!block) {
			if (is_gc) {
				p_addr = nvm_alloc_phys_addr(ap->gc_cur);
				if (p_addr == LTOP_EMPTY) {
					block = nvm_pool_get_block(pool, 1);
					if (!block) {
						DMERR("No more blocks");
						BUG_ON(1);
					}
					ap->gc_cur = block;
					ap->gc_cur->ap = ap;
					p_addr =
						nvm_alloc_phys_addr(ap->gc_cur);
				}
				*ret_victim_block = ap->gc_cur;
				BUG_ON(!ap->gc_cur);
			}
			goto finished;
		}

		nvm_set_ap_cur(ap, block);
		p_addr = nvm_alloc_phys_addr(block);
	}
	*ret_victim_block = block;
finished:
	spin_unlock(&ap->lock);

	return p_addr;
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
						struct nvm_addr *l2p_map)
{
	struct nvm_addr *addr;

	BUG_ON(!(l_addr >= 0 && l_addr < nvmd->nr_pages));

	while (1) {
		spin_lock(&nvmd->trans_lock);
		addr = &l2p_map[l_addr];
		spin_unlock(&nvmd->trans_lock);

		if (!addr->block)
			return addr;

		/* during gc, the mapping will be updated accordently. We
		 * therefore stop submitting new reads to the address, until it
		 * is copied to the new place. */
		if (!atomic_read(&addr->block->gc_running))
			return addr;

		schedule();
	}
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
 * Returns the physical mapped address.
 */
sector_t nvm_alloc_ltop_rr(struct nvmd *nvmd, sector_t l_addr,
		struct nvm_block **block, int is_gc, void *private)
{
	struct nvm_ap *ap;
	sector_t p_addr;

	ap = get_next_ap(nvmd);

	p_addr = nvm_alloc_addr_from_ap(ap, block, is_gc);

	if (p_addr != LTOP_EMPTY)
		return p_addr;

	nvm_gc_kick(ap->pool);

	WARN_ON(is_gc);
	WARN_ON((*block));

	return LTOP_EMPTY;
}

struct nvm_addr *nvm_alloc_map_ltop_rr(struct nvmd *nvmd, sector_t l_addr,
					   int is_gc, void *private)
{
	struct nvm_addr *addr = NULL;
	struct nvm_block *block = NULL;
	sector_t p_addr;

	p_addr = nvm_alloc_ltop_rr(nvmd, l_addr, &block, is_gc, private);

	if (block)
		addr = nvm_update_map(nvmd, l_addr, p_addr, block);

	if (is_gc) {
		//printk("l: %llu b: %u\n", p_addr, block->id);
	}


	return addr;
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

	BUG_ON(pb->physical_addr == LTOP_EMPTY);

	p = pb->addr;
	block = p->block;
	ap = pb->ap;
	nvmd = ap->parent;
	pool = ap->pool;

	/* TODO: This can be optimized to only account on read */
	kref_put(&block->ref_count, nvm_block_release);

	if (bio_data_dir(bio) == WRITE) {
		/* mark addr landed (persisted) */
		atomic_dec(&p->inflight);

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

	spin_lock(&pool->waiting_lock);
	deferred_bio = bio_list_peek(&pool->waiting_bios);
	spin_unlock(&pool->waiting_lock);
	// Remember that the IO is first officially finished from here
	if (deferred_bio)
		queue_work(nvmd->kbiod_wq, &pool->waiting_ws);
	else
		atomic_dec(&pool->is_active);

	/* Finish up */
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->sync)
		complete(&pb->event);

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

struct nvm_addr *nvm_alloc_addr(struct nvmd *nvmd, sector_t l_addr,
				    int is_gc, void *private)
{
	return nvmd->map_ltop(nvmd, l_addr, is_gc, private);
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

	bio->bi_sector = p->addr * NR_PHY_IN_LOG +
					(bio->bi_sector % NR_PHY_IN_LOG);

	
	if (!p->block) {
		bio->bi_sector = 0;
		nvm_fill_bio_and_end(bio);
		return DM_MAPIO_SUBMITTED;
	}

	/* When physical page contains several logical pages, we may need to
	 * read from buffer. Check if so, and if page is cached in ap, read from
	 * there */
	if (NR_HOST_PAGES_IN_FLASH_PAGE > 1
				&& nvm_handle_buffered_read(nvmd, bio, p))
		return DM_MAPIO_SUBMITTED;

	//printk("phys_addr: %lu blockid %u bio addr: %lu bi_sectors: %u\n", phys->addr, phys->block->id, bio->bi_sector, bio_sectors(bio));
	nvm_submit_bio(nvmd, p, READ, bio, 0);

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

void nvm_defer_bio(struct nvmd *nvmd, struct bio *bio)
{
	spin_lock(&nvmd->deferred_lock);
	bio_list_add(&nvmd->deferred_bios, bio);
	spin_unlock(&nvmd->deferred_lock);
}

/* returns 0 if deferred */
void nvm_write_execute_bio(struct nvmd *nvmd, struct bio *bio, int is_gc,
		void *private)
{
	struct nvm_addr *p;
	struct bio *issue_bio;
	sector_t l_addr;

	l_addr = bio->bi_sector / NR_PHY_IN_LOG;
	p = nvm_alloc_addr(nvmd, l_addr, is_gc, private);

	if (p) {
		issue_bio = nvm_write_init_bio(nvmd, bio, p);
		nvm_submit_bio(nvmd, p, WRITE, issue_bio, is_gc);
		bio_endio(bio, 0);
	} else {
		BUG_ON(is_gc);
		nvm_defer_bio(nvmd, bio);
	}
}

int nvm_write_bio(struct nvmd *nvmd, struct bio *bio)
{
	nvm_write_execute_bio(nvmd, bio, 0, NULL);
	return DM_MAPIO_SUBMITTED;
}

void __nvm_submit_bio(struct bio *bio)
{
	int sync = bio->bi_rw & REQ_SYNC;
	if (sync) {
		struct per_bio_data *pb = get_per_bio_data(bio);
		init_completion(&pb->event);
		submit_bio(bio->bi_rw, bio);
		wait_for_completion_io(&pb->event);
	} else {
		submit_bio(bio->bi_rw, bio);
	}
}

void nvm_submit_bio(struct nvmd *nvmd, struct nvm_addr *p, int rw, struct bio *bio, int sync)
{
	struct nvm_ap *ap = block_to_ap(nvmd, p->block);
	struct nvm_pool *pool = ap->pool;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(nvmd, bio);
	pb->ap = ap;
	pb->addr = p;
	pb->physical_addr = bio->bi_sector;
	pb->sync = sync;

	/* is set prematurely because we need it for deferred bios */
	bio->bi_rw |= rw;
	if (sync)
		bio->bi_rw |= REQ_SYNC;

	/* setup timings - remember overhead. */
	getnstimeofday(&pb->start_tv);

	if (rw == WRITE)
		bio->bi_end_io = nvm_end_write_bio;
	else
		bio->bi_end_io = nvm_end_read_bio;

	kref_get(&p->block->ref_count);

	if (nvmd->config.flags & NVM_OPT_POOL_SERIALIZE
				&& atomic_inc_return(&pool->is_active) == 1) {
		__nvm_submit_bio(bio);
	} else {
		atomic_dec(&pool->is_active);
		spin_lock(&pool->waiting_lock);
		ap->io_delayed++;
		bio_list_add(&pool->waiting_bios, bio);
		spin_unlock(&pool->waiting_lock);
	}

	// We allow counting to be semi-accurate as theres no locking for accounting.
	ap->io_accesses[bio_data_dir(bio)]++;
}
