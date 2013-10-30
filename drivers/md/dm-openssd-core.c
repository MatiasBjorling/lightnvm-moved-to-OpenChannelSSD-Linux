#include "dm-openssd.h"
#include "dm-openssd-hint.h"
#include <linux/percpu-refcount.h>

// TODO make inline?
static unsigned long diff_tv(struct timeval *curr_tv, struct timeval *ap_tv)
{
	if(curr_tv->tv_sec == ap_tv->tv_sec)
		return curr_tv->tv_usec - ap_tv->tv_usec;

	return (curr_tv->tv_sec - ap_tv->tv_sec -1) * 1000000 + (1000000-ap_tv->tv_usec) + curr_tv->tv_usec;
}

static inline struct per_bio_data *get_per_bio_data(struct bio *bio) {
	return (struct per_bio_data *) bio->bi_private;
}

static struct per_bio_data *alloc_decorate_per_bio_data(struct openssd *os, struct bio *bio) {
	struct per_bio_data *pb = mempool_alloc(os->per_bio_pool, GFP_NOIO);

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

static void free_per_bio_data(struct openssd *os, struct per_bio_data *pb)
{
	mempool_free(pb, os->per_bio_pool);
}

void openssd_delayed_bio_submit(struct work_struct *work)
{
	struct nvm_pool *pool = container_of(work, struct nvm_pool, waiting_ws);
	struct bio *bio;

	spin_lock(&pool->waiting_lock);
	bio = bio_list_pop(&pool->waiting_bios);
	spin_unlock(&pool->waiting_lock);

	generic_make_request(bio);
}

void openssd_update_map_generic(struct openssd *os,  sector_t l_addr,
                                sector_t p_addr, struct nvm_block *p_block)
{
	struct nvm_addr *l;
	unsigned int page_offset;

	if (l_addr >= os->nr_pages || p_addr >= os->nr_pages)
		return;

	BUG_ON(l_addr >= os->nr_pages);
	BUG_ON(p_addr >= os->nr_pages);

	l = &os->trans_map[l_addr];
	if (l->block) {
		page_offset = l->addr % (os->nr_host_pages_in_blk);
		if (test_and_set_bit(page_offset, l->block->invalid_pages))
			WARN_ON(true);
		l->block->nr_invalid_pages++;
	}

	l->addr = p_addr;
	l->block = p_block;

	os->rev_trans_map[p_addr] = l_addr;
}

/* requires pool->lock taken */
inline void openssd_reset_block(struct nvm_block *block)
{
	struct openssd *os = block->pool->os;
	unsigned int order = ffs(os->nr_host_pages_in_blk) - 1;

	BUG_ON(!block);

	spin_lock(&block->lock);

	if (block->data) {
		WARN_ON(!bitmap_full(block->invalid_pages, os->nr_host_pages_in_blk));
		bitmap_zero(block->invalid_pages, os->nr_host_pages_in_blk);
		__free_pages(block->data, order);
	}

	block->next_page = 0;
	block->next_offset = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->data_size, 0);
	atomic_set(&block->data_cmnt_size, 0);
	percpu_ref_init(&block->ref_count, openssd_block_release);
	block->parent_ap = NULL;
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
struct nvm_block *nvm_pool_get_block(struct nvm_pool *pool) {
	struct openssd *os = pool->os;
	struct nvm_block *block = NULL;
	struct page *data;
	unsigned int order = ffs(os->nr_host_pages_in_blk) - 1;

	data = alloc_pages(GFP_NOIO, order);

	if (!data)
		return NULL;

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		spin_unlock(&pool->lock);
		__free_pages(data, order);
		return NULL;
	}

	block = list_first_entry(&pool->free_list, struct nvm_block, list);
	list_move_tail(&block->list, &pool->used_list);

	DMINFO("dec nr_free_blocks");
	pool->nr_free_blocks--;

	spin_unlock(&pool->lock);

	block->data = data;

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

	openssd_reset_block(block);

	list_move_tail(&block->list, &pool->free_list);

	pool->nr_free_blocks++;
	spin_unlock(&pool->lock);
}

static sector_t __openssd_alloc_phys_addr(struct nvm_block *block,
                int req_fast)
{
	sector_t addr = LTOP_EMPTY;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;
	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		if (req_fast && !page_is_fast(block->next_page + 1))
			goto out;

		block->next_offset = 0;
		block->next_page++;
	}

	addr = block_to_addr(block) +
	       (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) + block->next_offset;
	block->next_offset++;

	/* pack ap's need an ap not related to any inode*/ 
	if (block_is_full(block)){
		DMDEBUG("__openssd_alloc_phys_addr - block is full. init ap_hint. block->parent_ap %p", block->parent_ap);
		BUG_ON(!block->parent_ap);
		if(block->parent_ap->hint_private)
			init_ap_hint(block->parent_ap);
		block->parent_ap = NULL;
	}
out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t openssd_alloc_phys_addr(struct nvm_block *block)
{
	return __openssd_alloc_phys_addr(block, 0);
}

sector_t openssd_alloc_phys_pack_addr(struct openssd *os, struct
		nvm_block **ret_victim_block, struct openssd_hint_map_private *map_alloc_data)
{
	struct nvm_ap *ap;
	sector_t addr = LTOP_EMPTY;
	struct openssd_ap_hint* ap_pack_data = NULL;
	struct timeval curr_tv;
	unsigned long diff;
	int i;

	/* find open ap for requested inode number*/
	for (i = 0, ap = &os->aps[0]; i < os->nr_pools; i++, ap = &os->aps[i]){
		/* not hint related */
		if(!ap->hint_private) 
			continue;
		ap_pack_data = (struct openssd_ap_hint*)ap->hint_private;

		/* got it */
		if(ap_pack_data->ino == map_alloc_data->hint_info->hint.ino){
			DMINFO("ap with block_addr %ld associated to requested inode %d", block_to_addr(ap->cur), ap_pack_data->ino);
			addr = openssd_alloc_addr_from_ap(ap, ret_victim_block);
			break;
		}
	}

	if (addr != LTOP_EMPTY){
		DMINFO("allocated addr %ld from PREVIOUS associated ap ", addr);
		goto pack_alloc_done;
	}

	/* no ap associated to requested inode.
	   find some empty pack ap, and use it*/
	DMDEBUG("no ap associated to inode %u", map_alloc_data->hint_info->hint.ino);
	for (i = 0; addr == LTOP_EMPTY && i < os->nr_pools; i++) {
		ap = get_next_ap(os);

		/* not hint associated */
		if(!ap->hint_private)
			continue;

		ap_pack_data = (struct openssd_ap_hint*)ap->hint_private;

		/* associated to an other inode */
		if(ap_pack_data->ino != INODE_EMPTY && 
		   ap_pack_data->ino != map_alloc_data->hint_info->hint.ino){
			/* check threshold and decide whether to replace associated inode */
			do_gettimeofday(&curr_tv);
			diff = diff_tv(&curr_tv, &ap_pack_data->tv);
			if(AP_DISASSOCIATE_TIME > diff)
				continue;
			DMINFO("ap association timeout expired");
			/* proceed to associate with some other inode*/			
		}

		/* got it - empty ap not associated to any inode */
		ap_pack_data->ino = map_alloc_data->hint_info->hint.ino; // do this before alloc_addr
		addr = openssd_alloc_addr_from_ap(ap, ret_victim_block);
		DMINFO("re-associated ap with block_addr %ld to new inode %d", block_to_addr(ap->cur), ap_pack_data->ino);

		break;
	}

	if (addr != LTOP_EMPTY){
		DMDEBUG("allocated addr %ld from NEW associated ap ", addr);
		goto pack_alloc_done;
	}

	DMDEBUG("no new/previous ap associated to inode. do regular allocation");
	/* haven't found any relevant/empty pack ap. resort to regular allocation
	   (from non-packed ap)*/
	/* TODO: overtake "regular" ap? return error? */
	do{
		ap = get_next_ap(os);
	}while(ap->hint_private);

	addr = openssd_alloc_addr_from_ap(ap, ret_victim_block);

pack_alloc_done:
	if(ap_pack_data)
		do_gettimeofday(&ap_pack_data->tv);
	return addr;
}


sector_t openssd_alloc_phys_fastest_addr(struct openssd *os, struct
                nvm_block **ret_victim_block)
{
	struct nvm_ap *ap;
	struct nvm_block *block = NULL;
	sector_t addr = LTOP_EMPTY;
	int i;

	for (i = 0; addr == LTOP_EMPTY && i < os->nr_pools; i++) {
		ap = get_next_ap(os);
		block = ap->cur;

		addr = __openssd_alloc_phys_addr(block, 1);
	}

	if (addr == LTOP_EMPTY)
		addr = openssd_alloc_phys_addr(block);

	(*ret_victim_block) = block;
	return addr;
}

void openssd_set_ap_cur(struct nvm_ap *ap, struct nvm_block *block)
{
	spin_lock(&ap->lock);
	if(ap->cur)
		ap->cur->parent_ap = NULL;
	ap->cur = block;
	ap->cur->parent_ap = ap;
	DMINFO("Set ap->cur with block in addr %ld", block_to_addr(block));
	spin_unlock(&ap->lock);
}

void openssd_print_total_blocks(struct openssd *os)
{
	struct nvm_pool *pool;
	unsigned int total = 0;
	int i;

	ssd_for_each_pool(os, pool, i)
	total += pool->nr_free_blocks;

	DMINFO("Total free blocks: %u", total);
}

sector_t openssd_lookup_ptol(struct openssd *os, sector_t physical_addr)
{
	return os->rev_trans_map[physical_addr];
}

sector_t openssd_alloc_addr_from_ap(struct nvm_ap *ap,
                                    struct nvm_block **ret_victim_block)
{
	struct nvm_block *block = ap->cur;
	sector_t p_addr;

	//DMINFO("openssd_alloc_addr_from_ap - call openssd_alloc_phys_addr");
	p_addr = openssd_alloc_phys_addr(block);
	DMINFO("openssd_alloc_addr_from_ap - got p_addr %ld", p_addr);

	while (p_addr == LTOP_EMPTY) {
		block = nvm_pool_get_block(block->pool);

		if (!block)
			return LTOP_EMPTY;

		openssd_set_ap_cur(ap, block);
		p_addr = openssd_alloc_phys_addr(block);
	}

	(*ret_victim_block) = block;

	return p_addr;
}

void openssd_erase_block(struct nvm_block *block)
{
	/* Send erase command to device. */
}



static void openssd_fill_bio_and_end(struct bio *bio)
{
	zero_fill_bio(bio);
	bio_endio(bio, 0);
}

/* lookup the primary translation table. If there isn't an associated block to
 * the addr. We shall assume that there is no data and doesn't take a ref */
struct nvm_addr *openssd_lookup_ltop(struct openssd *os, sector_t logical_addr) {
	// TODO: during GC or w-r-w we may get a translation for an old page.
	//       do we care enough to enforce some serializibilty in LBA accesses?
	struct nvm_addr *addr;

	while (1) {
		addr = &os->trans_map[logical_addr];

		if (!addr->block)
			return addr;

		/* during gc, the mapping will be updated accordently. We
		 * therefore stop submitting new reads to the address, until it
		 * is copied to the new place. */
		if (!spin_is_locked(&addr->block->gc_lock)) {
			openssd_get_block(addr->block);
			return addr;
		}

		schedule();
	}
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for the
 * next write to the disk.
 *
 * Returns the physical mapped address.
 */
sector_t openssd_alloc_ltop_rr(struct openssd *os, sector_t l_addr,
                               struct nvm_block **ret_victim_block, void *private)
{
	struct nvm_ap *ap;
	sector_t p_addr;

	ap = get_next_ap(os);

	p_addr = openssd_alloc_addr_from_ap(ap, ret_victim_block);

	if (p_addr != LTOP_EMPTY)
		DMDEBUG("l_addr=%ld new p_addr=%ld (blkid=%u)",
		        l_addr, p_addr, (*ret_victim_block)->id);

	return p_addr;
}

sector_t openssd_alloc_map_ltop_rr(struct openssd *os, sector_t l_addr,
                                   struct nvm_block **ret_victim_block, void *private)
{
	sector_t p_addr;

	p_addr = openssd_alloc_ltop_rr(os, l_addr, ret_victim_block, private);
	openssd_update_map_generic(os, l_addr, p_addr, (*ret_victim_block));

	return p_addr;
}

static void openssd_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb;
	struct openssd *os;
	struct nvm_ap *ap;
	struct nvm_pool *pool;
	struct nvm_block *block;
	struct timeval end_tv;
	unsigned long diff, dev_wait, total_wait = 0;

	pb = get_per_bio_data(bio);
	block = pb->block;
	ap = pb->ap;
	DMDEBUG("endio: starting. pb %p sync %p", pb, pb->sync);

	os = ap->parent;
	pool = ap->pool;
	/* TODO: This can be optimized to only account on read */
	openssd_put_block(block);

	if (pb->physical_addr == LTOP_EMPTY) {
		DMDEBUG("openssd_endio: no real IO performed. goto done");
		goto done;
	}

	if (bio_data_dir(bio) == WRITE)
		dev_wait = ap->t_write;
	else
		dev_wait = ap->t_read;

	openssd_delay_endio_hint(os, bio, pb, &dev_wait);

	if (dev_wait) {
		do_gettimeofday(&end_tv);
		diff = end_tv.tv_usec - pb->start_tv.tv_usec;
		if (dev_wait > diff)
			total_wait = dev_wait - diff;

		if (total_wait > 50)
			udelay(total_wait);
	}

	// Remember that the IO is first officially finished from here
	if (bio_list_peek(&pool->waiting_bios))
		queue_work(os->kbiod_wq, &pool->waiting_ws);
	else
		atomic_set(&pool->is_active, 0);

done:
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->sync)
		complete(&pb->event);

	free_per_bio_data(os, pb);
}

static void openssd_end_read_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of reads
	 * Remember that bio->bi_end_io is overwritten during bio_split()
	 */
	openssd_endio(bio, err);
}

static void openssd_end_write_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of writes */
	openssd_endio(bio, err);
}

sector_t openssd_alloc_addr_retries(struct openssd *os, sector_t logical_addr, struct nvm_block **victim_block, void *private)
{
	unsigned int retries;
	sector_t physical_addr = LTOP_EMPTY;

	for (retries = 0; retries < 3; retries++) {
		physical_addr = os->map_ltop(os, logical_addr, victim_block, private);

		if (physical_addr != LTOP_EMPTY)
			break;

		openssd_gc_collect(os);
	}

	return physical_addr;
}

static int openssd_handle_buffered_read(struct openssd *os, struct bio *bio, struct nvm_addr *phys)
{
	int i, j, pool_idx = phys->addr / (os->nr_pages / os->nr_pools);
	sector_t addr;
	void *src_p, *dst_p;
	struct nvm_ap *ap;
	struct bio_vec *bv;
	int idx = phys->addr % (os->nr_host_pages_in_blk);

	for (i = 0; i < os->nr_aps_per_pool; i++) {
		ap = &os->aps[(pool_idx * os->nr_aps_per_pool) + i];
		addr = block_to_addr(ap->cur) + ap->cur->next_page * NR_HOST_PAGES_IN_FLASH_PAGE;

		// if this is the first page in a the ap buffer
		if (addr == phys->addr) {
			printk("buffered data\n");
			bio_for_each_segment(bv, bio, j) {
				dst_p = kmap_atomic(bv->bv_page);
				src_p = kmap_atomic(&ap->cur->data[idx]);

				memcpy(dst_p, src_p, bv->bv_len);
				kunmap_atomic(dst_p);
				kunmap_atomic(src_p);
				break;
			}
			bio_endio(bio, 0);

			return 0;
		}
	}

	return 1;
}

int openssd_read_bio_generic(struct openssd *os, struct bio *bio)
{
	struct bio *exec_bio, *split_bio;
	struct bio_pair *bp;
	struct bio_vec *bv;
	struct nvm_addr *phys;
	sector_t l_addr;
	int i;

	if (bio_sectors(bio) > NR_PHY_IN_LOG) {
		split_bio = bio;
		bio_for_each_segment(bv, bio, i) {
			bp = bio_split(split_bio, NR_PHY_IN_LOG);

			exec_bio = &bp->bio1;
			split_bio = &bp->bio2;

			l_addr = exec_bio->bi_sector / NR_PHY_IN_LOG;
			phys = os->lookup_ltop(os, l_addr);

			if (!phys->block) {
				openssd_fill_bio_and_end(bio);
				return DM_MAPIO_SUBMITTED;
			}

			exec_bio->bi_sector = phys->addr * NR_PHY_IN_LOG;

			// XXX buffered reads!

			//printk("exec_bio addr: %lu bi_sectors: %u orig_addr: %lu\n", exec_bio->bi_sector, bio_sectors(exec_bio), bio->bi_sector);
			openssd_submit_bio(os, phys->block, READ, exec_bio, 0);
		}
	} else {
		l_addr = bio->bi_sector / NR_PHY_IN_LOG;
		phys = os->lookup_ltop(os, l_addr);

		bio->bi_sector = phys->addr * NR_PHY_IN_LOG;

		if (!phys->block) {
			openssd_fill_bio_and_end(bio);
			return DM_MAPIO_SUBMITTED;
		}

		/* When physical page contains several logical pages, we may need to
		 * read from buffer. Check if so, and if page is cached in ap, read from
		 * there */
		if (NR_HOST_PAGES_IN_FLASH_PAGE > 1) {
			if (openssd_handle_buffered_read(os, bio, phys) == 0)
				return DM_MAPIO_SUBMITTED;
		}

		//printk("phys_addr: %lu blockid %u bio addr: %lu bi_sectors: %u\n", phys->addr, phys->block->id, bio->bi_sector, bio_sectors(bio));
		openssd_submit_bio(os, phys->block, READ, bio, 0);
	}

	return DM_MAPIO_SUBMITTED;
}

int openssd_handle_buffered_write(sector_t p_addr, struct nvm_block *block,
                                  struct bio_vec *bv)
{
	struct openssd *os = block->pool->os;
	unsigned int idx;
	void *src_p, *dst_p;

	idx = p_addr % (NR_HOST_PAGES_IN_FLASH_PAGE * os->nr_pages_per_blk);
	src_p = kmap_atomic(bv->bv_page);
	dst_p = kmap_atomic(&block->data[idx]);
	memcpy(dst_p, src_p, bv->bv_len);

	kunmap_atomic(dst_p);
	kunmap_atomic(src_p);

	return atomic_inc_return(&block->data_size);
}

void openssd_submit_write(struct openssd *os, sector_t physical_addr,
                          struct nvm_block* victim_block, int size)
{
	struct bio *issue_bio;
	int bv_i;

	//FIXME: can fail
	issue_bio = bio_alloc(GFP_NOIO, 2);
	issue_bio->bi_bdev = os->dev->bdev;
	issue_bio->bi_sector = ((physical_addr-1) * NR_PHY_IN_LOG);

	for (bv_i = 0; bv_i < NR_HOST_PAGES_IN_FLASH_PAGE; bv_i++) {
		unsigned int idx_to_write = size - NR_HOST_PAGES_IN_FLASH_PAGE + bv_i;
		bio_add_page(issue_bio, &victim_block->data[idx_to_write], PAGE_SIZE, 0);
	}
	openssd_submit_bio(os, victim_block, WRITE, issue_bio, 0);
}

int openssd_write_bio_generic(struct openssd *os, struct bio *bio)
{
	struct nvm_block *victim_block;
	struct bio_vec *bv;
	sector_t logical_addr, physical_addr;
	int i, size;

	bio_for_each_segment(bv, bio, i) {
		if (bv->bv_len != PAGE_SIZE && bv->bv_offset != 0) {
			DMERR("Only system page size supported. \
			(bv_len %u bv_offset %u)", bv->bv_len, bv->bv_offset);
			return -ENOSPC;
		}

		logical_addr = (bio->bi_sector / NR_PHY_IN_LOG) + i;

		physical_addr = openssd_alloc_addr_retries(os, logical_addr, &victim_block, NULL);

		if (physical_addr == LTOP_EMPTY) {
			DMERR("Out of physical addresses. Retry");
			return DM_MAPIO_REQUEUE;
		}

		/* Submit bio for all physical addresses*/
		//DMINFO("Logical: %lu Physical: %lu OS Sector addr: %ld Sectors: %u Size: %u", logical_addr, physical_addr, bio->bi_sector, bio_sectors(bio), bio->bi_size);

		size = openssd_handle_buffered_write(physical_addr, victim_block, bv);
		if (size % NR_HOST_PAGES_IN_FLASH_PAGE == 0)
			openssd_submit_write(os, physical_addr, victim_block, size);
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

void openssd_submit_bio(struct openssd *os, struct nvm_block *block, int rw, struct bio *bio, int sync)
{
	struct nvm_ap *ap = block_to_ap(os, block);
	struct nvm_pool *pool = ap->pool;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(os, bio);
	pb->ap = ap;
	pb->block = block;
	pb->physical_addr = bio->bi_sector;

	DMDEBUG("submit_bio: physical_addr %ld ap %p", pb->physical_addr, ap);
	if (rw == WRITE)
		bio->bi_end_io = openssd_end_write_bio;
	else
		bio->bi_end_io = openssd_end_read_bio;

	/* setup timings - remember overhead. */
	do_gettimeofday(&pb->start_tv);

	if (os->config.flags & NVM_OPT_POOL_SERIALIZE && atomic_read(&pool->is_active)) {
		spin_lock(&pool->waiting_lock);
		ap->io_delayed++;
		bio_list_add(&pool->waiting_bios, bio);
		spin_unlock(&pool->waiting_lock);
	} else {
		atomic_inc(&pool->is_active);
	}

	// We allow counting to be semi-accurate as theres no locking for accounting.
	ap->io_accesses[bio_data_dir(bio)]++;

	if (sync) {
		rw |= REQ_SYNC;
		pb->sync = 1;
		init_completion(&pb->event);
		submit_bio(rw, bio);
		wait_for_completion(&pb->event);
	} else {
		pb->sync = 0;
		submit_bio(rw, bio);
	}
}
