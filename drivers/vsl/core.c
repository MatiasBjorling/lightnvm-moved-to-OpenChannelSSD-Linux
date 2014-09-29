#include <linux/openvsl.h>
#include <trace/events/block.h>
#include "vsl.h"

inline void __invalidate_block_page(struct vsl_stor *s,
				struct vsl_addr *p)
{
	unsigned int page_offset;
	struct vsl_block *block = p->block;

	VSL_ASSERT(spin_is_locked(&s->rev_lock));
	VSL_ASSERT(spin_is_locked(&block->lock));

	page_offset = p->addr % s->nr_pages_per_blk;
	WARN_ON(test_and_set_bit(page_offset, block->invalid_pages));
	block->nr_invalid_pages++;
}

void invalidate_block_page(struct vsl_stor *s, struct vsl_addr *p)
{
	struct vsl_block *block = p->block;

	spin_lock(&block->lock);
	__invalidate_block_page(s, p);
	spin_unlock(&block->lock);
}

void vsl_update_map(struct vsl_stor *s, sector_t l_addr, struct vsl_addr *p,
					int is_gc)
{
	struct vsl_addr *gp;
	struct vsl_rev_addr *rev;

	BUG_ON(l_addr >= s->nr_pages);
	if (p->addr >= s->nr_pages)
		printk("%lu %lu\n", p->addr, s->nr_pages);
	BUG_ON(p->addr >= s->nr_pages);

	gp = &s->trans_map[l_addr];
	spin_lock(&s->rev_lock);
	if (gp->block) {
		invalidate_block_page(s, gp);
		s->rev_trans_map[gp->addr].addr = LTOP_POISON;
	}

	gp->addr = p->addr;
	gp->block = p->block;

	rev = &s->rev_trans_map[p->addr];
	rev->addr = l_addr;
	spin_unlock(&s->rev_lock);
}

/* requires pool->lock taken */
inline void vsl_reset_block(struct vsl_block *block)
{
	struct vsl_stor *s;

	BUG_ON(!block);

	s = block->pool->s;
	spin_lock(&block->lock);
	bitmap_zero(block->invalid_pages, s->nr_pages_per_blk);
	block->ap = NULL;
	block->next_page = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->gc_running, 0);
	atomic_set(&block->data_size, 0);
	atomic_set(&block->data_cmnt_size, 0);
	spin_unlock(&block->lock);
}


static sector_t __vsl_alloc_phys_addr(struct vsl_block *block)
{
	struct vsl_stor *s;
	sector_t addr = LTOP_EMPTY;

	BUG_ON(!block);

	s = block->pool->s;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;


	addr = block_to_addr(block) + block->next_page;

	block->next_page++;

	if (s->type->alloc_phys_addr)
		s->type->alloc_phys_addr(s, block);

out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t vsl_alloc_phys_addr(struct vsl_block *block)
{
	return __vsl_alloc_phys_addr(block);
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

void vsl_erase_block(struct vsl_block *block)
{
	/* Send erase command to device. */
}

void vsl_endio(struct vsl_dev *vsl_dev, struct request *rq, int err)
{
	struct vsl_stor *s = vsl_dev->stor;
	struct per_rq_data *pb = get_per_rq_data(vsl_dev, rq);
	struct vsl_addr *p = pb->addr;
	struct vsl_block *block = p->block;
	unsigned int data_cnt;

	//printk("p: %p s: %llu l: %u pp:%p e:%u (%u)\n", p, p->addr, pb->l_addr, p, err, rq_data_dir(rq));
	vsl_unlock_laddr_range(s, pb->l_addr, 1);

	if (rq_data_dir(rq) == WRITE) {
		/* maintain data in buffer until block is full */
		data_cnt = atomic_inc_return(&block->data_cmnt_size);
		if (data_cnt == s->nr_pages_per_blk) {
			/*defer scheduling of the block for recycling*/
			queue_work(s->kgc_wq, &block->ws_eio);
		}
	}

	/* all submitted requests allocate their own addr,
	 * except GC reads */
	if (pb->flags & VSL_RQ_GC)
		return;

	mempool_free(pb->addr, s->addr_pool);
}

/* remember to lock l_add before calling vsl_submit_rq */
void vsl_setup_rq(struct vsl_stor *s, struct request *rq, struct vsl_addr *p,
		  sector_t l_addr, unsigned int flags)
{
	struct vsl_block *block = p->block;
	struct vsl_ap *ap;
	struct per_rq_data *pb;

	if (block)
		ap = block_to_ap(s, block);
	else
		ap = &s->aps[0];

	pb = get_per_rq_data(s->dev, rq);
	pb->ap = ap;
	pb->addr = p;

	pb->l_addr = l_addr;
	pb->flags = flags;
}

int vsl_read_rq(struct vsl_stor *s, struct request *rq)
{
	struct vsl_addr *p;
	sector_t l_addr;

	l_addr = blk_rq_pos(rq) / NR_PHY_IN_LOG;

	vsl_lock_laddr_range(s, l_addr, 1);

	p = s->type->lookup_ltop(s, l_addr);
	if (!p) {
		vsl_unlock_laddr_range(s, l_addr, 1);
		vsl_gc_kick(s);
		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	rq->__sector = p->addr * NR_PHY_IN_LOG +
					(blk_rq_pos(rq) % NR_PHY_IN_LOG);

	if (!p->block)
		rq->__sector = 0;

	vsl_setup_rq(s, rq, p, l_addr, VSL_RQ_NONE);
	return BLK_MQ_RQ_QUEUE_OK;
}


int __vsl_write_rq(struct vsl_stor *s, struct request *rq, int is_gc)
{
	struct vsl_addr *p;
	sector_t l_addr = blk_rq_pos(rq) / NR_PHY_IN_LOG;

	vsl_lock_laddr_range(s, l_addr, 1);
	p = s->type->map_page(s, l_addr, is_gc);
	if (!p) {
		BUG_ON(is_gc);
		vsl_unlock_laddr_range(s, l_addr, 1);
		vsl_gc_kick(s);

		return BLK_MQ_RQ_QUEUE_BUSY;
	}

	/*
	 * MB: Should be revised. We might need a different hook into device
	 * driver
	 */
	rq->__sector = p->addr * NR_PHY_IN_LOG;
	/*printk("vsl: W %llu(%llu) B: %u\n", p->addr, p->addr * NR_PHY_IN_LOG,
			p->block->id);*/

	vsl_setup_rq(s, rq, p, l_addr, VSL_RQ_NONE);

	return BLK_MQ_RQ_QUEUE_OK;
}

int vsl_write_rq(struct vsl_stor *s, struct request *rq)
{
	return __vsl_write_rq(s, rq, 0);
}
