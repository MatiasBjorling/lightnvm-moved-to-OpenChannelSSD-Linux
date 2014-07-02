#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/types.h>
#include <linux/blk-mq.h>
#include <linux/genhd.h>

enum VSL_RSP_VAL {
	VSL_RSP_OFF	= 0,
	VSL_RSP_ON	= 1,
};

enum VSL_RSP {
	VSL_RSP_L2P	= 0x00,
	VSL_RSP_P2L	= 0x01,
	VSL_RSP_GC	= 0x02,
	VSL_RSP_ECC	= 0x03,
};

enum VSL_NVM_TYPE {
	VSL_NVMT_BLK	= 0,
	VSL_NVMT_B	= 1,
};

enum VSL_IOSCHED {
	VSL_IOSCHED_CHANNEL	= 0,
	VSL_IOSCHED_CHIP	= 1,
};

enum vsl_status_codes {
	VSL_SUCCESS		= 0x0000,
	VSL_INVALID_OPCODE	= 0x0001,
	VSL_INVALID_FIELD	= 0x0002,
	VSL_INTERNAL_DEV_ERROR	= 0x0006,
	VSL_INVALID_CHNLID	= 0x000b,
	VSL_LBA_RANGE		= 0x0080,
	VSL_MAX_QSIZE_EXCEEDED	= 0x0102,
	VSL_RESERVED		= 0x0104,
	VSL_CONFLICTING_ATTRS	= 0x0180,
	VSL_RID_NOT_SAVEABLE	= 0x010d,
	VSL_RID_NOT_CHANGEABLE	= 0x010e,
	VSL_ACCESS_DENIED	= 0x0286,
	VSL_MORE		= 0x2000,
	VSL_DNR			= 0x4000,
	VSL_NO_COMPLETE		= 0xffff,
};

struct vsl_id {
	u16	ver_id;
	u8	nvm_type;
	u16	nchannels;
	u8	reserved[11];
};

struct vsl_id_chnl {
	u64	queue_size;
	u64	gran_read;
	u64	gran_write;
	u64	gran_erase;
	u64	oob_size;
	u32	t_r;
	u32	t_sqr;
	u32	t_w;
	u32	t_sqw;
	u32	t_e;
	u8	io_sched;
	u64	laddr_begin;
	u64	laddr_end;
	u8	reserved[4034];
};

struct vsl_get_features {
	u64	rsp[4];
	u64	ext[4];
};

struct vsl_dev;

typedef int (vsl_id_fn)(struct vsl_dev *dev, struct vsl_id *);
typedef int (vsl_id_chnl_fn)(struct vsl_dev *dev, int chnl_num, struct vsl_id_chnl *);
typedef int (vsl_get_features_fn)(struct vsl_dev *dev, struct vsl_get_features *);
typedef int (vsl_set_rsp_fn)(struct vsl_dev *dev, u8 rsp, u8 val);
typedef int (vsl_queue_rq_fn)(struct request *, void *);
typedef int (vsl_init_hctx_fn)(struct vsl_dev *, void *, unsigned int);
typedef int (vsl_erase_blk_fn)(struct vsl_dev *, sector_t);

struct vsl_dev_ops {
	vsl_id_fn		*identify;
	vsl_id_chnl_fn		*identify_channel;
	vsl_get_features_fn 	*get_features;
	vsl_set_rsp_fn		*set_responsibility;

	/* Requests */
	vsl_queue_rq_fn		*vsl_queue_rq;
	vsl_init_hctx_fn	*vsl_init_hctx;

	/* LightNVM commands */
	vsl_erase_blk_fn	*vsl_erase_blk;
};

struct vsl_dev {
	struct request_queue *q;
	struct request_queue *admin_q;

	struct vsl_dev_ops *ops;

	struct gendisk *disk;

	unsigned int drv_cmd_size;

	void *driver_data;
	void *stor;
};

/* OpenVSL configuration */
void vsl_config_cmd_size(struct vsl_dev *, struct blk_mq_tag_set *);

int vsl_init(struct gendisk *disk, struct vsl_dev *);
void vsl_exit(struct vsl_dev *);
struct vsl_dev *vsl_alloc(void);
void vsl_free(struct vsl_dev *);

int vsl_add_sysfs(struct vsl_dev *);
void vsl_remove_sysfs(struct vsl_dev *);

/* OpenVSL Requests */
int vsl_queue_rq(struct blk_mq_hw_ctx *, struct request *);
int vsl_init_hctx(struct blk_mq_hw_ctx *, void *, unsigned int);
int vsl_init_request(void *, struct request *, unsigned int, unsigned int,
								unsigned int);
void vsl_end_io(struct request *, int);
void vsl_complete_request(struct request *);
#endif
