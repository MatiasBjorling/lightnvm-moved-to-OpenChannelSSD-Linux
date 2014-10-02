#ifndef LIGHTNVM_H
#define LIGHTNVM_H

#include <uapi/linux/lightnvm.h>
#include <linux/types.h>
#include <linux/blk-mq.h>
#include <linux/genhd.h>

/* HW Responsibilities */
enum {
	NVM_RSP_L2P	= 0x00,
	NVM_RSP_P2L	= 0x01,
	NVM_RSP_GC	= 0x02,
	NVM_RSP_ECC	= 0x03,
};

/* Physical NVM Type */
enum {
	NVM_NVMT_BLK	= 0,
	NVM_NVMT_BYTE	= 1,
};

/* Internal IO Scheduling algorithm */
enum {
	NVM_IOSCHED_CHANNEL	= 0,
	NVM_IOSCHED_CHIP	= 1,
};

/* Status codes */
enum {
	NVM_SUCCESS		= 0x0000,
	NVM_INVALID_OPCODE	= 0x0001,
	NVM_INVALID_FIELD	= 0x0002,
	NVM_INTERNAL_DEV_ERROR	= 0x0006,
	NVM_INVALID_CHNLID	= 0x000b,
	NVM_LBA_RANGE		= 0x0080,
	NVM_MAX_QSIZE_EXCEEDED	= 0x0102,
	NVM_RESERVED		= 0x0104,
	NVM_CONFLICTING_ATTRS	= 0x0180,
	NVM_RID_NOT_SAVEABLE	= 0x010d,
	NVM_RID_NOT_CHANGEABLE	= 0x010e,
	NVM_ACCESS_DENIED	= 0x0286,
	NVM_MORE		= 0x2000,
	NVM_DNR			= 0x4000,
	NVM_NO_COMPLETE		= 0xffff,
};

struct nvm_id {
	u16	ver_id;
	u8	nvm_type;
	u16	nchannels;
	u8	reserved[11];
};

struct nvm_id_chnl {
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

struct nvm_get_features {
	u64	rsp[4];
	u64	ext[4];
};

struct nvm_dev;

typedef int (nvm_id_fn)(struct nvm_dev *dev, struct nvm_id *);
typedef int (nvm_id_chnl_fn)(struct nvm_dev *dev, int chnl_num, struct nvm_id_chnl *);
typedef int (nvm_get_features_fn)(struct nvm_dev *dev, struct nvm_get_features *);
typedef int (nvm_set_rsp_fn)(struct nvm_dev *dev, u8 rsp, u8 val);
typedef int (nvm_queue_rq_fn)(struct nvm_dev *, struct request *);
typedef int (nvm_erase_blk_fn)(struct nvm_dev *, sector_t);

struct lightnvm_dev_ops {
	nvm_id_fn		*identify;
	nvm_id_chnl_fn		*identify_channel;
	nvm_get_features_fn 	*get_features;
	nvm_set_rsp_fn		*set_responsibility;

	/* Requests */
	nvm_queue_rq_fn		*nvm_queue_rq;

	/* LightNVM commands */
	nvm_erase_blk_fn	*nvm_erase_block;
};

struct nvm_dev {
	struct lightnvm_dev_ops *ops;

	struct request_queue *q;
	struct gendisk *disk;

	unsigned int drv_cmd_size;

	void *driver_data;
	void *stor;
};

/* LightNVM configuration */
unsigned int nvm_cmd_size(void);

int nvm_init(struct gendisk *disk, struct nvm_dev *);
void nvm_exit(struct nvm_dev *);
struct nvm_dev *nvm_alloc(void);
void nvm_free(struct nvm_dev *);

int nvm_add_sysfs(struct nvm_dev *);
void nvm_remove_sysfs(struct nvm_dev *);

/* LightNVM blk-mq request management */
int nvm_queue_rq(struct nvm_dev *, struct request *);
void nvm_end_io(struct nvm_dev *, struct request *, int);
void nvm_complete_request(struct nvm_dev *, struct request *);

int nvm_ioctl(struct nvm_dev *dev, fmode_t mode, unsigned int cmd, unsigned long arg);
int nvm_compat_ioctl(struct nvm_dev *dev, fmode_t mode, unsigned int cmd, unsigned long arg);

#endif
