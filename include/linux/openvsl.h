#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/blk-mq.h>

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

struct openvsl_id {
	uint16	ver_id;
	uint8	nvm_type;
	uint16	nchannels;
	uint8	reserved[11];
};

struct openvsl_id_chnl {
	u64	queue_size;
	u64	page_size;
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

typedef struct vsl_id_fn (vsl_id_fn)(struct vsl_dev *dev);
typedef struct vsl_id_chnl_fn (vsl_id_channel_fn)(struct vsl_dev *dev, int chnl_num);
typedef struct vsl_get_features_fn (vsl_get_features)(struct vsl_dev *dev);
typedef int vsl_set_rsp (vsl_set_rsp)(struct vsl_dev *dev, u8 feat, enum VSL_RSP_VAL val);

struct openvsl_dev_ops {
	vsl_id_fn		*identify;
	vsl_id_chnl_fn		*identify_channel;
	vsl_get_features_fn 	*get_features;
	vsl_set_rsp_fn		*set_responsibility;

	/* Requests */
	queue_fq_fn		*queue_rq;
	rq_timed_out_fn		*timeout;
};

struct openvsl_dev {
	struct request_queue *q;
	struct request_queue *admin_q;

	struct openvsl_dev_ops ops;

	void *stor;
};

/* OpenVSL configuration */
int openvsl_config_blk_reg(struct blk_mq_reg *reg);

int openvsl_init(struct openvsl_dev *dev);
void openvsl_exit(struct openvl_dev *dev)
struct openvsl_dev *openvsl_alloc();
void openvsl_free(struct openvsl_dev *dev);

#endif
