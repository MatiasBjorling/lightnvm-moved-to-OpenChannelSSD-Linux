#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/types.h>
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

enum VSL_IOSCHED {
	VSL_IOSCHED_CHANNEL	= 0,
	VSL_IOSCHED_CHIP	= 1,
};

struct openvsl_id {
	u16	ver_id;
	u8	nvm_type;
	u16	nchannels;
	u8	reserved[11];
};

struct openvsl_id_chnl {
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

struct openvsl_get_features {
	u64	rsp[4];
	u64	ext[4];
};

struct openvsl_dev;

typedef struct openvsl_id (vsl_id_fn)(struct openvsl_dev *dev);
typedef struct openvsl_id_chnl (vsl_id_chnl_fn)(struct openvsl_dev *dev, int chnl_num);
typedef struct openvsl_get_features (vsl_get_features_fn)(struct openvsl_dev *dev);
typedef int (vsl_set_rsp_fn)(struct openvsl_dev *dev, u8 feat, unsigned int val);

struct openvsl_dev_ops {
	vsl_id_fn		*identify;
	vsl_id_chnl_fn		*identify_channel;
	vsl_get_features_fn 	*get_features;
	vsl_set_rsp_fn		*set_responsibility;

	/* Requests */
	queue_rq_fn		*queue_rq;
	rq_timed_out_fn		*timeout;
};

struct openvsl_dev {
	struct request_queue *q;
	struct request_queue *admin_q;

	struct openvsl_dev_ops ops;

	void *stor;
};

/* OpenVSL configuration */
int openvsl_config_blk_tags(struct blk_mq_tag_set *);

int openvsl_init(struct openvsl_dev *);
void openvsl_exit(struct openvsl_dev *);
struct openvsl_dev *openvsl_alloc(void);
void openvsl_free(struct openvsl_dev *);

#endif
