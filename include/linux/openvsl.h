#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/blk-mq>

enum VSL_RSP {
	OFF	= 0,
	ON	= 1,
};

struct openvsl_identify {
	
};

typedef struct vsl_id_fn (vsl_id_fn)(struct vsl_dev *dev);
typedef struct vsl_id_chnl_fn (vsl_id_channel_fn)(struct vsl_dev *dev, int chnl_num);
typedef struct vsl_get_features_fn (vsl_get_features)(struct vsl_dev *dev);
typedef int vsl_set_rsp (vsl_set_rsp)(struct vsl_dev *dev, uint8 feat, int val);

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
	void *priv;

	struct openvsl_dev_ops ops;
};

/* OpenVSL configuration */
int openvsl_rq_data_size();
int openvsl_config_blk_reg(struct blk_mq_reg *reg);

int openvsl_init(struct openvsl_dev *dev);
void openvsl_exit(struct openvl_dev *dev)
struct openvsl_dev *openvsl_alloc();
void openvsl_free(struct openvsl_dev *dev);

/* Request logic */


#endif
