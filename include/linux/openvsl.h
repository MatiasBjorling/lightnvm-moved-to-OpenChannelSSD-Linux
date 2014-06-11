#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/blk-mq>

struct openvsl_identify {
	/* TODO fill in */
};

typedef struct openvsl_identify (openvsl_identify_fn)(struct openvsl_dev *dev);

struct openvsl_dev {
	struct request_queue *q;
	struct request_queue *admin_q;

	openvsl_identify_fn	*identify;

	/* Requests */
	queue_rq_fn		*queue_rq;
	rq_timed_out_fn		*timeout;
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
