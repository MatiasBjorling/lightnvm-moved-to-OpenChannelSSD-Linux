#ifndef OPENVSL_H
#define OPENVSL_H

#include <linux/blk-mq>

struct openvsl_identify {
	/* TODO fill in */
};

typedef struct openvsl_identify_fn *(openvsl_identify)(struct openvsl_dev *dev);

struct openvsl_dev {
	struct request_queue *q;
	struct request_queue *admin_q;

	openvsl_identify_fn *identify;
};

int openvsl_rq_data_size();

#endif
