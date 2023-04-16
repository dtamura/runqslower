/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __RUNQSLOWER_H
#define __RUNQSLOWER_H

#define TASK_COMM_LEN 16

struct event {
	__u8 task[TASK_COMM_LEN];
	__u8 prev_task[TASK_COMM_LEN];
	__u64 delta_us;
	__u64 switch_time;
	int target_cpu;
	pid_t pid;
	pid_t prev_pid;
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

#endif /* __RUNQSLOWER_H */
