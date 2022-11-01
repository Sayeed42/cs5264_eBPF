#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

SEC("kprobe/pick_next_task_fair")
int mem_prog1(struct pt_regs *ctx)
{
	// bpf_printk("In pick_next_task_fair");
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;