#include <linux/version.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/mm.h>
#include "bpf_helpers.h"
#include "bpf_tracing.h"

SEC("kprobe/swap_readpage")
int mem_prog1(struct pt_regs *ctx)
{
	struct page *p = (struct page*)PT_REGS_PARM1(ctx);
	bpf_printk("In swap_readpage");
	return 0;
}

SEC("kprobe/swap_writepage")
int mem_prog2(struct pt_regs *ctx)
{
	struct page *p = (struct page*)PT_REGS_PARM1(ctx);
	bpf_printk("In swap_writepage");
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
