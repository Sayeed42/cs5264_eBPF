#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <linux/limits.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define aligned_alloca(align, size) (((uintptr_t)alloca((size) + (align)-1) + ((align)-1)) & ~(uintptr_t)((align)-1));

static int print_bpf_verifier(enum libbpf_print_level level,
							const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err, ret = 0, progfd;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGUSR1);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit failed");
		return 1;
	}
	libbpf_set_print(print_bpf_verifier);

	ret = bpf_prog_load(filename, BPF_PROG_TYPE_MEM_SWAP, &obj, &progfd);
	if (ret) {
			printf("Failed to load bpf program\n");
			exit(1);
	}

	// Get a page that we can use in our bpf code (kinda hacky)
	char* scratch_mem = aligned_alloca(4096, 4096);
	memset(scratch_mem, 0, 4096);

	// Register our bpf code with our syscall
	printf("First call\n");
	int res = syscall(451, progfd, scratch_mem);
	if (res != 0) {
		fprintf(stderr, "Failure on syscall");
		exit(res);
	}
	printf("Second call\n");
	res = syscall(451, progfd, scratch_mem);
	if (res != 0) {
		fprintf(stderr, "Failure on syscall");
		exit(res);
	}

	int sig, quit = 0;

	err = sigprocmask(SIG_BLOCK, &signal_mask, NULL);
	if (err != 0) {
		fprintf(stderr, "Error: Failed to set signal mask\n");
		exit(EXIT_FAILURE);
	}

	while (!quit) {
		err = sigwait(&signal_mask, &sig);
		if (err != 0) {
			fprintf(stderr, "Error: Failed to wait for signal\n");
			exit(EXIT_FAILURE);
		}

		switch (sig) {
			case SIGINT:
			case SIGTERM:
			case SIGALRM:
				quit = 1;
				break;

			case SIGUSR1:
				quit = ret;
				break;

			default:
				fprintf(stderr, "Unknown signal\n");
				break;
		}
	}

cleanup:
	bpf_object__close(obj);
	return 0;
}
