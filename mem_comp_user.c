#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int print_bpf_verifier(enum libbpf_print_level level,
							const char *format, va_list args)
{
	return vfprintf(stdout, format, args);
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_link *links[2] = {};
	int link_count = 0;
	struct bpf_program *prog;
	struct bpf_object *obj;
	char filename[PATH_MAX];
	int err, ret = 0;

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

	obj = bpf_object__open(filename);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	bpf_object__for_each_program(prog, obj) {
		links[link_count] = bpf_program__attach(prog);
		err = libbpf_get_error(links[link_count]);
		if (err < 0) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			links[link_count] = NULL;
			goto cleanup;
		}
		link_count++;
	}

	int sig, quit = 0;
	FILE *fp = NULL;

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
				quit = 1;
				break;

			case SIGALRM:
				if (fp != NULL) {
					fclose(fp);
				}
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
	while (link_count) {
		bpf_link__destroy(links[--link_count]);
	}
	bpf_object__close(obj);
	return 0;
}
