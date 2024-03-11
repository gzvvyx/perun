// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <inttypes.h>

#include <bpf/libbpf.h>

#include "gotrace.skel.h"
#include "gotrace.h"

FILE *file;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

void sig_handler(int sig) {
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct basic_info *e = data;
	FILE *out = (FILE *)ctx;
	// fwrite(e, sizeof(e), 1, out);
	// fID;TYPE;PID;TGID;GOID;TIMESTAMP
	fprintf(out, "%d;%d;%d;%d;%d;%" PRIu64 "\n", e->func, e->type, e->pid, e->tgid, 0, e->ts);

	// fprintf(stdout, "FUNC: %d, PID: %d, TGID: %d, GOID: %ld, TIME: %" PRIu64 "\n", evt->func, evt->pid, evt->tgid, evt->goid, evt->time);
	return 0;
}

int main(int argc, char **argv)
{
	bump_memlock_rlimit();

	FILE *out = NULL;
	struct ring_buffer *rb = NULL;
	struct gotrace_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	/* Load and verify BPF application */
	skel = gotrace_bpf__open_and_load();
	if (!skel) {
		fprintf(stdout, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Let libbpf perform auto-attach for greet_handler
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = gotrace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");


	// Prepare output file
	out = fopen("output.txt", "w+");
    if (out == NULL) {
        goto cleanup;
    }
	printf("File opened.\n");

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, (void *)out, NULL);


	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 10 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	gotrace_bpf__destroy(skel);
	if (out != NULL) {
		fclose(out);
	}
	return err < 0 ? -err : 0;
}
