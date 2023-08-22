#include <err.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static void setup_namespaces(void)
{
	int fd;
	char buffer[128];
	int buffer_size;
	int ret;
	uid_t uid;
	ssize_t nb_write;

	uid = getuid();

	ret = unshare(CLONE_NEWUSER | CLONE_NEWNET);
	if (ret < 0) {
		err(1, "Failed to unshare");
	}

	buffer_size = snprintf(buffer, sizeof(buffer), "0 %u 1", uid);
	if (buffer_size < 0) {
		errx(1, "Failed to snprintf");
	}

	fd = openat(AT_FDCWD, "/proc/self/uid_map", O_WRONLY);
	if (fd < 0) {
		err(1, "Failed to open");
	}
	nb_write = write(fd, buffer, buffer_size);
	if (nb_write != buffer_size) {
		err(1, "Failed to write");
	}
	close(fd);

	fd = openat(AT_FDCWD, "/proc/self/setgroups", O_WRONLY);
	if (fd < 0) {
		err(1, "Failed to open");
	}
	nb_write = write(fd, "deny", strlen("deny"));
	if (nb_write != strlen("deny")) {
		err(1, "Failed to write");
	}
	close(fd);

	fd = openat(AT_FDCWD, "/proc/self/gid_map", O_WRONLY);
	if (fd < 0) {
		err(1, "Failed to open");
	}
	nb_write = write(fd, buffer, buffer_size);
	if (nb_write != buffer_size) {
		err(1, "Failed to write");
	}
	close(fd);
}

int main(int argc, char *argv[], char *envp[])
{
	(void)argc;

	setup_namespaces();

	execve(argv[1], &argv[1], envp);
	err(1, "Failed to exec stage payload");

	return 0;
}
