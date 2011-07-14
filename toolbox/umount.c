
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/loop.h>
#include <errno.h>

#define LOOPDEV_MAXLEN 64
#define LOOP_MAJOR 7

static int is_loop(char *dev)
{
    struct stat st;
    int ret = 0;

    if (stat(dev, &st) == 0) {
        if (S_ISBLK(st.st_mode) && (major(st.st_rdev) == LOOP_MAJOR)) {
            ret = 1;
        }
    }

    return ret;
}

static int is_loop_mount(const char* path, char *loopdev)
{
    FILE* f;
    int count;
    char device[256];
    char mount_path[256];
    char rest[256];
    int result = 0;
    int path_length = strlen(path);
    
    f = fopen("/proc/mounts", "r");
    if (!f) {
        fprintf(stdout, "could not open /proc/mounts: %s\n", strerror(errno));
        return -1;
    }

    do {
        count = fscanf(f, "%255s %255s %255s\n", device, mount_path, rest);
        if (count == 3) {
            if (is_loop(device) && strcmp(path, mount_path) == 0) {
                strlcpy(loopdev, device, LOOPDEV_MAXLEN);
                result = 1;
                break;
            }
        }
    } while (count == 3);

    fclose(f);
    return result;
}

int umount_main(int argc, char *argv[])
{
    int loop, loop_fd;
    char loopdev[LOOPDEV_MAXLEN];

    if(argc != 2) {
        fprintf(stderr,"umount <path>\n");
        return 1;
    }

    loop = is_loop_mount(argv[1], loopdev);
    if (umount(argv[1])) {
        fprintf(stderr, "failed: %s\n", strerror(errno));
        return 1;
    }

    if (loop) {
        // free the loop device
        loop_fd = open(loopdev, O_RDONLY);
        if (loop_fd < 0) {
            fprintf(stderr, "open loop device failed: %s\n", strerror(errno));
            return 1;
        }
        if (ioctl(loop_fd, LOOP_CLR_FD, 0) < 0) {
            fprintf(stderr, "ioctl LOOP_CLR_FD failed: %s\n", strerror(errno));
            return 1;
        }

        close(loop_fd);
    }

    return 0;
}
