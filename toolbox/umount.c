
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/loop.h>

// FIXME - only one loop mount is supported at a time
#define LOOP_DEVICE "/dev/block/loop0"

static int is_loop_mount(const char* path)
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
        fprintf(stdout, "could not open /proc/mounts\n");
        return -1;
    }

    do {
        count = fscanf(f, "%255s %255s %255s\n", device, mount_path, rest);
        if (count == 3) {
            if (strcmp(LOOP_DEVICE, device) == 0 && strcmp(path, mount_path) == 0) {
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
    
    if(argc != 2) {
        fprintf(stderr,"umount <path>\n");
        return 1;
    }

    loop = is_loop_mount(argv[1]);
    if(umount(argv[1])){
        fprintf(stderr,"failed.\n");
        return 1;
    }

    if (loop) {
        // free the loop device
        loop_fd = open(LOOP_DEVICE, O_RDONLY);
        if (loop_fd < -1) {
            perror("open loop device failed");
            return 1;
        }
        if (ioctl(loop_fd, LOOP_CLR_FD, 0) < 0) {
            perror("ioctl LOOP_CLR_FD failed");
            return 1;
        }

        close(loop_fd);
    }

    return 0;
}
