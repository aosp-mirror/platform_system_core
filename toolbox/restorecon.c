#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <selinux/selinux.h>
#include <selinux/label.h>

#define FCPATH "/file_contexts"

static struct selabel_handle *sehandle;
static const char *progname;
static int nochange;
static int verbose;

static void usage(void)
{
    fprintf(stderr, "usage:  %s [-f file_contexts] [-nrRv] pathname...\n", progname);
    exit(1);
}

static int restore(const char *pathname, const struct stat *sb)
{
    char *oldcontext, *newcontext;

    if (lgetfilecon(pathname, &oldcontext) < 0) {
        fprintf(stderr, "Could not get context of %s:  %s\n",
                pathname, strerror(errno));
        return -1;
    }
    if (selabel_lookup(sehandle, &newcontext, pathname, sb->st_mode) < 0) {
        fprintf(stderr, "Could not lookup context for %s:  %s\n", pathname,
                strerror(errno));
        return -1;
    }
    if (strcmp(newcontext, "<<none>>") &&
        strcmp(oldcontext, newcontext)) {
        if (verbose)
            printf("Relabeling %s from %s to %s.\n", pathname, oldcontext, newcontext);
        if (!nochange) {
            if (lsetfilecon(pathname, newcontext) < 0) {
                fprintf(stderr, "Could not label %s with %s:  %s\n",
                        pathname, newcontext, strerror(errno));
                return -1;
            }
        }
    }
    freecon(oldcontext);
    freecon(newcontext);
    return 0;
}

int restorecon_main(int argc, char **argv)
{
    struct selinux_opt seopts[] = {
        { SELABEL_OPT_PATH, FCPATH }
    };
    int ch, recurse = 0, ftsflags = FTS_PHYSICAL;

    progname = argv[0];

    do {
        ch = getopt(argc, argv, "f:nrRv");
        if (ch == EOF)
            break;
        switch (ch) {
        case 'f':
            seopts[0].value = optarg;
            break;
        case 'n':
            nochange = 1;
            break;
        case 'r':
        case 'R':
            recurse = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            usage();
        }
    } while (1);

    argc -= optind;
    argv += optind;
    if (!argc)
        usage();

    sehandle = selabel_open(SELABEL_CTX_FILE, seopts, 1);
    if (!sehandle) {
        fprintf(stderr, "Could not load file contexts from %s:  %s\n", seopts[0].value,
                strerror(errno));
        return -1;
    }

    if (recurse) {
        FTS *fts;
        FTSENT *ftsent;
        fts = fts_open(argv, ftsflags, NULL);
        if (!fts) {
            fprintf(stderr, "Could not traverse filesystems (first was %s):  %s\n",
                    argv[0], strerror(errno));
            return -1;
        }
        while ((ftsent = fts_read(fts))) {
            switch (ftsent->fts_info) {
            case FTS_DP:
                break;
            case FTS_DNR:
            case FTS_ERR:
            case FTS_NS:
                fprintf(stderr, "Could not access %s:  %s\n", ftsent->fts_path,
                        strerror(errno));
                fts_set(fts, ftsent, FTS_SKIP);
                break;
            default:
                if (restore(ftsent->fts_path, ftsent->fts_statp) < 0)
                    fts_set(fts, ftsent, FTS_SKIP);
                break;
            }
        }
    } else {
        int i, rc;
        struct stat sb;

        for (i = 0; i < argc; i++) {
            rc = lstat(argv[i], &sb);
            if (rc < 0) {
                fprintf(stderr, "Could not stat %s:  %s\n", argv[i],
                        strerror(errno));
                continue;
            }
            restore(argv[i], &sb);
        }
    }

    return 0;
}
