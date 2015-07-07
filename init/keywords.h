#ifndef KEYWORD
int do_bootchart_init(int nargs, char **args);
int do_class_start(int nargs, char **args);
int do_class_stop(int nargs, char **args);
int do_class_reset(int nargs, char **args);
int do_domainname(int nargs, char **args);
int do_enable(int nargs, char **args);
int do_exec(int nargs, char **args);
int do_export(int nargs, char **args);
int do_hostname(int nargs, char **args);
int do_ifup(int nargs, char **args);
int do_insmod(int nargs, char **args);
int do_installkey(int nargs, char **args);
int do_mkdir(int nargs, char **args);
int do_mount_all(int nargs, char **args);
int do_mount(int nargs, char **args);
int do_powerctl(int nargs, char **args);
int do_restart(int nargs, char **args);
int do_restorecon(int nargs, char **args);
int do_restorecon_recursive(int nargs, char **args);
int do_rm(int nargs, char **args);
int do_rmdir(int nargs, char **args);
int do_setprop(int nargs, char **args);
int do_setrlimit(int nargs, char **args);
int do_start(int nargs, char **args);
int do_stop(int nargs, char **args);
int do_swapon_all(int nargs, char **args);
int do_trigger(int nargs, char **args);
int do_symlink(int nargs, char **args);
int do_sysclktz(int nargs, char **args);
int do_write(int nargs, char **args);
int do_copy(int nargs, char **args);
int do_chown(int nargs, char **args);
int do_chmod(int nargs, char **args);
int do_loglevel(int nargs, char **args);
int do_load_persist_props(int nargs, char **args);
int do_load_all_props(int nargs, char **args);
int do_verity_load_state(int nargs, char **args);
int do_verity_update_state(int nargs, char **args);
int do_wait(int nargs, char **args);
#define __MAKE_KEYWORD_ENUM__
#define KEYWORD(symbol, flags, nargs, func) K_##symbol,
enum {
    K_UNKNOWN,
#endif
    KEYWORD(bootchart_init,        COMMAND, 0, do_bootchart_init)
    KEYWORD(chmod,       COMMAND, 2, do_chmod)
    KEYWORD(chown,       COMMAND, 2, do_chown)
    KEYWORD(class,       OPTION,  0, 0)
    KEYWORD(class_reset, COMMAND, 1, do_class_reset)
    KEYWORD(class_start, COMMAND, 1, do_class_start)
    KEYWORD(class_stop,  COMMAND, 1, do_class_stop)
    KEYWORD(console,     OPTION,  0, 0)
    KEYWORD(copy,        COMMAND, 2, do_copy)
    KEYWORD(critical,    OPTION,  0, 0)
    KEYWORD(disabled,    OPTION,  0, 0)
    KEYWORD(domainname,  COMMAND, 1, do_domainname)
    KEYWORD(enable,      COMMAND, 1, do_enable)
    KEYWORD(exec,        COMMAND, 1, do_exec)
    KEYWORD(export,      COMMAND, 2, do_export)
    KEYWORD(group,       OPTION,  0, 0)
    KEYWORD(hostname,    COMMAND, 1, do_hostname)
    KEYWORD(ifup,        COMMAND, 1, do_ifup)
    KEYWORD(import,      SECTION, 1, 0)
    KEYWORD(insmod,      COMMAND, 1, do_insmod)
    KEYWORD(installkey,  COMMAND, 1, do_installkey)
    KEYWORD(ioprio,      OPTION,  0, 0)
    KEYWORD(keycodes,    OPTION,  0, 0)
    KEYWORD(load_all_props,        COMMAND, 0, do_load_all_props)
    KEYWORD(load_persist_props,    COMMAND, 0, do_load_persist_props)
    KEYWORD(loglevel,    COMMAND, 1, do_loglevel)
    KEYWORD(mkdir,       COMMAND, 1, do_mkdir)
    KEYWORD(mount_all,   COMMAND, 1, do_mount_all)
    KEYWORD(mount,       COMMAND, 3, do_mount)
    KEYWORD(oneshot,     OPTION,  0, 0)
    KEYWORD(onrestart,   OPTION,  0, 0)
    KEYWORD(on,          SECTION, 0, 0)
    KEYWORD(powerctl,    COMMAND, 1, do_powerctl)
    KEYWORD(restart,     COMMAND, 1, do_restart)
    KEYWORD(restorecon,  COMMAND, 1, do_restorecon)
    KEYWORD(restorecon_recursive,  COMMAND, 1, do_restorecon_recursive)
    KEYWORD(rm,          COMMAND, 1, do_rm)
    KEYWORD(rmdir,       COMMAND, 1, do_rmdir)
    KEYWORD(seclabel,    OPTION,  0, 0)
    KEYWORD(service,     SECTION, 0, 0)
    KEYWORD(setenv,      OPTION,  2, 0)
    KEYWORD(setprop,     COMMAND, 2, do_setprop)
    KEYWORD(setrlimit,   COMMAND, 3, do_setrlimit)
    KEYWORD(socket,      OPTION,  0, 0)
    KEYWORD(start,       COMMAND, 1, do_start)
    KEYWORD(stop,        COMMAND, 1, do_stop)
    KEYWORD(swapon_all,  COMMAND, 1, do_swapon_all)
    KEYWORD(symlink,     COMMAND, 1, do_symlink)
    KEYWORD(sysclktz,    COMMAND, 1, do_sysclktz)
    KEYWORD(trigger,     COMMAND, 1, do_trigger)
    KEYWORD(user,        OPTION,  0, 0)
    KEYWORD(verity_load_state,      COMMAND, 0, do_verity_load_state)
    KEYWORD(verity_update_state,    COMMAND, 0, do_verity_update_state)
    KEYWORD(wait,        COMMAND, 1, do_wait)
    KEYWORD(write,       COMMAND, 2, do_write)
    KEYWORD(writepid,    OPTION,  0, 0)
#ifdef __MAKE_KEYWORD_ENUM__
    KEYWORD_COUNT,
};
#undef __MAKE_KEYWORD_ENUM__
#undef KEYWORD
#endif
