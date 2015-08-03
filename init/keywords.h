#ifndef KEYWORD
#include <string>
#include <vector>
int do_bootchart_init(const std::vector<std::string>& args);
int do_class_start(const std::vector<std::string>& args);
int do_class_stop(const std::vector<std::string>& args);
int do_class_reset(const std::vector<std::string>& args);
int do_domainname(const std::vector<std::string>& args);
int do_enable(const std::vector<std::string>& args);
int do_exec(const std::vector<std::string>& args);
int do_export(const std::vector<std::string>& args);
int do_hostname(const std::vector<std::string>& args);
int do_ifup(const std::vector<std::string>& args);
int do_insmod(const std::vector<std::string>& args);
int do_installkey(const std::vector<std::string>& args);
int do_mkdir(const std::vector<std::string>& args);
int do_mount_all(const std::vector<std::string>& args);
int do_mount(const std::vector<std::string>& args);
int do_powerctl(const std::vector<std::string>& args);
int do_restart(const std::vector<std::string>& args);
int do_restorecon(const std::vector<std::string>& args);
int do_restorecon_recursive(const std::vector<std::string>& args);
int do_rm(const std::vector<std::string>& args);
int do_rmdir(const std::vector<std::string>& args);
int do_setprop(const std::vector<std::string>& args);
int do_setrlimit(const std::vector<std::string>& args);
int do_setusercryptopolicies(const std::vector<std::string>& args);
int do_start(const std::vector<std::string>& args);
int do_stop(const std::vector<std::string>& args);
int do_swapon_all(const std::vector<std::string>& args);
int do_trigger(const std::vector<std::string>& args);
int do_symlink(const std::vector<std::string>& args);
int do_sysclktz(const std::vector<std::string>& args);
int do_write(const std::vector<std::string>& args);
int do_copy(const std::vector<std::string>& args);
int do_chown(const std::vector<std::string>& args);
int do_chmod(const std::vector<std::string>& args);
int do_loglevel(const std::vector<std::string>& args);
int do_load_persist_props(const std::vector<std::string>& args);
int do_load_system_props(const std::vector<std::string>& args);
int do_verity_load_state(const std::vector<std::string>& args);
int do_verity_update_state(const std::vector<std::string>& args);
int do_wait(const std::vector<std::string>& args);
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
    KEYWORD(load_system_props,     COMMAND, 0, do_load_system_props)
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
    KEYWORD(setusercryptopolicies,   COMMAND, 1, do_setusercryptopolicies)
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
