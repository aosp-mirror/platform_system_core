#include "fs.h"


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/wait.h>
#else
#include <tchar.h>
#include <windows.h>
#endif
#include <unistd.h>
#include <vector>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

using android::base::GetExecutableDirectory;
using android::base::StringPrintf;
using android::base::unique_fd;

#ifdef _WIN32
static int exec_cmd(const char* path, const char** argv, const char** envp) {
    std::string cmd;
    int i = 0;
    while (argv[i] != nullptr) {
        cmd += argv[i++];
        cmd += " ";
    }
    cmd = cmd.substr(0, cmd.size() - 1);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 0;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    std::string env_str;
    if (envp != nullptr) {
        while (*envp != nullptr) {
            env_str += std::string(*envp) + std::string("\0", 1);
            envp++;
        }
    }

    if (!CreateProcessA(nullptr,                         // No module name (use command line)
                        const_cast<char*>(cmd.c_str()),  // Command line
                        nullptr,                         // Process handle not inheritable
                        nullptr,                         // Thread handle not inheritable
                        FALSE,                           // Set handle inheritance to FALSE
                        0,                               // No creation flags
                        env_str.empty() ? nullptr : LPSTR(env_str.c_str()),
                        nullptr,  // Use parent's starting directory
                        &si,      // Pointer to STARTUPINFO structure
                        &pi)      // Pointer to PROCESS_INFORMATION structure
    ) {
        fprintf(stderr, "CreateProcess failed: %s\n",
                android::base::SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0) {
        fprintf(stderr, "%s failed: %lu\n", path, exit_code);
        return -1;
    }
    return 0;
}
#else
static int exec_cmd(const char* path, const char** argv, const char** envp) {
    int status;
    pid_t child;
    if ((child = fork()) == 0) {
        execve(path, const_cast<char**>(argv), const_cast<char**>(envp));
        _exit(EXIT_FAILURE);
    }
    if (child < 0) {
        fprintf(stderr, "%s failed with fork %s\n", path, strerror(errno));
        return -1;
    }
    if (TEMP_FAILURE_RETRY(waitpid(child, &status, 0)) == -1) {
        fprintf(stderr, "%s failed with waitpid %s\n", path, strerror(errno));
        return -1;
    }
    int ret = -1;
    if (WIFEXITED(status)) {
        ret = WEXITSTATUS(status);
    }

    if (ret != 0) {
        fprintf(stderr, "%s failed with status %d\n", path, ret);
        return -1;
    }
    return 0;
}
#endif

static int generate_ext4_image(const char* fileName, long long partSize,
                               const std::string& initial_dir, unsigned eraseBlkSize,
                               unsigned logicalBlkSize, const unsigned fsOptions) {
    static constexpr int block_size = 4096;
    const std::string exec_dir = android::base::GetExecutableDirectory();

    const std::string mke2fs_path = exec_dir + "/mke2fs";
    std::vector<const char*> mke2fs_args = {mke2fs_path.c_str(), "-t", "ext4", "-b"};

    std::string block_size_str = std::to_string(block_size);
    mke2fs_args.push_back(block_size_str.c_str());

    std::string ext_attr = "android_sparse";
    if (eraseBlkSize != 0 && logicalBlkSize != 0) {
        int raid_stride = logicalBlkSize / block_size;
        int raid_stripe_width = eraseBlkSize / block_size;
        // stride should be the max of 8kb and logical block size
        if (logicalBlkSize != 0 && logicalBlkSize < 8192) raid_stride = 8192 / block_size;
        // stripe width should be >= stride
        if (raid_stripe_width < raid_stride) raid_stripe_width = raid_stride;
        ext_attr += StringPrintf(",stride=%d,stripe-width=%d", raid_stride, raid_stripe_width);
    }
    mke2fs_args.push_back("-E");
    mke2fs_args.push_back(ext_attr.c_str());
    mke2fs_args.push_back("-O");
    mke2fs_args.push_back("uninit_bg");

    if (fsOptions & (1 << FS_OPT_PROJID)) {
        mke2fs_args.push_back("-I");
        mke2fs_args.push_back("512");
    }

    mke2fs_args.push_back(fileName);

    std::string size_str = std::to_string(partSize / block_size);
    mke2fs_args.push_back(size_str.c_str());
    mke2fs_args.push_back(nullptr);

    const std::string mke2fs_env = "MKE2FS_CONFIG=" + GetExecutableDirectory() + "/mke2fs.conf";
    std::vector<const char*> mke2fs_envp = {mke2fs_env.c_str(), nullptr};

    int ret = exec_cmd(mke2fs_args[0], mke2fs_args.data(), mke2fs_envp.data());
    if (ret != 0) {
        return -1;
    }

    if (initial_dir.empty()) {
        return 0;
    }

    const std::string e2fsdroid_path = exec_dir + "/e2fsdroid";
    std::vector<const char*> e2fsdroid_args = {e2fsdroid_path.c_str(), "-f", initial_dir.c_str(),
                                               fileName, nullptr};

    return exec_cmd(e2fsdroid_args[0], e2fsdroid_args.data(), nullptr);
}

static int generate_f2fs_image(const char* fileName, long long partSize,
                               const std::string& initial_dir, unsigned /* unused */,
                               unsigned /* unused */, const unsigned fsOptions) {
    const std::string exec_dir = android::base::GetExecutableDirectory();
    const std::string mkf2fs_path = exec_dir + "/make_f2fs";
    std::vector<const char*> mkf2fs_args = {mkf2fs_path.c_str()};

    mkf2fs_args.push_back("-S");
    std::string size_str = std::to_string(partSize);
    mkf2fs_args.push_back(size_str.c_str());
    mkf2fs_args.push_back("-g");
    mkf2fs_args.push_back("android");

    if (fsOptions & (1 << FS_OPT_PROJID)) {
        mkf2fs_args.push_back("-O");
        mkf2fs_args.push_back("project_quota,extra_attr");
    }

    if (fsOptions & (1 << FS_OPT_CASEFOLD)) {
        mkf2fs_args.push_back("-O");
        mkf2fs_args.push_back("casefold");
        mkf2fs_args.push_back("-C");
        mkf2fs_args.push_back("utf8");
    }

    if (fsOptions & (1 << FS_OPT_COMPRESS)) {
        mkf2fs_args.push_back("-O");
        mkf2fs_args.push_back("compression");
        mkf2fs_args.push_back("-O");
        mkf2fs_args.push_back("extra_attr");
    }

    mkf2fs_args.push_back(fileName);
    mkf2fs_args.push_back(nullptr);

    int ret = exec_cmd(mkf2fs_args[0], mkf2fs_args.data(), nullptr);
    if (ret != 0) {
        return -1;
    }

    if (initial_dir.empty()) {
        return 0;
    }

    const std::string sload_path = exec_dir + "/sload_f2fs";
    std::vector<const char*> sload_args = {sload_path.c_str(), "-S",
                                       "-f", initial_dir.c_str(), fileName, nullptr};

    return exec_cmd(sload_args[0], sload_args.data(), nullptr);
}

static const struct fs_generator {
    const char* fs_type;  //must match what fastboot reports for partition type

    //returns 0 or error value
    int (*generate)(const char* fileName, long long partSize, const std::string& initial_dir,
                    unsigned eraseBlkSize, unsigned logicalBlkSize, const unsigned fsOptions);

} generators[] = {
    { "ext4", generate_ext4_image},
    { "f2fs", generate_f2fs_image},
};

const struct fs_generator* fs_get_generator(const std::string& fs_type) {
    for (size_t i = 0; i < sizeof(generators) / sizeof(*generators); i++) {
        if (fs_type == generators[i].fs_type) {
            return generators + i;
        }
    }
    return nullptr;
}

int fs_generator_generate(const struct fs_generator* gen, const char* fileName, long long partSize,
                          const std::string& initial_dir, unsigned eraseBlkSize,
                          unsigned logicalBlkSize, const unsigned fsOptions) {
    return gen->generate(fileName, partSize, initial_dir, eraseBlkSize, logicalBlkSize, fsOptions);
}
