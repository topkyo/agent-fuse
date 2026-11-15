#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int afuse_clonefile_nofollow(const char *src, const char *dst) {
    if (clonefile(src, dst, CLONE_NOFOLLOW) == 0) {
        return 0;
    }
    return errno ? errno : -1;
}

int afuse_swap_paths(const char *path_a, const char *path_b) {
    if (renamex_np(path_a, path_b, RENAME_SWAP) == 0) {
        return 0;
    }
    return errno ? errno : -1;
}

int afuse_statfs_info(
    const char *path,
    int32_t *fsid0,
    int32_t *fsid1,
    uint64_t *avail_bytes,
    char *fstype_buf,
    size_t fstype_len
) {
    struct statfs sfs;
    if (statfs(path, &sfs) != 0) {
        return errno ? errno : -1;
    }
    if (fsid0) *fsid0 = sfs.f_fsid.val[0];
    if (fsid1) *fsid1 = sfs.f_fsid.val[1];
    if (avail_bytes) {
        *avail_bytes = (uint64_t)sfs.f_bavail * (uint64_t)sfs.f_bsize;
    }
    if (fstype_buf && fstype_len > 0) {
        strncpy(fstype_buf, sfs.f_fstypename, fstype_len - 1);
        fstype_buf[fstype_len - 1] = '\0';
    }
    return 0;
}

int afuse_lstat_inode_mode(const char *path, uint64_t *ino, uint32_t *mode) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno ? errno : -1;
    }
    if (ino) *ino = (uint64_t)st.st_ino;
    if (mode) *mode = (uint32_t)st.st_mode;
    return 0;
}

int afuse_force_unlock_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno ? errno : -1;
    }
    if ((st.st_flags & UF_IMMUTABLE) != 0) {
        (void)lchflags(path, st.st_flags & ~((uint32_t)UF_IMMUTABLE));
    }
    if (!S_ISLNK(st.st_mode)) {
        mode_t writable = (st.st_mode & 07777) | S_IWUSR | S_IRUSR;
        if (S_ISDIR(st.st_mode)) {
            writable |= S_IXUSR;
        }
        (void)chmod(path, writable);
    }
    return 0;
}

int afuse_acquire_flock(const char *lock_path, int *out_fd) {
    int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return errno ? errno : -1;
    }
    if (flock(fd, LOCK_EX) != 0) {
        int err = errno ? errno : EWOULDBLOCK;
        close(fd);
        return err;
    }
    *out_fd = fd;
    return 0;
}

int afuse_try_acquire_flock(const char *lock_path, int *out_fd) {
    int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        return errno ? errno : -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int err = errno ? errno : EWOULDBLOCK;
        close(fd);
        return err;
    }
    *out_fd = fd;
    return 0;
}

void afuse_release_flock(int fd) {
    if (fd >= 0) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

int afuse_isatty_stdin(void) {
    return isatty(STDIN_FILENO);
}

int afuse_real_home_dir(char *buf, size_t len) {
    if (!buf || len == 0) {
        return EINVAL;
    }
    struct passwd *pw = getpwuid(getuid());
    if (!pw || !pw->pw_dir || pw->pw_dir[0] == '\0') {
        return ENOENT;
    }
    size_t dlen = strlen(pw->pw_dir);
    if (dlen + 1 > len) {
        return ERANGE;
    }
    memcpy(buf, pw->pw_dir, dlen + 1);
    return 0;
}

int afuse_spawn_in_new_pgroup(const char *const argv[], const char *cwd, int *out_pid) {
    pid_t pid = fork();
    if (pid < 0) {
        return errno ? errno : -1;
    }
    if (pid == 0) {
        (void)setpgid(0, 0);
        if (cwd != NULL && cwd[0] != '\0') {
            if (chdir(cwd) != 0) {
                _exit(126);
            }
        }
        (void)setenv("AFUSE_GUARDED", "1", 1);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    (void)setpgid(pid, pid);
    *out_pid = (int)pid;
    return 0;
}

int afuse_try_wait_pid(int pid, int *out_exited, int *out_code) {
    int status = 0;
    pid_t rc = waitpid((pid_t)pid, &status, WNOHANG);
    if (rc == 0) {
        *out_exited = 0;
        *out_code = 0;
        return 0;
    }
    if (rc < 0) {
        return errno ? errno : -1;
    }
    *out_exited = 1;
    if (WIFEXITED(status)) {
        *out_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *out_code = 128 + WTERMSIG(status);
    } else {
        *out_code = 1;
    }
    return 0;
}

#ifdef __APPLE__
extern ssize_t fsgetpath(char *buf, size_t bufsize, fsid_t *fsid, uint64_t objid);
#endif

int afuse_fsgetpath(int32_t fsid0, int32_t fsid1, uint64_t obj_id, char *buf, size_t len) {
    if (!buf || len == 0) {
        return EINVAL;
    }
    fsid_t fsid;
    fsid.val[0] = fsid0;
    fsid.val[1] = fsid1;
    ssize_t rc = fsgetpath(buf, len, &fsid, obj_id);
    if (rc < 0) {
        return errno ? errno : -1;
    }
    buf[len - 1] = '\0';
    return 0;
}

int afuse_can_write(const char *path) {
    if (!path || access(path, W_OK) != 0) {
        return errno ? errno : EACCES;
    }
    return 0;
}

void afuse_freeze_kill_reap_pgid(int pgid) {
    if (pgid <= 1) {
        return;
    }
    (void)kill(-(pid_t)pgid, SIGSTOP);
    (void)kill(-(pid_t)pgid, SIGKILL);
    int status = 0;
    while (waitpid(-(pid_t)pgid, &status, 0) > 0) {
    }
    for (int i = 0; i < 40 && kill(-(pid_t)pgid, SIGKILL) == 0; i++) {
        usleep(1000);
    }
}
