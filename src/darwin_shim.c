#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
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

extern char **environ;

#define AFUSE_MAX_REMOVE_DEPTH 128

int afuse_clonefile_nofollow(const char *src, const char *dst) {
    if (!src || !dst) {
        return EINVAL;
    }
    if (clonefile(src, dst, CLONE_NOFOLLOW) == 0) {
        return 0;
    }
    return errno ? errno : -1;
}

int afuse_swap_paths(const char *path_a, const char *path_b) {
    if (!path_a || !path_b) {
        return EINVAL;
    }
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
    if (!path) {
        return EINVAL;
    }
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
    if (!path) {
        return EINVAL;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno ? errno : -1;
    }
    if (ino) *ino = (uint64_t)st.st_ino;
    if (mode) *mode = (uint32_t)st.st_mode;
    return 0;
}

int afuse_chmod_nofollow(const char *path, uint32_t mode) {
    if (!path) {
        return EINVAL;
    }
    mode_t clean = (mode_t)(mode & 0777);
    int fd = open(path, O_EVTONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        struct stat st;
        int rc = 0;
        if (fstat(fd, &st) != 0) {
            rc = errno ? errno : -1;
        } else if (S_ISLNK(st.st_mode)) {
            rc = EINVAL;
        } else if (fchmod(fd, clean) != 0) {
            rc = errno ? errno : -1;
        }
        close(fd);
        return rc;
    }
    if (errno == ELOOP) {
        return EINVAL;
    }
    if (errno == ENOENT) {
        return ENOENT;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno ? errno : -1;
    }
    if (S_ISLNK(st.st_mode)) {
        return EINVAL;
    }
    if (fchmodat(AT_FDCWD, path, clean, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno ? errno : -1;
    }
    return 0;
}

static void afuse_unlock_at(int dirfd, const char *name) {
    int fd = openat(dirfd, name, O_EVTONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))) {
            if ((st.st_flags & UF_IMMUTABLE) != 0) {
                (void)fchflags(fd, st.st_flags & ~((uint32_t)UF_IMMUTABLE));
            }
            mode_t writable = (st.st_mode & 0777) | S_IWUSR | S_IRUSR;
            if (S_ISDIR(st.st_mode)) {
                writable |= S_IXUSR;
            }
            (void)fchmod(fd, writable);
        }
        close(fd);
        return;
    }
    if (errno == ELOOP) {
        return;
    }
    struct stat st;
    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) {
        return;
    }
    if (dirfd == AT_FDCWD && (st.st_flags & UF_IMMUTABLE) != 0) {
        (void)lchflags(name, st.st_flags & ~((uint32_t)UF_IMMUTABLE));
    }
    mode_t writable = (st.st_mode & 0777) | S_IWUSR | S_IRUSR;
    if (S_ISDIR(st.st_mode)) {
        writable |= S_IXUSR;
    }
    (void)fchmodat(dirfd, name, writable, AT_SYMLINK_NOFOLLOW);
}

int afuse_force_unlock_path(const char *path) {
    if (!path) {
        return EINVAL;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno ? errno : -1;
    }
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
        return 0;
    }
    afuse_unlock_at(AT_FDCWD, path);
    return 0;
}

static int afuse_remove_dir_fd(int dirfd, int depth) {
    if (depth >= AFUSE_MAX_REMOVE_DEPTH) {
        close(dirfd);
        return ELOOP;
    }
    DIR *dir = fdopendir(dirfd);
    if (!dir) {
        int err = errno ? errno : -1;
        close(dirfd);
        return err;
    }
    int first_err = 0;
    struct dirent *ent;
    for (;;) {
        errno = 0;
        ent = readdir(dir);
        if (ent == NULL) {
            if (errno != 0 && first_err == 0) {
                first_err = errno;
            }
            break;
        }
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        struct stat cst;
        if (fstatat(dirfd, ent->d_name, &cst, AT_SYMLINK_NOFOLLOW) != 0) {
            if (errno == ENOENT) {
                continue;
            }
            if (first_err == 0) first_err = errno ? errno : -1;
            continue;
        }
        if (S_ISDIR(cst.st_mode)) {
            afuse_unlock_at(dirfd, ent->d_name);
            int cfd = openat(dirfd, ent->d_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (cfd < 0) {
                if (errno == ENOENT) continue;
                if (first_err == 0) first_err = errno ? errno : -1;
                continue;
            }
            int rc = afuse_remove_dir_fd(cfd, depth + 1);
            if (rc != 0 && first_err == 0) {
                first_err = rc;
            }
            if (unlinkat(dirfd, ent->d_name, AT_REMOVEDIR) != 0 && errno != ENOENT) {
                if (first_err == 0) first_err = errno ? errno : -1;
            }
        } else {
            if (S_ISREG(cst.st_mode)) {
                afuse_unlock_at(dirfd, ent->d_name);
            }
            if (unlinkat(dirfd, ent->d_name, 0) != 0 && errno != ENOENT) {
                if (first_err == 0) first_err = errno ? errno : -1;
            }
        }
    }
    closedir(dir);
    return first_err;
}

int afuse_remove_all_nofollow(const char *path) {
    if (!path) {
        return EINVAL;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return errno ? errno : -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (S_ISREG(st.st_mode)) {
            afuse_unlock_at(AT_FDCWD, path);
        }
        if (unlink(path) != 0 && errno != ENOENT) {
            return errno ? errno : -1;
        }
        return 0;
    }
    afuse_unlock_at(AT_FDCWD, path);
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return errno ? errno : -1;
    }
    int rc = afuse_remove_dir_fd(fd, 0);
    if (rc != 0) {
        return rc;
    }
    if (rmdir(path) != 0 && errno != ENOENT) {
        return errno ? errno : -1;
    }
    return 0;
}

static int afuse_open_and_flock(const char *lock_path, int flock_op, int *out_fd) {
    if (!lock_path || !out_fd) {
        return EINVAL;
    }
    int max_attempts = (flock_op & LOCK_NB) ? 4 : 16;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        int fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            return errno ? errno : -1;
        }
        struct stat st;
        if (fstat(fd, &st) != 0) {
            int err = errno ? errno : -1;
            close(fd);
            return err;
        }
        if (!S_ISREG(st.st_mode)) {
            close(fd);
            return EINVAL;
        }
        if (st.st_uid != geteuid()) {
            close(fd);
            return EPERM;
        }
        while (flock(fd, flock_op) != 0) {
            if (errno == EINTR) {
                continue;
            }
            int err = errno ? errno : EWOULDBLOCK;
            close(fd);
            return err;
        }
        struct stat path_st;
        if (lstat(lock_path, &path_st) == 0
            && path_st.st_dev == st.st_dev
            && path_st.st_ino == st.st_ino) {
            *out_fd = fd;
            return 0;
        }
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
    return (flock_op & LOCK_NB) ? EWOULDBLOCK : ENOENT;
}

int afuse_acquire_flock(const char *lock_path, int *out_fd) {
    return afuse_open_and_flock(lock_path, LOCK_EX, out_fd);
}

int afuse_try_acquire_flock(const char *lock_path, int *out_fd) {
    return afuse_open_and_flock(lock_path, LOCK_EX | LOCK_NB, out_fd);
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
    uid_t uid = getuid();
    struct passwd pwd;
    struct passwd *res = NULL;
    size_t pw_len = 4096;
    char *pw_buf = (char *)malloc(pw_len);
    if (!pw_buf) {
        return ENOMEM;
    }
    int rc = 0;
    for (int i = 0; i < 4; i++) {
        rc = getpwuid_r(uid, &pwd, pw_buf, pw_len, &res);
        if (rc != ERANGE) {
            break;
        }
        pw_len *= 2;
        char *grown = (char *)realloc(pw_buf, pw_len);
        if (!grown) {
            free(pw_buf);
            return ENOMEM;
        }
        pw_buf = grown;
    }
    if (rc != 0 || !res || !res->pw_dir || res->pw_dir[0] == '\0') {
        free(pw_buf);
        return rc != 0 ? rc : ENOENT;
    }
    size_t dlen = strlen(res->pw_dir);
    if (dlen + 1 > len) {
        free(pw_buf);
        return ERANGE;
    }
    memcpy(buf, res->pw_dir, dlen + 1);
    free(pw_buf);
    return 0;
}

static char **afuse_build_guarded_env(void) {
    size_t count = 0;
    if (environ) {
        while (environ[count] != NULL) {
            count++;
        }
    }
    char **envp = (char **)calloc(count + 2, sizeof(char *));
    if (!envp) {
        return NULL;
    }
    size_t out_idx = 0;
    for (size_t i = 0; i < count; i++) {
        if (strncmp(environ[i], "AFUSE_GUARDED=", 14) == 0) {
            continue;
        }
        envp[out_idx++] = environ[i];
    }
    envp[out_idx++] = (char *)"AFUSE_GUARDED=1";
    envp[out_idx] = NULL;
    return envp;
}

int afuse_spawn_in_new_pgroup(const char *const argv[], const char *cwd, int *out_pid) {
    if (!argv || !argv[0] || !out_pid) {
        return EINVAL;
    }
    char **envp = afuse_build_guarded_env();
    if (!envp) {
        return ENOMEM;
    }
    posix_spawnattr_t attr;
    int rc = posix_spawnattr_init(&attr);
    if (rc != 0) {
        free(envp);
        return rc;
    }
    rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
    if (rc == 0) {
        rc = posix_spawnattr_setpgroup(&attr, 0);
    }
    posix_spawn_file_actions_t actions;
    int has_actions = 0;
    if (rc == 0 && cwd != NULL && cwd[0] != '\0') {
        rc = posix_spawn_file_actions_init(&actions);
        if (rc == 0) {
            has_actions = 1;
            rc = posix_spawn_file_actions_addchdir_np(&actions, cwd);
        }
    }
    pid_t pid = 0;
    if (rc == 0) {
        rc = posix_spawnp(
            &pid,
            argv[0],
            has_actions ? &actions : NULL,
            &attr,
            (char *const *)argv,
            envp
        );
    }
    if (has_actions) {
        posix_spawn_file_actions_destroy(&actions);
    }
    posix_spawnattr_destroy(&attr);
    free(envp);
    if (rc != 0) {
        return rc;
    }
    *out_pid = (int)pid;
    return 0;
}

int afuse_try_wait_pid(int pid, int *out_exited, int *out_code) {
    if (pid <= 0 || !out_exited || !out_code) {
        return EINVAL;
    }
    int status = 0;
    pid_t rc;
    do {
        rc = waitpid((pid_t)pid, &status, WNOHANG);
    } while (rc < 0 && errno == EINTR);
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
    if (!path) {
        return EINVAL;
    }
    if (access(path, W_OK) != 0) {
        return errno ? errno : EACCES;
    }
    return 0;
}

int afuse_can_read_write(const char *path) {
    if (!path) {
        return EINVAL;
    }
    if (access(path, R_OK | W_OK) != 0) {
        return errno ? errno : EACCES;
    }
    return 0;
}

unsigned int afuse_current_euid(void) {
    return (unsigned int)geteuid();
}

int afuse_pgid_disk_bytes_written(int pgid, uint64_t *out_bytes) {
    if (pgid <= 1 || !out_bytes) {
        return EINVAL;
    }
    *out_bytes = 0;
    pid_t pids[256];
    int bytes = proc_listpgrppids((pid_t)pgid, pids, (int)sizeof(pids));
    if (bytes <= 0) {
        return 0;
    }
    int count = bytes / (int)sizeof(pid_t);
    uint64_t total = 0;
    for (int i = 0; i < count; i++) {
        if (pids[i] <= 0) {
            continue;
        }
        struct rusage_info_v4 ri;
        memset(&ri, 0, sizeof(ri));
        if (proc_pid_rusage(pids[i], RUSAGE_INFO_V4, (rusage_info_t *)&ri) == 0) {
            uint64_t w = ri.ri_diskio_byteswritten;
            if (UINT64_MAX - total < w) {
                total = UINT64_MAX;
            } else {
                total += w;
            }
        }
    }
    *out_bytes = total;
    return 0;
}

int afuse_pgid_alive(int pgid) {
    if (pgid <= 1) {
        return 0;
    }
    if (kill(-(pid_t)pgid, 0) == 0) {
        return 1;
    }
    return errno == EPERM ? 1 : 0;
}

void afuse_freeze_kill_reap_pgid(int pgid) {
    if (pgid <= 1) {
        return;
    }
    (void)kill(-(pid_t)pgid, SIGSTOP);
    (void)kill(-(pid_t)pgid, SIGKILL);
    int status = 0;
    for (;;) {
        pid_t w = waitpid(-(pid_t)pgid, &status, 0);
        if (w > 0) {
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    for (int i = 0; i < 40 && kill(-(pid_t)pgid, SIGKILL) == 0; i++) {
        usleep(1000);
    }
}
