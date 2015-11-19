#include "nc_common.h"
#include "nc_libbb.h"
#include <sys/time.h>
#include <sys/syscall.h>

static void signal_handler(int sig);

/* Like strncpy but make sure the resulting string is always 0 terminated. */
char* safe_strncpy(char *dst, const char *src, size_t size)
{
    if (!size) return dst;
    dst[--size] = '\0';
    return strncpy(dst, src, size);
}

/* Wrapper which restarts poll on EINTR or ENOMEM.
 * On other errors does perror("poll") and returns.
 * Warning! May take longer than timeout_ms to return! */
int safe_poll(struct pollfd *ufds, nfds_t nfds, int timeout)
{
    while (1)
    {
        int n = poll(ufds, nfds, timeout);
        if (n >= 0)
            return n;
        /* Make sure we inch towards completion */
        if (timeout > 0)
            timeout--;
        /* E.g. strace causes poll to return this */
        if (errno == EINTR)
            continue;
        /* Kernel is very low on memory. Retry. */
        /* I doubt many callers would handle this correctly! */
        if (errno == ENOMEM)
            continue;
        return n;
    }
}


ssize_t safe_write(int fd, const void *buf, size_t count)
{
    ssize_t n;

    do
    {
        n = write(fd, buf, count);
    }
    while (n < 0 && errno == EINTR);

    return n;
}

ssize_t safe_read(int fd, void *buf, size_t count)
{
    ssize_t n;

    do
    {
        n = read(fd, buf, count);
    }
    while (n < 0 && errno == EINTR);

    return n;
}


void* xzalloc(size_t size)
{
    void *ptr = malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

void get_mono(struct timespec *ts)
{
    if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
        memset((char*)ts,0,sizeof(struct timespec));
}

unsigned long long monotonic_ms(void)
{
    struct timespec ts;
    get_mono(&ts);
    return ts.tv_sec * 1000ULL + ts.tv_nsec/1000000;
}

unsigned monotonic_sec(void)
{
    struct timespec ts;
    get_mono(&ts);
    return ts.tv_sec;
}


int ioctl_or_perror(int fd, unsigned request, void *argp, const char *fmt,...)
{
    //va_list p;
    int ret = ioctl(fd, request, argp);

    if (ret < 0)
    {
        //va_start(p, fmt);
        //bb_verror_msg(fmt, p, strerror(errno));
        //va_end(p);
    }
    return ret;
}

int bb_ioctl_or_warn(int fd, unsigned request, void *argp)
{
    int ret;

    ret = ioctl(fd, request, argp);

    return ret;
}

char* strncpy_IFNAMSIZ(char *dst, const char *src)
{
#ifndef IFNAMSIZ
    enum { IFNAMSIZ = 16 };
#endif
    return strncpy(dst, src, IFNAMSIZ);
}

static struct fd_pair signal_pipe;

static void signal_handler(int sig)
{
    unsigned char ch = sig; /* use char, avoid dealing with partial writes */
    write(signal_pipe.wr, &ch, 1);
}

int ndelay_on(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int ndelay_off(int fd)
{
    return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
}

int close_on_exec_on(int fd)
{
    return fcntl(fd, F_SETFD, FD_CLOEXEC);
}

void bb_signals(int sigs, void (*f)(int))
{
    int sig_no = 0;
    int bit = 1;

    while (sigs)
    {
        if (sigs & bit)
        {
            sigs &= ~bit;
            signal(sig_no, f);
        }
        sig_no++;
        bit <<= 1;
    }
}

void xpipe(int filedes[2])
{
    pipe(filedes);
}

/* Call this before doing anything else. Sets up the socket pair
 * and installs the signal handler */
void udhcp_sp_setup(void)
{
    /* was socketpair, but it needs AF_UNIX in kernel */
    xpiped_pair(signal_pipe);
    close_on_exec_on(signal_pipe.rd);
    close_on_exec_on(signal_pipe.wr);
    ndelay_on(signal_pipe.wr);
    bb_signals(0
               + (1 << SIGUSR1)
               + (1 << SIGUSR2)
               + (1 << SIGTERM)
               , signal_handler);
}


/* Quick little function to setup the rfds. Will return the
 * max_fd for use with select. Limited in that you can only pass
 * one extra fd */
int udhcp_sp_fd_set(fd_set *rfds, int extra_fd)
{
    FD_ZERO(rfds);
    FD_SET(signal_pipe.rd, rfds);
    if (extra_fd >= 0)
    {
        close_on_exec_on(extra_fd);
        FD_SET(extra_fd, rfds);
    }
    return signal_pipe.rd > extra_fd ? signal_pipe.rd : extra_fd;
}


/* Read a signal from the signal pipe. Returns 0 if there is
 * no signal, -1 on error (and sets errno appropriately), and
 * your signal on success */
int udhcp_sp_read(const fd_set *rfds)
{
    unsigned char sig;

    if (!FD_ISSET(signal_pipe.rd, rfds))
        return 0;

    if (safe_read(signal_pipe.rd, &sig, 1) != 1)
        return -1;

    return sig;
}

