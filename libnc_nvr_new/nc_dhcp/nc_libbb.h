#ifndef nc_libbb_h
#define nc_libbb_h 1

void xpipe(int filedes[2]);

/* In this form code with pipes is much more readable */
struct fd_pair
{
    int rd;
    int wr;
};

#define piped_pair(pair) pipe(&((pair).rd))
#define xpiped_pair(pair) xpipe(&((pair).rd))

char* safe_strncpy(char *dst, const char *src, size_t size);

int safe_poll(struct pollfd *ufds, nfds_t nfds, int timeout);

ssize_t safe_read(int fd, void *buf, size_t count);

ssize_t safe_write(int fd, const void *buf, size_t count);

void* xzalloc(size_t size);

unsigned long long monotonic_ms(void);

unsigned monotonic_sec(void);

int ioctl_or_perror(int fd, unsigned request, void *argp, const char *fmt,...) __attribute__ ((format (printf, 4, 5)));

int bb_ioctl_or_warn(int fd, unsigned request, void *argp);

#define ioctl_or_warn(fd,request,argp) bb_ioctl_or_warn(fd,request,argp,#request)

char* strncpy_IFNAMSIZ(char *dst, const char *src);

int ndelay_on(int fd);

int ndelay_off(int fd);

int close_on_exec_on(int fd);

void bb_signals(int sigs, void (*f)(int));


void udhcp_sp_setup(void);

int udhcp_sp_fd_set(fd_set *rfds, int extra_fd);

int udhcp_sp_read(const fd_set *rfds);

#endif
