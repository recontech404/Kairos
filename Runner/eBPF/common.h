//tracepoints can be found at /sys/kernel/tracing/events/syscalls

#ifndef __MSG_H__
#define __MSG_H__

#define MAX_DATA_SIZE 4096
#define ARGSIZE  128

struct mkdir_event_t {
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;
    
    char pathname[256];
};

struct openat_event_t {
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    char filename[256];
    u64 flags;
};

struct fork_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;
};

struct prctl_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 option;
    u64 arg2;
    u64 arg3;
    u64 arg4; 
    u64 arg5;
};

struct getpid_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;
};

struct getppid_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;
};

struct execve_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    char filename[256];
    char argv[256];
    char envp[MAX_DATA_SIZE];
    u32 args_size;
};

struct read_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    char buf[256];
    u64 count;    
};

struct readlink_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    char path[256];
    char buf[256];
    u64 bufsiz;
};

struct unlink_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    char pathname[256];
};

struct write_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    char buf[256];
    u64 count;
};

struct renameat_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 olddfd;
    char oldname[256];
    u64 newdfd;
    char newname[256];
};

struct fcntl_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u64 cmd;
    u64 arg;
};

struct socket_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 family;
    u64 type;
    u64 protocol;
};

struct getsockopt_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u64 level;
    u64 optname;
    char optval[256];
    u64 optlen;
};

struct bind_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u32 ip;
    u16 port;
    u64 addrlen;
    
    char ip6[16];
};

struct connect_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u32 ip;
    u16 port;
    u64 addrlen;

    char ip6[16];
};

struct sendto_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u64 len;
    u64 flags;
    u32 ip;
    u16 port;
    u64 addr_len;

    char ip6[16];
};

struct recvfrom_event_t{ 
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u64 fd;
    u64 size;
    u64 flags;
    u32 ip;
    u16 port;
    u64 addr_len;

    char ip6[16];
};

struct dns_event_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u32 len;
    char domain[256];
};


// SSL data
struct ssl_data_t{
    u64 paramtype;
    u32 host_pid;
    u32 host_ppid;

    u32 tid;
    char data[MAX_DATA_SIZE];
    u32 data_len;
};

#endif // __MSG_H__