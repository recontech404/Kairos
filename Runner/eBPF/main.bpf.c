/*
* Copyright 2024 - recontech404
*/

//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1024);
} pid_map SEC(".maps");

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 /* 16 KB */);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 32 * 1024 /* 16 KB */);
} ssl_events SEC(".maps");

/* **********OpenSSL Maps************* */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ssl_data_t);
} data_buffer_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} ssl_write_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} ssl_read_args_map SEC(".maps");
/* **********End SSL Maps *********/

/* **********GnuTLS Maps ************/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} gnu_send_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} gnu_recv_args_map SEC(".maps");
/* **********End GnuTLS Maps*/

/* **********NSS Maps ************/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} nss_write_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} nss_read_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, uint64_t);
    __type(value, char*);
} nss_recv_args_map SEC(".maps");
/* **********NSS Maps*/

struct mkdir_params_t{
    char _[16];
    uint64_t *pathname_ptr;
};

struct mkdirat_params_arm64_t{
    char _[16];
    uint64_t dfd;
    uint64_t *pathname_ptr;
};

struct openat_params_t{
    char _[16];
    uint64_t dfd;
    uint64_t *filename_ptr;
    uint64_t flags;
};

struct fork_params_t{
    //empty struct for now
};

struct prctl_params_t{
    char _[16];
    uint64_t option;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4; 
    uint64_t arg5;
};

struct getpid_params_t{
    //empty for now
};

struct getppid_params_t{
    //empty for now
};

struct execve_params_t{
    char _[16];
    uint64_t *filename_ptr;
    const char *const *argv;
    const char *const *envp;
};

struct read_params_t{
    char _[16];
    uint64_t fd;
    uint64_t *buf_ptr;
    uint64_t count;
};

struct readlink_params_t{
    char _[16];
    uint64_t *path_ptr;
    uint64_t *buf_ptr;
    uint64_t bufsiz;
};

struct readlinkat_params_arm64_t{
    char _[16];
    uint64_t dfd;
    uint64_t *path_ptr;
    uint64_t *buf_ptr;
    uint64_t bufsiz;
};

struct unlink_params_t{
    char _[16];
    uint64_t *pathname_ptr;
};

struct unlinkat_params_arm64_t{
    char _[16];
    uint64_t dfd;
    uint64_t *pathname_ptr;
};

struct write_params_t{
    char _[16];
    uint64_t fd;
    uint64_t buf_ptr;
    uint64_t count;
};

struct renameat_params_t{
    char _[16];
    uint64_t olddfd;
    uint64_t *oldname_ptr;
    uint64_t newdfd;
    uint64_t *newname_ptr;
};

struct fcntl_params_t{
    char _[16];
    uint64_t fd;
    uint64_t cmd;
    uint64_t arg;
};

struct socket_params_t{
    char _[16];
    uint64_t family;
    uint64_t type;
    uint64_t protocol;
};

struct getsockopt_params_t{
    char _[16];
    uint64_t fd;
    uint64_t level;
    uint64_t optname;
    uint64_t *optval_ptr;
    uint64_t optlen;
};

struct bind_params_t{
    char _[16];
    uint64_t fd;
    struct sockaddr *umyaddr; 
    uint64_t addrlen;
};

struct connect_params_t{
    char _[16];
    uint64_t fd;
    struct sockaddr *uservaddr;
    uint64_t addrlen;
};

struct sendto_params_t{
    char _[16];
    uint64_t fd;
    void *buff; 
    uint64_t len;
    uint64_t flags;
    struct sockaddr *addr;
    uint64_t addr_len;
};

struct recvfrom_params_t{
    char _[16];
    uint64_t fd;
    void *ubuf; 
    size_t size;
    uint64_t flags;
    struct sockaddr *addr;
    uint64_t addr_len;
};

struct dns_params_t{
    char _[8];
    uint64_t skbaddr_ptr;
};

struct dns_header {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/

static inline unsigned short ntohs(unsigned short netshort) {
    return (netshort << 8) | (netshort >> 8);
}


SEC("tracepoint/syscalls/sys_enter_mkdir")
int handle_mkdir(struct mkdir_params_t *params) 
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct mkdir_event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

    event->paramtype = 1; //tells Go prog which struct to extract into

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *pathname_ptr = (char *)params->pathname_ptr;    
    bpf_core_read_user_str(&event->pathname, sizeof(event->pathname), pathname_ptr);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_mkdirat(struct mkdirat_params_arm64_t *params) 
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct mkdir_event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct*)bpf_get_current_task();

    event->paramtype = 1; //tells Go prog which struct to extract into

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *pathname_ptr = (char *)params->pathname_ptr;    
    bpf_core_read_user_str(&event->pathname, sizeof(event->pathname), pathname_ptr);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct openat_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct openat_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 2;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *filename_ptr = (char *)params->filename_ptr;
    bpf_core_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);

    event->flags = (u64)params->flags;    
    
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int handle_fork(struct fork_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct fork_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 3;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int handle_prctl(struct prctl_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct prctl_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 4;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->option = (u64)params->option;
    event->arg2 = (u64)params->arg2;
    event->arg3 = (u64)params->arg3;
    event->arg4 = (u64)params->arg4;
    event->arg5 = (u64)params->arg5;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle_getpid(struct getpid_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct getpid_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 5;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int handle_getppid(struct getppid_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct getppid_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 6;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct execve_params_t *params){
    //do not filter on pid for execve to detect new malware

    struct execve_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 7;

    event->host_pid = bpf_get_current_pid_tgid() >> 32;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *filename_ptr = (char *)params->filename_ptr;
    bpf_core_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);

    int ret;
    const char *arg;

    for (int i = 0; i < 60; i++) {
        const char *arg;
        if (bpf_probe_read(&arg, sizeof(arg), &params->argv[i]) < 0 || !arg){
            break; 
        }

        if (event->args_size > MAX_DATA_SIZE - ARGSIZE + 1){ //ensure last byte for null term
            break;
        }

        ret = bpf_probe_read_user_str(&event->argv[event->args_size], ARGSIZE, arg);
        if (ret < 0){
            break;
        }

        event->args_size += ret;

        if (event->args_size < MAX_DATA_SIZE){
            event->argv[event->args_size] = ' '; // add space
            event->args_size++;
        }
    }

    if(event->args_size < MAX_DATA_SIZE){
        event->argv[event->args_size] = '\0'; //null term
    }

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct read_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct read_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 8;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;
    
    char *buf_ptr = (char *)params->buf_ptr;
    bpf_core_read_user_str(&event->buf, sizeof(event->buf), buf_ptr);

    event->count = (u64)params->count;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int handle_readlink(struct readlink_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct readlink_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 9;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *path_ptr = (char *)params->path_ptr;
    bpf_core_read_user_str(&event->path, sizeof(event->path), path_ptr);

    char *buf_ptr = (char *)params->buf_ptr;
    bpf_core_read_user_str(&event->buf, sizeof(event->buf), buf_ptr);

    event->bufsiz = (u64)params->bufsiz;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int handle_readlinkat(struct readlinkat_params_arm64_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct readlink_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 9;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *path_ptr = (char *)params->path_ptr;
    bpf_core_read_user_str(&event->path, sizeof(event->path), path_ptr);

    char *buf_ptr = (char *)params->buf_ptr;
    bpf_core_read_user_str(&event->buf, sizeof(event->buf), buf_ptr);

    event->bufsiz = (u64)params->bufsiz;

    bpf_ringbuf_submit(event, 0);

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct unlink_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct unlink_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 10;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *pathname_ptr = (char *)params->pathname_ptr;
    bpf_core_read_user_str(&event->pathname, sizeof(event->pathname), pathname_ptr);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct unlinkat_params_arm64_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct unlink_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 10;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    char *pathname_ptr = (char *)params->pathname_ptr;
    bpf_core_read_user_str(&event->pathname, sizeof(event->pathname), pathname_ptr);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct write_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct write_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 11;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;

    char *buf_ptr = (char *)params->buf_ptr;
    bpf_core_read_user_str(&event->buf, sizeof(event->buf), buf_ptr);

    event->count = (u64)params->count;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct renameat_params_t *params){
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct renameat_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 12;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->olddfd = (u64)params->olddfd;

    char *oldname_ptr = (char *)params->oldname_ptr;
    bpf_core_read_user_str(&event->oldname, sizeof(event->oldname), oldname_ptr);

    event->newdfd = (u64)params->newdfd;

    char *newname_ptr = (char *)params->newname_ptr;
    bpf_core_read_user_str(&event->newname, sizeof(event->newname), newname_ptr);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int handle_fcntl(struct fcntl_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct fcntl_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 13;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;
    event->cmd = (u64)params->cmd;
    event->arg = (u64)params->arg;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_socket(struct socket_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct socket_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 14;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->family = (u64)params->family;
    event->type = (u64)params->type;
    event->protocol = (u64)params->protocol;

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int handle_getsockopt(struct getsockopt_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct getsockopt_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 15;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;
    event->level = (u64)params->level;
    event->optname = (u64)params->optname;

    char *optval_ptr = (char *)params->optval_ptr;
    bpf_core_read_user_str(event->optval, sizeof(event->optval), optval_ptr);
    
    event->optlen = (u64)params->optlen;

    bpf_ringbuf_submit(event, 0);

    return 0;    
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind(struct bind_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct bind_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 16;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;

    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;

    bpf_probe_read(&addr, sizeof(addr), (void *)(params->umyaddr));

    if (addr.sa_family == 2){
        bpf_probe_read(&addr_in, sizeof(addr_in), (void *)params->umyaddr);
        event->ip = addr_in.sin_addr.s_addr;
        event->port = ntohs(addr_in.sin_port);
    } else if (addr.sa_family == 10){
        bpf_probe_read(&addr_in6, sizeof(addr_in6), (void *)params->umyaddr);
        bpf_probe_read(event->ip6, sizeof(event->ip6), addr_in6.sin6_addr.in6_u.u6_addr8);
        event->port = ntohs(addr_in6.sin6_port);
    }

    event->addrlen = (u64)params->addrlen;

    bpf_ringbuf_submit(event, 0);

    return 0;    
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct connect_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct connect_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 17;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;

    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;

    bpf_probe_read(&addr, sizeof(addr), (void *)(params->uservaddr));

    if (addr.sa_family == 2){
        bpf_probe_read(&addr_in, sizeof(addr_in), (void *)params->uservaddr);
        event->ip = addr_in.sin_addr.s_addr;
        event->port = ntohs(addr_in.sin_port);
    } else if (addr.sa_family == 10){
        bpf_probe_read(&addr_in6, sizeof(addr_in6), (void *)params->uservaddr);
        bpf_probe_read(event->ip6, sizeof(event->ip6), addr_in6.sin6_addr.in6_u.u6_addr8);
        event->port = ntohs(addr_in6.sin6_port);
    }

    event->addrlen = (u64)params->addrlen;

    bpf_ringbuf_submit(event, 0);

    return 0;    
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct sendto_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct sendto_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 18;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;
    event->len = (u64)params->len;
    event->flags = (u64)params->flags;

    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;

    bpf_probe_read(&addr, sizeof(addr), (void *)(params->addr));

    if (addr.sa_family == 2){
        bpf_probe_read(&addr_in, sizeof(addr_in), (void *)params->addr);
        event->ip = addr_in.sin_addr.s_addr;
        event->port = ntohs(addr_in.sin_port);
    } else if (addr.sa_family == 10){
        bpf_probe_read(&addr_in6, sizeof(addr_in6), (void *)params->addr);
        bpf_probe_read(event->ip6, sizeof(event->ip6), addr_in6.sin6_addr.in6_u.u6_addr8);
        event->port = ntohs(addr_in6.sin6_port);
    }
    
    event->addr_len = (u64)params->addr_len;

    bpf_ringbuf_submit(event, 0);

    return 0;    
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct recvfrom_params_t *params)
{
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct recvfrom_event_t *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 19;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    event->fd = (u64)params->fd;
    event->size = (u64)params->size;
    event->flags = (u64)params->flags;


    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;

    bpf_probe_read(&addr, sizeof(addr), (void *)(params->addr));

    if (addr.sa_family == 2){
        bpf_probe_read(&addr_in, sizeof(addr_in), (void *)params->addr);
        event->ip = addr_in.sin_addr.s_addr;
        event->port = ntohs(addr_in.sin_port);
    } else if (addr.sa_family == 10){
        bpf_probe_read(&addr_in6, sizeof(addr_in6), (void *)params->addr);
        bpf_probe_read(event->ip6, sizeof(event->ip6), addr_in6.sin6_addr.in6_u.u6_addr8);
        event->port = ntohs(addr_in6.sin6_port);
    }
    
    event->addr_len = (u64)params->addr_len;

    bpf_ringbuf_submit(event, 0);

    return 0;    
}

SEC("tracepoint/net/net_dev_queue")
int handle_dns(struct dns_params_t *ctx){
    uint32_t pid = bpf_get_current_pid_tgid() >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct sk_buff *skb_pointer = (void *)ctx->skbaddr_ptr;
    
    struct sk_buff skb;
    bpf_probe_read(&skb, sizeof(skb), skb_pointer);

    struct iphdr iph;
    bpf_core_read(&iph, sizeof(iph), skb.head + skb.network_header);

    if (skb.protocol != bpf_htons(ETH_P_IP)){
        return 0; //skip non IP packets
    }

    int dns_offset = 0;

    if (iph.protocol == IPPROTO_TCP){
        struct tcphdr tcph;
        bpf_core_read(&tcph, sizeof(tcph), skb.head + skb.transport_header);
        
        if (tcph.source != 13568 && tcph.dest != 13568){ //ntohs(53) = 13568
            return 0; //ignore non dns requests
        }

        dns_offset = sizeof(struct tcphdr);

    } else if (iph.protocol == IPPROTO_UDP){
        struct udphdr udph;
        bpf_core_read(&udph, sizeof(udph), skb.head + skb.transport_header);
        if (udph.source != 13568 && udph.dest != 13568){
            return 0;    
        }
    
        dns_offset = sizeof(struct udphdr);

    } else {
        return 0;
    }

    struct dns_event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(struct dns_event_t), 0);
    if (!event){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->paramtype = 20;

    event->host_pid = pid;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct dns_header dns_hdr;
    bpf_core_read(&dns_hdr, sizeof(dns_hdr), skb.head + skb.transport_header + dns_offset);

    char *question = event->domain;
    int offset = skb.transport_header + dns_offset + sizeof(dns_hdr);
    int len = 0;

    // Read domain name
    for (int i = 0; i < 255; i++) {
        char c;
        bpf_core_read(&c, 1, skb.head + offset + i);
        if (c == 0) {
            question[len++] = '.';
            break;
        }
        if (c < 32) {
            question[len++] = '.';
        } else {
            question[len++] = c;
        }
    }
    question[len] = '\0';

    event->len = len;

    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

/********************************************** 
 *************** OpenSSL Capture Logic ************
 **********************************************
*/

static __inline struct ssl_data_t* create_ssl_data_event(){
    uint32_t kZero = 0;
    struct ssl_data_t* event = bpf_map_lookup_elem(&data_buffer_heap, &kZero);

    if (event == NULL){
        return NULL;
    }

    return event;
}

static int process_SSL_data(struct pt_regs* ctx, uint64_t pid_tgid, uint32_t ppid, uint64_t paramType, const char* buf){
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0){
        return 0;
    }

    struct ssl_data_t* event = create_ssl_data_event();
    if (event == NULL){
        return 0;
    }

    event = bpf_ringbuf_reserve(&ssl_events, sizeof(*event),0);
    if (!event){
        return 0;
    }

    const uint32_t kMask32b = 0xffffffff;
    
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid  & kMask32b;

    event->paramtype= paramType;
    event->host_pid = pid;
    event->host_ppid = ppid;
    event->tid = tid;
    event->data_len = (len < MAX_DATA_SIZE ? (len & (MAX_DATA_SIZE -1)) : MAX_DATA_SIZE);
    bpf_probe_read_user(event->data, event->data_len, buf);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("uprobe/SSL_write_ex")
int handle_entry_SSL_write(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    const char* buf = (const char*)PT_REGS_PARM2(ctx);
    bpf_map_update_elem(&ssl_write_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_write_ex")
int handle_ret_SSL_write(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&ssl_write_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 1, *buf);
    }

    bpf_map_delete_elem(&ssl_write_args_map, &current_pid_tgid);

    return 0;
}

SEC("uprobe/SSL_read_ex")
int handle_entry_SSL_read(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&ssl_read_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_read_ex")
int handle_ret_SSL_read(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&ssl_read_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 2, *buf);
    }

    bpf_map_delete_elem(&ssl_read_args_map, &current_pid_tgid);

    return 0;
}

/************** Gnu TLS *******************/
SEC("uprobe/gnutls_record_send")
int handle_entry_gnu_send(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&gnu_send_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/gnutls_record_send")
int handle_ret_gnu_send(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&gnu_send_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 3, *buf);
    }

    bpf_map_delete_elem(&gnu_send_args_map, &current_pid_tgid);

    return 0;
}


SEC("uprobe/gnutls_record_recv")
int handle_entry_gnu_recv(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&gnu_recv_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/gnutls_record_recv")
int handle_ret_gnu_recv(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&gnu_recv_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 4, *buf);
    }

    bpf_map_delete_elem(&gnu_recv_args_map, &current_pid_tgid);

    return 0;
}


/********* NSS SSL ***********/
SEC("uprobe/PR_Write")
int handle_entry_nss_write(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&nss_write_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/PR_Write")
int handle_ret_nss_write(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();

    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&nss_write_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 5, *buf);
    }

    bpf_map_delete_elem(&nss_write_args_map, &current_pid_tgid);

    return 0;
}

SEC("uprobe/PR_Read")
int handle_entry_nss_read(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&nss_read_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/PR_Read")
int handle_ret_nss_read(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&nss_read_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 6, *buf);
    }

    bpf_map_delete_elem(&nss_read_args_map, &current_pid_tgid);

    return 0;
}

SEC("uprobe/PR_Recv")
int handle_entry_nss_recv(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }

    const char* buf = (const char*)PT_REGS_PARM2(ctx);

    bpf_map_update_elem(&nss_recv_args_map, &current_pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("uretprobe/PR_Recv")
int handle_ret_nss_recv(struct pt_regs* ctx){
    uint64_t current_pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = current_pid_tgid >> 32;

    if(bpf_map_lookup_elem(&pid_map, &pid) == NULL){
        return 0;
    }
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t ppid = BPF_CORE_READ(task, real_parent, tgid);

    const char** buf = bpf_map_lookup_elem(&nss_recv_args_map, &current_pid_tgid);
    if (buf != NULL){
        process_SSL_data(ctx, current_pid_tgid, ppid, 7, *buf);
    }

    bpf_map_delete_elem(&nss_recv_args_map, &current_pid_tgid);

    return 0;
}