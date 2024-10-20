//go:build amd64

package types

const (
	Sys_enter_mkdir = "sys_enter_mkdir" //tracepoint
	Handle_mkdir    = "handle_mkdir"    //ebpf program name

	Sys_enter_openat = "sys_enter_openat"
	Handle_Openat    = "handle_openat"

	Sys_enter_fork = "sys_enter_fork"
	Handle_fork    = "handle_fork"

	Sys_enter_prctl = "sys_enter_prctl"
	Handle_prctl    = "handle_prctl"

	Sys_enter_getpid = "sys_enter_getpid"
	Handle_getpid    = "handle_getpid"

	Sys_enter_getppid = "sys_enter_getppid"
	Handle_getppid    = "handle_getppid"

	Sys_enter_execve = "sys_enter_execve"
	Handle_execve    = "handle_execve"

	Sys_enter_read = "sys_enter_read"
	Handle_read    = "handle_read"

	Sys_enter_readlink = "sys_enter_readlink"
	Handle_readlink    = "handle_readlink"

	Sys_enter_unlink = "sys_enter_unlink"
	Handle_unlink    = "handle_unlink"

	Sys_enter_unlinkat = "sys_enter_unlinkat"
	Handle_unlink_at   = "handle_unlinkat"

	Sys_enter_write = "sys_enter_write"
	Handle_write    = "handle_write"

	Sys_enter_renameat = "sys_enter_renameat2"
	Handle_renameat    = "handle_renameat2"

	Sys_enter_fcntl = "sys_enter_fcntl"
	Handle_fcntl    = "handle_fcntl"

	Sys_enter_socket = "sys_enter_socket"
	Handle_socket    = "handle_socket"

	Sys_enter_getsockopt = "sys_enter_getsockopt"
	Handle_getsockopt    = "handle_getsockopt"

	Sys_enter_bind = "sys_enter_bind"
	Handle_bind    = "handle_bind"

	Sys_enter_connect = "sys_enter_connect"
	Handle_connect    = "handle_connect"

	Sys_enter_sendto = "sys_enter_sendto"
	Handle_sendto    = "handle_sendto"

	Sys_enter_recvfrom = "sys_enter_recvfrom"
	Handle_recvfrom    = "handle_recvfrom"

	Net_dev_queue = "net_dev_queue"
	Handle_dns    = "handle_dns"
)

var EBPFProgramToTracepoint = map[string]string{
	Handle_mkdir:     Sys_enter_mkdir,
	Handle_Openat:    Sys_enter_openat,
	Handle_fork:      Sys_enter_fork,
	Handle_prctl:     Sys_enter_prctl,
	Handle_getpid:    Sys_enter_getpid,
	Handle_getppid:   Sys_enter_getppid,
	Handle_execve:    Sys_enter_execve,
	Handle_read:      Sys_enter_read,
	Handle_readlink:  Sys_enter_readlink,
	Handle_unlink:    Sys_enter_unlink,
	Handle_unlink_at: Sys_enter_unlinkat,
	Handle_write:     Sys_enter_write,
	Handle_renameat:  Sys_enter_renameat,
	// Handle_fcntl: Sys_enter_fcntl, //remove as no real information is used for LLM
	Handle_socket:     Sys_enter_socket,
	Handle_getsockopt: Sys_enter_getsockopt,
	Handle_bind:       Sys_enter_bind,
	Handle_connect:    Sys_enter_connect,
	Handle_sendto:     Sys_enter_sendto,
	Handle_recvfrom:   Sys_enter_recvfrom,
}

// map to parse incoming ebpf events to the proper data struct
var NumberToSysMap = map[int]string{
	1:  Sys_enter_mkdir,
	2:  Sys_enter_openat,
	3:  Sys_enter_fork,
	4:  Sys_enter_prctl,
	5:  Sys_enter_getpid,
	6:  Sys_enter_getppid,
	7:  Sys_enter_execve,
	8:  Sys_enter_read,
	9:  Sys_enter_readlink,
	10: Sys_enter_unlink,
	11: Sys_enter_write,
	12: Sys_enter_renameat,
	13: Sys_enter_fcntl,
	14: Sys_enter_socket,
	15: Sys_enter_getsockopt,
	16: Sys_enter_bind,
	17: Sys_enter_connect,
	18: Sys_enter_sendto,
	19: Sys_enter_recvfrom,
	20: Net_dev_queue,
}
