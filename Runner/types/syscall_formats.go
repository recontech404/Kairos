package types

type (
	CheckParamType struct {
		ParamType uint64
		Pid       uint32
		PPid      uint32
	}

	MkdirData struct {
		Pathname [256]byte
	}

	OpenatData struct {
		Pathname [256]byte
		Flags    uint64
	}

	ForkData struct {
		//empty struct for now
	}

	PrctlData struct {
		Option uint64
		Arg2   uint64
		Arg3   uint64
		Arg4   uint64
		Arg5   uint64
	}

	GetpidData struct {
		//empty for now
	}

	GetPPidData struct {
		//empty for now
	}

	ExecveData struct {
		Filename [256]byte
		Argv     [4096]byte
		Envp     [256]byte
	}

	ReadData struct {
		Fd    uint64
		Buf   [256]byte
		Count uint64
	}

	ReadlinkData struct {
		Path   [256]byte
		Buf    [256]byte
		Bufsiz uint64
	}

	UnlinkData struct {
		Pathname [256]byte
	}

	WriteData struct {
		Fd    uint64
		Buf   [256]byte
		Count uint64
	}

	RenameatData struct {
		Olddfd  uint64
		Oldname [256]byte
		Newdfd  uint64
		Newname [256]byte
	}

	FcntlData struct {
		Fd  uint64
		Cmd uint64
		Arg uint64
	}

	SocketData struct {
		Family   uint64
		Type     uint64
		Protocol uint64
	}

	GetSockOptData struct {
		Fd      uint64
		Level   uint64
		Optname uint64
		Optval  [256]byte
		Optlen  uint64
	}

	BindData struct {
		Fd      uint64
		IP      uint32
		Port    uint16
		Addrlen uint64
		IP6     [16]byte
	}

	ConnectData struct {
		Fd      uint64
		IP      uint32
		Port    uint16
		Addrlen uint64
		IP6     [16]byte
	}

	SendToData struct {
		Fd       uint64
		Len      uint64
		Flags    uint64
		IP       uint32
		Port     uint16
		Addr_len uint64
		IP6      [16]byte
	}

	RecvFromData struct {
		Fd       uint64
		Size     uint64
		Flags    uint64
		IP       uint32
		Port     uint16
		Addr_len uint64
		IP6      [16]byte
	}

	DNSData struct {
		Len    uint32
		Domain [256]byte
	}

	SSLData struct {
		Tid      uint32
		Data     [4096]byte
		Data_len uint32
	}
)
