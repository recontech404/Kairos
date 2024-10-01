package types

const (
	// ****** Shared Encryption Library Data ****** //
	SSL_TLS_Base_Path = "/usr/lib/"

	// ****** Uprobe SSL captures ****** //
	Libssl_lib = "libssl.so*"

	Handle_entry_ssl_write  = "handle_entry_SSL_write"
	Handle_ret_ssl_write    = "handle_ret_SSL_write"
	SSL_write_offset_symbol = "SSL_write"
	SSL_write_header        = "SSL Write"

	Handle_entry_ssl_read  = "handle_entry_SSL_read"
	Handle_ret_ssl_read    = "handle_ret_SSL_read"
	SSL_read_offset_symbol = "SSL_read"
	SSL_read_header        = "SSL Read"

	// ******* Uprobe GnuTLS ********* //
	Gnutls_lib = "libgnutls.so*"

	Handle_entry_gnu_send  = "handle_entry_gnu_send"
	Handle_ret_gnu_send    = "handle_ret_gnu_send"
	Gnu_send_offset_symbol = "gnutls_record_send"
	Gnu_send_header        = "GNUTLS Send"

	Handle_entry_gnu_read  = "handle_entry_gnu_recv"
	Handle_ret_gnu_read    = "handle_ret_gnu_recv"
	Gnu_read_offset_symbol = "gnutls_record_recv"
	Gnu_recv_header        = "GNUTLS Recv"

	// ******* Uprobe NSS ****** //
	NSS_lib = "libnspr*.so*"

	Handle_entry_nss_write  = "handle_entry_nss_write"
	Handle_ret_nss_write    = "handle_ret_nss_write"
	NSS_write_offset_symbol = "PR_Write"
	NSS_write_header        = "NSS Write"

	Handle_entry_nss_read  = "handle_entry_nss_read"
	Handle_ret_nss_read    = "handle_ret_nss_read"
	NSS_read_offset_symbol = "PR_Read"
	NSS_read_header        = "NSS Read"

	Handle_entry_nss_recv  = "handle_entry_nss_recv"
	Handle_ret_nss_recv    = "handle_ret_nss_recv"
	NSS_recv_offset_symbol = "PR_RecvFrom"
	NSS_recv_header        = "NSS Recv"
)

var EBPFUprobeMap = map[string]map[string]string{
	Libssl_lib: {
		Handle_entry_ssl_write: SSL_write_offset_symbol,
		Handle_entry_ssl_read:  SSL_read_offset_symbol,
	},
	Gnutls_lib: {
		Handle_entry_gnu_send: Gnu_send_offset_symbol,
		Handle_entry_gnu_read: Gnu_read_offset_symbol,
	},
	NSS_lib: {
		Handle_entry_nss_write: NSS_write_offset_symbol,
		Handle_entry_nss_read:  NSS_read_offset_symbol,
		Handle_entry_nss_recv:  NSS_recv_offset_symbol,
	},
}

var EBPFUretprobeMap = map[string]map[string]string{
	Libssl_lib: {
		Handle_ret_ssl_write: SSL_write_offset_symbol,
		Handle_ret_ssl_read:  SSL_read_offset_symbol,
	},
	Gnutls_lib: {
		Handle_ret_gnu_send: Gnu_send_offset_symbol,
		Handle_ret_gnu_read: Gnu_read_offset_symbol,
	},
	NSS_lib: {
		Handle_ret_nss_write: NSS_write_offset_symbol,
		Handle_ret_nss_read:  NSS_read_offset_symbol,
		Handle_ret_nss_recv:  NSS_recv_offset_symbol,
	},
}

var NumberToSSLHeaderMap = map[int]string{
	1: SSL_write_header,
	2: SSL_read_header,
	3: Gnu_send_header,
	4: Gnu_recv_header,
	5: NSS_write_header,
	6: NSS_read_header,
	7: NSS_recv_header,
}
