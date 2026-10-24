# Safety and scope

NetSentry's initial release performs only an explicitly requested TLS connection to the host and port supplied on the command line. It validates certificates using the operating system/Python trust store and reports certificate metadata. It does not discover hosts, scan port ranges, authenticate, send application requests, change services, or alter server configuration.

Only check systems you own or are authorized to assess. A successful TLS handshake confirms certificate validation at check time; it does not establish that the service or host is otherwise secure.
