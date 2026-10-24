# Safety and scope

NetSentry's initial release performs only an explicitly requested TLS connection to the host and port supplied on the command line. It validates certificates using the operating system/Python trust store and reports certificate metadata. It does not discover hosts, scan port ranges, authenticate, send application requests, change services, or alter server configuration.

Only check systems you own or are authorized to assess. A successful TLS handshake confirms certificate validation at check time; it does not establish that the service or host is otherwise secure.


Phase 4 adds an explicit, approval-hash-gated Caddy route executor. It stages and validates the proposed file, makes a timestamped backup, atomically replaces the Caddyfile, reloads Caddy, checks HTTPS routes, records the outcome, and attempts rollback on reload or connectivity failure. It is limited to Caddy route additions; it does not execute Docker or firewall changes. Execution was not run on the project owner’s Pi during development.
