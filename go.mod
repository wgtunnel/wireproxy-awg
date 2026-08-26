module github.com/wgtunnel/wireproxy-awg

go 1.27.0

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/amnezia-vpn/amneziawg-go/v3 v3.0.3
	github.com/go-ini/ini v1.67.0
	github.com/miekg/dns v1.1.72
	github.com/things-go/go-socks5 v0.1.0
	golang.org/x/net v0.57.0
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => github.com/wgtunnel/amneziawg-go/v3 v3.0.0-20260826061744-01780d1dd3b8
