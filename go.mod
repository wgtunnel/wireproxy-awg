module github.com/wgtunnel/wireproxy-awg

go 1.27.0

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/amnezia-vpn/amneziawg-go/v3 v3.0.3
	github.com/miekg/dns v1.1.73
	github.com/things-go/go-socks5 v0.1.3
	golang.org/x/net v0.62.0
	gopkg.in/ini.v1 v1.67.3
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c // indirect
)

replace github.com/amnezia-vpn/amneziawg-go/v3 => github.com/wgtunnel/amneziawg-go/v3 v3.0.0-20260926105223-c434976f60d4
