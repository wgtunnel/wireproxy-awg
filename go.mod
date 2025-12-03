module github.com/wgtunnel/wireproxy-awg

go 1.25.1

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/amnezia-vpn/amneziawg-go v0.2.16
	github.com/go-ini/ini v1.67.0
	github.com/miekg/dns v1.1.68
	github.com/things-go/go-socks5 v0.1.0
	golang.org/x/net v0.47.0
)

require (
	github.com/google/btree v1.1.3 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20231202080848-1f7806d17489 // indirect
)

replace github.com/amnezia-vpn/amneziawg-go => github.com/wgtunnel/amneziawg-go v0.0.0-20251203041619-ce7e843a4cef
