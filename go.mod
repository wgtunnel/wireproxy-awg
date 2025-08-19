module github.com/wgtunnel/wireproxy-awg

go 1.25

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	github.com/amnezia-vpn/amneziawg-go v0.2.13
	github.com/go-ini/ini v1.67.0
	github.com/things-go/go-socks5 v0.0.6
	golang.org/x/net v0.43.0
)

require (
	github.com/google/btree v1.1.3 // indirect
	github.com/tevino/abool v1.2.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/time v0.9.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gvisor.dev/gvisor v0.0.0-20250816195534-fc2f4df6597a // indirect
)

replace github.com/amnezia-vpn/amneziawg-go => github.com/wgtunnel/amneziawg-go v0.0.0-20250819013046-a4a71a3dba5c
