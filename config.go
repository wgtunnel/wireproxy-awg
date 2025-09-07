package wireproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/go-ini/ini"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

type ASecConfigType struct {
	junkPacketCount            int    // Jc
	junkPacketMinSize          int    // Jmin
	junkPacketMaxSize          int    // Jmax
	initPacketJunkSize         int    // s1
	responsePacketJunkSize     int    // s2
	initPacketMagicHeader      uint32 // h1
	responsePacketMagicHeader  uint32 // h2
	underloadPacketMagicHeader uint32 // h3
	transportPacketMagicHeader uint32 // h4
	i1                         *string
	i2                         *string
	i3                         *string
	i4                         *string
	i5                         *string
	j1                         *string
	j2                         *string
	j3                         *string
	itime                      *int
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey             string
	Endpoint              []netip.Addr
	Peers                 []PeerConfig
	DNS                   []netip.Addr
	MTU                   int
	ListenPort            *int
	CheckAlive            []netip.Addr
	DomainBlockingEnabled bool
	BlockedDomains        []string
	CheckAliveInterval    int
	ASecConfig            *ASecConfigType
}

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type STDIOTunnelConfig struct {
	Target string
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress string
	Username    string
	Password    string
}

type HTTPConfig struct {
	BindAddress string
	Username    string
	Password    string
}

type Configuration struct {
	Device   *DeviceConfig
	Routines []RoutineSpawner
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	value := key.String()
	if strings.HasPrefix(value, "$") {
		if strings.HasPrefix(value, "$$") {
			return strings.Replace(value, "$$", "$", 1), nil
		}
		var ok bool
		value, ok = os.LookupEnv(strings.TrimPrefix(value, "$"))
		if !ok {
			return "", errors.New(keyName + " references unset environment variable " + key.String())
		}
		return value, nil
	}
	return key.String(), nil
}

func parsePort(section *ini.Section, keyName string) (int, error) {
	key := section.Key(keyName)
	if key == nil {
		return 0, errors.New(keyName + " should not be empty")
	}

	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if !(port >= 0 && port < 65536) {
		return 0, errors.New("port should be >= 0 and < 65536")
	}

	return port, nil
}

func parseTCPAddr(section *ini.Section, keyName string) (*net.TCPAddr, error) {
	addrStr, err := parseString(section, keyName)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", addrStr)
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseStrings(section *ini.Section, keyName string) ([]string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []string{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var result []string
	for _, key := range keys {
		result = append(result, strings.TrimSpace(key))
	}
	return result, nil
}

func parseStringList(section *ini.Section, keyName string) ([]string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []string{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var strs = make([]string, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		strs = append(strs, str)
	}
	return strs, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}

		if addr, err := netip.ParseAddr(str); err == nil {
			ips = append(ips, addr)
		} else {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}

			addr := prefix.Addr()
			ips = append(ips, addr)
		}
	}
	return ips, nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key, err := parseString(section, "AllowedIPs")
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Prefix{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Prefix, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// ParseInterface parses the [Interface] section and extract the information into `device`
func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.Endpoint = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = &value
	}

	checkAlive, err := parseNetIP(section, "CheckAlive")
	if err != nil {
		return err
	}
	device.CheckAlive = checkAlive

	if sectionKey, err := section.GetKey("DomainBlockingEnabled"); err == nil {
		value, err := sectionKey.Bool()
		if err != nil {
			return err
		}
		device.DomainBlockingEnabled = value
	}

	blockedDomains, err := parseStrings(section, "BlockedDomains")
	if err != nil {
		return err
	}
	device.BlockedDomains = blockedDomains

	device.CheckAliveInterval = 5
	if sectionKey, err := section.GetKey("CheckAliveInterval"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		if len(checkAlive) == 0 {
			return errors.New("CheckAliveInterval is only valid when CheckAlive is set")
		}
		device.CheckAliveInterval = value
	}

	aSecConfig, err := ParseASecConfig(section)
	if err != nil {
		return err
	}
	device.ASecConfig = aSecConfig

	return nil
}

func ParseASecConfig(section *ini.Section) (*ASecConfigType, error) {
	var aSecConfig *ASecConfigType

	initializeASecConfig := func() {
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
	}

	if sectionKey, err := section.GetKey("Jc"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 || value > 200 {
			return nil, fmt.Errorf("value of the Jc field must be within the range of 0 to 200")
		}
		initializeASecConfig()
		aSecConfig.junkPacketCount = value
	}

	if sectionKey, err := section.GetKey("Jmin"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 || value > 1280 {
			return nil, fmt.Errorf("value of the Jmin field must be within the range of 0 to 1280")
		}
		initializeASecConfig()
		aSecConfig.junkPacketMinSize = value
	}

	if sectionKey, err := section.GetKey("Jmax"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 || value > 1280 {
			return nil, fmt.Errorf("value of the Jmax field must be within the range of 0 to 1280")
		}
		initializeASecConfig()
		aSecConfig.junkPacketMaxSize = value
	}

	if sectionKey, err := section.GetKey("S1"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 || value > 1280 {
			return nil, fmt.Errorf("value of the S1 field must be within the range of 0 to 1280")
		}
		initializeASecConfig()
		aSecConfig.initPacketJunkSize = value
	}

	if sectionKey, err := section.GetKey("S2"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 || value > 1280 {
			return nil, fmt.Errorf("value of the S2 field must be within the range of 0 to 1280")
		}
		initializeASecConfig()
		aSecConfig.responsePacketJunkSize = value
	}

	if sectionKey, err := section.GetKey("H1"); err == nil {
		value64, err := sectionKey.Uint64()
		if err != nil {
			return nil, err
		}
		if value64 < 1 || value64 > 4294967295 {
			return nil, fmt.Errorf("value of the H1 field must be within the range of 1 to 4294967295")
		}
		initializeASecConfig()
		aSecConfig.initPacketMagicHeader = uint32(value64)
	}

	if sectionKey, err := section.GetKey("H2"); err == nil {
		value64, err := sectionKey.Uint64()
		if err != nil {
			return nil, err
		}
		if value64 < 1 || value64 > 4294967295 {
			return nil, fmt.Errorf("value of the H2 field must be within the range of 1 to 4294967295")
		}
		initializeASecConfig()
		aSecConfig.responsePacketMagicHeader = uint32(value64)
	}

	if sectionKey, err := section.GetKey("H3"); err == nil {
		value64, err := sectionKey.Uint64()
		if err != nil {
			return nil, err
		}
		if value64 < 1 || value64 > 4294967295 {
			return nil, fmt.Errorf("value of the H3 field must be within the range of 1 to 4294967295")
		}
		initializeASecConfig()
		aSecConfig.underloadPacketMagicHeader = uint32(value64)
	}

	if sectionKey, err := section.GetKey("H4"); err == nil {
		value64, err := sectionKey.Uint64()
		if err != nil {
			return nil, err
		}
		if value64 < 1 || value64 > 4294967295 {
			return nil, fmt.Errorf("value of the H4 field must be within the range of 1 to 4294967295")
		}
		initializeASecConfig()
		aSecConfig.transportPacketMagicHeader = uint32(value64)
	}

	if sectionKey, err := section.GetKey("I1"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.i1 = &value
	}
	if sectionKey, err := section.GetKey("I2"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.i2 = &value
	}
	if sectionKey, err := section.GetKey("I3"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.i3 = &value
	}
	if sectionKey, err := section.GetKey("I4"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.i4 = &value
	}
	if sectionKey, err := section.GetKey("I5"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.i5 = &value
	}

	if sectionKey, err := section.GetKey("J1"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.j1 = &value
	}
	if sectionKey, err := section.GetKey("J2"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.j2 = &value
	}
	if sectionKey, err := section.GetKey("J3"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.j3 = &value
	}

	if sectionKey, err := section.GetKey("ITime"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 {
			return nil, fmt.Errorf("value of the ITime field must be non-negative")
		}
		initializeASecConfig()
		aSecConfig.itime = &value
	}

	if err := ValidateASecConfig(aSecConfig); err != nil {
		return nil, err
	}

	return aSecConfig, nil
}

func ValidateASecConfig(config *ASecConfigType) error {
	if config == nil {
		return nil
	}
	if config.junkPacketCount > 0 && config.junkPacketMinSize > config.junkPacketMaxSize {
		return errors.New("value of the Jmin field must be less than or equal to Jmax field value")
	}

	// Check S1 + 148 ≠ S2 + 92
	const messageInitiationSize = 148
	const messageResponseSize = 92
	if messageInitiationSize+config.initPacketJunkSize == messageResponseSize+config.responsePacketJunkSize {
		return errors.New(
			"value of the field S1 + message initiation size (148) must not equal S2 + message response size (92)",
		)
	}

	// Validate H1-H4 uniqueness (allow unset/default to 0, but check if any are set)
	headers := []uint32{
		config.initPacketMagicHeader,
		config.responsePacketMagicHeader,
		config.underloadPacketMagicHeader,
		config.transportPacketMagicHeader,
	}
	seen := make(map[uint32]bool)
	anyHeaderSet := false
	for i, h := range headers {
		if h != 0 { // Only check non-zero (set) headers
			anyHeaderSet = true
			if seen[h] {
				return fmt.Errorf("values of the H1-H4 fields must be unique; H%d conflicts", i+1)
			}
			seen[h] = true
		}
	}
	// If any header is set, all should be set to avoid conflicts with default 0
	if anyHeaderSet {
		for i, h := range headers {
			if h == 0 {
				return fmt.Errorf("H%d is unset (0) while other headers are set; all H1-H4 must be explicitly set if any are used", i+1)
			}
		}
	}

	return nil
}

// ParsePeers parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return errors.New("at least one [Peer] is expected")
	}

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		decoded, err := parseBase64KeyToHex(section, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = decoded

		if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
			value, err := encodeBase64ToHex(sectionKey.String())
			if err != nil {
				return err
			}
			peer.PreSharedKey = value
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
			value := sectionKey.String()
			decoded, err = resolveIPPAndPort(strings.ToLower(value))
			if err != nil {
				return err
			}
			peer.Endpoint = &decoded
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return err
			}
			peer.KeepAlive = value
		}

		peer.AllowedIPs, err = parseAllowedIPs(section)
		if err != nil {
			return err
		}

		*peers = append(*peers, peer)
	}
	return nil
}

func parseSocks5Config(section *ini.Section) (RoutineSpawner, error) {
	config := &Socks5Config{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

func parseHTTPConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &HTTPConfig{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

// Takes a function that parses an individual section into a config, and apply it on all
// specified sections
func parseRoutinesConfig(routines *[]RoutineSpawner, cfg *ini.File, sectionName string, f func(*ini.Section) (RoutineSpawner, error)) error {
	sections, err := cfg.SectionsByName(sectionName)
	if err != nil {
		return nil
	}

	for _, section := range sections {
		config, err := f(section)
		if err != nil {
			return err
		}

		*routines = append(*routines, config)
	}

	return nil
}

// ParseConfig takes the path of a configuration file and parses it into Configuration
func ParseConfig(path string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, path)
	if err != nil {
		return nil, err
	}

	return Parse(cfg)
}

// ParseConfigString takes the config as a string and parses it into Configuration
func ParseConfigString(config string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, []byte(config))
	if err != nil {
		return nil, err
	}

	return Parse(cfg)

}

func Parse(cfg *ini.File) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	device := &DeviceConfig{
		MTU: 1420,
	}

	root := cfg.Section("")
	wgConf, err := root.GetKey("WGConfig")
	wgCfg := cfg
	if err == nil {
		wgCfg, err = ini.LoadSources(iniOpt, wgConf.String())
		if err != nil {
			return nil, err
		}
	}

	err = ParseInterface(wgCfg, device)
	if err != nil {
		return nil, err
	}

	err = ParsePeers(wgCfg, &device.Peers)
	if err != nil {
		return nil, err
	}

	var routinesSpawners []RoutineSpawner

	err = parseRoutinesConfig(&routinesSpawners, cfg, "Socks5", parseSocks5Config)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "http", parseHTTPConfig)
	if err != nil {
		return nil, err
	}

	return &Configuration{
		Device:   device,
		Routines: routinesSpawners,
	}, nil
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig, isUpdate bool) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	if conf.ASecConfig != nil {
		aSecConfig := conf.ASecConfig

		var aSecBuilder strings.Builder

		aSecBuilder.WriteString(fmt.Sprintf("jc=%d\n", aSecConfig.junkPacketCount))
		aSecBuilder.WriteString(fmt.Sprintf("jmin=%d\n", aSecConfig.junkPacketMinSize))
		aSecBuilder.WriteString(fmt.Sprintf("jmax=%d\n", aSecConfig.junkPacketMaxSize))
		aSecBuilder.WriteString(fmt.Sprintf("s1=%d\n", aSecConfig.initPacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("s2=%d\n", aSecConfig.responsePacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("h1=%d\n", aSecConfig.initPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h2=%d\n", aSecConfig.responsePacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h3=%d\n", aSecConfig.underloadPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h4=%d\n", aSecConfig.transportPacketMagicHeader))

		if aSecConfig.i1 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i1=%s\n", *aSecConfig.i1))
		}
		if aSecConfig.i2 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i2=%s\n", *aSecConfig.i2))
		}
		if aSecConfig.i3 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i3=%s\n", *aSecConfig.i3))
		}
		if aSecConfig.i4 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i4=%s\n", *aSecConfig.i4))
		}
		if aSecConfig.i5 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i5=%s\n", *aSecConfig.i5))
		}
		if aSecConfig.j1 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j1=%s\n", *aSecConfig.j1))
		}
		if aSecConfig.j2 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j2=%s\n", *aSecConfig.j2))
		}
		if aSecConfig.j3 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j3=%s\n", *aSecConfig.j3))
		}
		if aSecConfig.itime != nil {
			aSecBuilder.WriteString(fmt.Sprintf("itime=%d\n", *aSecConfig.itime))
		}

		request.WriteString(aSecBuilder.String())
	}

	if isUpdate {
		request.WriteString("replace_peers=true\n")
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		request.WriteString("replace_allowed_ips=true\n")
		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// CreatePeerIPCRequest builds a UAPI string for updating peers only, based on the provided DeviceConfig.
func CreatePeerIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString("replace_peers=true\n")

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString("update_only=true\n")

		request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.KeepAlive))
		request.WriteString(fmt.Sprintf("preshared_key=%s\n", peer.PreSharedKey))

		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		request.WriteString("replace_allowed_ips=true\n")

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
                allowed_ip=0.0.0.0/0
                allowed_ip=::/0
            `))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}
