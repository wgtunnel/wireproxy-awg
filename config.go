package wireproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/go-ini/ini"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    string // now supports ranges, so we change to string
	AllowedIPs   []netip.Prefix
}

type ASecConfigType struct {
	junkPacketCount            int    // Jc
	junkPacketMinSize          int    // Jmin
	junkPacketMaxSize          int    // Jmax
	initPacketJunkSize         int    // s1
	responsePacketJunkSize     int    // s2
	cookieReplyPacketJunkSize  int    // s3
	transportPacketJunkSize    int    // s4
	initPacketMagicHeader      string // h1
	responsePacketMagicHeader  string // h2
	underloadPacketMagicHeader string // h3
	transportPacketMagicHeader string // h4
	i1                         *string
	i2                         *string
	i3                         *string
	i4                         *string
	i5                         *string

	// Amnezia 3.0 values
	headerProtectionKey    string // hex after base64 decode
	contentPaddingAddition string
	rekeyAfterTime         string
	rekeyTimeout           string
	rejectAfterTime        string
	keepaliveTimeout       string
	maxHandshakeAttempts   string

	// Amnezia 3.1 values
	randomTrailers string
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey          string
	Address            []netip.Addr
	Peers              []PeerConfig
	DNS                []netip.Addr
	SearchDomains      []string
	MTU                int
	ListenPort         *int
	CheckAlive         []netip.Addr
	CheckAliveInterval int
	ASecConfig         *ASecConfigType
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

func parseDNS(section *ini.Section, keyName string) ([]netip.Addr, []string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, []string{}, nil
		}
		return nil, nil, err
	}

	keys := strings.Split(key, ",")
	var ips []netip.Addr
	var domains []string
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		if ip, err := netip.ParseAddr(str); err == nil {
			ips = append(ips, ip)
		} else {
			domains = append(domains, str)
		}
	}
	return ips, domains, nil
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

func validateUintRangeOrScalar(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s == "(off)" {
		return nil
	}
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid range %q", s)
		}
		lo, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		hi, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid range %q", s)
		}
		if lo > hi {
			return fmt.Errorf("range low > high: %q", s)
		}
		return nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return err
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

	device.Address = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dnsIps, searchDomains, err := parseDNS(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dnsIps
	device.SearchDomains = searchDomains

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

	if sectionKey, err := section.GetKey("S3"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 {
			return nil, fmt.Errorf("value of the S3 field must be non-negative")
		}
		initializeASecConfig()
		aSecConfig.cookieReplyPacketJunkSize = value
	}

	if sectionKey, err := section.GetKey("S4"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if value < 0 {
			return nil, fmt.Errorf("value of the S4 field must be non-negative")
		}
		initializeASecConfig()
		aSecConfig.transportPacketJunkSize = value
	}

	if sectionKey, err := section.GetKey("H1"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.initPacketMagicHeader = value
	}

	if sectionKey, err := section.GetKey("H2"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.responsePacketMagicHeader = value
	}

	if sectionKey, err := section.GetKey("H3"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.underloadPacketMagicHeader = value
	}

	if sectionKey, err := section.GetKey("H4"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.transportPacketMagicHeader = value
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

	if sectionKey, err := section.GetKey("HeaderProtectionKey"); err == nil {
		hexKey, err := encodeBase64ToHex(strings.TrimSpace(sectionKey.String()))
		if err != nil {
			return nil, fmt.Errorf("HeaderProtectionKey: %w", err)
		}
		initializeASecConfig()
		aSecConfig.headerProtectionKey = hexKey
	}

	setRange := func(name string) (string, error) {
		sectionKey, err := section.GetKey(name)
		if err != nil {
			return "", nil
		}
		v := strings.TrimSpace(sectionKey.String())
		if v == "" {
			return "", nil
		}
		if err := validateUintRangeOrScalar(v); err != nil {
			return "", fmt.Errorf("%s: %w", name, err)
		}
		return v, nil
	}

	if v, err := setRange("ContentPaddingAddition"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.contentPaddingAddition = v
	}
	if v, err := setRange("RekeyAfterTime"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.rekeyAfterTime = v
	}
	if v, err := setRange("RekeyTimeout"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.rekeyTimeout = v
	}
	if v, err := setRange("RejectAfterTime"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.rejectAfterTime = v
	}
	if v, err := setRange("KeepaliveTimeout"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.keepaliveTimeout = v
	}
	if v, err := setRange("MaxHandshakeAttempts"); err != nil {
		return nil, err
	} else if v != "" {
		initializeASecConfig()
		aSecConfig.maxHandshakeAttempts = v
	}

	if sectionKey, err := section.GetKey("RandomTrailers"); err == nil {
		value := sectionKey.String()
		initializeASecConfig()
		aSecConfig.randomTrailers = value
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

	const (
		messageInitiationSize = 148
		messageResponseSize   = 92
		cookieReplySize       = 64
		headerCipherNonceSize = 12
	)

	if messageInitiationSize+config.initPacketJunkSize == messageResponseSize+config.responsePacketJunkSize {
		return errors.New("S1 + 148 must not equal S2 + 92")
	}
	if messageInitiationSize+config.initPacketJunkSize == cookieReplySize+config.cookieReplyPacketJunkSize {
		return errors.New("S1 + 148 must not equal S3 + 64")
	}
	if messageResponseSize+config.responsePacketJunkSize == cookieReplySize+config.cookieReplyPacketJunkSize {
		return errors.New("S2 + 92 must not equal S3 + 64")
	}

	if config.headerProtectionKey != "" {
		checks := []struct {
			name string
			val  int
		}{
			{"S1", config.initPacketJunkSize},
			{"S2", config.responsePacketJunkSize},
			{"S3", config.cookieReplyPacketJunkSize},
			{"S4", config.transportPacketJunkSize},
		}
		for _, c := range checks {
			if c.val < headerCipherNonceSize {
				return fmt.Errorf("%s must be >= %d when HeaderProtectionKey is set", c.name, headerCipherNonceSize)
			}
		}
	}
	return nil
}

// ParsePeers parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if err != nil {
		*peers = []PeerConfig{}
		return nil
	}

	*peers = make([]PeerConfig, 0, len(sections))

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    "",
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
			peer.Endpoint = &value
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			v := strings.TrimSpace(sectionKey.String())
			if v != "" {
				if err := validateUintRangeOrScalar(v); err != nil {
					return fmt.Errorf("PersistentKeepalive: %w", err)
				}
				peer.KeepAlive = v
			}
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
		aSecBuilder.WriteString(fmt.Sprintf("s3=%d\n", aSecConfig.cookieReplyPacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("s4=%d\n", aSecConfig.transportPacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("h1=%s\n", aSecConfig.initPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h2=%s\n", aSecConfig.responsePacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h3=%s\n", aSecConfig.underloadPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h4=%s\n", aSecConfig.transportPacketMagicHeader))

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
		if aSecConfig.headerProtectionKey != "" {
			aSecBuilder.WriteString(fmt.Sprintf("header_protection_key=%s\n", aSecConfig.headerProtectionKey))
		}
		if aSecConfig.contentPaddingAddition != "" {
			aSecBuilder.WriteString(fmt.Sprintf("content_padding_addition=%s\n", aSecConfig.contentPaddingAddition))
		}
		if aSecConfig.rekeyAfterTime != "" {
			aSecBuilder.WriteString(fmt.Sprintf("rekey_after_time=%s\n", aSecConfig.rekeyAfterTime))
		}
		if aSecConfig.rekeyTimeout != "" {
			aSecBuilder.WriteString(fmt.Sprintf("rekey_timeout=%s\n", aSecConfig.rekeyTimeout))
		}
		if aSecConfig.rejectAfterTime != "" {
			aSecBuilder.WriteString(fmt.Sprintf("reject_after_time=%s\n", aSecConfig.rejectAfterTime))
		}
		if aSecConfig.keepaliveTimeout != "" {
			aSecBuilder.WriteString(fmt.Sprintf("keepalive_timeout=%s\n", aSecConfig.keepaliveTimeout))
		}
		if aSecConfig.maxHandshakeAttempts != "" {
			aSecBuilder.WriteString(fmt.Sprintf("max_handshake_attempts=%s\n", aSecConfig.maxHandshakeAttempts))
		}
		if aSecConfig.maxHandshakeAttempts != "" {
			aSecBuilder.WriteString(fmt.Sprintf("random_trailers=%s\n", aSecConfig.randomTrailers))
		}

		request.WriteString(aSecBuilder.String())
	}

	if isUpdate {
		request.WriteString("replace_peers=true\n")
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		if peer.KeepAlive != "" {
			request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%s\n", peer.KeepAlive))
		}
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

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Address, MTU: conf.MTU}
	return setting, nil
}

func ParsePeerEndpoint(endpoint string) (host netip.Prefix, port uint16, err error) {
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	addr := addrPort.Addr()
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	return prefix, addrPort.Port(), nil
}

// CreatePeerIPCRequest builds a UAPI string for updating peers only, based on the provided DeviceConfig.
func CreatePeerIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	//request.WriteString("replace_peers=true\n")

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf("public_key=%s\n", peer.PublicKey))
		request.WriteString("update_only=true\n")

		if peer.KeepAlive != "" {
			request.WriteString(fmt.Sprintf("persistent_keepalive_interval=%s\n", peer.KeepAlive))
		}
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

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Address, MTU: conf.MTU}
	return setting, nil
}

// NeedsResolution returns true if the peer's endpoint is a domain name that needs DNS resolution
func (p *PeerConfig) NeedsResolution() bool {
	if p.Endpoint == nil {
		return false
	}
	host, _, err := net.SplitHostPort(*p.Endpoint)
	if err != nil {
		return false
	}
	_, err = netip.ParseAddr(host)
	return err != nil // parse failed, it's a domain
}

// UpdateEndpointIP updates the peer's endpoint with the provided resolved IP, preserving the original port.
func (p *PeerConfig) UpdateEndpointIP(resolvedIP netip.Addr) error {
	if p.Endpoint == nil {
		return errors.New("no endpoint set")
	}
	_, port, err := net.SplitHostPort(*p.Endpoint)
	if err != nil {
		return err
	}

	ipStr := resolvedIP.String()
	if resolvedIP.Is6() {
		ipStr = "[" + ipStr + "]"
	}
	newEndpoint := ipStr + ":" + port
	p.Endpoint = &newEndpoint
	return nil
}
