package wireguard

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const amneziaModulePath = "github.com/amnezia-vpn/amneziawg-go/v3"

var errAmneziaDeviceNotCreated = errors.New("amneziawg device is not created")

// ipcDevice is the part of an amneziawg-go device the backend drives.
type ipcDevice interface {
	IpcSet(uapiConf string) error
	IpcGet() (string, error)
	Up() error
	Close()
}

// amneziaDevice runs AmneziaWG in-process: amneziawg-go on a TUN interface, so no
// kernel module is needed. It is both the Manager's tunnel and its wgClient, and it
// speaks the UAPI text protocol to the device.
type amneziaDevice struct {
	// settings are the device-level AmneziaWG UAPI lines, sent with every full device config.
	settings []string
	open     func(name string) (ipcDevice, error)

	mu  sync.Mutex
	dev ipcDevice
}

// NewAmneziaManager creates a manager whose interface is an in-process AmneziaWG device.
func NewAmneziaManager(interfaceName string, config *AmneziaConfig) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	settings, err := config.uapiLines()
	if err != nil {
		return nil, err
	}

	dev := &amneziaDevice{settings: settings, open: openAmneziaDevice}
	return &Manager{
		client:    dev,
		tunnel:    dev,
		iFaceName: interfaceName,
		nl:        defaultNetlinkOps{},
		configure: defaultConfigureDevice,
	}, nil
}

func (a *amneziaDevice) create(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
	dev, err := a.open(name)
	if err != nil {
		return err
	}
	a.dev = dev
	return nil
}

func (a *amneziaDevice) start() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev == nil {
		return errAmneziaDeviceNotCreated
	}
	// The device also comes up on the TUN up event; calling Up here returns a bind
	// failure (port in use) instead of only logging it.
	return a.dev.Up()
}

func (a *amneziaDevice) destroy() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev != nil {
		a.dev.Close()
		a.dev = nil
	}
}

func (a *amneziaDevice) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev == nil {
		return errAmneziaDeviceNotCreated
	}
	var settings []string
	if cfg.PrivateKey != nil {
		settings = a.settings
	}
	return a.dev.IpcSet(buildUAPISet(cfg, settings))
}

func (a *amneziaDevice) Device(name string) (*wgtypes.Device, error) {
	a.mu.Lock()
	dev := a.dev
	a.mu.Unlock()

	if dev == nil {
		return nil, errAmneziaDeviceNotCreated
	}
	text, err := dev.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseUAPIDevice(name, text)
}

func (a *amneziaDevice) Close() error {
	a.destroy()
	return nil
}

// buildUAPISet renders cfg as a UAPI "set" body. settings go with the other device-level
// lines, before the first peer.
func buildUAPISet(cfg wgtypes.Config, settings []string) string {
	var b strings.Builder
	line := func(format string, args ...any) {
		fmt.Fprintf(&b, format, args...)
		b.WriteByte('\n')
	}

	if cfg.PrivateKey != nil {
		line("private_key=%s", hex.EncodeToString(cfg.PrivateKey[:]))
	}
	if cfg.ListenPort != nil {
		line("listen_port=%d", *cfg.ListenPort)
	}
	if cfg.FirewallMark != nil {
		line("fwmark=%d", *cfg.FirewallMark)
	}
	if cfg.ReplacePeers {
		line("replace_peers=true")
	}
	for _, setting := range settings {
		line("%s", setting)
	}

	for _, peer := range cfg.Peers {
		line("public_key=%s", hex.EncodeToString(peer.PublicKey[:]))
		if peer.Remove {
			line("remove=true")
			continue
		}
		if peer.UpdateOnly {
			line("update_only=true")
		}
		if peer.PresharedKey != nil {
			line("preshared_key=%s", hex.EncodeToString(peer.PresharedKey[:]))
		}
		if peer.Endpoint != nil {
			line("endpoint=%s", peer.Endpoint.String())
		}
		if peer.PersistentKeepaliveInterval != nil {
			line("persistent_keepalive_interval=%d", int(peer.PersistentKeepaliveInterval.Seconds()))
		}
		if peer.ReplaceAllowedIPs {
			line("replace_allowed_ips=true")
		}
		for _, allowedIP := range peer.AllowedIPs {
			line("allowed_ip=%s", allowedIP.String())
		}
	}

	return b.String()
}

// parseUAPIDevice reads a UAPI "get" body. AmneziaWG device settings are skipped: the
// backend only reads keys and peer state back.
func parseUAPIDevice(name, text string) (*wgtypes.Device, error) {
	device := &wgtypes.Device{Name: name, Type: wgtypes.Userspace}
	var peer *wgtypes.Peer
	var handshakeSec, handshakeNsec int64

	finishPeer := func() {
		if peer == nil {
			return
		}
		if handshakeSec != 0 || handshakeNsec != 0 {
			peer.LastHandshakeTime = time.Unix(handshakeSec, handshakeNsec)
		}
		device.Peers = append(device.Peers, *peer)
		peer = nil
		handshakeSec, handshakeNsec = 0, 0
	}

	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}

		if key == "public_key" {
			finishPeer()
			publicKey, err := parseHexKey(value)
			if err != nil {
				return nil, fmt.Errorf("uapi public_key: %w", err)
			}
			peer = &wgtypes.Peer{PublicKey: publicKey}
			continue
		}

		if peer == nil {
			switch key {
			case "private_key":
				privateKey, err := parseHexKey(value)
				if err != nil {
					return nil, fmt.Errorf("uapi private_key: %w", err)
				}
				device.PrivateKey = privateKey
				device.PublicKey = privateKey.PublicKey()
			case "listen_port":
				port, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("uapi listen_port: %w", err)
				}
				device.ListenPort = port
			case "fwmark":
				mark, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("uapi fwmark: %w", err)
				}
				device.FirewallMark = mark
			}
			continue
		}

		var err error
		switch key {
		case "preshared_key":
			peer.PresharedKey, err = parseHexKey(value)
		case "endpoint":
			var addrPort netip.AddrPort
			addrPort, err = netip.ParseAddrPort(value)
			if err == nil {
				peer.Endpoint = net.UDPAddrFromAddrPort(addrPort)
			}
		case "last_handshake_time_sec":
			handshakeSec, err = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			handshakeNsec, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			peer.ReceiveBytes, err = strconv.ParseInt(value, 10, 64)
		case "tx_bytes":
			peer.TransmitBytes, err = strconv.ParseInt(value, 10, 64)
		case "persistent_keepalive_interval":
			// AmneziaWG allows a "lo-hi" range here; report its lower bound.
			var interval AmneziaRange
			interval, err = ParseAmneziaRange(value)
			peer.PersistentKeepaliveInterval = time.Duration(interval.Lo) * time.Second
		case "allowed_ip":
			var prefix netip.Prefix
			prefix, err = netip.ParsePrefix(value)
			if err == nil {
				peer.AllowedIPs = append(peer.AllowedIPs, net.IPNet{
					IP:   prefix.Addr().AsSlice(),
					Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
				})
			}
		case "protocol_version":
			peer.ProtocolVersion, err = strconv.Atoi(value)
		}
		if err != nil {
			return nil, fmt.Errorf("uapi %s: %w", key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	finishPeer()

	return device, nil
}

func parseHexKey(value string) (wgtypes.Key, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.NewKey(raw)
}

// amneziaVersion reports the linked amneziawg-go module version.
func amneziaVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == amneziaModulePath {
				if dep.Replace != nil {
					dep = dep.Replace
				}
				return "amneziawg-go " + dep.Version
			}
		}
	}
	return "amneziawg-go"
}
