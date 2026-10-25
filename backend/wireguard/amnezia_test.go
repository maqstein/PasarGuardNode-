package wireguard

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var testHeaderProtectionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))

// panelAmneziaJSON is shaped like the panel's AmneziaProperties dump.
var panelAmneziaJSON = `{
	"jc": 4, "jmin": 40, "jmax": 70,
	"s1": 15, "s2": 16, "s3": 17, "s4": 18,
	"h1": "100000-100100", "h2": "200000", "h3": "300000-300100", "h4": "400000-400100",
	"i1": "<b 0xf6ab3267fa><r 10>",
	"header_protection_key": "` + testHeaderProtectionKey + `",
	"content_padding_addition": "0-16",
	"rekey_after_time": 120, "rekey_timeout": "5", "reject_after_time": "170-180",
	"keepalive_timeout": 10, "max_handshake_attempts": 18,
	"random_trailers": "on", "disable_cookies": "off"
}`

func TestNewConfigParsesPanelAmneziaProperties(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"x","listen_port":51821,"address":["10.8.0.1/24"],"amnezia":` + panelAmneziaJSON + `}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Amnezia == nil {
		t.Fatal("expected amnezia settings")
	}

	lines, err := cfg.Amnezia.uapiLines()
	if err != nil {
		t.Fatalf("uapiLines: %v", err)
	}
	want := []string{
		"jc=4", "jmin=40", "jmax=70",
		"s1=15", "s2=16", "s3=17", "s4=18",
		"h1=100000-100100", "h2=200000", "h3=300000-300100", "h4=400000-400100",
		"i1=<b 0xf6ab3267fa><r 10>",
		"header_protection_key=" + strings.Repeat("6b", 32),
		"content_padding_addition=0-16",
		"rekey_after_time=120", "rekey_timeout=5", "reject_after_time=170-180",
		"keepalive_timeout=10", "max_handshake_attempts=18",
		"random_trailers=true", "disable_cookies=false",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("uapi lines:\n got %q\nwant %q", lines, want)
	}
}

func TestNewConfigWithoutAmneziaStaysWireGuard(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"wg0","private_key":"x","listen_port":51820,"address":["10.0.0.1/24"]}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Amnezia != nil {
		t.Fatalf("expected no amnezia settings, got %+v", cfg.Amnezia)
	}
}

func TestNewConfigEmptyAmneziaEnablesAmneziaWG(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"x","address":["10.8.0.1/24"],"amnezia":{}}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if cfg.Amnezia == nil {
		t.Fatal("an empty amnezia object should still select AmneziaWG")
	}
	lines, err := cfg.Amnezia.uapiLines()
	if err != nil || len(lines) != 0 {
		t.Fatalf("expected no settings, got %q, %v", lines, err)
	}
}

func TestNewConfigRejectsInvalidAmnezia(t *testing.T) {
	tests := []struct {
		name    string
		amnezia string
		wantErr string
	}{
		{"jmin above jmax", `{"jmin": 80, "jmax": 70}`, "jmin must not exceed jmax"},
		{"overlapping headers", `{"h1": "100-200", "h2": "150-300", "h3": "5", "h4": "6"}`, "h1 and h2 must not overlap"},
		{"set header hits a default one", `{"h1": "2"}`, "h1 and h2 must not overlap"},
		{"reversed range", `{"h1": "200-100"}`, "min exceeds max"},
		{"non-numeric range", `{"rekey_timeout": "soon"}`, "invalid range"},
		{"bad switch", `{"random_trailers": "maybe"}`, "invalid switch"},
		{"padding above 16 bits", `{"s1": 70000}`, "cannot unmarshal"},
		{"short header protection key", `{"header_protection_key": "` + base64.StdEncoding.EncodeToString([]byte("short")) + `", "s1": 12, "s2": 12, "s3": 12, "s4": 12}`, "32-byte key"},
		{"header protection with small padding", `{"header_protection_key": "` + testHeaderProtectionKey + `", "s1": 12, "s2": 12, "s3": 11, "s4": 12}`, "s3 must be at least 12"},
		{"header protection without padding", `{"header_protection_key": "` + testHeaderProtectionKey + `"}`, "s1 must be at least 12"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConfig(`{"interface_name":"awg0","private_key":"x","address":["10.8.0.1/24"],"amnezia":` + tt.amnezia + `}`)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestAmneziaSwitchAcceptsBooleans(t *testing.T) {
	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"x","address":["10.8.0.1/24"],"amnezia":{"random_trailers":true,"disable_cookies":"OFF"}}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if !bool(*cfg.Amnezia.RandomTrailers) || bool(*cfg.Amnezia.DisableCookies) {
		t.Fatalf("unexpected switches: %v %v", *cfg.Amnezia.RandomTrailers, *cfg.Amnezia.DisableCookies)
	}
}

func TestBuildUAPISetPutsSettingsBeforePeers(t *testing.T) {
	privateKey := mustGenerateKey(t)
	peerKey := mustGenerateKey(t).PublicKey()
	removedKey := mustGenerateKey(t).PublicKey()
	psk := mustGenerateKey(t)
	port := 51821
	keepalive := 25 * time.Second
	_, allowed, _ := net.ParseCIDR("10.8.0.2/32")

	text := buildUAPISet(wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:                   peerKey,
				PresharedKey:                &psk,
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{*allowed},
			},
			{PublicKey: removedKey, Remove: true},
		},
	}, []string{"jc=4", "h1=5"})

	want := strings.Join([]string{
		"private_key=" + hexKey(privateKey),
		"listen_port=51821",
		"replace_peers=true",
		"jc=4",
		"h1=5",
		"public_key=" + hexKey(peerKey),
		"preshared_key=" + hexKey(psk),
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=10.8.0.2/32",
		"public_key=" + hexKey(removedKey),
		"remove=true",
	}, "\n") + "\n"
	if text != want {
		t.Fatalf("uapi set:\n got %q\nwant %q", text, want)
	}
}

func TestParseUAPIDeviceReadsPeers(t *testing.T) {
	privateKey := mustGenerateKey(t)
	peerKey := mustGenerateKey(t).PublicKey()
	idleKey := mustGenerateKey(t).PublicKey()

	text := strings.Join([]string{
		"private_key=" + hexKey(privateKey),
		"listen_port=51821",
		"jc=4",
		"header_protection_key=" + strings.Repeat("6b", 32),
		"random_trailers=1",
		"public_key=" + hexKey(peerKey),
		"preshared_key=" + strings.Repeat("00", 32),
		"protocol_version=1",
		"endpoint=[2001:db8::1]:40000",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=5",
		"tx_bytes=100",
		"rx_bytes=200",
		"persistent_keepalive_interval=20-30",
		"allowed_ip=10.8.0.2/32",
		"allowed_ip=fd00::2/128",
		"public_key=" + hexKey(idleKey),
		"last_handshake_time_sec=0",
		"last_handshake_time_nsec=0",
		"allowed_ip=10.8.0.3/32",
	}, "\n") + "\n"

	dev, err := parseUAPIDevice("awg0", text)
	if err != nil {
		t.Fatalf("parseUAPIDevice: %v", err)
	}
	if dev.Name != "awg0" || dev.ListenPort != 51821 || dev.PrivateKey != privateKey || dev.PublicKey != privateKey.PublicKey() {
		t.Fatalf("unexpected device fields: %+v", dev)
	}
	if len(dev.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(dev.Peers))
	}

	active := dev.Peers[0]
	if active.PublicKey != peerKey || active.ReceiveBytes != 200 || active.TransmitBytes != 100 || active.ProtocolVersion != 1 {
		t.Fatalf("unexpected active peer: %+v", active)
	}
	if !active.LastHandshakeTime.Equal(time.Unix(1700000000, 5)) {
		t.Fatalf("unexpected handshake time %v", active.LastHandshakeTime)
	}
	if active.Endpoint == nil || active.Endpoint.String() != "[2001:db8::1]:40000" {
		t.Fatalf("unexpected endpoint %v", active.Endpoint)
	}
	if active.PersistentKeepaliveInterval != 20*time.Second {
		t.Fatalf("unexpected keepalive %v", active.PersistentKeepaliveInterval)
	}
	if len(active.AllowedIPs) != 2 || active.AllowedIPs[0].String() != "10.8.0.2/32" || active.AllowedIPs[1].String() != "fd00::2/128" {
		t.Fatalf("unexpected allowed IPs %v", active.AllowedIPs)
	}

	if idle := dev.Peers[1]; !idle.LastHandshakeTime.IsZero() || len(idle.AllowedIPs) != 1 {
		t.Fatalf("unexpected idle peer: %+v", idle)
	}
}

type fakeIPCDevice struct {
	sets   []string
	upErr  error
	ups    int
	closed int
}

func (d *fakeIPCDevice) IpcSet(conf string) error { d.sets = append(d.sets, conf); return nil }
func (d *fakeIPCDevice) IpcGet() (string, error)  { return "", nil }
func (d *fakeIPCDevice) Up() error                { d.ups++; return d.upErr }
func (d *fakeIPCDevice) Close()                   { d.closed++ }

func newFakeAmneziaManager(t *testing.T, amnezia string, fake *fakeIPCDevice, linkDels *int) *Manager {
	t.Helper()

	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"x","address":["10.8.0.1/24"],"amnezia":` + amnezia + `}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	manager, err := NewAmneziaManager("awg0", cfg.Amnezia)
	if err != nil {
		t.Fatalf("NewAmneziaManager: %v", err)
	}
	dev := manager.tunnel.(*amneziaDevice)
	dev.open = func(name string) (ipcDevice, error) {
		if name != "awg0" {
			t.Errorf("opened %q, want awg0", name)
		}
		return fake, nil
	}

	// The interface only "exists" while the fake device is open.
	manager.nl = mockNetlinkOps{
		parseAddrFn: netlink.ParseAddr,
		linkAddFn: func(netlink.Link) error {
			return errors.New("AmneziaWG must not create a kernel wireguard link")
		},
		linkByName: func(name string) (netlink.Link, error) {
			if dev.dev == nil {
				return nil, linkNotFoundError()
			}
			return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1420}}, nil
		},
		addrAddFn:   func(netlink.Link, *netlink.Addr) error { return nil },
		linkSetUpFn: func(netlink.Link) error { return nil },
		linkDelFn: func(netlink.Link) error {
			*linkDels++
			return nil
		},
	}
	return manager
}

func TestAmneziaManagerInitializesAndClosesDevice(t *testing.T) {
	fake := &fakeIPCDevice{}
	linkDels := 0
	manager := newFakeAmneziaManager(t, `{"jc": 4, "h1": "100000-100100"}`, fake, &linkDels)

	privateKey := mustGenerateKey(t)
	_, allowed, _ := net.ParseCIDR("10.8.0.2/32")
	peer := buildAddConfig(mustGenerateKey(t).PublicKey(), []net.IPNet{*allowed}, nil)
	if err := manager.InitializeWithPeers(privateKey, 51821, []string{"10.8.0.1/24"}, []wgtypes.PeerConfig{peer}); err != nil {
		t.Fatalf("InitializeWithPeers: %v", err)
	}

	if len(fake.sets) != 1 {
		t.Fatalf("expected one UAPI set, got %d", len(fake.sets))
	}
	for _, want := range []string{"private_key=" + hexKey(privateKey) + "\n", "listen_port=51821\n", "jc=4\nh1=100000-100100\npublic_key=", "allowed_ip=10.8.0.2/32\n"} {
		if !strings.Contains(fake.sets[0], want) {
			t.Fatalf("UAPI set %q is missing %q", fake.sets[0], want)
		}
	}
	if fake.ups != 1 {
		t.Fatalf("expected the device to be brought up once, got %d", fake.ups)
	}

	// Peer-only updates do not resend the device settings.
	if err := manager.ApplyPeers([]wgtypes.PeerConfig{buildRemoveConfig(peer.PublicKey)}); err != nil {
		t.Fatalf("ApplyPeers: %v", err)
	}
	if got := fake.sets[1]; strings.Contains(got, "jc=") || !strings.Contains(got, "remove=true") {
		t.Fatalf("unexpected peer update %q", got)
	}

	if err := manager.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.closed != 1 || linkDels != 0 {
		t.Fatalf("expected the device closed once without a netlink delete, got closed=%d linkDels=%d", fake.closed, linkDels)
	}
}

func TestAmneziaManagerStartFailureClosesDevice(t *testing.T) {
	fake := &fakeIPCDevice{upErr: errors.New("port in use")}
	linkDels := 0
	manager := newFakeAmneziaManager(t, `{}`, fake, &linkDels)

	err := manager.InitializeWithPeers(mustGenerateKey(t), 51821, []string{"10.8.0.1/24"}, nil)
	if err == nil || !strings.Contains(err.Error(), "port in use") {
		t.Fatalf("expected start error, got %v", err)
	}
	if fake.closed != 1 {
		t.Fatalf("expected the device closed after a failed start, got %d", fake.closed)
	}
}

// awgEndpoint is one side of an in-memory AmneziaWG tunnel: a real amneziawg-go device on a
// channel TUN, talking UDP over loopback.
type awgEndpoint struct {
	tun *tuntest.ChannelTUN
	dev *device.Device
}

func newTestAmneziaDevice(t *testing.T) (*amneziaDevice, *awgEndpoint, AmneziaConfig) {
	t.Helper()
	cfg, err := NewConfig(`{"interface_name":"awg0","private_key":"x","address":["10.8.0.1/24"],"amnezia":` + panelAmneziaJSON + `}`)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	settings, err := cfg.Amnezia.uapiLines()
	if err != nil {
		t.Fatalf("uapiLines: %v", err)
	}

	server := &awgEndpoint{tun: tuntest.NewChannelTUN()}
	dev := &amneziaDevice{settings: settings, open: func(string) (ipcDevice, error) {
		server.dev = device.NewDevice(server.tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "server: "))
		return server.dev, nil
	}}
	if err := dev.create("awg0"); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(dev.destroy)
	return dev, server, *cfg.Amnezia
}

// startTestAmneziaClient starts a client for server whose AmneziaWG settings are amnezia.
func startTestAmneziaClient(t *testing.T, serverKey wgtypes.Key, serverPort int, clientKey wgtypes.Key, amnezia AmneziaConfig) *awgEndpoint {
	t.Helper()
	settings, err := amnezia.uapiLines()
	if err != nil {
		t.Fatalf("client uapiLines: %v", err)
	}

	client := &awgEndpoint{tun: tuntest.NewChannelTUN()}
	client.dev = device.NewDevice(client.tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "client: "))
	t.Cleanup(client.dev.Close)

	conf := fmt.Sprintf("private_key=%s\n%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=10.8.0.1/32\n",
		hexKey(clientKey), strings.Join(settings, "\n"), hexKey(serverKey), serverPort)
	if err := client.dev.IpcSet(conf); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := client.dev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}
	return client
}

func configureTestServer(t *testing.T, dev *amneziaDevice, serverKey, clientKey wgtypes.Key) int {
	t.Helper()
	port := 0
	_, allowed, _ := net.ParseCIDR("10.8.0.2/32")
	err := dev.ConfigureDevice("awg0", wgtypes.Config{
		PrivateKey:   &serverKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{buildAddConfig(clientKey.PublicKey(), []net.IPNet{*allowed}, nil)},
	})
	if err != nil {
		t.Fatalf("server ConfigureDevice: %v", err)
	}
	if err := dev.start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	state, err := dev.Device("awg0")
	if err != nil {
		t.Fatalf("server Device: %v", err)
	}
	if state.ListenPort == 0 {
		t.Fatal("server did not bind a port")
	}
	return state.ListenPort
}

func TestAmneziaDeviceCarriesTrafficWithMatchingSettings(t *testing.T) {
	dev, server, amnezia := newTestAmneziaDevice(t)
	serverKey, clientKey := mustGenerateKey(t), mustGenerateKey(t)
	port := configureTestServer(t, dev, serverKey, clientKey)
	client := startTestAmneziaClient(t, serverKey.PublicKey(), port, clientKey, amnezia)

	ping := tuntest.Ping(netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("10.8.0.2"))
	client.tun.Outbound <- ping
	select {
	case got := <-server.tun.Inbound:
		if !bytes.Equal(got, ping) {
			t.Fatal("packet did not transit intact")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("packet did not reach the server")
	}

	state, err := dev.Device("awg0")
	if err != nil {
		t.Fatalf("server Device: %v", err)
	}
	if len(state.Peers) != 1 {
		t.Fatalf("expected one peer, got %d", len(state.Peers))
	}
	peer := state.Peers[0]
	if peer.PublicKey != clientKey.PublicKey() || peer.LastHandshakeTime.IsZero() || peer.ReceiveBytes == 0 {
		t.Fatalf("expected a handshake and received bytes, got %+v", peer)
	}
	if peer.Endpoint == nil || !peer.Endpoint.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("unexpected endpoint %v", peer.Endpoint)
	}
}

func TestAmneziaDeviceRejectsClientWithOtherSettings(t *testing.T) {
	otherKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	tests := []struct {
		name   string
		mutate func(*AmneziaConfig)
	}{
		{"header protection key", func(a *AmneziaConfig) { a.HeaderProtectionKey = otherKey }},
		{"init header", func(a *AmneziaConfig) { a.H1 = &AmneziaRange{Lo: 500000, Hi: 500100} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev, server, amnezia := newTestAmneziaDevice(t)
			serverKey, clientKey := mustGenerateKey(t), mustGenerateKey(t)
			port := configureTestServer(t, dev, serverKey, clientKey)
			tt.mutate(&amnezia)
			client := startTestAmneziaClient(t, serverKey.PublicKey(), port, clientKey, amnezia)

			client.tun.Outbound <- tuntest.Ping(netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("10.8.0.2"))
			select {
			case <-server.tun.Inbound:
				t.Fatal("server accepted a client with different AmneziaWG settings")
			case <-time.After(2 * time.Second):
			}

			state, err := dev.Device("awg0")
			if err != nil {
				t.Fatalf("server Device: %v", err)
			}
			if !state.Peers[0].LastHandshakeTime.IsZero() {
				t.Fatal("expected no handshake")
			}
		})
	}
}

func mustGenerateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return key
}

func hexKey(key wgtypes.Key) string {
	return fmt.Sprintf("%x", key[:])
}
