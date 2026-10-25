//go:build integration

package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/pasarguard/node/common"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// startNetstackAmneziaClient connects an in-process AmneziaWG client to the server on
// loopback. Its traffic leaves through gVisor netstack, so it needs no interface or namespace.
func startNetstackAmneziaClient(t *testing.T, clientKey wgtypes.Key, clientIP string, serverPublicKey string, serverPort int, amnezia *AmneziaConfig) *http.Client {
	t.Helper()

	settings, err := amnezia.uapiLines()
	if err != nil {
		t.Fatalf("client uapiLines: %v", err)
	}
	serverKey, err := wgtypes.ParseKey(serverPublicKey)
	if err != nil {
		t.Fatalf("server public key: %v", err)
	}

	tunDevice, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(clientIP)}, nil, device.DefaultMTU)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "awg-client: "))
	t.Cleanup(dev.Close)

	conf := fmt.Sprintf("private_key=%s\n%s\npublic_key=%s\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n",
		hexKey(clientKey), strings.Join(settings, "\n"), hexKey(serverKey), serverPort)
	if err := dev.IpcSet(conf); err != nil {
		t.Fatalf("client IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	return &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext:       tnet.DialContext,
			DisableKeepAlives: true,
		},
	}
}

func httpReachable(client *http.Client, url string) error {
	response, err := client.Get(url)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", response.StatusCode)
	}
	return nil
}

func TestIntegrationE2EAmneziaWG(t *testing.T) {
	const (
		iface      = "awg-e2e"
		awgPort    = 51990
		configCIDR = "10.211.0.1/24"
		clientIP   = "10.211.0.2"
		email      = "awg-user@example.com"
	)

	serverPrivateKey := mustGeneratePrivateKey(t)
	clientKey := mustGenerateKey(t)

	configJSON := fmt.Sprintf(
		`{"interface_name":"%s","listen_port":%d,"private_key":"%s","address":["%s"],"amnezia":%s}`,
		iface, awgPort, serverPrivateKey, configCIDR, panelAmneziaJSON,
	)
	wg := createTestWireGuardWithUsers(t, configJSON, []*common.User{
		buildWGUser(email, clientKey.PublicKey().String(), clientIP+"/32", iface, true),
	})
	defer wg.Shutdown()

	if version := wg.Version(); !strings.HasPrefix(version, "amneziawg-go v3.") {
		t.Fatalf("unexpected version %q", version)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		t.Fatalf("interface %s not found: %v", iface, err)
	}
	if link.Type() != "tuntap" {
		t.Fatalf("expected a TUN interface, got %s", link.Type())
	}
	if _, err := wg.GetSysStats(context.Background()); err != nil {
		t.Fatalf("GetSysStats: %v", err)
	}

	url := startWGHTTPServerAtIP(t, strings.Split(configCIDR, "/")[0])
	client := startNetstackAmneziaClient(t, clientKey, clientIP, wireGuardServerPublicKey(t, wg), awgPort, wg.config.Amnezia)

	deadline := time.Now().Add(connectRetryWindow)
	for {
		err := httpReachable(client, url)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not reachable over AmneziaWG: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for range 5 {
		if err := httpReachable(client, url); err != nil {
			t.Fatalf("request over AmneziaWG failed: %v", err)
		}
	}

	time.Sleep(statsGatherWait)
	if total := userTrafficTotal(t, wg, email); total <= 0 {
		t.Fatalf("expected traffic for %s, got %d", email, total)
	}
	if online := userOnline(t, wg, email); online != 1 {
		t.Fatalf("expected %s online, got %d", email, online)
	}

	// Restart reapplies the AmneziaWG settings with the full peer snapshot. Replacing the
	// peers drops their sessions, as on kernel WireGuard, so the client only reconnects once
	// it gives up on the old one: keepalive_timeout + rekey_timeout = 15s with these settings.
	if err := wg.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		err := httpReachable(client, url)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not reachable after restart: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Dropping the user from the interface removes the peer.
	if err := wg.SyncUser(context.Background(), buildWGUser(email, clientKey.PublicKey().String(), clientIP+"/32", iface, false)); err != nil {
		t.Fatalf("SyncUser: %v", err)
	}
	if err := httpReachable(client, url); err == nil {
		t.Fatal("removed user still reaches the server")
	}

	wg.Shutdown()
	if _, err := netlink.LinkByName(iface); err == nil {
		t.Fatalf("interface %s still exists after shutdown", iface)
	} else if _, ok := err.(netlink.LinkNotFoundError); !ok {
		t.Fatalf("LinkByName after shutdown: %v", err)
	}
	if _, err := net.InterfaceByName(iface); err == nil {
		t.Fatalf("interface %s still listed after shutdown", iface)
	}
}
