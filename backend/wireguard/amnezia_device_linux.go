//go:build linux

package wireguard

import (
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// linuxAmneziaDevice is an amneziawg-go device plus the UAPI socket that lets
// amneziawg-tools (awg show) inspect it.
type linuxAmneziaDevice struct {
	*device.Device
	uapi net.Listener
}

func (d *linuxAmneziaDevice) Close() {
	if d.uapi != nil {
		_ = d.uapi.Close()
	}
	d.Device.Close()
}

func openAmneziaDevice(name string) (ipcDevice, error) {
	tunDevice, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf(
				"creating amneziawg interface: AmneziaWG requires CAP_NET_ADMIN and /dev/net/tun (if running in Docker, add NET_ADMIN and the /dev/net/tun device): %w",
				err,
			)
		}
		return nil, fmt.Errorf("creating amneziawg interface: %w", err)
	}

	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			log.Printf("amneziawg (%s): "+format, append([]any{name}, args...)...)
		},
	}
	dev := &linuxAmneziaDevice{Device: device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)}

	// The UAPI socket is only for inspection, so failing to open it does not stop the interface.
	if file, err := ipc.UAPIOpen(name); err != nil {
		log.Printf("amneziawg (%s): UAPI socket unavailable, awg show will not see this interface: %v", name, err)
	} else if listener, err := ipc.UAPIListen(name, file); err != nil {
		_ = file.Close()
		log.Printf("amneziawg (%s): UAPI socket unavailable, awg show will not see this interface: %v", name, err)
	} else {
		dev.uapi = listener
		go func() {
			for {
				uapiConn, err := listener.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(uapiConn)
			}
		}()
	}

	return dev, nil
}
