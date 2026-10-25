//go:build !linux

package wireguard

import "errors"

func openAmneziaDevice(string) (ipcDevice, error) {
	return nil, errors.New("AmneziaWG is only supported on Linux")
}
