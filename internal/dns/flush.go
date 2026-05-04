package dns

import (
	"os/exec"
)

func FlushDNSCache() error {
	return exec.Command("ipconfig", "/flushdns").Run()
}
