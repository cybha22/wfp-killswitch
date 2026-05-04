package monitor

import (
	"net"
	"net/netip"
	"strings"
)

type VPNInterface struct {
	Name           string
	Index          int
	IsUp           bool
	Addresses      []netip.Addr
	LUID           uint64
	HardwareAddr   net.HardwareAddr
}

func DetectVPNInterface(adapterName string) *VPNInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, iface := range ifaces {
		if !strings.EqualFold(iface.Name, adapterName) {
			continue
		}

		vpn := &VPNInterface{
			Name:         iface.Name,
			Index:        iface.Index,
			IsUp:         iface.Flags&net.FlagUp != 0,
			HardwareAddr: iface.HardwareAddr,
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					if a, ok := netip.AddrFromSlice(ipNet.IP); ok {
						vpn.Addresses = append(vpn.Addresses, a)
					}
				}
			}
		}

		return vpn
	}

	return nil
}

func HasValidVPNIP(iface *VPNInterface, vpnIPRange string) bool {
	prefix, err := netip.ParsePrefix(vpnIPRange)
	if err != nil {
		return false
	}

	for _, addr := range iface.Addresses {
		a := addr.Unmap()
		if prefix.Contains(a) {
			return true
		}
	}

	return false
}

func GetInterfaceLUID(ifaceIndex int) uint64 {
	luid, err := DetectVPNInterfaceLUID(ifaceIndex)
	if err != nil {
		return uint64(ifaceIndex)
	}
	return luid
}

func IsDefaultRouteViaVPN(vpnIfaceIndex int) bool {
	routes, err := getRouteTable()
	if err != nil {
		return false
	}

	for _, route := range routes {
		isDefaultRoute := route.ForwardDest == 0 && route.ForwardMask == 0
		if isDefaultRoute && int(route.ForwardIfIndex) == vpnIfaceIndex {
			return true
		}
	}

	return false
}
