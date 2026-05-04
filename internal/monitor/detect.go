package monitor

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi2                    = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable           = modiphlpapi2.NewProc("GetIpForwardTable")
	procGetAdaptersAddresses        = modiphlpapi2.NewProc("GetAdaptersAddresses")
	procConvertInterfaceIndexToLuid = modiphlpapi2.NewProc("ConvertInterfaceIndexToLuid")
)

type mibIpForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

func DetectVPNServerIPs(vpnInterfaceIndex int) ([]netip.Addr, error) {
	routes, err := getRouteTable()
	if err != nil {
		return nil, fmt.Errorf("get route table: %w", err)
	}

	var serverIPs []netip.Addr

	for _, route := range routes {
		isHostRoute := route.ForwardMask == 0xFFFFFFFF
		notViaVPN := int(route.ForwardIfIndex) != vpnInterfaceIndex
		notLoopback := route.ForwardIfIndex != 1
		notDefaultRoute := route.ForwardDest != 0

		if isHostRoute && notViaVPN && notLoopback && notDefaultRoute {
			ip := uint32ToIP(route.ForwardDest)
			isBroadcast := ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
			if !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !isBroadcast {
				serverIPs = append(serverIPs, ip)
			}
		}
	}

	return serverIPs, nil
}

func DetectVPNDNSServers(adapterName string) ([]netip.Addr, error) {
	output, err := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`(Get-DnsClientServerAddress -InterfaceAlias "%s" -AddressFamily IPv4).ServerAddresses`, adapterName),
	).Output()
	if err != nil {
		return nil, fmt.Errorf("get DNS servers: %w", err)
	}

	var servers []netip.Addr
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if addr, err := netip.ParseAddr(line); err == nil {
			servers = append(servers, addr)
		}
	}

	return servers, nil
}

func DetectVPNInterfaceLUID(interfaceIndex int) (uint64, error) {
	var luid uint64
	ret, _, _ := procConvertInterfaceIndexToLuid.Call(
		uintptr(uint32(interfaceIndex)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid failed with code %d", ret)
	}
	return luid, nil
}

func DetectVPNInterfaceIndex(adapterName string) (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	for _, iface := range ifaces {
		if strings.EqualFold(iface.Name, adapterName) {
			return iface.Index, nil
		}
	}

	return 0, fmt.Errorf("adapter %q not found", adapterName)
}

func getRouteTable() ([]mibIpForwardRow, error) {
	var size uint32
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	buf := make([]byte, size)
	ret, _, _ := procGetIpForwardTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetIpForwardTable failed: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rows := make([]mibIpForwardRow, numEntries)

	rowSize := unsafe.Sizeof(mibIpForwardRow{})
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		row := (*mibIpForwardRow)(unsafe.Pointer(&buf[offset]))
		rows[i] = *row
	}

	return rows, nil
}

func uint32ToIP(ip uint32) netip.Addr {
	b := [4]byte{
		byte(ip),
		byte(ip >> 8),
		byte(ip >> 16),
		byte(ip >> 24),
	}
	return netip.AddrFrom4(b)
}
