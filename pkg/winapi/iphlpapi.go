package winapi

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHlpAPI                      = windows.NewLazySystemDLL("iphlpapi.dll")
	procConvertInterfaceIndexToLuid  = modIPHlpAPI.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceLuidToIndex  = modIPHlpAPI.NewProc("ConvertInterfaceLuidToIndex")
	procNotifyAddrChange             = modIPHlpAPI.NewProc("NotifyAddrChange")
	procCancelIPChangeNotify         = modIPHlpAPI.NewProc("CancelIPChangeNotify")
)

type NetLUID struct {
	Value uint64
}

func ConvertInterfaceIndexToLUID(index uint32) (uint64, error) {
	var luid NetLUID
	ret, _, _ := procConvertInterfaceIndexToLuid.Call(
		uintptr(index),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceIndexToLuid failed: %d", ret)
	}
	return luid.Value, nil
}

func ConvertInterfaceLUIDToIndex(luid uint64) (uint32, error) {
	var index uint32
	netLuid := NetLUID{Value: luid}
	ret, _, _ := procConvertInterfaceLuidToIndex.Call(
		uintptr(unsafe.Pointer(&netLuid)),
		uintptr(unsafe.Pointer(&index)),
	)
	if ret != 0 {
		return 0, fmt.Errorf("ConvertInterfaceLuidToIndex failed: %d", ret)
	}
	return index, nil
}
