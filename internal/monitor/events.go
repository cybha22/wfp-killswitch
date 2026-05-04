package monitor

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procNotifyAddrChange     = modiphlpapi.NewProc("NotifyAddrChange")
	procCancelIPChangeNotify = modiphlpapi.NewProc("CancelIPChangeNotify")
)

func (m *Monitor) runEventLoop(ctx context.Context) {
	m.log.Info("starting event-driven network monitor (NotifyAddrChange)")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := waitForNetworkChange(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.log.Warnf("NotifyAddrChange error: %v", err)
			continue
		}

		m.log.Debug("network change event received")
		m.checkVPNStatus()
	}
}

func waitForNetworkChange(ctx context.Context) error {
	var overlapped windows.Overlapped
	overlapped.HEvent, _ = windows.CreateEvent(nil, 1, 0, nil)
	if overlapped.HEvent == 0 {
		return windows.ERROR_INVALID_HANDLE
	}
	defer windows.CloseHandle(overlapped.HEvent)

	var handle windows.Handle
	ret, _, _ := procNotifyAddrChange.Call(
		uintptr(unsafe.Pointer(&handle)),
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if ret != uintptr(windows.ERROR_IO_PENDING) {
		return windows.Errno(ret)
	}

	waitHandles := []windows.Handle{overlapped.HEvent}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			cancelIPChangeNotify(&overlapped)
		case <-done:
		}
	}()

	event, err := windows.WaitForMultipleObjects(waitHandles, false, windows.INFINITE)
	close(done)

	if err != nil {
		return err
	}

	if event == windows.WAIT_OBJECT_0 {
		return nil
	}

	return windows.ERROR_TIMEOUT
}

func cancelIPChangeNotify(overlapped *windows.Overlapped) {
	procCancelIPChangeNotify.Call(uintptr(unsafe.Pointer(overlapped)))
}
