package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/muhsh/advanced-killswitch/internal/config"
	"github.com/muhsh/advanced-killswitch/internal/logger"
	"github.com/muhsh/advanced-killswitch/internal/service"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := strings.ToLower(os.Args[1])

	cfg, err := config.Load("configs/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log, err := logger.New(cfg.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	svc := service.New(cfg, log)

	switch cmd {
	case "install":
		if err := svc.Install(); err != nil {
			log.Fatalf("install failed: %v", err)
		}
		fmt.Println("Service installed successfully.")

	case "uninstall":
		if err := svc.Uninstall(); err != nil {
			log.Fatalf("uninstall failed: %v", err)
		}
		fmt.Println("Service uninstalled. All WFP filters removed.")

	case "start":
		if err := svc.Start(); err != nil {
			log.Fatalf("start failed: %v", err)
		}
		fmt.Println("Service started.")

	case "stop":
		if err := svc.Stop(); err != nil {
			log.Fatalf("stop failed: %v", err)
		}
		fmt.Println("Service stopped.")

	case "status":
		status, err := svc.Status()
		if err != nil {
			log.Fatalf("status check failed: %v", err)
		}
		fmt.Printf("Service status: %s\n", status)

	case "run":
		// Run as Windows service (called by SCM)
		if err := svc.Run(); err != nil {
			log.Fatalf("service run failed: %v", err)
		}

	case "debug":
		if err := svc.RunInteractive(); err != nil {
			log.Fatalf("debug run failed: %v", err)
		}

	case "cleanup":
		fmt.Println("Removing all WFP filters and NRPT rules...")
		svc.ForceCleanup()
		fmt.Println("Cleanup complete. Internet should be restored.")

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Advanced VPN Kill Switch")
	fmt.Println()
	fmt.Println("Usage: killswitch.exe <command>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  install    Install as Windows service")
	fmt.Println("  uninstall  Uninstall service and remove all WFP filters")
	fmt.Println("  start      Start the service")
	fmt.Println("  stop       Stop the service")
	fmt.Println("  status     Show service status")
	fmt.Println("  run        Run as Windows service (called by SCM)")
	fmt.Println("  debug      Run in foreground for debugging")
	fmt.Println("  cleanup    Remove all WFP filters and restore internet")
}
