package fwebpf

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnsureBPFFilesystem ensures the BPF filesystem is mounted at /sys/fs/bpf
func EnsureBPFFilesystem() error {
	bpfFsPath := "/sys/fs/bpf"
	// Check if /sys/fs/bpf exists
	if _, err := os.Stat(bpfFsPath); os.IsNotExist(err) {
		if err := os.MkdirAll(bpfFsPath, 0755); err != nil {
			return fmt.Errorf("creating /sys/fs/bpf: %v", err)
		}
	}

	// Check if bpffs is mounted
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(bpfFsPath, &statfs); err != nil {
		return fmt.Errorf("checking BPF filesystem: %v", err)
	}
	if statfs.Type != unix.BPF_FS_MAGIC {
		// Attempt to mount bpffs
		if err := syscall.Mount("bpffs", bpfFsPath, "bpf", 0, ""); err != nil {
			return fmt.Errorf("mounting BPF filesystem at %s: %v (run 'sudo mount -t bpf bpffs /sys/fs/bpf')", bpfFsPath, err)
		}
		fmt.Printf("Mounted BPF filesystem at %s\n", bpfFsPath)
	} else {
		fmt.Printf("BPF filesystem already mounted at %s\n", bpfFsPath)
	}
	return nil
}