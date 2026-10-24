"""Windows 11 ARM64 QEMU setup helpers for Glassbox.

This module prepares/boots a VM for OS installation and configuration.
It does NOT run untrusted samples or claim to provide Windows analysis.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

BASE = Path(__file__).resolve().parent
DISK = BASE / "windows.qcow2"


def firmware_path():
    candidates = [
        Path("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"),
        Path("/usr/share/AAVMF/AAVMF_CODE.fd"),
        Path("/usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "ARM64 UEFI firmware not found; install qemu-efi-aarch64 and check its path."
    )


def boot_windows(iso=None, memory_mb=4096, cpus=4):
    if not DISK.is_file():
        raise FileNotFoundError(
            f"Missing {DISK}. Create with: qemu-img create -f qcow2 windows.qcow2 64G"
        )
    if not shutil.which("qemu-system-aarch64"):
        raise RuntimeError("Install qemu-system-arm to get qemu-system-aarch64.")
    if iso is not None and not Path(iso).is_file():
        raise FileNotFoundError(f"ISO not found: {iso}")

    cmd = [
        "qemu-system-aarch64",
        "-machine", "virt,accel=kvm",
        "-cpu", "host",
        "-smp", str(cpus),
        "-m", str(memory_mb),
        "-bios", str(firmware_path()),
        "-drive", f"if=none,file={DISK},format=qcow2,id=system",
        "-device", "virtio-blk-device,drive=system",
        "-device", "qemu-xhci",
        "-device", "usb-tablet",
        "-device", "usb-kbd",
        "-device", "ramfb",
        "-nic", "user,restrict=on",
        "-display", "gtk",
    ]
    if iso:
        cmd.extend([
            "-drive", f"if=none,file={Path(iso).resolve()},media=cdrom,readonly=on,id=install",
            "-device", "usb-storage,drive=install",
            "-boot", "order=d",
        ])
    print("Starting Windows ARM64 VM. This is setup mode, not sandbox analysis.")
    print("Note: Windows 11 requires TPM 2.0, Secure Boot and compatible storage drivers.")
    print("This initial QEMU configuration may require further adjustments to install.")
    subprocess.run(cmd, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows ARM64 VM setup (not sample analysis)")
    parser.add_argument("--iso", type=Path, help="Path to Windows 11 ARM64 installer ISO")
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--cpus", type=int, default=4)
    args = parser.parse_args()
    boot_windows(args.iso, args.memory, args.cpus)
