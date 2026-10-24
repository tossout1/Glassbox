"""Boot the Windows 11 ARM64 installer with persistent UEFI and TPM 2.0."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parent
DISK = BASE / "windows.qcow2"
STATE = BASE / "windows_vm_state"


def firmware():
    # Secure Boot requires firmware built with Secure Boot support AND enrolled keys.
    pairs = [
        ("/usr/share/AAVMF/AAVMF_CODE.ms.fd", "/usr/share/AAVMF/AAVMF_VARS.ms.fd"),
        ("/usr/share/AAVMF/AAVMF_CODE.secboot.fd", "/usr/share/AAVMF/AAVMF_VARS.ms.fd"),
        ("/usr/share/AAVMF/AAVMF_CODE.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"),
        ("/usr/share/qemu-efi-aarch64/QEMU_EFI-pflash.raw", None),
    ]
    for code, vars_template in pairs:
        if Path(code).is_file():
            return Path(code), Path(vars_template) if vars_template and Path(vars_template).is_file() else None
    raise FileNotFoundError("ARM64 UEFI firmware missing. Install qemu-efi-aarch64 / AAVMF.")


def boot_windows(iso=None, memory_mb=4096, cpus=4):
    if not DISK.is_file():
        raise FileNotFoundError(f"Missing existing Windows disk: {DISK}")
    for binary in ("qemu-system-aarch64", "swtpm"):
        if not shutil.which(binary):
            raise RuntimeError(f"Missing {binary}; install qemu-system-arm and swtpm.")
    if iso is not None and not Path(iso).is_file():
        raise FileNotFoundError(f"ISO not found: {iso}")
    STATE.mkdir(exist_ok=True)
    tpm_state = STATE / "tpm"
    tpm_state.mkdir(exist_ok=True)
    socket_path = STATE / "swtpm.sock"
    if socket_path.exists():
        socket_path.unlink()
    code, vars_template = firmware()
    vars_file = STATE / "uefi_vars.fd"
    if vars_template and not vars_file.exists():
        shutil.copyfile(vars_template, vars_file)
    if not vars_template:
        raise RuntimeError(
            f"Found {code}, but no writable ARM64 UEFI variables template. "
            "Install AAVMF firmware with matching CODE and VARS images. "
            "Secure Boot additionally requires Secure Boot-capable firmware and enrolled keys."
        )
    accel = "kvm" if os.uname().machine.lower() in ("aarch64", "arm64") and Path("/dev/kvm").exists() else "tcg"
    cpu = "host" if accel == "kvm" else "cortex-a72"
    tpm = subprocess.Popen([
        "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}",
        "--ctrl", f"type=unixio,path={socket_path}", "--flags", "not-need-init"
    ])
    try:
        for _ in range(50):
            if socket_path.exists():
                break
            if tpm.poll() is not None:
                raise RuntimeError("swtpm exited before creating its socket.")
            time.sleep(0.1)
        else:
            raise RuntimeError("Timed out waiting for swtpm.")
        cmd = [
            "qemu-system-aarch64", "-machine", f"virt,accel={accel}",
            "-cpu", cpu, "-smp", str(cpus), "-m", str(memory_mb),
            "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
            "-drive", f"if=pflash,format=raw,file={vars_file}",
            "-chardev", f"socket,id=chrtpm,path={socket_path}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
            "-device", "tpm-tis-device,tpmdev=tpm0",
            "-drive", f"if=none,file={DISK},format=qcow2,id=system",
            "-device", "qemu-xhci", "-device", "usb-tablet",
            "-device", "nvme,drive=system,serial=GLASSBOX001",
            "-device", "usb-kbd", "-device", "ramfb",
            "-nic", "user,restrict=on", "-display", "gtk",
        ]
        if iso:
            cmd += [
                "-drive", f"if=none,file={Path(iso).resolve()},media=cdrom,readonly=on,id=install",
                "-device", "usb-storage,drive=install", "-boot", "order=d",
            ]
        print(f"Starting Windows ARM64 setup: {accel.upper()}, TPM 2.0, persistent UEFI.")
        print("Secure Boot requires signed ARM64 firmware with enrolled Microsoft keys.")
        subprocess.run(cmd, check=True)
    finally:
        tpm.terminate()
        try:
            tpm.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tpm.kill()
            tpm.wait()
        if socket_path.exists():
            socket_path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows 11 ARM64 VM setup")
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--memory", type=int, default=4096)
    parser.add_argument("--cpus", type=int, default=4)
    args = parser.parse_args()
    boot_windows(args.iso, args.memory, args.cpus)
