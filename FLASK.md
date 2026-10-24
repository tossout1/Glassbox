# Glassbox — Flask web interface

This branch replaces Tkinter with a browser-based upload interface while retaining the original QEMU/SSH analyzer.

## Requirements

The existing prototype still requires a **Linux ARM64 host**, KVM, QEMU (`qemu-system-aarch64`), SSH/SCP, its Debian ARM64 QCOW2 image, `seed.iso`, the synthetic data directory, the SSH key at `~/.ssh/tln_sandbox`, and the firmware file configured in `main.py`. The VM assets are not bundled in this repository.

Install Flask:

```bash
python3 -m pip install -r web-requirements.txt
```

Start:

```bash
python3 main.py
```

Open <http://127.0.0.1:5000> and select or drag a file. The VM boots at the first scan. Results appear under the upload panel.

**Security notes:** Keep the service on localhost. The upload size cap is 30 MiB. Analyses use a lock because the VM has shared workspace paths. ZIP archives undergo basic traversal/size checks, but this prototype is **not** a hardened malware analysis service. Never change the binding to a public interface without a thorough security review. Safety scores are estimates, not proof that a file is safe.
