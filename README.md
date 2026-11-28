# Glassbox

**Glassbox** is a locally hosted file-analysis prototype built with Flask, QEMU, and a small PyTorch report classifier. It combines static inspection with optional execution inside a disposable Debian Linux virtual machine, then presents the observations in a web report.

> **Current release: Linux only.** Glassbox is not a production malware-analysis service. Its heuristic score and experimental neural summary are not proof that a file is safe.

## What works in this release

- Flask web interface for uploading a file (30 MiB maximum).
- Static file inspection, SHA-256 hashing, file-signature identification, and image metadata inspection.
- Optional dynamic analysis inside a Debian 12 ARM64 QEMU guest.
- ZIP validation and extraction inside the guest workspace.
- A local PyTorch classifier that summarizes report indicators when locally trained weights are available.
- Progress reporting while an analysis job runs.

Windows and macOS analysis are **not supported** in this release.

## How it works

1. The Flask application accepts an upload and places it in a temporary host directory.
2. A separate worker process starts a QEMU Linux guest using the local Debian disk image and cloud-init seed.
3. The worker transfers the submitted file into the guest over forwarded SSH.
4. Static inspection and, where applicable, time-limited execution take place in the guest.
5. The worker returns the report. The local PyTorch model can add an experimental summary.

The guest is launched with QEMU snapshot mode so changes to its base disk are discarded when the VM exits. This is a prototype containment measure, **not a guarantee against VM escape or every form of malicious behavior**.

## Requirements

Use a 64-bit Linux host with Python 3 and venv support, Git LFS, QEMU ARM64 and UEFI firmware, and OpenSSH client tools. `run.sh` creates `.venv` and installs the Python packages from `requirements.txt` the first time it runs. QEMU and SSH host packages must already be installed.

## Quick start

### 1. Clone the repository

    git clone https://github.com/tossout1/Glassbox.git
    cd Glassbox

### 2. Download the VM files with Git LFS

    git lfs pull

This downloads the Debian disk image and `seed.iso` used by the Linux guest.

### 3. Get the SSH key

Glassbox needs the private key at `~/.ssh/tln_sandbox`. The matching public key is in `cloud-init/user-data`, and the LFS `seed.iso` is configured to accept that key. The private key is not in this public repository. Get the matching private key securely from the person who prepared the seed ISO; a newly generated key will not work with the supplied ISO.

Save the key with the expected filename and set private permissions:

    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    # Save the matching private key as ~/.ssh/tln_sandbox
    chmod 600 ~/.ssh/tln_sandbox

Confirm that it matches the public key in `cloud-init/user-data`:

    ssh-keygen -y -f ~/.ssh/tln_sandbox

Never send the private key in a public message or commit it to Git.

### 4. Start Glassbox

    bash run.sh

On first run, the script creates `.venv` and installs the Python requirements. It then compiles and trains the local report model and starts Gunicorn. Open `http://127.0.0.1:5000`. The first analysis starts the QEMU guest and may take a little time while it boots.

The WSGI entry point is `wsgi.py`. Keep **one Gunicorn worker process** because job state is held in process memory. To change the bind address or port, set `GLASSBOX_BIND` before starting. To disable the optional model summary, set `GLASSBOX_AI_ENABLED=0`.

## Important security and deployment notes

- Do not expose the upload endpoint to the unrestricted public internet. It accepts user-supplied files and can execute supported content inside a VM. For a demonstration, restrict access to trusted testers using an authenticated reverse proxy or equivalent access control.
- A VM is an isolation boundary, but not an absolute security guarantee. Keep QEMU and the host patched; use disposable test files and avoid real accounts or personal data in the guest.
- The guest's network is configured with QEMU's restricted user networking. Do not loosen that setting without reviewing the security implications.
- The upload limit is 30 MiB. ZIP files are also subject to entry-count and expanded-size limits.
- The heuristic safety score is experimental and can produce false positives or false negatives. A high score must never be interpreted as proof of safety.
- The Debian VM image and seed ISO are stored with Git LFS. Model weights, SSH private keys, VM state, and temporary analysis data should remain outside Git.

## Repository layout

    Glassbox/
    ├── binary_analysis.py
    ├── cloud-init/
    │   ├── meta-data
    │   └── user-data
    ├── glassbox_nn.py
    ├── image_analysis.py
    ├── main.py
    ├── requirements.txt
    ├── run.sh
    ├── run_wsgi.sh
    ├── static/
    │   └── favicon.svg
    ├── templates/
    │   └── index.html
    └── wsgi.py

The Debian disk image and seed.iso are retrieved with Git LFS. SyntheticData/, the SSH private key, and locally trained model weights are local runtime assets.

## License

A license has not yet been selected for this repository. Add a LICENSE file before accepting outside contributions or presenting the project as formally open source.
