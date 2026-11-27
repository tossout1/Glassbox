# Glassbox

**Glassbox** is a locally hosted file-analysis prototype built with Flask, QEMU, and a small PyTorch report classifier. It combines static inspection with optional execution inside a disposable Debian Linux virtual machine, then presents the observations in a web report.

> **Current release: Linux only.** Glassbox is an experimental prototype, not a production malware-analysis service. Its heuristic score and experimental neural summary are not proof that a file is safe.

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

- 64-bit Linux host. The project was developed on a Raspberry Pi 5.
- Python 3 and virtual-environment support.
- QEMU ARM64 system emulator and ARM64 UEFI firmware.
- Debian 12 ARM64 cloud image.
- cloud-localds (provided by the Debian package cloud-image-utils).
- OpenSSH client tools.
- A local SSH key pair matching the public key in cloud-init/user-data.
- The project's SyntheticData/ directory.

On Debian or Raspberry Pi OS, install the host packages:

    sudo apt update
    sudo apt install -y qemu-system-arm qemu-utils qemu-efi-aarch64 cloud-image-utils openssh-client

Package names and firmware paths can vary by distribution.

## Setup

### 1. Clone the source and install Python packages

    git clone https://github.com/tossout1/Glassbox.git
    cd Glassbox

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

### 2. Prepare the Linux guest files

Place an official Debian 12 ARM64 generic cloud image in the project root with this exact filename:

    debian-12-genericcloud-arm64.qcow2

Obtain the image from an official Debian cloud-image source and verify its published checksum. Do not use an untrusted preconfigured VM image.

Make sure the synthetic test data directory exists:

    mkdir -p SyntheticData

Glassbox expects the guest to have a user named sandbox, SSH access on the forwarded host port 2222, and the synthetic home directory /home/Augustine Ramswell.

### 3. Check the SSH key

Glassbox expects this private key on the host:

    ~/.ssh/tln_sandbox

The matching public key must appear under ssh_authorized_keys in cloud-init/user-data. The public key may be stored in this repository; **never commit the private key**.

To display the public key corresponding to an existing private key:

    ssh-keygen -y -f ~/.ssh/tln_sandbox

Compare the output with the key in cloud-init/user-data. If they differ, update the cloud-init file with the correct public key before generating the seed image.

### 4. Generate the cloud-init seed ISO

From the project root:

    cloud-localds seed.iso cloud-init/user-data cloud-init/meta-data

The generated seed.iso is a local VM configuration file and is intentionally excluded from Git.

### 5. Train the optional local report model

The model weights are generated locally and are not included in the source repository:

    python3 glassbox_nn.py --train

This creates models/glassbox_nn.pt. Training uses synthetic feature combinations; it is not training on a validated malware corpus. If the weights are unavailable, the detailed analysis report still works without the neural summary. To disable the summary explicitly:

    export GLASSBOX_AI_ENABLED=0

### 6. Run Glassbox locally

For development:

    python3 main.py

Open the local URL printed by Flask. The first analysis starts the QEMU guest and may take a little time while the VM boots.

## Run with a WSGI server

For a single-host deployment, use Gunicorn:

    source .venv/bin/activate
    GLASSBOX_TRUSTED_HOSTS=localhost,127.0.0.1 \
    gunicorn --bind 127.0.0.1:8000 --workers 1 --threads 8 --timeout 60 wsgi:app

The WSGI entry point is wsgi.py. Keep **one Gunicorn worker process**: job state and the worker semaphore are currently held in process memory. Multiple Gunicorn worker processes could cause progress requests to reach a process that does not know about the submitted job. The application starts analysis in background threads and launches a separate QEMU-owning subprocess for each job.

If a reverse proxy uses a public hostname, add that exact hostname to GLASSBOX_TRUSTED_HOSTS as a comma-separated value. Keep Gunicorn bound to localhost and put a properly configured HTTPS reverse proxy in front of it.

## Important security and deployment notes

- Do not expose the upload endpoint to the unrestricted public internet. It accepts user-supplied files and can execute supported content inside a VM. For a demonstration, restrict access to trusted testers using an authenticated reverse proxy or equivalent access control.
- A VM is an isolation boundary, but not an absolute security guarantee. Keep QEMU and the host patched; use disposable test files and avoid real accounts or personal data in the guest.
- The guest's network is configured with QEMU's restricted user networking. Do not loosen that setting without reviewing the security implications.
- The upload limit is 30 MiB. ZIP files are also subject to entry-count and expanded-size limits.
- The heuristic safety score is experimental and can produce false positives or false negatives. A high score must never be interpreted as proof of safety.
- VM images, generated seed ISOs, model weights, SSH private keys, VM state, and temporary analysis data should remain outside Git.

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
    ├── static/
    │   └── favicon.svg
    ├── templates/
    │   └── index.html
    └── wsgi.py

The Debian disk image, seed.iso, SyntheticData/, SSH private key, and locally trained model weights must be prepared on the host.

## License

See LICENSE for the project license.
