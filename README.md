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
- OpenSSH client tools.
- Git LFS.
- A local SSH key pair matching the public key in cloud-init/user-data.
- The project's SyntheticData/ directory.

On Debian or Raspberry Pi OS, install the host packages:

    sudo apt update
    sudo apt install -y qemu-system-arm qemu-utils qemu-efi-aarch64 openssh-client

Package names and firmware paths can vary by distribution.

## Setup

### 1. Clone the source and install Python packages

    git clone https://github.com/tossout1/Glassbox.git
    cd Glassbox
    git lfs pull

    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt

### 2. Check the SSH key

Glassbox expects this private key on the host:

    ~/.ssh/tln_sandbox

The matching public key must appear under ssh_authorized_keys in cloud-init/user-data. The public key may be stored in this repository; **never commit the private key**.

To display the public key corresponding to an existing private key:

    ssh-keygen -y -f ~/.ssh/tln_sandbox

Compare the output with the key in cloud-init/user-data. It must match the key configured in the LFS seed ISO for guest SSH access to work.

### 3. Run Glassbox locally

For local Flask development over HTTP:

    python3 main.py

Open the local URL printed by Flask. The first analysis starts the QEMU guest and may take a little time while the VM boots.

## Run with a WSGI server

Start the included Gunicorn server with:

    source .venv/bin/activate
    ./run.sh

`run.sh` compiles the model script, trains the local model, then starts Gunicorn through `run_wsgi.sh`. Model weights are generated locally and are not included in Git. The server listens over HTTP at `http://127.0.0.1:5000` by default. Set `GLASSBOX_BIND` to change the bind address and port. Set `GLASSBOX_TRUSTED_HOSTS` to a comma-separated list of allowed hostnames when using a hostname. To disable the optional model summary, set `GLASSBOX_AI_ENABLED=0` before starting the app.

The WSGI entry point is wsgi.py. Keep **one Gunicorn worker process**: job state and the worker semaphore are currently held in process memory. Multiple Gunicorn worker processes could cause progress requests to reach a process that does not know about the submitted job. The application starts analysis in background threads and launches a separate QEMU-owning subprocess for each job.

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
