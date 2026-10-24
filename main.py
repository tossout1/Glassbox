"""Flask interface and isolated QEMU-based file analyzer for Glassbox.

The VM runs on a Linux ARM64 host. Uploaded files are analyzed inside the
VM, not executed by the Flask server on the host.
"""
import atexit
import json
import os
import socket
import platform
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import uuid
import time
import zipfile
from pathlib import Path, PurePosixPath

from flask import Flask, jsonify, render_template, request
from glassbox_nn import summarize_report
from image_analysis import inspect_image
from binary_analysis import inspect_binary
from werkzeug.exceptions import RequestEntityTooLarge

# ============================================================

BASE_DIR = Path(__file__).resolve().parent

PAYLOAD_PATH = BASE_DIR / "SyntheticData"
SEED_FILE = BASE_DIR / "seed.iso"

SSH_KEY = Path.home() / ".ssh" / "tln_sandbox"

SSH_PORT = os.environ.get("GLASSBOX_SSH_PORT", "2222")
SSH_USER = "sandbox"
SSH_HOST = "127.0.0.1"

SYNTHETIC_HOME = "/home/Augustine Ramswell"

REMOTE_INPUT = "/tmp/glassbox-input"
REMOTE_WORKSPACE = "/tmp/glassbox-workspace"

EXECUTION_TIMEOUT = 8

MAX_ZIP_FILES = 200
MAX_ZIP_TOTAL_SIZE = 100 * 1024 * 1024
MAX_ZIP_SINGLE_FILE = 25 * 1024 * 1024

vm = None

# ============================================================

def stop_vm():
    global vm

    if vm is not None and vm.poll() is None:

        print("Stopping VM...")

        vm.terminate()

        try:
            vm.wait(timeout=5)

        except subprocess.TimeoutExpired:

            print("VM did not stop gracefully. Killing it...")

            vm.kill()
            vm.wait()

        print("VM stopped.")

def handle_exit(signum, frame):
    stop_vm()
    sys.exit(0)

atexit.register(stop_vm)

signal.signal(signal.SIGINT, handle_exit)
signal.signal(signal.SIGTERM, handle_exit)

# Only one analysis may use the shared VM and its fixed workspace paths at once.
WORKER_LIMIT = max(1, int(os.environ.get("GLASSBOX_WORKERS", "1")))
WORKER_SLOTS = threading.BoundedSemaphore(WORKER_LIMIT)

_ANALYSIS_MESSAGES = []
_BOOTED = False
JOBS = {}
JOBS_LOCK = threading.Lock()

def set_progress(job_id, percent, stage):
    """Update a scan's completed milestone; percentages are stage estimates."""
    with JOBS_LOCK:
        JOBS[job_id].update(percent=percent, stage=stage)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 30 * 1024 * 1024
app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1"]

def add_text(value=""):
    """Append a line to the current analysis report."""
    _ANALYSIS_MESSAGES.append(str(value))

# ============================================================

def ssh_base():

    return [
        "ssh",
        "-4",

        "-i",
        str(SSH_KEY),

        "-p",
        SSH_PORT,

        "-o",
        "StrictHostKeyChecking=no",

        "-o",
        "UserKnownHostsFile=/dev/null",

        "-o",
        "ConnectTimeout=5",

        "-o",
        "BatchMode=yes",

        f"{SSH_USER}@{SSH_HOST}",
    ]

def vm_run(command, check=True, timeout=None):

    try:

        result = subprocess.run(
            ssh_base() + [command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "SSH command exceeded its host-side timeout."
        )

    if check and result.returncode != 0:

        raise RuntimeError(
            f"VM command failed:\n"
            f"{command}\n\n"
            f"{result.stderr.strip()}"
        )

    return result

def wait_for_vm(timeout=120, interval=2):

    add_text("Waiting for VM SSH...")

    start = time.time()

    while time.time() - start < timeout:

        if vm.poll() is not None:

            raise RuntimeError(
                f"QEMU exited unexpectedly with "
                f"code {vm.returncode}"
            )

        result = subprocess.run(
            ssh_base() + ["echo READY"],
            capture_output=True,
            text=True,
        )

        if (
            result.returncode == 0
            and
            "READY" in result.stdout
        ):

            add_text("VM SSH is ready.")
            return

        time.sleep(interval)

    raise RuntimeError(
        "VM SSH did not become ready."
    )

# --- SCP ---

def scp_to_vm(local_file, remote_directory):

    result = subprocess.run(
        [
            "scp",
            "-4",

            "-i",
            str(SSH_KEY),

            "-P",
            SSH_PORT,

            "-o",
            "StrictHostKeyChecking=no",

            "-o",
            "UserKnownHostsFile=/dev/null",

            str(local_file),

            f"{SSH_USER}@{SSH_HOST}:{remote_directory}/",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:

        raise RuntimeError(
            f"SCP failed:\n"
            f"{result.stderr.strip()}"
        )

# --- SAFE FILE NAME ---

def safe_filename(filename):

    cleaned = ""

    for char in filename:

        if (
            char.isalnum()
            or
            char in "._-"
        ):
            cleaned += char

        else:
            cleaned += "_"

    if not cleaned:
        cleaned = "submitted_file"

    return cleaned

# --- ZIP VALIDATION ---

def inspect_zip(local_path):

    files = []
    total_size = 0

    with zipfile.ZipFile(local_path) as archive:

        infos = archive.infolist()

        if len(infos) > MAX_ZIP_FILES:

            raise RuntimeError(
                f"ZIP contains too many entries "
                f"({len(infos)} > {MAX_ZIP_FILES})."
            )

        for info in infos:

            if info.is_dir():
                continue

            normalized = info.filename.replace(
                "\\",
                "/"
            )

            path = PurePosixPath(normalized)

            # Reject traversal / absolute paths
            if (
                path.is_absolute()
                or
                ".." in path.parts
            ):

                raise RuntimeError(
                    "ZIP contains an unsafe path: "
                    f"{info.filename}"
                )

            if (
                path.parts
                and
                ":" in path.parts[0]
            ):

                raise RuntimeError(
                    "ZIP contains an unsafe path: "
                    f"{info.filename}"
                )

            # Reject encrypted entries
            if info.flag_bits & 0x1:

                raise RuntimeError(
                    "Encrypted ZIP entries are not "
                    "supported by this prototype."
                )

            # Reject symbolic links
            unix_mode = info.external_attr >> 16

            if stat.S_ISLNK(unix_mode):

                raise RuntimeError(
                    "ZIP symbolic links are not supported."
                )

            if (
                info.file_size
                > MAX_ZIP_SINGLE_FILE
            ):

                raise RuntimeError(
                    f"ZIP entry too large: "
                    f"{info.filename}"
                )

            total_size += info.file_size

            if total_size > MAX_ZIP_TOTAL_SIZE:

                raise RuntimeError(
                    "ZIP expands beyond the sandbox "
                    "prototype's size limit."
                )

            files.append(normalized)

    return files, total_size

# --- ZIP ENTRYPOINT ---

def choose_zip_entrypoint(files):

    priorities = [
        "__main__.py",
        "main.py",
        "app.py",
        "run.py",
        "start.py",

        "main.sh",
        "run.sh",
        "start.sh",

        "index.js",
        "main.js",

        "main.pl",
        "main.rb",
    ]

    actual_files = [
        name
        for name in files
        if not name.endswith("/")
    ]

    # First look for common entrypoint names
    for priority in priorities:

        matches = [
            name
            for name in actual_files
            if PurePosixPath(name).name.lower()
            == priority.lower()
        ]

        if matches:

            return sorted(
                matches,
                key=lambda x: (
                    len(PurePosixPath(x).parts),
                    x
                )
            )[0]

    # Otherwise first script we understand
    supported_extensions = (
        ".py",
        ".sh",
        ".js",
        ".pl",
        ".rb",
        ".jar",
    )

    candidates = [
        name
        for name in actual_files
        if name.lower().endswith(
            supported_extensions
        )
    ]

    if candidates:

        return sorted(
            candidates,
            key=lambda x: (
                len(PurePosixPath(x).parts),
                x
            )
        )[0]

    return None

# --- STATIC ANALYSIS ---

def static_analysis(remote_file):

    quoted = shlex.quote(remote_file)

    # Identify file type
    file_result = vm_run(
        f"file -b {quoted}",
        check=False
    )

    type_text = (
        file_result.stdout.strip()
        or "Unknown"
    )

    # SHA-256
    hash_result = vm_run(
        f"sha256sum {quoted}",
        check=False
    )

    sha256 = "Unknown"

    if hash_result.returncode == 0:

        parts = hash_result.stdout.split()

        if parts:
            sha256 = parts[0]

    # File size
    size_result = vm_run(
        f"stat -c '%s' {quoted}",
        check=False
    )

    size = (
        size_result.stdout.strip()
        or "Unknown"
    )

    # Detect whether this looks like readable text
    text_check = vm_run(
        f"grep -Iq . {quoted}",
        check=False
    )

    text_preview = ""

    if text_check.returncode == 0:

        preview_result = vm_run(
            f"head -n 30 {quoted}",
            check=False
        )

        text_preview = (
            preview_result.stdout.strip()
        )

    # Look for interesting strings
    strings_result = vm_run(
        (
            f"strings -a -n 6 {quoted} "
            "2>/dev/null | "
            "grep -Ei "
            "'curl|wget|powershell|"
            "/etc/passwd|"
            "ssh|socket|subprocess|"
            "os\\.system|chmod|chown|"
            "base64|http://|https://' "
            "| head -n 30"
        ),
        check=False
    )

    interesting_strings = (
        strings_result.stdout.strip()
    )

    return {
        "type": type_text,
        "sha256": sha256,
        "size": size,
        "strings": interesting_strings,
        "text_preview": text_preview,
    }

# --- FILE MANIFEST ---

def create_manifest(output_file):

    home = shlex.quote(
        SYNTHETIC_HOME
    )

    out = shlex.quote(
        output_file
    )

    command = (
        f"find {home} "
        "-type f "
        "-print0 "
        "| sort -z "
        "| xargs -0 -r sha256sum "
        f"> {out}"
    )

    vm_run(
        command,
        check=False
    )

# --- EXECUTION COMMAND ---

def build_execution_command(remote_file):

    quoted = shlex.quote(remote_file)

    extension = (
        PurePosixPath(
            remote_file
        ).suffix.lower()
    )

    # Python
    if extension == ".py":

        return (
            f"python3 {quoted}"
        )

    # Shell
    if extension == ".sh":

        return (
            f"bash {quoted}"
        )

    # JavaScript
    if extension == ".js":

        available = vm_run(
            "command -v node",
            check=False
        )

        if available.returncode == 0:

            return (
                f"node {quoted}"
            )

        return None

    # Perl
    if extension == ".pl":

        available = vm_run(
            "command -v perl",
            check=False
        )

        if available.returncode == 0:

            return (
                f"perl {quoted}"
            )

        return None

    # Ruby
    if extension == ".rb":

        available = vm_run(
            "command -v ruby",
            check=False
        )

        if available.returncode == 0:

            return (
                f"ruby {quoted}"
            )

        return None

    # Java archive
    if extension == ".jar":

        available = vm_run(
            "command -v java",
            check=False
        )

        if available.returncode == 0:

            return (
                f"java -jar {quoted}"
            )

        return None

    # Determine whether it is an ELF executable
    result = vm_run(
        f"file -b {quoted}",
        check=False
    )

    description = (
        result.stdout.lower()
    )

    if "elf" in description:

        return (
            f"chmod +x {quoted} "
            f"&& {quoted}"
        )

    # Try executable script with a shebang
    shebang = vm_run(
        f"head -c 2 {quoted}",
        check=False
    )

    if shebang.stdout == "#!":

        return (
            f"chmod +x {quoted} "
            f"&& {quoted}"
        )

    return None

# --- BEHAVIOR EXECUTION ---

def execute_and_monitor(
    remote_file,
    working_directory
):

    add_text("")
    add_text(
        "Starting behavioral analysis..."
    )

    # Snapshot synthetic environment before
    create_manifest(
        "/tmp/glassbox_before.txt"
    )

    vm_run(
        "rm -f /tmp/glassbox_trace.txt",
        check=False
    )

    execution = build_execution_command(
        remote_file
    )

    if execution is None:

        return {
            "executed": False,
            "reason": (
                "Glassbox does not currently have an "
                "interpreter for this file type."
            ),
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "changes": "",
            "trace": "",
        }

    workdir = shlex.quote(
        working_directory
    )

    # Give the program the synthetic home
    inner_command = (
        f"cd {workdir} && "
        f"HOME={shlex.quote(SYNTHETIC_HOME)} "
        f"USER='Augustine Ramswell' "
        f"timeout {EXECUTION_TIMEOUT}s "
        f"{execution}"
    )

    # Use strace if the image already contains it.
    has_strace = vm_run(
        "command -v strace",
        check=False
    )

    if has_strace.returncode == 0:

        run_command = (
            "strace "
            "-f "
            "-qq "
            "-e trace=file,process,network "
            "-o /tmp/glassbox_trace.txt "
            f"sh -c {shlex.quote(inner_command)}"
        )

    else:

        run_command = (
            f"sh -c "
            f"{shlex.quote(inner_command)}"
        )

    result = vm_run(
        run_command,
        check=False,
        timeout=EXECUTION_TIMEOUT + 10
    )

    # Snapshot after
    create_manifest(
        "/tmp/glassbox_after.txt"
    )

    diff = vm_run(
        (
            "diff -u "
            "/tmp/glassbox_before.txt "
            "/tmp/glassbox_after.txt "
            "| tail -n 100"
        ),
        check=False
    )

    trace = ""

    if has_strace.returncode == 0:

        trace_result = vm_run(
            (
                "grep -E "
                "'connect\\(|execve\\(|"
                "unlink|rename|chmod|"
                "/etc/|/home/' "
                "/tmp/glassbox_trace.txt "
                "2>/dev/null "
                "| tail -n 60"
            ),
            check=False
        )

        trace = trace_result.stdout.strip()

    return {
        "executed": True,
        "reason": "",
        "stdout": result.stdout[-5000:],
        "stderr": result.stderr[-5000:],
        "returncode": result.returncode,
        "changes": diff.stdout[-8000:],
        "trace": trace[-8000:],
    }

# --- DISPLAY REPORT ---

def calculate_safety_score(static, behavior):

    score = 100
    reasons = []

    suspicious_strings = static.get(
        "strings",
        ""
    ).lower()

    trace = behavior.get(
        "trace",
        ""
    ).lower()

    changes = behavior.get(
        "changes",
        ""
    )

    dangerous_terms = {
        "powershell": 15,
        "/etc/passwd": 20,
        "wget": 8,
        "curl": 8,
        "base64": 5,
        "chmod": 6,
        "chown": 6,
        "subprocess": 5,
        "os.system": 10,
        "socket": 5,
    }

    for term, penalty in dangerous_terms.items():

        if term in suspicious_strings:

            score -= penalty

            reasons.append(
                f"- Suspicious reference: {term}"
            )

    if changes:

        score -= 20

        reasons.append(
            "- Synthetic files were changed"
        )

    else:

        reasons.append(
            "+ No synthetic files were changed"
        )

    suspicious_trace_terms = [
        "connect(",
        "/etc/passwd",
        "/etc/shadow",
        "unlink",
        "chmod",
        "rename",
    ]

    trace_hits = 0

    for term in suspicious_trace_terms:

        if term in trace:
            trace_hits += 1

    if trace_hits:

        score -= min(
            trace_hits * 10,
            30
        )

        reasons.append(
            f"- {trace_hits} potentially suspicious "
            f"system behaviors detected"
        )

    elif behavior.get("executed"):

        reasons.append(
            "+ No high-risk traced behavior detected"
        )

    if behavior.get("executed"):

        returncode = behavior.get(
            "returncode"
        )

        if returncode == 124:

            score -= 10

            reasons.append(
                "- Program reached execution timeout"
            )

        elif returncode == 0:

            reasons.append(
                "+ Program exited normally"
            )

        elif returncode is not None:

            score -= 5

            reasons.append(
                f"- Program exited with code "
                f"{returncode}"
            )

    else:

        reasons.append(
            "+ No executable behavior was detected"
        )

    if not suspicious_strings:

        reasons.append(
            "+ No suspicious static strings detected"
        )

    score = max(
        0,
        min(100, score)
    )

    if score >= 80:

        verdict = "LIKELY SAFE"

    elif score >= 55:

        verdict = "CAUTION"

    else:

        verdict = "SUSPICIOUS"

    return score, verdict, reasons

def show_report(
    name,
    static,
    behavior,
    zip_info=None
):

    add_text("")
    add_text("=" * 60)

    add_text(
        "GLASSBOX ANALYSIS REPORT"
    )

    add_text("=" * 60)

    add_text(
        f"File: {name}"
    )

    add_text(
        f"Type: {static['type']}"
    )

    add_text(
        f"Size: {static['size']} bytes"
    )

    add_text(
        f"SHA-256: {static['sha256']}"
    )

    # ========================================================
    # ZIP INFORMATION
    # ========================================================

    if zip_info:

        add_text("")
        add_text("ZIP WORKSPACE")

        add_text(
            f"Files: {zip_info['count']}"
        )

        add_text(
            f"Expanded size: "
            f"{zip_info['size']} bytes"
        )

        add_text(
            f"Entrypoint: "
            f"{zip_info['entrypoint']}"
        )

    # ========================================================
    # STATIC FINDINGS
    # ========================================================

    if static.get("strings"):

        add_text("")
        add_text(
            "Interesting static strings:"
        )

        add_text(
            static["strings"]
        )

    # ========================================================
    # BEHAVIOR
    # ========================================================

    add_text("")
    add_text("BEHAVIOR")

    file_type = static.get(
        "type",
        ""
    ).lower()

    is_plain_text = (
        "text" in file_type
        or
        "ascii" in file_type
        or
        "utf-8" in file_type
    )

    if not behavior["executed"]:

        if is_plain_text:

            add_text(
                "Dynamic execution: NOT REQUIRED"
            )

            add_text(
                "Plain text file — no executable "
                "behavior detected."
            )

        else:

            add_text(
                "Dynamic execution: NOT PERFORMED"
            )

            add_text(
                behavior["reason"]
            )

    else:

        add_text(
            "Dynamic execution: COMPLETED"
        )

        if behavior["returncode"] == 124:

            add_text(
                "Execution reached the sandbox "
                "time limit."
            )

        else:

            add_text(
                f"Return code: "
                f"{behavior['returncode']}"
            )

        if behavior["stdout"]:

            add_text("")
            add_text(
                "Program output:"
            )

            add_text(
                behavior["stdout"]
            )

        if behavior["stderr"]:

            add_text("")
            add_text(
                "Program error output:"
            )

            add_text(
                behavior["stderr"]
            )

        add_text("")
        add_text(
            "Changes to synthetic environment:"
        )

        if behavior["changes"]:

            add_text(
                behavior["changes"]
            )

        else:

            add_text(
                "No synthetic files changed."
            )

        if behavior["trace"]:

            add_text("")
            add_text(
                "Observed system activity:"
            )

            add_text(
                behavior["trace"]
            )

    # ========================================================
    # SAFETY SCORE
    # ========================================================

    score, verdict, reasons = (
        calculate_safety_score(
            static,
            behavior
        )
    )

    add_text("")
    add_text("=" * 60)

    add_text(
        "SAFETY ASSESSMENT"
    )

    add_text("=" * 60)

    add_text(
        f"Verdict: {verdict}"
    )

    add_text(
        f"Estimated safety score: {score}%"
    )

    add_text("")
    add_text("Reasons:")

    for reason in reasons:

        add_text(reason)

    add_text("")

    add_text(
        "This is a heuristic estimate based on "
        "observed behavior, not a guarantee that "
        "the file is safe."
    )

    add_text("")
    add_text("=" * 60)

    add_text(
        "Analysis finished."
    )

    add_text("=" * 60)

# --- ANALYZE NORMAL FILE ---

def analyze_normal_file(
    local_path,
    remote_path
):

    add_text(
        "Performing static analysis..."
    )

    static = static_analysis(
        remote_path
    )

    # Every upload receives a format-independent raw-byte inspection.
    add_text("")
    add_text(inspect_binary(local_path))

    image_info = inspect_image(local_path)
    if image_info is not None:
        add_text("")
        add_text("IMAGE INSPECTION")
        add_text(image_info)
        behavior = {
            "executed": False,
            "reason": "Image files are inspected as data and are not executed.",
            "stdout": "", "stderr": "", "returncode": None,
            "changes": "", "trace": "",
        }
    else:
        behavior = execute_and_monitor(
            remote_path,
            REMOTE_INPUT
        )

    show_report(
        local_path.name,
        static,
        behavior
    )

# --- ANALYZE ZIP ---

def analyze_zip(
    local_path,
    remote_zip
):

    add_text(
        "ZIP detected."
    )

    add_text(
        "Validating archive..."
    )

    files, total_size = inspect_zip(
        local_path
    )

    add_text(
        f"Archive contains "
        f"{len(files)} files."
    )

    entrypoint = choose_zip_entrypoint(
        files
    )

    vm_run(
        f"rm -rf "
        f"{shlex.quote(REMOTE_WORKSPACE)} "
        f"&& mkdir -p "
        f"{shlex.quote(REMOTE_WORKSPACE)}"
    )

    add_text(
        "Extracting ZIP inside sandbox..."
    )

    result = vm_run(
        (
            "python3 -m zipfile -e "
            f"{shlex.quote(remote_zip)} "
            f"{shlex.quote(REMOTE_WORKSPACE)}"
        ),
        check=False
    )

    if result.returncode != 0:

        raise RuntimeError(
            "ZIP extraction failed:\n"
            f"{result.stderr}"
        )

    listing = vm_run(
        (
            f"find "
            f"{shlex.quote(REMOTE_WORKSPACE)} "
            "-type f "
            "-printf '%P\\n' "
            "| head -n 100"
        ),
        check=False
    )

    add_text("")
    add_text(
        "Extracted workspace:"
    )

    add_text(
        listing.stdout.strip()
    )

    # Static analysis on ZIP itself
    static = static_analysis(
        remote_zip
    )

    if entrypoint is None:

        behavior = {
            "executed": False,
            "reason": (
                "ZIP was safely extracted and inspected, "
                "but no supported entrypoint was found."
            ),
            "stdout": "",
            "stderr": "",
            "returncode": None,
            "changes": "",
            "trace": "",
        }

        entry_display = (
            "No supported entrypoint found"
        )

    else:

        entry_remote = (
            REMOTE_WORKSPACE
            + "/"
            + entrypoint
        )

        parent = str(
            PurePosixPath(
                entry_remote
            ).parent
        )

        add_text("")
        add_text(
            f"Detected entrypoint: "
            f"{entrypoint}"
        )

        behavior = execute_and_monitor(
            entry_remote,
            parent
        )

        entry_display = entrypoint

    show_report(
        local_path.name,
        static,
        behavior,
        zip_info={
            "count": len(files),
            "size": total_size,
            "entrypoint": entry_display,
        }
    )

def process_selected_file(local_path, original_name):
    """Analyze a saved upload without executing any submitted code on the host."""
    safe_name = safe_filename(original_name)
    vm_run(
        f"rm -rf {shlex.quote(REMOTE_INPUT)} {shlex.quote(REMOTE_WORKSPACE)} "
        f"&& mkdir -p {shlex.quote(REMOTE_INPUT)}"
    )
    # Staging path has an intentionally simple name for scp remote shell safety.
    stage_path = local_path.parent / (".glassbox_" + safe_name)
    shutil.copyfile(local_path, stage_path)
    try:
        add_text("Copying file into isolated VM...")
        scp_to_vm(stage_path, REMOTE_INPUT)
    finally:
        stage_path.unlink(missing_ok=True)
    remote_file = REMOTE_INPUT + "/" + stage_path.name
    add_text("File transferred.")
    if zipfile.is_zipfile(local_path):
        analyze_zip(local_path, remote_file)
    else:
        analyze_normal_file(local_path, remote_file)

def boot_sandbox():
    """Start the original ARM64 Linux sandbox once, on the first analysis."""
    global vm, _BOOTED
    if _BOOTED and vm is not None and vm.poll() is None:
        return
    stop_vm()
    _BOOTED = False
    # ============================================================

    add_text(
        "Detecting computer..."
    )

    system = platform.system()
    arch = platform.machine().lower()

    add_text(
        f"Host: {system} / {arch}"
    )

    # ============================================================
    # CURRENT TESTED CONFIGURATION
    # ============================================================

    if system != "Linux":

        raise RuntimeError(
            "Current hackathon prototype is "
            "configured for Linux."
        )

    qemu = "qemu-system-aarch64"

    qcow2_file = (
        BASE_DIR /
        "debian-12-genericcloud-arm64.qcow2"
    )

    firmware_candidates = [
        Path("/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"),
        Path("/usr/share/AAVMF/AAVMF_CODE.fd"),
    ]
    firmware = next((p for p in firmware_candidates if p.is_file()), firmware_candidates[0])

    # KVM only accelerates ARM64 guests on compatible ARM64 Linux hosts.
    # Other Linux architectures can emulate ARM64 through QEMU TCG.
    use_kvm = arch in ("arm64", "aarch64") and Path("/dev/kvm").exists()
    accelerator = "kvm" if use_kvm else "tcg"
    guest_cpu = "host" if use_kvm else "cortex-a72"
    add_text(f"QEMU accelerator: {accelerator} (guest CPU: {guest_cpu})")

    # ============================================================
    # CHECK REQUIRED COMPONENTS
    # ============================================================

    required_paths = [
        qcow2_file,
        SEED_FILE,
        PAYLOAD_PATH,
        SSH_KEY,
        firmware,
    ]

    for required in required_paths:

        if not required.exists():

            raise RuntimeError(
                f"Required file missing: "
                f"{required}"
            )

    if shutil.which(qemu) is None:

        raise RuntimeError(
            f"{qemu} is not installed."
        )

    # ============================================================
    # QEMU COMMAND
    # ============================================================

    cmd = [
        qemu,

        "-accel",
        accelerator,

        "-M",
        "virt",

        "-cpu",
        guest_cpu,

        "-m",
        "4096",

        "-smp",
        "4",

        "-bios",
        str(firmware),

        # Discard disk changes when VM exits
        "-snapshot",

        "-drive",
        (
            f"if=none,"
            f"file={qcow2_file},"
            f"format=qcow2,"
            f"id=hd0"
        ),

        "-device",
        "virtio-blk-device,drive=hd0",

        "-drive",
        (
            f"if=none,"
            f"file={SEED_FILE},"
            f"format=raw,"
            f"id=seed0"
        ),

        "-device",
        "virtio-blk-device,drive=seed0",

        # Host can SSH in.
        # Guest-initiated external networking is restricted.
        "-nic",
        (
            "user,"
            "restrict=on,"
            f"hostfwd=tcp:127.0.0.1:{SSH_PORT}-:22"
        ),

        "-nographic",
    ]

    # ============================================================
    # START VM
    # ============================================================

    add_text(
        "Starting isolated virtual machine..."
    )

    vm = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True
    )

    add_text(
        f"VM PID: {vm.pid}"
    )

    # ============================================================
    # WAIT FOR VM
    # ============================================================

    wait_for_vm()

    # ============================================================
    # PREPARE SYNTHETIC HOME
    # ============================================================

    add_text(
        "Preparing synthetic environment..."
    )

    vm_run(
        f"sudo mkdir -p "
        f"{shlex.quote(SYNTHETIC_HOME)}"
    )

    vm_run(
        f"sudo chown sandbox:sandbox "
        f"{shlex.quote(SYNTHETIC_HOME)}"
    )

    # ============================================================
    # PACKAGE SYNTHETIC DATA
    # ============================================================

    archive_path = Path(tempfile.mkstemp(prefix="glassbox_synthetic_", suffix=".tar")[1])

    add_text(
        "Loading synthetic files..."
    )

    try:

        with tarfile.open(
            archive_path,
            "w"
        ) as archive:

            for item in PAYLOAD_PATH.iterdir():

                archive.add(
                    item,
                    arcname=item.name
                )

        scp_to_vm(
            archive_path,
            "/tmp"
        )

        vm_run(
            (
                "sudo tar -xf "
                f"{shlex.quote('/tmp/' + archive_path.name)} "
                f"-C "
                f"{shlex.quote(SYNTHETIC_HOME)}"
            )
        )

        vm_run(
            (
                "sudo chown -R "
                "sandbox:sandbox "
                f"{shlex.quote(SYNTHETIC_HOME)}"
            )
        )

        vm_run("rm -f " + shlex.quote("/tmp/" + archive_path.name))

    finally:

        if archive_path.exists():

            archive_path.unlink()

    # ============================================================
    # READY
    # ============================================================

    vm_run(
        f"mkdir -p "
        f"{shlex.quote(REMOTE_INPUT)} "
        f"{shlex.quote(REMOTE_WORKSPACE)}"
    )

    add_text("")
    add_text(
        "Glassbox is ready."
    )

    add_text(
        "Drop a file above to analyze it."
    )

    _BOOTED = True

def _free_local_port():
    """Reserve a candidate SSH forwarding port for an isolated VM process."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_analysis(job_id, local_path, original_name, temp_dir, selected_os):
    """Queue jobs and run each scan in its own QEMU-owning process."""
    try:
        with WORKER_SLOTS:
            set_progress(job_id, 10, "Starting isolated VM worker")
            if selected_os == "windows":
                from windows_analysis import inspect_windows_file
                report = inspect_windows_file(local_path, original_name)
                with JOBS_LOCK:
                    JOBS[job_id].update(percent=100, stage="Static inspection complete",
                                        done=True, report=report)
                return
            env = os.environ.copy()
            env["GLASSBOX_SSH_PORT"] = str(_free_local_port())
            # Every worker process owns its QEMU instance, SSH port and report.
            command = [sys.executable, str(BASE_DIR / "main.py"),
                       "--worker", str(local_path), original_name]
            result = subprocess.run(command, env=env, capture_output=True,
                                    text=True, timeout=900)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout)[-3000:]
                                   or "Worker failed.")
            report = result.stdout
            # Run the local AI model on the completed report before publishing.
            # Keep the underlying observations available for verification.
            set_progress(job_id, 95, "Summarizing findings with local AI")
            summary = summarize_report(report)
            if summary:
                report = "AI SUMMARY\n" + summary + "\n\nDETAILED ANALYSIS\n" + report
            else:
                report = ("AI summary unavailable (model disabled or not cached).\n\n"
                          "DETAILED ANALYSIS\n" + report)
            with JOBS_LOCK:
                JOBS[job_id].update(percent=100, stage="Analysis complete",
                                    done=True, report=report)
    except subprocess.TimeoutExpired:
        with JOBS_LOCK:
            JOBS[job_id].update(done=True, error="Worker exceeded 15-minute limit.")
    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id].update(done=True, error=str(exc))
    finally:
        temp_dir.cleanup()


def worker_main(local_path, original_name):
    """CLI entry point: one process, one VM, one report."""
    try:
        if zipfile.is_zipfile(local_path):
            inspect_zip(local_path)
        boot_sandbox()
        process_selected_file(Path(local_path), original_name)
        print("\n".join(_ANALYSIS_MESSAGES))
        return 0
    except Exception as exc:
        print(f"Worker error: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_vm()


@app.route("/", methods=["GET", "POST"])
def index():
    """Display the upload interface and accept legacy form submissions."""
    if request.method == "POST":
        return start_analysis()
    return render_template("index.html", report=None, error=None)


@app.route("/analyze", methods=["POST"])
def start_analysis():
    """Save a file and start background analysis."""
    selected_os = request.form.get("os", "linux")
    if selected_os not in ("linux", "windows", "macos"):
        return jsonify(error="Invalid OS selection."), 400
    if selected_os != "linux":
        return jsonify(error="Windows and macOS analysis are future goals. Select Linux."), 400

    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify(error="Choose a file to analyze."), 400

    temp_dir = None
    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="glassbox_")
        safe_name = safe_filename(Path(uploaded.filename).name)
        local_path = Path(temp_dir.name) / safe_name
        uploaded.save(local_path)
        job_id = uuid.uuid4().hex
        with JOBS_LOCK:
            # Keep only recent jobs to avoid unbounded status history.
            if len(JOBS) >= 30:
                oldest = next(iter(JOBS))
                JOBS.pop(oldest)
            JOBS[job_id] = dict(percent=5, stage="Queued for available VM worker", done=False, report="", error=None)
        threading.Thread(
            target=run_analysis,
            args=(job_id, local_path, safe_name, temp_dir, selected_os),
            daemon=True,
        ).start()
        return jsonify(job_id=job_id), 202
    except Exception as exc:
        if temp_dir is not None:
            temp_dir.cleanup()
        return jsonify(error=str(exc)), 500


@app.route("/progress/<job_id>", methods=["GET"])
def progress(job_id):
    """Return scan progress for browser polling."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return jsonify(error="Unknown analysis."), 404
        return jsonify(job)


@app.errorhandler(RequestEntityTooLarge)
def too_large(exc):
    """Show a friendly error for uploads exceeding the size limit."""
    return render_template("index.html", report=None, error="File exceeds 30 MiB upload limit."), 413

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        sys.exit(worker_main(sys.argv[2], sys.argv[3]))
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True, use_reloader=False)
    