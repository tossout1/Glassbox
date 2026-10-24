"""Glassbox-owned lightweight neural report classifier and evidence-grounded summarizer.

Train with: python3 glassbox_nn.py --train
No external pretrained models or network downloads are used.
Training data are synthetic and must not be mistaken for validated malware labels.
"""
import argparse
import json
import os
import re
from pathlib import Path

import torch
from torch import nn

ROOT = Path(__file__).resolve().parent
WEIGHTS = ROOT / "models" / "glassbox_nn.pt"
FEATURES = ("suspicious", "timeout", "not_performed", "completed", "network",
            "filesystem", "process", "no_high_risk", "static_strings", "error")
PATTERNS = (
    r"verdict:\\s*suspicious|potentially suspicious|suspicious reference",
    r"execution reached the sandbox|execution timeout|timed out",
    r"dynamic execution:\\s*not performed",
    r"dynamic execution:\\s*completed",
    r"network|connect\\(",
    r"file changes|filesystem|created|deleted|modified",
    r"process|execve|fork",
    r"no high-risk traced behavior detected",
    r"no suspicious static strings detected",
    r"error|failed|exception",
)
LABELS = ("limited evidence", "observed activity", "potentially suspicious activity")


def features(report):
    low = report.lower()
    return torch.tensor([float(bool(re.search(p, low))) for p in PATTERNS],
                        dtype=torch.float32)


class ReportNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.layers = nn.Sequential(nn.Linear(len(FEATURES), 24), nn.ReLU(),
                                    nn.Linear(24, 12), nn.ReLU(), nn.Linear(12, 3))

    def forward(self, x):
        return self.layers(x)


def training_examples():
    """Synthetic labeled combinations; classification is advisory only."""
    xs, ys = [], []
    for mask in range(1 << len(FEATURES)):
        bits = [(mask >> i) & 1 for i in range(len(FEATURES))]
        # Suspicious evidence outweighs ordinary observed activity.
        label = (2 if bits[0] or (bits[4] and bits[9])
                 else 0 if bits[2] or not bits[3] else 1)
        xs.append(bits)
        ys.append(label)
    return torch.tensor(xs, dtype=torch.float32), torch.tensor(ys)


def train(epochs=100):
    torch.manual_seed(42)
    torch.set_num_threads(min(2, torch.get_num_threads()))
    model = ReportNet()
    x, y = training_examples()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.012)
    for _ in range(epochs):
        optimizer.zero_grad()
        loss = nn.functional.cross_entropy(model(x), y)
        loss.backward()
        optimizer.step()
    WEIGHTS.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), WEIGHTS)
    print(f"Saved locally trained neural model to {WEIGHTS}")


def summarize_report(report):
    """Return two evidence-grounded sentences, or None when untrained."""
    if os.environ.get("GLASSBOX_AI_ENABLED", "1") == "0" or not WEIGHTS.exists():
        return None
    try:
        model = ReportNet()
        # Only load model weights, never executable pickled objects.
        model.load_state_dict(torch.load(WEIGHTS, map_location="cpu", weights_only=True))
        model.eval()
        bits = features(report)
        with torch.inference_mode():
            label = LABELS[int(model(bits.unsqueeze(0)).argmax(dim=1).item())]
        status = ("was not dynamically executed" if bits[2] else
                  "completed dynamic execution" if bits[3] else
                  "has no confirmed completed execution in this report")
        observations = []
        if bits[0]: observations.append("suspicious references or trace indicators")
        if bits[1]: observations.append("an execution timeout")
        if bits[4]: observations.append("network-related evidence")
        if bits[5]: observations.append("filesystem-related evidence")
        if bits[6]: observations.append("process-related evidence")
        if bits[9]: observations.append("reported errors")
        if not observations: observations.append("no specific high-risk indicators in the parsed report")
        detail = ", ".join(observations[:4])
        return (f"The Glassbox analysis {status} and recorded {detail}. "
                f"Its locally trained neural classifier categorized the report as {label}; "
                "this is an experimental classification based on synthetic training examples, not proof of file safety.")
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Glassbox neural summary unavailable: {exc}", file=__import__("sys").stderr)
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", action="store_true", help="Train and save the local neural model")
    args = parser.parse_args()
    if args.train:
        train()
    else:
        parser.error("Use --train to train the model")
