# Local PyTorch AI summary setup

Glassbox summarizes completed sandbox reports in one or two sentences with a
local PyTorch/Transformers language model. This is optional: if the model is
missing, the full original report is still shown.

On the **host** computer (not inside the QEMU guest), install a compatible
PyTorch build for your Python version and CPU architecture. On Raspberry Pi 5,
PyTorch wheel availability depends on the OS and Python version.

```bash
python3 -m pip install torch transformers huggingface_hub
```

Download the default model once while connected to the internet:

```bash
python3 -c "from huggingface_hub import snapshot_download; snapshot_download('Qwen/Qwen2.5-0.5B-Instruct')"
```

Then start Glassbox normally:

```bash
python3 main.py
```

By default the model loads only from the local Hugging Face cache. Set
`GLASSBOX_AI_MODEL` to a locally cached Hugging Face model ID or local model
directory to change models. Set `GLASSBOX_AI_ENABLED=0` to disable summaries.

Note: Each analysis currently runs in its own worker process, so the model is
loaded separately per active worker. Running multiple simultaneous AI summaries
can consume substantial RAM on an 8 GB Raspberry Pi. AI inference has not been
benchmarked or tested on this device.

Security reports can contain untrusted text; the AI summary is explanatory and
must not replace the original observations or safety assessment.
