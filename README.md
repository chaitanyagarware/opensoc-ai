# 🛡️ OpenSOC-AI

> Most small businesses cannot afford a SOC.  
> So I built one using AI.
> **Democratizing Security Operations: An LLM-Based Log Analysis Framework for Resource-Constrained Organizations**

OpenSOC-AI is a lightweight, local LLM-powered SOC automation system that analyzes security logs, detects threats, maps MITRE ATT&CK techniques, and generates actionable remediation — all on consumer hardware.

📄 Paper: https://arxiv.org/abs/2604.26217  
🌐 Live Demo: https://chaitanyagarware.github.io/opensoc-ai/



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Model: TinyLlama-1.1B](https://img.shields.io/badge/Model-TinyLlama--1.1B-blue)](https://huggingface.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0)
[![Fine-tuning: LoRA](https://img.shields.io/badge/Fine--tuning-LoRA%20%2F%20QLoRA-green)](https://github.com/huggingface/peft)
[![Hardware: T4 GPU](https://img.shields.io/badge/Hardware-T4%20GPU-orange)](https://colab.research.google.com)



OpenSOC-AI is a lightweight, open-source security log analyzer that uses a fine-tuned 1.1B parameter language model to automatically classify threats, map MITRE ATT&CK techniques, and generate remediation recommendations — all runnable on consumer-grade hardware.

---

## 📊 Results

| Metric | Baseline (TinyLlama) | Fine-Tuned (OpenSOC-AI) | Improvement |
|--------|---------------------|------------------------|-------------|
| Threat Classification Accuracy | 0.0% | **68.0%** | +68 pp |
| Severity Classification Accuracy | 28.0% | **58.0%** | +30 pp |
| Trainable Parameters | 1.1B | **12.6M (1.13%)** | 98.9% reduction |
| Training Time | — | **4m 21s** | T4 GPU |

---

## 🗂️ Repository Structure

```
opensoc-ai/
├── notebooks/
│   ├── 01_train.ipynb          # Fine-tuning: install → train → save adapters
│   └── 02_eval.ipynb           # Evaluation: baseline vs fine-tuned comparison
├── web/
│   └── opensoc-ui.jsx          # React web interface (single log + batch file scan)
├── data/
│   ├── soc_train.json          # 450 training examples (hosted on Google Drive)
│   └── soc_eval.json           # 50 evaluation examples (hosted on Google Drive)
├── adapters/
│   └── README.md               # Instructions to download adapters from Google Drive
├── docs/
│   └── opensoc-paper.docx      # Research paper draft
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

## ⚡ Run in 5 Lines

```python
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base_model = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
adapter_path = "Chaitanyag01/opensoc-ai"

tokenizer = AutoTokenizer.from_pretrained(base_model)
model = AutoModelForCausalLM.from_pretrained(base_model)

model = PeftModel.from_pretrained(model, adapter_path)

input_text = "Failed login attempts detected from multiple IPs"

inputs = tokenizer(input_text, return_tensors="pt")
outputs = model.generate(**inputs, max_new_tokens=200)

print(tokenizer.decode(outputs[0]))

### 1. Fine-tune (Google Colab)

Open `notebooks/01_train.ipynb` in Google Colab with a **T4 GPU runtime**.

The notebook will:
- Install all dependencies
- Mount your Google Drive
- Fine-tune TinyLlama-1.1B with LoRA on `soc_train.json`
- Save **only the LoRA adapters** to `MyDrive/opensoc-adapters/`

### 2. Evaluate

Open `notebooks/02_eval.ipynb` to run baseline vs fine-tuned evaluation on `soc_eval.json`.

### 3. Run the Web UI

```bash
# Clone the repo
git clone https://github.com/chaitanyagarware/opensoc-ai.git
cd opensoc-ai

# Install dependencies
npm install

# Copy the JSX into a Vite/Next.js project and run
# Or paste opensoc-ui.jsx directly into claude.ai to preview
```

---

## 🔧 Model Details

| Component | Value |
|-----------|-------|
| Base Model | TinyLlama/TinyLlama-1.1B-Chat-v1.0 |
| Quantization | 4-bit NF4 (QLoRA) |
| LoRA rank | r=16, alpha=32 |
| Target modules | q_proj, k_proj, v_proj, o_proj, gate/up/down_proj |
| Training data | 450 labeled SOC log examples |
| Epochs | 3 |
| Final training loss | 0.0886 |
| Adapter size | ~50MB |

---

## 📋 Output Format

For each log entry, OpenSOC-AI returns:

```
THREAT_TYPE:     SQL Injection — Union
MITRE_ID:        T1190
SEVERITY:        HIGH
RISK_SCORE:      82
EVIDENCE:        OR 1=1-- pattern detected in query param; user-agent: burpsuite
RECOMMENDATION:  Implement parameterized queries; block known scanner UAs at WAF
```

---

## 📁 Data & Adapters

Training data and adapter weights are stored on Google Drive (too large for GitHub):

- **Training data**: `MyDrive/soc_train.json` (450 examples)
- **Eval data**: `MyDrive/soc_eval.json` (50 examples)
- **Adapters**: `MyDrive/opensoc-adapters/` → see `adapters/README.md`

---

## ⚠️ Critical Implementation Notes

These mistakes will corrupt your model — learned the hard way:

```python
# ❌ NEVER do this with 4-bit quantized models
model.merge_and_unload()          # corrupts weights
model.save_pretrained(full_path)  # embeds broken quantization config

# ✅ ALWAYS do this instead
trainer.model.save_pretrained(adapter_path)           # saves adapters only
PeftModel.from_pretrained(base_model, adapter_path)   # correct reload
```

---

## 🧱 Tech Stack

- **Model**: TinyLlama-1.1B-Chat-v1.0
- **Fine-tuning**: LoRA via PEFT 0.10.0 + QLoRA via bitsandbytes
- **Training**: TRL SFTTrainer
- **Hardware**: Google Colab T4 GPU
- **Web UI**: React + Claude API
- **Language**: Python 3.12

---

## 📄 Citation

# OpenSOC-AI

📄 Paper: https://arxiv.org/abs/2604.26217

If you use this work, please cite:

```bibtex
@article{garware2026opensoc,
  title={OpenSOC-AI: Automating Threat Classification in Security Operations Centers Using Fine-Tuned Language Models},
  author={Garware, Chaitanya},
  year={2026},
  journal={arXiv preprint arXiv:2604.26217}
}
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
