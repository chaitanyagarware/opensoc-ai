# 🛡️ OpenSOC-AI

> Most small businesses cannot afford a SOC.  
> So I built one using AI.

OpenSOC-AI is a lightweight, open-source security log analysis framework that uses a fine-tuned TinyLlama-1.1B model with LoRA (QLoRA) to automatically:

- Classify threats from raw logs  
- Map attacks to MITRE ATT&CK techniques  
- Assign severity and risk scores  
- Generate actionable remediation recommendations  

All running locally on consumer hardware — no expensive APIs required.

---

## 📄 Research Paper
https://arxiv.org/abs/2604.26217  

---

## 🌐 Live Demo
https://chaitanyagarware.github.io/opensoc-ai/

---

## 🚀 Demo
(Add your demo.gif in assets/)

---

## ❓ Why OpenSOC-AI?

- SMBs cannot afford full SOC teams  
- Logs go unanalyzed  
- Attacks remain undetected  

---

## 📊 Results

| Metric | Baseline | OpenSOC-AI | Improvement |
|--------|----------|------------|------------|
| Threat Classification | 0% | 68% | +68 pp |
| Severity Accuracy | 28% | 58% | +30 pp |

---

## ⚡ Quick Start

```python
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base_model = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
adapter_path = "chaitanyagarware/opensoc-ai"

tokenizer = AutoTokenizer.from_pretrained(base_model)
model = AutoModelForCausalLM.from_pretrained(base_model)

model = PeftModel.from_pretrained(model, adapter_path)

input_text = "Failed login attempts detected from multiple IPs"

inputs = tokenizer(input_text, return_tensors="pt")
outputs = model.generate(**inputs, max_new_tokens=200)

print(tokenizer.decode(outputs[0]))
```

---

## 📌 Citation

```bibtex
@article{garware2026opensocai,
  title={OpenSOC-AI: Democratizing Security Operations with Parameter Efficient LLM Log Analysis},
  author={Garware, Chaitanya Vilas and Zisad, Sharif Noor},
  journal={arXiv preprint arXiv:2604.26217},
  year={2026}
}
```

---

## ⭐ Support

Give a ⭐ if you find this useful.

---

## 📜 License

MIT License
