# AI Agent Challenge 2026 - Final Archive

This directory is prepared for GitHub publication as a completed challenge archive.

Status: challenge finished.

## Final Result

- Leaderboard position: **138 / 1971 teams**

## What This Repository Contains

This project stores:
- official challenge material and rules;
- train and validation datasets used during the competition;
- a shared agentic fraud-detection script;
- produced validation outputs.


**Agentic System Design:**
The solution implements a multi-agent ReAct orchestrator with specialized components:
- **Data Analyst Agent** - Extracts pattern signatures from transaction history, user personas, and behavioral context
- **Anomaly Detection Engine** - Applies heuristic baseline + LLM-based decision making with economic impact awareness
- **Review Agent** - Secondary review pass for uncertain/disputed cases to improve precision-recall balance

**Key Optimizations:**
| Metric | Initial | Optimized | Outcome |
|--------|---------|-----------|---------|
| Recursion Limit | 90 | 70 (adaptive by dataset) | 30% token overhead reduction |
| Token Usage | 1800 (max) | 1200 (max) | Cost efficiency maintained |
| Fallback Models | 3 duplicates | 1 unique | Failure cascade prevention |
| Z-Score Threshold | 3.0 | 3.5 | Enhanced outlier detection |
| Model Invocations | Full batch | Adaptive calibration | Budget-aware selection |

**Detection Quality Improvements:**
- Enhanced system prompt with explicit fraud signals (behavioral anomalies, economic misalignment, channel anomalies, location contradictions)
- Implemented balance-impact scorer detecting transactions causing >50% balance drops
- Added whitelisted legitimate patterns (salary, recurring utilities, subscriptions) for false positive reduction
- Calibrated ranking to prioritize high-value fraud detection

**Technology Stack:**
- LangChain (agentic orchestration), OpenRouter API (LLM access), Langfuse (observability & tracing)
- Environment: Python 3.10+, Jupyter for experimentation, Makefile for reproducible setup
- Infrastructure: Full .env-based credential management, token budget tracking, submission session logging

## Directory Structure

```text
02_AI_Agents_Challenge/
├── README.md
├── 00_How_It_Works/
│   ├── README.md
│   ├── api_guidelines.md
│   ├── model_whitelist.md
│   ├── submission_guide.md
│   └── challenge_day_checklist.md
└── 01_Material_Implementaion/
    ├── AIAgentChallenge-ProblemStatement16April.md
    ├── 01_The+Truman+Show+-+train/
    ├── 02_Brave+New+World+-+train/
    ├── 03_Deus+Ex+-+train/
    ├── Script/
    │   ├── main.py
    │   ├── agent.py
    │   ├── tools.py
    │   ├── requirements.txt
    │   ├── .env.example
    │   └── README.md
    └── validation_outputs/
```

Notes:
- `__MACOSX` directories are extraction artifacts and can be ignored.
- Folder name `Implementaion` is intentionally preserved to avoid breaking existing paths.

## Dataset Compatibility With Shared Script

The shared script in `01_Material_Implementaion/Script/` is reusable across datasets that expose the expected schema.

Required files:
- `transactions.csv`
- `users.json`
- `locations.json`

Optional files:
- `sms.json`
- `mails.json`

Current availability:

| Dataset block | Train files present | Validation files present | Runnable with Script |
|---|---:|---:|---:|
| The Truman Show | Yes | Yes | Yes |
| Brave New World | No | Yes | Validation only |
| Deus Ex | Yes | Yes | Yes |

## Quick Start

1. Move into the shared script folder:

```bash
cd 01_Material_Implementaion/Script
```

2. Create and activate a Python virtual environment.

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Create your environment file:

```bash
cp .env.example .env
```

5. Fill `.env` with your keys and team name.

6. Run on a dataset folder that contains the required files:

```bash
python main.py \
  --dataset "../01_The+Truman+Show+-+train/The+Truman+Show+-+validation/The Truman Show - validation" \
  --model "deepseek/deepseek-v3.2" \
  -o "../validation_outputs/output_truman_validation.txt"
```

## Publish Readiness Notes

- `.env` is ignored through `.gitignore`; only `.env.example` is committed.
- Python cache/editor temporary files are ignored.
- Existing output files are kept as experiment artifacts.
