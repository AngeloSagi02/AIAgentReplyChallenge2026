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

The challenge objective was to build an agent-based system that detects fraudulent transactions while balancing:
- detection quality;
- economic impact of decisions;
- latency;
- cost efficiency;
- architecture quality.

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

## Challenge Rules Snapshot

- Solution must be agent-based (LLM orchestration is central).
- Output must be ASCII text, one transaction ID per line.
- Empty output or all-transactions output is invalid.
- Evaluation submissions were one-shot.
- Langfuse session tracking was mandatory.

For full details, see files inside `00_How_It_Works/`.

## Publish Readiness Notes

- `.env` is ignored through `.gitignore`; only `.env.example` is committed.
- Python cache/editor temporary files are ignored.
- Existing output files are kept as experiment artifacts.
