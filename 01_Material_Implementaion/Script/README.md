# Shared Fraud Agent Script

This folder contains the reusable agentic fraud-detection runner used across challenge datasets.

## Files

- `main.py`: CLI entrypoint, output generation, final calibration.
- `agent.py`: LLM orchestration and ReAct workflow.
- `tools.py`: dataset loading, scoring tools, investigation utilities.
- `requirements.txt`: Python dependencies.
- `.env.example`: required environment variables template.

## Python Version

Use Python 3.10, 3.11, 3.12, or 3.13.
Python 3.14 is not supported by Langfuse.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Fill `.env` with your values.

## Required Dataset Schema

Required:
- `transactions.csv`
- `users.json`
- `locations.json`

Optional:
- `sms.json`
- `mails.json`

## Run Example

```bash
python main.py \
  --dataset "../01_The+Truman+Show+-+train/The+Truman+Show+-+validation/The Truman Show - validation" \
  --model "deepseek/deepseek-v3.2" \
  -o "../validation_outputs/output_truman_validation.txt"
```

## Notes

- Use a whitelisted model from `../../00_How_It_Works/model_whitelist.md`.
- Keep output as ASCII text, one transaction ID per line.
- Do not commit real secrets.