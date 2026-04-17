# 03 Deus Ex

Questa cartella contiene:

- `Angelo_AgentSpace_deus_ex_mid_smoke/`: implementazione agente fraud detection
- `Deus Ex - train/`: dataset train
- `Deus+Ex+-+validation/Deus Ex - validation/`: dataset validation
- `__MACOSX/`: artefatti non necessari

## File principali

- `Angelo_AgentSpace_deus_ex_mid_smoke/main.py`: runner CLI
- `Angelo_AgentSpace_deus_ex_mid_smoke/agent.py`: orchestrazione LLM + fallback
- `Angelo_AgentSpace_deus_ex_mid_smoke/tools.py`: tool di analisi e scoring

## Setup rapido

Da questa cartella:

```bash
/home/angelo/Desktop/AIAgent/.venv/bin/pip install -r Angelo_AgentSpace_deus_ex_mid_smoke/requirements.txt
```

Variabili ambiente richieste:

- `OPENROUTER_API_KEY`
- `TEAM_NAME`

## Esecuzione su train (DeepSeek 3.2)

```bash
/home/angelo/Desktop/AIAgent/.venv/bin/python Angelo_AgentSpace_deus_ex_mid_smoke/main.py \
  --dataset "Deus Ex - train" \
  --model "deepseek/deepseek-v3.2" \
  --quiet \
  --output "Angelo_AgentSpace_deus_ex_mid_smoke/output_deus_ex_train_deepseek_v3_2.txt"
```

## Esecuzione su validation (DeepSeek 3.2)

```bash
/home/angelo/Desktop/AIAgent/.venv/bin/python Angelo_AgentSpace_deus_ex_mid_smoke/main.py \
  --dataset "Deus+Ex+-+validation/Deus Ex - validation" \
  --model "deepseek/deepseek-v3.2" \
  --quiet \
  --output "Angelo_AgentSpace_deus_ex_mid_smoke/output_deus_ex_validation_deepseek_v3_2.txt"
```

## Output

Output atteso: file `.txt` con un transaction UUID per riga.
