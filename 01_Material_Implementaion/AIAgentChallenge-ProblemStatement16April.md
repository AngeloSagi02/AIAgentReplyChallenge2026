# Reply Mirror

Problem Statement - 16th April 2026

## Abstract

In the futuristic digital metropolis of Reply Mirror, the financial institutions
MirrorPay are synonymous with reliability and speed: cloud data platforms
capable of processing billions of transactions for millions of customers.

In this highly interconnected world, most transactions are monitored, data is
widely accessible and privacy is increasingly limited. As key managers of
economic activity, you guide financial flows and support trust in digital systems.

As a member of The Eye, you are enrolled to intelligently, responsively and
dynamically monitor the system. The mission is clear: when artificial
intelligence becomes the weapon of fraudsters, only an even more advanced
intelligence can restore balance.

## 1. Problem Statement

It is 2087 and the digital metropolis of Reply Mirror thrives on transparency:
almost every piece of personal data is publicly accessible. Financial
institutions like MirrorPay not only manage the flow of economic transactions,
but also hold vast troves of demographic and behavioral data about their
citizens.

In this data-rich world, fraudulent behavior hides in plain sight, blending with
legitimate activity. Your mission as The Eye is to detect and neutralize fraud,
preserving system integrity and protecting honest citizens.

The Mirror Hackers are adaptive and strategic. They constantly reshape their
patterns to evade detection. Their tactics include:

- targeting new merchants and transaction categories;
- shifting temporal habits (for example from daytime to late-night activity);
- operating across changing geographic regions and jurisdictions;
- varying transaction amounts and frequency;
- creating new deceptive behavioral sequences.

At the heart of the challenge lies the constant evolution of fraudulent activity.
Static models fail; only dynamic and adaptive systems can keep up.

### Challenge Flow

The challenge unfolds in five levels.

- At each level, teams receive a training dataset representing economic
  transactions between Reply Mirror citizens.
- Additional datasets provide varying levels of information about citizens,
  communications and habits.
- Each level also includes an evaluation dataset of comparable difficulty.
- Only evaluation datasets count toward official score.
- For each evaluation dataset, only the first submission is accepted and final.

Teams must design cooperative intelligent agents that identify anomalies while
fraud strategies evolve over time. For every transaction, the system must decide
whether it is legitimate or fraudulent.

The leaderboard rewards resilience and adaptability across all levels.

### Challenge Goal

Design an agent-based system capable of:

- detecting fraud that evolves over time and blends with legitimate behavior;
- anticipating new attack patterns using memory of past interactions;
- responding in real time to sudden changes without performance degradation;
- keeping false positives low and avoiding unnecessary transaction blocks.

Decision errors have asymmetric costs:

- false positive: economic and reputational losses;
- false negative: significant financial damage.

Final score combines accuracy, temporal stability and adaptability to structural
data changes.

## 2. Input Format

The input consists of datasets with increasing complexity. Multiple data sources
are provided.

### Transactions.csv (T records)

- Transaction ID: unique transaction identifier;
- Sender ID: unique sender identifier;
- Recipient ID: unique recipient identifier;
- Transaction Type:
  - bank transfer
  - in-person payment
  - e-commerce
  - direct debit
  - withdrawal
- Amount;
- Location (only for in-person payments);
- Payment Method:
  - debit card
  - mobile device
  - smartwatch
  - GooglePay
  - PayPal
- Sender IBAN (only for bank transfers);
- Recipient IBAN (only for bank transfers);
- Balance after transaction;
- Timestamp.

### Locations

Geo-referenced citizen data captured via GPS systems, including:

- BioTag: unique citizen identifier;
- Datetime;
- Lat;
- Lng.

### Users

Summary of citizen personal data.

### Conversations

Threads of conversations, including:

- User ID;
- SMS complete textual thread.

### Messages

Email interactions, including:

- mail: complete textual thread.

## 3. Output Format

The output must be an ASCII text file.

- Each line is separated by newline.
- Each line contains one suspected fraudulent Transaction ID.

Line format:

```
t
```

Where `t` is one Transaction ID from input.

Output is invalid if:

- no transactions are reported;
- all transactions are reported;
- less than 15% of fraudulent transactions are correctly identified.

## 4. Scoring Rules

Evaluation uses a composite score across two key dimensions, with economic
impact as primary driver.

Goal: not a static deterministic high-accuracy model, but an agent-based AI
system that is economically sustainable and operationally efficient in
production-like conditions.

### Accuracy

Measures ability to detect fraud while minimizing unnecessary blocks of
legitimate transactions.

### Additional Metrics

Cost, speed and efficiency are complementary metrics. They reward optimized
agent architecture capable of real-time fraud detection with low operational
expense.

These metrics emphasize:

- efficient resource usage;
- low latency;
- scalability and adaptability;
- economic sustainability.

## 5. Example

Three rows from `Transactions.csv` are shown. Two are suspected fraudulent,
and their Transaction IDs are written in output.

### Input Example

```csv
4a92ab00-8a27-4623-ab1d-56ac85fcd6b0,SCHV-SVRA-7BC-COR-0,,e-commerce,56.63,,mobile device,IT16Y9430002300167070752952,IT35O1753705526805948017123071,603.37,,2025-11-17T00:35:29.446363
8830a720-ff34-4dce-a578-e5b8006b2976,LRNT-MTTH-7BF-PAR-1,,prelievo,150,Turin,debit card,FR46C7104822278076244862444,IT39S3051166323954859019873188,142.58,,2025-11-17T14:33:28.068080
1c6db202-22d8-443f-86e7-fb1a8df05e84,TRBU-MRTT-7C4-MUL-0,BTSWF98176,e-commerce,170.33,SwiftCart Marketplace,debit card,DE20X3656132271467727362296,IT14Q8802310964869133978727249,54000.24,,2027-01-04T00:00:00
```

### Output Example

```text
4a92ab00-8a27-4623-ab1d-56ac85fcd6b0
8830a720-ff34-4dce-a578-e5b8006b2976
```

## 6. Requirements

- Only agent-based solutions are permitted.
- Fully deterministic approaches are evaluated with reservation.
- Submissions must include implemented code, execution instructions and full
  dependency list for reproducibility.
- Top-performing teams may be re-evaluated on new datasets not provided
  during the challenge.
