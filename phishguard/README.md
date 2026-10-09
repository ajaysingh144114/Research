# PhishGuard: phishing and smishing message checker

Paste an email or a text message (SMS, WhatsApp) and PhishGuard tells you whether it is **SAFE**, **SUSPICIOUS** or **PHISHING**, with the reasons in plain English and what to do next.

It works in two layers:

1. **Local rule checks** run on your computer, free and instantly. They look for look-alike links (`paypa1-billing.com`), link shorteners, sender names that don't match the address, requests for OTPs or passwords, fake prizes, unpaid-toll and parcel stories, KYC/PAN updates, gift-card requests and more.
2. **Claude on Amazon Bedrock** reads the whole message like a security analyst and gives its verdict, confidence and reasons. This catches well-written AI-generated scams that have no obvious keywords.

If AWS is not set up yet, PhishGuard still works using the local rules only, and tells you so.

```
=== samples/02-sms-kyc-bank-india.txt ===
Verdict: PHISHING
Why:
  - Link mentions sbi but goes to sbi-kyc-upd8.top, which is not an official sbi website
  - Threatens to block or suspend your account or service
  - Mentions a KYC, PAN or Aadhaar update, a very common Indian SMS scam
  ...
What to do: Do not click any link, reply, call the number or share any code. ...
```

## Setup (about 15 minutes, once)

### 1. Install Python

You need Python 3.10 or newer. Check with:

```
python3 --version
```

If it is missing, download it from https://www.python.org/downloads/ (on Windows, tick "Add Python to PATH" in the installer, and use `python` instead of `python3` below).

### 2. Download the code and install the libraries

```
git clone https://github.com/ajaysingh144114/Research.git
cd Research/phishguard
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

The `venv` step makes a private folder for this project's libraries so they don't clash with anything else on your computer. Run the `activate` line again each time you open a new terminal.

### 3. Connect to AWS (only needed for the Claude check)

1. **Turn on the model.** Sign in to the AWS console, open **Amazon Bedrock**, go to **Model catalog**, choose **Claude Opus 5.5** and open it once in the playground. The first time, AWS asks you to fill in Anthropic's short use-case form; approval is usually immediate. Use a region where the model is offered, for example `us-east-1`.
2. **Create an access key.** In **IAM**, create a user for this tool, give it Bedrock permissions (the AWS-managed `AmazonBedrockFullAccess` policy is simplest while testing; narrow it down before production), then create an **access key** for it.
3. **Save the key on your computer.** Install the AWS command line tool (https://aws.amazon.com/cli/) and run:

   ```
   aws configure
   ```

   Paste the access key ID and secret, and enter `us-east-1` as the region. Never put these keys in the code or commit them to GitHub.

## Using it

Check one of the included examples:

```
python3 -m phishguard samples/01-sms-toll-smishing.txt
```

Check all of them:

```
python3 -m phishguard samples/*.txt
```

Paste your own message (finish with **Ctrl-D** on Mac/Linux, or **Ctrl-Z then Enter** on Windows):

```
python3 -m phishguard
```

Other options:

| Option | What it does |
|---|---|
| `--offline` | Use only the local rules. No AWS, no cost. |
| `--json` | Print the result as JSON, for feeding into other tools or a dashboard. |
| `--model ID` | Use a different Bedrock model. |

Settings you can put in the environment instead:

| Variable | Default | Meaning |
|---|---|---|
| `AWS_REGION` | `us-east-1` | Bedrock region to call. |
| `PHISHGUARD_MODEL` | `anthropic.claude-opus-5-5` | Model ID. `anthropic.claude-haiku-5-5` is much cheaper and fast, good for high volume. |

### Using it from your own Python code

```python
from phishguard import check_message

result = check_message("Your parcel is held. Pay the redelivery fee: https://bit.ly/x")
print(result.verdict, result.reasons)
```

## How the final verdict is decided

- Rule score: each warning sign adds points. 0 to 2 is safe, 3 to 5 suspicious, 6 or more phishing. This is the answer when Claude isn't available.
- With Claude: Claude's verdict is used, with one safety net. If the rules found strong warning signs (6+ points) but Claude said "safe", the result is raised to "suspicious". That protects against messages written to trick AI scanners (see `samples/08-email-prompt-injection.txt`).
- The message is always sent to Claude as untrusted data, and Claude is told never to follow instructions written inside it.

## Cost and privacy

- Each Claude check is one short Bedrock request, roughly a cent with Opus and a small fraction of that with Haiku. Check the Bedrock pricing page for your region; `--offline` is free.
- The message text is sent to Amazon Bedrock in your own AWS account. Bedrock does not use it to train models. Don't paste messages you are not allowed to share with your AWS account.

## Running the tests

```
pip install -r requirements-dev.txt
pytest
```

The tests need no AWS account: they use a fake Bedrock client and check the rules against the sample messages.

## What's in this folder

| Path | What it is |
|---|---|
| `phishguard/signals.py` | The local rule checks. Add new brands or scam phrases here. |
| `phishguard/ai.py` | The Claude on Bedrock call, its instructions and the answer format. |
| `phishguard/checker.py` | Combines both into one verdict. |
| `phishguard/__main__.py` | The command line. |
| `samples/` | Example scams and genuine messages to try. |
| `tests/` | Automated tests. |

## Limits of this prototype, and next steps

- It does not open links or look up domain age or threat feeds. Next: add domain-age (WHOIS/RDAP), Google Safe Browsing or VirusTotal lookups, and expand short links safely.
- It reads text only. Next: read `.eml` files with full headers (SPF, DKIM, DMARC results), screenshots of SMS, and QR codes.
- The brand list in `signals.py` is small. Add the banks and companies your customers use.
- To run it as a service for customers: put `check_message` behind an AWS Lambda function with API Gateway, or hook it to Amazon SES / WorkMail to scan incoming mail, and log verdicts to DynamoDB.

This tool helps people spot scams; it can be wrong. Treat "safe" as "no warning signs found", not a guarantee.
