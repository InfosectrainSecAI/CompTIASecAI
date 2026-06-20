import json
import subprocess

print("Script is running...")

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL_FILE      = "/home/kali/labfiles5.3/Alert File1.json"
MODEL_NAME      = "mistral:7b"
DOCKER_CONTAINER = "open-webui"
# ────────────────────────────────────────────────────────────────────────────────

# 1) Load JSON file
with open(MODEL_FILE, "r") as f:
    model_data = json.load(f)
    print("JSON loaded")


def build_prompt(data, follow_up=None):
    event = data.get("Event", {})
    if not event:
        print("No Event data found.")
        exit()

    info         = event.get("info",           "No info provided")
    analysis     = event.get("analysis",       "N/A")
    threat_level = event.get("threat_level_id","N/A")
    tags         = ", ".join(tag.get("name", "") for tag in event.get("Tag", []))
    attributes   = event.get("Attribute", [])

    ioc_summary = [
        f"{a.get('category','Unknown')} - {a.get('type','Unknown')}: {a.get('value','No value')}"
        for a in attributes
    ]
    ioc_text = "\n".join(ioc_summary)

    base = f"""
Analyze the following threat report:

[THREAT_SUMMARY]
Info: {info}
Analysis Level: {analysis}
Threat Level ID: {threat_level}
Tags: {tags}
Indicators of Compromise:
{ioc_text}
"""
    if follow_up:
        return base + f"Follow-up question: {follow_up}\nPlease answer in plain language."
    else:
        return base + "Please provide a concise summary and security recommendations in plain language."


def send_request(prompt_text):
    print("\nFinal prompt:")
    print(prompt_text)
    print("\n--- Model Output ---\n")

    result = subprocess.run(
        ["docker", "exec", DOCKER_CONTAINER, "ollama", "run", MODEL_NAME, prompt_text],
        capture_output=True, text=True, timeout=300
    )

    output = result.stdout.strip()
    error  = result.stderr.strip()

    if output:
        print(output)
    elif error:
        print(f"Error from model: {error}")
    else:
        print("No response from model.")


# ── Initial one-shot ────────────────────────────────────────────────────────────
initial_prompt = build_prompt(model_data)
send_request(initial_prompt)

# ── Interactive follow-ups ──────────────────────────────────────────────────────
while True:
    try:
        user_q = input("\nEnter follow-up question (or Ctrl+C to exit): ")
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        break

    if not user_q.strip():
        continue

    send_request(build_prompt(model_data, follow_up=user_q))
