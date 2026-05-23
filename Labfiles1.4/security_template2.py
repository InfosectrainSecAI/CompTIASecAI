import json
import requests

print("Script is running...")

# ── Configuration ──────────────────────────────────────────────────────────────
MODEL_FILE = "/home/kali/Labfiles1.4/Alert File1.json"
API_URL     = "http://localhost:11434/api/generate"  # ← correct Ollama endpoint :contentReference[oaicite:0]{index=0}
API_KEY     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImM1ZjAzMDZhLWYyNDQtNDRlMi04MjlmLTliMTQ4YjFjNzY3OSJ9._qyeg4cH1kF9i3nTQLaPvP4ZQffJwbYjutbEADbu58Y"
MODEL_NAME  = "mistral:7b"                            # or "llama3", "phi3", etc.
STREAM       = True                                   # set False to disable streaming
# ────────────────────────────────────────────────────────────────────────────────

# Common headers
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type":  "application/json",
}

# 1) Load JSON file
with open(MODEL_FILE, "r") as f:
    model_data = json.load(f)
    print("JSON loaded")

def build_prompt(data, follow_up=None):
    event = data.get("Event", {})
    if not event:
        print("No Event data found.")
        exit()

    info         = event.get("info",        "No info provided")
    analysis     = event.get("analysis",   "N/A")
    threat_level = event.get("threat_level_id", "N/A")
    tags         = ", ".join(tag.get("name","") for tag in event.get("Tag", []))
    attributes   = event.get("Attribute", [])
    ioc_summary  = [
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
        return base + f"Follow‑up question: {follow_up}\nPlease answer in plain language."
    else:
        return base + "Please provide a concise summary and security recommendations in plain language."

def send_request(prompt_text):
    print("\nFinal prompt:")
    print(prompt_text)

    payload = {
        "model":   MODEL_NAME,
        "prompt":  prompt_text,
        "stream":  STREAM,
        "options": {
            "temperature": 0.7,
            "num_predict": 300
        }
    }

    if STREAM:
        resp = requests.post(API_URL, headers=headers, json=payload, stream=True)
        if resp.status_code != 200:
            print(f"Error: {resp.status_code}")
            print(f"Response text: {resp.text}")
            return
        print("\n--- Model Output (streaming) ---\n")
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                chunk = json.loads(line)
                token = chunk.get("response") or ""
                print(token, end="", flush=True)
            except json.JSONDecodeError:
                print(line, end="", flush=True)
        print()  # final newline
    else:
        resp = requests.post(API_URL, headers=headers, json=payload)
        if resp.status_code == 200:
            output = resp.json().get("response", "").strip()
            print("\n--- Model Output ---\n")
            print(output or "No response from model.")
        else:
            print(f"Error: {resp.status_code}")
            print(f"Response text: {resp.text}")

# ── Initial one‑shot ────────────────────────────────────────────────────────────
initial_prompt = build_prompt(model_data)
send_request(initial_prompt)

# ── Interactive follow‑ups ─────────────────────────────────────────────────────
while True:
    try:
        user_q = input("\nEnter follow‑up question (or Ctrl+C to exit): ")
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")
        break

    if not user_q.strip():
        continue

    send_request(build_prompt(model_data, follow_up=user_q))

