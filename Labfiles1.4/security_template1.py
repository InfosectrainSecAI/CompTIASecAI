import json
import requests

print("Script is running...")

# Load JSON file
with open("/home/kali/Labfiles1.4/Alert File1.json", "r") as f:
	model_data = json.load(f)
	print("JSON loaded")
        
# Access the Event section
event = model_data.get("Event", {})
if not event:
	print("No Event data found.")
	exit()
                
# Extract threat metadata
info = event.get("info", "No info provided")
analysis = event.get("analysis", "N/A")
threat_level = event.get("threat_level_id", "N/A")
tags = ", ".join(tag.get("name", "") for tag in event.get("Tag", []))
attributes = event.get("Attribute", [])
                
# Extract indicators
ioc_summary = []
for attr in attributes:
	category = attr.get("category", "Unknown")
	attr_type = attr.get("type", "Unknown")
	value = attr.get("value", "No value")
	ioc_summary.append(f"{category} - {attr_type}: {value}")
                                
ioc_text = "\n".join(ioc_summary)
                                
# Build the prompt
prompt = f"""
Analyze the following threat report:
                                
[THREAT_SUMMARY]
Info: {info}
Analysis Level: {analysis}
Threat Level ID: {threat_level}
Tags: {tags}
Indicators of Compromise:
{ioc_text}

Please provide a concise summary and security recommendations in plain language.
"""

print("Final prompt:")
print(prompt)
                                
# Make the request
response = requests.post(
	"http://localhost:11434/api/generate",
 	json={
		"model": "mistral:7b",  # Or use "llama3" or "phi3"
		"prompt": prompt,
		"stream": False,
		"options": {
			"temperature": 0.7,
			"num_predict": 300
		}
	}
)

# Output the result
if response.status_code == 200:
	output = response.json().get("response", "").strip()
	print("\n--- Model Output ---\n")
	print(output or "No response from model.")
else:
	print(f"Error: {response.status_code}")
	print(f"Response text: {response.text}")
