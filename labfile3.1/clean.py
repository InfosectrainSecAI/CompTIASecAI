#!/usr/bin/env python3
import re, sys, os
import pandas as pd
import numpy as np
from datetime import datetime

IN_FILE  = "dirty_data.csv"
OUT_FILE = "cleaned_data.csv"

US_STATES = {
    "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA",
    "ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK",
    "OR","PA","RI","SC","SD","TN","TX","UT","VT","VA","WA","WV","WI","WY","DC"
}

# ----------------------------- Helpers ---------------------------------

def read_csv_all_str(path):
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    df = df.replace({"": np.nan, "N/A": np.nan, "NULL": np.nan, "null": np.nan})
    return df

def title_or_nan(s):
    if pd.isna(s) or not str(s).strip():
        return np.nan
    return str(s).strip().title()

def normalize_email(s):
    if pd.isna(s): return np.nan
    s = s.strip().lower()
    pat = r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$"
    return s if re.match(pat, s) else np.nan

def normalize_phone(s):
    if pd.isna(s): return np.nan
    d = re.sub(r"\D", "", s)
    return f"({d[:3]}) {d[3:6]}-{d[6:10]}" if len(d)==10 else np.nan

def normalize_state(s):
    if pd.isna(s): return np.nan
    t = s.strip().upper()
    return t if t in US_STATES else np.nan

def normalize_zip(s):
    if pd.isna(s): return np.nan
    d = re.sub(r"\D", "", s)
    return d[:5] if len(d)>=5 else np.nan

def parse_date_to_ymd(s):
    if pd.isna(s): return np.nan
    raw = str(s).strip()
    fmts = [
        "%Y-%m-%d","%m/%d/%Y","%m/%d/%y","%d-%m-%Y","%d/%m/%Y","%m-%d-%Y",
        "%B %d %Y","%b %d %Y","%d-%b-%Y","%d-%B-%Y","%Y/%m/%d","%d-%m-%y","%d/%m/%y"
    ]
    for f in fmts:
        try:
            return datetime.strptime(raw, f).strftime("%Y-%m-%d")
        except: pass
    try:
        dt = pd.to_datetime(raw, errors="coerce", dayfirst=True, infer_datetime_format=True)
        return dt.strftime("%Y-%m-%d") if not pd.isna(dt) else np.nan
    except:
        return np.nan

_SUFFIX_MAP = {
    r"\bSt\.?\b": "Street",
    r"\bAve\.?\b": "Avenue",
    r"\bRd\.?\b": "Road",
    r"\bBlvd\.?\b": "Boulevard",
    r"\bLn\.?\b": "Lane",
    r"\bDr\.?\b": "Drive",
}

def fix_ordinals(text: str) -> str:
    def repl(m):
        num = m.group(1)
        suf = m.group(2).lower()
        return f"{num}{suf}"
    return re.sub(r"\b(\d+)(ST|ND|RD|TH)\b", repl, text, flags=re.IGNORECASE)

def normalize_address(s):
    if pd.isna(s) or not str(s).strip():
        return np.nan
    t = s.strip()
    t = fix_ordinals(t)
    for pat, repl in _SUFFIX_MAP.items():
        t = re.sub(pat, repl, t, flags=re.IGNORECASE)
    t = " ".join(w.capitalize() if not re.fullmatch(r"[A-Z]{2,}", w) else w for w in t.split())
    return t

def mask_ssn(s):
    if pd.isna(s): return np.nan
    d = re.sub(r"\D", "", str(s))
    return f"***-**-{d[-4:]}" if len(d)==9 else np.nan

def mask_cc(s):
    if pd.isna(s): return np.nan
    if str(s).strip().upper() == "REDACTED":
        return "REDACTED"
    d = re.sub(r"\D", "", str(s))
    return f"XXXX-XXXX-XXXX-{d[-4:]}" if len(d)>=4 else np.nan

def mask_acct(s):
    if pd.isna(s): return np.nan
    d = re.sub(r"\D", "", str(s))
    return f"*****{d[-4:]}" if len(d)>=4 else np.nan

def license_from_state_prefix(state):
    prefix = str(state).strip().upper()[:2] if isinstance(state, str) and str(state).strip() else "XX"
    return f"{prefix}{np.random.randint(10_000_000, 100_000_000)}"

# ----------------------------- Main ---------------------------------

def main():
    if not os.path.exists(IN_FILE):
        print(f"Input not found: {IN_FILE}"); sys.exit(1)

    df = read_csv_all_str(IN_FILE)

    # Normalize identity/location
    if "First_Name" in df.columns: df["First_Name"] = df["First_Name"].apply(title_or_nan)
    if "Last_Name"  in df.columns: df["Last_Name"]  = df["Last_Name"].apply(title_or_nan)
    if "City"       in df.columns: df["City"]       = df["City"].apply(title_or_nan)
    if "Address"    in df.columns: df["Address"]    = df["Address"].apply(normalize_address)

    if "Email"         in df.columns: df["Email"]         = df["Email"].apply(normalize_email)
    if "Phone"         in df.columns: df["Phone"]         = df["Phone"].apply(normalize_phone)
    if "State"         in df.columns: df["State"]         = df["State"].apply(normalize_state)
    if "ZIP_Code"      in df.columns: df["ZIP_Code"]      = df["ZIP_Code"].apply(normalize_zip)
    if "Date_of_Birth" in df.columns: df["Date_of_Birth"] = df["Date_of_Birth"].apply(parse_date_to_ymd)

    if "SSN"          in df.columns: df["SSN"]          = df["SSN"].apply(mask_ssn)
    if "Credit_Card"  in df.columns: df["Credit_Card"]  = df["Credit_Card"].apply(mask_cc)
    if "Bank_Account" in df.columns: df["Bank_Account"] = df["Bank_Account"].apply(mask_acct)
    if "Password"     in df.columns: df["Password"]     = "[REDACTED]"

    if "License_Number" in df.columns:
        if "State" not in df.columns: df["State"] = np.nan
        def fix_license(row):
            v, st = row.get("License_Number", np.nan), row.get("State", np.nan)
            if pd.isna(v) or not str(v).strip():
                return license_from_state_prefix(st)
            v, st = str(v).strip().upper(), str(st).strip().upper() if isinstance(st,str) else "XX"
            digits = re.sub(r"\D", "", v[2:]) if len(v) >= 2 else ""
            return v if v.startswith(st[:2]) and len(digits)==8 else license_from_state_prefix(st)
        df["License_Number"] = df.apply(fix_license, axis=1)

    # Drop rows missing either first OR last name
    for c in ("First_Name","Last_Name"):
        if c not in df.columns: df[c] = np.nan
    keep = df["First_Name"].notna() & df["Last_Name"].notna()
    df = df.loc[keep].copy()

    # Light dedupe
    if "Email" not in df.columns: df["Email"] = np.nan
    df["_k"] = (
        df["First_Name"].fillna("").str.lower()+"|"+
        df["Last_Name"].fillna("").str.lower()+"|"+
        df["Email"].fillna("").str.lower()
    )
    df = df.drop_duplicates(subset=["_k"]).drop(columns=["_k"])

    # Ensure sequential IDs (reindex if missing or bad)
    if "ID" not in df.columns: df["ID"] = np.arange(1, len(df)+1)
    else:
        try:
            df["ID"] = pd.to_numeric(df["ID"], errors="coerce")
        except:
            df["ID"] = np.nan
        df = df.reset_index(drop=True)
        df["ID"] = np.arange(1, len(df)+1)

    order = ["ID","First_Name","Last_Name","Email","Phone","Address","City","State","ZIP_Code",
             "SSN","Date_of_Birth","Credit_Card","Bank_Account","Username","Password",
             "Medical_ID","License_Number"]
    cols = [c for c in order if c in df.columns] + [c for c in df.columns if c not in order]
    df = df[cols]

    # Fill missing with "Missing or Incomplete"
    df = df.fillna("Missing or Incomplete")

    df.to_csv(OUT_FILE, index=False)
    print(f"[OK] Wrote {OUT_FILE} (rows: {len(df)})")

if __name__ == "__main__":
    main()

