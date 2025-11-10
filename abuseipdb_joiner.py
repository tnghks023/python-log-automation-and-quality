import pandas as pd
from pathlib import Path
from tkinter import Tk, filedialog

# ===== 1) 파일 선택 =====
Tk().withdraw()

abuse_path = filedialog.askopenfilename(
    title="abuse 50 이상 엑셀 선택",
    filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
)
if not abuse_path:
    print("❌ abuse 파일이 선택되지 않았습니다.")
    raise SystemExit

all_path = filedialog.askopenfilename(
    title="전체 IP 정보 파일 선택 (.xlsx 또는 .csv)",
    filetypes=[("Excel files", "*.xlsx"), ("CSV files", "*.csv"), ("All files", "*.*")]
)
if not all_path:
    print("❌ 전체 IP 파일이 선택되지 않았습니다.")
    raise SystemExit

print(f"📂 abuse: {abuse_path}")
print(f"📂 all  : {all_path}")

# ===== 2) 로드 =====
abuse = pd.read_excel(abuse_path, dtype=str)  # 컬럼: ipAddress, abuseConfidenceScore 등
if all_path.lower().endswith(".csv"):
    allip = pd.read_csv(all_path, dtype=str)
else:
    allip = pd.read_excel(all_path, sheet_name="IP_Summary", dtype=str)  # 컬럼: IP, hits, first_seen, ...
#    allip = pd.read_excel(all_path, dtype=str)  # 컬럼: IP, hits, first_seen, ...
    
#sheets = pd.ExcelFile(all_path).sheet_names
#print("📄 시트 목록:", sheets)

# ===== 3) 전처리 (공백 제거)
for df in (abuse, allip):
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].str.strip()

# 숫자형으로 쓸만한 것 변환(엑셀 경고 방지용)
num_cols_abuse = ["abuseConfidenceScore", "isPublic", "ipVersion", "isWhitelisted", "isTor", "totalReports", "numDistinctUsers"]
for c in num_cols_abuse:
    if c in abuse.columns:
        abuse[c] = pd.to_numeric(abuse[c], errors="coerce")

num_cols_all = ["hits", "pct_4xx", "pct_5xx", "dur_min", "rpm"]
for c in num_cols_all:
    if c in allip.columns:
        allip[c] = pd.to_numeric(allip[c], errors="coerce")

# ===== 4) 키 정렬
# - abuse: ipAddress
# - all:   IP
# 병합용 보조키 생성(공백 제거된 원형은 보존, 보조키는 소문자/공백제거)
if "ipAddress" not in abuse.columns:
    raise ValueError("abuse 파일에 'ipAddress' 컬럼이 없습니다.")
if "IP" not in allip.columns:
    raise ValueError("전체 IP 파일에 'IP' 컬럼이 없습니다.")

abuse["_key_ip"] = abuse["ipAddress"].astype(str).str.strip().str.lower()
allip["_key_ip"] = allip["IP"].astype(str).str.strip().str.lower()

# (옵션) 같은 IP가 여러 번 있으면 먼저 중복 제거(필요에 따라 유지해도 됨)
# abuse = abuse.drop_duplicates(subset=["_key_ip"])
# allip = allip.drop_duplicates(subset=["_key_ip"])

# ===== 5) 병합
matched = abuse.merge(allip, how="inner", on="_key_ip", suffixes=("_abuse", "_all"))


# (보기 편의) 정렬: score↓, hits↓
if "abuseConfidenceScore" in matched.columns:
    matched = matched.sort_values(["abuseConfidenceScore"], ascending=[False])
if "hits" in matched.columns:
    matched = matched.sort_values(["abuseConfidenceScore", "hits"], ascending=[False, False]) if "abuseConfidenceScore" in matched.columns else matched.sort_values("hits", ascending=False)

# ===== 6) 매칭 안 된 목록도 저장(좌/우)
left_only = abuse[~abuse["_key_ip"].isin(matched["_key_ip"])].copy()
right_only = allip[~allip["_key_ip"].isin(matched["_key_ip"])].copy()

# ✅ 불필요한 IP 컬럼 정리 (_key_ip, IP 중복 제거)
# 'ipAddress'만 남기고 싶을 경우:
drop_cols = [c for c in ["_key_ip", "IP"] if c in matched.columns]
matched = matched.drop(columns=drop_cols)

# ===== 7) 요약 시트
summary = pd.DataFrame({
    "metric": ["abuse_rows", "all_rows", "matched_rows", "left_only_rows", "right_only_rows"],
    "value": [len(abuse), len(allip), len(matched), len(left_only), len(right_only)]
})

# ===== 8) 저장
out_dir = Path("../merge_abuseip50")
out_dir.mkdir(parents=True, exist_ok=True)

base = Path(abuse_path).stem.split("_")[0]  # 예: 20251011
out_path = out_dir / f"{base}_abuse50_joined.xlsx"

with pd.ExcelWriter(out_path, engine="openpyxl") as w:
    summary.to_excel(w, sheet_name="summary", index=False)
    matched.to_excel(w, sheet_name="matched", index=False)
    left_only.to_excel(w, sheet_name="only_in_abuse", index=False)
    right_only.to_excel(w, sheet_name="only_in_all", index=False)

print(f"✅ 저장 완료: {out_path}")
print(f"   - matched: {len(matched)} rows")
print(f"   - only_in_abuse: {len(left_only)} rows")
print(f"   - only_in_all: {len(right_only)} rows")
