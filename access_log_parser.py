import re
import os
import ipaddress
import bisect
import pandas as pd
from tkinter import Tk, filedialog
from pathlib import Path
from datetime import date

# ===== [메모리 최적화 0] pandas Copy-on-Write =====
pd.set_option("mode.copy_on_write", True)

# 고정 경로 설정
ROOT_DIR = Path(r"./LogAnalysis")
asn_csv = ROOT_DIR / "0.GeoLite2-ASN-CSV_20251001" / "GeoLite2-ASN-Blocks-IPv4.csv"
save_dir = ROOT_DIR / "2.accesslog_to_excel_with_asn"
ip_summary_dir = ROOT_DIR / "3.ip_summary"

# -------------------------------
# 0) 입력/출력 선택
# -------------------------------
Tk().withdraw()

log_path = filedialog.askopenfilename(
    title="분석할 로그 파일을 선택하세요",
    filetypes=[("All files","*.*")]
)
if not log_path:
    print("❌ 로그 파일이 선택되지 않았습니다.")
    raise SystemExit(1)
    
# GUI 대신 고정 경로 지정
if not os.path.exists(asn_csv):
    print(f"❌ ASN CSV 파일이 존재하지 않습니다: {asn_csv}")
    raise SystemExit(1)

# 0) 출력 디렉토리 보장


# 주간 폴더 생성 (예: 2025W40)
y, w, _ = date.today().isocalendar()
week_label = f"{y}W{w:02d}"

# ip_summary 저장
week_dir = Path(ip_summary_dir / week_label)
week_dir.mkdir(parents=True, exist_ok=True)

# 엑셀 저장용
week_dir2 = Path(save_dir / week_label)
week_dir2.mkdir(parents=True, exist_ok=True)

# 파일 이름 구성
base = os.path.splitext(os.path.basename(log_path))[0]
save_base = f"{base}_parsed_with_asn_before_after.xlsx"
save_path = week_dir2 / save_base           # ✅ Path 결합으로 통일

# 중복 파일 자동 회피
i = 1
while os.path.exists(save_path):
    save_path = os.path.join(save_dir, f"{base}_parsed_with_asn_before_after_v{i}.xlsx")
    i += 1

# -------------------------------
# 1) 로그 파싱 (최적화)
# -------------------------------
log_re = re.compile(
    r'(?P<ip>\S+)\s+\[(?P<dt>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>[^"]+?)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+(?P<rtime>\S+))?'
)

rows, total, skipped, excluded = [], 0, 0, 0
with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        total += 1
        m = log_re.search(line)
        if not m:
            skipped += 1
            continue

        ip = m.group("ip")
        dt_raw = m.group("dt")
        method = m.group("method")
        url = m.group("url")
        proto = m.group("proto")
        status = m.group("status")
        size = m.group("size")
        rtime = m.group("rtime")

        # 숫자 캐스팅(방어적)
        try: status = int(status)
        except: status = None
        try: size = int(size) if size not in (None, "-", "") else 0
        except: size = 0
        try: rtime = int(float(rtime)) if rtime not in (None, "-", "") else None
        except: rtime = None

        rows.append([ip, dt_raw, method, url, proto, status, size, rtime])

print(f"[+] 총 라인: {total:,} | 파싱: {len(rows):,} | 스킵: {skipped:,}")
if not rows:
    print("❌ 파싱된 행이 없습니다. 패턴을 확인하세요.")
    raise SystemExit(1)

df = pd.DataFrame(rows, columns=[
    "IP", "Datetime", "Method", "URL", "Protocol",
    "Status", "Bytes", "ResponseTime(ms)"
])

# Datetime: UTC로 읽고 → Asia/Seoul → tz 제거
dt = pd.to_datetime(
    df["Datetime"],
    format="%d/%b/%Y:%H:%M:%S %z",
    errors="coerce",
    utc=True
).dt.tz_convert("Asia/Seoul").dt.tz_localize(None)
df["Datetime"] = dt

# ===== [메모리 최적화 1] NaT 제거 & 정수 downcast & 카테고리화 =====
# NaT 제거 (요약/피벗 계산 왜곡 방지)
df = df.dropna(subset=["Datetime"])

# 정수형 downcast
df["Status"] = pd.to_numeric(df["Status"], downcast="integer")
df["Bytes"] = pd.to_numeric(df["Bytes"], downcast="unsigned")
df["ResponseTime(ms)"] = pd.to_numeric(df["ResponseTime(ms)"], downcast="integer")

# 값 종류가 적은 문자열 → category
for col in ["Method", "Protocol"]:
    df[col] = df[col].astype("category")

# -------------------------------
# 2) GeoLite2 ASN 로드 & 이진탐색 테이블 구축 (필요 컬럼만 로드)
# -------------------------------
print("[*] ASN CSV 로드(필요 컬럼만):", asn_csv)
usecols = ["network", "autonomous_system_number", "autonomous_system_organization"]
asn_df = pd.read_csv(asn_csv, usecols=usecols)

def net_to_bounds(n):
    try:
        net = ipaddress.ip_network(n, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return int(net.network_address), int(net.broadcast_address)
    except:
        return None

bounds = asn_df["network"].apply(net_to_bounds)
mask = bounds.notna()
asn_df = asn_df[mask].copy()
asn_df["start"] = [b[0] for b in bounds[mask]]
asn_df["end"]   = [b[1] for b in bounds[mask]]

# ASN/Org dtype 가벼워주기
asn_df["autonomous_system_number"] = pd.to_numeric(
    asn_df["autonomous_system_number"], errors="coerce", downcast="integer"
)
asn_df["autonomous_system_organization"] = asn_df["autonomous_system_organization"].astype("category")

asn_df.sort_values("start", inplace=True)
starts = asn_df["start"].to_list()
ends   = asn_df["end"].to_list()
asns   = asn_df["autonomous_system_number"].to_list()
orgs   = asn_df["autonomous_system_organization"].to_list()

def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))

def lookup_asn_org(ip: str):
    try:
        ipnum = ip_to_int(ip)
    except:
        return None, None
    i = bisect.bisect_right(starts, ipnum) - 1
    if i >= 0 and ipnum <= ends[i]:
        return asns[i], orgs[i]
    return None, None

# 유니크 IP만 매핑 → 원본에 조인
unique_ips = df["IP"].dropna().unique().tolist()
ip_asn_map = {ip: lookup_asn_org(ip) for ip in unique_ips}
df["ASN"] = df["IP"].map(lambda x: ip_asn_map.get(x, (None, None))[0])
df["Org"] = df["IP"].map(lambda x: ip_asn_map.get(x, (None, None))[1])

# ===== [메모리 최적화 2] Org를 category로 확정 =====
df["Org"] = df["Org"].astype("category")

# -------------------------------
# 3) 국내 ISP 필터 + 세 시트 저장(전/후/국내만) + 요약
# -------------------------------
exclude_keywords = [
    "Korea Telecom","KT","SK","SK Broadband","SKTelecom","LG","Hanaro","BORANET","KORNET"
]
def is_domestic(org) -> bool:
    if pd.isna(org):
        return False
    o = str(org).lower()
    #return any(k.lower() in o for k in exclude_keywords)
    return bool(any(k.lower() in o for k in exclude_keywords))  # bool로 강제

df_before   = df                                   # 복사 없이 바로 사용 (메모리 절약)
mask_domestic = df["Org"].apply(is_domestic).fillna(False).astype(bool)
df_after    = df[~mask_domestic].copy()
df_domestic = df[ mask_domestic].copy()

print(f"[+] 국내 ISP 제외: {len(df_before):,} → {len(df_after):,} (국내만: {len(df_domestic):,})")

# --- 요약 지표 생성 (NaT는 위에서 제거됨) ---
df["is4xx"] = df["Status"].between(400, 499)
df["is5xx"] = df["Status"].between(500, 599)

# IP별 요약
ip_summary = (
    df.groupby("IP")
      .agg(
          hits=("IP", "size"),
          first_seen=("Datetime", "min"),
          last_seen=("Datetime", "max"),
          cnt_4xx=("is4xx", "sum"),
          cnt_5xx=("is5xx", "sum"),
          pct_4xx=("is4xx", lambda s: round(100 * s.mean(), 2)),
          pct_5xx=("is5xx", lambda s: round(100 * s.mean(), 2))
      )
      .sort_values("hits", ascending=False)
      .reset_index()
)

# 관측 기간(분 단위) 및 분당 요청수 계산
ip_summary = ip_summary.assign(
    dur_min=(ip_summary["last_seen"] - ip_summary["first_seen"]).dt.total_seconds() / 60
)
ip_summary["dur_min"] = ip_summary["dur_min"].clip(lower=1)
ip_summary["rpm"] = (ip_summary["hits"] / ip_summary["dur_min"]).round(2)

# ✅ 일별 ip_summary CSV 저장
ip_summary.to_csv(
    os.path.join(week_dir, f"ip_summary_{base}.csv"),
    index=False
)

# ✅ (추가) 분당 히트 집계 per_min 생성  ←←← 여기 추가
#   - 국내 ISP 제외 후 트래픽 기준으로 보고 싶다면 df_after 사용 권장
df_min = df.copy()   # df를 쓰면 국내 포함 전체 기준
df_min["minute"] = df_min["Datetime"].dt.floor("min")
per_min = (
    df_min.groupby(["IP","minute"])
          .size()
          .reset_index(name="hits_per_min")
)

# Top 50 IP만 per_min 추출
top_ips = ip_summary.head(50)["IP"]
per_min_top = per_min[per_min["IP"].isin(top_ips)]

# -------------------------------
# 4) 엑셀 저장
# -------------------------------
with pd.ExcelWriter(save_path, engine="openpyxl") as writer:
    cols = ["IP","Datetime","Method","URL","Protocol","Status","Bytes","ResponseTime(ms)","ASN","Org"]
    df_before[cols].to_excel(writer, sheet_name="Before_Filter", index=False)
    df_after[cols].to_excel(writer, sheet_name="After_Filter", index=False)
    df_domestic[cols].to_excel(writer, sheet_name="Only_Domestic", index=False)
    
    # 시각 점검용 Top30만
    ip_summary.head(30).to_excel(writer, "ip_summary_top30", index=False)  # 전체 대신 상위 30개만
    
    # 분당 히트 Top50
    per_min_top.sort_values(["IP","minute"]).to_excel(writer, sheet_name="PerMin_Top50", index=False)

print(f"✅ 저장 완료: {save_path}")
print("   시트: Before_Filter(제외 전), After_Filter(국내 제외 후), Only_Domestic(국내만), IP_Summary, PerMin_Hits")
