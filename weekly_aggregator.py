import argparse, os, glob
import pandas as pd
from pathlib import Path

pd.set_option("mode.copy_on_write", True)

def collect_files(input_arg: str, pattern: str = "*.csv", recursive: bool = False):
    p = Path(input_arg)
    if p.is_dir():
        # 폴더 입력이면 지정 패턴으로 수집
        glob_pat = str(p / ("**" if recursive else "") / pattern)
        files = sorted(glob.glob(glob_pat, recursive=recursive))
    else:
        # 글롭 문자열이면 그대로 사용
        files = sorted(glob.glob(input_arg, recursive=recursive))
    return files

def read_daily_ip_summaries(files):
    if not files:
        raise FileNotFoundError("No ip_summary files found.")
    dfs = []
    for f in files:
        ext = Path(f).suffix.lower()
        if ext == ".csv":
            df = pd.read_csv(f)
        elif ext in (".xlsx", ".xls"):
            df = pd.read_excel(f)
        else:
            # 확장자 미지정 파일은 CSV로 가정 (추측입니다/확실하지 않음)
            df = pd.read_csv(f)

        # 필수 컬럼 체크(없으면 에러)
        needed = ["IP","hits","first_seen","last_seen"]
        missing = [c for c in needed if c not in df.columns]
        if missing:
            raise ValueError(f"{f} is missing required columns: {missing}")

        # 타입 보정
        df["IP"] = df["IP"].astype(str)
        df["hits"] = pd.to_numeric(df["hits"], errors="coerce").fillna(0).astype(int)
        df["cnt_4xx"] = pd.to_numeric(df.get("cnt_4xx", 0), errors="coerce").fillna(0).astype(int)
        df["cnt_5xx"] = pd.to_numeric(df.get("cnt_5xx", 0), errors="coerce").fillna(0).astype(int)
        df["first_seen"] = pd.to_datetime(df["first_seen"], errors="coerce")
        df["last_seen"] = pd.to_datetime(df["last_seen"], errors="coerce")

        # dur_min 없으면 관측 스팬으로 대체 (추측입니다/확실하지 않음)
        if "dur_min" not in df.columns:
            dur = (df["last_seen"] - df["first_seen"]).dt.total_seconds() / 60
            df["dur_min"] = dur.clip(lower=1)
        else:
            df["dur_min"] = pd.to_numeric(df["dur_min"], errors="coerce").fillna(1.0).clip(lower=1)

        # 파일명에서 날짜 추출(가중평균용 보조 라벨)
        stem = Path(f).stem
        day_digits = "".join(filter(str.isdigit, stem))[-8:]
        df["file_date"] = pd.to_datetime(day_digits, format="%Y%m%d", errors="coerce")

        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)

def aggregate_week(daily_df, dur_mode="sum"):
    grp = daily_df.groupby("IP", as_index=False).agg(
        hits_week=("hits","sum"),
        cnt_4xx_week=("cnt_4xx","sum"),
        cnt_5xx_week=("cnt_5xx","sum"),
        first_seen_week=("first_seen","min"),
        last_seen_week=("last_seen","max"),
        days_active=("file_date","nunique")
    )

    if dur_mode == "sum":
        dur_sum = (daily_df.groupby("IP")["dur_min"].sum().rename("dur_min_week")).reset_index()
        weekly = grp.merge(dur_sum, on="IP", how="left")
    elif dur_mode == "span":
        weekly = grp.copy()
        span_min = (weekly["last_seen_week"] - weekly["first_seen_week"]).dt.total_seconds()/60
        weekly["dur_min_week"] = pd.Series(span_min).clip(lower=1)
    else:
        raise ValueError("dur_mode must be 'sum' or 'span'")

    weekly["pct_4xx_week"] = (100 * weekly["cnt_4xx_week"] / weekly["hits_week"]).round(2).fillna(0)
    weekly["pct_5xx_week"] = (100 * weekly["cnt_5xx_week"] / weekly["hits_week"]).round(2).fillna(0)
    weekly["rpm_week"] = (weekly["hits_week"] / weekly["dur_min_week"]).round(2)

    cols = [
        "IP",
        "hits_week","cnt_4xx_week","cnt_5xx_week","pct_4xx_week","pct_5xx_week",
        "first_seen_week","last_seen_week","days_active",
        "dur_min_week","rpm_week"
    ]
    return weekly[cols].sort_values(["hits_week","rpm_week"], ascending=[False,False]).reset_index(drop=True)

def add_flags(df, rpm_th=60, p4_th=70.0, p5_th=10.0, c5_cnt=50):
    flags = []
    for _, r in df.iterrows():
        f = []
        if r["rpm_week"] >= rpm_th: f.append("HIGH_RPM")
        if r["pct_4xx_week"] >= p4_th: f.append("SCANNER_LIKE")
        if r["pct_5xx_week"] >= p5_th or r["cnt_5xx_week"] >= c5_cnt: f.append("SERVER_ERROR_FOCUS")
        flags.append(",".join(f))
    df["flags"] = flags
    return df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True,
                    help="폴더 경로 또는 글롭 패턴 (예: ...\\ip_summary_*.csv)")
    ap.add_argument("--pattern", default="*.csv", help="폴더 입력일 때 매칭할 패턴 (기본: *.csv)")
    ap.add_argument("--recursive", action="store_true", help="폴더 입력 시 하위 폴더까지 포함")
    ap.add_argument("--out", help="결과 파일 경로(미지정 시 폴더명 기반 자동 저장)")
    ap.add_argument("--out-dir", help="출력 디렉토리 강제 지정(미지정 시 입력 폴더)")
    ap.add_argument("--dur-mode", choices=["sum","span"], default="sum",
                    help="sum=일별 dur 합산(권장), span=주 스팬")
    args = ap.parse_args()

    files = collect_files(args.input, pattern=args.pattern, recursive=args.recursive)
    daily = read_daily_ip_summaries(files)
    weekly = aggregate_week(daily, dur_mode=args.dur_mode)
    weekly = add_flags(weekly)

    # 출력 경로 자동 결정: 폴더 입력이면 ${폴더이름}_weekly.csv
    input_path = Path(args.input)
    if args.out:
        out_path = Path(args.out)
    else:
        if input_path.is_dir():
            out_dir = Path(args.out_dir) if args.out_dir else input_path
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{input_path.name}_weekly.csv"
        else:
            # 글롭 문자열이면 현재 작업 디렉토리에 고정 이름
            out_dir = Path(args.out_dir) if args.out_dir else Path.cwd()
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / "weekly_from_daily.csv"

    weekly.to_csv(out_path, index=False)
    print(f"Saved: {out_path}")

if __name__ == "__main__":
    main()
