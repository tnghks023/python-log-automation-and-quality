# Access Log Analyzer & Weekly Aggregator

## 📘 프로젝트 개요
Python을 활용해 Access Log를 자동으로 파싱, 분석, 요약 리포트를 생성하는 시스템입니다.
GeoLite2 ASN DB를 이용해 IP별 조직 정보를 매핑하고, 국내 ISP 트래픽을 필터링합니다.

## ⚙️ 주요 기능
- Access Log 정규식 파싱 및 구조화 (IP, URL, Status Code, Response Time)
- GeoLite2 ASN DB 기반 IP 매핑 및 국내 트래픽 필터링
- IP별 요청수·4xx·5xx 비율·분당 요청수(RPM) 계산
- 자동 Excel 리포트 생성
- 주간 단위 집계 스크립트 (CSV → Weekly Summary)
- AbuseIPDB 분석 결과 병합 기능

## 🧠 기술 스택
- Python 3.11
- pandas, re, ipaddress, bisect
- openpyxl, tkinter, pathlib
- GeoLite2 ASN CSV

## 📈 기대 효과
- 로그 분석 자동화로 운영 효율 및 분석 정확도 향상
- 국내 ISP 트래픽 필터링을 통한 보안 점검 효율화
- 반복적 수작업 보고서 자동화

## 🗂️ 프로젝트 구조
- access_log_parser.py
- weekly_aggregator.py
- abuseipdb_joiner.py
- sample_logs/access_sample.log
- README.md
