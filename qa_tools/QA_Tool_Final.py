# ==========================================
# 🛡️ Vamserlike 통합 QA 테스트 툴 (v7 - WAF 분리 버전)
# ==========================================
# v6 → v7 변경점:
#   - (관심사 분리) 방대해진 WAF 보안 테스트(13케이스)를 waf_security_test.py로 분리.
#   - 본 툴은 백엔드 기능 QA(인증, 데이터 무결성, 캐릭터 해금 등) 전용으로 원복.
#
# v3 → v4 변경점:
#   1. 캐릭터 해금 시나리오 추가 — 팀 요청 핵심 기능
#   2. bypass-login 검증 시나리오 추가
#   3. reset-test-data 전체 초기화 메뉴 추가
#   4. _delete_test_user 에 email 속성 검색 폴백 추가 (유저 잔존 방지)
#   5. 데이터 무결성 검증 강화 (gold 누적 / selectedCharacterId 유지 추가)
#
# 시나리오 구성:
#   1. 인증 정상 흐름      : 실제 signup→인증→login→init→me (실 엔드포인트 검증)
#   2. 데이터 무결성       : bypass-login 셋업 후 2판 누적·갱신 정밀 검증
#   3. bypass-login 검증   : 강제 로그인이 init까지 끝내는지 확인
#   4. 캐릭터 해금         : 골드 차감 실측 + 중복 해금 멱등성
# ==========================================

import os
import sys
import time
from pathlib import Path
from dataclasses import dataclass, field

## ★ 부모 폴더(루트)의 config.py를 찾을 수 있게 경로 추가
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

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

    print(f"\n{'=' * 55}")
    print(f"📊 [시나리오 2] 데이터 무결성 검증 ({email})")
    print("=" * 55)

    try:
        # 셋업
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

        # --- 2판 ---
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

        # 별도 init 호출 없이 바로 /me 가 성공해야 함
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

        # 1) 골드 충전
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
        print(f"  ℹ️  실측된 '{UNLOCK_TARGET_CHARACTER_ID}' 해금 비용: {actual_cost} 골드")

        # 3) 멱등성
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
# 메인 컨트롤러
# ==========================================
def run_all_tests() -> bool:
    print("=" * 55)
    print(f"🎯 QA 대상 서버: {BASE_URL}")
    print("=" * 55)
    
    report = TestReport()
    test_auth_happy_path(report)
    test_data_integrity(report)
    test_bypass_login(report)
    test_character_unlock(report)
    return report.summary()


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
        elif choice == "0":
            print("👋 종료합니다.")
            break
        else:
            print("⚠️ 잘못된 입력입니다.")


if __name__ == "__main__":
    if "--ci" in sys.argv:
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