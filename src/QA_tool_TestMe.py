# ==========================================
# 📊 데이터 무결성 검증기 (v2)
# ==========================================
# 개선 사항:
#   1. 각 단계 응답 코드를 검증하고 실패 시 즉시 중단 (fail-fast)
#   2. assert 기반 검증 + 결과 집계 → CI/CD 자동 판정 지원
#   3. 테스트 종료 후 Cognito 계정 자동 정리 (teardown)
#   4. BOTO_CONFIG 적용 (adaptive retry)
#   5. 2회 플레이 저장 후 누적 검증 (bestScore 갱신 + playCount 증가)
#   6. 전체 결과 요약 리포트 및 종료 코드 반환
# ==========================================

import sys
import time
from dataclasses import dataclass, field

import boto3
import requests

from config import (
    BASE_URL,
    BOTO_CONFIG,
    REGION,
    TEST_PW,
    USER_POOL_ID,
)

cognito = boto3.client("cognito-idp", region_name=REGION, config=BOTO_CONFIG)


# ==========================================
# 테스트 결과 수집기 (SignupTest.py와 동일 패턴)
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

    def summary(self) -> bool:
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print("\n" + "=" * 55)
        print("📋 데이터 무결성 검수 결과")
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
# 유틸
# ==========================================
def _delete_test_user(email: str):
    """Cognito에서 테스트 유저를 정리합니다."""
    try:
        cognito.admin_delete_user(
            UserPoolId=USER_POOL_ID, Username=email
        )
    except Exception:
        pass


def _extract_token(login_body: dict) -> str | None:
    """기영님 백엔드 응답 구조에서 토큰을 추출합니다."""
    return (
        login_body.get("data", {}).get("idToken")
        or login_body.get("idToken")
    )


# ==========================================
# 메인 테스트: 데이터 무결성 정밀 검수
# ==========================================
def test_data_integrity(report: TestReport):
    ts = int(time.time())
    email = f"qa_data_{ts}@test.com"

    # ---- 검증용 게임 데이터 (1판, 2판) ----
    game_1 = {"score": 2500, "level": 15, "playedCharacterId": "potato_farmer"}
    game_2 = {"score": 1200, "level": 8,  "playedCharacterId": "rice_farmer"}
    # 기대값: bestScore=2500 (1판이 더 높으므로), highestLevel=15, totalPlayCount=2

    print(f"\n{'=' * 55}")
    print(f"🚀 [데이터 무결성] 통합 시나리오 ({email})")
    print("=" * 55)

    try:
        # --------------------------------------------------
        # 1단계: 회원가입
        # --------------------------------------------------
        print("\n📌 1단계: 회원가입")
        res_signup = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        report.record(
            "회원가입 (200/201)",
            res_signup.status_code in (200, 201),
            f"실제: {res_signup.status_code}",
        )
        if res_signup.status_code not in (200, 201):
            return  # 가입 실패 시 이후 무의미

        # --------------------------------------------------
        # 2단계: Cognito 강제 인증 + 로그인
        # --------------------------------------------------
        print("\n📌 2단계: 강제 인증 + 로그인")
        cognito.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID, Username=email
        )

        res_login = requests.post(
            f"{BASE_URL}/api/Auth/login",
            json={"email": email, "password": TEST_PW},
        )
        login_body = res_login.json() if res_login.headers.get("content-type", "").startswith("application/json") else {}
        token = _extract_token(login_body)

        report.record(
            "로그인 및 토큰 발급",
            token is not None,
            "토큰 추출 실패" if not token else "",
        )
        if not token:
            return

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # --------------------------------------------------
        # 3단계: 프로필 초기화
        # --------------------------------------------------
        print("\n📌 3단계: 프로필 초기화 (/init)")
        res_init = requests.post(
            f"{BASE_URL}/api/players/me/init", headers=headers
        )
        report.record(
            "/init 호출 (200/204)",
            res_init.status_code in (200, 204),
            f"실제: {res_init.status_code}",
        )
        if res_init.status_code not in (200, 204):
            return

        # --------------------------------------------------
        # 4단계: 1판 게임 결과 저장
        # --------------------------------------------------
        print(f"\n📌 4단계: 1판 저장 (점수:{game_1['score']}, 레벨:{game_1['level']})")
        res_prog1 = requests.put(
            f"{BASE_URL}/api/players/me/progress",
            json=game_1,
            headers=headers,
        )
        report.record(
            "1판 결과 저장 (200/204)",
            res_prog1.status_code in (200, 204),
            f"실제: {res_prog1.status_code}",
        )
        if res_prog1.status_code not in (200, 204):
            return

        # --------------------------------------------------
        # 5단계: 1판 후 데이터 검증
        # --------------------------------------------------
        print("\n📌 5단계: 1판 후 무결성 검증 (GET /me)")
        res_me1 = requests.get(
            f"{BASE_URL}/api/players/me", headers=headers
        )
        report.record(
            "1판 후 /me 조회 (200)",
            res_me1.status_code == 200,
            f"실제: {res_me1.status_code}",
        )
        if res_me1.status_code != 200:
            return

        data1 = res_me1.json()
        p1 = data1.get("data", data1)  # ApiResponse 구조 분해

        report.record(
            f"bestScore == {game_1['score']}",
            p1.get("bestScore") == game_1["score"],
            f"서버값: {p1.get('bestScore')}",
        )
        report.record(
            f"highestLevel == {game_1['level']}",
            p1.get("highestLevel") == game_1["level"],
            f"서버값: {p1.get('highestLevel')}",
        )
        report.record(
            f"lastPlayedCharacterId == {game_1['playedCharacterId']}",
            p1.get("lastPlayedCharacterId") == game_1["playedCharacterId"],
            f"서버값: {p1.get('lastPlayedCharacterId')}",
        )
        report.record(
            "totalPlayCount == 1",
            p1.get("totalPlayCount") == 1,
            f"서버값: {p1.get('totalPlayCount')}",
        )

        # --------------------------------------------------
        # 6단계: 2판 게임 결과 저장 (낮은 점수)
        # --------------------------------------------------
        print(f"\n📌 6단계: 2판 저장 (점수:{game_2['score']}, 레벨:{game_2['level']})")
        res_prog2 = requests.put(
            f"{BASE_URL}/api/players/me/progress",
            json=game_2,
            headers=headers,
        )
        report.record(
            "2판 결과 저장 (200/204)",
            res_prog2.status_code in (200, 204),
            f"실제: {res_prog2.status_code}",
        )
        if res_prog2.status_code not in (200, 204):
            return

        # --------------------------------------------------
        # 7단계: 2판 후 누적 검증 (핵심!)
        # --------------------------------------------------
        print("\n📌 7단계: 2판 후 누적 무결성 검증")
        res_me2 = requests.get(
            f"{BASE_URL}/api/players/me", headers=headers
        )
        report.record(
            "2판 후 /me 조회 (200)",
            res_me2.status_code == 200,
            f"실제: {res_me2.status_code}",
        )
        if res_me2.status_code != 200:
            return

        data2 = res_me2.json()
        p2 = data2.get("data", data2)

        # bestScore는 1판(2500)이 더 높으므로 갱신되면 안 됨
        report.record(
            f"bestScore 유지 == {game_1['score']} (2판이 더 낮으므로)",
            p2.get("bestScore") == game_1["score"],
            f"서버값: {p2.get('bestScore')}",
        )
        # highestLevel도 1판(15)이 더 높으므로 유지
        report.record(
            f"highestLevel 유지 == {game_1['level']}",
            p2.get("highestLevel") == game_1["level"],
            f"서버값: {p2.get('highestLevel')}",
        )
        # lastPlayedCharacterId는 2판 캐릭터로 갱신되어야 함
        report.record(
            f"lastPlayedCharacterId 갱신 == {game_2['playedCharacterId']}",
            p2.get("lastPlayedCharacterId") == game_2["playedCharacterId"],
            f"서버값: {p2.get('lastPlayedCharacterId')}",
        )
        # 플레이 횟수는 2가 되어야 함
        report.record(
            "totalPlayCount == 2",
            p2.get("totalPlayCount") == 2,
            f"서버값: {p2.get('totalPlayCount')}",
        )

        # --------------------------------------------------
        # 8단계: 랭킹 조회
        # --------------------------------------------------
        print("\n📌 8단계: 랭킹 시스템 검증")
        res_rank = requests.get(
            f"{BASE_URL}/api/players/ranking?take=5", headers=headers
        )
        report.record(
            "랭킹 조회 (200)",
            res_rank.status_code == 200,
            f"실제: {res_rank.status_code}",
        )

    except Exception as e:
        report.record("시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("\n  🧹 테스트 유저 정리 완료")


# ==========================================
# 메인 실행
# ==========================================
def run_all_tests() -> bool:
    """전체 무결성 테스트를 실행하고 통과 여부를 반환합니다."""
    report = TestReport()
    test_data_integrity(report)
    all_passed = report.summary()
    return all_passed


def main_menu():
    while True:
        print("\n" + "=" * 40)
        print("📊 Vamserlike 데이터 무결성 QA (Jang Bros)")
        print("=" * 40)
        print("  1. 데이터 무결성 정밀 검수 실행")
        print("  0. 종료")
        print("-" * 40)

        choice = input("실행할 번호를 선택하세요: ").strip()

        if choice == "1":
            passed = run_all_tests()
            if not passed:
                print("\n⚠️  일부 검증이 실패했습니다. 위 리포트를 확인하세요.")
        elif choice == "0":
            print("👋 종료합니다.")
            break
        else:
            print("  ⚠️ 잘못된 입력입니다.")


if __name__ == "__main__":
    # --ci 플래그: 메뉴 없이 실행 → 종료 코드로 결과 반환
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
            print("   'dotnet run'을 먼저 실행하세요!")
