# ==========================================
# 🛡️ Vamserlike 통합 QA 테스트 툴 (v3)
# ==========================================
# 통합/개선 사항:
#   1. SignupTest와 TestMe를 하나의 파일로 통합 (중복 제거)
#   2. 팀원 요청에 따라 네거티브 테스트 일괄 제거
#   3. 인증(Auth) 정상 동작 및 데이터 무결성(Data Integrity) 중심의 검증
#   4. 각 테스트 독립 실행 및 종료 후 자동 계정 정리(Teardown)
#   5. CI/CD 자동 판정 및 요약 리포트 지원
# ==========================================

import sys

from pathlib import Path

# ★ 중요: 부모 폴더(루트)에 있는 config.py를 찾을 수 있게 경로 추가
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.append(_ROOT)

import time
from dataclasses import dataclass, field

import boto3
import requests

# 이제 부모 폴더의 config를 정상적으로 불러옵니다.
from config import BASE_URL, BOTO_CONFIG, REGION, TEST_PW, USER_POOL_ID

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
    """Cognito에서 테스트 유저를 정리합니다."""
    try:
        cognito.admin_delete_user(
            UserPoolId=USER_POOL_ID, Username=email
        )
    except Exception:
        pass


def _extract_token(login_body: dict) -> str | None:
    """백엔드 응답 구조에서 토큰을 추출합니다."""
    return (
        login_body.get("data", {}).get("idToken")
        or login_body.get("idToken")
    )


# ==========================================
# 시나리오 1: 인증 시스템 정상 흐름 (Happy Path)
# ==========================================
def test_auth_happy_path(report: TestReport):
    ts = int(time.time())
    email = f"qa_auth_{ts}@test.com"

    print(f"\n{'=' * 55}")
    print(f"🔐 [시나리오 1] 인증 정상 흐름 검증 ({email})")
    print("=" * 55)

    try:
        # 1) 회원가입
        res_signup = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        report.record(
            "회원가입 요청 (200/201)",
            res_signup.status_code in (200, 201),
            f"실제: {res_signup.status_code}",
        )
        if res_signup.status_code not in (200, 201):
            return

        # 2) Cognito 강제 인증
        cognito.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID, Username=email
        )

        # 3) 로그인 & 토큰 추출
        res_login = requests.post(
            f"{BASE_URL}/api/Auth/login",
            json={"email": email, "password": TEST_PW},
        )
        login_body = res_login.json() if res_login.headers.get("content-type", "").startswith("application/json") else {}
        token = _extract_token(login_body)
        
        report.record(
            "로그인 및 토큰 발급",
            token is not None,
            "토큰 없음" if not token else "",
        )
        if not token:
            return

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

        # 4) 초기화 (Init)
        res_init = requests.post(
            f"{BASE_URL}/api/players/me/init", headers=headers
        )
        report.record(
            "프로필 초기화 /init (200/204)",
            res_init.status_code in (200, 204),
            f"실제: {res_init.status_code}",
        )

        # 5) 내 정보 조회 (Me)
        res_me = requests.get(
            f"{BASE_URL}/api/players/me", headers=headers
        )
        report.record(
            "내 정보 조회 /me (200)",
            res_me.status_code == 200,
            f"실제: {res_me.status_code}",
        )

    except Exception as e:
        report.record("인증 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 시나리오 2: 게임 데이터 무결성 (Integrity)
# ==========================================
def test_data_integrity(report: TestReport):
    ts = int(time.time())
    email = f"qa_data_{ts}@test.com"

    # 검증용 게임 데이터
    game_1 = {"score": 2500, "level": 15, "playedCharacterId": "potato_farmer"}
    game_2 = {"score": 1200, "level": 8,  "playedCharacterId": "rice_farmer"}

    print(f"\n{'=' * 55}")
    print(f"📊 [시나리오 2] 데이터 무결성 검증 ({email})")
    print("=" * 55)

    try:
        # 가입 -> 인증 -> 로그인 -> 초기화 (빠르게 진행)
        requests.post(f"{BASE_URL}/api/Auth/signup", json={"email": email, "password": TEST_PW})
        cognito.admin_confirm_sign_up(UserPoolId=USER_POOL_ID, Username=email)
        res_login = requests.post(f"{BASE_URL}/api/Auth/login", json={"email": email, "password": TEST_PW})
        
        token = _extract_token(res_login.json())
        if not token:
            report.record("사전 설정 실패", False, "로그인 토큰을 발급받지 못했습니다.")
            return

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        requests.post(f"{BASE_URL}/api/players/me/init", headers=headers)

        # --------------------------------------------------
        # 1판 게임 결과 저장 및 검증
        # --------------------------------------------------
        print(f"\n📌 1판 저장 (점수:{game_1['score']}, 레벨:{game_1['level']})")
        res_prog1 = requests.put(f"{BASE_URL}/api/players/me/progress", json=game_1, headers=headers)
        report.record("1판 결과 저장 (200/204)", res_prog1.status_code in (200, 204), f"실제: {res_prog1.status_code}")
        
        res_me1 = requests.get(f"{BASE_URL}/api/players/me", headers=headers)
        if res_me1.status_code != 200: return

        p1 = res_me1.json().get("data", res_me1.json())
        report.record(f"bestScore == {game_1['score']}", p1.get("bestScore") == game_1["score"], f"서버값: {p1.get('bestScore')}")
        report.record(f"highestLevel == {game_1['level']}", p1.get("highestLevel") == game_1["level"], f"서버값: {p1.get('highestLevel')}")
        report.record("totalPlayCount == 1", p1.get("totalPlayCount") == 1, f"서버값: {p1.get('totalPlayCount')}")

        # --------------------------------------------------
        # 2판 게임 결과 저장 (더 낮은 점수) 및 누적 검증
        # --------------------------------------------------
        print(f"\n📌 2판 저장 (점수:{game_2['score']}, 레벨:{game_2['level']})")
        res_prog2 = requests.put(f"{BASE_URL}/api/players/me/progress", json=game_2, headers=headers)
        report.record("2판 결과 저장 (200/204)", res_prog2.status_code in (200, 204), f"실제: {res_prog2.status_code}")

        res_me2 = requests.get(f"{BASE_URL}/api/players/me", headers=headers)
        if res_me2.status_code != 200: return

        p2 = res_me2.json().get("data", res_me2.json())
        report.record(f"bestScore 유지 == {game_1['score']}", p2.get("bestScore") == game_1["score"], f"서버값: {p2.get('bestScore')}")
        report.record(f"highestLevel 유지 == {game_1['level']}", p2.get("highestLevel") == game_1["level"], f"서버값: {p2.get('highestLevel')}")
        report.record(f"lastCharacter 갱신 == {game_2['playedCharacterId']}", p2.get("lastPlayedCharacterId") == game_2["playedCharacterId"], f"서버값: {p2.get('lastPlayedCharacterId')}")
        report.record("totalPlayCount == 2", p2.get("totalPlayCount") == 2, f"서버값: {p2.get('totalPlayCount')}")

        # --------------------------------------------------
        # 랭킹 조회
        # --------------------------------------------------
        print("\n📌 랭킹 시스템 연동 확인")
        res_rank = requests.get(f"{BASE_URL}/api/players/ranking?take=5", headers=headers)
        report.record("랭킹 조회 성공 (200)", res_rank.status_code == 200, f"실제: {res_rank.status_code}")

    except Exception as e:
        report.record("무결성 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("\n  🧹 테스트 유저 정리 완료")


# ==========================================
# 메인 실행 컨트롤러
# ==========================================
def run_all_tests() -> bool:
    report = TestReport()
    test_auth_happy_path(report)
    test_data_integrity(report)
    return report.summary()


def main_menu():
    while True:
        print("\n" + "=" * 45)
        print("🛡️ Vamserlike 통합 QA 테스트 툴 (Jang Bros)")
        print("=" * 45)
        print("  1. 전체 테스트 실행 (인증 + 데이터 무결성)")
        print("  2. 인증(Auth) 정상 시나리오만 실행")
        print("  3. 데이터 무결성(Integrity) 시나리오만 실행")
        print("  0. 종료")
        print("-" * 45)

        choice = input("실행할 번호를 선택하세요: ").strip()

        report = TestReport()
        if choice == "1":
            test_auth_happy_path(report)
            test_data_integrity(report)
            report.summary()
        elif choice == "2":
            test_auth_happy_path(report)
            report.summary()
        elif choice == "3":
            test_data_integrity(report)
            report.summary()
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