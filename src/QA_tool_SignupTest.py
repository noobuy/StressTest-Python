# ==========================================
# 🛡️ 인증 및 예외 처리 검증기 (v2)
# ==========================================
# 개선 사항:
#   1. 각 테스트가 self-contained (자체 유저 생성 → 검증 → 정리)
#   2. assert 기반 검증 + 결과 집계 → CI/CD 자동 판정 지원
#   3. 테스트 종료 후 Cognito 계정 자동 정리 (teardown)
#   4. BOTO_CONFIG 적용 (adaptive retry)
#   5. 전체 결과 요약 리포트 및 종료 코드 반환
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
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print("\n" + "=" * 55)
        print("📋 테스트 결과 요약")
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
# 유틸: 테스트 유저 생성 / 정리
# ==========================================
def _create_test_user(email: str) -> bool:
    """Cognito에 테스트 유저를 생성하고 강제 인증합니다."""
    try:
        cognito.admin_create_user(
            UserPoolId=USER_POOL_ID,
            Username=email,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
            ],
            MessageAction="SUPPRESS",
        )
        cognito.admin_set_user_password(
            UserPoolId=USER_POOL_ID,
            Username=email,
            Password=TEST_PW,
            Permanent=True,
        )
        return True
    except cognito.exceptions.UsernameExistsException:
        return True  # 이미 존재해도 테스트 진행 가능
    except Exception as e:
        print(f"  ⚠️  테스트 유저 생성 실패: {e}")
        return False


def _delete_test_user(email: str):
    """Cognito에서 테스트 유저를 정리합니다."""
    try:
        cognito.admin_delete_user(
            UserPoolId=USER_POOL_ID,
            Username=email,
        )
    except cognito.exceptions.UserNotFoundException:
        pass  # 이미 없으면 무시
    except Exception:
        pass  # 정리 실패는 테스트 결과에 영향 없음


def _login_and_get_token(email: str, password: str) -> dict | None:
    """백엔드 로그인 API를 호출하고 응답 전체를 반환합니다."""
    res = requests.post(
        f"{BASE_URL}/api/Auth/login",
        json={"email": email, "password": password},
    )
    return {"status": res.status_code, "body": res.json() if res.headers.get("content-type", "").startswith("application/json") else {}, "raw": res.text}


# ==========================================
# 테스트 1: 정상 시나리오 (가입 → 인증 → 로그인 → 조회)
# ==========================================
def test_happy_path(report: TestReport):
    ts = int(time.time())
    email = f"qa_signup_{ts}@test.com"

    print(f"\n{'=' * 55}")
    print(f"🚀 [정상 시나리오] {email}")
    print("=" * 55)

    try:
        # 1) 회원가입
        res = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        report.record(
            "회원가입 요청 (200/201)",
            res.status_code in (200, 201),
            f"실제: {res.status_code}",
        )
        if res.status_code not in (200, 201):
            return

        # 2) Cognito 강제 인증
        cognito.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID, Username=email
        )

        # 3) 로그인 & 토큰 추출
        login = _login_and_get_token(email, TEST_PW)
        token = (
            login["body"].get("data", {}).get("idToken")
            or login["body"].get("idToken")
        )
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

        # 4) Init
        res_init = requests.post(
            f"{BASE_URL}/api/players/me/init", headers=headers
        )
        report.record(
            "프로필 초기화 /init (200/204)",
            res_init.status_code in (200, 204),
            f"실제: {res_init.status_code}",
        )

        # 5) 내 정보 조회
        res_me = requests.get(
            f"{BASE_URL}/api/players/me", headers=headers
        )
        report.record(
            "내 정보 조회 /me (200)",
            res_me.status_code == 200,
            f"실제: {res_me.status_code}",
        )

    except Exception as e:
        report.record("정상 시나리오 실행", False, f"예외 발생: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 테스트 2: 네거티브 - 틀린 비밀번호
# ==========================================
def test_wrong_password(report: TestReport):
    ts = int(time.time())
    email = f"qa_wrongpw_{ts}@test.com"

    print(f"\n{'=' * 55}")
    print(f"🔐 [네거티브] 틀린 비밀번호 로그인 → {email}")
    print("=" * 55)

    try:
        if not _create_test_user(email):
            report.record("틀린 비밀번호 테스트", False, "유저 생성 실패")
            return

        login = _login_and_get_token(email, "CompletelyWrong!!!")
        report.record(
            "틀린 비밀번호 → 401 거절",
            login["status"] == 401,
            f"실제: {login['status']}",
        )

    except Exception as e:
        report.record("틀린 비밀번호 테스트", False, f"예외: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 테스트 3: 네거티브 - 중복 가입
# ==========================================
def test_duplicate_signup(report: TestReport):
    ts = int(time.time())
    email = f"qa_dup_{ts}@test.com"

    print(f"\n{'=' * 55}")
    print(f"👥 [네거티브] 중복 가입 시도 → {email}")
    print("=" * 55)

    try:
        # 1차 가입
        res1 = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        if res1.status_code not in (200, 201):
            report.record("중복 가입 테스트 (1차 가입)", False, f"1차 가입부터 실패: {res1.status_code}")
            return

        cognito.admin_confirm_sign_up(
            UserPoolId=USER_POOL_ID, Username=email
        )

        # 2차 가입 (동일 이메일 → 차단되어야 함)
        res2 = requests.post(
            f"{BASE_URL}/api/Auth/signup",
            json={"email": email, "password": TEST_PW},
        )
        is_blocked = res2.status_code in (400, 409)
        report.record(
            "중복 가입 → 400/409 차단",
            is_blocked,
            f"실제: {res2.status_code}" + (" ⚠️ 크리티컬 버그! 중복 가입이 허용됨" if not is_blocked else ""),
        )

    except Exception as e:
        report.record("중복 가입 테스트", False, f"예외: {e}")
    finally:
        _delete_test_user(email)
        print("  🧹 테스트 유저 정리 완료")


# ==========================================
# 테스트 4: 네거티브 - 토큰 없이 보호 API 접근
# ==========================================
def test_unauthorized_access(report: TestReport):
    print(f"\n{'=' * 55}")
    print("🔒 [네거티브] 토큰 없이 보호 API 접근")
    print("=" * 55)

    try:
        res = requests.get(f"{BASE_URL}/api/players/me")
        report.record(
            "토큰 없이 /me 접근 → 401 차단",
            res.status_code == 401,
            f"실제: {res.status_code}" + (" ⚠️ 크리티컬! 인증 없이 데이터 노출됨" if res.status_code != 401 else ""),
        )
    except Exception as e:
        report.record("무인증 접근 테스트", False, f"예외: {e}")


# ==========================================
# 테스트 5: 네거티브 - 잘못된(변조된) 토큰으로 접근
# ==========================================
def test_invalid_token(report: TestReport):
    print(f"\n{'=' * 55}")
    print("🪪 [네거티브] 변조된 토큰으로 보호 API 접근")
    print("=" * 55)

    try:
        headers = {
            "Authorization": "Bearer this.is.a.fake.token",
            "Content-Type": "application/json",
        }
        res = requests.get(f"{BASE_URL}/api/players/me", headers=headers)
        report.record(
            "변조 토큰 → 401 차단",
            res.status_code == 401,
            f"실제: {res.status_code}",
        )
    except Exception as e:
        report.record("변조 토큰 테스트", False, f"예외: {e}")


# ==========================================
# 메인 실행
# ==========================================
def run_all_tests() -> bool:
    """모든 테스트를 실행하고 전체 통과 여부를 반환합니다."""
    report = TestReport()

    test_happy_path(report)
    test_wrong_password(report)
    test_duplicate_signup(report)
    test_unauthorized_access(report)
    test_invalid_token(report)

    all_passed = report.summary()
    return all_passed


def main_menu():
    while True:
        print("\n" + "=" * 40)
        print("🛡️  Vamserlike 인증 QA 테스트 (Jang Bros)")
        print("=" * 40)
        print("  1. 전체 테스트 실행 (정상 + 네거티브)")
        print("  2. 정상 시나리오만 실행")
        print("  3. 네거티브 테스트만 실행")
        print("  0. 종료")
        print("-" * 40)

        choice = input("실행할 번호를 선택하세요: ").strip()

        if choice == "1":
            passed = run_all_tests()
            if not passed:
                print("\n⚠️  일부 테스트가 실패했습니다. 위 리포트를 확인하세요.")
        elif choice == "2":
            report = TestReport()
            test_happy_path(report)
            report.summary()
        elif choice == "3":
            report = TestReport()
            test_wrong_password(report)
            test_duplicate_signup(report)
            test_unauthorized_access(report)
            test_invalid_token(report)
            report.summary()
        elif choice == "0":
            print("👋 종료합니다.")
            break
        else:
            print("  ⚠️ 잘못된 입력입니다.")


if __name__ == "__main__":
    # --ci 플래그가 있으면 메뉴 없이 전체 실행 후 종료 코드 반환
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
            print("   백엔드 서버를 먼저 실행하세요!")
