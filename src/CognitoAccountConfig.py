# ==========================================
# 👤 AWS Cognito 계정 자동화 엔진 (v2)
# ==========================================
# 개선 사항:
#   1. BOTO_CONFIG 적용 (adaptive retry → Throttling 자동 방어)
#   2. config.py의 USER_COUNT 연동 (매직 넘버 제거)
#   3. 삭제 시 list_users Limit 상향 (60 → 최대치)으로 속도 개선
#   4. 생성 결과 요약 리포트 (성공/스킵/실패 카운트)
#   5. 삭제 전 대상 수 미리 표시하여 안전성 확보
#   6. sleep 간격을 BOTO_CONFIG의 adaptive retry에 위임
# ==========================================

import sys
import time

import boto3

from config import (
    BOTO_CONFIG,
    CLIENT_ID,
    REGION,
    TEST_PW,
    USER_COUNT,
    USER_POOL_ID,
    USER_PREFIX,
)

# adaptive retry가 적용된 클라이언트
client = boto3.client("cognito-idp", region_name=REGION, config=BOTO_CONFIG)


# ==========================================
# 1. 더미 유저 생성
# ==========================================
def create_dummy_users(count: int = USER_COUNT):
    """지정한 수만큼 더미 유저를 생성하고 인증을 완료합니다."""
    print(f"\n🚀 {count}명의 더미 유저 생성을 시작합니다...")

    success_count = 0
    skipped_count = 0
    failed_count = 0
    failed_list: list[str] = []

    for i in range(1, count + 1):
        email = f"{USER_PREFIX}{i}@test.com"
        try:
            # 1) 유저 생성 (이메일 인증 완료 상태, 알림 메일 차단)
            client.admin_create_user(
                UserPoolId=USER_POOL_ID,
                Username=email,
                UserAttributes=[
                    {"Name": "email", "Value": email},
                    {"Name": "email_verified", "Value": "true"},
                ],
                MessageAction="SUPPRESS",
            )

            # 2) 비밀번호 영구 설정 (첫 로그인 Challenge 회피)
            client.admin_set_user_password(
                UserPoolId=USER_POOL_ID,
                Username=email,
                Password=TEST_PW,
                Permanent=True,
            )

            success_count += 1

        except client.exceptions.UsernameExistsException:
            skipped_count += 1

        except Exception as e:
            failed_count += 1
            failed_list.append(email)
            print(f"  ❌ [{i}/{count}] {email} 생성 에러: {e}")

        # 진행 상황 출력 (100명 단위)
        if i % 100 == 0:
            print(f"  📦 [{i}/{count}] 처리 완료 (신규: {success_count} / 스킵: {skipped_count} / 실패: {failed_count})")

    # ---- 결과 요약 리포트 ----
    print("\n" + "=" * 50)
    print("📋 유저 생성 결과 리포트")
    print("=" * 50)
    print(f"  ✅ 신규 생성: {success_count}명")
    print(f"  ⏭️  이미 존재 (스킵): {skipped_count}명")
    print(f"  ❌ 실패: {failed_count}명")
    if failed_list:
        print(f"  💡 실패 목록: {failed_list[:10]}{'...' if len(failed_list) > 10 else ''}")
    print("=" * 50)


# ==========================================
# 2. 더미 유저 삭제
# ==========================================
def _collect_dummy_users() -> list[dict]:
    """USER_PREFIX로 시작하는 모든 유저를 검색하여 리스트로 반환합니다."""
    targets = []
    pagination_token = None

    while True:
        kwargs = {
            "UserPoolId": USER_POOL_ID,
            "Limit": 60,  # list_users API 최대값
        }
        if pagination_token:
            kwargs["PaginationToken"] = pagination_token

        response = client.list_users(**kwargs)

        for user in response.get("Users", []):
            # Cognito가 이메일 가입일 때 Username이 UUID로 변환되므로
            # email 속성에서 우리 접두사를 확인합니다.
            email = ""
            for attr in user.get("Attributes", []):
                if attr["Name"] == "email":
                    email = attr["Value"]
                    break

            if email.startswith(USER_PREFIX):
                targets.append(
                    {"username": user["Username"], "email": email}
                )

        pagination_token = response.get("PaginationToken")
        if not pagination_token:
            break

    return targets


def delete_dummy_users():
    """USER_PREFIX로 시작하는 모든 유저를 안전하게 삭제합니다."""
    print(f"\n🔍 '{USER_PREFIX}'로 시작하는 더미 유저를 검색 중...")

    targets = _collect_dummy_users()

    if not targets:
        print("  ℹ️  삭제할 더미 유저가 없습니다.")
        return

    print(f"  🎯 삭제 대상: {len(targets)}명")

    deleted_count = 0
    failed_count = 0

    for i, user in enumerate(targets, 1):
        try:
            client.admin_delete_user(
                UserPoolId=USER_POOL_ID,
                Username=user["username"],
            )
            deleted_count += 1
        except Exception as e:
            failed_count += 1
            print(f"  ❌ {user['email']} 삭제 에러: {e}")

        if i % 100 == 0:
            print(f"  🗑️  [{i}/{len(targets)}] 삭제 진행 중...")

    # ---- 결과 요약 ----
    print("\n" + "=" * 50)
    print("📋 유저 삭제 결과 리포트")
    print("=" * 50)
    print(f"  ✅ 삭제 완료: {deleted_count}명")
    print(f"  ❌ 삭제 실패: {failed_count}명")
    print("=" * 50)


# ==========================================
# 3. 메뉴
# ==========================================
def main_menu():
    while True:
        print("\n" + "=" * 40)
        print("👤 AWS Cognito 계정 관리자 (Jang Bros)")
        print("=" * 40)
        print(f"  1. 부하 테스트용 유저 {USER_COUNT}명 생성")
        print("  2. 더미 유저 전체 삭제 (청소)")
        print("  0. 종료")
        print("-" * 40)

        choice = input("명령을 선택하세요: ").strip()

        if choice == "1":
            create_dummy_users(USER_COUNT)
        elif choice == "2":
            targets = _collect_dummy_users()
            if not targets:
                print("  ℹ️  삭제할 더미 유저가 없습니다.")
                continue
            confirm = input(
                f"  ❗ {len(targets)}명의 더미 유저를 삭제합니다. 계속하시겠습니까? (y/n): "
            )
            if confirm.strip().lower() == "y":
                delete_dummy_users()
        elif choice == "0":
            print("👋 종료합니다.")
            break
        else:
            print("  ⚠️ 잘못된 입력입니다.")


if __name__ == "__main__":
    main_menu()
