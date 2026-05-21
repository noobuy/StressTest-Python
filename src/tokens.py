# ==========================================
# 🔑 JWT 토큰 추출기 (v2)
# ==========================================
# 개선 사항:
#   1. BOTO_CONFIG 적용 (adaptive retry → Throttling 자동 방어)
#   2. config.py의 TOKENS_FILE 절대경로 사용 (실행 위치 무관)
#   3. CSV 헤더에 발급 시각(issued_at) 추가 → locustfile.py 만료 경고 연동
#   4. 기존 tokens.csv가 있으면 만료 여부를 체크하고 덮어쓸지 확인
#   5. 실패한 유저 목록 요약 리포트
#   6. USER_COUNT를 config에서 가져와 매직 넘버 제거
# ==========================================

import csv
import os
import sys
import time

import boto3

from config import (
    BOTO_CONFIG,
    CLIENT_ID,
    REGION,
    TEST_PW,
    TOKENS_FILE,
    USER_COUNT,
    USER_POOL_ID,
    USER_PREFIX,
)

# adaptive retry가 적용된 클라이언트
client = boto3.client("cognito-idp", region_name=REGION, config=BOTO_CONFIG)

# Cognito IdToken 기본 만료 시간 (초)
TOKEN_EXPIRY_SECONDS = 3600


def _check_existing_tokens() -> bool:
    """기존 tokens.csv가 있으면 만료 여부를 확인하고 재발급 여부를 묻습니다."""
    if not TOKENS_FILE.exists():
        return True  # 파일 없음 → 바로 생성

    file_age = time.time() - os.path.getmtime(TOKENS_FILE)
    remaining = TOKEN_EXPIRY_SECONDS - file_age

    if remaining > 0:
        minutes = int(remaining // 60)
        print(f"\n📄 기존 tokens.csv가 존재합니다 (만료까지 약 {minutes}분 남음)")
    else:
        print(f"\n📄 기존 tokens.csv가 존재하지만 이미 만료되었습니다 (⚠️ 재발급 권장)")

    answer = input("   덮어쓰고 새로 발급하시겠습니까? (y/n): ").strip().lower()
    return answer == "y"


def generate_tokens(count: int = USER_COUNT):
    """가상 유저 계정으로 로그인하여 JWT 토큰을 추출하고 CSV에 저장합니다."""

    if not _check_existing_tokens():
        print("   ℹ️  기존 토큰 파일을 유지합니다.")
        return

    print(f"\n🚀 {count}명의 유저로부터 JWT 토큰 추출을 시작합니다...")

    issued_at = int(time.time())  # 발급 시각 (에포크)
    success_count = 0
    failed_count = 0
    failed_list: list[str] = []

    with open(TOKENS_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        # locustfile.py가 읽는 헤더: email, token
        # issued_at은 만료 경고용 메타데이터
        writer.writerow(["email", "token", "issued_at"])

        for i in range(1, count + 1):
            email = f"{USER_PREFIX}{i}@test.com"
            try:
                response = client.admin_initiate_auth(
                    UserPoolId=USER_POOL_ID,
                    ClientId=CLIENT_ID,
                    AuthFlow="ADMIN_NO_SRP_AUTH",
                    AuthParameters={
                        "USERNAME": email,
                        "PASSWORD": TEST_PW,
                    },
                )

                token = response["AuthenticationResult"]["IdToken"]
                writer.writerow([email, token, issued_at])
                success_count += 1

            except client.exceptions.UserNotFoundException:
                failed_count += 1
                failed_list.append(email)
                if failed_count <= 5:
                    print(f"  ⚠️  {email} → 유저가 존재하지 않습니다 (CognitoAccountConfig.py를 먼저 실행하세요)")

            except client.exceptions.NotAuthorizedException:
                failed_count += 1
                failed_list.append(email)
                if failed_count <= 5:
                    print(f"  ⚠️  {email} → 비밀번호가 틀립니다 (config.py의 TEST_PW 확인)")

            except Exception as e:
                failed_count += 1
                failed_list.append(email)
                if failed_count <= 5:
                    print(f"  ❌ {email} → 토큰 발급 에러: {e}")

            # 진행 상황 (100명 단위)
            if i % 100 == 0:
                print(f"  🔑 [{i}/{count}] 추출 완료 (성공: {success_count} / 실패: {failed_count})")

    # ---- 결과 요약 리포트 ----
    print("\n" + "=" * 50)
    print("📋 토큰 추출 결과 리포트")
    print("=" * 50)
    print(f"  ✅ 성공: {success_count}개")
    print(f"  ❌ 실패: {failed_count}개")
    print(f"  📄 저장 위치: {TOKENS_FILE}")
    print(f"  ⏰ 만료 예정: 약 {TOKEN_EXPIRY_SECONDS // 60}분 후")
    if failed_list:
        print(f"  💡 실패 샘플: {failed_list[:5]}{'...' if len(failed_list) > 5 else ''}")
    if failed_count > 0 and success_count == 0:
        print("\n  🚨 토큰이 하나도 발급되지 않았습니다!")
        print("     → CognitoAccountConfig.py로 유저를 먼저 생성했는지 확인하세요.")
    print("=" * 50)


if __name__ == "__main__":
    generate_tokens(USER_COUNT)
