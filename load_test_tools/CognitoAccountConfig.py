# ==========================================
# 🛠️ Vamserlike 통합 테스트 & 유저 관리 툴
# ==========================================
# 기능:
#   1. Cognito 더미 유저 생성 (config 연동)
#   2. DB + Cognito 전체 데이터 삭제 (API 호출)
#   3. 가상 유저 상태 확인 (원하는 수만큼 콘솔 조회)
# ==========================================

import sys
import csv
import time
from pathlib import Path

# ★ 중요: 부모 폴더(루트)에 있는 config.py를 찾을 수 있게 경로 추가
_ROOT = str(Path(__file__).resolve().parent.parent)
if _ROOT not in sys.path:
    sys.path.append(_ROOT)

import boto3
import requests

# config.py 설정 불러오기
from config import (
    BOTO_CONFIG, CLIENT_ID, REGION, TEST_PW, 
    USER_COUNT, USER_POOL_ID, USER_PREFIX,
    BASE_URL, RESET_CONFIRM_TEXT, TOKENS_FILE
)

# adaptive retry가 적용된 클라이언트
client = boto3.client("cognito-idp", region_name=REGION, config=BOTO_CONFIG)


# ==========================================
# [기능 1] 더미 유저 생성
# ==========================================
def create_dummy_users(count: int = USER_COUNT, skip_verification: bool = True):
    mode_text = "이메일 인증 스킵 모드" if skip_verification else "실제 이메일 인증(메일 발송) 모드"
    print(f"\n🚀 {count}명의 더미 유저 생성을 시작합니다... [{mode_text}]")

    success_count = 0
    skipped_count = 0
    failed_count = 0
    failed_list: list[str] = []

    for i in range(1, count + 1):
        email = f"{USER_PREFIX}{i}@test.com"
        try:
            # 1) 유저 생성 기본 설정
            user_attributes = [{"Name": "email", "Value": email}]
            create_kwargs = {
                "UserPoolId": USER_POOL_ID,
                "Username": email,
            }

            if skip_verification:
                user_attributes.append({"Name": "email_verified", "Value": "true"})
                create_kwargs["MessageAction"] = "SUPPRESS"

            create_kwargs["UserAttributes"] = user_attributes
            client.admin_create_user(**create_kwargs)

            # 2) 비밀번호 영구 설정
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

        if i % 100 == 0:
            print(f"  📦 [{i}/{count}] 처리 완료 (신규: {success_count} / 스킵: {skipped_count} / 실패: {failed_count})")

    # 결과 요약
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
# [기능 2] 전체 테스트 데이터 삭제
# ==========================================
def delete_all_test_data():
    print("\n" + "🚨" * 20)
    print("위험: API를 통해 DynamoDB 플레이어를 '전부' 삭제합니다.")
    print("      Cognito 유저까지 지우면 부하테스트용 1,000명 + 실제 계정도 모두 삭제됩니다!")
    print("🚨" * 20)

    confirm = input(f"\n정말 진행하려면 '{RESET_CONFIRM_TEXT}' 를 그대로 입력하세요: ").strip()
    if confirm != RESET_CONFIRM_TEXT:
        print("  ❌ 확인 문구 불일치. 취소합니다.")
        return

    wipe = input("Cognito 유저도 전부 삭제할까요? (정말 위험) (y/N): ").strip().lower() == "y"
    
    print(f"\n🗑️ 백엔드 API({BASE_URL}) 호출 중...")
    try:
        res = requests.delete(
            f"{BASE_URL}/api/dev/reset-test-data",
            json={"confirmText": RESET_CONFIRM_TEXT, "deleteAllCognitoUsers": wipe},
        )
        if res.status_code == 200:
            body = res.json()
            d = body.get("data", body) if isinstance(body, dict) else {}
            print(f"\n  ✅ 초기화 완료")
            print(f"     - 삭제된 DB 플레이어: {d.get('deletedDbPlayers', '알수없음')}명")
            print(f"     - 삭제된 Cognito 유저: {d.get('deletedCognitoUsers', '알수없음')}명")
        else:
            print(f"  ❌ API 호출 실패: {res.status_code} - {res.text[:200]}")
    except requests.exceptions.ConnectionError:
        print(f"  💥 연결 실패: {BASE_URL} 서버에 연결할 수 없습니다. 백엔드 서버가 켜져있는지 확인하세요.")
    except Exception as e:
        print(f"  💥 알 수 없는 에러 발생: {e}")


# ==========================================
# [기능 3] 유저 상태 확인
# ==========================================
def _get_tokens() -> list[tuple[str, str]]:
    if not TOKENS_FILE.exists():
        print(f"❌ 토큰 파일이 없습니다: {TOKENS_FILE}")
        print("   토큰 발급을 먼저 진행해주세요.")
        return []

    tokens = []
    with open(TOKENS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tokens.append((row["email"], row["token"]))
    return tokens

def print_user_data(limit: int):
    tokens = _get_tokens()
    if not tokens:
        return

    # 가지고 있는 토큰 수보다 많이 입력한 경우 최대치로 보정
    target_tokens = tokens[:limit]
    total_users = len(tokens)
    
    print("\n" + "=" * 80)
    print(f"📊 가상 유저 상태 조회 (총 {total_users}명 중 상위 {len(target_tokens)}명)")
    print("=" * 80)
    print(f"{'이메일':<25} | {'골드':<7} | {'최고점수':<8} | {'레벨':<5} | {'플레이수':<7} | {'현재캐릭터'}")
    print("-" * 80)

    success_count = 0
    
    for email, token in target_tokens:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        try:
            res = requests.get(f"{BASE_URL}/api/players/me", headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json().get("data", res.json())
                gold = data.get("gold", 0)
                best_score = data.get("bestScore", 0)
                level = data.get("highestLevel", 0)
                play_count = data.get("totalPlayCount", 0)
                char_id = data.get("selectedCharacterId", "None")
                
                print(f"{email:<25} | {gold:<8} | {best_score:<10} | {level:<6} | {play_count:<9} | {char_id}")
                success_count += 1
            elif res.status_code == 404:
                print(f"{email:<25} | ⚠️ 아직 /init 되지 않은 유저입니다.")
            else:
                print(f"{email:<25} | ❌ API 에러: {res.status_code}")
        except Exception as e:
            print(f"{email:<25} | ❌ 에러: {e}")

    print("-" * 80)
    print(f"✅ 조회 완료 (성공: {success_count}/{len(target_tokens)}명)")
    print("=" * 80 + "\n")


# ==========================================
# 🚀 메인 메뉴
# ==========================================
def main_menu():
    while True:
        print("\n" + "=" * 50)
        print("🛠️ Vamserlike 통합 테스트 & 유저 관리 툴")
        print("=" * 50)
        print(f"  1. 부하 테스트용 유저 {USER_COUNT}명 생성 (Cognito)")
        print("  2. DB + Cognito 데이터 전체 삭제 (API 호출)")
        print("  3. 가상 유저 상태 확인 (조회수 직접 입력)")
        print("  0. 종료")
        print("-" * 50)

        choice = input("명령을 선택하세요: ").strip()

        if choice == "1":
            skip_input = input("  📧 이메일 인증을 스킵하시겠습니까? (Y/n): ").strip().lower()
            skip_verification = False if skip_input == "n" else True
            create_dummy_users(USER_COUNT, skip_verification)
            
        elif choice == "2":
            delete_all_test_data()
            
        elif choice == "3":
            limit_input = input("  👀 조회할 유저 숫자를 입력하세요 (예: 20): ").strip()
            try:
                limit = int(limit_input)
                if limit > 0:
                    print_user_data(limit)
                else:
                    print("  ⚠️ 1 이상의 숫자를 입력해주세요.")
            except ValueError:
                print("  ⚠️ 올바른 숫자를 입력해주세요.")
                
        elif choice == "0":
            print("👋 프로그램을 종료합니다.")
            break
        else:
            print("  ⚠️ 잘못된 입력입니다.")

if __name__ == "__main__":
    main_menu()