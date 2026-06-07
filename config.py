# ==========================================
# ⚙️ Vamserlike 테스트 툴 통합 설정 파일 (v3)
# ==========================================
# 개선 사항:
#   1. 민감 정보를 .env 파일로 분리 (보안 강화)
#   2. 환경 변수 우선 → .env 파일 → 기본값 순으로 폴백
#   3. tokens.csv 경로를 load_test_tools 폴더 기준 절대경로로 고정
#   4. 환경(local/cloud) 전환을 ENV 변수 하나로 제어
#   5. (v3) 캐릭터 해금 / Dev 리셋 설정 추가  ← QA 툴이 import 함
# ==========================================

import os
from pathlib import Path
from botocore.config import Config as BotoConfig

# ------------------------------------------
# 0. .env 파일 자동 로드 (있을 때만)
# ------------------------------------------
try:
    from dotenv import load_dotenv
    # config.py가 루트에 있으므로, 같은 경로의 .env를 찾습니다.
    _env_path = Path(__file__).resolve().parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path, override=False)
except ImportError:
    pass

# ------------------------------------------
# 1. 실행 환경 선택 (local / cloud)
# ------------------------------------------
# 터미널에서 전환: ENV=cloud python load_test_tools/tokens.py
ENV = os.environ.get("ENV", "local")

_URL_MAP = {
    "local": "http://localhost:5159",
    "cloud": os.environ.get("CLOUD_URL", "http://43.201.20.218:5159"),
}
BASE_URL = _URL_MAP.get(ENV, _URL_MAP["local"])

# ------------------------------------------
# 2. AWS Cognito 설정 (민감 정보)
# ------------------------------------------
REGION       = os.environ.get("AWS_REGION",       "ap-northeast-2")
USER_POOL_ID = os.environ.get("USER_POOL_ID",     "ap-northeast-2_nvW6TzXwN")
CLIENT_ID    = os.environ.get("COGNITO_CLIENT_ID", "78kvv0qos4gmvi29d26vf15bac")

# ------------------------------------------
# 3. 테스트용 공통 정보
# ------------------------------------------
TEST_PW     = os.environ.get("TEST_PW",     "Password123!")
USER_PREFIX = os.environ.get("USER_PREFIX",  "loadtest_user_")
USER_COUNT  = int(os.environ.get("USER_COUNT", "20"))

# ------------------------------------------
# 4. DynamoDB 설정
# ------------------------------------------
#TABLE_NAME    = os.environ.get("TABLE_NAME",    "VamserlikeGame")
#PARTITION_KEY = os.environ.get("PARTITION_KEY",  "UserId")
# 정렬 키(Sort Key)에 대한 설정도 필요하다면 추가 (현재는 필수는 아님)
#SORT_KEY      = "SK"

# ------------------------------------------
# 4-2. 캐릭터 해금 테스트 설정  (★ v3 복원)
# ------------------------------------------
# appsettings.json 의 GameOptions:CharacterUnlockCosts 에 등록된
# '비용 1 이상'인 실제 캐릭터 ID 를 지정하세요. (비용 숫자는 코드가 자동 실측)
UNLOCK_TARGET_CHARACTER_ID = os.environ.get("UNLOCK_TARGET_CHARACTER_ID", "potato_farmer")

# ------------------------------------------
# 4-3. Dev 리셋 확인 문구  (★ v3 복원)
# ------------------------------------------
# DevController 의 하드코딩 값과 반드시 일치해야 함
RESET_CONFIRM_TEXT = os.environ.get("RESET_CONFIRM_TEXT", "DELETE_TEST_DATA")

# ------------------------------------------
# 5. 파일 경로
# ------------------------------------------
# config.py가 위치한 디렉토리를 기준으로 tokens.csv 경로를 고정합니다.
_ROOT_DIR = Path(__file__).resolve().parent
# tokens.csv를 무조건 load_test_tools 폴더 안에 넣습니다.
TOKENS_FILE = _ROOT_DIR / "load_test_tools" / "tokens.csv"

# ------------------------------------------
# 6. Boto3 재시도 설정 (Cognito Throttling 방어)
# ------------------------------------------
# CognitoAccountConfig.py, tokens.py 등에서 공용으로 사용합니다.
# 사용법: boto3.client('cognito-idp', region_name=REGION, config=BOTO_CONFIG)
BOTO_CONFIG = BotoConfig(retries={"max_attempts": 5, "mode": "adaptive"})

# ------------------------------------------
# 부팅 시 현재 설정 요약 출력 (디버깅용)
# ------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("⚙️  현재 적용된 설정값")
    print("=" * 50)
    print(f"  ENV                        : {ENV}")
    print(f"  BASE_URL                   : {BASE_URL}")
    print(f"  REGION                     : {REGION}")
    print(f"  USER_POOL_ID               : {USER_POOL_ID[:15]}... (마스킹)")
    print(f"  CLIENT_ID                  : {CLIENT_ID[:10]}... (마스킹)")
    print(f"  USER_PREFIX                : {USER_PREFIX}")
    print(f"  USER_COUNT                 : {USER_COUNT}")
    print(f"  UNLOCK_TARGET_CHARACTER_ID : {UNLOCK_TARGET_CHARACTER_ID}")
    print(f"  RESET_CONFIRM_TEXT         : {RESET_CONFIRM_TEXT}")
    print(f"  TOKENS_FILE                : {TOKENS_FILE}")
    print("=" * 50)
