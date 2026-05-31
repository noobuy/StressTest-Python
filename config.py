# ==========================================
# ⚙️ Vamserlike 테스트 툴 통합 설정 파일 (v2)
# ==========================================
# 개선 사항:
#   1. 민감 정보를 .env 파일로 분리 (보안 강화)
#   2. 환경 변수 우선 → .env 파일 → 기본값 순으로 폴백
#   3. tokens.csv 경로를 스크립트 기준 절대경로로 고정
#   4. 환경(local/cloud) 전환을 ENV 변수 하나로 제어
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
# 터미널에서 전환: ENV=cloud python src/tokens.py
ENV = os.environ.get("ENV", "local")

_URL_MAP = {
    "local": "http://localhost:5159",
    "cloud": os.environ.get("CLOUD_URL", "http://43.201.49.116:5159"),
}
BASE_URL = _URL_MAP.get(ENV, _URL_MAP["local"])

# ------------------------------------------
# 2. AWS Cognito 설정 (민감 정보)
# ------------------------------------------
REGION       = os.environ.get("AWS_REGION",       "ap-northeast-2")
USER_POOL_ID = os.environ.get("USER_POOL_ID",     "ap-northeast-2_mgNamTmpN")
CLIENT_ID    = os.environ.get("COGNITO_CLIENT_ID", "4h53oqgo30ps6q2p3ao7b9d4kt")

# ------------------------------------------
# 3. 테스트용 공통 정보
# ------------------------------------------
TEST_PW     = os.environ.get("TEST_PW",     "Password123!")
USER_PREFIX = os.environ.get("USER_PREFIX",  "loadtest_user_")
USER_COUNT  = int(os.environ.get("USER_COUNT", "1000"))

# ------------------------------------------
# 4. DynamoDB 설정
# ------------------------------------------
TABLE_NAME    = os.environ.get("TABLE_NAME",    "VamserlikeGame")
PARTITION_KEY = os.environ.get("PARTITION_KEY",  "UserId")

# ------------------------------------------
# 5. 파일 경로 
# ------------------------------------------
# config.py가 위치한 디렉토리를 기준으로 tokens.csv 경로를 고정합니다.
_ROOT_DIR = Path(__file__).resolve().parent
# 수정된 부분: tokens.csv를 무조건 load_test_tools 폴더 안에 넣습니다.
TOKENS_FILE = _ROOT_DIR / "load_test_tools" / "tokens.csv"

# ------------------------------------------
# 6. Boto3 재시도 설정 (Cognito Throttling 방어)
# ------------------------------------------
# CognitoAccountConfig.py, tokens.py 등에서 공용으로 사용합니다.
# 사용법: boto3.client('cognito-idp', region_name=REGION, config=BOTO_CONFIG)
#
BOTO_CONFIG = BotoConfig(retries={"max_attempts": 5, "mode": "adaptive"})

# ------------------------------------------
# 부팅 시 현재 설정 요약 출력 (디버깅용)
# ------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("⚙️  현재 적용된 설정값")
    print("=" * 50)
    print(f"  ENV          : {ENV}")
    print(f"  BASE_URL     : {BASE_URL}")
    print(f"  REGION       : {REGION}")
    print(f"  USER_POOL_ID : {USER_POOL_ID[:15]}... (마스킹)")
    print(f"  CLIENT_ID    : {CLIENT_ID[:10]}... (마스킹)")
    print(f"  USER_PREFIX  : {USER_PREFIX}")
    print(f"  USER_COUNT   : {USER_COUNT}")
    print(f"  TOKENS_FILE  : {TOKENS_FILE}")
    print("=" * 50)
