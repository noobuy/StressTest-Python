# 🎮 Vamserlike Backend Test & QA Automation Kit (v2)
---

## 📂 프로젝트 구조 (Project Structure)


본 저장소는 Vamserlike 백엔드 서버의 API 기능 정상 동작 여부를 검증하고, 대규모 트래픽 발생 시의 서버 성능을 측정하기 위해 구축된 통합 테스트 환경입니다. 목적에 따라 기능 검증용 QA 툴과 성능 측정용 부하 테스트 툴로 분리되어 있습니다.

1. 디렉토리 구조
프로젝트의 전체 구조와 각 파일의 역할은 다음과 같습니다.

Vamserlike_Test/
├── .env.example                  # 환경 변수 설정 템플릿
├── config.py                     # 프로젝트 전역 통합 설정 파일
├── qa_tools/
│   └── QA_Tool_Final.py          # 백엔드 API 기능 및 데이터 무결성 검증 스크립트
└── load_test_tools/
    ├── CognitoAccountConfig.py   # 부하 테스트용 AWS Cognito 더미 계정 생성/삭제
    ├── tokens.py                 # 더미 계정의 JWT 토큰 추출 및 CSV 파일 저장
    ├── locustfile.py             # Locust 기반의 부하 테스트 실행 시나리오
    └── tokens.csv                # tokens.py 실행 시 자동 생성되는 토큰 저장 파일

2. 초기 설정 (Setup)
테스트 툴을 정상적으로 실행하기 위해 다음의 사전 설정이 필요합니다.

2.1. 패키지 설치
Python 환경에서 아래의 라이브러리들이 설치되어 있어야 합니다. 터미널에서 다음 명령어를 실행하십시오.

code
Bash
pip install requests boto3 locust python-dotenv

2.2. 환경 변수 설정
보안 및 환경 분리를 위해 환경 변수 파일을 구성해야 합니다.
프로젝트 루트 디렉토리에 있는 .env.example 파일을 복사하여 .env 파일을 생성합니다.
생성된 .env 파일 내부에 AWS Cognito 정보, 테스트 비밀번호, 대상 서버 URL 등의 실제 값을 기입합니다.
(주의: .env 파일은 절대 Git 등 버전 관리 시스템에 커밋되지 않도록 해야 합니다.)


3. 기능 검증 도구 (QA Tools) 사용 방법
QA_Tool_Final.py는 백엔드 비즈니스 로직의 정확성과 데이터 무결성을 검증하기 위한 스크립트입니다. 실행 시 일회성 테스트 계정을 생성하여 검증을 수행하고, 완료 후 해당 계정을 자동으로 삭제합니다.

code
Bash
python qa_tools/QA_Tool_Final.py

(CI/CD 파이프라인에서 자동화된 테스트를 수행하려면 python qa_tools/QA_Tool_Final.py --ci 명령어를 사용하십시오. 성공 시 종료 코드 0, 실패 시 1을 반환합니다.)

지원 시나리오 (메뉴 구성)

전체 테스트 실행: 하위의 1~4번 시나리오를 순차적으로 모두 실행합니다.

인증 정상 시나리오: 실제 회원가입, Cognito 인증, 로그인, 초기화(init), 내 정보 조회(me)의 정상 동작을 확인합니다.

데이터 무결성 시나리오: 강제 로그인(bypass-login)을 통해 테스트 계정을 준비한 뒤, 다수의 게임 결과를 저장하여 재화 누적, 최고 기록 갱신 여부, 캐릭터 선택 상태 보존 등 비즈니스 로직이 올바르게 적용되는지 검증합니다.

캐릭터 해금 시나리오: 특정 캐릭터의 해금을 요청하고 실제 골드 차감액 검증, 최초 해금 시 자동 장착 여부, 중복 해금 요청 시 이중 차감 방지(멱등성) 로직을 검증합니다.

테스트 데이터 전체 초기화: 지정된 확인 문구(RESET_CONFIRM_TEXT) 입력 시, DynamoDB와 Cognito의 테스트 데이터를 모두 삭제하는 개발 환경 전용 초기화 기능입니다.

4. 부하 테스트 도구 (Load Test Tools) 사용 방법
서버의 동시 접속 처리 능력과 성능 한계를 측정하기 위한 도구입니다. 다수의 가상 유저를 생성하여 테스트를 진행하므로 반드시 아래의 순서대로 실행해야 합니다.

@ 단계 1: 부하 테스트용 더미 계정 생성
AWS Cognito에 설정된 수(USER_COUNT)만큼의 더미 유저를 일괄 생성합니다.
code
Bash
python load_test_tools/CognitoAccountConfig.py
메뉴 1번을 선택하여 계정을 생성합니다.

이메일 인증 스킵 여부를 묻는 프롬프트가 나타나면, 기본값(스킵)을 사용하여 신속하게 생성할 수 있습니다.

@ 단계 2: JWT 토큰 추출 및 저장
생성된 더미 유저들로 로그인을 시도하여 JWT(IdToken)를 추출하고, 이를 부하 테스트에서 사용할 수 있도록 tokens.csv 파일로 저장합니다.

code
Bash
python load_test_tools/tokens.py
해당 토큰은 발급 시점으로부터 1시간 동안 유효합니다. 1시간 이상 부하 테스트를 진행해야 할 경우, 이 명령어를 다시 실행하여 토큰을 재발급해야 합니다.

@단계 3: 부하 테스트 실행 (Locust)
추출된 토큰 파일을 바탕으로 가상 유저 트래픽을 서버에 전송합니다.

code
Bash
locust -f load_test_tools/locustfile.py

명령어 실행 후 웹 브라우저에서 http://localhost:8089로 접속합니다.

Number of users (총 가상 유저 수)와 Spawn rate (초당 생성 유저 수)를 입력하여 공격을 시작합니다.

부하 테스트는 정보 조회(info), 게임 결과 저장(clear), 캐릭터 해금(unlock), 랭킹 조회(ranking) 기능에 대해 무작위 비중으로 API를 호출하도록 설계되어 있습니다.

(테스트 종료 후 계정을 정리하려면 다시 CognitoAccountConfig.py를 실행하여 2번 삭제 메뉴를 이용하십시오.)


5. 주요 설정 변수 안내 (.env)
원활한 테스트 진행을 위해 .env 파일 내 다음 변수들의 의미를 숙지하시기 바랍니다.

ENV: 실행 환경을 지정합니다. (local 또는 cloud)
USER_COUNT: 부하 테스트 시 생성 및 활용할 최대 가상 유저 수를 지정합니다. (기본값: 1000)

THRESHOLD_MS: 부하 테스트 시 허용되는 최대 응답 시간(밀리초)입니다. 이 시간을 초과하는 응답은 실패(Failure)로 간주됩니다. (기본값: 3000)

UNLOCK_TARGET_CHARACTER_ID: QA 캐릭터 해금 테스트 및 부하 테스트에서 구매 시도를 진행할 캐릭터의 고유 ID입니다.

RESET_CONFIRM_TEXT: 데이터베이스 초기화(reset-test-data) 실행 시 실수 방지를 위해 요구되는 텍스트 비밀번호입니다. 서버 측의 설정값과 일치해야 합니다.