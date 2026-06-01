
# Vamserlike 통합 테스트 환경 가이드 (QA & Load Test)

본 저장소는 Vamserlike 백엔드 서버의 API 기능 검증 및 서버 성능 측정을 위해 구축된 통합 테스트 환경입니다. 툴의 목적에 따라 **기능 검증(QA)**과 **부하 테스트(Load Test)**로 분리되어 관리됩니다.

---

## 1. 프로젝트 구조 (Project Structure)

전체 디렉토리 구조와 각 파일의 역할은 다음과 같습니다.

```text
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
```

---

## 2. 초기 설정 (Setup)

테스트 툴을 실행하기 위해 반드시 다음의 사전 설정이 완료되어야 합니다.

### 2.1. 패키지 설치
Python 환경에서 아래의 라이브러리를 설치하십시오.
```bash
pip install requests boto3 locust python-dotenv
```

### 2.2. 환경 변수 설정
보안 및 환경별 설정을 위해 환경 변수 파일을 구성해야 합니다.
1. 루트 디렉토리에 있는 `.env.example` 파일을 복사하여 `.env` 파일을 생성합니다.
2. 생성된 `.env` 파일 내부에 AWS 정보, 서버 URL 등을 실제 값으로 기입합니다.
   * **주의:** `.env` 파일은 보안상 절대 버전 관리 시스템(Git)에 커밋하지 마십시오.

---

## 3. 기능 검증 도구 (QA Tools) 사용 방법

`QA_Tool_Final.py`는 백엔드 비즈니스 로직의 정확성과 데이터 무결성을 검증합니다. 실행 시 일회성 테스트 계정을 생성하며, 검증 완료 후 해당 계정을 자동 삭제합니다.

### 3.1. 실행 명령어
```bash
python qa_tools/QA_Tool_Final.py
```
*   **CI/CD 지원:** 자동화된 환경에서 수행하려면 `--ci` 플래그를 사용하십시오.
    ```bash
    python qa_tools/QA_Tool_Final.py --ci
    ```

### 3.2. 지원 시나리오 (메뉴 구성)
*   **전체 테스트 실행:** 하단의 1~4번 시나리오를 순차적으로 모두 수행합니다.
*   **인증 정상 시나리오:** 실제 회원가입, Cognito 인증, 로그인, 프로필 초기화, 정보 조회의 정상 동작을 확인합니다.
*   **데이터 무결성 시나리오:** 강제 로그인(`bypass-login`)을 통해 계정을 준비한 뒤, 재화 누적, 최고 기록 갱신, 캐릭터 선택 상태 보존 로직을 정밀 검증합니다.
*   **캐릭터 해금 시나리오:** 캐릭터 해금 시 골드 차감액 실측, 최초 해금 시 자동 장착 여부, 중복 해금 요청 시 이중 차감 방지(멱등성)를 검증합니다.
*   **테스트 데이터 전체 초기화:** 확인 문구(`RESET_CONFIRM_TEXT`) 입력 시 DB 및 Cognito의 모든 테스트 데이터를 일괄 삭제합니다.

---

## 4. 부하 테스트 도구 (Load Test Tools) 사용 방법

대규모 동시 접속 상황에서의 성능 한계를 측정합니다. 반드시 아래 **Step 1 ~ 3**의 순서대로 진행하십시오.

### Step 1: 더미 계정 생성
AWS Cognito에 설정된 수(`USER_COUNT`)만큼 계정을 생성합니다.
```bash
python load_test_tools/CognitoAccountConfig.py
```
*   메뉴 1번을 선택하여 계정을 생성합니다. 이메일 인증 프롬프트 시 기본값(스킵)을 권장합니다.

### Step 2: JWT 토큰 추출 및 저장
생성된 더미 유저로 로그인하여 토큰을 `tokens.csv`로 저장합니다.
```bash
python load_test_tools/tokens.py
```
*   토큰은 발급 후 **1시간 동안 유효**합니다. 유효 시간 초과 시 재발급이 필요합니다.

### Step 3: 부하 테스트 실행 (Locust)
추출된 토큰을 기반으로 서버에 가상 트래픽을 전송합니다.
```bash
locust -f load_test_tools/locustfile.py
```
1. 실행 후 브라우저에서 `http://localhost:8089`에 접속합니다.
2. 총 유저 수와 초당 생성 유저 수를 입력하여 테스트를 시작합니다.
3. 테스트 종료 후 계정 정리는 `CognitoAccountConfig.py`의 2번 메뉴를 이용하십시오.

---

## 5. 주요 환경 변수 안내 (.env)

| 변수명 | 설명 | 비고 |
| :--- | :--- | :--- |
| `ENV` | 실행 환경 지정 | `local` 또는 `cloud` |
| `USER_COUNT` | 생성 및 활용할 가상 유저 수 | 기본값: 1000 |
| `THRESHOLD_MS` | 허용 응답 시간 임계값 | 초과 시 실패 처리 (기본 3000ms) |
| `UNLOCK_TARGET_CHARACTER_ID` | 해금 테스트 대상 캐릭터 ID | appsettings.json과 일치 필요 |
| `RESET_CONFIRM_TEXT` | DB 초기화 시 확인 문구 | `DELETE_TEST_DATA` 등 하드코딩 값 |