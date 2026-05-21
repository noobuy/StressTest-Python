# 🎮 Vamserlike Backend Test & QA Automation Kit (v2)

본 저장소는 **Vamserlike 게임 백엔드 서버(.NET 8)**의 보안 규격 검증(QA), 데이터 무결성 검수(Data Integrity), 그리고 대규모 분산 환경 하에서의 시스템 임계치(SLA) 측정을 자동화하기 위해 구축된 **Enterprise-grade 자동화 테스트 프레임워크**입니다. 


---

## 📂 프로젝트 구조 (Project Structure)

```text
BACKEND_TEST_TOOLS/
├── docs/                        # 테스트 결과 리포트 및 아키텍처 다이어그램
├── src/                         # 핵심 자동화 스크립트 엔진
│   ├── config.py                # ⚙️ 통합 환경 설정 및 AWS SDK (Boto3) 전역 설정
│   ├── CognitoAccountConfig.py  # 👤 AWS Cognito 대용량 계정 프로비저닝 & 정리기
│   ├── tokens.py                # 🔑 시나리오 기반 1,000명 JWT 토큰 추출 및 로컬 캐싱 엔진
│   ├── QA_tool_SignupTest.py    # 🛡️ 가입/로그인 시나리오 및 변조 토큰 예외 처리 검증기
│   ├── QA_tool_TestMe.py        # 📊 2회차 플레이 데이터 누적/갱신 데이터 무결성 검수기
│   └── locustfile.py            # 🚀 Locust 기반 분산형 API 부하 테스트 스크립트
├── .env.example                 # 로컬 환경 변수 설정 템플릿
├── .gitignore                   # 민감 정보(.env) 및 임시 파일 유출 방지 설정
├── README.md                    # 프로젝트 종합 마스터 가이드
└── requirements.txt             # 파이썬 의존성 패키지 목록


💎 v2 핵심 고도화 기술 (Core Architecture)

1. 보안 성능 고도화 및 자격 증명 격리 (.env)
보안 위생(Hygiene) 강화: Cognito Pool ID, Client ID, DB Table 이름 등 민감 정보가 소스 코드에 하드코딩되지 않도록 .env 환경 변수 관리 기법을 도입했습니다.

유연한 환경 스위칭: ENV=local 또는 ENV=cloud 옵션 하나만으로 로컬 개발 서버와 배포된 실서버 타겟을 유연하게 전환하여 테스트할 수 있습니다.

2. AWS SDK 레벨의 회복 탄력성 구축 (Boto3 Adaptive Retry)
API Throttling 자동 방어: Cognito의 엄격한 가입/로그인 속도 제한을 방어하기 위해 인위적인 지연코드(time.sleep)를 걷어내고, AWS SDK가 제공하는 지수 백오프(Exponential Backoff) 기반의 adaptive 리트라이 설정을 전역에 적용하였습니다.

3. CI/CD 파이프라인 자동화 대응 (--ci 및 TestReport)
헤드리스 모드 지원: QA_tool_SignupTest.py 및 QA_tool_TestMe.py는 --ci 옵션을 지원하여 메뉴 선택 없이 전체 테스트를 수행하고 표준 셸 종료 코드(0=통과, 1=실패, 2=서버 미연결)를 반환합니다. 이는 GitHub Actions 등의 CI 파이프라인에 즉시 통합이 가능합니다.

테스트 무결성(Self-Contained Sandbox): 테스트 실행 시 임시 유저를 즉시 생성하여 시나리오를 검증한 후, finally 구문을 통해 계정을 자동 청소(Teardown)함으로써 인프라 오염을 원천 차단합니다.


4. 2회 플레이 누적 검증을 통한 데이터 무결성 검수 (TestMe)

실전형 게임 데이터 검증:

1회차 플레이(2,500점, 15레벨) 데이터를 저장한 뒤 정상 여부를 확인합니다.

2회차 플레이(1,200점, 8레벨) 데이터를 추가 저장한 뒤, 최고 점수와 최고 레벨은 갱신되지 않고 유지되는지, 마지막 플레이 캐릭터는 정상 업데이트되는지, 총 플레이 횟수가 2로 정상 누적되는지를 정밀 교차 검증합니다.

5. 대용량 분산 부하 테스트 지원 (locustfile.py)
Thread-safe Token Queue: 전역 리스트의 pop(0)으로 발생할 수 있는 동시성 이슈를 Queue 객체로 극복했습니다.

분산 노드 간 토큰 슬라이싱: 부하 생성 노드가 여러 대인 분산 환경(Master-Worker)에서 중복 로그인이 발생하지 않도록 WORKER_INDEX 기반의 토큰 분할 알고리즘을 지원합니다.

SLA 임계치 검증: 응답 시간이 특정 임계치(기본 3,000ms)를 초과할 경우 응답 성공 여부와 상관없이 자동 실패 처리하여 서비스 수준 협약(SLA) 충족 여부를 확인합니다.

⚙️ 사전 준비 및 환경 설정 (Setup)

1. 의존성 설치
code
Bash
pip install -r requirements.txt
2. 환경 변수 세팅
루트 폴더의 .env.example 파일을 복사하여 .env 파일을 생성하고 본인의 AWS 설정을 입력합니다.

code
Bash
cp .env.example .env
# .env 파일을 열어 USER_POOL_ID, COGNITO_CLIENT_ID 등을 기입합니다.
3. 백엔드 서버 구동
백엔드 저장소의 코드를 클론한 뒤 dotnet run으로 서버를 로컬에서 구동합니다. (기본 포트: http://localhost:5159)

📖 사용 방법 (Usage)

Step 1. AWS Cognito 가상 유저 생성 및 청소
부하 테스트를 가동하기 전에 1,000명의 인증된 더미 유저 풀을 생성합니다.

code
Bash
python src/CognitoAccountConfig.py
1번 메뉴: 더미 유저 1,000명 신규 생성 및 비밀번호 영구 지정

2번 메뉴: 테스트 종료 후 더미 유저 일괄 청소 (Teardown)

Step 2. 부하 테스트용 JWT 토큰 로컬 캐싱
Cognito 로그인 Rate Limit 회비를 방어하기 위해 토큰을 미리 로컬 파일에 장전합니다.

code
Bash
python src/tokens.py
실행 후 src/tokens.csv가 정상적으로 생성 및 업데이트되었는지 확인합니다. (토큰 만료 시간인 1시간 이내에 부하 테스트를 실시해야 합니다.)

Step 3. 기능 검수 및 데이터 무결성 QA 테스트
유니티 클라이언트 연동 전, 서버의 로직과 보안 수준을 테스트 매니저 메뉴를 통해 개별/통합 검증합니다.

code
Bash
# 회원가입 및 비정상/변조 토큰 차단 등의 보안 검사
python src/QA_tool_SignupTest.py

# 게임 클리어 결과 누적 및 기록 갱신 무결성 검사
python src/QA_tool_TestMe.py
Step 4. 실전 분하 테스트 (Locust)
code
Bash
# 1) 전체 종합 부하 테스트 (실제 게임 시나리오 비율 적용)
locust -f src/locustfile.py

# 2) [SLA 검증] 게임 결과(클리어) 저장 API 집중 공격
locust -f src/locustfile.py --tags clear

# 3) [SLA 검증] 랭킹 조회 API 집중 공격 (정렬 부하 테스트)
locust -f src/locustfile.py --tags ranking
🏆 주요 트러블 슈팅 및 성과 리포트
DynamoDB 스키마 불일치 해결: 백엔드 C# 코드와 DynamoDB 설계 간의 PK/SK 구조 미스매치를 발견하여, 단일 키 구조(UserId)로 인프라를 직접 재구축해 백엔드 부팅 시 발생하는 500 내부 에러 해결 완료.

중복 가입 차단 예외 처리 누락 발견: 네거티브 테스트(QA_tool_SignupTest.py)를 가동하여 이미 존재하는 이메일 가입 요청 시 409/400이 아닌 200을 반환하는 중복 가입 버그를 탐지하여 백엔드 파트에 버그 리포팅 완료.

시스템 한계 측정: t3.micro 단일 인스턴스 기준, 동시 접속자 500명 / RPS 125 구간에서 CPU 100% 도달 및 응답 지연 발생을 확인하여 향후 Auto Scaling 그룹 도입 타당성 증명.