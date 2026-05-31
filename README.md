# 🎮 Vamserlike Backend Test & QA Automation Kit (v2)
---

## 📂 프로젝트 구조 (Project Structure)

```text
BACKEND_TEST_TOOLS/
├── docs/                        # 테스트 결과 리포트 및 아키텍처 다이어그램
│
├── 🛠️ qa_tools/                 <-- [1. 기능 검증/QA 툴] (버그 잡는 용도)
│   └── QA_Tool_Final.py         # 백엔드 로직이 정상 작동하는지 검증 (통합 QA)
│
├── 🚀 load_test_tools/          <-- [2. 부하 테스트 툴] (서버 터뜨려보는 용도)
│   ├── CognitoAccountConfig.py  # 더미 유저 대량 생성/삭제 (1000명 등)
│   ├── tokens.py                # 생성된 대량 유저의 토큰을 뽑아 CSV로 저장
│   ├── locustfile.py            # 뽑아낸 토큰으로 서버에 실제 트래픽 공격 (Locust)
│   └── tokens.csv               # (tokens.py 실행 시 자동 생성됨)
│
└── ⚙️ config.py                 <-- [공통 설정] (양쪽에서 모두 사용)
├── .env.example                 # 로컬 환경 변수 설정 템플릿
├── .gitignore                   # 민감 정보(.env) 및 임시 파일 유출 방지 설정
├── README.md                    # 프로젝트 종합 마스터 가이드
└── requirements.txt             # 파이썬 의존성 패키지 목록


🛠️ 1. QA 툴 (qa_tools/)
백엔드 API 기능이 정상적으로 작동하는지, 데이터 저장이 꼬이지 않는지 정확성을 테스트할 때 씁니다.

QA_Tool_Final.py

실행하면 임시 테스트 계정을 딱 1개 만들어서 회원가입 → 로그인 → 게임 결과 저장 → 누적 검증 → 랭킹 조회를 순서대로 진행합니다.

테스트가 끝나면 만들었던 계정을 깔끔하게 스스로 지웁니다.

실행 방법: python QA_Tool_Final.py


--------

🚀 2. 부하 테스트 툴 (load_test_tools/)

수백~수천 명의 유저가 동시에 접속했을 때 서버가 뻗지 않고 버티는지 성능을 테스트할 때 씁니다. 다음 순서대로 실행해야 합니다.

1단계: CognitoAccountConfig.py (유저 대량 생성)

수백 명의 더미 유저(가짜 계정)를 AWS Cognito에 한 번에 만듭니다. (이메일 인증 스킵 가능)

실행 방법: python CognitoAccountConfig.py

2단계: tokens.py (로그인 토큰 추출)

1단계에서 만든 수백 명의 유저로 로그인하여 JWT 토큰을 쫙 뽑아내어 tokens.csv 파일로 저장합니다. (Locust가 공격할 때 쓸 총알을 만드는 과정입니다.)

실행 방법: python tokens.py

3단계: locustfile.py (실제 부하 공격)

tokens.csv에 담긴 토큰들을 이용해 수백 명의 가상 유저가 동시에 게임을 플레이하는 것처럼 서버에 트래픽을 쏟아붓습니다.

실행 방법: 터미널에 locust -f locustfile.py 입력 후, 브라우저에서 http://localhost:8089로 접속하여 공격 시작.


-----

💡 요약
버그나 로직 검증이 필요하다? 👉 QA_Tool_Final.py 하나만 실행

동시 접속자 부하 테스트가 필요하다? 👉 AccountConfig로 유저 만들고 ➡️ tokens로 토큰 뽑고 ➡️ locustfile로 쏘기