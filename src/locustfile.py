# ==========================================
# 🚀 Vamserlike 부하 테스트 엔진 (v2)
# ==========================================
# 개선 사항:
#   1. 분산 모드(Worker) 안전한 토큰 분배 (Queue + 중복 방지)
#   2. 토큰 만료(1h) 사전 경고 시스템
#   3. 토큰 소진 시 유저를 즉시 중단 (통계 왜곡 방지)
#   4. config.py의 TOKENS_FILE 절대경로 사용 (실행 위치 무관)
#   5. 응답 시간 임계값 초과 시 자동 실패 마킹
# ==========================================

import csv
import os
import sys
import time
import logging
from queue import Queue, Empty

from locust import HttpUser, task, between, tag, events

# config.py에서 경로·설정 가져오기
# (locustfile.py와 config.py가 같은 폴더에 있다고 가정)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import TOKENS_FILE, BASE_URL

logger = logging.getLogger(__name__)

# ==========================================
# 1. 토큰 로딩 (Thread-safe Queue)
# ==========================================
# Queue는 greenlet/thread 환경 모두에서 안전합니다.
# 분산 모드에서는 각 Worker가 독립된 Queue를 갖게 되므로
# 토큰 파일을 Worker 수에 맞게 분할하거나,
# Worker 인덱스 기반으로 슬라이싱합니다.

TOKEN_QUEUE: Queue = Queue()
TOKEN_LOAD_TIME: float = 0.0  # 토큰 파일의 수정 시각 (만료 경고용)
TOKEN_EXPIRY_SECONDS = 3600   # Cognito IdToken 기본 만료: 1시간


def _load_tokens():
    """tokens.csv를 읽어 Queue에 적재합니다."""
    global TOKEN_LOAD_TIME

    if not TOKENS_FILE.exists():
        logger.error(
            f"❌ 토큰 파일을 찾을 수 없습니다: {TOKENS_FILE}\n"
            f"   먼저 'python tokens.py'를 실행하여 토큰을 생성하세요."
        )
        return 0

    # 파일 수정 시각으로 만료 여부 추정
    TOKEN_LOAD_TIME = os.path.getmtime(TOKENS_FILE)

    count = 0
    with open(TOKENS_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            TOKEN_QUEUE.put(row["token"])
            count += 1

    # ---- 분산 모드 토큰 슬라이싱 ----
    # Locust 분산 실행 시 환경 변수로 Worker 분할을 지원합니다.
    # 사용법: WORKER_INDEX=0 WORKER_TOTAL=4 locust -f locustfile.py --worker
    worker_index = int(os.environ.get("WORKER_INDEX", "0"))
    worker_total = int(os.environ.get("WORKER_TOTAL", "1"))

    if worker_total > 1:
        # Queue를 리스트로 꺼내서 이 Worker 몫만 다시 넣습니다.
        all_tokens = []
        while not TOKEN_QUEUE.empty():
            all_tokens.append(TOKEN_QUEUE.get())

        my_tokens = all_tokens[worker_index::worker_total]
        for t in my_tokens:
            TOKEN_QUEUE.put(t)

        logger.info(
            f"🔀 Worker {worker_index}/{worker_total}: "
            f"{len(my_tokens)}개 토큰 할당 (전체 {len(all_tokens)}개)"
        )
        return len(my_tokens)

    logger.info(f"✅ {count}개 토큰 로딩 완료 ({TOKENS_FILE})")
    return count


def _check_token_expiry():
    """토큰 발급 후 경과 시간을 확인하고 만료 임박 시 경고합니다."""
    if TOKEN_LOAD_TIME == 0:
        return

    elapsed = time.time() - TOKEN_LOAD_TIME
    remaining = TOKEN_EXPIRY_SECONDS - elapsed

    if remaining <= 0:
        logger.warning(
            "⚠️  토큰이 이미 만료되었을 수 있습니다! "
            "'python tokens.py'로 재발급 후 다시 실행하세요."
        )
    elif remaining < 600:  # 10분 미만
        logger.warning(
            f"⏰ 토큰 만료까지 약 {int(remaining // 60)}분 남았습니다. "
            "장시간 테스트 시 토큰을 재발급하세요."
        )


# ==========================================
# 2. Locust 이벤트 훅: 테스트 시작 전 토큰 로딩
# ==========================================
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Master/Standalone에서 테스트 시작 시 1회 실행됩니다."""
    loaded = _load_tokens()
    if loaded == 0:
        logger.error("토큰이 0개입니다. 테스트를 중단합니다.")
        environment.runner.quit()
        return
    _check_token_expiry()


# ==========================================
# 3. 응답 시간 임계값 (ms)
# ==========================================
# 이 값을 초과하면 Locust에서 '실패'로 마킹합니다.
RESPONSE_TIME_THRESHOLD_MS = int(os.environ.get("THRESHOLD_MS", "3000"))


# ==========================================
# 4. 가상 유저 정의
# ==========================================
class VamserlikePlayer(HttpUser):
    # 실제 유저 행동 패턴: 1~3초 간격
    wait_time = between(1.0, 3.0)

    # config.py의 BASE_URL을 Locust host 기본값으로 사용
    host = BASE_URL

    def on_start(self):
        """가상 유저 생성 시 토큰 1개를 할당받고 /init을 호출합니다."""
        try:
            self.token = TOKEN_QUEUE.get_nowait()
        except Empty:
            # 토큰이 모두 소진되면 이 유저는 즉시 종료합니다.
            # 통계에 무의미한 0건 유저가 쌓이는 것을 방지합니다.
            logger.warning(
                "⚠️  할당 가능한 토큰이 없습니다. "
                "이 가상 유저는 테스트에 참여하지 않습니다."
            )
            self.environment.runner.quit()
            return

        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

        # 최초 1회: 플레이어 데이터 초기화
        with self.client.post(
            "/api/players/me/init",
            headers=self.headers,
            catch_response=True,
            name="/api/players/me/init [startup]",
        ) as resp:
            if resp.status_code in (200, 201, 204):
                resp.success()
            elif resp.status_code == 409:
                # 이미 init된 유저 → 정상 케이스
                resp.success()
            else:
                resp.failure(f"Init 실패: {resp.status_code} - {resp.text[:200]}")

    # ---------------------------------------------------------
    # 공통 응답 검증 헬퍼
    # ---------------------------------------------------------
    def _validate(self, response, success_codes=(200,)):
        """상태 코드 + 응답 시간 임계값을 함께 검증합니다."""
        if response.status_code not in success_codes:
            response.failure(
                f"HTTP {response.status_code} - {response.text[:200]}"
            )
        elif response.elapsed.total_seconds() * 1000 > RESPONSE_TIME_THRESHOLD_MS:
            response.failure(
                f"느린 응답: {response.elapsed.total_seconds():.2f}s "
                f"(임계값: {RESPONSE_TIME_THRESHOLD_MS}ms)"
            )
        else:
            response.success()

    # ---------------------------------------------------------
    # 🎯 [기능 1] 내 정보 조회 (읽기 부하)
    # ---------------------------------------------------------
    @tag("info")
    @task(3)
    def get_my_info(self):
        if not hasattr(self, "token"):
            return
        with self.client.get(
            "/api/players/me",
            headers=self.headers,
            catch_response=True,
        ) as resp:
            self._validate(resp)

    # ---------------------------------------------------------
    # ⚔️ [기능 2] 게임 결과(클리어) 저장 (쓰기 부하)
    # ---------------------------------------------------------
    @tag("clear")
    @task(2)
    def save_progress(self):
        if not hasattr(self, "token"):
            return
        payload = {
            "score": 1500,
            "level": 10,
            "playedCharacterId": "rice_farmer",
        }
        with self.client.put(
            "/api/players/me/progress",
            json=payload,
            headers=self.headers,
            catch_response=True,
        ) as resp:
            self._validate(resp, success_codes=(200, 204))

    # ---------------------------------------------------------
    # 🏆 [기능 3] 랭킹 조회 (정렬/DB 과부하)
    # ---------------------------------------------------------
    @tag("ranking")
    @task(1)
    def check_ranking(self):
        if not hasattr(self, "token"):
            return
        with self.client.get(
            "/api/players/ranking?take=20",
            headers=self.headers,
            catch_response=True,
        ) as resp:
            self._validate(resp)
