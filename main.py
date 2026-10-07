import os
import requests
from dotenv import load_dotenv
from gitleaks_scanner import scan_text

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_API")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
URL = "https://api.github.com/events"

headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "User-Agent": "My-Gitleaks-Python-Scanner",
}


def send_slack_alert(webhook_url, findings):
    """
    Gitleaks 탐지 결과를 Slack Webhook으로 알립니다.
    """
    if not webhook_url:
        print("⚠️ SLACK_WEBHOOK_URL이 설정되지 않아 슬랙 알림을 건너뜁니다.")
        return

    # Slack 메시지 블록 구성
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 [Gitleaks Alert] API 응답 Secret 누출 감지!",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*총 {len(findings)}건*의 의심스러운 Secret이 감지되었습니다. 즉시 확인 및 조치가 필요합니다.",
            },
        },
        {"type": "divider"},
    ]

    # 탐지된 항목 중 최대 5개까지 상단 표기 (슬랙 메시지 길이고려)
    for idx, item in enumerate(findings[:5], 1):
        rule_id = item.get("rule_id", "N/A")
        desc = item.get("description", "No description")
        match_secret = item.get("match", "")
        # Secret 일부 마스킹 처리 (앞 4자리만 표시)
        masked_secret = (
            f"`{match_secret[:4]}***`" if len(match_secret) >= 4 else "`***`"
        )

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*{idx}. 규칙 ID:* `{rule_id}`\n"
                    f"*설명:* {desc}\n"
                    f"*감지된 토큰:* {masked_secret}"
                ),
            },
        })

    if len(findings) > 5:
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"외 {len(findings) - 5}건의 추가 탐지 내역이 존재합니다.",
            }],
        })

    payload = {"blocks": blocks}

    try:
        res = requests.post(webhook_url, json=payload, timeout=5)
        if res.status_code == 200:
            print("📢 Slack 알림 전송 완료!")
        else:
            print(
                f"⚠️ Slack 알림 전송 실패 (Status Code: {res.status_code}): {res.text}"
            )
    except Exception as e:
        print(f"⚠️ Slack 알림 전송 중 에러 발생: {e}")


def main():
    try:
        response = requests.get(URL, headers=headers)
        response.raise_for_status()

        # Gitleaks 스캔 호출
        results = scan_text(response.text)

        # Gitleaks CLI 실행 불가 예외 처리
        if results and results[0].get("rule_id") == "ERROR":
            print("❌ Gitleaks 실행 불가 상태입니다.")
            return

        if results:
            print(
                f"🚨 [경고] API 응답 데이터에서 {len(results)}건의 Secret 누출이 감지되었습니다!"
            )
            for item in results:
                print(
                    f" - [{item['rule_id']}] {item['description']}: {item['match'][:10]}***"
                )

            # 🔔 Slack 알림 발송
            send_slack_alert(SLACK_WEBHOOK_URL, results)

        else:
            print("✅ API 응답 데이터가 안전합니다 (Gitleaks CLI 검사 통과).")
            events = response.json()
            print(f"수신된 이벤트 개수: {len(events)}")

    except requests.exceptions.RequestException as e:
        print(f"API 요청 실패: {e}")


if __name__ == "__main__":
    main()