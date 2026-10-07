import json
import os
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, ".gitleaks.toml")


def scan_text(text, config_path=DEFAULT_CONFIG_PATH):
    """
    gitleaks CLI를 subprocess로 실행하여 전달받은 텍스트(stdin)를 스캔합니다.
    """
    # 1. gitleaks CLI 명령어 구성 (Windows 호환성을 위해 /dev/stdout 제거)
    cmd = [
        "gitleaks",
        "detect",
        "--no-git",
        "--pipe",
        f"--config={config_path}",
        "--report-format=json",
    ]

    try:
        # 2. 프로세스 실행 및 stdin으로 텍스트 전달
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )

        stdout, stderr = process.communicate(input=text)

        findings = []

        # 3. Gitleaks 반환 코드 처리 (1: Secret 감지, 0: 정상)
        if process.returncode == 1 and stdout.strip():
            try:
                raw_findings = json.loads(stdout)
                for item in raw_findings:
                    findings.append({
                        "rule_id": item.get("RuleID"),
                        "description": item.get("Description"),
                        "match": item.get("Secret") or item.get("Match"),
                        "file": item.get("File"),
                    })
            except json.JSONDecodeError:
                findings.append({"rule_id": "raw-output", "description": stdout})

        elif process.returncode != 0:
            print(f"⚠️ Gitleaks 실행 중 에러 발생 (Exit Code {process.returncode}): {stderr}")

        return findings

    except FileNotFoundError:
        print("❌ [에러] 시스템에 'gitleaks'가 인식되지 않습니다. 터미널/VS Code를 재시작해 주세요.")
        return [{"rule_id": "ERROR", "description": "Gitleaks CLI Not Found", "match": "N/A"}]
    except Exception as e:
        print(f"⚠️ 실행 실패: {e}")
        return []