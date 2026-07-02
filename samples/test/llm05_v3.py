import subprocess
import anthropic

client = anthropic.Anthropic(api_key="sk-test-placeholder")


def run_suggested_command(user_request: str) -> str:
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=256,
        messages=[
            {"role": "user", "content": f"이 작업을 수행하는 bash 명령어를 알려줘: {user_request}"}
        ],
    )
    cmd = message.content[0].text
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout
