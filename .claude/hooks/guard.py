#!/usr/bin/env python3
"""学習用リポジトリで Claude が学習対象のコードを書かないようにするガード。

PreToolUse フックとして動き、違反するツール呼び出しを deny する。
環境構築は本筋ではないので、設定ファイルの編集やパッケージ管理コマンドは許可している。
"""
import json
import os
import re
import sys

PROJECT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()

# Claude が書いてよいパス(プロジェクトルートからの相対)
ALLOWED_FILES = {"PROGRESS.md", "CLAUDE.md"}
ALLOWED_DIRS = ("attacks/", "reviews/", "tools/", ".claude/")
# 設定ファイルはどのディレクトリにあっても書いてよい
ALLOWED_BASENAMES = re.compile(
    r"^(package\.json|tsconfig(\..+)?\.json|pnpm-workspace\.yaml|\.gitignore|\.gitkeep|mise\.toml)$"
)

# Claude に実行させないコマンド
BLOCKED_COMMANDS = [
    r"/etc/hosts",
]


def deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))
    sys.exit(0)


def is_allowed_path(path: str) -> bool:
    abs_path = os.path.realpath(os.path.join(PROJECT, path))
    root = os.path.realpath(PROJECT)
    if not abs_path.startswith(root + os.sep):
        # プロジェクト外(scratchpad やメモリなど)は対象外
        return True
    rel = os.path.relpath(abs_path, root)
    return (
        rel in ALLOWED_FILES
        or rel.startswith(ALLOWED_DIRS)
        or bool(ALLOWED_BASENAMES.match(os.path.basename(rel)))
    )


def main() -> None:
    data = json.load(sys.stdin)
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if path and not is_allowed_path(path):
            deny(
                f"{path} は本人が書くファイルです(CLAUDE.md 参照)。"
                "コードを書かず、ヒント・レビュー・仕様の案内で支援してください。"
            )

    if tool == "Bash":
        command = tool_input.get("command", "")
        for pattern in BLOCKED_COMMANDS:
            if re.search(pattern, command):
                deny("hosts ファイルは本人が編集します(CLAUDE.md 参照)。追加する行を示してください。")


if __name__ == "__main__":
    main()
