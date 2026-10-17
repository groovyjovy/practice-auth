#!/usr/bin/env python3
"""学習用リポジトリで Claude がコードを書いたり環境構築を代行したりしないようにするガード。

PreToolUse フックとして動き、違反するツール呼び出しを deny する。
"""
import json
import os
import re
import sys

PROJECT = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()

# Claude が書いてよいパス(プロジェクトルートからの相対)
ALLOWED_FILES = {"PROGRESS.md", "CLAUDE.md"}
ALLOWED_DIRS = ("attacks/", "reviews/", ".claude/")

# Claude に実行させない環境構築系コマンド
BLOCKED_COMMANDS = [
    r"\bpnpm\s+(add|install|i|init|create|dlx|import|up|update|remove|rm)\b",
    r"\bnpm\s+(install|i|init|create|ci|uninstall)\b",
    r"\byarn\s+(add|install|init|create)\b",
    r"\bbun\s+(add|install|init|create)\b",
    r"\bnpx\b",
    r"\bcorepack\b",
    r"\bbrew\s+install\b",
    r"\b(mise|nvm|volta|fnm|asdf)\s+(install|use)\b",
    r"\btsc\s+--init\b",
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
    return rel in ALLOWED_FILES or rel.startswith(ALLOWED_DIRS)


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
                deny(
                    "環境構築は本人が行います(CLAUDE.md 参照)。"
                    "コマンドを実行せず、何を調べればよいか・どのドキュメントを見ればよいかを示してください。"
                )


if __name__ == "__main__":
    main()
