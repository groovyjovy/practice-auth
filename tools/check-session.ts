// セッションまわり(/me)の動作確認をまとめて実行するスクリプト。
//
// 使い方(リポジトリのルートで、サーバーを起動した状態で):
//   node tools/check-session.ts          すぐ終わる確認だけ
//   node tools/check-session.ts --slow   アイドルタイムアウトの確認もする(2〜3 分かかる)
//
// tools/.cookies.json(req.ts の Cookie)は使わず、確認ごとに空の Cookie から始める。
// ユーザー名は毎回ランダムに作るので、サーバーを再起動しなくても何度でも実行できる。
// 「サーバーを再起動したら 401」は自動化できないので、req.ts で手で確認する。
// 接続先は環境変数 BASE_URL、アイドルタイムアウトの秒数は IDLE_S で変更できる。

import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

const BASE_URL = process.env.BASE_URL ?? "http://localhost:3000";
const IDLE_S = Number(process.env.IDLE_S ?? 60);
const COOKIE_NAME = "__Host-session";
const slow = process.argv.includes("--slow");

type Res = { status: number; text: string };

// Cookie を覚えるクライアント。属性(Secure など)は req.ts と同じく無視する。
class Client {
  #cookies = new Map<string, string>();

  setCookie(name: string, value: string): void {
    this.#cookies.set(name, value);
  }

  async request(method: string, path: string, body?: unknown): Promise<Res> {
    const headers: Record<string, string> = {};
    if (this.#cookies.size > 0) {
      headers["Cookie"] = [...this.#cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    }
    if (body !== undefined) headers["Content-Type"] = "application/json";

    const res = await fetch(new URL(path, BASE_URL), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    // Set-Cookie を反映する。値が空か Max-Age<=0 なら削除扱い。
    for (const header of res.headers.getSetCookie()) {
      const [pair = "", ...attrs] = header.split(";").map((s) => s.trim());
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      const maxAge = attrs.find((a) => a.toLowerCase().startsWith("max-age="));
      if (value === "" || (maxAge && Number(maxAge.split("=")[1]) <= 0)) this.#cookies.delete(name);
      else this.#cookies.set(name, value);
    }

    const text = await res.text();
    console.log(`    ${method} ${path} -> ${res.status} ${text}`);
    return { status: res.status, text };
  }
}

const failures: string[] = [];
// 401 の本文を集め、どの理由でも同じ本文になっているかを最後に確かめる
const unauthorizedBodies = new Set<string>();

function expect(label: string, actual: unknown, expected: unknown): void {
  const ok = actual === expected;
  console.log(`  ${ok ? "✓" : "✗"} ${label}${ok ? "" : `(期待: ${String(expected)} / 実際: ${String(actual)})`}`);
  if (!ok) failures.push(label);
}

function expectUnauthorized(label: string, res: Res): void {
  expect(label, res.status, 401);
  unauthorizedBodies.add(res.text);
}

// 新しいユーザーを登録してログインしたクライアントを返す
async function loggedIn(): Promise<{ client: Client; username: string }> {
  const username = `user-${randomBytes(4).toString("hex")}`;
  const password = "password";
  const client = new Client();
  await client.request("POST", "/register", { username, password });
  expect("ログインできる", (await client.request("POST", "/login", { username, password })).status, 200);
  return { client, username };
}

type Check = { name: string; slow?: boolean; run: () => Promise<void> };

const checks: Check[] = [
  {
    name: "ログインしてから /me",
    run: async () => {
      const { client, username } = await loggedIn();
      const res = await client.request("GET", "/me");
      expect("200 が返る", res.status, 200);
      expect("ユーザー名が返る", res.text, username);
    },
  },
  {
    name: "Cookie なしで /me",
    run: async () => {
      expectUnauthorized("401 が返る", await new Client().request("GET", "/me"));
    },
  },
  {
    name: "でたらめなセッション ID で /me",
    run: async () => {
      const client = new Client();
      client.setCookie(COOKIE_NAME, randomBytes(32).toString("hex"));
      expectUnauthorized("401 が返る", await client.request("GET", "/me"));
    },
  },
  {
    name: `${IDLE_S} 秒以上放置してから /me(アイドルタイムアウト)`,
    slow: true,
    run: async () => {
      const { client } = await loggedIn();
      expect("直後は 200", (await client.request("GET", "/me")).status, 200);
      console.log(`    … ${IDLE_S + 5} 秒待つ`);
      await sleep((IDLE_S + 5) * 1000);
      expectUnauthorized("放置後は 401", await client.request("GET", "/me"));
      expectUnauthorized("もう一度送っても 401", await client.request("GET", "/me"));
    },
  },
  {
    name: `${IDLE_S / 2} 秒ごとに /me を 3 回(アクセスで期限が延びる)`,
    slow: true,
    run: async () => {
      const { client } = await loggedIn();
      for (let i = 1; i <= 3; i++) {
        console.log(`    … ${IDLE_S / 2} 秒待つ`);
        await sleep((IDLE_S / 2) * 1000);
        expect(`${i} 回目も 200`, (await client.request("GET", "/me")).status, 200);
      }
    },
  },
];

try {
  for (const check of checks) {
    if (check.slow && !slow) {
      console.log(`- ${check.name}: スキップ(--slow で実行)`);
      continue;
    }
    console.log(`- ${check.name}`);
    await check.run();
  }
} catch (err) {
  const code = (err as { cause?: { code?: string } }).cause?.code;
  if (code === "ECONNREFUSED") {
    console.error(`\n${BASE_URL} に接続できません。サーバーを起動してから実行してください。`);
    process.exit(1);
  }
  throw err;
}

console.log("- 401 の本文");
expect("どの理由でも同じ本文", unauthorizedBodies.size <= 1, true);

console.log("\n手で確認すること: サーバーを再起動してから `node tools/req.ts me` → 401");
console.log(failures.length === 0 ? "\nすべて期待どおり" : `\n期待と違う結果: ${failures.length} 件`);
process.exitCode = failures.length === 0 ? 0 : 1;
