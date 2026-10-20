// 動作確認用のリクエスト送信ツール。curl の代わり。
//
// 使い方(リポジトリのルートで):
//   node tools/req.ts register <username> <password>
//   node tools/req.ts login <username> <password>
//   node tools/req.ts me
//   node tools/req.ts logout
//   node tools/req.ts raw <METHOD> <path> [JSON ボディ]
//       例: node tools/req.ts raw POST /register '{"username":["alice"],"password":"x"}'
//   node tools/req.ts cookies         保存中の Cookie を表示
//   node tools/req.ts cookies clear   保存中の Cookie を削除
//
// Cookie はブラウザのように tools/.cookies.json に保存し、次のリクエストで自動送信する。
// SameSite / Secure / Domain などの属性は無視する(curl と同じく、ブラウザの制約は再現しない)。
// 接続先は環境変数 BASE_URL で変更できる(デフォルト http://localhost:3000)。

import { readFileSync, writeFileSync, rmSync } from "node:fs";

const BASE_URL = process.env.BASE_URL ?? "http://localhost:3000";
const JAR_PATH = new URL(".cookies.json", import.meta.url);

type Jar = Record<string, string>;

function loadJar(): Jar {
  try {
    return JSON.parse(readFileSync(JAR_PATH, "utf8")) as Jar;
  } catch {
    return {};
  }
}

function saveJar(jar: Jar): void {
  writeFileSync(JAR_PATH, JSON.stringify(jar, null, 2) + "\n");
}

// Set-Cookie を Cookie jar に反映する。値が空、Max-Age<=0、Expires が過去なら削除扱い。
function applySetCookies(jar: Jar, setCookies: string[]): void {
  for (const header of setCookies) {
    const [pair = "", ...attrs] = header.split(";").map((s) => s.trim());
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq);
    const value = pair.slice(eq + 1);

    let expired = value === "";
    for (const attr of attrs) {
      const [key = "", val = ""] = attr.split("=");
      if (key.toLowerCase() === "max-age" && Number(val) <= 0) expired = true;
      if (key.toLowerCase() === "expires" && Date.parse(val) < Date.now()) expired = true;
    }

    if (expired) delete jar[name];
    else jar[name] = value;
  }
}

async function send(method: string, path: string, body?: unknown): Promise<void> {
  const jar = loadJar();
  const headers: Record<string, string> = {};
  const cookie = Object.entries(jar)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  if (cookie) headers["Cookie"] = cookie;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const url = new URL(path, BASE_URL);
  console.log(`> ${method} ${url}`);
  if (cookie) console.log(`> Cookie: ${cookie}`);
  if (body !== undefined) console.log(`> ${JSON.stringify(body)}`);

  const started = performance.now();
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  const elapsed = Math.round(performance.now() - started);

  console.log(`\n< ${res.status} ${res.statusText}  (${elapsed} ms)`);
  for (const [k, v] of res.headers) {
    if (k === "set-cookie") continue;
    console.log(`< ${k}: ${v}`);
  }
  const setCookies = res.headers.getSetCookie();
  for (const sc of setCookies) console.log(`< set-cookie: ${sc}`);
  console.log();
  console.log(await res.text());

  if (setCookies.length > 0) {
    applySetCookies(jar, setCookies);
    saveJar(jar);
  }
}

function usage(): never {
  console.error(
    [
      "usage:",
      "  node tools/req.ts register <username> <password>",
      "  node tools/req.ts login <username> <password>",
      "  node tools/req.ts me",
      "  node tools/req.ts logout",
      "  node tools/req.ts raw <METHOD> <path> [JSON body]",
      "  node tools/req.ts cookies [clear]",
    ].join("\n"),
  );
  process.exit(1);
}

const [command, ...args] = process.argv.slice(2);

switch (command) {
  case "register":
  case "login": {
    const [username, password] = args;
    if (username === undefined || password === undefined) usage();
    await send("POST", `/${command}`, { username, password });
    break;
  }
  case "me":
    await send("GET", "/me");
    break;
  case "logout":
    await send("POST", "/logout");
    break;
  case "raw": {
    const [method, path, json] = args;
    if (method === undefined || path === undefined) usage();
    await send(method.toUpperCase(), path, json === undefined ? undefined : JSON.parse(json));
    break;
  }
  case "cookies":
    if (args[0] === "clear") {
      rmSync(JAR_PATH, { force: true });
      console.log("cleared");
    } else {
      console.log(loadJar());
    }
    break;
  default:
    usage();
}
