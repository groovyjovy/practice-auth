import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { scrypt } from "node:crypto";

const app = new Hono();
const map: Map<string, string> = new Map();
const sessionMap: Map<string, { userName: string, expireAt: number }> = new Map();

// for hashing
const n = 17;
const r = 8;
const p = 1;
const keyLen = 32;
const maxmem = 256 * 1024 * 1024;
const cost = 2 ** n;
const faleSalt = Buffer.from("8d475c86a12e3fcedf758a200ab9e2a1", "hex");

// 8 hour
const ABSOLUTE_TIMEOUT_S  = 60 * 60 * 8
const ABSOLUTE_TIMEOUT_MS  = ABSOLUTE_TIMEOUT_S * 10 ** 3;

const generateHash = async (password: string, salt: NonSharedBuffer, keyLen: number) => {
  return await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, keyLen, { N: cost, r, p, maxmem }, (err, value) => {
      if (err) {
        reject(err);
        // c.status(500);
        // return c.text("Internal Server Error.")
        return;
      }
      resolve(value);
    });
  });
};

const validateAuthParams = (req: unknown) => {
  // object型以外?
  if (typeof req !== "object" || req === null) {
    return Error("can not validate.");
  }
  if (!("username" in req) || !("password" in req)) {
    return Error("can not validate.");
  }

  if (typeof req.username !== "string" || typeof req.password !== "string") {
    return Error("can not validate.");
  }

  // falthy?
  if (!req.username || !req.password) {
    return Error("can not validate.");
  }

  return {
    userName: req.username,
    password: req.password,
  };
};

app.get("/", (c) => {
  return c.text("hello, world!");
});

// 1.　リクエストからユーザー名とパスワードを取り出す
// 2. ソルトを作成する。
// 3. ソルトとパスワードでハッシュを生成する
// 4. DBにソルトやハッシュ、生成方式を保存するためにphcを生成する
// 5. DBにユーザー名をkeyとして、phcをDBに保存する
app.post("register", async (c) => {
  const req = await c.req.json();
  const result = validateAuthParams(req);
  if (result instanceof Error) {
    c.status(400);
    return c.text("paramater is inncorrect.");
  }

  // すでに登録されているユーザーなら400
  if (map.has(result.userName)) {
    c.status(400);
    return c.text("username is duplicate.");
  }
  const salt = randomBytes(16);
  const hash = await generateHash(result.password, salt, keyLen);

  const bufferToString = (buf: Buffer) => {
    return buf.toString("base64").replace(/=+$/, "");
  };

  const phc = `$scrypt$ln=${n},r=8,p=1$${bufferToString(salt)}$${bufferToString(hash)}`;

  // 登録操作
  map.set(result.userName, phc);

  c.status(201);
  return c.text("hoge");
});

// 1. リクエストからユーザー名とパスワードを取り出す
// 2. ユーザー名をキーとして、phcを取り出す
// 3. ユーザーから送信されてきたパスワードと、phcから復元したソルトを用いてハッシュを生成する
// 4. 手順3で生成したハッシュと、phcから復元したハッシュを比較し、同一であればセッションcokkieを発行する
app.post("login", async (c) => {
  const req = await c.req.json();
  const result = validateAuthParams(req);
  if (result instanceof Error) {
    c.status(400);
    return c.text("paramater is inncorrect.");
  }

  const phc = map.get(result.userName);

  // ユーザーが存在していないときは、仮の値でログイン処理をして攻撃者にユーザーが存在しないことを悟らせない。
  if (!phc) {
    const hash1 = await generateHash("fakepassword", faleSalt, keyLen);
    timingSafeEqual(hash1, hash1);
    c.status(403);
    return c.text("Wrong password or username!");
  }

  const [, alg, params, salt, hash] = phc.split("$");
  if (!alg || !params || !salt || !hash) {
    c.status(500);
    return c.text("Internal Server Error");
  }

  const [ln, n, p] = params.split(",").map((c) => {
    return Number(c.split("=")[1]);
  });

  if (!ln || !n || !p) {
    c.status(500);
    return c.text("Internal Server Error");
  }

  const plainSalt = Buffer.from(salt, "base64");
  const plainHash = Buffer.from(hash, "base64");

  const hash2 = await generateHash(result.password, plainSalt, plainHash.length);
  if (timingSafeEqual(plainHash, hash2)) {

    // 1. randomBytes(32) でセッション ID を作り、文字列に変換する
    const sessionId = randomBytes(32).toString("hex");
    // 2. セッション用の Map に、セッション ID → { userName, expiresAt } を保存する

    const expireAt = Date.now() + ABSOLUTE_TIMEOUT_MS;
    sessionMap.set(sessionId, { userName: result.userName, expireAt });
    // 3. レスポンスに Set-Cookie ヘッダーを付ける
    // - __Host-session
    //   ブラウザが特別扱いするプレフィックス。Secure属性が必須、Path属性の値が"/"、Domain属性がついていない
    // - Secure
    //   HTTPS通信のときにだけ送信される
    // - Path
    //   Cokkieが送信される範囲の指定
    // - Domain
    //   Cookieの上書きを許可するドメイン
    // - SameSite
    //   Strict：他サイトからのリクエストには一切送らない
    //   Lax：他サイトからでも、リンクをクリックしたときのようなトップレベルのGET遷移では送る。フォームのPOST、fetch、iframe、画像などでは送らない
    //   None：常に送る（Secure が必須）
    c.header("Set-Cookie", `__Host-session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${ABSOLUTE_TIMEOUT_S}`)

    c.status(200);
    return c.text("logined!");
  } else {
    c.status(403);
    return c.text("Wrong password or username!");
  }
});

serve(
  {
    fetch: app.fetch,
    port: 3000,
  },
  (info) => {
    console.log(`server is running on http://localhost:${info.port}`);
  },
);
