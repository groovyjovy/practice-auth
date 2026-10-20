import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { scrypt } from "node:crypto";
import { findPackageJSON } from "node:module";

const app = new Hono();
const map: Map<string, string> = new Map();
const n = 17;
const r = 8;
const p = 1;
const keyLen = 32;
const maxmem = 256 * 1024 * 1024;
const cost = 2 ** n;
const faleSalt = Buffer.from("8d475c86a12e3fcedf758a200ab9e2a1", "hex");

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
    timingSafeEqual(hash1, hash1)
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
