import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

// ===== ステップ 1: base64url の変換 =====
// - Buffer の "base64url" を使う
// - エンコード: 文字列(またはバイト列) → base64url の文字列
// - デコード: base64url の文字列 → バイト列(JSON に戻すときは、さらに文字列にする)
const encodeBase64Url = (str: string) => {
  return Buffer.from(str).toString("base64url");
};

const decodeBase64Url = (base64url: string) => {
  return Buffer.from(base64url, "base64url");
};

const key = randomBytes(32);

// 署名を作る関数 sign(signingInput, key)
// - createHmac("sha256", key) を使う(node:crypto から import する)
// - update() に、署名対象の文字列(3)を渡す
// - digest() で結果を取り出す。引数で出力の形を選べる(Buffer の toString と同じ考え方)
// - 戻り値は base64url の文字列
// 鍵は generateJWT の引数で受け取る
// - 試すときは randomBytes(32) で作った鍵を渡す
// - 呼ぶたびに作らず、1 回だけ作って使い回す(検証のときに同じ鍵が必要になるため)
const sign = (signingInput: string, key: Buffer) => {
  return createHmac("sha256", key).update(signingInput).digest("base64url");
};

const nowSeconds = () => {
  const now_ms = Date.now();
  return Math.floor(now_ms / 10 ** 3);
};

const jsonParse = (str: string) => {
  try {
    return JSON.parse(str);
  } catch {
    return { ok: false, value: Error("invarid.") }
  }
}

// ===== ステップ 2: JWT を作る =====
// 1. ヘッダー { alg: "HS256", typ: "JWT" } を JSON にして、base64url にする
// 2. ペイロード(sub, iat, exp など)を JSON にして、base64url にする
//    - iat / exp は「秒」(RFC 7519 §2 の NumericDate)。Date.now() はミリ秒なので注意
// 3. 「1 + "." + 2」を署名対象の文字列にする(RFC 7515 §5.1)
// 4. createHmac("sha256", 秘密鍵) で、3 の文字列の HMAC を計算し、base64url にする
//    - 秘密鍵は 256 ビット(32 バイト)以上(RFC 7518 §3.2)
// 5. 「3 + "." + 4」を返す
// RFC の例で試せるように、4(署名の計算)だけを別の関数にしておくとよい
// 確認: RFC 7515 付録 A.1 の例と同じ署名が出る
//   - ヘッダーとペイロードは、RFC に載っている base64url 済みの文字列をそのまま使う(JSON に改行が入っているため)
//   - 鍵は JWK の k(base64url)をバイト列に戻してから HMAC に渡す
const generateJWT = (sub: string, key: NonSharedBuffer) => {
  const header = { alg: "HS256", typ: "JWT" };
  const headerStr = JSON.stringify(header);
  const headerStrBase64url = encodeBase64Url(headerStr);

  const now_s = nowSeconds();
  const iat = now_s;
  const exp = now_s + 60 * 15;

  const payload = { sub, iat, exp };
  const payloadStr = JSON.stringify(payload);
  const payloadStrBase64url = encodeBase64Url(payloadStr);

  const signTarget = `${headerStrBase64url}.${payloadStrBase64url}`;
  const signature = sign(signTarget, key);

  return `${signTarget}.${signature}`;
};

const hoge = generateJWT("hoge", key);

// ===== ステップ 3: JWT を検証する =====
// 1. "." で分ける。3 つでなければ失敗
// 2. ヘッダーを JSON に戻し、alg が "HS256" であることを確認する
//    - ヘッダーの alg を見て処理を切り替えない(RFC 8725 §3.1)
// 3. 受け取った「ヘッダー部分 + "." + ペイロード部分」の文字列から、署名を計算し直す
//    - JSON を作り直さず、受け取った文字列をそのまま使う
// 4. 受け取った署名と timingSafeEqual で比べる
//    - 長さが違うと例外になるので、先に長さを確認する
// 5. 署名が正しいと分かってから、ペイロードを JSON に戻す
//    - JSON.parse は壊れた入力で例外を投げるので、失敗として扱う
// 6. exp が今の時刻(秒)より前なら失敗
// 7. ここまで通ったら、ペイロードを返す
// 確認: 正しいトークン → 成功 / ペイロードを 1 文字変えたもの → 失敗
//       別の秘密鍵で作ったもの → 失敗 / exp を過去にして作ったもの → 失敗

type Result = { ok: true; value: unknown } | { ok: false; value: Error };

const verifyJWT = (jwt: string): Result => {
  // -----------------
  // 1
  const splited = jwt.split(".");

  // -----------------
  // 2
  const JWTParseResult = () => {
    return { ok: false, value: Error("JWT is not correct.") };
  };

  if (splited.length !== 3) {
    return JWTParseResult();
  }

  const header = splited[0];
  const payload = splited[1];
  const signature = splited[2];

  if (!header || !payload || !signature) {
    return JWTParseResult();
  }

  const decodedHeader = decodeBase64Url(header).toString();
  const { alg, typ } = jsonParse(decodedHeader);

  if (typeof alg !== "string" || typeof typ !== "string") {
    return JWTParseResult();
  }

  if (alg !== "HS256") {
    return JWTParseResult();
  }

  // -----------------
  // 3
  const signature2 = sign(`${header}.${payload}`, key);

  // -----------------
  // 4
  const bufSig = Buffer.from(signature);
  const bufSig2 = Buffer.from(signature2);

  try {
    if (!timingSafeEqual(bufSig, bufSig2)) {
      return { ok: false, value: Error("invarid.") }
    }
  } catch {
    return { ok: false, value: Error("invarid.") }
  }

  // -----------------
  // 5
  const decodedPayload = decodeBase64Url(payload).toString();
  const { sub, iat, exp } = jsonParse(decodedPayload);

  if (
    typeof sub !== "string" ||
    typeof iat !== "number" ||
    typeof exp !== "number"
  ) {
    return JWTParseResult();
  }

  // -----------------
  // 6
  const now_s = nowSeconds();
  if (now_s >= exp) {
    return { ok: false, value: Error("invarid.") }
  }

  // -----------------
  // 7
  console.log({sub, iat, exp });
  return { ok: true, value: {sub, iat, exp } };
};

verifyJWT(hoge);
