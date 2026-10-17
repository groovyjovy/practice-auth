---
name: spec
description: 実装中に湧いた疑問(「このエラーはどう返す?」「このパラメータは必須?」)に対して、該当する RFC / 仕様の節を案内する。仕様の要約は最小限にし、本人に原文を読ませる。
argument-hint: "<疑問>"
---

# 仕様の案内

疑問: `$ARGUMENTS`

## 手順

1. 疑問に答える仕様の **節番号** を特定する。不確かなときは WebFetch で原文を確認してから示す(記憶だけで節番号を断言しない)
   - RFC は `https://www.rfc-editor.org/rfc/rfcXXXX.html#section-Y` の形でリンクする
   - OIDC は `https://openid.net/specs/openid-connect-core-1_0.html#<anchor>`
2. 次の形で返す:
   - **読む場所**:仕様名 §節番号(リンク)。多くても 2〜3 箇所
   - **読むときの観点**:「MUST / SHOULD / MAY のどれになっているか」「エラー時の挙動」など、何に注目して読めばよいか
   - **問い**:読んだ後に本人が答えられるべき質問を 1 つ
3. 答えそのもの(「必須です」など)は、本人が読んで答えを言ってから確認する形にする。本人が「急いでいるので結論だけ」と言った場合は結論 + 根拠の節を示してよい
4. 本人のコードと仕様がずれていそうなら `path:line` を挙げて指摘する

## よく使う仕様

| 仕様 | 主な節 |
|---|---|
| RFC 6265 Cookie | §4.1(Set-Cookie), §8(Security) |
| RFC 7519 JWT | §4.1(Registered Claims), §7.2(Validating) |
| RFC 7515 JWS | §4.1(Header), §5.2(Validation) |
| RFC 8725 JWT BCP | §2(Threats), §3(Best Practices) |
| RFC 6749 OAuth 2.0 | §1(Roles), §2(Client Registration), §3.1.2(Redirection Endpoint), §4.1(Authorization Code), §4.1.2.1 / §5.2(Error), §10(Security) |
| RFC 7636 PKCE | §4(Protocol) |
| RFC 6750 Bearer | §2(Authenticated Requests), §3(WWW-Authenticate) |
| RFC 7662 Introspection | §2 |
| RFC 9700 Security BCP | §2(Recommendations), §4(Attacks and Mitigations) |
| OIDC Core 1.0 | §2(ID Token), §3.1(Code Flow), §3.1.3.7(ID Token Validation), §5.3(UserInfo) |
| OIDC Discovery 1.0 | §3(Provider Metadata), §4(Obtaining Configuration) |
| RFC 7517 JWK | §4(JWK Parameters) |
