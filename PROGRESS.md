# 進捗

現在のフェーズ: 未開始

凡例: `[ ]` 未 / `[~]` 部分的に説明できた / `[x]` 口頭試問で合格

## フェーズ 0:環境構築

- [ ] Node.js(Active LTS)を用意した
- [ ] pnpm workspace を作り、`minimumReleaseAge: 10080` を設定した
- [ ] TypeScript を `strict: true` で設定した
- [ ] Hono で Hello World を返せた
- [ ] `/etc/hosts` に `client.local auth.local api.local` を追加した(フェーズ 3 までに)

## フェーズ 1:パスワード + サーバーセッション + Cookie

作るもの: [ ] 登録 [ ] ログイン [ ] セッション発行 [ ] `/me` [ ] ログアウト

- [ ] パスワードを暗号化ではなくハッシュ化する理由 / 遅いハッシュを使う理由
- [ ] ソルトは何を防いでいるか
- [ ] `timingSafeEqual` を使う理由
- [ ] 「ログインしている状態」とは技術的に何か
- [ ] `HttpOnly` / `Secure` / `SameSite` がそれぞれ何を防いでいるか
- [ ] ログイン成功時にセッション ID を作り直す理由
- [ ] ユーザー不存在とパスワード誤りを区別しない理由

実験: [ ] XSS で Cookie 窃取 [ ] CSRF [ ] ブルートフォース

## フェーズ 2:JWT を自作してセッションと比べる

作るもの: [ ] HS256 生成・検証 [ ] Bearer 認証版 API

- [ ] JWT の 3 パートの中身 / base64url は暗号化ではない
- [ ] 署名が保証すること・しないこと
- [ ] `alg: none` 攻撃と、アルゴリズム固定の理由
- [ ] JWT 失効の難しさと、短い exp + リフレッシュトークン
- [ ] ステートフルとステートレスのトレードオフ
- [ ] localStorage と HttpOnly Cookie の XSS / CSRF リスクの違い
- [ ] Firebase Auth がやっていることを説明できる

実験: [ ] role 改ざん [ ] `alg: none` 突破

## フェーズ 3:OAuth 2.0 認可サーバーを自作(本丸)

作るもの: [ ] AS `/authorize` [ ] AS `/token` + PKCE [ ] Client [ ] RS(Introspection) [ ] RS(JWT 検証) [ ] リフレッシュ(任意)

- [ ] 認可コードを挟む理由(フロント / バックチャネル)
- [ ] `state` が防ぐもの
- [ ] PKCE が防ぐもの / `code_challenge` がハッシュである理由
- [ ] `redirect_uri` 完全一致の必要性
- [ ] confidential client と public client
- [ ] Implicit / ROPC が非推奨になった理由
- [ ] scope と role の違い
- [ ] アクセストークンが「誰であるか」を証明しない理由

実験: [ ] ログイン CSRF [ ] redirect_uri 前方一致バグ [ ] PKCE なしでのコード横取り

## フェーズ 4:OIDC プロバイダー化

作るもの: [ ] ID トークン(RS256) [ ] JWKS [ ] Discovery [ ] `/userinfo` [ ] Client 側 nonce / 検証

- [ ] ID トークンとアクセストークンの違い
- [ ] RS256 / ES256 が主流な理由
- [ ] `aud` を検証しないと何が起きるか
- [ ] `nonce` と `state` の違い
- [ ] `sub` が識別子として正しく、メールがそうでない理由
- [ ] Discovery と JWKS で何が自動化できるか

## フェーズ 5:Google に繋ぐ

- [ ] 自作サーバーと Google の同じ点・違う点
- [ ] ソーシャルログインの裏側を全ステップ説明できる
- [ ] `iss` + `sub` でのユーザー紐づけ

## フェーズ 6:アクセス制御としての認可

作るもの: [ ] RBAC [ ] ABAC 的ルール [ ] `can()` への集約

- [ ] RBAC / ABAC / ReBAC の違い
- [ ] ロールを JWT に入れる vs 毎回 DB を引く
- [ ] UI でボタンを隠すのは認可ではない理由
- [ ] IDOR とその防ぎ方

## フェーズ 7(任意):パスキー / WebAuthn

- [ ] 公開鍵だけ保存する意味
- [ ] チャレンジ署名がリプレイを防ぐ理由
- [ ] フィッシングに強い理由

## 仕上げ:何も見ずに描く図

- [ ] 1. パスワードログイン〜ログアウト
- [ ] 2. 認可コードフロー + PKCE
- [ ] 3. OIDC ログイン
- [ ] 4. リフレッシュトークン
- [ ] 5. RS でのトークン検証(2 通り)
- [ ] 6. パスキー登録・ログイン
- [ ] 7. better-auth / Firebase Auth の実フロー

## ログ

<!-- /quiz や /check の結果を日付付きで追記 -->
