# SENTINEL AUDIT — Web公開手順（Render・無料プラン）

自PC内でしか動かなかった診断サイトを、インターネットに公開して誰でも使える状態にする手順です。
**マネージド（Render）** を使うので、サーバー管理・HTTPS設定は不要。Gitに上げて数クリックで公開できます。

---

## 前提

- GitHub アカウント（無料）… コードの置き場所
- Render アカウント（無料）… https://render.com （GitHubでログイン可）

このフォルダ（`sentinel-audit/`）は既に **Gitリポジトリとして初期化済み** です。
公開に必要なファイルは揃っています:

| ファイル | 役割 |
|---|---|
| `render.yaml` | Renderの設定（自動で読み込まれる） |
| `requirements.txt` | 依存パッケージ（dnspython） |
| `server.py` | 本番では `PORT` 環境変数と `0.0.0.0` で自動待受 |

---

## 手順（所要 約10分）

### 1. GitHubにリポジトリを作る
1. https://github.com/new を開く
2. Repository name: `sentinel-audit`（任意）／ **Private** でOK
3. 「Create repository」→ 表示される `git remote add ...` のURLをコピー

### 2. コードをGitHubへ push（このフォルダで実行）
PowerShellでこのフォルダを開き、以下を実行:
```powershell
git remote add origin https://github.com/<あなたのユーザー名>/sentinel-audit.git
git branch -M main
git push -u origin main
```
（初回はGitHubのログインを求められます）

### 3. Renderにデプロイ
1. https://dashboard.render.com/ にGitHubでログイン
2. 右上 **New +** → **Web Service**
3. 先ほどのGitHubリポジトリを選択（Connect）
4. Renderが `render.yaml` を検出 → 設定はほぼ自動で入る
   - Plan: **Free**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python server.py`
5. **Create Web Service** をクリック
6. 2〜3分でビルド完了 → `https://sentinel-audit-xxxx.onrender.com` のURLが発行される

これで公開完了。URLを開くとホーム（LP）が表示され、`/scan` で実際に診断できます。

---

## 無料プランの注意点

- **スリープ**：15分アクセスが無いとサーバーが休止し、次のアクセスで復帰に30〜50秒かかります（コールドスタート）。
  - 商談前に一度自分でURLを開いて起こしておくと安心です。
  - 常時起動が必要になったら Render の Starter（$7/月）にアップグレードで解消します。
- 無料プランでも診断機能・HTTPSはフル動作します。

---

## 公開後にやると良いこと（任意）

- **独自ドメイン**：Renderの Settings → Custom Domains から `sentinel-audit.jp` 等を接続（DNSにCNAMEを設定）。HTTPS証明書はRenderが自動発行。
- **常時起動**：Starterプランにアップグレード。
- **利用ログの確認**：Renderのダッシュボード → Logs で、どのドメインが診断されたか確認できます。

---

## セキュリティ上の実装（公開対応済み）

公開にあたり、以下を実装済みです:

- **踏み台防止（SSRF対策）**：入力ドメインがプライベートIP・ループバック・クラウドメタデータ（169.254.x）等の内部宛先を指す場合は診断を拒否（`scanner.is_public_domain`）。
- **レート制限**：同一IPあたり60秒に10回まで。プロキシ越しの実IPを `X-Forwarded-For` で判定。
- **自サイトのセキュリティヘッダー**：HSTS / CSP / X-Frame-Options 等を付与（自分の診断に自分で合格する構成）。
- **非侵入**：対象への侵入・負荷はかけず、公開情報のみ観測。
