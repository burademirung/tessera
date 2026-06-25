# Deploy — Cloudflare Pages

Cloudflare has no GitHub OIDC for Wrangler. Create a least-privilege,
**account-owned** API token (not the global key):

1. Cloudflare dashboard → Manage Account → API Tokens → Create Token →
   "Create Custom Token".
2. Grant the minimum permission for Pages deploys: **Account → Cloudflare Pages →
   Edit**. Scope "Account Resources" to this account only. (The "Edit Cloudflare
   Workers" template is broader than needed; Pages deploys only require the
   `Cloudflare Pages: Edit` permission group.)
3. Store it in the GitHub repo as the **environment** secret
   `CLOUDFLARE_API_TOKEN` under a `production` environment with required
   reviewers. Add `CLOUDFLARE_ACCOUNT_ID` likewise.

Manual deploy (local). Project name and output dir come from `site/wrangler.jsonc`
(`name` + `pages_build_output_dir`), so no positional args are needed:

    pnpm --dir site build
    pnpm --dir site exec wrangler pages deploy
