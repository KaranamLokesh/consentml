# Marketing landing page

`index.html` is the custom landing page served at the site root
(`https://consentml.lokeshkaranam.me/`). It is a standalone, self-contained
page (its own CSS and fonts), intentionally separate from the MkDocs Material
documentation theme.

## How it ships

The docs deploy (`.github/workflows/deploy-ec2.yml`) builds MkDocs into `site/`,
then overlays this page on top:

- `landing/index.html` → `site/index.html` (replaces the MkDocs homepage)
- `demo/demo.gif` → `site/assets/demo.gif` (the single source-of-truth gif,
  produced by `demo/demo.tape`)

Every documentation page keeps its own URL (`/getting-started/`, `/guides/`,
`/reference/`, `/why/`). Only the root `/` becomes the landing page. Both files
must live inside `site/` because the rsync step mirrors with `--delete`.

## Editing

- The page references the demo as `/assets/demo.gif` (served at the site root),
  the same gif produced by `demo/demo.tape`. Update both if the demo changes.
- Keep links to docs pages absolute (`https://consentml.lokeshkaranam.me/...`)
  or root-relative so they resolve from the root page.
