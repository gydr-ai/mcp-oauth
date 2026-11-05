import { escapeHtml } from "./text.js"

/**
 * Wrap page content in a complete, self-contained HTML document with inline
 * styles only, so it works under the pages' Content-Security-Policy.
 *
 * @param title - Page title; escaped here.
 * @param body - Body HTML; the caller escapes its values.
 * @returns The HTML document.
 * @internal
 */
export function document(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>${escapeHtml(title)}</title>
<style>
html{font:16px/1.55 ui-sans-serif,system-ui,sans-serif;background:Canvas;color:CanvasText}
body{margin:0 auto;max-width:34rem;padding:2rem 1rem}
h1{font-size:1.3rem;font-weight:600}
.facts{padding:.75rem 1rem;border-left:3px solid GrayText;margin:1.25rem 0}
.facts span{display:block;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;opacity:.7}
.facts p{margin:.6rem 0;overflow-wrap:anywhere}
.note{padding:.75rem 1rem;border:1px dashed #b45309}
.choices{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1.5rem}
button{font:inherit;padding:.55rem 1.4rem;border:1px solid GrayText;background:transparent;color:inherit;cursor:pointer}
button.go{background:#0f766e;border-color:#0f766e;color:#fff}
</style>
</head>
<body>
${body}
</body>
</html>`
}
