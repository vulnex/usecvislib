# USecVisLib: response to the BytesRevealer feature requests

**Date:** 2026-10-06
**In reply to:** the BytesRevealer integration's feature request list (2026-10-06), kept in the BytesRevealer repository as `devnotes/usecvislib-feature-requests.md`
**USecVisLib version:** 0.6.0 (`ce04188` and earlier)

## Status

| ID | Request | Status |
|---|---|---|
| A1 | `config_json` partial updates reset unspecified fields | **Done** |
| A2 | `visualization_type=all` returns only the entropy chart | **Done** (response format changed, see below) |
| A3 | Chart titles show the server's temp file name | **Done** |
| A4 | Wind rose is a first-byte histogram, and slow on large files | **Done** |
| A5 | CORS: no `DELETE`, no exposed response headers | **Done** (partly, see below) |
| A6 | Rate-limit responses carry no retry hint | **Done** |
| B1 | Render a byte range, with file-offset overlays | Deferred to 0.7.0 |
| B2 | True byte-pair (digraph) plot | **Done** |
| B3 | Hilbert-curve layout | Deferred to 0.7.0 |
| B4 | Compare two binaries | Deferred to 0.7.0 |
| B5 | Chart data as JSON | Deferred to 0.7.0 |
| B6 | Larger files through streaming | Deferred to 0.7.0 |
| B7 | Binary support in `/batch/visualize` | Deferred to 0.7.0 |

Every bug and gap you reported was confirmed against the code. Thanks for the precise file and line references.

## Availability

The changes are committed in USecVisLib 0.6.0 but **not pushed or released yet**. They reach you when 0.6.0 is published. Until then, you can test against a local checkout by building the API Docker image from it.

Unchanged: 50 MB upload limit, 10 visualize requests per minute, 120 s visualize timeout.

---

## What changed for BytesRevealer

### A2. One request returns every chart (action needed)

`POST /visualize/binary?visualization_type=all` now returns **JSON**, not an image:

```json
{
  "charts": [
    {"type": "entropy",      "content_type": "image/png", "filename": "binary_entropy.png",      "data": "<base64>"},
    {"type": "distribution", "content_type": "image/png", "filename": "binary_distribution.png", "data": "<base64>"},
    {"type": "windrose",     "content_type": "image/png", "filename": "binary_windrose.png",     "data": "<base64>"},
    {"type": "heatmap",      "content_type": "image/png", "filename": "binary_heatmap.png",      "data": "<base64>"},
    {"type": "digraph",      "content_type": "image/png", "filename": "binary_digraph.png",      "data": "<base64>"}
  ]
}
```

- This is option 1 from your proposal.
- There are **five** charts now, in this order, because `all` includes the new digraph (B2).
- `content_type` follows the `format` parameter (`image/png`, `image/svg+xml`, `application/pdf`).
- One upload, and it counts once against the rate limit.
- **Action:** the Export grid can replace its four requests with this one call, and must read JSON instead of an image body. Any code that sends `all` and expects an image must be updated. Single-chart types still return the image directly, as before.

### A1. Partial `config_json`

- Only the fields you send are applied. Everything else keeps the library's defaults.
- `{"wind_rose": {"bar_alpha": 0.5}}` keeps the radial labels at 22.5°.
- `{"heatmap": {"block_size": 512}}` changes only the heatmap's row width.
- The `wind_rose.rlabel_position` schema default is now 22.5, matching the library.
- No client change needed.

### A3. Chart titles

- New optional form field **`title`** on `POST /visualize/binary`.
- With `title`: charts read e.g. "Entropy Analysis: firmware.bin".
- Without it: charts read just "Entropy Analysis". There is no automatic fallback to the uploaded file name, as you asked.
- The server never shows its `upload_<hex>.bin` temp name any more.
- The title is cleaned: printable characters only, `$` removed (it would trigger Matplotlib math mode), at most 120 characters.
- **Action (optional):** send `title` when the user chooses to share the file name.

### A4. Wind rose

- Byte counting now uses NumPy instead of a per-byte Python loop: 0.4 s instead of about 11 s on a 50 MB file.
- The chart itself is unchanged. It is now described accurately as a **polar histogram of byte values** (one direction per byte value), and its title is "Byte Value Wind Rose (log scale)".
- The byte-pair view is the new digraph chart (B2).
- **Action:** BytesRevealer's UI no longer needs to explain the difference; the wind rose can be labelled as a byte-value histogram.

While measuring this we found the **entropy** chart was the real bottleneck on large files (64 s on 50 MB), and the byte distribution was also slow. Both are vectorised now, with identical results:

| Chart, 50 MB file | Before | After |
|---|---|---|
| entropy | 64.5 s | 9.1 s |
| distribution | 4.0 s | 0.4 s |
| wind rose | ~11 s | 0.4 s |
| heatmap | 4.1 s | 2.6 s |
| digraph (new) | – | 0.2 s |
| all five charts | ~85 s | ~13 s |

`all` on a 50 MB file now finishes well inside the 120 s timeout.

### A5. CORS

- `DELETE` is allowed, so `DELETE /images/{id}` works from the browser.
- Exposed response headers: `Content-Disposition` and `Retry-After`.
- **Not done:** `X-RateLimit-Limit` / `X-RateLimit-Remaining`. The rate limiter does not send them, so there is nothing to expose. Enabling them would require changing every endpoint's signature; we can revisit if you need the remaining count.

### A6. Retry hint on 429

- 429 responses now carry `Retry-After`: the number of seconds until the rate-limit window resets (1 to 60 with the default limits).
- It is readable from browser code through CORS (A5).
- The body is unchanged: `{"error": "Rate limit exceeded: 10 per 1 minute"}`.

### B2. Byte-pair (digraph) plot

- Request: `POST /visualize/binary?visualization_type=digraph`.
- A 256×256 image: the pixel at (next byte, first byte) shows how often that pair occurs, on a log scale.
- Dashed guides mark the printable ASCII range (0x20–0x7E). Plain text forms a dense block inside it; random or encrypted data looks uniform.
- Works with all 12 `bv_*` styles, including `bv_dark`, and in PNG, SVG and PDF.
- Options in `config_json`:

  ```json
  {"digraph": {"show_ascii_guides": true, "show_colorbar": true, "dpi": 150}}
  ```

- Renders in about 0.2 s on a 50 MB file.
- Also included in `visualization_type=all` (A2).

---

## Deferred to 0.7.0

We plan these as one "binary analysis" release. They change chart axes and add API surface, so they need their own design and testing pass, and 0.6.0 was already a large release.

| ID | Request | Estimate | Notes |
|---|---|---|---|
| B1 | Byte range with file-offset overlays | ~1 day | Highest value of the deferred items. Touches the axes of every chart. |
| B3 | Hilbert-curve layout | ~1 day | New layout algorithm plus downsampling for large files. |
| B4 | Compare two binaries | 1–1.5 days | New endpoint and chart designs. |
| B5 | Chart data as JSON | ~0.5 day | Best done together with B1 and B3, so ranges and Hilbert data are covered too. The digraph counts are already computed internally. |
| B6 | Streaming for larger files | – | Low priority; B1 (uploading only a slice) covers most of the need. |
| B7 | Binaries in `/batch/visualize` | ~2 h | Low priority; A2 covers several charts for one file. |

If any of these is more urgent for you, tell us and we can reorder.

---

## Other changes you may notice

- **Chart titles from the CLI and Python library** still show the input file's name, which is correct there. The Python API has a new `BinVis(display_name=...)` option.
- **Python library:** new `visualize_digraph()` and `byte_pair_counts()` (the 256×256 counts as a NumPy array). `visualize_all()` now returns five paths.
- **MCP server (usecvislib-mcp 0.5.0):** new `analyze_binary_digraph` tool. A bug where the binary tools reported an output file that was never written is fixed.
- **Gallery:** all binary charts, including the digraph in every style, are at https://vulnex.github.io/usecvislib-gallery/#binary-visualization

## Corrections to your appendix

All the facts you listed match what we see. Two additions:

- `/styles` still lists 12 `bv_*` presets under `binary_visualization`. All of them now also style the digraph chart.
- `visualization_type` values are now `entropy`, `distribution`, `windrose`, `heatmap`, `digraph` and `all`.
