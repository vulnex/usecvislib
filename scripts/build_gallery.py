#
# VULNEX -Universal Security Visualization Library-
#
# File: build_gallery.py
# Author: Simon Roses Femerling
# Created: 2026-10-06
# Last Modified: 2026-10-06
# Version: 0.6.0
# License: Apache-2.0
# Copyright (c) 2026 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Render every template with every engine, view and style preset into a
browsable gallery (one folder per module plus an ``index.html``).

Needs Graphviz, mmdc and the cloud-diagram icons, so run it in the API image
with the repo mounted:

    docker run --rm -v "$PWD":/repo -v "$OUT":/out -w /repo \\
        -e PYTHONPATH=/repo/src -e PYTHONHASHSEED=0 --entrypoint python usecvislib-usecvislib-api \\
        scripts/build_gallery.py /out
"""

import argparse
import contextlib
import html
import io
import json
import multiprocessing
import os
import re
import shutil
import sys
import time
from pathlib import Path
from urllib.parse import quote

import tomllib

REPO = Path(__file__).resolve().parent.parent
TEMPLATES = REPO / "templates"
MODELS = REPO / "src" / "usecvislib" / "models"

GV_FORMATS = ("dot", "pdf", "png", "svg")
SVG_FORMATS = ("pdf", "png", "svg")

AT, TM, BV, AG = "01 Attack Trees", "02 Threat Modeling", "03 Binary Visualization", "04 Attack Graphs"
CD, CL, MM, PG = "05 Custom Diagrams", "06 Cloud Diagrams", "07 Mermaid", "08 Privilege Gradient"
CO, DG, KC, TL = "09 Component Diagram", "10 Dependency Graph", "11 Kill Chain", "12 Incident Timeline"
VT, MA, SH = "13 Vulnerability Tree", "14 MAESTRO", "15 Shine Pack"
CATEGORIES = (AT, TM, BV, AG, CD, CL, MM, PG, CO, DG, KC, TL, VT, MA, SH)
STYLES_DIR = "_styles (all presets)"

# category, CLI mode, template glob, SVG engine?, views (-v), style module, style template
GRAPH_MODULES = [
    (AT, 0, "attack-trees/*", True, None, "attacktrees", "attack-trees/ransomware_attack.tml"),
    (TM, 1, "threat-models/*", True, None, "threatmodeling", "threat-models/ecommerce_platform.tml"),
    (AG, 3, "attack-graphs/*", True, None, "attackgraphs", "attack-graphs/corporate_network.tml"),
    (PG, 6, "privilege-gradient/*", True, None, "privilegegradient", "privilege-gradient/corporate_network.tml"),
    (CO, 7, "architecture/component-*", True, None, "componentdiagram", "architecture/component-diagram-example.json"),
    (DG, 8, "architecture/dependency-*", True, None, "dependencygraph", "architecture/dependency-graph-example.json"),
    (KC, 9, "kill-chains/*", True, None, "killchain", "kill-chains/apt_intrusion.tml"),
    (
        VT,
        11,
        "vuln-trees/*",
        True,
        ("tree", "vulnerable_only", "critical_path"),
        "vulntree",
        "vuln-trees/npm_supply_chain.tml",
    ),
]
TIMELINE_VIEWS = ("swimlane", "gantt", "vertical", "compact")
MAESTRO_VIEWS = ("layered", "graph", "heatmap")
BINVIS_VIEWS = ("entropy", "distribution", "windrose", "heatmap", "digraph")
BINVIS_INPUTS = {
    "ls_binary": "/bin/ls",
    "png_file": str(REPO / "usecvislib_logo.png"),
    "text_readme": str(REPO / "README.md"),
}
SHINE = [
    ("attack-trees", 0, "attack-trees/ransomware_attack.tml"),
    ("attack-graphs", 3, "attack-graphs/corporate_network.tml"),
    ("threat-models", 1, "threat-models/ecommerce_platform.tml"),
]


def presets(module: str) -> list[str]:
    """Top-level preset ids of a module's style file, in file order."""
    with open(MODELS / f"config_{module}.tml", "rb") as f:
        return list(tomllib.load(f))


def template_dir(path: Path) -> str:
    return f"{path.stem} ({path.suffix[1:]})"


def templates(pattern: str) -> list[Path]:
    return sorted(p for p in TEMPLATES.glob(pattern) if p.suffix in (".toml", ".tml", ".json", ".yaml"))


# --------------------------------------------------------------------------- jobs
# A job is (kind, out_base_without_ext, params); kinds: cli, pytm, custom.


def cli(out: Path, inp, mode: int, fmt: str, *extra: str):
    return ("cli", str(out), ["-i", str(inp), "-o", str(out), "-m", str(mode), "-f", fmt, *extra])


def build_jobs(out: Path) -> list[tuple]:
    jobs = []
    for cat, mode, pattern, svg, views, module, style_tpl in GRAPH_MODULES:
        for tpl in templates(pattern):
            d = out / cat / template_dir(tpl)
            for view in views or (None,):
                pre = f"{view}__" if view else ""
                vflag = ("-v", view) if view else ()
                jobs += [cli(d / f"{pre}graphviz", tpl, mode, f, *vflag) for f in GV_FORMATS]
                if svg:
                    jobs += [
                        cli(d / f"{pre}svg-engine", tpl, mode, f, "--render-engine", "svg", *vflag) for f in SVG_FORMATS
                    ]
        view = f"__{views[0]}" if views else ""
        vflag = ("-v", views[0]) if views else ()
        for style in presets(module):
            engine = ("--render-engine", "svg") if style.startswith("sv_") else ()
            fmts = ("png", "svg") if engine else ("png",)
            jobs += [
                cli(
                    out / cat / STYLES_DIR / f"{style}{view}",
                    TEMPLATES / style_tpl,
                    mode,
                    f,
                    "-s",
                    style,
                    *engine,
                    *vflag,
                )
                for f in fmts
            ]

    # Threat models through the OWASP pytm engine (Python API only)
    for tpl in templates("threat-models/*.tml"):
        d = out / TM / template_dir(tpl)
        jobs += [("pytm", str(d / "pytm"), {"tpl": str(tpl), "fmt": f}) for f in GV_FORMATS]

    # Incident timeline: 4 views x matplotlib / SVG engine
    for tpl in templates("timelines/*"):
        d = out / TL / template_dir(tpl)
        for view in TIMELINE_VIEWS:
            for f in SVG_FORMATS:
                jobs.append(cli(d / f"{view}__matplotlib", tpl, 10, f, "-v", view))
                jobs.append(cli(d / f"{view}__svg-engine", tpl, 10, f, "-v", view, "--render-engine", "svg"))
    for style in presets("timeline"):
        engine = ("--render-engine", "svg") if style.startswith("sv_") else ()
        for f in ("png", "svg") if engine else ("png",):
            jobs.append(
                cli(
                    out / TL / STYLES_DIR / f"{style}__swimlane",
                    TEMPLATES / "timelines/ransomware_incident.tml",
                    10,
                    f,
                    "-s",
                    style,
                    *engine,
                )
            )

    # MAESTRO: layered (Graphviz), graph (Graphviz + SVG engine), heatmap (Matplotlib)
    for tpl in templates("maestro/*"):
        d = out / MA / template_dir(tpl)
        jobs += [cli(d / "layered__graphviz", tpl, 12, f, "-v", "layered") for f in GV_FORMATS]
        jobs += [cli(d / "graph__graphviz", tpl, 12, f, "-v", "graph") for f in GV_FORMATS]
        jobs += [cli(d / "graph__svg-engine", tpl, 12, f, "-v", "graph", "--render-engine", "svg") for f in SVG_FORMATS]
        jobs += [cli(d / "heatmap__matplotlib", tpl, 12, f, "-v", "heatmap") for f in SVG_FORMATS]
    for style in presets("maestro"):
        sv = style.startswith("sv_")
        for view in ("graph",) if sv else ("graph", "layered"):
            engine = ("--render-engine", "svg") if sv else ()
            for f in ("png", "svg") if sv else ("png",):
                jobs.append(
                    cli(
                        out / MA / STYLES_DIR / f"{style}__{view}",
                        TEMPLATES / "maestro/multi-agent-support.toml",
                        12,
                        f,
                        "-s",
                        style,
                        "-v",
                        view,
                        *engine,
                    )
                )

    # Binary visualization: the CLI writes <out>_<view>.<fmt>, so "<cfg>_" gives "<cfg>__<view>"
    for name, inp in BINVIS_INPUTS.items():
        d = out / BV / name
        for cfg, extra in (("default-config", ()), ("custom-config", ("-C", str(TEMPLATES / "binvis_config.toml")))):
            for view in BINVIS_VIEWS:
                jobs += [cli(d / f"{cfg}_", inp, 2, f, "-v", view, *extra) for f in SVG_FORMATS]
    for style in presets("binvis"):
        jobs.append(cli(out / BV / STYLES_DIR / style, "/bin/ls", 2, "png", "-s", style, "-v", "all"))

    # Custom diagrams (no CLI mode): every template, then every preset on one template
    for tpl in templates("custom-diagrams/*/*"):
        d = out / CD / tpl.parent.name / template_dir(tpl)
        jobs += [("custom", str(d / "diagram"), {"tpl": str(tpl), "fmt": f}) for f in GV_FORMATS]
    for style in presets("customdiagrams"):
        jobs.append(
            (
                "custom",
                str(out / CD / STYLES_DIR / style),
                {"tpl": str(TEMPLATES / "custom-diagrams/software/architecture.toml"), "fmt": "png", "style": style},
            )
        )

    # Cloud diagrams (two directions) and Mermaid (two themes)
    for tpl in templates("cloud/*/*"):
        d = out / CL / tpl.parent.name / template_dir(tpl)
        jobs += [cli(d / direction, tpl, 5, f, "-d", direction) for direction in ("TB", "LR") for f in GV_FORMATS]
    for tpl in templates("mermaid/*/*"):
        d = out / MM / tpl.parent.name / template_dir(tpl)
        jobs += [cli(d / theme, tpl, 4, f, "-t", theme) for theme in ("default", "dark") for f in SVG_FORMATS]

    # Shine pack: Graphviz SVG post-processed with --shine
    for name, mode, tpl in SHINE:
        jobs.append(cli(out / SH / name, TEMPLATES / tpl, mode, "svg", "--shine"))
    return jobs


def run_group(group: list[tuple]) -> list[tuple[str, str]]:
    """Run the jobs sharing one output base in order: Graphviz writes its
    source to the extensionless base path, so parallel formats would race."""
    return [run_job(job) for job in group]


def run_job(job: tuple) -> tuple[str, str]:
    """Run one job in a worker; returns (out_base, error or "")."""
    kind, base, params = job
    Path(base).parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            if kind == "cli":
                from usecvislib.usecvis import main

                code = main(params)
                if code:
                    return base, f"exit {code}: {buf.getvalue()[-400:]}"
            elif kind == "pytm":
                from usecvislib.threatmodeling import ThreatModeling

                ThreatModeling(params["tpl"], base, params["fmt"], "", engine="pytm").BuildThreatModel()
            else:
                from usecvislib.customdiagrams import CustomDiagrams

                cd = CustomDiagrams()
                cd.load(params["tpl"])
                if "style" in params and cd.settings:
                    cd.settings.style = params["style"]
                cd.BuildCustomDiagram(output=base, output_format=params["fmt"])
    except SystemExit as e:
        return base, f"exit {e.code}: {buf.getvalue()[-400:]}"
    except Exception as e:  # report every failure, keep going
        return base, f"{type(e).__name__}: {e}"
    return base, ""


# --------------------------------------------------------------------------- index

CSS = """
:root{--bg:#f6f7f9;--fg:#1f2937;--card:#fff;--line:#d6dbe1;--link:#2563eb;--muted:#6b7280}
@media (prefers-color-scheme: dark){:root{--bg:#111418;--fg:#e5e7eb;--card:#1b2026;--line:#2d343c;--link:#7aa7ff;--muted:#9ca3af}}
body{font-family:-apple-system,Helvetica,Arial,sans-serif;margin:0 24px 48px;background:var(--bg);color:var(--fg)}
nav{position:sticky;top:0;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--line);z-index:2}
nav a{margin-right:14px;font-size:13px;color:var(--link);text-decoration:none;white-space:nowrap}
h1 small{font-size:13px;font-weight:normal;color:var(--muted)}
h2{margin-top:36px;border-bottom:2px solid var(--fg);padding-bottom:4px}h3{margin:22px 0 8px;font-size:15px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px}
.card img{width:100%;height:190px;object-fit:contain;background:#fff;border-radius:4px;cursor:zoom-in}
.cap{font-size:12px;margin-top:6px;word-break:break-word}.cap a{color:var(--link);margin-right:6px}
"""


def anchor(category: str) -> str:
    """Stable section id: "01 Attack Trees" -> "attack-trees" (docs deep-link to these)."""
    return category.split(" ", 1)[1].lower().replace(" ", "-")


def write_index(out: Path, version: str) -> int:
    def href(p: Path) -> str:
        return html.escape(quote(p.relative_to(out).as_posix()), quote=True)

    parts, cards = [], 0
    nav = "".join(f"<a href='#{anchor(c)}'>{html.escape(c)}</a>\n" for c in CATEGORIES if (out / c).is_dir())
    for cat in CATEGORIES:
        root = out / cat
        if not root.is_dir():
            continue
        parts.append(f"<h2 id='{anchor(cat)}'>{html.escape(cat)}</h2>")
        groups = sorted(
            {p.parent for p in root.rglob("*") if p.is_file()},
            key=lambda d: (d.name != STYLES_DIR, d.relative_to(root).as_posix()),
        )
        for group in groups:
            title = group.relative_to(out / cat).as_posix()
            parts.append(f"<h3>{html.escape('' if title == '.' else title)}</h3><div class='grid'>")
            stems: dict[str, list[Path]] = {}
            for f in sorted(group.iterdir()):
                if f.is_file():
                    stems.setdefault(f.stem, []).append(f)
            for stem, files in stems.items():
                by_ext = {f.suffix[1:]: f for f in files}
                preview = by_ext.get("png") or by_ext.get("svg")
                if not preview:
                    continue
                links = "".join(
                    f"<a href='{href(by_ext[e])}' target='_blank'>{e}</a>"
                    for e in ("png", "svg", "pdf", "dot")
                    if e in by_ext
                )
                parts.append(
                    f"<div class='card'><a href='{href(preview)}' target='_blank'><img loading='lazy' "
                    f"alt='{html.escape(stem, quote=True)}' src='{href(preview)}'></a>"
                    f"<div class='cap'><b>{html.escape(stem)}</b><br>{links}</div></div>"
                )
                cards += 1
            parts.append("</div>")
    page = (
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>USecVisLib Gallery</title><style>{CSS}</style></head><body>"
        f"<h1>USecVisLib render gallery <small>v{html.escape(version)} · {cards} renders · "
        f"generated by scripts/build_gallery.py</small></h1><nav>{nav}</nav>\n" + "\n".join(parts) + "</body></html>"
    )
    (out / "index.html").write_text(page, encoding="utf-8")
    return cards


# Personal data that must never reach the published gallery. Home-directory
# paths are searched in every file; e-mail addresses only in text formats,
# since compressed PNG/PDF streams match the pattern by chance.
HOME_PATH = re.compile(rb"/Users/[^/\s\"']+|/home/[^/\s\"']+|/root/")
EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}")
TEXT_SUFFIXES = {".svg", ".dot", ".html", ".json"}
# Files the gallery repository owns; a rebuild neither deletes nor scans them.
KEEP = {"README.md", "LICENSE"}


def scan_private_data(out: Path) -> list[str]:
    """Outputs (with the offending match) that leak personal data."""
    hits = []
    for p in sorted(out.rglob("*")):
        rel = p.relative_to(out)
        if not p.is_file() or rel.name in KEEP or any(part.startswith(".") for part in rel.parts):
            continue
        data = p.read_bytes()
        m = HOME_PATH.search(data) or (EMAIL.search(data) if p.suffix in TEXT_SUFFIXES else None)
        if m:
            hits.append(f"{rel}: {m.group().decode('latin1')}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    ap.add_argument("out", type=Path, help="output directory (emptied first, except dotfiles, README.md and LICENSE)")
    ap.add_argument("-j", "--jobs", type=int, default=multiprocessing.cpu_count())
    args = ap.parse_args()

    out = args.out.resolve()
    if out.exists():
        for child in out.iterdir():
            if child.name.startswith(".") or child.name in KEEP:
                continue
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    out.mkdir(parents=True, exist_ok=True)

    # Fixed creation dates in PDF/SVG metadata, so unchanged renders stay byte-identical across rebuilds
    os.environ.setdefault("SOURCE_DATE_EPOCH", "1767225600")  # 2026-01-01
    jobs = build_jobs(out)
    groups: dict[str, list[tuple]] = {}
    for job in jobs:
        groups.setdefault(job[1], []).append(job)
    print(f"{len(jobs)} jobs, {args.jobs} workers -> {out}", flush=True)
    start, errors = time.time(), []
    with multiprocessing.Pool(args.jobs, maxtasksperchild=10) as pool:
        for n, results in enumerate(pool.imap_unordered(run_group, groups.values()), 1):
            for base, err in results:
                if err:
                    rel = Path(base).relative_to(out)
                    errors.append({"out": str(rel), "error": err})
                    print(f"FAIL {rel}: {err.splitlines()[0] if err else ''}", flush=True)
            if n % 50 == 0:
                print(f"  {n}/{len(groups)} outputs", flush=True)

    from usecvislib import __version__

    cards = write_index(out, __version__)
    files = [p for p in out.rglob("*") if p.is_file() and not p.relative_to(out).parts[0].startswith(".")]
    (out / "errors.json").write_text(json.dumps(errors, indent=2)) if errors else None
    print(f"done in {time.time() - start:.0f}s: {len(files)} files, {cards} cards, {len(errors)} errors", flush=True)
    leaks = scan_private_data(out)
    for leak in leaks:
        print(f"PRIVATE DATA {leak}", flush=True)
    print(f"private-data scan: {len(leaks)} hits", flush=True)
    return 1 if errors or leaks else 0


if __name__ == "__main__":
    sys.exit(main())
