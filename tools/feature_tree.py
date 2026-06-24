#!/usr/bin/env python3
"""Render the APKLeaks-for-AI-Agents feature tree as a mind-map.

Pure standard library — no Mermaid, Graphviz, or third-party deps. The same
tree definition produces two outputs:

  * an SVG mind-map (left root, branches fanning right) for embedding in the
    README as a plain ``![](...)`` image — renders everywhere, unlike Mermaid;
  * an ASCII tree (``--ascii``) for a 100%-visible text fallback.

Usage:
    python3 tools/feature_tree.py --svg docs/feature-tree.svg
    python3 tools/feature_tree.py --ascii
    python3 tools/feature_tree.py            # both (svg to default path + ascii)
"""
from __future__ import annotations

import argparse
import html
from dataclasses import dataclass, field

# --- the product feature tree -------------------------------------------------
# (label, [children]); keep node text English so the figure is shared verbatim
# between README.md and README.zh-CN.md.
TREE = (
    "APKLeaks for AI Agents",
    [
        ("Built on upstream", [
            ("Fork of dwisiswant0/apkleaks", []),
            ("Scanning engine unchanged", []),
            ("AI-native layer added on top", []),
        ]),
        ("Agent access surfaces", [
            ("MCP server — 12 tools / 4 resources / 4 prompts", []),
            ("Structured-JSON CLI — 13 subcommands", []),
            ("Claude Code skills — 9 rev-* skills", []),
        ]),
        ("Core capabilities", [
            ("check / info", []),
            ("scan — severity-graded", []),
            ("decompile / search", []),
            ("explain — impact + fix", []),
            ("rule add / test / remove", []),
        ]),
        ("Detection coverage", [
            ("95+ patterns", []),
            ("12 categories", []),
        ]),
        ("Agent contract", [
            ("ok flag + stable error_code", []),
            ("schema self-discovery", []),
            ("has_critical triage", []),
        ]),
    ],
)

# branch palette (one hue per first-level branch, inherited by its leaves)
PALETTE = ["#2563eb", "#7c3aed", "#059669", "#d97706", "#dc2626", "#0891b2"]


# --- layout -------------------------------------------------------------------
@dataclass
class Node:
    label: str
    children: list["Node"] = field(default_factory=list)
    depth: int = 0
    color: str = "#334155"
    x: float = 0.0
    y: float = 0.0
    w: float = 0.0


ROW_H = 34          # vertical spacing between leaves
COL_GAP = 46        # horizontal gap between columns
PAD_X = 14          # text padding inside a node box
CHAR_W = 7.4        # approx width of one char at the chosen font size
BOX_H = 27
MARGIN = 22


def build(raw, depth=0, color=None) -> Node:
    label, kids = raw
    node = Node(label=label, depth=depth, color=color or "#334155")
    for i, kid in enumerate(kids):
        c = PALETTE[i % len(PALETTE)] if depth == 0 else node.color
        node.children.append(build(kid, depth + 1, c))
    return node


def measure(node: Node) -> None:
    node.w = len(node.label) * CHAR_W + PAD_X * 2
    for c in node.children:
        measure(c)


def column_x(node: Node, col_left: dict[int, float]) -> None:
    """Assign each node an x so every column starts past the widest box of the
    previous column."""
    node.x = col_left[node.depth]
    nxt = node.x + node.w + COL_GAP
    for c in node.children:
        col_left[c.depth] = max(col_left.get(c.depth, 0.0), nxt)
    for c in node.children:
        column_x(c, col_left)


def assign_y(node: Node, cursor: list[float]) -> float:
    if not node.children:
        node.y = cursor[0]
        cursor[0] += ROW_H
        return node.y
    ys = [assign_y(c, cursor) for c in node.children]
    node.y = (ys[0] + ys[-1]) / 2
    return node.y


def widest_per_column(node: Node, cols: dict[int, float]) -> None:
    cols[node.depth] = max(cols.get(node.depth, 0.0), node.w)
    for c in node.children:
        widest_per_column(c, cols)


# --- SVG emit -----------------------------------------------------------------
def svg(node: Node) -> str:
    measure(node)
    cols: dict[int, float] = {}
    widest_per_column(node, cols)
    col_left = {0: float(MARGIN)}
    column_x(node, col_left)
    assign_y(node, [float(MARGIN) + BOX_H])

    nodes: list[Node] = []
    edges: list[tuple[Node, Node]] = []

    def walk(n: Node):
        nodes.append(n)
        for c in n.children:
            edges.append((n, c))
            walk(c)
    walk(node)

    width = max(n.x + n.w for n in nodes) + MARGIN
    height = max(n.y for n in nodes) + BOX_H + MARGIN

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
        f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">'
    )
    # light card background so it stays readable under GitHub light AND dark theme
    parts.append(
        f'<rect x="0" y="0" width="{width:.0f}" height="{height:.0f}" rx="12" '
        f'fill="#f6f8fa" stroke="#d0d7de"/>'
    )
    # edges (cubic bezier from parent right-mid to child left-mid)
    for p, c in edges:
        x1, y1 = p.x + p.w, p.y + BOX_H / 2
        x2, y2 = c.x, c.y + BOX_H / 2
        mx = (x1 + x2) / 2
        parts.append(
            f'<path d="M{x1:.1f},{y1:.1f} C{mx:.1f},{y1:.1f} {mx:.1f},{y2:.1f} '
            f'{x2:.1f},{y2:.1f}" fill="none" stroke="{c.color}" '
            f'stroke-width="1.6" opacity="0.55"/>'
        )
    # boxes
    for n in nodes:
        label = html.escape(n.label)
        ty = n.y + BOX_H / 2 + 4
        if n.depth == 0:                       # root: solid dark, white text
            parts.append(
                f'<rect x="{n.x:.1f}" y="{n.y:.1f}" width="{n.w:.1f}" '
                f'height="{BOX_H}" rx="8" fill="#0f172a"/>'
                f'<text x="{n.x + n.w/2:.1f}" y="{ty:.1f}" text-anchor="middle" '
                f'fill="#ffffff" font-size="13.5" font-weight="700">{label}</text>'
            )
        elif n.depth == 1:                     # branch: solid colour, white text
            parts.append(
                f'<rect x="{n.x:.1f}" y="{n.y:.1f}" width="{n.w:.1f}" '
                f'height="{BOX_H}" rx="7" fill="{n.color}"/>'
                f'<text x="{n.x + n.w/2:.1f}" y="{ty:.1f}" text-anchor="middle" '
                f'fill="#ffffff" font-size="12.5" font-weight="600">{label}</text>'
            )
        else:                                  # leaf: white card, coloured left bar
            parts.append(
                f'<rect x="{n.x:.1f}" y="{n.y:.1f}" width="{n.w:.1f}" '
                f'height="{BOX_H}" rx="6" fill="#ffffff" stroke="{n.color}" '
                f'stroke-width="1.2"/>'
                f'<rect x="{n.x:.1f}" y="{n.y:.1f}" width="4" height="{BOX_H}" '
                f'rx="2" fill="{n.color}"/>'
                f'<text x="{n.x + PAD_X:.1f}" y="{ty:.1f}" '
                f'fill="#1f2937" font-size="12">{label}</text>'
            )
    parts.append("</svg>")
    return "\n".join(parts)


# --- ASCII emit ---------------------------------------------------------------
def ascii_tree(raw, prefix="", is_last=True, is_root=True) -> list[str]:
    label, kids = raw
    if is_root:
        lines = [label]
    else:
        lines = [prefix + ("└─ " if is_last else "├─ ") + label]
    child_prefix = "" if is_root else prefix + ("   " if is_last else "│  ")
    for i, kid in enumerate(kids):
        lines += ascii_tree(kid, child_prefix, i == len(kids) - 1, False)
    return lines


def main() -> None:
    ap = argparse.ArgumentParser(description="Render the feature tree mind-map.")
    ap.add_argument("--svg", metavar="PATH", help="write SVG mind-map to PATH")
    ap.add_argument("--ascii", action="store_true", help="print ASCII tree")
    args = ap.parse_args()

    do_default = not args.svg and not args.ascii
    svg_path = args.svg or ("docs/feature-tree.svg" if do_default else None)

    if svg_path:
        out = svg(build(TREE))
        with open(svg_path, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"[svg ] wrote {svg_path} ({len(out)} bytes)")

    if args.ascii or do_default:
        print("\n".join(ascii_tree(TREE)))


if __name__ == "__main__":
    main()
