#!/usr/bin/env python3
"""Plot bot positions from C++ CSV trace.

Auto-fetches trace from the running container via docker exec.

Usage:
    # Plot last 30 seconds (auto-fetch from container)
    uv run python plot_trace.py

    # Custom time window and map
    uv run python plot_trace.py --last 60 --map district_coop

    # From a local file
    uv run python plot_trace.py /path/to/smartbots_trace.csv

    # Animate: one frame per second of trace
    uv run python plot_trace.py --animate --output /tmp/trace_anim.gif
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import ndimage


# ---------------------------------------------------------------------------
# Map data
# ---------------------------------------------------------------------------

def find_data_dir() -> Path:
    """Locate the data/ directory relative to this script."""
    return Path(__file__).resolve().parent.parent / "data"


def find_nav_file(map_name: str) -> Path | None:
    repo_root = Path(__file__).resolve().parent.parent
    p = repo_root / "insurgency-server" / "server-files" / "insurgency" / "maps" / f"{map_name}.nav"
    return p if p.exists() else None


def load_nav_areas(nav_path: Path, floor_z: float, floor_tolerance: float
                   ) -> list[tuple[float, float, float, float]]:
    repo_root = Path(__file__).resolve().parent.parent
    nav_parser_dir = repo_root / "navMeshParser"
    if not nav_parser_dir.exists():
        return []
    sys.path.insert(0, str(nav_parser_dir))
    try:
        from parse_nav import parse_nav
    except ImportError:
        return []

    mesh = parse_nav(nav_path)
    rects = []
    for area in mesh.areas.values():
        avg_z = (area.nw.z + area.se.z + area.ne_z + area.sw_z) / 4
        if abs(avg_z - floor_z) < floor_tolerance:
            x_min = min(area.nw.x, area.se.x)
            x_max = max(area.nw.x, area.se.x)
            y_min = min(area.nw.y, area.se.y)
            y_max = max(area.nw.y, area.se.y)
            rects.append((x_min, y_min, x_max - x_min, y_max - y_min))
    return rects


def load_objectives(data_dir: Path, map_name: str) -> dict:
    p = data_dir / f"{map_name}_objectives.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def build_wall_grid(floor_points_2d: np.ndarray, cell: float = 16.0,
                    close_iterations: int = 2):
    x_min = floor_points_2d[:, 0].min() - cell * 2
    y_min = floor_points_2d[:, 1].min() - cell * 2
    x_max = floor_points_2d[:, 0].max() + cell * 2
    y_max = floor_points_2d[:, 1].max() + cell * 2

    nx = int((x_max - x_min) / cell) + 1
    ny = int((y_max - y_min) / cell) + 1

    grid = np.zeros((ny, nx), dtype=bool)
    xi = ((floor_points_2d[:, 0] - x_min) / cell).astype(int)
    yi = ((floor_points_2d[:, 1] - y_min) / cell).astype(int)
    grid[yi, xi] = True
    grid = ndimage.binary_closing(grid, structure=np.ones((3, 3)),
                                  iterations=close_iterations)

    xs = np.linspace(x_min, x_max, nx)
    ys = np.linspace(y_min, y_max, ny)
    return grid, xs, ys, cell


# ---------------------------------------------------------------------------
# Drawing
# ---------------------------------------------------------------------------

def draw_nav_walls(ax, nav_rects: list[tuple[float, float, float, float]]):
    from matplotlib.patches import Rectangle
    from matplotlib.collections import PatchCollection

    if not nav_rects:
        return
    ax.set_facecolor("#e0e0e0")
    patches = [Rectangle((x, y), w, h) for x, y, w, h in nav_rects]
    pc = PatchCollection(patches, facecolor="white", edgecolor="#d0d0d0",
                         linewidth=0.15, zorder=0)
    ax.add_collection(pc)


def draw_walls(ax, wall_grid, wall_xs, wall_ys, wall_cell: float):
    grid, xs, ys = wall_grid, wall_xs, wall_ys
    nx, ny = len(xs), len(ys)
    x_edges = np.linspace(xs[0] - wall_cell / 2, xs[-1] + wall_cell / 2, nx + 1)
    y_edges = np.linspace(ys[0] - wall_cell / 2, ys[-1] + wall_cell / 2, ny + 1)
    ax.pcolormesh(x_edges, y_edges, grid.astype(float),
                  cmap="Greys_r", alpha=0.12, zorder=0, rasterized=True)
    ax.contour(xs, ys, grid.astype(float), levels=[0.5],
               colors="#444", linewidths=0.8)


def draw_objectives(ax, objectives: dict):
    for name, info in objectives.items():
        if "center" not in info:
            continue
        c = info["center"]
        role = info.get("role", "")
        obj_type = info.get("type", "")

        if role == "objective":
            color = "#e74c3c" if obj_type == "destroy" else "#3498db"
            marker = "D" if obj_type == "destroy" else "s"
            ax.scatter(c[0], c[1], s=120, marker=marker, c=color,
                       edgecolors="black", linewidth=1.5, zorder=8)
            ax.annotate(name.upper(), xy=(c[0], c[1]),
                        xytext=(c[0] + 40, c[1] + 40), fontsize=7,
                        color=color, fontweight="bold",
                        arrowprops=dict(arrowstyle="-", color=color, alpha=0.4))
        elif role == "enemy_spawn":
            ax.scatter(c[0], c[1], s=80, marker="^", c="red",
                       edgecolors="darkred", linewidth=1, zorder=7, alpha=0.7)
            ax.annotate("ATTACKER\nSPAWN", xy=(c[0], c[1]),
                        xytext=(c[0] + 50, c[1] - 50), fontsize=6,
                        color="red", alpha=0.7)


def draw_bot_snapshot(ax, frame: pd.DataFrame, tab20):
    """Draw all bots at a single time instant."""
    bots = frame[frame["team"] == 3]  # insurgent bots
    players = frame[frame["team"] == 2]  # security players

    for _, row in bots.iterrows():
        bid = int(row["bot_id"])
        c = tab20[bid % 20]
        alive = bool(row["alive"])

        if not alive:
            ax.scatter(row["x"], row["y"], s=40, marker="x",
                       c="gray", alpha=0.3, zorder=3)
            continue

        # Bot position
        ax.scatter(row["x"], row["y"], s=50, c=[c], edgecolors="black",
                   linewidth=0.5, zorder=5)
        ax.annotate(f"B{bid}", xy=(row["x"], row["y"]),
                    xytext=(row["x"] + 25, row["y"] + 25), fontsize=6,
                    color=c, fontweight="bold")

        # Look direction from yaw
        yaw_rad = np.radians(row["yaw"])
        dx = np.cos(yaw_rad) * 100
        dy = np.sin(yaw_rad) * 100
        ax.arrow(row["x"], row["y"], dx, dy,
                 head_width=15, head_length=8, fc=c, ec=c,
                 alpha=0.5, linewidth=0.8, zorder=4)

        # Movement target
        tx, ty = row["target_x"], row["target_y"]
        if tx != 0 or ty != 0:
            ax.plot([row["x"], tx], [row["y"], ty],
                    "--", color=c, alpha=0.3, linewidth=0.8, zorder=3)
            ax.scatter(tx, ty, s=30, marker="x", c=[c],
                       linewidths=1.5, zorder=4, alpha=0.6)

        # Enemy indicator
        if row["has_enemy"]:
            ax.scatter(row["x"], row["y"], s=200, facecolors="none",
                       edgecolors="red", linewidth=2, zorder=6, alpha=0.7)

    # Players
    for _, row in players.iterrows():
        if not row["alive"]:
            continue
        ax.scatter(row["x"], row["y"], s=80, marker="s", c="red",
                   edgecolors="darkred", linewidth=1, zorder=6)
        ax.annotate(f"P{int(row['bot_id'])}", xy=(row["x"], row["y"]),
                    xytext=(row["x"] + 25, row["y"] - 25), fontsize=7,
                    color="darkred", fontweight="bold")


def draw_bot_trails(ax, df: pd.DataFrame, tab20, trail_seconds: float = 5.0):
    """Draw fading trails for each bot over the time window."""
    bots = df[df["team"] == 3]
    for bid, group in bots.groupby("bot_id"):
        alive = group[group["alive"] == 1]
        if len(alive) < 2:
            continue
        c = tab20[int(bid) % 20]
        xs = alive["x"].values
        ys = alive["y"].values
        n = len(xs)
        alphas = np.linspace(0.05, 0.4, n)
        for i in range(1, n):
            ax.plot(xs[i - 1:i + 1], ys[i - 1:i + 1],
                    "-", color=c, alpha=alphas[i], linewidth=1)


# ---------------------------------------------------------------------------
# Main modes
# ---------------------------------------------------------------------------

def plot_snapshot(args, df: pd.DataFrame, nav_rects, wall_data, objectives):
    """Plot the last N seconds as a single overview frame."""
    tab20 = plt.cm.tab20(np.linspace(0, 1, 20))

    t_max = df["time"].max()
    t_min = t_max - args.last
    window = df[df["time"] >= t_min]

    if window.empty:
        print("No data in time window.", file=sys.stderr)
        sys.exit(1)

    # Use last tick for positions
    last_tick = window["tick"].max()
    frame = window[window["tick"] == last_tick]

    fig, ax = plt.subplots(1, 1, figsize=(20, 14))

    if nav_rects is not None:
        draw_nav_walls(ax, nav_rects)
    elif wall_data is not None:
        draw_walls(ax, *wall_data)

    draw_objectives(ax, objectives)
    draw_bot_trails(ax, window, tab20)
    draw_bot_snapshot(ax, frame, tab20)

    # Auto-fit to bot positions
    alive = frame[frame["alive"] == 1]
    if len(alive) > 0:
        cx = (alive["x"].min() + alive["x"].max()) / 2
        cy = (alive["y"].min() + alive["y"].max()) / 2
        span = max(alive["x"].max() - alive["x"].min(),
                   alive["y"].max() - alive["y"].min()) / 2 + args.margin
    else:
        cx, cy, span = 0, 0, 2000

    ax.set_aspect("equal")
    ax.set_xlim(cx - span, cx + span)
    ax.set_ylim(cy - span, cy + span)
    ax.grid(True, alpha=0.15)

    n_bots = len(frame[(frame["team"] == 3) & (frame["alive"] == 1)])
    n_enemies = len(frame[(frame["team"] == 3) & (frame["has_enemy"] == 1)])
    obj_idx = int(frame["objective_idx"].iloc[0]) if len(frame) > 0 else -1

    ax.set_title(
        f"{args.map} — Trace snapshot (last {args.last:.0f}s)\n"
        f"tick {last_tick} | {n_bots} bots alive | {n_enemies} in combat | objective #{obj_idx}\n"
        f"Arrows = look dir | Dashed = move target | Red ring = has enemy",
        fontsize=12,
    )

    plt.tight_layout()
    plt.savefig(args.output, dpi=args.dpi, bbox_inches="tight")
    print(f"Saved to {args.output}")


def plot_animate(args, df: pd.DataFrame, nav_rects, wall_data, objectives):
    """Create an animated GIF with one frame per second."""
    from matplotlib.animation import FuncAnimation, PillowWriter

    tab20 = plt.cm.tab20(np.linspace(0, 1, 20))

    t_max = df["time"].max()
    t_min = t_max - args.last
    window = df[df["time"] >= t_min]

    if window.empty:
        print("No data in time window.", file=sys.stderr)
        sys.exit(1)

    # One frame per unique tick
    ticks = sorted(window["tick"].unique())

    # Compute fixed bounds from all positions
    alive_all = window[window["alive"] == 1]
    if len(alive_all) > 0:
        cx = (alive_all["x"].min() + alive_all["x"].max()) / 2
        cy = (alive_all["y"].min() + alive_all["y"].max()) / 2
        span = max(alive_all["x"].max() - alive_all["x"].min(),
                   alive_all["y"].max() - alive_all["y"].min()) / 2 + args.margin
    else:
        cx, cy, span = 0, 0, 2000

    fig, ax = plt.subplots(1, 1, figsize=(16, 12))

    def draw_frame(tick_idx):
        ax.clear()
        tick = ticks[tick_idx]
        frame = window[window["tick"] == tick]

        # Draw up to 5 seconds of trail
        trail_start_time = frame["time"].iloc[0] - 5.0
        trail = window[(window["time"] >= trail_start_time) & (window["tick"] <= tick)]

        if nav_rects is not None:
            draw_nav_walls(ax, nav_rects)
        elif wall_data is not None:
            draw_walls(ax, *wall_data)

        draw_objectives(ax, objectives)
        draw_bot_trails(ax, trail, tab20)
        draw_bot_snapshot(ax, frame, tab20)

        ax.set_aspect("equal")
        ax.set_xlim(cx - span, cx + span)
        ax.set_ylim(cy - span, cy + span)
        ax.grid(True, alpha=0.15)

        t = frame["time"].iloc[0] if len(frame) > 0 else 0
        ax.set_title(f"{args.map} — tick {tick} | t={t:.1f}s", fontsize=12)

    print(f"Rendering {len(ticks)} frames...")
    anim = FuncAnimation(fig, draw_frame, frames=len(ticks), interval=1000)
    anim.save(args.output, writer=PillowWriter(fps=1))
    print(f"Saved animation to {args.output}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("csv", nargs="?", default=None,
                        help="Path to smartbots_trace.csv (auto-fetched from container if omitted)")
    parser.add_argument("--last", type=float, default=30,
                        help="Show last N seconds of trace (default: 30)")
    parser.add_argument("--map", default="ministry_coop", help="Map name")
    parser.add_argument("--data-dir", default=None,
                        help="Path to precomputed map data (auto-detected)")
    parser.add_argument("--output", default="/tmp/trace.png",
                        help="Output image path (.png or .gif for --animate)")
    parser.add_argument("--animate", action="store_true",
                        help="Create animated GIF (1 fps)")
    parser.add_argument("--floor-z", type=float, default=32.0,
                        help="Floor Z height for wall rendering")
    parser.add_argument("--floor-tolerance", type=float, default=20.0,
                        help="Z tolerance for floor filter")
    parser.add_argument("--margin", type=float, default=500.0,
                        help="Zoom margin (units)")
    parser.add_argument("--dpi", type=int, default=150)
    args = parser.parse_args()

    # Fetch trace from container if no path given
    if args.csv is None:
        import subprocess, tempfile
        print("Fetching trace from insurgency-server container...")
        result = subprocess.run(
            ["docker", "exec", "insurgency-server",
             "cat", "/dev/shm/smartbots_trace.csv"],
            capture_output=True)
        if result.returncode != 0 or len(result.stdout) == 0:
            print("Failed to fetch trace from container.", file=sys.stderr)
            sys.exit(1)
        tmp = Path(tempfile.gettempdir()) / "smartbots_trace.csv"
        tmp.write_bytes(result.stdout)
        args.csv = str(tmp)
        print(f"  Saved to {args.csv}")

    # Load trace CSV
    print(f"Loading {args.csv}...")
    df = pd.read_csv(args.csv)
    print(f"  {len(df)} rows, {df['bot_id'].nunique()} unique bots, "
          f"time range {df['time'].min():.1f} - {df['time'].max():.1f}s")

    # Map data
    data_dir = Path(args.data_dir) if args.data_dir else find_data_dir()
    objectives = load_objectives(data_dir, args.map)

    # Wall rendering: prefer nav mesh, fall back to vismatrix
    nav_rects = None
    wall_data = None
    nav_path = find_nav_file(args.map)
    if nav_path:
        nav_rects = load_nav_areas(nav_path, args.floor_z, args.floor_tolerance)
        print(f"  Loaded {len(nav_rects)} nav areas from {nav_path.name}")
    else:
        vis_path = data_dir / f"{args.map}_vismatrix.npz"
        if vis_path.exists():
            vis = np.load(vis_path)
            points = vis["point_positions"]
            floor_mask = abs(points[:, 2] - args.floor_z) < args.floor_tolerance
            floor_pts_2d = points[floor_mask, :2]
            wall_data = build_wall_grid(floor_pts_2d)
            print(f"  Built wall grid from vismatrix ({len(floor_pts_2d)} floor points)")
        else:
            print("  No map data found (no nav file, no vismatrix)")

    if args.animate:
        plot_animate(args, df, nav_rects, wall_data, objectives)
    else:
        plot_snapshot(args, df, nav_rects, wall_data, objectives)


if __name__ == "__main__":
    main()
