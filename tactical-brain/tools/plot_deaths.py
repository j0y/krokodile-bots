#!/usr/bin/env python3
"""Plot recent bot deaths or live session overview.

Reads telemetry from PostgreSQL and overlays on the walk graph mesh so walls
are visible as gaps.

Usage:
    # Default: last 5 deaths, connect to localhost:5432
    python tools/plot_deaths.py

    # Custom
    python tools/plot_deaths.py --deaths 10 --output /tmp/deaths.png

    # Last 10 seconds of the session (all bots)
    python tools/plot_deaths.py --last 10 --output /tmp/overview.png

    # Use with docker compose
    python tools/plot_deaths.py --host localhost --port 5432
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import ndimage

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def connect_db(host: str, port: int, user: str, password: str, dbname: str):
    import psycopg
    return psycopg.connect(host=host, port=port, user=user, password=password, dbname=dbname)


def fetch_latest_session(conn) -> str | None:
    """Return the most recent session_id."""
    cur = conn.cursor()
    cur.execute("SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1")
    row = cur.fetchone()
    cur.close()
    return str(row[0]) if row else None


def fetch_deaths(conn, limit: int, session_id: str | None = None):
    """Return recent deaths: (bot_id, death_tick, px, py, pz, dist_to_player)."""
    cur = conn.cursor()
    session_filter = "AND bs.session_id = %s" if session_id else ""
    session_subq = f"AND bs2.session_id = '{session_id}'" if session_id else ""
    cur.execute(f"""
        WITH deaths AS (
            SELECT bot_id, tick, alive, session_id,
                   LAG(alive) OVER (PARTITION BY bot_id, session_id ORDER BY tick) AS prev_alive
            FROM bot_state
            {"WHERE session_id = %s" if session_id else ""}
        )
        SELECT d.bot_id, d.tick AS death_tick,
               bs.pos_x, bs.pos_y, bs.pos_z,
               bs.team, bs.is_bot,
               (SELECT bs2.pos_x FROM bot_state bs2 WHERE bs2.bot_id = 1 AND bs2.tick = d.tick {session_subq}) AS player_x,
               (SELECT bs2.pos_y FROM bot_state bs2 WHERE bs2.bot_id = 1 AND bs2.tick = d.tick {session_subq}) AS player_y,
               sqrt(power(bs.pos_x - (SELECT bs2.pos_x FROM bot_state bs2 WHERE bs2.bot_id = 1 AND bs2.tick = d.tick {session_subq}), 2) +
                    power(bs.pos_y - (SELECT bs2.pos_y FROM bot_state bs2 WHERE bs2.bot_id = 1 AND bs2.tick = d.tick {session_subq}), 2)) AS dist
        FROM deaths d
        JOIN bot_state bs ON bs.bot_id = d.bot_id AND bs.tick = d.tick AND bs.session_id = d.session_id
        WHERE d.alive = false AND d.prev_alive = true
        ORDER BY d.tick DESC
        LIMIT %s
    """, ([session_id] if session_id else []) + [limit])
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_death_trajectory(conn, bot_id: int, death_tick: int, lookback: int = 80,
                           session_id: str | None = None):
    """Return trajectory + look + player position for one death."""
    cur = conn.cursor()
    session_filter = "AND bc.session_id = %s" if session_id else ""
    session_bs = f"AND bs.session_id = '{session_id}'" if session_id else ""
    session_subq = f"AND bs2.session_id = '{session_id}'" if session_id else ""
    cur.execute(f"""
        SELECT bc.tick,
               bs.pos_x, bs.pos_y,
               bc.look_x, bc.look_y,
               bc.target_x, bc.target_y,
               bc.profile,
               (SELECT bs2.pos_x FROM bot_state bs2
                WHERE bs2.bot_id = 1 AND bs2.tick = bc.tick {session_subq}) AS plr_x,
               (SELECT bs2.pos_y FROM bot_state bs2
                WHERE bs2.bot_id = 1 AND bs2.tick = bc.tick {session_subq}) AS plr_y
        FROM bot_commands bc
        JOIN bot_state bs ON bs.bot_id = bc.bot_id AND bs.tick = bc.tick {session_bs}
        WHERE bc.bot_id = %s
          AND bc.tick BETWEEN %s AND %s
          {session_filter}
        ORDER BY bc.tick
    """, [bot_id, death_tick - lookback, death_tick] + ([session_id] if session_id else []))
    rows = cur.fetchall()
    cur.close()
    return rows


def fetch_session_tail(conn, session_id: str, seconds: float):
    """Return (bots, commands) for the last N seconds of the session.

    bots:  {bot_id: [(tick, x, y, is_bot, team)]}
    cmds:  {bot_id: [(tick, move_x, move_y, look_x, look_y)]}
    """
    cur = conn.cursor()
    cur.execute("SELECT max(tick) FROM bot_state WHERE session_id = %s", (session_id,))
    last_tick = cur.fetchone()[0]
    if last_tick is None:
        cur.close()
        return {}, {}, 0
    start_tick = last_tick - int(seconds * 66)

    cur.execute("""
        SELECT tick, bot_id, is_bot, team, pos_x, pos_y
        FROM bot_state
        WHERE session_id = %s AND tick >= %s AND alive = true
        ORDER BY tick, bot_id
    """, (session_id, start_tick))
    bots: dict[int, list] = {}
    for tick, bot_id, is_bot, team, x, y in cur.fetchall():
        bots.setdefault(bot_id, []).append(
            (tick, float(x), float(y), is_bot, team))

    cur.execute("""
        SELECT tick, bot_id, target_x, target_y, look_x, look_y
        FROM bot_commands
        WHERE session_id = %s AND tick >= %s
        ORDER BY tick, bot_id
    """, (session_id, start_tick))
    cmds: dict[int, list] = {}
    for tick, bot_id, mx, my, lx, ly in cur.fetchall():
        cmds.setdefault(bot_id, []).append(
            (tick, float(mx), float(my), float(lx), float(ly)))

    cur.close()
    return bots, cmds, last_tick


# ---------------------------------------------------------------------------
# Map data
# ---------------------------------------------------------------------------

def load_map_data(data_dir: Path, map_name: str):
    """Load vismatrix points and area definitions for wall rendering."""
    vis_path = data_dir / f"{map_name}_vismatrix.npz"
    vis = np.load(vis_path)
    points = vis["point_positions"]

    areas = {}
    areas_path = data_dir / f"{map_name}_areas.json"
    if areas_path.exists():
        import json
        with open(areas_path) as f:
            areas = json.load(f)

    return points, areas


def build_wall_grid(floor_points_2d: np.ndarray, cell: float = 16.0,
                    close_iterations: int = 2):
    """Build an occupancy grid from floor nav points and return contour-ready data.

    Returns (grid, xs, ys) where grid is a boolean 2D array and xs/ys are the
    world-space coordinates of each column/row for use with ax.contour().
    """
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

    # Morphological closing: bridge small gaps between nav points
    grid = ndimage.binary_closing(grid, structure=np.ones((3, 3)),
                                  iterations=close_iterations)

    xs = np.linspace(x_min, x_max, nx)
    ys = np.linspace(y_min, y_max, ny)
    return grid, xs, ys, cell


# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def draw_walls(ax, wall_grid, wall_xs, wall_ys, wall_cell: float):
    """Draw wall outlines from occupancy grid.  Light fill + contour edges."""
    grid, xs, ys = wall_grid, wall_xs, wall_ys
    nx, ny = len(xs), len(ys)

    # Light fill for walkable area
    x_edges = np.linspace(xs[0] - wall_cell / 2, xs[-1] + wall_cell / 2, nx + 1)
    y_edges = np.linspace(ys[0] - wall_cell / 2, ys[-1] + wall_cell / 2, ny + 1)
    ax.pcolormesh(x_edges, y_edges, grid.astype(float),
                  cmap="Greys_r", alpha=0.12, zorder=0, rasterized=True)

    # Wall outlines
    ax.contour(xs, ys, grid.astype(float), levels=[0.5],
               colors="#444", linewidths=0.8)


def draw_areas(ax, areas: dict, cx: float, cy: float, margin: float):
    """Draw named area polygons."""
    for area_name, area_info in areas.items():
        if "polygon" not in area_info:
            continue
        poly_pts = np.array(area_info["polygon"])
        pcx, pcy = poly_pts[:, 0].mean(), poly_pts[:, 1].mean()
        if abs(pcx - cx) < margin and abs(pcy - cy) < margin:
            ax.fill(poly_pts[:, 0], poly_pts[:, 1], alpha=0.06,
                    edgecolor="#aaa", linewidth=0.3)
            ax.text(pcx, pcy, area_name.replace("_", "\n"), fontsize=5,
                    ha="center", va="center", color="#999", style="italic")


def draw_trajectory(ax, traj: list, death_tick: int, dist: float, profile: str,
                    bot_id: int):
    """Draw one bot's trajectory with look arrows + player position."""
    if not traj:
        return

    n = len(traj)
    t_colors = plt.cm.Blues(np.linspace(0.3, 1.0, n))

    px = [r[1] for r in traj]
    py = [r[2] for r in traj]
    lx = [r[3] for r in traj]
    ly = [r[4] for r in traj]
    tx = traj[-1][5]
    ty = traj[-1][6]
    plr_x = [r[8] for r in traj]
    plr_y = [r[9] for r in traj]

    # Bot path
    ax.plot(px, py, "b-", linewidth=1.5, alpha=0.3, zorder=2)
    for i in range(n):
        ax.scatter(px[i], py[i], c=[t_colors[i]], s=30, zorder=3,
                   edgecolors="blue", linewidth=0.3)
        if lx[i] is not None and ly[i] is not None:
            dx = lx[i] - px[i]
            dy = ly[i] - py[i]
            length = (dx ** 2 + dy ** 2) ** 0.5
            if length > 0:
                scale = min(120.0, length) / length
                ax.annotate("", xy=(px[i] + dx * scale, py[i] + dy * scale),
                            xytext=(px[i], py[i]),
                            arrowprops=dict(arrowstyle="->", color=t_colors[i],
                                            lw=1.5, alpha=0.7),
                            zorder=4)

    # Full look line from last position
    if lx[-1] is not None and ly[-1] is not None:
        ax.plot([px[-1], lx[-1]], [py[-1], ly[-1]],
                "b--", alpha=0.25, linewidth=1, zorder=1)

    # Player path
    valid_plr = [(x, y) for x, y in zip(plr_x, plr_y) if x is not None]
    if valid_plr:
        ax.plot([p[0] for p in valid_plr], [p[1] for p in valid_plr],
                "r-", linewidth=1.5, alpha=0.3, zorder=2)
        for i in range(n):
            if plr_x[i] is not None:
                ax.scatter(plr_x[i], plr_y[i], c=[t_colors[i]], s=25, zorder=3,
                           marker="s", edgecolors="red", linewidth=0.3)

    # Move target
    if tx is not None and ty is not None:
        ax.scatter(tx, ty, s=100, marker="x", c="green", linewidths=2.5, zorder=5)

    # Death marker
    ax.scatter(px[-1], py[-1], s=150, marker="X", c="red", linewidths=2.5, zorder=6)

    ax.annotate("DEATH", xy=(px[-1], py[-1]),
                xytext=(px[-1] - 15, py[-1] + 20), fontsize=7,
                color="red", fontweight="bold")
    if valid_plr:
        ax.annotate("YOU", xy=(valid_plr[-1]),
                    xytext=(valid_plr[-1][0] + 15, valid_plr[-1][1] + 15),
                    fontsize=7, color="darkred", fontweight="bold")

    ax.set_title(f"Bot {bot_id} — {profile or '?'} — {dist:.0f}u from you\n"
                 f"killed at tick {death_tick}", fontsize=10, fontweight="bold")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

BOT_COLORS = ["blue", "purple", "green", "orange", "red", "cyan", "magenta", "brown"]


def plot_session_tail(args, conn, session_id: str, points, areas):
    """Plot the last N seconds of a session showing all bots + player."""
    floor_mask = abs(points[:, 2] - args.floor_z) < args.floor_tolerance
    floor_pts_2d = points[floor_mask, :2]
    wall_grid, wall_xs, wall_ys, wall_cell = build_wall_grid(floor_pts_2d)

    bots, cmds, last_tick = fetch_session_tail(conn, session_id, args.last)
    if not bots:
        print("No data in session.", file=sys.stderr)
        sys.exit(1)

    # Separate player from bots
    player_data = None
    bot_ids = []
    for bid, traj in bots.items():
        if traj and not traj[0][3]:  # is_bot == False
            player_data = traj
        else:
            bot_ids.append(bid)

    fig, ax = plt.subplots(1, 1, figsize=(20, 14))
    draw_walls(ax, wall_grid, wall_xs, wall_ys, wall_cell)

    # Compute bounds from all bot/player positions for area overlay
    all_x = [p[1] for traj in bots.values() for p in traj]
    all_y = [p[2] for traj in bots.values() for p in traj]
    cx = (min(all_x) + max(all_x)) / 2
    cy = (min(all_y) + max(all_y)) / 2
    span = max(max(all_x) - min(all_x), max(all_y) - min(all_y)) / 2 + args.margin
    draw_areas(ax, areas, cx, cy, span)

    tab20 = plt.cm.tab20(np.linspace(0, 1, 20))

    for bid in bot_ids:
        traj = bots[bid]
        xs = [p[1] for p in traj]
        ys = [p[2] for p in traj]
        c = tab20[bid % 20]

        ax.plot(xs, ys, "-", color=c, alpha=0.4, linewidth=1)
        ax.plot(xs[-1], ys[-1], "o", color=c, markersize=6)
        ax.text(xs[-1] + 20, ys[-1] + 20, f"B{bid}", fontsize=7,
                color=c, fontweight="bold")

        if bid in cmds:
            cmd_list = cmds[bid]
            for i in range(0, len(cmd_list), 5):
                tick, mx, my, lx, ly = cmd_list[i]
                # Find bot pos at this tick
                pos_at = None
                for t, bx, by, _, _ in traj:
                    if t == tick:
                        pos_at = (bx, by)
                        break
                if pos_at is None:
                    continue
                dx = lx - pos_at[0]
                dy = ly - pos_at[1]
                length = (dx * dx + dy * dy) ** 0.5
                if length > 1:
                    scale = 150 / length
                    ax.arrow(pos_at[0], pos_at[1], dx * scale, dy * scale,
                             head_width=20, head_length=10, fc=c, ec=c,
                             alpha=0.5, linewidth=0.8)

    if player_data:
        px = [p[1] for p in player_data]
        py = [p[2] for p in player_data]
        ax.plot(px, py, "-", color="red", linewidth=2, alpha=0.6)
        ax.plot(px[-1], py[-1], "s", color="red", markersize=10)
        ax.text(px[-1] + 20, py[-1] + 20, "YOU", fontsize=9,
                color="red", fontweight="bold")

    ax.set_aspect("equal")
    ax.set_xlim(cx - span, cx + span)
    ax.set_ylim(cy - span, cy + span)
    ax.grid(True, alpha=0.2)
    start_tick = last_tick - int(args.last * 66)
    ax.set_title(
        f"{args.map} — Last {args.last:.0f}s of session {session_id[:8]}\n"
        f"ticks {start_tick}-{last_tick} | Arrows = look direction",
        fontsize=14,
    )

    plt.tight_layout()
    plt.savefig(args.output, dpi=args.dpi, bbox_inches="tight")
    print(f"Saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--deaths", type=int, default=5, help="Number of recent deaths to plot")
    parser.add_argument("--last", type=float, default=0,
                        help="Plot last N seconds of session (all bots overview). 0 = deaths mode.")
    parser.add_argument("--session", default="latest",
                        help="Session ID or 'latest' (default) or 'all'")
    parser.add_argument("--host", default="localhost", help="Telemetry DB host")
    parser.add_argument("--port", type=int, default=5432, help="Telemetry DB port")
    parser.add_argument("--user", default="smartbots")
    parser.add_argument("--password", default="smartbots")
    parser.add_argument("--dbname", default="telemetry")
    parser.add_argument("--map", default="ministry_coop", help="Map name")
    parser.add_argument("--data-dir", default="data", help="Path to precomputed map data")
    parser.add_argument("--output", default="/tmp/deaths.png", help="Output image path")
    parser.add_argument("--floor-z", type=float, default=32.0, help="Floor Z height")
    parser.add_argument("--floor-tolerance", type=float, default=20.0, help="Z tolerance for floor filter")
    parser.add_argument("--margin", type=float, default=300.0, help="Zoom margin per panel (units)")
    parser.add_argument("--lookback", type=int, default=80, help="Ticks before death to show")
    parser.add_argument("--dpi", type=int, default=150)
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    points, areas = load_map_data(data_dir, args.map)

    conn = connect_db(args.host, args.port, args.user, args.password, args.dbname)

    session_id = None
    if args.session == "latest":
        session_id = fetch_latest_session(conn)
        if session_id:
            print(f"Using latest session: {session_id}")
    elif args.session != "all":
        session_id = args.session

    # --last mode: overview of all bots in the last N seconds
    if args.last > 0:
        if not session_id:
            print("No session found.", file=sys.stderr)
            sys.exit(1)
        plot_session_tail(args, conn, session_id, points, areas)
        conn.close()
        return

    floor_mask = abs(points[:, 2] - args.floor_z) < args.floor_tolerance
    floor_pts_2d = points[floor_mask, :2]
    wall_grid, wall_xs, wall_ys, wall_cell = build_wall_grid(floor_pts_2d)

    deaths = fetch_deaths(conn, args.deaths, session_id=session_id)

    if not deaths:
        print("No deaths found in telemetry.", file=sys.stderr)
        sys.exit(1)

    n_deaths = len(deaths)
    # Layout: overview + one panel per death
    n_panels = n_deaths + 1
    cols = min(3, n_panels)
    rows = (n_panels + cols - 1) // cols

    fig, axes = plt.subplots(rows, cols, figsize=(8 * cols, 8 * rows))
    if rows * cols == 1:
        axes = np.array([axes])
    axes_flat = axes.flatten()

    # Hide unused panels
    for i in range(n_panels, len(axes_flat)):
        axes_flat[i].set_visible(False)

    # ---- Overview panel ----
    ax0 = axes_flat[0]
    all_x = [d[2] for d in deaths]
    all_y = [d[3] for d in deaths]
    overview_cx = (min(all_x) + max(all_x)) / 2
    overview_cy = (min(all_y) + max(all_y)) / 2
    overview_margin = max(max(all_x) - min(all_x), max(all_y) - min(all_y)) / 2 + 400

    draw_walls(ax0, wall_grid, wall_xs, wall_ys, wall_cell)
    draw_areas(ax0, areas, overview_cx, overview_cy, overview_margin)

    for i, d in enumerate(deaths):
        bot_id, death_tick, px, py, pz, team, is_bot, player_x, player_y, dist = d
        color = BOT_COLORS[i % len(BOT_COLORS)]
        ax0.scatter(px, py, s=100, marker="X", c=color, zorder=6, linewidths=2)
        ax0.annotate(f"Bot {bot_id}\n({dist:.0f}u)", xy=(px, py),
                     xytext=(px + 40, py + 25), fontsize=7, color=color, fontweight="bold")
        if player_x is not None and player_y is not None:
            ax0.scatter(player_x, player_y, s=40, marker="s", c="lime",
                        edgecolors=color, linewidth=1.5, zorder=6)

    ax0.set_title("Overview — all deaths\n(X = death, square = your position)", fontsize=10)
    ax0.set_aspect("equal")
    ax0.set_xlim(overview_cx - overview_margin, overview_cx + overview_margin)
    ax0.set_ylim(overview_cy - overview_margin, overview_cy + overview_margin)
    ax0.grid(True, alpha=0.1)

    # ---- Individual panels ----
    for i, d in enumerate(deaths):
        bot_id, death_tick, px, py, pz, team, is_bot, player_x, player_y, dist = d
        ax = axes_flat[i + 1]

        traj = fetch_death_trajectory(conn, bot_id, death_tick, args.lookback,
                                      session_id=session_id)
        profile = traj[-1][7] if traj else "?"

        draw_walls(ax, wall_grid, wall_xs, wall_ys, wall_cell)
        draw_areas(ax, areas, px, py, args.margin)
        draw_trajectory(ax, traj, death_tick, dist, profile, bot_id)

        ax.set_aspect("equal")
        ax.set_xlim(px - args.margin, px + args.margin)
        ax.set_ylim(py - args.margin, py + args.margin)
        ax.grid(True, alpha=0.1)

    conn.close()

    plt.suptitle(
        f"{args.map} — Last {n_deaths} Bot Deaths\n"
        "Blue arrows = bot look dir | Dashed = look line | Grey = walkable | Dark outline = walls",
        fontsize=13, y=0.99,
    )
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(args.output, dpi=args.dpi)
    print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
