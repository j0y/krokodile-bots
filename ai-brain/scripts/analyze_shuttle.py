#!/usr/bin/env python3
"""Layered telemetry analyzer — physical movement, local nav quality, goal completion.

Subcommands:
    summary              Per-bot overview (default)
    trace --bot N        Tick-by-tick trajectory for one bot
    areas                Per-area navigation quality
    arrivals             Goal completion stats (optional, needs arrival_telemetry)

Examples:
    uv run python scripts/analyze_shuttle.py
    uv run python scripts/analyze_shuttle.py trace --bot 3 --from 1000 --to 2000
    uv run python scripts/analyze_shuttle.py areas --stuck
    uv run python scripts/analyze_shuttle.py areas --deviation 50
    uv run python scripts/analyze_shuttle.py arrivals --err2d 30
    uv run python scripts/analyze_shuttle.py arrivals --csv
"""

from __future__ import annotations

import argparse
import csv
import math
import sys

import psycopg


# ── DB connection ──────────────────────────────────────────────────────


def connect(host: str, port: int) -> psycopg.Connection:
    conninfo = f"host={host} port={port} dbname=telemetry user=smartbots password=smartbots"
    return psycopg.connect(conninfo, autocommit=True)


def table_exists(conn: psycopg.Connection, name: str) -> bool:
    with conn.cursor() as cur:
        cur.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = %s)",
            (name,),
        )
        row = cur.fetchone()
        return bool(row and row[0])


# ── Output ─────────────────────────────────────────────────────────────


def print_table(
    rows: list[dict], columns: list[tuple[str, str, int]], *, csv_mode: bool,
) -> None:
    """Print rows as aligned table or CSV.

    *columns* is [(key, header, width), ...].  Width is used for alignment;
    negative = left-align, positive = right-align.
    """
    if not rows:
        print("No data.")
        return

    keys = [c[0] for c in columns]
    headers = [c[1] for c in columns]
    widths = [c[2] for c in columns]

    if csv_mode:
        writer = csv.DictWriter(sys.stdout, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return

    # Header
    parts = []
    for header, w in zip(headers, widths):
        aw = abs(w)
        if w < 0:
            parts.append(f"{header:<{aw}}")
        else:
            parts.append(f"{header:>{aw}}")
    print("  ".join(parts))
    print("-" * (sum(abs(w) for w in widths) + 2 * (len(widths) - 1)))

    # Rows
    for row in rows:
        parts = []
        for key, _, w in columns:
            val = row.get(key, "")
            aw = abs(w)
            if val is None:
                s = "-"
            elif isinstance(val, float):
                s = f"{val:.1f}"
            elif isinstance(val, bool):
                s = "Y" if val else ""
            else:
                s = str(val)
            if w < 0:
                parts.append(f"{s:<{aw}}")
            else:
                parts.append(f"{s:>{aw}}")
        print("  ".join(parts))


# ── summary ────────────────────────────────────────────────────────────


def cmd_summary(conn: psycopg.Connection, args: argparse.Namespace) -> None:
    bot_filter = "AND bot_id = %s" if args.bot is not None else ""
    params: list = [args.bot] if args.bot is not None else []

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT bot_id, tick, x, y, z, deviation, stuck_count, area_id
            FROM nav_telemetry
            WHERE 1=1 {bot_filter}
            ORDER BY bot_id, tick
            """,
            params,
        )
        nav_rows = cur.fetchall()

    if not nav_rows:
        print("No nav_telemetry data.")
        return

    # Group by bot
    bots: dict[int, list[tuple]] = {}
    for row in nav_rows:
        bots.setdefault(row[0], []).append(row)

    # Arrival counts (optional)
    arrival_counts: dict[int, int] = {}
    if table_exists(conn, "arrival_telemetry"):
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT bot_id, COUNT(*) FROM arrival_telemetry
                WHERE 1=1 {bot_filter}
                GROUP BY bot_id
                """,
                params,
            )
            for bid, cnt in cur.fetchall():
                arrival_counts[bid] = cnt

    result: list[dict] = []
    for bot_id in sorted(bots):
        rows = bots[bot_id]
        n = len(rows)

        # Speed: 2D distance between consecutive ticks
        speeds: list[float] = []
        for i in range(1, n):
            dx = rows[i][2] - rows[i - 1][2]
            dy = rows[i][3] - rows[i - 1][3]
            speeds.append(math.sqrt(dx * dx + dy * dy))

        areas = len({r[7] for r in rows})
        avg_speed = sum(speeds) / len(speeds) if speeds else 0.0
        stall_count = sum(1 for s in speeds if s < 1.0)
        stall_pct = 100.0 * stall_count / len(speeds) if speeds else 0.0
        avg_dev = sum(r[5] for r in rows) / n
        stuck_ticks = sum(1 for r in rows if r[6] > 0)

        result.append({
            "bot": bot_id,
            "ticks": n,
            "areas": areas,
            "avg_speed": avg_speed,
            "stall_pct": stall_pct,
            "avg_dev": avg_dev,
            "stuck": stuck_ticks,
            "arrivals": arrival_counts.get(bot_id, 0),
        })

    columns = [
        ("bot", "Bot", 5),
        ("ticks", "Ticks", 7),
        ("areas", "Areas", 6),
        ("avg_speed", "Speed", 7),
        ("stall_pct", "Stall%", 7),
        ("avg_dev", "AvgDev", 7),
        ("stuck", "Stuck", 6),
        ("arrivals", "Arrv", 5),
    ]
    print_table(result, columns, csv_mode=args.csv)


# ── trace ──────────────────────────────────────────────────────────────


def cmd_trace(conn: psycopg.Connection, args: argparse.Namespace) -> None:
    if args.bot is None:
        print("Error: --bot is required for trace", file=sys.stderr)
        sys.exit(1)

    conditions = ["bot_id = %s"]
    params: list = [args.bot]

    if args.tick_from is not None:
        conditions.append("tick >= %s")
        params.append(args.tick_from)
    if args.tick_to is not None:
        conditions.append("tick <= %s")
        params.append(args.tick_to)

    where = " AND ".join(conditions)

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT tick, x, y, z, area_id, deviation, stuck_count, flags,
                   goal_x, goal_y
            FROM nav_telemetry
            WHERE {where}
            ORDER BY tick
            """,
            params,
        )
        rows = cur.fetchall()

    if not rows:
        print("No data for this bot/range.")
        return

    result: list[dict] = []
    prev_x, prev_y = rows[0][1], rows[0][2]
    for row in rows:
        tick, x, y, z, area_id, deviation, stuck, flags, gx, gy = row
        speed = math.sqrt((x - prev_x) ** 2 + (y - prev_y) ** 2)
        dist_goal = math.sqrt((x - gx) ** 2 + (y - gy) ** 2)
        result.append({
            "tick": tick,
            "x": x,
            "y": y,
            "z": z,
            "speed": speed,
            "area": area_id,
            "dev": deviation,
            "stuck": stuck,
            "d_goal": dist_goal,
            "flags": flags,
        })
        prev_x, prev_y = x, y

    columns = [
        ("tick", "Tick", 7),
        ("x", "X", 8),
        ("y", "Y", 8),
        ("z", "Z", 7),
        ("speed", "Speed", 7),
        ("area", "Area", 6),
        ("dev", "Dev", 7),
        ("stuck", "Stk", 4),
        ("d_goal", "DGoal", 7),
        ("flags", "Flg", 4),
    ]
    print_table(result, columns, csv_mode=args.csv)


# ── areas ──────────────────────────────────────────────────────────────


def cmd_areas(conn: psycopg.Connection, args: argparse.Namespace) -> None:
    bot_filter = "AND bot_id = %s" if args.bot is not None else ""
    params: list = [args.bot] if args.bot is not None else []

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT area_id, bot_id, deviation, stuck_count, x, y, tick
            FROM nav_telemetry
            WHERE 1=1 {bot_filter}
            ORDER BY area_id, bot_id, tick
            """,
            params,
        )
        nav_rows = cur.fetchall()

    if not nav_rows:
        print("No nav_telemetry data.")
        return

    # Group by area
    areas: dict[int, list[tuple]] = {}
    for row in nav_rows:
        areas.setdefault(row[0], []).append(row)

    result: list[dict] = []
    for area_id in sorted(areas):
        rows = areas[area_id]
        n = len(rows)
        bot_ids = {r[1] for r in rows}
        devs = [r[2] for r in rows]
        avg_dev = sum(devs) / n
        max_dev = max(devs)
        stuck = sum(1 for r in rows if r[3] > 0)

        # Avg speed within area per bot
        speeds: list[float] = []
        by_bot: dict[int, list[tuple]] = {}
        for r in rows:
            by_bot.setdefault(r[1], []).append(r)
        for bot_rows in by_bot.values():
            for i in range(1, len(bot_rows)):
                dx = bot_rows[i][4] - bot_rows[i - 1][4]
                dy = bot_rows[i][5] - bot_rows[i - 1][5]
                speeds.append(math.sqrt(dx * dx + dy * dy))

        avg_speed = sum(speeds) / len(speeds) if speeds else 0.0

        row_dict = {
            "area": area_id,
            "ticks": n,
            "bots": len(bot_ids),
            "avg_dev": avg_dev,
            "max_dev": max_dev,
            "stuck": stuck,
            "avg_speed": avg_speed,
        }

        # Apply threshold filters
        if args.deviation is not None and avg_dev < args.deviation:
            continue
        if args.stuck and stuck == 0:
            continue

        result.append(row_dict)

    columns = [
        ("area", "Area", 7),
        ("ticks", "Ticks", 7),
        ("bots", "Bots", 5),
        ("avg_dev", "AvgDev", 7),
        ("max_dev", "MaxDev", 7),
        ("stuck", "Stuck", 6),
        ("avg_speed", "Speed", 7),
    ]
    print_table(result, columns, csv_mode=args.csv)


# ── arrivals ───────────────────────────────────────────────────────────


def compute_path_metrics(
    conn: psycopg.Connection, bot_id: int, t0: int, t1: int,
    gx: float, gy: float, sx: float, sy: float,
) -> dict:
    """Compute path_length, straight_dist, efficiency for a tick range."""
    if t0 >= t1 or t0 == 0:
        return {"path_length": None, "straight_dist": None, "efficiency": None}

    with conn.cursor() as cur:
        cur.execute(
            "SELECT x, y FROM nav_telemetry "
            "WHERE bot_id = %s AND tick >= %s AND tick <= %s ORDER BY tick",
            (bot_id, t0, t1),
        )
        points = cur.fetchall()

    if len(points) < 2:
        return {"path_length": None, "straight_dist": None, "efficiency": None}

    path_length = 0.0
    for i in range(1, len(points)):
        dx = points[i][0] - points[i - 1][0]
        dy = points[i][1] - points[i - 1][1]
        path_length += math.sqrt(dx * dx + dy * dy)

    straight_dist = math.sqrt((gx - sx) ** 2 + (gy - sy) ** 2)
    efficiency = path_length / straight_dist if straight_dist > 1.0 else None

    return {
        "path_length": path_length,
        "straight_dist": straight_dist,
        "efficiency": efficiency,
    }


def cmd_arrivals(conn: psycopg.Connection, args: argparse.Namespace) -> None:
    if not table_exists(conn, "arrival_telemetry"):
        print("No arrival_telemetry table found.")
        return

    bot_filter = "AND bot_id = %s" if args.bot is not None else ""
    params: list = [args.bot] if args.bot is not None else []

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT tick, bot_id, goal_x, goal_y, goal_z,
                   actual_x, actual_y, actual_z,
                   error_2d, error_3d,
                   leg_start_tick, leg_start_x, leg_start_y, leg_start_z
            FROM arrival_telemetry
            WHERE 1=1 {bot_filter}
            ORDER BY tick
            """,
            params,
        )
        arrivals = cur.fetchall()

    if not arrivals:
        print("No arrivals recorded.")
        return

    result: list[dict] = []
    for row in arrivals:
        (tick, bot_id, gx, gy, gz, ax, ay, az,
         err2d, err3d, t0, sx, sy, sz) = row

        duration = tick - t0 if t0 > 0 else None
        metrics = compute_path_metrics(conn, bot_id, t0, tick, gx, gy, sx, sy)

        entry = {
            "tick": tick,
            "bot": bot_id,
            "err2d": err2d,
            "err3d": err3d,
            "duration": duration,
            "straight": metrics["straight_dist"],
            "path_len": metrics["path_length"],
            "effic": metrics["efficiency"],
        }

        # Threshold filters
        if args.err2d is not None and err2d < args.err2d:
            continue
        if args.efficiency is not None:
            if metrics["efficiency"] is None or metrics["efficiency"] < args.efficiency:
                continue

        result.append(entry)

    columns = [
        ("tick", "Tick", 7),
        ("bot", "Bot", 5),
        ("err2d", "Err2D", 7),
        ("err3d", "Err3D", 7),
        ("duration", "Dur", 6),
        ("straight", "Straight", 8),
        ("path_len", "PathLen", 8),
        ("effic", "Effic", 6),
    ]
    print_table(result, columns, csv_mode=args.csv)


# ── main ───────────────────────────────────────────────────────────────


def main() -> None:
    # Common flags shared by all subcommands
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", default="localhost")
    common.add_argument("--port", type=int, default=5432)
    common.add_argument("--csv", action="store_true", help="Output as CSV")
    common.add_argument("--bot", type=int, default=None, help="Filter to specific bot")

    parser = argparse.ArgumentParser(
        description="Layered telemetry analyzer for bot movement",
        parents=[common],
    )

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("summary", parents=[common], help="Per-bot overview (default)")

    trace_p = sub.add_parser("trace", parents=[common],
                             help="Tick-by-tick trajectory for one bot")
    trace_p.add_argument("--from", type=int, default=None, dest="tick_from",
                         help="Start tick")
    trace_p.add_argument("--to", type=int, default=None, dest="tick_to",
                         help="End tick")

    areas_p = sub.add_parser("areas", parents=[common],
                             help="Per-area navigation quality")
    areas_p.add_argument("--deviation", type=float, default=None,
                         help="Only areas with avg deviation above this")
    areas_p.add_argument("--stuck", action="store_true",
                         help="Only areas with stuck events")

    arr_p = sub.add_parser("arrivals", parents=[common],
                           help="Goal completion stats")
    arr_p.add_argument("--err2d", type=float, default=None,
                       help="Only arrivals with error_2d above this")
    arr_p.add_argument("--efficiency", type=float, default=None,
                       help="Only arrivals with efficiency above this")

    args = parser.parse_args()
    conn = connect(args.host, args.port)

    cmd = args.command or "summary"
    if cmd == "summary":
        cmd_summary(conn, args)
    elif cmd == "trace":
        cmd_trace(conn, args)
    elif cmd == "areas":
        cmd_areas(conn, args)
    elif cmd == "arrivals":
        cmd_arrivals(conn, args)

    conn.close()


if __name__ == "__main__":
    main()
