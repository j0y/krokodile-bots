"""CLI: extract, visibility, clearance, vismatrix, influence.

Usage:
    uv run python -m bsp_mesh_exporter extract ministry_coop \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --output-dir ../data/

    uv run python -m bsp_mesh_exporter vismatrix ministry_coop \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --mesh-dir ../data/ \
        --output-dir ../data/

    uv run python -m bsp_mesh_exporter influence ministry_coop \
        --vismatrix-dir ../data/ \
        --output-dir ../data/
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import trimesh

from bsp_mesh_exporter.areas_extraction import extract_areas
from bsp_mesh_exporter.bsp_extraction import extract_mesh
from bsp_mesh_exporter.clearance import compute_clearance
from bsp_mesh_exporter.influence import compute_influence
from bsp_mesh_exporter.nav_parser import parse_nav
from bsp_mesh_exporter.visibility import compute_visibility
from bsp_mesh_exporter.vismatrix import compute_vismatrix, generate_grid_points
from bsp_mesh_exporter.walk_graph import compute_walk_graph

log = logging.getLogger("bsp_mesh_exporter")


# ── extract subcommand ───────────────────────────────────────────────


def _extract_one(map_name: str, maps_dir: Path, output_dir: Path) -> bool:
    bsp_path = maps_dir / f"{map_name}.bsp"
    if not bsp_path.exists():
        log.error("BSP not found: %s", bsp_path)
        return False

    log.info("=== Extracting %s ===", map_name)
    mesh = extract_mesh(bsp_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    glb_path = output_dir / f"{map_name}.glb"
    mesh.export(str(glb_path))
    log.info("Exported mesh: %s (%.1f MB)", glb_path, glb_path.stat().st_size / 1e6)
    return True


def _cmd_extract(args: argparse.Namespace) -> None:
    if args.batch:
        bsp_files = sorted(args.maps_dir.glob("*.bsp"))
        ok, fail = 0, 0
        for f in bsp_files:
            if _extract_one(f.stem, args.maps_dir, args.output_dir):
                ok += 1
            else:
                fail += 1
        log.info("Extract batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _extract_one(args.map_name, args.maps_dir, args.output_dir):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── visibility subcommand ────────────────────────────────────────────


def _visibility_one(
    map_name: str,
    maps_dir: Path,
    mesh_dir: Path,
    output_dir: Path,
    *,
    max_distance: float,
    eye_height: float,
) -> bool:
    glb_path = mesh_dir / f"{map_name}.glb"
    nav_path = maps_dir / f"{map_name}.nav"

    if not glb_path.exists():
        log.error("GLB not found: %s (run 'extract' first)", glb_path)
        return False
    if not nav_path.exists():
        log.error("NAV not found: %s", nav_path)
        return False

    log.info("=== Visibility %s ===", map_name)

    mesh: trimesh.Trimesh = trimesh.load(str(glb_path), force="mesh")  # type: ignore[assignment]
    log.info("Loaded mesh: %d verts, %d faces", len(mesh.vertices), len(mesh.faces))

    nav = parse_nav(nav_path)
    log.info("Nav areas: %d", len(nav.areas))
    if not nav.areas:
        log.error("No nav areas in %s", nav_path)
        return False

    area_ids_list: list[int] = []
    positions_list: list[tuple[float, float, float]] = []
    for area in nav.areas.values():
        c = area.center()
        area_ids_list.append(area.id)
        positions_list.append((c.x, c.y, c.z + eye_height))

    area_ids = np.array(area_ids_list, dtype=np.int32)
    positions = np.array(positions_list, dtype=np.float32)

    vis = compute_visibility(mesh, area_ids, positions, max_distance=max_distance)

    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_visibility.npz"
    vis.save(npz_path)
    return True


def _cmd_visibility(args: argparse.Namespace) -> None:
    kw = dict(max_distance=args.max_distance, eye_height=args.eye_height)
    if args.batch:
        glb_files = sorted(args.mesh_dir.glob("*.glb"))
        ok, fail = 0, 0
        for f in glb_files:
            nav_path = args.maps_dir / f"{f.stem}.nav"
            if not nav_path.exists():
                log.info("Skipping %s (no .nav)", f.stem)
                continue
            if _visibility_one(f.stem, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
                ok += 1
            else:
                fail += 1
        log.info("Visibility batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _visibility_one(args.map_name, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── clearance subcommand ─────────────────────────────────────────────


def _clearance_one(
    map_name: str,
    maps_dir: Path,
    mesh_dir: Path,
    output_dir: Path,
    *,
    grid_spacing: float,
    max_range: float,
    ray_heights: tuple[float, ...],
) -> bool:
    glb_path = mesh_dir / f"{map_name}.glb"
    nav_path = maps_dir / f"{map_name}.nav"

    if not glb_path.exists():
        log.error("GLB not found: %s (run 'extract' first)", glb_path)
        return False
    if not nav_path.exists():
        log.error("NAV not found: %s", nav_path)
        return False

    log.info("=== Clearance %s ===", map_name)

    mesh: trimesh.Trimesh = trimesh.load(str(glb_path), force="mesh")  # type: ignore[assignment]
    log.info("Loaded mesh: %d verts, %d faces", len(mesh.vertices), len(mesh.faces))

    nav = parse_nav(nav_path)
    log.info("Nav areas: %d", len(nav.areas))
    if not nav.areas:
        log.error("No nav areas in %s", nav_path)
        return False

    result = compute_clearance(
        mesh, nav,
        grid_spacing=grid_spacing,
        max_range=max_range,
        ray_heights=ray_heights,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_clearance.npz"
    result.save(npz_path)
    return True


def _cmd_clearance(args: argparse.Namespace) -> None:
    heights = (8.0, 32.0, args.eye_height)
    kw = dict(grid_spacing=args.grid_spacing, max_range=args.max_range, ray_heights=heights)
    if args.batch:
        glb_files = sorted(args.mesh_dir.glob("*.glb"))
        ok, fail = 0, 0
        for f in glb_files:
            nav_path = args.maps_dir / f"{f.stem}.nav"
            if not nav_path.exists():
                log.info("Skipping %s (no .nav)", f.stem)
                continue
            if _clearance_one(f.stem, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
                ok += 1
            else:
                fail += 1
        log.info("Clearance batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _clearance_one(args.map_name, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── vismatrix subcommand ─────────────────────────────────────────────


def _vismatrix_one(
    map_name: str,
    maps_dir: Path,
    mesh_dir: Path,
    output_dir: Path,
    *,
    grid_spacing: float,
    max_distance: float,
    eye_height: float,
) -> bool:
    glb_path = mesh_dir / f"{map_name}.glb"
    nav_path = maps_dir / f"{map_name}.nav"

    if not glb_path.exists():
        log.error("GLB not found: %s (run 'extract' first)", glb_path)
        return False
    if not nav_path.exists():
        log.error("NAV not found: %s", nav_path)
        return False

    log.info("=== Vismatrix %s ===", map_name)

    mesh: trimesh.Trimesh = trimesh.load(str(glb_path), force="mesh")  # type: ignore[assignment]
    log.info("Loaded mesh: %d verts, %d faces", len(mesh.vertices), len(mesh.faces))

    nav = parse_nav(nav_path)
    log.info("Nav areas: %d", len(nav.areas))
    if not nav.areas:
        log.error("No nav areas in %s", nav_path)
        return False

    points = generate_grid_points(nav, grid_spacing=grid_spacing)
    result = compute_vismatrix(
        mesh, points, max_distance=max_distance, eye_height=eye_height, grid_spacing=grid_spacing,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_vismatrix.npz"
    result.save(npz_path)
    return True


def _cmd_vismatrix(args: argparse.Namespace) -> None:
    kw = dict(grid_spacing=args.grid_spacing, max_distance=args.max_distance, eye_height=args.eye_height)
    if args.batch:
        glb_files = sorted(args.mesh_dir.glob("*.glb"))
        ok, fail = 0, 0
        for f in glb_files:
            nav_path = args.maps_dir / f"{f.stem}.nav"
            if not nav_path.exists():
                log.info("Skipping %s (no .nav)", f.stem)
                continue
            if _vismatrix_one(f.stem, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
                ok += 1
            else:
                fail += 1
        log.info("Vismatrix batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _vismatrix_one(args.map_name, args.maps_dir, args.mesh_dir, args.output_dir, **kw):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── influence subcommand ─────────────────────────────────────────────


def _influence_one(
    map_name: str,
    vismatrix_dir: Path,
    output_dir: Path,
) -> bool:
    vismatrix_path = vismatrix_dir / f"{map_name}_vismatrix.npz"
    if not vismatrix_path.exists():
        log.error("Vismatrix not found: %s (run 'vismatrix' first)", vismatrix_path)
        return False

    log.info("=== Influence %s ===", map_name)
    result = compute_influence(vismatrix_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_influence.npz"
    result.save(npz_path)
    return True


def _cmd_influence(args: argparse.Namespace) -> None:
    if args.batch:
        vm_files = sorted(args.vismatrix_dir.glob("*_vismatrix.npz"))
        ok, fail = 0, 0
        for f in vm_files:
            map_name = f.name.removesuffix("_vismatrix.npz")
            if _influence_one(map_name, args.vismatrix_dir, args.output_dir):
                ok += 1
            else:
                fail += 1
        log.info("Influence batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _influence_one(args.map_name, args.vismatrix_dir, args.output_dir):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── walk-graph subcommand ────────────────────────────────────────


def _walk_graph_one(
    map_name: str,
    vismatrix_dir: Path,
    output_dir: Path,
    *,
    walk_radius: float,
    cell_size: float,
) -> bool:
    vismatrix_path = vismatrix_dir / f"{map_name}_vismatrix.npz"
    if not vismatrix_path.exists():
        log.error("Vismatrix not found: %s (run 'vismatrix' first)", vismatrix_path)
        return False

    log.info("=== Walk graph %s ===", map_name)
    result = compute_walk_graph(vismatrix_path, walk_radius=walk_radius, cell_size=cell_size)

    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_walkgraph.npz"
    result.save(npz_path)
    return True


def _cmd_walk_graph(args: argparse.Namespace) -> None:
    kw = dict(walk_radius=args.walk_radius, cell_size=args.cell_size)
    if args.batch:
        vm_files = sorted(args.vismatrix_dir.glob("*_vismatrix.npz"))
        ok, fail = 0, 0
        for f in vm_files:
            map_name = f.name.removesuffix("_vismatrix.npz")
            if _walk_graph_one(map_name, args.vismatrix_dir, args.output_dir, **kw):
                ok += 1
            else:
                fail += 1
        log.info("Walk graph batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _walk_graph_one(args.map_name, args.vismatrix_dir, args.output_dir, **kw):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── areas subcommand ────────────────────────────────────────────────


def _areas_one(map_name: str, maps_dir: Path, output_dir: Path) -> bool:
    bsp_path = maps_dir / f"{map_name}.bsp"
    if not bsp_path.exists():
        log.error("BSP not found: %s", bsp_path)
        return False

    log.info("=== Areas %s ===", map_name)
    areas = extract_areas(bsp_path)

    if not areas:
        log.warning("No areas extracted for %s", map_name)
        return False

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{map_name}_areas.json"
    json_path.write_text(json.dumps(areas, indent=2) + "\n")
    log.info("Wrote %s (%d areas)", json_path, len(areas))
    return True


def _cmd_areas(args: argparse.Namespace) -> None:
    if args.batch:
        bsp_files = sorted(args.maps_dir.glob("*_coop.bsp"))
        ok, fail = 0, 0
        for f in bsp_files:
            if _areas_one(f.stem, args.maps_dir, args.output_dir):
                ok += 1
            else:
                fail += 1
        log.info("Areas batch: %d succeeded, %d failed", ok, fail)
    elif args.map_name:
        if not _areas_one(args.map_name, args.maps_dir, args.output_dir):
            sys.exit(1)
    else:
        log.error("Provide a map name or use --batch")
        sys.exit(1)


# ── main ─────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="BSP mesh exporter and visibility computer.")
    sub = parser.add_subparsers(dest="command")

    # extract
    p_ext = sub.add_parser("extract", help="BSP → GLB mesh")
    p_ext.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_ext.add_argument("--batch", action="store_true", help="Process all .bsp files")
    p_ext.add_argument("--maps-dir", type=Path, required=True, help="Directory with .bsp files")
    p_ext.add_argument("--output-dir", type=Path, required=True, help="Output directory for .glb")

    # visibility
    p_vis = sub.add_parser("visibility", help="GLB + NAV → visibility NPZ")
    p_vis.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_vis.add_argument("--batch", action="store_true", help="Process all .glb files")
    p_vis.add_argument("--maps-dir", type=Path, required=True, help="Directory with .nav files")
    p_vis.add_argument("--mesh-dir", type=Path, required=True, help="Directory with .glb files")
    p_vis.add_argument("--output-dir", type=Path, required=True, help="Output directory for .npz")
    p_vis.add_argument("--max-distance", type=float, default=3000.0, help="Max visibility distance")
    p_vis.add_argument("--eye-height", type=float, default=64.0, help="Eye height above area center")

    # clearance
    p_clr = sub.add_parser("clearance", help="GLB + NAV → clearance NPZ")
    p_clr.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_clr.add_argument("--batch", action="store_true", help="Process all .glb files")
    p_clr.add_argument("--maps-dir", type=Path, required=True, help="Directory with .nav files")
    p_clr.add_argument("--mesh-dir", type=Path, required=True, help="Directory with .glb files")
    p_clr.add_argument("--output-dir", type=Path, required=True, help="Output directory for .npz")
    p_clr.add_argument("--grid-spacing", type=float, default=20.0, help="Sample grid spacing (u)")
    p_clr.add_argument("--max-range", type=float, default=500.0, help="Max ray distance (u)")
    p_clr.add_argument("--eye-height", type=float, default=64.0, help="Eye-level height offset (u)")

    # vismatrix
    p_vm = sub.add_parser("vismatrix", help="GLB + NAV → point-to-point visibility matrix NPZ")
    p_vm.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_vm.add_argument("--batch", action="store_true", help="Process all .glb files")
    p_vm.add_argument("--maps-dir", type=Path, required=True, help="Directory with .nav files")
    p_vm.add_argument("--mesh-dir", type=Path, required=True, help="Directory with .glb files")
    p_vm.add_argument("--output-dir", type=Path, required=True, help="Output directory for .npz")
    p_vm.add_argument("--grid-spacing", type=float, default=32.0, help="Grid spacing in units (default 32)")
    p_vm.add_argument("--max-distance", type=float, default=2000.0, help="Max visibility distance (default 2000)")
    p_vm.add_argument("--eye-height", type=float, default=64.0, help="Eye height above foot level (default 64)")

    # influence
    p_inf = sub.add_parser("influence", help="Vismatrix → influence/cover NPZ")
    p_inf.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_inf.add_argument("--batch", action="store_true", help="Process all *_vismatrix.npz files")
    p_inf.add_argument("--vismatrix-dir", type=Path, required=True, help="Directory with *_vismatrix.npz files")
    p_inf.add_argument("--output-dir", type=Path, required=True, help="Output directory for .npz")

    # walk-graph
    p_wg = sub.add_parser("walk-graph", help="Vismatrix → walk graph + coarse routing NPZ")
    p_wg.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_wg.add_argument("--batch", action="store_true", help="Process all *_vismatrix.npz files")
    p_wg.add_argument("--vismatrix-dir", type=Path, required=True, help="Directory with *_vismatrix.npz files")
    p_wg.add_argument("--output-dir", type=Path, required=True, help="Output directory for .npz")
    p_wg.add_argument("--walk-radius", type=float, default=100.0, help="Max edge distance for walk graph (default 100)")
    p_wg.add_argument("--cell-size", type=float, default=256.0, help="Coarse cell size in units (default 256)")

    # areas
    p_areas = sub.add_parser("areas", help="BSP entities → areas JSON (objectives, spawns)")
    p_areas.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    p_areas.add_argument("--batch", action="store_true", help="Process all *_coop.bsp files")
    p_areas.add_argument("--maps-dir", type=Path, required=True, help="Directory with .bsp files")
    p_areas.add_argument("--output-dir", type=Path, required=True, help="Output directory for .json")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.command == "extract":
        _cmd_extract(args)
    elif args.command == "visibility":
        _cmd_visibility(args)
    elif args.command == "clearance":
        _cmd_clearance(args)
    elif args.command == "vismatrix":
        _cmd_vismatrix(args)
    elif args.command == "influence":
        _cmd_influence(args)
    elif args.command == "walk-graph":
        _cmd_walk_graph(args)
    elif args.command == "areas":
        _cmd_areas(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
