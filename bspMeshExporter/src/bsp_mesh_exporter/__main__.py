"""CLI with two subcommands: extract (BSP → GLB) and visibility (GLB + NAV → NPZ).

Usage:
    uv run python -m bsp_mesh_exporter extract ministry_coop \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --output-dir ../ai-brain/data/

    uv run python -m bsp_mesh_exporter extract --batch \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --output-dir ../ai-brain/data/

    uv run python -m bsp_mesh_exporter visibility ministry_coop \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --mesh-dir ../ai-brain/data/ \
        --output-dir ../ai-brain/data/

    uv run python -m bsp_mesh_exporter visibility --batch \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --mesh-dir ../ai-brain/data/ \
        --output-dir ../ai-brain/data/
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import trimesh

from bsp_mesh_exporter.bsp_extraction import extract_mesh
from bsp_mesh_exporter.nav_parser import parse_nav
from bsp_mesh_exporter.visibility import compute_visibility

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
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
