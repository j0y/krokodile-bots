"""CLI: extract BSP mesh and compute nav area visibility.

Usage:
    uv run python -m bsp_mesh_exporter ministry_coop \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --output-dir ../ai-brain/data/

    uv run python -m bsp_mesh_exporter --batch \
        --maps-dir ../insurgency-server/server-files/insurgency/maps/ \
        --output-dir ../ai-brain/data/
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np

from bsp_mesh_exporter.bsp_extraction import extract_mesh
from bsp_mesh_exporter.nav_parser import parse_nav
from bsp_mesh_exporter.visibility import compute_visibility

log = logging.getLogger("bsp_mesh_exporter")


def _process_map(
    map_name: str,
    maps_dir: Path,
    output_dir: Path,
    *,
    export_mesh: bool = False,
    max_distance: float = 3000.0,
    eye_height: float = 64.0,
) -> bool:
    """Process a single map: extract mesh, compute visibility, save results.

    Returns True on success.
    """
    bsp_path = maps_dir / f"{map_name}.bsp"
    nav_path = maps_dir / f"{map_name}.nav"

    if not bsp_path.exists():
        log.error("BSP not found: %s", bsp_path)
        return False
    if not nav_path.exists():
        log.error("NAV not found: %s", nav_path)
        return False

    log.info("=== Processing %s ===", map_name)

    # Extract world geometry
    mesh = extract_mesh(bsp_path)

    if export_mesh:
        glb_path = output_dir / f"{map_name}.glb"
        mesh.export(str(glb_path))
        log.info("Exported mesh: %s (%.1f MB)", glb_path, glb_path.stat().st_size / 1e6)

    # Parse nav mesh for area positions
    nav = parse_nav(nav_path)
    log.info("Nav areas: %d", len(nav.areas))

    if not nav.areas:
        log.error("No nav areas found in %s", nav_path)
        return False

    # Build area positions at eye height
    area_ids_list: list[int] = []
    positions_list: list[tuple[float, float, float]] = []

    for area in nav.areas.values():
        c = area.center()
        area_ids_list.append(area.id)
        positions_list.append((c.x, c.y, c.z + eye_height))

    area_ids = np.array(area_ids_list, dtype=np.int32)
    positions = np.array(positions_list, dtype=np.float32)

    # Compute visibility
    vis = compute_visibility(mesh, area_ids, positions, max_distance=max_distance)

    # Save
    output_dir.mkdir(parents=True, exist_ok=True)
    npz_path = output_dir / f"{map_name}_visibility.npz"
    vis.save(npz_path)

    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract BSP mesh and compute nav area visibility.",
    )
    parser.add_argument("map_name", nargs="?", help="Map name (e.g. ministry_coop)")
    parser.add_argument(
        "--maps-dir", type=Path, required=True,
        help="Directory containing .bsp and .nav files",
    )
    parser.add_argument(
        "--output-dir", type=Path, required=True,
        help="Directory for output files (.npz, .glb)",
    )
    parser.add_argument("--batch", action="store_true", help="Process all maps with .bsp + .nav")
    parser.add_argument("--export-mesh", action="store_true", help="Export .glb mesh for debugging")
    parser.add_argument("--max-distance", type=float, default=3000.0, help="Max visibility distance")
    parser.add_argument("--eye-height", type=float, default=64.0, help="Eye height above area center")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.batch:
        # Find all maps with both .bsp and .nav
        bsp_files = sorted(args.maps_dir.glob("*.bsp"))
        succeeded = 0
        failed = 0
        for bsp_file in bsp_files:
            map_name = bsp_file.stem
            nav_file = args.maps_dir / f"{map_name}.nav"
            if not nav_file.exists():
                log.info("Skipping %s (no .nav)", map_name)
                continue
            ok = _process_map(
                map_name, args.maps_dir, args.output_dir,
                export_mesh=args.export_mesh,
                max_distance=args.max_distance,
                eye_height=args.eye_height,
            )
            if ok:
                succeeded += 1
            else:
                failed += 1
        log.info("Batch complete: %d succeeded, %d failed", succeeded, failed)
    elif args.map_name:
        ok = _process_map(
            args.map_name, args.maps_dir, args.output_dir,
            export_mesh=args.export_mesh,
            max_distance=args.max_distance,
            eye_height=args.eye_height,
        )
        if not ok:
            sys.exit(1)
    else:
        parser.error("Provide a map name or use --batch")


if __name__ == "__main__":
    main()
