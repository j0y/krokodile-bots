"""Extract world geometry from a Source Engine BSP file into a trimesh."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np
import trimesh

log = logging.getLogger(__name__)

# Surface flags to skip (non-occluding)
SURF_SKY_2D = 0x0002
SURF_SKY = 0x0004
SURF_WARP = 0x0008
SURF_TRANSLUCENT = 0x0010
SURF_NO_DRAW = 0x0080
SURF_HINT = 0x0100
SURF_SKIP = 0x0200
SURF_TRIGGER = 0x40000000

_SKIP_FLAGS = SURF_SKY_2D | SURF_SKY | SURF_HINT | SURF_SKIP | SURF_TRIGGER | SURF_NO_DRAW

# Displacement flags
DISP_NO_PHYS = 0x02
DISP_NO_HULL = 0x04
DISP_NO_RAY = 0x08


def _face_vertices(bsp: object, face: object) -> list[tuple[float, float, float]]:
    """Extract ordered vertex positions for a BSP face via the surfedge chain."""
    verts: list[tuple[float, float, float]] = []
    for i in range(face.num_edges):  # type: ignore[attr-defined]
        surfedge = bsp.SURFEDGES[face.first_edge + i]  # type: ignore[attr-defined]
        if surfedge >= 0:
            edge = bsp.EDGES[surfedge]  # type: ignore[attr-defined]
            v = bsp.VERTICES[edge[0]]  # type: ignore[attr-defined]
        else:
            edge = bsp.EDGES[-surfedge]  # type: ignore[attr-defined]
            v = bsp.VERTICES[edge[1]]  # type: ignore[attr-defined]
        verts.append((float(v.x), float(v.y), float(v.z)))
    return verts


def _triangulate_fan(verts: list[tuple[float, float, float]]) -> list[tuple[int, int, int]]:
    """Fan-triangulate a convex polygon: N verts -> N-2 triangles."""
    return [(0, i, i + 1) for i in range(1, len(verts) - 1)]


def _find_start_corner(
    corners: list[tuple[float, float, float]], start: tuple[float, float, float],
) -> int:
    """Find which corner index is closest to the displacement start_position."""
    best_idx = 0
    best_dist = float("inf")
    for i, c in enumerate(corners):
        d = (c[0] - start[0]) ** 2 + (c[1] - start[1]) ** 2 + (c[2] - start[2]) ** 2
        if d < best_dist:
            best_dist = d
            best_idx = i
    return best_idx


def _extract_displacement(
    bsp: object,
    face: object,
    dispinfo: object,
) -> tuple[list[tuple[float, float, float]], list[tuple[int, int, int]]]:
    """Build displacement surface vertices and triangles.

    Returns (verts, tris) where tris index into verts starting at 0.
    """
    # Get the 4 corners of the base face
    base_corners = _face_vertices(bsp, face)
    if len(base_corners) != 4:
        return [], []

    # Reorder corners so index 0 matches dispinfo.start_position
    sp = dispinfo.start_position  # type: ignore[attr-defined]
    start = (float(sp.x), float(sp.y), float(sp.z))
    si = _find_start_corner(base_corners, start)
    corners = base_corners[si:] + base_corners[:si]

    power: int = dispinfo.power  # type: ignore[attr-defined]
    side = 1 << power
    num_verts_per_side = side + 1

    # Bilinear interpolation of base quad + displacement offsets
    first_dv: int = dispinfo.first_displacement_vertex  # type: ignore[attr-defined]
    disp_verts_lump = bsp.DISPLACEMENT_VERTICES  # type: ignore[attr-defined]

    verts: list[tuple[float, float, float]] = []
    c0, c1, c2, c3 = corners  # CCW: 0=start, 1, 2, 3

    for row in range(num_verts_per_side):
        t = row / side
        for col in range(num_verts_per_side):
            s = col / side

            # Bilinear base position
            bx = (
                c0[0] * (1 - s) * (1 - t)
                + c1[0] * s * (1 - t)
                + c2[0] * s * t
                + c3[0] * (1 - s) * t
            )
            by = (
                c0[1] * (1 - s) * (1 - t)
                + c1[1] * s * (1 - t)
                + c2[1] * s * t
                + c3[1] * (1 - s) * t
            )
            bz = (
                c0[2] * (1 - s) * (1 - t)
                + c1[2] * s * (1 - t)
                + c2[2] * s * t
                + c3[2] * (1 - s) * t
            )

            dv_idx = first_dv + row * num_verts_per_side + col
            dv = disp_verts_lump[dv_idx]
            dist = float(dv.distance)
            nx, ny, nz = float(dv.normal.x), float(dv.normal.y), float(dv.normal.z)

            verts.append((bx + nx * dist, by + ny * dist, bz + nz * dist))

    # Triangulate the grid
    tris: list[tuple[int, int, int]] = []
    for row in range(side):
        for col in range(side):
            i0 = row * num_verts_per_side + col
            i1 = i0 + 1
            i2 = (row + 1) * num_verts_per_side + col
            i3 = i2 + 1
            tris.append((i0, i2, i3))
            tris.append((i0, i3, i1))

    return verts, tris


def extract_mesh(bsp_path: str | Path) -> trimesh.Trimesh:
    """Load a BSP file and extract worldspawn geometry as a Trimesh.

    Only extracts Model 0 (worldspawn) — excludes doors, breakables, etc.
    Skips sky, trigger, hint, skip, and nodraw faces.
    Includes displacement surfaces (terrain).
    """
    import bsp_tool
    from bsp_tool.branches.valve import sdk_2013

    bsp_path = Path(bsp_path)
    log.info("Loading BSP: %s", bsp_path)
    bsp: Any = bsp_tool.load_bsp(str(bsp_path), force_branch=sdk_2013)

    model0 = bsp.MODELS[0]
    first_face = model0.first_face
    num_faces = model0.num_faces

    all_verts: list[tuple[float, float, float]] = []
    all_tris: list[tuple[int, int, int]] = []

    face_count = 0
    disp_count = 0
    skipped = 0

    for fi in range(first_face, first_face + num_faces):
        face = bsp.FACES[fi]

        # Check texture flags — skip non-occluding surfaces
        ti = face.texture_info
        if 0 <= ti < len(bsp.TEXTURE_INFO):
            flags = int(bsp.TEXTURE_INFO[ti].flags)
            if flags & _SKIP_FLAGS:
                skipped += 1
                continue

        # Check if this face has a displacement
        disp_idx = face.displacement_info
        if disp_idx >= 0:
            try:
                dispinfo = bsp.DISPLACEMENT_INFO[disp_idx]
                # Skip non-solid displacements
                dflags = int(dispinfo.flags) if hasattr(dispinfo, "flags") else 0
                if dflags & (DISP_NO_HULL | DISP_NO_RAY):
                    skipped += 1
                    continue

                dverts, dtris = _extract_displacement(bsp, face, dispinfo)
                if dverts:
                    base = len(all_verts)
                    all_verts.extend(dverts)
                    all_tris.extend((a + base, b + base, c + base) for a, b, c in dtris)
                    disp_count += 1
            except (IndexError, AttributeError):
                log.warning("Failed to extract displacement %d for face %d", disp_idx, fi)
            continue

        # Regular face — fan triangulate
        fverts = _face_vertices(bsp, face)
        if len(fverts) < 3:
            continue

        base = len(all_verts)
        all_verts.extend(fverts)
        for t in _triangulate_fan(fverts):
            all_tris.append((t[0] + base, t[1] + base, t[2] + base))
        face_count += 1

    log.info(
        "Extracted %d faces, %d displacements, skipped %d (total %d tris, %d verts)",
        face_count, disp_count, skipped, len(all_tris), len(all_verts),
    )

    vertices = np.array(all_verts, dtype=np.float64)
    faces = np.array(all_tris, dtype=np.int32)

    mesh = trimesh.Trimesh(vertices=vertices, faces=faces, process=True)
    log.info("Final mesh: %d vertices, %d faces", len(mesh.vertices), len(mesh.faces))
    return mesh
