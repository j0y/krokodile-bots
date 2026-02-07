"""
Insurgency 2014 NAV mesh parser.

Parses Source Engine .nav files (version 16, subversion 4) as shipped
with Insurgency 2014.  Extracts the navigation graph: areas with their
corner positions, inter-area connections, hiding spots, light intensity,
and visibility data.

The section between hiding spots and light intensity uses a custom
Insurgency layout that differs from the standard Valve SDK format.
This parser locates light intensity by scanning for four consecutive
floats in [0, 1.5], which reliably anchors the remainder of each area.

Usage:
    python parse_nav.py <path_to.nav> [--dump] [--stats] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path


# ── data classes ─────────────────────────────────────────────────────

@dataclass
class Vector3:
    x: float
    y: float
    z: float

    def to_list(self) -> list[float]:
        return [self.x, self.y, self.z]


@dataclass
class HidingSpot:
    id: int
    pos: Vector3
    flags: int  # 1=IN_COVER 2=GOOD_SNIPER 4=IDEAL_SNIPER 8=EXPOSED


@dataclass
class AreaBind:
    area_id: int
    attributes: int  # 0=not_visible 1=potentially 2=completely


@dataclass
class NavArea:
    id: int
    flags: int
    nw: Vector3         # north-west corner
    se: Vector3         # south-east corner
    ne_z: float         # north-east corner height
    sw_z: float         # south-west corner height
    connections: list[list[int]]    # [north_ids, east_ids, south_ids, west_ids]
    hiding_spots: list[HidingSpot]
    light: list[float]              # 4 corner intensities
    visible_areas: list[AreaBind]
    inherit_visibility_from: int

    # derived helpers
    def center(self) -> Vector3:
        return Vector3(
            (self.nw.x + self.se.x) / 2,
            (self.nw.y + self.se.y) / 2,
            (self.nw.z + self.se.z) / 2,
        )

    def neighbor_ids(self) -> set[int]:
        return {aid for direction in self.connections for aid in direction}


@dataclass
class NavLadder:
    id: int
    width: float
    top: Vector3
    bottom: Vector3
    length: float
    direction: int
    top_forward_area_id: int
    top_left_area_id: int
    top_right_area_id: int
    top_behind_area_id: int
    bottom_area_id: int


@dataclass
class NavMesh:
    version: int
    subversion: int
    bsp_size: int
    is_analyzed: bool
    places: list[str]
    areas: dict[int, NavArea]          # keyed by area id
    ladders: dict[int, NavLadder]      # keyed by ladder id


# ── binary reader helpers ────────────────────────────────────────────

class BinaryReader:
    """Thin wrapper around a memoryview for sequential reading."""

    def __init__(self, data: bytes | memoryview):
        self._data = data if isinstance(data, memoryview) else memoryview(data)
        self.pos = 0

    def _read(self, n: int) -> memoryview:
        chunk = self._data[self.pos : self.pos + n]
        if len(chunk) < n:
            raise EOFError(f"need {n} bytes at offset {self.pos}, only {len(chunk)} left")
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self._read(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._read(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._read(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self._read(4))[0]

    def f32(self) -> float:
        return struct.unpack("<f", self._read(4))[0]

    def vec3(self) -> Vector3:
        return Vector3(self.f32(), self.f32(), self.f32())

    def skip(self, n: int) -> None:
        self.pos += n

    def remaining(self) -> int:
        return len(self._data) - self.pos

    def peek_f32_at(self, offset: int) -> float:
        return struct.unpack_from("<f", self._data, offset)[0]

    def peek_u32_at(self, offset: int) -> int:
        return struct.unpack_from("<I", self._data, offset)[0]


# ── parser ───────────────────────────────────────────────────────────

def _looks_like_area_header(data: bytes | memoryview, off: int) -> bool:
    """Quick sanity check: does offset look like the start of a nav area?

    Checks: valid ID (1-100000), flags (<=0xFFFF), 6 corner floats in
    range, NE_Z and SW_Z heights in range, and first connection count
    is reasonable.
    """
    if off + 48 > len(data):
        return False
    aid = struct.unpack_from("<I", data, off)[0]
    flags = struct.unpack_from("<I", data, off + 4)[0]
    if aid < 1 or aid > 100000:
        return False
    if flags > 0xFFFF:
        return False
    # 6 corner floats + 2 height floats = 8 floats at off+8
    floats = struct.unpack_from("<8f", data, off + 8)
    for v in floats:
        if not (-20000 < v < 20000):
            return False
    # First connection count (north) at off+40
    first_conn = struct.unpack_from("<I", data, off + 40)[0]
    if first_conn > 500:
        return False
    return True


def _find_light_offset(data: bytes | memoryview, search_start: int,
                       max_areas: int, current_id: int = 0,
                       is_last: bool = False,
                       max_scan: int = 5000) -> int | None:
    """
    Locate the 4 light-intensity floats by scanning forward from
    *search_start*.  Returns the byte offset of the first float, or
    None if not found.

    Heuristic: four consecutive LE floats each in [-0.01, 1.5], followed
    by a uint32 visible-area count in [0, max_areas], and after the
    visibility data + inherit + 4 extra bytes, the next bytes must look
    like a valid area header (unless this is the last area).

    The *current_id* parameter enables monotonic-ID validation: the
    next area's ID must be strictly greater than the current area's.
    """
    # Minimum gap: enc_count(4) + place_id(2) + lad_up(4)
    # + lad_down(4) + occupy(8) = 22.  Gaps are always even.
    min_off = search_start + 22
    end = min(search_start + max_scan, len(data) - 20)
    candidates = []

    for off in range(min_off, end):
        vals = struct.unpack_from("<ffff", data, off)
        if not all(-0.01 <= v <= 1.5 for v in vals):
            continue
        vc = struct.unpack_from("<I", data, off + 16)[0]
        if vc > max_areas:
            continue
        after_vis = off + 20 + vc * 5
        if after_vis + 8 > len(data):
            continue
        inherit = struct.unpack_from("<I", data, after_vis)[0]
        if inherit > 100000:
            continue

        next_area = after_vis + 8  # inherit(4) + extra(4)
        if not is_last:
            if not _looks_like_area_header(data, next_area):
                continue
            if current_id > 0:
                next_id = struct.unpack_from("<I", data, next_area)[0]
                if next_id <= current_id:
                    continue

        # Score: prefer vis>0, non-zero lights, even gaps
        gap = off - search_start
        score = (
            (2 if vc > 0 else 0)
            + sum(1 for v in vals if v > 0.01)
            + (1 if gap % 2 == 0 else 0)  # even gaps preferred
        )
        candidates.append((score, gap, off))

    if candidates:
        # Highest score wins; for tied scores, smallest gap
        candidates.sort(key=lambda x: (-x[0], x[1]))
        return candidates[0][2]
    return None


def parse_nav(path: str | Path) -> NavMesh:
    """Parse a .nav file and return a NavMesh."""
    raw = Path(path).read_bytes()
    r = BinaryReader(raw)

    # ── header ───────────────────────────────────────────────────────
    magic = r.u32()
    if magic != 0xFEEDFACE:
        raise ValueError(f"bad magic: 0x{magic:08X}")

    version = r.u32()
    subversion = r.u32() if version >= 10 else 0
    bsp_size = r.u32() if version >= 4 else 0
    is_analyzed = bool(r.u8()) if version >= 14 else False

    places: list[str] = []
    if version >= 5:
        place_count = r.u16()
        for _ in range(place_count):
            name_len = r.u16()
            places.append(bytes(r._read(name_len)).decode("ascii", errors="replace"))

    if version >= 12:
        _has_unnamed = r.u8()

    area_count = r.u32()

    # ── areas ────────────────────────────────────────────────────────
    areas: dict[int, NavArea] = {}

    for area_idx in range(area_count):
        area_start = r.pos

        # --- reliable section (identical to standard Valve format) ---
        try:
            aid = r.u32()
            aflags = r.i32()
        except EOFError:
            print(f"warning: EOF at area {area_idx}/{area_count}, offset {r.pos}", file=sys.stderr)
            break

        try:
            nw = r.vec3()
            se = r.vec3()
            ne_z = r.f32()
            sw_z = r.f32()

            connections: list[list[int]] = []
            for _ in range(4):
                cc = r.u32()
                if cc > 1000:
                    raise ValueError(
                        f"area {aid} (index {area_idx}): connection count {cc} "
                        f"at offset {r.pos - 4} — likely misaligned"
                    )
                connections.append([r.u32() for _ in range(cc)])

            hiding_count = r.u8()
            hiding_spots: list[HidingSpot] = []
            for _ in range(hiding_count):
                hs_id = r.u32()
                hs_pos = r.vec3()
                hs_flags = r.u8()
                hiding_spots.append(HidingSpot(hs_id, hs_pos, hs_flags))
        except (EOFError, ValueError):
            print(f"warning: parse error at area {area_idx}/{area_count}, "
                  f"offset {r.pos}", file=sys.stderr)
            break

        hiding_end = r.pos

        # --- variable section (Insurgency-specific, skip via scan) ---
        is_last_area = (area_idx == area_count - 1)
        light_off = _find_light_offset(raw, hiding_end, area_count,
                                       current_id=aid,
                                       is_last=is_last_area)
        # Fallback: near end of file, the scanner may have merged areas
        # earlier, so we may effectively be at the last area even if
        # area_idx says otherwise.  Retry without next-header check.
        if light_off is None and r.remaining() < 20000:
            light_off = _find_light_offset(raw, hiding_end, area_count,
                                           current_id=aid,
                                           is_last=True)
        if light_off is None:
            print(f"warning: cannot locate light for area {aid} "
                  f"(index {area_idx}), stopping", file=sys.stderr)
            break
        r.pos = light_off

        light = [r.f32() for _ in range(4)]

        vis_count = r.u32()
        visible_areas: list[AreaBind] = []
        for _ in range(vis_count):
            bind_id = r.u32()
            bind_attr = r.u8()
            visible_areas.append(AreaBind(bind_id, bind_attr))

        inherit_vis = r.u32()

        # extra 4 bytes (Insurgency game-specific, purpose unknown)
        # last area may not have trailing bytes before ladder section
        if area_idx < area_count - 1:
            r.skip(4)

        areas[aid] = NavArea(
            id=aid,
            flags=aflags,
            nw=nw,
            se=se,
            ne_z=ne_z,
            sw_z=sw_z,
            connections=connections,
            hiding_spots=hiding_spots,
            light=light,
            visible_areas=visible_areas,
            inherit_visibility_from=inherit_vis,
        )

    # ── ladders ──────────────────────────────────────────────────────
    ladders: dict[int, NavLadder] = {}
    try:
        if r.remaining() >= 4:
            ladder_count = r.u32()
            if ladder_count > 1000:
                # Likely corrupt — area drift consumed the ladder section
                pass
            else:
                for _ in range(ladder_count):
                    lid = r.u32()
                    width = r.f32()
                    top = r.vec3()
                    bottom = r.vec3()
                    length = r.f32()
                    direction = r.u32()
                    tf = r.u32()
                    tl = r.u32()
                    tr = r.u32()
                    tb = r.u32()
                    ba = r.u32()
                    ladders[lid] = NavLadder(lid, width, top, bottom, length,
                                             direction, tf, tl, tr, tb, ba)
    except EOFError:
        pass  # area drift consumed ladder data

    return NavMesh(
        version=version,
        subversion=subversion,
        bsp_size=bsp_size,
        is_analyzed=is_analyzed,
        places=places,
        areas=areas,
        ladders=ladders,
    )


# ── CLI ──────────────────────────────────────────────────────────────

def _print_stats(mesh: NavMesh) -> None:
    print(f"Version:     {mesh.version}  (subversion {mesh.subversion})")
    print(f"BSP size:    {mesh.bsp_size:,}")
    print(f"Analyzed:    {mesh.is_analyzed}")
    print(f"Places:      {len(mesh.places)}")
    print(f"Areas:       {len(mesh.areas)}")
    print(f"Ladders:     {len(mesh.ladders)}")

    if mesh.areas:
        xs = [a.nw.x for a in mesh.areas.values()] + [a.se.x for a in mesh.areas.values()]
        ys = [a.nw.y for a in mesh.areas.values()] + [a.se.y for a in mesh.areas.values()]
        zs = [a.nw.z for a in mesh.areas.values()] + [a.se.z for a in mesh.areas.values()]
        print(f"X range:     {min(xs):.0f} .. {max(xs):.0f}")
        print(f"Y range:     {min(ys):.0f} .. {max(ys):.0f}")
        print(f"Z range:     {min(zs):.0f} .. {max(zs):.0f}")

        total_conns = sum(len(c) for a in mesh.areas.values() for c in a.connections)
        total_hiding = sum(len(a.hiding_spots) for a in mesh.areas.values())
        total_vis = sum(len(a.visible_areas) for a in mesh.areas.values())
        print(f"Connections: {total_conns}")
        print(f"Hiding:      {total_hiding}")
        print(f"Visibility:  {total_vis}")


def _print_dump(mesh: NavMesh, limit: int = 20) -> None:
    for i, area in enumerate(mesh.areas.values()):
        if i >= limit:
            print(f"  ... ({len(mesh.areas) - limit} more)")
            break
        c = area.center()
        n = area.neighbor_ids()
        print(
            f"  Area {area.id:5d}  center=({c.x:7.0f},{c.y:7.0f},{c.z:7.0f})"
            f"  neighbors={len(n):2d}  hiding={len(area.hiding_spots)}"
            f"  vis={len(area.visible_areas):4d}"
            f"  light=[{','.join(f'{l:.2f}' for l in area.light)}]"
        )

    if mesh.ladders:
        print(f"\nLadders:")
        for lad in mesh.ladders.values():
            print(
                f"  Ladder {lad.id:3d}  top=({lad.top.x:.0f},{lad.top.y:.0f},{lad.top.z:.0f})"
                f"  bot=({lad.bottom.x:.0f},{lad.bottom.y:.0f},{lad.bottom.z:.0f})"
                f"  len={lad.length:.0f}  w={lad.width:.0f}"
            )


def _export_json(mesh: NavMesh, path: str) -> None:
    """Export a compact JSON for use by the Python AI brain."""
    out = {
        "version": mesh.version,
        "subversion": mesh.subversion,
        "area_count": len(mesh.areas),
        "ladder_count": len(mesh.ladders),
        "areas": {
            str(a.id): {
                "nw": a.nw.to_list(),
                "se": a.se.to_list(),
                "ne_z": round(a.ne_z, 3),
                "sw_z": round(a.sw_z, 3),
                "flags": a.flags,
                "neighbors": {
                    "north": a.connections[0],
                    "east": a.connections[1],
                    "south": a.connections[2],
                    "west": a.connections[3],
                },
                "hiding_spots": [
                    {"pos": hs.pos.to_list(), "flags": hs.flags}
                    for hs in a.hiding_spots
                ],
            }
            for a in mesh.areas.values()
        },
        "ladders": {
            str(l.id): {
                "top": l.top.to_list(),
                "bottom": l.bottom.to_list(),
                "width": round(l.width, 2),
                "length": round(l.length, 2),
                "connected_areas": {
                    "top_forward": l.top_forward_area_id,
                    "top_left": l.top_left_area_id,
                    "top_right": l.top_right_area_id,
                    "top_behind": l.top_behind_area_id,
                    "bottom": l.bottom_area_id,
                },
            }
            for l in mesh.ladders.values()
        },
    }
    Path(path).write_text(json.dumps(out, separators=(",", ":")))
    print(f"Wrote {Path(path).stat().st_size:,} bytes to {path}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Parse Insurgency 2014 .nav files")
    ap.add_argument("nav_file", help="Path to .nav file")
    ap.add_argument("--stats", action="store_true", help="Print summary statistics")
    ap.add_argument("--dump", action="store_true", help="Print first N areas")
    ap.add_argument("--json", metavar="OUT", help="Export navigation graph as JSON")
    args = ap.parse_args()

    mesh = parse_nav(args.nav_file)

    if args.stats or (not args.dump and not args.json):
        _print_stats(mesh)

    if args.dump:
        _print_dump(mesh)

    if args.json:
        _export_json(mesh, args.json)


if __name__ == "__main__":
    main()
