# Insurgency 2014 Nav Mesh Parser

Parser for Source Engine `.nav` files (version 16, subversion 4) as shipped
with **Insurgency 2014** (Steam App ID 237410).

Extracts the navigation graph: areas with corner positions, inter-area
connections, hiding spots, light intensity, and visibility data.
Exports to JSON for use by external tools.

## Files

| File | Description |
|---|---|
| `parse_nav.py` | Python parser (standalone, no dependencies beyond stdlib) |
| `insurgency_nav.ksy` | [Kaitai Struct](https://kaitai.io/) spec (header only, for reference) |

## Usage

```bash
# Print summary statistics (default)
python parse_nav.py path/to/map.nav

# Print first 20 areas with positions, neighbors, visibility
python parse_nav.py path/to/map.nav --dump

# Export navigation graph as compact JSON
python parse_nav.py path/to/map.nav --json output.json

# Combine flags
python parse_nav.py path/to/map.nav --stats --dump --json output.json
```

### Example output (`--stats`)

```
Version:     16  (subversion 4)
BSP size:    46,370,816
Analyzed:    True
Places:      15
Areas:       3196
Ladders:     0
X range:     -4480 .. 4464
Y range:     -5920 .. 3712
Z range:     -288 .. 448
Connections: 16970
Hiding:      3432
Visibility:  653998
```

## JSON format

The `--json` export produces a compact JSON file with this structure:

```jsonc
{
  "version": 16,
  "subversion": 4,
  "area_count": 3196,
  "ladder_count": 0,
  "areas": {
    "1": {
      "nw": [x, y, z],       // north-west corner
      "se": [x, y, z],       // south-east corner
      "ne_z": 0.0,           // north-east corner height
      "sw_z": 0.0,           // south-west corner height
      "flags": 0,            // nav_attribute bitmask
      "neighbors": {
        "north": [2, 5],     // connected area IDs per direction
        "east": [],
        "south": [3],
        "west": [7, 8, 9]
      },
      "hiding_spots": [
        {"pos": [x, y, z], "flags": 1}
      ]
    }
    // ...
  },
  "ladders": {
    "1": {
      "top": [x, y, z],
      "bottom": [x, y, z],
      "width": 32.0,
      "length": 128.0,
      "connected_areas": {
        "top_forward": 10,
        "top_left": 0,
        "top_right": 0,
        "top_behind": 11,
        "bottom": 12
      }
    }
  }
}
```

## How it works

The standard Valve SDK nav format stores areas sequentially with no length
prefix. Most fields (ID, flags, corners, connections, hiding spots) follow
the published SDK layout. However, the section between hiding spots and
light intensity (encounter paths, place index, ladder connections, occupy
times) uses an **Insurgency-specific encoding** that differs from the
standard Valve SDK.

Since this variable section has no explicit length field and cannot be
parsed declaratively, the parser locates the light-intensity floats by
scanning forward: it looks for four consecutive little-endian floats in
`[0, 1.5]`, then validates the candidate by checking the subsequent
visibility count, inherit ID, and next area header. A score-based
selection picks the best candidate when multiple matches exist.

This approach achieves **99.9% area recovery** across all 30 stock
Insurgency 2014 maps (163,969 / 164,188 areas).

## Kaitai Struct spec

The `.ksy` file parses the **header only** (magic through area_count).
Individual areas cannot be expressed in Kaitai's declarative format due to
the variable-length encounter section. The spec includes type definitions
for `hiding_spot`, `area_bind`, `nav_ladder`, and `encounter_path`
(reference only) for documentation purposes.

## Nav attribute flags

| Flag | Name |
|------|------|
| `0x0001` | Crouch |
| `0x0002` | Jump |
| `0x0004` | Precise |
| `0x0008` | No Jump |
| `0x0010` | Stop |
| `0x0020` | Run |
| `0x0040` | Walk |
| `0x0080` | Avoid |
| `0x0100` | Transient |
| `0x0200` | Don't Hide |
| `0x0400` | Stand |
| `0x0800` | No Hostages |
| `0x1000` | Stairs |
| `0x2000` | No Merge |
| `0x4000` | Obstacle Top |
| `0x8000` | Cliff |

## Hiding spot flags

| Flag | Name |
|------|------|
| `0x01` | In Cover |
| `0x02` | Good Sniper Spot |
| `0x04` | Ideal Sniper Spot |
| `0x08` | Exposed |

## Requirements

Python 3.10+ (uses `X | Y` union type syntax). No external dependencies.

## References

- [Valve NAV file format wiki](https://developer.valvesoftware.com/wiki/NAV_(file_format))
- [TF2 Kaitai Struct spec](https://gist.github.com/WhyIsEvery4thYearAlwaysBad/39d286ccf03f1e06954b942c65362912)
- [Valve Source SDK 2013](https://github.com/ValveSoftware/source-sdk-2013) (`nav_file.cpp`, `nav_area.cpp`)
