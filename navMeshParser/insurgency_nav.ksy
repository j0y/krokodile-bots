meta:
  id: insurgency_nav
  title: Insurgency 2014 Navigation Mesh
  file-extension: nav
  tags:
    - valve
    - source_engine
    - nav_mesh
    - insurgency
  endian: le

doc: |
  Source Engine NAV file format (version 16, subversion 4) as used by
  Insurgency 2014 (Steam App ID 237410).

  Based on the TF2 Kaitai Struct spec by WhyIsEvery4thYearAlwaysBad and
  the Valve Source SDK 2013 nav_file.cpp / nav_area.cpp.

  ## What parses correctly

  The header (magic through area_count) parses identically to the
  standard Valve format.  Within each area, the fields from area ID
  through hiding spots also match the SDK.  After hiding spots, the
  four light-intensity floats, the visibility array, the
  inherit_visibility_from ID, and a trailing 4-byte field all parse
  correctly once located.

  ## What differs from the standard format

  The variable-length section between hiding spots and light intensity
  (encounter paths, place index, per-area ladder connections, earliest
  occupy times) uses an Insurgency-specific layout.  In the standard
  Valve SDK this section starts with encounter_count(u32) followed by
  encounter entries, then place_id(u16), then ladder connections, then
  occupy times.  Insurgency 2014 appears to use a custom engine branch
  that changes the encoding of this section.

  Key observations about the variable section:
    - Total size is always even, minimum 22 bytes.
    - When all bytes are zero the size is exactly 22, matching
      enc_count(u32)=0 + place_id(u16)=0 + lad_up(u32)=0 +
      lad_down(u32)=0 + occupy(2*f32)=0.
    - Larger gaps contain 2-byte-aligned data that includes
      coordinate values and possible area ID references.

  Because this section cannot be expressed declaratively, areas are NOT
  parsed in the KSY seq.  Use the companion Python parser (parse_nav.py)
  which locates light intensity by scanning for four consecutive floats
  in [0, 1.5].

  ## Per-area layout (for reference)

  Each area is stored sequentially with NO length prefix:

    Offset  Type        Field
    ------  ----------  ----------------------------
    +0      u4          area ID (sparse, monotonically increasing)
    +4      u4          attribute flags (see nav_attribute enum)
    +8      f4 * 3      NW corner (x, y, z)
    +20     f4 * 3      SE corner (x, y, z)
    +32     f4          NE corner Z height
    +36     f4          SW corner Z height
    +40     connections (4 directions, each: count(u4) + IDs(u4 * count))
    ...     u1          hiding spot count
    ...     hiding_spot * count
    ...     VARIABLE    encounter section (Insurgency-specific, see above)
    ...     f4 * 4      light intensity (NW, NE, SE, SW corners)
    ...     u4          visible area count
    ...     area_bind * count   (5 bytes each: area_id(u4) + attr(u1))
    ...     u4          inherit_visibility_from (area ID, 0 = none)
    ...     u4          unknown (Insurgency-specific, not present on last area)

  After all areas: ladder_count(u4) + nav_ladder * count.

  Ref:
    - https://developer.valvesoftware.com/wiki/NAV_(file_format)
    - https://gist.github.com/WhyIsEvery4thYearAlwaysBad/39d286ccf03f1e06954b942c65362912
    - https://github.com/ValveSoftware/source-sdk-2013

seq:
  - id: magic
    contents: [0xce, 0xfa, 0xed, 0xfe]
    doc: NAV magic number 0xFEEDFACE (little-endian).

  - id: version
    type: u4
    doc: |
      Base NAV format version.
      Insurgency 2014 uses version 16.

  - id: subversion
    type: u4
    if: version >= 10
    doc: |
      Game-specific subversion.
      Insurgency 2014 = 4, TF2 = 2, CS:GO = 1, base SDK = 0.

  - id: bsp_size
    type: u4
    if: version >= 4
    doc: Size of the BSP file this NAV was generated for.

  - id: is_analyzed
    type: u1
    if: version >= 14
    doc: Whether nav_analyze has been run on this mesh.

  - id: place_count
    type: u2
    if: version >= 5
    doc: Number of named places.

  - id: places
    type: place_name
    repeat: expr
    repeat-expr: place_count
    if: version >= 5

  - id: has_unnamed_areas
    type: u1
    if: version >= 12

  - id: area_count
    type: u4
    doc: Number of navigation areas.

  # Areas are NOT parsed here — see doc above and parse_nav.py.

types:
  place_name:
    doc: A named location (e.g. "Lobby", "Courtyard").
    seq:
      - id: length
        type: u2
      - id: name
        type: str
        size: length
        encoding: ASCII

  hiding_spot:
    doc: A pre-computed hiding position inside a nav area (17 bytes).
    seq:
      - id: id
        type: u4
      - id: x
        type: f4
      - id: y
        type: f4
      - id: z
        type: f4
      - id: flags
        type: u1
        doc: |
          Bitmask:
            0x01 = IN_COVER
            0x02 = GOOD_SNIPER_SPOT
            0x04 = IDEAL_SNIPER_SPOT
            0x08 = EXPOSED

  area_bind:
    doc: Visibility relationship to another area.
    seq:
      - id: area_id
        type: u4
      - id: attributes
        type: u1
        doc: |
          0x01 = potentially visible
          0x02 = completely visible

  encounter_spot:
    doc: A waypoint along an encounter path (standard Valve format).
    seq:
      - id: area_id
        type: u4
      - id: parametric_distance
        type: u1
        doc: 0-255 mapped to 0.0-1.0.

  encounter_path:
    doc: |
      Standard Valve encounter path layout.
      NOTE: Insurgency 2014 does NOT use this layout.
      Included for reference only.
    seq:
      - id: from_area_id
        type: u4
      - id: from_direction
        type: u1
      - id: to_area_id
        type: u4
      - id: to_direction
        type: u1
      - id: spot_count
        type: u1
      - id: spots
        type: encounter_spot
        repeat: expr
        repeat-expr: spot_count

  nav_ladder:
    doc: A ladder connecting two nav areas vertically (56 bytes).
    seq:
      - id: id
        type: u4
      - id: width
        type: f4
      - id: top_x
        type: f4
      - id: top_y
        type: f4
      - id: top_z
        type: f4
      - id: bottom_x
        type: f4
      - id: bottom_y
        type: f4
      - id: bottom_z
        type: f4
      - id: length
        type: f4
      - id: direction
        type: u4
        doc: See nav_direction enum.
      - id: top_forward_area_id
        type: u4
      - id: top_left_area_id
        type: u4
      - id: top_right_area_id
        type: u4
      - id: top_behind_area_id
        type: u4
      - id: bottom_area_id
        type: u4

enums:
  nav_direction:
    0: north
    1: east
    2: south
    3: west

  nav_attribute:
    0x0001: crouch
    0x0002: jump
    0x0004: precise
    0x0008: no_jump
    0x0010: stop
    0x0020: run
    0x0040: walk
    0x0080: avoid
    0x0100: transient
    0x0200: dont_hide
    0x0400: stand
    0x0800: no_hostages
    0x1000: stairs
    0x2000: no_merge
    0x4000: obstacle_top
    0x8000: cliff
