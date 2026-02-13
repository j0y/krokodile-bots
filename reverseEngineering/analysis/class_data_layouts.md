# Class Data Layouts — Extracted from Constructor Disassembly
# Source: server_srv.so
# 49 constructors analyzed

## Action<CINSNextBot> Base Class Layout

All Action-derived classes share this 56-byte (0x38) base layout:
(From source-sdk-2013 Action.h + NWI secondary vtable)

```
  Offset  Type                  Member Name
  ------  ----                  -----------
+0x0000     vtable*               Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*     IContextualQuery vtable (vtable+0x1A0)
+0x0008     Behavior*             m_behavior — owning Behavior tree
+0x000c     Action*               m_parent — containing Action
+0x0010     Action*               m_child — active child (top of stack)
+0x0014     Action*               m_buriedUnderMe — action below in stack
+0x0018     Action*               m_coveringMe — action above in stack
+0x001c     CINSNextBot*          m_actor — the bot entity
+0x0020     int                   m_eventResult.type (ActionResultType)
+0x0024     Action*               m_eventResult.m_action
+0x0028     const char*           m_eventResult.m_reason
+0x002c     int                   m_eventResult.m_priority (EventResultPriorityType)
+0x0030     bool                  m_isStarted
+0x0031     bool                  m_isSuspended
+0x0034     int                   m_eventResult (secondary/unused)
```

## CINSBotActionAmbush
Constructor: `CINSBotActionAmbush::CINSBotActionAmbush()` @ 0x007267a0
Constructor size: 144 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b88ee8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8907c        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     bool                      0x00              
+0x0039     bool                      0x00              
+0x003c     float (nan)               0xffffffff        
```

## CINSBotActionFlashpoint
Constructor: `CINSBotActionFlashpoint::CINSBotActionFlashpoint()` @ 0x00728480
Constructor size: 128 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b89688        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8981c        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotActionSkirmish
Constructor: `CINSBotActionSkirmish::CINSBotActionSkirmish()` @ 0x0072b630
Constructor size: 128 bytes
Derived members: 1 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8a208        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8a39c        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     bool                      0x00              
```

## CINSBotActionStrike
Constructor: `CINSBotActionStrike::CINSBotActionStrike()` @ 0x0072c020
Constructor size: 128 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8a3e8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8a578        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotApproach
Constructor: `CINSBotApproach::CINSBotApproach(Vector)` @ 0x006e7490
Constructor size: 304 bytes
Derived members: 5 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b84628        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b847c0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0050     bool                      0x00              
+0x0058     int/ptr/float             0x00000000        
+0x005c     float (-1)                0xbf800000        
+0x0060     bool                      0x00              
```

## CINSBotAttack
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttack::CINSBotAttack()` @ 0x006f56a0
Constructor size: 240 bytes
Derived members: 2 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b84a08        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b84ba8        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     float (nan)               0xffffffff        
```

  Coverage: 2 derived members (+0x0038 to +0x0048), object size: 0x0050

## CINSBotAttackAdvance
Constructor: `CINSBotAttackAdvance::CINSBotAttackAdvance()` @ 0x006f5ef0
Constructor size: 304 bytes
Derived members: 2 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b84c08        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b84db0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0044     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

## CINSBotAttackCQC
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackCQC::CINSBotAttackCQC()` @ 0x006f8030
Constructor size: 368 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b84e08        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b84fb0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

  Coverage: 3 derived members (+0x0038 to +0x004c), object size: 0x0050

## CINSBotAttackFromCover
Constructor: `CINSBotAttackFromCover::CINSBotAttackFromCover()` @ 0x006f89f0
Constructor size: 336 bytes
Derived members: 8 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85008        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b851b0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x004c     int/ptr/float             0x00000000        
+0x0050     float (-1)                0xbf800000        
+0x0060     bool                      0x00              
+0x0061     bool                      0x00              
+0x0062     bool                      0x00              
+0x0063     bool                      0x00              
+0x0064     bool                      0x00              
```

## CINSBotAttackInPlace
Constructor: `CINSBotAttackInPlace::CINSBotAttackInPlace()` @ 0x006fb000
Constructor size: 320 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85208        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b853b0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

## CINSBotAttackIntoCover
Constructor: `CINSBotAttackIntoCover::CINSBotAttackIntoCover(Vector, bool, bool)` @ 0x006fcf60
Constructor size: 304 bytes
Derived members: 4 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85428        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b855d4        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0044     CountdownTimer.vtable*    0x00b181b8        
+0x0048     CountdownTimer.vtable*    0x00b181b8        
+0x004c     CountdownTimer.vtable*    0x00b181b8        
```

## CINSBotAttackLMG
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackLMG::CINSBotAttackLMG()` @ 0x006fe1f0
Constructor size: 368 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85628        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b857d0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

  Coverage: 3 derived members (+0x0038 to +0x004c), object size: 0x0050

## CINSBotAttackMelee
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackMelee::CINSBotAttackMelee()` @ 0x006ff240
Constructor size: 288 bytes
Derived members: 2 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85828        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b859d0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0050     sub_object                0x00000000        CINSPathFollower::CINSPathFollower
```

  Coverage: 2 derived members (+0x0038 to +0x0050), object size: 0x0050

## CINSBotAttackPistol
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackPistol::CINSBotAttackPistol()` @ 0x007003c0
Constructor size: 368 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85a28        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b85bd0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

  Coverage: 3 derived members (+0x0038 to +0x004c), object size: 0x0050

## CINSBotAttackRifle
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackRifle::CINSBotAttackRifle()` @ 0x00701680
Constructor size: 368 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85c28        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b85dd0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

  Coverage: 3 derived members (+0x0038 to +0x004c), object size: 0x0050

## CINSBotAttackSniper
Object size: 80 bytes (0x50)
Constructor: `CINSBotAttackSniper::CINSBotAttackSniper()` @ 0x007027c0
Constructor size: 368 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b85e28        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b85fd0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
```

  Coverage: 3 derived members (+0x0038 to +0x004c), object size: 0x0050

## CINSBotBody
Object size: 376 bytes (0x178)
Constructor: `CINSBotBody::CINSBotBody(INextBot*)` @ 0x007453b0
Constructor size: 848 bytes
Members found: 24

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8cea8        CINSBotBody
+0x00d0     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x00dc     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x00ec     int/ptr/float             0x00000000        
+0x00f4     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0100     int (7)                   0x00000007        
+0x0104     int/ptr/float             0x00000000        
+0x010c     int/ptr/float             0x00000000        
+0x0110     int (7)                   0x00000007        
+0x0114     int/ptr/float             0x00000000        
+0x0118     int (7)                   0x00000007        
+0x011c     bool                      0x00              
+0x0120     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0138     int/ptr/float             0x00000000        
+0x013c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0148     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0154     float (1)                 0x3f800000        
+0x0158     float (1)                 0x3f800000        
+0x015c     float (1)                 0x3f800000        
+0x0160     float (1)                 0x3f800000        
+0x0164     float (1)                 0x3f800000        
+0x0168     float (1)                 0x3f800000        
+0x0170     float (-1)                0xbf800000        
+0x0174     int/ptr/float             0x00000000        
```

  Coverage: 24 derived members (+0x0000 to +0x0174), object size: 0x0178
  Gaps (>4 bytes):
    +0x012c to +0x0138 (12 bytes uninstrumented)

## CINSBotCaptureCP
Constructor: `CINSBotCaptureCP::CINSBotCaptureCP(int, bool)` @ 0x00703010
Constructor size: 400 bytes
Derived members: 5 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b86028        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b861bc        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x003c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0048     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0054     IntervalTimer[8]          0xb28688          { vtable, m_timestamp }
+0x0074     float (-1)                0xbf800000        
+0x0078     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

## CINSBotCaptureFlag
Constructor: `CINSBotCaptureFlag::CINSBotCaptureFlag(CINSPlayer*, int)` @ 0x007045c0
Constructor size: 704 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b28688        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8639c        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotChatter
Constructor: `CINSBotChatter::CINSBotChatter(CINSNextBot*)` @ 0x007490b0
Constructor size: 32 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0004     secondary_vtable*         0x00000000        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotCombat
Object size: 136 bytes (0x88)
Constructor: `CINSBotCombat::CINSBotCombat()` @ 0x00705390
Constructor size: 624 bytes
Derived members: 13 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b863e8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b86580        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     float (nan)               0xffffffff        
+0x003c     int/ptr/float             0x00000000        
+0x0040     int/ptr/float             0x00000000        
+0x0044     int/ptr/float             0x00000000        
+0x0048     int/ptr/float             0x00000000        
+0x004c     bool                      0x00              
+0x004d     bool                      0x00              
+0x004e     bool                      0x00              
+0x0050     int/ptr/float             0x00000000        
+0x0054     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0060     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x006c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0078     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

  Coverage: 13 derived members (+0x0038 to +0x0078), object size: 0x0088

## CINSBotDestroyCache
Constructor: `CINSBotDestroyCache::CINSBotDestroyCache(int)` @ 0x007081d0
Constructor size: 832 bytes
Derived members: 4 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b867c8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b8695c        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     IntervalTimer[8]          0xb28688          { vtable, m_timestamp }
+0x0040     int/ptr/float             0x00000000        
+0x0044     float (-1)                0xbf800000        
+0x0048     sub_object                0x00000000        CINSPathFollower::CINSPathFollower
```

## CINSBotEscort
Object size: 156 bytes (0x9c)
Constructor: `CINSBotEscort::CINSBotEscort()` @ 0x0070a3e0
Constructor size: 576 bytes
Derived members: 9 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b869a8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b86b48        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     float (nan)               0xffffffff        
+0x0048     bool                      0x00              
+0x0050     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x005c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0068     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0074     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0080     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x008c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0098     bool                      0x00              
```

  Coverage: 9 derived members (+0x0038 to +0x0098), object size: 0x009c
  Gaps (>4 bytes):
    +0x0049 to +0x0050 (7 bytes uninstrumented)

## CINSBotFireRPG
Constructor: `CINSBotFireRPG::CINSBotFireRPG()` @ 0x0070f4f0
Constructor size: 656 bytes
Derived members: 12 (+ 15 base)

  Also: `CINSBotFireRPG::CINSBotFireRPG(Vector, Vector)` @ 0x0070ddd0 (20 members)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b86ba8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x428c0000        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer.vtable*    0x00b181b8        
+0x003c     CountdownTimer.vtable*    0x00b181b8        
+0x0040     CountdownTimer.vtable*    0x00b181b8        
+0x0044     CountdownTimer.vtable*    0x00b181b8        
+0x0048     CountdownTimer.vtable*    0x00b181b8        
+0x004c     CountdownTimer.vtable*    0x00b181b8        
+0x0050     CountdownTimer.vtable*    0x00b181b8        
+0x0054     CountdownTimer.vtable*    0x00b181b8        
+0x0058     CountdownTimer.vtable*    0x00b181b8        
+0x005c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0068     int/ptr/float             0x00000000        
+0x006c     bool                      0x00              
```

## CINSBotFollowCommand
Constructor: `CINSBotFollowCommand::CINSBotFollowCommand(eRadialCommands)` @ 0x00710350
Constructor size: 224 bytes
Derived members: 2 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b86fa8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b87138        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer.vtable*    0x00b181b8        
+0x0040     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

## CINSBotGuardCP
Constructor: `CINSBotGuardCP::CINSBotGuardCP(int, float)` @ 0x007108d0
Constructor size: 544 bytes
Derived members: 4 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87188        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b87318        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     IntervalTimer[8]          0xb28688          { vtable, m_timestamp }
+0x0044     secondary_vtable*         0x00b87318        CINSBotGuardCP
+0x0050     secondary_vtable*         0x00b87318        CINSBotGuardCP
+0x0054     sub_object                0x00000000        CINSPathFollower::CINSPathFollower
```

## CINSBotGuardDefensive
Constructor: `CINSBotGuardDefensive::CINSBotGuardDefensive(int)` @ 0x00711d70
Constructor size: 544 bytes
Derived members: 4 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87368        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b874f8        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     IntervalTimer[8]          0xb28688          { vtable, m_timestamp }
+0x0044     secondary_vtable*         0x00b874f8        CINSBotGuardDefensive
+0x0050     secondary_vtable*         0x00b874f8        CINSBotGuardDefensive
+0x0054     sub_object                0x00000000        CINSPathFollower::CINSPathFollower
```

## CINSBotInvestigate
Constructor: `CINSBotInvestigate::CINSBotInvestigate(CNavArea const*)` @ 0x00713fa0
Constructor size: 752 bytes
Derived members: 0 (+ 15 base)

  Also: `CINSBotInvestigate::CINSBotInvestigate(Vector)` @ 0x00714290 (15 members)
  Also: `CINSBotInvestigate::CINSBotInvestigate()` @ 0x007145b0 (15 members)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87548        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b876e0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotInvestigateGunshot
Constructor: `CINSBotInvestigateGunshot::CINSBotInvestigateGunshot(Vector)` @ 0x00714d40
Constructor size: 544 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87748        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b878e0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotLocomotion
Constructor: `CINSBotLocomotion::CINSBotLocomotion(INextBot*)` @ 0x00750920
Constructor size: 896 bytes
Members found: 2

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b92c00        PlayerLocomotion
+0x00ac     sub_object                0x00000000        CINSPathFollower::CINSPathFollower
```

## CINSBotPatrol
Constructor: `CINSBotPatrol::CINSBotPatrol()` @ 0x00716f10
Constructor size: 880 bytes
Derived members: 1 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87948        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b87ae0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x003c     IntervalTimer[8]          0xb28688          { vtable, m_timestamp }
```

## CINSBotPursue
Constructor: `CINSBotPursue::CINSBotPursue()` @ 0x0071a780
Constructor size: 240 bytes
Derived members: 4 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87b48        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b87ce0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0050     float (nan)               0xffffffff        
+0x0054     float (-1)                0xbf800000        
+0x0058     bool                      0x00              
```

## CINSBotReload
Constructor: `CINSBotReload::CINSBotReload()` @ 0x007079b0
Constructor size: 352 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0004     secondary_vtable*         0x00b87ed8        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0044     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0050     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

## CINSBotRetreat
Constructor: `CINSBotRetreat::CINSBotRetreat(bool, float)` @ 0x0071c190
Constructor size: 656 bytes
Derived members: 1 (+ 15 base)

  Also: `CINSBotRetreat::CINSBotRetreat(float)` @ 0x0071c420 (16 members)
  Also: `CINSBotRetreat::CINSBotRetreat(int)` @ 0x0071c6a0 (16 members)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b87f28        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b880c0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     vtable*                   0x00b843c8        CINSRetreatPath
```

## CINSBotRetreatToCover
Constructor: `CINSBotRetreatToCover::CINSBotRetreatToCover(bool, float)` @ 0x0071f700
Constructor size: 320 bytes
Derived members: 6 (+ 15 base)

  Also: `CINSBotRetreatToCover::CINSBotRetreatToCover(Vector, bool, float)` @ 0x0071f840 (21 members)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b88128        CINSBotRetreatToCover
+0x0004     secondary_vtable*         0x00b882c0        CINSBotRetreatToCover
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0040     secondary_vtable*         0x00b882c0        CINSBotRetreatToCover
+0x0044     vtable*                   0x00b181b8        CountdownTimer
+0x0048     int/ptr/float             0x00000000        
+0x004c     float (-1)                0xbf800000        
+0x005c     int/ptr/float             0x00000000        
+0x0060     float (-1)                0xbf800000        
```

## CINSBotRetreatToHidingSpot
Constructor: `CINSBotRetreatToHidingSpot::CINSBotRetreatToHidingSpot(bool, float)` @ 0x00720b40
Constructor size: 544 bytes
Derived members: 0 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b88328        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b884c0        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
```

## CINSBotSpecialAction
Constructor: `CINSBotSpecialAction::CINSBotSpecialAction(BotSpecialActions, bool)` @ 0x00721370
Constructor size: 304 bytes
Derived members: 3 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b88528        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b886b8        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x003c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x004c     int/ptr/float             0x00000000        
+0x0050     float (-1)                0xbf800000        
```

## CINSBotSuppressTarget
Constructor: `CINSBotSuppressTarget::CINSBotSuppressTarget(Vector, CBaseEntity*)` @ 0x00723170
Constructor size: 416 bytes
Derived members: 6 (+ 15 base)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b888e8        Action<CINSNextBot> primary vtable
+0x0004     secondary_vtable*         0x00b88a80        IContextualQuery vtable (vtable+0x1A0)
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0038     float (nan)               0xffffffff        
+0x003c     secondary_vtable*         0x00b88a80        CINSBotSuppressTarget
+0x0040     secondary_vtable*         0x00b88a80        CINSBotSuppressTarget
+0x0054     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0060     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x006c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
```

## CINSBotThrowGrenade
Constructor: `CINSBotThrowGrenade::CINSBotThrowGrenade()` @ 0x00725f70
Constructor size: 416 bytes
Derived members: 5 (+ 15 base)

  Also: `CINSBotThrowGrenade::CINSBotThrowGrenade(Vector, Vector)` @ 0x00724d10 (18 members)

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b88cc8        CINSBotThrowGrenade
+0x0004     secondary_vtable*         0x00000001        
  ...       [Action<T> base]          (0x08-0x34)       see base layout above
  ----      --- derived members ---   ----------        -----
+0x0050     vtable*                   0x00b181b8        CountdownTimer
+0x0054     int/ptr/float             0x00000000        
+0x0058     float (-1)                0xbf800000        
+0x0060     int/ptr/float             0x00000000        
+0x0064     float (-1)                0xbf800000        
```

## CINSBotVision
Object size: 640 bytes (0x280)
Constructor: `CINSBotVision::CINSBotVision(INextBot*)` @ 0x0075b550
Constructor size: 864 bytes
Members found: 16

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8d308        CINSBotVision
+0x0144     int/ptr/float             0x00000000        
+0x0148     int/ptr/float             0x00000000        
+0x014c     int/ptr/float             0x00000000        
+0x0150     int/ptr/float             0x00000000        
+0x0154     int/ptr/float             0x00000000        
+0x0158     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0164     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0170     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x017c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0188     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0194     float (nan)               0xffffffff        
+0x0258     int/ptr/float             0x00000000        
+0x025c     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x0268     float (nan)               0xffffffff        
+0x026c     float (nan)               0xffffffff        
```

  Coverage: 16 derived members (+0x0000 to +0x026c), object size: 0x0280
  Gaps (>4 bytes):
    +0x0198 to +0x0258 (192 bytes uninstrumented)
    +0x0270 to +0x0280 (16 bytes uninstrumented)

## CINSNextBot
Constructor: `CINSNextBot::CINSNextBot()` @ 0x00738c00
Constructor size: 4528 bytes
Members found: 1

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8b2c8        CINSNextBot
```

## CINSNextBotManager
Constructor: `CINSNextBotManager::CINSNextBotManager()` @ 0x00754ee0
Constructor size: 1360 bytes
Members found: 47

```
  Offset  Type                      Init Value        Notes
  ------  ----                      ----------        -----
+0x0000     vtable*                   0x00b8d288        CINSNextBotManager
+0x0008     float (-1)                0xbf800000        
+0x0050     vtable*                   0x00b8d288        CINSNextBotManager
+0x0054     int (42)                  0x0000002a        
+0x0058     bool                      0x00              
+0x005c     int/ptr/float             0x00000000        
+0x0060     int/ptr/float             0x00000000        
+0x0064     int/ptr/float             0x00000000        
+0x0068     int/ptr/float             0x00000000        
+0x006c     int/ptr/float             0x00000000        
+0x0070     int/ptr/float             0x00000000        
+0x0074     int/ptr/float             0x00000000        
+0x0078     int/ptr/float             0x00000000        
+0x007c     int/ptr/float             0x00000000        
+0x0080     int/ptr/float             0x00000000        
+0x0084     int/ptr/float             0x00000000        
+0x0088     int/ptr/float             0x00000000        
+0x008c     int/ptr/float             0x00000000        
+0x0090     int/ptr/float             0x00000000        
+0x0094     int/ptr/float             0x00000000        
+0x0098     CountdownTimer[12]        0xb181b8          { vtable, m_timestamp=0, m_duration=-1.0f }
+0x00a8     int/ptr/float             0x00000000        
+0x00ac     float (-1)                0xbf800000        
+0x00b4     int/ptr/float             0x00000000        
+0x00b8     float (-1)                0xbf800000        
+0x00cc     int/ptr/float             0x00000000        
+0x00d0     float (-1)                0xbf800000        
+0x00d8     int/ptr/float             0x00000000        
+0x00dc     float (-1)                0xbf800000        
+0x00e0     float (1)                 0x3f800000        
+0x00e4     int (1)                   0x00000001        
+0x00e8     int/ptr/float             0x00000000        
+0x00ec     int/ptr/float             0x00000000        
+0x00f0     int/ptr/float             0x00000000        
+0x00f4     int/ptr/float             0x00000000        
+0x00f8     int/ptr/float             0x00000000        
+0x00fc     int/ptr/float             0x00000000        
+0x0100     int/ptr/float             0x00000000        
+0x0104     int/ptr/float             0x00000000        
+0x0108     int/ptr/float             0x00000000        
+0x010c     int/ptr/float             0x00000000        
+0x0114     int/ptr/float             0x00000000        
+0x0118     float (-1)                0xbf800000        
+0x0120     int/ptr/float             0x00000000        
+0x0124     float (-1)                0xbf800000        
+0x0128     bool                      0x00              
+0x0129     bool                      0x00              
```

## Summary

- Total constructors analyzed: 49
- Total classes: 42 (37 Action-derived, 5 components)
- Total member slots found: 878
- CountdownTimer sub-objects: 51
- IntervalTimer sub-objects: 5
- Sub-object constructor calls: 5
