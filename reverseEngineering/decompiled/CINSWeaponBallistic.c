/*
 * CINSWeaponBallistic -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 52
 */

/* ----------------------------------------
 * CINSWeaponBallistic::AllowPlayerJump
 * Address: 002fdd60  Size: 79 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::AllowPlayerJump() const */

void __thiscall CINSWeaponBallistic::AllowPlayerJump(CINSWeaponBallistic *this)

{
  char cVar1;
  CINSWeapon *extraout_ECX;
  CINSWeapon *extraout_ECX_00;
  CINSWeapon *this_00;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  this_00 = extraout_ECX;
  if (0 < in_stack_00000004[0x1091]) {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x60c))();
    this_00 = extraout_ECX_00;
    if (cVar1 == '\0') {
      return;
    }
  }
  CINSWeapon::AllowPlayerJump(this_00);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::AllowPlayerSprint
 * Address: 002fddc0  Size: 53 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::AllowPlayerSprint() const */

void __thiscall CINSWeaponBallistic::AllowPlayerSprint(CINSWeaponBallistic *this)

{
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (0 < (int)*(CINSWeapon **)(in_stack_00000004 + 0x4244)) {
    return;
  }
  CINSWeapon::AllowPlayerSprint(*(CINSWeapon **)(in_stack_00000004 + 0x4244));
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::BeginCocking
 * Address: 002fffd0  Size: 1329 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::BeginCocking() */

void __thiscall CINSWeaponBallistic::BeginCocking(CINSWeaponBallistic *this)

{
  CBaseEdict *pCVar1;
  ushort uVar2;
  ushort uVar3;
  uint *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  float fVar7;
  int *piVar8;
  int iVar9;
  ushort *puVar10;
  CINSWeaponBallistic *this_00;
  CINSWeapon *this_01;
  CBaseAnimating *extraout_ECX;
  CBaseAnimating *this_02;
  CBaseEdict *this_03;
  CBaseEdict *extraout_ECX_00;
  CBaseEdict *extraout_ECX_01;
  CBaseAnimating *this_04;
  CBaseAnimating *extraout_ECX_02;
  CBaseEdict *pCVar11;
  CBaseEdict *pCVar12;
  int unaff_EBX;
  float fVar13;
  float10 fVar14;
  float10 fVar15;
  CStudioHdr *in_stack_00000004;
  uint local_24;
  uint local_20;
  
  __i686_get_pc_thunk_bx();
  fVar14 = (float10)GetBoltSpeedModifier(this_00);
  fVar7 = (float)(**(code **)(*(int *)in_stack_00000004 + 0x76c))(in_stack_00000004);
  CINSWeapon::SendWeaponAnimWithPlaybackRate(this_01,(int)in_stack_00000004,fVar7);
  fVar7 = *(float *)(**(int **)(unaff_EBX + 0x8a68c5) + 0xc);
  piVar8 = (int *)0x0;
  this_02 = extraout_ECX;
  if (in_stack_00000004[0x32d] == (CStudioHdr)0x0) {
    this_02 = *(CBaseAnimating **)(in_stack_00000004 + 0x498);
    if ((this_02 == (CBaseAnimating *)0x0) &&
       (iVar9 = CBaseEntity::GetModel(), this_02 = this_04, iVar9 != 0)) {
      CBaseAnimating::LockStudioHdr(this_04);
      this_02 = extraout_ECX_02;
    }
    piVar8 = *(int **)(in_stack_00000004 + 0x498);
    if ((piVar8 != (int *)0x0) && (*piVar8 == 0)) {
      piVar8 = (int *)0x0;
    }
  }
  fVar15 = (float10)CBaseAnimating::SequenceDuration(this_02,in_stack_00000004,(int)piVar8);
  fVar7 = (float)fVar15 / (float)fVar14 + fVar7;
  pCVar12 = this_03;
  fVar13 = *(float *)(in_stack_00000004 + 0x4d8);
  if (*(float *)(in_stack_00000004 + 0x4d8) != fVar7) {
    fVar13 = fVar7;
    if (in_stack_00000004[0x5c] == (CStudioHdr)0x0) {
      puVar4 = *(uint **)(in_stack_00000004 + 0x20);
      pCVar12 = this_03;
      if ((puVar4 != (uint *)0x0) && (pCVar12 = this_03, (*puVar4 & 0x100) == 0)) {
        *puVar4 = *puVar4 | 1;
        puVar10 = (ushort *)CBaseEdict::GetChangeAccessor(this_03);
        pCVar12 = (CBaseEdict *)(uint)puVar10[1];
        puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a67a1);
        if (pCVar12 == (CBaseEdict *)(uint)*puVar5) {
          pCVar1 = (CBaseEdict *)(puVar5 + (uint)*puVar10 * 0x14);
          pCVar11 = pCVar1 + 2;
          uVar2 = *(ushort *)(pCVar1 + 0x28);
          local_20 = (uint)uVar2;
          if (uVar2 == 0) {
LAB_0030051a:
            *(undefined2 *)(pCVar11 + local_20 * 2) = 0x4d8;
            *(ushort *)(pCVar1 + 0x28) = uVar2 + 1;
            pCVar12 = pCVar11;
          }
          else {
            pCVar12 = pCVar1;
            if (*(ushort *)(pCVar1 + 2) != 0x4d8) {
              iVar9 = 0;
              do {
                if (iVar9 == (local_20 - 1 & 0xffff) * 2) {
                  if (uVar2 == 0x13) goto LAB_00300330;
                  goto LAB_0030051a;
                }
                iVar9 = iVar9 + 2;
                pCVar12 = pCVar11;
              } while (*(short *)(pCVar11 + iVar9) != 0x4d8);
            }
          }
        }
        else {
          pCVar11 = (CBaseEdict *)(uint)*puVar5;
          if ((puVar5[0x7d1] == 100) || (pCVar11 = pCVar12, pCVar12 != (CBaseEdict *)0x0)) {
LAB_00300330:
            puVar10[1] = 0;
            *puVar4 = *puVar4 | 0x100;
            pCVar12 = pCVar11;
          }
          else {
            pCVar12 = *(CBaseEdict **)(unaff_EBX + 0x8a67a1);
            *puVar10 = puVar5[0x7d1];
            puVar6 = *(ushort **)pCVar12;
            puVar5 = puVar6 + 0x7d1;
            *puVar5 = *puVar5 + 1;
            puVar10[1] = *puVar6;
            iVar9 = *(int *)pCVar12 + (uint)*puVar10 * 0x28;
            *(undefined2 *)(iVar9 + 2) = 0x4d8;
            *(undefined2 *)(iVar9 + 0x28) = 1;
          }
        }
      }
      *(float *)(in_stack_00000004 + 0x4d8) = fVar7;
    }
    else {
      in_stack_00000004[0x60] = (CStudioHdr)((byte)in_stack_00000004[0x60] | 1);
      *(float *)(in_stack_00000004 + 0x4d8) = fVar7;
    }
  }
  if (*(float *)(in_stack_00000004 + 0x4b4) != fVar13) {
    if (in_stack_00000004[0x5c] == (CStudioHdr)0x0) {
      puVar4 = *(uint **)(in_stack_00000004 + 0x20);
      if ((puVar4 != (uint *)0x0) && ((*puVar4 & 0x100) == 0)) {
        *puVar4 = *puVar4 | 1;
        puVar10 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar12);
        puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a67a1);
        if (puVar10[1] == *puVar5) {
          uVar2 = *puVar10;
          uVar3 = puVar5[(uint)uVar2 * 0x14 + 0x14];
          local_24 = (uint)uVar3;
          if (uVar3 == 0) {
LAB_00300482:
            puVar5[(uint)uVar2 * 0x14 + local_24 + 1] = 0x4b4;
            puVar5[(uint)uVar2 * 0x14 + 0x14] = uVar3 + 1;
          }
          else if (puVar5[(uint)uVar2 * 0x14 + 1] != 0x4b4) {
            iVar9 = 0;
            do {
              if (iVar9 == (local_24 - 1 & 0xffff) * 2) {
                if (uVar3 == 0x13) goto LAB_00300318;
                goto LAB_00300482;
              }
              iVar9 = iVar9 + 2;
            } while (*(short *)((int)puVar5 + iVar9 + (uint)uVar2 * 0x28 + 2) != 0x4b4);
          }
        }
        else if ((puVar5[0x7d1] == 100) || (puVar10[1] != 0)) {
LAB_00300318:
          puVar10[1] = 0;
          *puVar4 = *puVar4 | 0x100;
        }
        else {
          piVar8 = *(int **)(unaff_EBX + 0x8a67a1);
          *puVar10 = puVar5[0x7d1];
          puVar6 = (ushort *)*piVar8;
          puVar5 = puVar6 + 0x7d1;
          *puVar5 = *puVar5 + 1;
          puVar10[1] = *puVar6;
          iVar9 = *piVar8 + (uint)*puVar10 * 0x28;
          *(undefined2 *)(iVar9 + 2) = 0x4b4;
          *(undefined2 *)(iVar9 + 0x28) = 1;
        }
      }
      *(float *)(in_stack_00000004 + 0x4b4) = fVar13;
    }
    else {
      in_stack_00000004[0x60] = (CStudioHdr)((byte)in_stack_00000004[0x60] | 1);
      *(float *)(in_stack_00000004 + 0x4b4) = fVar13;
    }
  }
  iVar9 = CINSWeapon::GetINSPlayerOwner();
  pCVar12 = extraout_ECX_00;
  if (iVar9 != 0) {
    CINSPlayer::DoAnimationEvent();
    pCVar12 = extraout_ECX_01;
  }
  if (*(int *)(in_stack_00000004 + 0x424c) != 2) {
    if (in_stack_00000004[0x5c] == (CStudioHdr)0x0) {
      puVar4 = *(uint **)(in_stack_00000004 + 0x20);
      if ((puVar4 != (uint *)0x0) && ((*puVar4 & 0x100) == 0)) {
        *puVar4 = *puVar4 | 1;
        puVar10 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar12);
        puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a67a1);
        if (puVar10[1] == *puVar5) {
          uVar2 = *puVar10;
          uVar3 = puVar5[(uint)uVar2 * 0x14 + 0x14];
          if (uVar3 == 0) {
LAB_003003e2:
            puVar5[(uint)uVar2 * 0x14 + uVar3 + 1] = 0x424c;
            puVar5[(uint)uVar2 * 0x14 + 0x14] = uVar3 + 1;
          }
          else if (puVar5[(uint)uVar2 * 0x14 + 1] != 0x424c) {
            iVar9 = 0;
            do {
              if (iVar9 == (uVar3 - 1 & 0xffff) * 2) {
                if (uVar3 == 0x13) goto LAB_00300300;
                goto LAB_003003e2;
              }
              iVar9 = iVar9 + 2;
            } while (*(short *)((int)puVar5 + iVar9 + (uint)uVar2 * 0x28 + 2) != 0x424c);
          }
        }
        else if ((puVar5[0x7d1] == 100) || (puVar10[1] != 0)) {
LAB_00300300:
          puVar10[1] = 0;
          *puVar4 = *puVar4 | 0x100;
        }
        else {
          piVar8 = *(int **)(unaff_EBX + 0x8a67a1);
          *puVar10 = puVar5[0x7d1];
          puVar6 = (ushort *)*piVar8;
          puVar5 = puVar6 + 0x7d1;
          *puVar5 = *puVar5 + 1;
          puVar10[1] = *puVar6;
          iVar9 = *piVar8 + (uint)*puVar10 * 0x28;
          *(undefined2 *)(iVar9 + 2) = 0x424c;
          *(undefined2 *)(iVar9 + 0x28) = 1;
        }
      }
    }
    else {
      in_stack_00000004[0x60] = (CStudioHdr)((byte)in_stack_00000004[0x60] | 1);
    }
    *(undefined4 *)(in_stack_00000004 + 0x424c) = 2;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CanAttack
 * Address: 002ff020  Size: 80 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CanAttack() const */

undefined4 CINSWeaponBallistic::CanAttack(void)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  CINSWeaponBallistic *this;
  CINSWeaponBallistic *this_00;
  CINSWeaponBallistic *this_01;
  CINSWeapon *extraout_ECX;
  
  __i686_get_pc_thunk_bx();
  cVar1 = IsBoltAction(this);
  this_01 = this_00;
  if (cVar1 != '\0') {
    iVar3 = GetBoltState(this_00);
    this_01 = (CINSWeaponBallistic *)extraout_ECX;
    if (iVar3 != 0) {
      return 0;
    }
  }
  uVar2 = CINSWeapon::CanAttack((CINSWeapon *)this_01);
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CanBeDropped
 * Address: 002fdb40  Size: 86 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CanBeDropped(bool) const */

undefined4 __thiscall CINSWeaponBallistic::CanBeDropped(CINSWeaponBallistic *this,bool param_1)

{
  undefined4 uVar1;
  int iVar2;
  CINSWeapon *this_00;
  undefined3 in_stack_00000005;
  char in_stack_00000008;
  
  uVar1 = __i686_get_pc_thunk_bx();
  if (in_stack_00000008 != '\0') {
    iVar2 = CINSWeapon::GetWeaponDefinition(this_00);
    if (*(int *)(iVar2 + 4) != 1) {
      return CONCAT31((int3)((uint)*(int *)(_param_1 + 0x4d0) >> 8),0 < *(int *)(_param_1 + 0x4d0));
    }
    uVar1 = 0;
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CanHolster
 * Address: 002fde40  Size: 53 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CanHolster() */

void __thiscall CINSWeaponBallistic::CanHolster(CINSWeaponBallistic *this)

{
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (0 < *(int *)(in_stack_00000004 + 0x4244)) {
    return;
  }
  CINSWeapon::CanHolster();
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CanReload
 * Address: 002fde00  Size: 53 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CanReload() const */

void __thiscall CINSWeaponBallistic::CanReload(CINSWeaponBallistic *this)

{
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (0 < (int)*(CINSWeapon **)(in_stack_00000004 + 0x4244)) {
    return;
  }
  CINSWeapon::CanReload(*(CINSWeapon **)(in_stack_00000004 + 0x4244));
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ChamberRound
 * Address: 002fdf00  Size: 497 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ChamberRound() */

void __thiscall CINSWeaponBallistic::ChamberRound(CINSWeaponBallistic *this)

{
  ushort uVar1;
  ushort uVar2;
  uint *puVar3;
  ushort *puVar4;
  int *piVar5;
  ushort *puVar6;
  char cVar7;
  ushort *puVar8;
  CBaseEntity *this_00;
  CBaseEdict *this_01;
  CBaseEntity *this_02;
  CBaseEdict *extraout_ECX;
  int iVar9;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar7 = (**(code **)(*in_stack_00000004 + 0x744))();
  this_01 = (CBaseEdict *)this_00;
  if (((cVar7 != '\0') && (*(char *)((int)in_stack_00000004 + 0x4249) == '\0')) &&
     (iVar9 = in_stack_00000004[0x134], 0 < iVar9)) {
    CBaseEntity::NetworkStateChanged(this_00,in_stack_00000004);
    in_stack_00000004[0x134] = iVar9 + -1;
    this_01 = (CBaseEdict *)this_02;
    if (*(char *)((int)in_stack_00000004 + 0x4249) != '\x01') {
      CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
      iVar9 = in_stack_00000004[0x1093];
      *(undefined1 *)((int)in_stack_00000004 + 0x4249) = 1;
      this_01 = extraout_ECX;
      goto joined_r0x002fdf9f;
    }
  }
  iVar9 = in_stack_00000004[0x1093];
joined_r0x002fdf9f:
  if (iVar9 == 0) {
    return;
  }
  if ((char)in_stack_00000004[0x17] == '\0') {
    puVar3 = (uint *)in_stack_00000004[8];
    if ((puVar3 != (uint *)0x0) && ((*puVar3 & 0x100) == 0)) {
      *puVar3 = *puVar3 | 1;
      puVar8 = (ushort *)CBaseEdict::GetChangeAccessor(this_01);
      puVar4 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a8868);
      if (puVar8[1] == *puVar4) {
        uVar1 = *puVar8;
        uVar2 = puVar4[(uint)uVar1 * 0x14 + 0x14];
        if (uVar2 == 0) {
LAB_002fe0ea:
          puVar4[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x424c;
          puVar4[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
        }
        else if (puVar4[(uint)uVar1 * 0x14 + 1] != 0x424c) {
          iVar9 = 0;
          do {
            if (iVar9 == (uVar2 - 1 & 0xffff) * 2) {
              if (uVar2 != 0x13) goto LAB_002fe0ea;
              goto LAB_002fe060;
            }
            iVar9 = iVar9 + 2;
          } while (*(short *)((int)puVar4 + iVar9 + (uint)uVar1 * 0x28 + 2) != 0x424c);
        }
      }
      else if ((puVar4[0x7d1] == 100) || (puVar8[1] != 0)) {
LAB_002fe060:
        puVar8[1] = 0;
        *puVar3 = *puVar3 | 0x100;
      }
      else {
        piVar5 = *(int **)(unaff_EBX + 0x8a8868);
        *puVar8 = puVar4[0x7d1];
        puVar6 = (ushort *)*piVar5;
        puVar4 = puVar6 + 0x7d1;
        *puVar4 = *puVar4 + 1;
        puVar8[1] = *puVar6;
        iVar9 = *piVar5 + (uint)*puVar8 * 0x28;
        *(undefined2 *)(iVar9 + 2) = 0x424c;
        *(undefined2 *)(iVar9 + 0x28) = 1;
      }
    }
    in_stack_00000004[0x1093] = 0;
  }
  else {
    *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
    in_stack_00000004[0x1093] = 0;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ChargeBayonet
 * Address: 002ff080  Size: 96 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ChargeBayonet() */

void __thiscall CINSWeaponBallistic::ChargeBayonet(CINSWeaponBallistic *this)

{
  int iVar1;
  CINSWeaponBallistic *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSWeapon *extraout_ECX;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = GetBoltState(this_00);
  this_02 = this_01;
  if ((iVar1 == 2) && (*(int *)((int)in_stack_00000004 + 0x424c) != 1)) {
    CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
    *(undefined4 *)((int)in_stack_00000004 + 0x424c) = 1;
    this_02 = (CBaseEntity *)extraout_ECX;
  }
  CINSWeapon::ChargeBayonet((CINSWeapon *)this_02);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CINSWeaponBallistic
 * Address: 002ff910  Size: 886 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CINSWeaponBallistic() */

void __thiscall CINSWeaponBallistic::CINSWeaponBallistic(CINSWeaponBallistic *this)

{
  CINSWeaponBallistic *pCVar1;
  ushort uVar2;
  ushort uVar3;
  uint *puVar4;
  ushort *puVar5;
  int *piVar6;
  ushort *puVar7;
  ushort *puVar8;
  CINSWeapon *this_00;
  CBaseEdict *this_01;
  CBaseEntity *this_02;
  CBaseEdict *this_03;
  CBaseEdict *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CINSWeaponBallistic *pCVar9;
  CINSWeaponBallistic *pCVar10;
  int iVar11;
  int unaff_EBX;
  int *in_stack_00000004;
  uint local_20;
  
  __i686_get_pc_thunk_bx();
  CINSWeapon::CINSWeapon(this_00);
  *in_stack_00000004 = unaff_EBX + 0x833fea;
  in_stack_00000004[0x1090] = 0;
  in_stack_00000004[0x1091] = 0;
  *(undefined1 *)(in_stack_00000004 + 0x1092) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x4249) = 0;
  in_stack_00000004[0x1093] = 0;
  if ((char)in_stack_00000004[0x17] == '\0') {
    puVar4 = (uint *)in_stack_00000004[8];
    pCVar10 = (CINSWeaponBallistic *)this_01;
    if ((puVar4 != (uint *)0x0) &&
       (pCVar10 = (CINSWeaponBallistic *)this_01, (*puVar4 & 0x100) == 0)) {
      *puVar4 = *puVar4 | 1;
      puVar8 = (ushort *)CBaseEdict::GetChangeAccessor(this_01);
      pCVar10 = (CINSWeaponBallistic *)(uint)puVar8[1];
      puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a6e5e);
      if (pCVar10 == (CINSWeaponBallistic *)(uint)*puVar5) {
        pCVar1 = (CINSWeaponBallistic *)(puVar5 + (uint)*puVar8 * 0x14);
        pCVar9 = pCVar1 + 2;
        uVar2 = *(ushort *)(pCVar1 + 0x28);
        local_20 = (uint)uVar2;
        if (uVar2 == 0) {
LAB_002ffc0a:
          *(undefined2 *)(pCVar9 + local_20 * 2) = 0x4240;
          *(ushort *)(pCVar1 + 0x28) = uVar2 + 1;
          pCVar10 = pCVar9;
        }
        else {
          pCVar10 = pCVar1;
          if (*(ushort *)(pCVar1 + 2) != 0x4240) {
            iVar11 = 0;
            do {
              if (iVar11 == (local_20 - 1 & 0xffff) * 2) {
                if (uVar2 != 0x13) goto LAB_002ffc0a;
                goto LAB_002ffb48;
              }
              iVar11 = iVar11 + 2;
              pCVar10 = pCVar9;
            } while (*(short *)(pCVar9 + iVar11) != 0x4240);
          }
        }
      }
      else {
        pCVar9 = (CINSWeaponBallistic *)(uint)*puVar5;
        if ((puVar5[0x7d1] == 100) || (pCVar9 = pCVar10, pCVar10 != (CINSWeaponBallistic *)0x0)) {
LAB_002ffb48:
          puVar8[1] = 0;
          *puVar4 = *puVar4 | 0x100;
          pCVar10 = pCVar9;
        }
        else {
          pCVar10 = *(CINSWeaponBallistic **)(unaff_EBX + 0x8a6e5e);
          *puVar8 = puVar5[0x7d1];
          puVar7 = *(ushort **)pCVar10;
          puVar5 = puVar7 + 0x7d1;
          *puVar5 = *puVar5 + 1;
          puVar8[1] = *puVar7;
          iVar11 = *(int *)pCVar10 + (uint)*puVar8 * 0x28;
          *(undefined2 *)(iVar11 + 2) = 0x4240;
          *(undefined2 *)(iVar11 + 0x28) = 1;
        }
      }
    }
  }
  else {
    *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
    pCVar10 = (CINSWeaponBallistic *)this_01;
  }
  in_stack_00000004[0x1090] = -1;
  ResetBurst(pCVar10);
  this_03 = (CBaseEdict *)this_02;
  if ((char)in_stack_00000004[0x1092] != '\x01') {
    CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
    *(undefined1 *)(in_stack_00000004 + 0x1092) = 1;
    this_03 = (CBaseEdict *)extraout_ECX_00;
  }
  if (*(char *)((int)in_stack_00000004 + 0x4249) != '\0') {
    CBaseEntity::NetworkStateChanged((CBaseEntity *)this_03,in_stack_00000004);
    *(undefined1 *)((int)in_stack_00000004 + 0x4249) = 0;
    this_03 = extraout_ECX;
  }
  if (in_stack_00000004[0x1093] == 0) {
    return;
  }
  if ((char)in_stack_00000004[0x17] == '\0') {
    puVar4 = (uint *)in_stack_00000004[8];
    if ((puVar4 != (uint *)0x0) && ((*puVar4 & 0x100) == 0)) {
      *puVar4 = *puVar4 | 1;
      puVar8 = (ushort *)CBaseEdict::GetChangeAccessor(this_03);
      puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a6e5e);
      if (puVar8[1] == *puVar5) {
        uVar2 = *puVar8;
        uVar3 = puVar5[(uint)uVar2 * 0x14 + 0x14];
        if (uVar3 == 0) {
LAB_002ffcaa:
          puVar5[(uint)uVar2 * 0x14 + uVar3 + 1] = 0x424c;
          puVar5[(uint)uVar2 * 0x14 + 0x14] = uVar3 + 1;
        }
        else if (puVar5[(uint)uVar2 * 0x14 + 1] != 0x424c) {
          iVar11 = 0;
          do {
            if (iVar11 == (uVar3 - 1 & 0xffff) * 2) {
              if (uVar3 != 0x13) goto LAB_002ffcaa;
              goto LAB_002ffb78;
            }
            iVar11 = iVar11 + 2;
          } while (*(short *)((int)puVar5 + iVar11 + (uint)uVar2 * 0x28 + 2) != 0x424c);
        }
      }
      else if ((puVar5[0x7d1] == 100) || (puVar8[1] != 0)) {
LAB_002ffb78:
        puVar8[1] = 0;
        *puVar4 = *puVar4 | 0x100;
      }
      else {
        piVar6 = *(int **)(unaff_EBX + 0x8a6e5e);
        *puVar8 = puVar5[0x7d1];
        puVar7 = (ushort *)*piVar6;
        puVar5 = puVar7 + 0x7d1;
        *puVar5 = *puVar5 + 1;
        puVar8[1] = *puVar7;
        iVar11 = *piVar6 + (uint)*puVar8 * 0x28;
        *(undefined2 *)(iVar11 + 2) = 0x424c;
        *(undefined2 *)(iVar11 + 0x28) = 1;
      }
    }
    in_stack_00000004[0x1093] = 0;
  }
  else {
    *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
    in_stack_00000004[0x1093] = 0;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::CycleFiremodes
 * Address: 002ff110  Size: 1040 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::CycleFiremodes() */

undefined4 __thiscall CINSWeaponBallistic::CycleFiremodes(CINSWeaponBallistic *this)

{
  ushort uVar1;
  ushort uVar2;
  uint *puVar3;
  code *pcVar4;
  ushort *puVar5;
  ushort *puVar6;
  char cVar7;
  int iVar8;
  undefined4 uVar9;
  int *piVar10;
  ushort *puVar11;
  CBaseEdict *extraout_ECX;
  CBaseEdict *this_00;
  CINSPlayer *this_01;
  CBaseEdict *extraout_ECX_00;
  CBaseAnimating *extraout_ECX_01;
  CBaseAnimating *this_02;
  CBaseEntity *this_03;
  CBaseEdict *extraout_ECX_02;
  CBaseAnimating *this_04;
  CBaseAnimating *extraout_ECX_03;
  int unaff_EBX;
  int iVar12;
  float10 fVar13;
  float fVar14;
  CStudioHdr *in_stack_00000004;
  int iVar15;
  uint local_24;
  
  __i686_get_pc_thunk_bx();
  iVar8 = *(int *)(in_stack_00000004 + 0x4240);
  iVar12 = iVar8;
  while( true ) {
    iVar12 = iVar12 + 1;
    if (6 < iVar12) {
      iVar12 = 0;
    }
    cVar7 = (**(code **)(*(int *)in_stack_00000004 + 0x750))(in_stack_00000004,iVar12);
    if (cVar7 != '\0') break;
    if (iVar12 == iVar8) {
      return 0;
    }
  }
  if (iVar8 == iVar12) {
    return 0;
  }
  cVar7 = (**(code **)(*(int *)in_stack_00000004 + 0x648))(in_stack_00000004);
  this_00 = extraout_ECX;
  if ((cVar7 == '\0') &&
     (cVar7 = CINSWeapon::InBipodTransition(), this_00 = extraout_ECX_00, cVar7 == '\0')) {
    uVar9 = (**(code **)(*(int *)in_stack_00000004 + 0x6d8))(in_stack_00000004);
    (**(code **)(*(int *)in_stack_00000004 + 0x3f8))(in_stack_00000004,uVar9);
    uVar9 = *(undefined4 *)(in_stack_00000004 + 0x3d0);
    fVar14 = *(float *)(**(int **)(&LAB_008a7785 + unaff_EBX) + 0xc);
    piVar10 = (int *)0x0;
    this_02 = extraout_ECX_01;
    if (in_stack_00000004[0x32d] == (CStudioHdr)0x0) {
      if ((*(int *)(in_stack_00000004 + 0x498) == 0) &&
         (iVar8 = CBaseEntity::GetModel(), this_02 = this_04, iVar8 != 0)) {
        CBaseAnimating::LockStudioHdr(this_04);
        this_02 = extraout_ECX_03;
      }
      piVar10 = *(int **)(in_stack_00000004 + 0x498);
      if ((piVar10 != (int *)0x0) && (this_02 = (CBaseAnimating *)0x0, *piVar10 == 0)) {
        piVar10 = (int *)0x0;
      }
    }
    fVar13 = (float10)CBaseAnimating::SequenceDuration(this_02,in_stack_00000004,(int)piVar10);
    fVar14 = (float)fVar13 + fVar14;
    if (*(float *)(in_stack_00000004 + 0x4b4) != fVar14) {
      CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
      *(float *)(in_stack_00000004 + 0x4b4) = fVar14;
    }
    (**(code **)(*(int *)in_stack_00000004 + 0x408))(in_stack_00000004,fVar14,uVar9);
    this_00 = extraout_ECX_02;
  }
  if (*(int *)(in_stack_00000004 + 0x4240) != iVar12) {
    if (in_stack_00000004[0x5c] == (CStudioHdr)0x0) {
      puVar3 = *(uint **)(in_stack_00000004 + 0x20);
      if ((puVar3 != (uint *)0x0) && ((*puVar3 & 0x100) == 0)) {
        *puVar3 = *puVar3 | 1;
        puVar11 = (ushort *)CBaseEdict::GetChangeAccessor(this_00);
        puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a7661);
        if (puVar11[1] == *puVar5) {
          uVar1 = *puVar11;
          uVar2 = puVar5[(uint)uVar1 * 0x14 + 0x14];
          local_24 = (uint)uVar2;
          if (uVar2 == 0) {
LAB_002ff4d2:
            puVar5[(uint)uVar1 * 0x14 + local_24 + 1] = 0x4240;
            puVar5[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
          }
          else if (puVar5[(uint)uVar1 * 0x14 + 1] != 0x4240) {
            iVar8 = 0;
            do {
              if (iVar8 == (local_24 - 1 & 0xffff) * 2) {
                if (uVar2 != 0x13) goto LAB_002ff4d2;
                goto LAB_002ff4ef;
              }
              iVar8 = iVar8 + 2;
            } while (*(short *)((int)puVar5 + iVar8 + (uint)uVar1 * 0x28 + 2) != 0x4240);
          }
        }
        else if ((puVar5[0x7d1] == 100) || (puVar11[1] != 0)) {
LAB_002ff4ef:
          puVar11[1] = 0;
          *puVar3 = *puVar3 | 0x100;
        }
        else {
          piVar10 = *(int **)(unaff_EBX + 0x8a7661);
          *puVar11 = puVar5[0x7d1];
          puVar6 = (ushort *)*piVar10;
          puVar5 = puVar6 + 0x7d1;
          *puVar5 = *puVar5 + 1;
          puVar11[1] = *puVar6;
          iVar8 = *piVar10 + (uint)*puVar11 * 0x28;
          *(undefined2 *)(iVar8 + 2) = 0x4240;
          *(undefined2 *)(iVar8 + 0x28) = 1;
        }
      }
    }
    else {
      in_stack_00000004[0x60] = (CStudioHdr)((byte)in_stack_00000004[0x60] | 1);
    }
    *(int *)(in_stack_00000004 + 0x4240) = iVar12;
  }
  iVar8 = CINSWeapon::GetINSPlayerOwner();
  if (iVar8 == 0) {
    return 1;
  }
  uVar9 = CINSWeapon::GetWeaponDefinitionHandle((CINSWeapon *)0x1);
  CINSPlayer::GetPlayerInventory(this_01);
  iVar15 = iVar12;
  CPlayerInventory::UpdateFiremodePreference();
  piVar10 = (int *)**(undefined4 **)(unaff_EBX + 0x8a7db5);
  pcVar4 = *(code **)(*piVar10 + 0x1c);
  uVar9 = LookupEventByID(0x6c,uVar9,iVar15);
  piVar10 = (int *)(*pcVar4)(piVar10,uVar9,0,0);
  if (piVar10 != (int *)0x0) {
    pcVar4 = *(code **)(*piVar10 + 0x34);
    uVar9 = CINSWeapon::GetWeaponDefinitionHandle((CINSWeapon *)0x1);
    (*pcVar4)(piVar10,unaff_EBX + 0x62a4ed,uVar9);
    pcVar4 = *(code **)(*piVar10 + 0x34);
    uVar9 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x8a750d) + 0x40))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x8a750d),*(undefined4 *)(iVar8 + 0x20))
    ;
    (*pcVar4)(piVar10,unaff_EBX + 0x653cee,uVar9);
    (**(code **)(*piVar10 + 0x34))(piVar10,unaff_EBX + 0x647d22,iVar12);
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x8a7db5) + 0x20))
              ((int *)**(undefined4 **)(unaff_EBX + 0x8a7db5),piVar10,0);
    return 1;
  }
  return 1;
}



/* ----------------------------------------
 * CINSWeaponBallistic::DecrementAmmo
 * Address: 002feb90  Size: 525 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::DecrementAmmo() */

void __thiscall CINSWeaponBallistic::DecrementAmmo(CINSWeaponBallistic *this)

{
  ushort uVar1;
  ushort uVar2;
  uint *puVar3;
  ushort *puVar4;
  int *piVar5;
  ushort *puVar6;
  char cVar7;
  ushort *puVar8;
  CBaseCombatWeapon *this_00;
  CINSWeaponBallistic *this_01;
  CBaseEdict *this_02;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_03;
  CINSWeapon *extraout_ECX_00;
  CINSWeapon *this_04;
  CBaseEntity *extraout_ECX_01;
  int iVar9;
  int unaff_EBX;
  int *in_stack_00000004;
  uint local_20;
  
  __i686_get_pc_thunk_bx();
  cVar7 = CBaseCombatWeapon::UsesPrimaryAmmo(this_00);
  if (cVar7 == '\0') {
    return;
  }
  cVar7 = IsBoltAction(this_01);
  if (cVar7 != '\0') {
    if (in_stack_00000004[0x1093] != 1) {
      if ((char)in_stack_00000004[0x17] == '\0') {
        puVar3 = (uint *)in_stack_00000004[8];
        if ((puVar3 != (uint *)0x0) && ((*puVar3 & 0x100) == 0)) {
          *puVar3 = *puVar3 | 1;
          puVar8 = (ushort *)CBaseEdict::GetChangeAccessor(this_02);
          puVar4 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a7bde);
          if (puVar8[1] == *puVar4) {
            uVar1 = *puVar8;
            uVar2 = puVar4[(uint)uVar1 * 0x14 + 0x14];
            local_20 = (uint)uVar2;
            if (uVar2 == 0) {
LAB_002fedaa:
              puVar4[(uint)uVar1 * 0x14 + local_20 + 1] = 0x424c;
              puVar4[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
            }
            else if (puVar4[(uint)uVar1 * 0x14 + 1] != 0x424c) {
              iVar9 = 0;
              do {
                if (iVar9 == (local_20 - 1 & 0xffff) * 2) {
                  if (uVar2 != 0x13) goto LAB_002fedaa;
                  goto LAB_002fed20;
                }
                iVar9 = iVar9 + 2;
              } while (*(short *)((int)puVar4 + iVar9 + (uint)uVar1 * 0x28 + 2) != 0x424c);
            }
          }
          else if ((puVar4[0x7d1] == 100) || (puVar8[1] != 0)) {
LAB_002fed20:
            puVar8[1] = 0;
            *puVar3 = *puVar3 | 0x100;
          }
          else {
            piVar5 = *(int **)(unaff_EBX + 0x8a7bde);
            *puVar8 = puVar4[0x7d1];
            puVar6 = (ushort *)*piVar5;
            puVar4 = puVar6 + 0x7d1;
            *puVar4 = *puVar4 + 1;
            puVar8[1] = *puVar6;
            iVar9 = *piVar5 + (uint)*puVar8 * 0x28;
            *(undefined2 *)(iVar9 + 2) = 0x424c;
            *(undefined2 *)(iVar9 + 0x28) = 1;
          }
        }
      }
      else {
        *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
      }
      in_stack_00000004[0x1093] = 1;
    }
    cVar7 = (**(code **)(*in_stack_00000004 + 0x744))(in_stack_00000004);
    this_03 = extraout_ECX;
    if (cVar7 != '\0') goto LAB_002fec1a;
  }
  cVar7 = (**(code **)(*in_stack_00000004 + 0x548))(in_stack_00000004);
  this_04 = extraout_ECX_00;
  if (((cVar7 == '\0') || (0 < in_stack_00000004[0x134])) ||
     (cVar7 = (**(code **)(*in_stack_00000004 + 0x744))(in_stack_00000004),
     this_03 = extraout_ECX_01, this_04 = (CINSWeapon *)extraout_ECX_01, cVar7 == '\0')) {
    CINSWeapon::DecrementAmmo(this_04);
    return;
  }
LAB_002fec1a:
  if (*(char *)((int)in_stack_00000004 + 0x4249) != '\0') {
    CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
    *(undefined1 *)((int)in_stack_00000004 + 0x4249) = 0;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::FinishCocking
 * Address: 002ffce0  Size: 493 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::FinishCocking() */

void __thiscall CINSWeaponBallistic::FinishCocking(CINSWeaponBallistic *this)

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint *puVar4;
  ushort *puVar5;
  int *piVar6;
  ushort *puVar7;
  CBaseEdict *this_00;
  char cVar8;
  ushort *puVar9;
  int iVar10;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEdict *extraout_ECX;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000004[0x1093] != 0) {
    CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
    in_stack_00000004[0x1093] = 0;
  }
  cVar8 = (**(code **)(*in_stack_00000004 + 0x744))();
  if (cVar8 == '\0') {
    return;
  }
  if (*(char *)((int)in_stack_00000004 + 0x4249) == '\x01') {
    iVar3 = in_stack_00000004[0x134];
    cVar8 = (char)in_stack_00000004[0x17];
    this_00 = (CBaseEdict *)this_02;
  }
  else {
    CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
    iVar3 = in_stack_00000004[0x134];
    *(undefined1 *)((int)in_stack_00000004 + 0x4249) = 1;
    cVar8 = (char)in_stack_00000004[0x17];
    this_00 = extraout_ECX;
  }
  if (cVar8 == '\0') {
    puVar4 = (uint *)in_stack_00000004[8];
    if ((puVar4 != (uint *)0x0) && ((*puVar4 & 0x100) == 0)) {
      *puVar4 = *puVar4 | 1;
      puVar9 = (ushort *)CBaseEdict::GetChangeAccessor(this_00);
      puVar5 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a6a88);
      if (puVar9[1] == *puVar5) {
        uVar1 = *puVar9;
        uVar2 = puVar5[(uint)uVar1 * 0x14 + 0x14];
        if (uVar2 == 0) {
LAB_002ffeb2:
          puVar5[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x4d0;
          puVar5[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
        }
        else if (puVar5[(uint)uVar1 * 0x14 + 1] != 0x4d0) {
          iVar10 = 0;
          do {
            if (iVar10 == (uVar2 - 1 & 0xffff) * 2) {
              if (uVar2 == 0x13) goto LAB_002ffed0;
              goto LAB_002ffeb2;
            }
            iVar10 = iVar10 + 2;
          } while (*(short *)((int)puVar5 + iVar10 + (uint)uVar1 * 0x28 + 2) != 0x4d0);
        }
      }
      else if ((puVar5[0x7d1] == 100) || (puVar9[1] != 0)) {
LAB_002ffed0:
        puVar9[1] = 0;
        *puVar4 = *puVar4 | 0x100;
      }
      else {
        piVar6 = *(int **)(unaff_EBX + 0x8a6a88);
        *puVar9 = puVar5[0x7d1];
        puVar7 = (ushort *)*piVar6;
        puVar5 = puVar7 + 0x7d1;
        *puVar5 = *puVar5 + 1;
        puVar9[1] = *puVar7;
        iVar10 = *piVar6 + (uint)*puVar9 * 0x28;
        *(undefined2 *)(iVar10 + 2) = 0x4d0;
        *(undefined2 *)(iVar10 + 0x28) = 1;
      }
    }
  }
  else {
    *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
  }
  in_stack_00000004[0x134] = iVar3 + -1;
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::FinishReload
 * Address: 002fedd0  Size: 191 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::FinishReload() */

void __thiscall CINSWeaponBallistic::FinishReload(CINSWeaponBallistic *this)

{
  char cVar1;
  CINSWeapon *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar2;
  CBaseEntity *extraout_ECX_00;
  CINSWeaponBallistic *this_01;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CINSWeapon::FinishReload(this_00);
  pCVar2 = extraout_ECX;
  if ((0 < in_stack_00000004[0x134]) ||
     ((cVar1 = (**(code **)(*in_stack_00000004 + 0x744))(in_stack_00000004), cVar1 != '\0' &&
      (pCVar2 = extraout_ECX_02, *(char *)((int)in_stack_00000004 + 0x4249) != '\0')))) {
    if ((char)in_stack_00000004[0x1092] == '\0') {
      cVar1 = IsBoltAction((CINSWeaponBallistic *)pCVar2);
      pCVar2 = extraout_ECX_00;
    }
    else {
      CBaseEntity::NetworkStateChanged(pCVar2,in_stack_00000004);
      *(undefined1 *)(in_stack_00000004 + 0x1092) = 0;
      cVar1 = IsBoltAction(this_01);
      pCVar2 = extraout_ECX_01;
    }
    if ((cVar1 != '\0') && (in_stack_00000004[0x1093] != 0)) {
      CBaseEntity::NetworkStateChanged(pCVar2,in_stack_00000004);
      in_stack_00000004[0x1093] = 0;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::FireBullet
 * Address: 003009d0  Size: 1314 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::FireBullet() */

void __thiscall CINSWeaponBallistic::FireBullet(CINSWeaponBallistic *this)

{
  Vector VVar1;
  ushort uVar2;
  ushort uVar3;
  int *piVar4;
  uint *puVar5;
  code *pcVar6;
  ushort *puVar7;
  ushort *puVar8;
  char cVar9;
  Vector *pVVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  CAmmoDef *this_00;
  undefined4 uVar14;
  int *piVar15;
  ushort *puVar16;
  int iVar17;
  CINSWeapon *this_01;
  CINSWeaponBallistic *extraout_ECX;
  CINSWeaponBallistic *this_02;
  CBaseEdict *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeaponBallistic *extraout_ECX_00;
  CINSWeaponBallistic *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar18;
  float fVar19;
  Vector *in_stack_00000004;
  CINSPlayer *local_68;
  uint local_64;
  QAngle *local_58;
  Vector local_4c [12];
  QAngle local_40 [12];
  QAngle local_34 [12];
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x3009db;
  __i686_get_pc_thunk_bx();
  pVVar10 = (Vector *)CINSWeapon::GetINSPlayerOwner();
  if (pVVar10 != (Vector *)0x0) {
    piVar4 = (int *)**(undefined4 **)(unaff_EBX + 0x8a6771);
    (**(code **)(*piVar4 + 0x80))(piVar4);
    iVar11 = CINSWeapon::GetWeaponDefinition(this_01);
    if (iVar11 != 0) {
      cVar9 = (**(code **)(*(int *)pVVar10 + 0x5e0))(pVVar10);
      if (cVar9 == '\0') {
        CINSPlayer::CalcThirdPersonMuzzleData((CINSPlayer *)local_40,pVVar10,local_4c);
        this_02 = extraout_ECX_00;
      }
      else {
        cVar9 = (**(code **)(*(int *)in_stack_00000004 + 0x5f4))(in_stack_00000004);
        if ((cVar9 == '\0') &&
           (cVar9 = (**(code **)(*(int *)in_stack_00000004 + 0x620))(in_stack_00000004),
           cVar9 == '\0')) {
          CINSPlayer::CalculateMuzzleEyeData(pVVar10,(QAngle *)local_4c);
          AngleVectors(local_34,(Vector *)local_40);
          this_02 = extraout_ECX_01;
        }
        else {
          CINSWeapon::FindMuzzle(in_stack_00000004,local_4c,SUB41(local_40,0));
          this_02 = extraout_ECX;
        }
      }
      local_58 = local_40;
      local_68 = (CINSPlayer *)local_4c;
      fVar18 = (float10)GetFireCycle(this_02);
      fVar19 = (float)fVar18 + *(float *)(**(int **)(unaff_EBX + 0x8a5ec5) + 0xc);
      if (*(float *)(in_stack_00000004 + 0x4b4) != fVar19) {
        if (in_stack_00000004[0x5c] == (Vector)0x0) {
          puVar5 = *(uint **)(in_stack_00000004 + 0x20);
          if ((puVar5 != (uint *)0x0) && ((*puVar5 & 0x100) == 0)) {
            *puVar5 = *puVar5 | 1;
            puVar16 = (ushort *)CBaseEdict::GetChangeAccessor(this_03);
            puVar7 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a5da1);
            if (puVar16[1] == *puVar7) {
              uVar2 = *puVar16;
              uVar3 = puVar7[(uint)uVar2 * 0x14 + 0x14];
              local_64 = (uint)uVar3;
              if (uVar3 == 0) {
LAB_00300ee6:
                puVar7[(uint)uVar2 * 0x14 + local_64 + 1] = 0x4b4;
                puVar7[(uint)uVar2 * 0x14 + 0x14] = uVar3 + 1;
              }
              else if (puVar7[(uint)uVar2 * 0x14 + 1] != 0x4b4) {
                iVar17 = 0;
                do {
                  if (iVar17 == (local_64 - 1 & 0xffff) * 2) {
                    if (uVar3 == 0x13) goto LAB_00300e50;
                    goto LAB_00300ee6;
                  }
                  iVar17 = iVar17 + 2;
                } while (*(short *)((int)puVar7 + iVar17 + (uint)uVar2 * 0x28 + 2) != 0x4b4);
              }
            }
            else if (puVar7[0x7d1] == 100) {
              puVar16[1] = 0;
              *puVar5 = *puVar5 | 0x100;
            }
            else if (puVar16[1] == 0) {
              piVar15 = *(int **)(unaff_EBX + 0x8a5da1);
              *puVar16 = puVar7[0x7d1];
              puVar8 = (ushort *)*piVar15;
              puVar7 = puVar8 + 0x7d1;
              *puVar7 = *puVar7 + 1;
              puVar16[1] = *puVar8;
              iVar17 = *piVar15 + (uint)*puVar16 * 0x28;
              *(undefined2 *)(iVar17 + 2) = 0x4b4;
              *(undefined2 *)(iVar17 + 0x28) = 1;
            }
            else {
LAB_00300e50:
              puVar16[1] = 0;
              *puVar5 = *puVar5 | 0x100;
            }
          }
        }
        else {
          in_stack_00000004[0x60] = (Vector)((byte)in_stack_00000004[0x60] | 1);
        }
        *(float *)(in_stack_00000004 + 0x4b4) = fVar19;
      }
      iVar17 = *(int *)(in_stack_00000004 + 0x4d0);
      VVar1 = in_stack_00000004[0x4249];
      fVar18 = (float10)GetSpreadMod();
      local_20 = (float)fVar18;
      local_28 = local_20 * *(float *)(iVar11 + 0x1a8);
      local_24 = *(float *)(iVar11 + 0x1ac) * local_20;
      local_20 = local_20 * *(float *)(iVar11 + 0x1b0);
      iVar12 = (**(code **)(*(int *)in_stack_00000004 + 0x558))(in_stack_00000004);
      iVar13 = CINSWeapon::GetWeaponDefinitionHandle(this_04);
      CINSPlayer::FireBullet
                (local_68,pVVar10,(Vector *)local_68,local_58,(float)&local_28,0x3f800000 /* 1.0f */,iVar13,
                 iVar12,(uint)(byte)VVar1 + iVar17);
      (**(code **)(*(int *)in_stack_00000004 + 0x4bc))
                (in_stack_00000004,1,*(undefined4 *)(in_stack_00000004 + 0x4b4));
      (**(code **)(*(int *)in_stack_00000004 + 0x74c))(in_stack_00000004);
      if (*(float *)(iVar11 + 0x194) <= 0.0) {
        pcVar6 = *(code **)(*(int *)in_stack_00000004 + 0x3f8);
        uVar14 = (**(code **)(*(int *)in_stack_00000004 + 0x6d4))(in_stack_00000004);
        (*pcVar6)(in_stack_00000004,uVar14);
      }
      this_00 = (CAmmoDef *)(**(code **)(*(int *)in_stack_00000004 + 0x558))(in_stack_00000004);
      iVar11 = GetAmmoDef();
      iVar11 = CAmmoDef::GetAmmoOfIndex(this_00,iVar11);
      if (iVar11 != 0) {
        piVar15 = (int *)**(undefined4 **)(unaff_EBX + 0x8a64f5);
        pcVar6 = *(code **)(*piVar15 + 0x1c);
        uVar14 = LookupEventByID(0x45,this_00);
        piVar15 = (int *)(*pcVar6)(piVar15,uVar14,0,0);
        if (piVar15 != (int *)0x0) {
          pcVar6 = *(code **)(*piVar15 + 0x34);
          uVar14 = CINSWeapon::GetWeaponDefinitionHandle(this_05);
          (*pcVar6)(piVar15,unaff_EBX + 0x628c2d,uVar14);
          pcVar6 = *(code **)(*piVar15 + 0x34);
          uVar14 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x8a5c4d) + 0x40))
                             ((int *)**(undefined4 **)(unaff_EBX + 0x8a5c4d),
                              *(undefined4 *)(pVVar10 + 0x20));
          (*pcVar6)(piVar15,unaff_EBX + 0x65242e,uVar14);
          (**(code **)(*piVar15 + 0x34))
                    (piVar15,unaff_EBX + 0x659209,*(undefined4 *)(iVar11 + 0x10));
          (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x8a64f5) + 0x20))
                    ((int *)**(undefined4 **)(unaff_EBX + 0x8a64f5),piVar15,0);
        }
      }
      (**(code **)(*(int *)in_stack_00000004 + 0x748))(in_stack_00000004);
      (**(code **)(*(int *)in_stack_00000004 + 0x408))
                (in_stack_00000004,
                 *(float *)(unaff_EBX + 0x5b8139) + *(float *)(in_stack_00000004 + 0x4b4));
    }
    (**(code **)(*piVar4 + 0x84))(piVar4);
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetBallisticBase
 * Address: 00300f90  Size: 8 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetBallisticBase() */

undefined4 __thiscall CINSWeaponBallistic::GetBallisticBase(CINSWeaponBallistic *this)

{
  undefined4 in_stack_00000004;
  
  return in_stack_00000004;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetBaseMap
 * Address: 002fe580  Size: 22 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetBaseMap() */

undefined4 CINSWeaponBallistic::GetBaseMap(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return *(undefined4 *)(&DAT_008a8443 + extraout_ECX);
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetBoltActionActivity
 * Address: 002fdca0  Size: 172 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetBoltActionActivity() const */

int __thiscall CINSWeaponBallistic::GetBoltActionActivity(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSWeapon::InIronsights();
  if (cVar1 != '\0') {
    cVar1 = CINSWeapon::InBipod();
    if ((cVar1 != '\0') &&
       (cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xf6), cVar1 != '\0')) {
      return 0xf6;
    }
    cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xf5);
    if (cVar1 != '\0') {
      return 0xf5;
    }
  }
  cVar1 = CINSWeapon::InBipod();
  if (cVar1 == '\0') {
    return 0xf9;
  }
  cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xfa);
  return 0xfa - (uint)(cVar1 == '\0');
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetBoltSpeedModifier
 * Address: 002fff50  Size: 114 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetBoltSpeedModifier() */

float10 __thiscall CINSWeaponBallistic::GetBoltSpeedModifier(CINSWeaponBallistic *this)

{
  int iVar1;
  int iVar2;
  CINSWeapon *this_00;
  int unaff_EBX;
  float fVar3;
  undefined4 in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CINSWeapon::GetWeaponDefinition(this_00);
  fVar3 = *(float *)(unaff_EBX + 0x5b8bb9);
  if (iVar1 != 0) {
    fVar3 = *(float *)(iVar1 + 0xb34);
    iVar1 = 0;
    do {
      iVar2 = CINSWeapon::GetUpgradeInSlot(in_stack_00000004,iVar1);
      if (iVar2 != 0) {
        fVar3 = fVar3 * *(float *)(iVar2 + 0x378);
      }
      iVar1 = iVar1 + 1;
    } while (iVar1 != 10);
  }
  return (float10)fVar3;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetBoltState
 * Address: 002feea0  Size: 38 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetBoltState() const */

undefined4 __thiscall CINSWeaponBallistic::GetBoltState(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 uVar2;
  int in_stack_00000004;
  
  cVar1 = IsBoltAction(this);
  uVar2 = 0;
  if (cVar1 != '\0') {
    uVar2 = *(undefined4 *)(in_stack_00000004 + 0x424c);
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetDataDescMap
 * Address: 002fdab0  Size: 22 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetDataDescMap() */

char * CINSWeaponBallistic::GetDataDescMap(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return "ACT_GESTURE_DEPLOY_PISTOL_TWOHAND" + extraout_ECX + 0x23;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetFireCycle
 * Address: 00300740  Size: 94 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetFireCycle() const */

float10 __thiscall CINSWeaponBallistic::GetFireCycle(CINSWeaponBallistic *this)

{
  char cVar1;
  int iVar2;
  CINSWeapon *this_00;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_00000004 + 0x754))();
  if (cVar1 == '\0') {
    iVar2 = CINSWeapon::GetWeaponDefinition(this_00);
    return (float10)*(float *)(iVar2 + 0x188);
  }
  iVar2 = CINSWeapon::GetWeaponDefinition(this_00);
  return (float10)*(float *)(iVar2 + 0x18c);
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetFireMode
 * Address: 002fdb20  Size: 14 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetFireMode() const */

undefined4 __thiscall CINSWeaponBallistic::GetFireMode(CINSWeaponBallistic *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x4240);
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetPrimaryAttackActivity
 * Address: 002fe9e0  Size: 255 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetPrimaryAttackActivity() const */

undefined4 __thiscall CINSWeaponBallistic::GetPrimaryAttackActivity(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 uVar2;
  CINSWeaponBallistic *this_00;
  CINSWeapon *extraout_ECX;
  CINSWeapon *extraout_ECX_00;
  CINSWeapon *extraout_ECX_01;
  CINSWeapon *extraout_ECX_02;
  CINSWeapon *pCVar3;
  CINSWeapon *extraout_ECX_03;
  CINSWeapon *extraout_ECX_04;
  undefined4 in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = IsBoltAction(this_00);
  pCVar3 = extraout_ECX;
  if (cVar1 != '\0') {
    cVar1 = CINSWeapon::InIronsights();
    if (cVar1 != '\0') {
      cVar1 = CINSWeapon::InBipod();
      pCVar3 = extraout_ECX_00;
      if ((cVar1 != '\0') &&
         (cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xf4),
         pCVar3 = extraout_ECX_04, cVar1 != '\0')) {
        return 0xf4;
      }
      cVar1 = CINSWeapon::IsLastBullet(pCVar3);
      if ((cVar1 != '\0') &&
         (cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0x113), cVar1 != '\0')) {
        return 0x113;
      }
      cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xf3);
      if (cVar1 != '\0') {
        return 0xf3;
      }
    }
    cVar1 = CINSWeapon::InBipod();
    pCVar3 = extraout_ECX_01;
    if ((cVar1 != '\0') &&
       (cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,0xf8),
       pCVar3 = extraout_ECX_03, cVar1 != '\0')) {
      return 0xf8;
    }
    cVar1 = CINSWeapon::IsLastBullet(pCVar3);
    pCVar3 = extraout_ECX_02;
    if (cVar1 == '\0') {
      return 0xf7;
    }
  }
  uVar2 = CINSWeapon::GetPrimaryAttackActivity(pCVar3);
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetReloadActivity
 * Address: 002feaf0  Size: 146 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetReloadActivity() const */

void __thiscall CINSWeaponBallistic::GetReloadActivity(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 uVar2;
  CINSWeaponBallistic *this_00;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *extraout_ECX;
  CINSWeapon *extraout_ECX_00;
  CINSWeapon *extraout_ECX_01;
  CINSWeapon *extraout_ECX_02;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = IsBoltAction(this_00);
  this_02 = this_01;
  if (cVar1 != '\0') {
    cVar1 = CINSWeapon::IsSingleReload(this_01);
    this_02 = extraout_ECX;
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*in_stack_00000004 + 0x744))(in_stack_00000004);
      this_02 = extraout_ECX_00;
      if (cVar1 != '\0') {
        cVar1 = (**(code **)(*in_stack_00000004 + 0x738))(in_stack_00000004);
        this_02 = extraout_ECX_01;
        if (cVar1 == '\0') {
          uVar2 = (**(code **)(*in_stack_00000004 + 0x6e0))(in_stack_00000004);
          cVar1 = CINSWeapon::HaveSequenceForActivity(in_stack_00000004,uVar2);
          this_02 = extraout_ECX_02;
          if (cVar1 != '\0') {
            (**(code **)(*in_stack_00000004 + 0x6e0))(in_stack_00000004);
            return;
          }
        }
      }
    }
  }
  CINSWeapon::GetReloadActivity(this_02);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetServerClass
 * Address: 002fda20  Size: 22 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetServerClass() */

char * CINSWeaponBallistic::GetServerClass(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return "bipod_yaw_limit" + extraout_ECX + 9;
}



/* ----------------------------------------
 * CINSWeaponBallistic::GetSpreadMod
 * Address: 003008e0  Size: 231 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::GetSpreadMod() const */

float10 CINSWeaponBallistic::GetSpreadMod(void)

{
  CUtlRBTree<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
  *this;
  char cVar1;
  int iVar2;
  int iVar3;
  CINSWeapon *this_00;
  CINSPlayer *this_01;
  CINSWeapon *this_02;
  int unaff_EBX;
  int iVar4;
  float10 fVar5;
  float fVar6;
  undefined4 local_30;
  
  __i686_get_pc_thunk_bx();
  fVar5 = (float10)CINSWeapon::GetSpreadFrac(this_00);
  local_30 = (float)fVar5;
  iVar2 = CINSWeapon::GetINSPlayerOwner();
  if (iVar2 != 0) {
    cVar1 = CINSPlayer::IsJumping(this_01);
    if (cVar1 != '\0') {
      iVar2 = CINSWeapon::GetWeaponDefinition(this_02);
      if (iVar2 != 0) {
        fVar6 = *(float *)(iVar2 + 0x1b8);
        if (*(float *)(iVar2 + 0x1b8) <= *(float *)(unaff_EBX + 0x5b8229)) {
          fVar6 = *(float *)(unaff_EBX + 0x5b8229);
        }
        local_30 = fVar6 * local_30;
      }
    }
  }
  iVar2 = *(int *)(**(int **)(unaff_EBX + 0x8a65ed) + 0x18);
  this = (CUtlRBTree<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
          *)(iVar2 + 4);
  iVar4 = 0;
  do {
    iVar3 = CUtlRBTree<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
            ::Find(this,(Node_t *)this);
    if ((iVar3 != -1) && (iVar3 = *(int *)(iVar3 * 0x18 + *(int *)(iVar2 + 8) + 0x14), iVar3 != 0))
    {
      local_30 = local_30 * *(float *)(iVar3 + 0x324);
    }
    iVar4 = iVar4 + 1;
  } while (iVar4 != 9);
  return (float10)local_30;
}



/* ----------------------------------------
 * CINSWeaponBallistic::HandleAnimEvent
 * Address: 002ffef0  Size: 77 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::HandleAnimEvent(animevent_t*) */

void __thiscall CINSWeaponBallistic::HandleAnimEvent(CINSWeaponBallistic *this,animevent_t *param_1)

{
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if ((*(byte *)((int)in_stack_00000008 + 0x11) & 4) == 0) {
    if (*in_stack_00000008 == 0x3f) goto LAB_002fff37;
  }
  else if (*(short *)((int)in_stack_00000008 + 2) == 0x3f) {
LAB_002fff37:
    FinishCocking((CINSWeaponBallistic *)param_1);
    return;
  }
  CINSWeapon::HandleAnimEvent((CINSWeapon *)param_1,param_1);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::HandleFireOnEmpty
 * Address: 003007b0  Size: 295 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::HandleFireOnEmpty() */

void __thiscall CINSWeaponBallistic::HandleFireOnEmpty(CINSWeaponBallistic *this)

{
  float *pfVar1;
  code *pcVar2;
  char cVar3;
  undefined4 uVar4;
  CINSWeaponBallistic *this_00;
  CBaseEntity *this_01;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_00000004;
  int *piVar6;
  
  __i686_get_pc_thunk_bx();
  cVar3 = CINSWeapon::IsHoldingButton();
  if (cVar3 == '\0') {
    piVar6 = (int *)0x0;
    cVar3 = CINSWeapon::IsPreventedUntilButtonRelease();
    if ((cVar3 == '\0') &&
       (pfVar1 = (float *)(**(int **)(unaff_EBX + 0x8a60e2) + 0xc),
       (float)in_stack_00000004[0x12d] < *pfVar1 || (float)in_stack_00000004[0x12d] == *pfVar1)) {
      if ((char)in_stack_00000004[0x1092] == '\0') {
        piVar6 = (int *)0x0;
        (**(code **)(*in_stack_00000004 + 0x4bc))(in_stack_00000004,0,0);
        if ((char)in_stack_00000004[0x1092] != '\x01') {
          piVar6 = in_stack_00000004 + 0x1092;
          CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
          *(undefined1 *)(in_stack_00000004 + 0x1092) = 1;
        }
      }
      pcVar2 = *(code **)(*in_stack_00000004 + 0x3f8);
      uVar4 = (**(code **)(*in_stack_00000004 + 0x6dc))(in_stack_00000004,piVar6);
      (*pcVar2)(in_stack_00000004,uVar4);
      pcVar2 = *(code **)(*in_stack_00000004 + 0x680);
      fVar5 = (float10)GetFireCycle(this_00);
      (*pcVar2)(in_stack_00000004,(float)fVar5,0);
      CINSWeapon::MarkAsHoldingButton();
      CINSWeapon::EmitWeaponGameEvent(in_stack_00000004,0x46,0);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::HasChamberedRound
 * Address: 002fdaf0  Size: 15 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::HasChamberedRound() const */

undefined1 __thiscall CINSWeaponBallistic::HasChamberedRound(CINSWeaponBallistic *this)

{
  int in_stack_00000004;
  
  return *(undefined1 *)(in_stack_00000004 + 0x4249);
}



/* ----------------------------------------
 * CINSWeaponBallistic::HasFireMode
 * Address: 002fdba0  Size: 69 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::HasFireMode(eWeaponFireModes) const */

bool __thiscall CINSWeaponBallistic::HasFireMode(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  CINSWeapon *this;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CINSWeapon::GetWeaponDefinition(this);
  return (*(uint *)(iVar1 + 0x1028 + (param_3 >> 5) * 4) & 1 << ((byte)param_3 & 0x1f)) != 0;
}



/* ----------------------------------------
 * CINSWeaponBallistic::IsBoltAction
 * Address: 002fe990  Size: 67 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::IsBoltAction() const */

undefined4 __thiscall CINSWeaponBallistic::IsBoltAction(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 uVar2;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x754))();
  uVar2 = 1;
  if (cVar1 == '\0') {
    uVar2 = (**(code **)(*in_stack_00000004 + 0x754))();
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponBallistic::IsBoltReady
 * Address: 002ff0f0  Size: 24 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::IsBoltReady() const */

bool __thiscall CINSWeaponBallistic::IsBoltReady(CINSWeaponBallistic *this)

{
  int iVar1;
  
  iVar1 = GetBoltState(this);
  return iVar1 == 0;
}



/* ----------------------------------------
 * CINSWeaponBallistic::IsClosedBolt
 * Address: 002fe690  Size: 70 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::IsClosedBolt() const */

undefined1 CINSWeaponBallistic::IsClosedBolt(void)

{
  int iVar1;
  CINSWeapon *this;
  CINSWeapon *this_00;
  undefined1 uVar2;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CINSWeapon::GetWeaponDefinition(this);
  uVar2 = 1;
  if (iVar1 != 0) {
    iVar1 = CINSWeapon::GetWeaponDefinition(this_00);
    uVar2 = *(undefined1 *)(iVar1 + 0x19d);
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponBallistic::IsFireMode
 * Address: 002fdb00  Size: 20 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::IsFireMode(eWeaponFireModes) const */

bool __thiscall CINSWeaponBallistic::IsFireMode(undefined4 param_1,int param_2,int param_3)

{
  return *(int *)(param_2 + 0x4240) == param_3;
}



/* ----------------------------------------
 * CINSWeaponBallistic::IsFullyAutomatic
 * Address: 002fe6f0  Size: 111 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::IsFullyAutomatic() const */

undefined4 __thiscall CINSWeaponBallistic::IsFullyAutomatic(CINSWeaponBallistic *this)

{
  char cVar1;
  undefined4 uVar2;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x754))();
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x754))();
    if (cVar1 == '\0') {
      uVar2 = (**(code **)(*in_stack_00000004 + 0x754))();
      return uVar2;
    }
  }
  return 1;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ItemDebugPostFrame
 * Address: 002feed0  Size: 325 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ItemDebugPostFrame() */

int __thiscall CINSWeaponBallistic::ItemDebugPostFrame(CINSWeaponBallistic *this)

{
  undefined4 *puVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  CINSWeapon *this_00;
  CINSWeaponBallistic *this_01;
  CINSWeaponBallistic *this_02;
  CINSWeaponBallistic *this_03;
  int iVar7;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar4 = CINSWeapon::ItemDebugPostFrame(this_00);
  puVar1 = *(undefined4 **)(unaff_EBX + 0x8a774d);
  iVar5 = unaff_EBX + 0x694768;
  iVar6 = unaff_EBX + 0x62596e;
  iVar7 = iVar5;
  if (*(char *)(in_stack_00000004 + 0x4248) == '\0') {
    iVar7 = iVar6;
  }
  (**(code **)(*(int *)*puVar1 + 0xbc))((int *)*puVar1,iVar4 + 1,unaff_EBX + 0x63ebf1,iVar7);
  iVar7 = iVar5;
  if (*(char *)(in_stack_00000004 + 0x4249) == '\0') {
    iVar7 = iVar6;
  }
  (**(code **)(*(int *)*puVar1 + 0xbc))((int *)*puVar1,iVar4 + 2,unaff_EBX + 0x63ec01,iVar7);
  pcVar2 = *(code **)(*(int *)*puVar1 + 0xbc);
  cVar3 = IsBoltAction(this_01);
  if (cVar3 == '\0') {
    iVar5 = iVar6;
  }
  (*pcVar2)(*puVar1,iVar4 + 3,unaff_EBX + 0x63ec15,iVar5);
  pcVar2 = *(code **)(*(int *)*puVar1 + 0xbc);
  iVar6 = GetBoltState(this_02);
  iVar5 = unaff_EBX + 0x635aad;
  if (iVar6 != 0) {
    iVar6 = GetBoltState(this_03);
    iVar5 = unaff_EBX + 0x63ebe5;
    if (iVar6 != 1) {
      iVar5 = unaff_EBX + 0x63ebdd;
    }
  }
  (*pcVar2)(*puVar1,iVar4 + 4,unaff_EBX + 0x63ec25,iVar5);
  return iVar4 + 4;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ItemPostFrame
 * Address: 00300550  Size: 458 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ItemPostFrame() */

void __thiscall CINSWeaponBallistic::ItemPostFrame(CINSWeaponBallistic *this)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  CINSWeapon *extraout_ECX;
  CINSWeaponBallistic *extraout_ECX_00;
  CINSWeapon *extraout_ECX_01;
  CINSWeapon *this_00;
  CINSWeaponBallistic *this_01;
  CINSWeaponBallistic *extraout_ECX_02;
  CINSWeaponBallistic *pCVar5;
  CINSWeaponBallistic *extraout_ECX_03;
  CBaseEntity *this_02;
  CINSWeapon *this_03;
  CBaseEntity *this_04;
  CINSWeapon *extraout_ECX_04;
  CINSWeaponBallistic *this_05;
  int unaff_EBX;
  float fVar6;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar3 = CINSWeapon::GetINSPlayerOwner();
  if (iVar3 == 0) {
    return;
  }
  this_00 = extraout_ECX;
  if (0 < in_stack_00000004[0x1091]) {
    cVar2 = (**(code **)(*in_stack_00000004 + 0x668))(in_stack_00000004);
    pCVar5 = extraout_ECX_00;
    if ((cVar2 == '\0') ||
       (cVar2 = (**(code **)(*in_stack_00000004 + 0x740))(in_stack_00000004),
       pCVar5 = extraout_ECX_03, cVar2 != '\0')) {
      ResetBurst(pCVar5);
      this_00 = extraout_ECX_01;
    }
    else {
      this_00 = (CINSWeapon *)in_stack_00000004[0x1091];
      if ((0 < (int)this_00) &&
         (piVar1 = *(int **)(unaff_EBX + 0x8a6342),
         (float)in_stack_00000004[0x12d] <= *(float *)(*piVar1 + 0xc))) {
        (**(code **)(*in_stack_00000004 + 0x768))(in_stack_00000004);
        iVar4 = in_stack_00000004[0x1091];
        CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
        in_stack_00000004[0x1091] = iVar4 + -1;
        iVar4 = CINSWeapon::GetWeaponDefinition(this_03);
        if (in_stack_00000004[0x1091] == 0) {
          fVar6 = *(float *)(iVar4 + 400);
        }
        else {
          fVar6 = *(float *)(iVar4 + 0x188);
        }
        fVar6 = fVar6 + *(float *)(*piVar1 + 0xc);
        this_00 = (CINSWeapon *)this_04;
        if ((float)in_stack_00000004[0x12d] != fVar6) {
          CBaseEntity::NetworkStateChanged(this_04,in_stack_00000004);
          in_stack_00000004[0x12d] = (int)fVar6;
          this_00 = extraout_ECX_04;
        }
      }
    }
  }
  CINSWeapon::ItemPostFrame(this_00);
  cVar2 = IsBoltAction(this_01);
  if ((cVar2 != '\0') &&
     ((float)in_stack_00000004[0x12d] <= *(float *)(**(int **)(unaff_EBX + 0x8a6342) + 0xc))) {
    iVar4 = in_stack_00000004[0x1093];
    pCVar5 = extraout_ECX_02;
    if (iVar4 == 1) {
      if (in_stack_00000004[0x134] < 1) {
        return;
      }
      cVar2 = (**(code **)(*in_stack_00000004 + 0x66c))(in_stack_00000004);
      if ((cVar2 != '\0') && ((*(byte *)(iVar3 + 0xf24) & 1) == 0)) {
        BeginCocking(this_05);
        return;
      }
      iVar4 = in_stack_00000004[0x1093];
      pCVar5 = this_05;
    }
    if (iVar4 == 2) {
      FinishCocking(pCVar5);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ItemPostFrameFireTrigger
 * Address: 002ff540  Size: 154 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ItemPostFrameFireTrigger() */

undefined4 __thiscall CINSWeaponBallistic::ItemPostFrameFireTrigger(CINSWeaponBallistic *this)

{
  char cVar1;
  int iVar2;
  CINSWeaponBallistic *this_00;
  int unaff_EBX;
  undefined4 uVar3;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  uVar3 = 0;
  iVar2 = CINSWeapon::GetINSPlayerOwner();
  if ((iVar2 != 0) && ((*(byte *)(iVar2 + 0xf25) & 0x10) != 0)) {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x648))(in_stack_00000004);
    if ((cVar1 != '\0') ||
       ((float)in_stack_00000004[0x12d] <= *(float *)(**(int **)(unaff_EBX + 0x8a7352) + 0xc))) {
      uVar3 = 0;
      cVar1 = CINSWeapon::IsPreventedUntilButtonRelease();
      if (cVar1 == '\0') {
        uVar3 = CycleFiremodes(this_00);
        CINSWeapon::PreventUntilButtonReleased();
      }
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSWeaponBallistic::MakeTracer
 * Address: 002fdad0  Size: 5 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::MakeTracer(Vector const&, CGameTrace const&, int) */

void __cdecl CINSWeaponBallistic::MakeTracer(Vector *param_1,CGameTrace *param_2,int param_3)

{
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::MakeTracerCustom
 * Address: 002fdae0  Size: 5 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::MakeTracerCustom(Vector const&, CGameTrace const&, int, char const*, bool)
    */

void __cdecl
CINSWeaponBallistic::MakeTracerCustom
          (Vector *param_1,CGameTrace *param_2,int param_3,char *param_4,bool param_5)

{
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::OnDeploy
 * Address: 002ff830  Size: 209 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::OnDeploy() */

void __thiscall CINSWeaponBallistic::OnDeploy(CINSWeaponBallistic *this)

{
  char cVar1;
  CINSWeapon *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar2;
  CINSWeaponBallistic *extraout_ECX_00;
  CBaseEntity *this_01;
  CBaseEntity *extraout_ECX_01;
  int iVar3;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CINSWeapon::OnDeploy(this_00);
  pCVar2 = extraout_ECX;
  if ((char)in_stack_00000004[0x104c] != '\0') {
    if (in_stack_00000004[0x1090] == -1) {
      iVar3 = 6;
      do {
        cVar1 = (**(code **)(*in_stack_00000004 + 0x750))(in_stack_00000004,iVar3);
        pCVar2 = this_01;
        if (cVar1 != '\0') {
          if (in_stack_00000004[0x1090] != iVar3) {
            CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
            in_stack_00000004[0x1090] = iVar3;
            pCVar2 = extraout_ECX_01;
          }
          goto LAB_002ff867;
        }
        iVar3 = iVar3 + -1;
      } while (iVar3 != -1);
      cVar1 = (char)in_stack_00000004[0x1092];
    }
    else {
LAB_002ff867:
      cVar1 = (char)in_stack_00000004[0x1092];
    }
    if (cVar1 != '\0') {
      CBaseEntity::NetworkStateChanged(pCVar2,in_stack_00000004);
      *(undefined1 *)(in_stack_00000004 + 0x1092) = 0;
    }
    (**(code **)(*in_stack_00000004 + 0x73c))(in_stack_00000004);
    pCVar2 = (CBaseEntity *)extraout_ECX_00;
  }
  ResetBurst((CINSWeaponBallistic *)pCVar2);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::OnHolster
 * Address: 002ff7d0  Size: 89 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::OnHolster() */

void __thiscall CINSWeaponBallistic::OnHolster(CINSWeaponBallistic *this)

{
  CINSWeapon *this_00;
  CINSWeaponBallistic *this_01;
  CBaseEntity *this_02;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CINSWeapon::OnHolster(this_00);
  ResetBurst(this_01);
  if (*(int *)((int)in_stack_00000004 + 0x424c) == 2) {
    CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
    *(undefined4 *)((int)in_stack_00000004 + 0x424c) = 1;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::Precache
 * Address: 002fdbf0  Size: 63 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::Precache() */

void CINSWeaponBallistic::Precache(void)

{
  CINSWeapon *this;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  CINSWeapon::Precache(this);
  PrecacheEffect((char *)(unaff_EBX + 0x63fe13));
  PrecacheEffect((char *)(unaff_EBX + 0x63fe22));
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::PrimaryAttack
 * Address: 002fe770  Size: 536 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::PrimaryAttack() */

void __thiscall CINSWeaponBallistic::PrimaryAttack(CINSWeaponBallistic *this)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  CINSWeaponBallistic *this_00;
  CINSWeapon *this_01;
  CBaseEntity *this_02;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar4;
  CBaseEntity *this_03;
  CBaseEntity *extraout_ECX_00;
  int unaff_EBX;
  float fVar5;
  int *in_stack_00000004;
  undefined4 uVar6;
  
  __i686_get_pc_thunk_bx();
  iVar3 = CINSWeapon::GetINSPlayerOwner();
  if (iVar3 == 0) {
    return;
  }
  cVar2 = (**(code **)(*in_stack_00000004 + 0x668))(in_stack_00000004);
  if (cVar2 == '\0') {
    return;
  }
  cVar2 = (**(code **)(*in_stack_00000004 + 0x740))(in_stack_00000004);
  if (cVar2 != '\0') {
    return;
  }
  cVar2 = CINSWeapon::IsHoldingButton();
  if ((cVar2 != '\0') && (cVar2 = IsFullyAutomatic(this_00), cVar2 == '\0')) {
    return;
  }
  cVar2 = CINSWeapon::IsPreventedUntilButtonRelease();
  if (cVar2 != '\0') {
    return;
  }
  cVar2 = (**(code **)(*in_stack_00000004 + 0x754))(in_stack_00000004,1);
  if ((cVar2 != '\0') && (0 < in_stack_00000004[0x1091])) {
    return;
  }
  iVar3 = CINSWeapon::GetWeaponDefinition(this_01);
  if (iVar3 == 0) {
    return;
  }
  fVar5 = *(float *)(iVar3 + 0x194);
  if (fVar5 < *(float *)(unaff_EBX + 0x5ba38a) || fVar5 == *(float *)(unaff_EBX + 0x5ba38a)) {
    (**(code **)(*in_stack_00000004 + 0x768))(in_stack_00000004);
    CINSWeapon::MarkAsHoldingButton();
    cVar2 = (**(code **)(*in_stack_00000004 + 0x754))(in_stack_00000004,1);
    if (cVar2 == '\0') {
      return;
    }
    fVar5 = *(float *)(**(int **)(unaff_EBX + 0x8a8122) + 0xc) + *(float *)(iVar3 + 0x188);
    pCVar4 = this_03;
    if ((float)in_stack_00000004[0x12d] != fVar5) {
      CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
      in_stack_00000004[0x12d] = (int)fVar5;
      pCVar4 = extraout_ECX_00;
    }
    iVar3 = *(int *)(iVar3 + 0x198);
    if (iVar3 == in_stack_00000004[0x1091]) {
      return;
    }
    CBaseEntity::NetworkStateChanged(pCVar4,in_stack_00000004);
    in_stack_00000004[0x1091] = iVar3;
    return;
  }
  if (0 < in_stack_00000004[0x1091]) {
    return;
  }
  fVar5 = fVar5 + *(float *)(**(int **)(unaff_EBX + 0x8a8122) + 0xc);
  pCVar4 = this_02;
  if ((float)in_stack_00000004[0x12d] != fVar5) {
    CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
    in_stack_00000004[0x12d] = (int)fVar5;
    pCVar4 = extraout_ECX;
    if (in_stack_00000004[0x1091] == 1) goto LAB_002fe87f;
  }
  CBaseEntity::NetworkStateChanged(pCVar4,in_stack_00000004);
  in_stack_00000004[0x1091] = 1;
LAB_002fe87f:
  uVar6 = 0;
  CINSWeapon::MarkAsHoldingButton();
  pcVar1 = *(code **)(*in_stack_00000004 + 0x3f8);
  uVar6 = (**(code **)(*in_stack_00000004 + 0x6d4))(in_stack_00000004,uVar6);
  (*pcVar1)(in_stack_00000004,uVar6);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::ResetBurst
 * Address: 002ff630  Size: 388 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::ResetBurst() */

void __thiscall CINSWeaponBallistic::ResetBurst(CINSWeaponBallistic *this)

{
  ushort uVar1;
  ushort uVar2;
  uint *puVar3;
  ushort *puVar4;
  int *piVar5;
  ushort *puVar6;
  ushort *puVar7;
  CBaseEdict *this_00;
  int iVar8;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(in_stack_00000004 + 0x4244) == 0) {
    return;
  }
  if (*(char *)(in_stack_00000004 + 0x5c) == '\0') {
    puVar3 = *(uint **)(in_stack_00000004 + 0x20);
    if ((puVar3 != (uint *)0x0) && ((*puVar3 & 0x100) == 0)) {
      *puVar3 = *puVar3 | 1;
      puVar7 = (ushort *)CBaseEdict::GetChangeAccessor(this_00);
      puVar4 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a7138);
      if (puVar7[1] == *puVar4) {
        uVar1 = *puVar7;
        uVar2 = puVar4[(uint)uVar1 * 0x14 + 0x14];
        if (uVar2 == 0) {
LAB_002ff7aa:
          puVar4[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x4244;
          puVar4[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
        }
        else if (puVar4[(uint)uVar1 * 0x14 + 1] != 0x4244) {
          iVar8 = 0;
          do {
            if (iVar8 == (uVar2 - 1 & 0xffff) * 2) {
              if (uVar2 != 0x13) goto LAB_002ff7aa;
              goto LAB_002ff720;
            }
            iVar8 = iVar8 + 2;
          } while (*(short *)((int)puVar4 + iVar8 + (uint)uVar1 * 0x28 + 2) != 0x4244);
        }
      }
      else if ((puVar4[0x7d1] == 100) || (puVar7[1] != 0)) {
LAB_002ff720:
        puVar7[1] = 0;
        *puVar3 = *puVar3 | 0x100;
      }
      else {
        piVar5 = *(int **)(unaff_EBX + 0x8a7138);
        *puVar7 = puVar4[0x7d1];
        puVar6 = (ushort *)*piVar5;
        puVar4 = puVar6 + 0x7d1;
        *puVar4 = *puVar4 + 1;
        puVar7[1] = *puVar6;
        iVar8 = *piVar5 + (uint)*puVar7 * 0x28;
        *(undefined2 *)(iVar8 + 2) = 0x4244;
        *(undefined2 *)(iVar8 + 0x28) = 1;
      }
    }
    *(undefined4 *)(in_stack_00000004 + 0x4244) = 0;
  }
  else {
    *(byte *)(in_stack_00000004 + 0x60) = *(byte *)(in_stack_00000004 + 0x60) | 1;
    *(undefined4 *)(in_stack_00000004 + 0x4244) = 0;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::SetFiremode
 * Address: 002ff5e0  Size: 79 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::SetFiremode(eWeaponFireModes) */

void __thiscall CINSWeaponBallistic::SetFiremode(undefined4 param_1,int *param_2,int param_3)

{
  char cVar1;
  CBaseEntity *this;
  
  cVar1 = (**(code **)(*param_2 + 0x750))(param_2,param_3);
  if ((cVar1 != '\0') && (param_3 != param_2[0x1090])) {
    CBaseEntity::NetworkStateChanged(this,param_2);
    param_2[0x1090] = param_3;
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::UseChamberRound
 * Address: 002fe6e0  Size: 9 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::UseChamberRound() const */

void CINSWeaponBallistic::UseChamberRound(void)

{
  IsClosedBolt();
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::UsesFireModes
 * Address: 002fdb30  Size: 10 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::UsesFireModes() const */

undefined4 CINSWeaponBallistic::UsesFireModes(void)

{
  return 1;
}



/* ----------------------------------------
 * CINSWeaponBallistic::YouForgotToImplementOrDeclareServerClass
 * Address: 002fda40  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::YouForgotToImplementOrDeclareServerClass() */

undefined4 CINSWeaponBallistic::YouForgotToImplementOrDeclareServerClass(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeaponBallistic::~CINSWeaponBallistic
 * Address: 002fdc30  Size: 43 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::~CINSWeaponBallistic() */

void __thiscall CINSWeaponBallistic::~CINSWeaponBallistic(CINSWeaponBallistic *this)

{
  CINSWeapon *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x835ccf;
  CINSWeapon::~CINSWeapon(this_00);
  return;
}



/* ----------------------------------------
 * CINSWeaponBallistic::~CINSWeaponBallistic
 * Address: 002fdc60  Size: 52 bytes
 * ---------------------------------------- */

/* CINSWeaponBallistic::~CINSWeaponBallistic() */

void __thiscall CINSWeaponBallistic::~CINSWeaponBallistic(CINSWeaponBallistic *this)

{
  CINSWeaponBallistic *this_00;
  CBaseEntity *this_01;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSWeaponBallistic(this_00);
  CBaseEntity::operator_delete(this_01,in_stack_00000004);
  return;
}



