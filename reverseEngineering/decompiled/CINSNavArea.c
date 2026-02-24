/*
 * CINSNavArea -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 47
 */

/* ----------------------------------------
 * CINSNavArea::Update
 * Address: 006e2cc0
 * ---------------------------------------- */

/* CINSNavArea::Update() */

void CINSNavArea::Update(void)

{
  return;
}



/* ----------------------------------------
 * CINSNavArea::AddPathingBot
 * Address: 006e6140
 * ---------------------------------------- */

/* CINSNavArea::AddPathingBot(CBaseCombatCharacter*, float) */

void __thiscall
CINSNavArea::AddPathingBot(CINSNavArea *this,CBaseCombatCharacter *param_1,float param_2)

{
  CBaseCombatCharacter *pCVar1;
  int iVar2;
  uint uVar3;
  CBaseEntity *this_00;
  int iVar4;
  int unaff_EBX;
  float10 fVar5;
  float in_stack_0000000c;
  int local_28;
  float local_24;
  float local_20 [3];
  undefined4 uStack_14;
  
  uStack_14 = 0x6e614b;
  __i686_get_pc_thunk_bx();
  if (param_2 != 0.0) {
    iVar2 = CBaseEntity::GetTeamNumber(this_00);
    uVar3 = iVar2 - 2;
    if (1 < uVar3) {
      uVar3 = 2;
    }
    pCVar1 = param_1 + uVar3 * 0x14 + 0x230;
    iVar2 = *(int *)(pCVar1 + 0xc);
    if (0 < iVar2) {
      if (*(int *)((int)param_2 + 0x20) == 0) {
        iVar4 = 0;
        do {
          if (*(int *)(*(int *)pCVar1 + iVar4 * 0x10) == 0) {
            return;
          }
          iVar4 = iVar4 + 1;
        } while (iVar4 != iVar2);
      }
      else {
        iVar4 = 0;
        do {
          if (*(int *)((int)param_2 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x4c0755 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4
              == *(int *)(*(int *)pCVar1 + iVar4 * 0x10)) {
            return;
          }
          iVar4 = iVar4 + 1;
        } while (iVar4 != iVar2);
      }
    }
    local_28 = unaff_EBX + 0x44206d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    local_24 = 0.0;
    CountdownTimer::NetworkStateChanged(&local_28);
    local_20[0] = -1.0;
    (**(code **)(local_28 + 4))(&local_28,local_20);
    fVar5 = (float10)CountdownTimer::Now();
    if (local_20[0] != (float)fVar5 + in_stack_0000000c) {
      (**(code **)(local_28 + 4))(&local_28,local_20);
      local_20[0] = (float)fVar5 + in_stack_0000000c;
    }
    if (local_24 != in_stack_0000000c) {
      (**(code **)(local_28 + 4))(&local_28,&local_24);
      local_24 = in_stack_0000000c;
    }
    CUtlVector<CINSPathingBotInfo,CUtlMemory<CINSPathingBotInfo,int>>::InsertBefore
              ((int)pCVar1,*(CINSPathingBotInfo **)(pCVar1 + 0xc));
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::AddPotentiallyVisibleActor
 * Address: 006e62d0
 * ---------------------------------------- */

/* CINSNavArea::AddPotentiallyVisibleActor(CBaseCombatCharacter*) */

void __thiscall
CINSNavArea::AddPotentiallyVisibleActor(CINSNavArea *this,CBaseCombatCharacter *param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  uint *puVar10;
  int iVar11;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX_00;
  CUtlVector<CHandle<CBaseCombatCharacter>,CUtlMemory<CHandle<CBaseCombatCharacter>,int>> *this_01;
  int iVar12;
  int unaff_EBX;
  bool bVar13;
  int *in_stack_00000008;
  int local_54;
  int local_30;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x4c0699 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  this_00 = *(CBaseEntity **)(iVar2 + 0x100c);
  bVar13 = this_00 != (CBaseEntity *)0x0;
  if ((bVar13) &&
     (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), this_00 = extraout_ECX,
     iVar8 == iVar7)) {
    piVar9 = *(int **)(iVar2 + 0x1014);
    if (*piVar9 != unaff_EBX + 0x298651 /* "CINSNavArea::AddPotentiallyVisibleActor" */ /* "CINSNavArea::AddPotentiallyVisibleActor" */ /* "CINSNavArea::AddPotentiallyVisibleActor" */) {
      piVar9 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar9,unaff_EBX + 0x298651 /* "CINSNavArea::AddPotentiallyVisibleActor" */ /* "CINSNavArea::AddPotentiallyVisibleActor" */ /* "CINSNavArea::AddPotentiallyVisibleActor" */,(char *)0x0,
                                 unaff_EBX + 0x29832d /* "INSNavMesh" */ /* "INSNavMesh" */ /* "INSNavMesh" */);
      *(int **)(iVar2 + 0x1014) = piVar9;
    }
    puVar10 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar9[0x1c] * 8 + 4);
    *puVar10 = *puVar10 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
    this_00 = extraout_ECX_00;
  }
  if (in_stack_00000008 != (int *)0x0) {
    iVar8 = CBaseEntity::GetTeamNumber(this_00);
    if (iVar8 - 2U < 2) {
      cVar6 = (**(code **)(*in_stack_00000008 + 0x158))(in_stack_00000008);
      if (cVar6 != '\0') {
        cVar6 = (**(code **)(*in_stack_00000008 + 0x158))(in_stack_00000008);
        piVar9 = (int *)0x0;
        if (cVar6 != '\0') {
          piVar9 = in_stack_00000008;
        }
        cVar6 = (**(code **)(*piVar9 + 0x7b4 /* CBasePlayer::IsBotOfType */))(piVar9,0x539);
        if ((cVar6 != '\0') && ((*(byte *)(in_stack_00000008 + 0x8a5) & 1) != 0)) goto LAB_006e632d;
      }
      puVar10 = (uint *)(**(code **)(*in_stack_00000008 + 0xc))(in_stack_00000008);
      uVar3 = *puVar10;
      iVar8 = (iVar8 - 2U) * 0x14;
      iVar7 = *(int *)(param_1 + iVar8 + 0x170);
      if (0 < iVar7) {
        iVar4 = **(int **)(&DAT_004c04fd + unaff_EBX);
        if (uVar3 == 0xffffffff) {
          iVar12 = 0;
          do {
            uVar3 = *(uint *)(*(int *)(param_1 + iVar8 + 0x164) + iVar12 * 4);
            if (((uVar3 == 0xffffffff) ||
                (iVar11 = iVar4 + (uVar3 & 0xffff) * 0x18, *(uint *)(iVar11 + 8) != uVar3 >> 0x10))
               || (*(int *)(iVar11 + 4) == 0)) goto LAB_006e632d;
            iVar12 = iVar12 + 1;
          } while (iVar12 != iVar7);
        }
        else {
          iVar11 = 0;
          iVar12 = iVar4 + (uVar3 & 0xffff) * 0x18;
          do {
            local_54 = 0;
            if (*(uint *)(iVar12 + 8) == uVar3 >> 0x10) {
              local_54 = *(int *)(iVar12 + 4);
            }
            local_30 = 0;
            uVar5 = *(uint *)(*(int *)(param_1 + iVar8 + 0x164) + iVar11 * 4);
            if ((uVar5 != 0xffffffff) &&
               (iVar1 = iVar4 + (uVar5 & 0xffff) * 0x18, *(uint *)(iVar1 + 8) == uVar5 >> 0x10)) {
              local_30 = *(int *)(iVar1 + 4);
            }
            if (local_54 == local_30) goto LAB_006e632d;
            iVar11 = iVar11 + 1;
          } while (iVar11 != iVar7);
        }
      }
      (**(code **)(*in_stack_00000008 + 0xc))(in_stack_00000008);
      CUtlVector<CHandle<CBaseCombatCharacter>,CUtlMemory<CHandle<CBaseCombatCharacter>,int>>::
      InsertBefore(this_01,(int)(param_1 + iVar8 + 0x164),*(CHandle **)(param_1 + iVar8 + 0x170));
    }
  }
LAB_006e632d:
  if (((bVar13) && ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) &&
     (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar8 == iVar7)) {
    cVar6 = CVProfNode::ExitScope();
    iVar8 = *(int *)(iVar2 + 0x1014);
    if (cVar6 != '\0') {
      iVar8 = *(int *)(iVar8 + 100);
      *(int *)(iVar2 + 0x1014) = iVar8;
    }
    *(bool *)(iVar2 + 0x1010) = iVar8 == iVar2 + 0x1018;
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::AssociateWithControlPoint
 * Address: 006e43c0
 * ---------------------------------------- */

/* CINSNavArea::AssociateWithControlPoint(int) */

void __cdecl CINSNavArea::AssociateWithControlPoint(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int unaff_EBX;
  
  iVar3 = __i686_get_pc_thunk_bx();
  uVar2 = *(uint *)(**(int **)(unaff_EBX + 0x4c294b /* &g_pObjectiveResource */ /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x7cc + iVar3 * 4);
  if ((uVar2 == 0xffffffff) ||
     (iVar1 = **(int **)(unaff_EBX + 0x4c2407 /* &g_pEntityList */ /* &g_pEntityList */ /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
     *(uint *)(iVar1 + 8) != uVar2 >> 0x10)) {
    iVar3 = -1;
  }
  else if (*(int *)(iVar1 + 4) == 0) {
    iVar3 = -1;
  }
  *(int *)(param_1 + 0x25c) = iVar3;
  return;
}



/* ----------------------------------------
 * CINSNavArea::AssociateWithSpawnZone
 * Address: 006e3680
 * ---------------------------------------- */

/* CINSNavArea::AssociateWithSpawnZone(CINSSpawnZone*) */

void __thiscall CINSNavArea::AssociateWithSpawnZone(CINSNavArea *this,CINSSpawnZone *param_1)

{
  undefined4 *puVar1;
  int *in_stack_00000008;
  
  if (in_stack_00000008 != (int *)0x0) {
    *(uint *)(param_1 + 0x160) = *(uint *)(param_1 + 0x160) | 0x100;
    puVar1 = (undefined4 *)(**(code **)(*in_stack_00000008 + 0xc))();
    *(undefined4 *)(param_1 + 600) = *puVar1;
    return;
  }
  ClearAssociatedSpawnZone(this);
  return;
}



/* ----------------------------------------
 * CINSNavArea::CINSNavArea
 * Address: 006e5d40
 * ---------------------------------------- */

/* CINSNavArea::CINSNavArea() */

void __thiscall CINSNavArea::CINSNavArea(CINSNavArea *this)

{
  code *pcVar1;
  int iVar2;
  CNavArea *this_00;
  CINSNavArea *extraout_ECX;
  CINSNavArea *this_01;
  int unaff_EBX;
  int *piVar3;
  int *in_stack_00000004;
  int local_20;
  
  __i686_get_pc_thunk_bx();
  CNavArea::CNavArea(this_00);
  iVar2 = *(int *)(unaff_EBX + 0x4c0f05 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  *in_stack_00000004 = unaff_EBX + 0x4ae47d /* vtable for CINSNavArea+0x8 */ /* vtable for CINSNavArea+0x8 */ /* vtable for CINSNavArea+0x8 */;
  in_stack_00000004[0x59] = 0;
  in_stack_00000004[0x5a] = 0;
  in_stack_00000004[100] = iVar2 + 8;
  pcVar1 = *(code **)(iVar2 + 0x10);
  in_stack_00000004[0x5b] = 0;
  in_stack_00000004[0x5c] = 0;
  in_stack_00000004[0x5d] = 0;
  in_stack_00000004[0x5e] = 0;
  in_stack_00000004[0x5f] = 0;
  in_stack_00000004[0x60] = 0;
  in_stack_00000004[0x61] = 0;
  in_stack_00000004[0x62] = 0;
  in_stack_00000004[0x65] = -0x40800000 /* -1.0f */;
  (*pcVar1)(in_stack_00000004 + 100,in_stack_00000004 + 0x65);
  in_stack_00000004[0x7c] = 0;
  in_stack_00000004[0x7b] = unaff_EBX + 0x44246d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_0 */
  (*(code *)(unaff_EBX + -0x4b55db /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0x7b,in_stack_00000004 + 0x7c);
  in_stack_00000004[0x7d] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x7b] + 4))(in_stack_00000004 + 0x7b,in_stack_00000004 + 0x7d); /* timer_0.NetworkStateChanged() */
  piVar3 = in_stack_00000004 + 0x7f;
  do {
    *piVar3 = unaff_EBX + 0x44246d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
    *(undefined4 *)
     ((int)in_stack_00000004 + (int)piVar3 + (0x200 - (int)(in_stack_00000004 + 0x7f))) = 0;
    (*(code *)(unaff_EBX + -0x4b55db /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar3,piVar3 + 1);
    piVar3[2] = -0x40800000 /* -1.0f */;
    (**(code **)(*piVar3 + 4))(piVar3,piVar3 + 2);
    piVar3 = piVar3 + 3;
  } while (piVar3 != in_stack_00000004 + 0x85);
  iVar2 = *(int *)(unaff_EBX + 0x4c0f05 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  in_stack_00000004[0x88] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x87] = iVar2 + 8;
  (*pcVar1)(in_stack_00000004 + 0x87,in_stack_00000004 + 0x88);
  iVar2 = *(int *)(unaff_EBX + 0x4c0f05 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  in_stack_00000004[0x8a] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x89] = iVar2 + 8;
  (*pcVar1)(in_stack_00000004 + 0x89,in_stack_00000004 + 0x8a);
  local_20 = 0;
  in_stack_00000004[0x8c] = 0;
  in_stack_00000004[0x8d] = 0;
  in_stack_00000004[0x8e] = 0;
  in_stack_00000004[0x8f] = 0;
  in_stack_00000004[0x90] = 0;
  in_stack_00000004[0x91] = 0;
  in_stack_00000004[0x92] = 0;
  in_stack_00000004[0x93] = 0;
  in_stack_00000004[0x94] = 0;
  in_stack_00000004[0x95] = 0;
  in_stack_00000004[0x96] = -1;
  in_stack_00000004[0x58] = 0;
  in_stack_00000004[99] = 0;
  in_stack_00000004[0x8b] = 0;
  in_stack_00000004[0x97] = -1;
  piVar3 = in_stack_00000004;
  do {
    piVar3[0x85] = 0;
    this_01 = (CINSNavArea *)(in_stack_00000004 + local_20 * 3 + 0x7f);
    if (in_stack_00000004[local_20 * 3 + 0x81] != -0x40800000 /* -1.0f */) {
      (**(code **)(in_stack_00000004[local_20 * 3 + 0x7f] + 4))
                (this_01,in_stack_00000004 + local_20 * 3 + 0x81);
      in_stack_00000004[local_20 * 3 + 0x81] = -0x40800000 /* -1.0f */;
      this_01 = extraout_ECX;
    }
    local_20 = local_20 + 1;
    piVar3[0x67] = 0;
    piVar3[0x69] = -0x3b860000 /* -1000.0f */;
    piVar3 = piVar3 + 1;
  } while (local_20 != 2);
  iVar2 = 0;
  do {
    in_stack_00000004[iVar2 + 0x6b] = -0x40800000 /* -1.0f */;
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x10);
  CleanupPathingBots(this_01,SUB41(in_stack_00000004,0));
  return;
}



/* ----------------------------------------
 * CINSNavArea::CleanupPathingBots
 * Address: 006e5770
 * ---------------------------------------- */

/* CINSNavArea::CleanupPathingBots(bool) */

void __thiscall CINSNavArea::CleanupPathingBots(CINSNavArea *this,bool param_1)

{
  float *pfVar1;
  uint *puVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int unaff_EBX;
  int iVar6;
  bool bVar7;
  float10 fVar8;
  undefined3 in_stack_00000005;
  char in_stack_00000008;
  int local_30;
  
  __i686_get_pc_thunk_bx();
  bVar7 = *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bVar7) &&
     (iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
     iVar6 == iVar4)) {
    piVar5 = *(int **)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar5 != unaff_EBX + 0x299191 /* "CINSNavArea::CleanupPathingBots" */ /* "CINSNavArea::CleanupPathingBots" */ /* "CINSNavArea::CleanupPathingBots" */) {
      piVar5 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar5,unaff_EBX + 0x299191 /* "CINSNavArea::CleanupPathingBots" */ /* "CINSNavArea::CleanupPathingBots" */ /* "CINSNavArea::CleanupPathingBots" */,(char *)0x0,
                                 unaff_EBX + 0x29088f /* "NPCs" */ /* "NPCs" */ /* "NPCs" */);
      *(int **)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar5;
    }
    puVar2 = (uint *)(piVar5[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar2 = *puVar2 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  if (in_stack_00000008 == '\0') {
    if (0 < *(int *)(_param_1 + 0x23c)) {
      iVar6 = *(int *)(_param_1 + 0x23c) + -1;
      local_30 = iVar6 * 0x10;
      do {
        iVar4 = *(int *)(_param_1 + 0x230);
        fVar8 = (float10)CountdownTimer::Now();
        pfVar1 = (float *)(local_30 + iVar4 + 0xc);
        if (*pfVar1 <= (float)fVar8 && (float)fVar8 != *pfVar1) {
          CUtlVector<CINSPathingBotInfo,CUtlMemory<CINSPathingBotInfo,int>>::Remove
                    (_param_1 + 0x230);
        }
        local_30 = local_30 + -0x10;
        iVar6 = iVar6 + -1;
      } while (iVar6 != -1);
    }
    if (0 < *(int *)(_param_1 + 0x250)) {
      iVar6 = *(int *)(_param_1 + 0x250) + -1;
      local_30 = iVar6 * 0x10;
      do {
        iVar4 = *(int *)(_param_1 + 0x244);
        fVar8 = (float10)CountdownTimer::Now();
        pfVar1 = (float *)(local_30 + iVar4 + 0xc);
        if (*pfVar1 <= (float)fVar8 && (float)fVar8 != *pfVar1) {
          CUtlVector<CINSPathingBotInfo,CUtlMemory<CINSPathingBotInfo,int>>::Remove
                    (_param_1 + 0x244);
        }
        local_30 = local_30 + -0x10;
        iVar6 = iVar6 + -1;
      } while (iVar6 != -1);
    }
    if (!bVar7) {
      return;
    }
    iVar6 = *(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
    cVar3 = *(char *)(iVar6 + 0x1010);
  }
  else {
    *(undefined4 *)(_param_1 + 0x23c) = 0;
    *(undefined4 *)(_param_1 + 0x250) = 0;
    if (!bVar7) {
      return;
    }
    iVar6 = *(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
    cVar3 = *(char *)(iVar6 + 0x1010);
  }
  if (((cVar3 == '\0') || (*(int *)(iVar6 + 0x100c) != 0)) &&
     (iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
     iVar6 == iVar4)) {
    cVar3 = CVProfNode::ExitScope();
    iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (cVar3 != '\0') {
      iVar6 = *(int *)(iVar6 + 100);
      *(int *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar6;
    }
    *(bool *)(*(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
         iVar6 == *(int *)(unaff_EBX + 0x4c11f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::ClearAssociatedControlPoint
 * Address: 006e4440
 * ---------------------------------------- */

/* CINSNavArea::ClearAssociatedControlPoint() */

void __thiscall CINSNavArea::ClearAssociatedControlPoint(CINSNavArea *this)

{
  int in_stack_00000004;
  
  *(undefined4 *)(in_stack_00000004 + 0x25c) = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSNavArea::ClearAssociatedSpawnZone
 * Address: 006e3660
 * ---------------------------------------- */

/* CINSNavArea::ClearAssociatedSpawnZone() */

void __thiscall CINSNavArea::ClearAssociatedSpawnZone(CINSNavArea *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x160) = *(uint *)(in_stack_00000004 + 0x160) & 0xfffffeff;
  *(undefined4 *)(in_stack_00000004 + 600) = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSNavArea::CollectSpotsWithScoreAbove
 * Address: 006e60b0
 * ---------------------------------------- */

/* CINSNavArea::CollectSpotsWithScoreAbove(float, int, CUtlVector<HidingSpot const*,
   CUtlMemory<HidingSpot const*, int> >&) */

void __thiscall
CINSNavArea::CollectSpotsWithScoreAbove
          (CINSNavArea *this,float param_1,int param_2,CUtlVector *param_3)

{
  CUtlVector<HidingSpot_const*,CUtlMemory<HidingSpot_const*,int>> *pCVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int in_stack_00000010;
  
  piVar3 = *(int **)((int)param_1 + 0xd0);
  if (0 < *piVar3) {
    iVar4 = 0;
    do {
      while (iVar2 = iVar4 + 1,
            pCVar1 = (CUtlVector<HidingSpot_const*,CUtlMemory<HidingSpot_const*,int>> *)
                     piVar3[iVar2] + ((param_3 != (CUtlVector *)0x2) + 8) * 4,
            (float)param_2 < *(float *)pCVar1 || (float)param_2 == *(float *)pCVar1) {
        iVar4 = iVar4 + 1;
        CUtlVector<HidingSpot_const*,CUtlMemory<HidingSpot_const*,int>>::InsertBefore
                  ((CUtlVector<HidingSpot_const*,CUtlMemory<HidingSpot_const*,int>> *)piVar3[iVar2],
                   in_stack_00000010,*(HidingSpot ***)(in_stack_00000010 + 0xc));
        piVar3 = *(int **)((int)param_1 + 0xd0);
        if (*piVar3 <= iVar4) {
          return;
        }
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < *piVar3);
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::ComputeDangerSpotData
 * Address: 006e3000
 * ---------------------------------------- */

/* CINSNavArea::ComputeDangerSpotData() */

void CINSNavArea::ComputeDangerSpotData(void)

{
  return;
}



/* ----------------------------------------
 * CINSNavArea::CustomAnalysis
 * Address: 006e4ce0
 * ---------------------------------------- */

/* CINSNavArea::CustomAnalysis(bool) */

void __cdecl CINSNavArea::CustomAnalysis(bool param_1)

{
  int *piVar1;
  CINSNavArea *pCVar2;
  int iVar3;
  bool bVar4;
  char cVar5;
  int iVar6;
  CTraceFilterSimple *this;
  CINSNavArea *this_00;
  float fVar7;
  int unaff_EBX;
  undefined3 in_stack_00000005;
  int local_e8;
  int local_e0;
  Vector local_dc [12];
  Vector local_d0 [32];
  float local_b0;
  char local_a5;
  undefined4 local_90;
  undefined4 local_7c;
  undefined4 local_78;
  float local_74;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_3c;
  undefined1 local_38;
  undefined1 local_37;
  IHandleEntity local_2c [24];
  undefined4 uStack_14;
  
  uStack_14 = 0x6e4cee;
  __i686_get_pc_thunk_bx();
  local_3c = 0;
  local_6c = 0;
  local_90 = 0;
  local_68 = 0;
  local_64 = 0x432d0000 /* 173.0f */;
  local_7c = *(undefined4 *)(_param_1 + 0x2c);
  local_37 = 1;
  local_38 = 1;
  local_78 = *(undefined4 *)(_param_1 + 0x30);
  local_44 = 0;
  local_74 = *(float *)(unaff_EBX + 0x2793b2 /* 55.0f */ /* 55.0f */ /* 55.0f */) + *(float *)(_param_1 + 0x34);
  local_48 = 0;
  *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) & 0x5ef3;
  local_4c = 0;
  local_54 = 0;
  local_58 = 0;
  local_5c = 0;
  CTraceFilterSimple::CTraceFilterSimple(this,local_2c,0,(_func_bool_IHandleEntity_ptr_int *)0x0);
  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c1a8a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
            ((int *)**(undefined4 **)(unaff_EBX + 0x4c1a8a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_7c,0x2400b,local_2c,local_dc);
  piVar1 = *(int **)(unaff_EBX + 0x4c1d52 /* &r_visualizetraces */ /* &r_visualizetraces */ /* &r_visualizetraces */);
  iVar6 = (**(code **)(*piVar1 + 0x40))(piVar1);
  if (iVar6 != 0) {
    iVar6 = (**(code **)(*piVar1 + 0x40))(piVar1);
    fVar7 = 0.5;
    if (iVar6 != 0) {
      fVar7 = -1.0;
    }
    DebugDrawLine(local_dc,local_d0,0xff,0,0,true,fVar7);
  }
  local_e0 = 0;
  if ((*(float *)(&DAT_001d3e26 + unaff_EBX) <= local_b0) || (local_a5 != '\0')) {
    local_e8 = 4;
    do {
      local_7c = *(undefined4 *)(_param_1 + 0x2c);
      local_3c = 0;
      local_6c = 0;
      local_78 = *(undefined4 *)(_param_1 + 0x30);
      local_68 = 0;
      local_74 = *(float *)(unaff_EBX + 0x2793b2 /* 55.0f */ /* 55.0f */ /* 55.0f */) + *(float *)(_param_1 + 0x34);
      local_64 = 0x432d0000 /* 173.0f */;
      local_37 = 1;
      local_44 = 0;
      local_48 = 0;
      local_4c = 0;
      local_38 = 1;
      local_54 = 0;
      local_58 = 0;
      local_5c = 0;
      CTraceFilterSimple::CTraceFilterSimple
                ((CTraceFilterSimple *)local_2c,local_2c,0,(_func_bool_IHandleEntity_ptr_int *)0x0);
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c1a8a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
                ((int *)**(undefined4 **)(unaff_EBX + 0x4c1a8a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_7c,0x2400b,local_2c,local_dc)
      ;
      iVar6 = (**(code **)(*piVar1 + 0x40))(piVar1);
      if (iVar6 != 0) {
        iVar6 = (**(code **)(*piVar1 + 0x40))(piVar1);
        fVar7 = 0.5;
        if (iVar6 != 0) {
          fVar7 = -1.0;
        }
        DebugDrawLine(local_dc,local_d0,0xff,0,0,true,fVar7);
      }
      if (local_b0 < *(float *)(&DAT_001d3e26 + unaff_EBX)) {
        local_e0 = local_e0 + (uint)(local_a5 == '\0');
      }
      local_e8 = local_e8 + -1;
    } while (local_e8 != 0);
    if (local_e0 < 2) {
      *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x40;
      goto LAB_006e4f22;
    }
  }
  *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x80;
LAB_006e4f22:
  this_00 = (CINSNavArea *)**(int **)(_param_1 + 0x6c);
  iVar6 = **(int **)(_param_1 + 0x74);
  pCVar2 = (CINSNavArea *)**(int **)(_param_1 + 0x70);
  iVar3 = **(int **)(_param_1 + 0x78);
  if (this_00 + iVar6 + (int)pCVar2 + iVar3 == (CINSNavArea *)0x2) {
    if (pCVar2 == (CINSNavArea *)0x0 && iVar3 == 0) {
      if (((0 < iVar6) && (this_00 == (CINSNavArea *)0x1)) ||
         ((bVar4 = 0 < (int)this_00, iVar6 == 1 && (bVar4)))) {
        *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x4000;
        bVar4 = true;
      }
    }
    else {
      bVar4 = 0 < (int)this_00;
    }
    if ((iVar6 == 0 && this_00 == (CINSNavArea *)0x0) &&
       (((iVar3 == 1 && (0 < (int)pCVar2)) || ((0 < iVar3 && (pCVar2 == (CINSNavArea *)0x1)))))) {
      *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x4000;
    }
    if ((((bVar4) && (iVar6 == 0)) || ((0 < iVar6 && (this_00 == (CINSNavArea *)0x0)))) &&
       (((iVar3 == 0 && (0 < (int)pCVar2)) ||
        ((0 < iVar3 && (this_00 = pCVar2, pCVar2 == (CINSNavArea *)0x0)))))) {
      *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x20;
    }
  }
  cVar5 = IsDoorway(this_00);
  if (cVar5 != '\0') {
    *(uint *)(_param_1 + 0x160) = *(uint *)(_param_1 + 0x160) | 0x400;
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::Draw
 * Address: 006e5320
 * ---------------------------------------- */

/* CINSNavArea::Draw() const */

void __thiscall CINSNavArea::Draw(CINSNavArea *this)

{
  char cVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  CNavArea *this_00;
  CFmtStrN<256,false> *this_01;
  int *piVar5;
  char *pcVar6;
  int unaff_EBX;
  double dVar7;
  CFmtStrN<256,false> *in_stack_00000004;
  char local_47c [5];
  char local_477 [275];
  CFmtStrN<256,false> local_364 [5];
  char local_35f [263];
  CFmtStrN<256,false> local_258 [5];
  char local_253 [263];
  char local_14c [5];
  char local_147 [255];
  char local_48 [4];
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x6e532b;
  __i686_get_pc_thunk_bx();
  CNavArea::Draw(this_00);
  iVar3 = (**(code **)(*(int *)(unaff_EBX + 0x605995 /* nb_nav_hiding_spot_show_score */ /* nb_nav_hiding_spot_show_score */ /* nb_nav_hiding_spot_show_score */) + 0x40))(unaff_EBX + 0x605995 /* nb_nav_hiding_spot_show_score */ /* nb_nav_hiding_spot_show_score */ /* nb_nav_hiding_spot_show_score */);
  if (((iVar3 != 0) && (in_stack_00000004 != (CFmtStrN<256,false> *)0xffffff30)) &&
     (piVar5 = *(int **)(in_stack_00000004 + 0xd0), 0 < *piVar5)) {
    iVar3 = 0;
    do {
      iVar2 = piVar5[iVar3 + 1];
      iVar3 = iVar3 + 1;
      CFmtStrN<256,false>::CFmtStrN
                (local_364,(char *)local_364,unaff_EBX + 0x299301 /* " C1:%3.1f , C2:%3.1f" */ /* " C1:%3.1f , C2:%3.1f" */ /* " C1:%3.1f , C2:%3.1f" */,
                 SUB84((double)*(float *)(iVar2 + 0x20),0),
                 (int)((ulonglong)(double)*(float *)(iVar2 + 0x20) >> 0x20),
                 SUB84((double)*(float *)(iVar2 + 0x24),0),
                 (int)((ulonglong)(double)*(float *)(iVar2 + 0x24) >> 0x20));
      local_40 = *(undefined4 *)(iVar2 + 4);
      local_38 = *(float *)(unaff_EBX + 0x24f8e9 /* 72.0f */ /* 72.0f */ /* 72.0f */) + *(float *)(iVar2 + 0xc);
      local_3c = *(undefined4 *)(iVar2 + 8);
      NDebugOverlay::Text((Vector *)&local_40,local_35f,false,0.01023);
      CFmtStrN<256,false>::CFmtStrN
                (local_258,(char *)local_258,unaff_EBX + 0x299316 /* " S1:%3.1f , S2:%3.1f" */ /* " S1:%3.1f , S2:%3.1f" */ /* " S1:%3.1f , S2:%3.1f" */,
                 SUB84((double)*(float *)(iVar2 + 0x28),0),
                 (int)((ulonglong)(double)*(float *)(iVar2 + 0x28) >> 0x20),
                 SUB84((double)*(float *)(iVar2 + 0x2c),0),
                 (int)((ulonglong)(double)*(float *)(iVar2 + 0x2c) >> 0x20));
      local_34 = *(undefined4 *)(iVar2 + 4);
      local_2c = *(float *)(unaff_EBX + 0x2586dd /* 48.0f */ /* 48.0f */ /* 48.0f */) + *(float *)(iVar2 + 0xc);
      local_30 = *(undefined4 *)(iVar2 + 8);
      NDebugOverlay::Text((Vector *)&local_34,local_253,false,0.01023);
      piVar5 = *(int **)(in_stack_00000004 + 0xd0);
    } while (iVar3 < *piVar5);
  }
  iVar3 = (**(code **)(*(int *)(unaff_EBX + 0x6059f5 /* ins_nav_debug_distance_to_cp */ /* ins_nav_debug_distance_to_cp */ /* ins_nav_debug_distance_to_cp */) + 0x40))(unaff_EBX + 0x6059f5 /* ins_nav_debug_distance_to_cp */ /* ins_nav_debug_distance_to_cp */ /* ins_nav_debug_distance_to_cp */);
  if (iVar3 == 0) {
    return;
  }
  iVar3 = 0;
  CFmtStrN<256,false>::CFmtStrN(this_01,local_14c,unaff_EBX + 0x29932b /* "CPDist: " */ /* "CPDist: " */ /* "CPDist: " */);
  do {
    if (0.0 < *(float *)(in_stack_00000004 + iVar3 * 4 + 0x1ac)) {
      dVar7 = (double)*(float *)(in_stack_00000004 + iVar3 * 4 + 0x1ac);
      CFmtStrN<256,false>::CFmtStrN
                (in_stack_00000004,local_47c,unaff_EBX + 0x299334 /* "%i:%3.2f " */ /* "%i:%3.2f " */ /* "%i:%3.2f " */,iVar3,SUB84(dVar7,0),
                 (int)((ulonglong)dVar7 >> 0x20));
      pcVar4 = local_147 + local_44;
      if (pcVar4 < local_48) {
        pcVar6 = local_477;
        cVar1 = local_477[0];
        while (cVar1 != '\0') {
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
          *pcVar4 = cVar1;
          pcVar4 = pcVar4 + 1;
          if (pcVar4 == local_48) break;
          cVar1 = *pcVar6;
        }
      }
      *pcVar4 = '\0';
      local_44 = (int)pcVar4 - (int)local_147;
    }
    iVar3 = iVar3 + 1;
    if (iVar3 == 0x10) {
      local_28 = *(undefined4 *)(in_stack_00000004 + 0x2c);
      local_20 = *(float *)(unaff_EBX + 0x243009 /* 12.0f */ /* 12.0f */ /* 12.0f */) + *(float *)(in_stack_00000004 + 0x34);
      local_24 = *(undefined4 *)(in_stack_00000004 + 0x30);
      NDebugOverlay::Text((Vector *)&local_28,local_147,false,0.01023);
      return;
    }
  } while( true );
}



/* ----------------------------------------
 * CINSNavArea::DrawSelectedSet
 * Address: 006e26e0
 * ---------------------------------------- */

/* CINSNavArea::DrawSelectedSet(Vector const&) const */

void __cdecl CINSNavArea::DrawSelectedSet(Vector *param_1)

{
  CNavArea *this;
  
  __i686_get_pc_thunk_bx();
  CNavArea::DrawSelectedSet(this,param_1);
  return;
}



/* ----------------------------------------
 * CINSNavArea::GetAssociatedControlPoint
 * Address: 006e4460
 * ---------------------------------------- */

/* CINSNavArea::GetAssociatedControlPoint() */

undefined4 __thiscall CINSNavArea::GetAssociatedControlPoint(CINSNavArea *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x25c);
}



/* ----------------------------------------
 * CINSNavArea::GetAssociatedSpawnZone
 * Address: 006e36d0
 * ---------------------------------------- */

/* CINSNavArea::GetAssociatedSpawnZone() */

undefined4 CINSNavArea::GetAssociatedSpawnZone(void)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int unaff_EBX;
  undefined8 uVar4;
  
  uVar4 = __i686_get_pc_thunk_bx();
  iVar3 = (int)((ulonglong)uVar4 >> 0x20);
  uVar2 = (undefined4)uVar4;
  if ((*(byte *)(iVar3 + 0x161) & 1) != 0) {
    uVar1 = *(uint *)(iVar3 + 600);
    if ((uVar1 != 0xffffffff) &&
       (iVar3 = **(int **)(unaff_EBX + 0x4c30f5 /* &g_pEntityList */ /* &g_pEntityList */ /* &g_pEntityList */) + (uVar1 & 0xffff) * 0x18,
       *(uint *)(iVar3 + 8) == uVar1 >> 0x10)) {
      uVar2 = *(undefined4 *)(iVar3 + 4);
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSNavArea::GetCombatIntensity
 * Address: 006e3010
 * ---------------------------------------- */

/* CINSNavArea::GetCombatIntensity() const */

float10 __thiscall CINSNavArea::GetCombatIntensity(CINSNavArea *this)

{
  uint *puVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  float fVar8;
  int unaff_EBX;
  bool bVar9;
  float10 fVar10;
  float10 fVar11;
  float fVar12;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar3 = *(int *)(unaff_EBX + 0x4c3959 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar9 = *(int *)(iVar3 + 0x100c) != 0;
  if ((bVar9) && (iVar6 = *(int *)(iVar3 + 0x19b8), iVar5 = ThreadGetCurrentId(), iVar6 == iVar5)) {
    piVar7 = *(int **)(iVar3 + 0x1014);
    if (*piVar7 != unaff_EBX + 0x29b85d /* "CINSNavArea::GetCombatIntensity" */ /* "CINSNavArea::GetCombatIntensity" */ /* "CINSNavArea::GetCombatIntensity" */) {
      piVar7 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar7,unaff_EBX + 0x29b85d /* "CINSNavArea::GetCombatIntensity" */ /* "CINSNavArea::GetCombatIntensity" */ /* "CINSNavArea::GetCombatIntensity" */,(char *)0x0,
                                 unaff_EBX + 0x29b5ed /* "INSNavMesh" */ /* "INSNavMesh" */ /* "INSNavMesh" */);
      *(int **)(iVar3 + 0x1014) = piVar7;
    }
    puVar1 = (uint *)(*(int *)(iVar3 + 0x10a0) + piVar7[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar3 + 0x1010) = 0;
    fVar12 = *(float *)(in_stack_00000004 + 0x194);
  }
  else {
    fVar12 = *(float *)(in_stack_00000004 + 0x194);
  }
  if (fVar12 <= 0.0) {
    fVar12 = 0.0;
  }
  else {
    fVar12 = *(float *)(in_stack_00000004 + 0x18c);
    fVar10 = (float10)IntervalTimer::Now();
    piVar7 = *(int **)(unaff_EBX + 0x608021 /* nb_nav_combat_decay_rate+0x1c */ /* nb_nav_combat_decay_rate+0x1c */ /* nb_nav_combat_decay_rate+0x1c */);
    fVar2 = *(float *)(in_stack_00000004 + 0x194);
    if (piVar7 == (int *)(unaff_EBX + 0x608005 /* nb_nav_combat_decay_rate */ /* nb_nav_combat_decay_rate */ /* nb_nav_combat_decay_rate */U)) {
      fVar8 = (float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x608031 /* nb_nav_combat_decay_rate+0x2c */ /* nb_nav_combat_decay_rate+0x2c */ /* nb_nav_combat_decay_rate+0x2c */));
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7);
      fVar8 = (float)fVar11;
    }
    fVar12 = fVar12 - ((float)fVar10 - fVar2) * fVar8;
    if (fVar12 <= 0.0) {
      fVar12 = 0.0;
    }
  }
  if ((bVar9) &&
     (((*(char *)(iVar3 + 0x1010) == '\0' || (*(int *)(iVar3 + 0x100c) != 0)) &&
      (iVar6 = *(int *)(iVar3 + 0x19b8), iVar5 = ThreadGetCurrentId(), iVar6 == iVar5)))) {
    cVar4 = CVProfNode::ExitScope();
    iVar6 = *(int *)(iVar3 + 0x1014);
    if (cVar4 != '\0') {
      iVar6 = *(int *)(iVar6 + 100);
      *(int *)(iVar3 + 0x1014) = iVar6;
    }
    *(bool *)(iVar3 + 0x1010) = iVar6 == iVar3 + 0x1018;
    return (float10)fVar12;
  }
  return (float10)fVar12;
}



/* ----------------------------------------
 * CINSNavArea::GetDeathIntensity
 * Address: 006e3450
 * ---------------------------------------- */

/* CINSNavArea::GetDeathIntensity(int) const */

float10 __thiscall CINSNavArea::GetDeathIntensity(CINSNavArea *this,int param_1)

{
  uint *puVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  float fVar8;
  int unaff_EBX;
  bool bVar9;
  float10 fVar10;
  float10 fVar11;
  float fVar12;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar3 = *(int *)(unaff_EBX + 0x4c3519 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar9 = *(int *)(iVar3 + 0x100c) != 0;
  if (bVar9) {
    iVar6 = *(int *)(iVar3 + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar6 == iVar5) {
      piVar7 = *(int **)(iVar3 + 0x1014);
      if (*piVar7 != unaff_EBX + 0x29b469 /* "CINSNavArea::GetDeathIntensity" */ /* "CINSNavArea::GetDeathIntensity" */ /* "CINSNavArea::GetDeathIntensity" */) {
        piVar7 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar7,unaff_EBX + 0x29b469 /* "CINSNavArea::GetDeathIntensity" */ /* "CINSNavArea::GetDeathIntensity" */ /* "CINSNavArea::GetDeathIntensity" */,(char *)0x0,
                                   unaff_EBX + 0x29b1ad /* "INSNavMesh" */ /* "INSNavMesh" */ /* "INSNavMesh" */);
        *(int **)(iVar3 + 0x1014) = piVar7;
      }
      puVar1 = (uint *)(*(int *)(iVar3 + 0x10a0) + piVar7[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar3 + 0x1010) = 0;
    }
  }
  iVar6 = param_1 + 0xc + ((in_stack_00000008 != 2) + 0x42) * 8;
  if (*(float *)(iVar6 + 4) <= 0.0) {
    fVar12 = 0.0;
  }
  else {
    fVar12 = *(float *)(param_1 + 4 + ((in_stack_00000008 != 2) + 0x84) * 4);
    fVar10 = (float10)IntervalTimer::Now();
    piVar7 = *(int **)(unaff_EBX + 0x607941 /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */);
    fVar2 = *(float *)(iVar6 + 4);
    if (piVar7 == (int *)(unaff_EBX + 0x607925 /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */U)) {
      fVar8 = (float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x607951 /* nb_nav_death_decay_rate+0x2c */ /* nb_nav_death_decay_rate+0x2c */ /* nb_nav_death_decay_rate+0x2c */));
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7);
      fVar8 = (float)fVar11;
    }
    fVar12 = fVar12 - ((float)fVar10 - fVar2) * fVar8;
    if (fVar12 <= 0.0) {
      fVar12 = 0.0;
    }
  }
  if ((bVar9) && ((*(char *)(iVar3 + 0x1010) == '\0' || (*(int *)(iVar3 + 0x100c) != 0)))) {
    iVar6 = *(int *)(iVar3 + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar6 == iVar5) {
      cVar4 = CVProfNode::ExitScope();
      iVar6 = *(int *)(iVar3 + 0x1014);
      if (cVar4 != '\0') {
        iVar6 = *(int *)(iVar6 + 100);
        *(int *)(iVar3 + 0x1014) = iVar6;
      }
      *(bool *)(iVar3 + 0x1010) = iVar6 == iVar3 + 0x1018;
      return (float10)fVar12;
    }
  }
  return (float10)fVar12;
}



/* ----------------------------------------
 * CINSNavArea::GetDistanceToNearestHidingSpot
 * Address: 006e2ef0
 * ---------------------------------------- */

/* CINSNavArea::GetDistanceToNearestHidingSpot(Vector) */

float10 __cdecl
CINSNavArea::GetDistanceToNearestHidingSpot(int param_1,float param_2,float param_3,float param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int unaff_EBX;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  
  __i686_get_pc_thunk_bx();
  fVar7 = *(float *)(&DAT_001d5c16 + unaff_EBX);
  if (param_1 != -0xd0) {
    iVar1 = **(int **)(param_1 + 0xd0);
    if ((iVar1 != 0) && (fVar7 = *(float *)(unaff_EBX + 0x242116 /* 1000.0f */ /* 1000.0f */ /* 1000.0f */), 0 < iVar1)) {
      iVar3 = 0;
      do {
        iVar2 = (*(int **)(param_1 + 0xd0))[iVar3 + 1];
        if ((iVar2 != 0) &&
           (fVar6 = param_2 - *(float *)(iVar2 + 4), fVar4 = param_3 - *(float *)(iVar2 + 8),
           fVar5 = param_4 - *(float *)(iVar2 + 0xc),
           fVar4 = SQRT(fVar4 * fVar4 + fVar6 * fVar6 + fVar5 * fVar5), fVar4 <= fVar7)) {
          fVar7 = fVar4;
        }
        iVar3 = iVar3 + 1;
      } while (iVar3 != iVar1);
    }
  }
  return (float10)fVar7;
}



/* ----------------------------------------
 * CINSNavArea::GetInOutAdjacentCount
 * Address: 006e4a40
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x006e4aa5) */
/* WARNING: Removing unreachable block (ram,0x006e4ac6) */
/* WARNING: Removing unreachable block (ram,0x006e4acf) */
/* WARNING: Removing unreachable block (ram,0x006e4af4) */
/* WARNING: Removing unreachable block (ram,0x006e4afd) */
/* WARNING: Removing unreachable block (ram,0x006e4ab8) */
/* WARNING: Removing unreachable block (ram,0x006e4abe) */
/* WARNING: Removing unreachable block (ram,0x006e4b20) */
/* CINSNavArea::GetInOutAdjacentCount(int&, int&) */

void __thiscall CINSNavArea::GetInOutAdjacentCount(CINSNavArea *this,int *param_1,int *param_2)

{
  CNavArea *this_00;
  undefined4 *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  *in_stack_0000000c = 0;
  *param_2 = 0;
  CNavArea::CollectAdjacentAreas(this_00,(CUtlVector *)param_1);
  return;
}



/* ----------------------------------------
 * CINSNavArea::GetNearbyDeathIntensity
 * Address: 006e4470
 * ---------------------------------------- */

/* CINSNavArea::GetNearbyDeathIntensity(int) const */

float10 __thiscall CINSNavArea::GetNearbyDeathIntensity(CINSNavArea *this,int param_1)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  float fVar5;
  int *piVar6;
  CNavArea *extraout_ECX;
  CNavArea *extraout_ECX_00;
  CNavArea *this_00;
  int unaff_EBX;
  int iVar7;
  float10 fVar8;
  float fVar9;
  CINSNavArea *in_stack_00000008;
  int *piVar10;
  CINSNavArea *pCVar11;
  float local_4c;
  float local_44;
  float local_40;
  int local_3c;
  undefined4 local_38;
  int local_34;
  int local_30;
  int local_2c;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6e447b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  this_00 = extraout_ECX;
  if (((bool)local_1d) &&
     (iVar7 = *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar3 = ThreadGetCurrentId(),
     this_00 = extraout_ECX_00, iVar7 == iVar3)) {
    piVar6 = *(int **)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar6 != unaff_EBX + 0x29a469 /* "CINSNavArea::GetNearbyDeathIntensity" */ /* "CINSNavArea::GetNearbyDeathIntensity" */ /* "CINSNavArea::GetNearbyDeathIntensity" */) {
      piVar6 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar6,unaff_EBX + 0x29a469 /* "CINSNavArea::GetNearbyDeathIntensity" */ /* "CINSNavArea::GetNearbyDeathIntensity" */ /* "CINSNavArea::GetNearbyDeathIntensity" */,(char *)0x0,
                                 unaff_EBX + 0x29a18d /* "INSNavMesh" */ /* "INSNavMesh" */ /* "INSNavMesh" */);
      *(int **)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar6;
    }
    puVar1 = (uint *)(piVar6[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    this_00 = *(CNavArea **)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
    this_00[0x1010] = (CNavArea)0x0;
  }
  pCVar11 = (CINSNavArea *)&local_3c;
  local_3c = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  piVar6 = (int *)param_1;
  CNavArea::CollectAdjacentAreas(this_00,(CUtlVector *)param_1);
  if (local_30 < 2) {
    local_40 = 0.0;
  }
  else {
    local_40 = 0.0;
    iVar7 = 0;
    do {
      if ((iVar7 < local_30) && (piVar10 = *(int **)(local_3c + iVar7 * 4), piVar10 != (int *)0x0))
      {
        pCVar11 = *(CINSNavArea **)(unaff_EBX + 0x4c216d /* &typeinfo for CNavArea */ /* &typeinfo for CNavArea */ /* &typeinfo for CNavArea */);
        piVar4 = (int *)__dynamic_cast(piVar10,pCVar11,unaff_EBX + 0x4afd25 /* typeinfo for CINSNavArea */ /* typeinfo for CINSNavArea */ /* typeinfo for CINSNavArea */,0);
        piVar6 = piVar10;
        if (piVar4 != (int *)0x0) {
          pCVar11 = in_stack_00000008;
          fVar8 = (float10)GetDeathIntensity(in_stack_00000008,(int)piVar4);
          local_40 = (float)fVar8 + local_40;
          piVar6 = piVar4;
        }
      }
      iVar7 = iVar7 + 1;
    } while (iVar7 < local_30 + -1);
  }
  local_4c = 0.0;
  fVar9 = *(float *)(param_1 + 4 + ((in_stack_00000008 != (CINSNavArea *)0x2) + 0x84) * 4);
  piVar10 = (int *)(param_1 + 0xc + ((in_stack_00000008 != (CINSNavArea *)0x2) + 0x42) * 8);
  if ((float)piVar10[1] <= 0.0) {
    piVar4 = *(int **)(unaff_EBX + 0x606921 /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */);
    local_44 = *(float *)(unaff_EBX + 0x249215 /* 99999.9f */ /* 99999.9f */ /* 99999.9f */);
    if (piVar4 != (int *)(unaff_EBX + 0x606905 /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */)) goto LAB_006e45cc;
  }
  else {
    piVar6 = piVar10;
    fVar8 = (float10)IntervalTimer::Now();
    piVar4 = *(int **)(unaff_EBX + 0x606921 /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */ /* nb_nav_death_decay_rate+0x1c */);
    local_44 = (float)fVar8 - (float)piVar10[1];
    if (piVar4 != (int *)(unaff_EBX + 0x606905 /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */ /* nb_nav_death_decay_rate */)) {
LAB_006e45cc:
      fVar8 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4,pCVar11);
      fVar5 = (float)fVar8;
      goto joined_r0x006e46b6;
    }
  }
  fVar5 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x606931 /* nb_nav_death_decay_rate+0x2c */ /* nb_nav_death_decay_rate+0x2c */ /* nb_nav_death_decay_rate+0x2c */));
  piVar4 = piVar6;
joined_r0x006e46b6:
  if (local_34 < 0) {
    local_30 = 0;
    local_2c = local_3c;
  }
  else {
    local_30 = 0;
    if (local_3c != 0) {
      piVar4 = (int *)**(int **)(unaff_EBX + 0x4c23fd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
      (**(code **)(*piVar4 + 8))(piVar4,local_3c);
      local_3c = 0;
    }
    local_38 = 0;
    local_2c = 0;
  }
  if ((local_1d != '\0') &&
     (((*(char *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
       (*(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
      (iVar7 = *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar3 = ThreadGetCurrentId(piVar4)
      , iVar7 == iVar3)))) {
    cVar2 = CVProfNode::ExitScope();
    if (cVar2 == '\0') {
      iVar7 = *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar7 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar7;
    }
    *(bool *)(*(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
         iVar7 == *(int *)(unaff_EBX + 0x4c24f9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  }
  fVar9 = (local_40 + fVar9) - fVar5 * local_44;
  if (fVar9 <= 0.0) {
    fVar9 = local_4c;
  }
  return (float10)fVar9;
}



/* ----------------------------------------
 * CINSNavArea::GetSpawnScore
 * Address: 006e3730
 * ---------------------------------------- */

/* CINSNavArea::GetSpawnScore(int) */

float10 __thiscall CINSNavArea::GetSpawnScore(CINSNavArea *this,int param_1)

{
  CINSRules *this_00;
  char cVar1;
  int iVar2;
  int *piVar3;
  CINSBlockZoneBase *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  uint uVar4;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  int in_stack_00000008;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  fVar6 = *(float *)(**(int **)(unaff_EBX + 0x4c3165 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
  fVar7 = *(float *)(param_1 + 0x1a4 + iVar2 * 4);
  piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c3971 /* &nav_spawn_rescore_time */ /* &nav_spawn_rescore_time */ /* &nav_spawn_rescore_time */))[7];
  if (piVar3 == *(int **)(unaff_EBX + 0x4c3971 /* &nav_spawn_rescore_time */ /* &nav_spawn_rescore_time */ /* &nav_spawn_rescore_time */)) {
    fVar8 = (float)((uint)piVar3 ^ piVar3[0xb]);
  }
  else {
    fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
    fVar8 = (float)fVar5;
  }
  if (fVar6 < fVar7 + fVar8) {
    iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
    return (float10)*(float *)(param_1 + 0x19c + iVar2 * 4);
  }
  piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c32c9 /* &nav_spawn_score_base */ /* &nav_spawn_score_base */ /* &nav_spawn_score_base */))[7];
  if (piVar3 == *(int **)(unaff_EBX + 0x4c32c9 /* &nav_spawn_score_base */ /* &nav_spawn_score_base */ /* &nav_spawn_score_base */)) {
    local_24 = (float)((uint)piVar3 ^ piVar3[0xb]);
  }
  else {
    fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
    local_24 = (float)fVar5;
  }
  iVar2 = GetAssociatedSpawnZone();
  if (iVar2 != 0) {
    cVar1 = CINSBlockZoneBase::IsActive(this_01);
    if (cVar1 != '\0') {
      GetAssociatedSpawnZone();
      iVar2 = CBaseEntity::GetTeamNumber(this_02);
      if (in_stack_00000008 != iVar2) {
        iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
        *(undefined4 *)(param_1 + 0x19c + iVar2 * 4) = 0xbf800000 /* -1.0f */;
        iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
        *(undefined4 *)(param_1 + 0x1a4 + iVar2 * 4) =
             *(undefined4 *)(**(int **)(unaff_EBX + 0x4c3165 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
        return (float10)-1.0;
      }
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c33f5 /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x4c33f5 /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */)) {
        local_20 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_20 = (float)fVar5;
      }
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c2fed /* &nav_spawn_score_friendly_spawn_bonus_max_distance */ /* &nav_spawn_score_friendly_spawn_bonus_max_distance */ /* &nav_spawn_score_friendly_spawn_bonus_max_distance */))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x4c2fed /* &nav_spawn_score_friendly_spawn_bonus_max_distance */ /* &nav_spawn_score_friendly_spawn_bonus_max_distance */ /* &nav_spawn_score_friendly_spawn_bonus_max_distance */)) {
        local_28 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_28 = (float)fVar5;
      }
      iVar2 = GetAssociatedSpawnZone();
      if ((*(byte *)(iVar2 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_03);
      }
      fVar8 = *(float *)(iVar2 + 0x208) - *(float *)(param_1 + 0x2c);
      fVar6 = *(float *)(iVar2 + 0x20c) - *(float *)(param_1 + 0x30);
      fVar7 = *(float *)(iVar2 + 0x210) - *(float *)(param_1 + 0x34);
      fVar6 = SQRT(fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7);
      if (local_28 == 0.0) {
        local_20 = (float)((uint)local_20 & -(uint)(fVar6 < 0.0));
      }
      else {
        fVar6 = fVar6 / local_28;
        if (*(float *)(unaff_EBX + 0x1d53d9 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= fVar6) {
          fVar6 = *(float *)(unaff_EBX + 0x1d53d9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
        }
        if (fVar6 <= 0.0) {
          fVar6 = 0.0;
        }
        local_20 = local_20 - fVar6 * local_20;
      }
      local_24 = local_24 + local_20;
    }
  }
  uVar4 = *(uint *)(param_1 + 0x160);
  if ((uVar4 & 0x80) != 0) {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c336d /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4c336d /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */)) {
      fVar6 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
      fVar6 = (float)fVar5;
      uVar4 = *(uint *)(param_1 + 0x160);
    }
    local_24 = fVar6 * local_24;
  }
  if (((uVar4 & 0x2004) == 0) ||
     (in_stack_00000008 !=
      *(int *)(**(int **)(unaff_EBX + 0x4c35e1 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490 + *(int *)(param_1 + 0x25c) * 4)))
  goto LAB_006e395a;
  this_00 = *(CINSRules **)(&DAT_004c31bd + unaff_EBX);
  piVar3 = *(int **)this_00;
  iVar2 = (**(code **)(*piVar3 + 0x404 /* CBaseCombatCharacter::HeadDirection2D */))(piVar3,in_stack_00000008);
  if (iVar2 == 3) goto LAB_006e395a;
  cVar1 = CINSRules::IsOutpost(this_00);
  if (cVar1 != '\0') goto LAB_006e395a;
  if (*(int *)(**(int **)(unaff_EBX + 0x4c35e1 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x6f0 + *(int *)(param_1 + 0x25c) * 4) == 0) {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c365d /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4c365d /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */)) goto LAB_006e3ae5;
LAB_006e3ab6:
    fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
    fVar6 = (float)fVar5;
  }
  else {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c357d /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */))[7];
    if (piVar3 != *(int **)(unaff_EBX + 0x4c357d /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */)) goto LAB_006e3ab6;
LAB_006e3ae5:
    fVar6 = (float)((uint)piVar3 ^ piVar3[0xb]);
  }
  local_24 = fVar6 * local_24;
LAB_006e395a:
  local_20 = local_24 + (float)**(int **)(param_1 + 0xd0);
  cVar1 = (**(code **)(*(int *)param_1 + 0x88))(param_1,(in_stack_00000008 == 2) + '\x02');
  if (cVar1 != '\0') {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4c37a9 /* &nav_spawn_score_potentially_visible */ /* &nav_spawn_score_potentially_visible */ /* &nav_spawn_score_potentially_visible */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4c37a9 /* &nav_spawn_score_potentially_visible */ /* &nav_spawn_score_potentially_visible */ /* &nav_spawn_score_potentially_visible */)) {
      fVar6 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar5 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
      fVar6 = (float)fVar5;
    }
    local_20 = fVar6 * local_20;
  }
  fVar5 = (float10)RandomFloat(0x3f4ccccd /* 0.8f */,0x3f99999a /* 1.2f */);
  iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
  *(float *)(param_1 + 0x19c + iVar2 * 4) = (float)fVar5 * local_20;
  iVar2 = ShiftPlayTeamLeft(in_stack_00000008);
  *(undefined4 *)(param_1 + 0x1a4 + iVar2 * 4) =
       *(undefined4 *)(**(int **)(unaff_EBX + 0x4c3165 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  return (float10)((float)fVar5 * local_20);
}



/* ----------------------------------------
 * CINSNavArea::HasAdjacentInsideArea
 * Address: 006e4920
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x006e4976) */
/* WARNING: Removing unreachable block (ram,0x006e4988) */
/* WARNING: Removing unreachable block (ram,0x006e498f) */
/* WARNING: Removing unreachable block (ram,0x006e49b4) */
/* WARNING: Removing unreachable block (ram,0x006e4a00) */
/* WARNING: Removing unreachable block (ram,0x006e49bd) */
/* WARNING: Removing unreachable block (ram,0x006e49db) */
/* CINSNavArea::HasAdjacentInsideArea() */

undefined1 __thiscall CINSNavArea::HasAdjacentInsideArea(CINSNavArea *this)

{
  CNavArea *this_00;
  CUtlVector *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CNavArea::CollectAdjacentAreas(this_00,in_stack_00000004);
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::HasAdjacentOutsideArea
 * Address: 006e4800
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x006e4856) */
/* WARNING: Removing unreachable block (ram,0x006e4868) */
/* WARNING: Removing unreachable block (ram,0x006e486f) */
/* WARNING: Removing unreachable block (ram,0x006e4894) */
/* WARNING: Removing unreachable block (ram,0x006e48e0) */
/* WARNING: Removing unreachable block (ram,0x006e489d) */
/* WARNING: Removing unreachable block (ram,0x006e48bb) */
/* CINSNavArea::HasAdjacentOutsideArea() */

undefined1 __thiscall CINSNavArea::HasAdjacentOutsideArea(CINSNavArea *this)

{
  CNavArea *this_00;
  CUtlVector *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CNavArea::CollectAdjacentAreas(this_00,in_stack_00000004);
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::INSMark
 * Address: 006e2d40
 * ---------------------------------------- */

/* CINSNavArea::INSMark() */

void __thiscall CINSNavArea::INSMark(CINSNavArea *this)

{
  int extraout_ECX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)(in_stack_00000004 + 0x198) = *(undefined4 *)(extraout_ECX + 0x52a47b /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */);
  return;
}



/* ----------------------------------------
 * CINSNavArea::InvalidateSpawnScore
 * Address: 006e2fa0
 * ---------------------------------------- */

/* CINSNavArea::InvalidateSpawnScore(int) */

void __thiscall CINSNavArea::InvalidateSpawnScore(CINSNavArea *this,int param_1)

{
  int iVar1;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar1 = ShiftPlayTeamLeft(in_stack_00000008);
  *(undefined4 *)(param_1 + 0x19c + iVar1 * 4) = 0;
  iVar1 = ShiftPlayTeamLeft(in_stack_00000008);
  *(undefined4 *)(param_1 + 0x1a4 + iVar1 * 4) = 0xc47a0000 /* -1000.0f */;
  return;
}



/* ----------------------------------------
 * CINSNavArea::IsDoorway
 * Address: 006e4b70
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x006e4bfa) */
/* WARNING: Removing unreachable block (ram,0x006e4c00) */
/* WARNING: Removing unreachable block (ram,0x006e4c07) */
/* WARNING: Removing unreachable block (ram,0x006e4c2f) */
/* WARNING: Removing unreachable block (ram,0x006e4c38) */
/* WARNING: Removing unreachable block (ram,0x006e4c96) */
/* WARNING: Removing unreachable block (ram,0x006e4c57) */
/* WARNING: Removing unreachable block (ram,0x006e4c7d) */
/* CINSNavArea::IsDoorway() */

undefined1 __thiscall CINSNavArea::IsDoorway(CINSNavArea *this)

{
  CINSNavArea *this_00;
  CNavArea *this_01;
  CUtlVector *in_stack_00000004;
  int local_2c [3];
  int local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x6e4b7b;
  __i686_get_pc_thunk_bx();
  if ((((byte)in_stack_00000004[0x160] & 0x80) != 0) &&
     (GetInOutAdjacentCount(this_00,(int *)in_stack_00000004,local_2c), local_20 == 1)) {
    CNavArea::CollectAdjacentAreas(this_01,in_stack_00000004);
  }
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::IsINSMarked
 * Address: 006e2d10
 * ---------------------------------------- */

/* CINSNavArea::IsINSMarked() const */

bool __thiscall CINSNavArea::IsINSMarked(CINSNavArea *this)

{
  int extraout_ECX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  return *(int *)(in_stack_00000004 + 0x198) == *(int *)(extraout_ECX + 0x52a4ab /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */);
}



/* ----------------------------------------
 * CINSNavArea::IsInCombat
 * Address: 006e3300
 * ---------------------------------------- */

/* CINSNavArea::IsInCombat() const */

bool CINSNavArea::IsInCombat(void)

{
  CINSNavArea *this;
  int unaff_EBX;
  float10 extraout_ST0;
  
  __i686_get_pc_thunk_bx();
  GetCombatIntensity(this);
  return *(float *)(unaff_EBX + 0x241d27 /* 0.01f */ /* 0.01f */ /* 0.01f */) <= (float)extraout_ST0 &&
         (float)extraout_ST0 != *(float *)(unaff_EBX + 0x241d27 /* 0.01f */ /* 0.01f */ /* 0.01f */);
}



/* ----------------------------------------
 * CINSNavArea::IsPotentiallyVisibleToTeam
 * Address: 006e65d0
 * ---------------------------------------- */

/* CINSNavArea::IsPotentiallyVisibleToTeam(int) const */

undefined4 __thiscall CINSNavArea::IsPotentiallyVisibleToTeam(CINSNavArea *this,int param_1)

{
  int iVar1;
  int in_stack_00000008;
  
  if (1 < in_stack_00000008 - 2U) {
    return 0;
  }
  iVar1 = *(int *)(param_1 + 0x170 + (in_stack_00000008 - 2U) * 0x14);
  return CONCAT31((int3)((uint)iVar1 >> 8),0 < iVar1);
}



/* ----------------------------------------
 * CINSNavArea::IsValid
 * Address: 006e5190
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x006e52b7) */
/* CINSNavArea::IsValid() */

undefined4 __thiscall CINSNavArea::IsValid(CINSNavArea *this)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  CNavMesh *this_00;
  int unaff_EBX;
  CUtlVector *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if ((((*(uint *)(in_stack_00000004 + 0x9c) <= *(uint *)(**(uint **)(unaff_EBX + 0x4c151a /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */) + 0x34))
       && (iVar4 = CNavMesh::GetNavAreaByID(this_00,**(uint **)(unaff_EBX + 0x4c151a /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */)), iVar4 != 0))
      && (fVar1 = *(float *)(in_stack_00000004 + 0x2c), ((uint)fVar1 & 0x7f800000) != 0x7f800000))
     && (fVar2 = *(float *)(in_stack_00000004 + 0x30), ((uint)fVar2 & 0x7f800000) != 0x7f800000)) {
    fVar3 = *(float *)(in_stack_00000004 + 0x34);
    if (((CNavArea *)((uint)fVar3 & 0x7f800000) != (CNavArea *)0x7f800000) &&
       (SQRT(fVar2 * fVar2 + fVar1 * fVar1 + fVar3 * fVar3) < *(float *)(unaff_EBX + 0x24850a /* rodata:0x49742400 */ /* rodata:0x49742400 */ /* rodata:0x49742400 */))) {
      CNavArea::CollectAdjacentAreas((CNavArea *)((uint)fVar3 & 0x7f800000),in_stack_00000004);
    }
  }
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::Load
 * Address: 006e2870
 * ---------------------------------------- */

/* CINSNavArea::Load(CUtlBuffer&, unsigned int, unsigned int) */

undefined4 __cdecl CINSNavArea::Load(CUtlBuffer *param_1,uint param_2,uint param_3)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  CNavArea *this;
  CUtlBuffer *this_00;
  uint extraout_EDX;
  char *__nptr;
  int iVar4;
  int unaff_EBX;
  char **__endptr;
  uint uVar5;
  ulong local_2c;
  undefined4 local_24;
  char *local_20 [4];
  
  __i686_get_pc_thunk_bx();
  uVar2 = param_2;
  uVar5 = extraout_EDX;
  CNavArea::Load(this,param_1,param_2,param_3);
  uVar2 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c3e37 /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */) + 0x38))
                    ((int *)**(undefined4 **)(unaff_EBX + 0x4c3e37 /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */),uVar2,param_3,uVar5);
  if (uVar2 < extraout_EDX) {
    Warning(unaff_EBX + 0x29bf5b /* "Unknown NavArea sub-version number
" */ /* "Unknown NavArea sub-version number
" */ /* "Unknown NavArea sub-version number
" */);
    return 2;
  }
  if (extraout_EDX < 2) {
    *(undefined4 *)(param_1 + 0x160) = 0;
    return 0;
  }
  if ((*(byte *)(param_2 + 0x15) & 1) == 0) {
    __endptr = (char **)0x4;
    cVar1 = CUtlBuffer::CheckGet(this_00,param_2);
    if (cVar1 != '\0') {
      if ((*(byte *)(param_2 + 0x34) & 1) == 0) {
        iVar4 = *(int *)(param_2 + 0xc);
        local_2c = *(ulong *)(*(int *)param_2 + (iVar4 - *(int *)(param_2 + 0x20)));
      }
      else {
        CByteswap::SwapBufferToTargetEndian<unsigned_int>
                  ((uint *)((*(int *)(param_2 + 0xc) - *(int *)(param_2 + 0x20)) + *(int *)param_2),
                   (uint *)__endptr,param_3);
        iVar4 = *(int *)(param_2 + 0xc);
      }
      *(int *)(param_2 + 0xc) = iVar4 + 4;
      goto LAB_006e28f4;
    }
  }
  else {
    param_3 = (uint)&local_24;
    local_24 = 0x80;
    __endptr = (char **)0x0;
    cVar1 = CUtlBuffer::CheckArbitraryPeekGet(this_00,param_2,(int *)0x0);
    if (cVar1 != '\0') {
      __endptr = local_20;
      __nptr = (char *)((*(int *)(param_2 + 0xc) - *(int *)(param_2 + 0x20)) + *(int *)param_2);
      param_3 = 10;
      local_20[0] = __nptr;
      local_2c = strtoul(__nptr,__endptr,10);
      if ((int)local_20[0] - (int)__nptr != 0) {
        *(int *)(param_2 + 0xc) = *(int *)(param_2 + 0xc) + ((int)local_20[0] - (int)__nptr);
      }
      goto LAB_006e28f4;
    }
  }
  local_2c = 0;
LAB_006e28f4:
  *(ulong *)(param_1 + 0x160) = local_2c;
  uVar3 = 0;
  if (*(char *)(param_2 + 0x14) != '\0') {
    Warning(unaff_EBX + 0x29bf7f /* "Can't read INS-specific attributes
" */ /* "Can't read INS-specific attributes
" */ /* "Can't read INS-specific attributes
" */,__endptr,param_3);
    uVar3 = 2;
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSNavArea::MakeNewINSMarker
 * Address: 006e2cd0
 * ---------------------------------------- */

/* CINSNavArea::MakeNewINSMarker() */

void CINSNavArea::MakeNewINSMarker(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(int *)(extraout_ECX + 0x52a4eb /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */) = *(int *)(extraout_ECX + 0x52a4eb /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */) + 1;
  return;
}



/* ----------------------------------------
 * CINSNavArea::OnCombat
 * Address: 006e3220
 * ---------------------------------------- */

/* CINSNavArea::OnCombat() */

void __thiscall CINSNavArea::OnCombat(CINSNavArea *this)

{
  int *piVar1;
  float fVar2;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar4 = *(float *)(in_stack_00000004 + 0x18c);
  piVar1 = *(int **)(unaff_EBX + 0x607e6e /* nb_nav_combat_build_rate+0x1c */ /* nb_nav_combat_build_rate+0x1c */ /* nb_nav_combat_build_rate+0x1c */);
  if (piVar1 == (int *)(unaff_EBX + 0x607e52 /* nb_nav_combat_build_rate */ /* nb_nav_combat_build_rate */ /* nb_nav_combat_build_rate */U)) {
    fVar2 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x607e7e /* nb_nav_combat_build_rate+0x2c */ /* nb_nav_combat_build_rate+0x2c */ /* nb_nav_combat_build_rate+0x2c */));
  }
  else {
    fVar3 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar2 = (float)fVar3;
  }
  fVar4 = fVar4 + fVar2;
  fVar2 = *(float *)(unaff_EBX + 0x1d58e6 /* 1.0f */ /* 1.0f */ /* 1.0f */);
  *(float *)(in_stack_00000004 + 0x18c) = fVar4;
  if (fVar2 < fVar4) {
    *(float *)(in_stack_00000004 + 0x18c) = fVar2;
  }
  fVar3 = (float10)IntervalTimer::Now();
  if (*(float *)(in_stack_00000004 + 0x194) != (float)fVar3) {
    (**(code **)(*(int *)(in_stack_00000004 + 400) + 8))
              (in_stack_00000004 + 400,in_stack_00000004 + 0x194);
    *(float *)(in_stack_00000004 + 0x194) = (float)fVar3;
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::OnDeath
 * Address: 006e3340
 * ---------------------------------------- */

/* CINSNavArea::OnDeath(int) */

void __cdecl CINSNavArea::OnDeath(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  float fVar4;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  
  iVar3 = __i686_get_pc_thunk_bx();
  if (iVar3 - 2U < 2) {
    iVar1 = (iVar3 != 2) + 0x84;
    piVar2 = *(int **)(unaff_EBX + 0x607aab /* nb_nav_death_build_rate+0x1c */ /* nb_nav_death_build_rate+0x1c */ /* nb_nav_death_build_rate+0x1c */);
    fVar6 = *(float *)(param_1 + 4 + iVar1 * 4);
    if (piVar2 == (int *)(unaff_EBX + 0x607a8f /* nb_nav_death_build_rate */ /* nb_nav_death_build_rate */ /* nb_nav_death_build_rate */U)) {
      fVar4 = (float)((uint)piVar2 ^ *(uint *)(unaff_EBX + 0x607abb /* nb_nav_death_build_rate+0x2c */ /* nb_nav_death_build_rate+0x2c */ /* nb_nav_death_build_rate+0x2c */));
    }
    else {
      fVar5 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
      fVar4 = (float)fVar5;
    }
    fVar6 = fVar6 + fVar4;
    iVar3 = param_1 + ((iVar3 != 2) + 0x42) * 8;
    if (*(float *)(unaff_EBX + 0x1d57c3 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= fVar6) {
      fVar6 = *(float *)(unaff_EBX + 0x1d57c3 /* 1.0f */ /* 1.0f */ /* 1.0f */);
    }
    *(float *)(param_1 + 4 + iVar1 * 4) = fVar6;
    fVar5 = (float10)IntervalTimer::Now();
    if (*(float *)(iVar3 + 0x10) != (float)fVar5) {
      (**(code **)(*(int *)(iVar3 + 0xc) + 8))(iVar3 + 0xc,iVar3 + 0x10);
      *(float *)(iVar3 + 0x10) = (float)fVar5;
      return;
    }
  }
  else {
    Warning(unaff_EBX + 0x29b547 /* "CINSNavArea::OnDeath - Invalid team (%i)
" */ /* "CINSNavArea::OnDeath - Invalid team (%i)
" */ /* "CINSNavArea::OnDeath - Invalid team (%i)
" */,iVar3);
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::OnRoundRestart
 * Address: 006e5a00
 * ---------------------------------------- */

/* CINSNavArea::OnRoundRestart() */

void __thiscall CINSNavArea::OnRoundRestart(CINSNavArea *this)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  CNavArea *extraout_ECX;
  CNavArea *this_00;
  CINSNavArea *extraout_ECX_00;
  CINSNavArea *this_01;
  CINSNavArea *extraout_ECX_01;
  CINSNavArea *extraout_ECX_02;
  CINSNavArea *this_02;
  CNavArea *extraout_ECX_03;
  CINSNavArea *extraout_ECX_04;
  int unaff_EBX;
  bool bVar8;
  int in_stack_00000004;
  undefined4 uVar9;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x4c0f69 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  this_00 = *(CNavArea **)(iVar2 + 0x100c);
  bVar8 = this_00 != (CNavArea *)0x0;
  if (bVar8) {
    iVar6 = *(int *)(iVar2 + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    this_00 = extraout_ECX;
    if (iVar6 == iVar4) {
      piVar7 = *(int **)(iVar2 + 0x1014);
      if (*piVar7 != unaff_EBX + 0x298c5e /* "CINSNavArea::OnRoundRestart" */ /* "CINSNavArea::OnRoundRestart" */ /* "CINSNavArea::OnRoundRestart" */) {
        piVar7 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar7,unaff_EBX + 0x298c5e /* "CINSNavArea::OnRoundRestart" */ /* "CINSNavArea::OnRoundRestart" */ /* "CINSNavArea::OnRoundRestart" */,(char *)0x0,
                                   unaff_EBX + 0x2905ff /* "NPCs" */ /* "NPCs" */ /* "NPCs" */);
        *(int **)(iVar2 + 0x1014) = piVar7;
      }
      puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar7[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar2 + 0x1010) = 0;
      this_00 = extraout_ECX_03;
    }
  }
  *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
  iVar6 = in_stack_00000004;
  CNavArea::ClearAllNavCostEntities(this_00);
  if (*(int *)(iVar2 + 0x100c) == 0) {
    *(undefined4 *)(in_stack_00000004 + 0x170) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x184) = 0;
    this_01 = (CINSNavArea *)0x0;
  }
  else {
    iVar4 = *(int *)(iVar2 + 0x19b8);
    iVar5 = ThreadGetCurrentId(iVar6);
    if (iVar4 == iVar5) {
      piVar7 = *(int **)(iVar2 + 0x1014);
      if (*piVar7 != unaff_EBX + 0x298e19 /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */) {
        piVar7 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar7,unaff_EBX + 0x298e19 /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */,(char *)0x0,
                                   unaff_EBX + 0x2905ff /* "NPCs" */ /* "NPCs" */ /* "NPCs" */);
        *(int **)(iVar2 + 0x1014) = piVar7;
      }
      puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar7[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      iVar6 = *(int *)(iVar2 + 0x1014);
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar2 + 0x1010) = 0;
    }
    *(undefined4 *)(in_stack_00000004 + 0x170) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x184) = 0;
    if ((*(char *)(iVar2 + 0x1010) == '\0') ||
       (this_01 = *(CINSNavArea **)(iVar2 + 0x100c), this_01 != (CINSNavArea *)0x0)) {
      iVar4 = *(int *)(iVar2 + 0x19b8);
      iVar6 = ThreadGetCurrentId(iVar6);
      this_01 = extraout_ECX_00;
      if (iVar4 == iVar6) {
        cVar3 = CVProfNode::ExitScope();
        if (cVar3 == '\0') {
          iVar6 = *(int *)(iVar2 + 0x1014);
        }
        else {
          iVar6 = *(int *)(*(int *)(iVar2 + 0x1014) + 100);
          *(int *)(iVar2 + 0x1014) = iVar6;
        }
        *(bool *)(iVar2 + 0x1010) = iVar6 == iVar2 + 0x1018;
        this_01 = extraout_ECX_04;
      }
    }
  }
  *(undefined4 *)(in_stack_00000004 + 0x18c) = 0;
  *(undefined4 *)(in_stack_00000004 + 0x214) = 0;
  if (*(int *)(in_stack_00000004 + 0x204) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x1fc) + 4))
              (in_stack_00000004 + 0x1fc,in_stack_00000004 + 0x204);
    *(undefined4 *)(in_stack_00000004 + 0x204) = 0xbf800000 /* -1.0f */;
    this_01 = extraout_ECX_01;
  }
  *(undefined4 *)(in_stack_00000004 + 0x1a4) = 0xbf800000 /* -1.0f */;
  *(undefined4 *)(in_stack_00000004 + 0x218) = 0;
  if (*(int *)(in_stack_00000004 + 0x210) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x208) + 4))
              (in_stack_00000004 + 0x208,in_stack_00000004 + 0x210);
    *(undefined4 *)(in_stack_00000004 + 0x210) = 0xbf800000 /* -1.0f */;
    this_01 = extraout_ECX_02;
  }
  *(undefined4 *)(in_stack_00000004 + 0x1a8) = 0xbf800000 /* -1.0f */;
  uVar9 = 1;
  CleanupPathingBots(this_01,SUB41(in_stack_00000004,0));
  *(undefined4 *)(in_stack_00000004 + 0x1f8) = 0xbf800000 /* -1.0f */;
  ResetHidingSpotScores(this_02);
  if ((bVar8) && ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) {
    iVar6 = *(int *)(iVar2 + 0x19b8);
    iVar4 = ThreadGetCurrentId(in_stack_00000004,uVar9);
    if (iVar6 == iVar4) {
      cVar3 = CVProfNode::ExitScope();
      iVar6 = *(int *)(iVar2 + 0x1014);
      if (cVar3 != '\0') {
        iVar6 = *(int *)(iVar6 + 100);
        *(int *)(iVar2 + 0x1014) = iVar6;
      }
      *(bool *)(iVar2 + 0x1010) = iVar6 == iVar2 + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::OnRoundRestartPreEntity
 * Address: 006e2ac0
 * ---------------------------------------- */

/* CINSNavArea::OnRoundRestartPreEntity() */

void __thiscall CINSNavArea::OnRoundRestartPreEntity(CINSNavArea *this)

{
  int in_stack_00000004;
  
  *(undefined4 *)(in_stack_00000004 + 600) = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSNavArea::OnServerActivate
 * Address: 006e2ae0
 * ---------------------------------------- */

/* CINSNavArea::OnServerActivate() */

void __thiscall CINSNavArea::OnServerActivate(CINSNavArea *this)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  CNavArea *this_00;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar6 = in_stack_00000004;
  CNavArea::OnServerActivate(this_00);
  iVar2 = *(int *)(unaff_EBX + 0x4c3e86 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  if (*(int *)(iVar2 + 0x100c) == 0) {
    *(undefined4 *)(in_stack_00000004 + 0x170) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x184) = 0;
    return;
  }
  iVar3 = *(int *)(iVar2 + 0x19b8);
  iVar5 = ThreadGetCurrentId(iVar6);
  if (iVar3 == iVar5) {
    piVar7 = *(int **)(iVar2 + 0x1014);
    if (*piVar7 != unaff_EBX + 0x29bd36 /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */) {
      piVar7 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar7,unaff_EBX + 0x29bd36 /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */ /* "CINSNavArea::ClearAllPotentiallyVisibleActors" */,(char *)0x0,
                                 unaff_EBX + 0x29351c /* "NPCs" */ /* "NPCs" */ /* "NPCs" */);
      *(int **)(iVar2 + 0x1014) = piVar7;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar7[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    iVar6 = *(int *)(iVar2 + 0x1014);
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x170) = 0;
  *(undefined4 *)(in_stack_00000004 + 0x184) = 0;
  if ((*(char *)(iVar2 + 0x1010) == '\0') || (*(int *)(iVar2 + 0x100c) != 0)) {
    iVar3 = *(int *)(iVar2 + 0x19b8);
    iVar6 = ThreadGetCurrentId(iVar6);
    if (iVar3 == iVar6) {
      cVar4 = CVProfNode::ExitScope();
      iVar6 = *(int *)(iVar2 + 0x1014);
      if (cVar4 != '\0') {
        iVar6 = *(int *)(iVar6 + 100);
        *(int *)(iVar2 + 0x1014) = iVar6;
      }
      *(bool *)(iVar2 + 0x1010) = iVar6 == iVar2 + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::RemovePathingBot
 * Address: 006e5610
 * ---------------------------------------- */

/* CINSNavArea::RemovePathingBot(CBaseCombatCharacter*) */

undefined4 __thiscall CINSNavArea::RemovePathingBot(CINSNavArea *this,CBaseCombatCharacter *param_1)

{
  CBaseCombatCharacter *pCVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  int iVar5;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 != 0) {
    iVar2 = CBaseEntity::GetTeamNumber(this_00);
    if (iVar2 - 2U < 2) {
      iVar2 = CBaseEntity::GetTeamNumber(this_01);
      uVar3 = iVar2 - 2;
      if (1 < uVar3) {
        uVar3 = 2;
      }
      pCVar1 = param_1 + uVar3 * 0x14 + 0x230;
      if (0 < *(int *)(pCVar1 + 0xc)) {
        iVar2 = *(int *)(pCVar1 + 0xc) + -1;
        iVar5 = iVar2 * 0x10;
        do {
          if ((int *)(*(int *)pCVar1 + iVar5) != (int *)0x0) {
            iVar4 = 0;
            if (*(int *)(in_stack_00000008 + 0x20) != 0) {
              iVar4 = *(int *)(in_stack_00000008 + 0x20) -
                      *(int *)(**(int **)(CNavArea::CalcDebugID + unaff_EBX + 3) + 0x5c) >> 4;
            }
            if (*(int *)(*(int *)pCVar1 + iVar5) == iVar4) {
              CUtlVector<CINSPathingBotInfo,CUtlMemory<CINSPathingBotInfo,int>>::Remove((int)pCVar1)
              ;
              return 1;
            }
          }
          iVar2 = iVar2 + -1;
          iVar5 = iVar5 + -0x10;
          if (iVar2 == -1) {
            return 0;
          }
        } while( true );
      }
    }
  }
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::RemovePathingBot
 * Address: 006e5700
 * ---------------------------------------- */

/* CINSNavArea::RemovePathingBot(int) */

undefined4 __cdecl CINSNavArea::RemovePathingBot(int param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  CINSNavArea *this;
  undefined4 uStack00000008;
  
  iVar1 = __i686_get_pc_thunk_bx();
  piVar2 = (int *)UTIL_PlayerByIndex(iVar1);
  if (piVar2 != (int *)0x0) {
    iVar1 = (**(code **)(*piVar2 + 0x134))(piVar2);
    if (iVar1 != 0) {
      uStack00000008 = (**(code **)(*piVar2 + 0x134))(piVar2);
      uVar3 = RemovePathingBot(this,(CBaseCombatCharacter *)param_1);
      return uVar3;
    }
  }
  return 0;
}



/* ----------------------------------------
 * CINSNavArea::ResetHidingSpotScores
 * Address: 006e2d60
 * ---------------------------------------- */

/* CINSNavArea::ResetHidingSpotScores() */

void __thiscall CINSNavArea::ResetHidingSpotScores(CINSNavArea *this)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int unaff_EBX;
  int iVar6;
  bool bVar7;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  bVar7 = *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if (bVar7) {
    iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      piVar5 = *(int **)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar5 != unaff_EBX + 0x29bae9 /* "CINSNavArea::ResetHidingSpotScores" */ /* "CINSNavArea::ResetHidingSpotScores" */ /* "CINSNavArea::ResetHidingSpotScores" */) {
        piVar5 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar5,unaff_EBX + 0x29bae9 /* "CINSNavArea::ResetHidingSpotScores" */ /* "CINSNavArea::ResetHidingSpotScores" */ /* "CINSNavArea::ResetHidingSpotScores" */,(char *)0x0,
                                   unaff_EBX + 0x29329f /* "NPCs" */ /* "NPCs" */ /* "NPCs" */);
        *(int **)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar5;
      }
      puVar1 = (uint *)(piVar5[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
    }
  }
  piVar5 = *(int **)(in_stack_00000004 + 0xd0);
  iVar6 = 0;
  do {
    iVar4 = 0;
    if (0 < *piVar5) {
      do {
        *(undefined4 *)(piVar5[iVar4 + 1] + (iVar6 + 8) * 4) = 0xbf800000 /* -1.0f */;
        iVar2 = iVar4 * 4;
        iVar4 = iVar4 + 1;
        *(undefined4 *)
         (*(int *)(*(int *)(in_stack_00000004 + 0xd0) + 4 + iVar2) + 8 + (iVar6 + 8) * 4) =
             0xbf800000 /* -1.0f */;
        piVar5 = *(int **)(in_stack_00000004 + 0xd0);
      } while (iVar4 < *piVar5);
    }
    iVar6 = iVar6 + 1;
  } while (iVar6 != 2);
  if ((bVar7) &&
     ((*(char *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)))) {
    iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      cVar3 = CVProfNode::ExitScope();
      iVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (cVar3 != '\0') {
        iVar6 = *(int *)(iVar6 + 100);
        *(int *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar6;
      }
      *(bool *)(*(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
           iVar6 == *(int *)(unaff_EBX + 0x4c3c09 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::ResetINSMarker
 * Address: 006e2cf0
 * ---------------------------------------- */

/* CINSNavArea::ResetINSMarker() */

void CINSNavArea::ResetINSMarker(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)(extraout_ECX + 0x52a4cb /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */ /* CINSNavArea::m_masterINSMark */) = 1;
  return;
}



/* ----------------------------------------
 * CINSNavArea::Save
 * Address: 006e2790
 * ---------------------------------------- */

/* CINSNavArea::Save(CUtlBuffer&, unsigned int) const */

void __cdecl CINSNavArea::Save(CUtlBuffer *param_1,uint param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  CNavArea *this;
  CUtlBuffer *this_00;
  CUtlBuffer *extraout_ECX;
  CUtlBuffer *extraout_ECX_00;
  CUtlBuffer *this_01;
  int unaff_EBX;
  uint *puVar4;
  CUtlBuffer *local_20 [4];
  
  iVar2 = __i686_get_pc_thunk_bx();
  CNavArea::Save(this,param_1,param_2);
  local_20[0] = (CUtlBuffer *)(*(uint *)(param_1 + 0x160) & 0x5ef3);
  if ((*(byte *)(param_2 + 0x15) & 1) == 0) {
    puVar4 = (uint *)0x4;
    cVar1 = CUtlBuffer::CheckPut(this_00,param_2);
    if (cVar1 != '\0') {
      iVar3 = *(int *)(param_2 + 0x10);
      if ((*(byte *)(param_2 + 0x34) & 1) == 0) {
        *(CUtlBuffer **)(*(int *)param_2 + (iVar3 - *(int *)(param_2 + 0x20))) = local_20[0];
        iVar3 = *(int *)(param_2 + 0x10);
        this_01 = local_20[0];
      }
      else {
        this_01 = extraout_ECX;
        if ((iVar3 - *(int *)(param_2 + 0x20)) + *(int *)param_2 != 0) {
          CByteswap::SwapBufferToTargetEndian<unsigned_int>((uint *)local_20,puVar4,iVar2);
          iVar3 = *(int *)(param_2 + 0x10);
          this_01 = extraout_ECX_00;
        }
      }
      *(int *)(param_2 + 0x10) = iVar3 + 4;
      CUtlBuffer::AddNullTermination(this_01,param_2);
    }
    return;
  }
  CUtlBuffer::Printf(this_00,(char *)param_2,unaff_EBX + 0x29aa68 /* "%u" */ /* "%u" */ /* "%u" */,local_20[0]);
  return;
}



/* ----------------------------------------
 * CINSNavArea::ScoreHidingSpot
 * Address: 006e3bc0
 * ---------------------------------------- */

/* CINSNavArea::ScoreHidingSpot(HidingSpot*) */

void __thiscall CINSNavArea::ScoreHidingSpot(CINSNavArea *this,HidingSpot *param_1)

{
  HidingSpot *pHVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  CINSBlockZoneBase *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSRules *this_03;
  int unaff_EBX;
  float10 fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  int in_stack_00000008;
  int local_30;
  float local_2c;
  uint local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  local_28 = 0;
  local_30 = in_stack_00000008;
  do {
    iVar9 = local_28 + 2;
    piVar8 = *(int **)(unaff_EBX + 0x4c2e39 /* &nav_spawn_score_base */ /* &nav_spawn_score_base */ /* &nav_spawn_score_base */);
    iVar7 = *(int *)(param_1 + 0x25c);
    piVar2 = (int *)piVar8[7];
    if (piVar2 == piVar8) {
      local_2c = (float)(piVar8[0xb] ^ (uint)piVar8);
      iVar6 = iVar7;
    }
    else {
      fVar10 = (float10)(**(code **)(*piVar2 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar2);
      local_2c = (float)fVar10;
      iVar6 = *(int *)(param_1 + 0x25c);
    }
    if (((iVar6 != -1) &&
        (iVar3 = **(int **)(unaff_EBX + 0x4c3151 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */ /* &g_pObjectiveResource */), iVar7 < *(int *)(iVar3 + 0x37c))) &&
       (iVar7 = *(int *)(iVar3 + 0x490 + iVar7 * 4), iVar7 - 2U < 2)) {
      if (iVar9 == 2) {
        cVar5 = *(char *)(iVar3 + 0x690 + iVar6);
      }
      else {
        cVar5 = *(char *)(iVar3 + 0x6a0 + iVar6);
      }
      if (cVar5 != '\0') {
        if ((local_28 ^ 1) == 0) {
          cVar5 = *(char *)(iVar3 + 0x690 + iVar6);
        }
        else {
          cVar5 = *(char *)(iVar3 + 0x6a0 + iVar6);
        }
        if (cVar5 != '\0') goto LAB_006e3c49;
      }
      if (iVar7 == iVar9) {
        iVar7 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c2d2d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */) + 0x404))
                          ((int *)**(undefined4 **)(unaff_EBX + 0x4c2d2d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */),iVar9);
        if ((iVar7 != 3) && (cVar5 = CINSRules::IsOutpost(this_03), cVar5 == '\0')) {
          if (*(int *)(**(int **)(unaff_EBX + 0x4c3151 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x6f0 + *(int *)(param_1 + 0x25c) * 4) ==
              0) {
            piVar8 = (int *)(*(int **)(unaff_EBX + 0x4c31cd /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */))[7];
            if (piVar8 != *(int **)(unaff_EBX + 0x4c31cd /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */ /* &nav_spawn_score_cachepoint_bonus */)) goto LAB_006e40a0;
LAB_006e40cc:
            fVar11 = (float)((uint)piVar8 ^ piVar8[0xb]);
          }
          else {
            piVar8 = (int *)(*(int **)(unaff_EBX + 0x4c30ed /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */))[7];
            if (piVar8 == *(int **)(unaff_EBX + 0x4c30ed /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */ /* &nav_spawn_score_controlpoint_bonus */)) goto LAB_006e40cc;
LAB_006e40a0:
            fVar10 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
            fVar11 = (float)fVar10;
          }
          local_2c = fVar11 + local_2c;
        }
      }
      else {
        local_2c = -1.0;
      }
    }
LAB_006e3c49:
    iVar7 = GetAssociatedSpawnZone();
    if ((iVar7 == 0) || (cVar5 = CINSBlockZoneBase::IsActive(this_00), cVar5 == '\0')) {
LAB_006e3de0:
      local_24 = *(float *)(CINSRules::ClientDisconnected + unaff_EBX + 5);
      if ((*(float *)(unaff_EBX + 0x1d4f45 /* -1.0f */ /* -1.0f */ /* -1.0f */) <= local_2c &&
           local_2c != *(float *)(unaff_EBX + 0x1d4f45 /* -1.0f */ /* -1.0f */ /* -1.0f */)) && (((byte)param_1[0x160] & 0x80) != 0)) {
        piVar8 = (int *)(*(int **)(unaff_EBX + 0x4c2edd /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */))[7];
        if (piVar8 == *(int **)(unaff_EBX + 0x4c2edd /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */ /* &nav_spawn_score_inside */)) {
          fVar11 = (float)((uint)piVar8 ^ piVar8[0xb]);
        }
        else {
          fVar10 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
          fVar11 = (float)fVar10;
        }
        local_2c = fVar11 + local_2c;
        local_24 = *(float *)(CINSRules::ClientDisconnected + unaff_EBX + 5);
      }
    }
    else {
      GetAssociatedSpawnZone();
      iVar7 = CBaseEntity::GetTeamNumber(this_01);
      if (iVar7 == iVar9) {
        piVar8 = (int *)(*(int **)(unaff_EBX + 0x4c2f65 /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */))[7];
        if (piVar8 == *(int **)(unaff_EBX + 0x4c2f65 /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */ /* &nav_spawn_score_friendly_spawn_bonus */)) {
          fVar11 = (float)((uint)piVar8 ^ piVar8[0xb]);
        }
        else {
          fVar10 = (float10)(**(code **)(*piVar8 + 0x3c))(piVar8);
          fVar11 = (float)fVar10;
        }
        local_2c = fVar11 + local_2c;
        goto LAB_006e3de0;
      }
      local_2c = -1.0;
      local_24 = -1.0;
    }
    pHVar1 = param_1 + (local_28 ^ 1) * 0x14 + 0x164;
    iVar7 = *(int *)(pHVar1 + 0xc);
    if (iVar7 == 0) {
      if (*(float *)(unaff_EBX + 0x1d4f45 /* -1.0f */ /* -1.0f */ /* -1.0f */) <= local_2c &&
          local_2c != *(float *)(unaff_EBX + 0x1d4f45 /* -1.0f */ /* -1.0f */ /* -1.0f */)) {
        local_2c = local_2c + *(float *)(unaff_EBX + 0x240ba1 /* 5.0f */ /* 5.0f */ /* 5.0f */);
        pHVar1 = param_1 + local_28 * 0x14 + 0x164;
        if (*(int *)(pHVar1 + 0xc) == 0) {
          local_2c = *(float *)(unaff_EBX + 0x240ba1 /* 5.0f */ /* 5.0f */ /* 5.0f */) + local_2c;
        }
        else if (0 < *(int *)(pHVar1 + 0xc)) {
          piVar8 = *(int **)(unaff_EBX + 0x4c2c0d /* &g_pEntityList */ /* &g_pEntityList */ /* &g_pEntityList */);
          iVar7 = 0;
          do {
            uVar4 = *(uint *)(*(int *)pHVar1 + iVar7 * 4);
            if (((uVar4 != 0xffffffff) &&
                (iVar9 = *piVar8 + (uVar4 & 0xffff) * 0x18, *(uint *)(iVar9 + 8) == uVar4 >> 0x10))
               && ((piVar2 = *(int **)(iVar9 + 4), piVar2 != (int *)0x0 &&
                   ((cVar5 = (**(code **)(*piVar2 + 0x118 /* CBaseEntity::IsAlive */))(piVar2), cVar5 != '\0' &&
                    (cVar5 = (**(code **)(*piVar2 + 0x434 /* CBaseCombatCharacter::IsLookingTowards */))(piVar2,in_stack_00000008 + 4,0x3f666666 /* 0.9f */)
                    , cVar5 != '\0')))))) {
              local_2c = -1.0;
              break;
            }
            iVar7 = iVar7 + 1;
          } while (iVar7 < *(int *)(pHVar1 + 0xc));
        }
      }
    }
    else {
      local_24 = local_24 - (float)iVar7;
      if (0 < iVar7) {
        piVar8 = *(int **)(unaff_EBX + 0x4c2c0d /* &g_pEntityList */ /* &g_pEntityList */ /* &g_pEntityList */);
        iVar7 = 0;
        do {
          uVar4 = *(uint *)(*(int *)pHVar1 + iVar7 * 4);
          if ((((uVar4 != 0xffffffff) &&
               (iVar9 = *piVar8 + (uVar4 & 0xffff) * 0x18, *(uint *)(iVar9 + 8) == uVar4 >> 0x10))
              && (piVar2 = *(int **)(iVar9 + 4), piVar2 != (int *)0x0)) &&
             (cVar5 = (**(code **)(*piVar2 + 0x118 /* CBaseEntity::IsAlive */))(piVar2), cVar5 != '\0')) {
            cVar5 = (**(code **)(*piVar2 + 0x434 /* CBaseCombatCharacter::IsLookingTowards */))(piVar2,in_stack_00000008 + 4,0x3f666666 /* 0.9f */);
            if (cVar5 != '\0') {
              local_24 = local_24 - *(float *)(unaff_EBX + 0x1d4f49 /* 1.0f */ /* 1.0f */ /* 1.0f */);
            }
            if ((*(byte *)((int)piVar2 + 0xd1) & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_02);
            }
            fVar13 = *(float *)(in_stack_00000008 + 4) - (float)piVar2[0x82];
            fVar11 = *(float *)(in_stack_00000008 + 8) - (float)piVar2[0x83];
            fVar12 = *(float *)(in_stack_00000008 + 0xc) - (float)piVar2[0x84];
            if (SQRT(fVar11 * fVar11 + fVar13 * fVar13 + fVar12 * fVar12) <
                *(float *)(unaff_EBX + 0x243215 /* 250.0f */ /* 250.0f */ /* 250.0f */)) {
              local_24 = local_24 - *(float *)(unaff_EBX + 0x1d4f49 /* 1.0f */ /* 1.0f */ /* 1.0f */);
            }
          }
          iVar7 = iVar7 + 1;
        } while (iVar7 < *(int *)(pHVar1 + 0xc));
      }
      local_2c = -1.0;
      if (local_24 <= *(float *)(unaff_EBX + 0x1d4f3d /* 0.0f */ /* 0.0f */ /* 0.0f */)) {
        local_24 = *(float *)(unaff_EBX + 0x1d4f3d /* 0.0f */ /* 0.0f */ /* 0.0f */);
      }
    }
    local_28 = local_28 + 1;
    *(float *)(local_30 + 0x20) = local_24;
    *(float *)(local_30 + 0x28) = local_2c;
    local_30 = local_30 + 4;
    if (local_28 == 2) {
      return;
    }
  } while( true );
}



/* ----------------------------------------
 * CINSNavArea::UpdateCover
 * Address: 006e40e0
 * ---------------------------------------- */

/* CINSNavArea::UpdateCover(float*) */

void __thiscall CINSNavArea::UpdateCover(CINSNavArea *this,float *param_1)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  CINSNavArea *extraout_ECX;
  CINSNavArea *extraout_ECX_00;
  CINSNavArea *extraout_ECX_01;
  CINSNavArea *this_00;
  CINSNavArea *extraout_ECX_02;
  int unaff_EBX;
  int iVar5;
  bool bVar6;
  float10 fVar7;
  float10 fVar8;
  float fVar9;
  float *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  bVar6 = *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bVar6) &&
     (iVar5 = *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar3 = ThreadGetCurrentId(),
     iVar5 == iVar3)) {
    piVar4 = *(int **)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar4 != unaff_EBX + 0x29a528 /* "CINSNavArea::UpdateCover" */ /* "CINSNavArea::UpdateCover" */ /* "CINSNavArea::UpdateCover" */) {
      piVar4 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar4,unaff_EBX + 0x29a528 /* "CINSNavArea::UpdateCover" */ /* "CINSNavArea::UpdateCover" */ /* "CINSNavArea::UpdateCover" */,(char *)0x0,
                                 unaff_EBX + 0x29a51d /* "INSNavMesh" */ /* "INSNavMesh" */ /* "INSNavMesh" */);
      *(int **)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar4;
    }
    puVar1 = (uint *)(piVar4[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  if (in_stack_00000008 == (float *)0x0) {
    fVar7 = (float10)CountdownTimer::Now();
    if ((float)fVar7 < param_1[0x7d] || (float)fVar7 == param_1[0x7d]) goto LAB_006e4220;
  }
  else if (*(float *)(**(int **)(CNavArea::GetClosestPointOnArea + unaff_EBX + 5) + 0xc) -
           param_1[0x7e] < *in_stack_00000008) goto LAB_006e4220;
  fVar7 = (float10)RandomFloat(0xbf800000 /* -1.0f */,0x3f800000 /* 1.0f */);
  fVar8 = (float10)CountdownTimer::Now();
  fVar9 = (float)fVar7 + *(float *)(unaff_EBX + 0x240681 /* 5.0f */ /* 5.0f */ /* 5.0f */);
  this_00 = extraout_ECX;
  if (param_1[0x7d] != (float)fVar8 + fVar9) {
    (**(code **)((int)param_1[0x7b] + 4))(param_1 + 0x7b,param_1 + 0x7d);
    param_1[0x7d] = (float)fVar8 + fVar9; /* timer_0.Start(5.0f) */
    this_00 = extraout_ECX_00;
  }
  if (param_1[0x7c] != fVar9) {
    (**(code **)((int)param_1[0x7b] + 4))(param_1 + 0x7b,param_1 + 0x7c);
    param_1[0x7c] = fVar9; /* timer_0.m_duration */
    this_00 = extraout_ECX_01;
  }
  iVar5 = **(int **)(CNavArea::GetClosestPointOnArea + unaff_EBX + 5);
  param_1[0x7e] = *(float *)(iVar5 + 0xc);
  iVar5 = *(int *)(iVar5 + 0x18);
  if (((int)param_1[0x12] < iVar5) && ((int)param_1[0x8b] < iVar5)) {
    if (0 < *(int *)param_1[0x34]) {
      iVar5 = 0;
      do {
        ScoreHidingSpot(this_00,(HidingSpot *)param_1);
        iVar5 = iVar5 + 1;
        this_00 = extraout_ECX_02;
      } while (iVar5 < *(int *)param_1[0x34]);
    }
  }
  else {
    ResetHidingSpotScores(this_00);
  }
LAB_006e4220:
  if ((bVar6) &&
     (((*(char *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
       (*(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
      (iVar5 = *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar3 = ThreadGetCurrentId(),
      iVar5 == iVar3)))) {
    cVar2 = CVProfNode::ExitScope();
    if (cVar2 == '\0') {
      iVar5 = *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar5 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar5;
    }
    *(bool *)(*(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
         iVar5 == *(int *)(unaff_EBX + 0x4c2889 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSNavArea::~CINSNavArea
 * Address: 006e6830
 * ---------------------------------------- */

/* CINSNavArea::~CINSNavArea() */

void __thiscall CINSNavArea::~CINSNavArea(CINSNavArea *this)

{
  int iVar1;
  CUtlMemory<CINSPathingBotInfo,int> *extraout_ECX;
  CUtlMemory<CINSPathingBotInfo,int> *extraout_ECX_00;
  CUtlMemory<CINSPathingBotInfo,int> *extraout_ECX_01;
  CUtlMemory<CINSPathingBotInfo,int> *extraout_ECX_02;
  CUtlMemory<CINSPathingBotInfo,int> *pCVar2;
  CNavArea *this_00;
  int unaff_EBX;
  int *piVar3;
  int *piVar4;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar3 = in_stack_00000004 + 0x96;
  *in_stack_00000004 = unaff_EBX + 0x4ad98d /* vtable for CINSNavArea+0x8 */ /* vtable for CINSNavArea+0x8 */ /* vtable for CINSNavArea+0x8 */;
  piVar4 = in_stack_00000004 + 0x91;
  pCVar2 = extraout_ECX;
  do {
    piVar3[-2] = 0;
    iVar1 = *piVar4;
    if (-1 < piVar3[-3]) {
      if (iVar1 != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c003d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4c003d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar1);
        *piVar4 = 0;
        pCVar2 = extraout_ECX_00;
      }
      piVar4[1] = 0;
      iVar1 = 0;
    }
    piVar3[-1] = iVar1;
    piVar3 = piVar3 + -5;
    CUtlMemory<CINSPathingBotInfo,int>::~CUtlMemory(pCVar2);
    piVar4 = piVar4 + -5;
    pCVar2 = extraout_ECX_01;
  } while (in_stack_00000004 + 0x8c != piVar3);
  piVar3 = in_stack_00000004 + 99;
  piVar4 = in_stack_00000004 + 0x5e;
  do {
    piVar3[-2] = 0;
    iVar1 = *piVar4;
    if (-1 < piVar3[-3]) {
      if (iVar1 != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4c003d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4c003d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar1);
        *piVar4 = 0;
        pCVar2 = extraout_ECX_02;
      }
      piVar4[1] = 0;
      iVar1 = 0;
    }
    piVar3[-1] = iVar1;
    piVar3 = piVar3 + -5;
    CUtlMemory<CHandle<CBaseCombatCharacter>,int>::~CUtlMemory
              ((CUtlMemory<CHandle<CBaseCombatCharacter>,int> *)pCVar2);
    piVar4 = piVar4 + -5;
    pCVar2 = (CUtlMemory<CINSPathingBotInfo,int> *)this_00;
  } while (in_stack_00000004 + 0x59 != piVar3);
  CNavArea::~CNavArea(this_00);
  return;
}



/* ----------------------------------------
 * CINSNavArea::~CINSNavArea
 * Address: 006e69a0
 * ---------------------------------------- */

/* CINSNavArea::~CINSNavArea() */

void __thiscall CINSNavArea::~CINSNavArea(CINSNavArea *this)

{
  CINSNavArea *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSNavArea(this_00);
  operator_delete(in_stack_00000004);
  return;
}



