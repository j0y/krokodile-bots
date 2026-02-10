/*
 * CINSBotVision -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 29
 */

/* ----------------------------------------
 * CINSBotVision::CINSBotVision
 * Address: 0076b550
 * ---------------------------------------- */

/* CINSBotVision::CINSBotVision(INextBot*) */

void __thiscall CINSBotVision::CINSBotVision(CINSBotVision *this,INextBot *param_1)

{
  code *pcVar1;
  bool bVar2;
  uint uVar3;
  IVision *this_00;
  uint uVar4;
  INextBot *pIVar5;
  uint uVar6;
  int iVar7;
  int unaff_EBX;
  uint uVar8;
  int local_20;
  
  __i686_get_pc_thunk_bx();
  iVar7 = unaff_EBX + 0x3bcc5d /* vtable for CountdownTimer+0x8 */;
  IVision::IVision(this_00,param_1);
  *(undefined4 *)(param_1 + 0x144) = 0;
  *(int *)param_1 = unaff_EBX + 0x431dad /* vtable for CINSBotVision+0x8 */;
  *(undefined4 *)(param_1 + 0x148) = 0;
  pcVar1 = (code *)(unaff_EBX + -0x53adeb /* CountdownTimer::NetworkStateChanged */);
  *(undefined4 *)(param_1 + 0x14c) = 0;
  *(undefined4 *)(param_1 + 0x150) = 0;
  *(undefined4 *)(param_1 + 0x154) = 0;
  *(int *)(param_1 + 0x158) = iVar7;
  *(undefined4 *)(param_1 + 0x15c) = 0;
  (*pcVar1)(param_1 + 0x158,param_1 + 0x15c);
  *(undefined4 *)(param_1 + 0x160) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x158) + 4))(param_1 + 0x158,param_1 + 0x160);
  *(int *)(param_1 + 0x164) = iVar7;
  *(undefined4 *)(param_1 + 0x168) = 0;
  (*pcVar1)(param_1 + 0x164,param_1 + 0x168);
  *(undefined4 *)(param_1 + 0x16c) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x164) + 4))(param_1 + 0x164,param_1 + 0x16c);
  *(int *)(param_1 + 0x170) = iVar7;
  *(undefined4 *)(param_1 + 0x174) = 0;
  (*pcVar1)(param_1 + 0x170,param_1 + 0x174);
  *(undefined4 *)(param_1 + 0x178) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x170) + 4))(param_1 + 0x170,param_1 + 0x178);
  *(int *)(param_1 + 0x17c) = iVar7;
  *(undefined4 *)(param_1 + 0x180) = 0;
  (*pcVar1)(param_1 + 0x17c,param_1 + 0x180);
  *(undefined4 *)(param_1 + 0x184) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x17c) + 4))(param_1 + 0x17c,param_1 + 0x184);
  *(int *)(param_1 + 0x188) = iVar7;
  *(undefined4 *)(param_1 + 0x18c) = 0;
  (*pcVar1)(param_1 + 0x188,param_1 + 0x18c);
  *(undefined4 *)(param_1 + 400) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x188) + 4))(param_1 + 0x188,param_1 + 400);
  *(int *)(param_1 + 0x25c) = iVar7;
  *(undefined4 *)(param_1 + 0x260) = 0;
  (*pcVar1)(param_1 + 0x25c,param_1 + 0x260);
  *(undefined4 *)(param_1 + 0x264) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x25c) + 4))(param_1 + 0x25c,param_1 + 0x264);
  *(undefined4 *)(param_1 + 0x268) = 0xffffffff;
  *(undefined4 *)(param_1 + 0x26c) = 0xffffffff;
  *(undefined4 *)(param_1 + 600) = 0;
  uVar4 = -(((uint)(param_1 + 0x198) & 0xf) >> 2) & 3;
  if (uVar4 == 0) {
    local_20 = 0x30;
    uVar3 = 1;
  }
  else {
    uVar8 = 1;
    do {
      *(undefined4 *)(param_1 + uVar8 * 4 + 0x194) = 0xffffffff;
      uVar3 = uVar8 + 1;
      local_20 = 0x31 - uVar3;
      bVar2 = uVar8 < uVar4;
      uVar8 = uVar3;
    } while (bVar2);
  }
  uVar8 = 0x30 - uVar4 >> 2;
  if (uVar8 != 0) {
    pIVar5 = param_1 + uVar4 * 4 + 0x198;
    uVar6 = 0;
    do {
      uVar6 = uVar6 + 1;
      *(undefined4 *)pIVar5 = 0xffffffff;
      *(undefined4 *)(pIVar5 + 4) = 0xffffffff;
      *(undefined4 *)(pIVar5 + 8) = 0xffffffff;
      *(undefined4 *)(pIVar5 + 0xc) = 0xffffffff;
      pIVar5 = pIVar5 + 0x10;
    } while (uVar6 < uVar8);
    uVar3 = uVar3 + uVar8 * 4;
    local_20 = local_20 + uVar8 * -4;
    if (0x30 - uVar4 == uVar8 * 4) {
      return;
    }
  }
  iVar7 = 0;
  do {
    *(undefined4 *)(param_1 + iVar7 + uVar3 * 4 + 0x194) = 0xffffffff;
    iVar7 = iVar7 + 4;
  } while (iVar7 != local_20 << 2);
  return;
}



/* ----------------------------------------
 * CINSBotVision::Update
 * Address: 0076adb0
 * ---------------------------------------- */

/* CINSBotVision::Update() */

void __thiscall CINSBotVision::Update(CINSBotVision *this)

{
  code cVar1;
  uint uVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int *piVar8;
  int iVar9;
  code *pcVar10;
  IVision *this_00;
  CBaseEntity *this_01;
  CFmtStrN<256,false> *this_02;
  CBaseEntity *this_03;
  CINSBotVision *this_04;
  code *pcVar11;
  char *pcVar12;
  int unaff_EBX;
  int iVar13;
  float10 fVar14;
  float fVar15;
  CINSBotVision *in_stack_00000004;
  char *local_264;
  CFmtStrN<256,false> local_25c [5];
  undefined1 local_257 [255];
  undefined1 local_158 [4];
  int local_154;
  char local_14c [5];
  char local_147 [263];
  undefined4 local_40;
  undefined4 local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x76adbb;
  __i686_get_pc_thunk_bx();
  IVision::Update(this_00);
  piVar8 = *(int **)(unaff_EBX + 0x43ba1d /* &g_pEntityList */);
  uVar2 = *(uint *)(in_stack_00000004 + 0x26c);
  if ((((uVar2 == 0xffffffff) ||
       (iVar5 = *piVar8 + (uVar2 & 0xffff) * 0x18, *(uint *)(iVar5 + 8) != uVar2 >> 0x10)) ||
      (*(int *)(iVar5 + 4) == 0)) &&
     (((uVar2 = *(uint *)(in_stack_00000004 + 0x268), uVar2 == 0xffffffff ||
       (iVar5 = *piVar8 + (uVar2 & 0xffff) * 0x18, *(uint *)(iVar5 + 8) != uVar2 >> 0x10)) ||
      (*(int *)(iVar5 + 4) == 0)))) {
    pcVar11 = *(code **)(*(int *)in_stack_00000004 + 0xdc);
    piVar4 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
    (**(code **)(*piVar4 + 200))(piVar4);
    iVar5 = CBaseEntity::GetTeamNumber(this_03);
    iVar5 = (*pcVar11)(in_stack_00000004,(iVar5 == 2) + '\x02',0,0xbf800000);
    if ((float)iVar5 < *(float *)(unaff_EBX + 0x14dd4d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) ||
        (float)iVar5 == *(float *)(unaff_EBX + 0x14dd4d /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) goto LAB_0076ae0c;
LAB_0076ae3b:
    CalculatePrimaryThreat(in_stack_00000004);
    fVar14 = (float10)CountdownTimer::Now();
    fVar15 = (float)fVar14 + *(float *)(unaff_EBX + 0x1b8cd1 /* typeinfo name for ISaveRestoreOps+0x67 */);
    if (*(float *)(in_stack_00000004 + 0x264) != fVar15) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x25c) + 4))
                (in_stack_00000004 + 0x25c,in_stack_00000004 + 0x264);
      *(float *)(in_stack_00000004 + 0x264) = fVar15;
    }
    if (*(int *)(in_stack_00000004 + 0x260) != 0x3e800000) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x25c) + 4))
                (in_stack_00000004 + 0x25c,in_stack_00000004 + 0x260);
      *(undefined4 *)(in_stack_00000004 + 0x260) = 0x3e800000;
    }
  }
  else {
LAB_0076ae0c:
    fVar14 = (float10)CountdownTimer::Now();
    if (*(float *)(in_stack_00000004 + 0x264) <= (float)fVar14 &&
        (float)fVar14 != *(float *)(in_stack_00000004 + 0x264)) goto LAB_0076ae3b;
  }
  piVar4 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
  cVar3 = (**(code **)(*piVar4 + 0x140 /* CBaseEntity::IsMoving */))(piVar4,0x200);
  if (cVar3 != '\0') {
    uVar2 = *(uint *)(in_stack_00000004 + 0x26c);
    if (((uVar2 != 0xffffffff) &&
        (iVar5 = *piVar8 + (uVar2 & 0xffff) * 0x18, *(uint *)(iVar5 + 8) == uVar2 >> 0x10)) &&
       (*(int *)(iVar5 + 4) != 0)) {
      (**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
      pcVar11 = *(code **)(*(int *)in_stack_00000004 + 0xdc);
      iVar5 = CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_00000004);
      uVar6 = (*pcVar11)(in_stack_00000004,(iVar5 == 2) + '\x02',0,0xbf800000);
      uVar2 = *(uint *)(in_stack_00000004 + 0x26c);
      fVar15 = *(float *)(in_stack_00000004 + 0x274);
      iVar5 = 0;
      if ((uVar2 != 0xffffffff) &&
         (iVar13 = *piVar8 + (uVar2 & 0xffff) * 0x18, *(uint *)(iVar13 + 8) == uVar2 >> 0x10)) {
        iVar5 = *(int *)(iVar13 + 4);
      }
      this_01 = *(CBaseEntity **)(iVar5 + 0x20);
      iVar5 = 0;
      if (this_01 != (CBaseEntity *)0x0) {
        this_01 = this_01 + -*(int *)(**(int **)(&DAT_0043bae5 + unaff_EBX) + 0x5c);
        iVar5 = (int)this_01 >> 4;
      }
      if (uVar2 != 0xffffffff) {
        this_01 = (CBaseEntity *)((uVar2 & 0xffff) * 3);
      }
      uVar7 = CBaseEntity::GetDebugName(this_01);
      CFmtStrN<256,false>::CFmtStrN
                (this_02,local_14c,unaff_EBX + 0x21c38d /* "threat chosen:%s - %i, score: %3.2f , count: %i" */,uVar7,iVar5,(double)fVar15,uVar6);
      piVar8 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
      piVar8 = (int *)(**(code **)(*piVar8 + 200))(piVar8);
      (**(code **)(*piVar8 + 0x20c /* CINSNextBot::EyePosition */))(&local_40,piVar8);
      local_2c = local_38 - *(float *)(unaff_EBX + 0x1bd579 /* typeinfo name for IPartitionEnumerator+0x21 */);
      local_34 = local_40;
      local_30 = local_3c;
      NDebugOverlay::Text((Vector *)&local_34,local_147,true,0.1);
    }
  }
  iVar5 = (**(code **)(*(int *)(unaff_EBX + 0x5876c5 /* ins_bot_debug_silhouette */) + 0x40))(unaff_EBX + 0x5876c5 /* ins_bot_debug_silhouette */);
  if (iVar5 != 0) {
    piVar8 = *(int **)(&DAT_0043bae5 + unaff_EBX);
    if (*(int *)(*piVar8 + 0x14) < 2) {
      piVar4 = (int *)UTIL_GetLocalPlayer();
    }
    else {
      cVar3 = (**(code **)(*(int *)**(undefined4 **)(&DAT_0043b86d + unaff_EBX) + 8))
                        ((int *)**(undefined4 **)(&DAT_0043b86d + unaff_EBX));
      if (cVar3 != '\0') goto LAB_0076b0f8;
      piVar4 = (int *)UTIL_GetListenServerHost();
    }
    if (((piVar4 != (int *)0x0) && (iVar5 = (**(code **)(*piVar4 + 0x678 /* CBasePlayer::GetObserverMode */))(piVar4), iVar5 - 4U < 2))
       && (iVar5 = (**(code **)(*piVar4 + 0x684 /* CBasePlayer::GetObserverTarget */))(piVar4), iVar5 != 0)) {
      iVar13 = 0;
      if (*(int *)(iVar5 + 0x20) != 0) {
        iVar13 = *(int *)(iVar5 + 0x20) - *(int *)(*piVar8 + 0x5c) >> 4;
      }
      piVar4 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
      iVar5 = (**(code **)(*piVar4 + 200))(piVar4);
      iVar9 = 0;
      if (*(int *)(iVar5 + 0x20) != 0) {
        iVar9 = *(int *)(iVar5 + 0x20) - *(int *)(*piVar8 + 0x5c) >> 4;
      }
      if (iVar13 == iVar9) {
        iVar5 = 1;
        do {
          piVar8 = (int *)UTIL_PlayerByIndex(iVar5);
          if (((piVar8 != (int *)0x0) &&
              (cVar3 = (**(code **)(*piVar8 + 0x118 /* CBaseEntity::IsAlive */))(piVar8), cVar3 != '\0')) &&
             (iVar13 = (**(code **)(*(int *)in_stack_00000004 + 0xe4))(in_stack_00000004,piVar8),
             iVar13 != 0)) {
            CFmtStrN<256,false>::CFmtStrN(local_25c,(char *)local_25c,unaff_EBX + 0x21c218 /* "Sil:" */);
            cVar3 = CanReadSilhouette(this_04,(CKnownEntity *)in_stack_00000004);
            if (cVar3 != '\0') {
              pcVar12 = (char *)(unaff_EBX + 0x21c1f3 /* " Readable -" */);
              local_264 = local_257 + local_154;
              if (local_264 < local_158) {
                do {
                  cVar3 = *pcVar12;
                  pcVar12 = pcVar12 + 1;
                  *local_264 = cVar3;
                  local_264 = local_264 + 1;
                  if (local_264 == local_158) break;
                } while (*pcVar12 != '\0');
              }
              *local_264 = '\0';
              local_154 = (int)local_264 - (int)local_257;
            }
            local_264 = local_257;
            iVar13 = *(int *)(in_stack_00000004 + iVar5 * 4 + 0x194);
            if (iVar13 == 0) {
              pcVar11 = CBaseGameStats_Driver::~CBaseGameStats_Driver + unaff_EBX + 4;
              pcVar10 = (code *)(local_257 + local_154);
              if (pcVar10 < local_158) {
                do {
                  cVar1 = *pcVar11;
                  pcVar11 = pcVar11 + 1;
                  *pcVar10 = cVar1;
                  pcVar10 = pcVar10 + 1;
                  if (pcVar10 == (code *)local_158) break;
                } while (*pcVar11 != (code)0x0);
              }
LAB_0076b290:
              *pcVar10 = (code)0x0;
              local_154 = (int)pcVar10 - (int)local_264;
            }
            else {
              if (0 < iVar13) {
                if (iVar13 == 1) {
                  pcVar11 = (code *)(unaff_EBX + 0x21c20a /* " Fuzzy" */);
                  pcVar10 = (code *)(local_257 + local_154);
                  if (pcVar10 < local_158) {
                    do {
                      cVar1 = *pcVar11;
                      pcVar11 = pcVar11 + 1;
                      *pcVar10 = cVar1;
                      pcVar10 = pcVar10 + 1;
                      if (pcVar10 == (code *)local_158) break;
                    } while (*pcVar11 != (code)0x0);
                  }
                }
                else {
                  if (iVar13 != 2) goto LAB_0076b29f;
                  pcVar11 = (code *)(unaff_EBX + 0x21c211 /* " Clear" */);
                  pcVar10 = (code *)(local_257 + local_154);
                  if (pcVar10 < local_158) {
                    do {
                      cVar1 = *pcVar11;
                      pcVar11 = pcVar11 + 1;
                      *pcVar10 = cVar1;
                      pcVar10 = pcVar10 + 1;
                      if (pcVar10 == (code *)local_158) break;
                    } while (*pcVar11 != (code)0x0);
                  }
                }
                goto LAB_0076b290;
              }
              if (iVar13 == -1) {
                pcVar11 = (code *)(&DAT_0021c1ff + unaff_EBX);
                pcVar10 = (code *)(local_257 + local_154);
                if (pcVar10 < local_158) {
                  do {
                    cVar1 = *pcVar11;
                    pcVar11 = pcVar11 + 1;
                    *pcVar10 = cVar1;
                    pcVar10 = pcVar10 + 1;
                    if (pcVar10 == (code *)local_158) break;
                  } while (*pcVar11 != (code)0x0);
                }
                goto LAB_0076b290;
              }
            }
LAB_0076b29f:
            (**(code **)(*piVar8 + 0x20c /* CINSNextBot::EyePosition */))(local_28,piVar8);
            NDebugOverlay::Text(local_28,local_264,false,0.11);
          }
          iVar5 = iVar5 + 1;
        } while (iVar5 != 0x31);
      }
    }
  }
LAB_0076b0f8:
  UpdateSilhouettes(in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSBotVision::CalculatePrimaryThreat
 * Address: 0076aad0
 * ---------------------------------------- */

/* CINSBotVision::CalculatePrimaryThreat() */

void __thiscall CINSBotVision::CalculatePrimaryThreat(CINSBotVision *this)

{
  float fVar1;
  IVision *this_00;
  uint uVar2;
  char cVar3;
  char *pcVar4;
  int *piVar5;
  undefined4 *puVar6;
  CINSBotVision *extraout_ECX;
  CINSBotVision *extraout_ECX_00;
  CINSBotVision *this_01;
  int unaff_EBX;
  int iVar7;
  float10 fVar8;
  INSBotThreatAssessment *in_stack_00000004;
  undefined4 uVar9;
  int local_50;
  int local_4c;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  undefined4 local_30;
  int local_2c;
  int local_28;
  undefined4 local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x76aadb;
  __i686_get_pc_thunk_bx();
  local_38 = (**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
  if ((local_38 != 0) && (local_38 = local_38 + -0x2060, local_38 != 0)) {
    local_34 = 0;
    local_30 = 0;
    local_2c = 0;
    local_28 = 0;
    local_24 = 0;
    local_3c = unaff_EBX + 0x4329fd /* vtable for CINSThreatAssessment+0x8 */;
    cVar3 = (**(code **)(*(int *)in_stack_00000004 + 200))(in_stack_00000004,&local_3c);
    if ((cVar3 != '\0') && (0 < local_28)) {
      *(undefined4 *)(in_stack_00000004 + 0x274) = 0;
      *(undefined4 *)(in_stack_00000004 + 0x27c) = 0;
      *(undefined4 *)(in_stack_00000004 + 0x278) = 0;
      local_40 = 0;
      local_50 = 0;
      local_4c = 0;
      iVar7 = 0;
      this_01 = extraout_ECX;
      do {
        if (iVar7 < local_28) {
          pcVar4 = (char *)(local_40 + local_34);
          fVar8 = (float10)GetAssessmentScore(this_01,in_stack_00000004,(int)pcVar4);
          fVar1 = (float)fVar8;
          *(float *)(in_stack_00000004 + 0x278) = *(float *)(in_stack_00000004 + 0x278) + fVar1;
          if (*(float *)(in_stack_00000004 + 0x274) <= fVar1 &&
              fVar1 != *(float *)(in_stack_00000004 + 0x274)) {
            *(float *)(in_stack_00000004 + 0x274) = fVar1;
            local_4c = iVar7;
          }
          this_01 = extraout_ECX_00;
          if ((*pcVar4 != '\0') &&
             (*(float *)(in_stack_00000004 + 0x27c) <= fVar1 &&
              fVar1 != *(float *)(in_stack_00000004 + 0x27c))) {
            *(float *)(in_stack_00000004 + 0x27c) = fVar1;
            local_50 = iVar7;
          }
        }
        iVar7 = iVar7 + 1;
        local_40 = local_40 + 0x1c;
      } while (iVar7 <= local_28);
      if ((-1 < local_4c) && (local_4c < local_28)) {
        piVar5 = (int *)UTIL_PlayerByIndex(*(int *)(local_4c * 0x1c + local_34 + 0x18));
        if (piVar5 == (int *)0x0) {
          *(undefined4 *)(in_stack_00000004 + 0x26c) = 0xffffffff;
        }
        else {
          puVar6 = (undefined4 *)(**(code **)(*piVar5 + 0xc))(piVar5);
          *(undefined4 *)(in_stack_00000004 + 0x26c) = *puVar6;
        }
      }
      if ((-1 < local_50) && (local_50 < local_28)) {
        piVar5 = (int *)UTIL_PlayerByIndex(*(int *)(local_50 * 0x1c + local_34 + 0x18));
        if (piVar5 == (int *)0x0) {
          *(undefined4 *)(in_stack_00000004 + 0x268) = 0xffffffff;
        }
        else {
          puVar6 = (undefined4 *)(**(code **)(*piVar5 + 0xc))(piVar5);
          *(undefined4 *)(in_stack_00000004 + 0x268) = *puVar6;
        }
      }
      *(float *)(in_stack_00000004 + 0x270) =
           *(float *)(unaff_EBX + 0x1bc2d5 /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x30 */) + *(float *)(**(int **)(unaff_EBX + 0x43bdc5 /* &gpGlobals */) + 0xc);
    }
    this_00 = (IVision *)**(undefined4 **)(unaff_EBX + 0x43bcfd /* &g_pEntityList */);
    uVar2 = *(uint *)(in_stack_00000004 + 0x26c);
    if (((uVar2 == 0xffffffff) ||
        (*(uint *)(this_00 + (uVar2 & 0xffff) * 0x18 + 8) != uVar2 >> 0x10)) ||
       (*(int *)(this_00 + (uVar2 & 0xffff) * 0x18 + 4) == 0)) {
      uVar9 = 0;
      piVar5 = (int *)IVision::GetPrimaryKnownThreat(this_00,SUB41(in_stack_00000004,0));
      if (piVar5 != (int *)0x0) {
        piVar5 = (int *)(**(code **)(*piVar5 + 0x10))(piVar5,uVar9);
        if (piVar5 == (int *)0x0) {
          *(undefined4 *)(in_stack_00000004 + 0x26c) = 0xffffffff;
        }
        else {
          puVar6 = (undefined4 *)(**(code **)(*piVar5 + 0xc))(piVar5);
          *(undefined4 *)(in_stack_00000004 + 0x26c) = *puVar6;
        }
      }
    }
    local_28 = 0;
    if ((-1 < local_2c) && (local_34 != 0)) {
      local_3c = unaff_EBX + 0x4329fd /* vtable for CINSThreatAssessment+0x8 */;
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x43bd9d /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x43bd9d /* &GCSDK::GetPchTempTextBuffer */),local_34);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotVision::CanReadSilhouette
 * Address: 007691f0
 * ---------------------------------------- */

/* CINSBotVision::CanReadSilhouette(CKnownEntity const*) const */

bool __thiscall CINSBotVision::CanReadSilhouette(CINSBotVision *this,CKnownEntity *param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSRules *this_02;
  int unaff_EBX;
  float10 fVar5;
  float10 extraout_ST0;
  int *in_stack_00000008;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  iVar2 = TheINSNextBots();
  if (*(char *)(iVar2 + 0x129) == '\0') {
    return true;
  }
  if (in_stack_00000008 == (int *)0x0) {
    return false;
  }
  cVar1 = (**(code **)(*in_stack_00000008 + 0x54))(in_stack_00000008);
  if (cVar1 != '\0') {
    return false;
  }
  iVar2 = (**(code **)(*in_stack_00000008 + 0x10))(in_stack_00000008);
  if (iVar2 == 0) {
    return false;
  }
  iVar2 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
  if (iVar2 == 0) {
    return false;
  }
  cVar1 = CINSRules::IsSoloMode();
  if (cVar1 != '\0') {
    piVar3 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    (**(code **)(*piVar3 + 200))(piVar3);
    iVar2 = CBaseEntity::GetTeamNumber(this_01);
    iVar4 = CINSRules::GetHumanTeam(this_02);
    if (iVar2 == iVar4) {
      return true;
    }
  }
  iVar2 = (**(code **)(*in_stack_00000008 + 0x10))(in_stack_00000008);
  if (*(int *)(iVar2 + 0x20) == 0) {
    return false;
  }
  iVar2 = *(int *)(iVar2 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x43d6a2 /* &gpGlobals */) + 0x5c) >> 4;
  if (0x2f < iVar2 - 1U) {
    return false;
  }
  iVar2 = iVar2 + 100;
  iVar4 = *(int *)(param_1 + iVar2 * 4 + 4);
  if (iVar4 == -1) {
    return false;
  }
  piVar3 = (int *)(*(int **)(unaff_EBX + 0x43dc9a /* &bot_silhouette_readtime_clear */))[7];
  if (piVar3 == *(int **)(unaff_EBX + 0x43dc9a /* &bot_silhouette_readtime_clear */)) {
    local_24 = (float)((uint)piVar3 ^ piVar3[0xb]);
  }
  else {
    fVar5 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
    local_24 = (float)fVar5;
    iVar4 = *(int *)(param_1 + iVar2 * 4 + 4);
  }
  if (iVar4 == 0) {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x43d4f2 /* &bot_silhouette_readtime_dark */))[7];
    if (piVar3 != *(int **)(unaff_EBX + 0x43d4f2 /* &bot_silhouette_readtime_dark */)) {
      fVar5 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      local_24 = (float)fVar5;
      iVar4 = *(int *)(param_1 + iVar2 * 4 + 4);
      goto LAB_007692e9;
    }
  }
  else {
LAB_007692e9:
    if (iVar4 != 1) goto LAB_007692f2;
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x43dc5e /* &bot_silhouette_readtime_fuzzy */))[7];
    if (piVar3 != *(int **)(unaff_EBX + 0x43dc5e /* &bot_silhouette_readtime_fuzzy */)) {
      fVar5 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      local_24 = (float)fVar5;
      goto LAB_007692f2;
    }
  }
  local_24 = (float)((uint)piVar3 ^ piVar3[0xb]);
LAB_007692f2:
  iVar2 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
  if ((iVar2 != 0) && (iVar2 != 0x2060)) {
    iVar2 = CINSNextBot::GetDifficulty(this_00);
    if (iVar2 == 2) {
      local_24 = local_24 * *(float *)(unaff_EBX + 0x1ba892 /* typeinfo name for ISaveRestoreOps+0x6b */);
    }
    else if (iVar2 == 3) {
      local_24 = local_24 * *(float *)(unaff_EBX + 0x1bb55a /* typeinfo name for CBaseGameSystem+0x1e */);
    }
  }
  (**(code **)(*in_stack_00000008 + 0x50))(in_stack_00000008);
  return local_24 < (float)extraout_ST0;
}



/* ----------------------------------------
 * CINSBotVision::CollectPotentiallyVisibleEntities
 * Address: 0076bb50
 * ---------------------------------------- */

/* CINSBotVision::CollectPotentiallyVisibleEntities(CUtlVector<CBaseEntity*,
   CUtlMemory<CBaseEntity*, int> >*) */

void __thiscall
CINSBotVision::CollectPotentiallyVisibleEntities(CINSBotVision *this,CUtlVector *param_1)

{
  uint *puVar1;
  uint uVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  CINSBotVision *this_00;
  int unaff_EBX;
  int iVar6;
  CUtlVector *in_stack_00000008;
  CUtlVector *pCVar7;
  int *local_28;
  undefined4 local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x76bb5b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x100c) != 0;
  if ((bool)local_1d) {
    iVar6 = *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      piVar5 = *(int **)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1014);
      if (*piVar5 != unaff_EBX + 0x21b651 /* "CINSBotVision::CollectPotentiallyVisibleEntities" */) {
        piVar5 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar5,unaff_EBX + 0x21b651 /* "CINSBotVision::CollectPotentiallyVisibleEntities" */,(char *)0x0,
                                   unaff_EBX + 0x21510b /* "INSNextBot" */);
        *(int **)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1014) = piVar5;
      }
      puVar1 = (uint *)(piVar5[0x1c] * 8 + *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x10a0) +
                       4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1010) = 0;
    }
  }
  piVar5 = *(int **)(CCascadeLight::SetEnvLightShadowPitch + unaff_EBX + 5);
  *(undefined4 *)(in_stack_00000008 + 0xc) = 0;
  this_00 = *(CINSBotVision **)(*piVar5 + 0x14);
  if (0 < (int)this_00) {
    iVar6 = 1;
    do {
      piVar5 = (int *)UTIL_PlayerByIndex(iVar6);
      if (piVar5 != (int *)0x0) {
        cVar3 = (**(code **)(*piVar5 + 0x158))(piVar5);
        if (cVar3 != '\0') {
          cVar3 = (**(code **)(*piVar5 + 0x118))(piVar5);
          if ((cVar3 != '\0') && ((*(byte *)(piVar5 + 0x3e6) & 8) == 0)) {
            local_28 = piVar5;
            CUtlVector<CBaseEntity*,CUtlMemory<CBaseEntity*,int>>::InsertBefore
                      ((CUtlVector<CBaseEntity*,CUtlMemory<CBaseEntity*,int>> *)&local_28,
                       (int)in_stack_00000008,*(CBaseEntity ***)(in_stack_00000008 + 0xc));
          }
        }
      }
      this_00 = *(CINSBotVision **)(CCascadeLight::SetEnvLightShadowPitch + unaff_EBX + 5);
      iVar6 = iVar6 + 1;
    } while (iVar6 <= *(int *)(*(int *)this_00 + 0x14));
  }
  pCVar7 = param_1;
  UpdatePotentiallyVisibleNPCVector(this_00);
  if (0 < *(int *)(param_1 + 0x150)) {
    iVar6 = 0;
    do {
      local_24 = 0;
      uVar2 = *(uint *)(*(int *)(param_1 + 0x144) + iVar6 * 4);
      if ((uVar2 != 0xffffffff) &&
         (iVar4 = **(int **)(unaff_EBX + 0x43ac7d /* &g_pEntityList */) + (uVar2 & 0xffff) * 0x18,
         *(uint *)(iVar4 + 8) == uVar2 >> 0x10)) {
        local_24 = *(undefined4 *)(iVar4 + 4);
      }
      pCVar7 = in_stack_00000008;
      CUtlVector<CBaseEntity*,CUtlMemory<CBaseEntity*,int>>::InsertBefore
                ((CUtlVector<CBaseEntity*,CUtlMemory<CBaseEntity*,int>> *)&local_24,
                 (int)in_stack_00000008,*(CBaseEntity ***)(in_stack_00000008 + 0xc));
      iVar6 = iVar6 + 1;
    } while (iVar6 < *(int *)(param_1 + 0x150));
  }
  if ((local_1d != '\0') &&
     ((*(char *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x100c) != 0)))) {
    iVar6 = *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x19b8);
    iVar4 = ThreadGetCurrentId(pCVar7);
    if (iVar6 == iVar4) {
      cVar3 = CVProfNode::ExitScope();
      if (cVar3 == '\0') {
        iVar6 = *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1014);
      }
      else {
        iVar6 = *(int *)(*(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1014) + 100);
        *(int *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1014) = iVar6;
      }
      *(bool *)(*(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1010) =
           iVar6 == *(int *)(&DAT_0043ae19 + unaff_EBX) + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotVision::ForgetAllKnownEntities
 * Address: 00767d50
 * ---------------------------------------- */

/* CINSBotVision::ForgetAllKnownEntities() */

void __thiscall CINSBotVision::ForgetAllKnownEntities(CINSBotVision *this)

{
  IVision *this_00;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(in_stack_00000004 + 0x26c) = 0xffffffff;
  *(undefined4 *)(in_stack_00000004 + 0x268) = 0xffffffff;
  IVision::ForgetAllKnownEntities(this_00);
  return;
}



/* ----------------------------------------
 * CINSBotVision::GetAssessmentScore
 * Address: 0076a620
 * ---------------------------------------- */

/* CINSBotVision::GetAssessmentScore(INSBotThreatAssessment*, int) */

float10 __thiscall
CINSBotVision::GetAssessmentScore(CINSBotVision *this,INSBotThreatAssessment *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  int *piVar5;
  int iVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  char *pcVar9;
  CBaseEntity *this_00;
  CFmtStrN<256,false> *this_01;
  char *pcVar10;
  int unaff_EBX;
  float fVar11;
  int in_stack_0000000c;
  char *local_154;
  char *local_150;
  char local_14c [5];
  char local_147 [255];
  char local_48 [4];
  int local_44;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  fVar11 = 0.0;
  uStack_14 = 0x76a62e;
  __i686_get_pc_thunk_bx();
  if (param_2 != 0) {
    fVar1 = *(float *)(param_2 + 0x14);
    fVar11 = *(float *)(param_2 + 0xc) + *(float *)(param_2 + 0x10) + fVar1 +
             *(float *)(param_2 + 8);
    if (*(char *)(param_2 + 3) != '\0') {
      fVar11 = fVar11 + fVar1 + fVar1;
    }
    if (*(char *)(param_2 + 4) != '\0') {
      fVar11 = fVar11 + *(float *)(unaff_EBX + 0x1bc78a /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x38 */) * fVar1;
    }
    if (*(char *)(param_2 + 1) != '\0') {
      fVar11 = fVar11 + fVar1 * *(float *)(unaff_EBX + 0x1bc78a /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x38 */);
    }
    if (*(char *)(param_2 + 2) != '\0') {
      fVar11 = fVar11 * *(float *)(unaff_EBX + 0x1ba13e /* typeinfo name for CBaseGameSystem+0x32 */);
    }
    piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
    cVar4 = (**(code **)(*piVar5 + 0x140 /* CBaseEntity::IsMoving */))(piVar5,0x200);
    if ((cVar4 != '\0') && (iVar6 = UTIL_PlayerByIndex(*(int *)(param_2 + 0x18)), iVar6 != 0)) {
      fVar1 = *(float *)(param_2 + 8);
      fVar2 = *(float *)(param_2 + 0x10);
      fVar3 = *(float *)(param_2 + 0xc);
      uVar7 = CBaseEntity::GetDebugName(this_00);
      piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
      uVar8 = (**(code **)(*piVar5 + 0x144 /* CBaseEntity::DamageDecal */))(piVar5);
      CFmtStrN<256,false>::CFmtStrN
                (this_01,local_14c,unaff_EBX + 0x21cac6 /* "Assessment: bot:%s , target: %s , score: %3.2f,dtm: %3.2f,dtd: %3.2f,looking:..." */,uVar8,uVar7,(double)fVar11,(double)fVar3,
                 (double)fVar2,(double)fVar1);
      if (*(char *)(param_2 + 3) != '\0') {
        pcVar10 = &DAT_0021c959 + unaff_EBX;
        local_150 = local_147 + local_44;
        if (local_150 < local_48) {
          do {
            cVar4 = *pcVar10;
            pcVar10 = pcVar10 + 1;
            *local_150 = cVar4;
            local_150 = local_150 + 1;
            if (local_150 == local_48) break;
          } while (*pcVar10 != '\0');
        }
        *local_150 = '\0';
        local_44 = (int)local_150 - (int)local_147;
      }
      local_150 = local_147;
      if (*(char *)(param_2 + 4) != '\0') {
        pcVar10 = &DAT_0021c963 + unaff_EBX;
        local_154 = local_147 + local_44;
        if (local_154 < local_48) {
          do {
            cVar4 = *pcVar10;
            pcVar10 = pcVar10 + 1;
            *local_154 = cVar4;
            local_154 = local_154 + 1;
            if (local_154 == local_48) goto LAB_0076a945;
          } while (*pcVar10 != '\0');
          *local_154 = '\0';
          local_44 = (int)local_154 - (int)local_150;
        }
        else {
LAB_0076a945:
          *local_154 = '\0';
          local_44 = (int)local_154 - (int)local_150;
        }
      }
      if (*(char *)(param_2 + 1) != '\0') {
        pcVar10 = &DAT_0021c96d + unaff_EBX;
        local_154 = local_147 + local_44;
        if (local_154 < local_48) {
          do {
            cVar4 = *pcVar10;
            pcVar10 = pcVar10 + 1;
            *local_154 = cVar4;
            local_154 = local_154 + 1;
            if (local_154 == local_48) goto LAB_0076a9bd;
          } while (*pcVar10 != '\0');
          *local_154 = '\0';
          local_44 = (int)local_154 - (int)local_150;
        }
        else {
LAB_0076a9bd:
          *local_154 = '\0';
          local_44 = (int)local_154 - (int)local_150;
        }
      }
      if (*(char *)(param_2 + 2) != '\0') {
        pcVar9 = local_147 + local_44;
        pcVar10 = &DAT_0021c975 + unaff_EBX;
        if (pcVar9 < local_48) {
          do {
            cVar4 = *pcVar10;
            pcVar10 = pcVar10 + 1;
            *pcVar9 = cVar4;
            pcVar9 = pcVar9 + 1;
            if (pcVar9 == local_48) break;
          } while (*pcVar10 != '\0');
        }
        *pcVar9 = '\0';
        local_44 = (int)pcVar9 - (int)local_150;
      }
      piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
      piVar5 = (int *)(**(code **)(*piVar5 + 200))(piVar5);
      (**(code **)(*piVar5 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar5);
      local_34 = local_28;
      local_30 = local_24;
      local_2c = (float)(in_stack_0000000c * 6) + local_20;
      NDebugOverlay::Text((Vector *)&local_34,local_150,true,0.25);
    }
  }
  return (float10)fVar11;
}



/* ----------------------------------------
 * CINSBotVision::GetCombatIntensity
 * Address: 00769b60
 * ---------------------------------------- */

/* CINSBotVision::GetCombatIntensity() */

float10 __thiscall CINSBotVision::GetCombatIntensity(CINSBotVision *this)

{
  int extraout_ECX;
  float fVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  fVar1 = *(float *)(extraout_ECX + 0x217f1f /* typeinfo name for CINSBotRetreat+0x12 */) * *(float *)(in_stack_00000004 + 0x278);
  if (*(float *)(extraout_ECX + 0x14efaf /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar1) {
    fVar1 = *(float *)(extraout_ECX + 0x14efaf /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
  }
  if (fVar1 <= *(float *)(_GLOBAL__sub_I_movie_display_cpp + extraout_ECX + 3)) {
    fVar1 = *(float *)(_GLOBAL__sub_I_movie_display_cpp + extraout_ECX + 3);
  }
  return (float10)fVar1;
}



/* ----------------------------------------
 * CINSBotVision::GetDefaultFieldOfView
 * Address: 00767e50
 * ---------------------------------------- */

/* CINSBotVision::GetDefaultFieldOfView() const */

float10 __thiscall CINSBotVision::GetDefaultFieldOfView(CINSBotVision *this)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  float fVar5;
  float fVar6;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSRules *extraout_ECX;
  CINSRules *extraout_ECX_00;
  CINSRules *this_02;
  CINSRules *extraout_ECX_01;
  int unaff_EBX;
  float10 fVar7;
  float fVar8;
  int *in_stack_00000004;
  float local_10;
  
  __i686_get_pc_thunk_bx();
  iVar3 = (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  if ((iVar3 == 0) || (iVar3 == 0x2060)) {
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x43f012 /* &bot_fov_idle_base */))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x43f012 /* &bot_fov_idle_base */)) {
      local_10 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      local_10 = (float)fVar7;
    }
    goto LAB_00767fa9;
  }
  cVar2 = CINSPlayer::IsAttacking();
  if (cVar2 == '\0') {
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x43f012 /* &bot_fov_idle_base */))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x43f012 /* &bot_fov_idle_base */)) goto LAB_00767fc9;
LAB_00767ea8:
    fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
    local_10 = (float)fVar7;
    iVar3 = CINSNextBot::GetDifficulty(this_01);
    this_02 = extraout_ECX;
    if (iVar3 == 2) goto LAB_00767fe0;
LAB_00767ec4:
    if (iVar3 == 3) {
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x43eb72 /* &bot_fov_frac_impossible */))[7];
      if (piVar4 != *(int **)(unaff_EBX + 0x43eb72 /* &bot_fov_frac_impossible */)) goto LAB_00767ee3;
LAB_00767ff1:
      fVar5 = (float)((uint)piVar4 ^ piVar4[0xb]);
      goto LAB_00767ef3;
    }
    if (iVar3 == 0) {
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x43efde /* &bot_fov_frac_easy */))[7];
      if (piVar4 == *(int **)(unaff_EBX + 0x43efde /* &bot_fov_frac_easy */)) goto LAB_00767ff1;
      goto LAB_00767ee3;
    }
  }
  else {
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x43ef56 /* &bot_fov_attack_base */))[7];
    if (piVar4 != *(int **)(unaff_EBX + 0x43ef56 /* &bot_fov_attack_base */)) goto LAB_00767ea8;
LAB_00767fc9:
    local_10 = (float)((uint)piVar4 ^ piVar4[0xb]);
    iVar3 = CINSNextBot::GetDifficulty(this_00);
    this_02 = extraout_ECX_01;
    if (iVar3 != 2) goto LAB_00767ec4;
LAB_00767fe0:
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x43f212 /* &bot_fov_frac_hard */))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x43f212 /* &bot_fov_frac_hard */)) goto LAB_00767ff1;
LAB_00767ee3:
    fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
    fVar5 = (float)fVar7;
    this_02 = extraout_ECX_00;
LAB_00767ef3:
    local_10 = fVar5 * local_10;
  }
  piVar4 = *(int **)(unaff_EBX + 0x43ea9e /* &g_pGameRules */);
  if ((*piVar4 != 0) && (cVar2 = CINSRules::IsSurvival(this_02), cVar2 != '\0')) {
    piVar1 = (int *)(*(int **)(unaff_EBX + 0x43eb16 /* &bot_fov_frac_survival_end */))[7];
    if (piVar1 == *(int **)(unaff_EBX + 0x43eb16 /* &bot_fov_frac_survival_end */)) {
      fVar5 = (float)((uint)piVar1 ^ piVar1[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
      fVar5 = (float)fVar7;
    }
    piVar1 = (int *)(*(int **)(&LAB_0043e8be + unaff_EBX))[7];
    if (piVar1 == *(int **)(&LAB_0043e8be + unaff_EBX)) {
      fVar6 = (float)((uint)piVar1 ^ piVar1[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
      fVar6 = (float)fVar7;
    }
    fVar8 = ((float)*(int *)(*piVar4 + 1000) + *(float *)(unaff_EBX + 0x150cb6 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x30 */)) *
            *(float *)(CBaseAchievement::GetCount + unaff_EBX + 6);
    if (*(float *)(unaff_EBX + 0x150cba /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar8) {
      fVar8 = *(float *)(unaff_EBX + 0x150cba /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
    }
    if (fVar8 <= *(float *)(unaff_EBX + 0x150cae /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
      fVar8 = *(float *)(unaff_EBX + 0x150cae /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
    }
    local_10 = ((fVar5 - fVar6) * fVar8 + fVar6) * local_10;
  }
LAB_00767fa9:
  return (float10)local_10;
}



/* ----------------------------------------
 * CINSBotVision::GetMaxVisionRange
 * Address: 00767b60
 * ---------------------------------------- */

/* CINSBotVision::GetMaxVisionRange() const */

float10 CINSBotVision::GetMaxVisionRange(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return (float10)*(float *)(extraout_ECX + 0x1ff4bf /* typeinfo name for CEntityFactory<CPhysicsSpring>+0x24 */);
}



/* ----------------------------------------
 * CINSBotVision::GetMinRecognizeTime
 * Address: 007682e0
 * ---------------------------------------- */

/* CINSBotVision::GetMinRecognizeTime() const */

float10 __thiscall CINSBotVision::GetMinRecognizeTime(CINSBotVision *this)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  float fVar6;
  float fVar7;
  CBaseEntity *this_00;
  CINSRules *this_01;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *pCVar8;
  CINSRules *extraout_ECX_01;
  int unaff_EBX;
  int *piVar9;
  float10 fVar10;
  float fVar11;
  int *in_stack_00000004;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar3 = (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  piVar9 = (int *)0x0;
  if (iVar3 != 0) {
    piVar9 = (int *)(iVar3 + -0x2060);
  }
  piVar1 = (int *)(*(int **)(unaff_EBX + 0x43e463 /* &bot_recognizetime_base */))[7];
  if (piVar1 == *(int **)(unaff_EBX + 0x43e463 /* &bot_recognizetime_base */)) {
    local_20 = (float)((uint)piVar1 ^ piVar1[0xb]);
  }
  else {
    fVar10 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    local_20 = (float)fVar10;
  }
  if (piVar9 == (int *)0x0) goto LAB_00768354;
  piVar1 = *(int **)(unaff_EBX + 0x43e60b /* &g_pGameRules */);
  cVar2 = CINSRules::IsSoloMode();
  if (cVar2 == '\0') {
    cVar2 = (char)piVar9[0x2d27];
    pCVar8 = (CINSNextBot *)this_00;
joined_r0x00768381:
    if (cVar2 == '\0') {
      iVar3 = CINSNextBot::GetDifficulty(pCVar8);
      if (iVar3 == 3) {
        piVar5 = (int *)(*(int **)(unaff_EBX + 0x43e7af /* &bot_recognizetime_frac_impossible */))[7];
        pCVar8 = this_02;
        if (piVar5 != *(int **)(unaff_EBX + 0x43e7af /* &bot_recognizetime_frac_impossible */)) {
LAB_007684c5:
          fVar10 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
          local_24 = (float)fVar10;
          pCVar8 = (CINSNextBot *)extraout_ECX_01;
          goto LAB_007683c2;
        }
      }
      else {
        iVar3 = CINSNextBot::GetDifficulty(this_02);
        if (iVar3 == 2) {
          piVar5 = (int *)(*(int **)(unaff_EBX + 0x43ea1f /* &bot_recognizetime_frac_hard */))[7];
          pCVar8 = this_03;
          if (piVar5 != *(int **)(unaff_EBX + 0x43ea1f /* &bot_recognizetime_frac_hard */)) goto LAB_007684c5;
        }
        else {
          iVar3 = CINSNextBot::GetDifficulty(this_03);
          local_24 = *(float *)(unaff_EBX + 0x150827 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
          pCVar8 = extraout_ECX_00;
          if (iVar3 != 0) goto LAB_007683c2;
          piVar5 = (int *)(*(int **)(unaff_EBX + 0x43ee1f /* &bot_recognizetime_frac_easy */))[7];
          if (piVar5 != *(int **)(unaff_EBX + 0x43ee1f /* &bot_recognizetime_frac_easy */)) goto LAB_007684c5;
        }
      }
      local_24 = (float)((uint)piVar5 ^ piVar5[0xb]);
LAB_007683c2:
      if ((*piVar1 != 0) && (cVar2 = CINSRules::IsSurvival((CINSRules *)pCVar8), cVar2 != '\0')) {
        piVar5 = (int *)(*(int **)(unaff_EBX + 0x43edb3 /* &bot_recognizetime_frac_survival_end */))[7];
        if (piVar5 == *(int **)(unaff_EBX + 0x43edb3 /* &bot_recognizetime_frac_survival_end */)) {
          fVar7 = (float)((uint)piVar5 ^ piVar5[0xb]);
        }
        else {
          fVar10 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
          fVar7 = (float)fVar10;
        }
        piVar5 = (int *)(*(int **)(&DAT_0043e2ff + unaff_EBX))[7];
        if (piVar5 == *(int **)(&DAT_0043e2ff + unaff_EBX)) {
          fVar6 = (float)((uint)piVar5 ^ piVar5[0xb]);
        }
        else {
          fVar10 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
          fVar6 = (float)fVar10;
        }
        fVar11 = ((float)*(int *)(*piVar1 + 1000) + *(float *)(unaff_EBX + 0x150823 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x30 */)) *
                 *(float *)(unaff_EBX + 0x1cb853 /* typeinfo name for CINSRules_Survival+0x20 */);
        if (*(float *)(unaff_EBX + 0x150827 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar11) {
          fVar11 = *(float *)(unaff_EBX + 0x150827 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
        }
        if (fVar11 <= *(float *)(unaff_EBX + 0x15081b /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
          fVar11 = *(float *)(unaff_EBX + 0x15081b /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
        }
        local_24 = ((fVar7 - fVar6) * fVar11 + fVar6) * local_24;
      }
      (**(code **)(*piVar9 + 0x970 /* CINSNextBot::GetBodyInterface */))(piVar9);
      fVar10 = (float10)CINSBotBody::GetArousalFrac();
      return (float10)((float)fVar10 * local_24 * local_20);
    }
  }
  else {
    iVar3 = CBaseEntity::GetTeamNumber(this_00);
    iVar4 = CINSRules::GetHumanTeam(this_01);
    if (iVar3 != iVar4) {
      cVar2 = (char)piVar9[0x2d27];
      pCVar8 = extraout_ECX;
      goto joined_r0x00768381;
    }
  }
  local_20 = 0.0;
LAB_00768354:
  return (float10)local_20;
}



/* ----------------------------------------
 * CINSBotVision::GetPrimaryKnownThreat
 * Address: 007691e0
 * ---------------------------------------- */

/* CINSBotVision::GetPrimaryKnownThreat(bool) const */

void __cdecl CINSBotVision::GetPrimaryKnownThreat(bool param_1)

{
  GetPrimaryKnownThreatCached(param_1);
  return;
}



/* ----------------------------------------
 * CINSBotVision::GetPrimaryKnownThreatCached
 * Address: 00769130
 * ---------------------------------------- */

/* CINSBotVision::GetPrimaryKnownThreatCached(bool) const */

void __cdecl CINSBotVision::GetPrimaryKnownThreatCached(bool param_1)

{
  uint uVar1;
  byte extraout_CL;
  int iVar2;
  int unaff_EBX;
  undefined3 in_stack_00000005;
  
  __i686_get_pc_thunk_bx();
  if (((((extraout_CL == 0) || (uVar1 = _param_1[0x9a], uVar1 == 0xffffffff)) ||
       (iVar2 = **(int **)(unaff_EBX + 0x43d696 /* &g_pEntityList */) + (uVar1 & 0xffff) * 0x18,
       *(uint *)(iVar2 + 8) != uVar1 >> 0x10)) || (iVar2 = *(int *)(iVar2 + 4), iVar2 == 0)) &&
     (((uVar1 = _param_1[0x9b], uVar1 == 0xffffffff ||
       (iVar2 = **(int **)(unaff_EBX + 0x43d696 /* &g_pEntityList */) + (uVar1 & 0xffff) * 0x18,
       *(uint *)(iVar2 + 8) != uVar1 >> 0x10)) || (iVar2 = *(int *)(iVar2 + 4), iVar2 == 0)))) {
    IVision::GetPrimaryKnownThreat((IVision *)(uint)extraout_CL,param_1);
    return;
  }
  (**(code **)(*_param_1 + 0xe4))(_param_1,iVar2);
  return;
}



/* ----------------------------------------
 * CINSBotVision::GetSilhouetteType
 * Address: 00769420
 * ---------------------------------------- */

/* CINSBotVision::GetSilhouetteType(CBaseEntity*) */

uint __thiscall CINSBotVision::GetSilhouetteType(CINSBotVision *this,CBaseEntity *param_1)

{
  float fVar1;
  undefined4 *puVar2;
  int *piVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  char cVar7;
  int iVar8;
  int *piVar9;
  float *pfVar10;
  int *piVar11;
  CINSNavMesh *this_00;
  CINSNavMesh *this_01;
  CBaseEntity *this_02;
  uint uVar12;
  int unaff_EBX;
  float10 fVar13;
  float10 fVar14;
  float fVar15;
  float fVar16;
  int *in_stack_00000008;
  int *piVar17;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar8 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
  if (iVar8 == 0) {
    return 0xffffffff;
  }
  if (in_stack_00000008 == (int *)0x0) {
    return 0xffffffff;
  }
  cVar7 = (**(code **)(*in_stack_00000008 + 0x158 /* CBasePlayer::IsPlayer */))(in_stack_00000008);
  if (cVar7 == '\0') {
    return 2;
  }
  piVar9 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  piVar9 = (int *)(**(code **)(*piVar9 + 200))(piVar9);
  if (piVar9 == (int *)0x0) {
    return 0xffffffff;
  }
  puVar2 = *(undefined4 **)(unaff_EBX + 0x43d284 /* &TheNavMesh */);
  fVar13 = (float10)CINSNavMesh::GetLightIntensity(this_00,(CBaseEntity *)*puVar2);
  piVar17 = in_stack_00000008;
  fVar14 = (float10)CINSNavMesh::GetLightIntensity(this_01,(CBaseEntity *)*puVar2);
  fVar1 = (float)fVar14;
  pfVar10 = (float *)(**(code **)(*in_stack_00000008 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000008,piVar17);
  (**(code **)(*piVar9 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar9);
  fVar15 = SQRT((local_24 - pfVar10[1]) * (local_24 - pfVar10[1]) +
                (local_28 - *pfVar10) * (local_28 - *pfVar10) +
                (local_20 - pfVar10[2]) * (local_20 - pfVar10[2]));
  if ((*(byte *)((int)in_stack_00000008 + 0xd1) & 0x10) != 0) {
    CBaseEntity::CalcAbsoluteVelocity(this_02);
  }
  piVar9 = *(int **)(&LAB_0043d05c + unaff_EBX);
  piVar17 = (int *)piVar9[7];
  fVar16 = SQRT((float)in_stack_00000008[0x6b] * (float)in_stack_00000008[0x6b] +
                (float)in_stack_00000008[0x6a] * (float)in_stack_00000008[0x6a]);
  bVar4 = fVar16 != *(float *)(unaff_EBX + 0x14fb4c /* typeinfo name for IServerBenchmark+0x17 */);
  bVar5 = *(float *)(unaff_EBX + 0x14fb4c /* typeinfo name for IServerBenchmark+0x17 */) <= fVar16;
  bVar6 = bVar5 && bVar4;
  if (piVar17 == piVar9) {
    fVar16 = (float)(piVar9[0xb] ^ (uint)piVar9);
  }
  else {
    fVar14 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
    fVar16 = (float)fVar14;
  }
  if (fVar16 <= (float)fVar13) {
    piVar17 = *(int **)(&DAT_0043d06c + unaff_EBX);
    piVar11 = (int *)piVar17[7];
    if (piVar11 == piVar17) {
      fVar16 = (float)(piVar17[0xb] ^ (uint)piVar17);
    }
    else {
      fVar14 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
      fVar16 = (float)fVar14;
    }
    piVar11 = *(int **)(unaff_EBX + 0x43d1f8 /* &bot_silhouette_range_close */);
    piVar3 = (int *)piVar11[7];
    if ((float)fVar13 <= fVar16) {
      if (piVar3 == piVar11) {
        fVar16 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar13 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
        fVar16 = (float)fVar13;
      }
      if (fVar16 <= fVar15) {
        piVar11 = (int *)(*(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */))[7];
        if (piVar11 == *(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */)) {
          fVar16 = (float)((uint)piVar11 ^ piVar11[0xb]);
        }
        else {
          fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
          fVar16 = (float)fVar13;
        }
        piVar11 = (int *)piVar9[7];
        if (fVar15 <= fVar16) {
          if (piVar11 == piVar9) {
            fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
          }
          else {
            fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
            fVar15 = (float)fVar13;
          }
          if ((fVar1 < fVar15) && (!bVar5 || !bVar4)) {
            return 0;
          }
          piVar9 = (int *)piVar17[7];
          if (piVar9 == piVar17) {
            return 2;
          }
          (**(code **)(*piVar9 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar9);
          return 2;
        }
        if (piVar11 == piVar9) {
          fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
        }
        else {
          fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
          fVar15 = (float)fVar13;
        }
        uVar12 = 0;
        goto joined_r0x007698d4;
      }
      piVar11 = (int *)piVar9[7];
      if (piVar11 != piVar9) goto LAB_0076972d;
      fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
    }
    else {
      if (piVar3 == piVar11) {
        fVar16 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar13 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
        fVar16 = (float)fVar13;
      }
      if (fVar16 <= fVar15) {
        piVar11 = (int *)(*(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */))[7];
        if (piVar11 == *(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */)) {
          fVar16 = (float)((uint)piVar11 ^ piVar11[0xb]);
        }
        else {
          fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
          fVar16 = (float)fVar13;
        }
        piVar11 = (int *)piVar9[7];
        if (fVar16 < fVar15) {
          if (piVar11 == piVar9) {
            fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
          }
          else {
            fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
            fVar15 = (float)fVar13;
          }
          if (fVar1 < fVar15) {
            return 0;
          }
          piVar9 = (int *)piVar17[7];
          if (piVar9 == piVar17) {
            fVar15 = (float)((uint)piVar17 ^ piVar17[0xb]);
            goto LAB_00769647;
          }
          goto LAB_00769637;
        }
        if (piVar11 == piVar9) {
          fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
        }
        else {
          fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
          fVar15 = (float)fVar13;
        }
        uVar12 = (uint)bVar6;
joined_r0x007698d4:
        if (fVar1 < fVar15) {
          return uVar12;
        }
        piVar9 = (int *)piVar17[7];
        if (piVar9 == piVar17) {
          fVar15 = (float)((uint)piVar17 ^ piVar17[0xb]);
        }
        else {
          fVar13 = (float10)(**(code **)(*piVar9 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar9);
          fVar15 = (float)fVar13;
        }
        goto LAB_0076986b;
      }
      piVar11 = (int *)piVar9[7];
      if (piVar11 == piVar9) {
        fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
      }
      else {
        fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
        fVar15 = (float)fVar13;
      }
      if (fVar1 < fVar15) {
        return (uint)bVar6;
      }
      piVar11 = (int *)piVar17[7];
      if (piVar11 == piVar17) {
        fVar15 = (float)((uint)piVar17 ^ piVar17[0xb]);
      }
      else {
LAB_0076972d:
        fVar13 = (float10)(**(code **)(*piVar11 + 0x3c))(piVar11);
        fVar15 = (float)fVar13;
      }
    }
    if (fVar15 <= fVar1) {
      return 2;
    }
  }
  else {
    piVar17 = (int *)(*(int **)(unaff_EBX + 0x43d1f8 /* &bot_silhouette_range_close */))[7];
    if (piVar17 == *(int **)(unaff_EBX + 0x43d1f8 /* &bot_silhouette_range_close */)) {
      fVar16 = (float)((uint)piVar17 ^ piVar17[0xb]);
    }
    else {
      fVar13 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
      fVar16 = (float)fVar13;
    }
    if (fVar15 < fVar16) {
      piVar17 = (int *)piVar9[7];
      if (piVar17 == piVar9) {
        fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
      }
      else {
        fVar13 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
        fVar15 = (float)fVar13;
      }
      return (fVar15 <= fVar1) + 1;
    }
    piVar17 = (int *)(*(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */))[7];
    if (piVar17 == *(int **)(unaff_EBX + 0x43d2c0 /* &bot_silhouette_range_far */)) {
      fVar16 = (float)((uint)piVar17 ^ piVar17[0xb]);
    }
    else {
      fVar13 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
      fVar16 = (float)fVar13;
    }
    piVar17 = (int *)piVar9[7];
    if (fVar16 < fVar15) {
      if (piVar17 == piVar9) {
        fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
      }
      else {
        fVar13 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
        fVar15 = (float)fVar13;
      }
      if (fVar1 < fVar15) {
        return 0;
      }
      piVar9 = (int *)(*(int **)(&DAT_0043d06c + unaff_EBX))[7];
      if (piVar9 == *(int **)(&DAT_0043d06c + unaff_EBX)) {
        fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
        goto LAB_00769647;
      }
LAB_00769637:
      fVar13 = (float10)(**(code **)(*piVar9 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar9);
      fVar15 = (float)fVar13;
LAB_00769647:
      if (fVar15 < fVar1) {
        return 2;
      }
      return (uint)bVar6;
    }
    if (piVar17 == piVar9) {
      fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
    }
    else {
      fVar13 = (float10)(**(code **)(*piVar17 + 0x3c))(piVar17);
      fVar15 = (float)fVar13;
    }
    if ((fVar1 < fVar15) && (!bVar5 || !bVar4)) {
      return 0;
    }
    piVar9 = (int *)(*(int **)(&DAT_0043d06c + unaff_EBX))[7];
    if (piVar9 == *(int **)(&DAT_0043d06c + unaff_EBX)) {
      fVar15 = (float)((uint)piVar9 ^ piVar9[0xb]);
    }
    else {
      fVar13 = (float10)(**(code **)(*piVar9 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar9);
      fVar15 = (float)fVar13;
    }
LAB_0076986b:
    if (fVar15 < fVar1) {
      return 2;
    }
  }
  return 2 - (!bVar5 || !bVar4);
}



/* ----------------------------------------
 * CINSBotVision::GetSilhouetteType
 * Address: 00769a70
 * ---------------------------------------- */

/* CINSBotVision::GetSilhouetteType(CBaseEntity*) const */

undefined4 __thiscall CINSBotVision::GetSilhouetteType(CINSBotVision *this,CBaseEntity *param_1)

{
  char cVar1;
  int iVar2;
  undefined4 uVar3;
  int unaff_EBX;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (int *)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    cVar1 = (**(code **)(*in_stack_00000008 + 0x158))(in_stack_00000008);
    uVar3 = 0xffffffff;
    if (cVar1 != '\0') {
      iVar2 = 0;
      if (in_stack_00000008[8] != 0) {
        iVar2 = in_stack_00000008[8] - *(int *)(**(int **)(unaff_EBX + 0x43ce26 /* &gpGlobals */) + 0x5c) >> 4;
      }
      uVar3 = *(undefined4 *)(param_1 + iVar2 * 4 + 0x194);
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSBotVision::IsAbleToSee
 * Address: 00767be0
 * ---------------------------------------- */

/* CINSBotVision::IsAbleToSee(Vector const&, IVision::FieldOfViewCheckType) const */

undefined4 __thiscall
CINSBotVision::IsAbleToSee(undefined4 param_1_00,int *param_1,undefined4 param_3,int param_4)

{
  code *pcVar1;
  char cVar2;
  int *piVar3;
  undefined4 uVar4;
  float10 fVar5;
  
  piVar3 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
  pcVar1 = *(code **)(*piVar3 + 300);
  fVar5 = (float10)(**(code **)(*param_1 + 0xfc))(param_1);
  cVar2 = (*pcVar1)(piVar3,param_3,(float)fVar5);
  if (cVar2 == '\0') {
    piVar3 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
    piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3);
    cVar2 = (**(code **)(*piVar3 + 0x414 /* CBaseCombatCharacter::IsHiddenByFog */))(piVar3,param_3);
    if ((cVar2 == '\0') &&
       ((param_4 != 0 || (cVar2 = (**(code **)(*param_1 + 0x114))(param_1,param_3), cVar2 != '\0')))
       ) {
      uVar4 = (**(code **)(*param_1 + 0x128))(param_1,param_3);
      return uVar4;
    }
  }
  return 0;
}



/* ----------------------------------------
 * CINSBotVision::IsAbleToSee
 * Address: 007687a0
 * ---------------------------------------- */

/* CINSBotVision::IsAbleToSee(CBaseEntity*, IVision::FieldOfViewCheckType, Vector*) const */

uint __thiscall
CINSBotVision::IsAbleToSee
          (undefined4 param_1_00,int *param_1,int *param_3,int param_4,float *param_5)

{
  uint *puVar1;
  int iVar2;
  code *pcVar3;
  float *pfVar4;
  float fVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int *piVar10;
  char *pcVar11;
  undefined4 uVar12;
  int *piVar13;
  CVProfScope *this;
  uint uVar14;
  uint uVar15;
  int unaff_EBX;
  bool bVar16;
  float10 fVar17;
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7687ab;
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x43e1c9 /* &GCSDK::GetPchTempTextBuffer */);
  local_1d = *(int *)(iVar2 + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar8 == iVar7)) {
    pcVar11 = *(char **)(iVar2 + 0x1014);
    if (*(undefined **)pcVar11 != &UNK_0021e7c1 + unaff_EBX) {
      pcVar11 = (char *)CVProfNode::GetSubNode
                                  (pcVar11,(int)(&UNK_0021e7c1 + unaff_EBX),(char *)0x0,
                                   unaff_EBX + 0x2170c3 /* "NextBotExpensive" */);
      *(char **)(iVar2 + 0x1014) = pcVar11;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + *(int *)(pcVar11 + 0x70) * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
  }
  if ((((param_3 != (int *)0x0) && (iVar8 = (**(code **)(*param_1 + 0xc4))(param_1), iVar8 != 0)) &&
      (iVar8 = (**(code **)(*param_1 + 0xc4))(param_1), iVar8 != 0)) &&
     ((piVar13 = (int *)(iVar8 + -0x2060), piVar13 != (int *)0x0 &&
      (cVar6 = (**(code **)(*(int *)(iVar8 + -0x2060) + 0x118))(piVar13), cVar6 != '\0')))) {
    bVar16 = *(int *)(iVar2 + 0x100c) != 0;
    local_2c = (float)CONCAT31(local_2c._1_3_,bVar16);
    if ((bVar16) && (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar8 == iVar7)
       ) {
      piVar9 = *(int **)(iVar2 + 0x1014);
      if (*piVar9 != unaff_EBX + 0x21e891 /* "CINSBotVision::IsAbleToSee - Range/Fog/FOV" */) {
        piVar9 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar9,unaff_EBX + 0x21e891 /* "CINSBotVision::IsAbleToSee - Range/Fog/FOV" */,(char *)0x0,
                                   unaff_EBX + 0x2170c3 /* "NextBotExpensive" */);
        *(int **)(iVar2 + 0x1014) = piVar9;
      }
      puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar9[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar2 + 0x1010) = 0;
    }
    piVar9 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
    pcVar3 = *(code **)(*piVar9 + 0x128);
    fVar17 = (float10)(**(code **)(*param_1 + 0xfc))(param_1);
    cVar6 = (*pcVar3)(piVar9,param_3,(float)fVar17);
    if (cVar6 == '\0') {
      if (((local_2c._0_1_ != (CBaseEntity)0x0) &&
          ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) &&
         (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar8 == iVar7)) {
        piVar9 = *(int **)(iVar2 + 0x1014);
        cVar6 = CVProfNode::ExitScope();
        if (cVar6 == '\0') {
          iVar8 = *(int *)(iVar2 + 0x1014);
        }
        else {
          iVar8 = *(int *)(*(int *)(iVar2 + 0x1014) + 100);
          *(int *)(iVar2 + 0x1014) = iVar8;
        }
        *(bool *)(iVar2 + 0x1010) = iVar8 == iVar2 + 0x1018;
      }
      if (param_4 == 0) {
        piVar9 = param_1;
        cVar6 = (**(code **)(*param_1 + 0x118))(param_1,param_3);
        uVar14 = 0;
        if (cVar6 == '\0') goto LAB_00768a4a;
      }
      bVar16 = *(int *)(iVar2 + 0x100c) != 0;
      local_2c = (float)CONCAT31(local_2c._1_3_,bVar16);
      if ((bVar16) &&
         (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(piVar9), iVar8 == iVar7)) {
        piVar9 = *(int **)(iVar2 + 0x1014);
        if (*piVar9 != unaff_EBX + 0x21e8bd /* "CINSBotVision::IsAbleToSee - Fog" */) {
          piVar9 = (int *)CVProfNode::GetSubNode
                                    ((char *)piVar9,unaff_EBX + 0x21e8bd /* "CINSBotVision::IsAbleToSee - Fog" */,(char *)0x0,
                                     unaff_EBX + 0x2170c3 /* "NextBotExpensive" */);
          *(int **)(iVar2 + 0x1014) = piVar9;
        }
        puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar9[0x1c] * 8 + 4);
        *puVar1 = *puVar1 | 4;
        CVProfNode::EnterScope();
        *(undefined1 *)(iVar2 + 0x1010) = 0;
      }
      piVar9 = (int *)(**(code **)(*param_1 + 0xc4))(param_1);
      piVar10 = (int *)(**(code **)(*piVar9 + 200))(piVar9);
      piVar9 = param_3;
      cVar6 = (**(code **)(*piVar10 + 0x418 /* CBaseCombatCharacter::IsHiddenByFog */))(piVar10,param_3);
      if (cVar6 == '\0') {
        CVProfScope::~CVProfScope(this);
        if ((param_4 == 0) && (cVar6 = (**(code **)(*param_3 + 0x158 /* CBasePlayer::IsPlayer */))(param_3), cVar6 != '\0')) {
          piVar10 = param_3;
          CINSNextBot::GetEntityViewPosition((CBaseEntity *)&local_2c);
          fVar5 = local_2c;
          pfVar4 = *(float **)(unaff_EBX + 0x43de21 /* &vec3_origin */);
          if (((local_2c != *pfVar4) ||
              ((pfVar4[1] != local_28 || (piVar9 = piVar13, pfVar4[2] != local_24)))) &&
             (piVar9 = param_3, cVar6 = (**(code **)(*param_1 + 0x110))(param_1,param_3,piVar10),
             cVar6 != '\0')) {
            uVar14 = 1;
            if (param_5 != (float *)0x0) {
              *param_5 = fVar5;
              param_5[1] = local_28;
              param_5[2] = local_24;
            }
            goto LAB_00768a4a;
          }
        }
        pcVar3 = *(code **)(*param_1 + 0x128);
        uVar12 = (**(code **)(*param_3 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_3,piVar9);
        uVar14 = (*pcVar3)(param_1,uVar12);
        goto LAB_00768a4a;
      }
      CVProfScope::~CVProfScope(this);
    }
    else if ((local_2c._0_1_ != (CBaseEntity)0x0) &&
            (((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)) &&
             (iVar8 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar8 == iVar7)))) {
      cVar6 = CVProfNode::ExitScope();
      if (cVar6 == '\0') {
        iVar8 = *(int *)(iVar2 + 0x1014);
      }
      else {
        iVar8 = *(int *)(*(int *)(iVar2 + 0x1014) + 100);
        *(int *)(iVar2 + 0x1014) = iVar8;
      }
      *(bool *)(iVar2 + 0x1010) = iVar8 == iVar2 + 0x1018;
      uVar14 = 0;
      goto LAB_00768a4a;
    }
  }
  uVar14 = 0;
LAB_00768a4a:
  uVar15 = uVar14;
  if ((local_1d != '\0') && ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))
     ) {
    iVar8 = *(int *)(iVar2 + 0x19b8);
    iVar7 = ThreadGetCurrentId();
    uVar15 = uVar14 & 0xff;
    if (iVar8 == iVar7) {
      cVar6 = CVProfNode::ExitScope();
      iVar8 = *(int *)(iVar2 + 0x1014);
      if (cVar6 != '\0') {
        iVar8 = *(int *)(iVar8 + 100);
        *(int *)(iVar2 + 0x1014) = iVar8;
      }
      *(bool *)(iVar2 + 0x1010) = iVar8 == iVar2 + 0x1018;
      return uVar14 & 0xff;
    }
  }
  return uVar15;
}



/* ----------------------------------------
 * CINSBotVision::IsBlinded
 * Address: 00769ba0
 * ---------------------------------------- */

/* CINSBotVision::IsBlinded() */

bool __thiscall CINSBotVision::IsBlinded(CINSBotVision *this)

{
  bool bVar1;
  int iVar2;
  float10 fVar3;
  float10 extraout_ST0;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
  bVar1 = true;
  if ((iVar2 != 0) && (iVar2 != 0x2060)) {
    if ((0.0 < *(float *)(iVar2 + -0x840)) &&
       (fVar3 = (float10)CountdownTimer::Now(),
       (float)fVar3 < *(float *)(iVar2 + -0x840) || (float)fVar3 == *(float *)(iVar2 + -0x840))) {
      return true;
    }
    bVar1 = false;
    if (0.0 < (float)in_stack_00000004[0x5b]) {
      CountdownTimer::Now();
      return (float)extraout_ST0 < (float)in_stack_00000004[0x5b] ||
             (float)extraout_ST0 == (float)in_stack_00000004[0x5b];
    }
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSBotVision::IsIgnored
 * Address: 00767d90
 * ---------------------------------------- */

/* CINSBotVision::IsIgnored(CBaseEntity*) const */

uint __thiscall CINSBotVision::IsIgnored(CINSBotVision *this,CBaseEntity *param_1)

{
  int *piVar1;
  char cVar2;
  float fVar3;
  uint uVar4;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  cVar2 = (**(code **)(*in_stack_00000008 + 0x118 /* CBaseEntity::IsAlive */))();
  uVar4 = 1;
  if (cVar2 != '\0') {
    cVar2 = (**(code **)(*in_stack_00000008 + 0x158 /* CBasePlayer::IsPlayer */))();
    uVar4 = 0;
    if (cVar2 != '\0') {
      cVar2 = (**(code **)(*in_stack_00000008 + 0x158 /* CBasePlayer::IsPlayer */))();
      uVar4 = 1;
      if (cVar2 == '\0') {
        in_stack_00000008 = (int *)0x0;
      }
      if ((*(byte *)(in_stack_00000008 + 0x3e6) & 8) == 0) {
        piVar1 = (int *)(*(int **)(CEnvEffectsScript::GetBaseMap + unaff_EBX + 4))[7];
        if (piVar1 == *(int **)(CEnvEffectsScript::GetBaseMap + unaff_EBX + 4)) {
          fVar3 = (float)((uint)piVar1 ^ piVar1[0xb]);
        }
        else {
          fVar5 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
          fVar3 = (float)fVar5;
        }
        uVar4 = 0;
        if (*(float *)(unaff_EBX + 0x150d64 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= fVar3 && fVar3 != *(float *)(unaff_EBX + 0x150d64 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */))
        {
          uVar4 = (**(code **)(*in_stack_00000008 + 0x7b0 /* NextBotPlayer::IsBot */))(in_stack_00000008);
          uVar4 = uVar4 ^ 1;
        }
      }
    }
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSBotVision::IsLineOfFireClear
 * Address: 00769c60
 * ---------------------------------------- */

/* CINSBotVision::IsLineOfFireClear(Vector const&, Vector) */

undefined4 __cdecl
CINSBotVision::IsLineOfFireClear
          (int *param_1,float *param_2,float param_3,float param_4,float param_5)

{
  uint *puVar1;
  float *pfVar2;
  char cVar3;
  int iVar4;
  float fVar5;
  int iVar6;
  int *piVar7;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this;
  CTraceFilterSimple *this_00;
  CVisibilityBlockers *extraout_ECX_01;
  CVisibilityBlockers *this_01;
  CVisibilityBlockers *extraout_ECX_02;
  int unaff_EBX;
  int iVar8;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  Vector *pVVar13;
  Vector *pVVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  Vector local_10c [12];
  Vector local_100 [32];
  float local_e0;
  char local_d5;
  undefined4 local_c0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_9c;
  float local_98;
  float local_94;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_6c;
  undefined1 local_68;
  undefined1 local_67;
  int local_5c [4];
  int local_4c;
  undefined4 local_48;
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  int local_38;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x769c6b;
  __i686_get_pc_thunk_bx();
  iVar4 = (**(code **)(*param_1 + 0xc4))(param_1);
  if ((iVar4 == 0) || (iVar8 = iVar4 + -0x2060, iVar8 == 0)) {
    return 0;
  }
  pfVar2 = *(float **)(unaff_EBX + 0x43c961 /* &vec3_origin */);
  if (((*pfVar2 == param_3) && (pfVar2[1] == param_4)) && (pfVar2[2] == param_5)) {
    (**(code **)(*(int *)(iVar4 + -0x2060) + 0x20c))(&local_2c,iVar8);
    this = extraout_ECX_00;
  }
  else {
    local_2c = param_3;
    local_28 = param_4;
    local_24 = param_5;
    this = extraout_ECX;
  }
  local_c0 = 0;
  iVar4 = CBaseEntity::GetTeamNumber(this);
  uVar16 = 0;
  uVar15 = 0;
  iVar4 = (iVar4 == 2) + 2;
  CTraceFilterSimple::CTraceFilterSimple
            (this_00,(IHandleEntity *)local_5c,iVar8,(_func_bool_IHandleEntity_ptr_int *)0x0);
  local_4c = 0;
  local_48 = 0;
  fVar12 = local_2c - *param_2;
  local_44 = 0;
  fVar10 = local_28 - param_2[1];
  local_40 = 0;
  fVar11 = local_24 - param_2[2];
  local_3c = 0;
  piVar7 = (int *)(*(int **)(unaff_EBX + 0x43c8dd /* &bot_foliage_threshold */))[7];
  local_5c[0] = unaff_EBX + 0x42b785 /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */;
  local_38 = iVar4;
  if (piVar7 == *(int **)(unaff_EBX + 0x43c8dd /* &bot_foliage_threshold */)) {
    fVar5 = (float)((uint)piVar7 ^ piVar7[0xb]);
  }
  else {
    fVar9 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7,iVar8,uVar15,uVar16);
    fVar5 = (float)fVar9;
  }
  uVar15 = 0x2006241;
  local_68 = 1;
  local_9c = *param_2 - local_2c;
  local_6c = 0;
  local_ac = local_2c;
  local_a8 = local_28;
  local_98 = param_2[1] - local_28;
  if (SQRT(fVar10 * fVar10 + fVar12 * fVar12 + fVar11 * fVar11) < fVar5) {
    uVar15 = 0x2006041;
  }
  local_94 = param_2[2] - local_24;
  local_a4 = local_24;
  local_74 = 0;
  local_78 = 0;
  local_7c = 0;
  local_67 = local_98 * local_98 + local_9c * local_9c + local_94 * local_94 != 0.0;
  local_84 = 0;
  local_88 = 0;
  local_8c = 0;
  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x43cb0d /* &enginetrace */) + 0x14))
            ((int *)**(undefined4 **)(unaff_EBX + 0x43cb0d /* &enginetrace */),&local_ac,uVar15,local_5c,local_10c);
  piVar7 = *(int **)(unaff_EBX + 0x43cdd5 /* &r_visualizetraces */);
  iVar4 = (**(code **)(*piVar7 + 0x40))(piVar7);
  if (iVar4 != 0) {
    iVar4 = (**(code **)(*piVar7 + 0x40))(piVar7);
    fVar10 = 0.5;
    if (iVar4 != 0) {
      fVar10 = -1.0;
    }
    DebugDrawLine(local_10c,local_100,0xff,0,0,true,fVar10);
  }
  uVar15 = 0;
  if ((*(float *)(unaff_EBX + 0x14eea9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= local_e0) && (local_d5 == '\0')) {
    fVar10 = SQRT((local_28 - param_2[1]) * (local_28 - param_2[1]) +
                  (local_2c - *param_2) * (local_2c - *param_2) +
                  (local_24 - param_2[2]) * (local_24 - param_2[2]));
    if (*(float *)(unaff_EBX + 0x1bf55d /* typeinfo name for CTraceFilterIgnoreWeapons+0x3d */) <= fVar10 && fVar10 != *(float *)(unaff_EBX + 0x1bf55d /* typeinfo name for CTraceFilterIgnoreWeapons+0x3d */)) {
      iVar4 = *(int *)(unaff_EBX + 0x43cd09 /* &GCSDK::GetPchTempTextBuffer */);
      this_01 = *(CVisibilityBlockers **)(iVar4 + 0x100c);
      local_ac = (float)CONCAT31(local_ac._1_3_,this_01 != (CVisibilityBlockers *)0x0);
      if (this_01 != (CVisibilityBlockers *)0x0) {
        iVar8 = *(int *)(iVar4 + 0x19b8);
        iVar6 = ThreadGetCurrentId();
        this_01 = extraout_ECX_01;
        if (iVar8 == iVar6) {
          piVar7 = *(int **)(iVar4 + 0x1014);
          if (*piVar7 != unaff_EBX + 0x21d459 /* "CINSBotVision::IsLineOfFireClear - Smoke Check" */) {
            piVar7 = (int *)CVProfNode::GetSubNode
                                      ((char *)piVar7,unaff_EBX + 0x21d459 /* "CINSBotVision::IsLineOfFireClear - Smoke Check" */,(char *)0x0,
                                       unaff_EBX + 0x216ffb /* "INSNextBot" */);
            *(int **)(iVar4 + 0x1014) = piVar7;
          }
          puVar1 = (uint *)(*(int *)(iVar4 + 0x10a0) + piVar7[0x1c] * 8 + 4);
          *puVar1 = *puVar1 | 4;
          CVProfNode::EnterScope();
          *(undefined1 *)(iVar4 + 0x1010) = 0;
          this_01 = extraout_ECX_02;
        }
      }
      pVVar14 = (Vector *)&local_2c;
      pVVar13 = (Vector *)**(undefined4 **)(unaff_EBX + 0x43cb1d /* &g_VisibilityBlockers */);
      cVar3 = CVisibilityBlockers::DoesLineIntersectBlocker(this_01,pVVar13,pVVar14);
      if (cVar3 != '\0') {
        if ((local_ac._0_1_ != '\0') &&
           ((*(char *)(iVar4 + 0x1010) == '\0' || (*(int *)(iVar4 + 0x100c) != 0)))) {
          iVar8 = *(int *)(iVar4 + 0x19b8);
          iVar6 = ThreadGetCurrentId(pVVar13,pVVar14,param_2);
          if (iVar8 == iVar6) {
            cVar3 = CVProfNode::ExitScope();
            if (cVar3 == '\0') {
              iVar8 = *(int *)(iVar4 + 0x1014);
            }
            else {
              iVar8 = *(int *)(*(int *)(iVar4 + 0x1014) + 100);
              *(int *)(iVar4 + 0x1014) = iVar8;
            }
            *(bool *)(iVar4 + 0x1010) = iVar8 == iVar4 + 0x1018;
            uVar15 = 0;
            goto LAB_00769f02;
          }
        }
        uVar15 = 0;
        goto LAB_00769f02;
      }
      if ((local_ac._0_1_ != '\0') &&
         ((*(char *)(iVar4 + 0x1010) == '\0' || (*(int *)(iVar4 + 0x100c) != 0)))) {
        iVar8 = *(int *)(iVar4 + 0x19b8);
        iVar6 = ThreadGetCurrentId(pVVar13,pVVar14,param_2);
        if (iVar8 == iVar6) {
          cVar3 = CVProfNode::ExitScope();
          if (cVar3 == '\0') {
            iVar8 = *(int *)(iVar4 + 0x1014);
          }
          else {
            iVar8 = *(int *)(*(int *)(iVar4 + 0x1014) + 100);
            *(int *)(iVar4 + 0x1014) = iVar8;
          }
          *(bool *)(iVar4 + 0x1010) = iVar8 == iVar4 + 0x1018;
          uVar15 = 1;
          goto LAB_00769f02;
        }
      }
    }
    uVar15 = 1;
  }
LAB_00769f02:
  local_5c[0] = unaff_EBX + 0x42a90d /* vtable for INSVisionTraceFilter+0x8 */;
  local_40 = 0;
  if ((-1 < local_44) && (local_4c != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x43cc0d /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x43cc0d /* &GCSDK::GetPchTempTextBuffer */),local_4c);
  }
  return uVar15;
}



/* ----------------------------------------
 * CINSBotVision::IsLineOfSightClear
 * Address: 00768d70
 * ---------------------------------------- */

/* CINSBotVision::IsLineOfSightClear(Vector const&) const */

undefined4 __thiscall CINSBotVision::IsLineOfSightClear(CINSBotVision *this,Vector *param_1)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  int *piVar6;
  float *pfVar7;
  Vector *pVVar8;
  int iVar9;
  CTraceFilterSimple *this_00;
  CVisibilityBlockers *extraout_ECX;
  CVisibilityBlockers *this_01;
  CVProfScope *this_02;
  CVisibilityBlockers *extraout_ECX_00;
  int *piVar10;
  int unaff_EBX;
  float10 fVar11;
  float10 fVar12;
  float fVar13;
  Vector *in_stack_00000008;
  undefined4 uVar14;
  undefined4 uVar15;
  CGameTrace local_bc [44];
  float local_90;
  char local_85;
  undefined4 local_70;
  int local_5c [4];
  int local_4c;
  undefined4 local_48;
  int local_44;
  undefined4 local_40;
  undefined4 local_3c;
  float local_2c;
  float local_28;
  float local_24;
  undefined1 local_1d;
  
  piVar5 = (int *)__i686_get_pc_thunk_bx();
  piVar5 = (int *)(**(code **)(*piVar5 + 0xc4))(piVar5);
  if (piVar5 == (int *)0x0) {
    return 0;
  }
  piVar10 = piVar5 + -0x818;
  if (piVar10 == (int *)0x0) {
    return 0;
  }
  cVar4 = (**(code **)(piVar5[-0x818] + 0x118))(piVar10);
  if (cVar4 == '\0') {
    return 0;
  }
  piVar6 = (int *)(**(code **)(piVar5[-0x818] + 0x970))(piVar10);
  pfVar7 = (float *)(**(code **)(*piVar6 + 0xcc))(piVar6);
  local_2c = *pfVar7;
  local_28 = pfVar7[1];
  local_24 = pfVar7[2];
  fVar11 = (float10)(**(code **)(piVar5[-0x818] + 0x420))(piVar10,in_stack_00000008);
  if (*(double *)(unaff_EBX + 0x1e39d4 /* typeinfo name for CEntityFactory<CBaseFlex>+0x24 */) <= (double)(float)fVar11) {
    return 0;
  }
  local_70 = 0;
  uVar15 = 0;
  uVar14 = 0;
  CTraceFilterSimple::CTraceFilterSimple
            (this_00,(IHandleEntity *)local_5c,(int)piVar10,(_func_bool_IHandleEntity_ptr_int *)0x0)
  ;
  local_5c[0] = unaff_EBX + 0x42b80c /* vtable for INSVisionTraceFilterIgnorePlayers+0x8 */;
  local_4c = 0;
  local_48 = 0;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  fVar11 = (float10)(**(code **)(*piVar5 + 0x134))(piVar5,in_stack_00000008,uVar14,uVar15);
  piVar5 = (int *)(*(int **)(unaff_EBX + 0x43d7c4 /* &bot_foliage_threshold */))[7];
  if (piVar5 == *(int **)(unaff_EBX + 0x43d7c4 /* &bot_foliage_threshold */)) {
    fVar13 = (float)((uint)piVar5 ^ piVar5[0xb]);
  }
  else {
    fVar12 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
    fVar13 = (float)fVar12;
  }
  pVVar8 = (Vector *)0x2006241;
  if ((float)fVar11 < fVar13) {
    pVVar8 = (Vector *)0x2006041;
  }
  UTIL_TraceLine((Vector *)&local_2c,in_stack_00000008,(uint)pVVar8,(ITraceFilter *)local_5c,
                 local_bc);
  uVar14 = 0;
  if ((*(float *)(unaff_EBX + 0x14fd90 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= local_90) && (local_85 == '\0')) {
    fVar13 = SQRT((local_28 - *(float *)(in_stack_00000008 + 4)) *
                  (local_28 - *(float *)(in_stack_00000008 + 4)) +
                  (local_2c - *(float *)in_stack_00000008) *
                  (local_2c - *(float *)in_stack_00000008) +
                  (local_24 - *(float *)(in_stack_00000008 + 8)) *
                  (local_24 - *(float *)(in_stack_00000008 + 8)));
    if (*(float *)(unaff_EBX + 0x1c0444 /* typeinfo name for CTraceFilterIgnoreWeapons+0x3d */) <= fVar13 && fVar13 != *(float *)(unaff_EBX + 0x1c0444 /* typeinfo name for CTraceFilterIgnoreWeapons+0x3d */)) {
      iVar2 = *(int *)(unaff_EBX + 0x43dbf0 /* &GCSDK::GetPchTempTextBuffer */);
      this_01 = *(CVisibilityBlockers **)(iVar2 + 0x100c);
      local_1d = this_01 != (CVisibilityBlockers *)0x0;
      if (((bool)local_1d) &&
         (iVar3 = *(int *)(iVar2 + 0x19b8), iVar9 = ThreadGetCurrentId(), this_01 = extraout_ECX,
         iVar3 == iVar9)) {
        piVar5 = *(int **)(iVar2 + 0x1014);
        if (*piVar5 != unaff_EBX + 0x21e308 /* "CINSBotVision::IsLineOfSightClearToEntity - Smoke Check" */) {
          piVar5 = (int *)CVProfNode::GetSubNode
                                    ((char *)piVar5,unaff_EBX + 0x21e308 /* "CINSBotVision::IsLineOfSightClearToEntity - Smoke Check" */,(char *)0x0,
                                     unaff_EBX + 0x217ee2 /* "INSNextBot" */);
          *(int **)(iVar2 + 0x1014) = piVar5;
        }
        puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar5[0x1c] * 8 + 4);
        *puVar1 = *puVar1 | 4;
        CVProfNode::EnterScope();
        *(undefined1 *)(iVar2 + 0x1010) = 0;
        this_01 = extraout_ECX_00;
      }
      cVar4 = CVisibilityBlockers::DoesLineIntersectBlocker
                        (this_01,(Vector *)**(undefined4 **)(unaff_EBX + 0x43da04 /* &g_VisibilityBlockers */),
                         (Vector *)&local_2c);
      if (cVar4 != '\0') {
        CVProfScope::~CVProfScope(this_02);
        uVar14 = 0;
        pVVar8 = in_stack_00000008;
        goto LAB_00769022;
      }
      CVProfScope::~CVProfScope(this_02);
      pVVar8 = in_stack_00000008;
    }
    uVar14 = 1;
  }
LAB_00769022:
  local_5c[0] = unaff_EBX + 0x42b7f4 /* vtable for INSVisionTraceFilter+0x8 */;
  local_40 = 0;
  if ((-1 < local_44) && (local_4c != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x43daf4 /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x43daf4 /* &GCSDK::GetPchTempTextBuffer */),local_4c,pVVar8);
  }
  return uVar14;
}



/* ----------------------------------------
 * CINSBotVision::IsLineOfSightClearToEntity
 * Address: 00768520
 * ---------------------------------------- */

/* CINSBotVision::IsLineOfSightClearToEntity(CBaseEntity const*, Vector*) const */

undefined4 __thiscall
CINSBotVision::IsLineOfSightClearToEntity(CINSBotVision *this,CBaseEntity *param_1,Vector *param_2)

{
  uint *puVar1;
  int iVar2;
  code *pcVar3;
  float *pfVar4;
  char cVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int unaff_EBX;
  undefined4 uVar9;
  float10 fVar10;
  float *in_stack_0000000c;
  Vector *pVVar11;
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x76852b;
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x43e449 /* &GCSDK::GetPchTempTextBuffer */);
  local_1d = *(int *)(iVar2 + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar7 = *(int *)(iVar2 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar7 == iVar6)) {
    piVar8 = *(int **)(iVar2 + 0x1014);
    if (*piVar8 != unaff_EBX + 0x21eae5 /* "CINSBotVision::IsLineOfSightClearToEntity" */) {
      piVar8 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar8,unaff_EBX + 0x21eae5 /* "CINSBotVision::IsLineOfSightClearToEntity" */,(char *)0x0,
                                 (int)(&UNK_0021873b + unaff_EBX));
      *(int **)(iVar2 + 0x1014) = piVar8;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar8[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
  }
  if (param_2 != (Vector *)0x0) {
    cVar5 = (**(code **)(*(int *)param_2 + 0x158 /* CBasePlayer::IsPlayer */))(param_2);
    if (cVar5 == '\0') {
      param_2 = (Vector *)0x0;
    }
    iVar7 = (**(code **)(*(int *)param_1 + 0xc4))(param_1);
    if ((((iVar7 != 0) && (piVar8 = (int *)(iVar7 + -0x2060), piVar8 != (int *)0x0)) &&
        (param_2 != (Vector *)0x0)) &&
       (cVar5 = (**(code **)(*piVar8 + 0x118))(piVar8), cVar5 != '\0')) {
      pcVar3 = *(code **)(*piVar8 + 0x420);
      uVar9 = (**(code **)(*(int *)param_2 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_2);
      fVar10 = (float10)(*pcVar3)(piVar8,uVar9);
      uVar9 = 0;
      if (*(double *)(unaff_EBX + 0x1e422d /* typeinfo name for CEntityFactory<CBaseFlex>+0x24 */) <= (double)(float)fVar10) goto LAB_007685a3;
      pVVar11 = param_2;
      CINSNextBot::GetEntityViewPosition((CBaseEntity *)&local_2c);
      pfVar4 = *(float **)(unaff_EBX + 0x43e0a1 /* &vec3_origin */);
      if ((((local_2c != *pfVar4) || (pfVar4[1] != local_28)) || (pfVar4[2] != local_24)) &&
         (cVar5 = (**(code **)(*(int *)param_1 + 0x110))(param_1,param_2,pVVar11), cVar5 != '\0')) {
        uVar9 = 1;
        if (in_stack_0000000c != (float *)0x0) {
          *in_stack_0000000c = local_2c;
          in_stack_0000000c[1] = local_28;
          in_stack_0000000c[2] = local_24;
        }
        goto LAB_007685a3;
      }
    }
  }
  uVar9 = 0;
LAB_007685a3:
  if (((local_1d != '\0') &&
      ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) &&
     (iVar7 = *(int *)(iVar2 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar7 == iVar6)) {
    cVar5 = CVProfNode::ExitScope();
    iVar7 = *(int *)(iVar2 + 0x1014);
    if (cVar5 != '\0') {
      iVar7 = *(int *)(iVar7 + 100);
      *(int *)(iVar2 + 0x1014) = iVar7;
    }
    *(bool *)(iVar2 + 0x1010) = iVar7 == iVar2 + 0x1018;
    return uVar9;
  }
  return uVar9;
}



/* ----------------------------------------
 * CINSBotVision::IsVisibleEntityNoticed
 * Address: 00769ae0
 * ---------------------------------------- */

/* CINSBotVision::IsVisibleEntityNoticed(CBaseEntity*) const */

bool __cdecl CINSBotVision::IsVisibleEntityNoticed(CBaseEntity *param_1)

{
  bool bVar1;
  int iVar2;
  CINSBotVision *this;
  float10 fVar3;
  
  __i686_get_pc_thunk_bx();
  fVar3 = (float10)CountdownTimer::Now();
  bVar1 = false;
  if (*(float *)(param_1 + 0x16c) <= (float)fVar3 && (float)fVar3 != *(float *)(param_1 + 0x16c)) {
    iVar2 = TheINSNextBots();
    bVar1 = true;
    if (*(char *)(iVar2 + 0x129) != '\0') {
      iVar2 = GetSilhouetteType(this,param_1);
      return iVar2 != 0;
    }
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSBotVision::OnBlinded
 * Address: 00768070
 * ---------------------------------------- */

/* CINSBotVision::OnBlinded(CBaseEntity*, bool) */

void __thiscall CINSBotVision::OnBlinded(CINSBotVision *this,CBaseEntity *param_1,bool param_2)

{
  CBaseEntity *pCVar1;
  float fVar2;
  int *piVar3;
  char cVar4;
  int *piVar5;
  int unaff_EBX;
  float10 fVar6;
  undefined3 in_stack_00000009;
  char in_stack_0000000c;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  piVar5 = (int *)(*(int **)(unaff_EBX + 0x43f08d /* &ins_bot_flashbang_effect_max_time */))[7];
  if (piVar5 == *(int **)(unaff_EBX + 0x43f08d /* &ins_bot_flashbang_effect_max_time */)) {
    local_24 = (float)((uint)piVar5 ^ piVar5[0xb]);
  }
  else {
    fVar6 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
    local_24 = (float)fVar6;
  }
  local_20 = *(float *)(unaff_EBX + 0x1bc6dd /* typeinfo name for CBaseGameSystem+0x1e */);
  if (in_stack_0000000c == '\0') goto LAB_007680c6;
  piVar5 = (int *)(**(code **)(*(int *)param_1 + 0xc4))(param_1);
  fVar6 = (float10)(**(code **)(*piVar5 + 0x130))(piVar5,_param_2);
  piVar5 = *(int **)(unaff_EBX + 0x43e521 /* &ins_bot_flashbang_effect_max_distance */);
  fVar2 = (float)fVar6;
  piVar3 = (int *)piVar5[7];
  if (piVar3 == piVar5) {
    local_20 = (float)(piVar5[0xb] ^ (uint)piVar5);
  }
  else {
    fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
    local_20 = (float)fVar6;
  }
  local_20 = local_20 * *(float *)(unaff_EBX + 0x1bba11 /* typeinfo name for ISaveRestoreOps+0x67 */);
  cVar4 = (**(code **)(*(int *)param_1 + 0x118))(param_1,_param_2);
  if (cVar4 == '\0') {
    if (local_20 <= fVar2) {
      local_20 = *(float *)(unaff_EBX + 0x150aa1 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */);
    }
    else {
      local_20 = (fVar2 * local_24) / local_20;
LAB_00768205:
      local_20 = local_24 - local_20;
      if (local_20 <= 0.0) {
        local_20 = *(float *)(unaff_EBX + 0x150aa1 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */);
        goto LAB_007680c6;
      }
    }
  }
  else {
    if (local_20 < fVar2) {
      piVar5 = *(int **)(unaff_EBX + 0x43e521 /* &ins_bot_flashbang_effect_max_distance */);
      piVar3 = (int *)piVar5[7];
      if (piVar3 == piVar5) {
        local_20 = (float)(piVar5[0xb] ^ (uint)piVar5);
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
        local_20 = (float)fVar6;
      }
      local_20 = (local_24 * fVar2) / local_20;
      goto LAB_00768205;
    }
    local_20 = *(float *)(unaff_EBX + 0x150aa1 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x3c */);
  }
  if (local_24 <= local_20) {
    local_20 = local_24;
  }
LAB_007680c6:
  pCVar1 = param_1 + 0x164;
  if (*(int *)(param_1 + 0x16c) != -0x40800000) {
    (**(code **)(*(int *)(param_1 + 0x164) + 4))(pCVar1,param_1 + 0x16c);
    *(undefined4 *)(param_1 + 0x16c) = 0xbf800000;
  }
  fVar6 = (float10)CountdownTimer::Now();
  if (*(float *)(param_1 + 0x16c) != (float)fVar6 + local_20) {
    (**(code **)(*(int *)(param_1 + 0x164) + 4))(pCVar1,param_1 + 0x16c);
    *(float *)(param_1 + 0x16c) = (float)fVar6 + local_20;
  }
  if (*(float *)(param_1 + 0x168) != local_20) {
    (**(code **)(*(int *)(param_1 + 0x164) + 4))(pCVar1,param_1 + 0x168);
    *(float *)(param_1 + 0x168) = local_20;
  }
  return;
}



/* ----------------------------------------
 * CINSBotVision::Reset
 * Address: 00767b80
 * ---------------------------------------- */

/* CINSBotVision::Reset() */

void __thiscall CINSBotVision::Reset(CINSBotVision *this)

{
  code *pcVar1;
  IVision *this_00;
  int unaff_EBX;
  float10 fVar2;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  IVision::Reset(this_00);
  pcVar1 = *(code **)(*in_stack_00000004 + 0x124);
  fVar2 = (float10)(**(code **)(*in_stack_00000004 + 0x11c))(in_stack_00000004);
  (*pcVar1)(in_stack_00000004,(float)fVar2);
  in_stack_00000004[0x96] = *(int *)(**(int **)(unaff_EBX + 0x43ed12 /* &gpGlobals */) + 0xc);
  return;
}



/* ----------------------------------------
 * CINSBotVision::UpdatePotentiallyVisibleNPCVector
 * Address: 0076b8b0
 * ---------------------------------------- */

/* CINSBotVision::UpdatePotentiallyVisibleNPCVector() */

void __thiscall CINSBotVision::UpdatePotentiallyVisibleNPCVector(CINSBotVision *this)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int iVar6;
  int *piVar7;
  CUtlVector<CHandle<CBaseEntity>,CUtlMemory<CHandle<CBaseEntity>,int>> *this_00;
  CINSNextBotManager *this_01;
  int unaff_EBX;
  int iVar8;
  float10 fVar9;
  float fVar10;
  int in_stack_00000004;
  uint local_2c [2];
  undefined4 local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x76b8bb;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bool)local_1d) {
    iVar8 = *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar3 = ThreadGetCurrentId();
    if (iVar8 == iVar3) {
      piVar7 = *(int **)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar7 != unaff_EBX + 0x21b8bd /* "CINSBotVision::UpdatePotentiallyVisibleNPCVector" */) {
        piVar7 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar7,unaff_EBX + 0x21b8bd /* "CINSBotVision::UpdatePotentiallyVisibleNPCVector" */,(char *)0x0,
                                   unaff_EBX + 0x2153ab /* "INSNextBot" */);
        *(int **)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar7;
      }
      puVar1 = (uint *)(piVar7[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
    }
  }
  iVar8 = in_stack_00000004 + 0x158;
  iVar3 = iVar8;
  fVar9 = (float10)CountdownTimer::Now();
  if (*(float *)(in_stack_00000004 + 0x160) <= (float)fVar9 &&
      (float)fVar9 != *(float *)(in_stack_00000004 + 0x160)) {
    fVar9 = (float10)CountdownTimer::Now();
    fVar10 = (float)fVar9 + *(float *)(unaff_EBX + 0x1b81d1 /* typeinfo name for ISaveRestoreOps+0x67 */);
    if (*(float *)(in_stack_00000004 + 0x160) != fVar10) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x158) + 4))(iVar8,in_stack_00000004 + 0x160);
      *(float *)(in_stack_00000004 + 0x160) = fVar10;
    }
    if (*(int *)(in_stack_00000004 + 0x15c) != 0x3e800000) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x158) + 4))(iVar8,in_stack_00000004 + 0x15c);
      *(undefined4 *)(in_stack_00000004 + 0x15c) = 0x3e800000;
    }
    *(undefined4 *)(in_stack_00000004 + 0x150) = 0;
    iVar8 = 0;
    while( true ) {
      iVar3 = TheINSNextBots();
      iVar6 = CINSNextBotManager::GetTotalThrownGrenades(this_01);
      if (iVar6 <= iVar8) break;
      uVar4 = TheINSNextBots();
      iVar3 = iVar8;
      CINSNextBotManager::GetThrownGrenade((int)local_2c);
      if (((local_2c[0] != 0xffffffff) &&
          (iVar6 = **(int **)(unaff_EBX + 0x43af1d /* &g_pEntityList */) + (local_2c[0] & 0xffff) * 0x18,
          *(uint *)(iVar6 + 8) == local_2c[0] >> 0x10)) &&
         (piVar7 = *(int **)(iVar6 + 4), piVar7 != (int *)0x0)) {
        local_24 = 0xffffffff;
        puVar5 = (undefined4 *)(**(code **)(*piVar7 + 0xc))(piVar7,uVar4,iVar3);
        local_24 = *puVar5;
        CUtlVector<CHandle<CBaseEntity>,CUtlMemory<CHandle<CBaseEntity>,int>>::InsertBefore
                  (this_00,in_stack_00000004 + 0x144,*(CHandle **)(in_stack_00000004 + 0x150));
      }
      iVar8 = iVar8 + 1;
    }
  }
  if ((local_1d != '\0') &&
     ((*(char *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)))) {
    iVar8 = *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar3 = ThreadGetCurrentId(iVar3);
    if (iVar8 == iVar3) {
      cVar2 = CVProfNode::ExitScope();
      iVar8 = *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (cVar2 != '\0') {
        iVar8 = *(int *)(iVar8 + 100);
        *(int *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar8;
      }
      *(bool *)(*(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
           iVar8 == *(int *)(unaff_EBX + 0x43b0b9 /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotVision::UpdateSilhouettes
 * Address: 0076a230
 * ---------------------------------------- */

/* CINSBotVision::UpdateSilhouettes() */

void __thiscall CINSBotVision::UpdateSilhouettes(CINSBotVision *this)

{
  code *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  CBaseEntity *pCVar9;
  int *piVar10;
  uint uVar11;
  int iVar12;
  undefined4 uVar13;
  float fVar14;
  CINSRules *this_00;
  CINSRules *this_01;
  uint uVar15;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CINSBotVision *this_04;
  uint uVar16;
  int unaff_EBX;
  uint uVar17;
  bool bVar18;
  float10 fVar19;
  CBaseEntity *in_stack_00000004;
  CBaseEntity *pCVar20;
  
  __i686_get_pc_thunk_bx();
  fVar19 = (float10)CountdownTimer::Now();
  if ((float)fVar19 < *(float *)(in_stack_00000004 + 0x184) ||
      (float)fVar19 == *(float *)(in_stack_00000004 + 0x184)) {
    return;
  }
  iVar6 = (**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
  if (iVar6 == 0) {
    return;
  }
  piVar10 = *(int **)(&DAT_0043c6bd + unaff_EBX);
  pCVar20 = (CBaseEntity *)0x4;
  cVar5 = CINSRules::IsGameState(this_00,*piVar10);
  if (cVar5 == '\0') {
    pCVar20 = (CBaseEntity *)0x3;
    cVar5 = CINSRules::IsGameState(this_01,*piVar10);
    if (cVar5 == '\0') {
      return;
    }
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004,pCVar20);
    iVar6 = (**(code **)(*piVar7 + 200))(piVar7);
    iVar8 = 0;
    if (*(int *)(iVar6 + 0x20) != 0) {
      iVar8 = *(int *)(iVar6 + 0x20) - *(int *)(**(int **)(&DAT_0043c665 + unaff_EBX) + 0x5c) >> 4;
    }
    pCVar9 = (CBaseEntity *)UTIL_PlayerByIndex(iVar8);
    if (((pCVar9 != (CBaseEntity *)0x0) &&
        (cVar5 = (**(code **)(*(int *)pCVar9 + 0x158 /* CBasePlayer::IsPlayer */))(pCVar9), cVar5 != '\0')) &&
       (cVar5 = (**(code **)(*(int *)*piVar10 + 0x3a8))((int *)*piVar10,pCVar9), pCVar20 = pCVar9,
       cVar5 == '\0')) {
      return;
    }
  }
  piVar10 = (int *)(*(int **)(unaff_EBX + 0x43c3c1 /* &bot_silhouette_scan_frequency */))[7];
  if (piVar10 == *(int **)(unaff_EBX + 0x43c3c1 /* &bot_silhouette_scan_frequency */)) {
    fVar14 = (float)((uint)piVar10 ^ piVar10[0xb]);
  }
  else {
    fVar19 = (float10)(**(code **)(*piVar10 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar10,pCVar20);
    fVar14 = (float)fVar19;
  }
  fVar19 = (float10)CountdownTimer::Now();
  if (*(float *)(in_stack_00000004 + 0x184) != (float)fVar19 + fVar14) {
    pCVar20 = in_stack_00000004 + 0x184;
    (**(code **)(*(int *)(in_stack_00000004 + 0x17c) + 4))(in_stack_00000004 + 0x17c,pCVar20);
    *(float *)(in_stack_00000004 + 0x184) = (float)fVar19 + fVar14;
  }
  if (*(float *)(in_stack_00000004 + 0x180) != fVar14) {
    pCVar20 = in_stack_00000004 + 0x180;
    (**(code **)(*(int *)(in_stack_00000004 + 0x17c) + 4))(in_stack_00000004 + 0x17c,pCVar20);
    *(float *)(in_stack_00000004 + 0x180) = fVar14;
  }
  piVar10 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0xc4))(in_stack_00000004);
  iVar6 = (**(code **)(*piVar10 + 200))(piVar10);
  iVar8 = 0;
  if (*(int *)(iVar6 + 0x20) != 0) {
    iVar8 = *(int *)(iVar6 + 0x20) - *(int *)(**(int **)(&DAT_0043c665 + unaff_EBX) + 0x5c) >> 4;
  }
  piVar10 = (int *)UTIL_PlayerByIndex(iVar8);
  if ((piVar10 != (int *)0x0) && (iVar6 = (**(code **)(*piVar10 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar10), iVar6 != 0)) {
    iVar6 = TheINSNextBots();
    iVar8 = 1;
    if (*(char *)(iVar6 + 0x129) == '\0') {
      uVar15 = -(((uint)(in_stack_00000004 + 0x198) & 0xf) >> 2) & 3;
      if (uVar15 == 0) {
        iVar6 = 0x30;
        uVar11 = 1;
      }
      else {
        uVar17 = 1;
        do {
          *(undefined4 *)(in_stack_00000004 + uVar17 * 4 + 0x194) = 2;
          uVar11 = uVar17 + 1;
          iVar6 = 0x31 - uVar11;
          bVar18 = uVar17 < uVar15;
          uVar17 = uVar11;
        } while (bVar18);
      }
      uVar17 = 0x30 - uVar15 >> 2;
      if (uVar17 != 0) {
        uVar13 = *(undefined4 *)(unaff_EBX + 0x21cfe5 /* typeinfo name for CINSThreatAssessment+0x24 */);
        uVar2 = *(undefined4 *)(unaff_EBX + 0x21cfe9 /* typeinfo name for CINSThreatAssessment+0x28 */);
        uVar3 = *(undefined4 *)(unaff_EBX + 0x21cfed /* typeinfo name for CINSThreatAssessment+0x2c */);
        uVar4 = *(undefined4 *)(unaff_EBX + 0x21cff1 /* typeinfo name for CINSThreatAssessment+0x30 */);
        pCVar20 = in_stack_00000004 + uVar15 * 4 + 0x198;
        uVar16 = 0;
        do {
          uVar16 = uVar16 + 1;
          *(undefined4 *)pCVar20 = uVar13;
          *(undefined4 *)(pCVar20 + 4) = uVar2;
          *(undefined4 *)(pCVar20 + 8) = uVar3;
          *(undefined4 *)(pCVar20 + 0xc) = uVar4;
          pCVar20 = pCVar20 + 0x10;
        } while (uVar16 < uVar17);
        uVar11 = uVar11 + uVar17 * 4;
        iVar6 = iVar6 + uVar17 * -4;
        if (uVar17 * 4 == 0x30 - uVar15) {
          return;
        }
      }
      iVar8 = 0;
      do {
        *(undefined4 *)(in_stack_00000004 + iVar8 + uVar11 * 4 + 0x194) = 2;
        iVar8 = iVar8 + 4;
      } while (iVar8 != iVar6 * 4);
    }
    else {
      do {
        pCVar9 = (CBaseEntity *)UTIL_PlayerByIndex(iVar8);
        if (((pCVar9 == (CBaseEntity *)0x0) ||
            (cVar5 = (**(code **)(*(int *)pCVar9 + 0x118 /* CBaseEntity::IsAlive */))(pCVar9,pCVar20), cVar5 == '\0')) ||
           (iVar6 = (**(code **)(*(int *)pCVar9 + 0x548 /* CINSNextBot::GetLastKnownArea */))(pCVar9), iVar6 == 0)) {
          pCVar9 = pCVar20;
          *(undefined4 *)(in_stack_00000004 + iVar8 * 4 + 0x194) = 0xffffffff;
        }
        else {
          iVar6 = CBaseEntity::GetTeamNumber(this_02);
          iVar12 = CBaseEntity::GetTeamNumber(this_03);
          if (iVar6 == iVar12) {
            *(undefined4 *)(in_stack_00000004 + iVar8 * 4 + 0x194) = 2;
            pCVar9 = pCVar20;
          }
          else {
            piVar7 = (int *)(**(code **)(*piVar10 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar10);
            pcVar1 = *(code **)(*piVar7 + 0x84);
            pCVar20 = (CBaseEntity *)(**(code **)(*(int *)pCVar9 + 0x548 /* CINSNextBot::GetLastKnownArea */))(pCVar9);
            cVar5 = (*pcVar1)(piVar7);
            if (cVar5 == '\0') {
              *(undefined4 *)(in_stack_00000004 + iVar8 * 4 + 0x194) = 0xffffffff;
              pCVar9 = pCVar20;
            }
            else {
              uVar13 = GetSilhouetteType(this_04,in_stack_00000004);
              *(undefined4 *)(in_stack_00000004 + iVar8 * 4 + 0x194) = uVar13;
            }
          }
        }
        iVar8 = iVar8 + 1;
        pCVar20 = pCVar9;
      } while (iVar8 != 0x31);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotVision::~CINSBotVision
 * Address: 0076cc00
 * ---------------------------------------- */

/* CINSBotVision::~CINSBotVision() */

void __thiscall CINSBotVision::~CINSBotVision(CINSBotVision *this)

{
  undefined4 uVar1;
  int unaff_EBX;
  int iVar2;
  int iVar3;
  CUtlMemory<CHandle<CBaseEntity>,int> *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(in_stack_00000004 + 0x150) = 0;
  *(int *)in_stack_00000004 = unaff_EBX + 0x4306fd /* vtable for CINSBotVision+0x8 */;
  if (*(int *)(in_stack_00000004 + 0x14c) < 0) {
    uVar1 = *(undefined4 *)(in_stack_00000004 + 0x144);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x144) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(&DAT_00439c6d + unaff_EBX) + 8))
                ((int *)**(undefined4 **)(&DAT_00439c6d + unaff_EBX),
                 *(int *)(in_stack_00000004 + 0x144));
      *(undefined4 *)(in_stack_00000004 + 0x144) = 0;
    }
    uVar1 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x148) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x154) = uVar1;
  CUtlMemory<CHandle<CBaseEntity>,int>::~CUtlMemory(in_stack_00000004);
  *(int *)in_stack_00000004 = *(int *)(&DAT_00439ead + unaff_EBX) + 8;
  iVar2 = *(int *)(in_stack_00000004 + 0x34) + -1;
  iVar3 = iVar2 * 0x54;
  for (; -1 < iVar2; iVar2 = iVar2 + -1) {
    (*(code *)**(undefined4 **)(*(int *)(in_stack_00000004 + 0x28) + iVar3))
              ((undefined4 *)(*(int *)(in_stack_00000004 + 0x28) + iVar3));
    iVar3 = iVar3 + -0x54;
  }
  *(undefined4 *)(in_stack_00000004 + 0x34) = 0;
  if (*(int *)(in_stack_00000004 + 0x30) < 0) {
    *(undefined4 *)(in_stack_00000004 + 0x38) = *(undefined4 *)(in_stack_00000004 + 0x28);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x28) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(&DAT_00439c6d + unaff_EBX) + 8))
                ((int *)**(undefined4 **)(&DAT_00439c6d + unaff_EBX),
                 *(int *)(in_stack_00000004 + 0x28));
      *(undefined4 *)(in_stack_00000004 + 0x28) = 0;
    }
    *(undefined4 *)(in_stack_00000004 + 0x2c) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x38) = 0;
  }
  *(int *)in_stack_00000004 = unaff_EBX + 0x3bc3fd /* vtable for INextBotEventResponder+0x8 */;
  operator_delete(in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSBotVision::~CINSBotVision
 * Address: 0076cdc0
 * ---------------------------------------- */

/* CINSBotVision::~CINSBotVision() */

void __thiscall CINSBotVision::~CINSBotVision(CINSBotVision *this)

{
  undefined4 uVar1;
  int unaff_EBX;
  int iVar2;
  int iVar3;
  CUtlMemory<CHandle<CBaseEntity>,int> *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(in_stack_00000004 + 0x150) = 0;
  *(int *)in_stack_00000004 = unaff_EBX + 0x43053d /* vtable for CINSBotVision+0x8 */;
  if (*(int *)(in_stack_00000004 + 0x14c) < 0) {
    uVar1 = *(undefined4 *)(in_stack_00000004 + 0x144);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x144) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x439aad /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x439aad /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x144))
      ;
      *(undefined4 *)(in_stack_00000004 + 0x144) = 0;
    }
    uVar1 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x148) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x154) = uVar1;
  CUtlMemory<CHandle<CBaseEntity>,int>::~CUtlMemory(in_stack_00000004);
  *(int *)in_stack_00000004 = *(int *)(&DAT_00439ced + unaff_EBX) + 8;
  iVar2 = *(int *)(in_stack_00000004 + 0x34) + -1;
  iVar3 = iVar2 * 0x54;
  for (; -1 < iVar2; iVar2 = iVar2 + -1) {
    (*(code *)**(undefined4 **)(*(int *)(in_stack_00000004 + 0x28) + iVar3))
              ((undefined4 *)(*(int *)(in_stack_00000004 + 0x28) + iVar3));
    iVar3 = iVar3 + -0x54;
  }
  *(undefined4 *)(in_stack_00000004 + 0x34) = 0;
  if (*(int *)(in_stack_00000004 + 0x30) < 0) {
    *(undefined4 *)(in_stack_00000004 + 0x38) = *(undefined4 *)(in_stack_00000004 + 0x28);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x28) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x439aad /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x439aad /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x28));
      *(undefined4 *)(in_stack_00000004 + 0x28) = 0;
    }
    *(undefined4 *)(in_stack_00000004 + 0x2c) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x38) = 0;
  }
  *(undefined **)in_stack_00000004 = &UNK_003bc23d + unaff_EBX;
  return;
}



