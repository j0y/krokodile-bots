/*
 * CINSNextBotManager -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSNextBotManager::CINSNextBotManager
 * Address: 00764ee0
 * ---------------------------------------- */

/* CINSNextBotManager::CINSNextBotManager() */

void __thiscall CINSNextBotManager::CINSNextBotManager(CINSNextBotManager *this)

{
  int *piVar1;
  int iVar2;
  code *pcVar3;
  int *piVar4;
  NextBotManager *this_00;
  int *piVar5;
  int *piVar6;
  int unaff_EBX;
  int *piVar7;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  NextBotManager::NextBotManager(this_00);
  *in_stack_00000004 = unaff_EBX + 0x43839d /* vtable for CINSNextBotManager+0x8 */ /* vtable for CINSNextBotManager+0x8 */;
  in_stack_00000004[0x14] = unaff_EBX + 0x4383e9 /* vtable for CINSNextBotManager+0x54 */ /* vtable for CINSNextBotManager+0x54 */;
  iVar2 = unaff_EBX + 0x3c32cd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  *(undefined1 *)(in_stack_00000004 + 0x16) = 0;
  in_stack_00000004[0x15] = 0x2a;
  in_stack_00000004[0x17] = 0;
  in_stack_00000004[0x18] = 0;
  in_stack_00000004[0x19] = 0;
  in_stack_00000004[0x1a] = 0;
  in_stack_00000004[0x1b] = 0;
  in_stack_00000004[0x1c] = 0;
  in_stack_00000004[0x1d] = 0;
  in_stack_00000004[0x1e] = 0;
  in_stack_00000004[0x1f] = 0;
  in_stack_00000004[0x20] = 0;
  in_stack_00000004[0x21] = 0;
  in_stack_00000004[0x22] = 0;
  in_stack_00000004[0x23] = 0;
  in_stack_00000004[0x24] = 0;
  in_stack_00000004[0x25] = 0;
  piVar5 = in_stack_00000004 + 0x26;
  in_stack_00000004[0x26] = iVar2;
  pcVar3 = (code *)(unaff_EBX + -0x53477b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[0x27] = 0;
  (*pcVar3)(piVar5,in_stack_00000004 + 0x27);
  in_stack_00000004[0x28] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x26] + 4))(piVar5,in_stack_00000004 + 0x28);
  piVar4 = in_stack_00000004 + 0x29;
  in_stack_00000004[0x2a] = 0;
  in_stack_00000004[0x29] = iVar2;
  (*pcVar3)(piVar4,in_stack_00000004 + 0x2a);
  in_stack_00000004[0x2b] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x29] + 4))(piVar4,in_stack_00000004 + 0x2b);
  in_stack_00000004[0x2d] = 0;
  in_stack_00000004[0x2c] = iVar2;
  (*pcVar3)(in_stack_00000004 + 0x2c,in_stack_00000004 + 0x2d);
  in_stack_00000004[0x2e] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x2c] + 4))(in_stack_00000004 + 0x2c,in_stack_00000004 + 0x2e);
  in_stack_00000004[0x33] = 0;
  in_stack_00000004[0x32] = iVar2;
  (*pcVar3)(in_stack_00000004 + 0x32,in_stack_00000004 + 0x33);
  in_stack_00000004[0x34] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x32] + 4))(in_stack_00000004 + 0x32,in_stack_00000004 + 0x34);
  in_stack_00000004[0x36] = 0;
  in_stack_00000004[0x35] = iVar2;
  (*pcVar3)(in_stack_00000004 + 0x35,in_stack_00000004 + 0x36);
  in_stack_00000004[0x37] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x35] + 4))(in_stack_00000004 + 0x35,in_stack_00000004 + 0x37);
  in_stack_00000004[0x3a] = 0;
  in_stack_00000004[0x3b] = 0;
  in_stack_00000004[0x3c] = 0;
  in_stack_00000004[0x3d] = 0;
  in_stack_00000004[0x3e] = 0;
  in_stack_00000004[0x3f] = 0;
  in_stack_00000004[0x40] = 0;
  in_stack_00000004[0x41] = 0;
  in_stack_00000004[0x42] = 0;
  in_stack_00000004[0x43] = 0;
  piVar6 = in_stack_00000004 + 0x44;
  in_stack_00000004[0x44] = iVar2;
  in_stack_00000004[0x45] = 0;
  (*pcVar3)(piVar6,in_stack_00000004 + 0x45);
  in_stack_00000004[0x46] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x44] + 4))(piVar6,in_stack_00000004 + 0x46);
  in_stack_00000004[0x48] = 0;
  in_stack_00000004[0x47] = iVar2;
  (*pcVar3)(in_stack_00000004 + 0x47,in_stack_00000004 + 0x48);
  in_stack_00000004[0x49] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x47] + 4))(in_stack_00000004 + 0x47,in_stack_00000004 + 0x49);
  piVar7 = in_stack_00000004 + 0x4b;
  do {
    piVar1 = piVar7 + 0xc;
    do {
      *piVar7 = iVar2;
      piVar7[1] = 0;
      (*pcVar3)(piVar7,piVar7 + 1);
      piVar7[2] = -0x40800000 /* -1.0f */;
      (**(code **)(*piVar7 + 4))(piVar7,piVar7 + 2);
      piVar7 = piVar7 + 3;
    } while (piVar1 != piVar7);
    piVar7 = piVar1;
  } while (piVar1 != in_stack_00000004 + 0x117);
  iVar2 = in_stack_00000004[0x28];
  *(int **)(unaff_EBX + 0x58d031 /* INSNextBotManager */ /* INSNextBotManager */) = in_stack_00000004;
  if (iVar2 != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x26] + 4))(piVar5,in_stack_00000004 + 0x28);
    in_stack_00000004[0x28] = -0x40800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x2b] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x29] + 4))(piVar4,in_stack_00000004 + 0x2b);
    in_stack_00000004[0x2b] = -0x40800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x46] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x44] + 4))(piVar6,in_stack_00000004 + 0x46);
    in_stack_00000004[0x46] = -0x40800000 /* -1.0f */;
  }
  *(undefined1 *)(in_stack_00000004 + 0x4a) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x129) = 0;
  in_stack_00000004[0x38] = 0x3f800000 /* 1.0f */;
  in_stack_00000004[0x39] = 1;
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::Update
 * Address: 00766690
 * ---------------------------------------- */

/* CINSNextBotManager::Update() */

void __thiscall CINSNextBotManager::Update(CINSNextBotManager *this)

{
  ushort uVar1;
  CINSNextBotSurvivalCacheNotify *this_00;
  char cVar2;
  CINSNextBotManager *pCVar3;
  int iVar4;
  CUtlVector *pCVar5;
  int *piVar6;
  int iVar7;
  CINSRules *this_01;
  CUtlVector<CINSNextBot*,CUtlMemory<CINSNextBot*,int>> *extraout_ECX;
  CUtlVector<CINSNextBot*,CUtlMemory<CINSNextBot*,int>> *this_02;
  CINSBotChatter *this_03;
  NextBotManager *extraout_ECX_00;
  NextBotManager *this_04;
  CBaseEntity *this_05;
  CBaseEntity *this_06;
  NextBotManager *extraout_ECX_01;
  NextBotManager *extraout_ECX_02;
  NextBotManager *extraout_ECX_03;
  NextBotManager *extraout_ECX_04;
  NextBotManager *this_07;
  CINSNextBotManager *this_08;
  CINSNextBotSurvivalCacheNotify *extraout_ECX_05;
  CUtlVector<CINSNextBot*,CUtlMemory<CINSNextBot*,int>> *extraout_ECX_06;
  CINSNextBotManager *this_09;
  int unaff_EBX;
  float10 fVar8;
  float fVar9;
  CINSNextBotManager *in_stack_00000004;
  CINSNextBotManager *pCVar10;
  int *piVar11;
  int local_50;
  int local_4c;
  undefined4 local_48;
  int local_44;
  CINSNextBotManager *local_40;
  int local_3c;
  int local_2c;
  int *local_20 [3];
  undefined4 uStack_14;
  
  uStack_14 = 0x76669b;
  __i686_get_pc_thunk_bx();
  pCVar10 = (CINSNextBotManager *)0x4;
  cVar2 = CINSRules::IsGameState(this_01,**(int **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */));
  if (cVar2 == '\0') {
    return;
  }
  fVar8 = (float10)CountdownTimer::Now();
  if (*(float *)(in_stack_00000004 + 0xa0) <= (float)fVar8 &&
      (float)fVar8 != *(float *)(in_stack_00000004 + 0xa0)) {
    UpdateGrenades(in_stack_00000004);
    UpdateGrenadeTargets(this_09);
    piVar11 = (int *)(*(int **)(unaff_EBX + 0x440921 /* &ins_bot_grenade_think_time */ /* &ins_bot_grenade_think_time */))[7];
    if (piVar11 == *(int **)(unaff_EBX + 0x440921 /* &ins_bot_grenade_think_time */ /* &ins_bot_grenade_think_time */)) {
      fVar9 = (float)((uint)piVar11 ^ piVar11[0xb]);
    }
    else {
      fVar8 = (float10)(**(code **)(*piVar11 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar11,pCVar10);
      fVar9 = (float)fVar8;
    }
    fVar8 = (float10)CountdownTimer::Now();
    if (*(float *)(in_stack_00000004 + 0xa0) != (float)fVar8 + fVar9) {
      pCVar10 = in_stack_00000004 + 0xa0;
      (**(code **)(*(int *)(in_stack_00000004 + 0x98) + 4))(in_stack_00000004 + 0x98,pCVar10);
      *(float *)(in_stack_00000004 + 0xa0) = (float)fVar8 + fVar9;
    }
    if (*(float *)(in_stack_00000004 + 0x9c) != fVar9) {
      pCVar10 = in_stack_00000004 + 0x9c;
      (**(code **)(*(int *)(in_stack_00000004 + 0x98) + 4))(in_stack_00000004 + 0x98,pCVar10);
      *(float *)(in_stack_00000004 + 0x9c) = fVar9;
    }
  }
  fVar8 = (float10)CountdownTimer::Now();
  if ((*(float *)(in_stack_00000004 + 0x124) <= (float)fVar8 &&
       (float)fVar8 != *(float *)(in_stack_00000004 + 0x124)) &&
     ((*(int *)*(CINSRules **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */) == 0 ||
      (cVar2 = CINSRules::IsSurvival(*(CINSRules **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */)), cVar2 == '\0')))) {
    local_4c = 0;
    local_48 = 0;
    local_44 = 0;
    local_40 = (CINSNextBotManager *)0x0;
    local_3c = 0;
    if (0 < *(int *)(**(int **)(&DAT_00440205 + unaff_EBX) + 0x14)) {
      local_50 = 1;
      do {
        pCVar3 = (CINSNextBotManager *)UTIL_PlayerByIndex(local_50);
        if (((pCVar3 != (CINSNextBotManager *)0x0) &&
            (cVar2 = (**(code **)(*(int *)pCVar3 + 0x7b0 /* NextBotPlayer::IsBot */))(pCVar3,pCVar10), cVar2 != '\0')) &&
           (cVar2 = (**(code **)(*(int *)pCVar3 + 0x118 /* CBaseEntity::IsAlive */))(pCVar3), cVar2 != '\0')) {
          pCVar10 = *(CINSNextBotManager **)(unaff_EBX + 0x4400e9 /* &typeinfo for CBasePlayer */ /* &typeinfo for CBasePlayer */);
          local_2c = __dynamic_cast(pCVar3,pCVar10,*(undefined4 *)(unaff_EBX + 0x44038d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0);
          if ((((local_2c != 0) &&
               ((CBasePlayer *)**(undefined4 **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */) != (CBasePlayer *)0x0)) &&
              ((cVar2 = CINSRules::IsCoopBot((CBasePlayer *)**(undefined4 **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */))
               , pCVar10 = pCVar3, cVar2 != '\0' &&
               ((this_02 = extraout_ECX, *(int *)(local_2c + 0xb448) != 0 ||
                (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x440195 /* &nb_blind */ /* &nb_blind */) + 0x40))
                                   (*(int **)(unaff_EBX + 0x440195 /* &nb_blind */ /* &nb_blind */)), this_02 = extraout_ECX_06,
                pCVar10 = pCVar3, iVar4 != 0)))))) &&
             (pCVar10 = pCVar3, *(char *)(local_2c + 0x2290) != '\0')) {
            pCVar10 = local_40;
            CUtlVector<CINSNextBot*,CUtlMemory<CINSNextBot*,int>>::InsertBefore
                      (this_02,(int)&local_4c,(CINSNextBot **)local_40);
          }
        }
        local_50 = local_50 + 1;
      } while (local_50 <= *(int *)(**(int **)(&DAT_00440205 + unaff_EBX) + 0x14));
      if (0 < (int)local_40) {
        iVar4 = RandomInt(0,local_40 + -1);
        piVar11 = *(int **)(local_4c + iVar4 * 4);
        if (piVar11 != (int *)0x0) {
          (**(code **)(*piVar11 + 0x978 /* CINSNextBot::GetChatter */))(piVar11);
          CINSBotChatter::IdleChatter(this_03);
        }
      }
    }
    fVar8 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x41000000 /* 8.0f */);
    fVar9 = (float)fVar8;
    fVar8 = (float10)CountdownTimer::Now();
    if (*(float *)(in_stack_00000004 + 0x124) != fVar9 + (float)fVar8) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x11c) + 4))
                (in_stack_00000004 + 0x11c,in_stack_00000004 + 0x124);
      *(float *)(in_stack_00000004 + 0x124) = fVar9 + (float)fVar8;
    }
    if (*(float *)(in_stack_00000004 + 0x120) != fVar9) {
      (**(code **)(*(int *)(in_stack_00000004 + 0x11c) + 4))
                (in_stack_00000004 + 0x11c,in_stack_00000004 + 0x120);
      *(float *)(in_stack_00000004 + 0x120) = fVar9;
    }
    local_40 = (CINSNextBotManager *)0x0;
    if (local_44 < 0) {
      local_3c = local_4c;
    }
    else {
      if (local_4c != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4401dd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4401dd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_4c);
        local_4c = 0;
      }
      local_48 = 0;
      local_3c = 0;
    }
  }
  fVar8 = (float10)CountdownTimer::Now();
  if (((*(float *)(in_stack_00000004 + 0xac) <= (float)fVar8 &&
        (float)fVar8 != *(float *)(in_stack_00000004 + 0xac)) &&
      (*(int *)*(CINSRules **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */) != 0)) &&
     (piVar11 = *(int **)(unaff_EBX + 0x440681 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */), *piVar11 != 0)) {
    cVar2 = CINSRules::IsSurvival(*(CINSRules **)(unaff_EBX + 0x44025d /* &g_pGameRules */ /* &g_pGameRules */));
    if (cVar2 != '\0') {
      iVar4 = *piVar11;
      iVar7 = *(int *)(iVar4 + 0x770);
      if ((iVar7 != -1) && (*(int *)(in_stack_00000004 + 0xbc) != iVar7)) {
        iVar4 = iVar4 + iVar7 * 0xc;
        local_4c = *(int *)(iVar4 + 0x5d0);
        local_48 = *(undefined4 *)(iVar4 + 0x5d4);
        local_44 = *(int *)(iVar4 + 0x5d8);
        *(int *)(in_stack_00000004 + 0xbc) = iVar7;
        CINSRules::GetBotTeam((CINSRules *)in_stack_00000004);
        iVar4 = TheNextBots();
        GenerateCPGrenadeTargets(this_08,iVar4,iVar7);
        local_20[0] = &local_4c;
        this_00 = (CINSNextBotSurvivalCacheNotify *)in_stack_00000004;
        for (uVar1 = *(ushort *)(in_stack_00000004 + 0x10); uVar1 != 0xffff;
            uVar1 = *(ushort *)(*(int *)(in_stack_00000004 + 4) + 6 + (uint)uVar1 * 8)) {
          cVar2 = CINSNextBotSurvivalCacheNotify::operator()(this_00,(INextBot *)local_20);
          if (cVar2 == '\0') break;
          this_00 = extraout_ECX_05;
        }
      }
    }
    fVar8 = (float10)CountdownTimer::Now();
    fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x1bd3f1 /* 0.25f */ /* 0.25f */);
    if (*(float *)(in_stack_00000004 + 0xac) != fVar9) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xa4) + 4))
                (in_stack_00000004 + 0xa4,in_stack_00000004 + 0xac);
      *(float *)(in_stack_00000004 + 0xac) = fVar9;
    }
    if (*(int *)(in_stack_00000004 + 0xa8) != 0x3e800000 /* 0.25f */) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xa4) + 4))
                (in_stack_00000004 + 0xa4,in_stack_00000004 + 0xa8);
      *(undefined4 *)(in_stack_00000004 + 0xa8) = 0x3e800000 /* 0.25f */;
    }
  }
  fVar8 = (float10)CountdownTimer::Now();
  this_07 = extraout_ECX_00;
  if (*(float *)(in_stack_00000004 + 0xb8) <= (float)fVar8 &&
      (float)fVar8 != *(float *)(in_stack_00000004 + 0xb8)) {
    *(undefined4 *)(in_stack_00000004 + 0xc0) = 0;
    piVar11 = &local_4c;
    *(undefined4 *)(in_stack_00000004 + 0xc4) = 0;
    local_4c = 0;
    local_48 = 0;
    local_44 = 0;
    local_40 = (CINSNextBotManager *)0x0;
    local_3c = 0;
    pCVar5 = (CUtlVector *)TheNextBots();
    NextBotManager::CollectAllBots(this_04,pCVar5);
    if (0 < (int)local_40) {
      iVar4 = 0;
      do {
        while( true ) {
          piVar6 = *(int **)(local_4c + iVar4 * 4);
          piVar6 = (int *)(**(code **)(*piVar6 + 200))(piVar6,piVar11);
          if ((piVar6 != (int *)0x0) &&
             (cVar2 = (**(code **)(*piVar6 + 0x118))(piVar6), cVar2 != '\0')) break;
LAB_00766a38:
          iVar4 = iVar4 + 1;
          if ((int)local_40 <= iVar4) goto LAB_00766af0;
        }
        piVar11 = *(int **)(local_4c + iVar4 * 4);
        piVar6 = (int *)(**(code **)(*piVar11 + 0xdc /* CBaseAnimating::GetBaseAnimating */))(piVar11);
        piVar11 = (int *)0x0;
        piVar6 = (int *)(**(code **)(*piVar6 + 0xd0))(piVar6);
        if ((piVar6 == (int *)0x0) || (cVar2 = (**(code **)(*piVar6 + 0x3c))(piVar6), cVar2 == '\0')
           ) goto LAB_00766a38;
        iVar7 = CBaseEntity::GetTeamNumber(this_05);
        if (iVar7 == 2) {
          *(int *)(in_stack_00000004 + 0xc0) = *(int *)(in_stack_00000004 + 0xc0) + 1;
        }
        iVar7 = CBaseEntity::GetTeamNumber(this_06);
        if (iVar7 != 3) goto LAB_00766a38;
        iVar4 = iVar4 + 1;
        *(int *)(in_stack_00000004 + 0xc4) = *(int *)(in_stack_00000004 + 0xc4) + 1;
      } while (iVar4 < (int)local_40);
    }
LAB_00766af0:
    fVar8 = (float10)CountdownTimer::Now();
    fVar9 = (float)fVar8 + *(float *)(unaff_EBX + 0x1be0bd /* 0.5f */ /* 0.5f */);
    this_07 = extraout_ECX_01;
    if (*(float *)(in_stack_00000004 + 0xb8) != fVar9) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xb0) + 4))
                (in_stack_00000004 + 0xb0,in_stack_00000004 + 0xb8);
      *(float *)(in_stack_00000004 + 0xb8) = fVar9;
      this_07 = extraout_ECX_02;
    }
    if (*(int *)(in_stack_00000004 + 0xb4) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xb0) + 4))
                (in_stack_00000004 + 0xb0,in_stack_00000004 + 0xb4);
      *(undefined4 *)(in_stack_00000004 + 0xb4) = 0x3f000000 /* 0.5f */;
      this_07 = extraout_ECX_03;
    }
    local_40 = (CINSNextBotManager *)0x0;
    if (local_44 < 0) {
      local_3c = local_4c;
    }
    else {
      if (local_4c != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4401dd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4401dd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_4c);
        local_4c = 0;
        this_07 = extraout_ECX_04;
      }
      local_48 = 0;
      local_3c = 0;
    }
  }
  NextBotManager::Update(this_07);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnKilled
 * Address: 007615f0
 * ---------------------------------------- */

/* CINSNextBotManager::OnKilled(CBaseCombatCharacter*, CTakeDamageInfo const&) */

void __cdecl CINSNextBotManager::OnKilled(CBaseCombatCharacter *param_1,CTakeDamageInfo *param_2)

{
  NextBotManager *this;
  
  __i686_get_pc_thunk_bx();
  NextBotManager::OnKilled(this,param_1,param_2);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnWeaponFired
 * Address: 00764230
 * ---------------------------------------- */

/* WARNING: Restarted to delay deadcode elimination for space: stack */
/* CINSNextBotManager::OnWeaponFired(CBaseCombatCharacter*, CBaseCombatWeapon*) */

void __thiscall
CINSNextBotManager::OnWeaponFired
          (CINSNextBotManager *this,CBaseCombatCharacter *param_1,CBaseCombatWeapon *param_2)

{
  float fVar1;
  float fVar2;
  char cVar3;
  CUtlVector *pCVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  NextBotManager *this_00;
  CBasePlayer *extraout_ECX;
  CTraceFilterSimple *this_01;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_02;
  CBasePlayer *extraout_ECX_01;
  CBasePlayer *this_03;
  CBaseEntity *extraout_ECX_02;
  int unaff_EBX;
  float10 fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  int *in_stack_0000000c;
  Vector *pVVar15;
  int *piVar16;
  float fVar17;
  float local_188;
  Vector local_140 [12];
  float local_134;
  float local_130;
  float local_12c;
  undefined4 local_f4;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_dc;
  float local_d8;
  float local_d4;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_ac;
  undefined1 local_a8;
  undefined1 local_a7;
  int local_9c;
  undefined4 local_98;
  int local_94;
  int local_90;
  undefined4 local_8c;
  IHandleEntity local_7c [16];
  float local_6c;
  float local_68;
  float local_64;
  float local_5c;
  float local_58;
  float local_54;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x764241;
  __i686_get_pc_thunk_bx();
  local_9c = 0;
  local_98 = 0;
  local_94 = 0;
  local_90 = 0;
  local_8c = 0;
  pCVar4 = (CUtlVector *)TheNextBots();
  NextBotManager::CollectAllBots(this_00,pCVar4);
  if ((in_stack_0000000c == (int *)0x0) ||
     (cVar3 = (**(code **)(*in_stack_0000000c + 0x170 /* CBaseEntity::IsWeapon */))(in_stack_0000000c),
     piVar16 = in_stack_0000000c, cVar3 == '\0')) {
    piVar16 = (int *)0x0;
  }
  if ((piVar16 != (int *)0x0) && (param_2 != (CBaseCombatWeapon *)0x0)) {
    iVar5 = (**(code **)(*piVar16 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar16);
    if ((iVar5 - 8U < 7) &&
       (local_188 = *(float *)(unaff_EBX + 0x222d03 /* CSWTCH.989 */ /* CSWTCH.989 */ + (iVar5 - 8U) * 4), 0.0 < local_188)) {
      cVar3 = (**(code **)(*piVar16 + 0x760 /* CINSPlayer::ForceChangeTeam */))(piVar16);
      this_03 = extraout_ECX;
      if (cVar3 != '\0') {
        piVar16 = (int *)(*(int **)(unaff_EBX + 0x44281f /* &ins_bot_silenced_weapon_sound_reduction */ /* &ins_bot_silenced_weapon_sound_reduction */))[7];
        if (piVar16 == *(int **)(unaff_EBX + 0x44281f /* &ins_bot_silenced_weapon_sound_reduction */ /* &ins_bot_silenced_weapon_sound_reduction */)) {
          fVar17 = (float)((uint)piVar16 ^ piVar16[0xb]);
        }
        else {
          fVar10 = (float10)(**(code **)(*piVar16 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar16);
          fVar17 = (float)fVar10;
          this_03 = extraout_ECX_01;
        }
        local_188 = fVar17 * local_188;
      }
      pVVar15 = (Vector *)&local_4c;
      fVar17 = 0.0;
      piVar16 = (int *)0x0;
      CBasePlayer::EyeVectors(this_03,(Vector *)param_2,pVVar15,(Vector *)0x0);
      if (0 < local_90) {
        iVar5 = 0;
        do {
          while( true ) {
            piVar7 = *(int **)(local_9c + iVar5 * 4);
            if (((piVar7 != (int *)0x0) &&
                (piVar7 = (int *)(**(code **)(*piVar7 + 200))(piVar7,pVVar15,piVar16,fVar17),
                piVar7 != (int *)0x0)) && (cVar3 = (**(code **)(*piVar7 + 0x118 /* CBaseEntity::IsAlive */))(), cVar3 != '\0'))
            break;
LAB_007643d0:
            iVar5 = iVar5 + 1;
            if (local_90 <= iVar5) goto LAB_00764770;
          }
          (**(code **)(*(int *)param_2 + 0x20c /* CINSNextBot::EyePosition */))(&local_6c);
          fVar13 = local_44;
          fVar12 = local_48;
          fVar11 = local_4c;
          local_f4 = 0;
          (**(code **)(*(int *)param_2 + 0x20c /* CINSNextBot::EyePosition */))(&local_34,param_2);
          fVar2 = local_2c;
          fVar1 = local_30;
          fVar14 = local_34;
          (**(code **)(*(int *)param_2 + 0x20c /* CINSNextBot::EyePosition */))(&local_40,param_2);
          local_a8 = 1;
          local_ec = local_40;
          local_ac = 0;
          local_e8 = local_3c;
          local_dc = (*(float *)(unaff_EBX + 0x1e7a4f /* 16384.0f */ /* 16384.0f */) * fVar11 - local_40) + fVar14;
          local_e4 = local_38;
          local_d8 = (*(float *)(unaff_EBX + 0x1e7a4f /* 16384.0f */ /* 16384.0f */) * fVar12 - local_3c) + fVar1;
          local_d4 = (*(float *)(unaff_EBX + 0x1e7a4f /* 16384.0f */ /* 16384.0f */) * fVar13 - local_38) + fVar2;
          local_b4 = 0;
          local_b8 = 0;
          local_bc = 0;
          local_c4 = 0;
          local_c8 = 0;
          local_cc = 0;
          local_a7 = local_d8 * local_d8 + local_dc * local_dc + local_d4 * local_d4 != 0.0;
          CTraceFilterSimple::CTraceFilterSimple
                    (this_01,local_7c,(int)param_2,(_func_bool_IHandleEntity_ptr_int *)0x0);
          pVVar15 = local_140;
          (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x442537 /* &enginetrace */ /* &enginetrace */) + 0x14))
                    ((int *)**(undefined4 **)(unaff_EBX + 0x442537 /* &enginetrace */ /* &enginetrace */),&local_ec,0x600400b);
          iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x4427ff /* &r_visualizetraces */ /* &r_visualizetraces */) + 0x40))
                            (*(int **)(unaff_EBX + 0x4427ff /* &r_visualizetraces */ /* &r_visualizetraces */));
          if (iVar8 != 0) {
            iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x4427ff /* &r_visualizetraces */ /* &r_visualizetraces */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4427ff /* &r_visualizetraces */ /* &r_visualizetraces */));
            fVar17 = 0.5;
            if (iVar8 != 0) {
              fVar17 = -1.0;
            }
            piVar16 = (int *)0x1;
            pVVar15 = (Vector *)0x0;
            DebugDrawLine(local_140,(Vector *)&local_134,0xff,0,0,true,fVar17);
          }
          local_6c = local_134;
          local_68 = local_130;
          local_64 = local_12c;
          (**(code **)(*piVar7 + 0x20c /* CINSNextBot::EyePosition */))(&local_5c,piVar7);
          fVar12 = SQRT((local_58 - local_68) * (local_58 - local_68) +
                        (local_5c - local_6c) * (local_5c - local_6c) +
                        (local_54 - local_64) * (local_54 - local_64));
          (**(code **)(*piVar7 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar7);
          pfVar9 = (float *)(**(code **)(*(int *)param_2 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_2);
          fVar14 = *pfVar9 - local_28;
          fVar11 = pfVar9[1] - local_24;
          fVar13 = pfVar9[2] - local_20;
          cVar3 = (**(code **)(*piVar7 + 0x444 /* CINSPlayer::IsLineOfSightClear */))(piVar7,&local_6c,0,0);
          this_02 = extraout_ECX_00;
          if (cVar3 != '\0') {
            pVVar15 = (Vector *)&local_6c;
            cVar3 = (**(code **)(*piVar7 + 0x43c /* CBaseCombatCharacter::IsInFieldOfView */))();
            this_02 = extraout_ECX_02;
            if ((cVar3 == '\0') || (*(float *)(unaff_EBX + 0x1c2b9f /* 250.0f */ /* 250.0f */) <= fVar12)) goto LAB_0076472f;
LAB_00764390:
            iVar8 = CBaseEntity::GetTeamNumber(this_02);
            iVar6 = CBaseEntity::GetTeamNumber((CBaseEntity *)param_2);
            if (iVar8 != iVar6) {
LAB_007643a9:
              piVar16 = in_stack_0000000c;
              pVVar15 = (Vector *)param_2;
              (**(code **)(**(int **)(local_9c + iVar5 * 4) + 0x5c))();
            }
            goto LAB_007643d0;
          }
LAB_0076472f:
          if (fVar12 < *(float *)(unaff_EBX + 0x1548df /* 100.0f */ /* 100.0f */)) goto LAB_00764390;
          if (SQRT(fVar11 * fVar11 + fVar14 * fVar14 + fVar13 * fVar13) <= local_188)
          goto LAB_007643a9;
          iVar5 = iVar5 + 1;
        } while (iVar5 < local_90);
      }
LAB_00764770:
      if (((byte)param_1[0x34] & 0x80) != 0) {
        fVar17 = (float)(**(code **)(*in_stack_0000000c + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(in_stack_0000000c);
        piVar16 = (int *)CBaseEntity::GetDebugName((CBaseEntity *)param_2);
        DevMsg((char *)(unaff_EBX + 0x222b6b /* "%3.2f: OnWeaponFired( %s, %s )
" */ /* "%3.2f: OnWeaponFired( %s, %s )
" */));
      }
      local_90 = 0;
      if (local_94 < 0) {
        return;
      }
      if (local_9c == 0) {
        return;
      }
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x442637 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x442637 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_9c,piVar16,fVar17);
      return;
    }
  }
  local_90 = 0;
  if ((-1 < local_94) && (local_9c != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x442637 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x442637 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_9c);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::AddGrenadeTarget
 * Address: 00765cc0
 * ---------------------------------------- */

/* CINSNextBotManager::AddGrenadeTarget(int, CINSGrenadeTarget*) */

uint __thiscall
CINSNextBotManager::AddGrenadeTarget
          (CINSNextBotManager *this,int param_1,CINSGrenadeTarget *param_2)

{
  int iVar1;
  CINSGrenadeTarget **ppCVar2;
  int iVar3;
  uint uVar4;
  CINSGrenadeTarget **ppCVar5;
  int unaff_EBX;
  float fVar6;
  float fVar7;
  float fVar8;
  CUtlVector<CINSGrenadeTarget*,CUtlMemory<CINSGrenadeTarget*,int>> *in_stack_0000000c;
  
  uVar4 = __i686_get_pc_thunk_bx();
  if (in_stack_0000000c != (CUtlVector<CINSGrenadeTarget*,CUtlMemory<CINSGrenadeTarget*,int>> *)0x0)
  {
    if ((CINSGrenadeTarget *)0x1 < param_2 + -2) {
      Warning(unaff_EBX + 0x2210ff /* "Tried adding grenade target for invalid team %i
" */ /* "Tried adding grenade target for invalid team %i
" */,param_2);
      operator_delete(in_stack_0000000c);
      return uVar4 & 0xff;
    }
    iVar1 = param_1 + 0xe0 + (uint)(param_2 != (CINSGrenadeTarget *)0x2) * 0x14;
    ppCVar2 = *(CINSGrenadeTarget ***)(iVar1 + 0x14);
    if (0 < (int)ppCVar2) {
      ppCVar5 = (CINSGrenadeTarget **)0x0;
      do {
        iVar3 = *(int *)(*(int *)(iVar1 + 8) + (int)ppCVar5 * 4);
        if ((iVar3 != 0) &&
           (fVar8 = *(float *)(in_stack_0000000c + 0x10) - *(float *)(iVar3 + 0x10),
           fVar6 = *(float *)(in_stack_0000000c + 0x14) - *(float *)(iVar3 + 0x14),
           fVar7 = *(float *)(in_stack_0000000c + 0x18) - *(float *)(iVar3 + 0x18),
           SQRT(fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7) <
           *(float *)(iVar3 + 0x20) + *(float *)(iVar3 + 0x20))) {
          operator_delete(in_stack_0000000c);
          return 0;
        }
        ppCVar5 = (CINSGrenadeTarget **)((int)ppCVar5 + 1);
      } while (ppCVar5 != ppCVar2);
    }
    CUtlVector<CINSGrenadeTarget*,CUtlMemory<CINSGrenadeTarget*,int>>::InsertBefore
              (in_stack_0000000c,iVar1 + 8,ppCVar2);
    uVar4 = 1;
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSNextBotManager::AreBotsOnTeamInCombat
 * Address: 007628b0
 * ---------------------------------------- */

/* CINSNextBotManager::AreBotsOnTeamInCombat(int) */

undefined4 __thiscall
CINSNextBotManager::AreBotsOnTeamInCombat(CINSNextBotManager *this,int param_1)

{
  int in_stack_00000008;
  
  if (in_stack_00000008 == 2) {
    return CONCAT31((int3)((uint)*(int *)(param_1 + 0xc0) >> 8),0 < *(int *)(param_1 + 0xc0));
  }
  if (in_stack_00000008 != 3) {
    return 0;
  }
  return CONCAT31((int3)((uint)*(int *)(param_1 + 0xc4) >> 8),0 < *(int *)(param_1 + 0xc4));
}



/* ----------------------------------------
 * CINSNextBotManager::BotAddCommand
 * Address: 00762790
 * ---------------------------------------- */

/* CINSNextBotManager::BotAddCommand() */

bool __thiscall CINSNextBotManager::BotAddCommand(CINSNextBotManager *this)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  ConVar *this_00;
  int unaff_EBX;
  bool bVar4;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(unaff_EBX + 0x443f1a /* &TheNavMesh */ /* &TheNavMesh */);
  cVar2 = CINSNavMesh::NavMeshExists();
  if (cVar2 != '\0') {
    iVar3 = *piVar1;
    if (*(char *)(iVar3 + 0x38) == '\0') {
      Warning(unaff_EBX + 0x2244f6 /* "INSNextBot - NavMesh exists but not currently loaded.
" */ /* "INSNextBot - NavMesh exists but not currently loaded.
" */);
      bVar4 = false;
      if (*(char *)(in_stack_00000004 + 0x128) == '\0') {
        *(undefined1 *)(in_stack_00000004 + 0x128) = 1;
        Warning(unaff_EBX + 0x22452e /* "Forcing a load, This is bad and will most likely cause a hitch. This should n..." */ /* "Forcing a load, This is bad and will most likely cause a hitch. This should n..." */);
        piVar1 = (int *)*piVar1;
        iVar3 = (**(code **)(*piVar1 + 0x28))(piVar1);
        if ((iVar3 == 4) || (iVar3 == 0)) {
          Msg(unaff_EBX + 0x22459a /* "Successfully loaded NavMesh on demand, restarting game.
" */ /* "Successfully loaded NavMesh on demand, restarting game.
" */);
          ConVar::SetValue(this_00,*(int *)(&LAB_00444526 + unaff_EBX));
          bVar4 = false;
        }
        else {
          Warning(unaff_EBX + 0x22435e /* "Failed loading navmesh!
" */ /* "Failed loading navmesh!
" */);
          bVar4 = false;
        }
      }
    }
    else {
      bVar4 = *(int *)(iVar3 + 0x514) == 0;
    }
    return bVar4;
  }
  Warning(&UNK_002244be + unaff_EBX);
  return false;
}



/* ----------------------------------------
 * CINSNextBotManager::CallForReinforcements
 * Address: 00762a90
 * ---------------------------------------- */

/* CINSNextBotManager::CallForReinforcements(int) */

void __cdecl CINSNextBotManager::CallForReinforcements(int param_1)

{
  float fVar1;
  int iVar2;
  int unaff_EBX;
  float10 fVar3;
  
  iVar2 = __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x443e57 /* &g_pGameRules */ /* &g_pGameRules */) != 0) {
    if (iVar2 == 2) {
      fVar3 = (float10)GetCallForReinforcementCooldown();
      fVar1 = (float)fVar3;
      fVar3 = (float10)CountdownTimer::Now();
      if (*(float *)(param_1 + 0xd0) != (float)fVar3 + fVar1) {
        (**(code **)(*(int *)(param_1 + 200) + 4))(param_1 + 200,param_1 + 0xd0);
        *(float *)(param_1 + 0xd0) = (float)fVar3 + fVar1;
      }
      if (*(float *)(param_1 + 0xcc) != fVar1) {
        (**(code **)(*(int *)(param_1 + 200) + 4))(param_1 + 200,param_1 + 0xcc);
        *(float *)(param_1 + 0xcc) = fVar1;
      }
    }
    else if (iVar2 == 3) {
      fVar3 = (float10)GetCallForReinforcementCooldown();
      fVar1 = (float)fVar3;
      fVar3 = (float10)CountdownTimer::Now();
      if (*(float *)(param_1 + 0xdc) != (float)fVar3 + fVar1) {
        (**(code **)(*(int *)(param_1 + 0xd4) + 4))(param_1 + 0xd4,param_1 + 0xdc);
        *(float *)(param_1 + 0xdc) = (float)fVar3 + fVar1;
      }
      if (*(float *)(param_1 + 0xd8) != fVar1) {
        (**(code **)(*(int *)(param_1 + 0xd4) + 4))(param_1 + 0xd4,param_1 + 0xd8);
        *(float *)(param_1 + 0xd8) = fVar1;
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::CanCallForReinforcements
 * Address: 007628f0
 * ---------------------------------------- */

/* CINSNextBotManager::CanCallForReinforcements(int) */

uint __thiscall CINSNextBotManager::CanCallForReinforcements(CINSNextBotManager *this,int param_1)

{
  CINSRules *this_00;
  uint uVar1;
  int unaff_EBX;
  float10 fVar2;
  int in_stack_00000008;
  
  uVar1 = __i686_get_pc_thunk_bx();
  this_00 = *(CINSRules **)(unaff_EBX + 0x443ff8 /* &g_pGameRules */ /* &g_pGameRules */);
  if (*(int *)this_00 != 0) {
    if (in_stack_00000008 == 2) {
      fVar2 = (float10)CountdownTimer::Now();
      if ((float)fVar2 < *(float *)(param_1 + 0xd0) || (float)fVar2 == *(float *)(param_1 + 0xd0)) {
        return uVar1 & 0xff;
      }
    }
    else if (in_stack_00000008 == 3) {
      fVar2 = (float10)CountdownTimer::Now();
      if ((float)fVar2 < *(float *)(param_1 + 0xdc) || (float)fVar2 == *(float *)(param_1 + 0xdc)) {
        return uVar1 & 0xff;
      }
    }
    uVar1 = CINSRules::IsSurvival(this_00);
    if ((char)uVar1 != '\0') {
      if (in_stack_00000008 == 2) {
        return CONCAT31((int3)((uint)*(int *)(param_1 + 0xc0) >> 8),*(int *)(param_1 + 0xc0) < 1);
      }
      uVar1 = 1;
      if (in_stack_00000008 == 3) {
        uVar1 = CONCAT31((int3)((uint)*(int *)(param_1 + 0xc4) >> 8),*(int *)(param_1 + 0xc4) < 1);
      }
    }
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBotManager::CommandApproach
 * Address: 00764950
 * ---------------------------------------- */

/* CINSNextBotManager::CommandApproach(int, Vector, float, float) */

void __cdecl
CINSNextBotManager::CommandApproach
          (CUtlVector *param_1,int param_2,float param_3,float param_4,float param_5,
          undefined4 param_6,float param_7)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  float *pfVar5;
  NextBotManager *this;
  CBaseEntity *this_00;
  int unaff_EBX;
  int iVar6;
  int *piVar7;
  int local_3c [10];
  undefined4 uStack_14;
  
  piVar7 = local_3c;
  uStack_14 = 0x76495e;
  __i686_get_pc_thunk_bx();
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_3c[3] = 0;
  local_3c[4] = 0;
  NextBotManager::CollectAllBots(this,param_1);
  if (0 < local_3c[3]) {
    iVar6 = 0;
LAB_007649bc:
    do {
      iVar1 = iVar6 * 4;
      piVar3 = *(int **)(local_3c[0] + iVar6 * 4);
      piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3,piVar7);
      cVar2 = (**(code **)(*piVar3 + 0x118))(piVar3);
      if (cVar2 != '\0') {
        (**(code **)(**(int **)(local_3c[0] + iVar1) + 200))(*(int **)(local_3c[0] + iVar1));
        iVar4 = CBaseEntity::GetTeamNumber(this_00);
        if (iVar4 == param_2) {
          pfVar5 = (float *)(**(code **)(**(int **)(local_3c[0] + iVar1) + 0xe4))
                                      (*(int **)(local_3c[0] + iVar1));
          if (SQRT((pfVar5[1] - param_4) * (pfVar5[1] - param_4) +
                   (*pfVar5 - param_3) * (*pfVar5 - param_3) +
                   (pfVar5[2] - param_5) * (pfVar5[2] - param_5)) <= param_7) {
            piVar7 = (int *)&param_3;
            (**(code **)(**(int **)(local_3c[0] + iVar1) + 0x78))
                      (*(int **)(local_3c[0] + iVar1),piVar7,param_7);
            iVar6 = iVar6 + 1;
            if (local_3c[3] <= iVar6) break;
            goto LAB_007649bc;
          }
        }
      }
      iVar6 = iVar6 + 1;
    } while (iVar6 < local_3c[3]);
  }
  local_3c[3] = 0;
  if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x441f1a /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x441f1a /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_3c[0]);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::CommandAttack
 * Address: 00764b00
 * ---------------------------------------- */

/* CINSNextBotManager::CommandAttack(int, CBaseEntity*) */

void __thiscall
CINSNextBotManager::CommandAttack(CINSNextBotManager *this,int param_1,CBaseEntity *param_2)

{
  char cVar1;
  int *piVar2;
  CBaseEntity *pCVar3;
  NextBotManager *this_00;
  CBaseEntity *this_01;
  int unaff_EBX;
  int iVar4;
  int *in_stack_0000000c;
  int *piVar5;
  int local_3c [10];
  undefined4 uStack_14;
  
  piVar5 = local_3c;
  uStack_14 = 0x764b0e;
  __i686_get_pc_thunk_bx();
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_3c[3] = 0;
  local_3c[4] = 0;
  NextBotManager::CollectAllBots(this_00,(CUtlVector *)param_1);
  if (0 < local_3c[3]) {
    iVar4 = 0;
LAB_00764b68:
    do {
      piVar2 = *(int **)(local_3c[0] + iVar4 * 4);
      piVar2 = (int *)(**(code **)(*piVar2 + 200))(piVar2,piVar5);
      cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2);
      if (cVar1 != '\0') {
        piVar2 = *(int **)(local_3c[0] + iVar4 * 4);
        (**(code **)(*piVar2 + 200))(piVar2);
        pCVar3 = (CBaseEntity *)CBaseEntity::GetTeamNumber(this_01);
        if (pCVar3 == param_2) {
          piVar2 = *(int **)(local_3c[0] + iVar4 * 4);
          piVar5 = in_stack_0000000c;
          (**(code **)(*piVar2 + 0x74))(piVar2);
          iVar4 = iVar4 + 1;
          if (local_3c[3] <= iVar4) break;
          goto LAB_00764b68;
        }
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < local_3c[3]);
  }
  local_3c[3] = 0;
  if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x441d6a /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x441d6a /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_3c[0]);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::FireGameEvent
 * Address: 00761ab0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBotManager::FireGameEvent(IGameEvent*) */

void __thiscall CINSNextBotManager::FireGameEvent(CINSNextBotManager *this,IGameEvent *param_1)

{
  FireGameEvent(this,param_1 + -0x50);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::FireGameEvent
 * Address: 00761ac0
 * ---------------------------------------- */

/* CINSNextBotManager::FireGameEvent(IGameEvent*) */

void __thiscall CINSNextBotManager::FireGameEvent(CINSNextBotManager *this,IGameEvent *param_1)

{
  code *pcVar1;
  byte *pbVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  int iVar9;
  byte *pbVar10;
  int unaff_EBX;
  int *in_stack_00000008;
  undefined4 uVar11;
  
  __i686_get_pc_thunk_bx();
  iVar4 = (**(code **)(*in_stack_00000008 + 0x1c))();
  if (iVar4 != -1) {
    iVar9 = unaff_EBX + 0x1f1335 /* "userid" */ /* "userid" */;
    uVar11 = 0;
    iVar5 = (**(code **)(*in_stack_00000008 + 0x1c))();
    piVar6 = (int *)UTIL_PlayerByUserId(iVar5);
    if ((piVar6 == (int *)0x0) ||
       (cVar3 = (**(code **)(*piVar6 + 0x158))(piVar6,iVar9,uVar11), cVar3 == '\0')) {
      piVar6 = (int *)0x0;
    }
    if (iVar4 == 0x6e) {
      iVar4 = unaff_EBX + 0x1c6b30 /* "entityid" */ /* "entityid" */;
      uVar11 = 0;
      iVar9 = (**(code **)(*in_stack_00000008 + 0x1c))();
      pbVar2 = *(byte **)(**(int **)(unaff_EBX + 0x444dcc /* &gpGlobals */ /* &gpGlobals */) + 0x5c);
      if (((pbVar2 != (byte *)0x0) &&
          (((pbVar10 = pbVar2 + iVar9 * 0x10, (pbVar2[iVar9 * 0x10] & 2) == 0 ||
            (pbVar10 = pbVar2, (*pbVar2 & 2) == 0)) &&
           (piVar6 = *(int **)(pbVar10 + 0xc), piVar6 != (int *)0x0)))) &&
         (iVar4 = (**(code **)(*piVar6 + 0x18))(piVar6,iVar4,uVar11), iVar4 != 0)) {
        (**(code **)(*(int *)param_1 + 0x34))(param_1,iVar4);
      }
    }
    else if (iVar4 < 0x6f) {
      if (iVar4 == 0x45) {
        pcVar1 = *(code **)(*(int *)param_1 + 0x28);
        uVar11 = CINSPlayer::GetActiveINSWeapon();
        (*pcVar1)(param_1,piVar6,uVar11);
        return;
      }
      if (iVar4 == 0x6d) {
        iVar4 = unaff_EBX + 0x1c6b30 /* "entityid" */ /* "entityid" */;
        uVar11 = 0;
        iVar9 = (**(code **)(*in_stack_00000008 + 0x1c))();
        pbVar2 = *(byte **)(**(int **)(unaff_EBX + 0x444dcc /* &gpGlobals */ /* &gpGlobals */) + 0x5c);
        if (((pbVar2 != (byte *)0x0) &&
            ((pbVar10 = pbVar2 + iVar9 * 0x10, (pbVar2[iVar9 * 0x10] & 2) == 0 ||
             (pbVar10 = pbVar2, (*pbVar2 & 2) == 0)))) &&
           ((piVar6 = *(int **)(pbVar10 + 0xc), piVar6 != (int *)0x0 &&
            (iVar4 = (**(code **)(*piVar6 + 0x18))(piVar6,iVar4,uVar11), iVar4 != 0)))) {
          (**(code **)(*(int *)param_1 + 0x30))(param_1,iVar4);
        }
      }
    }
    else {
      if (iVar4 == 0x79) {
        pcVar1 = *(code **)(*(int *)param_1 + 0x3c);
        iVar4 = (**(code **)(*in_stack_00000008 + 0x1c))();
        uVar11 = *(undefined4 *)(**(int **)(unaff_EBX + 0x445248 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */) + 0x490 + iVar4 * 4);
        uVar7 = (**(code **)(*in_stack_00000008 + 0x1c))();
        uVar8 = (**(code **)(*in_stack_00000008 + 0x1c))();
        (*pcVar1)(param_1,uVar8,uVar7,uVar11);
        return;
      }
      if (iVar4 == 0x7c) {
        pcVar1 = *(code **)(*(int *)param_1 + 0x40);
        uVar11 = (**(code **)(*in_stack_00000008 + 0x1c))();
        uVar7 = (**(code **)(*in_stack_00000008 + 0x1c))();
        (*pcVar1)(param_1,uVar7,uVar11);
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::GenerateCPGrenadeTargets
 * Address: 00765df0
 * ---------------------------------------- */

/* WARNING: Restarted to delay deadcode elimination for space: stack */
/* CINSNextBotManager::GenerateCPGrenadeTargets(int, int) */

void __thiscall
CINSNextBotManager::GenerateCPGrenadeTargets(CINSNextBotManager *this,int param_1,int param_2)

{
  undefined4 *puVar1;
  uint *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  char cVar6;
  int iVar7;
  undefined4 *puVar8;
  int *piVar9;
  CUtlMemory<CINSNavArea*,int> *extraout_ECX;
  CUtlMemory<CINSNavArea*,int> *this_00;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX_00;
  CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *extraout_ECX_01;
  int unaff_EBX;
  int iVar10;
  int iVar11;
  float10 fVar12;
  float fVar13;
  CINSNextBotManager *in_stack_0000000c;
  int *local_78;
  int local_68;
  int local_54;
  int local_4c [2];
  CUtlMemory<CINSNavArea*,int> *local_44;
  CINSNavArea **local_40;
  int local_3c;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  int local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x765dfb;
  __i686_get_pc_thunk_bx();
  if (param_2 < 0) {
    DevWarning((char *)(unaff_EBX + 0x221005 /* "Tried to call GenerateCPGrenadeTargets with an invalid control point index (%..." */ /* "Tried to call GenerateCPGrenadeTargets with an invalid control point index (%..." */));
    return;
  }
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar10 = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar7 = ThreadGetCurrentId(),
     iVar10 == iVar7)) {
    piVar9 = *(int **)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar9 != unaff_EBX + 0x221061 /* "CINSNextBotManager::GenerateCPGrenadeTargets" */ /* "CINSNextBotManager::GenerateCPGrenadeTargets" */) {
      piVar9 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar9,unaff_EBX + 0x221061 /* "CINSNextBotManager::GenerateCPGrenadeTargets" */ /* "CINSNextBotManager::GenerateCPGrenadeTargets" */,(char *)0x0,
                                 unaff_EBX + 0x21ae6b /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
    }
    puVar2 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar2 = *puVar2 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  iVar11 = param_2 * 0x30 + 0x120 + (int)in_stack_0000000c * 0xc + param_1;
  iVar10 = iVar11 + 0xc;
  iVar7 = iVar10;
  fVar12 = (float10)CountdownTimer::Now();
  if ((float)fVar12 < *(float *)(iVar11 + 0x14) || (float)fVar12 == *(float *)(iVar11 + 0x14)) {
    if (local_1d == '\0') {
      return;
    }
    if ((*(char *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
       (*(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
      return;
    }
    iVar10 = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar7 = ThreadGetCurrentId(iVar7);
    if (iVar10 != iVar7) {
      return;
    }
    cVar6 = CVProfNode::ExitScope();
    iVar10 = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (cVar6 != '\0') {
      iVar10 = *(int *)(iVar10 + 100);
      *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar10;
    }
  }
  else {
    fVar12 = (float10)CountdownTimer::Now();
    fVar13 = *(float *)(unaff_EBX + 0x1c0da5 /* 40.0f */ /* 40.0f */) + (float)fVar12;
    if (*(float *)(iVar11 + 0x14) != fVar13) {
      (**(code **)(*(int *)(iVar11 + 0xc) + 4))(iVar10,iVar11 + 0x14);
      *(float *)(iVar11 + 0x14) = fVar13;
    }
    if (*(int *)(iVar11 + 0x10) != 0x42200000 /* 40.0f */) {
      (**(code **)(*(int *)(iVar11 + 0xc) + 4))(iVar10,iVar11 + 0x10);
      *(undefined4 *)(iVar11 + 0x10) = 0x42200000 /* 40.0f */;
    }
    local_78 = (int *)param_2;
    DevMsg(&UNK_00221091 + unaff_EBX);
    iVar10 = **(int **)(unaff_EBX + 0x4408bd /* &TheNavMesh */ /* &TheNavMesh */);
    if ((uint)param_2 < 0x10) {
      piVar9 = (int *)(iVar10 + 0x974 + param_2 * 0x14);
      if (piVar9 != (int *)0x0) {
        local_4c[0] = 0;
        local_4c[1] = 0;
        local_44 = (CUtlMemory<CINSNavArea*,int> *)0x0;
        local_40 = (CINSNavArea **)0x0;
        local_3c = 0;
        if (piVar9[3] < 1) {
          iVar10 = 0;
        }
        else {
          iVar10 = 0;
          do {
            local_24 = *(int *)(*piVar9 + iVar10 * 4);
            if (local_24 != 0) {
              CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>>::InsertBefore
                        ((CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *)local_4c,
                         (int)local_4c,local_40);
            }
            iVar10 = iVar10 + 1;
          } while (iVar10 < piVar9[3]);
          iVar10 = local_4c[0];
          if (0 < (int)local_40) {
            iVar10 = 0;
            do {
              uVar3 = *(undefined4 *)(local_4c[0] + iVar10 * 4);
              iVar7 = RandomInt(0,(int)local_40 + -1);
              *(undefined4 *)(local_4c[0] + iVar10 * 4) = *(undefined4 *)(local_4c[0] + iVar7 * 4);
              iVar10 = iVar10 + 1;
              *(undefined4 *)(local_4c[0] + iVar7 * 4) = uVar3;
            } while (iVar10 < (int)local_40);
            iVar10 = local_4c[0];
            if (0 < (int)local_40) {
              local_68 = 0;
              do {
                if (*(int *)(iVar10 + local_68 * 4) != 0) {
                  local_54 = 4;
                  CNavArea::GetRandomPoint();
                  while( true ) {
                    puVar8 = (undefined4 *)::operator_new(0x24);
                    uVar5 = local_28;
                    uVar4 = local_2c;
                    uVar3 = local_30;
                    puVar1 = puVar8 + 1;
                    puVar8[2] = 0;
                    puVar8[1] = unaff_EBX + 0x3c23bd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
                    CountdownTimer::NetworkStateChanged(puVar1);
                    puVar8[3] = 0xbf800000 /* -1.0f */;
                    (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 3);
                    puVar8[4] = uVar3;
                    puVar8[5] = uVar4;
                    puVar8[6] = uVar5;
                    fVar12 = (float10)CountdownTimer::Now();
                    fVar13 = *(float *)(unaff_EBX + 0x1c0da5 /* 40.0f */ /* 40.0f */) + (float)fVar12;
                    if ((float)puVar8[3] != fVar13) {
                      (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 3);
                      puVar8[3] = fVar13;
                    }
                    if (puVar8[2] != 0x42200000 /* 40.0f */) {
                      (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 2);
                      puVar8[2] = 0x42200000 /* 40.0f */;
                    }
                    *(undefined1 *)(puVar8 + 7) = 0;
                    *(undefined1 *)((int)puVar8 + 0x1d) = 0;
                    *puVar8 = 2;
                    puVar8[8] = 0x437a0000 /* 250.0f */;
                    iVar10 = TheNextBots();
                    AddGrenadeTarget(in_stack_0000000c,iVar10,(CINSGrenadeTarget *)in_stack_0000000c
                                    );
                    local_54 = local_54 + -1;
                    iVar10 = local_4c[0];
                    if (local_54 == 0) break;
                    CNavArea::GetRandomPoint();
                  }
                }
                local_68 = local_68 + 1;
              } while (local_68 < (int)local_40);
            }
          }
        }
        local_78 = local_4c;
        local_40 = (CINSNavArea **)0x0;
        this_00 = local_44;
        if (-1 < (int)local_44) {
          if (iVar10 != 0) {
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x440a7d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x440a7d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar10);
            local_4c[0] = 0;
            this_00 = extraout_ECX;
          }
          local_4c[1] = 0;
          iVar10 = 0;
        }
        local_3c = iVar10;
        CUtlMemory<CINSNavArea*,int>::~CUtlMemory(this_00);
        iVar10 = **(int **)(unaff_EBX + 0x4408bd /* &TheNavMesh */ /* &TheNavMesh */);
      }
      piVar9 = (int *)(iVar10 + 0x834 + param_2 * 0x14);
      if (piVar9 != (int *)0x0) {
        local_4c[0] = 0;
        local_4c[1] = 0;
        local_44 = (CUtlMemory<CINSNavArea*,int> *)0x0;
        local_40 = (CINSNavArea **)0x0;
        local_3c = 0;
        if (piVar9[3] < 1) {
          iVar10 = 0;
          param_2 = (int)local_4c;
        }
        else {
          iVar10 = 0;
          do {
            local_24 = *(int *)(*piVar9 + iVar10 * 4);
            if (local_24 != 0) {
              CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>>::InsertBefore
                        ((CUtlVector<CINSNavArea*,CUtlMemory<CINSNavArea*,int>> *)local_4c,
                         (int)local_4c,local_40);
              param_2 = (int)extraout_ECX_00;
            }
            iVar10 = iVar10 + 1;
          } while (iVar10 < piVar9[3]);
          iVar10 = local_4c[0];
          if (0 < (int)local_40) {
            iVar10 = 0;
            do {
              uVar3 = *(undefined4 *)(local_4c[0] + iVar10 * 4);
              iVar7 = RandomInt(0,(int)local_40 + -1);
              *(undefined4 *)(local_4c[0] + iVar10 * 4) = *(undefined4 *)(local_4c[0] + iVar7 * 4);
              iVar10 = iVar10 + 1;
              *(undefined4 *)(local_4c[0] + iVar7 * 4) = uVar3;
            } while (iVar10 < (int)local_40);
            param_2 = (int)local_4c;
            iVar10 = local_4c[0];
            if (0 < (int)local_40) {
              local_68 = 0;
              do {
                if (*(int *)(iVar10 + local_68 * 4) != 0) {
                  local_54 = 4;
                  CNavArea::GetRandomPoint();
                  while( true ) {
                    puVar8 = (undefined4 *)::operator_new(0x24);
                    uVar5 = local_28;
                    uVar4 = local_2c;
                    uVar3 = local_30;
                    puVar1 = puVar8 + 1;
                    puVar8[2] = 0;
                    puVar8[1] = unaff_EBX + 0x3c23bd /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
                    CountdownTimer::NetworkStateChanged(puVar1);
                    puVar8[3] = 0xbf800000 /* -1.0f */;
                    (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 3);
                    puVar8[4] = uVar3;
                    puVar8[5] = uVar4;
                    puVar8[6] = uVar5;
                    fVar12 = (float10)CountdownTimer::Now();
                    fVar13 = *(float *)(unaff_EBX + 0x1c0da5 /* 40.0f */ /* 40.0f */) + (float)fVar12;
                    if ((float)puVar8[3] != fVar13) {
                      (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 3);
                      puVar8[3] = fVar13;
                    }
                    if (puVar8[2] != 0x42200000 /* 40.0f */) {
                      (**(code **)(puVar8[1] + 4))(puVar1,puVar8 + 2);
                      puVar8[2] = 0x42200000 /* 40.0f */;
                    }
                    *(undefined1 *)(puVar8 + 7) = 0;
                    *(undefined1 *)((int)puVar8 + 0x1d) = 0;
                    *puVar8 = 9;
                    puVar8[8] = 0x435c0000 /* 220.0f */;
                    iVar10 = TheNextBots();
                    AddGrenadeTarget(in_stack_0000000c,iVar10,(CINSGrenadeTarget *)in_stack_0000000c
                                    );
                    local_54 = local_54 + -1;
                    iVar10 = local_4c[0];
                    if (local_54 == 0) break;
                    CNavArea::GetRandomPoint();
                  }
                }
                local_68 = local_68 + 1;
              } while (local_68 < (int)local_40);
            }
          }
        }
        local_78 = local_4c;
        local_40 = (CINSNavArea **)0x0;
        if (-1 < (int)local_44) {
          if (iVar10 != 0) {
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x440a7d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x440a7d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar10);
            local_4c[0] = 0;
            param_2 = (int)extraout_ECX_01;
          }
          local_4c[1] = 0;
          iVar10 = 0;
        }
        local_3c = iVar10;
        CUtlMemory<CINSNavArea*,int>::~CUtlMemory((CUtlMemory<CINSNavArea*,int> *)param_2);
      }
    }
    if (local_1d == '\0') {
      return;
    }
    if ((*(char *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
       (*(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
      return;
    }
    iVar10 = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar7 = ThreadGetCurrentId(local_78);
    if (iVar10 != iVar7) {
      return;
    }
    cVar6 = CVProfNode::ExitScope();
    if (cVar6 == '\0') {
      iVar10 = *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar10 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar10;
    }
  }
  *(bool *)(*(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
       iVar10 == *(int *)(unaff_EBX + 0x440b79 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::GetActiveGrenade
 * Address: 00762fc0
 * ---------------------------------------- */

/* CINSNextBotManager::GetActiveGrenade(int) */

undefined4 __thiscall CINSNextBotManager::GetActiveGrenade(CINSNextBotManager *this,int param_1)

{
  int in_stack_00000008;
  
  if (((0 < *(int *)(param_1 + 0x68)) && (-1 < in_stack_00000008)) &&
     (in_stack_00000008 < *(int *)(param_1 + 0x68))) {
    return *(undefined4 *)(*(int *)(param_1 + 0x5c) + in_stack_00000008 * 4);
  }
  return 0;
}



/* ----------------------------------------
 * CINSNextBotManager::GetAverageDirectionToPlayersOnTeam
 * Address: 00762cf0
 * ---------------------------------------- */

/* CINSNextBotManager::GetAverageDirectionToPlayersOnTeam(Vector, int) */

Vector * CINSNextBotManager::GetAverageDirectionToPlayersOnTeam
                   (Vector *param_1,undefined4 param_2,float param_3,float param_4,float param_5,
                   int param_6)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CBaseEntity *this;
  int unaff_EBX;
  int iVar4;
  float fVar5;
  float local_2c;
  float local_28;
  int local_24;
  float local_20;
  
  local_2c = 0.0;
  iVar4 = 1;
  __i686_get_pc_thunk_bx();
  local_24 = 0;
  local_28 = local_2c;
  local_20 = local_2c;
  do {
    while ((((piVar2 = (int *)UTIL_PlayerByIndex(iVar4), piVar2 == (int *)0x0 ||
             (cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2), cVar1 == '\0')) ||
            (cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2), cVar1 == '\0')) ||
           (iVar3 = CINSPlayer::GetTeamID(), iVar3 != param_6))) {
      iVar4 = iVar4 + 1;
      if (iVar4 == 0x31) goto LAB_00762dc8;
    }
    if ((*(byte *)((int)piVar2 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    iVar4 = iVar4 + 1;
    local_24 = local_24 + 1;
    local_20 = local_20 + (float)piVar2[0x82];
    local_2c = local_2c + (float)piVar2[0x83];
    local_28 = local_28 + (float)piVar2[0x84];
  } while (iVar4 != 0x31);
LAB_00762dc8:
  fVar5 = *(float *)(unaff_EBX + 0x155e11 /* 1.0f */ /* 1.0f */) / (float)local_24;
  *(float *)(param_1 + 4) = local_2c * fVar5 - param_4;
  *(float *)(param_1 + 8) = local_28 * fVar5 - param_5;
  *(float *)param_1 = fVar5 * local_20 - param_3;
  VectorNormalize(param_1);
  return param_1;
}



/* ----------------------------------------
 * CINSNextBotManager::GetCallForReinforcementCooldown
 * Address: 007629f0
 * ---------------------------------------- */

/* CINSNextBotManager::GetCallForReinforcementCooldown() */

float10 CINSNextBotManager::GetCallForReinforcementCooldown(void)

{
  int *piVar1;
  char cVar2;
  CINSRules *this;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  
  fVar4 = 0.0;
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(unaff_EBX + 0x443ef7 /* &g_pGameRules */ /* &g_pGameRules */);
  if (*piVar1 != 0) {
    cVar2 = CINSRules::IsSurvival(this);
    fVar4 = *(float *)(unaff_EBX + 0x1c17af /* 10.0f */ /* 10.0f */);
    if (cVar2 != '\0') {
      fVar3 = (float10)RandomFloat(0x42200000 /* 40.0f */,0x42480000 /* 50.0f */);
      fVar4 = (*(float *)(unaff_EBX + 0x1c67c3 /* -10.0f */ /* -10.0f */) -
              ((float)*(int *)(*piVar1 + 1000) + *(float *)(unaff_EBX + 0x15610f /* -1.0f */ /* -1.0f */)) *
              *(float *)(unaff_EBX + 0x224567 /* CSWTCH.989+0x24 */ /* CSWTCH.989+0x24 */)) + (float)fVar3;
    }
  }
  return (float10)fVar4;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredBattleTypeObjective
 * Address: 007621a0
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredBattleTypeObjective(CINSNextBot*) */

CBaseEntity * __thiscall
CINSNextBotManager::GetDesiredBattleTypeObjective(CINSNextBotManager *this,CINSNextBot *param_1)

{
  int *piVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *this_01;
  int unaff_EBX;
  CBaseEntity *pCVar5;
  int iVar6;
  CBaseEntity *pCVar7;
  int in_stack_00000008;
  int local_6c;
  int local_68;
  int local_64;
  int local_60;
  int local_5c [18];
  undefined4 uStack_14;
  
  pCVar5 = (CBaseEntity *)0x0;
  uStack_14 = 0x7621ad;
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(unaff_EBX + 0x444b6f /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
  if (((*(int *)(*piVar1 + 0x37c) != 0) && (*(int *)(*piVar1 + 0x37c) < 0x11)) &&
     (iVar3 = CBaseEntity::GetTeamNumber(this_00), iVar3 - 2U < 2)) {
    iVar3 = *piVar1;
    pCVar5 = extraout_ECX;
    if (0 < *(int *)(iVar3 + 0x37c)) {
      iVar6 = 0;
      local_64 = 0;
      local_68 = 0;
      local_60 = 0;
      local_6c = 0;
      do {
        while( true ) {
          iVar3 = *(int *)(iVar3 + 0x490 + iVar6 * 4);
          local_5c[iVar6] = iVar3;
          if (iVar3 - 2U < 2) {
            iVar4 = CBaseEntity::GetTeamNumber(pCVar5);
            if (iVar4 == iVar3) {
              local_6c = local_6c + 1;
            }
            else {
              local_68 = local_68 + 1;
            }
          }
          else {
            local_60 = local_60 + 1;
          }
          iVar3 = *piVar1;
          iVar4 = *(int *)(iVar3 + 0x450 + iVar6 * 4);
          pCVar5 = (CBaseEntity *)(iVar4 + -2);
          if (pCVar5 < (CBaseEntity *)0x2) break;
          pCVar5 = *(CBaseEntity **)(iVar3 + 0x37c);
          iVar6 = iVar6 + 1;
          if ((int)pCVar5 <= iVar6) goto LAB_007622b0;
        }
        iVar3 = CBaseEntity::GetTeamNumber(pCVar5);
        if (iVar3 != iVar4) {
          local_64 = local_64 + 1;
        }
        iVar3 = *piVar1;
        iVar6 = iVar6 + 1;
        pCVar5 = *(CBaseEntity **)(iVar3 + 0x37c);
      } while (iVar6 < (int)pCVar5);
LAB_007622b0:
      if (local_60 == 0) {
        bVar2 = local_64 == 0 && local_68 == 1;
      }
      else {
        if (0 < (int)pCVar5) {
          pCVar7 = (CBaseEntity *)0x0;
          while( true ) {
            if (local_5c[0] == 0) {
              return pCVar7;
            }
            pCVar7 = pCVar7 + 1;
            if (pCVar7 == pCVar5) break;
            local_5c[0] = local_5c[(int)pCVar7];
          }
        }
        bVar2 = (local_64 == 0 && local_60 == 0) && local_68 == 1;
      }
      pCVar5 = (CBaseEntity *)CONCAT31((int3)((uint)pCVar5 >> 8),local_68 == 1);
      if ((bVar2) && (0 < *(int *)(*piVar1 + 0x37c))) {
        pCVar7 = (CBaseEntity *)0x0;
        do {
          iVar3 = local_5c[(int)pCVar7];
          if ((iVar3 - 2U < 2) &&
             (iVar6 = CBaseEntity::GetTeamNumber(pCVar5), pCVar5 = extraout_ECX_00, iVar3 != iVar6))
          {
            return pCVar7;
          }
          pCVar7 = pCVar7 + 1;
        } while ((int)pCVar7 < *(int *)(*piVar1 + 0x37c));
      }
      if (((local_64 == 1) && (local_6c == 1)) && (0 < *(int *)(*piVar1 + 0x37c))) {
        pCVar7 = (CBaseEntity *)0x0;
        do {
          iVar3 = local_5c[(int)pCVar7];
          iVar4 = CBaseEntity::GetTeamNumber(pCVar5);
          iVar6 = *piVar1;
          pCVar5 = extraout_ECX_01;
          if (iVar3 == iVar4) {
            iVar3 = *(int *)(iVar6 + 0x450 + (int)pCVar7 * 4);
            pCVar5 = (CBaseEntity *)(iVar3 + -2);
            if (pCVar5 < (CBaseEntity *)0x2) {
              iVar6 = CBaseEntity::GetTeamNumber(pCVar5);
              if (iVar6 != iVar3) {
                return pCVar7;
              }
              iVar6 = *piVar1;
              pCVar5 = extraout_ECX_02;
            }
          }
          pCVar7 = pCVar7 + 1;
        } while ((int)pCVar7 < *(int *)(iVar6 + 0x37c));
      }
    }
    if ((*(byte *)(in_stack_00000008 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar5);
      pCVar5 = extraout_ECX_03;
    }
    iVar3 = CBaseEntity::GetTeamNumber(pCVar5);
    pCVar7 = (CBaseEntity *)((uint)(iVar3 == 2) * 3 + -1);
    iVar3 = CBaseEntity::GetTeamNumber(this_01);
    if (iVar3 == 3) {
      pCVar5 = (CBaseEntity *)0x2;
    }
    else {
      pCVar5 = (CBaseEntity *)0x0;
      if (pCVar7 != (CBaseEntity *)0xffffffff) {
        pCVar5 = pCVar7;
      }
    }
  }
  return pCVar5;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredHuntTypeObjective
 * Address: 00762710
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredHuntTypeObjective(CINSNextBot*) */

int __cdecl CINSNextBotManager::GetDesiredHuntTypeObjective(CINSNextBot *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  CINSRules *this;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (((**(int **)(unaff_EBX + 0x4441de /* &g_pGameRules */ /* &g_pGameRules */) != 0) &&
      (piVar1 = *(int **)(unaff_EBX + 0x444602 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */), *piVar1 != 0)) &&
     (cVar4 = CINSRules::IsHunt(this), cVar4 != '\0')) {
    iVar2 = *piVar1;
    if (0 < *(int *)(iVar2 + 0x37c)) {
      iVar5 = 0;
      iVar3 = *(int *)(iVar2 + 0x6f0);
      while( true ) {
        if (iVar3 != 1) {
          return iVar5;
        }
        iVar5 = iVar5 + 1;
        if (iVar5 == *(int *)(iVar2 + 0x37c)) break;
        iVar3 = *(int *)(iVar2 + 0x6f0 + iVar5 * 4);
      }
    }
  }
  DevMsg((char *)(unaff_EBX + 0x22451a /* "Failed to load active Hunt objective
" */ /* "Failed to load active Hunt objective
" */));
  return -1;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredOccupyTypeObjective
 * Address: 007624f0
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredOccupyTypeObjective(CINSNextBot*) */

int __thiscall
CINSNextBotManager::GetDesiredOccupyTypeObjective(CINSNextBotManager *this,CINSNextBot *param_1)

{
  float *pfVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  int iVar6;
  int iVar7;
  int unaff_EBX;
  int iVar8;
  int iVar9;
  int iVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  int in_stack_00000008;
  float local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  piVar2 = *(int **)(&DAT_0044481f + unaff_EBX);
  iVar5 = *(int *)(*piVar2 + 0x37c);
  if (iVar5 == 0) {
    return 0;
  }
  iVar4 = CBaseEntity::GetTeamNumber(this_00);
  if ((*(byte *)(in_stack_00000008 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_01);
  }
  iVar8 = -1;
  iVar10 = -1;
  if (0 < iVar5) {
    iVar3 = *piVar2;
    fVar17 = 0.0;
    local_28 = 0.0;
    local_24 = 0.0;
    iVar6 = iVar3 + 0x5d0;
    iVar7 = 0;
    iVar9 = -1;
    do {
      if ((iVar4 != *(int *)(iVar3 + 0x490 + iVar7 * 4)) || (iVar8 = iVar9, 1 < iVar4 - 2U)) {
        pfVar1 = (float *)(unaff_EBX + 0x1c6ccf /* -0.01f */ /* -0.01f */);
        iVar8 = iVar7;
        if (((fVar17 < *(float *)(unaff_EBX + 0x1c6ccf /* -0.01f */ /* -0.01f */) ||
              fVar17 == *(float *)(unaff_EBX + 0x1c6ccf /* -0.01f */ /* -0.01f */)) ||
            (((*(float *)(unaff_EBX + 0x1c2b33 /* 0.01f */ /* 0.01f */) <= fVar17 ||
              (local_24 < *pfVar1 || local_24 == *pfVar1)) ||
             (*(float *)(unaff_EBX + 0x1c2b33 /* 0.01f */ /* 0.01f */) <= local_24)))) ||
           ((local_28 < *pfVar1 || local_28 == *pfVar1 ||
            (*(float *)(unaff_EBX + 0x1c2b33 /* 0.01f */ /* 0.01f */) <= local_28)))) {
          fVar14 = *(float *)(in_stack_00000008 + 0x208) - fVar17;
          fVar13 = *(float *)(in_stack_00000008 + 0x20c) - local_24;
          fVar11 = *(float *)(in_stack_00000008 + 0x210) - local_28;
          pfVar1 = (float *)(iVar6 + iVar7 * 0xc);
          fVar16 = *(float *)(in_stack_00000008 + 0x208) - *pfVar1;
          fVar15 = *(float *)(in_stack_00000008 + 0x210) - pfVar1[2];
          fVar12 = *(float *)(in_stack_00000008 + 0x20c) - pfVar1[1];
          if (SQRT(fVar12 * fVar12 + fVar16 * fVar16 + fVar15 * fVar15) <
              SQRT(fVar13 * fVar13 + fVar14 * fVar14 + fVar11 * fVar11)) {
            iVar8 = iVar9;
            iVar10 = iVar7;
          }
        }
        else {
          pfVar1 = (float *)(iVar6 + iVar7 * 0xc);
          local_24 = pfVar1[1];
          local_28 = pfVar1[2];
          fVar17 = *pfVar1;
          iVar10 = iVar7;
        }
      }
      iVar7 = iVar7 + 1;
      iVar9 = iVar8;
    } while (iVar7 != iVar5);
  }
  iVar5 = RandomInt(0,1);
  if (iVar5 < 1) {
    iVar8 = iVar10;
  }
  return iVar8;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredPushTypeObjective
 * Address: 00762450
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredPushTypeObjective(CINSNextBot*) */

undefined4 __cdecl CINSNextBotManager::GetDesiredPushTypeObjective(CINSNextBot *param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  CINSRules *this;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSRules *this_02;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (((**(int **)(unaff_EBX + 0x44449a /* &g_pGameRules */ /* &g_pGameRules */) == 0) ||
      (piVar1 = *(int **)(unaff_EBX + 0x4448be /* &g_pObjectiveResource */ /* &g_pObjectiveResource */), *piVar1 == 0)) ||
     ((cVar2 = CINSRules::IsPush(this), cVar2 == '\0' &&
      (((cVar2 = CINSRules::IsInvasion(this_00), cVar2 == '\0' &&
        (cVar2 = CINSRules::IsCheckpoint(this_01), cVar2 == '\0')) &&
       (cVar2 = CINSRules::IsConquer(this_02), cVar2 == '\0')))))) {
    DevMsg((char *)(unaff_EBX + 0x2247a2 /* "Failed to load active Push / Checkpoint objective
" */ /* "Failed to load active Push / Checkpoint objective
" */));
    uVar3 = 0xffffffff;
  }
  else {
    uVar3 = *(undefined4 *)(*piVar1 + 0x770);
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredSkirmishObjective
 * Address: 00761e40
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredSkirmishObjective(CINSNextBot*) */

int __cdecl CINSNextBotManager::GetDesiredSkirmishObjective(CINSNextBot *param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_01;
  CBaseEntity *pCVar6;
  CBaseEntity *this_02;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_03;
  CBaseEntity *this_04;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *this_05;
  CBaseEntity *this_06;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *extraout_ECX_04;
  int unaff_EBX;
  int iVar7;
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  int local_64;
  int local_60;
  int aiStack_5c [19];
  
  __i686_get_pc_thunk_bx();
  local_70 = 2;
  piVar1 = *(int **)(unaff_EBX + 0x444ecb /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
  if ((((*(int *)(*piVar1 + 0x37c) != 0) && (*(int *)(*piVar1 + 0x37c) < 0x11)) &&
      (iVar3 = CBaseEntity::GetTeamNumber(this), iVar3 - 2U < 2)) &&
     ((cVar2 = CINSNextBot::HasExplosive(), pCVar6 = this_00, cVar2 == '\0' ||
      (((iVar3 = CBaseEntity::GetTeamNumber(this_00), iVar3 != 2 ||
        (local_70 = 4, *(int *)(*piVar1 + 0x4a0) != 3)) &&
       ((iVar3 = CBaseEntity::GetTeamNumber(this_06), pCVar6 = extraout_ECX_02, iVar3 != 3 ||
        (local_70 = 0, *(int *)(*piVar1 + 0x490) != 2)))))))) {
    iVar3 = *piVar1;
    iVar4 = *(int *)(iVar3 + 0x37c);
    if (iVar4 < 1) {
      local_64 = 0;
      local_60 = 0;
      local_6c = 2;
      local_74 = 1;
    }
    else {
      iVar7 = 0;
      local_60 = 0;
      local_64 = 0;
      do {
        iVar4 = *(int *)(iVar3 + 0x490 + iVar7 * 4);
        iVar3 = *(int *)(iVar3 + 0x450 + iVar7 * 4);
        if (((CBaseEntity *)(iVar3 + -2) < (CBaseEntity *)0x2) && (iVar4 != iVar3)) {
          aiStack_5c[iVar7] = iVar3;
          iVar4 = iVar3;
        }
        else {
          aiStack_5c[iVar7] = iVar4;
          if (1 < iVar4 - 2U) {
            return iVar7;
          }
        }
        iVar3 = CBaseEntity::GetTeamNumber((CBaseEntity *)(iVar3 + -2));
        if (iVar3 == iVar4) {
          local_64 = local_64 + 1;
        }
        else {
          local_60 = local_60 + 1;
        }
        iVar3 = *piVar1;
        iVar7 = iVar7 + 1;
        iVar4 = *(int *)(iVar3 + 0x37c);
      } while (iVar7 < iVar4);
      pCVar6 = extraout_ECX;
      if (iVar4 < 1) {
        local_6c = 2;
        local_74 = 1;
      }
      else {
        iVar3 = 0;
        local_6c = 2;
        local_74 = 1;
        do {
          iVar4 = CBaseEntity::GetTeamNumber(pCVar6);
          pCVar6 = this_02;
          if ((((iVar4 != 2) ||
               (iVar4 = aiStack_5c[iVar3], iVar5 = CBaseEntity::GetTeamNumber(this_02),
               pCVar6 = extraout_ECX_00, iVar7 = iVar3, iVar4 != iVar5)) &&
              (iVar4 = CBaseEntity::GetTeamNumber(pCVar6), pCVar6 = this_01, iVar7 = local_74,
              iVar4 == 3)) &&
             (iVar4 = aiStack_5c[iVar3], iVar5 = CBaseEntity::GetTeamNumber(this_01),
             pCVar6 = extraout_ECX_04, iVar4 != iVar5)) {
            local_6c = iVar3;
          }
          local_74 = iVar7;
          iVar3 = iVar3 + 1;
          iVar4 = *(int *)(*piVar1 + 0x37c);
        } while (iVar3 < iVar4);
      }
    }
    local_78 = 3;
    iVar4 = iVar4 + -1;
    local_70 = 2;
    if (-1 < iVar4) {
      do {
        iVar3 = CBaseEntity::GetTeamNumber(pCVar6);
        pCVar6 = this_04;
        if (((iVar3 != 3) ||
            (iVar3 = aiStack_5c[iVar4], iVar5 = CBaseEntity::GetTeamNumber(this_04),
            pCVar6 = extraout_ECX_01, iVar7 = iVar4, iVar3 != iVar5)) &&
           ((iVar3 = CBaseEntity::GetTeamNumber(pCVar6), pCVar6 = this_03, iVar7 = local_78,
            iVar3 == 2 &&
            (iVar3 = aiStack_5c[iVar4], iVar5 = CBaseEntity::GetTeamNumber(this_03),
            pCVar6 = extraout_ECX_03, iVar3 != iVar5)))) {
          local_70 = iVar4;
        }
        local_78 = iVar7;
        iVar4 = iVar4 + -1;
      } while (iVar4 != -1);
    }
    if (local_60 < local_64) {
      iVar3 = CBaseEntity::GetTeamNumber(pCVar6);
      if (iVar3 == 2) {
        iVar3 = RandomInt(0,1);
        if (iVar3 < 1) {
          local_70 = local_74;
        }
      }
      else {
        iVar3 = CBaseEntity::GetTeamNumber(this_05);
        if (iVar3 == 3) {
          iVar3 = RandomInt(0,1);
          local_70 = local_6c;
          if (iVar3 < 1) {
            local_70 = local_78;
          }
        }
        else {
          local_70 = 2;
          if (*(int *)(*piVar1 + 0x37c) != 5) {
            local_70 = (*(int *)(*piVar1 + 0x37c) != 3) + 1;
          }
        }
      }
    }
    else {
      iVar3 = CBaseEntity::GetTeamNumber(pCVar6);
      if (iVar3 != 2) {
        local_70 = local_6c;
      }
    }
  }
  return local_70;
}



/* ----------------------------------------
 * CINSNextBotManager::GetDesiredStrongholdTypeObjective
 * Address: 00765790
 * ---------------------------------------- */

/* CINSNextBotManager::GetDesiredStrongholdTypeObjective(CINSNextBot*, CUtlVector<int,
   CUtlMemory<int, int> >&) */

int __thiscall
CINSNextBotManager::GetDesiredStrongholdTypeObjective
          (CINSNextBotManager *this,CINSNextBot *param_1,CUtlVector *param_2)

{
  float *pfVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  CINSRules *this_00;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSRules *this_03;
  CINSRules *this_04;
  CINSRules *this_05;
  CINSRules *pCVar10;
  CBaseEntity *this_06;
  CINSRules *extraout_ECX;
  CUtlVector<int,CUtlMemory<int,int>> *this_07;
  CBaseEntity *extraout_ECX_00;
  CINSRules CVar11;
  int unaff_EBX;
  float fVar12;
  float fVar13;
  int in_stack_0000000c;
  float local_44;
  int local_38;
  int local_2c;
  
  __i686_get_pc_thunk_bx();
  local_38 = 0;
  piVar4 = *(int **)(unaff_EBX + 0x441581 /* &g_pObjectiveResource */ /* &g_pObjectiveResource */);
  iVar5 = *(int *)(*piVar4 + 0x37c);
  if (iVar5 != 0) {
    iVar7 = CBaseEntity::GetTeamNumber(this_01);
    if (((byte)param_2[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_02);
    }
    local_2c = 0;
    local_38 = -1;
    if (0 < iVar5) {
      local_44 = *(float *)(unaff_EBX + 0x1c3a11 /* FLT_MAX */ /* FLT_MAX */);
      do {
        this_00 = (CINSRules *)*piVar4;
        pCVar10 = this_00 + local_2c * 0xc + 0x5d0;
        fVar12 = *(float *)pCVar10;
        fVar2 = *(float *)(pCVar10 + 8);
        fVar3 = *(float *)(pCVar10 + 4);
        pfVar1 = (float *)(&LAB_001c3a31 + unaff_EBX);
        if (((((fVar12 < *(float *)(&LAB_001c3a31 + unaff_EBX) ||
                fVar12 == *(float *)(&LAB_001c3a31 + unaff_EBX)) ||
              (fVar13 = *(float *)(unaff_EBX + 0x1bf895 /* 0.01f */ /* 0.01f */), fVar13 <= fVar12)) ||
             (fVar3 < *pfVar1 || fVar3 == *pfVar1)) ||
            ((fVar13 <= fVar3 || (fVar2 < *pfVar1 || fVar2 == *pfVar1)))) || (fVar13 <= fVar2)) {
          if (iVar7 == 2) {
            CVar11 = this_00[local_2c + 0x690];
LAB_00765908:
            if (CVar11 != (CINSRules)0x0) goto LAB_007658e3;
          }
          else if (iVar7 == 3) {
            CVar11 = this_00[local_2c + 0x6a0];
            goto LAB_00765908;
          }
          iVar6 = *(int *)(this_00 + local_2c * 4 + 0x490);
          iVar8 = CINSRules::GetAttackingTeam(this_00);
          pCVar10 = this_03;
          if ((iVar7 == iVar8) &&
             (iVar8 = CINSRules::GetDefendingTeam(this_03), pCVar10 = (CINSRules *)this_06,
             iVar8 == iVar6)) {
            if (((byte)param_2[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_06);
              pCVar10 = extraout_ECX;
            }
            fVar13 = SQRT((*(float *)(param_2 + 0x20c) - fVar3) *
                          (*(float *)(param_2 + 0x20c) - fVar3) +
                          (*(float *)(param_2 + 0x208) - fVar12) *
                          (*(float *)(param_2 + 0x208) - fVar12) +
                          (*(float *)(param_2 + 0x210) - fVar2) *
                          (*(float *)(param_2 + 0x210) - fVar2));
            if (fVar13 < local_44) {
              local_38 = local_2c;
              local_44 = fVar13;
            }
          }
          iVar8 = CINSRules::GetDefendingTeam(pCVar10);
          if (iVar7 == iVar8) {
            iVar8 = *(int *)(*piVar4 + 0x450 + local_2c * 4);
            iVar9 = CINSRules::GetAttackingTeam(this_04);
            pCVar10 = this_05;
            if ((iVar9 == iVar8) &&
               (iVar8 = *(int *)(*piVar4 + 0x490 + iVar6 * 4),
               iVar9 = CINSRules::GetDefendingTeam(this_05), pCVar10 = (CINSRules *)this_07,
               iVar9 == iVar8)) {
              CUtlVector<int,CUtlMemory<int,int>>::InsertBefore
                        (this_07,in_stack_0000000c,*(int **)(in_stack_0000000c + 0xc));
              pCVar10 = (CINSRules *)extraout_ECX_00;
            }
            if (iVar7 == iVar6) {
              if (((byte)param_2[0xd1] & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition((CBaseEntity *)pCVar10);
              }
              fVar12 = SQRT((*(float *)(param_2 + 0x20c) - fVar3) *
                            (*(float *)(param_2 + 0x20c) - fVar3) +
                            (*(float *)(param_2 + 0x208) - fVar12) *
                            (*(float *)(param_2 + 0x208) - fVar12) +
                            (*(float *)(param_2 + 0x210) - fVar2) *
                            (*(float *)(param_2 + 0x210) - fVar2));
              if (fVar12 < local_44) {
                local_38 = local_2c;
                local_44 = fVar12;
              }
            }
          }
        }
LAB_007658e3:
        local_2c = local_2c + 1;
        if (iVar5 <= local_2c) {
          return local_38;
        }
      } while( true );
    }
  }
  return local_38;
}



/* ----------------------------------------
 * CINSNextBotManager::GetGrenadeTargets
 * Address: 007636c0
 * ---------------------------------------- */

/* CINSNextBotManager::GetGrenadeTargets(int) */

int __thiscall CINSNextBotManager::GetGrenadeTargets(CINSNextBotManager *this,int param_1)

{
  int iVar1;
  int in_stack_00000008;
  
  iVar1 = 0;
  if (in_stack_00000008 - 2U < 2) {
    iVar1 = param_1 + 0xe8 + (uint)(in_stack_00000008 != 2) * 0x14;
  }
  return iVar1;
}



/* ----------------------------------------
 * CINSNextBotManager::GetThrownGrenade
 * Address: 00763010
 * ---------------------------------------- */

/* CINSNextBotManager::GetThrownGrenade(int) */

void CINSNextBotManager::GetThrownGrenade(int param_1)

{
  int in_stack_00000008;
  int in_stack_0000000c;
  
  if (((0 < *(int *)(in_stack_00000008 + 0x7c)) && (-1 < in_stack_0000000c)) &&
     (in_stack_0000000c < *(int *)(in_stack_00000008 + 0x7c))) {
    *(undefined4 *)param_1 =
         *(undefined4 *)(*(int *)(in_stack_00000008 + 0x70) + in_stack_0000000c * 4);
    return;
  }
  *(undefined4 *)param_1 = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::GetTotalActiveGrenades
 * Address: 00762fb0
 * ---------------------------------------- */

/* CINSNextBotManager::GetTotalActiveGrenades() */

undefined4 __thiscall CINSNextBotManager::GetTotalActiveGrenades(CINSNextBotManager *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x68);
}



/* ----------------------------------------
 * CINSNextBotManager::GetTotalThrownGrenades
 * Address: 00763000
 * ---------------------------------------- */

/* CINSNextBotManager::GetTotalThrownGrenades() */

undefined4 __thiscall CINSNextBotManager::GetTotalThrownGrenades(CINSNextBotManager *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x7c);
}



/* ----------------------------------------
 * CINSNextBotManager::Init
 * Address: 00766ef0
 * ---------------------------------------- */

/* CINSNextBotManager::Init() */

void __thiscall CINSNextBotManager::Init(CINSNextBotManager *this)

{
  int iVar1;
  undefined4 *puVar2;
  code *pcVar3;
  int *piVar4;
  undefined4 uVar5;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  puVar2 = *(undefined4 **)(unaff_EBX + 0x43ffd5 /* &gameeventmanager */ /* &gameeventmanager */);
  pcVar3 = *(code **)(*(int *)*puVar2 + 0x10);
  uVar5 = LookupEventByID(0x45);
  iVar1 = in_stack_00000004 + 0x50;
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x79);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x7c);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x6d);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x6e);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x6f);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  piVar4 = (int *)*puVar2;
  *(undefined1 *)(in_stack_00000004 + 0x58) = 1;
  pcVar3 = *(code **)(*piVar4 + 0x10);
  uVar5 = LookupEventByID(0x70);
  (*pcVar3)(*puVar2,iVar1,uVar5,1);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::IsAllBotTeam
 * Address: 00762c30
 * ---------------------------------------- */

/* CINSNextBotManager::IsAllBotTeam(int) */

bool __thiscall CINSNextBotManager::IsAllBotTeam(CINSNextBotManager *this,int param_1)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  bool bVar6;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)GetGlobalTeam(in_stack_00000008);
  bVar6 = false;
  if (piVar2 != (int *)0x0) {
    iVar3 = (**(code **)(*piVar2 + 0x348 /* CBaseAnimating::GetBoneTransform */))(piVar2);
    if (0 < iVar3) {
      iVar5 = 0;
      do {
        piVar4 = (int *)(**(code **)(*piVar2 + 0x34c /* CINSPlayer::SetupBones */))(piVar2,iVar5);
        if (piVar4 != (int *)0x0) {
          cVar1 = (**(code **)(*piVar4 + 0x158 /* CBasePlayer::IsPlayer */))(piVar4);
          if (cVar1 != '\0') {
            cVar1 = (**(code **)(*piVar4 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar4);
            if (cVar1 == '\0') {
              return false;
            }
          }
        }
        iVar5 = iVar5 + 1;
      } while (iVar5 != iVar3);
    }
    iVar3 = (**(code **)(*piVar2 + 0x348 /* CBaseAnimating::GetBoneTransform */))(piVar2);
    bVar6 = iVar3 != 0;
  }
  return bVar6;
}



/* ----------------------------------------
 * CINSNextBotManager::IssueOrder
 * Address: 00764090
 * ---------------------------------------- */

/* CINSNextBotManager::IssueOrder(int, eRadialCommands, int, Vector, OrderPriority, int, float) */

void __cdecl
CINSNextBotManager::IssueOrder
          (CUtlVector *param_1,int param_2,int *param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9,
          undefined4 param_10)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  NextBotManager *this;
  CBaseEntity *this_00;
  int unaff_EBX;
  int iVar5;
  int *piVar6;
  int local_3c [10];
  undefined4 uStack_14;
  
  piVar6 = local_3c;
  uStack_14 = 0x76409e;
  __i686_get_pc_thunk_bx();
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_3c[3] = 0;
  local_3c[4] = 0;
  NextBotManager::CollectAllBots(this,param_1);
  iVar5 = 0;
  if (0 < local_3c[3]) {
    do {
      while( true ) {
        piVar3 = *(int **)(local_3c[0] + iVar5 * 4);
        iVar1 = iVar5 * 4;
        piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3,piVar6);
        cVar2 = (**(code **)(*piVar3 + 0x118))(piVar3);
        if (cVar2 != '\0') break;
LAB_007640f0:
        iVar5 = iVar5 + 1;
        if (local_3c[3] <= iVar5) goto LAB_007641c0;
      }
      (**(code **)(**(int **)(local_3c[0] + iVar1) + 200))(*(int **)(local_3c[0] + iVar1));
      iVar4 = CBaseEntity::GetTeamNumber(this_00);
      if (((iVar4 != param_2) || (*(int *)(local_3c[0] + iVar1) == 0)) ||
         (iVar4 = *(int *)(local_3c[0] + iVar1) + -0x2060, iVar4 == 0)) goto LAB_007640f0;
      piVar6 = param_3;
      CINSNextBot::AddOrder(iVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
      (**(code **)(**(int **)(local_3c[0] + iVar1) + 0xb4))(*(int **)(local_3c[0] + iVar1));
      iVar5 = iVar5 + 1;
    } while (iVar5 < local_3c[3]);
  }
LAB_007641c0:
  local_3c[3] = 0;
  if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4427da /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x4427da /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_3c[0]);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnEnemySight
 * Address: 007617e0
 * ---------------------------------------- */

/* CINSNextBotManager::OnEnemySight(CINSNextBot*, CBaseEntity*) */

void __thiscall
CINSNextBotManager::OnEnemySight(CINSNextBotManager *this,CINSNextBot *param_1,CBaseEntity *param_2)

{
  code *pcVar1;
  int *piVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  float fVar8;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  uint uVar9;
  int unaff_EBX;
  float10 fVar10;
  float10 fVar11;
  undefined4 in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  uVar9 = (uint)*(ushort *)(param_1 + 0x10);
  if (uVar9 != 0xffff) {
    iVar5 = *(int *)(param_1 + 4);
    do {
      piVar7 = *(int **)(iVar5 + uVar9 * 8);
      piVar4 = (int *)(**(code **)(*piVar7 + 200))(piVar7);
      cVar3 = (**(code **)(*piVar4 + 0x118))(piVar4);
      if (cVar3 != '\0') {
        (**(code **)(*piVar7 + 200))(piVar7);
        iVar5 = CBaseEntity::GetTeamNumber(this_00);
        iVar6 = CBaseEntity::GetTeamNumber(this_01);
        if (iVar5 == iVar6) {
          pcVar1 = *(code **)(*piVar7 + 0x134);
          if (((byte)param_2[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(param_2);
          }
          fVar10 = (float10)(*pcVar1)(piVar7,param_2 + 0x208);
          piVar4 = *(int **)(&LAB_00445969 + unaff_EBX);
          piVar2 = (int *)piVar4[7];
          if (piVar2 == piVar4) {
            fVar8 = (float)(piVar4[0xb] ^ (uint)piVar4);
          }
          else {
            fVar11 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
            fVar8 = (float)fVar11;
          }
          if ((float)fVar10 < fVar8) {
            piVar7 = (int *)(**(code **)(*piVar7 + 0xdc))(piVar7);
            (**(code **)(*piVar7 + 0xe8))(piVar7,in_stack_0000000c);
          }
        }
      }
      iVar5 = *(int *)(param_1 + 4);
      uVar9 = (uint)*(ushort *)(iVar5 + 6 + uVar9 * 8);
    } while (uVar9 != 0xffff);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnGrenadeDetonate
 * Address: 00765bb0
 * ---------------------------------------- */

/* CINSNextBotManager::OnGrenadeDetonate(CBaseDetonator*) */

void __thiscall
CINSNextBotManager::OnGrenadeDetonate(CINSNextBotManager *this,CBaseDetonator *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 *puVar4;
  CBaseEntity *this_00;
  CUtlVector<CINSActiveGrenade*,CUtlMemory<CINSActiveGrenade*,int>> *this_01;
  int unaff_EBX;
  float10 fVar5;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 != 0) {
    puVar4 = (undefined4 *)::operator_new(0x1c);
    if ((*(byte *)(in_stack_00000008 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
    }
    *puVar4 = *(undefined4 *)(in_stack_00000008 + 0x208);
    puVar4[1] = *(undefined4 *)(in_stack_00000008 + 0x20c);
    puVar4[2] = *(undefined4 *)(in_stack_00000008 + 0x210);
    fVar1 = *(float *)(in_stack_00000008 + 0x4ac);
    iVar3 = **(int **)(unaff_EBX + 0x440cdc /* &gpGlobals */ /* &gpGlobals */);
    fVar2 = *(float *)(iVar3 + 0xc);
    puVar4[4] = 0x43340000 /* 180.0f */;
    puVar4[3] = fVar1 + fVar2;
    puVar4[5] = *(float *)(in_stack_00000008 + 0x4b0) + *(float *)(iVar3 + 0xc);
    fVar5 = (float10)CBaseDetonator::GetDetonateDamageRadius();
    puVar4[6] = (float)fVar5;
    CUtlVector<CINSActiveGrenade*,CUtlMemory<CINSActiveGrenade*,int>>::InsertBefore
              (this_01,(int)(param_1 + 0x5c),*(CINSActiveGrenade ***)(param_1 + 0x68));
    return;
  }
  Warning(unaff_EBX + 0x220f7d /* "grenade == NULL
" */ /* "grenade == NULL
" */);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnGrenadeThrown
 * Address: 00765b30
 * ---------------------------------------- */

/* CINSNextBotManager::OnGrenadeThrown(CBaseDetonator*) */

void __cdecl CINSNextBotManager::OnGrenadeThrown(CBaseDetonator *param_1)

{
  int *piVar1;
  CUtlVector<CHandle<CBaseEntity>,CUtlMemory<CHandle<CBaseEntity>,int>> *this;
  int unaff_EBX;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0xc))(piVar1);
    CUtlVector<CHandle<CBaseEntity>,CUtlMemory<CHandle<CBaseEntity>,int>>::InsertBefore
              (this,(int)(param_1 + 0x70),*(CHandle **)(param_1 + 0x7c));
    return;
  }
  Warning(unaff_EBX + 0x220fea /* "NULL grenade thrown?
" */ /* "NULL grenade thrown?
" */);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnMapLoaded
 * Address: 00761920
 * ---------------------------------------- */

/* CINSNextBotManager::OnMapLoaded() */

void __thiscall CINSNextBotManager::OnMapLoaded(CINSNextBotManager *this)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  float fVar4;
  NextBotManager *this_00;
  int unaff_EBX;
  float10 fVar5;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  NextBotManager::OnMapLoaded(this_00);
  piVar1 = (int *)(*(int **)(unaff_EBX + 0x445691 /* &ins_bot_grenade_think_time */ /* &ins_bot_grenade_think_time */))[7];
  if (piVar1 == *(int **)(unaff_EBX + 0x445691 /* &ins_bot_grenade_think_time */ /* &ins_bot_grenade_think_time */)) {
    fVar4 = (float)((uint)piVar1 ^ piVar1[0xb]);
  }
  else {
    fVar5 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar4 = (float)fVar5;
  }
  fVar5 = (float10)CountdownTimer::Now();
  if (*(float *)(in_stack_00000004 + 0xa0) != (float)fVar5 + fVar4) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x98) + 4))
              (in_stack_00000004 + 0x98,in_stack_00000004 + 0xa0);
    *(float *)(in_stack_00000004 + 0xa0) = (float)fVar5 + fVar4;
  }
  if (*(float *)(in_stack_00000004 + 0x9c) != fVar4) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x98) + 4))
              (in_stack_00000004 + 0x98,in_stack_00000004 + 0x9c);
    *(float *)(in_stack_00000004 + 0x9c) = fVar4;
  }
  if (*(int *)(in_stack_00000004 + 0x118) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x110) + 4))
              (in_stack_00000004 + 0x110,in_stack_00000004 + 0x118);
    *(undefined4 *)(in_stack_00000004 + 0x118) = 0xbf800000 /* -1.0f */;
  }
  CINSBotGuardCP::ResetHidingSpots();
  piVar1 = *(int **)(unaff_EBX + 0x444f75 /* &gpGlobals */ /* &gpGlobals */);
  *(undefined1 *)(in_stack_00000004 + 0x128) = 0;
  iVar3 = *(int *)(*piVar1 + 0x3c);
  if (iVar3 == 0) {
    iVar3 = unaff_EBX + 0x1f8150 /* rodata:0x73250900 */ /* rodata:0x73250900 */;
  }
  pcVar2 = (char *)CMapDatabase::GetMapDatabaseReference();
  iVar3 = CMapDatabase::GetMapDatabaseItem(pcVar2,SUB41(iVar3,0));
  if (iVar3 != 0) {
    if (*(char *)(iVar3 + 0xba0) != '\0') {
      *(undefined1 *)(in_stack_00000004 + 0x129) = 1;
      DevMsg((char *)(unaff_EBX + 0x225271 /* "Using light calculation for NextBot vision.
" */ /* "Using light calculation for NextBot vision.
" */));
      return;
    }
    *(undefined1 *)(in_stack_00000004 + 0x129) = 0;
    DevMsg((char *)(unaff_EBX + 0x2252a1 /* "Not using light calculation for NextBot vision.
" */ /* "Not using light calculation for NextBot vision.
" */));
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnPointCaptured
 * Address: 00764d70
 * ---------------------------------------- */

/* CINSNextBotManager::OnPointCaptured(int, int, int) */

void __thiscall
CINSNextBotManager::OnPointCaptured(CINSNextBotManager *this,int param_1,int param_2,int param_3)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  NextBotManager *this_00;
  CBaseEntity *this_01;
  int unaff_EBX;
  int iVar5;
  int in_stack_00000010;
  int *piVar6;
  int local_3c [10];
  undefined4 uStack_14;
  
  piVar6 = local_3c;
  uStack_14 = 0x764d7e;
  __i686_get_pc_thunk_bx();
  local_3c[0] = 0;
  local_3c[1] = 0;
  local_3c[2] = 0;
  local_3c[3] = 0;
  local_3c[4] = 0;
  NextBotManager::CollectAllBots(this_00,(CUtlVector *)param_1);
  if (0 < local_3c[3]) {
    iVar5 = 0;
    do {
      while( true ) {
        iVar1 = iVar5 * 4;
        piVar3 = *(int **)(local_3c[0] + iVar5 * 4);
        piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3,piVar6);
        cVar2 = (**(code **)(*piVar3 + 0x118))(piVar3);
        if (cVar2 != '\0') break;
LAB_00764dd0:
        iVar5 = iVar5 + 1;
        if (local_3c[3] <= iVar5) goto LAB_00764e68;
      }
      piVar6 = (int *)param_2;
      (**(code **)(**(int **)(local_3c[0] + iVar1) + 0x9c))(*(int **)(local_3c[0] + iVar1));
      (**(code **)(**(int **)(local_3c[0] + iVar1) + 200))(*(int **)(local_3c[0] + iVar1));
      iVar4 = CBaseEntity::GetTeamNumber(this_01);
      if (iVar4 != in_stack_00000010) goto LAB_00764dd0;
      piVar6 = (int *)param_2;
      (**(code **)(**(int **)(local_3c[0] + iVar1) + 0xa0))(*(int **)(local_3c[0] + iVar1));
      iVar5 = iVar5 + 1;
    } while (iVar5 < local_3c[3]);
  }
LAB_00764e68:
  local_3c[3] = 0;
  if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x441afa /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x441afa /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_3c[0]);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnPointContested
 * Address: 00764c40
 * ---------------------------------------- */

/* CINSNextBotManager::OnPointContested(int, int) */

void __thiscall
CINSNextBotManager::OnPointContested(CINSNextBotManager *this,int param_1,int param_2)

{
  char cVar1;
  int *piVar2;
  NextBotManager *this_00;
  int unaff_EBX;
  int iVar3;
  int in_stack_0000000c;
  int *piVar4;
  int local_3c [10];
  undefined4 uStack_14;
  
  uStack_14 = 0x764c4b;
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c != *(int *)(**(int **)(&DAT_004420d1 + unaff_EBX) + 0x490 + param_2 * 4)) {
    piVar4 = local_3c;
    local_3c[0] = 0;
    local_3c[1] = 0;
    local_3c[2] = 0;
    local_3c[3] = 0;
    local_3c[4] = 0;
    NextBotManager::CollectAllBots(this_00,(CUtlVector *)param_1);
    if (0 < local_3c[3]) {
      iVar3 = 0;
      do {
        while( true ) {
          piVar2 = *(int **)(local_3c[0] + iVar3 * 4);
          piVar2 = (int *)(**(code **)(*piVar2 + 200))(piVar2,piVar4);
          cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2);
          if (cVar1 == '\0') break;
          piVar2 = *(int **)(local_3c[0] + iVar3 * 4);
          piVar4 = (int *)param_2;
          (**(code **)(*piVar2 + 0x98))(piVar2);
          iVar3 = iVar3 + 1;
          if (local_3c[3] <= iVar3) goto LAB_00764d03;
        }
        iVar3 = iVar3 + 1;
      } while (iVar3 < local_3c[3]);
    }
LAB_00764d03:
    local_3c[3] = 0;
    if ((-1 < local_3c[2]) && (local_3c[0] != 0)) {
      (**(code **)(*(int *)**(undefined4 **)(&DAT_00441c2d + unaff_EBX) + 8))
                ((int *)**(undefined4 **)(&DAT_00441c2d + unaff_EBX),local_3c[0]);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::OnRoundRestart
 * Address: 00761630
 * ---------------------------------------- */

/* CINSNextBotManager::OnRoundRestart() */

void __thiscall CINSNextBotManager::OnRoundRestart(CINSNextBotManager *this)

{
  int iVar1;
  undefined4 uVar2;
  NextBotManager *this_00;
  int unaff_EBX;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  NextBotManager::OnRoundRestart(this_00);
  if (0 < *(int *)(in_stack_00000004 + 0x68)) {
    iVar3 = 0;
    do {
      iVar5 = iVar3 * 4;
      iVar3 = iVar3 + 1;
      operator_delete(*(void **)(*(int *)(in_stack_00000004 + 0x5c) + iVar5));
    } while (iVar3 < *(int *)(in_stack_00000004 + 0x68));
  }
  *(undefined4 *)(in_stack_00000004 + 0x68) = 0;
  if (*(int *)(in_stack_00000004 + 100) < 0) {
    uVar2 = *(undefined4 *)(in_stack_00000004 + 0x5c);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x5c) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44523d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x44523d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x5c));
      *(undefined4 *)(in_stack_00000004 + 0x5c) = 0;
    }
    uVar2 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x60) = 0;
  }
  iVar3 = 0;
  *(undefined4 *)(in_stack_00000004 + 0x6c) = uVar2;
  *(undefined4 *)(in_stack_00000004 + 0x7c) = 0;
  do {
    iVar5 = in_stack_00000004 + 0xe0 + iVar3 * 0x14;
    if (0 < *(int *)(iVar5 + 0x14)) {
      iVar4 = 0;
      do {
        iVar1 = iVar4 * 4;
        iVar4 = iVar4 + 1;
        operator_delete(*(void **)(*(int *)(iVar5 + 8) + iVar1));
      } while (iVar4 < *(int *)(iVar5 + 0x14));
    }
    *(undefined4 *)(iVar5 + 0x14) = 0;
    if (*(int *)(iVar5 + 0x10) < 0) {
      uVar2 = *(undefined4 *)(iVar5 + 8);
    }
    else {
      if (*(int *)(iVar5 + 8) != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44523d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x44523d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),*(int *)(iVar5 + 8));
        *(undefined4 *)(iVar5 + 8) = 0;
      }
      *(undefined4 *)(iVar5 + 0xc) = 0;
      uVar2 = 0;
    }
    iVar3 = iVar3 + 1;
    *(undefined4 *)(iVar5 + 0x18) = uVar2;
  } while (iVar3 != 2);
  iVar3 = 0;
  do {
    iVar5 = 0;
    do {
      iVar4 = iVar3 * 0x30 + 0x120 + iVar5 * 0xc + in_stack_00000004;
      if (*(int *)(iVar4 + 0x14) != -0x40800000 /* -1.0f */) {
        (**(code **)(*(int *)(iVar4 + 0xc) + 4))(iVar4 + 0xc,iVar4 + 0x14);
        *(undefined4 *)(iVar4 + 0x14) = 0xbf800000 /* -1.0f */;
      }
      iVar5 = iVar5 + 1;
    } while (iVar5 != 4);
    iVar3 = iVar3 + 1;
  } while (iVar3 != 0x11);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::UpdateGrenadeTargets
 * Address: 00763050
 * ---------------------------------------- */

/* CINSNextBotManager::UpdateGrenadeTargets() */

void __thiscall CINSNextBotManager::UpdateGrenadeTargets(CINSNextBotManager *this)

{
  float *pfVar1;
  int *piVar2;
  float fVar3;
  float fVar4;
  byte *pbVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  CBaseEntity *this_00;
  bool bVar13;
  int iVar14;
  int unaff_EBX;
  int iVar15;
  int iVar16;
  float10 fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  int in_stack_00000004;
  int local_170;
  int local_16c;
  int local_164;
  char local_158 [256];
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x76305b;
  __i686_get_pc_thunk_bx();
  iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x443a8d /* &ins_debug_grenade_targets */ /* &ins_debug_grenade_targets */) + 0x40))(*(int **)(unaff_EBX + 0x443a8d /* &ins_debug_grenade_targets */ /* &ins_debug_grenade_targets */));
  if (iVar7 != 0) {
    local_170 = 0;
    do {
      piVar2 = (int *)(in_stack_00000004 + 0xe8 + local_170 * 0x14);
      if (0 < piVar2[3]) {
        iVar7 = 0;
        do {
          iVar15 = iVar7 * 4;
          iVar8 = *(int *)(*piVar2 + iVar7 * 4);
          if (iVar8 != 0) {
            fVar17 = (float10)CountdownTimer::Now();
            pfVar1 = (float *)(iVar8 + 0xc);
            if ((float)fVar17 < *pfVar1 || (float)fVar17 == *pfVar1) {
              pbVar5 = *(byte **)(*piVar2 + iVar15);
              iVar8 = unaff_EBX + 0x1f6a20 /* rodata:0x73250900 */ /* rodata:0x73250900 */;
              iVar12 = unaff_EBX + 0x223aba /* "INCENDIARY" */ /* "INCENDIARY" */;
              if ((*pbVar5 & 8) == 0) {
                iVar12 = iVar8;
              }
              iVar16 = unaff_EBX + 0x223ac5 /* "SMOKE" */ /* "SMOKE" */;
              if ((*pbVar5 & 2) == 0) {
                iVar16 = iVar8;
              }
              iVar14 = unaff_EBX + 0x1c34c3 /* "FLASH" */ /* "FLASH" */;
              if ((*pbVar5 & 4) == 0) {
                iVar14 = iVar8;
              }
              if ((*pbVar5 & 1) != 0) {
                iVar8 = unaff_EBX + 0x223acb /* "FRAG" */ /* "FRAG" */;
              }
              iVar9 = unaff_EBX + 0x1bffa3 /* "YES" */ /* "YES" */;
              if (pbVar5[0x1d] == 0) {
                iVar9 = unaff_EBX + 0x1bffbc /* "NO" */ /* "NO" */;
              }
              iVar10 = unaff_EBX + 0x1bffa3 /* "YES" */ /* "YES" */;
              if (pbVar5[0x1c] == 0) {
                iVar10 = unaff_EBX + 0x1bffbc /* "NO" */ /* "NO" */;
              }
              V_snprintf(local_158,0x100,(char *)(unaff_EBX + 0x223d19 /* "Grenade Target
Clear: %s
Used: %s
Types: %s %s %s %s" */ /* "Grenade Target
Clear: %s
Used: %s
Types: %s %s %s %s" */),iVar10,iVar9,iVar8,iVar14,
                         iVar16,iVar12);
              iVar8 = *(int *)(*piVar2 + iVar15);
              local_58 = *(undefined4 *)(iVar8 + 0x10);
              local_54 = *(undefined4 *)(iVar8 + 0x14);
              local_50 = *(undefined4 *)(iVar8 + 0x18);
              NDebugOverlay::Text((Vector *)&local_58,local_158,false,0.1);
              piVar11 = (int *)(iVar15 + *piVar2);
              local_34 = 0;
              local_30 = 0xbf800000 /* -1.0f */;
              local_2c = 0;
              local_40 = 0x3f800000 /* 1.0f */;
              local_3c = 0;
              local_38 = 0;
              iVar15 = *piVar11;
              local_4c = *(undefined4 *)(iVar15 + 0x10);
              local_48 = *(undefined4 *)(iVar15 + 0x14);
              local_44 = *(undefined4 *)(iVar15 + 0x18);
              NDebugOverlay::Circle
                        ((Vector *)&local_4c,(Vector *)&local_40,(Vector *)&local_34,
                         *(float *)(*piVar11 + 0x20),
                         -(uint)(*(char *)(*piVar11 + 0x1d) == '\0') & 0xff,
                         ~-(uint)(*(char *)(*piVar11 + 0x1d) == '\0') & 0xff,0,100,true,0.1);
            }
          }
          iVar7 = iVar7 + 1;
        } while (iVar7 < piVar2[3]);
      }
      local_170 = local_170 + 1;
    } while (local_170 != 2);
  }
  fVar17 = (float10)CountdownTimer::Now();
  if ((float)fVar17 < *(float *)(in_stack_00000004 + 0x118) ||
      (float)fVar17 == *(float *)(in_stack_00000004 + 0x118)) {
    return;
  }
  fVar17 = (float10)CountdownTimer::Now();
  fVar18 = (float)fVar17 + *(float *)(unaff_EBX + 0x1c0a31 /* 0.25f */ /* 0.25f */);
  if (*(float *)(in_stack_00000004 + 0x118) != fVar18) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x110) + 4))
              (in_stack_00000004 + 0x110,in_stack_00000004 + 0x118);
    *(float *)(in_stack_00000004 + 0x118) = fVar18;
  }
  if (*(int *)(in_stack_00000004 + 0x114) != 0x3e800000 /* 0.25f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x110) + 4))
              (in_stack_00000004 + 0x110,in_stack_00000004 + 0x114);
    *(undefined4 *)(in_stack_00000004 + 0x114) = 0x3e800000 /* 0.25f */;
  }
  local_164 = 0;
  do {
    piVar2 = (int *)(in_stack_00000004 + 0xe8 + local_164 * 0x14);
    iVar7 = piVar2[3];
    if (0 < iVar7) {
      iVar15 = iVar7 + -1;
      iVar7 = iVar7 << 2;
      do {
        iVar8 = iVar7 + -4;
        iVar12 = *(int *)(*piVar2 + -4 + iVar7);
        if (iVar12 == 0) {
LAB_0076346d:
          iVar12 = piVar2[3];
          iVar16 = (iVar12 - iVar15) + -1;
          if (0 < iVar16) {
            _V_memmove((void *)(*piVar2 + iVar8),(void *)(iVar7 + *piVar2),iVar16 * 4);
            iVar12 = piVar2[3];
          }
          piVar2[3] = iVar12 + -1;
        }
        else {
          fVar17 = (float10)CountdownTimer::Now();
          pfVar1 = (float *)(iVar12 + 0xc);
          if (*pfVar1 <= (float)fVar17 && (float)fVar17 != *pfVar1) {
            if (*(void **)(*piVar2 + iVar8) != (void *)0x0) {
              operator_delete(*(void **)(*piVar2 + iVar8));
            }
            goto LAB_0076346d;
          }
        }
        iVar15 = iVar15 + -1;
        iVar7 = iVar8;
      } while (iVar15 != -1);
    }
    local_164 = local_164 + 1;
    if (local_164 == 2) {
      local_16c = 0;
      do {
        piVar2 = (int *)(in_stack_00000004 + 0xe8 + local_16c * 0x14);
        if (0 < piVar2[3]) {
          local_164 = 0;
          do {
            iVar7 = *(int *)(*piVar2 + local_164 * 4);
            if ((iVar7 != 0) && (*(char *)(iVar7 + 0x1d) == '\0')) {
              iVar15 = 1;
              fVar18 = *(float *)(iVar7 + 0x10);
              fVar3 = *(float *)(iVar7 + 0x14);
              fVar4 = *(float *)(iVar7 + 0x18);
              if (*(int *)(**(int **)(unaff_EBX + 0x443845 /* &gpGlobals */ /* &gpGlobals */) + 0x14) < 1) {
                bVar13 = true;
              }
              else {
                do {
                  piVar11 = (int *)UTIL_PlayerByIndex(iVar15);
                  if (piVar11 == (int *)0x0) {
LAB_007635ca:
                    bVar13 = true;
                  }
                  else {
                    cVar6 = (**(code **)(*piVar11 + 0x118 /* CBaseEntity::IsAlive */))(piVar11);
                    if (cVar6 == '\0') goto LAB_007635ca;
                    iVar7 = CBaseEntity::GetTeamNumber(this_00);
                    bVar13 = true;
                    if (iVar7 == 3 - (uint)(local_16c == 0)) {
                      (**(code **)(*piVar11 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar11);
                      fVar21 = local_28 - fVar18;
                      fVar19 = local_24 - fVar3;
                      fVar20 = local_20 - fVar4;
                      bVar13 = *(float *)(unaff_EBX + 0x1d4dbd /* 32.0f */ /* 32.0f */) +
                               *(float *)(*(int *)(*piVar2 + local_164 * 4) + 0x20) <=
                               SQRT(fVar19 * fVar19 + fVar21 * fVar21 + fVar20 * fVar20);
                    }
                  }
                  iVar15 = iVar15 + 1;
                } while ((iVar15 <= *(int *)(**(int **)(unaff_EBX + 0x443845 /* &gpGlobals */ /* &gpGlobals */) + 0x14)) && (bVar13));
                iVar7 = *(int *)(*piVar2 + local_164 * 4);
              }
              *(bool *)(iVar7 + 0x1c) = bVar13;
            }
            local_164 = local_164 + 1;
          } while (local_164 < piVar2[3]);
        }
        local_16c = local_16c + 1;
        if (local_16c == 2) {
          return;
        }
      } while( true );
    }
  } while( true );
}



/* ----------------------------------------
 * CINSNextBotManager::UpdateGrenades
 * Address: 00762e30
 * ---------------------------------------- */

/* CINSNextBotManager::UpdateGrenades() */

void __thiscall CINSNextBotManager::UpdateGrenades(CINSNextBotManager *this)

{
  float fVar1;
  void *pvVar2;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  int iVar6;
  int unaff_EBX;
  int iVar7;
  int iVar8;
  int in_stack_00000004;
  int local_20;
  
  __i686_get_pc_thunk_bx();
  iVar7 = *(int *)(in_stack_00000004 + 0x68);
  if (0 < iVar7) {
    iVar8 = iVar7 + -1;
    iVar6 = iVar7 * 4;
    while( true ) {
      if ((((iVar8 < iVar7) &&
           (pvVar2 = *(void **)(*(int *)(in_stack_00000004 + 0x5c) + -4 + iVar6),
           pvVar2 != (void *)0x0)) &&
          (fVar1 = *(float *)(**(int **)(unaff_EBX + 0x443a65 /* &gpGlobals */ /* &gpGlobals */) + 0xc),
          *(float *)((int)pvVar2 + 0x14) <= fVar1)) && (*(float *)((int)pvVar2 + 0xc) <= fVar1)) {
        operator_delete(pvVar2);
        iVar7 = *(int *)(in_stack_00000004 + 0x68);
        iVar5 = (iVar7 - iVar8) + -1;
        if (0 < iVar5) {
          _V_memmove((void *)(*(int *)(in_stack_00000004 + 0x5c) + iVar6 + -4),
                     (void *)(iVar6 + *(int *)(in_stack_00000004 + 0x5c)),iVar5 * 4);
          iVar7 = *(int *)(in_stack_00000004 + 0x68);
        }
        *(int *)(in_stack_00000004 + 0x68) = iVar7 + -1;
      }
      iVar8 = iVar8 + -1;
      if (iVar8 == -1) break;
      iVar7 = *(int *)(in_stack_00000004 + 0x68);
      iVar6 = iVar6 + -4;
    }
  }
  iVar7 = *(int *)(in_stack_00000004 + 0x7c);
  if (0 < iVar7) {
    iVar8 = iVar7 + -1;
    local_20 = iVar7 << 2;
    do {
      while( true ) {
        iVar7 = local_20 + -4;
        puVar4 = (uint *)(*(int *)(in_stack_00000004 + 0x70) + iVar7);
        uVar3 = *puVar4;
        if (((uVar3 != 0xffffffff) &&
            (iVar6 = (uVar3 & 0xffff) * 0x18 + **(int **)(unaff_EBX + 0x44399d /* &g_pEntityList */ /* &g_pEntityList */),
            *(uint *)(iVar6 + 8) == uVar3 >> 0x10)) && (*(int *)(iVar6 + 4) != 0)) break;
        iVar6 = *(int *)(in_stack_00000004 + 0x7c);
        iVar5 = (iVar6 - iVar8) + -1;
        if (0 < iVar5) {
          _V_memmove(puVar4,(void *)(*(int *)(in_stack_00000004 + 0x70) + local_20),iVar5 * 4);
          iVar6 = *(int *)(in_stack_00000004 + 0x7c);
        }
        iVar8 = iVar8 + -1;
        *(int *)(in_stack_00000004 + 0x7c) = iVar6 + -1;
        local_20 = iVar7;
        if (iVar8 == -1) {
          return;
        }
      }
      iVar8 = iVar8 + -1;
      local_20 = iVar7;
    } while (iVar8 != -1);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::~CINSNextBotManager
 * Address: 00765430
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBotManager::~CINSNextBotManager() */

void __thiscall CINSNextBotManager::~CINSNextBotManager(CINSNextBotManager *this)

{
  ~CINSNextBotManager(this);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::~CINSNextBotManager
 * Address: 00765440
 * ---------------------------------------- */

/* CINSNextBotManager::~CINSNextBotManager() */

void __thiscall CINSNextBotManager::~CINSNextBotManager(CINSNextBotManager *this)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  CUtlMemory<CINSGrenadeTarget*,int> *extraout_ECX;
  CUtlMemory<CINSGrenadeTarget*,int> *extraout_ECX_00;
  CUtlMemory<CINSGrenadeTarget*,int> *this_00;
  CUtlMemory<CINSGrenadeTarget*,int> *extraout_ECX_01;
  NextBotManager *extraout_ECX_02;
  NextBotManager *this_01;
  int unaff_EBX;
  CUtlMemory<CINSNavArea*,int> *pCVar4;
  CUtlMemory<CINSNavArea*,int> *pCVar5;
  CUtlMemory<CINSNavArea*,int> *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  pCVar4 = in_stack_00000004 + 0x110;
  *(int *)in_stack_00000004 = unaff_EBX + 0x437e3d /* vtable for CINSNextBotManager+0x8 */ /* vtable for CINSNextBotManager+0x8 */;
  pCVar5 = in_stack_00000004 + 0xfc;
  *(int *)(in_stack_00000004 + 0x50) = unaff_EBX + 0x437e89 /* vtable for CINSNextBotManager+0x54 */ /* vtable for CINSNextBotManager+0x54 */;
  *(undefined4 *)(unaff_EBX + 0x58cad1 /* INSNextBotManager */ /* INSNextBotManager */) = 0;
  **(undefined4 **)(unaff_EBX + 0x441401 /* &NextBotManager::sInstance */ /* &NextBotManager::sInstance */) = 0;
  this_00 = extraout_ECX;
  do {
    *(undefined4 *)(pCVar4 + -8) = 0;
    iVar2 = *(int *)pCVar5;
    if (-1 < *(int *)(pCVar4 + -0xc)) {
      if (iVar2 != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar2);
        *(int *)pCVar5 = 0;
        this_00 = extraout_ECX_00;
      }
      *(int *)(pCVar5 + 4) = 0;
      iVar2 = 0;
    }
    *(int *)(pCVar4 + -4) = iVar2;
    pCVar4 = pCVar4 + -0x14;
    CUtlMemory<CINSGrenadeTarget*,int>::~CUtlMemory(this_00);
    pCVar5 = pCVar5 + -0x14;
    this_00 = extraout_ECX_01;
  } while (in_stack_00000004 + 0xe8 != pCVar4);
  *(undefined4 *)(in_stack_00000004 + 0x90) = 0;
  if (*(int *)(in_stack_00000004 + 0x8c) < 0) {
    uVar3 = *(undefined4 *)(in_stack_00000004 + 0x84);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x84) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x84));
      *(undefined4 *)(in_stack_00000004 + 0x84) = 0;
    }
    uVar3 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x88) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x94) = uVar3;
  CUtlMemory<CINSNavArea*,int>::~CUtlMemory(in_stack_00000004);
  *(undefined4 *)(in_stack_00000004 + 0x7c) = 0;
  if (*(int *)(in_stack_00000004 + 0x78) < 0) {
    uVar3 = *(undefined4 *)(in_stack_00000004 + 0x70);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x70) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x70));
      *(undefined4 *)(in_stack_00000004 + 0x70) = 0;
    }
    uVar3 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x74) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x80) = uVar3;
  CUtlMemory<CHandle<CBaseEntity>,int>::~CUtlMemory
            ((CUtlMemory<CHandle<CBaseEntity>,int> *)in_stack_00000004);
  *(undefined4 *)(in_stack_00000004 + 0x68) = 0;
  if (*(int *)(in_stack_00000004 + 100) < 0) {
    uVar3 = *(undefined4 *)(in_stack_00000004 + 0x5c);
  }
  else {
    if (*(int *)(in_stack_00000004 + 0x5c) != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x44142d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),*(int *)(in_stack_00000004 + 0x5c));
      *(undefined4 *)(in_stack_00000004 + 0x5c) = 0;
    }
    uVar3 = 0;
    *(undefined4 *)(in_stack_00000004 + 0x60) = 0;
  }
  *(undefined4 *)(in_stack_00000004 + 0x6c) = uVar3;
  CUtlMemory<CINSActiveGrenade*,int>::~CUtlMemory
            ((CUtlMemory<CINSActiveGrenade*,int> *)in_stack_00000004);
  *(int *)(in_stack_00000004 + 0x50) = unaff_EBX + 0x3bd2e5 /* vtable for CGameEventListener+0x8 */ /* vtable for CGameEventListener+0x8 */;
  *(undefined4 *)(in_stack_00000004 + 0x54) = 0xd;
  this_01 = extraout_ECX_02;
  if (in_stack_00000004[0x58] != (CUtlMemory<CINSNavArea*,int>)0x0) {
    piVar1 = (int *)**(int **)(unaff_EBX + 0x441a85 /* &gameeventmanager */ /* &gameeventmanager */);
    if (piVar1 != (int *)0x0) {
      (**(code **)(*piVar1 + 0x18))(piVar1,in_stack_00000004 + 0x50);
    }
    in_stack_00000004[0x58] = (CUtlMemory<CINSNavArea*,int>)0x0;
    this_01 = (NextBotManager *)in_stack_00000004;
  }
  *(int *)(in_stack_00000004 + 0x50) = unaff_EBX + 0x3bd2fd /* vtable for IGameEventListener2+0x8 */ /* vtable for IGameEventListener2+0x8 */;
  NextBotManager::~NextBotManager(this_01);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::~CINSNextBotManager
 * Address: 00765740
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBotManager::~CINSNextBotManager() */

void __thiscall CINSNextBotManager::~CINSNextBotManager(CINSNextBotManager *this)

{
  ~CINSNextBotManager(this);
  return;
}



/* ----------------------------------------
 * CINSNextBotManager::~CINSNextBotManager
 * Address: 00765750
 * ---------------------------------------- */

/* CINSNextBotManager::~CINSNextBotManager() */

void __thiscall CINSNextBotManager::~CINSNextBotManager(CINSNextBotManager *this)

{
  CINSNextBotManager *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSNextBotManager(this_00);
  operator_delete(in_stack_00000004);
  return;
}



