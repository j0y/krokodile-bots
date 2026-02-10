/*
 * CINSBotFireRPG -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 15
 */

/* ----------------------------------------
 * CINSBotFireRPG::CINSBotFireRPG
 * Address: 0071ddd0
 * ---------------------------------------- */

/* CINSBotFireRPG::CINSBotFireRPG(Vector, Vector) */

void __thiscall
CINSBotFireRPG::CINSBotFireRPG
          (undefined4 param_1,undefined4 *param_2,float param_3,float param_4,float param_5,
          float param_6,float param_7,float param_8)

{
  float fVar1;
  float fVar2;
  int unaff_EBX;
  float10 fVar3;
  float local_4c;
  float local_48;
  float local_44;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x71dddb;
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  *param_2 = &UNK_00478dcd + unaff_EBX;
  param_2[1] = unaff_EBX + 0x478f65 /* vtable for CINSBotFireRPG+0x1a0 */;
  param_2[9] = 0;
  param_2[10] = 0;
  param_2[3] = 0;
  param_2[4] = 0;
  param_2[5] = 0;
  param_2[6] = 0;
  param_2[7] = 0;
  param_2[2] = 0;
  *(undefined1 *)(param_2 + 0xc) = 0;
  *(undefined1 *)((int)param_2 + 0x31) = 0;
  param_2[0xb] = 0;
  param_2[0xd] = 0;
  param_2[0x17] = unaff_EBX + 0x40a3dd /* vtable for CountdownTimer+0x8 */;
  param_2[0x18] = 0;
  CountdownTimer::NetworkStateChanged(param_2 + 0x17);
  param_2[0x19] = 0xbf800000 /* -1.0f */;
  (**(code **)(param_2[0x17] + 4))(param_2 + 0x17,param_2 + 0x19);
  param_2[0x11] = param_6;
  param_2[0x12] = param_7;
  param_2[0x13] = param_8;
  local_28 = param_6 - param_3;
  local_24 = param_7 - param_4;
  local_20 = param_8 - param_5;
  VectorVectors((Vector *)&local_28,(Vector *)&local_34,(Vector *)&local_4c);
  fVar3 = (float10)RandomFloat(0xc2a00000 /* -80.0f */,0x42a00000 /* 80.0f */);
  fVar1 = (float)fVar3;
  fVar3 = (float10)RandomFloat(0xc1f00000 /* -30.0f */,0x428c0000 /* 70.0f */);
  fVar2 = (float)fVar3;
  param_2[0x1a] = 0;
  *(undefined1 *)(param_2 + 0x1b) = 0;
  param_2[0xe] = fVar1 * local_34 + param_6 + local_4c * fVar2;
  param_2[0xf] = fVar1 * local_30 + param_7 + local_48 * fVar2;
  param_2[0x14] = param_3;
  param_2[0x10] = fVar1 * local_2c + param_8 + fVar2 * local_44;
  param_2[0x15] = param_4;
  param_2[0x16] = param_5;
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::CINSBotFireRPG
 * Address: 0071f4f0
 * ---------------------------------------- */

/* CINSBotFireRPG::CINSBotFireRPG() */

void __thiscall CINSBotFireRPG::CINSBotFireRPG(CINSBotFireRPG *this)

{
  float fVar1;
  CINSNextBot *pCVar2;
  char cVar3;
  int *piVar4;
  float *pfVar5;
  int unaff_EBX;
  float10 fVar6;
  int *in_stack_00000004;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  int local_28;
  int local_24;
  int local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x71f4fb;
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x4776ad /* vtable for CINSBotFireRPG+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x477845 /* vtable for CINSBotFireRPG+0x1a0 */;
  in_stack_00000004[0x17] = unaff_EBX + 0x408cbd /* vtable for CountdownTimer+0x8 */;
  in_stack_00000004[10] = 0;
  in_stack_00000004[3] = 0;
  in_stack_00000004[4] = 0;
  in_stack_00000004[5] = 0;
  in_stack_00000004[6] = 0;
  in_stack_00000004[7] = 0;
  in_stack_00000004[2] = 0;
  *(undefined1 *)(in_stack_00000004 + 0xc) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x31) = 0;
  in_stack_00000004[0xb] = 0;
  in_stack_00000004[0xd] = 0;
  in_stack_00000004[0x18] = 0;
  CountdownTimer::NetworkStateChanged(in_stack_00000004 + 0x17);
  in_stack_00000004[0x19] = -0x40800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x17] + 4))(in_stack_00000004 + 0x17,in_stack_00000004 + 0x19);
  pCVar2 = (CINSNextBot *)in_stack_00000004[7];
  if (pCVar2 != (CINSNextBot *)0x0) {
    piVar4 = (int *)(**(code **)(*(int *)pCVar2 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar2);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,1);
    if (piVar4 != (int *)0x0) {
      cVar3 = HasRPGTarget(pCVar2,(Vector *)&local_64);
      if (cVar3 != '\0') {
        in_stack_00000004[0x11] = (int)local_64;
        in_stack_00000004[0x12] = (int)local_60;
        in_stack_00000004[0x13] = (int)local_5c;
        (**(code **)(*(int *)pCVar2 + 0x20c /* CINSNextBot::EyePosition */))(&local_34,pCVar2);
        pfVar5 = (float *)(**(code **)(*piVar4 + 0x18))(piVar4);
        local_40 = *pfVar5 - local_34;
        local_3c = pfVar5[1] - local_30;
        local_38 = pfVar5[2] - local_2c;
        VectorVectors((Vector *)&local_40,(Vector *)&local_58,(Vector *)&local_4c);
        fVar6 = (float10)RandomFloat(0xc2a00000 /* -80.0f */,0x42a00000 /* 80.0f */);
        fVar1 = (float)fVar6;
        local_60 = local_54 * fVar1 + local_60;
        local_5c = local_50 * fVar1 + local_5c;
        local_64 = fVar1 * local_58 + local_64;
        fVar6 = (float10)RandomFloat(0xc1f00000 /* -30.0f */,0x428c0000 /* 70.0f */);
        fVar1 = (float)fVar6;
        local_60 = local_48 * fVar1 + local_60;
        local_5c = local_44 * fVar1 + local_5c;
        local_64 = fVar1 * local_4c + local_64;
        (**(code **)(*(int *)pCVar2 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,pCVar2);
        *(undefined1 *)(in_stack_00000004 + 0x1b) = 0;
        in_stack_00000004[0x14] = local_28;
        in_stack_00000004[0x15] = local_24;
        in_stack_00000004[0x16] = local_20;
        in_stack_00000004[0xe] = (int)local_64;
        in_stack_00000004[0xf] = (int)local_60;
        in_stack_00000004[0x10] = (int)local_5c;
        *(undefined4 *)(pCVar2 + 0x2284) = 0;
        return;
      }
      *(undefined4 *)(pCVar2 + 0x2284) = 3;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::OnStart
 * Address: 0071da30
 * ---------------------------------------- */

/* CINSBotFireRPG::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotFireRPG::OnStart(CINSBotFireRPG *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  int *piVar2;
  CINSPlayer *this_00;
  CINSNextBot *this_01;
  int unaff_EBX;
  float10 fVar3;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar4;
  undefined4 uVar5;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(in_stack_0000000c + 0x2284) == 3) {
    *(undefined4 *)param_1 = 3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2635a8 /* "No Target to fire at" */;
    *(undefined4 *)(param_1 + 4) = 0;
    return param_1;
  }
  uVar5 = 0;
  uVar4 = 3;
  fVar1 = (float)CINSPlayer::GetWeaponInSlot(this_00,(int)in_stack_0000000c,true);
  if (fVar1 != 0.0) {
    (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,uVar4,uVar5);
    CINSBotLocomotion::ClearMovementRequests();
    uVar4 = 0x40a00000 /* 5.0f */;
    CINSNextBot::ChooseBestWeapon(this_01,in_stack_0000000c,fVar1);
    piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c,fVar1,uVar4);
    (**(code **)(*piVar2 + 0xd4 /* PlayerBody::AimHeadTowards */))
              (piVar2,param_2 + 0x38,5,0x40c00000 /* 6.0f */,unaff_EBX + 0x4ef7e1 /* rpgFireReply */,unaff_EBX + 0x2635cc /* "Aiming at RPG target" */);
    *(undefined4 *)(in_stack_0000000c + 0x2284) = 1;
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = (float)fVar3 + *(float *)(unaff_EBX + 0x19b541 /* typeinfo name for IServerBenchmark+0x13 */);
    if (*(float *)(in_stack_0000000c + 0xb390) != fVar1) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb388) + 4))
                (in_stack_0000000c + 0xb388,in_stack_0000000c + 0xb390);
      *(float *)(in_stack_0000000c + 0xb390) = fVar1;
    }
    if (*(int *)(in_stack_0000000c + 0xb38c) != 0x40400000 /* 3.0f */) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb388) + 4))
                (in_stack_0000000c + 0xb388,in_stack_0000000c + 0xb38c);
      *(undefined4 *)(in_stack_0000000c + 0xb38c) = 0x40400000 /* 3.0f */;
    }
    *(undefined4 *)(in_stack_0000000c + 0xb344) = 0x41200000 /* 10.0f */;
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = (float)fVar3 + *(float *)(unaff_EBX + 0x19b541 /* typeinfo name for IServerBenchmark+0x13 */);
    if (*(float *)(in_stack_0000000c + 0xb384) != fVar1) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb384);
      *(float *)(in_stack_0000000c + 0xb384) = fVar1;
    }
    if (*(int *)(in_stack_0000000c + 0xb380) != 0x40400000 /* 3.0f */) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb380);
      *(undefined4 *)(in_stack_0000000c + 0xb380) = 0x40400000 /* 3.0f */;
    }
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = (float)fVar3 + *(float *)(unaff_EBX + 0x19b541 /* typeinfo name for IServerBenchmark+0x13 */);
    if (*(float *)(in_stack_0000000c + 0xb378) != fVar1) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb370) + 4))
                (in_stack_0000000c + 0xb370,in_stack_0000000c + 0xb378);
      *(float *)(in_stack_0000000c + 0xb378) = fVar1;
    }
    if (*(int *)(in_stack_0000000c + 0xb374) != 0x40400000 /* 3.0f */) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb370) + 4))
                (in_stack_0000000c + 0xb370,in_stack_0000000c + 0xb374);
      *(undefined4 *)(in_stack_0000000c + 0xb374) = 0x40400000 /* 3.0f */;
    }
    *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(**(int **)(unaff_EBX + 0x488e65 /* &gpGlobals */) + 0xc);
    if (*(int *)(param_2 + 100) != -0x40800000 /* -1.0f */) {
      (**(code **)(*(int *)(param_2 + 0x5c) + 4))(param_2 + 0x5c,param_2 + 100);
      *(undefined4 *)(param_2 + 100) = 0xbf800000 /* -1.0f */;
    }
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3;
  *(int *)(param_1 + 8) = unaff_EBX + 0x2635bd /* "No grenade...
" */;
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotFireRPG::Update
 * Address: 0071f780
 * ---------------------------------------- */

/* CINSBotFireRPG::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotFireRPG::Update(CINSBotFireRPG *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  char *pcVar6;
  CINSPlayer *this_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSWeapon *pCVar7;
  CINSWeapon *this_04;
  CBaseEntity *this_05;
  CINSRules *this_06;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX_00;
  CountdownTimer *this_07;
  CountdownTimer *this_08;
  int unaff_EBX;
  float10 fVar8;
  float fVar9;
  double dVar10;
  CINSWeapon *in_stack_0000000c;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *this_09;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *local_54;
  int local_4c [3];
  CINSWeapon *local_40;
  undefined4 local_3c;
  int *local_2c [7];
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)CINSPlayer::GetWeaponInSlot(this_00,(int)in_stack_0000000c,true);
  piVar3 = (int *)CINSPlayer::GetActiveINSWeapon();
  if ((piVar2 == (int *)0x0) || (piVar3 == (int *)0x0)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x261867 /* "No grenade...
" */;
    return param_1;
  }
  cVar1 = CINSNextBot::IsIdle(this_01);
  if ((cVar1 != '\0') &&
     (fVar8 = (float10)CINSNextBot::GetIdleDuration(this_02),
     *(float *)(unaff_EBX + 0x204fdb /* typeinfo name for CBaseGameSystem+0x32 */) <= (float)fVar8 &&
     (float)fVar8 != *(float *)(unaff_EBX + 0x204fdb /* typeinfo name for CBaseGameSystem+0x32 */))) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2618a8 /* "Idle in fire rpg" */;
    return param_1;
  }
  if (*(int *)(in_stack_0000000c + 0x2284) == 3) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2618b9 /* "Error acquiring RPG target" */;
    return param_1;
  }
  fVar9 = *(float *)(**(int **)(&DAT_0048710f + unaff_EBX) + 0xc) - *(float *)((int)param_2 + 0x68);
  if (*(float *)(unaff_EBX + 0x204fcf /* typeinfo name for CBaseGameSystem+0x26 */) <= fVar9 && fVar9 != *(float *)(unaff_EBX + 0x204fcf /* typeinfo name for CBaseGameSystem+0x26 */)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2618d4 /* "Expired." */;
    return param_1;
  }
  if (piVar2 != piVar3) {
    DevMsg((char *)(CINSRules_Ambush::GetRapidDeploymentFrequencyForTeam + unaff_EBX + 3));
    CINSNextBot::ChooseBestWeapon(this_03,in_stack_0000000c,(float)piVar2);
  }
  if (*(float *)((int)param_2 + 100) <= 0.0) {
    if ((*(int *)(in_stack_0000000c + 0x2284) == 2) &&
       (fVar9 = *(float *)(**(int **)(&DAT_0048710f + unaff_EBX) + 0xc) -
                *(float *)((int)param_2 + 0x68),
       *(float *)(unaff_EBX + 0x204fc7 /* typeinfo name for CBaseGameSystem+0x1e */) <= fVar9 && fVar9 != *(float *)(unaff_EBX + 0x204fc7 /* typeinfo name for CBaseGameSystem+0x1e */))) {
      piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      this_09 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)0x0;
      pCVar7 = (CINSWeapon *)((int)param_2 + 0x44);
      cVar1 = (**(code **)(*piVar2 + 0x108 /* CINSBotVision::IsAbleToSee */))(piVar2,pCVar7,0);
      if (cVar1 == '\0') {
        DevMsg((char *)(unaff_EBX + 0x26196b /* "CINSBotFireRPG - Bailing, LoS not clear to our target (%.2f)
" */));
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined **)(param_1 + 8) = &UNK_002618ed + unaff_EBX;
        return param_1;
      }
      cVar1 = CINSWeapon::IsDeploying(this_04);
      if (cVar1 == '\0') {
        cVar1 = (**(code **)(*piVar3 + 0x668 /* CINSPlayer::StartObserverMode */))(piVar3);
        if (cVar1 != '\0') {
          if ((*(char *)((int)param_2 + 0x6c) == '\0') &&
             (cVar1 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x487167 /* &g_pGameRules */) + 0x29c))
                                ((int *)**(undefined4 **)(unaff_EBX + 0x487167 /* &g_pGameRules */)), cVar1 != '\0')) {
            local_4c[0] = 0;
            local_4c[1] = 0;
            local_4c[2] = 0;
            local_40 = (CINSWeapon *)0x0;
            iVar4 = **(int **)(&DAT_0048710f + unaff_EBX);
            local_3c = 0;
            *(undefined1 *)((int)param_2 + 0x6c) = 1;
            if (*(int *)(iVar4 + 0x14) < 1) {
              local_54 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)local_4c;
            }
            else {
              local_54 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)0x1;
              do {
                piVar2 = (int *)UTIL_PlayerByIndex((int)local_54);
                if ((piVar2 == (int *)0x0) ||
                   (cVar1 = (**(code **)(*piVar2 + 0x158 /* CBasePlayer::IsPlayer */))(piVar2,pCVar7,this_09), cVar1 == '\0')) {
                  local_2c[0] = (int *)0x0;
                }
                else {
                  local_2c[0] = piVar2;
                  cVar1 = (**(code **)(*piVar2 + 0x118 /* CBaseEntity::IsAlive */))(piVar2);
                  if (cVar1 != '\0') {
                    iVar4 = CBaseEntity::GetTeamNumber(this_05);
                    iVar5 = CINSRules::GetHumanTeam(this_06);
                    if ((iVar4 == iVar5) &&
                       (pCVar7 = in_stack_0000000c,
                       cVar1 = (**(code **)(*local_2c[0] + 0x438))(local_2c[0]), cVar1 != '\0')) {
                      this_09 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)local_2c;
                      pCVar7 = local_40;
                      CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>>::InsertBefore
                                (this_09,(int)local_4c,(CINSPlayer **)local_40);
                    }
                  }
                }
                local_54 = local_54 + 1;
              } while ((int)local_54 <= *(int *)(**(int **)(&DAT_0048710f + unaff_EBX) + 0x14));
            }
            if (0 < (int)local_40) {
              iVar4 = RandomInt(0,local_40 + -1);
              piVar2 = *(int **)(local_4c[0] + iVar4 * 4);
              local_54 = extraout_ECX;
              if (piVar2 != (int *)0x0) {
                (**(code **)(*piVar2 + 0x800 /* CINSPlayer::SpeakConceptIfAllowed */))(piVar2,0x4c,0,0,0,0);
                local_54 = extraout_ECX_00;
              }
            }
            CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>>::~CUtlVector(local_54);
          }
          dVar10 = (double)(*(float *)(**(int **)(&DAT_0048710f + unaff_EBX) + 0xc) -
                           *(float *)((int)param_2 + 0x68));
          DevMsg((char *)(unaff_EBX + 0x261a03 /* "CINSBotFireRPG - Pressing fire button for %.2f (%.2f)
" */));
          (**(code **)(*(int *)in_stack_0000000c + 0x8c0 /* NextBotPlayer::PressFireButton */))(in_stack_0000000c,0x3f000000 /* 0.5f */,dVar10);
          CountdownTimer::Start(this_07,(float)((int)param_2 + 0x5c));
          CountdownTimer::Start(this_08,(float)(in_stack_0000000c + 0xb388));
          *(undefined4 *)(in_stack_0000000c + 0xb344) = 0x41200000 /* 10.0f */;
          goto LAB_0071f8b7;
        }
        pcVar6 = (char *)(unaff_EBX + 0x2619d7 /* "CINSBotFireRPG - Unable to attack (%.2f)
" */);
      }
      else {
        pcVar6 = (char *)(unaff_EBX + 0x2619ab /* "CINSBotFireRPG - Still deploying (%.2f)
" */);
      }
      DevMsg(pcVar6);
    }
  }
  else {
    fVar8 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 100) <= (float)fVar8 &&
        (float)fVar8 != *(float *)((int)param_2 + 100)) {
      piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      (**(code **)(*piVar2 + 0x160 /* PlayerBody::ForceLookAtExpire */))(piVar2);
      DevMsg((char *)(CINSRules_Ambush::IsEliminationRules + unaff_EBX + 7));
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined **)(param_1 + 8) = &UNK_002618dd + unaff_EBX;
      return param_1;
    }
  }
LAB_0071f8b7:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotFireRPG::OnEnd
 * Address: 0071d990
 * ---------------------------------------- */

/* CINSBotFireRPG::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotFireRPG::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::GetName
 * Address: 0071fd30
 * ---------------------------------------- */

/* CINSBotFireRPG::GetName() const */

int CINSBotFireRPG::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2612a3 /* "Firing RPG" */;
}



/* ----------------------------------------
 * CINSBotFireRPG::ShouldAttack
 * Address: 0071fd50
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFireRPG::ShouldAttack(INextBot const*, CKnownEntity const*) const */

void __thiscall
CINSBotFireRPG::ShouldAttack(CINSBotFireRPG *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::ShouldAttack
 * Address: 0071fd60
 * ---------------------------------------- */

/* CINSBotFireRPG::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotFireRPG::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotFireRPG::HasRPGTarget
 * Address: 0071e020
 * ---------------------------------------- */

/* WARNING: Restarted to delay deadcode elimination for space: stack */
/* CINSBotFireRPG::HasRPGTarget(CINSNextBot*, Vector&) */

undefined4 __cdecl CINSBotFireRPG::HasRPGTarget(CINSNextBot *param_1,Vector *param_2)

{
  uint *puVar1;
  int *piVar2;
  char cVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  int iVar10;
  int *piVar11;
  undefined4 *puVar12;
  CINSRules *this;
  CBasePlayer *this_00;
  CINSPlayer *this_01;
  CINSRules *extraout_ECX;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *this_02;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  ConVar *this_03;
  CBaseEntity *this_04;
  CBaseEntity *this_05;
  CBaseEntity *this_06;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *this_07;
  CINSPlayer *extraout_ECX_04;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX_05;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX_06;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX_07;
  CBaseEntity *this_08;
  CBaseEntity *this_09;
  CBaseEntity *this_10;
  CBaseEntity *extraout_ECX_08;
  CUtlVector<Vector,CUtlMemory<Vector,int>> *pCVar13;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *extraout_ECX_09;
  CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *this_11;
  CUtlVector<Vector,CUtlMemory<Vector,int>> *extraout_ECX_10;
  CUtlVector<Vector,CUtlMemory<Vector,int>> *extraout_ECX_11;
  CBaseEntity *extraout_ECX_12;
  int unaff_EBX;
  undefined4 uVar14;
  ushort in_FPUControlWord;
  float10 fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  CINSNextBot *pCVar23;
  Vector *pVVar24;
  int **ppiVar25;
  Vector *pVVar26;
  int local_254;
  float local_250;
  float local_240;
  int local_23c;
  CBaseEntity *local_22c;
  float local_224;
  float local_210;
  float local_20c;
  float local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined4 local_1c4;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  undefined4 local_19c;
  undefined4 local_198;
  undefined4 local_194;
  undefined4 local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_17c;
  undefined1 local_178;
  undefined1 local_177;
  int *local_16c;
  undefined4 local_168;
  undefined4 local_164;
  CINSNextBot *local_160;
  undefined4 local_15c;
  int local_14c [3];
  Vector *local_140;
  int local_13c;
  IHandleEntity local_12c [16];
  float local_11c;
  float local_118;
  float local_114;
  float local_10c;
  float local_108;
  float local_104;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_ec;
  float local_e8;
  float local_e4;
  Vector local_d4 [12];
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  Vector local_80 [12];
  Vector local_74 [12];
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  int *local_2c [3];
  ushort local_20;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x71e02b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar8 = *(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
     iVar8 == iVar4)) {
    piVar11 = *(int **)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar11 != unaff_EBX + 0x262ff1 /* "CINSBotFireRPG::HasRPGTarget" */) {
      piVar11 = (int *)CVProfNode::GetSubNode
                                 ((char *)piVar11,unaff_EBX + 0x262ff1 /* "CINSBotFireRPG::HasRPGTarget" */,(char *)0x0,
                                  unaff_EBX + 0x262c3b /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar11;
    }
    iVar8 = *(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */);
    puVar1 = (uint *)(piVar11[0x1c] * 8 + *(int *)(iVar8 + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar8 + 0x1010) = 0;
  }
  if (param_1 == (CINSNextBot *)0x0) goto LAB_0071e6a0;
  piVar11 = *(int **)(unaff_EBX + 0x488f15 /* &ins_bot_rpg_minimum_player_cluster */);
  piVar6 = (int *)piVar11[7];
  if (piVar6 == piVar11) {
    uVar5 = piVar11[0xc] ^ (uint)piVar11;
  }
  else {
    uVar5 = (**(code **)(*piVar6 + 0x40))(piVar6);
  }
  uVar14 = 0;
  if (uVar5 == 0) goto LAB_0071e08c;
  fVar15 = (float10)CountdownTimer::Now();
  if (*(float *)(param_1 + 0xb378) <= (float)fVar15 && (float)fVar15 != *(float *)(param_1 + 0xb378)
     ) {
    if (**(int **)(unaff_EBX + 0x4888cd /* &g_pGameRules */) != 0) {
      cVar3 = CINSRules::IsTraining(this);
      uVar14 = 0;
      if (cVar3 != '\0') goto LAB_0071e08c;
    }
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_1);
    piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
    if ((piVar6 != (int *)0x0) && (cVar3 = (**(code **)(*piVar6 + 0x3c))(piVar6), cVar3 != '\0')) {
      pfVar9 = &local_b0;
      pVVar26 = (Vector *)&local_bc;
      pVVar24 = (Vector *)&local_c8;
      CBasePlayer::EyePositionAndVectors(this_00,(Vector *)param_1,local_d4,pVVar24,pVVar26);
      (**(code **)(*(int *)param_1 + 0x20c /* CINSNextBot::EyePosition */))(&local_98,param_1,pVVar24,pVVar26,pfVar9);
      fVar20 = *(float *)(unaff_EBX + 0x19af51 /* typeinfo name for IServerBenchmark+0x13 */);
      fVar17 = *(float *)(unaff_EBX + 0x206735 /* typeinfo name for CBaseGameSystem+0x26 */);
      ppiVar25 = (int **)0x0;
      uVar14 = 3;
      local_a4 = (local_bc * fVar20 + local_c8 * fVar17 + local_98) - local_b0;
      local_a0 = (local_b8 * fVar20 - local_ac) + local_94 + local_c4 * fVar17;
      local_9c = (fVar20 * local_b4 - local_a8) + local_90 + fVar17 * local_c0;
      piVar7 = (int *)CINSPlayer::GetWeaponInSlot(this_01,(int)param_1,true);
      if ((piVar7 != (int *)0x0) &&
         (cVar3 = (**(code **)(*piVar7 + 0x410 /* CBaseCombatCharacter::EyeDirection3D */))(piVar7,uVar14,ppiVar25), cVar3 != '\0')) {
        iVar8 = (**(code **)(*piVar7 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar7);
        uVar14 = 0;
        if (iVar8 != 7) goto LAB_0071e08c;
        piVar7 = (int *)(**(code **)(*piVar6 + 0x10))(piVar6);
        if ((piVar7 == (int *)0x0) ||
           (cVar3 = (**(code **)(*piVar7 + 0x158 /* CBasePlayer::IsPlayer */))(piVar7), cVar3 == '\0')) goto LAB_0071e6a0;
        pfVar9 = (float *)(**(code **)(*piVar7 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(piVar7);
        fVar20 = *pfVar9;
        fVar17 = pfVar9[1];
        fVar22 = pfVar9[2];
        pCVar23 = param_1;
        (**(code **)(*(int *)param_1 + 0x20c /* CINSNextBot::EyePosition */))(&local_11c,param_1);
        piVar7 = *(int **)(unaff_EBX + 0x48896d /* &ins_bot_rpg_minimum_firing_distance */);
        fVar16 = fVar20 - local_11c;
        fVar19 = fVar17 - local_118;
        fVar21 = fVar22 - local_114;
        piVar2 = (int *)piVar7[7];
        if (piVar2 == piVar7) {
          local_240 = (float)(piVar7[0xb] ^ (uint)piVar7);
LAB_0071e7a9:
          fVar18 = (float)((uint)piVar7 ^ piVar7[0xb]);
        }
        else {
          fVar15 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
          piVar2 = (int *)piVar7[7];
          local_240 = (float)fVar15;
          if (piVar2 == piVar7) goto LAB_0071e7a9;
          fVar15 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
          fVar18 = (float)fVar15;
        }
        uVar14 = 0;
        if (fVar19 * fVar19 + fVar16 * fVar16 + fVar21 * fVar21 < fVar18 * local_240)
        goto LAB_0071e08c;
        cVar3 = (**(code **)(*piVar6 + 0x3c))(piVar6);
        if (cVar3 != '\0') {
          local_16c = (int *)0x0;
          local_168 = 0;
          local_164 = 0;
          local_160 = (CINSNextBot *)0x0;
          local_15c = 0;
          this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)extraout_ECX;
          if (0 < *(int *)(**(int **)(unaff_EBX + 0x488875 /* &gpGlobals */) + 0x14)) {
            iVar8 = 1;
            do {
              piVar6 = (int *)UTIL_PlayerByIndex(iVar8);
              this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)extraout_ECX_00;
              if ((piVar6 == (int *)0x0) ||
                 (cVar3 = (**(code **)(*piVar6 + 0x158))(piVar6,pCVar23,ppiVar25),
                 this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)extraout_ECX_01,
                 cVar3 == '\0')) {
                local_2c[0] = (int *)0x0;
              }
              else {
                local_2c[0] = piVar6;
                cVar3 = (**(code **)(*piVar6 + 0x118))(piVar6);
                this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)this_02;
                if ((cVar3 != '\0') &&
                   (cVar3 = CINSPlayer::InSpawnZone(this_02),
                   this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)extraout_ECX_02,
                   cVar3 == '\0')) {
                  fVar16 = *(float *)(**(int **)(unaff_EBX + 0x488875 /* &gpGlobals */) + 0xc);
                  fVar19 = (float)local_2c[0][0x76e];
                  piVar6 = *(int **)(unaff_EBX + 0x5ce5f1 /* ins_bot_rpg_grace_time+0x1c */);
                  if (piVar6 == (int *)(unaff_EBX + 0x5ce5d5 /* ins_bot_rpg_grace_time */U)) {
                    fVar21 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x5ce601 /* ins_bot_rpg_grace_time+0x2c */));
                  }
                  else {
                    fVar15 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
                    fVar21 = (float)fVar15;
                    this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)extraout_ECX_03
                    ;
                  }
                  if (fVar21 <= fVar16 - fVar19) {
                    pfVar9 = (float *)(**(code **)(*local_2c[0] + 0x260))(local_2c[0]);
                    fVar21 = fVar20 - *pfVar9;
                    fVar16 = fVar17 - pfVar9[1];
                    fVar19 = fVar22 - pfVar9[2];
                    fVar15 = (float10)ConVar::GetFloat(this_03);
                    this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)this_04;
                    if ((SQRT(fVar16 * fVar16 + fVar21 * fVar21 + fVar19 * fVar19) <= (float)fVar15)
                       && (iVar4 = CBaseEntity::GetTeamNumber(this_04),
                          this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)this_05,
                          iVar4 - 2U < 2)) {
                      iVar4 = CBaseEntity::GetTeamNumber(this_05);
                      iVar10 = CBaseEntity::GetTeamNumber(this_06);
                      this_11 = this_07;
                      if (iVar4 != iVar10) {
                        ppiVar25 = local_2c;
                        pCVar23 = local_160;
                        CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>>::InsertBefore
                                  (this_07,(int)&local_16c,(CINSPlayer **)local_160);
                        this_11 = (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>> *)
                                  extraout_ECX_04;
                      }
                    }
                  }
                }
              }
              iVar8 = iVar8 + 1;
            } while (iVar8 <= *(int *)(**(int **)(unaff_EBX + 0x488875 /* &gpGlobals */) + 0x14));
          }
          local_22c = (CBaseEntity *)&local_16c;
          if (local_160 == (CINSNextBot *)0x0) {
            uVar14 = 0;
          }
          else {
            cVar3 = CINSRules::IsOutpost((CINSRules *)this_11);
            this_11 = extraout_ECX_05;
            if ((cVar3 == '\0') &&
               (cVar3 = CINSRules::IsEntrenchment(), this_11 = extraout_ECX_06, cVar3 == '\0')) {
              piVar6 = (int *)piVar11[7];
              if (piVar6 == piVar11) {
                uVar5 = piVar11[0xc] ^ (uint)piVar11;
              }
              else {
                uVar5 = (**(code **)(*piVar6 + 0x40))(piVar6);
                this_11 = extraout_ECX_07;
              }
              fVar20 = (float)(int)uVar5;
            }
            else {
              fVar20 = ((float)*(int *)(**(int **)(unaff_EBX + 0x4888cd /* &g_pGameRules */) + 1000) +
                       *(float *)(unaff_EBX + 0x19aae5 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x30 */)) * *(float *)(unaff_EBX + 0x2631d5 /* typeinfo name for INextBotReply+0x12 */);
              if (*(float *)(unaff_EBX + 0x19aae9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */) <= fVar20) {
                fVar20 = *(float *)(unaff_EBX + 0x19aae9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
              }
              if (fVar20 <= *(float *)(unaff_EBX + 0x19aadd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
                fVar20 = *(float *)(unaff_EBX + 0x19aadd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */);
              }
              local_2c[0] = (int *)CONCAT22(local_2c[0]._2_2_,in_FPUControlWord);
              local_20 = in_FPUControlWord & 0xf3ff | 0x400;
              fVar20 = ROUND(*(float *)(unaff_EBX + 0x208d85 /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x30 */) - fVar20);
            }
            if (((int)fVar20 < 2) || (uVar14 = 0, (int)fVar20 <= (int)local_160)) {
              pfVar9 = (float *)(**(code **)(*(int *)(*local_16c + 0xf0) + 4))(*local_16c + 0xf0);
              iVar8 = *local_16c;
              if ((*(byte *)(iVar8 + 0xd1) & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition(this_08);
              }
              local_10c = *pfVar9 + *(float *)(iVar8 + 0x208);
              local_108 = pfVar9[1] + *(float *)(iVar8 + 0x20c);
              local_104 = pfVar9[2] + *(float *)(iVar8 + 0x210);
              pfVar9 = (float *)(**(code **)(*(int *)(*local_16c + 0xf0) + 8))(*local_16c + 0xf0);
              iVar8 = *local_16c;
              this_10 = this_09;
              if ((*(byte *)(iVar8 + 0xd1) & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition(this_09);
                this_10 = extraout_ECX_12;
              }
              local_fc = *pfVar9 + *(float *)(iVar8 + 0x208);
              local_f8 = pfVar9[1] + *(float *)(iVar8 + 0x20c);
              local_f4 = pfVar9[2] + *(float *)(iVar8 + 0x210);
              if (0 < (int)local_160) {
                iVar8 = 0;
                do {
                  this_10 = (CBaseEntity *)(iVar8 * 4);
                  pfVar9 = (float *)(**(code **)(*(int *)(local_16c[iVar8] + 0xf0) + 4))
                                              (local_16c[iVar8] + 0xf0);
                  iVar4 = local_16c[iVar8];
                  iVar10 = iVar4;
                  if ((*(byte *)(iVar4 + 0xd1) & 8) != 0) {
                    CBaseEntity::CalcAbsolutePosition(local_22c);
                    iVar10 = local_16c[iVar8];
                  }
                  fVar20 = *(float *)(iVar4 + 0x208);
                  fVar17 = *(float *)(iVar4 + 0x20c);
                  fVar22 = *pfVar9;
                  fVar16 = pfVar9[1];
                  fVar19 = pfVar9[2];
                  fVar21 = *(float *)(iVar4 + 0x210);
                  pfVar9 = (float *)(**(code **)(*(int *)(iVar10 + 0xf0) + 8))(iVar10 + 0xf0);
                  iVar4 = local_16c[iVar8];
                  if ((*(byte *)(iVar4 + 0xd1) & 8) != 0) {
                    CBaseEntity::CalcAbsolutePosition(this_10);
                    this_10 = extraout_ECX_08;
                  }
                  iVar8 = iVar8 + 1;
                  fVar19 = fVar19 + fVar21;
                  fVar16 = fVar16 + fVar17;
                  fVar22 = fVar22 + fVar20;
                  if (local_108 <= fVar16) {
                    fVar16 = local_108;
                  }
                  if (local_10c <= fVar22) {
                    fVar22 = local_10c;
                  }
                  if (local_104 <= fVar19) {
                    fVar19 = local_104;
                  }
                  local_104 = fVar19;
                  fVar17 = *pfVar9 + *(float *)(iVar4 + 0x208);
                  fVar19 = pfVar9[1] + *(float *)(iVar4 + 0x20c);
                  fVar20 = pfVar9[2] + *(float *)(iVar4 + 0x210);
                  if (fVar19 <= local_f8) {
                    fVar19 = local_f8;
                  }
                  if (fVar17 <= local_fc) {
                    fVar17 = local_fc;
                  }
                  if (fVar20 <= local_f4) {
                    fVar20 = local_f4;
                  }
                  local_10c = fVar22;
                  local_108 = fVar16;
                  local_fc = fVar17;
                  local_f8 = fVar19;
                  local_f4 = fVar20;
                } while (iVar8 < (int)local_160);
              }
              fVar15 = (float10)ConVar::GetFloat((ConVar *)this_10);
              fVar20 = (float)fVar15;
              local_10c = local_10c - fVar20;
              local_108 = local_108 - fVar20;
              local_104 = local_104 - fVar20;
              local_fc = local_fc + fVar20;
              local_f8 = local_f8 + fVar20;
              local_f4 = fVar20 + local_f4;
              iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */) + 0x40))
                                (*(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */));
              if (iVar8 != 0) {
                local_8c = local_fc - local_10c;
                local_88 = local_f8 - local_108;
                local_84 = local_f4 - local_104;
                NDebugOverlay::Box((Vector *)&local_10c,*(Vector **)(unaff_EBX + 0x4885a1 /* &vec3_origin */),
                                   (Vector *)&local_8c,0,0,0xff,5,3.0);
              }
              local_e8 = local_f8 + local_108;
              local_e4 = local_f4 + local_104;
              local_ec = local_fc + local_10c;
              iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */) + 0x40))
                                (*(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */));
              if (iVar8 != 0) {
                NDebugOverlay::Cross((Vector *)&local_ec,16.0,0,0xff,0,true,3.0);
              }
              local_1c4 = 0;
              local_68 = local_ec - local_a4;
              local_64 = local_e8 - local_a0;
              local_60 = local_e4 - local_9c;
              VectorVectors((Vector *)&local_68,local_80,local_74);
              UTIL_TraceLine((Vector *)&local_a4,(Vector *)&local_ec,1,(IHandleEntity *)param_1,0,
                             (CGameTrace *)&local_210);
              local_5c = local_204 - local_210;
              local_58 = local_200 - local_20c;
              local_54 = local_1fc - local_208;
              cVar3 = IsBoxIntersectingRay
                                ((Vector *)&local_10c,(Vector *)&local_fc,(Vector *)&local_210,
                                 (Vector *)&local_5c,0.0);
              if (cVar3 != '\0') {
                iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */) + 0x40))
                                  (*(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */));
                if (iVar8 != 0) {
                  NDebugOverlay::Line((Vector *)&local_210,(Vector *)&local_204,0xff,0,0,true,3.0);
                }
                *(float *)param_2 = local_ec;
                *(float *)(param_2 + 4) = local_e8;
                *(float *)(param_2 + 8) = local_e4;
              }
              local_14c[0] = 0;
              local_14c[1] = 0x32;
              local_14c[2] = 0;
              local_14c[0] = (*(code *)**(undefined4 **)**(undefined4 **)(unaff_EBX + 0x48884d /* &GCSDK::GetPchTempTextBuffer */))
                                       ((undefined4 *)**(undefined4 **)(unaff_EBX + 0x48884d /* &GCSDK::GetPchTempTextBuffer */),600);
              fVar22 = local_fc - local_10c;
              local_140 = (Vector *)0x0;
              fVar16 = local_f8 - local_108;
              local_254 = 5;
              fVar20 = *(float *)(unaff_EBX + 0x20672d /* typeinfo name for CBaseGameSystem+0x1e */);
              fVar19 = local_f4 - local_104;
              local_250 = *(float *)(unaff_EBX + 0x20617d /* typeinfo name for CTraceFilterNoCombatCharacters+0x28 */);
              fVar17 = *(float *)(unaff_EBX + 0x20672d /* typeinfo name for CBaseGameSystem+0x1e */);
              local_13c = local_14c[0];
              do {
                iVar8 = 5;
                local_224 = 0.1;
                fVar21 = local_250 * fVar19;
                do {
                  local_50 = local_224 * fVar22 + local_10c;
                  local_4c = fVar20 * fVar16 + local_108;
                  local_48 = fVar21 + local_104;
                  CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)local_14c,local_140);
                  iVar8 = iVar8 + -1;
                  local_224 = *(float *)(unaff_EBX + 0x206bb9 /* typeinfo name for CBroadcastRecipientFilter+0x28 */) + local_224;
                } while (iVar8 != 0);
                fVar18 = 0.1;
                iVar8 = 5;
                do {
                  local_44 = fVar17 * fVar22 + local_10c;
                  local_40 = fVar18 * fVar16 + local_108;
                  local_3c = fVar21 + local_104;
                  CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)local_14c,local_140);
                  iVar8 = iVar8 + -1;
                  fVar18 = *(float *)(unaff_EBX + 0x206bb9 /* typeinfo name for CBroadcastRecipientFilter+0x28 */) + fVar18;
                } while (iVar8 != 0);
                local_254 = local_254 + -1;
                local_250 = local_250 - *(float *)(unaff_EBX + 0x206bb9 /* typeinfo name for CBroadcastRecipientFilter+0x28 */);
              } while (local_254 != 0);
              pCVar13 = extraout_ECX_10;
              if (0 < (int)local_140) {
                iVar8 = 0;
                local_23c = 0;
                do {
                  local_17c = 0;
                  pfVar9 = (float *)(iVar8 + local_14c[0]);
                  local_1bc = local_a4;
                  local_1ac = *pfVar9 - local_a4;
                  local_1b8 = local_a0;
                  local_1a8 = pfVar9[1] - local_a0;
                  local_178 = 1;
                  local_1a4 = pfVar9[2] - local_9c;
                  local_1b4 = local_9c;
                  local_184 = 0;
                  local_188 = 0;
                  local_18c = 0;
                  local_177 = local_1a8 * local_1a8 + local_1ac * local_1ac + local_1a4 * local_1a4
                              != 0.0;
                  local_194 = 0;
                  local_198 = 0;
                  local_19c = 0;
                  CTraceFilterSimple::CTraceFilterSimple
                            ((CTraceFilterSimple *)pCVar13,local_12c,(int)param_1,
                             (_func_bool_IHandleEntity_ptr_int *)0x0);
                  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x48874d /* &enginetrace */) + 0x14))
                            ((int *)**(undefined4 **)(unaff_EBX + 0x48874d /* &enginetrace */),&local_1bc,1,local_12c,
                             &local_210);
                  piVar11 = *(int **)(unaff_EBX + 0x488a15 /* &r_visualizetraces */);
                  iVar4 = (**(code **)(*piVar11 + 0x40))(piVar11);
                  if (iVar4 != 0) {
                    iVar4 = (**(code **)(*piVar11 + 0x40))(piVar11);
                    fVar20 = 0.5;
                    if (iVar4 != 0) {
                      fVar20 = -1.0;
                    }
                    DebugDrawLine((Vector *)&local_210,(Vector *)&local_204,0xff,0,0,true,fVar20);
                  }
                  local_38 = local_204 - local_210;
                  local_34 = local_200 - local_20c;
                  local_30 = local_1fc - local_208;
                  cVar3 = IsBoxIntersectingRay
                                    ((Vector *)&local_10c,(Vector *)&local_fc,(Vector *)&local_210,
                                     (Vector *)&local_38,0.0);
                  if (cVar3 != '\0') {
                    iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */) + 0x40))
                                      (*(int **)(unaff_EBX + 0x489065 /* &ins_debug_rpg_targets */));
                    if (iVar4 != 0) {
                      NDebugOverlay::Line((Vector *)&local_210,(Vector *)&local_204,0xff,0,0,true,
                                          3.0);
                    }
                    puVar12 = (undefined4 *)(iVar8 + local_14c[0]);
                    pCVar13 = (CUtlVector<Vector,CUtlMemory<Vector,int>> *)puVar12[1];
                    uVar14 = puVar12[2];
                    *(undefined4 *)param_2 = *puVar12;
                    *(CUtlVector<Vector,CUtlMemory<Vector,int>> **)(param_2 + 4) = pCVar13;
                    *(undefined4 *)(param_2 + 8) = uVar14;
                    uVar14 = 1;
                    goto LAB_0071ebb1;
                  }
                  local_23c = local_23c + 1;
                  iVar8 = iVar8 + 0xc;
                  pCVar13 = extraout_ECX_11;
                } while (local_23c < (int)local_140);
              }
              uVar14 = 0;
LAB_0071ebb1:
              CUtlVector<Vector,CUtlMemory<Vector,int>>::~CUtlVector(pCVar13);
              this_11 = extraout_ECX_09;
            }
          }
          CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>>::~CUtlVector(this_11);
          goto LAB_0071e08c;
        }
      }
    }
  }
LAB_0071e6a0:
  uVar14 = 0;
LAB_0071e08c:
  if ((local_1d != '\0') &&
     (((*(char *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
       (*(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
      (iVar8 = *(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
      iVar8 == iVar4)))) {
    cVar3 = CVProfNode::ExitScope();
    if (cVar3 == '\0') {
      iVar8 = *(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar8 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar8;
    }
    *(bool *)(*(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
         iVar8 == *(int *)(unaff_EBX + 0x488949 /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
    return uVar14;
  }
  return uVar14;
}



/* ----------------------------------------
 * CINSBotFireRPG::ShouldWalk
 * Address: 0071fd70
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFireRPG::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotFireRPG::ShouldWalk(CINSBotFireRPG *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::ShouldWalk
 * Address: 0071fd80
 * ---------------------------------------- */

/* CINSBotFireRPG::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotFireRPG::ShouldWalk(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotFireRPG::~CINSBotFireRPG
 * Address: 0071d9a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFireRPG::~CINSBotFireRPG() */

void __thiscall CINSBotFireRPG::~CINSBotFireRPG(CINSBotFireRPG *this)

{
  ~CINSBotFireRPG(this);
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::~CINSBotFireRPG
 * Address: 0071d9b0
 * ---------------------------------------- */

/* CINSBotFireRPG::~CINSBotFireRPG() */

void __thiscall CINSBotFireRPG::~CINSBotFireRPG(CINSBotFireRPG *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4791f3 /* vtable for CINSBotFireRPG+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_0047938b + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4897c3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::~CINSBotFireRPG
 * Address: 0071d9e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFireRPG::~CINSBotFireRPG() */

void __thiscall CINSBotFireRPG::~CINSBotFireRPG(CINSBotFireRPG *this)

{
  ~CINSBotFireRPG(this);
  return;
}



/* ----------------------------------------
 * CINSBotFireRPG::~CINSBotFireRPG
 * Address: 0071d9f0
 * ---------------------------------------- */

/* CINSBotFireRPG::~CINSBotFireRPG() */

void __thiscall CINSBotFireRPG::~CINSBotFireRPG(CINSBotFireRPG *this)

{
  CINSBotFireRPG *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSBotFireRPG(this_00);
  operator_delete(in_stack_00000004);
  return;
}



