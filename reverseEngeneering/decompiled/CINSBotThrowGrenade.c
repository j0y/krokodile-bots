/*
 * CINSBotThrowGrenade -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 17
 */

/* ----------------------------------------
 * CINSBotThrowGrenade::CINSBotThrowGrenade
 * Address: 00734d10
 * ---------------------------------------- */

/* CINSBotThrowGrenade::CINSBotThrowGrenade(Vector, Vector) */

void __thiscall
CINSBotThrowGrenade::CINSBotThrowGrenade
          (undefined4 param_1,int *param_2,int param_3,int param_4,int param_5,int param_6,
          int param_7,int param_8)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  *param_2 = unaff_EBX + 0x463fad /* vtable for CINSBotThrowGrenade+0x8 */;
  param_2[1] = unaff_EBX + 0x464145 /* vtable for CINSBotThrowGrenade+0x1a0 */;
  param_2[0x14] = unaff_EBX + 0x3f349d /* vtable for CountdownTimer+0x8 */;
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
  param_2[0x15] = 0;
  (*(code *)(unaff_EBX + -0x5045ab /* CountdownTimer::NetworkStateChanged */))(param_2 + 0x14,param_2 + 0x15);
  param_2[0x16] = -0x40800000;
  (**(code **)(param_2[0x14] + 4))(param_2 + 0x14,param_2 + 0x16);
  param_2[0x18] = 0;
  param_2[0x17] = unaff_EBX + 0x3f349d /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x5045ab /* CountdownTimer::NetworkStateChanged */))(param_2 + 0x17,param_2 + 0x18);
  param_2[0x19] = -0x40800000;
  (**(code **)(param_2[0x17] + 4))(param_2 + 0x17,param_2 + 0x19);
  param_2[0x11] = param_3;
  param_2[0x12] = param_4;
  param_2[0x13] = param_5;
  param_2[0xe] = param_6;
  param_2[0xf] = param_7;
  param_2[0x10] = param_8;
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::CINSBotThrowGrenade
 * Address: 00735f70
 * ---------------------------------------- */

/* CINSBotThrowGrenade::CINSBotThrowGrenade() */

void __thiscall CINSBotThrowGrenade::CINSBotThrowGrenade(CINSBotThrowGrenade *this)

{
  CINSNextBot *pCVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int unaff_EBX;
  int *in_stack_00000004;
  int local_3c;
  int local_38;
  int local_34;
  int local_2c;
  int local_28;
  int local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x735f7b;
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x462d4d /* vtable for CINSBotThrowGrenade+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x462ee5 /* vtable for CINSBotThrowGrenade+0x1a0 */;
  in_stack_00000004[0x14] = unaff_EBX + 0x3f223d /* vtable for CountdownTimer+0x8 */;
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
  in_stack_00000004[0x15] = 0;
  (*(code *)(unaff_EBX + -0x50580b /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0x14,in_stack_00000004 + 0x15);
  in_stack_00000004[0x16] = -0x40800000;
  (**(code **)(in_stack_00000004[0x14] + 4))(in_stack_00000004 + 0x14,in_stack_00000004 + 0x16);
  in_stack_00000004[0x18] = 0;
  in_stack_00000004[0x17] = unaff_EBX + 0x3f223d /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x50580b /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0x17,in_stack_00000004 + 0x18);
  in_stack_00000004[0x19] = -0x40800000;
  (**(code **)(in_stack_00000004[0x17] + 4))(in_stack_00000004 + 0x17,in_stack_00000004 + 0x19);
  pCVar1 = (CINSNextBot *)in_stack_00000004[7];
  if (pCVar1 != (CINSNextBot *)0x0) {
    piVar3 = (int *)(**(code **)(*(int *)pCVar1 + 0x974))(pCVar1);
    iVar4 = (**(code **)(*piVar3 + 0xd0))(piVar3,1);
    if (iVar4 != 0) {
      cVar2 = CanIThrowGrenade(pCVar1,(Vector *)&local_3c);
      if (cVar2 != '\0') {
        (**(code **)(*(int *)pCVar1 + 0x20c))(&local_2c,pCVar1);
        in_stack_00000004[0x11] = local_2c;
        in_stack_00000004[0x12] = local_28;
        in_stack_00000004[0x13] = local_24;
        in_stack_00000004[0xe] = local_3c;
        in_stack_00000004[0xf] = local_38;
        in_stack_00000004[0x10] = local_34;
        return;
      }
      *(undefined4 *)(pCVar1 + 0x2280) = 3;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::OnStart
 * Address: 00734540
 * ---------------------------------------- */

/* CINSBotThrowGrenade::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotThrowGrenade::OnStart(CINSBotThrowGrenade *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  int *piVar2;
  CINSPlayer *this_00;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *this_01;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar5;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x73454b;
  __i686_get_pc_thunk_bx();
  if (*(int *)(in_stack_0000000c + 0x2280) == 3) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24da71 /* "Nothing to throw at" */;
    return param_1;
  }
  uVar5 = 0;
  fVar1 = (float)CINSPlayer::GetWeaponInSlot(this_00,(int)in_stack_0000000c,true);
  if (fVar1 != 0.0) {
    *(undefined4 *)(in_stack_0000000c + 0x2280) = 1;
    fVar3 = (float10)CountdownTimer::Now();
    fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x184a31 /* typeinfo name for IServerBenchmark+0x13 */);
    if (*(float *)(in_stack_0000000c + 0xb378) != fVar4) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb370) + 4))
                (in_stack_0000000c + 0xb370,in_stack_0000000c + 0xb378,uVar5);
      *(float *)(in_stack_0000000c + 0xb378) = fVar4;
    }
    if (*(int *)(in_stack_0000000c + 0xb374) != 0x40400000) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb370) + 4))
                (in_stack_0000000c + 0xb370,in_stack_0000000c + 0xb374);
      *(undefined4 *)(in_stack_0000000c + 0xb374) = 0x40400000;
    }
    fVar3 = (float10)CountdownTimer::Now();
    fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x184a31 /* typeinfo name for IServerBenchmark+0x13 */);
    this_01 = extraout_ECX;
    if (*(float *)(in_stack_0000000c + 0xb384) != fVar4) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb384);
      *(float *)(in_stack_0000000c + 0xb384) = fVar4;
      this_01 = extraout_ECX_00;
    }
    if (*(int *)(in_stack_0000000c + 0xb380) != 0x40400000) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb380);
      *(undefined4 *)(in_stack_0000000c + 0xb380) = 0x40400000;
      this_01 = extraout_ECX_01;
    }
    uVar5 = 0x40a00000;
    CINSNextBot::ChooseBestWeapon(this_01,in_stack_0000000c,fVar1);
    piVar2 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c,fVar1,uVar5);
    fVar1 = *(float *)(unaff_EBX + 0x1f2889 /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x54 */);
    local_24 = *(float *)(param_2 + 0x3c) * fVar1 + *(float *)(param_2 + 0x48);
    local_20 = *(float *)(param_2 + 0x40) * fVar1 + *(float *)(param_2 + 0x4c);
    local_28 = fVar1 * *(float *)(param_2 + 0x38) + *(float *)(param_2 + 0x44);
    (**(code **)(*piVar2 + 0xd4))
              (piVar2,&local_28,5,0x40a00000,unaff_EBX + 0x4d8d1d /* grenadeThrowReply */,&UNK_0024dae5 + unaff_EBX);
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = (float)fVar3 + *(float *)(unaff_EBX + 0x1f0221 /* typeinfo name for CBaseGameSystem+0x32 */);
    if (*(float *)(in_stack_0000000c + 0xb390) != fVar1) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb388) + 4))
                (in_stack_0000000c + 0xb388,in_stack_0000000c + 0xb390);
      *(float *)(in_stack_0000000c + 0xb390) = fVar1;
    }
    if (*(int *)(in_stack_0000000c + 0xb38c) != 0x40a00000) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb388) + 4))
                (in_stack_0000000c + 0xb388,in_stack_0000000c + 0xb38c);
      *(undefined4 *)(in_stack_0000000c + 0xb38c) = 0x40a00000;
    }
    *(undefined4 *)(in_stack_0000000c + 0xb344) = 0x41200000;
    *(undefined4 *)(param_2 + 0x68) = *(undefined4 *)(**(int **)(unaff_EBX + 0x472355 /* &gpGlobals */) + 0xc);
    if (*(int *)(param_2 + 100) != -0x40800000) {
      (**(code **)(*(int *)(param_2 + 0x5c) + 4))(param_2 + 0x5c,param_2 + 100);
      *(undefined4 *)(param_2 + 100) = 0xbf800000;
    }
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = (float)fVar3 + *(float *)(unaff_EBX + 0x1f0221 /* typeinfo name for CBaseGameSystem+0x32 */);
    if (*(float *)(param_2 + 0x58) != fVar1) {
      (**(code **)(*(int *)(param_2 + 0x50) + 4))(param_2 + 0x50,param_2 + 0x58);
      *(float *)(param_2 + 0x58) = fVar1;
    }
    if (*(int *)(param_2 + 0x54) != 0x40a00000) {
      (**(code **)(*(int *)(param_2 + 0x50) + 4))(param_2 + 0x50,param_2 + 0x54);
      *(undefined4 *)(param_2 + 0x54) = 0x40a00000;
    }
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x24caad /* "No grenade...
" */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::Update
 * Address: 007348f0
 * ---------------------------------------- */

/* CINSBotThrowGrenade::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotThrowGrenade::Update(CINSBotThrowGrenade *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int *piVar3;
  CINSWeapon *this_00;
  float *pfVar4;
  CINSPlayer *this_01;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSNextBot *this_04;
  CINSWeapon *extraout_ECX;
  CountdownTimer *this_05;
  CountdownTimer *this_06;
  CINSNextBot *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  CINSWeapon *in_stack_0000000c;
  int *piVar9;
  undefined4 uVar10;
  
  __i686_get_pc_thunk_bx();
  uVar10 = 0;
  piVar9 = (int *)0x3;
  piVar2 = (int *)CINSPlayer::GetWeaponInSlot(this_01,(int)in_stack_0000000c,true);
  piVar3 = (int *)CINSPlayer::GetActiveINSWeapon();
  if ((piVar2 == (int *)0x0) || (piVar3 == (int *)0x0)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24c6fa /* "No grenade...
" */;
  }
  else {
    fVar5 = (float10)CountdownTimer::Now();
    if ((float)fVar5 < *(float *)((int)param_2 + 0x58) ||
        (float)fVar5 == *(float *)((int)param_2 + 0x58)) {
      cVar1 = CINSNextBot::IsIdle(this_02);
      this_04 = this_03;
      if ((cVar1 == '\0') ||
         (fVar5 = (float10)CINSNextBot::GetIdleDuration(this_03), this_04 = extraout_ECX_00,
         (float)fVar5 < *(float *)(&DAT_001efe6e + unaff_EBX) ||
         (float)fVar5 == *(float *)(&DAT_001efe6e + unaff_EBX))) {
        if (*(int *)(in_stack_0000000c + 0x2280) == 3) {
          *(undefined4 *)param_1 = 3;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x24d6e8 /* "Error aiming grenade." */;
        }
        else {
          if (*(float *)((int)param_2 + 100) <= 0.0) {
            if (piVar2 != piVar3) {
              uVar10 = 0x40a00000;
              CINSNextBot::ChooseBestWeapon(this_04,in_stack_0000000c,(float)piVar2);
              piVar9 = piVar2;
            }
            this_00 = (CINSWeapon *)
                      (**(code **)(*(int *)in_stack_0000000c + 0x96c))
                                (in_stack_0000000c,piVar9,uVar10);
            if ((this_00 != (CINSWeapon *)0x0) &&
               (pfVar4 = (float *)(**(code **)(*(int *)this_00 + 0x148))(this_00),
               fVar8 = *pfVar4 - *(float *)((int)param_2 + 0x44),
               fVar6 = pfVar4[1] - *(float *)((int)param_2 + 0x48),
               fVar7 = pfVar4[2] - *(float *)((int)param_2 + 0x4c),
               SQRT(fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7) <
               *(float *)(unaff_EBX + 0x1f22a2 /* typeinfo name for CEntityFactory<CFuncLadder>+0x20 */))) {
              (**(code **)(*(int *)this_00 + 200))(this_00,(int)param_2 + 0x44,0x3f800000);
              this_00 = extraout_ECX;
            }
            if (((*(int *)(in_stack_0000000c + 0x2280) == 2) &&
                (cVar1 = CINSWeapon::IsDeploying(this_00), cVar1 == '\0')) &&
               (cVar1 = (**(code **)(*piVar3 + 0x668))(piVar3), cVar1 != '\0')) {
              (**(code **)(*(int *)in_stack_0000000c + 0x8c0))(in_stack_0000000c,0x3f59999a);
              CountdownTimer::Start(this_05,(float)((int)param_2 + 0x5c));
              CountdownTimer::Start(this_06,(float)(in_stack_0000000c + 0xb388));
              *(undefined4 *)param_1 = 0;
              *(undefined4 *)(in_stack_0000000c + 0xb344) = 0x41200000;
              *(undefined4 *)(param_1 + 4) = 0;
              *(undefined4 *)(param_1 + 8) = 0;
              return param_1;
            }
          }
          else {
            piVar9 = (int *)(**(code **)(*piVar3 + 0x5dc))(piVar3);
            if (piVar9 == (int *)0x0) {
              *(undefined4 *)param_1 = 3;
              *(undefined4 *)(param_1 + 4) = 0;
              *(undefined **)(param_1 + 8) = &UNK_0024d6fe + unaff_EBX;
              return param_1;
            }
            if (((*(char *)((int)piVar9 + 0x4241) == '\0') && ((float)piVar9[0x1091] <= 0.0)) &&
               ((fVar5 = (float10)CountdownTimer::Now(),
                *(float *)((int)param_2 + 100) <= (float)fVar5 &&
                (float)fVar5 != *(float *)((int)param_2 + 100) &&
                (cVar1 = (**(code **)(*piVar9 + 0x770))(piVar9), cVar1 == '\0')))) {
              piVar9 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
              (**(code **)(*piVar9 + 0x160))(piVar9);
              *(undefined4 *)param_1 = 3;
              *(undefined4 *)(param_1 + 4) = 0;
              *(int *)(param_1 + 8) = unaff_EBX + 0x24c770 /* "Finished throw." */;
              return param_1;
            }
          }
          *(undefined4 *)param_1 = 0;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined4 *)(param_1 + 8) = 0;
        }
      }
      else {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24d6d2 /* "Idle in throw grenade" */;
      }
    }
    else {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24b993 /* "Timeout" */;
    }
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::OnEnd
 * Address: 007343e0
 * ---------------------------------------- */

/* CINSBotThrowGrenade::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotThrowGrenade::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  
  if (param_2 != (Action *)0x0) {
    piVar1 = (int *)(**(code **)(*(int *)param_2 + 0x970))(param_2);
    (**(code **)(*piVar1 + 0x160))(piVar1);
  }
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::GetName
 * Address: 00736110
 * ---------------------------------------- */

/* CINSBotThrowGrenade::GetName() const */

int CINSBotThrowGrenade::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x24be96 /* "Throwing Grenade" */;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::ShouldAttack
 * Address: 00736130
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotThrowGrenade::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotThrowGrenade::ShouldAttack(CINSBotThrowGrenade *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::ShouldAttack
 * Address: 00736140
 * ---------------------------------------- */

/* CINSBotThrowGrenade::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotThrowGrenade::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::AimForGrenadeToss
 * Address: 007352e0
 * ---------------------------------------- */

/* CINSBotThrowGrenade::AimForGrenadeToss(CINSNextBot*, Vector, Vector&) */

undefined4 __cdecl
CINSBotThrowGrenade::AimForGrenadeToss
          (Vector *param_1,float param_2,float param_3,float param_4,float *param_5)

{
  uint *puVar1;
  double dVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  CBasePlayer *extraout_ECX;
  CBasePlayer *this;
  CBasePlayer *extraout_ECX_00;
  int unaff_EBX;
  undefined4 uVar8;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  double local_6c;
  double local_64;
  float local_5c;
  float local_58;
  float local_54;
  float local_4c;
  float local_48;
  float local_44;
  Vector local_38 [12];
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7352eb;
  __i686_get_pc_thunk_bx();
  iVar3 = *(int *)(unaff_EBX + 0x471689 /* &GCSDK::GetPchTempTextBuffer */);
  this = *(CBasePlayer **)(iVar3 + 0x100c);
  local_1d = this != (CBasePlayer *)0x0;
  if (((bool)local_1d) &&
     (iVar6 = *(int *)(iVar3 + 0x19b8), iVar5 = ThreadGetCurrentId(), this = extraout_ECX,
     iVar6 == iVar5)) {
    piVar7 = *(int **)(iVar3 + 0x1014);
    if (*piVar7 != unaff_EBX + 0x24cd8d /* "CINSBotThrowGrenade::AimVectorForGrenade" */) {
      piVar7 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar7,unaff_EBX + 0x24cd8d /* "CINSBotThrowGrenade::AimVectorForGrenade" */,(char *)0x0,
                                 unaff_EBX + 0x24b97b /* "INSNextBot" */);
      *(int **)(iVar3 + 0x1014) = piVar7;
    }
    puVar1 = (uint *)(*(int *)(iVar3 + 0x10a0) + piVar7[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar3 + 0x1010) = 0;
    this = extraout_ECX_00;
  }
  if (param_1 == (Vector *)0x0) {
LAB_007356b0:
    uVar8 = 0;
  }
  else {
    CBasePlayer::EyeVectors(this,param_1,local_38,(Vector *)0x0);
    (**(code **)(*(int *)param_1 + 0x20c))(&local_5c,param_1);
    param_2 = param_2 - local_5c;
    param_3 = param_3 - local_58;
    piVar7 = (int *)(*(int **)(unaff_EBX + 0x471c5d /* &sv_gravity */))[7];
    fVar10 = SQRT(param_3 * param_3 + param_2 * param_2);
    if (piVar7 == *(int **)(unaff_EBX + 0x471c5d /* &sv_gravity */)) {
      fVar11 = (float)((uint)piVar7 ^ piVar7[0xb]);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar7 + 0x3c))(piVar7);
      fVar11 = (float)fVar9;
    }
    if (fVar10 == 0.0) goto LAB_007356b0;
    fVar11 = (float)((uint)(fVar11 * *(float *)(unaff_EBX + 0x1f1afd /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x68 */)) ^
                    *(uint *)(unaff_EBX + 0x1ef915 /* typeinfo name for CBroadcastRecipientFilter+0x44 */));
    fVar12 = fVar11 * fVar10;
    fVar10 = ((param_4 - local_54) * *(float *)(unaff_EBX + 0x24ce4d /* CSWTCH.864+0xc */) - fVar10 * fVar12) * fVar11 +
             *(float *)(unaff_EBX + 0x213c75 /* typeinfo name for CCleanupDefaultRelationShips+0x20 */);
    if (fVar10 <= 0.0) goto LAB_007356b0;
    fVar10 = SQRT(fVar10);
    fVar11 = *(float *)(unaff_EBX + 0x1f83bd /* typeinfo name for CEntityFactory<CINSRulesProxy>+0x48 */);
    fVar13 = atanf((fVar10 + fVar11) / fVar12);
    fVar12 = atanf((fVar10 - fVar11) / fVar12);
    local_44 = 0.0;
    local_4c = param_2;
    local_48 = param_3;
    VectorNormalize((Vector *)&local_4c);
    fVar11 = local_48;
    fVar10 = local_4c;
    local_2c = local_4c;
    local_28 = local_48;
    local_24 = local_44;
    sincos((double)(float)((uint)fVar13 ^ *(uint *)(unaff_EBX + 0x1ef915 /* typeinfo name for CBroadcastRecipientFilter+0x44 */)),&local_64,&local_6c);
    dVar2 = *(double *)(unaff_EBX + 0x20e1fd /* typeinfo name for ISceneTokenProcessor+0x1a */);
    local_4c = fVar10 * (float)(local_6c * dVar2);
    local_48 = (float)(local_6c * dVar2) * fVar11;
    local_44 = (float)(local_64 * dVar2);
    sincos((double)fVar12,&local_64,&local_6c);
    fVar10 = fVar10 * (float)(local_6c * dVar2);
    fVar11 = (float)(local_6c * dVar2) * fVar11;
    local_2c = fVar10;
    local_28 = fVar11;
    local_24 = (float)(dVar2 * local_64);
    cVar4 = TraceTrajectory();
    if (cVar4 != '\0') {
      uVar8 = 1;
      *param_5 = fVar10;
      param_5[1] = fVar11;
      param_5[2] = (float)(dVar2 * local_64);
      if (local_1d == '\0') {
        return 1;
      }
      goto LAB_007356b8;
    }
    cVar4 = TraceTrajectory();
    uVar8 = 0;
    if (cVar4 != '\0') {
      uVar8 = 1;
      *param_5 = local_4c;
      param_5[1] = local_48;
      param_5[2] = local_44;
    }
  }
  if (local_1d == '\0') {
    return uVar8;
  }
LAB_007356b8:
  if (((*(char *)(iVar3 + 0x1010) == '\0') || (*(int *)(iVar3 + 0x100c) != 0)) &&
     (iVar6 = *(int *)(iVar3 + 0x19b8), iVar5 = ThreadGetCurrentId(), iVar6 == iVar5)) {
    cVar4 = CVProfNode::ExitScope();
    iVar6 = *(int *)(iVar3 + 0x1014);
    if (cVar4 != '\0') {
      iVar6 = *(int *)(iVar6 + 100);
      *(int *)(iVar3 + 0x1014) = iVar6;
    }
    *(bool *)(iVar3 + 0x1010) = iVar6 == iVar3 + 0x1018;
    return uVar8;
  }
  return uVar8;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::CanIThrowGrenade
 * Address: 00735830
 * ---------------------------------------- */

/* CINSBotThrowGrenade::CanIThrowGrenade(CINSNextBot*, Vector&) */

undefined4 __cdecl CINSBotThrowGrenade::CanIThrowGrenade(CINSNextBot *param_1,Vector *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint *puVar5;
  int *piVar6;
  char cVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  float fVar11;
  CINSPlayer *this;
  CINSRules *this_00;
  CBaseEntity *extraout_ECX;
  CINSRules *this_01;
  CINSNextBotManager *this_02;
  CTraceFilterSimple *this_03;
  CTraceFilterSimple *extraout_ECX_00;
  CTraceFilterSimple *extraout_ECX_01;
  undefined4 uVar12;
  int unaff_EBX;
  float10 fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  undefined4 uVar18;
  float local_148;
  float local_144;
  int local_140;
  uint local_13c;
  int local_124;
  float local_120;
  int local_10c;
  float local_104;
  float local_100;
  Vector local_fc [12];
  Vector local_f0 [64];
  undefined4 local_b0;
  float local_9c;
  float local_98;
  float local_94;
  float local_8c;
  float local_88;
  undefined4 local_84;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_5c;
  undefined1 local_58;
  undefined1 local_57;
  int local_48 [4];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x73583b;
  __i686_get_pc_thunk_bx();
  iVar4 = *(int *)(unaff_EBX + 0x471139 /* &GCSDK::GetPchTempTextBuffer */);
  local_1d = *(int *)(iVar4 + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar10 = *(int *)(iVar4 + 0x19b8), iVar8 = ThreadGetCurrentId(), iVar10 == iVar8)) {
    piVar9 = *(int **)(iVar4 + 0x1014);
    if (*piVar9 != unaff_EBX + 0x24c869 /* "CINSBotThrowGrenade::CanThrowGrenade" */) {
      piVar9 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar9,unaff_EBX + 0x24c869 /* "CINSBotThrowGrenade::CanThrowGrenade" */,(char *)0x0,
                                 unaff_EBX + 0x24b42b /* "INSNextBot" */);
      *(int **)(iVar4 + 0x1014) = piVar9;
    }
    puVar5 = (uint *)(*(int *)(iVar4 + 0x10a0) + piVar9[0x1c] * 8 + 4);
    *puVar5 = *puVar5 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar4 + 0x1010) = 0;
  }
  if (param_1 != (CINSNextBot *)0x0) {
    fVar13 = (float10)CountdownTimer::Now();
    uVar12 = 0;
    if ((float)fVar13 < *(float *)(param_1 + 0xb378) ||
        (float)fVar13 == *(float *)(param_1 + 0xb378)) goto LAB_007358ae;
    uVar18 = 0;
    uVar12 = 3;
    piVar9 = (int *)CINSPlayer::GetWeaponInSlot(this,(int)param_1,true);
    if (((piVar9 != (int *)0x0) &&
        (cVar7 = (**(code **)(*piVar9 + 0x410))(piVar9,uVar12,uVar18), cVar7 != '\0')) &&
       ((iVar10 = (**(code **)(*piVar9 + 0x5f0))(piVar9), iVar10 == 2 ||
        (((iVar10 == 5 || (iVar10 == 4)) || (iVar10 == 3)))))) {
      this_01 = this_00;
      if (**(int **)(unaff_EBX + 0x4710bd /* &g_pGameRules */) != 0) {
        cVar7 = CINSRules::IsTraining(this_00);
        uVar12 = 0;
        this_01 = (CINSRules *)extraout_ECX;
        if (cVar7 != '\0') goto LAB_007358ae;
      }
      CBaseEntity::GetTeamNumber((CBaseEntity *)this_01);
      iVar8 = TheINSNextBots();
      piVar9 = (int *)CINSNextBotManager::GetGrenadeTargets(this_02,iVar8);
      if ((piVar9 != (int *)0x0) && (0 < piVar9[3])) {
        (**(code **)(*(int *)param_1 + 0x20c))(&local_38,param_1);
        local_13c = 1;
        if (iVar10 - 3U < 3) {
          local_13c = *(uint *)(unaff_EBX + 0x24c8f1 /* CSWTCH.864 */ + (iVar10 - 3U) * 4);
        }
        if (0 < piVar9[3]) {
          local_10c = 0;
          do {
            puVar5 = *(uint **)(*piVar9 + local_10c * 4);
            if (((puVar5 != (uint *)0x0) && (local_13c == (local_13c & *puVar5))) &&
               ((*(char *)((int)puVar5 + 0x1d) == '\0' && ((char)puVar5[7] != '\0')))) {
              fVar1 = (float)puVar5[4];
              fVar2 = (float)puVar5[5];
              fVar15 = (float)puVar5[6];
              fVar3 = (float)puVar5[8];
              fVar17 = fVar1 - local_38;
              fVar14 = fVar2 - local_34;
              piVar6 = *(int **)(unaff_EBX + 0x5b7621 /* ins_bot_max_grenade_range+0x1c */);
              fVar16 = fVar15 - local_30;
              if (piVar6 == (int *)(unaff_EBX + 0x5b7605 /* ins_bot_max_grenade_range */U)) {
                fVar11 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x5b7631 /* ins_bot_max_grenade_range+0x2c */));
              }
              else {
                fVar13 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
                fVar11 = (float)fVar13;
              }
              if (SQRT(fVar14 * fVar14 + fVar17 * fVar17 + fVar16 * fVar16) <= fVar11 + fVar3) {
                this_03 = (CTraceFilterSimple *)(unaff_EBX + 0x1f2af9 /* typeinfo name for IPartitionEnumerator+0x21 */);
                local_144 = *(float *)(unaff_EBX + 0x1832d9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */);
                local_b0 = 0;
                local_148 = 0.0;
                fVar15 = *(float *)this_03 + fVar15;
                local_140 = 0;
                do {
                  local_124 = 3;
                  local_120 = 0.0;
                  do {
                    fVar14 = local_120 * fVar3;
                    fVar16 = local_144 * fVar14 + fVar1;
                    fVar14 = fVar14 * local_148 + fVar2;
                    local_2c = fVar16;
                    local_28 = fVar14;
                    local_24 = fVar15;
                    CTraceFilterSimple::CTraceFilterSimple
                              (this_03,(IHandleEntity *)local_48,(int)param_1,
                               (_func_bool_IHandleEntity_ptr_int *)0x0);
                    local_58 = 1;
                    local_5c = 0;
                    local_84 = 0;
                    local_8c = fVar16 - fVar1;
                    local_88 = fVar14 - fVar2;
                    local_48[0] = *(int *)(unaff_EBX + 0x470d2d /* &vtable for CTraceFilterNoNPCsOrPlayer */) + 8;
                    local_64 = 0;
                    local_68 = 0;
                    local_6c = 0;
                    local_57 = local_88 * local_88 + local_8c * local_8c != 0.0;
                    local_74 = 0;
                    local_78 = 0;
                    local_7c = 0;
                    local_9c = fVar1;
                    local_98 = fVar2;
                    local_94 = fVar15;
                    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x470f3d /* &enginetrace */) + 0x14))
                              ((int *)**(undefined4 **)(unaff_EBX + 0x470f3d /* &enginetrace */),&local_9c,0x42006089,
                               local_48,local_fc);
                    iVar10 = (**(code **)(**(int **)(unaff_EBX + 0x471205 /* &r_visualizetraces */) + 0x40))
                                       (*(int **)(unaff_EBX + 0x471205 /* &r_visualizetraces */));
                    if (iVar10 != 0) {
                      iVar10 = (**(code **)(**(int **)(unaff_EBX + 0x471205 /* &r_visualizetraces */) + 0x40))
                                         (*(int **)(unaff_EBX + 0x471205 /* &r_visualizetraces */));
                      fVar14 = 0.5;
                      if (iVar10 != 0) {
                        fVar14 = -1.0;
                      }
                      DebugDrawLine(local_fc,local_f0,0xff,0,0,true,fVar14);
                    }
                    cVar7 = CGameTrace::DidHitWorld();
                    if (cVar7 != '\0') break;
                    cVar7 = AimForGrenadeToss(param_1,local_2c,local_28,local_24,param_2);
                    if (cVar7 != '\0') {
                      uVar12 = 1;
                      *(undefined1 *)((int)puVar5 + 0x1d) = 1;
                      goto LAB_007358ae;
                    }
                    local_124 = local_124 + -1;
                    local_120 = local_120 + *(float *)(unaff_EBX + 0x1eef1d /* typeinfo name for CBaseGameSystem+0x1e */);
                    this_03 = extraout_ECX_00;
                  } while (local_124 != 0);
                  local_140 = local_140 + 0x1e;
                  if (local_140 == 0x168) break;
                  sincosf((float)local_140 * *(float *)(unaff_EBX + 0x1eff95 /* typeinfo name for IPlayerAnimState+0x27 */),&local_100,&local_104)
                  ;
                  local_148 = local_100;
                  local_144 = local_104;
                  this_03 = extraout_ECX_01;
                } while( true );
              }
            }
            local_10c = local_10c + 1;
          } while (local_10c < piVar9[3]);
        }
      }
    }
  }
  uVar12 = 0;
LAB_007358ae:
  if ((local_1d != '\0') &&
     (((*(char *)(iVar4 + 0x1010) == '\0' || (*(int *)(iVar4 + 0x100c) != 0)) &&
      (iVar10 = *(int *)(iVar4 + 0x19b8), iVar8 = ThreadGetCurrentId(), iVar10 == iVar8)))) {
    cVar7 = CVProfNode::ExitScope();
    iVar10 = *(int *)(iVar4 + 0x1014);
    if (cVar7 != '\0') {
      iVar10 = *(int *)(iVar10 + 100);
      *(int *)(iVar4 + 0x1014) = iVar10;
    }
    *(bool *)(iVar4 + 0x1010) = iVar10 == iVar4 + 0x1018;
    return uVar12;
  }
  return uVar12;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::ShouldWalk
 * Address: 00736150
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotThrowGrenade::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotThrowGrenade::ShouldWalk(CINSBotThrowGrenade *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::ShouldWalk
 * Address: 00736160
 * ---------------------------------------- */

/* CINSBotThrowGrenade::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotThrowGrenade::ShouldWalk(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::TraceTrajectory
 * Address: 00734e50
 * ---------------------------------------- */

/* CINSBotThrowGrenade::TraceTrajectory(CINSNextBot*, Vector, Vector, Vector, float) */

bool __cdecl
CINSBotThrowGrenade::TraceTrajectory
          (int param_1,float param_2,float param_3,float param_4,float param_5,float param_6,
          float param_7,float param_8,float param_9,float param_10,float param_11)

{
  uint *puVar1;
  double dVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  CTraceFilterSimple *extraout_ECX;
  CTraceFilterSimple *extraout_ECX_00;
  CTraceFilterSimple *this;
  float fVar6;
  int unaff_EBX;
  bool bVar7;
  int iVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  Vector local_ec [12];
  float local_e0;
  float local_dc;
  float local_d8;
  float local_c0;
  undefined4 local_a0;
  float local_8c;
  float local_88;
  float local_84;
  float local_7c;
  float local_78;
  float local_74;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_4c;
  undefined1 local_48;
  undefined1 local_47;
  int local_3c [7];
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x734e5b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  this = extraout_ECX;
  if (((bool)local_1d) &&
     (iVar8 = *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
     this = extraout_ECX_00, iVar8 == iVar4)) {
    piVar5 = *(int **)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar5 != unaff_EBX + 0x24d1f5 /* "CINSBotThrowGrenade::TraceTrajectory" */) {
      piVar5 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar5,unaff_EBX + 0x24d1f5 /* "CINSBotThrowGrenade::TraceTrajectory" */,(char *)0x0,
                                 unaff_EBX + 0x24be0b /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar5;
    }
    puVar1 = (uint *)(piVar5[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    this = *(CTraceFilterSimple **)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */);
    this[0x1010] = (CTraceFilterSimple)0x0;
  }
  local_a0 = 0;
  CTraceFilterSimple::CTraceFilterSimple
            (this,(IHandleEntity *)local_3c,param_1,(_func_bool_IHandleEntity_ptr_int *)0x0);
  iVar8 = 0;
  dVar2 = *(double *)(unaff_EBX + 0x183ce5 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x60 */);
  local_3c[0] = *(int *)(unaff_EBX + 0x47170d /* &vtable for CTraceFilterNoNPCsOrPlayer */) + 8;
  piVar5 = *(int **)(unaff_EBX + 0x471be5 /* &r_visualizetraces */);
  fVar6 = param_4;
  fVar12 = param_3;
  fVar13 = param_2;
  while( true ) {
    iVar8 = iVar8 + 1;
    local_48 = 0;
    local_4c = 0;
    local_5c = 0x40400000;
    local_58 = 0x40400000;
    fVar11 = (float)iVar8 * *(float *)(unaff_EBX + 0x1efd89 /* typeinfo name for CBroadcastRecipientFilter+0x28 */);
    local_54 = 0x40400000;
    local_6c = 0x80000000;
    local_68 = 0x80000000;
    local_64 = 0x80000000;
    fVar9 = param_8 * fVar11 + param_2;
    local_7c = fVar9 - fVar13;
    fVar10 = param_9 * fVar11 + param_3;
    fVar11 = (float)((double)fVar11 * (double)fVar11 * (double)param_11 * dVar2 +
                    (double)(fVar11 * param_10 + param_4));
    local_78 = fVar10 - fVar12;
    local_74 = fVar11 - fVar6;
    local_47 = local_78 * local_78 + local_7c * local_7c + local_74 * local_74 != 0.0;
    local_8c = fVar13;
    local_88 = fVar12;
    local_84 = fVar6;
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47191d /* &enginetrace */) + 0x14))
              ((int *)**(undefined4 **)(unaff_EBX + 0x47191d /* &enginetrace */),&local_8c,0x42006089,local_3c,local_ec
              );
    iVar4 = (**(code **)(*piVar5 + 0x40))(piVar5);
    if (iVar4 != 0) {
      iVar4 = (**(code **)(*piVar5 + 0x40))(piVar5);
      fVar6 = 0.5;
      if (iVar4 != 0) {
        fVar6 = -1.0;
      }
      DebugDrawLine(local_ec,(Vector *)&local_e0,0xff,0xff,0,true,fVar6);
    }
    if (local_c0 < *(float *)(unaff_EBX + 0x183cb9 /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x34 */)) break;
    fVar6 = fVar11;
    fVar12 = fVar10;
    fVar13 = fVar9;
    if (iVar8 == 0x14) {
      bVar7 = false;
LAB_00735152:
      if ((local_1d != '\0') &&
         (((*(char *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
           (*(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
          (iVar8 = *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar4 = ThreadGetCurrentId(),
          iVar8 == iVar4)))) {
        cVar3 = CVProfNode::ExitScope();
        iVar8 = *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
        if (cVar3 != '\0') {
          iVar8 = *(int *)(iVar8 + 100);
          *(int *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar8;
        }
        *(bool *)(*(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
             iVar8 == *(int *)(unaff_EBX + 0x471b19 /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
        return bVar7;
      }
      return bVar7;
    }
  }
  bVar7 = SQRT((local_dc - param_6) * (local_dc - param_6) +
               (local_e0 - param_5) * (local_e0 - param_5) +
               (local_d8 - param_7) * (local_d8 - param_7)) < *(float *)(unaff_EBX + 0x1f0961 /* typeinfo name for IPlayerAnimState+0x13 */);
  goto LAB_00735152;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::~CINSBotThrowGrenade
 * Address: 00734410
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotThrowGrenade::~CINSBotThrowGrenade() */

void __thiscall CINSBotThrowGrenade::~CINSBotThrowGrenade(CINSBotThrowGrenade *this)

{
  ~CINSBotThrowGrenade(this);
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::~CINSBotThrowGrenade
 * Address: 00734420
 * ---------------------------------------- */

/* CINSBotThrowGrenade::~CINSBotThrowGrenade() */

void __thiscall CINSBotThrowGrenade::~CINSBotThrowGrenade(CINSBotThrowGrenade *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4648a3 /* vtable for CINSBotThrowGrenade+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_00464a3b + extraout_ECX);
  Action<CINSNextBot>::~Action
            ((Action<CINSNextBot> *)(CBreakableSurface::DropPane + extraout_ECX + 3));
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::~CINSBotThrowGrenade
 * Address: 00734450
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotThrowGrenade::~CINSBotThrowGrenade() */

void __thiscall CINSBotThrowGrenade::~CINSBotThrowGrenade(CINSBotThrowGrenade *this)

{
  ~CINSBotThrowGrenade(this);
  return;
}



/* ----------------------------------------
 * CINSBotThrowGrenade::~CINSBotThrowGrenade
 * Address: 00734460
 * ---------------------------------------- */

/* CINSBotThrowGrenade::~CINSBotThrowGrenade() */

void __thiscall CINSBotThrowGrenade::~CINSBotThrowGrenade(CINSBotThrowGrenade *this)

{
  CINSBotThrowGrenade *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSBotThrowGrenade(this_00);
  operator_delete(in_stack_00000004);
  return;
}



