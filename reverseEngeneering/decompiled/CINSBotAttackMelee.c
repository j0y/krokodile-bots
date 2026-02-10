/*
 * CINSBotAttackMelee -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 42
 */

/* ----------------------------------------
 * CINSBotAttackMelee::CINSBotAttackMelee
 * Address: 0070f240
 * ---------------------------------------- */

/* CINSBotAttackMelee::CINSBotAttackMelee() */

void __thiscall CINSBotAttackMelee::CINSBotAttackMelee(CINSBotAttackMelee *this)

{
  int *piVar1;
  CINSPathFollower *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  piVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x4865dd /* vtable for CINSBotAttackMelee+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_00486785 + unaff_EBX);
  in_stack_00000004[0xe] = unaff_EBX + 0x418f6d /* vtable for CountdownTimer+0x8 */;
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
  in_stack_00000004[0xf] = 0;
  CountdownTimer::NetworkStateChanged(piVar1);
  in_stack_00000004[0x10] = -0x40800000;
  (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
  CINSPathFollower::CINSPathFollower(this_00);
  if (in_stack_00000004[0x10] != -0x40800000) {
    (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = -0x40800000;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnStart
 * Address: 0070ea10
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackMelee::OnStart(CINSBotAttackMelee *this,CINSNextBot *param_1,Action *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x497eda /* &g_pGameRules */) == 0) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27145e /* "INSRules failed to initialize." */;
  }
  else {
    fVar3 = (float10)CountdownTimer::Now();
    fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x215d4e /* typeinfo name for CBaseGameSystem+0x32 */);
    if (*(float *)(in_stack_0000000c + 0xb384) != fVar4) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb384);
      *(float *)(in_stack_0000000c + 0xb384) = fVar4;
    }
    if (*(int *)(in_stack_0000000c + 0xb380) != 0x40a00000) {
      (**(code **)(*(int *)(in_stack_0000000c + 0xb37c) + 4))
                (in_stack_0000000c + 0xb37c,in_stack_0000000c + 0xb380);
      *(undefined4 *)(in_stack_0000000c + 0xb380) = 0x40a00000;
    }
    puVar1 = *(undefined4 **)(unaff_EBX + 0x497bae /* &vec3_origin */);
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_2 + 0x44) = *puVar1;
    uVar2 = puVar1[2];
    *(undefined4 *)(param_2 + 0x48) = puVar1[1];
    *(undefined4 *)(param_2 + 0x4c) = uVar2;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackMelee::Update
 * Address: 0070eb30
 * ---------------------------------------- */

/* CINSBotAttackMelee::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackMelee::Update(CINSBotAttackMelee *this,CINSNextBot *param_1,float param_2)

{
  int *piVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  CINSNextBot *pCVar6;
  CINSNextBot *this_00;
  float *pfVar7;
  int iVar8;
  CINSPlayer *this_01;
  CINSNextBot *this_02;
  CBaseEntity *this_03;
  CINSNextBot *extraout_ECX;
  CBaseEntity *this_04;
  int *extraout_EDX;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  float local_38;
  float local_2c;
  float local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*extraout_EDX + 0x974 /* CINSBotAttackPistol::ShouldHurry */))(extraout_EDX);
  piVar3 = (int *)(**(code **)(*piVar3 + 0xd0))(piVar3,0);
  if (((piVar3 != (int *)0x0) && (iVar4 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar4 != 0)) &&
     (cVar2 = (**(code **)(*piVar3 + 0x54))(piVar3), cVar2 == '\0')) {
    piVar5 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3);
    if ((piVar5 != (int *)0x0) && (cVar2 = (**(code **)(*piVar5 + 0x158))(piVar5), cVar2 != '\0')) {
      if (in_stack_0000000c[0x1864] == (CINSWeapon)0x0) {
        pCVar6 = (CINSNextBot *)CINSPlayer::GetActiveINSWeapon();
        uVar12 = 0;
        uVar11 = 2;
        this_00 = (CINSNextBot *)CINSPlayer::GetWeaponInSlot(this_01,(int)in_stack_0000000c,true);
        if (pCVar6 == this_00) {
          uVar11 = (**(code **)(*piVar3 + 0x10))(piVar3,uVar11,uVar12);
          CINSNextBot::UpdateChasePath(this_02,(CBaseEntity *)in_stack_0000000c);
          fVar9 = (float10)CountdownTimer::Now();
          if (*(float *)((int)param_2 + 0x40) <= (float)fVar9 &&
              (float)fVar9 != *(float *)((int)param_2 + 0x40)) {
            pfVar7 = (float *)(**(code **)(*piVar3 + 0x14))(piVar3,uVar11);
            local_2c = *pfVar7;
            local_28 = pfVar7[1];
            piVar5 = *(int **)(unaff_EBX + 0x497edb /* &ins_bot_knives_only_sprint_range */);
            local_24 = pfVar7[2];
            piVar1 = (int *)piVar5[7];
            if (piVar1 == piVar5) {
              fVar10 = (float)(piVar5[0xb] ^ (uint)piVar5);
            }
            else {
              fVar9 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
              fVar10 = (float)fVar9;
            }
            if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
            }
            if ((*(float *)(in_stack_0000000c + 0x20c) - local_28) *
                (*(float *)(in_stack_0000000c + 0x20c) - local_28) +
                (*(float *)(in_stack_0000000c + 0x208) - local_2c) *
                (*(float *)(in_stack_0000000c + 0x208) - local_2c) +
                (*(float *)(in_stack_0000000c + 0x210) - local_24) *
                (*(float *)(in_stack_0000000c + 0x210) - local_24) <= fVar10 * fVar10) {
              (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
              uVar13 = 0x3f19999a;
              uVar12 = 7;
              iVar4 = unaff_EBX + 0x2719ae /* "Jog at Target" */;
              uVar11 = 0xc;
              CINSBotBody::SetPosture();
            }
            else {
              (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
              uVar13 = 0x3f19999a;
              uVar12 = 7;
              iVar4 = unaff_EBX + 0x27199d /* "Sprint at Target" */;
              uVar11 = 0xd;
              CINSBotBody::SetPosture();
            }
            iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x497dd7 /* &ins_bot_knives_only_enable_slide */) + 0x40))
                              (*(int **)(unaff_EBX + 0x497dd7 /* &ins_bot_knives_only_enable_slide */),uVar11,uVar12,uVar13,iVar4);
            local_38 = *(float *)(&DAT_00215c17 + unaff_EBX);
            if ((iVar8 != 0) &&
               (cVar2 = CINSPlayer::IsSprinting((CINSPlayer *)this_00), cVar2 != '\0')) {
              uVar12 = 0x3f666666;
              cVar2 = (**(code **)(*(int *)in_stack_0000000c + 0x434))
                                (in_stack_0000000c,&local_2c,0x3f666666);
              if (cVar2 != '\0') {
                fVar9 = (float10)ConVar::GetFloat((ConVar *)this_00);
                fVar10 = (float)fVar9 + *(float *)(unaff_EBX + 0x21a687 /* typeinfo name for CTraceFilterIgnoreWeapons+0x3d */);
                if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
                  CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
                }
                if ((*(float *)(in_stack_0000000c + 0x20c) - local_28) *
                    (*(float *)(in_stack_0000000c + 0x20c) - local_28) +
                    (*(float *)(in_stack_0000000c + 0x208) - local_2c) *
                    (*(float *)(in_stack_0000000c + 0x208) - local_2c) +
                    (*(float *)(in_stack_0000000c + 0x210) - local_24) *
                    (*(float *)(in_stack_0000000c + 0x210) - local_24) < fVar10 * fVar10) {
                  fVar9 = (float10)RandomFloat(0,0x3f800000);
                  local_38 = *(float *)(&DAT_00215c17 + unaff_EBX);
                  if ((float)fVar9 < local_38) {
                    (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
                    uVar13 = 0x40400000;
                    uVar12 = 8;
                    iVar4 = unaff_EBX + 0x2719bc /* "Slide like a G" */;
                    CINSBotBody::SetPosture();
                  }
                }
                else {
                  local_38 = *(float *)(&DAT_00215c17 + unaff_EBX);
                }
              }
            }
            fVar9 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
            if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_00);
            }
            if ((*(float *)(in_stack_0000000c + 0x20c) - local_28) *
                (*(float *)(in_stack_0000000c + 0x20c) - local_28) +
                (*(float *)(in_stack_0000000c + 0x208) - local_2c) *
                (*(float *)(in_stack_0000000c + 0x208) - local_2c) +
                (*(float *)(in_stack_0000000c + 0x210) - local_24) *
                (*(float *)(in_stack_0000000c + 0x210) - local_24) < (float)fVar9 * (float)fVar9) {
              fVar9 = (float10)RandomFloat(0,0x3f800000,uVar12,uVar13,iVar4);
              if ((float)fVar9 <= local_38) {
                (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
                uVar13 = 0x40a00000;
                uVar12 = 7;
                iVar4 = unaff_EBX + 0x24af3a /* typeinfo name for CGlobalState+0x5c */;
                CINSBotBody::SetPosture();
              }
              else {
                (**(code **)(*(int *)in_stack_0000000c + 0x970))();
                uVar13 = 0x40a00000;
                uVar12 = 7;
                iVar4 = unaff_EBX + 0x24af3a /* typeinfo name for CGlobalState+0x5c */;
                CINSBotBody::SetPosture();
              }
            }
            fVar9 = (float10)CountdownTimer::Now();
            if (*(float *)((int)param_2 + 0x40) != (float)fVar9 + local_38) {
              (**(code **)(*(int *)((int)param_2 + 0x38) + 4))
                        ((int)param_2 + 0x38,(int)param_2 + 0x40,uVar12,uVar13,iVar4);
              *(float *)((int)param_2 + 0x40) = (float)fVar9 + local_38;
            }
            if (*(int *)((int)param_2 + 0x3c) != 0x3f000000) {
              (**(code **)(*(int *)((int)param_2 + 0x38) + 4))
                        ((int)param_2 + 0x38,(int)param_2 + 0x3c);
              *(undefined4 *)((int)param_2 + 0x3c) = 0x3f000000;
            }
          }
          fVar9 = (float10)CINSNextBot::GetMaxAttackRange(this_00,in_stack_0000000c);
          pfVar7 = (float *)(**(code **)(*piVar3 + 0x14))(piVar3,this_00);
          this_04 = this_03;
          if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition(this_03);
            this_04 = (CBaseEntity *)extraout_ECX;
          }
          if ((*(float *)(in_stack_0000000c + 0x20c) - pfVar7[1]) *
              (*(float *)(in_stack_0000000c + 0x20c) - pfVar7[1]) +
              (*(float *)(in_stack_0000000c + 0x208) - *pfVar7) *
              (*(float *)(in_stack_0000000c + 0x208) - *pfVar7) +
              (*(float *)(in_stack_0000000c + 0x210) - pfVar7[2]) *
              (*(float *)(in_stack_0000000c + 0x210) - pfVar7[2]) < (float)fVar9 * (float)fVar9) {
            CINSNextBot::FireWeaponAtEnemy((CINSNextBot *)this_04);
          }
        }
        else {
          CINSNextBot::ChooseBestWeapon(this_00,in_stack_0000000c,(float)this_00);
        }
      }
      *(undefined4 *)param_1 = 0;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x271810 /* "Non INS Player Enemy?" */;
    return param_1;
  }
  *(undefined4 *)param_1 = 3;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x27198c /* "Lost our threat." */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnEnd
 * Address: 0070e440
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackMelee::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(param_2 + 0xb384) != -0x40800000) {
    (**(code **)(*(int *)(param_2 + 0xb37c) + 4))(param_2 + 0xb37c,param_2 + 0xb384);
    *(undefined4 *)(param_2 + 0xb384) = 0xbf800000;
  }
  *(undefined4 *)(param_2 + 0xb338) = 0xffffffff;
  *(undefined4 *)(param_2 + 0xb33c) = *(undefined4 *)(**(int **)(unaff_EBX + 0x49844c /* &gpGlobals */) + 0xc);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::GetName
 * Address: 0070f360
 * ---------------------------------------- */

/* CINSBotAttackMelee::GetName() const */

int CINSBotAttackMelee::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x27115c /* "AttackMelee" */;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldHurry
 * Address: 0070e4c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackMelee::ShouldHurry(CINSBotAttackMelee *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldHurry
 * Address: 0070e4d0
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldRetreat
 * Address: 0070e4e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackMelee::ShouldRetreat(CINSBotAttackMelee *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldRetreat
 * Address: 0070e4f0
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldRetreat(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldAttack
 * Address: 0070e500
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotAttackMelee::ShouldAttack(CINSBotAttackMelee *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldAttack
 * Address: 0070e510
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnContact
 * Address: 0070e580
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackMelee::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnMoveToSuccess
 * Address: 0070e5b0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackMelee::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnMoveToFailure
 * Address: 0070e5e0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackMelee::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnStuck
 * Address: 0070e610
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnStuck(CINSNextBot*) */

void CINSBotAttackMelee::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnUnStuck
 * Address: 0070e640
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnUnStuck(CINSNextBot*) */

void CINSBotAttackMelee::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnInjured
 * Address: 0070e6a0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackMelee::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnKilled
 * Address: 0070e6d0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackMelee::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnOtherKilled
 * Address: 0070e700
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotAttackMelee::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnSight
 * Address: 0070e730
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackMelee::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnLostSight
 * Address: 0070e760
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackMelee::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnWeaponFired
 * Address: 0070e790
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackMelee::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnCommandApproach
 * Address: 0070e820
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackMelee::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnCommandApproach
 * Address: 0070e850
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackMelee::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnCommandString
 * Address: 0070e8b0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackMelee::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnBlinded
 * Address: 0070e8e0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackMelee::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnCommandAttack
 * Address: 0070e7f0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackMelee::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnCommandRetreat
 * Address: 0070e880
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackMelee::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnHeardFootsteps
 * Address: 0070e910
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackMelee::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnNavAreaChanged
 * Address: 0070e7c0
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackMelee::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnPostureChanged
 * Address: 0070e670
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackMelee::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::OnSeeSomethingSuspicious
 * Address: 0070e940
 * ---------------------------------------- */

/* CINSBotAttackMelee::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void CINSBotAttackMelee::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldIronsight
 * Address: 0070e540
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackMelee::ShouldIronsight(CINSBotAttackMelee *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldIronsight
 * Address: 0070e550
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldIronsight(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldProne
 * Address: 0070e560
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackMelee::ShouldProne(CINSBotAttackMelee *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldProne
 * Address: 0070e570
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldProne(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldWalk
 * Address: 0070e520
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackMelee::ShouldWalk(CINSBotAttackMelee *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::ShouldWalk
 * Address: 0070e530
 * ---------------------------------------- */

/* CINSBotAttackMelee::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackMelee::ShouldWalk(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackMelee::~CINSBotAttackMelee
 * Address: 0070f380
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::~CINSBotAttackMelee() */

void __thiscall CINSBotAttackMelee::~CINSBotAttackMelee(CINSBotAttackMelee *this)

{
  ~CINSBotAttackMelee(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::~CINSBotAttackMelee
 * Address: 0070f390
 * ---------------------------------------- */

/* CINSBotAttackMelee::~CINSBotAttackMelee() */

void __thiscall CINSBotAttackMelee::~CINSBotAttackMelee(CINSBotAttackMelee *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0048648a + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x486632 /* vtable for CINSBotAttackMelee+0x1b0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::~CINSBotAttackMelee
 * Address: 0070f3f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackMelee::~CINSBotAttackMelee() */

void __thiscall CINSBotAttackMelee::~CINSBotAttackMelee(CINSBotAttackMelee *this)

{
  ~CINSBotAttackMelee(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackMelee::~CINSBotAttackMelee
 * Address: 0070f400
 * ---------------------------------------- */

/* CINSBotAttackMelee::~CINSBotAttackMelee() */

void __thiscall CINSBotAttackMelee::~CINSBotAttackMelee(CINSBotAttackMelee *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48641a /* vtable for CINSBotAttackMelee+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4865c2 /* vtable for CINSBotAttackMelee+0x1b0 */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



