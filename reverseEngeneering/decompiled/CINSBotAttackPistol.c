/*
 * CINSBotAttackPistol -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackPistol::CINSBotAttackPistol
 * Address: 007103c0
 * ---------------------------------------- */

/* CINSBotAttackPistol::CINSBotAttackPistol() */

void __thiscall CINSBotAttackPistol::CINSBotAttackPistol(CINSBotAttackPistol *this)

{
  int *piVar1;
  int *piVar2;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48565d /* vtable for CINSBotAttackPistol+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x485805 /* vtable for CINSBotAttackPistol+0x1b0 */;
  piVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[0xe] = unaff_EBX + 0x417ded /* vtable for CountdownTimer+0x8 */;
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
  (*(code *)(unaff_EBX + -0x4dfc5b /* CountdownTimer::NetworkStateChanged */))(piVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000;
  (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
  piVar2 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = unaff_EBX + 0x417ded /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x4dfc5b /* CountdownTimer::NetworkStateChanged */))(piVar2,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = -0x40800000;
  (**(code **)(in_stack_00000004[0x11] + 4))(piVar2,in_stack_00000004 + 0x13);
  if (in_stack_00000004[0x10] != -0x40800000) {
    (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = -0x40800000;
  }
  if (in_stack_00000004[0x13] != -0x40800000) {
    (**(code **)(in_stack_00000004[0x11] + 4))(piVar2,in_stack_00000004 + 0x13);
    in_stack_00000004[0x13] = -0x40800000;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnStart
 * Address: 0070fc20
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackPistol::OnStart(CINSBotAttackPistol *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  int iVar2;
  float fVar3;
  int *piVar4;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_02;
  CINSNextBot *extraout_ECX_01;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  float10 fVar5;
  CINSWeapon *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c == (CINSWeapon *)0x0) goto LAB_0070fcc3;
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar2 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_00 = extraout_ECX,
     iVar2 == 0)) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))();
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0))(piVar4,0);
    if ((piVar4 == (int *)0x0) ||
       (iVar2 = (**(code **)(*piVar4 + 0x10))(piVar4), this_00 = extraout_ECX_01, iVar2 == 0)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
  }
  fVar3 = *(float *)(in_stack_0000000c + 0xb340);
  fVar5 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
  if (fVar3 < (float)fVar5) {
    cVar1 = CINSNextBot::IsSuppressed(this_01);
    if (cVar1 != '\0') {
      (**(code **)(*(int *)in_stack_0000000c + 0x970))();
      CINSBotBody::SetPosture();
      goto LAB_0070fcc3;
    }
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (fVar3 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
       this_02 = extraout_ECX_00, fVar3 == 0.0)) {
      piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))();
      piVar4 = (int *)(**(code **)(*piVar4 + 0xd0))(piVar4,0);
      fVar3 = 0.0;
      this_02 = extraout_ECX_02;
      if (piVar4 != (int *)0x0) {
        fVar3 = (float)(**(code **)(*piVar4 + 0x10))(piVar4);
        this_02 = extraout_ECX_03;
      }
    }
    cVar1 = CINSPlayer::IsThreatAimingTowardMe(this_02,(CBaseEntity *)in_stack_0000000c,fVar3);
    iVar2 = *(int *)in_stack_0000000c;
    if (cVar1 != '\0') {
      (**(code **)(iVar2 + 0x970))();
      CINSBotBody::SetPosture();
      goto LAB_0070fcc3;
    }
  }
  else {
    iVar2 = *(int *)in_stack_0000000c;
  }
  (**(code **)(iVar2 + 0x970))();
  CINSBotBody::SetPosture();
LAB_0070fcc3:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackPistol::InitialContainedAction
 * Address: 0070f9d0
 * ---------------------------------------- */

/* CINSBotAttackPistol::InitialContainedAction(CINSNextBot*) */

void * __thiscall
CINSBotAttackPistol::InitialContainedAction(CINSBotAttackPistol *this,CINSNextBot *param_1)

{
  float *pfVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  void *pvVar5;
  undefined4 uVar6;
  CINSNextBot *this_00;
  CINSBotAttackAdvance *this_01;
  CINSBotAttackInPlace *this_02;
  int unaff_EBX;
  float10 fVar7;
  float10 fVar8;
  CINSWeapon *in_stack_00000008;
  undefined4 uVar9;
  float local_2c;
  float local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 != (CINSWeapon *)0x0) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974))();
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0))(piVar4,0);
    if (piVar4 != (int *)0x0) {
      uVar9 = 1;
      CINSNextBot::GetAttackCover(true);
      pfVar1 = *(float **)(unaff_EBX + 0x496be8 /* &vec3_origin */);
      if (((*pfVar1 == local_2c) && (pfVar1[1] == local_28)) && (pfVar1[2] == local_24)) {
        pcVar2 = *(code **)(*(int *)(in_stack_00000008 + 0x2060) + 0x130);
        uVar6 = (**(code **)(*piVar4 + 0x10))(piVar4);
        fVar7 = (float10)(*pcVar2)(in_stack_00000008 + 0x2060,uVar6,uVar9);
        uVar9 = 0;
        fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_00000008);
        if (((float)fVar7 <= (float)fVar8) &&
           (cVar3 = (**(code **)(*piVar4 + 0x38))(piVar4,uVar9), cVar3 != '\0')) {
          pvVar5 = ::operator_new(0x50);
          CINSBotAttackInPlace::CINSBotAttackInPlace(this_02);
          return pvVar5;
        }
        pvVar5 = ::operator_new(0x5c);
        CINSBotAttackAdvance::CINSBotAttackAdvance(this_01);
        return pvVar5;
      }
      pvVar5 = ::operator_new(0x54);
      CINSBotAttackIntoCover::CINSBotAttackIntoCover();
      return pvVar5;
    }
  }
  return (void *)0x0;
}



/* ----------------------------------------
 * CINSBotAttackPistol::Update
 * Address: 0070fe40
 * ---------------------------------------- */

/* CINSBotAttackPistol::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackPistol::Update(CINSBotAttackPistol *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int *piVar5;
  CINSPlayer *this_00;
  CINSNextBot *this_01;
  CINSPlayer *this_02;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_03;
  CINSNextBot *this_04;
  CINSNextBot *this_05;
  CINSBotVision *this_06;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *this_07;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar6;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar7;
  undefined4 uVar8;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c != (CINSWeapon *)0x0) {
    fVar2 = (float)CINSPlayer::GetActiveINSWeapon();
    uVar8 = 0;
    uVar7 = 1;
    fVar3 = (float)CINSPlayer::GetWeaponInSlot(this_00,(int)in_stack_0000000c,true);
    if ((((fVar3 != 0.0) && (fVar2 != 0.0)) && (in_stack_0000000c[0x1864] == (CINSWeapon)0x0)) &&
       (fVar2 != fVar3)) {
      CINSNextBot::ChooseBestWeapon(this_01,in_stack_0000000c,fVar3);
      *(undefined4 *)param_1 = 0;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined4 *)(param_1 + 8) = 0;
      return param_1;
    }
    iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x496e58 /* &ins_bot_pistols_only */) + 0x40))
                      (*(int **)(unaff_EBX + 0x496e58 /* &ins_bot_pistols_only */),uVar7,uVar8);
    if ((iVar4 == 0) || (fVar3 != 0.0)) {
      fVar6 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x4c) <= (float)fVar6 &&
          (float)fVar6 != *(float *)((int)param_2 + 0x4c)) {
        if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
           (iVar4 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_03 = extraout_ECX
           , iVar4 == 0)) {
          piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))();
          piVar5 = (int *)(**(code **)(*piVar5 + 0xd0))(piVar5,0);
          if ((piVar5 == (int *)0x0) ||
             (iVar4 = (**(code **)(*piVar5 + 0x10))(piVar5), this_03 = extraout_ECX_00, iVar4 == 0))
          {
            *(undefined4 *)param_1 = 3;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined4 *)(param_1 + 8) = 0;
            return param_1;
          }
        }
        fVar2 = *(float *)(in_stack_0000000c + 0xb340);
        fVar6 = (float10)CINSNextBot::GetDesiredAttackRange(this_03,in_stack_0000000c);
        if (fVar2 < (float)fVar6) {
          cVar1 = CINSNextBot::IsSuppressed(this_04);
          if (cVar1 == '\0') {
            if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
               (fVar2 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
               this_07 = extraout_ECX_01, fVar2 == 0.0)) {
              piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))();
              piVar5 = (int *)(**(code **)(*piVar5 + 0xd0))(piVar5,0);
              fVar2 = 0.0;
              this_07 = extraout_ECX_02;
              if (piVar5 != (int *)0x0) {
                fVar2 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
                this_07 = extraout_ECX_03;
              }
            }
            cVar1 = CINSPlayer::IsThreatAimingTowardMe
                              (this_07,(CBaseEntity *)in_stack_0000000c,fVar2);
            if (cVar1 == '\0') {
              (**(code **)(*(int *)in_stack_0000000c + 0x970))();
              uVar8 = 0x3f0ccccd;
              uVar7 = 7;
              iVar4 = unaff_EBX + 0x27026a /* "Walking At Target" */;
              CINSBotBody::SetPosture();
              local_24 = *(float *)(unaff_EBX + 0x214904 /* typeinfo name for CBaseGameSystem+0x1e */);
            }
            else {
              (**(code **)(*(int *)in_stack_0000000c + 0x970))();
              uVar8 = 0x3f0ccccd;
              uVar7 = 7;
              iVar4 = unaff_EBX + 0x270236 /* "Crouching From Suppression" */;
              CINSBotBody::SetPosture();
              local_24 = *(float *)(unaff_EBX + 0x214904 /* typeinfo name for CBaseGameSystem+0x1e */);
            }
          }
          else {
            piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970))();
            cVar1 = (**(code **)(*piVar5 + 0x124))(piVar5,0xd);
            if (cVar1 == '\0') {
              (**(code **)(*(int *)in_stack_0000000c + 0x974))();
              fVar6 = (float10)CINSBotVision::GetCombatIntensity(this_06);
              local_24 = *(float *)(unaff_EBX + 0x214904 /* typeinfo name for CBaseGameSystem+0x1e */);
              if ((float)fVar6 <= local_24) {
                (**(code **)(*(int *)in_stack_0000000c + 0x970))();
                uVar8 = 0x3f0ccccd;
                uVar7 = 7;
                iVar4 = unaff_EBX + 0x270236 /* "Crouching From Suppression" */;
                CINSBotBody::SetPosture();
              }
              else {
                (**(code **)(*(int *)in_stack_0000000c + 0x970))();
                uVar8 = 0x3f0ccccd;
                uVar7 = 7;
                iVar4 = unaff_EBX + 0x27021c /* "Crawling From Suppression" */;
                CINSBotBody::SetPosture();
              }
            }
            else {
              (**(code **)(*(int *)in_stack_0000000c + 0x970))();
              uVar8 = 0x3f0ccccd;
              uVar7 = 7;
              iVar4 = unaff_EBX + 0x270251 /* "Walking From Suppression" */;
              CINSBotBody::SetPosture();
              local_24 = *(float *)(unaff_EBX + 0x214904 /* typeinfo name for CBaseGameSystem+0x1e */);
            }
          }
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x970))();
          uVar8 = 0x3f0ccccd;
          uVar7 = 7;
          iVar4 = unaff_EBX + 0x27027c /* "Sprinting At Target" */;
          CINSBotBody::SetPosture();
          local_24 = *(float *)(unaff_EBX + 0x214904 /* typeinfo name for CBaseGameSystem+0x1e */);
        }
        piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))();
        iVar4 = (**(code **)(*piVar5 + 0xec))(piVar5,in_stack_0000000c + 0x2060,uVar7,uVar8,iVar4);
        if (iVar4 != 0) {
          (**(code **)(*(int *)in_stack_0000000c + 0x95c))();
        }
        fVar6 = (float10)CountdownTimer::Now();
        if (*(float *)((int)param_2 + 0x4c) != (float)fVar6 + local_24) {
          (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c);
          *(float *)((int)param_2 + 0x4c) = (float)fVar6 + local_24;
        }
        if (*(int *)((int)param_2 + 0x48) != 0x3f000000) {
          (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48);
          *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000;
        }
      }
    }
    else {
      fVar2 = (float)CINSPlayer::GetWeaponInSlot(this_02,(int)in_stack_0000000c,true);
      CINSNextBot::ChooseBestWeapon(this_05,in_stack_0000000c,fVar2);
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnEnd
 * Address: 0070f490
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackPistol::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::GetName
 * Address: 00710530
 * ---------------------------------------- */

/* CINSBotAttackPistol::GetName() const */

undefined * CINSBotAttackPistol::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return &UNK_0026ffec + extraout_ECX;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldHurry
 * Address: 0070f4a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackPistol::ShouldHurry(CINSBotAttackPistol *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldHurry
 * Address: 0070f4b0
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldHurry(INextBot const*) const */

char __thiscall CINSBotAttackPistol::ShouldHurry(CINSBotAttackPistol *this,INextBot *param_1)

{
  code *pcVar1;
  int *piVar2;
  char cVar3;
  int unaff_EBX;
  float10 fVar4;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*in_stack_00000008 + 0xdc))();
  piVar2 = (int *)(**(code **)(*piVar2 + 0xd0))(piVar2,0);
  cVar3 = '\x02';
  if (piVar2 != (int *)0x0) {
    pcVar1 = *(code **)(*in_stack_00000008 + 0x134);
    (**(code **)(*piVar2 + 0x14))(piVar2);
    fVar4 = (float10)(*pcVar1)();
    cVar3 = (*(float *)(unaff_EBX + 0x215ca8 /* typeinfo name for CEntityFactory<CBaseViewModel>+0x2c */) <= (float)fVar4) * '\x02';
  }
  return cVar3;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldRetreat
 * Address: 0070f540
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackPistol::ShouldRetreat(CINSBotAttackPistol *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldRetreat
 * Address: 0070f550
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackPistol::ShouldRetreat(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldAttack
 * Address: 0070f560
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackPistol::ShouldAttack(CINSBotAttackPistol *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldAttack
 * Address: 0070f570
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackPistol::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnContact
 * Address: 0070f5e0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackPistol::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnMoveToSuccess
 * Address: 0070f610
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackPistol::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnMoveToFailure
 * Address: 0070f640
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackPistol::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnStuck
 * Address: 0070f670
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnStuck(CINSNextBot*) */

void CINSBotAttackPistol::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnUnStuck
 * Address: 0070f6a0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnUnStuck(CINSNextBot*) */

void CINSBotAttackPistol::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnInjured
 * Address: 0070f700
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackPistol::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnKilled
 * Address: 0070f730
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackPistol::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnOtherKilled
 * Address: 0070f760
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&)
    */

void CINSBotAttackPistol::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnSight
 * Address: 0070f790
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackPistol::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnLostSight
 * Address: 0070f7c0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackPistol::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnWeaponFired
 * Address: 0070f7f0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackPistol::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnCommandApproach
 * Address: 0070f880
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackPistol::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnCommandApproach
 * Address: 0070f8b0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackPistol::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnCommandString
 * Address: 0070f910
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackPistol::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnBlinded
 * Address: 0070f940
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackPistol::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnCommandAttack
 * Address: 0070f850
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackPistol::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnCommandRetreat
 * Address: 0070f8e0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackPistol::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnHeardFootsteps
 * Address: 0070f970
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackPistol::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnNavAreaChanged
 * Address: 0070f820
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackPistol::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnPostureChanged
 * Address: 0070f6d0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackPistol::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::OnSeeSomethingSuspicious
 * Address: 0070f9a0
 * ---------------------------------------- */

/* CINSBotAttackPistol::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void CINSBotAttackPistol::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldIronsight
 * Address: 0070f5a0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackPistol::ShouldIronsight(CINSBotAttackPistol *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldIronsight
 * Address: 0070f5b0
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackPistol::ShouldIronsight(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldProne
 * Address: 0070f5c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackPistol::ShouldProne(CINSBotAttackPistol *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldProne
 * Address: 0070f5d0
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackPistol::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldWalk
 * Address: 0070f580
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackPistol::ShouldWalk(CINSBotAttackPistol *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::ShouldWalk
 * Address: 0070f590
 * ---------------------------------------- */

/* CINSBotAttackPistol::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackPistol::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackPistol::~CINSBotAttackPistol
 * Address: 00710550
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::~CINSBotAttackPistol() */

void __thiscall CINSBotAttackPistol::~CINSBotAttackPistol(CINSBotAttackPistol *this)

{
  ~CINSBotAttackPistol(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::~CINSBotAttackPistol
 * Address: 00710560
 * ---------------------------------------- */

/* CINSBotAttackPistol::~CINSBotAttackPistol() */

void __thiscall CINSBotAttackPistol::~CINSBotAttackPistol(CINSBotAttackPistol *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4854c3 /* vtable for CINSBotAttackPistol+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x48566b /* vtable for CINSBotAttackPistol+0x1b0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x496c13 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::~CINSBotAttackPistol
 * Address: 00710590
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackPistol::~CINSBotAttackPistol() */

void __thiscall CINSBotAttackPistol::~CINSBotAttackPistol(CINSBotAttackPistol *this)

{
  ~CINSBotAttackPistol(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackPistol::~CINSBotAttackPistol
 * Address: 007105a0
 * ---------------------------------------- */

/* CINSBotAttackPistol::~CINSBotAttackPistol() */

void __thiscall CINSBotAttackPistol::~CINSBotAttackPistol(CINSBotAttackPistol *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48547a /* vtable for CINSBotAttackPistol+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x485622 /* vtable for CINSBotAttackPistol+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



