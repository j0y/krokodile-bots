/*
 * CINSBotAttackCQC -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 43
 */

/* ----------------------------------------
 * CINSBotAttackCQC::CINSBotAttackCQC
 * Address: 00708030
 * ---------------------------------------- */

/* CINSBotAttackCQC::CINSBotAttackCQC() */

void __thiscall CINSBotAttackCQC::CINSBotAttackCQC(CINSBotAttackCQC *this)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = &UNK_0048cdcd + unaff_EBX;
  in_stack_00000004[1] = &UNK_0048cf75 + unaff_EBX;
  puVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[0xe] = unaff_EBX + 0x42017d /* vtable for CountdownTimer+0x8 */;
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
  (*(code *)(unaff_EBX + -0x4d78cb /* CountdownTimer::NetworkStateChanged */))(puVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
  puVar2 = in_stack_00000004 + 0x11;
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = unaff_EBX + 0x42017d /* vtable for CountdownTimer+0x8 */;
  (*(code *)(unaff_EBX + -0x4d78cb /* CountdownTimer::NetworkStateChanged */))(puVar2,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = 0xbf800000 /* -1.0f */;
  (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
  if (in_stack_00000004[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0xe] + 4))(puVar1,in_stack_00000004 + 0x10);
    in_stack_00000004[0x10] = 0xbf800000 /* -1.0f */;
  }
  if (in_stack_00000004[0x13] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x11] + 4))(puVar2,in_stack_00000004 + 0x13);
    in_stack_00000004[0x13] = 0xbf800000 /* -1.0f */;
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnStart
 * Address: 00707d90
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackCQC::OnStart(CINSBotAttackCQC *this,CINSNextBot *param_1,Action *param_2)

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
  if (in_stack_0000000c == (CINSWeapon *)0x0) goto LAB_00707e33;
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar2 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_00 = extraout_ECX,
     iVar2 == 0)) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
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
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
      CINSBotBody::SetPosture();
      goto LAB_00707e33;
    }
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (fVar3 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
       this_02 = extraout_ECX_00, fVar3 == 0.0)) {
      piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
      piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
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
      goto LAB_00707e33;
    }
  }
  else {
    iVar2 = *(int *)in_stack_0000000c;
  }
  (**(code **)(iVar2 + 0x970))();
  CINSBotBody::SetPosture();
LAB_00707e33:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackCQC::InitialContainedAction
 * Address: 00707570
 * ---------------------------------------- */

/* CINSBotAttackCQC::InitialContainedAction(CINSNextBot*) */

void * __thiscall
CINSBotAttackCQC::InitialContainedAction(CINSBotAttackCQC *this,CINSNextBot *param_1)

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
    piVar4 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (piVar4 != (int *)0x0) {
      uVar9 = 1;
      CINSNextBot::GetAttackCover(true);
      pfVar1 = *(float **)(unaff_EBX + 0x49f048 /* &vec3_origin */);
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
 * CINSBotAttackCQC::Update
 * Address: 00707930
 * ---------------------------------------- */

/* CINSBotAttackCQC::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackCQC::Update(CINSBotAttackCQC *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  float fVar4;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSBotVision *this_02;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *this_03;
  CINSPlayer *extraout_ECX_02;
  CINSPlayer *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar5;
  CINSWeapon *in_stack_0000000c;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  fVar5 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x4c) <= (float)fVar5 &&
      (float)fVar5 != *(float *)((int)param_2 + 0x4c)) {
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (iVar2 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), this_00 = extraout_ECX,
       iVar2 == 0)) {
      piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
      piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
      if ((piVar3 == (int *)0x0) ||
         (iVar2 = (**(code **)(*piVar3 + 0x10))(piVar3), this_00 = extraout_ECX_00, iVar2 == 0)) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
    }
    fVar4 = *(float *)(in_stack_0000000c + 0xb340);
    uVar6 = 0;
    fVar5 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,in_stack_0000000c);
    if (fVar4 < (float)fVar5) {
      cVar1 = CINSNextBot::IsSuppressed(this_01);
      if (cVar1 == '\0') {
        if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
           (fVar4 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
           this_03 = extraout_ECX_01, fVar4 == 0.0)) {
          piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c,uVar6);
          piVar3 = (int *)(**(code **)(*piVar3 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar3,0);
          fVar4 = 0.0;
          this_03 = extraout_ECX_02;
          if (piVar3 != (int *)0x0) {
            fVar4 = (float)(**(code **)(*piVar3 + 0x10))(piVar3);
            this_03 = extraout_ECX_03;
          }
        }
        uVar6 = 0x3f4ccccd /* 0.8f */;
        cVar1 = CINSPlayer::IsThreatAimingTowardMe(this_03,(CBaseEntity *)in_stack_0000000c,fVar4);
        if (cVar1 == '\0') {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c,fVar4,uVar6);
          uVar8 = 0x3f0ccccd /* 0.55f */;
          uVar7 = 7;
          iVar2 = unaff_EBX + 0x278780 /* "Walking At Target" */;
          uVar6 = 0xc;
          CINSBotBody::SetPosture();
          local_24 = *(float *)(unaff_EBX + 0x21ce1a /* typeinfo name for CBaseGameSystem+0x1e */);
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
          uVar8 = 0x3f0ccccd /* 0.55f */;
          uVar7 = 7;
          iVar2 = unaff_EBX + 0x27874c /* "Crouching From Suppression" */;
          uVar6 = 3;
          CINSBotBody::SetPosture();
          local_24 = *(float *)(unaff_EBX + 0x21ce1a /* typeinfo name for CBaseGameSystem+0x1e */);
        }
      }
      else {
        piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        cVar1 = (**(code **)(*piVar3 + 0x124 /* CINSBotBody::IsActualPosture */))(piVar3,0xd);
        if (cVar1 == '\0') {
          (**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
          fVar5 = (float10)CINSBotVision::GetCombatIntensity(this_02);
          local_24 = *(float *)(unaff_EBX + 0x21ce1a /* typeinfo name for CBaseGameSystem+0x1e */);
          if ((float)fVar5 <= local_24) {
            (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            uVar8 = 0x3f0ccccd /* 0.55f */;
            uVar7 = 7;
            iVar2 = unaff_EBX + 0x27874c /* "Crouching From Suppression" */;
            uVar6 = 6;
            CINSBotBody::SetPosture();
          }
          else {
            (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
            uVar8 = 0x3f0ccccd /* 0.55f */;
            uVar7 = 7;
            iVar2 = unaff_EBX + 0x278732 /* "Crawling From Suppression" */;
            uVar6 = 2;
            CINSBotBody::SetPosture();
          }
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          uVar8 = 0x3f0ccccd /* 0.55f */;
          uVar7 = 7;
          iVar2 = unaff_EBX + 0x278767 /* "Walking From Suppression" */;
          uVar6 = 0xb;
          CINSBotBody::SetPosture();
          local_24 = *(float *)(unaff_EBX + 0x21ce1a /* typeinfo name for CBaseGameSystem+0x1e */);
        }
      }
    }
    else {
      (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      uVar8 = 0x3f0ccccd /* 0.55f */;
      uVar7 = 7;
      iVar2 = unaff_EBX + 0x278792 /* "Sprinting At Target" */;
      uVar6 = 0xd;
      CINSBotBody::SetPosture();
      local_24 = *(float *)(unaff_EBX + 0x21ce1a /* typeinfo name for CBaseGameSystem+0x1e */);
    }
    piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))
                              (in_stack_0000000c,uVar6,uVar7,uVar8,iVar2);
    iVar2 = (**(code **)(*piVar3 + 0xec /* IIntention::ShouldIronsight */))(piVar3,in_stack_0000000c + 0x2060);
    if (iVar2 != 0) {
      (**(code **)(*(int *)in_stack_0000000c + 0x95c /* CINSNextBot::PressIronsightButton */))(in_stack_0000000c,0x3f0ccccd /* 0.55f */);
    }
    fVar5 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x4c) != (float)fVar5 + local_24) {
      (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x4c);
      *(float *)((int)param_2 + 0x4c) = (float)fVar5 + local_24;
    }
    if (*(int *)((int)param_2 + 0x48) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x44) + 4))((int)param_2 + 0x44,(int)param_2 + 0x48);
      *(undefined4 *)((int)param_2 + 0x48) = 0x3f000000 /* 0.5f */;
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnEnd
 * Address: 007070d0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackCQC::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::GetName
 * Address: 007081a0
 * ---------------------------------------- */

/* CINSBotAttackCQC::GetName() const */

int CINSBotAttackCQC::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x277eba /* "CINSBotAttackCQC" */;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldHurry
 * Address: 007070e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackCQC::ShouldHurry(CINSBotAttackCQC *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldHurry
 * Address: 007070f0
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackCQC::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldRetreat
 * Address: 00707100
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackCQC::ShouldRetreat(CINSBotAttackCQC *this,INextBot *param_1)

{
  ShouldRetreat(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldRetreat
 * Address: 00707110
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldRetreat(INextBot const*) const */

undefined4 __cdecl CINSBotAttackCQC::ShouldRetreat(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldAttack
 * Address: 00707120
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldAttack(INextBot const*, CKnownEntity const*) const
    */

void __thiscall
CINSBotAttackCQC::ShouldAttack(CINSBotAttackCQC *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldAttack
 * Address: 00707130
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackCQC::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnContact
 * Address: 00707180
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackCQC::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnMoveToSuccess
 * Address: 007071b0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackCQC::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnMoveToFailure
 * Address: 007071e0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackCQC::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnStuck
 * Address: 00707210
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnStuck(CINSNextBot*) */

void CINSBotAttackCQC::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnUnStuck
 * Address: 00707240
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnUnStuck(CINSNextBot*) */

void CINSBotAttackCQC::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnInjured
 * Address: 007072a0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackCQC::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnKilled
 * Address: 007072d0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackCQC::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnOtherKilled
 * Address: 00707300
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&) */

void CINSBotAttackCQC::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnSight
 * Address: 00707330
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackCQC::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnLostSight
 * Address: 00707360
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackCQC::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnWeaponFired
 * Address: 00707390
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackCQC::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnCommandApproach
 * Address: 00707420
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackCQC::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnCommandApproach
 * Address: 00707450
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackCQC::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnCommandString
 * Address: 007074b0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackCQC::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnBlinded
 * Address: 007074e0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackCQC::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnCommandAttack
 * Address: 007073f0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackCQC::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnCommandRetreat
 * Address: 00707480
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackCQC::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnHeardFootsteps
 * Address: 00707510
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackCQC::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnNavAreaChanged
 * Address: 007073c0
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackCQC::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnPostureChanged
 * Address: 00707270
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackCQC::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::OnSeeSomethingSuspicious
 * Address: 00707540
 * ---------------------------------------- */

/* CINSBotAttackCQC::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackCQC::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldIronsight
 * Address: 007077c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackCQC::ShouldIronsight(CINSBotAttackCQC *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldIronsight
 * Address: 007077d0
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldIronsight(INextBot const*) const */

int __cdecl CINSBotAttackCQC::ShouldIronsight(INextBot *param_1)

{
  float fVar1;
  CINSWeapon *pCVar2;
  char cVar3;
  int iVar4;
  float fVar5;
  int *piVar6;
  CINSPlayer *this;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSNextBot *extraout_ECX_00;
  CINSPlayer *this_02;
  int unaff_EBX;
  int iVar7;
  float10 fVar8;
  
  iVar4 = __i686_get_pc_thunk_bx();
  iVar7 = 2;
  pCVar2 = *(CINSWeapon **)(iVar4 + 0x1c);
  if (pCVar2 != (CINSWeapon *)0x0) {
    iVar7 = 0;
    cVar3 = CINSPlayer::IsSprinting(this);
    if (cVar3 == '\0') {
      if ((*(int *)(pCVar2 + 0xb338) == -1) ||
         (fVar5 = (float)UTIL_EntityByIndex(*(int *)(pCVar2 + 0xb338)), this_00 = extraout_ECX,
         fVar5 == 0.0)) {
        piVar6 = (int *)(**(code **)(*(int *)pCVar2 + 0x974 /* CINSNextBot::GetVisionInterface */))(pCVar2);
        piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
        if (piVar6 == (int *)0x0) {
          return 0;
        }
        fVar5 = (float)(**(code **)(*piVar6 + 0x10))(piVar6);
        this_00 = extraout_ECX_00;
        if (fVar5 == 0.0) {
          return 0;
        }
      }
      fVar8 = (float10)CINSNextBot::GetDesiredAttackRange(this_00,pCVar2);
      fVar1 = *(float *)(pCVar2 + 0xb340);
      if (fVar1 < (float)fVar8) {
        return (fVar1 < (float)fVar8 * *(float *)(unaff_EBX + 0x21cf77 /* typeinfo name for CBaseGameSystem+0x1e */)) + 1;
      }
      iVar7 = 2;
      fVar8 = (float10)CINSNextBot::GetMaxAttackRange(this_01,pCVar2);
      if (fVar1 < (float)fVar8) {
        cVar3 = CINSPlayer::IsThreatAimingTowardMe(this_02,(CBaseEntity *)pCVar2,fVar5);
        iVar7 = ~-(uint)(cVar3 == '\0') + 2;
      }
    }
  }
  return iVar7;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldProne
 * Address: 00707160
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackCQC::ShouldProne(CINSBotAttackCQC *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldProne
 * Address: 00707170
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackCQC::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldWalk
 * Address: 00707140
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackCQC::ShouldWalk(CINSBotAttackCQC *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::ShouldWalk
 * Address: 00707150
 * ---------------------------------------- */

/* CINSBotAttackCQC::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackCQC::ShouldWalk(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackCQC::~CINSBotAttackCQC
 * Address: 007081c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::~CINSBotAttackCQC() */

void __thiscall CINSBotAttackCQC::~CINSBotAttackCQC(CINSBotAttackCQC *this)

{
  ~CINSBotAttackCQC(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::~CINSBotAttackCQC
 * Address: 007081d0
 * ---------------------------------------- */

/* CINSBotAttackCQC::~CINSBotAttackCQC() */

void __thiscall CINSBotAttackCQC::~CINSBotAttackCQC(CINSBotAttackCQC *this)

{
  int extraout_ECX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = &UNK_0048cc33 + extraout_ECX;
  in_stack_00000004[1] = &UNK_0048cddb + extraout_ECX;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x49efa3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::~CINSBotAttackCQC
 * Address: 00708200
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackCQC::~CINSBotAttackCQC() */

void __thiscall CINSBotAttackCQC::~CINSBotAttackCQC(CINSBotAttackCQC *this)

{
  ~CINSBotAttackCQC(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackCQC::~CINSBotAttackCQC
 * Address: 00708210
 * ---------------------------------------- */

/* CINSBotAttackCQC::~CINSBotAttackCQC() */

void __thiscall CINSBotAttackCQC::~CINSBotAttackCQC(CINSBotAttackCQC *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_0048cbea + unaff_EBX;
  in_stack_00000004[1] = &UNK_0048cd92 + unaff_EBX;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



