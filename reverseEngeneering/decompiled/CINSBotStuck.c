/*
 * CINSBotStuck -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 11
 */

/* ----------------------------------------
 * CINSBotStuck::OnStart
 * Address: 00732100
 * ---------------------------------------- */

/* WARNING: Removing unreachable block (ram,0x007323f0) */
/* CINSBotStuck::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotStuck::OnStart(CINSBotStuck *this,CINSNextBot *param_1,Action *param_2)

{
  Action *pAVar1;
  int iVar2;
  CBaseEntity *this_00;
  CINSNextBot *this_01;
  CUtlMemory<Vector,int> *this_02;
  int unaff_EBX;
  int *in_stack_0000000c;
  undefined4 uVar3;
  
  __i686_get_pc_thunk_bx();
  (**(code **)(*in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
  uVar3 = 0xd;
  CINSBotLocomotion::ClearMovementRequests();
  if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_00);
  }
  *(int *)(param_2 + 0x4c) = in_stack_0000000c[0x82];
  *(int *)(param_2 + 0x50) = in_stack_0000000c[0x83];
  *(int *)(param_2 + 0x54) = in_stack_0000000c[0x84];
  iVar2 = (**(code **)(*in_stack_0000000c + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_0000000c,uVar3);
  if (iVar2 == 0) {
    Warning(unaff_EBX + 0x24fd09 /* "Bot stuck on non-existant nav mesh" */ /* "Bot stuck on non-existant nav mesh" */);
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24fcd5 /* "Not on the nav mesh" */ /* "Not on the nav mesh" */;
  }
  else {
    *(uint *)(iVar2 + 0x68) = *(uint *)(iVar2 + 0x68) | 0x80;
    pAVar1 = param_2 + 0x58;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CUtlVector<Vector,CUtlMemory<Vector,int>>::InsertBefore((int)pAVar1,*(Vector **)(param_2 + 100))
    ;
    CINSNextBot::ResetIdleStatus(this_01);
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    CUtlMemory<Vector,int>::~CUtlMemory(this_02);
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotStuck::Update
 * Address: 00731660
 * ---------------------------------------- */

/* CINSBotStuck::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall CINSBotStuck::Update(CINSBotStuck *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  int iVar2;
  int *piVar3;
  CINSBotLocomotion *this_00;
  CINSBotLocomotion *this_01;
  CINSBotLocomotion *this_02;
  CTraceFilterSimple *this_03;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  float fVar6;
  CBasePlayer *in_stack_0000000c;
  Vector *pVVar7;
  Vector *pVVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  Vector local_13c [12];
  Vector local_130 [32];
  float local_110;
  char local_105;
  undefined4 local_f0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_cc;
  float local_c8;
  float local_c4;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_9c;
  undefined1 local_98;
  undefined1 local_97;
  int local_8c;
  int local_88;
  int local_84;
  int local_7c;
  undefined4 local_78;
  int local_74;
  undefined4 local_70;
  int local_6c;
  undefined4 local_68;
  Vector local_64 [12];
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
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x73166b;
  __i686_get_pc_thunk_bx();
  fVar4 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar4 &&
      (float)fVar4 != *(float *)((int)param_2 + 0x40)) {
    fVar4 = (float10)CountdownTimer::Now();
    fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x1f30ed /* 0.5f */ /* 0.5f */);
    if (*(float *)((int)param_2 + 0x40) != fVar5) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40);
      *(float *)((int)param_2 + 0x40) = fVar5;
    }
    if (*(int *)((int)param_2 + 0x3c) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c);
      *(undefined4 *)((int)param_2 + 0x3c) = 0x3f000000 /* 0.5f */;
    }
    fVar4 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                               (in_stack_0000000c + 0x2060,(int)param_2 + 0x4c);
    if (*(float *)(unaff_EBX + 0x2067ad /* 32.0f */ /* 32.0f */) <= (float)fVar4 &&
        (float)fVar4 != *(float *)(unaff_EBX + 0x2067ad /* 32.0f */ /* 32.0f */)) {
      piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
      (**(code **)(*piVar3 + 0x194 /* ILocomotion::ClearStuckStatus */))(piVar3,&UNK_00228410 + unaff_EBX);
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x250789 /* " moved from our stuck position" */ /* " moved from our stuck position" */;
      return param_1;
    }
    pVVar8 = (Vector *)&local_58;
    uVar10 = 0;
    pVVar7 = local_64;
    CBasePlayer::EyeVectors(in_stack_0000000c,(Vector *)in_stack_0000000c,pVVar7,pVVar8);
    fVar5 = *(float *)(unaff_EBX + 0x187911 /* 3.0f */ /* 3.0f */);
    fVar6 = *(float *)(**(int **)(unaff_EBX + 0x475235 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
    if (fVar5 < fVar6 - *(float *)((int)param_2 + 0x44)) {
      (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c,pVVar7,pVVar8,uVar10);
      fVar4 = (float10)CINSBotLocomotion::GetStillDuration(this_01);
      fVar6 = *(float *)(unaff_EBX + 0x1874a9 /* 1.0f */ /* 1.0f */);
      if (fVar6 < (float)fVar4) {
        *(undefined4 *)((int)param_2 + 0x44) =
             *(undefined4 *)(**(int **)(unaff_EBX + 0x475235 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
        (**(code **)(*(int *)in_stack_0000000c + 0x8e8 /* NextBotPlayer::PressForwardButton */))(in_stack_0000000c,fVar6);
        piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
        (**(code **)(*piVar3 + 0xd8 /* PlayerLocomotion::Jump */))(piVar3);
        goto LAB_00731699;
      }
      fVar6 = *(float *)(**(int **)(unaff_EBX + 0x475235 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
    }
    if (fVar5 < fVar6 - *(float *)((int)param_2 + 0x48)) {
      (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
      fVar4 = (float10)CINSBotLocomotion::GetStillDuration(this_02);
      if (*(float *)(unaff_EBX + 0x1f5745 /* 2.0f */ /* 2.0f */) <= (float)fVar4 &&
          (float)fVar4 != *(float *)(unaff_EBX + 0x1f5745 /* 2.0f */ /* 2.0f */)) {
        local_f0 = 0;
        uVar10 = CBaseEntity::GetTeamNumber((CBaseEntity *)in_stack_0000000c);
        uVar11 = 0;
        uVar9 = 0;
        CTraceFilterSimple::CTraceFilterSimple
                  (this_03,(IHandleEntity *)&local_8c,(int)in_stack_0000000c,
                   (_func_bool_IHandleEntity_ptr_int *)0x0);
        fVar1 = local_50;
        fVar6 = local_54;
        fVar5 = local_58;
        local_8c = unaff_EBX + 0x463d85 /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */ /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */;
        local_7c = 0;
        local_78 = 0;
        local_74 = 0;
        local_70 = 0;
        local_6c = 0;
        local_68 = uVar10;
        (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_40,in_stack_0000000c,uVar9,uVar11);
        (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_4c,in_stack_0000000c);
        local_98 = 1;
        local_dc = local_4c;
        local_9c = 0;
        local_d8 = local_48;
        local_d4 = local_44;
        local_cc = (*(float *)(unaff_EBX + 0x2067ad /* 32.0f */ /* 32.0f */) * fVar5 - local_4c) + local_40;
        local_c8 = (*(float *)(unaff_EBX + 0x2067ad /* 32.0f */ /* 32.0f */) * fVar6 - local_48) + local_3c;
        local_c4 = (*(float *)(unaff_EBX + 0x2067ad /* 32.0f */ /* 32.0f */) * fVar1 - local_44) + local_38;
        local_a4 = 0;
        local_a8 = 0;
        local_ac = 0;
        local_b4 = 0;
        local_b8 = 0;
        local_bc = 0;
        local_97 = local_c8 * local_c8 + local_cc * local_cc + local_c4 * local_c4 != 0.0;
        (**(code **)(*(int *)**(undefined4 **)(&DAT_0047510d + unaff_EBX) + 0x14))
                  ((int *)**(undefined4 **)(&DAT_0047510d + unaff_EBX),&local_dc,0x2006241,&local_8c
                   ,local_13c);
        piVar3 = *(int **)(&DAT_004753d5 + unaff_EBX);
        iVar2 = (**(code **)(*piVar3 + 0x40))(piVar3);
        if (iVar2 != 0) {
          iVar2 = (**(code **)(*piVar3 + 0x40))(piVar3);
          fVar5 = 0.5;
          if (iVar2 != 0) {
            fVar5 = -1.0;
          }
          DebugDrawLine(local_13c,local_130,0xff,0,0,true,fVar5);
        }
        if ((local_110 < *(float *)(unaff_EBX + 0x1874a9 /* 1.0f */ /* 1.0f */)) || (local_105 != '\0')) {
          (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_28,in_stack_0000000c);
          (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_34,in_stack_0000000c);
          fVar5 = *(float *)(unaff_EBX + 0x22ea9d /* CSWTCH.200+0xb4 */ /* CSWTCH.200+0xb4 */);
          local_9c = 0;
          local_98 = 1;
          local_dc = local_34;
          local_d8 = local_30;
          local_d4 = local_2c;
          local_cc = (local_58 * fVar5 - local_34) + local_28;
          local_c8 = (local_54 * fVar5 - local_30) + local_24;
          local_c4 = (fVar5 * local_50 - local_2c) + local_20;
          local_a4 = 0;
          local_a8 = 0;
          local_ac = 0;
          local_b4 = 0;
          local_b8 = 0;
          local_bc = 0;
          local_97 = local_c8 * local_c8 + local_cc * local_cc + local_c4 * local_c4 != 0.0;
          (**(code **)(*(int *)**(undefined4 **)(&DAT_0047510d + unaff_EBX) + 0x14))
                    ((int *)**(undefined4 **)(&DAT_0047510d + unaff_EBX),&local_dc,0x2006241,
                     &local_8c,local_13c);
          iVar2 = (**(code **)(*piVar3 + 0x40))(piVar3);
          if (iVar2 != 0) {
            iVar2 = (**(code **)(*piVar3 + 0x40))(piVar3);
            fVar5 = 0.5;
            if (iVar2 != 0) {
              fVar5 = -1.0;
            }
            DebugDrawLine(local_13c,local_130,0xff,0,0,true,fVar5);
          }
          if ((local_110 < *(float *)(unaff_EBX + 0x1874a9 /* 1.0f */ /* 1.0f */)) || (local_105 != '\0')) {
            local_70 = 0;
            *(undefined4 *)((int)param_2 + 0x48) =
                 *(undefined4 *)(**(int **)(unaff_EBX + 0x475235 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
            *(undefined4 *)param_1 = 0 /* Continue */;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined4 *)(param_1 + 8) = 0;
            local_8c = unaff_EBX + 0x462f0d /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */;
            if (local_74 < 0) {
              return param_1;
            }
            if (local_7c == 0) {
              return param_1;
            }
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47520d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x47520d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_7c);
            return param_1;
          }
          (**(code **)(*(int *)in_stack_0000000c + 0x8f8 /* NextBotPlayer::PressLeftButton */))(in_stack_0000000c,0x40000000 /* 2.0f */);
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x900 /* NextBotPlayer::PressRightButton */))(in_stack_0000000c,0x40000000 /* 2.0f */);
        }
        local_70 = 0;
        *(undefined4 *)((int)param_2 + 0x48) =
             *(undefined4 *)(**(int **)(unaff_EBX + 0x475235 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
        local_8c = unaff_EBX + 0x462f0d /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */;
        if (local_74 < 0) {
          local_6c = local_7c;
        }
        else {
          if (local_7c != 0) {
            (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47520d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x47520d /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_7c);
            local_7c = 0;
          }
          local_78 = 0;
          local_6c = 0;
        }
      }
    }
    (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
    fVar4 = (float10)CINSBotLocomotion::GetStillDuration(this_00);
    if ((*(float *)(unaff_EBX + 0x1f3101 /* 5.0f */ /* 5.0f */) <= (float)fVar4 &&
         (float)fVar4 != *(float *)(unaff_EBX + 0x1f3101 /* 5.0f */ /* 5.0f */)) && (0 < *(int *)((int)param_2 + 100))) {
      piVar3 = *(int **)((int)param_2 + 0x58);
      local_8c = *piVar3;
      local_88 = piVar3[1];
      local_84 = piVar3[2];
      uVar10 = (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
      CINSBotLocomotion::AddMovementRequest(uVar10,local_8c,local_88,local_84,0,9,0x40400000 /* 3.0f */);
      iVar2 = *(int *)((int)param_2 + 100) + -1;
      if (0 < iVar2) {
        _V_memmove(*(void **)((int)param_2 + 0x58),
                   (void *)((int)*(void **)((int)param_2 + 0x58) + 0xc),iVar2 * 0xc);
        iVar2 = *(int *)((int)param_2 + 100) + -1;
      }
      *(int *)((int)param_2 + 100) = iVar2;
      piVar3 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
      (**(code **)(*piVar3 + 0x194 /* ILocomotion::ClearStuckStatus */))(piVar3,&UNK_00228410 + unaff_EBX);
    }
  }
LAB_00731699:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotStuck::GetName
 * Address: 00732500
 * ---------------------------------------- */

/* CINSBotStuck::GetName() const */

int CINSBotStuck::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x24d550 /* "Stuck" */ /* "Stuck" */;
}



/* ----------------------------------------
 * CINSBotStuck::OnMoveToSuccess
 * Address: 00731580
 * ---------------------------------------- */

/* CINSBotStuck::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotStuck::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined **)(param_1 + 8) = &UNK_0025082d + extraout_ECX;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotStuck::OnMoveToFailure
 * Address: 007315c0
 * ---------------------------------------- */

/* CINSBotStuck::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotStuck::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotStuck::OnStuck
 * Address: 007315f0
 * ---------------------------------------- */

/* CINSBotStuck::OnStuck(CINSNextBot*) */

void CINSBotStuck::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotStuck::OnUnStuck
 * Address: 00731620
 * ---------------------------------------- */

/* CINSBotStuck::OnUnStuck(CINSNextBot*) */

void CINSBotStuck::OnUnStuck(CINSNextBot *param_1)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)param_1 = 3 /* Done */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(int *)(param_1 + 8) = extraout_ECX + 0x2507a7 /* "Successful unstuck " */ /* "Successful unstuck " */;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotStuck::~CINSBotStuck
 * Address: 00732520
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotStuck::~CINSBotStuck() */

void __thiscall CINSBotStuck::~CINSBotStuck(CINSBotStuck *this)

{
  ~CINSBotStuck(this);
  return;
}



/* ----------------------------------------
 * CINSBotStuck::~CINSBotStuck
 * Address: 00732530
 * ---------------------------------------- */

/* CINSBotStuck::~CINSBotStuck() */

void __thiscall CINSBotStuck::~CINSBotStuck(CINSBotStuck *this)

{
  int iVar1;
  CUtlMemory<Vector,int> *extraout_ECX;
  CUtlMemory<Vector,int> *extraout_ECX_00;
  CUtlMemory<Vector,int> *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[0x19] = 0;
  *in_stack_00000004 = unaff_EBX + 0x4661ce /* vtable for CINSBotStuck+0x8 */ /* vtable for CINSBotStuck+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46635e /* vtable for CINSBotStuck+0x198 */ /* vtable for CINSBotStuck+0x198 */;
  iVar1 = in_stack_00000004[0x16];
  this_00 = extraout_ECX;
  if (-1 < in_stack_00000004[0x18]) {
    if (iVar1 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47433e /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x47433e /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar1);
      in_stack_00000004[0x16] = 0;
      this_00 = extraout_ECX_00;
    }
    in_stack_00000004[0x17] = 0;
    iVar1 = 0;
  }
  in_stack_00000004[0x1a] = iVar1;
  CUtlMemory<Vector,int>::~CUtlMemory(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotStuck::~CINSBotStuck
 * Address: 007325e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotStuck::~CINSBotStuck() */

void __thiscall CINSBotStuck::~CINSBotStuck(CINSBotStuck *this)

{
  ~CINSBotStuck(this);
  return;
}



/* ----------------------------------------
 * CINSBotStuck::~CINSBotStuck
 * Address: 007325f0
 * ---------------------------------------- */

/* CINSBotStuck::~CINSBotStuck() */

void __thiscall CINSBotStuck::~CINSBotStuck(CINSBotStuck *this)

{
  int iVar1;
  CUtlMemory<Vector,int> *extraout_ECX;
  CUtlMemory<Vector,int> *extraout_ECX_00;
  CUtlMemory<Vector,int> *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[0x19] = 0;
  *in_stack_00000004 = unaff_EBX + 0x46610e /* vtable for CINSBotStuck+0x8 */ /* vtable for CINSBotStuck+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x46629e /* vtable for CINSBotStuck+0x198 */ /* vtable for CINSBotStuck+0x198 */;
  iVar1 = in_stack_00000004[0x16];
  this_00 = extraout_ECX;
  if (-1 < in_stack_00000004[0x18]) {
    if (iVar1 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x47427e /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x47427e /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar1);
      in_stack_00000004[0x16] = 0;
      this_00 = extraout_ECX_00;
    }
    in_stack_00000004[0x17] = 0;
    iVar1 = 0;
  }
  in_stack_00000004[0x1a] = iVar1;
  CUtlMemory<Vector,int>::~CUtlMemory(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



