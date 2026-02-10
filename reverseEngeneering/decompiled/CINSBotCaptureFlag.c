/*
 * CINSBotCaptureFlag -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 13
 */

/* ----------------------------------------
 * CINSBotCaptureFlag::CINSBotCaptureFlag
 * Address: 007145c0
 * ---------------------------------------- */

/* CINSBotCaptureFlag::CINSBotCaptureFlag(CINSPlayer*, int) */

void __thiscall
CINSBotCaptureFlag::CINSBotCaptureFlag(CINSBotCaptureFlag *this,CINSPlayer *param_1,int param_2)

{
  code *pcVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  CINSPathFollower *this_00;
  CINSPathFollower *this_01;
  int unaff_EBX;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(int *)param_1 = unaff_EBX + 0x481c3d;
  *(int *)(param_1 + 4) = unaff_EBX + 0x481dd1;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  param_1[0x30] = (CINSPlayer)0x0;
  param_1[0x31] = (CINSPlayer)0x0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  CINSPathFollower::CINSPathFollower(this_00);
  pcVar1 = (code *)(unaff_EBX + -0x4e3e5b);
  *(undefined4 *)(param_1 + 0x48b0) = 0;
  iVar2 = unaff_EBX + 0x413bed;
  *(int *)(param_1 + 0x48ac) = iVar2;
  (*pcVar1)(param_1 + 0x48ac,param_1 + 0x48b0);
  *(undefined4 *)(param_1 + 0x48b4) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48ac) + 4))(param_1 + 0x48ac,param_1 + 0x48b4);
  iVar4 = *(int *)(unaff_EBX + 0x492685);
  *(undefined4 *)(param_1 + 0x48cc) = 0xbf800000;
  *(int *)(param_1 + 0x48c8) = iVar4 + 8;
  (**(code **)(iVar4 + 0x10))(param_1 + 0x48c8,param_1 + 0x48cc);
  *(int *)(param_1 + 0x48d0) = iVar2;
  *(undefined4 *)(param_1 + 0x48d4) = 0;
  (*pcVar1)(param_1 + 0x48d0,param_1 + 0x48d4);
  *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48d0) + 4))(param_1 + 0x48d0,param_1 + 0x48d8);
  *(int *)(param_1 + 0x48dc) = iVar2;
  *(undefined4 *)(param_1 + 0x48e0) = 0;
  (*pcVar1)(param_1 + 0x48dc,param_1 + 0x48e0);
  *(undefined4 *)(param_1 + 0x48e4) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48dc) + 4))(param_1 + 0x48dc,param_1 + 0x48e4);
  *(int *)(param_1 + 0x48e8) = iVar2;
  *(undefined4 *)(param_1 + 0x48ec) = 0;
  (*pcVar1)(param_1 + 0x48e8,param_1 + 0x48ec);
  *(undefined4 *)(param_1 + 0x48f0) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(param_1 + 0x48e8,param_1 + 0x48f0);
  *(int *)(param_1 + 0x48f4) = iVar2;
  *(undefined4 *)(param_1 + 0x48f8) = 0;
  (*pcVar1)(param_1 + 0x48f4,param_1 + 0x48f8);
  *(undefined4 *)(param_1 + 0x48fc) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48f4) + 4))(param_1 + 0x48f4,param_1 + 0x48fc);
  CINSPathFollower::Invalidate(this_01);
  param_1[0x48c4] = (CINSPlayer)0x0;
  *(int *)(param_1 + 0x38) = in_stack_0000000c;
  puVar3 = (undefined4 *)(unaff_EBX + 0x5d7d55 + in_stack_0000000c * 4);
  if (param_2 != 0) {
    puVar5 = (undefined4 *)(**(code **)(*(int *)param_2 + 0xc))(param_2);
    *puVar3 = *puVar5;
    return;
  }
  *puVar3 = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::OnStart
 * Address: 007143c0
 * ---------------------------------------- */

/* CINSBotCaptureFlag::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotCaptureFlag::OnStart(CINSBotCaptureFlag *this,CINSNextBot *param_1,Action *param_2)

{
  CINSPathFollower *pCVar1;
  CINSNextBot *this_00;
  float10 fVar2;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar2 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this_00);
  *(float *)(param_2 + 0x4818) = (float)fVar2;
  fVar2 = (float10)CINSNextBot::MaxPathLength();
  pCVar1 = (CINSPathFollower *)0x0;
  if (in_stack_0000000c != 0) {
    pCVar1 = (CINSPathFollower *)(in_stack_0000000c + 0x2060);
  }
  CINSPathFollower::ComputePath
            ((CINSPathFollower *)(in_stack_0000000c + 0x2060),param_2 + 0x3c,pCVar1,param_2 + 0x48b8
             ,1,(float)fVar2,0,0x41f00000);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::Update
 * Address: 00714960
 * ---------------------------------------- */

/* CINSBotCaptureFlag::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotCaptureFlag::Update(CINSBotCaptureFlag *this,CINSNextBot *param_1,float param_2)

{
  float fVar1;
  CBaseEntity *pCVar2;
  undefined1 uVar3;
  char cVar4;
  int iVar5;
  CINSBotCaptureFlag *pCVar6;
  int *piVar7;
  CBaseEntity *this_00;
  CINSPathFollower *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_02;
  CINSNextBotManager *this_03;
  int unaff_EBX;
  bool bVar8;
  float10 fVar9;
  float fVar10;
  CINSBotCaptureFlag *in_stack_0000000c;
  int local_60;
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
  
  __i686_get_pc_thunk_bx();
  iVar5 = CBaseEntity::GetTeamNumber(this_00);
  if (1 < iVar5 - 2U) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26bc62;
    return param_1;
  }
  pCVar6 = (CINSBotCaptureFlag *)
           (**(code **)(*(int *)**(undefined4 **)(&DAT_00491f84 + unaff_EBX) + 0x334))
                     ((int *)**(undefined4 **)(&DAT_00491f84 + unaff_EBX),iVar5);
  bVar8 = pCVar6 != (CINSBotCaptureFlag *)0x0;
  if ((in_stack_0000000c != pCVar6) && (bVar8)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26be04;
    return param_1;
  }
  cVar4 = *(char *)((int)param_2 + 0x48c4);
  *(bool *)((int)param_2 + 0x48c4) = bVar8;
  if ((bVar8 != (bool)cVar4) && (*(int *)((int)param_2 + 0x48b4) != -0x40800000)) {
    (**(code **)(*(int *)((int)param_2 + 0x48ac) + 4))((int)param_2 + 0x48ac,(int)param_2 + 0x48b4);
    *(undefined4 *)((int)param_2 + 0x48b4) = 0xbf800000;
  }
  pCVar6 = (CINSBotCaptureFlag *)0x0;
  if (in_stack_0000000c != (CINSBotCaptureFlag *)0x0) {
    pCVar6 = in_stack_0000000c + 0x2060;
  }
  GetDesiredPosition(in_stack_0000000c,(INextBot *)&local_58);
  fVar10 = *(float *)(unaff_EBX + 0x214858);
  *(float *)((int)param_2 + 0x48b8) = local_58;
  *(float *)((int)param_2 + 0x48bc) = local_54;
  *(float *)((int)param_2 + 0x48c0) = local_50;
  if (((((fVar10 < local_58) && (fVar1 = *(float *)(unaff_EBX + 0x2106bc), local_58 < fVar1)) &&
       (fVar10 < local_54)) && ((local_54 < fVar1 && (fVar10 < local_50)))) && (local_50 < fVar1)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_0026bddb + unaff_EBX;
    return param_1;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x48b4) <= (float)fVar9 &&
      (float)fVar9 != *(float *)((int)param_2 + 0x48b4)) {
    fVar9 = (float10)RandomFloat(0x40a00000,0x40f00000,pCVar6);
    pCVar2 = (CBaseEntity *)(float)fVar9;
    fVar9 = (float10)CountdownTimer::Now();
    if (*(float *)((int)param_2 + 0x48b4) != (float)fVar9 + (float)pCVar2) {
      (**(code **)(*(int *)((int)param_2 + 0x48ac) + 4))
                ((int)param_2 + 0x48ac,(int)param_2 + 0x48b4);
      *(float *)((int)param_2 + 0x48b4) = (float)fVar9 + (float)pCVar2;
    }
    this_02 = *(CBaseEntity **)((int)param_2 + 0x48b0);
    if (this_02 != pCVar2) {
      (**(code **)(*(int *)((int)param_2 + 0x48ac) + 4))
                ((int)param_2 + 0x48ac,(int)param_2 + 0x48b0);
      *(CBaseEntity **)((int)param_2 + 0x48b0) = pCVar2;
      this_02 = extraout_ECX;
    }
    CBaseEntity::GetTeamNumber(this_02);
    iVar5 = TheINSNextBots();
    cVar4 = CINSNextBotManager::AreBotsOnTeamInCombat(this_03,iVar5);
    if (cVar4 != '\0') {
      fVar9 = (float10)CINSNextBot::MaxPathLength();
      pCVar6 = (CINSBotCaptureFlag *)0x0;
      if (in_stack_0000000c != (CINSBotCaptureFlag *)0x0) {
        pCVar6 = in_stack_0000000c + 0x2060;
      }
      CINSPathFollower::ComputePath
                ((CINSPathFollower *)((int)param_2 + 0x48b8),(int)param_2 + 0x3c,pCVar6,
                 (CINSPathFollower *)((int)param_2 + 0x48b8),1,(float)fVar9,0,0x41f00000);
    }
  }
  local_60 = (int)param_2 + 0x48b8;
  if (*(char *)((int)param_2 + 0x48c4) == '\0') {
    if ((*(char *)((int)param_2 + 0x48c5) != '\0') &&
       ((**(code **)(*(int *)in_stack_0000000c + 0x20c))(&local_4c,in_stack_0000000c),
       local_4c = local_4c - *(float *)((int)param_2 + 0x48b8),
       local_48 = local_48 - *(float *)((int)param_2 + 0x48bc),
       local_44 = local_44 - *(float *)((int)param_2 + 0x48c0),
       SQRT(local_48 * local_48 + local_4c * local_4c + local_44 * local_44) <
       *(float *)(unaff_EBX + 0x238570))) {
      piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
      (**(code **)(*piVar7 + 0xd4))(piVar7,local_60,5,0x3f800000,0,unaff_EBX + 0x26bdec);
      (**(code **)(*(int *)in_stack_0000000c + 0x20c))(&local_34,in_stack_0000000c);
      local_40 = *(float *)((int)param_2 + 0x48b8) - local_34;
      local_3c = *(float *)((int)param_2 + 0x48bc) - local_30;
      local_38 = *(float *)((int)param_2 + 0x48c0) - local_2c;
      VectorNormalize((Vector *)&local_40);
      fVar9 = (float10)CountdownTimer::Now();
      if ((*(float *)((int)param_2 + 0x48fc) <= (float)fVar9 &&
           (float)fVar9 != *(float *)((int)param_2 + 0x48fc)) &&
         ((**(code **)(*(int *)in_stack_0000000c + 0x20c))(&local_28,in_stack_0000000c),
         fVar10 = local_24 * local_3c + local_28 * local_40 + local_20 * local_38,
         *(float *)(unaff_EBX + 0x210694) <= fVar10 && fVar10 != *(float *)(unaff_EBX + 0x210694)))
      {
        (**(code **)(*(int *)in_stack_0000000c + 0x8d8))(in_stack_0000000c,0x3f000000);
        fVar9 = (float10)CountdownTimer::Now();
        fVar10 = (float)fVar9 + *(float *)(unaff_EBX + 0x1a41a0);
        if (*(float *)((int)param_2 + 0x48fc) != fVar10) {
          (**(code **)(*(int *)((int)param_2 + 0x48f4) + 4))
                    ((int)param_2 + 0x48f4,(int)param_2 + 0x48fc);
          *(float *)((int)param_2 + 0x48fc) = fVar10;
        }
        if (*(int *)((int)param_2 + 0x48f8) != 0x3f800000) {
          (**(code **)(*(int *)((int)param_2 + 0x48f4) + 4))
                    ((int)param_2 + 0x48f4,(int)param_2 + 0x48f8);
          *(undefined4 *)((int)param_2 + 0x48f8) = 0x3f800000;
        }
      }
      goto LAB_00714b53;
    }
    iVar5 = *(int *)in_stack_0000000c;
  }
  else {
    iVar5 = *(int *)in_stack_0000000c;
  }
  uVar3 = (**(code **)(iVar5 + 0x444))(in_stack_0000000c,local_60,1,0);
  *(undefined1 *)((int)param_2 + 0x48c5) = uVar3;
  CINSPathFollower::Update(this_01,(INextBot *)((int)param_2 + 0x3c));
LAB_00714b53:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::OnEnd
 * Address: 00714510
 * ---------------------------------------- */

/* CINSBotCaptureFlag::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotCaptureFlag::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(undefined4 *)(extraout_ECX + 0x5d7e0b + *(int *)(param_1 + 0x38) * 4) = 0xffffffff;
  *(undefined4 *)(extraout_ECX + 0x5d7e0b + *(int *)(param_1 + 0x38) * 4) = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::GetName
 * Address: 00714f10
 * ---------------------------------------- */

/* CINSBotCaptureFlag::GetName() const */

int CINSBotCaptureFlag::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x26b82b;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::ShouldHurry
 * Address: 007142f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureFlag::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotCaptureFlag::ShouldHurry(CINSBotCaptureFlag *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::ShouldHurry
 * Address: 00714300
 * ---------------------------------------- */

/* CINSBotCaptureFlag::ShouldHurry(INextBot const*) const */

int __cdecl CINSBotCaptureFlag::ShouldHurry(INextBot *param_1)

{
  return 2 - (uint)(param_1[0x48c5] == (INextBot)0x0);
}



/* ----------------------------------------
 * CINSBotCaptureFlag::OnMoveToSuccess
 * Address: 00714320
 * ---------------------------------------- */

/* CINSBotCaptureFlag::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotCaptureFlag::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x48cc) != (float)fVar1) {
    (**(code **)(*(int *)(param_2 + 0x48c8) + 8))(param_2 + 0x48c8,param_2 + 0x48cc);
    *(float *)(param_2 + 0x48cc) = (float)fVar1;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::GetDesiredPosition
 * Address: 00714880
 * ---------------------------------------- */

/* CINSBotCaptureFlag::GetDesiredPosition(INextBot const*) */

INextBot * __thiscall
CINSBotCaptureFlag::GetDesiredPosition(CINSBotCaptureFlag *this,INextBot *param_1)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 *puVar4;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (*(char *)(in_stack_00000008 + 0x48c4) != '\0') {
    iVar2 = (uint)(*(int *)(in_stack_00000008 + 0x38) == 0) * 0xc + **(int **)(unaff_EBX + 0x492492)
    ;
    *(undefined4 *)param_1 = *(undefined4 *)(iVar2 + 0x5d0);
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(iVar2 + 0x5d4);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0x5d8);
    return param_1;
  }
  uVar1 = *(uint *)(**(int **)(unaff_EBX + 0x492492) + 0x7cc +
                   *(int *)(in_stack_00000008 + 0x38) * 4);
  if (uVar1 != 0xffffffff) {
    iVar2 = (uVar1 & 0xffff) * 0x18 + *(int *)*(CPoint_ControlPoint **)(&DAT_00491f4e + unaff_EBX);
    if ((*(uint *)(iVar2 + 8) == uVar1 >> 0x10) && (*(int *)(iVar2 + 4) != 0)) {
      piVar3 = (int *)CPoint_ControlPoint::GetAssociatedObject
                                (*(CPoint_ControlPoint **)(&DAT_00491f4e + unaff_EBX));
      if (piVar3 != (int *)0x0) {
        puVar4 = (undefined4 *)(**(code **)(*piVar3 + 0x260))(piVar3);
        goto LAB_00714936;
      }
    }
  }
  puVar4 = *(undefined4 **)(unaff_EBX + 0x491d42);
LAB_00714936:
  *(undefined4 *)param_1 = *puVar4;
  *(undefined4 *)(param_1 + 4) = puVar4[1];
  *(undefined4 *)(param_1 + 8) = puVar4[2];
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::~CINSBotCaptureFlag
 * Address: 00714f30
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureFlag::~CINSBotCaptureFlag() */

void __thiscall CINSBotCaptureFlag::~CINSBotCaptureFlag(CINSBotCaptureFlag *this)

{
  ~CINSBotCaptureFlag(this);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::~CINSBotCaptureFlag
 * Address: 00714f40
 * ---------------------------------------- */

/* CINSBotCaptureFlag::~CINSBotCaptureFlag() */

void __thiscall CINSBotCaptureFlag::~CINSBotCaptureFlag(CINSBotCaptureFlag *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4812ba;
  in_stack_00000004[1] = unaff_EBX + 0x48144e;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::~CINSBotCaptureFlag
 * Address: 00714fa0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureFlag::~CINSBotCaptureFlag() */

void __thiscall CINSBotCaptureFlag::~CINSBotCaptureFlag(CINSBotCaptureFlag *this)

{
  ~CINSBotCaptureFlag(this);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureFlag::~CINSBotCaptureFlag
 * Address: 00714fb0
 * ---------------------------------------- */

/* CINSBotCaptureFlag::~CINSBotCaptureFlag() */

void __thiscall CINSBotCaptureFlag::~CINSBotCaptureFlag(CINSBotCaptureFlag *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x48124a;
  in_stack_00000004[1] = unaff_EBX + 0x4813de;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



