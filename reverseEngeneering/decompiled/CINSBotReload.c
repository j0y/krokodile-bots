/*
 * CINSBotReload -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 8
 */

/* ----------------------------------------
 * CINSBotReload::CINSBotReload
 * Address: 007179b0
 * ---------------------------------------- */

/* CINSBotReload::CINSBotReload() */

void __thiscall CINSBotReload::CINSBotReload(CINSBotReload *this)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  in_stack_00000004[8] = 0;
  iVar3 = *(int *)(&DAT_0048f03d + unaff_EBX);
  iVar1 = unaff_EBX + 0x4107fd;
  *(undefined1 *)(in_stack_00000004 + 0xc) = 0;
  in_stack_00000004[9] = 0;
  in_stack_00000004[10] = 0;
  in_stack_00000004[3] = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x31) = 0;
  in_stack_00000004[1] = iVar3 + 0x198;
  *in_stack_00000004 = iVar3 + 8;
  pcVar2 = (code *)(unaff_EBX + -0x4e724b);
  in_stack_00000004[4] = 0;
  in_stack_00000004[5] = 0;
  in_stack_00000004[6] = 0;
  in_stack_00000004[7] = 0;
  in_stack_00000004[2] = 0;
  in_stack_00000004[0xb] = 0;
  in_stack_00000004[0xd] = 0;
  in_stack_00000004[0xe] = iVar1;
  in_stack_00000004[0xf] = 0;
  (*pcVar2)(in_stack_00000004 + 0xe,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000;
  (**(code **)(in_stack_00000004[0xe] + 4))(in_stack_00000004 + 0xe,in_stack_00000004 + 0x10);
  in_stack_00000004[0x11] = iVar1;
  in_stack_00000004[0x12] = 0;
  (*pcVar2)(in_stack_00000004 + 0x11,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = -0x40800000;
  (**(code **)(in_stack_00000004[0x11] + 4))(in_stack_00000004 + 0x11,in_stack_00000004 + 0x13);
  in_stack_00000004[0x14] = iVar1;
  in_stack_00000004[0x15] = 0;
  (*pcVar2)(in_stack_00000004 + 0x14,in_stack_00000004 + 0x15);
  in_stack_00000004[0x16] = -0x40800000;
  (**(code **)(in_stack_00000004[0x14] + 4))(in_stack_00000004 + 0x14,in_stack_00000004 + 0x16);
  return;
}



/* ----------------------------------------
 * CINSBotReload::OnStart
 * Address: 0072a9f0
 * ---------------------------------------- */

/* CINSBotReload::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotReload::OnStart(CINSBotReload *this,CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  float fVar4;
  int *piVar5;
  CINSNextBot *this_00;
  CINSPlayer *extraout_ECX;
  CINSPlayer *this_01;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_02;
  CINSBotBody *this_03;
  CINSNextBot *this_04;
  CINSPlayer *extraout_ECX_01;
  CINSPlayer *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar6;
  CBaseEntity *in_stack_0000000c;
  undefined4 uVar7;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSNextBot::CheckAnyAmmo(this_00);
  if (cVar1 == '\0') {
    *(undefined4 *)param_1 = 3;
    *(int *)(param_1 + 8) = unaff_EBX + 0x256d5f;
    *(undefined4 *)(param_1 + 4) = 0;
    return param_1;
  }
  (**(code **)(*(int *)in_stack_0000000c + 0x96c))(in_stack_0000000c);
  uVar7 = 0xd;
  CINSBotLocomotion::ClearMovementRequests();
  if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
     (iVar3 = UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)), iVar3 == 0)) {
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c,uVar7);
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0))(piVar5,0);
    if ((piVar5 != (int *)0x0) && (iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5), iVar3 != 0))
    goto LAB_0072aa7a;
  }
  else {
LAB_0072aa7a:
    if ((*(int *)(in_stack_0000000c + 0xb338) == -1) ||
       (fVar4 = (float)UTIL_EntityByIndex(*(int *)(in_stack_0000000c + 0xb338)),
       this_01 = extraout_ECX, fVar4 == 0.0)) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
      piVar5 = (int *)(**(code **)(*piVar5 + 0xd0))(piVar5,0);
      fVar4 = 0.0;
      this_01 = extraout_ECX_01;
      if (piVar5 != (int *)0x0) {
        fVar4 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
        this_01 = extraout_ECX_02;
      }
    }
    uVar7 = 0x3f4ccccd;
    cVar1 = CINSPlayer::IsThreatAimingTowardMe(this_01,in_stack_0000000c,fVar4);
    if (cVar1 != '\0') {
      RandomFloat(0x40000000,0x40800000,uVar7);
      (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
      CINSBotBody::SetPosture();
      this_02 = extraout_ECX_03;
      goto LAB_0072ab00;
    }
  }
  RandomFloat(0x40000000,0x40800000);
  (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
  CINSBotBody::SetPosture();
  this_02 = extraout_ECX_00;
LAB_0072ab00:
  CINSNextBot::BotSpeakConceptIfAllowed
            (this_02,(int)in_stack_0000000c,(char *)0x40,(char *)0x0,0,(IRecipientFilter *)0x0);
  bVar2 = (bool)(**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
  CINSBotBody::CheckBadViewTarget(this_03,bVar2);
  CINSNextBot::ResetIdleStatus(this_04);
  (**(code **)(*(int *)in_stack_0000000c + 0x8e0))(in_stack_0000000c,0x3f800000);
  fVar6 = (float10)CountdownTimer::Now();
  fVar4 = (float)fVar6 + *(float *)(unaff_EBX + 0x1f9d5d);
  if (*(float *)(param_2 + 0x58) != fVar4) {
    (**(code **)(*(int *)(param_2 + 0x50) + 4))(param_2 + 0x50,param_2 + 0x58);
    *(float *)(param_2 + 0x58) = fVar4;
  }
  if (*(int *)(param_2 + 0x54) != 0x3f000000) {
    (**(code **)(*(int *)(param_2 + 0x50) + 4))(param_2 + 0x50,param_2 + 0x54);
    *(undefined4 *)(param_2 + 0x54) = 0x3f000000;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotReload::Update
 * Address: 0072acd0
 * ---------------------------------------- */

/* CINSBotReload::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotReload::Update(CINSBotReload *this,CINSNextBot *param_1,float param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSNextBot::IsIdle(this_00);
  if (cVar1 != '\0') {
    fVar4 = (float10)CINSNextBot::GetIdleDuration(this_01);
    if ((*(float *)(unaff_EBX + 0x1fc0cf) < (float)fVar4) &&
       (*(float *)(unaff_EBX + 0x1fc0cf) <
        *(float *)(**(int **)(&LAB_0047bbbf + unaff_EBX) + 0xc) - *(float *)((int)param_2 + 0x34)))
    {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined **)(param_1 + 8) = &UNK_00256abc + unaff_EBX;
      return param_1;
    }
  }
  fVar4 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x58) <= (float)fVar4 &&
      (float)fVar4 != *(float *)((int)param_2 + 0x58)) {
    piVar2 = (int *)CINSPlayer::GetActiveINSWeapon();
    if (piVar2 == (int *)0x0) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(undefined **)(param_1 + 8) = &UNK_00256acb + unaff_EBX;
      return param_1;
    }
    cVar1 = (**(code **)(*piVar2 + 0x648))(piVar2);
    if (cVar1 == '\0') {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x256ad6;
      return param_1;
    }
    cVar1 = CINSPlayer::IsProned(this_02);
    if ((cVar1 == '\0') || (cVar1 = CINSPlayer::IsCrouched(this_03), cVar1 == '\0')) {
      piVar2 = (int *)(**(code **)(*in_stack_0000000c + 0x974))(in_stack_0000000c);
      iVar3 = (**(code **)(*piVar2 + 0xd0))(piVar2,0);
      if (iVar3 == 0) {
        (**(code **)(*in_stack_0000000c + 0x970))(in_stack_0000000c);
        CINSBotBody::SetPosture();
      }
      else {
        (**(code **)(*in_stack_0000000c + 0x970))();
        CINSBotBody::SetPosture();
      }
    }
    fVar4 = (float10)CountdownTimer::Now();
    fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x1f8dab);
    if (*(float *)((int)param_2 + 0x58) != fVar5) {
      (**(code **)(*(int *)((int)param_2 + 0x50) + 4))((int)param_2 + 0x50,(int)param_2 + 0x58);
      *(float *)((int)param_2 + 0x58) = fVar5;
    }
    if (*(int *)((int)param_2 + 0x54) != 0x3e800000) {
      (**(code **)(*(int *)((int)param_2 + 0x50) + 4))((int)param_2 + 0x50,(int)param_2 + 0x54);
      *(undefined4 *)((int)param_2 + 0x54) = 0x3e800000;
    }
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotReload::GetName
 * Address: 0072afb0
 * ---------------------------------------- */

/* CINSBotReload::GetName() const */

int CINSBotReload::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x25679b;
}



/* ----------------------------------------
 * CINSBotReload::~CINSBotReload
 * Address: 0072afd0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotReload::~CINSBotReload() */

void __thiscall CINSBotReload::~CINSBotReload(CINSBotReload *this)

{
  ~CINSBotReload(this);
  return;
}



/* ----------------------------------------
 * CINSBotReload::~CINSBotReload
 * Address: 0072afe0
 * ---------------------------------------- */

/* CINSBotReload::~CINSBotReload() */

void __thiscall CINSBotReload::~CINSBotReload(CINSBotReload *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x46cd63;
  in_stack_00000004[1] = extraout_ECX + 0x46cef3;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x47c193));
  return;
}



/* ----------------------------------------
 * CINSBotReload::~CINSBotReload
 * Address: 0072b010
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotReload::~CINSBotReload() */

void __thiscall CINSBotReload::~CINSBotReload(CINSBotReload *this)

{
  ~CINSBotReload(this);
  return;
}



/* ----------------------------------------
 * CINSBotReload::~CINSBotReload
 * Address: 0072b020
 * ---------------------------------------- */

/* CINSBotReload::~CINSBotReload() */

void __thiscall CINSBotReload::~CINSBotReload(CINSBotReload *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46cd1a;
  in_stack_00000004[1] = unaff_EBX + 0x46ceaa;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



