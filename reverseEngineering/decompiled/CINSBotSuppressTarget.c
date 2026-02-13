/*
 * CINSBotSuppressTarget -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotSuppressTarget::CINSBotSuppressTarget
 * Address: 00733170
 * ---------------------------------------- */

/* CINSBotSuppressTarget::CINSBotSuppressTarget(Vector, CBaseEntity*) */

void __thiscall
CINSBotSuppressTarget::CINSBotSuppressTarget
          (undefined4 param_1,int *param_2,int param_3,int param_4,float param_5,int *param_6)

{
  int iVar1;
  code *pcVar2;
  float fVar3;
  int *piVar4;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  param_2[8] = 0;
  param_2[9] = 0;
  *param_2 = unaff_EBX + 0x46576d /* vtable for CINSBotSuppressTarget+0x8 */ /* vtable for CINSBotSuppressTarget+0x8 */;
  param_2[1] = unaff_EBX + 0x465905 /* vtable for CINSBotSuppressTarget+0x1a0 */ /* vtable for CINSBotSuppressTarget+0x1a0 */;
  iVar1 = unaff_EBX + 0x3f503d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  param_2[10] = 0;
  param_2[3] = 0;
  pcVar2 = (code *)(unaff_EBX + -0x502a0b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  param_2[4] = 0;
  param_2[5] = 0;
  param_2[6] = 0;
  param_2[7] = 0;
  param_2[2] = 0;
  *(undefined1 *)(param_2 + 0xc) = 0;
  *(undefined1 *)((int)param_2 + 0x31) = 0;
  param_2[0xb] = 0;
  param_2[0xd] = 0;
  param_2[0xe] = -1;
  param_2[0x15] = iVar1; /* CountdownTimer timer_0 */
  param_2[0x16] = 0;
  (*pcVar2)(param_2 + 0x15,param_2 + 0x16);
  param_2[0x17] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x15] + 4))(param_2 + 0x15,param_2 + 0x17); /* timer_0.NetworkStateChanged() */
  param_2[0x18] = iVar1; /* CountdownTimer timer_1 */
  param_2[0x19] = 0;
  (*pcVar2)(param_2 + 0x18,param_2 + 0x19);
  param_2[0x1a] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x18] + 4))(param_2 + 0x18,param_2 + 0x1a); /* timer_1.NetworkStateChanged() */
  param_2[0x1b] = iVar1; /* CountdownTimer timer_2 */
  param_2[0x1c] = 0;
  (*pcVar2)(param_2 + 0x1b,param_2 + 0x1c);
  param_2[0x1d] = -0x40800000 /* -1.0f */; /* timer_2.m_timestamp = -1 (not running) */
  (**(code **)(param_2[0x1b] + 4))(param_2 + 0x1b,param_2 + 0x1d); /* timer_2.NetworkStateChanged() */
  if (param_6 == (int *)0x0) {
    param_2[0xe] = -1;
  }
  else {
    piVar4 = (int *)(**(code **)(*param_6 + 0xc))(param_6);
    param_2[0xe] = *piVar4;
  }
  fVar3 = *(float *)(unaff_EBX + 0x24ed9d /* 56.0f */ /* 56.0f */);
  param_2[0xf] = param_3;
  param_2[0x11] = (int)(fVar3 + param_5);
  param_2[0x10] = param_4;
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::OnStart
 * Address: 007329f0
 * ---------------------------------------- */

/* CINSBotSuppressTarget::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotSuppressTarget::OnStart(CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  float10 fVar2;
  
  __i686_get_pc_thunk_bx();
  fVar2 = (float10)RandomFloat(0x40400000 /* 3.0f */,0x40c00000 /* 6.0f */);
  fVar1 = (float)fVar2;
  fVar2 = (float10)CountdownTimer::Now();
  if (*(float *)(param_2 + 0x5c) != (float)fVar2 + fVar1) {
    (**(code **)(*(int *)(param_2 + 0x54) + 4))(param_2 + 0x54,param_2 + 0x5c); /* timer_0.NetworkStateChanged() */
    *(float *)(param_2 + 0x5c) = (float)fVar2 + fVar1; /* timer_0.Start(...) */
  }
  if (*(float *)(param_2 + 0x58) != fVar1) {
    (**(code **)(*(int *)(param_2 + 0x54) + 4))(param_2 + 0x54,param_2 + 0x58); /* timer_0.NetworkStateChanged() */
    *(float *)(param_2 + 0x58) = fVar1; /* timer_0.m_duration */
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::Update
 * Address: 00732ac0
 * ---------------------------------------- */

/* CINSBotSuppressTarget::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotSuppressTarget::Update(CINSBotSuppressTarget *this,CINSNextBot *param_1,float param_2)

{
  uint uVar1;
  code *pcVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  int *piVar6;
  float *pfVar7;
  CINSNextBot *this_00;
  CINSNextBot *this_01;
  int iVar8;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  double dVar14;
  int *in_stack_0000000c;
  float local_70;
  float local_6c;
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
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
  piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))();
  if (((piVar6 != (int *)0x0) && (cVar5 = (**(code **)(*piVar6 + 0x38 /* CBaseAnimating::TestCollision */))(), cVar5 != '\0')) &&
     (fVar9 = (float10)(**(code **)(*piVar6 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(),
     *(float *)(unaff_EBX + 0x18603d /* 1.0f */ /* 1.0f */) <= (float)fVar9 &&
     (float)fVar9 != *(float *)(unaff_EBX + 0x18603d /* 1.0f */ /* 1.0f */))) {
    piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))();
    iVar8 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))();
    if (iVar8 != 0) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24f3fd /* "Spotted a threat while suppressing." */ /* "Spotted a threat while suppressing." */;
      return param_1;
    }
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < *(float *)((int)param_2 + 0x5c) || /* !timer_0.IsElapsed() */
      (float)fVar9 == *(float *)((int)param_2 + 0x5c)) {
    cVar5 = CINSNextBot::IsIdle(this_00);
    if ((cVar5 == '\0') ||
       (fVar9 = (float10)CINSNextBot::GetIdleDuration(this_01),
       (float)fVar9 < *(float *)(unaff_EBX + 0x1f1c95 /* 5.0f */ /* 5.0f */) ||
       (float)fVar9 == *(float *)(unaff_EBX + 0x1f1c95 /* 5.0f */ /* 5.0f */))) {
      piVar6 = (int *)CINSPlayer::GetActiveINSWeapon();
      if (piVar6 == (int *)0x0) {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24f3aa /* "Failed to init weapon entity" */ /* "Failed to init weapon entity" */;
      }
      else {
        cVar5 = (**(code **)(*piVar6 + 0x740 /* CINSPlayer::CanSpeak */))();
        if (cVar5 == '\0') {
          uVar1 = *(uint *)((int)param_2 + 0x38);
          if (((uVar1 != 0xffffffff) &&
              (iVar8 = (uVar1 & 0xffff) * 0x18 + **(int **)(unaff_EBX + 0x473d01 /* &g_pEntityList */ /* &g_pEntityList */),
              *(uint *)(iVar8 + 8) == uVar1 >> 0x10)) && (*(int *)(iVar8 + 4) != 0)) {
            piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))();
            (**(code **)(*piVar6 + 0xe4 /* IVision::GetKnown */))();
          }
          (**(code **)(*in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))();
          local_70 = *(float *)((int)param_2 + 0x3c) - local_64;
          local_6c = *(float *)((int)param_2 + 0x40) - local_60;
          local_68 = *(float *)((int)param_2 + 0x44) - local_5c;
          VectorVectors((Vector *)&local_70,(Vector *)&local_58,(Vector *)&local_4c);
          fVar13 = *(float *)(**(int **)(unaff_EBX + 0x473dc9 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
          local_40 = *(float *)((int)param_2 + 0x3c);
          local_3c = *(float *)((int)param_2 + 0x40);
          local_38 = *(float *)((int)param_2 + 0x44);
          dVar14 = sin((double)(*(float *)(unaff_EBX + 0x24f43d /* 3.5f */ /* 3.5f */) * fVar13));
          fVar4 = local_38;
          fVar3 = local_3c;
          fVar12 = (float)(dVar14 * *(double *)(unaff_EBX + 0x24f449 /* 0.0f */ /* 0.0f */));
          fVar10 = local_54 * fVar12;
          fVar11 = local_50 * fVar12;
          dVar14 = cos((double)(fVar13 * *(float *)(&DAT_001f0fb9 + unaff_EBX)));
          fVar13 = (float)(dVar14 * *(double *)(unaff_EBX + 0x24f451 /* 0.0f */ /* 0.0f */));
          local_3c = local_48 * fVar13 + fVar10 + fVar3;
          local_38 = local_44 * fVar13 + fVar11 + fVar4;
          local_40 = fVar12 * local_58 + fVar13 * local_4c + local_40;
          fVar9 = (float10)RandomFloat(0xc0a00000 /* -5.0f */,0x40a00000 /* 5.0f */);
          fVar13 = (float)fVar9;
          local_3c = local_54 * fVar13 + local_3c;
          local_38 = local_50 * fVar13 + local_38;
          local_40 = fVar13 * local_58 + local_40;
          fVar9 = (float10)RandomFloat(0xc0a00000 /* -5.0f */,0x40a00000 /* 5.0f */);
          fVar13 = (float)fVar9;
          local_3c = local_48 * fVar13 + local_3c;
          local_38 = local_44 * fVar13 + local_38;
          local_40 = fVar13 * local_4c + local_40;
          piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
          (**(code **)(*piVar6 + 0xd4 /* PlayerBody::AimHeadTowards */))(piVar6,&local_40,3,0x3dcccccd /* 0.1f */,0,unaff_EBX + 0x24f3e2 /* "Aiming at suppression area" */ /* "Aiming at suppression area" */);
          (**(code **)(*in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_28);
          local_34 = local_40 - local_28;
          local_30 = local_3c - local_24;
          local_2c = local_38 - local_20;
          fVar9 = (float10)VectorNormalize((Vector *)&local_34);
          dVar14 = atan((double)(*(float *)(&DAT_001f0fbd + unaff_EBX) / (float)fVar9));
          dVar14 = cos(dVar14);
          piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
          pfVar7 = (float *)(**(code **)(*piVar6 + 0xd0 /* CINSBotBody::GetViewVector */))(piVar6);
          if ((float)dVar14 <= pfVar7[1] * local_30 + *pfVar7 * local_34 + pfVar7[2] * local_2c) {
            pcVar2 = *(code **)(*in_stack_0000000c + 0x8c0);
            RandomFloat(0x3dcccccd /* 0.1f */,0x3eb33333 /* 0.35f */);
            (*pcVar2)();
          }
          *(undefined4 *)param_1 = 0 /* Continue */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(undefined4 *)(param_1 + 8) = 0;
        }
        else {
          *(undefined4 *)param_1 = 3 /* Done */;
          *(undefined4 *)(param_1 + 4) = 0;
          *(int *)(param_1 + 8) = unaff_EBX + 0x24f3c7 /* "Our weapon is out of ammo." */ /* "Our weapon is out of ammo." */;
        }
      }
    }
    else {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24f399 /* "Idle in suppress" */ /* "Idle in suppress" */;
    }
  }
  else {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24f381 /* "We're done suppressing." */ /* "We're done suppressing." */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::GetName
 * Address: 00733310
 * ---------------------------------------- */

/* CINSBotSuppressTarget::GetName() const */

int CINSBotSuppressTarget::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x24eb37 /* "Suppressing" */ /* "Suppressing" */;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::ShouldAttack
 * Address: 00732830
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSuppressTarget::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotSuppressTarget::ShouldAttack
          (CINSBotSuppressTarget *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::ShouldAttack
 * Address: 00732840
 * ---------------------------------------- */

/* CINSBotSuppressTarget::ShouldAttack(INextBot const*, CKnownEntity const*) const */

int __cdecl CINSBotSuppressTarget::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  CBaseEntity *pCVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_01;
  CINSPlayer *this_02;
  int *piVar5;
  int unaff_EBX;
  float fVar6;
  float fVar7;
  float fVar8;
  undefined8 uVar9;
  
  uVar9 = __i686_get_pc_thunk_bx();
  piVar5 = (int *)((ulonglong)uVar9 >> 0x20);
  iVar3 = (int)uVar9;
  pCVar1 = *(CBaseEntity **)(param_1 + 0x1c);
  if (pCVar1 != (CBaseEntity *)0x0) {
    iVar3 = (**(code **)(*piVar5 + 0x10))(piVar5);
    if ((*(byte *)(iVar3 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    fVar8 = *(float *)(param_1 + 0x3c) - *(float *)(iVar3 + 0x208);
    fVar6 = *(float *)(param_1 + 0x40) - *(float *)(iVar3 + 0x20c);
    fVar7 = *(float *)(param_1 + 0x44) - *(float *)(iVar3 + 0x210);
    iVar3 = 0;
    if (*(float *)(unaff_EBX + 0x24f6b4 /* 114.0f */ /* 114.0f */) <= SQRT(fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7)) {
      iVar4 = (**(code **)(*piVar5 + 0x10))(piVar5);
      iVar3 = 1;
      if (iVar4 != 0) {
        this_01 = this_00;
        if ((*(byte *)(iVar4 + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_00);
          this_01 = extraout_ECX;
        }
        if (((byte)pCVar1[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_01);
        }
        iVar3 = 0;
        fVar8 = *(float *)(pCVar1 + 0x208) - *(float *)(iVar4 + 0x208);
        fVar6 = *(float *)(pCVar1 + 0x20c) - *(float *)(iVar4 + 0x20c);
        fVar7 = *(float *)(pCVar1 + 0x210) - *(float *)(iVar4 + 0x210);
        fVar6 = SQRT(fVar6 * fVar6 + fVar8 * fVar8 + fVar7 * fVar7);
        if ((fVar6 < *(float *)(unaff_EBX + 0x21943c /* 2000.0f */ /* 2000.0f */) || fVar6 == *(float *)(unaff_EBX + 0x21943c /* 2000.0f */ /* 2000.0f */))
           && (iVar3 = 1, *(float *)(unaff_EBX + 0x1fae28 /* 500.0f */ /* 500.0f */) <= fVar6)) {
          fVar6 = (float)(**(code **)(*piVar5 + 0x10))(piVar5);
          cVar2 = CINSPlayer::IsThreatAimingTowardMe(this_02,pCVar1,fVar6);
          iVar3 = ~-(uint)(cVar2 == '\0') + 2;
        }
      }
    }
  }
  return iVar3;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::ShouldIronsight
 * Address: 00732760
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSuppressTarget::ShouldIronsight(INextBot const*) const */

void __thiscall
CINSBotSuppressTarget::ShouldIronsight(CINSBotSuppressTarget *this,INextBot *param_1)

{
  ShouldIronsight(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::ShouldIronsight
 * Address: 00732770
 * ---------------------------------------- */

/* CINSBotSuppressTarget::ShouldIronsight(INextBot const*) const */

char __thiscall
CINSBotSuppressTarget::ShouldIronsight(CINSBotSuppressTarget *this,INextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  char cVar3;
  float fVar4;
  int *in_stack_00000008;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  cVar3 = '\x02';
  if (in_stack_00000008 != (int *)0x0) {
    iVar1 = (**(code **)(*in_stack_00000008 + 200))();
    if (iVar1 != 0) {
      piVar2 = (int *)(**(code **)(*in_stack_00000008 + 200))();
      (**(code **)(*piVar2 + 0x20c /* CINSNextBot::EyePosition */))(&local_28,piVar2);
      fVar4 = SQRT((*(float *)(param_1 + 0x40) - local_24) * (*(float *)(param_1 + 0x40) - local_24)
                   + (*(float *)(param_1 + 0x3c) - local_28) *
                     (*(float *)(param_1 + 0x3c) - local_28) +
                   (*(float *)(param_1 + 0x44) - local_20) * (*(float *)(param_1 + 0x44) - local_20)
                  );
      cVar3 = (fVar4 < *(float *)(&LAB_00209a0c + unaff_EBX) ||
              fVar4 == *(float *)(&LAB_00209a0c + unaff_EBX)) + '\x01';
    }
  }
  return cVar3;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::~CINSBotSuppressTarget
 * Address: 00733330
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSuppressTarget::~CINSBotSuppressTarget() */

void __thiscall CINSBotSuppressTarget::~CINSBotSuppressTarget(CINSBotSuppressTarget *this)

{
  ~CINSBotSuppressTarget(this);
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::~CINSBotSuppressTarget
 * Address: 00733340
 * ---------------------------------------- */

/* CINSBotSuppressTarget::~CINSBotSuppressTarget() */

void __thiscall CINSBotSuppressTarget::~CINSBotSuppressTarget(CINSBotSuppressTarget *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4655a3 /* vtable for CINSBotSuppressTarget+0x8 */ /* vtable for CINSBotSuppressTarget+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x46573b /* vtable for CINSBotSuppressTarget+0x1a0 */ /* vtable for CINSBotSuppressTarget+0x1a0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x473e33 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::~CINSBotSuppressTarget
 * Address: 00733370
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotSuppressTarget::~CINSBotSuppressTarget() */

void __thiscall CINSBotSuppressTarget::~CINSBotSuppressTarget(CINSBotSuppressTarget *this)

{
  ~CINSBotSuppressTarget(this);
  return;
}



/* ----------------------------------------
 * CINSBotSuppressTarget::~CINSBotSuppressTarget
 * Address: 00733380
 * ---------------------------------------- */

/* CINSBotSuppressTarget::~CINSBotSuppressTarget() */

void __thiscall CINSBotSuppressTarget::~CINSBotSuppressTarget(CINSBotSuppressTarget *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46555a /* vtable for CINSBotSuppressTarget+0x8 */ /* vtable for CINSBotSuppressTarget+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4656f2 /* vtable for CINSBotSuppressTarget+0x1a0 */ /* vtable for CINSBotSuppressTarget+0x1a0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



