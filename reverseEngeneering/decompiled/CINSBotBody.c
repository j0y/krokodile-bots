/*
 * CINSBotBody -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 40
 */

/* ----------------------------------------
 * CINSBotBody::CINSBotBody
 * Address: 007553b0
 * ---------------------------------------- */

/* CINSBotBody::CINSBotBody(INextBot*) */

void __thiscall CINSBotBody::CINSBotBody(CINSBotBody *this,INextBot *param_1)

{
  int iVar1;
  code *pcVar2;
  PlayerBody *this_00;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  iVar1 = unaff_EBX + 0x3d2dfd;
  PlayerBody::PlayerBody(this_00,param_1);
  *(int *)(param_1 + 0xd0) = iVar1;
  *(int *)param_1 = unaff_EBX + 0x447aed;
  *(undefined4 *)(param_1 + 0xd4) = 0;
  pcVar2 = (code *)(unaff_EBX + -0x524c4b);
  (*pcVar2)(param_1 + 0xd0,param_1 + 0xd4);
  *(undefined4 *)(param_1 + 0xd8) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0xd0) + 4))(param_1 + 0xd0,param_1 + 0xd8);
  *(int *)(param_1 + 0xdc) = iVar1;
  *(undefined4 *)(param_1 + 0xe0) = 0;
  (*pcVar2)(param_1 + 0xdc,param_1 + 0xe0);
  *(undefined4 *)(param_1 + 0xe4) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0xdc) + 4))(param_1 + 0xdc,param_1 + 0xe4);
  *(int *)(param_1 + 0xe8) = iVar1;
  *(undefined4 *)(param_1 + 0xec) = 0;
  (*pcVar2)(param_1 + 0xe8,param_1 + 0xec);
  *(undefined4 *)(param_1 + 0xf0) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0xe8) + 4))(param_1 + 0xe8,param_1 + 0xf0);
  *(int *)(param_1 + 0xf4) = iVar1;
  *(undefined4 *)(param_1 + 0xf8) = 0;
  (*pcVar2)(param_1 + 0xf4,param_1 + 0xf8);
  *(undefined4 *)(param_1 + 0xfc) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0xf4) + 4))(param_1 + 0xf4,param_1 + 0xfc);
  *(int *)(param_1 + 0x120) = iVar1;
  *(undefined4 *)(param_1 + 0x124) = 0;
  (*pcVar2)(param_1 + 0x120,param_1 + 0x124);
  *(undefined4 *)(param_1 + 0x128) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x120) + 4))(param_1 + 0x120,param_1 + 0x128);
  *(int *)(param_1 + 0x13c) = iVar1;
  *(undefined4 *)(param_1 + 0x140) = 0;
  (*pcVar2)(param_1 + 0x13c,param_1 + 0x140);
  *(undefined4 *)(param_1 + 0x144) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x13c) + 4))(param_1 + 0x13c,param_1 + 0x144);
  *(int *)(param_1 + 0x148) = iVar1;
  *(undefined4 *)(param_1 + 0x14c) = 0;
  (*pcVar2)(param_1 + 0x148,param_1 + 0x14c);
  *(undefined4 *)(param_1 + 0x150) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x148) + 4))(param_1 + 0x148,param_1 + 0x150);
  iVar1 = *(int *)(unaff_EBX + 0x451895);
  *(undefined4 *)(param_1 + 0x170) = 0xbf800000;
  *(int *)(param_1 + 0x16c) = iVar1 + 8;
  (**(code **)(iVar1 + 0x10))(param_1 + 0x16c,param_1 + 0x170);
  *(undefined4 *)(param_1 + 0x118) = 7;
  *(undefined4 *)(param_1 + 0x104) = 0;
  *(undefined4 *)(param_1 + 0x10c) = 0;
  *(undefined4 *)(param_1 + 0x114) = 0;
  param_1[0x11c] = (INextBot)0x0;
  *(undefined4 *)(param_1 + 0x138) = 0;
  *(undefined4 *)(param_1 + 0x174) = 0;
  *(undefined4 *)(param_1 + 0x110) = 7;
  *(undefined4 *)(param_1 + 0x100) = 7;
  *(undefined4 *)(param_1 + 0x154) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x158) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x15c) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x160) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x164) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x168) = 0x3f800000;
  return;
}



/* ----------------------------------------
 * CINSBotBody::Update
 * Address: 00758300
 * ---------------------------------------- */

/* CINSBotBody::Update() */

void __thiscall CINSBotBody::Update(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  CINSBotBody *extraout_ECX;
  CINSBotBody *extraout_ECX_00;
  CINSBotBody *this_00;
  CINSBotBody *this_01;
  CINSBotBody *this_02;
  CINSBotBody *extraout_ECX_01;
  CINSBotBody *extraout_ECX_02;
  CINSBotBody *extraout_ECX_03;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
  this_00 = extraout_ECX;
  if (iVar2 != 0) {
    fVar4 = (float10)CountdownTimer::Now();
    this_00 = extraout_ECX_00;
    if ((float)in_stack_00000004[0x39] <= (float)fVar4 &&
        (float)fVar4 != (float)in_stack_00000004[0x39]) {
      piVar3 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))();
      piVar3 = (int *)(**(code **)(*piVar3 + 200))(piVar3);
      cVar1 = (**(code **)(*piVar3 + 0x118))(piVar3);
      this_00 = this_02;
      if (cVar1 != '\0') {
        UpdatePosture(this_02);
        fVar4 = (float10)CountdownTimer::Now();
        fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x1f3990);
        this_00 = extraout_ECX_01;
        if ((float)in_stack_00000004[0x39] != fVar5) {
          (**(code **)(in_stack_00000004[0x37] + 4))
                    (in_stack_00000004 + 0x37,in_stack_00000004 + 0x39);
          in_stack_00000004[0x39] = (int)fVar5;
          this_00 = extraout_ECX_02;
        }
        if (in_stack_00000004[0x38] != 0x3e000000) {
          (**(code **)(in_stack_00000004[0x37] + 4))
                    (in_stack_00000004 + 0x37,in_stack_00000004 + 0x38);
          in_stack_00000004[0x38] = 0x3e000000;
          this_00 = extraout_ECX_03;
        }
      }
    }
  }
  UpdateArousal(this_00);
  CheckBadViewTarget(this_01,SUB41(in_stack_00000004,0));
  return;
}



/* ----------------------------------------
 * CINSBotBody::CalculateArousalFrac
 * Address: 00756880
 * ---------------------------------------- */

/* CINSBotBody::CalculateArousalFrac(ArousalFracType) */

float10 __thiscall
CINSBotBody::CalculateArousalFrac(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int unaff_EBX;
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  if (param_3 < 6) {
                    /* WARNING: Could not recover jumptable at 0x007568b3. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    fVar1 = (float10)(*(code *)(*(int *)(unaff_EBX + 0x22cefa + param_3 * 4) + unaff_EBX + 0x4508ee)
                     )();
    return fVar1;
  }
  return (float10)*(float *)(unaff_EBX + 0x16228a);
}



/* ----------------------------------------
 * CINSBotBody::CanTransition
 * Address: 00757070
 * ---------------------------------------- */

/* CINSBotBody::CanTransition(IBody::PostureType, IBody::PostureType) */

undefined4 __thiscall
CINSBotBody::CanTransition(undefined4 param_1,int *param_2,int param_3,uint param_4)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  CINSPlayer *this;
  CINSPlayer *this_00;
  uint uVar5;
  int unaff_EBX;
  undefined4 uVar6;
  float10 fVar7;
  undefined4 uVar8;
  
  __i686_get_pc_thunk_bx();
  uVar6 = 0;
  fVar7 = (float10)CountdownTimer::Now();
  if ((float)param_2[0x3c] <= (float)fVar7 && (float)fVar7 != (float)param_2[0x3c]) {
    iVar2 = (**(code **)(*param_2 + 0x15c))(param_2);
    if (iVar2 != 0) {
      iVar2 = (**(code **)(*param_2 + 0x15c))(param_2);
      if (iVar2 != 0) {
        piVar3 = (int *)__dynamic_cast(iVar2,*(undefined4 *)(&DAT_00450086 + unaff_EBX),
                                       *(undefined4 *)(unaff_EBX + 0x44f9aa),0);
        if (piVar3 != (int *)0x0) {
          uVar4 = -(uint)(param_3 - 1U < 2) & 2;
          if ((param_3 == 6) || (param_3 == 3)) {
            uVar4 = 1;
          }
          uVar5 = -(uint)(param_4 - 1 < 2) & 2;
          if ((param_4 == 6) || (param_4 == 3)) {
            uVar5 = 1;
          }
          uVar6 = 0;
          cVar1 = CINSPlayer::CanChangeStance(this,(int)piVar3,uVar4);
          if (cVar1 != '\0') {
            uVar8 = 0x40;
            cVar1 = CINSPlayer::HasPlayerFlag(this_00,(int)piVar3);
            if (cVar1 == '\0') {
              piVar3 = (int *)(**(code **)(*piVar3 + 0x974))(piVar3,uVar8,uVar5);
              (**(code **)(*piVar3 + 0xd0))(piVar3,0);
              if (param_4 < 0xf) {
                    /* WARNING: Could not recover jumptable at 0x007571bc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
                uVar6 = (*(code *)(*(int *)(unaff_EBX + 0x22c752 + param_4 * 4) +
                                  unaff_EBX + 0x4500fa))();
                return uVar6;
              }
              uVar6 = 1;
            }
          }
        }
      }
    }
  }
  return uVar6;
}



/* ----------------------------------------
 * CINSBotBody::CheckBadViewTarget
 * Address: 00755700
 * ---------------------------------------- */

/* CINSBotBody::CheckBadViewTarget(bool) */

void __thiscall CINSBotBody::CheckBadViewTarget(CINSBotBody *this,bool param_1)

{
  float *pfVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  int *piVar6;
  int iVar7;
  Vector *pVVar8;
  int *piVar9;
  CINSRules *this_00;
  CINSRules *this_01;
  CBasePlayer *extraout_ECX;
  CBasePlayer *extraout_ECX_00;
  CTraceFilterSimple *this_02;
  CINSBotLocomotion *this_03;
  CBaseEntity *this_04;
  CBaseEntity *this_05;
  CBaseEntity *this_06;
  CBasePlayer *this_07;
  CBaseEntity *this_08;
  CBaseEntity *this_09;
  CBaseEntity *this_10;
  CBasePlayer *extraout_ECX_01;
  int iVar10;
  float fVar11;
  int unaff_EBX;
  float fVar12;
  float10 fVar13;
  float fVar14;
  float fVar15;
  undefined3 in_stack_00000005;
  char in_stack_00000008;
  undefined4 uVar16;
  Vector *pVVar17;
  undefined4 uVar18;
  float local_144;
  float local_140;
  float local_13c;
  float local_134;
  float local_130;
  Vector local_12c [12];
  float local_120;
  float local_11c;
  float local_118;
  undefined4 local_e0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_8c;
  undefined1 local_88;
  undefined1 local_87;
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
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75570b;
  __i686_get_pc_thunk_bx();
  piVar9 = *(int **)(unaff_EBX + 0x4511ed);
  cVar5 = CINSRules::IsGameState(this_00,*piVar9);
  if (cVar5 == '\0') {
    uVar16 = 3;
    cVar5 = CINSRules::IsGameState(this_01,*piVar9);
    if (cVar5 == '\0') {
      return;
    }
    piVar6 = (int *)(**(code **)(*_param_1 + 0xc4))(_param_1,uVar16);
    iVar7 = (**(code **)(*piVar6 + 200))(piVar6);
    iVar10 = 0;
    if (*(int *)(iVar7 + 0x20) != 0) {
      iVar10 = *(int *)(iVar7 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x451195) + 0x5c) >> 4;
    }
    piVar6 = (int *)UTIL_PlayerByIndex(iVar10);
    if (((piVar6 != (int *)0x0) && (cVar5 = (**(code **)(*piVar6 + 0x158))(piVar6), cVar5 != '\0'))
       && (cVar5 = (**(code **)(*(int *)*piVar9 + 0x3a8))((int *)*piVar9,piVar6), cVar5 == '\0')) {
      return;
    }
  }
  if ((in_stack_00000008 == '\0') &&
     (fVar13 = (float10)CountdownTimer::Now(),
     (float)fVar13 < (float)_param_1[0x36] || (float)fVar13 == (float)_param_1[0x36])) {
    return;
  }
  fVar13 = (float10)CountdownTimer::Now();
  fVar14 = (float)fVar13 + *(float *)(unaff_EBX + 0x1ce381);
  if ((float)_param_1[0x36] != fVar14) {
    (**(code **)(_param_1[0x34] + 4))(_param_1 + 0x34,_param_1 + 0x36);
    _param_1[0x36] = (int)fVar14;
  }
  if (_param_1[0x35] != 0x3e800000) {
    (**(code **)(_param_1[0x34] + 4))(_param_1 + 0x34,_param_1 + 0x35);
    _param_1[0x35] = 0x3e800000;
  }
  iVar7 = (**(code **)(*_param_1 + 0x15c))(_param_1);
  if (iVar7 == 0) {
    return;
  }
  pVVar8 = (Vector *)
           __dynamic_cast(iVar7,*(undefined4 *)(&DAT_004519f9 + unaff_EBX),
                          *(undefined4 *)(unaff_EBX + 0x45131d),0);
  if (pVVar8 == (Vector *)0x0) {
    return;
  }
  piVar9 = *(int **)(unaff_EBX + 0x451195);
  if (in_stack_00000008 != '\0') {
LAB_007558c3:
    if (_param_1[0x5c] != -0x40800000) {
      (**(code **)(_param_1[0x5b] + 8))(_param_1 + 0x5b,_param_1 + 0x5c);
      _param_1[0x5c] = -0x40800000;
    }
    _param_1[0x5d] = *(int *)(*piVar9 + 0xc);
    piVar9 = (int *)(**(code **)(*_param_1 + 0x15c))(_param_1);
    (**(code **)(*piVar9 + 0x20c))(&local_4c,piVar9);
    pfVar1 = *(float **)(unaff_EBX + 0x450ec1);
    local_6c = *pfVar1;
    local_64 = pfVar1[2];
    local_68 = pfVar1[1];
    local_34 = local_6c;
    local_30 = local_68;
    local_2c = local_64;
    pVVar8 = (Vector *)(**(code **)(*_param_1 + 0x15c))(_param_1);
    this_07 = extraout_ECX;
    if ((pVVar8 == (Vector *)0x0) ||
       (cVar5 = (**(code **)(*(int *)pVVar8 + 0x158))(pVVar8), this_07 = extraout_ECX_00,
       cVar5 == '\0')) {
      pVVar8 = (Vector *)0x0;
    }
    uVar18 = 0;
    uVar16 = 0;
    CBasePlayer::EyeVectors(this_07,pVVar8,(Vector *)&local_34,(Vector *)0x0);
    fVar2 = local_2c;
    fVar15 = local_30;
    fVar11 = local_34;
    local_e0 = 0;
    fVar14 = *(float *)(unaff_EBX + 0x1cf911);
    local_64 = local_2c * fVar14 + local_44;
    local_6c = local_34 * fVar14 + local_4c;
    local_68 = fVar14 * local_30 + local_48;
    fVar14 = *(float *)(unaff_EBX + 0x163401);
    if ((float)((uint)(local_64 - local_44) & *(uint *)(unaff_EBX + 0x1cf945)) <= fVar14) {
      (**(code **)(*(int *)pVVar8 + 0x20c))(&local_28,pVVar8,uVar16,uVar18);
      local_68 = fVar15 * fVar14 + local_24;
      local_64 = fVar2 * fVar14 + local_20;
      local_6c = fVar14 * fVar11 + local_28;
      piVar9 = (int *)(**(code **)(*_param_1 + 0xc4))(_param_1);
      piVar9 = (int *)(**(code **)(*piVar9 + 0xdc))(piVar9);
      cVar5 = (**(code **)(*piVar9 + 0x108))(piVar9,&local_6c,0);
      if (cVar5 != '\0') {
        return;
      }
    }
    pfVar1 = *(float **)(unaff_EBX + 0x450ec1);
    local_144 = 0.0;
    piVar9 = *(int **)(unaff_EBX + 0x451335);
    fVar14 = *(float *)(unaff_EBX + 0x208965);
    local_5c = *pfVar1;
    local_58 = pfVar1[1];
    local_54 = pfVar1[2];
    iVar7 = 0x10;
    do {
      sincosf(local_144,&local_130,&local_134);
      local_68 = local_130 * *(float *)(unaff_EBX + 0x1cf905) + local_48;
      local_6c = *(float *)(unaff_EBX + 0x1cf905) * local_134 + local_4c;
      local_64 = local_44 + fVar14;
      iVar10 = (**(code **)(*_param_1 + 0x15c))(_param_1);
      local_8c = 0;
      local_bc = local_6c - local_4c;
      local_88 = 1;
      local_b8 = local_68 - local_48;
      local_b4 = local_64 - local_44;
      local_c4 = local_44;
      local_94 = 0;
      local_98 = 0;
      local_9c = 0;
      local_a4 = 0;
      local_a8 = 0;
      local_c8 = local_48;
      local_87 = local_b8 * local_b8 + local_bc * local_bc + local_b4 * local_b4 != 0.0;
      local_ac = 0;
      local_cc = local_4c;
      CTraceFilterSimple::CTraceFilterSimple
                (this_02,local_7c,iVar10,(_func_bool_IHandleEntity_ptr_int *)0x0);
      (**(code **)(*(int *)**(undefined4 **)(&DAT_0045106d + unaff_EBX) + 0x14))
                ((int *)**(undefined4 **)(&DAT_0045106d + unaff_EBX),&local_cc,0x2006241,local_7c,
                 local_12c);
      iVar10 = (**(code **)(*piVar9 + 0x40))(piVar9);
      if (iVar10 != 0) {
        iVar10 = (**(code **)(*piVar9 + 0x40))(piVar9);
        fVar11 = 0.5;
        if (iVar10 != 0) {
          fVar11 = -1.0;
        }
        DebugDrawLine(local_12c,(Vector *)&local_120,0xff,0,0,true,fVar11);
      }
      if (0.0 < SQRT((local_48 - local_11c) * (local_48 - local_11c) +
                     (local_4c - local_120) * (local_4c - local_120) +
                     (local_44 - local_118) * (local_44 - local_118))) {
        local_5c = local_6c;
        local_58 = local_68;
        local_54 = local_64;
      }
      iVar7 = iVar7 + -1;
      local_144 = *(float *)(unaff_EBX + 0x1d067d) + local_144;
    } while (iVar7 != 0);
    pfVar1 = *(float **)(unaff_EBX + 0x450ec1);
    if (((*pfVar1 == local_5c) && (pfVar1[1] == local_58)) && (pfVar1[2] == local_54)) {
      return;
    }
    (**(code **)(*_param_1 + 0xd4))(_param_1,&local_5c,3,0x3f800000,0,unaff_EBX + 0x22df89);
    return;
  }
  (**(code **)(*(int *)pVVar8 + 0x96c))(pVVar8);
  fVar13 = (float10)CINSBotLocomotion::GetStillDuration(this_03);
  if (*(float *)(unaff_EBX + 0x1d16a5) <= (float)fVar13 &&
      (float)fVar13 != *(float *)(unaff_EBX + 0x1d16a5)) {
    fVar14 = *(float *)(unaff_EBX + 0x1ceaa5);
    if (fVar14 < *(float *)(*piVar9 + 0xc) - (float)_param_1[0x5d]) goto LAB_007558c3;
  }
  else {
    fVar14 = *(float *)(unaff_EBX + 0x1ceaa5);
  }
  piVar9 = (int *)(**(code **)(*(int *)pVVar8 + 0x96c))(pVVar8);
  fVar13 = (float10)(**(code **)(*piVar9 + 0x16c))(piVar9);
  if ((float)fVar13 <= fVar14) {
    return;
  }
  pfVar1 = *(float **)(unaff_EBX + 0x450ec1);
  local_4c = *pfVar1;
  local_48 = pfVar1[1];
  local_44 = pfVar1[2];
  this_05 = this_04;
  if (((byte)pVVar8[0xd1] & 0x10) != 0) {
    CBaseEntity::CalcAbsoluteVelocity(this_04);
    this_05 = (CBaseEntity *)extraout_ECX_01;
  }
  local_13c = *(float *)(pVVar8 + 0x1b0);
  pVVar17 = (Vector *)&local_4c;
  local_140 = *(float *)(pVVar8 + 0x1a8);
  local_144 = *(float *)(pVVar8 + 0x1ac);
  uVar18 = 0;
  uVar16 = 0;
  CBasePlayer::EyeVectors((CBasePlayer *)this_05,pVVar8,pVVar17,(Vector *)0x0);
  fVar14 = *(float *)(unaff_EBX + 0x163415);
  local_4c = local_4c * fVar14;
  local_48 = local_48 * fVar14;
  local_44 = fVar14 * local_44;
  if (((byte)pVVar8[0xd1] & 8) == 0) {
    fVar11 = *(float *)(pVVar8 + 0x208);
    fVar14 = *(float *)(pVVar8 + 0x20c);
    fVar15 = *(float *)(pVVar8 + 0x210);
    local_4c = local_4c + fVar11;
    local_48 = local_48 + fVar14;
    local_44 = local_44 + fVar15;
LAB_00755f90:
    local_140 = local_140 + fVar11;
    local_144 = local_144 + fVar14;
    local_13c = local_13c + fVar15;
LAB_00755fb4:
    local_140 = local_140 - fVar11;
    local_144 = local_144 - fVar14;
    local_13c = local_13c - fVar15;
  }
  else {
    CBaseEntity::CalcAbsolutePosition(this_06);
    fVar11 = *(float *)(pVVar8 + 0x208);
    fVar14 = *(float *)(pVVar8 + 0x20c);
    fVar15 = *(float *)(pVVar8 + 0x210);
    local_4c = local_4c + fVar11;
    local_48 = local_48 + fVar14;
    local_44 = local_44 + fVar15;
    if ((*(uint *)(pVVar8 + 0xd0) & 0x800) == 0) goto LAB_00755f90;
    CBaseEntity::CalcAbsolutePosition(this_08);
    fVar11 = *(float *)(pVVar8 + 0x208);
    fVar14 = *(float *)(pVVar8 + 0x20c);
    local_140 = local_140 + fVar11;
    fVar15 = *(float *)(pVVar8 + 0x210);
    local_144 = local_144 + fVar14;
    local_13c = local_13c + fVar15;
    if (((byte)pVVar8[0xd1] & 8) == 0) goto LAB_00755fb4;
    CBaseEntity::CalcAbsolutePosition(this_09);
    fVar11 = *(float *)(pVVar8 + 0x208);
    fVar14 = *(float *)(pVVar8 + 0x20c);
    local_140 = local_140 - fVar11;
    fVar15 = *(float *)(pVVar8 + 0x210);
    local_144 = local_144 - fVar14;
    local_13c = local_13c - fVar15;
    if (((byte)pVVar8[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_10);
      fVar11 = *(float *)(pVVar8 + 0x208);
      fVar14 = *(float *)(pVVar8 + 0x20c);
      fVar15 = *(float *)(pVVar8 + 0x210);
    }
  }
  fVar4 = local_44;
  fVar3 = local_48;
  fVar2 = local_4c;
  cVar5 = (**(code **)(*(int *)pVVar8 + 0x8a8))(pVVar8,pVVar17,uVar16,uVar18);
  if (cVar5 == '\0') {
    fVar12 = (float)_param_1[0x5c];
    if (((fVar3 - fVar14) * local_144 + (fVar2 - fVar11) * local_140 + local_13c * (fVar4 - fVar15)
         < *(float *)(unaff_EBX + 0x20a8fd)) && (fVar12 <= 0.0)) {
      fVar13 = (float10)IntervalTimer::Now();
      fVar11 = (float)fVar13;
      fVar14 = (float)_param_1[0x5c];
      if (fVar14 != fVar11) {
        (**(code **)(_param_1[0x5b] + 8))(_param_1 + 0x5b,_param_1 + 0x5c);
        _param_1[0x5c] = (int)fVar11;
        fVar14 = fVar11;
      }
      goto LAB_007561ab;
    }
  }
  else {
    fVar12 = (float)_param_1[0x5c];
  }
  if (fVar12 != -1.0) {
    (**(code **)(_param_1[0x5b] + 8))(_param_1 + 0x5b,_param_1 + 0x5c);
    _param_1[0x5c] = -0x40800000;
    return;
  }
  fVar14 = -1.0;
LAB_007561ab:
  if (0.0 < fVar14) {
    fVar13 = (float10)IntervalTimer::Now();
    if ((*(float *)(unaff_EBX + 0x1cfa59) <= (float)fVar13 - (float)_param_1[0x5c] &&
         (float)fVar13 - (float)_param_1[0x5c] != *(float *)(unaff_EBX + 0x1cfa59)) &&
       ((**(code **)(*_param_1 + 0x160))(_param_1), _param_1[0x5c] != -0x40800000)) {
      (**(code **)(_param_1[0x5b] + 8))(_param_1 + 0x5b,_param_1 + 0x5c);
      _param_1[0x5c] = -0x40800000;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::DetermineCurrentStance
 * Address: 00756de0
 * ---------------------------------------- */

/* CINSBotBody::DetermineCurrentStance() */

void __thiscall CINSBotBody::DetermineCurrentStance(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  CINSBotVision *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  CINSPlayer *this_04;
  CINSPlayer *this_05;
  CINSPlayer *this_06;
  CINSPlayer *this_07;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0x15c))();
  if (iVar2 != 0) {
    iVar2 = (**(code **)(*in_stack_00000004 + 0x15c))();
    if (iVar2 != 0) {
      piVar3 = (int *)__dynamic_cast(iVar2,*(undefined4 *)(unaff_EBX + 0x450310),
                                     *(undefined4 *)(unaff_EBX + 0x44fc34),0);
      if (piVar3 != (int *)0x0) {
        piVar4 = (int *)(**(code **)(*piVar3 + 0x96c))(piVar3);
        cVar1 = (**(code **)(*piVar4 + 0x10c))(piVar4);
        if (cVar1 == '\0') {
          in_stack_00000004[0x44] = 0x11;
        }
        else {
          (**(code **)(*piVar3 + 0x974))(piVar3);
          cVar1 = CINSBotVision::IsBlinded(this_00);
          if (cVar1 != '\0') {
            in_stack_00000004[0x44] = 0xf;
            return;
          }
          fVar5 = (float10)CINSPlayer::GetSuppressionFrac(this_01);
          if ((float)fVar5 < *(float *)(unaff_EBX + 0x1ccc9c) ||
              (float)fVar5 == *(float *)(unaff_EBX + 0x1ccc9c)) {
            cVar1 = CINSPlayer::HasPlayerFlag(this_02,(int)piVar3);
            if (cVar1 == '\0') {
              cVar1 = CINSPlayer::IsProned(this_03);
              if (cVar1 == '\0') {
                cVar1 = CINSPlayer::IsCrouched(this_04);
                if (cVar1 == '\0') {
                  cVar1 = CINSPlayer::IsMoving(this_05);
                  if (cVar1 == '\0') {
                    in_stack_00000004[0x44] = (in_stack_00000004[0x40] == 8) + 7;
                  }
                  else {
                    cVar1 = CINSPlayer::IsWalking(this_06);
                    if (cVar1 == '\0') {
                      cVar1 = CINSPlayer::IsSprinting(this_07);
                      in_stack_00000004[0x44] = 0xd - (uint)(cVar1 == '\0');
                    }
                    else {
                      in_stack_00000004[0x44] = 0xb;
                    }
                  }
                }
                else {
                  cVar1 = CINSPlayer::IsMoving(this_05);
                  in_stack_00000004[0x44] = (-(uint)(cVar1 == '\0') & 0xfffffffd) + 6;
                }
              }
              else {
                cVar1 = CINSPlayer::IsMoving(this_04);
                in_stack_00000004[0x44] = 2 - (uint)(cVar1 == '\0');
              }
            }
            else {
              in_stack_00000004[0x44] = 0xe;
            }
          }
          else {
            in_stack_00000004[0x44] = 0x10;
          }
        }
        return;
      }
    }
  }
  in_stack_00000004[0x44] = 7;
  return;
}



/* ----------------------------------------
 * CINSBotBody::GetActualPosture
 * Address: 00754a50
 * ---------------------------------------- */

/* CINSBotBody::GetActualPosture() const */

undefined4 __thiscall CINSBotBody::GetActualPosture(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x110);
}



/* ----------------------------------------
 * CINSBotBody::GetArousal
 * Address: 007548c0
 * ---------------------------------------- */

/* CINSBotBody::GetArousal() const */

int __thiscall CINSBotBody::GetArousal(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return (int)ROUND(*(float *)(in_stack_00000004 + 0x138));
}



/* ----------------------------------------
 * CINSBotBody::GetArousalFalloff
 * Address: 00756460
 * ---------------------------------------- */

/* CINSBotBody::GetArousalFalloff() */

float10 __thiscall CINSBotBody::GetArousalFalloff(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  float fVar4;
  CINSNextBot *this_00;
  int iVar5;
  int unaff_EBX;
  float10 fVar6;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
  if (iVar2 == 0) {
    return (float10)0;
  }
  iVar5 = iVar2 + -0x2060;
  if (iVar5 == 0) {
    return (float10)0;
  }
  cVar1 = CINSNextBot::IsSuppressed(this_00);
  if (cVar1 == '\0') {
    cVar1 = (**(code **)(*(int *)(iVar2 + -0x2060) + 0x8a8))(iVar5);
    if (cVar1 == '\0') {
      cVar1 = (**(code **)(*(int *)(iVar2 + -0x2060) + 0x8ac))(iVar5);
      if (cVar1 == '\0') {
        piVar3 = (int *)(*(int **)(unaff_EBX + 0x450384))[7];
        if (piVar3 != *(int **)(unaff_EBX + 0x450384)) {
LAB_00756601:
          fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
          return fVar6;
        }
      }
      else {
        iVar2 = (**(code **)(*in_stack_00000004 + 0x134))();
        piVar3 = (int *)(*(int **)(unaff_EBX + 0x450290))[7];
        if (piVar3 == *(int **)(unaff_EBX + 0x450290)) {
          fVar4 = (float)((uint)piVar3 ^ piVar3[0xb]);
        }
        else {
          fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
          fVar4 = (float)fVar6;
        }
        if (fVar4 <= (float)iVar2) goto LAB_007564ee;
        piVar3 = (int *)(*(int **)(&LAB_0045094c + unaff_EBX))[7];
        if (piVar3 != *(int **)(&LAB_0045094c + unaff_EBX)) goto LAB_00756601;
      }
    }
    else {
      iVar2 = (**(code **)(*in_stack_00000004 + 0x134))();
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x450890))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x450890)) {
        fVar4 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
        fVar4 = (float)fVar6;
      }
      if (fVar4 <= (float)iVar2) goto LAB_007564ee;
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x4505d4))[7];
      if (piVar3 != *(int **)(unaff_EBX + 0x4505d4)) goto LAB_00756601;
    }
  }
  else {
    iVar2 = (**(code **)(*in_stack_00000004 + 0x134))();
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4505bc))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4505bc)) {
      fVar4 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar6 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar4 = (float)fVar6;
    }
    if (fVar4 <= (float)iVar2) {
LAB_007564ee:
      return (float10)0;
    }
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4508a0))[7];
    if (piVar3 != *(int **)(unaff_EBX + 0x4508a0)) goto LAB_00756601;
  }
  return (float10)(float)((uint)piVar3 ^ piVar3[0xb]);
}



/* ----------------------------------------
 * CINSBotBody::GetArousalFrac
 * Address: 00756db0
 * ---------------------------------------- */

/* CINSBotBody::GetArousalFrac(ArousalFracType) const */

float10 __thiscall CINSBotBody::GetArousalFrac(undefined4 param_1,int param_2,int param_3)

{
  return (float10)*(float *)(param_2 + 0x154 + param_3 * 4);
}



/* ----------------------------------------
 * CINSBotBody::GetDesiredPosture
 * Address: 00754a00
 * ---------------------------------------- */

/* CINSBotBody::GetDesiredPosture() const */

undefined4 __thiscall CINSBotBody::GetDesiredPosture(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x100);
}



/* ----------------------------------------
 * CINSBotBody::GetDesiredPosturePriority
 * Address: 00756dd0
 * ---------------------------------------- */

/* CINSBotBody::GetDesiredPosturePriority() const */

undefined4 __thiscall CINSBotBody::GetDesiredPosturePriority(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x108);
}



/* ----------------------------------------
 * CINSBotBody::GetHeadAimTrackingInterval
 * Address: 00754f00
 * ---------------------------------------- */

/* CINSBotBody::GetHeadAimTrackingInterval() const */

float10 __thiscall CINSBotBody::GetHeadAimTrackingInterval(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  float fVar6;
  float fVar7;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_04;
  CINSNextBot *extraout_ECX_05;
  CINSNextBot *extraout_ECX_06;
  CINSNextBot *extraout_ECX_07;
  CINSNextBot *pCVar8;
  CINSPlayer *this_01;
  CINSNextBot *extraout_ECX_08;
  CINSRules *extraout_ECX_09;
  CBaseEntity *this_02;
  CINSRules *this_03;
  CINSNextBot *extraout_ECX_10;
  int unaff_EBX;
  float10 fVar9;
  float fVar10;
  float fVar11;
  int *in_stack_00000004;
  int *local_20;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  iVar4 = 0;
  if (iVar2 != 0) {
    iVar4 = iVar2 + -0x2060;
  }
  piVar3 = (int *)(*(int **)(unaff_EBX + 0x451a2b))[7];
  if (piVar3 == *(int **)(unaff_EBX + 0x451a2b)) {
    fVar10 = (float)((uint)piVar3 ^ piVar3[0xb]);
    pCVar8 = extraout_ECX;
  }
  else {
    fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
    fVar10 = (float)fVar9;
    pCVar8 = extraout_ECX_00;
  }
  if (iVar4 == 0) {
LAB_00754f65:
    return (float10)fVar10;
  }
  if ((*(byte *)(iVar4 + 0x2294) & 8) != 0) {
    fVar10 = *(float *)(unaff_EBX + 0x1d011f);
    goto LAB_00754f65;
  }
  iVar2 = CINSNextBot::GetDifficulty(pCVar8);
  if (iVar2 == 3) {
    local_20 = *(int **)(unaff_EBX + 0x4519eb);
    pCVar8 = extraout_ECX_01;
LAB_00755209:
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4519ef))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4519ef)) goto LAB_00755285;
LAB_00755220:
    fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
    fVar7 = (float)fVar9;
    pCVar8 = extraout_ECX_08;
  }
  else {
    iVar2 = (**(code **)(**(int **)(unaff_EBX + 0x451bbf) + 0x40))(*(int **)(unaff_EBX + 0x451bbf));
    local_20 = *(int **)(unaff_EBX + 0x4519eb);
    pCVar8 = extraout_ECX_02;
    if ((((iVar2 != 0) && (piVar3 = (int *)*local_20, piVar3 != (int *)0x0)) &&
        (cVar1 = (**(code **)(*piVar3 + 0x29c))(piVar3), pCVar8 = extraout_ECX_03, cVar1 != '\0'))
       && (cVar1 = CINSRules::IsSoloMode(), pCVar8 = (CINSNextBot *)this_02, cVar1 != '\0')) {
      iVar2 = CBaseEntity::GetTeamNumber(this_02);
      iVar5 = CINSRules::GetHumanTeam(this_03);
      pCVar8 = extraout_ECX_10;
      if (iVar2 == iVar5) goto LAB_00755209;
    }
    iVar2 = CINSNextBot::GetDifficulty(pCVar8);
    if (iVar2 == 2) {
      piVar3 = (int *)(*(int **)(CEntityFactory<CEnvTonemapController>::Create + unaff_EBX + 3))[7];
      pCVar8 = this_00;
      if (piVar3 != *(int **)(CEntityFactory<CEnvTonemapController>::Create + unaff_EBX + 3))
      goto LAB_00755220;
    }
    else {
      iVar2 = CINSNextBot::GetDifficulty(this_00);
      pCVar8 = extraout_ECX_04;
      if (iVar2 != 0) {
        cVar1 = *(char *)(iVar4 + 0xb49c);
        goto joined_r0x00755245;
      }
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x4515b3))[7];
      if (piVar3 != *(int **)(unaff_EBX + 0x4515b3)) goto LAB_00755220;
    }
LAB_00755285:
    fVar7 = (float)((uint)piVar3 ^ piVar3[0xb]);
  }
  cVar1 = *(char *)(iVar4 + 0xb49c);
  fVar10 = fVar10 * fVar7;
joined_r0x00755245:
  if (cVar1 != '\0') {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x45218f))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x45218f)) {
      fVar10 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar10 = (float)fVar9;
      pCVar8 = (CINSNextBot *)extraout_ECX_09;
    }
  }
  if ((*local_20 != 0) && (cVar1 = CINSRules::IsSurvival((CINSRules *)pCVar8), cVar1 != '\0')) {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x45182b))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x45182b)) {
      fVar7 = (float)((uint)piVar3 ^ piVar3[0xb]);
      pCVar8 = extraout_ECX_05;
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar7 = (float)fVar9;
      pCVar8 = extraout_ECX_06;
    }
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x4515e3))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x4515e3)) {
      fVar6 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar6 = (float)fVar9;
      pCVar8 = extraout_ECX_07;
    }
    fVar11 = ((float)*(int *)(*local_20 + 1000) + *(float *)(unaff_EBX + 0x163c03)) *
             *(float *)(unaff_EBX + 0x1dec33);
    if (*(float *)(unaff_EBX + 0x163c07) <= fVar11) {
      fVar11 = *(float *)(unaff_EBX + 0x163c07);
    }
    if (fVar11 <= *(float *)(unaff_EBX + 0x163bfb)) {
      fVar11 = *(float *)(unaff_EBX + 0x163bfb);
    }
    fVar10 = fVar10 * ((fVar7 - fVar6) * fVar11 + fVar6);
    piVar3 = (int *)CINSNextBot::GetTarget(pCVar8);
    if (((piVar3 != (int *)0x0) && (iVar4 = (**(code **)(*piVar3 + 0x10))(piVar3), iVar4 != 0)) &&
       ((cVar1 = (**(code **)(*piVar3 + 0x38))(piVar3), cVar1 != '\0' &&
        ((((fVar9 = (float10)(**(code **)(*piVar3 + 0x30))(piVar3),
           *(float *)(unaff_EBX + 0x1d1ea3) <= (float)fVar9 &&
           (float)fVar9 != *(float *)(unaff_EBX + 0x1d1ea3) &&
           (piVar3 = (int *)(**(code **)(*piVar3 + 0x10))(piVar3), piVar3 != (int *)0x0)) &&
          (cVar1 = (**(code **)(*piVar3 + 0x158))(piVar3), cVar1 != '\0')) &&
         ((cVar1 = (**(code **)(*piVar3 + 0x118))(piVar3), cVar1 != '\0' &&
          (cVar1 = CINSPlayer::IsSprinting(this_01), cVar1 != '\0')))))))) {
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x451b7f))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x451b7f)) {
        fVar7 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar9 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
        fVar7 = (float)fVar9;
      }
      fVar10 = fVar10 * fVar7;
    }
  }
  return (float10)(fVar10 * (float)in_stack_00000004[0x55]);
}



/* ----------------------------------------
 * CINSBotBody::GetHullWidth
 * Address: 00758480
 * ---------------------------------------- */

/* CINSBotBody::GetHullWidth() const */

float10 CINSBotBody::GetHullWidth(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return (float10)*(float *)(extraout_ECX + 0x1df993);
}



/* ----------------------------------------
 * CINSBotBody::GetMaxArousal
 * Address: 00756670
 * ---------------------------------------- */

/* CINSBotBody::GetMaxArousal(ArousalIncrementType) */

undefined4 __thiscall CINSBotBody::GetMaxArousal(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  uVar1 = 2;
  if (param_3 - 2U < 8) {
    uVar1 = *(undefined4 *)(extraout_ECX + 0x22d1eb + (param_3 - 2U) * 4);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSBotBody::GetMaxHeadAngularVelocity
 * Address: 00754c90
 * ---------------------------------------- */

/* CINSBotBody::GetMaxHeadAngularVelocity() const */

float10 __thiscall CINSBotBody::GetMaxHeadAngularVelocity(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  float fVar5;
  CINSPlayer *extraout_ECX;
  CINSPlayer *extraout_ECX_00;
  CINSPlayer *this_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CINSNextBot *this_04;
  CINSRules *this_05;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  int unaff_EBX;
  int *piVar6;
  float10 fVar7;
  int *in_stack_00000004;
  undefined4 uVar8;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
  piVar6 = (int *)0x0;
  if (iVar2 != 0) {
    piVar6 = (int *)(iVar2 + -0x2060);
  }
  piVar4 = (int *)(*(int **)(CEnvTonemapController::~CEnvTonemapController + unaff_EBX))[7];
  if (piVar4 == *(int **)(CEnvTonemapController::~CEnvTonemapController + unaff_EBX)) {
    local_20 = (float)((uint)piVar4 ^ piVar4[0xb]);
    this_00 = extraout_ECX;
  }
  else {
    fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
    local_20 = (float)fVar7;
    this_00 = extraout_ECX_00;
  }
  if (piVar6 == (int *)0x0) {
LAB_00754d01:
    return (float10)local_20;
  }
  uVar8 = 0x40;
  cVar1 = CINSPlayer::HasPlayerFlag(this_00,(int)piVar6);
  if (cVar1 != '\0') {
    local_20 = 0.0;
    goto LAB_00754d01;
  }
  cVar1 = (**(code **)(*piVar6 + 0x8ac))(piVar6,uVar8);
  this_01 = extraout_ECX_01;
  if (cVar1 != '\0') {
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x451e98))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x451e98)) {
      local_20 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      local_20 = (float)fVar7;
      this_01 = extraout_ECX_03;
    }
  }
  iVar2 = CINSNextBot::GetDifficulty(this_01);
  if (iVar2 == 3) {
LAB_00754e18:
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x452278))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x452278)) goto LAB_00754e28;
LAB_00754e9d:
    fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
    fVar5 = (float)fVar7;
  }
  else {
    cVar1 = CINSRules::IsSoloMode();
    this_03 = this_02;
    if (cVar1 != '\0') {
      iVar2 = CBaseEntity::GetTeamNumber(this_02);
      iVar3 = CINSRules::GetHumanTeam(this_05);
      this_03 = (CBaseEntity *)extraout_ECX_02;
      if (iVar2 == iVar3) goto LAB_00754e18;
    }
    iVar2 = CINSNextBot::GetDifficulty((CINSNextBot *)this_03);
    if (iVar2 == 2) {
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x4524cc))[7];
      if (piVar4 != *(int **)(unaff_EBX + 0x4524cc)) goto LAB_00754e9d;
    }
    else {
      iVar2 = CINSNextBot::GetDifficulty(this_04);
      if (iVar2 != 0) goto LAB_00754d78;
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x45248c))[7];
      if (piVar4 != *(int **)(unaff_EBX + 0x45248c)) goto LAB_00754e9d;
    }
LAB_00754e28:
    fVar5 = (float)((uint)piVar4 ^ piVar4[0xb]);
  }
  local_20 = fVar5 * local_20;
LAB_00754d78:
  fVar7 = (float10)CountdownTimer::Now();
  if ((float)fVar7 < (float)piVar6[0x2ce4] || (float)fVar7 == (float)piVar6[0x2ce4]) {
    local_20 = local_20 * (float)piVar6[0x2cd1];
  }
  if ((char)piVar6[0x2d27] != '\0') {
    piVar6 = (int *)(*(int **)(unaff_EBX + 0x452178))[7];
    if (piVar6 == *(int **)(unaff_EBX + 0x452178)) {
      fVar5 = (float)((uint)piVar6 ^ piVar6[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
      fVar5 = (float)fVar7;
    }
    local_20 = fVar5 * local_20;
  }
  return (float10)(local_20 * (float)in_stack_00000004[0x59]);
}



/* ----------------------------------------
 * CINSBotBody::GetTimeSinceLastTransition
 * Address: 007575a0
 * ---------------------------------------- */

/* CINSBotBody::GetTimeSinceLastTransition() */

float10 __thiscall CINSBotBody::GetTimeSinceLastTransition(CINSBotBody *this)

{
  int extraout_ECX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  return (float10)(*(float *)(**(int **)(extraout_ECX + 0x44f2fb) + 0xc) -
                  *(float *)(in_stack_00000004 + 0x114));
}



/* ----------------------------------------
 * CINSBotBody::GetViewVector
 * Address: 00754ad0
 * ---------------------------------------- */

/* CINSBotBody::GetViewVector() const */

Vector * __thiscall CINSBotBody::GetViewVector(CINSBotBody *this)

{
  int iVar1;
  float *pfVar2;
  int *piVar3;
  int *in_stack_00000004;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar1 = (**(code **)(*in_stack_00000004 + 0xc4))();
  piVar3 = (int *)0x0;
  if (iVar1 != 0) {
    piVar3 = (int *)(iVar1 + -0x2060);
  }
  (**(code **)(*piVar3 + 0x74c))(&local_34,piVar3);
  pfVar2 = (float *)(**(code **)(*piVar3 + 0x210))(piVar3);
  local_28 = local_34 + *pfVar2;
  local_24 = local_30 + pfVar2[1];
  local_20 = local_2c + pfVar2[2];
  AngleVectors((QAngle *)&local_28,(Vector *)(in_stack_00000004 + 0x4b));
  return (Vector *)(in_stack_00000004 + 0x4b);
}



/* ----------------------------------------
 * CINSBotBody::IncrementArousal
 * Address: 007566a0
 * ---------------------------------------- */

/* CINSBotBody::IncrementArousal(ArousalIncrementType) */

void __thiscall CINSBotBody::IncrementArousal(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (param_3 < 9) {
                    /* WARNING: Could not recover jumptable at 0x007566d2. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)(*(int *)(unaff_EBX + 0x22d0ac + param_3 * 4) + unaff_EBX + 0x450ac4))();
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::IsActualPosture
 * Address: 00754a60
 * ---------------------------------------- */

/* CINSBotBody::IsActualPosture(IBody::PostureType) const */

bool __thiscall CINSBotBody::IsActualPosture(undefined4 param_1,int param_2,int param_3)

{
  return *(int *)(param_2 + 0x110) == param_3;
}



/* ----------------------------------------
 * CINSBotBody::IsArousal
 * Address: 00754910
 * ---------------------------------------- */

/* CINSBotBody::IsArousal(IBody::ArousalType) const */

undefined4 __thiscall CINSBotBody::IsArousal(undefined4 param_1,int param_2,int param_3)

{
  return CONCAT31((int3)((uint)(int)ROUND(*(float *)(param_2 + 0x138)) >> 8),
                  param_3 == (int)ROUND(*(float *)(param_2 + 0x138)));
}



/* ----------------------------------------
 * CINSBotBody::IsDesiredPosture
 * Address: 00754a10
 * ---------------------------------------- */

/* CINSBotBody::IsDesiredPosture(IBody::PostureType) const */

bool __thiscall CINSBotBody::IsDesiredPosture(undefined4 param_1,int param_2,int param_3)

{
  return *(int *)(param_2 + 0x100) == param_3;
}



/* ----------------------------------------
 * CINSBotBody::IsInDesiredPosture
 * Address: 00754a30
 * ---------------------------------------- */

/* CINSBotBody::IsInDesiredPosture() const */

bool __thiscall CINSBotBody::IsInDesiredPosture(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return *(int *)(in_stack_00000004 + 0x100) == *(int *)(in_stack_00000004 + 0x110);
}



/* ----------------------------------------
 * CINSBotBody::IsMaxArousal
 * Address: 007549b0
 * ---------------------------------------- */

/* CINSBotBody::IsMaxArousal(IBody::ArousalType) const */

undefined4 __thiscall CINSBotBody::IsMaxArousal(undefined4 param_1,int param_2,int param_3)

{
  return CONCAT31((int3)((uint)(int)ROUND(*(float *)(param_2 + 0x138)) >> 8),
                  (int)ROUND(*(float *)(param_2 + 0x138)) <= param_3);
}



/* ----------------------------------------
 * CINSBotBody::IsMinArousal
 * Address: 00754960
 * ---------------------------------------- */

/* CINSBotBody::IsMinArousal(IBody::ArousalType) const */

undefined4 __thiscall CINSBotBody::IsMinArousal(undefined4 param_1,int param_2,int param_3)

{
  return CONCAT31((int3)((uint)(int)ROUND(*(float *)(param_2 + 0x138)) >> 8),
                  param_3 <= (int)ROUND(*(float *)(param_2 + 0x138)));
}



/* ----------------------------------------
 * CINSBotBody::IsPostureChanging
 * Address: 00754ac0
 * ---------------------------------------- */

/* CINSBotBody::IsPostureChanging() const */

undefined1 __thiscall CINSBotBody::IsPostureChanging(CINSBotBody *this)

{
  int in_stack_00000004;
  
  return *(undefined1 *)(in_stack_00000004 + 0x11c);
}



/* ----------------------------------------
 * CINSBotBody::IsPostureCompatible
 * Address: 00756fd0
 * ---------------------------------------- */

/* CINSBotBody::IsPostureCompatible(IBody::PostureType, IBody::PostureType) */

bool __thiscall
CINSBotBody::IsPostureCompatible(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  undefined1 uVar1;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (0xc < param_3) {
    return param_3 == param_4;
  }
                    /* WARNING: Could not recover jumptable at 0x00757001. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  uVar1 = (*(code *)(*(int *)(unaff_EBX + 0x22c7c3 + param_3 * 4) + unaff_EBX + 0x45019f))();
  return (bool)uVar1;
}



/* ----------------------------------------
 * CINSBotBody::IsPostureMobile
 * Address: 00754a80
 * ---------------------------------------- */

/* CINSBotBody::IsPostureMobile() const */

undefined4 __thiscall CINSBotBody::IsPostureMobile(CINSBotBody *this)

{
  int in_stack_00000004;
  
  if ((*(uint *)(in_stack_00000004 + 0x110) < 0xb) &&
     ((1 << ((byte)*(undefined4 *)(in_stack_00000004 + 0x110) & 0x1f) & 0x70aU) != 0)) {
    return 0;
  }
  return 1;
}



/* ----------------------------------------
 * CINSBotBody::IsValidStance
 * Address: 007572e0
 * ---------------------------------------- */

/* CINSBotBody::IsValidStance(IBody::PostureType) */

bool __thiscall CINSBotBody::IsValidStance(undefined4 param_1,undefined4 param_2,uint param_3)

{
  return param_3 < 0x14;
}



/* ----------------------------------------
 * CINSBotBody::ReleaseAllStanceButtons
 * Address: 007572f0
 * ---------------------------------------- */

/* CINSBotBody::ReleaseAllStanceButtons() */

void __thiscall CINSBotBody::ReleaseAllStanceButtons(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  CINSPlayer *this_00;
  CINSPlayer *extraout_ECX;
  CINSPlayer *this_01;
  CINSPlayer *extraout_ECX_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = (**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
  if (iVar2 != 0) {
    iVar2 = (**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
    if (iVar2 != 0) {
      piVar3 = (int *)__dynamic_cast(iVar2,*(undefined4 *)(unaff_EBX + 0x44fe0a),
                                     *(undefined4 *)(unaff_EBX + 0x44f72e),0);
      if (piVar3 != (int *)0x0) {
        (**(code **)(*piVar3 + 0x914))(piVar3);
        (**(code **)(*piVar3 + 0x940))(piVar3);
        (**(code **)(*piVar3 + 0x91c))(piVar3);
        (**(code **)(*piVar3 + 0x938))(piVar3);
        cVar1 = CINSPlayer::IsProned(this_00);
        this_01 = extraout_ECX;
        if (cVar1 != '\0') {
          (**(code **)(*piVar3 + 0x93c))(piVar3,0x3dcccccd);
          this_01 = extraout_ECX_00;
        }
        CINSPlayer::StanceReset(this_01);
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::SetArousal
 * Address: 00754880
 * ---------------------------------------- */

/* CINSBotBody::SetArousal(IBody::ArousalType) */

void __thiscall CINSBotBody::SetArousal(undefined4 param_1,int param_2,uint param_3)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  *(float *)(param_2 + 0x138) =
       (float)(param_3 >> 0x10) * *(float *)(extraout_ECX + 0x1d14c7) + (float)(param_3 & 0xffff);
  return;
}



/* ----------------------------------------
 * CINSBotBody::SetDesiredPosture
 * Address: 00757780
 * ---------------------------------------- */

/* CINSBotBody::SetDesiredPosture(IBody::PostureType) */

void __thiscall
CINSBotBody::SetDesiredPosture(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  CINSBotBody *extraout_ECX;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  SetPosture(extraout_ECX,param_2,param_3,3,0x3f000000,unaff_EBX + 0x22bee5);
  return;
}



/* ----------------------------------------
 * CINSBotBody::SetDesiredPosture
 * Address: 007577d0
 * ---------------------------------------- */

/* CINSBotBody::SetDesiredPosture(IBody::PostureType, float) */

void __thiscall
CINSBotBody::SetDesiredPosture
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  CINSBotBody *extraout_ECX;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  SetPosture(extraout_ECX,param_2,param_3,3,param_4,unaff_EBX + 0x22be95);
  return;
}



/* ----------------------------------------
 * CINSBotBody::SetPosture
 * Address: 007575e0
 * ---------------------------------------- */

/* CINSBotBody::SetPosture(IBody::PostureType, INSBotPriority, float, char const*) */

void __thiscall
CINSBotBody::SetPosture
          (undefined4 param_1,int *param_2,int param_3,int param_4,float param_5,int param_6)

{
  float fVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  CFmtStrN<256,false> *this;
  int unaff_EBX;
  char local_140 [5];
  char local_13b [263];
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x7575eb;
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)(**(code **)(*param_2 + 0xc4))(param_2);
  cVar2 = (**(code **)(*piVar3 + 0x140))(piVar3,0x400);
  iVar4 = param_4;
  if ((cVar2 != '\0') && (iVar4 = 4, param_4 != 4)) {
    iVar4 = unaff_EBX + 0x1cc87d;
    if (param_6 != 0) {
      iVar4 = param_6;
    }
    CFmtStrN<256,false>::CFmtStrN
              (this,local_140,unaff_EBX + 0x22c0d1,iVar4,param_3,param_4,(double)param_5);
    piVar3 = (int *)(**(code **)(*param_2 + 0x15c))(param_2);
    (**(code **)(*piVar3 + 0x20c))(&local_34,piVar3);
    local_20 = *(float *)(unaff_EBX + 0x1d0d49) + local_2c;
    local_28 = local_34;
    local_24 = local_30;
    NDebugOverlay::Text((Vector *)&local_28,local_13b,true,3.0);
    iVar4 = param_4;
  }
  if (param_3 == 0) {
    param_3 = 0xc;
  }
  if (param_2[0x42] < iVar4) {
    iVar4 = **(int **)(unaff_EBX + 0x44f2b5);
  }
  else {
    fVar1 = (float)param_2[0x43];
    iVar4 = **(int **)(unaff_EBX + 0x44f2b5);
    if (*(float *)(iVar4 + 0xc) <= fVar1) {
      if (param_2[0x40] != param_3) {
        return;
      }
      param_5 = *(float *)(iVar4 + 0xc) + param_5;
      if (param_5 <= fVar1) {
        param_5 = fVar1;
      }
      param_2[0x43] = (int)param_5;
      return;
    }
  }
  param_2[0x40] = param_3;
  param_2[0x43] = (int)(param_5 + *(float *)(iVar4 + 0xc));
  param_2[0x42] = param_4;
  param_2[0x41] = (int)param_5;
  return;
}



/* ----------------------------------------
 * CINSBotBody::ShouldEaseAngularVelocity
 * Address: 00754b80
 * ---------------------------------------- */

/* CINSBotBody::ShouldEaseAngularVelocity() const */

byte __thiscall CINSBotBody::ShouldEaseAngularVelocity(CINSBotBody *this)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  CINSPlayer *this_00;
  CINSNextBot *this_01;
  byte bVar4;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  bVar4 = 1;
  iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
  if (iVar2 != 0) {
    iVar2 = (**(code **)(*in_stack_00000004 + 0xc4))();
    if ((iVar2 != 0) && (iVar2 != 0x2060)) {
      bVar4 = 0;
      uVar3 = CINSPlayer::GetPlayerFlags(this_00);
      if ((uVar3 & 1) == 0) {
        cVar1 = CINSNextBot::IsEscorting(this_01);
        if (cVar1 == '\0') {
          return *(byte *)(iVar2 + 0x943c) ^ 1;
        }
      }
    }
  }
  return bVar4;
}



/* ----------------------------------------
 * CINSBotBody::TransitionToStance
 * Address: 007573b0
 * ---------------------------------------- */

/* CINSBotBody::TransitionToStance(IBody::PostureType, float) */

void __cdecl CINSBotBody::TransitionToStance(int *param_1,uint param_2)

{
  int iVar1;
  int *piVar2;
  CINSBotBody *this;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  iVar1 = (**(code **)(*param_1 + 0x15c))(param_1);
  if (iVar1 != 0) {
    iVar1 = (**(code **)(*param_1 + 0x15c))(param_1);
    if (iVar1 != 0) {
      piVar2 = (int *)__dynamic_cast(iVar1,*(undefined4 *)(unaff_EBX + 0x44fd40),
                                     *(undefined4 *)(unaff_EBX + 0x44f664),0);
      if (piVar2 != (int *)0x0) {
        ReleaseAllStanceButtons(this);
        if (param_2 < 0x11) {
                    /* WARNING: Could not recover jumptable at 0x00757469. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (*(code *)(*(int *)(unaff_EBX + 0x22c448 + param_2 * 4) + unaff_EBX + 0x44fdb4))();
          return;
        }
        (**(code **)(*piVar2 + 0x934))(piVar2,0x3f000000);
        param_1[0x45] = *(int *)(**(int **)(unaff_EBX + 0x44f4dc) + 0xc);
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::UpdateArousal
 * Address: 00757fa0
 * ---------------------------------------- */

/* CINSBotBody::UpdateArousal() */

void __thiscall CINSBotBody::UpdateArousal(CINSBotBody *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CFmtStrN<256,false> *this_00;
  CINSBotBody *this_01;
  CINSBotBody *this_02;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  float fVar6;
  int *in_stack_00000004;
  char local_134 [5];
  char local_12f [263];
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x757fab;
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
  cVar1 = (**(code **)(*piVar2 + 0x140))(piVar2,0x800);
  if (cVar1 != '\0') {
    CFmtStrN<256,false>::CFmtStrN
              (this_00,local_134,unaff_EBX + 0x22b785,(double)(float)in_stack_00000004[0x57],
               (double)(float)in_stack_00000004[0x58],(double)(float)in_stack_00000004[0x5a],
               (double)(float)in_stack_00000004[0x59]);
    piVar2 = (int *)(**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
    (**(code **)(*piVar2 + 0x20c))(local_28,piVar2);
    NDebugOverlay::Text(local_28,local_12f,true,0.2);
  }
  fVar4 = (float10)CountdownTimer::Now();
  if ((float)in_stack_00000004[0x51] <= (float)fVar4 &&
      (float)fVar4 != (float)in_stack_00000004[0x51]) {
    piVar2 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004);
    piVar2 = (int *)(**(code **)(*piVar2 + 200))(piVar2);
    cVar1 = (**(code **)(*piVar2 + 0x118))(piVar2);
    if (cVar1 == '\0') {
      (**(code **)(*in_stack_00000004 + 0x130))(in_stack_00000004,0);
    }
    else {
      fVar4 = (float10)CountdownTimer::Now();
      if ((float)in_stack_00000004[0x54] <= (float)fVar4 &&
          (float)fVar4 != (float)in_stack_00000004[0x54]) {
        fVar5 = (float)in_stack_00000004[0x4e];
        fVar4 = (float10)GetArousalFalloff(this_01);
        fVar6 = 0.0;
        if (0.0 < fVar5 - (float)fVar4) {
          fVar6 = (float)in_stack_00000004[0x4e];
          fVar4 = (float10)GetArousalFalloff(this_02);
          fVar6 = fVar6 - (float)fVar4;
        }
        in_stack_00000004[0x4e] = (int)fVar6;
        fVar4 = (float10)CountdownTimer::Now();
        fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x160b69);
        if ((float)in_stack_00000004[0x54] != fVar5) {
          (**(code **)(in_stack_00000004[0x52] + 4))
                    (in_stack_00000004 + 0x52,in_stack_00000004 + 0x54);
          in_stack_00000004[0x54] = (int)fVar5;
        }
        if (in_stack_00000004[0x53] != 0x3f800000) {
          (**(code **)(in_stack_00000004[0x52] + 4))
                    (in_stack_00000004 + 0x52,in_stack_00000004 + 0x53);
          in_stack_00000004[0x53] = 0x3f800000;
        }
      }
    }
    iVar3 = 0;
    do {
      fVar4 = (float10)CalculateArousalFrac();
      in_stack_00000004[iVar3 + 0x55] = (int)(float)fVar4;
      iVar3 = iVar3 + 1;
    } while (iVar3 != 6);
    fVar4 = (float10)CountdownTimer::Now();
    fVar5 = (float)fVar4 + *(float *)(unaff_EBX + 0x1cbae1);
    if ((float)in_stack_00000004[0x51] != fVar5) {
      (**(code **)(in_stack_00000004[0x4f] + 4))(in_stack_00000004 + 0x4f,in_stack_00000004 + 0x51);
      in_stack_00000004[0x51] = (int)fVar5;
    }
    if (in_stack_00000004[0x50] != 0x3e800000) {
      (**(code **)(in_stack_00000004[0x4f] + 4))(in_stack_00000004 + 0x4f,in_stack_00000004 + 0x50);
      in_stack_00000004[0x50] = 0x3e800000;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::UpdatePosture
 * Address: 00757820
 * ---------------------------------------- */

/* CINSBotBody::UpdatePosture() */

void __thiscall CINSBotBody::UpdatePosture(CINSBotBody *this)

{
  float fVar1;
  float fVar2;
  CFmtStrN<256,false> *this_00;
  int iVar3;
  char cVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  char *pcVar8;
  CINSPlayer *this_01;
  CINSWeapon *this_02;
  CINSPlayer *this_03;
  CFmtStrN<256,false> *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSBotBody *extraout_ECX;
  int *piVar9;
  char *pcVar10;
  int unaff_EBX;
  float10 fVar11;
  float fVar12;
  double dVar13;
  int *in_stack_00000004;
  ulonglong uVar14;
  char *local_250;
  char local_24c [5];
  char local_247 [255];
  char local_148 [4];
  int local_144;
  char local_13c [5];
  char local_137 [271];
  Vector local_28 [20];
  undefined4 uStack_14;
  
  uStack_14 = 0x75782b;
  __i686_get_pc_thunk_bx();
  iVar5 = (**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
  if (iVar5 == 0) {
    return;
  }
  iVar5 = (**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
  if (iVar5 == 0) {
    return;
  }
  piVar6 = (int *)__dynamic_cast(iVar5,*(undefined4 *)(unaff_EBX + 0x44f8d9),
                                 *(undefined4 *)(unaff_EBX + 0x44f1fd),0);
  if (piVar6 == (int *)0x0) {
    return;
  }
  cVar4 = (**(code **)(*piVar6 + 0x118))(piVar6);
  if (cVar4 == '\0') {
    return;
  }
  iVar5 = CINSPlayer::GetActiveINSWeapon();
  this_03 = this_01;
  if ((((iVar5 != 0) &&
       (cVar4 = CINSPlayer::IsSprinting(this_01), this_03 = (CINSPlayer *)this_02, cVar4 != '\0'))
      && (cVar4 = CINSWeapon::HasFlashlight(this_02), this_03 = (CINSPlayer *)this_05, cVar4 != '\0'
         )) && (cVar4 = CINSWeapon::IsFlashlightOn(this_05), this_03 = (CINSPlayer *)this_06,
               cVar4 != '\0')) {
    CINSWeapon::ToggleFlashlight(this_06);
    this_03 = (CINSPlayer *)extraout_ECX;
  }
  DetermineCurrentStance((CINSBotBody *)this_03);
  cVar4 = (**(code **)(*in_stack_00000004 + 0x124))(in_stack_00000004,1);
  if ((cVar4 != '\0') &&
     (cVar4 = (**(code **)(*in_stack_00000004 + 0x118))(in_stack_00000004,1), cVar4 == '\0')) {
    (**(code **)(*piVar6 + 0x93c))(piVar6,0x3dcccccd);
    return;
  }
  piVar9 = (int *)in_stack_00000004[0x40];
  uVar14 = ZEXT48(piVar9);
  piVar7 = (int *)in_stack_00000004[0x44];
  cVar4 = IsPostureCompatible();
  if (cVar4 != '\0') {
    *(undefined1 *)(in_stack_00000004 + 0x47) = 0;
    goto LAB_00757925;
  }
  if ((char)in_stack_00000004[0x47] == '\0') {
    fVar11 = (float10)CountdownTimer::Now();
    if ((float)fVar11 < (float)in_stack_00000004[0x3c] ||
        (float)fVar11 == (float)in_stack_00000004[0x3c]) {
      if ((char)in_stack_00000004[0x47] != '\0') {
        piVar9 = (int *)in_stack_00000004[0x40];
        goto LAB_00757aad;
      }
    }
    else {
      uVar14 = (ulonglong)(uint)in_stack_00000004[0x41];
      piVar7 = (int *)in_stack_00000004[0x40];
      TransitionToStance(in_stack_00000004,piVar7,in_stack_00000004[0x41]);
      fVar12 = *(float *)(unaff_EBX + 0x1612e9);
      *(undefined1 *)(in_stack_00000004 + 0x47) = 1;
      fVar12 = fVar12 + (float)in_stack_00000004[0x41];
      fVar11 = (float10)CountdownTimer::Now();
      if ((float)in_stack_00000004[0x3c] != (float)fVar11 + fVar12) {
        piVar7 = in_stack_00000004 + 0x3c;
        (**(code **)(in_stack_00000004[0x3a] + 4))(in_stack_00000004 + 0x3a,piVar7);
        in_stack_00000004[0x3c] = (int)((float)fVar11 + fVar12);
      }
      if ((float)in_stack_00000004[0x3b] != fVar12) {
        piVar7 = in_stack_00000004 + 0x3b;
        (**(code **)(in_stack_00000004[0x3a] + 4))(in_stack_00000004 + 0x3a,piVar7);
        piVar9 = (int *)in_stack_00000004[0x40];
        in_stack_00000004[0x3b] = (int)fVar12;
        goto LAB_00757925;
      }
    }
  }
  else {
LAB_00757aad:
    fVar12 = *(float *)(**(int **)(unaff_EBX + 0x44f075) + 0xc) - (float)in_stack_00000004[0x45];
    if (fVar12 < *(float *)(unaff_EBX + 0x1cf585) || fVar12 == *(float *)(unaff_EBX + 0x1cf585))
    goto LAB_00757925;
    uVar14 = (ulonglong)(uint)in_stack_00000004[0x41];
    TransitionToStance(in_stack_00000004,piVar9,in_stack_00000004[0x41]);
    piVar7 = piVar9;
  }
  piVar9 = (int *)in_stack_00000004[0x40];
LAB_00757925:
  if (piVar9 == (int *)0xd) {
    piVar7 = (int *)0x3e800000;
    (**(code **)(*piVar6 + 0x934))(piVar6,0x3e800000,uVar14);
  }
  piVar7 = (int *)(**(code **)(*in_stack_00000004 + 0xc4))(in_stack_00000004,piVar7);
  cVar4 = (**(code **)(*piVar7 + 0x140))(piVar7,0x400);
  if (cVar4 != '\0') {
    CFmtStrN<256,false>::CFmtStrN(this_04,local_24c,&UNK_0022be5e + unaff_EBX);
    if ((char)in_stack_00000004[0x47] != '\0') {
      pcVar8 = &DAT_0022be57 + unaff_EBX;
      pcVar10 = local_247 + local_144;
      if (pcVar10 < local_148) {
        do {
          cVar4 = *pcVar8;
          pcVar8 = pcVar8 + 1;
          *pcVar10 = cVar4;
          pcVar10 = pcVar10 + 1;
          if (pcVar10 == local_148) break;
        } while (*pcVar8 != '\0');
      }
      *pcVar10 = '\0';
      local_144 = (int)pcVar10 - (int)local_247;
    }
    local_250 = local_247;
    iVar5 = in_stack_00000004[0x42];
    this_00 = (CFmtStrN<256,false> *)in_stack_00000004[0x44];
    fVar12 = *(float *)(**(int **)(unaff_EBX + 0x44f075) + 0xc);
    iVar3 = in_stack_00000004[0x40];
    fVar1 = (float)in_stack_00000004[0x43];
    fVar11 = (float10)CountdownTimer::Now();
    dVar13 = 0.0;
    fVar2 = (float)in_stack_00000004[0x3c];
    if ((float)fVar11 <= fVar2) {
      fVar11 = (float10)CountdownTimer::Now();
      dVar13 = (double)(fVar2 - (float)fVar11);
    }
    CFmtStrN<256,false>::CFmtStrN
              (this_00,local_13c,unaff_EBX + 0x22bec9,dVar13,this_00,iVar3,iVar5,
               (double)(fVar12 - fVar1));
    pcVar8 = local_247 + local_144;
    if (pcVar8 < local_148) {
      pcVar10 = local_137;
      while (local_137[0] != '\0') {
        cVar4 = *pcVar10;
        pcVar10 = pcVar10 + 1;
        *pcVar8 = cVar4;
        pcVar8 = pcVar8 + 1;
        if (pcVar8 == local_148) break;
        local_137[0] = *pcVar10;
      }
    }
    *pcVar8 = '\0';
    local_144 = (int)pcVar8 - (int)local_250;
    piVar7 = (int *)(**(code **)(*in_stack_00000004 + 0x15c))(in_stack_00000004);
    (**(code **)(*piVar7 + 0x20c))(local_28,piVar7);
    uVar14 = 0x3e051eb800000001;
    NDebugOverlay::Text(local_28,local_250,true,0.13);
  }
  fVar11 = (float10)CountdownTimer::Now();
  if ((float)in_stack_00000004[0x3f] <= (float)fVar11 &&
      (float)fVar11 != (float)in_stack_00000004[0x3f]) {
    piVar7 = piVar6 + 0x818;
    piVar6 = (int *)(**(code **)(*piVar6 + 0x97c))(piVar6);
    iVar5 = (**(code **)(*piVar6 + 0xe8))(piVar6,piVar7);
    if (iVar5 == 1) {
      uVar14 = 0x3f19999a00000004;
      SetPosture();
    }
    else {
      iVar5 = (**(code **)(*piVar6 + 0xcc))(piVar6,piVar7);
      if (iVar5 == 1) {
        uVar14 = 0x3f19999a00000004;
        SetPosture();
      }
      else {
        iVar5 = (**(code **)(*piVar6 + 0xf0))(piVar6,piVar7);
        if (iVar5 == 1) {
          uVar14 = 0x3f19999a00000004;
          SetPosture();
        }
      }
    }
    fVar11 = (float10)CountdownTimer::Now();
    fVar12 = (float)fVar11 + *(float *)(unaff_EBX + 0x1ccf2d);
    if ((float)in_stack_00000004[0x3f] != fVar12) {
      (**(code **)(in_stack_00000004[0x3d] + 4))
                (in_stack_00000004 + 0x3d,in_stack_00000004 + 0x3f,uVar14);
      in_stack_00000004[0x3f] = (int)fVar12;
    }
    if (in_stack_00000004[0x3e] != 0x3f000000) {
      (**(code **)(in_stack_00000004[0x3d] + 4))(in_stack_00000004 + 0x3d,in_stack_00000004 + 0x3e);
      in_stack_00000004[0x3e] = 0x3f000000;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotBody::~CINSBotBody
 * Address: 00754c20
 * ---------------------------------------- */

/* CINSBotBody::~CINSBotBody() */

void __thiscall CINSBotBody::~CINSBotBody(CINSBotBody *this)

{
  PlayerBody *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x44827f;
  PlayerBody::~PlayerBody(this_00);
  return;
}



/* ----------------------------------------
 * CINSBotBody::~CINSBotBody
 * Address: 00754c50
 * ---------------------------------------- */

/* CINSBotBody::~CINSBotBody() */

void __thiscall CINSBotBody::~CINSBotBody(CINSBotBody *this)

{
  CINSBotBody *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSBotBody(this_00);
  operator_delete(in_stack_00000004);
  return;
}



