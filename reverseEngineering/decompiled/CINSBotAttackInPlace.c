/*
 * CINSBotAttackInPlace -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 42
 */

/* ----------------------------------------
 * CINSBotAttackInPlace::CINSBotAttackInPlace
 * Address: 0070b000
 * ---------------------------------------- */

/* CINSBotAttackInPlace::CINSBotAttackInPlace() */

void __thiscall CINSBotAttackInPlace::CINSBotAttackInPlace(CINSBotAttackInPlace *this)

{
  int *piVar1;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar1 = in_stack_00000004 + 0xe;
  in_stack_00000004[8] = 0;
  in_stack_00000004[9] = 0;
  *in_stack_00000004 = unaff_EBX + 0x48a1fd /* vtable for CINSBotAttackInPlace+0x8 */ /* vtable for CINSBotAttackInPlace+0x8 */ /* vtable for CINSBotAttackInPlace+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_0048a3a5 + unaff_EBX);
  in_stack_00000004[0xe] = unaff_EBX + 0x41d1ad /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_0 */
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
  (*(code *)(unaff_EBX + -0x4da89b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(piVar1,in_stack_00000004 + 0xf);
  in_stack_00000004[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10); /* timer_0.NetworkStateChanged() */
  in_stack_00000004[0x12] = 0;
  in_stack_00000004[0x11] = unaff_EBX + 0x41d1ad /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */; /* CountdownTimer timer_1 */
  (*(code *)(unaff_EBX + -0x4da89b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */))(in_stack_00000004 + 0x11,in_stack_00000004 + 0x12);
  in_stack_00000004[0x13] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x11] + 4))(in_stack_00000004 + 0x11,in_stack_00000004 + 0x13); /* timer_1.NetworkStateChanged() */
  if (in_stack_00000004[0x10] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0xe] + 4))(piVar1,in_stack_00000004 + 0x10); /* timer_0.NetworkStateChanged() */
    in_stack_00000004[0x10] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  }
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnStart
 * Address: 0070ac50
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotAttackInPlace::OnStart(CINSBotAttackInPlace *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  undefined4 uVar7;
  CINSNextBot *this_00;
  int unaff_EBX;
  float10 fVar8;
  CKnownEntity *in_stack_0000000c;
  undefined4 uVar9;
  undefined *puVar10;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x49bc9a /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */) == 0) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined **)(param_1 + 8) = &UNK_0027521e + unaff_EBX;
  }
  else {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,1);
    if (((piVar4 != (int *)0x0) && (iVar5 = (**(code **)(*piVar4 + 0x10))(piVar4), iVar5 != 0)) &&
       (cVar3 = (**(code **)(*piVar4 + 0x54))(piVar4), cVar3 == '\0')) {
      piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
      iVar5 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))(piVar6,in_stack_0000000c + 0x2060,piVar4);
      if (iVar5 == 0) {
        *(undefined4 *)param_1 = 3 /* Done */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x275321 /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */ /* "Should Not Attack This Threat" */;
        return param_1;
      }
      iVar5 = CINSPlayer::GetActiveINSWeapon();
      if (iVar5 != 0) {
        piVar6 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        pcVar2 = *(code **)(*piVar6 + 0xd8);
        uVar7 = (**(code **)(*piVar4 + 0x10))(piVar4);
        fVar1 = *(float *)(unaff_EBX + 0x219afa /* 0.5f */ /* 0.5f */ /* 0.5f */);
        (*pcVar2)(piVar6,uVar7,3,fVar1,0,unaff_EBX + 0x275617 /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */);
        fVar8 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
        if ((float)fVar8 <= fVar1) {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
          puVar10 = &UNK_0024ee1d + unaff_EBX;
          uVar9 = 0x3f800000 /* 1.0f */;
          uVar7 = 7;
          CINSBotBody::SetPosture();
        }
        else {
          (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))();
          puVar10 = &UNK_0024ee1d + unaff_EBX;
          uVar9 = 0x3f800000 /* 1.0f */;
          uVar7 = 7;
          CINSBotBody::SetPosture();
        }
        fVar8 = (float10)RandomFloat(0x41000000 /* 8.0f */,0x41400000 /* 12.0f */,uVar7,uVar9,puVar10);
        fVar1 = (float)fVar8;
        fVar8 = (float10)CountdownTimer::Now();
        if (*(float *)(param_2 + 0x4c) != (float)fVar8 + fVar1) {
          (**(code **)(*(int *)(param_2 + 0x44) + 4))(param_2 + 0x44,param_2 + 0x4c); /* timer_1.NetworkStateChanged() */
          *(float *)(param_2 + 0x4c) = (float)fVar8 + fVar1; /* timer_1.Start(...) */
        }
        if (*(float *)(param_2 + 0x48) != fVar1) {
          (**(code **)(*(int *)(param_2 + 0x44) + 4))(param_2 + 0x44,param_2 + 0x48); /* timer_1.NetworkStateChanged() */
          *(float *)(param_2 + 0x48) = fVar1; /* timer_1.m_duration */
        }
        (**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
        CINSBotLocomotion::ClearMovementRequests();
        *(undefined4 *)param_1 = 0 /* Continue */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
      CINSNextBot::ChooseBestWeapon(this_00,in_stack_0000000c);
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x275262 /* "Unable to determine active weapon." */ /* "Unable to determine active weapon." */ /* "Unable to determine active weapon." */;
      return param_1;
    }
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::Update
 * Address: 0070b140
 * ---------------------------------------- */

/* CINSBotAttackInPlace::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotAttackInPlace::Update(CINSBotAttackInPlace *this,CINSNextBot *param_1,float param_2)

{
  undefined4 *puVar1;
  code *pcVar2;
  char cVar3;
  int *piVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  Vector *pVVar10;
  void *pvVar11;
  CINSPlayer *this_00;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *pCVar12;
  CINSBotAttackAdvance *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  CBasePlayer *this_04;
  CBaseEntity *this_05;
  CINSBotAttackAdvance *this_06;
  INSVisionTraceFilterIgnoreTeam *this_07;
  int unaff_EBX;
  float10 fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  CINSNextBot *in_stack_0000000c;
  Vector *pVVar17;
  CGameTrace local_13c [12];
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
  int local_8c [4];
  int local_7c;
  undefined4 local_78;
  int local_74;
  undefined4 local_70;
  int local_6c;
  int local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  Vector local_58 [12];
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
  fVar13 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x4c) <= (float)fVar13 && /* timer_1.IsElapsed() */
      (float)fVar13 != *(float *)((int)param_2 + 0x4c)) {
    *(undefined4 *)param_1 = 3 /* Done */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x27513c /* " Timeout" */ /* " Timeout" */ /* " Timeout" */;
    return param_1;
  }
  fVar13 = (float10)CountdownTimer::Now();
  pCVar12 = (CINSNextBot *)param_2;
  if (*(float *)((int)param_2 + 0x40) <= (float)fVar13 && /* timer_0.IsElapsed() */
      (float)fVar13 != *(float *)((int)param_2 + 0x40)) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    piVar4 = (int *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
    if (piVar4 == (int *)0x0) {
      *(undefined4 *)param_1 = 3 /* Done */;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x275145 /* "No Known Threat" */ /* "No Known Threat" */ /* "No Known Threat" */;
      return param_1;
    }
    cVar3 = CINSNextBot::IsEscorting(in_stack_0000000c);
    if (((cVar3 == '\0') && (cVar3 = (**(code **)(*piVar4 + 0x38))(piVar4), cVar3 == '\0')) &&
       (cVar3 = (**(code **)(*piVar4 + 0x3c))(piVar4), cVar3 != '\0')) {
      pvVar11 = ::operator_new(0x5c);
      CINSBotAttackAdvance::CINSBotAttackAdvance(this_01);
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(void **)(param_1 + 4) = pvVar11;
      *(int *)(param_1 + 8) = unaff_EBX + 0x275184 /* "Advancing towards a lost target" */ /* "Advancing towards a lost target" */ /* "Advancing towards a lost target" */;
      return param_1;
    }
    puVar1 = *(undefined4 **)(unaff_EBX + 0x49b478 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    local_64 = *puVar1;
    local_60 = puVar1[1];
    local_5c = puVar1[2];
    uVar5 = (**(code **)(*piVar4 + 0x18))(piVar4);
    uVar6 = (**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
    cVar3 = CINSBotVision::IsLineOfFireClear(uVar6,uVar5,local_64,local_60,local_5c);
    if (cVar3 == '\0') {
      cVar3 = CINSPlayer::IsProned(this_00);
      if ((cVar3 != '\0') || (cVar3 = CINSPlayer::IsCrouched(this_02), cVar3 != '\0')) {
        (**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        CINSBotBody::SetPosture();
        *(undefined4 *)param_1 = 0 /* Continue */;
        *(undefined4 *)(param_1 + 4) = 0;
        *(undefined4 *)(param_1 + 8) = 0;
        return param_1;
      }
      cVar3 = CINSPlayer::InStanceTransition(this_03);
      if (cVar3 != '\0') goto LAB_0070b37b;
      pVVar10 = (Vector *)&local_4c;
      uVar5 = 0;
      pVVar17 = local_58;
      CBasePlayer::EyeVectors(this_04,(Vector *)in_stack_0000000c,pVVar17,pVVar10);
      piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))
                                (in_stack_0000000c,pVVar17,pVVar10,uVar5);
      fVar13 = (float10)(**(code **)(*piVar7 + 0x13c /* CINSBotBody::GetHullWidth */))(piVar7);
      fVar14 = (float)fVar13;
      fVar16 = local_4c * fVar14;
      fVar15 = local_48 * fVar14;
      fVar14 = fVar14 * local_44;
      (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_34,in_stack_0000000c);
      local_f0 = 0;
      local_40 = fVar16 + local_34;
      local_3c = fVar15 + local_30;
      local_38 = fVar14 + local_2c;
      iVar8 = CBaseEntity::GetTeamNumber(this_05);
      uVar6 = 0;
      uVar5 = 0;
      pCVar12 = in_stack_0000000c;
      CTraceFilterSimple::CTraceFilterSimple
                ((CTraceFilterSimple *)in_stack_0000000c,(IHandleEntity *)local_8c,
                 (int)in_stack_0000000c,(_func_bool_IHandleEntity_ptr_int *)0x0);
      local_8c[0] = unaff_EBX + 0x48a29c /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */ /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */ /* vtable for INSVisionTraceFilterIgnoreTeam+0x8 */;
      local_7c = 0;
      local_78 = 0;
      local_74 = 0;
      local_70 = 0;
      local_6c = 0;
      local_68 = (iVar8 == 2) + 2;
      pfVar9 = (float *)(**(code **)(*piVar4 + 0x18))(piVar4,pCVar12,uVar5,uVar6);
      local_9c = 0;
      local_cc = *pfVar9 - local_40;
      local_c8 = pfVar9[1] - local_3c;
      local_98 = 1;
      local_dc = local_40;
      local_c4 = pfVar9[2] - local_38;
      local_d8 = local_3c;
      local_d4 = local_38;
      local_a4 = 0;
      local_a8 = 0;
      local_ac = 0;
      local_97 = local_c8 * local_c8 + local_cc * local_cc + local_c4 * local_c4 != 0.0;
      local_b4 = 0;
      local_b8 = 0;
      local_bc = 0;
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49b624 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
                ((int *)**(undefined4 **)(unaff_EBX + 0x49b624 /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_dc,0x2006241,local_8c,
                 local_13c);
      piVar7 = *(int **)(unaff_EBX + 0x49b8ec /* &r_visualizetraces */ /* &r_visualizetraces */ /* &r_visualizetraces */);
      iVar8 = (**(code **)(*piVar7 + 0x40))(piVar7);
      if (iVar8 != 0) {
        iVar8 = (**(code **)(*piVar7 + 0x40))(piVar7);
        fVar14 = 0.5;
        if (iVar8 != 0) {
          fVar14 = -1.0;
        }
        DebugDrawLine((Vector *)local_13c,local_130,0xff,0,0,true,fVar14);
      }
      if ((*(float *)(unaff_EBX + 0x1ad9c0 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= local_110) || (local_105 != '\0')) {
        piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
        (**(code **)(*piVar4 + 200))(piVar4,&local_40,0x3f800000 /* 1.0f */);
      }
      else {
        piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
        fVar13 = (float10)(**(code **)(*piVar7 + 0x13c /* CINSBotBody::GetHullWidth */))(piVar7);
        (**(code **)(*(int *)in_stack_0000000c + 0x20c /* CINSNextBot::EyePosition */))(&local_28,in_stack_0000000c);
        fVar14 = (float)(*(uint *)(unaff_EBX + 0x219aac /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */) ^ (uint)(float)fVar13);
        local_dc = local_4c * fVar14 + local_28;
        local_d8 = local_48 * fVar14 + local_24;
        local_d4 = fVar14 * local_44 + local_20;
        pVVar10 = (Vector *)(**(code **)(*piVar4 + 0x18 /* INextBotEventResponder::OnContact */))(piVar4);
        UTIL_TraceLine((Vector *)&local_dc,pVVar10,0x2006241,(ITraceFilter *)local_8c,local_13c);
        if ((local_110 < *(float *)(unaff_EBX + 0x1ad9c0 /* 1.0f */ /* 1.0f */ /* 1.0f */)) && (local_105 == '\0')) {
          pvVar11 = ::operator_new(0x5c);
          CINSBotAttackAdvance::CINSBotAttackAdvance(this_06);
          *(undefined4 *)param_1 = 1 /* ChangeTo */;
          *(int *)(param_1 + 8) = unaff_EBX + 0x275166 /* "Advancing because of no LOS" */ /* "Advancing because of no LOS" */ /* "Advancing because of no LOS" */;
          *(void **)(param_1 + 4) = pvVar11;
          INSVisionTraceFilterIgnoreTeam::~INSVisionTraceFilterIgnoreTeam(this_07);
          return param_1;
        }
        piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x96c /* CINSNextBot::GetLocomotionInterface */))(in_stack_0000000c);
        (**(code **)(*piVar4 + 200))(piVar4,&local_dc,0x3f800000 /* 1.0f */);
      }
      local_8c[0] = unaff_EBX + 0x489424 /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */ /* vtable for INSVisionTraceFilter+0x8 */;
      local_70 = 0;
      if (local_74 < 0) {
        local_6c = local_7c;
      }
      else {
        if (local_7c != 0) {
          (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x49b724 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                    ((int *)**(undefined4 **)(unaff_EBX + 0x49b724 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_7c);
          local_7c = 0;
        }
        local_78 = 0;
        local_6c = 0;
      }
    }
    else {
      piVar7 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      pcVar2 = *(code **)(*piVar7 + 0xd8);
      uVar5 = (**(code **)(*piVar4 + 0x10 /* ILocomotion::OnLeaveGround */))(piVar4);
      (*pcVar2)(piVar7,uVar5,3,0x3f19999a /* 0.6f */,0,unaff_EBX + 0x275155 /* "Continue our Aim" */ /* "Continue our Aim" */ /* "Continue our Aim" */);
    }
    fVar13 = (float10)CountdownTimer::Now();
    fVar14 = (float)fVar13 + *(float *)(unaff_EBX + 0x219604 /* 0.5f */ /* 0.5f */ /* 0.5f */);
    pCVar12 = extraout_ECX;
    if (*(float *)((int)param_2 + 0x40) != fVar14) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x40); /* timer_0.NetworkStateChanged() */
      *(float *)((int)param_2 + 0x40) = fVar14; /* timer_0.Start(0.5f) */
      pCVar12 = (CINSNextBot *)param_2;
    }
    if (*(int *)((int)param_2 + 0x3c) != 0x3f000000 /* 0.5f */) {
      (**(code **)(*(int *)((int)param_2 + 0x38) + 4))((int)param_2 + 0x38,(int)param_2 + 0x3c); /* timer_0.NetworkStateChanged() */
      *(undefined4 *)((int)param_2 + 0x3c) = 0x3f000000 /* 0.5f */;
      pCVar12 = extraout_ECX_00;
    }
  }
  CINSNextBot::FireWeaponAtEnemy(pCVar12);
LAB_0070b37b:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnEnd
 * Address: 0070a5e0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotAttackInPlace::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::GetName
 * Address: 0070b9c0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::GetName() const */

int CINSBotAttackInPlace::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2748a2 /* "AttackInPlace" */ /* "AttackInPlace" */ /* "AttackInPlace" */;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldHurry
 * Address: 0070a5f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotAttackInPlace::ShouldHurry(CINSBotAttackInPlace *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldHurry
 * Address: 0070a600
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotAttackInPlace::ShouldHurry(INextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldRetreat
 * Address: 0070aa80
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldRetreat(INextBot const*) const */

void __thiscall CINSBotAttackInPlace::ShouldRetreat(CINSBotAttackInPlace *this,INextBot *param_1)

{
  ShouldRetreat(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldRetreat
 * Address: 0070aa90
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldRetreat(INextBot const*) const */

char __thiscall CINSBotAttackInPlace::ShouldRetreat(CINSBotAttackInPlace *this,INextBot *param_1)

{
  float fVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CINSPlayer *this_02;
  CINSNextBot *this_03;
  int unaff_EBX;
  char cVar7;
  float10 fVar8;
  int *in_stack_00000008;
  
  iVar4 = __i686_get_pc_thunk_bx();
  cVar7 = '\x02';
  iVar4 = *(int *)(iVar4 + 0x1c);
  if (iVar4 != 0) {
    cVar3 = CINSNextBot::CanCheckRetreat(this_00);
    if (cVar3 != '\0') {
      piVar5 = (int *)(**(code **)(*in_stack_00000008 + 0xdc))(in_stack_00000008);
      pcVar2 = *(code **)(*piVar5 + 0xdc);
      iVar6 = CBaseEntity::GetTeamNumber(this_01);
      iVar6 = (*pcVar2)(piVar5,(iVar6 == 2) + '\x02',1,0xbf800000 /* -1.0f */);
      fVar8 = (float10)CINSPlayer::GetHealthFraction(this_02);
      fVar1 = *(float *)(unaff_EBX + 0x219cb7 /* 0.5f */ /* 0.5f */ /* 0.5f */);
      if (((fVar1 <= (float)fVar8) || (iVar6 < 2)) || (cVar7 = '\x01', 1 < *(int *)(iVar4 + 0x1e94))
         ) {
        cVar7 = '\x02';
        cVar3 = CINSNextBot::IsSuppressed(this_03);
        if ((cVar3 != '\0') && (iVar6 != 0)) {
          cVar7 = (fVar1 <= (float)*(int *)(iVar4 + 0xb448) / (float)iVar6) + '\x01';
        }
      }
    }
  }
  return cVar7;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldAttack
 * Address: 0070a610
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotAttackInPlace::ShouldAttack
          (CINSBotAttackInPlace *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldAttack
 * Address: 0070a620
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotAttackInPlace::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnContact
 * Address: 0070a690
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void CINSBotAttackInPlace::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnMoveToSuccess
 * Address: 0070a6c0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotAttackInPlace::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnMoveToFailure
 * Address: 0070a6f0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void CINSBotAttackInPlace::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnStuck
 * Address: 0070a720
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnStuck(CINSNextBot*) */

void CINSBotAttackInPlace::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnUnStuck
 * Address: 0070a750
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnUnStuck(CINSNextBot*) */

void CINSBotAttackInPlace::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnInjured
 * Address: 0070a7b0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackInPlace::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnKilled
 * Address: 0070a7e0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void CINSBotAttackInPlace::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnOtherKilled
 * Address: 0070a810
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&)
    */

void CINSBotAttackInPlace::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnSight
 * Address: 0070a840
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackInPlace::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnLostSight
 * Address: 0070a870
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnLostSight(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackInPlace::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnWeaponFired
 * Address: 0070a8a0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void CINSBotAttackInPlace::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnCommandApproach
 * Address: 0070a930
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void CINSBotAttackInPlace::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnCommandApproach
 * Address: 0070a960
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackInPlace::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnCommandString
 * Address: 0070a9c0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnCommandString(CINSNextBot*, char const*) */

void CINSBotAttackInPlace::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnBlinded
 * Address: 0070a9f0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnBlinded(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackInPlace::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnCommandAttack
 * Address: 0070a900
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotAttackInPlace::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnCommandRetreat
 * Address: 0070a990
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void CINSBotAttackInPlace::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnHeardFootsteps
 * Address: 0070aa20
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void CINSBotAttackInPlace::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnNavAreaChanged
 * Address: 0070a8d0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void CINSBotAttackInPlace::OnNavAreaChanged
               (CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnPostureChanged
 * Address: 0070a780
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnPostureChanged(CINSNextBot*) */

void CINSBotAttackInPlace::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::OnSeeSomethingSuspicious
 * Address: 0070aa50
 * ---------------------------------------- */

/* CINSBotAttackInPlace::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector
   const&) */

void CINSBotAttackInPlace::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldIronsight
 * Address: 0070a650
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldIronsight(INextBot const*) const */

void __thiscall CINSBotAttackInPlace::ShouldIronsight(CINSBotAttackInPlace *this,INextBot *param_1)

{
  ShouldIronsight(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldIronsight
 * Address: 0070a660
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldIronsight(INextBot const*) const */

undefined4 __cdecl CINSBotAttackInPlace::ShouldIronsight(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldProne
 * Address: 0070a670
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldProne(INextBot const*) const */

void __thiscall CINSBotAttackInPlace::ShouldProne(CINSBotAttackInPlace *this,INextBot *param_1)

{
  ShouldProne(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldProne
 * Address: 0070a680
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldProne(INextBot const*) const */

undefined4 __cdecl CINSBotAttackInPlace::ShouldProne(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldWalk
 * Address: 0070a630
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::ShouldWalk(INextBot const*) const */

void __thiscall CINSBotAttackInPlace::ShouldWalk(CINSBotAttackInPlace *this,INextBot *param_1)

{
  ShouldWalk(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::ShouldWalk
 * Address: 0070a640
 * ---------------------------------------- */

/* CINSBotAttackInPlace::ShouldWalk(INextBot const*) const */

undefined4 __cdecl CINSBotAttackInPlace::ShouldWalk(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::~CINSBotAttackInPlace
 * Address: 0070b9e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::~CINSBotAttackInPlace() */

void __thiscall CINSBotAttackInPlace::~CINSBotAttackInPlace(CINSBotAttackInPlace *this)

{
  ~CINSBotAttackInPlace(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::~CINSBotAttackInPlace
 * Address: 0070b9f0
 * ---------------------------------------- */

/* CINSBotAttackInPlace::~CINSBotAttackInPlace() */

void __thiscall CINSBotAttackInPlace::~CINSBotAttackInPlace(CINSBotAttackInPlace *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x489813 /* vtable for CINSBotAttackInPlace+0x8 */ /* vtable for CINSBotAttackInPlace+0x8 */ /* vtable for CINSBotAttackInPlace+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x4899bb /* vtable for CINSBotAttackInPlace+0x1b0 */ /* vtable for CINSBotAttackInPlace+0x1b0 */ /* vtable for CINSBotAttackInPlace+0x1b0 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x49b783 /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::~CINSBotAttackInPlace
 * Address: 0070ba20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotAttackInPlace::~CINSBotAttackInPlace() */

void __thiscall CINSBotAttackInPlace::~CINSBotAttackInPlace(CINSBotAttackInPlace *this)

{
  ~CINSBotAttackInPlace(this);
  return;
}



/* ----------------------------------------
 * CINSBotAttackInPlace::~CINSBotAttackInPlace
 * Address: 0070ba30
 * ---------------------------------------- */

/* CINSBotAttackInPlace::~CINSBotAttackInPlace() */

void __thiscall CINSBotAttackInPlace::~CINSBotAttackInPlace(CINSBotAttackInPlace *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = &UNK_004897ca + unaff_EBX;
  in_stack_00000004[1] = unaff_EBX + 0x489972 /* vtable for CINSBotAttackInPlace+0x1b0 */ /* vtable for CINSBotAttackInPlace+0x1b0 */ /* vtable for CINSBotAttackInPlace+0x1b0 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



