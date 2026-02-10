/*
 * CINSBotActionTraining -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 13
 */

/* ----------------------------------------
 * CINSBotActionTraining::OnStart
 * Address: 0073d140
 * ---------------------------------------- */

/* CINSBotActionTraining::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void __thiscall
CINSBotActionTraining::OnStart(CINSBotActionTraining *this,CINSNextBot *param_1,Action *param_2)

{
  undefined4 uVar1;
  int iVar2;
  char *pcVar3;
  undefined4 *puVar4;
  CINSPathFollower *this_00;
  CINSNextBot *this_01;
  CBaseEntity *this_02;
  int unaff_EBX;
  float10 fVar5;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  CINSPathFollower::Invalidate(this_00);
  fVar5 = (float10)CINSNextBot::GetDesiredPathLookAheadRange(this_01);
  puVar4 = *(undefined4 **)(unaff_EBX + 0x469481 /* &vec3_origin */ /* &vec3_origin */);
  *(float *)(param_2 + 0x4818) = (float)fVar5;
  *(undefined4 *)(param_2 + 0x48b8) = *puVar4;
  uVar1 = puVar4[2];
  *(undefined4 *)(param_2 + 0x48bc) = puVar4[1];
  *(undefined4 *)(param_2 + 0x48c0) = uVar1;
  pcVar3 = (char *)in_stack_0000000c[0x36];
  if ((char *)in_stack_0000000c[0x36] == (char *)0x0) {
    pcVar3 = &UNK_0021c930 + unaff_EBX;
  }
  iVar2 = _V_stricmp(pcVar3,(char *)(unaff_EBX + 0x1f6a00 /* "vip_trainer" */ /* "vip_trainer" */));
  if (iVar2 == 0) {
    *(undefined4 *)(param_2 + 0x38) = 0;
  }
  else {
    pcVar3 = (char *)in_stack_0000000c[0x36];
    if ((char *)in_stack_0000000c[0x36] == (char *)0x0) {
      pcVar3 = &UNK_0021c930 + unaff_EBX;
    }
    iVar2 = _V_stricmp(pcVar3,(char *)(unaff_EBX + 0x1f69f9 /* "driver" */ /* "driver" */));
    if (iVar2 == 0) {
      *(undefined4 *)(param_2 + 0x38) = 1;
      puVar4 = (undefined4 *)(**(code **)(*in_stack_0000000c + 0xc))(in_stack_0000000c);
      *(undefined4 *)(unaff_EBX + 0x5b02b5 /* CINSBotActionTraining::m_pDriver */ /* CINSBotActionTraining::m_pDriver */) = *puVar4;
    }
    else {
      iVar2 = CBaseEntity::GetTeamNumber(this_02);
      *(uint *)(param_2 + 0x38) = (uint)(iVar2 == 3) * 3 + -1;
    }
  }
  *(undefined1 *)(in_stack_0000000c + 0x8a4) = 1;
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::Update
 * Address: 0073d2e0
 * ---------------------------------------- */

/* CINSBotActionTraining::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionTraining::Update(CINSBotActionTraining *this,CINSNextBot *param_1,float param_2)

{
  uint *puVar1;
  float *pfVar2;
  code *pcVar3;
  char cVar4;
  bool bVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  CNavArea *pCVar9;
  Vector *pVVar10;
  CNavArea *pCVar11;
  void *pvVar12;
  undefined4 uVar13;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CINSPathFollower *this_01;
  CINSNavArea *this_02;
  CINSNavArea *this_03;
  CBaseEntity *this_04;
  CINSBotCombat *this_05;
  Path *this_06;
  uint uVar14;
  undefined4 *puVar15;
  int unaff_EBX;
  float10 fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  int *in_stack_0000000c;
  Path *this_07;
  int *piVar20;
  Vector *pVVar21;
  float ****ppppfVar22;
  CNavMesh *pCVar23;
  CNavMesh *this_08;
  Vector *pVVar24;
  undefined4 uVar25;
  INextBot *local_7c;
  int *local_78;
  int *local_74;
  int *local_70;
  undefined *local_64;
  Vector *local_60;
  undefined4 local_5c;
  undefined4 local_58;
  CNavMesh *local_54;
  undefined4 local_50;
  undefined4 local_4c;
  float local_48;
  float local_44;
  float local_40;
  float ***local_3c;
  Vector *local_38;
  float local_34 [2];
  CNavArea *local_2c [3];
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x73d2eb;
  __i686_get_pc_thunk_bx();
  piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  piVar20 = (int *)0x0;
  iVar7 = (**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
  if (iVar7 != 0) {
    piVar6 = (int *)(**(code **)(*in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    piVar20 = in_stack_0000000c + 0x818;
    iVar7 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))(piVar6,piVar20,iVar7);
    if (iVar7 == 1) {
      pvVar12 = ::operator_new(0x88);
      CINSBotCombat::CINSBotCombat(this_05);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      *(void **)(param_1 + 4) = pvVar12;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2432d2 /* "Attacking nearby threats" */ /* "Attacking nearby threats" */;
      return param_1;
    }
  }
  iVar7 = *(int *)((int)param_2 + 0x38);
  if (iVar7 == 2) {
    local_74 = *(int **)(&DAT_004694ed + unaff_EBX);
    local_70 = (int *)*local_74;
    local_78 = *(int **)(unaff_EBX + 0x46960d /* &g_pGameRules */ /* &g_pGameRules */);
    uVar14 = *(uint *)(*local_78 + 0x270);
    if (uVar14 != 0xffffffff) goto LAB_0073d391;
LAB_0073d460:
    fVar19 = *(float *)((int)param_2 + 0x48b8);
  }
  else {
    local_74 = *(int **)(&DAT_004694ed + unaff_EBX);
    local_70 = (int *)*local_74;
    local_78 = *(int **)(unaff_EBX + 0x46960d /* &g_pGameRules */ /* &g_pGameRules */);
    uVar14 = *(uint *)(*local_78 + 0x26c);
    if (uVar14 == 0xffffffff) goto LAB_0073d460;
LAB_0073d391:
    iVar8 = (int)local_70 + (uVar14 & 0xffff) * 0x18;
    this_00 = (CBaseEntity *)(uVar14 >> 0x10);
    if ((*(CBaseEntity **)(iVar8 + 8) != this_00) || (iVar8 = *(int *)(iVar8 + 4), iVar8 == 0))
    goto LAB_0073d460;
    if ((*(byte *)(iVar8 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
      this_00 = extraout_ECX;
    }
    if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
      this_00 = extraout_ECX_00;
    }
    fVar19 = *(float *)(iVar8 + 0x208);
    fVar17 = (float)in_stack_0000000c[0x83] - *(float *)(iVar8 + 0x20c);
    fVar18 = (float)in_stack_0000000c[0x84] - *(float *)(iVar8 + 0x210);
    fVar17 = SQRT(fVar17 * fVar17 +
                  ((float)in_stack_0000000c[0x82] - fVar19) *
                  ((float)in_stack_0000000c[0x82] - fVar19) + fVar18 * fVar18);
    if (fVar17 < *(float *)(unaff_EBX + 0x1ebedd /* 64.0f */ /* 64.0f */) || fVar17 == *(float *)(unaff_EBX + 0x1ebedd /* 64.0f */ /* 64.0f */)) {
      iVar7 = *(int *)((int)param_2 + 0x38);
      goto LAB_0073d460;
    }
    if ((*(byte *)(iVar8 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
      fVar19 = *(float *)(iVar8 + 0x208);
    }
    *(float *)((int)param_2 + 0x48b8) = fVar19;
    *(undefined4 *)((int)param_2 + 0x48bc) = *(undefined4 *)(iVar8 + 0x20c);
    *(undefined4 *)((int)param_2 + 0x48c0) = *(undefined4 *)(iVar8 + 0x210);
    iVar7 = *(int *)((int)param_2 + 0x38);
  }
  pfVar2 = (float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */);
  if (((((fVar19 < *(float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */) || fVar19 == *(float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */))
        || (fVar17 = *(float *)(unaff_EBX + 0x1e7d45 /* 0.01f */ /* 0.01f */), fVar17 <= fVar19)) ||
       (fVar19 = *(float *)((int)param_2 + 0x48bc), fVar19 < *pfVar2 || fVar19 == *pfVar2)) ||
      ((fVar17 <= fVar19 ||
       (fVar19 = *(float *)((int)param_2 + 0x48c0), fVar19 < *pfVar2 || fVar19 == *pfVar2)))) ||
     (fVar17 <= fVar19)) {
    piVar6 = piVar20;
    if (iVar7 != 1) {
      fVar16 = (float10)CountdownTimer::Now();
      if (*(float *)((int)param_2 + 0x48b4) <= (float)fVar16 &&
          (float)fVar16 != *(float *)((int)param_2 + 0x48b4)) {
        fVar16 = (float10)CountdownTimer::Now();
        fVar19 = *(float *)(&DAT_001e746d + unaff_EBX);
        if (*(float *)((int)param_2 + 0x48b4) != (float)fVar16 + fVar19) {
          (**(code **)(*(int *)((int)param_2 + 0x48ac) + 4))
                    ((int)param_2 + 0x48ac,(int)param_2 + 0x48b4);
          *(float *)((int)param_2 + 0x48b4) = (float)fVar16 + fVar19;
        }
        if (*(int *)((int)param_2 + 0x48b0) != 0x3f000000 /* 0.5f */) {
          (**(code **)(*(int *)((int)param_2 + 0x48ac) + 4))
                    ((int)param_2 + 0x48ac,(int)param_2 + 0x48b0);
          *(undefined4 *)((int)param_2 + 0x48b0) = 0x3f000000 /* 0.5f */;
        }
        local_58 = *(undefined4 *)((int)param_2 + 0x48b8);
        pVVar21 = (Vector *)(in_stack_0000000c + 0x818);
        local_5c = 0;
        local_64 = &UNK_00457265 + unaff_EBX;
        local_54 = *(CNavMesh **)((int)param_2 + 0x48bc);
        local_50 = *(undefined4 *)((int)param_2 + 0x48c0);
        local_4c = 0xffffffff;
        local_60 = pVVar21;
        iVar7 = CNavMesh::GetNearestNavArea
                          (local_54,**(undefined4 **)(unaff_EBX + 0x4693cd /* &TheNavMesh */ /* &TheNavMesh */),&local_58,0,0x461c4000 /* 10000.0f */,0
                           ,1,0);
        if ((iVar7 != 0) && (iVar7 = CINSNavArea::GetAssociatedControlPoint(this_02), iVar7 != -1))
        {
          local_4c = CINSNavArea::GetAssociatedControlPoint(this_03);
        }
        piVar20 = (int *)(**(code **)(in_stack_0000000c[0x818] + 0xd0))(pVVar21);
        fVar16 = (float10)(**(code **)(*piVar20 + 0x14c /* CBaseEntity::ImpactTrace */))(piVar20);
        local_48 = (float)fVar16;
        piVar20 = (int *)(**(code **)(in_stack_0000000c[0x818] + 0xd0))(pVVar21);
        fVar16 = (float10)(**(code **)(*piVar20 + 0x150 /* CBaseEntity::OnControls */))(piVar20);
        local_44 = (float)fVar16;
        piVar20 = (int *)(**(code **)(in_stack_0000000c[0x818] + 0xd0))(pVVar21);
        fVar16 = (float10)(**(code **)(*piVar20 + 0x154 /* CBaseEntity::HasTarget */))(piVar20);
        this_07 = (Path *)((int)param_2 + 0x3c);
        local_40 = (float)fVar16;
        local_1d = *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
        if (((bool)local_1d) &&
           (iVar7 = *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar8 = ThreadGetCurrentId(),
           iVar7 == iVar8)) {
          piVar20 = *(int **)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
          if (*piVar20 != unaff_EBX + 0x1ec8f8 /* "Path::Compute(goal)" */ /* "Path::Compute(goal)" */) {
            piVar20 = (int *)CVProfNode::GetSubNode
                                       ((char *)piVar20,unaff_EBX + 0x1ec8f8 /* "Path::Compute(goal)" */ /* "Path::Compute(goal)" */,(char *)0x0,
                                        unaff_EBX + 0x1ec8c3 /* "NextBotSpiky" */ /* "NextBotSpiky" */);
            *(int **)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar20;
          }
          puVar1 = (uint *)(piVar20[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) +
                           4);
          *puVar1 = *puVar1 | 4;
          CVProfNode::EnterScope();
          *(undefined1 *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
        }
        (**(code **)(*(int *)((int)param_2 + 0x3c) + 0x44))(this_07);
        uVar13 = (**(code **)(in_stack_0000000c[0x818] + 0xe4))(pVVar21);
        piVar20 = (int *)(**(code **)(in_stack_0000000c[0x818] + 200))(pVVar21);
        pCVar9 = (CNavArea *)(**(code **)(*piVar20 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar20);
        if (pCVar9 == (CNavArea *)0x0) {
LAB_0073db65:
          pCVar23 = (CNavMesh *)0x2;
          (**(code **)(*(int *)((int)param_2 + 0x3c) + 0x60))(this_07,pVVar21,2);
          pCVar11 = (CNavArea *)this_07;
          pVVar10 = pVVar21;
        }
        else {
          this_08 = (CNavMesh *)((int)param_2 + 0x48b8);
          uVar25 = 0x43480000 /* 200.0f */;
          pVVar10 = (Vector *)
                    CNavMesh::GetNearestNavArea
                              (this_08,**(undefined4 **)(unaff_EBX + 0x4693cd /* &TheNavMesh */ /* &TheNavMesh */),this_08,1,0x43480000 /* 200.0f */,
                               1,1,1);
          if (pCVar9 == (CNavArea *)pVVar10) {
LAB_0073ddaa:
            Path::BuildTrivialPath((Path *)this_08,(INextBot *)this_07,pVVar21);
            pCVar11 = (CNavArea *)this_07;
            pVVar10 = pVVar21;
            pCVar23 = this_08;
          }
          else {
            ppppfVar22 = *(float *****)((int)param_2 + 0x48b8);
            pVVar24 = *(Vector **)((int)param_2 + 0x48bc);
            local_34[0] = *(float *)((int)param_2 + 0x48c0);
            local_3c = (float ***)ppppfVar22;
            local_38 = pVVar24;
            if (pVVar10 == (Vector *)0x0) {
              ppppfVar22 = &local_3c;
              uVar25 = 0;
              pVVar24 = (Vector *)local_34;
              CNavMesh::GetGroundHeight
                        ((CNavMesh *)0x0,(Vector *)**(undefined4 **)(unaff_EBX + 0x4693cd /* &TheNavMesh */ /* &TheNavMesh */),
                         (float *)ppppfVar22,pVVar24);
            }
            else {
              fVar16 = (float10)CNavArea::GetZ((CNavArea *)pVVar10,(float)pVVar10,(float)ppppfVar22)
              ;
              local_34[0] = (float)fVar16;
            }
            local_2c[0] = (CNavArea *)0x0;
            (**(code **)(in_stack_0000000c[0x818] + 200))(pVVar21,ppppfVar22,pVVar24,uVar25);
            iVar7 = CBaseEntity::GetTeamNumber(this_04);
            pCVar11 = pCVar9;
            pCVar23 = this_08;
            bVar5 = NavAreaBuildPath<CINSNextBotPathCost>
                              (pCVar9,(CNavArea *)pVVar10,(Vector *)this_08,
                               (CINSNextBotPathCost *)&local_64,local_2c,0.0,iVar7,false);
            if (local_2c[0] != (CNavArea *)0x0) {
              if (pCVar9 == local_2c[0]) goto LAB_0073ddaa;
              iVar7 = 1;
              pCVar11 = local_2c[0];
              do {
                pCVar11 = *(CNavArea **)(pCVar11 + 0x88);
                if (pCVar11 == (CNavArea *)0x0) {
                  if (iVar7 == 1) goto LAB_0073ddaa;
LAB_0073da7e:
                  *(int *)((int)param_2 + 0x4440) = iVar7;
                  goto LAB_0073da84;
                }
                iVar7 = iVar7 + 1;
                if (pCVar9 == pCVar11) goto LAB_0073da7e;
              } while (iVar7 != 0xff);
              *(undefined4 *)((int)param_2 + 0x4440) = 0xff;
LAB_0073da84:
              iVar7 = iVar7 + -1;
              puVar15 = (undefined4 *)((int)param_2 + 0x40 + iVar7 * 0x44);
              pCVar9 = local_2c[0];
              while( true ) {
                *puVar15 = pCVar9;
                uVar25 = *(undefined4 *)(pCVar9 + 0x8c);
                puVar15[6] = 0;
                puVar15[1] = uVar25;
                puVar15 = puVar15 + -0x11;
                pCVar9 = *(CNavArea **)(pCVar9 + 0x88);
                if ((pCVar9 == (CNavArea *)0x0) || (iVar7 == 0)) break;
                iVar7 = iVar7 + -1;
              }
              if (bVar5) {
                iVar7 = *(int *)((int)param_2 + 0x4440) * 0x44;
                *(CNavArea **)((int)param_2 + 0x40 + iVar7) = local_2c[0];
                *(float ****)(this_07 + iVar7 + 0xc) = local_3c;
                *(Vector **)(this_07 + iVar7 + 0x10) = local_38;
                *(float *)(this_07 + iVar7 + 0x14) = local_34[0];
                iVar7 = *(int *)((int)param_2 + 0x4440);
                iVar8 = iVar7 * 0x44 + (int)param_2;
                *(undefined4 *)(iVar8 + 0x54) = 0;
                *(undefined4 *)(iVar8 + 0x44) = 9;
                *(undefined4 *)(iVar8 + 0x58) = 0;
                *(int *)((int)param_2 + 0x4440) = iVar7 + 1;
              }
              pVVar10 = pVVar21;
              cVar4 = Path::ComputePathDetails(this_07,(INextBot *)this_07,pVVar21);
              if (cVar4 == '\0') {
                (**(code **)(*(int *)((int)param_2 + 0x3c) + 0x44))(this_07,pVVar10,uVar13);
                goto LAB_0073db65;
              }
              Path::Optimize((INextBot *)this_07);
              Path::PostProcess(this_06);
              pCVar23 = (CNavMesh *)(uint)!bVar5;
              (**(code **)(*(int *)((int)param_2 + 0x3c) + 0x60))(this_07,pVVar21,pCVar23);
              pCVar11 = (CNavArea *)this_07;
              pVVar10 = pVVar21;
            }
          }
        }
        if ((local_1d != '\0') &&
           (((*(char *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
             (*(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
            (iVar7 = *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
            iVar8 = ThreadGetCurrentId(pCVar11,pVVar10,pCVar23), iVar7 == iVar8)))) {
          cVar4 = CVProfNode::ExitScope();
          if (cVar4 == '\0') {
            iVar7 = *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
          }
          else {
            iVar7 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
            *(int *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar7;
          }
          *(bool *)(*(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
               iVar7 == *(int *)(unaff_EBX + 0x469689 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
        }
      }
      local_70 = in_stack_0000000c + 0x818;
      local_7c = (INextBot *)((int)param_2 + 0x3c);
      piVar20 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      (**(code **)(*piVar20 + 0x160 /* PlayerBody::ForceLookAtExpire */))(piVar20);
      CINSPathFollower::Update(this_01,local_7c);
      iVar7 = *(int *)((int)param_2 + 0x38);
      piVar20 = local_70;
      goto LAB_0073d4ea;
    }
  }
  else {
LAB_0073d4ea:
    piVar6 = piVar20;
    if (iVar7 == 0) {
      uVar14 = *(uint *)(unaff_EBX + 0x5b0115 /* CINSBotActionTraining::m_pDriver */ /* CINSBotActionTraining::m_pDriver */);
      if (uVar14 != 0xffffffff) {
        iVar8 = *local_74 + (uVar14 & 0xffff) * 0x18;
        if ((*(CBaseCombatCharacter **)(iVar8 + 8) == (CBaseCombatCharacter *)(uVar14 >> 0x10)) &&
           (piVar6 = *(int **)(iVar8 + 4), piVar6 != (int *)0x0)) {
          cVar4 = CBaseCombatCharacter::IsAbleToSee
                            ((CBaseCombatCharacter *)(uVar14 >> 0x10),in_stack_0000000c,piVar6,1);
          if (cVar4 != '\0') {
            piVar20 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
            uVar13 = 0;
            uVar14 = *(uint *)(unaff_EBX + 0x5b0115 /* CINSBotActionTraining::m_pDriver */ /* CINSBotActionTraining::m_pDriver */);
            if ((uVar14 != 0xffffffff) &&
               (iVar7 = *local_74 + (uVar14 & 0xffff) * 0x18, *(uint *)(iVar7 + 8) == uVar14 >> 0x10
               )) {
              uVar13 = *(undefined4 *)(iVar7 + 4);
            }
            (**(code **)(*piVar20 + 0xd8 /* PlayerBody::AimHeadTowards */))(piVar20,uVar13,2,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x2454e3 /* "Watching the driver." */ /* "Watching the driver." */);
            goto LAB_0073d622;
          }
          iVar7 = *(int *)((int)param_2 + 0x38);
          goto LAB_0073d547;
        }
      }
    }
    else {
LAB_0073d547:
      piVar20 = piVar6;
      if (iVar7 == 1) goto LAB_0073dd60;
    }
    piVar6 = piVar20;
    fVar19 = *(float *)((int)param_2 + 0x48b8);
    pfVar2 = (float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */);
    if ((((fVar19 < *(float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */) || fVar19 == *(float *)(unaff_EBX + 0x1ebee1 /* -0.01f */ /* -0.01f */))
         || (fVar17 = *(float *)(unaff_EBX + 0x1e7d45 /* 0.01f */ /* 0.01f */), fVar17 <= fVar19)) ||
        (fVar19 = *(float *)((int)param_2 + 0x48bc), fVar19 < *pfVar2 || fVar19 == *pfVar2)) ||
       (((fVar17 <= fVar19 ||
         (fVar19 = *(float *)((int)param_2 + 0x48c0), fVar19 < *pfVar2 || fVar19 == *pfVar2)) ||
        ((fVar17 <= fVar19 || (iVar7 == 2)))))) goto LAB_0073d622;
    uVar14 = *(uint *)(*local_78 + 0x274);
    if (((uVar14 != 0xffffffff) &&
        (iVar7 = *local_74 + (uVar14 & 0xffff) * 0x18, *(uint *)(iVar7 + 8) == uVar14 >> 0x10)) &&
       (iVar7 = *(int *)(iVar7 + 4), iVar7 != 0)) {
      piVar20 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c);
      (**(code **)(*piVar20 + 0xd8 /* PlayerBody::AimHeadTowards */))(piVar20,iVar7,2,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x2454f8 /* "Watching the player." */ /* "Watching the player." */);
      goto LAB_0073d622;
    }
  }
LAB_0073dd60:
  piVar20 = (int *)(**(code **)(*in_stack_0000000c + 0x970 /* CINSNextBot::GetBodyInterface */))(in_stack_0000000c,piVar6);
  pcVar3 = *(code **)(*piVar20 + 0xd8);
  uVar13 = UTIL_GetListenServerHost();
  (*pcVar3)(piVar20,uVar13,2,0x3f800000 /* 1.0f */,0,unaff_EBX + 0x2454f8 /* "Watching the player." */ /* "Watching the player." */);
LAB_0073d622:
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionTraining::OnEnd
 * Address: 0073cec0
 * ---------------------------------------- */

/* CINSBotActionTraining::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionTraining::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::GetName
 * Address: 0073de90
 * ---------------------------------------- */

/* CINSBotActionTraining::GetName() const */

int CINSBotActionTraining::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f5d67 /* "Training" */ /* "Training" */;
}



/* ----------------------------------------
 * CINSBotActionTraining::ShouldAttack
 * Address: 0073cf40
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionTraining::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionTraining::ShouldAttack
          (CINSBotActionTraining *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::ShouldAttack
 * Address: 0073cf50
 * ---------------------------------------- */

/* CINSBotActionTraining::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionTraining::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotActionTraining::OnMoveToSuccess
 * Address: 0073ced0
 * ---------------------------------------- */

/* CINSBotActionTraining::OnMoveToSuccess(CINSNextBot*, Path const*) */

void CINSBotActionTraining::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int extraout_EDX;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  puVar1 = *(undefined4 **)(unaff_EBX + 0x4696eb /* &vec3_origin */ /* &vec3_origin */);
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  *(undefined4 *)(extraout_EDX + 0x48b8 /* CINSBotTacticalMonitor::CheckPosture */ /* CINSBotTacticalMonitor::CheckPosture */) = *puVar1;
  uVar2 = puVar1[2];
  *(undefined4 *)(extraout_EDX + 0x48bc /* CINSBotTacticalMonitor::CheckPosture */ /* CINSBotTacticalMonitor::CheckPosture */) = puVar1[1];
  *(undefined4 *)(extraout_EDX + 0x48c0 /* CINSBotTacticalMonitor::CheckPosture */ /* CINSBotTacticalMonitor::CheckPosture */) = uVar2;
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::OnMoveToFailure
 * Address: 0073cf60
 * ---------------------------------------- */

/* CINSBotActionTraining::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

undefined4 * CINSBotActionTraining::OnMoveToFailure(undefined4 *param_1)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  Warning(unaff_EBX + 0x24582c /* "BOT PATH FAILED, CRITICAL
" */ /* "BOT PATH FAILED, CRITICAL
" */);
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionTraining::OnStuck
 * Address: 0073d060
 * ---------------------------------------- */

/* CINSBotActionTraining::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotActionTraining::OnStuck(CINSNextBot *param_1)

{
  float fVar1;
  float fVar2;
  int unaff_EBX;
  int in_stack_00000008;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  Warning(unaff_EBX + 0x245747 /* "BOT GOT STUCK, CRITICAL
" */ /* "BOT GOT STUCK, CRITICAL
" */);
  fVar1 = *(float *)(unaff_EBX + 0x1ec15e /* -0.01f */ /* -0.01f */);
  if (((((*(float *)(in_stack_00000008 + 0x48b8) <= fVar1) ||
        (fVar2 = *(float *)(unaff_EBX + 0x1e7fc2 /* 0.01f */ /* 0.01f */), fVar2 <= *(float *)(in_stack_00000008 + 0x48b8)))
       || (*(float *)(in_stack_00000008 + 0x48bc) <= fVar1)) ||
      (((fVar2 <= *(float *)(in_stack_00000008 + 0x48bc) ||
        (*(float *)(in_stack_00000008 + 0x48c0) <= fVar1)) ||
       (fVar2 <= *(float *)(in_stack_00000008 + 0x48c0))))) &&
     (*(int *)(in_stack_00000008 + 0x38) != 2)) {
    (**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0xe0))
              (in_stack_0000000c + 0x2060,in_stack_00000008 + 0x48b8);
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionTraining::~CINSBotActionTraining
 * Address: 0073deb0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionTraining::~CINSBotActionTraining() */

void __thiscall CINSBotActionTraining::~CINSBotActionTraining(CINSBotActionTraining *this)

{
  ~CINSBotActionTraining(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::~CINSBotActionTraining
 * Address: 0073dec0
 * ---------------------------------------- */

/* CINSBotActionTraining::~CINSBotActionTraining() */

void __thiscall CINSBotActionTraining::~CINSBotActionTraining(CINSBotActionTraining *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45c8fa /* vtable for CINSBotActionTraining+0x8 */ /* vtable for CINSBotActionTraining+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45ca8e /* vtable for CINSBotActionTraining+0x19c */ /* vtable for CINSBotActionTraining+0x19c */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::~CINSBotActionTraining
 * Address: 0073df20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionTraining::~CINSBotActionTraining() */

void __thiscall CINSBotActionTraining::~CINSBotActionTraining(CINSBotActionTraining *this)

{
  ~CINSBotActionTraining(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionTraining::~CINSBotActionTraining
 * Address: 0073df30
 * ---------------------------------------- */

/* CINSBotActionTraining::~CINSBotActionTraining() */

void __thiscall CINSBotActionTraining::~CINSBotActionTraining(CINSBotActionTraining *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45c88a /* vtable for CINSBotActionTraining+0x8 */ /* vtable for CINSBotActionTraining+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45ca1e /* vtable for CINSBotActionTraining+0x19c */ /* vtable for CINSBotActionTraining+0x19c */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



