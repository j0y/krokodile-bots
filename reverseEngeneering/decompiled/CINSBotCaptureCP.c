/*
 * CINSBotCaptureCP -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 14
 */

/* ----------------------------------------
 * CINSBotCaptureCP::CINSBotCaptureCP
 * Address: 00713010
 * ---------------------------------------- */

/* CINSBotCaptureCP::CINSBotCaptureCP(int, bool) */

void __thiscall CINSBotCaptureCP::CINSBotCaptureCP(CINSBotCaptureCP *this,int param_1,bool param_2)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  int unaff_EBX;
  undefined3 in_stack_00000009;
  undefined1 in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined **)param_1 = &UNK_0048300d + unaff_EBX;
  *(int *)(param_1 + 4) = unaff_EBX + 0x4831a1;
  pcVar1 = (code *)(unaff_EBX + -0x4e28ab);
  iVar2 = unaff_EBX + 0x41519d;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined1 *)(param_1 + 0x30) = 0;
  *(undefined1 *)(param_1 + 0x31) = 0;
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x34) = 0;
  *(int *)(param_1 + 0x3c) = iVar2;
  *(undefined4 *)(param_1 + 0x40) = 0;
  (*pcVar1)(param_1 + 0x3c,param_1 + 0x40);
  *(undefined4 *)(param_1 + 0x44) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x3c) + 4))(param_1 + 0x3c,param_1 + 0x44);
  *(int *)(param_1 + 0x48) = iVar2;
  *(undefined4 *)(param_1 + 0x4c) = 0;
  (*pcVar1)(param_1 + 0x48,param_1 + 0x4c);
  *(undefined4 *)(param_1 + 0x50) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48) + 4))(param_1 + 0x48,param_1 + 0x50);
  iVar3 = *(int *)(unaff_EBX + 0x493c35);
  *(undefined4 *)(param_1 + 0x74) = 0xbf800000;
  *(int *)(param_1 + 0x70) = iVar3 + 8;
  (**(code **)(iVar3 + 0x10))(param_1 + 0x70,param_1 + 0x74);
  *(int *)(param_1 + 0x78) = iVar2;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  (*pcVar1)(param_1 + 0x78,param_1 + 0x7c);
  *(undefined4 *)(param_1 + 0x80) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x78) + 4))(param_1 + 0x78,param_1 + 0x80);
  *(undefined4 *)(param_1 + 0x54) = _param_2;
  *(undefined1 *)(param_1 + 100) = in_stack_0000000c;
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::OnStart
 * Address: 00712e80
 * ---------------------------------------- */

/* CINSBotCaptureCP::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotCaptureCP::OnStart(CINSBotCaptureCP *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int unaff_EBX;
  int *in_stack_0000000c;
  undefined4 uVar5;
  float local_28;
  float local_24;
  float local_20;
  
  iVar3 = __i686_get_pc_thunk_bx();
  uVar4 = *(undefined4 *)(param_2 + 0x54);
  uVar5 = **(undefined4 **)(&DAT_0049382a + unaff_EBX);
  CINSNavMesh::GetControlPointHidingSpot(iVar3);
  fVar1 = *(float *)(unaff_EBX + 0x21633e);
  *(float *)(param_2 + 0x58) = local_28;
  *(float *)(param_2 + 0x5c) = local_24;
  *(float *)(param_2 + 0x60) = local_20;
  if ((((local_28 <= fVar1) || (fVar2 = *(float *)(unaff_EBX + 0x2121a2), fVar2 <= local_28)) ||
      (local_24 <= fVar1)) || (((fVar2 <= local_24 || (local_20 <= fVar1)) || (fVar2 <= local_20))))
  {
    uVar4 = (**(code **)(*in_stack_0000000c + 0x96c))(in_stack_0000000c,uVar5,uVar4);
    CINSBotLocomotion::AddMovementRequest
              (uVar4,*(undefined4 *)(param_2 + 0x58),*(undefined4 *)(param_2 + 0x5c),
               *(undefined4 *)(param_2 + 0x60),6,3,0x40a00000);
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26d7c6;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::Update
 * Address: 007131a0
 * ---------------------------------------- */

/* CINSBotCaptureCP::Update(CINSNextBot*, float) */

CINSNextBot * CINSBotCaptureCP::Update(CINSNextBot *param_1,float param_2)

{
  float fVar1;
  CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *pCVar2;
  int iVar3;
  code *pcVar4;
  bool bVar5;
  char cVar6;
  undefined1 uVar7;
  int iVar8;
  CNavArea **ppCVar9;
  int *piVar10;
  int *piVar11;
  char *pcVar12;
  CNavArea *pCVar13;
  void *pvVar14;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this;
  CINSNextBot *extraout_ECX_01;
  undefined4 *puVar15;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CFmtStrN<256,false> *extraout_ECX_04;
  CFmtStrN<256,false> *this_01;
  CBaseEntity *this_02;
  CINSBotInvestigate *this_03;
  char *pcVar16;
  int unaff_EBX;
  CINSNextBot *pCVar17;
  int iVar18;
  int iVar19;
  float10 fVar20;
  float fVar21;
  CINSNextBot *in_stack_0000000c;
  undefined4 in_stack_00000010;
  undefined4 uVar22;
  CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *this_04;
  undefined4 uVar23;
  int local_1a8;
  char local_19c [5];
  char local_197 [255];
  char local_98 [4];
  int local_94;
  float local_8c;
  int *local_88;
  float local_84;
  int local_80;
  CNavArea **local_7c;
  int *local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  undefined1 local_50 [12];
  float local_44;
  float local_40;
  float local_3c;
  Vector local_38 [12];
  CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *local_2c [6];
  undefined4 uStack_14;
  
  uStack_14 = 0x7131ab;
  __i686_get_pc_thunk_bx();
  fVar20 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_2 + 0x50) <= (float)fVar20 &&
      (float)fVar20 != *(float *)((int)param_2 + 0x50)) {
    fVar20 = (float10)CountdownTimer::Now();
    fVar21 = (float)fVar20 + *(float *)(unaff_EBX + 0x2108e1);
    if (*(float *)((int)param_2 + 0x50) != fVar21) {
      (**(code **)(*(int *)((int)param_2 + 0x48) + 4))((int)param_2 + 0x48,(int)param_2 + 0x50);
      *(float *)((int)param_2 + 0x50) = fVar21;
    }
    if (*(int *)((int)param_2 + 0x4c) != 0x3e800000) {
      (**(code **)(*(int *)((int)param_2 + 0x48) + 4))((int)param_2 + 0x48,(int)param_2 + 0x4c);
      *(undefined4 *)((int)param_2 + 0x4c) = 0x3e800000;
    }
    pCVar17 = in_stack_0000000c + 0x2060;
    iVar8 = (**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
    if ((iVar8 == 0) ||
       (((fVar21 = *(float *)(**(int **)(&DAT_004936f5 + unaff_EBX) + 0xc) -
                   *(float *)((int)param_2 + 0x34),
         *(float *)(unaff_EBX + 0x213c05) <= fVar21 && fVar21 != *(float *)(unaff_EBX + 0x213c05) &&
         (cVar6 = CINSNextBot::IsIdle((CINSNextBot *)param_2), cVar6 != '\0')) &&
        (fVar20 = (float10)CINSNextBot::GetIdleDuration(this_00),
        *(float *)(unaff_EBX + 0x1a5dd1) <= (float)fVar20 &&
        (float)fVar20 != *(float *)(unaff_EBX + 0x1a5dd1))))) {
      uVar23 = *(undefined4 *)((int)param_2 + 0x54);
      uVar22 = **(undefined4 **)(unaff_EBX + 0x49350d);
      CINSNavMesh::GetControlPointHidingSpot((int)&local_74);
      fVar21 = *(float *)(CGameRules::CreateStandardEntities + unaff_EBX + 1);
      *(float *)((int)param_2 + 0x58) = local_74;
      *(float *)((int)param_2 + 0x5c) = local_70;
      *(float *)((int)param_2 + 0x60) = local_6c;
      if (((((fVar21 < local_74) && (fVar1 = *(float *)(unaff_EBX + 0x211e85), local_74 < fVar1)) &&
           (fVar21 < local_70)) && ((local_70 < fVar1 && (fVar21 < local_6c)))) &&
         (local_6c < fVar1)) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26d4a9;
        return param_1;
      }
      uVar23 = (**(code **)(*(int *)in_stack_0000000c + 0x96c))(in_stack_0000000c,uVar22,uVar23);
      CINSBotLocomotion::AddMovementRequest
                (uVar23,*(undefined4 *)((int)param_2 + 0x58),*(undefined4 *)((int)param_2 + 0x5c),
                 *(undefined4 *)((int)param_2 + 0x60),6,3,0x40a00000);
    }
    piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
    iVar8 = (**(code **)(*piVar11 + 0xd0))(piVar11,0);
    this = extraout_ECX;
    if ((*(char *)((int)param_2 + 100) == '\0') && (iVar8 != 0)) {
      piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
      iVar8 = (**(code **)(*piVar11 + 0xd4))(piVar11,pCVar17,iVar8);
      this = extraout_ECX_00;
      if (iVar8 == 1) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x26d412;
        return param_1;
      }
    }
    iVar8 = CBaseEntity::GetTeamNumber(this);
    if (1 < iVar8 - 2U) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26d42b;
      return param_1;
    }
    iVar18 = *(int *)(**(int **)(unaff_EBX + 0x493b71) + 0x490 + *(int *)((int)param_2 + 0x54) * 4);
    iVar19 = CBaseEntity::GetTeamNumber((CBaseEntity *)param_2);
    if (iVar19 == iVar18) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26d444;
      return param_1;
    }
    iVar18 = *(int *)((int)param_2 + 0x54);
    iVar19 = **(int **)(unaff_EBX + 0x493b71);
    iVar3 = *(int *)(iVar19 + 0x450 + iVar18 * 4);
    if ((iVar8 != *(int *)(iVar19 + 0x490 + iVar18 * 4)) ||
       (bVar5 = true, (iVar8 == 2) + 2 != iVar3)) {
      bVar5 = false;
    }
    if (iVar3 == 2) {
      local_1a8 = *(int *)(iVar19 + 0x550 + iVar18 * 4);
    }
    else {
      local_1a8 = 0;
      if (iVar3 == 3) {
        local_1a8 = *(int *)(iVar19 + 0x590 + iVar18 * 4);
      }
    }
    if ((bVar5) || (0 < local_1a8)) {
      uVar23 = CINSNavMesh::GetRandomControlPointArea(**(int **)(unaff_EBX + 0x49350d));
      CINSNextBot::AddInvestigation(in_stack_0000000c,in_stack_0000000c,uVar23,0);
      pCVar13 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_03,pCVar13);
      *(undefined4 *)param_1 = 1;
      *(CNavArea **)(param_1 + 4) = pCVar13;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26d4dd;
      return param_1;
    }
    if ((((*(uint *)((int)param_2 + 0x58) & 0x7f800000) != 0x7f800000) &&
        ((*(uint *)((int)param_2 + 0x5c) & 0x7f800000) != 0x7f800000)) &&
       ((*(uint *)((int)param_2 + 0x60) & 0x7f800000) != 0x7f800000)) {
      piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
      uVar7 = (**(code **)(*piVar11 + 0x108))(piVar11,(int)param_2 + 0x58,0);
      *(undefined1 *)((int)param_2 + 0x6c) = uVar7;
    }
    fVar20 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                                (pCVar17,(int)param_2 + 0x58);
    if ((((float)fVar20 < *(float *)(unaff_EBX + 0x213c09)) &&
        (*(char *)((int)param_2 + 0x6c) != '\0')) &&
       ((iVar8 = *(int *)(**(int **)(unaff_EBX + 0x493b71) + 0x6f0 +
                         *(int *)((int)param_2 + 0x54) * 4), iVar8 == 0 || (iVar8 == 8)))) {
      pvVar14 = ::operator_new(0x4900);
      CINSBotDestroyCache::CINSBotDestroyCache((CINSBotDestroyCache *)param_2,(int)pvVar14);
      *(undefined4 *)param_1 = 1;
      *(void **)(param_1 + 4) = pvVar14;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26d501;
      return param_1;
    }
  }
  if (*(float *)((int)param_2 + 0x74) <= 0.0) {
    fVar20 = (float10)CountdownTimer::Now();
    if ((float)fVar20 < *(float *)((int)param_2 + 0x44) ||
        (float)fVar20 == *(float *)((int)param_2 + 0x44)) goto LAB_007132f0;
    fVar20 = (float10)CountdownTimer::Now();
    fVar21 = (float)fVar20 + *(float *)(unaff_EBX + 0x213c05);
    if (*(float *)((int)param_2 + 0x44) != fVar21) {
      (**(code **)(*(int *)((int)param_2 + 0x3c) + 4))((int)param_2 + 0x3c,(int)param_2 + 0x44);
      *(float *)((int)param_2 + 0x44) = fVar21;
    }
    this_01 = (CFmtStrN<256,false> *)param_2;
    if (*(int *)((int)param_2 + 0x40) != 0x40000000) {
      (**(code **)(*(int *)((int)param_2 + 0x3c) + 4))((int)param_2 + 0x3c,(int)param_2 + 0x40);
      *(undefined4 *)((int)param_2 + 0x40) = 0x40000000;
      this_01 = extraout_ECX_04;
    }
    CFmtStrN<256,false>::CFmtStrN(this_01,local_19c,unaff_EBX + 0x26d495);
    pCVar17 = in_stack_0000000c + 0x2060;
    iVar8 = (**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
    piVar11 = *(int **)(CUtlRBTree<CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::Node_t,unsigned_short,CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::Node_t,unsigned_short>,unsigned_short>>
                        ::NewNode + unaff_EBX + 1);
    if (iVar8 != 0) {
      piVar10 = (int *)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
      iVar8 = (**(code **)(*piVar10 + 0x20))(piVar10);
      if (iVar8 != 0) {
        if (*(int *)((int)param_2 + 0x38) != 0) {
          piVar10 = (int *)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
          iVar8 = (**(code **)(*piVar10 + 0x20))(piVar10);
          if (iVar8 == *(int *)((int)param_2 + 0x38)) {
            piVar10 = (int *)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
            uVar23 = (**(code **)(*piVar10 + 0x20))(piVar10);
            *(undefined4 *)((int)param_2 + 0x38) = uVar23;
            goto LAB_00713cb6;
          }
        }
        piVar11 = (int *)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x114))(pCVar17);
        uVar23 = (**(code **)(*piVar11 + 0x20))(piVar11);
        pcVar16 = (char *)(unaff_EBX + 0x26d3ff);
        *(undefined4 *)((int)param_2 + 0x38) = uVar23;
        pcVar12 = local_197 + local_94;
        if (pcVar12 < local_98) {
          do {
            cVar6 = *pcVar16;
            pcVar16 = pcVar16 + 1;
            *pcVar12 = cVar6;
            pcVar12 = pcVar12 + 1;
            if (pcVar12 == local_98) break;
          } while (*pcVar16 != '\0');
        }
        *pcVar12 = '\0';
        local_94 = (int)pcVar12 - (int)local_197;
        iVar8 = *(int *)((int)param_2 + 0x38);
        if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition((CBaseEntity *)param_2);
        }
        local_88 = (int *)(*(float *)(in_stack_0000000c + 0x20c) - *(float *)(iVar8 + 0xc));
        local_84 = *(float *)(in_stack_0000000c + 0x210) - *(float *)(iVar8 + 0x10);
        local_8c = *(float *)(in_stack_0000000c + 0x208) - *(float *)(iVar8 + 8);
        VectorNormalize((Vector *)&local_8c);
        local_3c = *(float *)(unaff_EBX + 0x1a5975);
        local_44 = local_8c * local_3c;
        local_40 = (float)local_88 * local_3c;
        local_3c = local_3c * local_84;
        if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_02);
        }
        piVar11 = *(int **)(CUtlRBTree<CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::Node_t,unsigned_short,CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<CUtlSymbol,CGlobalEventLine*,unsigned_short,bool(*)(CUtlSymbol_const&,CUtlSymbol_const&)>::Node_t,unsigned_short>,unsigned_short>>
                            ::NewNode + unaff_EBX + 1);
        local_44 = *(float *)(in_stack_0000000c + 0x208) - local_44;
        local_40 = *(float *)(in_stack_0000000c + 0x20c) - local_40;
        local_3c = *(float *)(in_stack_0000000c + 0x210) - local_3c;
        iVar8 = (**(code **)(*piVar11 + 0x40))(piVar11);
        if (iVar8 != 0) {
          if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
            CBaseEntity::CalcAbsolutePosition((CBaseEntity *)in_stack_0000000c);
          }
          NDebugOverlay::HorzArrow
                    ((Vector *)(in_stack_0000000c + 0x208),(Vector *)&local_44,5.0,0xff,0xff,0xff,
                     0xff,true,2.0);
        }
        pcVar16 = (char *)(unaff_EBX + 0x26d408);
        pcVar12 = local_197 + local_94;
        if (pcVar12 < local_98) {
          do {
            cVar6 = *pcVar16;
            pcVar16 = pcVar16 + 1;
            *pcVar12 = cVar6;
            pcVar12 = pcVar12 + 1;
            if (pcVar12 == local_98) break;
          } while (*pcVar16 != '\0');
        }
        *pcVar12 = '\0';
        local_94 = (int)pcVar12 - (int)local_197;
      }
    }
LAB_00713cb6:
    iVar8 = (**(code **)(*piVar11 + 0x40))(piVar11);
    if (iVar8 != 0) {
      (**(code **)(*(int *)in_stack_0000000c + 0x20c))(local_38,in_stack_0000000c);
      NDebugOverlay::Text(local_38,local_197,false,2.0);
    }
    goto LAB_007132f0;
  }
  iVar8 = *(int *)((int)param_2 + 0x54);
  iVar18 = **(int **)(unaff_EBX + 0x493b71);
  iVar19 = *(int *)(iVar18 + 0x450 + iVar8 * 4);
  if (iVar19 == 2) {
    iVar8 = *(int *)(iVar18 + 0x590 + iVar8 * 4);
LAB_00713477:
    if (iVar8 != 0) {
      in_stack_0000000c[0x2290] = (CINSNextBot)0x1;
      (**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
      iVar8 = unaff_EBX + 0x26d476;
      this_04 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)0x7;
      uVar22 = 3;
      uVar23 = in_stack_00000010;
      CINSBotBody::SetPosture();
      fVar20 = (float10)CountdownTimer::Now();
      pCVar17 = extraout_ECX_01;
      if (*(float *)((int)param_2 + 0x80) <= (float)fVar20 &&
          (float)fVar20 != *(float *)((int)param_2 + 0x80)) {
        iVar8 = (**(code **)(*(int *)in_stack_0000000c + 0x548))
                          (in_stack_0000000c,uVar22,this_04,uVar23,iVar8);
        piVar11 = local_78;
        if (iVar8 != 0) {
          local_84 = 0.0;
          local_88 = (int *)0x0;
          local_80 = 0;
          local_7c = (CNavArea **)0x0;
          **(int **)(unaff_EBX + 0x4938d1) = **(int **)(unaff_EBX + 0x4938d1) + 1;
          local_78 = (int *)0x0;
          local_8c = (float)((uint)local_8c & 0xffffff00);
          if (0 < *(int *)(iVar8 + 0x13c)) {
            iVar18 = 0;
            do {
              while( true ) {
                pCVar2 = *(CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> **)
                          (*(int *)(iVar8 + 0x134) + iVar18 * 8);
                if ((pCVar2 != (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)0x0) &&
                   (*(undefined4 *)(pCVar2 + 0x148) = **(undefined4 **)(unaff_EBX + 0x4938d1),
                   (*(byte *)(*(int *)(iVar8 + 0x134) + 4 + iVar18 * 8) & 2) != 0)) break;
LAB_00713558:
                iVar18 = iVar18 + 1;
                if (*(int *)(iVar8 + 0x13c) <= iVar18) goto LAB_00713618;
              }
              local_2c[0] = pCVar2;
              if ((local_8c._0_1_ != (Vector)0x0) && (0 < (int)local_7c)) {
                if (pCVar2 != (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)*local_88) {
                  ppCVar9 = (CNavArea **)0x0;
                  do {
                    ppCVar9 = (CNavArea **)((int)ppCVar9 + 1);
                    if (ppCVar9 == local_7c) goto LAB_007135e6;
                  } while (pCVar2 != (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)
                                     local_88[(int)ppCVar9]);
                  if ((int)ppCVar9 < 0) goto LAB_007135e6;
                }
                goto LAB_00713558;
              }
LAB_007135e6:
              this_04 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)local_2c;
              CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>>::InsertBefore
                        (this_04,(int)&local_88,local_7c);
              iVar18 = iVar18 + 1;
            } while (iVar18 < *(int *)(iVar8 + 0x13c));
          }
LAB_00713618:
          iVar18 = *(int *)(iVar8 + 300);
          if ((iVar18 != 0) && (0 < *(int *)(iVar18 + 0x13c))) {
            iVar19 = 0;
            do {
              iVar3 = *(int *)(*(int *)(iVar18 + 0x134) + iVar19 * 8);
              if ((iVar3 != 0) && (*(int *)(iVar3 + 0x148) != **(int **)(unaff_EBX + 0x4938d1))) {
                *(int *)(iVar3 + 0x148) = **(int **)(unaff_EBX + 0x4938d1);
                puVar15 = (undefined4 *)(iVar19 * 8 + *(int *)(iVar18 + 0x134));
                if ((*(byte *)(puVar15 + 1) & 2) != 0) {
                  local_2c[0] = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)*puVar15;
                  if ((local_8c._0_1_ == (Vector)0x0) || ((int)local_7c < 1)) {
LAB_007136f6:
                    this_04 = (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)local_2c;
                    CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>>::InsertBefore
                              (local_2c[0],(int)&local_88,local_7c);
                  }
                  else if (local_2c[0] !=
                           (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)*local_88) {
                    ppCVar9 = (CNavArea **)0x0;
                    do {
                      ppCVar9 = (CNavArea **)((int)ppCVar9 + 1);
                      if (ppCVar9 == local_7c) goto LAB_007136f6;
                    } while (local_2c[0] !=
                             (CUtlVector<CNavArea*,CUtlMemory<CNavArea*,int>> *)
                             local_88[(int)ppCVar9]);
                    if ((int)ppCVar9 < 0) goto LAB_007136f6;
                  }
                }
              }
              iVar19 = iVar19 + 1;
            } while (iVar19 < *(int *)(iVar18 + 0x13c));
          }
          if (0 < (int)local_7c) {
            iVar18 = RandomInt(0,(int)local_7c + -1,this_04);
            if ((iVar8 != local_88[iVar18]) && (local_88[iVar18] != 0)) {
              piVar11 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x970))(in_stack_0000000c);
              pcVar4 = *(code **)(*piVar11 + 0xd4);
              CNavArea::GetRandomPoint();
              CINSNextBot::GetViewPosition(local_50);
              (*pcVar4)(piVar11,local_50,0,0x3dcccccd,0,unaff_EBX + 0x26d486);
            }
          }
          local_7c = (CNavArea **)0x0;
          piVar11 = local_88;
          if (-1 < local_80) {
            if (local_88 != (int *)0x0) {
              (**(code **)(*(int *)**(undefined4 **)(&LAB_004936cd + unaff_EBX) + 8))
                        ((int *)**(undefined4 **)(&LAB_004936cd + unaff_EBX),local_88);
              local_88 = (int *)0x0;
            }
            local_84 = 0.0;
            local_78 = (int *)0x0;
            piVar11 = local_78;
          }
        }
        local_78 = piVar11;
        fVar20 = (float10)RandomFloat(0x3f800000,0x40a00000);
        fVar21 = (float)fVar20;
        fVar20 = (float10)CountdownTimer::Now();
        pCVar17 = extraout_ECX_02;
        if (*(float *)((int)param_2 + 0x80) != (float)fVar20 + fVar21) {
          (**(code **)(*(int *)((int)param_2 + 0x78) + 4))((int)param_2 + 0x78,(int)param_2 + 0x80);
          *(float *)((int)param_2 + 0x80) = (float)fVar20 + fVar21;
          pCVar17 = (CINSNextBot *)param_2;
        }
        if (*(float *)((int)param_2 + 0x7c) != fVar21) {
          (**(code **)(*(int *)((int)param_2 + 0x78) + 4))((int)param_2 + 0x78,(int)param_2 + 0x7c);
          *(float *)((int)param_2 + 0x7c) = fVar21;
          pCVar17 = extraout_ECX_03;
        }
      }
      uVar23 = 0;
      fVar20 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                                  (pCVar17,(float)in_stack_0000000c,0x41000000);
      if ((double)(float)fVar20 < *(double *)(unaff_EBX + 0x26d58d)) {
        (**(code **)(*(int *)in_stack_0000000c + 0x95c))(in_stack_0000000c,in_stack_00000010,uVar23)
        ;
      }
      goto LAB_007132f0;
    }
  }
  else if (iVar19 == 3) {
    iVar8 = *(int *)(iVar18 + 0x550 + iVar8 * 4);
    goto LAB_00713477;
  }
  DevMsg((char *)(unaff_EBX + 0x26d45b));
  uVar23 = *(undefined4 *)((int)param_2 + 0x54);
  CINSNavMesh::GetControlPointHidingSpot((int)&local_68);
  fVar21 = *(float *)(CGameRules::CreateStandardEntities + unaff_EBX + 1);
  *(float *)((int)param_2 + 0x58) = local_68;
  *(float *)((int)param_2 + 0x5c) = local_64;
  *(float *)((int)param_2 + 0x60) = local_60;
  if (((((fVar21 < local_68) && (fVar1 = *(float *)(unaff_EBX + 0x211e85), local_68 < fVar1)) &&
       (fVar21 < local_64)) && ((local_64 < fVar1 && (fVar21 < local_60)))) && (local_60 < fVar1)) {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x26d525;
    return param_1;
  }
  if (*(int *)((int)param_2 + 0x74) != -0x40800000) {
    (**(code **)(*(int *)((int)param_2 + 0x70) + 8))((int)param_2 + 0x70,(int)param_2 + 0x74,uVar23)
    ;
    *(undefined4 *)((int)param_2 + 0x74) = 0xbf800000;
  }
LAB_007132f0:
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::OnEnd
 * Address: 00712a10
 * ---------------------------------------- */

/* CINSBotCaptureCP::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotCaptureCP::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  char cVar1;
  
  if (param_2 != (Action *)0x0) {
    cVar1 = (**(code **)(*(int *)param_2 + 0x118))(param_2);
    if (cVar1 != '\0') {
      param_2[0x2290] = (Action)0x0;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::OnResume
 * Address: 00712c60
 * ---------------------------------------- */

/* CINSBotCaptureCP::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotCaptureCP::OnResume(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  uVar2 = (**(code **)(*piVar1 + 0x96c))(piVar1);
  CINSBotLocomotion::AddMovementRequest
            (uVar2,*(undefined4 *)(param_2 + 0x58),*(undefined4 *)(param_2 + 0x5c),
             *(undefined4 *)(param_2 + 0x60),6,3,0x40a00000);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::GetName
 * Address: 00714210
 * ---------------------------------------- */

/* CINSBotCaptureCP::GetName() const */

int CINSBotCaptureCP::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x26c388;
}



/* ----------------------------------------
 * CINSBotCaptureCP::ShouldHurry
 * Address: 00712cf0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureCP::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotCaptureCP::ShouldHurry(CINSBotCaptureCP *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::ShouldHurry
 * Address: 00712d00
 * ---------------------------------------- */

/* CINSBotCaptureCP::ShouldHurry(INextBot const*) const */

char __cdecl CINSBotCaptureCP::ShouldHurry(INextBot *param_1)

{
  char cVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  CINSRules *this;
  CINSRules *this_00;
  int unaff_EBX;
  float10 fVar5;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSRules::IsCheckpoint(this);
  if ((cVar1 == '\0') || (cVar1 = '\x01', param_1[0x6c] != (INextBot)0x0)) {
    cVar1 = '\x02';
    cVar2 = CINSRules::IsOutpost(this_00);
    if ((cVar2 == '\0') && (iVar3 = *(int *)(param_1 + 0x1c), iVar3 != 0)) {
      iVar3 = (**(code **)(*(int *)(iVar3 + 0x2060) + 0x114))(iVar3 + 0x2060);
      if (iVar3 != 0) {
        piVar4 = (int *)(**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x114))
                                  (*(int *)(param_1 + 0x1c) + 0x2060);
        iVar3 = 0;
        if (*(int *)(param_1 + 0x1c) != 0) {
          iVar3 = *(int *)(param_1 + 0x1c) + 0x2060;
        }
        fVar5 = (float10)(**(code **)(*piVar4 + 0x74))(piVar4,iVar3);
        cVar1 = ((float)fVar5 < *(float *)(&DAT_00246baa + unaff_EBX) ||
                (float)fVar5 == *(float *)(&DAT_00246baa + unaff_EBX)) + '\x01';
      }
    }
  }
  return cVar1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::OnMoveToSuccess
 * Address: 00712b80
 * ---------------------------------------- */

/* CINSBotCaptureCP::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * __thiscall
CINSBotCaptureCP::OnMoveToSuccess(CINSBotCaptureCP *this,CINSNextBot *param_1,Path *param_2)

{
  int extraout_EDX;
  int unaff_EBX;
  float10 fVar1;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                             (in_stack_0000000c + 0x2060,extraout_EDX + 0x58);
  if ((float)fVar1 < *(float *)(unaff_EBX + 0x1a5f89)) {
    fVar1 = (float10)IntervalTimer::Now();
    if (*(float *)(param_2 + 0x74) != (float)fVar1) {
      (**(code **)(*(int *)(param_2 + 0x70) + 8))(param_2 + 0x70,param_2 + 0x74);
      *(float *)(param_2 + 0x74) = (float)fVar1;
    }
    *(undefined1 *)(in_stack_0000000c + 0x2290) = 1;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::OnStuck
 * Address: 00712a40
 * ---------------------------------------- */

/* CINSBotCaptureCP::OnStuck(CINSNextBot*) */

CINSNextBot * CINSBotCaptureCP::OnStuck(CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)::operator_new(0x6c);
  piVar2[8] = 0;
  piVar2[9] = 0;
  piVar2[10] = 0;
  piVar2[3] = 0;
  piVar2[4] = 0;
  piVar2[5] = 0;
  piVar2[6] = 0;
  piVar2[7] = 0;
  piVar2[2] = 0;
  *(undefined1 *)(piVar2 + 0xc) = 0;
  *(undefined1 *)((int)piVar2 + 0x31) = 0;
  piVar2[0xb] = 0;
  piVar2[0xd] = 0;
  iVar1 = *(int *)(unaff_EBX + 0x493f6d);
  piVar2[0xf] = 0;
  piVar2[1] = iVar1 + 0x198;
  *piVar2 = iVar1 + 8;
  piVar2[0xe] = unaff_EBX + 0x41576d;
  CountdownTimer::NetworkStateChanged(piVar2 + 0xe);
  piVar2[0x10] = -0x40800000;
  (**(code **)(piVar2[0xe] + 4))(piVar2 + 0xe,piVar2 + 0x10);
  piVar2[0x16] = 0;
  *(int *)(param_1 + 8) = unaff_EBX + 0x26d006;
  piVar2[0x17] = 0;
  piVar2[0x18] = 0;
  piVar2[0x19] = 0;
  piVar2[0x1a] = 0;
  *(undefined4 *)param_1 = 1;
  *(int **)(param_1 + 4) = piVar2;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotCaptureCP::~CINSBotCaptureCP
 * Address: 00714230
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureCP::~CINSBotCaptureCP() */

void __thiscall CINSBotCaptureCP::~CINSBotCaptureCP(CINSBotCaptureCP *this)

{
  ~CINSBotCaptureCP(this);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::~CINSBotCaptureCP
 * Address: 00714240
 * ---------------------------------------- */

/* CINSBotCaptureCP::~CINSBotCaptureCP() */

void __thiscall CINSBotCaptureCP::~CINSBotCaptureCP(CINSBotCaptureCP *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x481de3;
  in_stack_00000004[1] = (int)(&UNK_00481f77 + extraout_ECX);
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x492f33));
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::~CINSBotCaptureCP
 * Address: 00714270
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotCaptureCP::~CINSBotCaptureCP() */

void __thiscall CINSBotCaptureCP::~CINSBotCaptureCP(CINSBotCaptureCP *this)

{
  ~CINSBotCaptureCP(this);
  return;
}



/* ----------------------------------------
 * CINSBotCaptureCP::~CINSBotCaptureCP
 * Address: 00714280
 * ---------------------------------------- */

/* CINSBotCaptureCP::~CINSBotCaptureCP() */

void __thiscall CINSBotCaptureCP::~CINSBotCaptureCP(CINSBotCaptureCP *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x481d9a;
  in_stack_00000004[1] = (int)(&UNK_00481f2e + unaff_EBX);
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



