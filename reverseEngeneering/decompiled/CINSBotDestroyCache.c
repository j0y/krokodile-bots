/*
 * CINSBotDestroyCache -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 13
 */

/* ----------------------------------------
 * CINSBotDestroyCache::CINSBotDestroyCache
 * Address: 007181d0
 * ---------------------------------------- */

/* CINSBotDestroyCache::CINSBotDestroyCache(int) */

void __thiscall CINSBotDestroyCache::CINSBotDestroyCache(CINSBotDestroyCache *this,int param_1)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  CINSPathFollower *this_00;
  CINSPathFollower *this_01;
  int unaff_EBX;
  undefined4 in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  *(undefined **)param_1 = &UNK_0047e5ed + unaff_EBX;
  *(int *)(param_1 + 4) = unaff_EBX + 0x47e781 /* vtable for CINSBotDestroyCache+0x19c */;
  iVar1 = param_1 + 0x3c;
  iVar2 = unaff_EBX + 0x40ffdd /* vtable for CountdownTimer+0x8 */;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  pcVar3 = (code *)(unaff_EBX + -0x4e7a6b /* CountdownTimer::NetworkStateChanged */);
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
  (*pcVar3)(iVar1,param_1 + 0x40);
  *(undefined4 *)(param_1 + 0x44) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x3c) + 4))(iVar1,param_1 + 0x44);
  CINSPathFollower::CINSPathFollower(this_00);
  *(int *)(param_1 + 0x48b8) = iVar2;
  *(undefined4 *)(param_1 + 0x48bc) = 0;
  (*pcVar3)(param_1 + 0x48b8,param_1 + 0x48bc);
  *(undefined4 *)(param_1 + 0x48c0) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48b8) + 4))(param_1 + 0x48b8,param_1 + 0x48c0);
  *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000;
  iVar6 = *(int *)(unaff_EBX + 0x48ea75 /* &vtable for IntervalTimer */);
  *(int *)(param_1 + 0x48d4) = iVar6 + 8;
  (**(code **)(iVar6 + 0x10))(param_1 + 0x48d4,param_1 + 0x48d8);
  *(int *)(param_1 + 0x48dc) = iVar2;
  *(undefined4 *)(param_1 + 0x48e0) = 0;
  (*pcVar3)(param_1 + 0x48dc,param_1 + 0x48e0);
  *(undefined4 *)(param_1 + 0x48e4) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48dc) + 4))(param_1 + 0x48dc,param_1 + 0x48e4);
  iVar6 = param_1 + 0x48e8;
  *(int *)(param_1 + 0x48e8) = iVar2;
  *(undefined4 *)(param_1 + 0x48ec) = 0;
  (*pcVar3)(iVar6,param_1 + 0x48ec);
  *(undefined4 *)(param_1 + 0x48f0) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(iVar6,param_1 + 0x48f0);
  iVar4 = param_1 + 0x48f4;
  *(int *)(param_1 + 0x48f4) = iVar2;
  *(undefined4 *)(param_1 + 0x48f8) = 0;
  (*pcVar3)(iVar4,param_1 + 0x48f8);
  *(undefined4 *)(param_1 + 0x48fc) = 0xbf800000;
  (**(code **)(*(int *)(param_1 + 0x48f4) + 4))(iVar4,param_1 + 0x48fc);
  CINSPathFollower::Invalidate(this_01);
  *(undefined4 *)(param_1 + 0x38) = in_stack_00000008;
  if (*(int *)(param_1 + 0x48d8) != -0x40800000) {
    (**(code **)(*(int *)(param_1 + 0x48d4) + 8))(param_1 + 0x48d4,param_1 + 0x48d8);
    *(undefined4 *)(param_1 + 0x48d8) = 0xbf800000;
  }
  if (*(int *)(param_1 + 0x48fc) != -0x40800000) {
    (**(code **)(*(int *)(param_1 + 0x48f4) + 4))(iVar4,param_1 + 0x48fc);
    *(undefined4 *)(param_1 + 0x48fc) = 0xbf800000;
  }
  if (*(int *)(param_1 + 0x48f0) != -0x40800000) {
    (**(code **)(*(int *)(param_1 + 0x48e8) + 4))(iVar6,param_1 + 0x48f0);
    *(undefined4 *)(param_1 + 0x48f0) = 0xbf800000;
  }
  if (*(int *)(param_1 + 0x44) != -0x40800000) {
    (**(code **)(*(int *)(param_1 + 0x3c) + 4))(iVar1,param_1 + 0x44);
    *(undefined4 *)(param_1 + 0x44) = 0xbf800000;
  }
  piVar5 = (int *)(unaff_EBX + 0x5d42c5 /* CINSBotDestroyCache::m_nTotalDestroyers */ + *(int *)(param_1 + 0x38) * 4);
  *piVar5 = *piVar5 + 1;
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::OnStart
 * Address: 00717ed0
 * ---------------------------------------- */

/* CINSBotDestroyCache::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotDestroyCache::OnStart(CINSBotDestroyCache *this,CINSNextBot *param_1,Action *param_2)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  CINSNextBot *this_00;
  int unaff_EBX;
  int *in_stack_0000000c;
  undefined4 uVar4;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x717edb;
  __i686_get_pc_thunk_bx();
  CINSNextBot::ResetIdleStatus(this_00);
  uVar3 = *(undefined4 *)(param_2 + 0x38);
  uVar4 = **(undefined4 **)(unaff_EBX + 0x48e7dd /* &TheNavMesh */);
  CINSNavMesh::GetControlPointHidingSpot((int)&local_28);
  fVar1 = *(float *)(unaff_EBX + 0x2112f1 /* typeinfo name for CTraceFilterIgnoreWeapons+0x41 */);
  *(float *)(param_2 + 0x48c4) = local_28;
  *(float *)(param_2 + 0x48c8) = local_24;
  *(float *)(param_2 + 0x48cc) = local_20;
  if ((((local_28 <= fVar1) || (fVar2 = *(float *)(unaff_EBX + 0x20d155 /* typeinfo name for ITraceFilter+0x40 */), fVar2 <= local_28)) ||
      (local_24 <= fVar1)) || (((fVar2 <= local_24 || (local_20 <= fVar1)) || (fVar2 <= local_20))))
  {
    uVar3 = (**(code **)(*in_stack_0000000c + 0x96c))(in_stack_0000000c,uVar4,uVar3);
    CINSBotLocomotion::AddMovementRequest
              (uVar3,*(undefined4 *)(param_2 + 0x48c4),*(undefined4 *)(param_2 + 0x48c8),
               *(undefined4 *)(param_2 + 0x48cc),8,3,0x40a00000);
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2687f5 /* "Unable to find hiding spots at this control point, falling back to investigate" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotDestroyCache::Update
 * Address: 007186a0
 * ---------------------------------------- */

/* CINSBotDestroyCache::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotDestroyCache::Update(CINSBotDestroyCache *this,CINSNextBot *param_1,float param_2)

{
  int iVar1;
  uint uVar2;
  char cVar3;
  undefined1 uVar4;
  int *piVar5;
  int iVar6;
  void *pvVar7;
  int *piVar8;
  undefined4 *puVar9;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_00;
  CPoint_ControlPoint *this_01;
  CINSBotRetreat *this_02;
  CountdownTimer *this_03;
  CountdownTimer *this_04;
  CBaseEntity *this_05;
  int unaff_EBX;
  undefined4 **ppuVar10;
  CINSNextBot *pCVar11;
  float10 fVar12;
  float fVar13;
  CINSNextBot *in_stack_0000000c;
  undefined4 *local_bc [7];
  float local_a0;
  float local_9c;
  undefined4 *local_84;
  undefined4 local_80;
  float local_7c;
  undefined4 *local_78;
  void *local_74;
  undefined4 *local_70;
  undefined4 *local_64 [4];
  undefined4 local_54;
  float local_50;
  undefined4 local_4c [3];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  fVar12 = (float10)CountdownTimer::Now();
  local_a0 = (float)fVar12;
  if (*(float *)((int)param_2 + 0x44) <= local_a0 && local_a0 != *(float *)((int)param_2 + 0x44)) {
    fVar12 = (float10)CountdownTimer::Now();
    local_a0 = (float)fVar12;
    fVar13 = local_a0 + *(float *)(unaff_EBX + 0x20c0a7 /* typeinfo name for CBaseGameSystem+0x1e */);
    if (*(float *)((int)param_2 + 0x44) != fVar13) {
      local_9c = fVar13;
      (**(code **)(*(int *)((int)param_2 + 0x3c) + 4))((int)param_2 + 0x3c);
      *(float *)((int)param_2 + 0x44) = local_9c;
    }
    if (*(int *)((int)param_2 + 0x40) != 0x3f000000) {
      (**(code **)(*(int *)((int)param_2 + 0x3c) + 4))((int)param_2 + 0x3c);
      *(undefined4 *)((int)param_2 + 0x40) = 0x3f000000;
    }
    piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
    iVar6 = (**(code **)(*piVar5 + 0xd0))(piVar5);
    this_00 = extraout_ECX;
    if (iVar6 != 0) {
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c))(in_stack_0000000c);
      iVar6 = (**(code **)(*piVar5 + 0xd4))(piVar5);
      this_00 = extraout_ECX_00;
      if (iVar6 == 1) {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x267f0c /* "Attacking nearby threats" */;
        return param_1;
      }
    }
    iVar6 = CBaseEntity::GetTeamNumber(this_00);
    if (1 < iVar6 - 2U) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x267f25 /* "Bot is not on a playteam" */;
      return param_1;
    }
    piVar5 = *(int **)(unaff_EBX + 0x48e66b /* &g_pObjectiveResource */);
    iVar6 = *piVar5;
    iVar1 = *(int *)(iVar6 + 0x6f0 + *(int *)((int)param_2 + 0x38) * 4);
    if ((((iVar1 != 0) && (iVar1 != 8)) && (iVar1 != 9)) && (iVar1 != 0xb)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x26863f /* "Not a weapon cache, radio or misc target?
" */;
      return param_1;
    }
    uVar2 = *(uint *)(iVar6 + 0x7cc + *(int *)((int)param_2 + 0x38) * 4);
    if (((uVar2 == 0xffffffff) ||
        (this_01 = (CPoint_ControlPoint *)
                   ((uVar2 & 0xffff) * 0x18 + **(int **)(unaff_EBX + 0x48e127 /* &g_pEntityList */)),
        *(uint *)(this_01 + 8) != uVar2 >> 0x10)) || (*(int *)(this_01 + 4) == 0)) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2685c0 /* "No CP" */;
      return param_1;
    }
    piVar8 = (int *)CPoint_ControlPoint::GetAssociatedObject(this_01);
    if (piVar8 == (int *)0x0) {
      *(undefined4 *)param_1 = 3;
      *(undefined4 *)(param_1 + 4) = 0;
      *(int *)(param_1 + 8) = unaff_EBX + 0x2685c6 /* "No object" */;
      return param_1;
    }
    iVar6 = *(int *)(*piVar5 + 0x6f0 + *(int *)((int)param_2 + 0x38) * 4);
    if (((iVar6 == 0) || (iVar6 == 9)) || (iVar6 == 0xb)) {
      cVar3 = CanIDestroyCache(in_stack_0000000c);
      if (cVar3 == '\0') {
        *(undefined4 *)param_1 = 3;
        *(undefined4 *)(param_1 + 4) = 0;
        *(int *)(param_1 + 8) = unaff_EBX + 0x2685d0 /* "Can no longer destroy it.
" */;
        return param_1;
      }
      puVar9 = (undefined4 *)(**(code **)(*piVar8 + 0x260))(piVar8);
      local_64[0] = (undefined4 *)*puVar9;
      local_84 = (undefined4 *)*puVar9;
      local_80 = puVar9[1];
      local_64[1] = (undefined4 *)puVar9[1];
      local_78 = (undefined4 *)puVar9[2];
      local_64[2] = (undefined4 *)puVar9[2];
      piVar5 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974))(in_stack_0000000c);
      local_64[3] = local_84;
      local_54 = local_80;
      local_50 = (float)local_78 + *(float *)(unaff_EBX + 0x2459c7 /* typeinfo name for CMemberFunctor0<CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>*, void (CParallelProcessor<CNavArea*, CFuncJobItemProcessor<CNavArea*>, 1>::*)(), CRefCounted1<CFunctor, CRefCountServiceBase<true, CRefMT> >, CFuncMemPolicyNone>+0xd8 */);
      uVar4 = (**(code **)(*piVar5 + 0x108))(piVar5);
      *(undefined1 *)((int)param_2 + 0x48d0) = uVar4;
      if (0.0 < *(float *)((int)param_2 + 0x48f0)) {
        fVar12 = (float10)CountdownTimer::Now();
        local_a0 = (float)fVar12;
        if (local_a0 < *(float *)((int)param_2 + 0x48f0) ||
            local_a0 == *(float *)((int)param_2 + 0x48f0)) {
          pvVar7 = ::operator_new(0x48f8);
          CINSBotRetreat::CINSBotRetreat(this_02,SUB41(pvVar7,0),0.0);
          *(undefined4 *)((int)param_2 + 0x20) = 0;
          *(undefined4 *)((int)param_2 + 0x24) = 0;
          *(undefined4 *)((int)param_2 + 0x28) = 0;
          *(undefined4 *)((int)param_2 + 0x2c) = 0;
          *(undefined4 *)param_1 = 2;
          *(void **)(param_1 + 4) = pvVar7;
          *(undefined4 *)(param_1 + 8) = 0;
          return param_1;
        }
      }
      fVar12 = (float10)(**(code **)(*(int *)(in_stack_0000000c + 0x2060) + 0x134))
                                  (in_stack_0000000c + 0x2060);
      local_a0 = (float)fVar12;
      if (((local_a0 < *(float *)(unaff_EBX + 0x20c967 /* typeinfo name for ITraceFilter+0x28 */)) &&
          (*(char *)((int)param_2 + 0x48d0) != '\0')) && (*(float *)((int)param_2 + 0x48d8) <= 0.0))
      {
        fVar12 = (float10)IntervalTimer::Now();
        fVar13 = (float)fVar12;
        local_a0 = fVar13;
        if (*(float *)((int)param_2 + 0x48d8) != fVar13) {
          (**(code **)(*(int *)((int)param_2 + 0x48d4) + 8))((int)param_2 + 0x48d4);
          *(float *)((int)param_2 + 0x48d8) = fVar13;
        }
      }
      local_74 = (void *)CINSNavMesh::GetRandomControlPointArea(**(int **)(unaff_EBX + 0x48e007 /* &TheNavMesh */));
      if (local_74 == (void *)0x0) {
        Warning(unaff_EBX + 0x26866b /* "NAV MESH: Unable to find a random area around cache %i for a grenade target, ..." */);
      }
      if (*(char *)((int)param_2 + 0x48d0) != '\0') {
        local_7c = (float)((int)param_2 + 0x48f4);
        fVar12 = (float10)CountdownTimer::Now();
        local_a0 = (float)fVar12;
        if (*(float *)((int)param_2 + 0x48fc) <= local_a0 &&
            local_a0 != *(float *)((int)param_2 + 0x48fc)) {
          local_bc[0] = local_4c;
          local_64[0] = local_84;
          local_64[1] = (undefined4 *)local_80;
          local_64[2] = local_78;
          ppuVar10 = local_64;
          puVar9 = (undefined4 *)&stack0xffffff38;
          local_78 = (undefined4 *)&stack0xffffff38;
          local_70 = local_bc[0];
          for (iVar6 = 3; iVar6 != 0; iVar6 = iVar6 + -1) {
            *puVar9 = *ppuVar10;
            ppuVar10 = ppuVar10 + 1;
            puVar9 = puVar9 + 1;
          }
          cVar3 = CINSBotThrowGrenade::AimForGrenadeToss(in_stack_0000000c);
          if (cVar3 != '\0') {
            CountdownTimer::Start(this_03,(float)((int)param_2 + 0x48e8));
            if (((byte)in_stack_0000000c[0xd1] & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_05);
            }
            local_74 = ::operator_new(0x6c);
            puVar9 = local_70;
            ppuVar10 = local_bc;
            for (iVar6 = 3; iVar6 != 0; iVar6 = iVar6 + -1) {
              *ppuVar10 = (undefined4 *)*puVar9;
              puVar9 = puVar9 + 1;
              ppuVar10 = ppuVar10 + 1;
            }
            pCVar11 = in_stack_0000000c + 0x208;
            puVar9 = local_78;
            for (iVar6 = 3; iVar6 != 0; iVar6 = iVar6 + -1) {
              *puVar9 = *(undefined4 *)pCVar11;
              pCVar11 = pCVar11 + 4;
              puVar9 = puVar9 + 1;
            }
            CINSBotThrowGrenade::CINSBotThrowGrenade((CINSBotThrowGrenade *)0x0,local_74);
            *(undefined4 *)((int)param_2 + 0x20) = 0;
            *(undefined4 *)((int)param_2 + 0x24) = 0;
            *(undefined4 *)((int)param_2 + 0x28) = 0;
            *(undefined4 *)((int)param_2 + 0x2c) = 0;
            *(undefined4 *)param_1 = 2;
            *(undefined4 *)(param_1 + 8) = 0;
            *(void **)(param_1 + 4) = local_74;
            return param_1;
          }
          if (local_74 != (void *)0x0) {
            CNavArea::GetRandomPoint();
            *(undefined4 *)((int)param_2 + 0x48c4) = local_40;
            *(undefined4 *)((int)param_2 + 0x48c8) = local_3c;
            *(undefined4 *)((int)param_2 + 0x48cc) = local_38;
            CountdownTimer::Start(this_04,local_7c);
            *(undefined4 *)param_1 = 0;
            *(undefined4 *)(param_1 + 4) = 0;
            *(undefined4 *)(param_1 + 8) = 0;
            return param_1;
          }
        }
      }
      if (((0.0 < *(float *)((int)param_2 + 0x48d8)) && (local_74 != (void *)0x0)) &&
         (*(char *)((int)param_2 + 0x48d0) == '\0')) {
        CNavArea::GetRandomPoint();
        *(undefined4 *)((int)param_2 + 0x48c4) = local_34;
        *(undefined4 *)((int)param_2 + 0x48c8) = local_30;
        *(undefined4 *)((int)param_2 + 0x48cc) = local_2c;
        if (*(int *)((int)param_2 + 0x48d8) != -0x40800000) {
          (**(code **)(*(int *)((int)param_2 + 0x48d4) + 8))((int)param_2 + 0x48d4);
          *(undefined4 *)((int)param_2 + 0x48d8) = 0xbf800000;
        }
      }
    }
  }
  else if ((*(int *)(**(int **)(unaff_EBX + 0x48e66b /* &g_pObjectiveResource */) + 0x6f0 + *(int *)((int)param_2 + 0x38) * 4)
            == 8) && (*(char *)((int)param_2 + 0x48d0) != '\0')) {
    iVar6 = **(int **)(unaff_EBX + 0x48e66b /* &g_pObjectiveResource */) + *(int *)((int)param_2 + 0x38) * 0xc;
    local_28 = *(undefined4 *)(iVar6 + 0x5d0);
    local_24 = *(undefined4 *)(iVar6 + 0x5d4);
    local_20 = *(undefined4 *)(iVar6 + 0x5d8);
    pvVar7 = ::operator_new(0x78);
    local_bc[0] = (undefined4 *)0x0;
    CINSBotSuppressTarget::CINSBotSuppressTarget();
    *(undefined4 *)param_1 = 1;
    *(void **)(param_1 + 4) = pvVar7;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2685eb /* "Attacking the cache" */;
    return param_1;
  }
  fVar13 = *(float *)(**(int **)(unaff_EBX + 0x48e1ef /* &gpGlobals */) + 0xc) - *(float *)((int)param_2 + 0x34);
  if ((fVar13 < *(float *)(unaff_EBX + 0x20e6ff /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x30 */) || fVar13 == *(float *)(unaff_EBX + 0x20e6ff /* typeinfo name for CTraceFilterSkipTwoEntitiesAndCheckTeamMask+0x30 */)) ||
     (fVar12 = (float10)CINSNextBot::GetIdleDuration((CINSNextBot *)param_2),
     (float)fVar12 < *(float *)(unaff_EBX + 0x20c0bb /* typeinfo name for CBaseGameSystem+0x32 */) ||
     (float)fVar12 == *(float *)(unaff_EBX + 0x20c0bb /* typeinfo name for CBaseGameSystem+0x32 */))) {
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    *(undefined4 *)param_1 = 3;
    *(undefined4 *)(param_1 + 4) = 0;
    *(int *)(param_1 + 8) = unaff_EBX + 0x2685ff /* "Idling in destroy cache" */;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotDestroyCache::OnEnd
 * Address: 00717e90
 * ---------------------------------------- */

/* CINSBotDestroyCache::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotDestroyCache::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  int *piVar1;
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  piVar1 = (int *)(extraout_ECX + 0x5d460b /* CINSBotDestroyCache::m_nTotalDestroyers */ + *(int *)(param_1 + 0x38) * 4);
  *piVar1 = *piVar1 + -1;
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::GetName
 * Address: 00718f00
 * ---------------------------------------- */

/* CINSBotDestroyCache::GetName() const */

int CINSBotDestroyCache::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x267d50 /* "Destroying cache" */;
}



/* ----------------------------------------
 * CINSBotDestroyCache::ShouldHurry
 * Address: 00717eb0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotDestroyCache::ShouldHurry(INextBot const*) const */

void __thiscall CINSBotDestroyCache::ShouldHurry(CINSBotDestroyCache *this,INextBot *param_1)

{
  ShouldHurry(param_1 + -4);
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::ShouldHurry
 * Address: 00717ec0
 * ---------------------------------------- */

/* CINSBotDestroyCache::ShouldHurry(INextBot const*) const */

undefined4 __cdecl CINSBotDestroyCache::ShouldHurry(INextBot *param_1)

{
  return 2;
}



/* ----------------------------------------
 * CINSBotDestroyCache::OnMoveToSuccess
 * Address: 007180b0
 * ---------------------------------------- */

/* CINSBotDestroyCache::OnMoveToSuccess(CINSNextBot*, Path const*) */

CINSNextBot * CINSBotDestroyCache::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x48d8) != (float)fVar1) {
    (**(code **)(*(int *)(param_2 + 0x48d4) + 8))(param_2 + 0x48d4,param_2 + 0x48d8);
    *(float *)(param_2 + 0x48d8) = (float)fVar1;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return param_1;
}



/* ----------------------------------------
 * CINSBotDestroyCache::CanIDestroyCache
 * Address: 00718510
 * ---------------------------------------- */

/* CINSBotDestroyCache::CanIDestroyCache(CINSNextBot*) */

undefined4 __cdecl CINSBotDestroyCache::CanIDestroyCache(CINSNextBot *param_1)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  CINSPlayer *extraout_ECX;
  CINSPlayer *this;
  CINSPlayer *extraout_ECX_00;
  int unaff_EBX;
  bool bVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x48e459 /* &GCSDK::GetPchTempTextBuffer */);
  this = *(CINSPlayer **)(iVar2 + 0x100c);
  bVar7 = this != (CINSPlayer *)0x0;
  if (bVar7) {
    iVar6 = *(int *)(iVar2 + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    this = extraout_ECX;
    if (iVar6 == iVar4) {
      piVar5 = *(int **)(iVar2 + 0x1014);
      if (*piVar5 != unaff_EBX + 0x2687ad /* "CINSBotDestroyCache::CanIDestroyCache" */) {
        piVar5 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar5,unaff_EBX + 0x2687ad /* "CINSBotDestroyCache::CanIDestroyCache" */,(char *)0x0,
                                   unaff_EBX + 0x26874b /* "INSNextBot" */);
        *(int **)(iVar2 + 0x1014) = piVar5;
      }
      puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + piVar5[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar2 + 0x1010) = 0;
      this = extraout_ECX_00;
    }
  }
  if (param_1 != (CINSNextBot *)0x0) {
    uVar9 = 0;
    uVar8 = 3;
    piVar5 = (int *)CINSPlayer::GetWeaponInSlot(this,(int)param_1,true);
    if (piVar5 != (int *)0x0) {
      cVar3 = (**(code **)(*piVar5 + 0x410))(piVar5,uVar8,uVar9);
      if (cVar3 != '\0') {
        iVar6 = (**(code **)(*piVar5 + 0x5f0))(piVar5);
        uVar8 = CONCAT31((int3)(iVar6 - 2U >> 8),iVar6 - 2U < 2);
        goto LAB_00718589;
      }
    }
  }
  uVar8 = 0;
LAB_00718589:
  if ((bVar7) && ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) {
    iVar6 = *(int *)(iVar2 + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      cVar3 = CVProfNode::ExitScope();
      iVar6 = *(int *)(iVar2 + 0x1014);
      if (cVar3 != '\0') {
        iVar6 = *(int *)(iVar6 + 100);
        *(int *)(iVar2 + 0x1014) = iVar6;
      }
      *(bool *)(iVar2 + 0x1010) = iVar6 == iVar2 + 0x1018;
      return uVar8;
    }
  }
  return uVar8;
}



/* ----------------------------------------
 * CINSBotDestroyCache::~CINSBotDestroyCache
 * Address: 00718f20
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotDestroyCache::~CINSBotDestroyCache() */

void __thiscall CINSBotDestroyCache::~CINSBotDestroyCache(CINSBotDestroyCache *this)

{
  ~CINSBotDestroyCache(this);
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::~CINSBotDestroyCache
 * Address: 00718f30
 * ---------------------------------------- */

/* CINSBotDestroyCache::~CINSBotDestroyCache() */

void __thiscall CINSBotDestroyCache::~CINSBotDestroyCache(CINSBotDestroyCache *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47d88a /* vtable for CINSBotDestroyCache+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x47da1e /* vtable for CINSBotDestroyCache+0x19c */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::~CINSBotDestroyCache
 * Address: 00718f90
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotDestroyCache::~CINSBotDestroyCache() */

void __thiscall CINSBotDestroyCache::~CINSBotDestroyCache(CINSBotDestroyCache *this)

{
  ~CINSBotDestroyCache(this);
  return;
}



/* ----------------------------------------
 * CINSBotDestroyCache::~CINSBotDestroyCache
 * Address: 00718fa0
 * ---------------------------------------- */

/* CINSBotDestroyCache::~CINSBotDestroyCache() */

void __thiscall CINSBotDestroyCache::~CINSBotDestroyCache(CINSBotDestroyCache *this)

{
  CINSPathFollower *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47d81a /* vtable for CINSBotDestroyCache+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x47d9ae /* vtable for CINSBotDestroyCache+0x19c */;
  CINSPathFollower::~CINSPathFollower(this_00);
  Action<CINSNextBot>::~Action(this_01);
  operator_delete(in_stack_00000004);
  return;
}



