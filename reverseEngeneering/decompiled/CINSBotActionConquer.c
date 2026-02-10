/*
 * CINSBotActionConquer -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 12
 */

/* ----------------------------------------
 * CINSBotActionConquer::OnStart
 * Address: 007378a0
 * ---------------------------------------- */

/* CINSBotActionConquer::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotActionConquer::OnStart(CINSBotActionConquer *this,CINSNextBot *param_1,Action *param_2)

{
  undefined4 *puVar1;
  CINSNextBot *this_00;
  char cVar2;
  int iVar3;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *this_05;
  CINSWeapon *this_06;
  CINSWeapon *extraout_ECX;
  int unaff_EBX;
  float10 fVar4;
  int *in_stack_0000000c;
  undefined4 uVar5;
  undefined4 uVar6;
  
  iVar3 = __i686_get_pc_thunk_bx();
  *(undefined1 *)(iVar3 + 0x44) = 0;
  puVar1 = *(undefined4 **)(unaff_EBX + 0x46ed1b /* &vec3_origin */ /* &vec3_origin */);
  *(undefined4 *)(iVar3 + 0x38) = *puVar1;
  this_00 = (CINSNextBot *)puVar1[1];
  uVar5 = puVar1[2];
  *(CINSNextBot **)(iVar3 + 0x3c) = this_00;
  *(undefined4 *)(iVar3 + 0x40) = uVar5;
  if (*(char *)(**(int **)(unaff_EBX + 0x46f047 /* &g_pGameRules */ /* &g_pGameRules */) + 0x40c) != '\0') {
    uVar6 = 0;
    uVar5 = 0x3f800000 /* 1.0f */;
    fVar4 = (float10)CINSNextBot::TransientlyConsistentRandomValue
                               (this_00,(float)in_stack_0000000c,0x3f800000 /* 1.0f */);
    if ((*(float *)(unaff_EBX + 0x1f1903 /* 0.35f */ /* 0.35f */) <= (float)fVar4 &&
         (float)fVar4 != *(float *)(unaff_EBX + 0x1f1903 /* 0.35f */ /* 0.35f */)) && (in_stack_0000000c != (int *)0x0)) {
      cVar2 = (**(code **)(*in_stack_0000000c + 0x158))(in_stack_0000000c,uVar5,uVar6);
      if (cVar2 != '\0') {
        iVar3 = CINSPlayer::GetActiveINSWeapon();
        if (iVar3 != 0) {
          cVar2 = CINSWeapon::HasLasersights(this_01);
          this_03 = this_02;
          if (cVar2 != '\0') {
            cVar2 = CINSWeapon::IsLasersightsOn(this_02);
            this_03 = this_06;
            if (cVar2 == '\0') {
              CINSWeapon::ToggleLasersights(this_06);
              this_03 = extraout_ECX;
            }
          }
          cVar2 = CINSWeapon::HasFlashlight(this_03);
          if (cVar2 != '\0') {
            cVar2 = CINSWeapon::IsFlashlightOn(this_04);
            if (cVar2 == '\0') {
              CINSWeapon::ToggleFlashlight(this_05);
            }
          }
        }
      }
    }
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionConquer::Update
 * Address: 00737480
 * ---------------------------------------- */

/* CINSBotActionConquer::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall
CINSBotActionConquer::Update(CINSBotActionConquer *this,CINSNextBot *param_1,float param_2)

{
  float *pfVar1;
  float fVar2;
  char cVar3;
  int *piVar4;
  CINSNextBot *this_00;
  int iVar5;
  void *pvVar6;
  int iVar7;
  CNavArea *pCVar8;
  CINSNextBot *extraout_ECX;
  CBaseEntity *this_01;
  CINSBotEscort *this_02;
  CINSBotPatrol *this_03;
  CINSRules *this_04;
  CINSNextBot *this_05;
  CINSBotInvestigate *this_06;
  CINSRules *this_07;
  CINSNextBot *extraout_ECX_00;
  CINSBotCombat *this_08;
  CINSBotCombat *this_09;
  int unaff_EBX;
  CINSNextBot *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(unaff_EBX + 0x46f46d /* &g_pGameRules */ /* &g_pGameRules */) == 0) {
    *(undefined4 *)param_1 = 0 /* Continue */;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    return param_1;
  }
  cVar3 = CINSBotEscort::HasEscortTarget(in_stack_0000000c);
  if (cVar3 != '\0') {
    pvVar6 = ::operator_new(0x9c);
    CINSBotEscort::CINSBotEscort(this_02);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar6;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24adcd /* "Escorting " */ /* "Escorting " */;
    return param_1;
  }
  piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_0000000c);
  this_00 = (CINSNextBot *)(**(code **)(*piVar4 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar4,0);
  if (this_00 != (CINSNextBot *)0x0) {
    piVar4 = (int *)(**(code **)(*(int *)in_stack_0000000c + 0x97c /* CINSNextBot::GetIntentionInterface */))(in_stack_0000000c);
    iVar5 = (**(code **)(*piVar4 + 0xd4 /* IIntention::ShouldAttack */))(piVar4,in_stack_0000000c + 0x2060,this_00);
    if (iVar5 == 1) {
      iVar5 = CBaseEntity::GetTeamNumber((CBaseEntity *)this_00);
      iVar7 = CINSRules::GetBotTeam(this_07);
      if (iVar5 == iVar7) {
        pvVar6 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_09);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar6;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(int *)(param_1 + 8) = unaff_EBX + 0x249132 /* "Attacking nearby threats" */ /* "Attacking nearby threats" */;
      }
      else {
        cVar3 = (**(code **)(*(int *)this_00 + 0x38))(this_00);
        this_00 = extraout_ECX_00;
        if (cVar3 == '\0') goto LAB_00737545;
        pvVar6 = ::operator_new(0x88);
        CINSBotCombat::CINSBotCombat(this_08);
        *(undefined4 *)((int)param_2 + 0x20) = 0;
        *(undefined4 *)((int)param_2 + 0x24) = 0;
        *(undefined4 *)((int)param_2 + 0x28) = 0;
        *(undefined4 *)((int)param_2 + 0x2c) = 0;
        *(void **)(param_1 + 4) = pvVar6;
        *(undefined4 *)param_1 = 2 /* SuspendFor */;
        *(int *)(param_1 + 8) = unaff_EBX + 0x24add8 /* "Attacking visible threat" */ /* "Attacking visible threat" */;
      }
      return param_1;
    }
    (**(code **)(*(int *)this_00 + 0x10))(this_00);
    CINSNextBot::AddInvestigation();
    this_00 = extraout_ECX;
  }
LAB_00737545:
  cVar3 = CINSNextBot::HasInvestigations(this_00);
  if (cVar3 != '\0') {
    iVar5 = CBaseEntity::GetTeamNumber(this_01);
    iVar7 = CINSRules::GetBotTeam(this_04);
    if (iVar5 == iVar7) {
      CINSNextBot::GetCurrentInvestigationArea(this_05);
      pCVar8 = (CNavArea *)::operator_new(0x4900);
      CINSBotInvestigate::CINSBotInvestigate(this_06,pCVar8);
      *(undefined4 *)((int)param_2 + 0x20) = 0;
      *(undefined4 *)((int)param_2 + 0x24) = 0;
      *(undefined4 *)((int)param_2 + 0x28) = 0;
      *(undefined4 *)((int)param_2 + 0x2c) = 0;
      *(CNavArea **)(param_1 + 4) = pCVar8;
      *(int *)(param_1 + 8) = unaff_EBX + 0x24ae19 /* "I have something to investigate" */ /* "I have something to investigate" */;
      *(undefined4 *)param_1 = 2 /* SuspendFor */;
      return param_1;
    }
  }
  pfVar1 = *(float **)(unaff_EBX + 0x46f141 /* &vec3_origin */ /* &vec3_origin */);
  if (((*pfVar1 == *(float *)((int)param_2 + 0x38)) &&
      (pfVar1[1] == *(float *)((int)param_2 + 0x3c))) &&
     (pfVar1[2] == *(float *)((int)param_2 + 0x40))) {
    pvVar6 = ::operator_new(0x4934);
    CINSBotPatrol::CINSBotPatrol(this_03);
    *(undefined4 *)((int)param_2 + 0x20) = 0;
    *(undefined4 *)((int)param_2 + 0x24) = 0;
    *(undefined4 *)((int)param_2 + 0x28) = 0;
    *(undefined4 *)((int)param_2 + 0x2c) = 0;
    *(void **)(param_1 + 4) = pvVar6;
    *(int *)(param_1 + 8) = unaff_EBX + 0x24ae02 /* "My Job is to Patrol" */ /* "My Job is to Patrol" */;
    *(undefined4 *)param_1 = 2 /* SuspendFor */;
    return param_1;
  }
  *(float *)((int)param_2 + 0x38) = *pfVar1;
  fVar2 = pfVar1[2];
  *(float *)((int)param_2 + 0x3c) = pfVar1[1];
  *(float *)((int)param_2 + 0x40) = fVar2;
  pvVar6 = ::operator_new(100);
  CINSBotApproach::CINSBotApproach();
  *(undefined4 *)((int)param_2 + 0x20) = 0;
  *(undefined4 *)((int)param_2 + 0x24) = 0;
  *(undefined4 *)((int)param_2 + 0x28) = 0;
  *(undefined4 *)((int)param_2 + 0x2c) = 0;
  *(void **)(param_1 + 4) = pvVar6;
  *(int *)(param_1 + 8) = unaff_EBX + 0x24adf1 /* "Approach Command" */ /* "Approach Command" */;
  *(undefined4 *)param_1 = 2 /* SuspendFor */;
  return param_1;
}



/* ----------------------------------------
 * CINSBotActionConquer::OnEnd
 * Address: 007373e0
 * ---------------------------------------- */

/* CINSBotActionConquer::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl CINSBotActionConquer::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::GetName
 * Address: 00737ae0
 * ---------------------------------------- */

/* CINSBotActionConquer::GetName() const */

int CINSBotActionConquer::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x1f6e63 /* "Conquer" */ /* "Conquer" */;
}



/* ----------------------------------------
 * CINSBotActionConquer::ShouldAttack
 * Address: 00737460
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionConquer::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
CINSBotActionConquer::ShouldAttack
          (CINSBotActionConquer *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::ShouldAttack
 * Address: 00737470
 * ---------------------------------------- */

/* CINSBotActionConquer::ShouldAttack(INextBot const*, CKnownEntity const*) const */

undefined4 __cdecl CINSBotActionConquer::ShouldAttack(INextBot *param_1,CKnownEntity *param_2)

{
  return 1;
}



/* ----------------------------------------
 * CINSBotActionConquer::OnCommandApproach
 * Address: 00737420
 * ---------------------------------------- */

/* CINSBotActionConquer::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void __thiscall
CINSBotActionConquer::OnCommandApproach
          (CINSBotActionConquer *this,CINSNextBot *param_1,Vector *param_2,float param_3)

{
  undefined4 uVar1;
  undefined4 *in_stack_00000010;
  
  uVar1 = *in_stack_00000010;
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_2 + 0x38) = uVar1;
  uVar1 = in_stack_00000010[1];
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  *(undefined4 *)(param_2 + 0x3c) = uVar1;
  *(undefined4 *)(param_2 + 0x40) = in_stack_00000010[2];
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::OnCommandAttack
 * Address: 007373f0
 * ---------------------------------------- */

/* CINSBotActionConquer::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void CINSBotActionConquer::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::~CINSBotActionConquer
 * Address: 00737b00
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionConquer::~CINSBotActionConquer() */

void __thiscall CINSBotActionConquer::~CINSBotActionConquer(CINSBotActionConquer *this)

{
  ~CINSBotActionConquer(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::~CINSBotActionConquer
 * Address: 00737b10
 * ---------------------------------------- */

/* CINSBotActionConquer::~CINSBotActionConquer() */

void __thiscall CINSBotActionConquer::~CINSBotActionConquer(CINSBotActionConquer *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x4617b3 /* vtable for CINSBotActionConquer+0x8 */ /* vtable for CINSBotActionConquer+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x461947 /* vtable for CINSBotActionConquer+0x19c */ /* vtable for CINSBotActionConquer+0x19c */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x46f663 /* &_DYNAMIC */ /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::~CINSBotActionConquer
 * Address: 00737b40
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotActionConquer::~CINSBotActionConquer() */

void __thiscall CINSBotActionConquer::~CINSBotActionConquer(CINSBotActionConquer *this)

{
  ~CINSBotActionConquer(this);
  return;
}



/* ----------------------------------------
 * CINSBotActionConquer::~CINSBotActionConquer
 * Address: 00737b50
 * ---------------------------------------- */

/* CINSBotActionConquer::~CINSBotActionConquer() */

void __thiscall CINSBotActionConquer::~CINSBotActionConquer(CINSBotActionConquer *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x46176a /* vtable for CINSBotActionConquer+0x8 */ /* vtable for CINSBotActionConquer+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x4618fe /* vtable for CINSBotActionConquer+0x19c */ /* vtable for CINSBotActionConquer+0x19c */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



