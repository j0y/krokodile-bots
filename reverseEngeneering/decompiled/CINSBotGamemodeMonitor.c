/*
 * CINSBotGamemodeMonitor -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 8
 */

/* ----------------------------------------
 * CINSBotGamemodeMonitor::OnStart
 * Address: 0073dfc0
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void CINSBotGamemodeMonitor::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::InitialContainedAction
 * Address: 0073e000
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::InitialContainedAction(CINSNextBot*) */

int * __cdecl CINSBotGamemodeMonitor::InitialContainedAction(CINSNextBot *param_1)

{
  code *pcVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  CINSRules *this;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSRules *this_02;
  CINSRules *this_03;
  CINSRules *this_04;
  CINSRules *this_05;
  CINSRules *this_06;
  CINSRules *this_07;
  CINSRules *this_08;
  CINSRules *this_09;
  CINSRules *this_10;
  CINSRules *this_11;
  CINSRules *this_12;
  CINSRules *this_13;
  CINSBotActionFlashpoint *this_14;
  CINSBotActionStrike *this_15;
  CINSBotActionSkirmish *this_16;
  CINSBotActionAmbush *this_17;
  CINSPathFollower *this_18;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (**(int **)(&DAT_004688ed + unaff_EBX) == 0) {
    piVar5 = (int *)0x0;
  }
  else {
    cVar4 = CINSRules::IsCheckpoint(this);
    if (cVar4 != '\0') {
      piVar5 = (int *)::operator_new(0x40);
      piVar5[8] = 0;
      piVar5[9] = 0;
      piVar5[10] = 0;
      piVar5[3] = 0;
      piVar5[4] = 0;
      piVar5[5] = 0;
      piVar5[6] = 0;
      piVar5[7] = 0;
      piVar5[2] = 0;
      *(undefined1 *)(piVar5 + 0xc) = 0;
      *(undefined1 *)((int)piVar5 + 0x31) = 0;
      piVar5[0xb] = 0;
      piVar5[0xd] = 0;
      iVar2 = *(int *)(unaff_EBX + 0x468521 /* &vtable for CINSBotActionCheckpoint */);
      piVar5[1] = iVar2 + 0x1a0;
      *piVar5 = iVar2 + 8;
      return piVar5;
    }
    cVar4 = CINSRules::IsHunt(this_00);
    if (cVar4 == '\0') {
      cVar4 = CINSRules::IsOutpost(this_01);
      if (cVar4 != '\0') {
        piVar5 = (int *)::operator_new(0x5c);
        piVar5[8] = 0;
        piVar5[9] = 0;
        piVar5[10] = 0;
        piVar5[3] = 0;
        piVar5[4] = 0;
        piVar5[5] = 0;
        piVar5[6] = 0;
        piVar5[7] = 0;
        piVar5[2] = 0;
        *(undefined1 *)(piVar5 + 0xc) = 0;
        *(undefined1 *)((int)piVar5 + 0x31) = 0;
        piVar5[0xb] = 0;
        piVar5[0xd] = 0;
        iVar2 = *(int *)(unaff_EBX + 0x468945 /* &vtable for CINSBotActionOutpost */);
        piVar5[0x10] = 0;
        piVar5[1] = iVar2 + 0x1a4;
        piVar5[0xf] = unaff_EBX + 0x3ea1ad /* vtable for CountdownTimer+0x8 */;
        *piVar5 = iVar2 + 8;
        CountdownTimer::NetworkStateChanged(piVar5 + 0xf);
        piVar5[0x11] = -0x40800000 /* -1.0f */;
        (**(code **)(piVar5[0xf] + 4))(piVar5 + 0xf,piVar5 + 0x11);
        return piVar5;
      }
      cVar4 = CINSRules::IsOccupy(this_02);
      if (cVar4 == '\0') {
        cVar4 = CINSRules::IsPush(this_03);
        if ((cVar4 == '\0') && (cVar4 = CINSRules::IsInvasion(this_04), cVar4 == '\0')) {
          cVar4 = CINSRules::IsFireFight(this_05);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x3c);
            piVar5[8] = 0;
            piVar5[9] = 0;
            piVar5[10] = 0;
            piVar5[3] = 0;
            piVar5[4] = 0;
            piVar5[5] = 0;
            piVar5[6] = 0;
            piVar5[7] = 0;
            piVar5[2] = 0;
            *(undefined1 *)(piVar5 + 0xc) = 0;
            *(undefined1 *)((int)piVar5 + 0x31) = 0;
            piVar5[0xb] = 0;
            piVar5[0xd] = 0;
            iVar2 = *(int *)(unaff_EBX + 0x468ef1 /* &vtable for CINSBotActionFirefight */);
            *piVar5 = iVar2 + 8;
            piVar5[1] = iVar2 + 0x19c;
            return piVar5;
          }
          cVar4 = CINSRules::IsInfiltrate(this_06);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x3c);
            piVar5[8] = 0;
            piVar5[9] = 0;
            piVar5[10] = 0;
            piVar5[3] = 0;
            piVar5[4] = 0;
            piVar5[5] = 0;
            piVar5[6] = 0;
            piVar5[7] = 0;
            piVar5[2] = 0;
            *(undefined1 *)(piVar5 + 0xc) = 0;
            *(undefined1 *)((int)piVar5 + 0x31) = 0;
            piVar5[0xb] = 0;
            piVar5[0xd] = 0;
            iVar2 = *(int *)(unaff_EBX + 0x4685d9 /* &vtable for CINSBotActionInfiltrate */);
            *piVar5 = iVar2 + 8;
            piVar5[1] = iVar2 + 0x19c;
            return piVar5;
          }
          cVar4 = CINSRules::IsStrike(this_07);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x38);
            CINSBotActionStrike::CINSBotActionStrike(this_15);
            return piVar5;
          }
          cVar4 = CINSRules::IsSkirmish(this_08);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x3c);
            CINSBotActionSkirmish::CINSBotActionSkirmish(this_16);
            return piVar5;
          }
          cVar4 = CINSRules::IsAmbush(this_09);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x40);
            CINSBotActionAmbush::CINSBotActionAmbush(this_17);
            return piVar5;
          }
          cVar4 = CINSRules::IsFlashpoint(this_10);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x3c);
            CINSBotActionFlashpoint::CINSBotActionFlashpoint(this_14);
            return piVar5;
          }
          cVar4 = CINSRules::IsTraining(this_11);
          if (cVar4 != '\0') {
            piVar5 = (int *)::operator_new(0x48c4);
            piVar5[8] = 0;
            piVar5[9] = 0;
            piVar5[10] = 0;
            piVar5[3] = 0;
            piVar5[4] = 0;
            piVar5[5] = 0;
            piVar5[6] = 0;
            piVar5[7] = 0;
            piVar5[2] = 0;
            *(undefined1 *)(piVar5 + 0xc) = 0;
            *(undefined1 *)((int)piVar5 + 0x31) = 0;
            piVar5[0xb] = 0;
            piVar5[0xd] = 0;
            iVar2 = *(int *)(unaff_EBX + 0x468565 /* &vtable for CINSBotActionTraining */);
            piVar5[1] = iVar2 + 0x19c;
            *piVar5 = iVar2 + 8;
            CINSPathFollower::CINSPathFollower(this_18);
            piVar5[0x122c] = 0;
            piVar5[0x122b] = unaff_EBX + 0x3ea1ad /* vtable for CountdownTimer+0x8 */;
            CountdownTimer::NetworkStateChanged(piVar5 + 0x122b);
            piVar5[0x122d] = -0x40800000 /* -1.0f */;
            (**(code **)(piVar5[0x122b] + 4))(piVar5 + 0x122b,piVar5 + 0x122d);
            return piVar5;
          }
          cVar4 = CINSRules::IsSurvival(this_12);
          if (cVar4 == '\0') {
            cVar4 = CINSRules::IsConquer(this_13);
            if (cVar4 == '\0') {
              return (int *)0x0;
            }
            piVar5 = (int *)::operator_new(0x48);
            piVar5[8] = 0;
            piVar5[9] = 0;
            piVar5[10] = 0;
            piVar5[3] = 0;
            piVar5[4] = 0;
            piVar5[5] = 0;
            piVar5[6] = 0;
            piVar5[7] = 0;
            piVar5[2] = 0;
            *(undefined1 *)(piVar5 + 0xc) = 0;
            *(undefined1 *)((int)piVar5 + 0x31) = 0;
            piVar5[0xb] = 0;
            piVar5[0xd] = 0;
            iVar2 = *(int *)(&LAB_004688f5 + unaff_EBX);
            *piVar5 = iVar2 + 8;
            piVar5[1] = iVar2 + 0x19c;
            return piVar5;
          }
          piVar5 = (int *)::operator_new(0x48);
          piVar5[8] = 0;
          piVar5[9] = 0;
          piVar5[10] = 0;
          piVar5[3] = 0;
          piVar5[4] = 0;
          piVar5[5] = 0;
          piVar5[6] = 0;
          piVar5[7] = 0;
          piVar5[2] = 0;
          *(undefined1 *)(piVar5 + 0xc) = 0;
          *(undefined1 *)((int)piVar5 + 0x31) = 0;
          piVar5[0xb] = 0;
          piVar5[0xd] = 0;
          iVar2 = *(int *)(&DAT_00468d6d + unaff_EBX);
          piVar5[0x10] = 0;
          piVar5[1] = iVar2 + 0x1a0;
          piVar5[0xf] = unaff_EBX + 0x3ea1ad /* vtable for CountdownTimer+0x8 */;
          *piVar5 = iVar2 + 8;
          CountdownTimer::NetworkStateChanged(piVar5 + 0xf);
          piVar5[0x11] = -0x40800000 /* -1.0f */;
          (**(code **)(piVar5[0xf] + 4))(piVar5 + 0xf,piVar5 + 0x11);
          return piVar5;
        }
        piVar5 = (int *)::operator_new(0x3c);
        piVar5[8] = 0;
        piVar5[9] = 0;
        piVar5[10] = 0;
        piVar5[3] = 0;
        piVar5[4] = 0;
        piVar5[5] = 0;
        piVar5[6] = 0;
        piVar5[7] = 0;
        piVar5[2] = 0;
        *(undefined1 *)(piVar5 + 0xc) = 0;
        *(undefined1 *)((int)piVar5 + 0x31) = 0;
        piVar5[0xb] = 0;
        piVar5[0xd] = 0;
        iVar2 = *(int *)(CEntityFactory<CAreaPortal>::Destroy + unaff_EBX + 1);
        *piVar5 = iVar2 + 8;
        piVar5[1] = iVar2 + 0x19c;
      }
      else {
        piVar5 = (int *)::operator_new(0x3c);
        piVar5[8] = 0;
        piVar5[9] = 0;
        piVar5[10] = 0;
        piVar5[3] = 0;
        piVar5[4] = 0;
        piVar5[5] = 0;
        piVar5[6] = 0;
        piVar5[7] = 0;
        piVar5[2] = 0;
        *(undefined1 *)(piVar5 + 0xc) = 0;
        *(undefined1 *)((int)piVar5 + 0x31) = 0;
        piVar5[0xb] = 0;
        piVar5[0xd] = 0;
        iVar2 = *(int *)(unaff_EBX + 0x468eb9 /* &vtable for CINSBotActionOccupy */);
        *piVar5 = iVar2 + 8;
        piVar5[1] = iVar2 + 0x19c;
      }
    }
    else {
      iVar2 = unaff_EBX + 0x3ea1ad /* vtable for CountdownTimer+0x8 */;
      piVar5 = (int *)::operator_new(100);
      piVar5[8] = 0;
      piVar5[9] = 0;
      piVar5[10] = 0;
      piVar5[3] = 0;
      piVar5[4] = 0;
      piVar5[5] = 0;
      piVar5[6] = 0;
      piVar5[7] = 0;
      piVar5[2] = 0;
      *(undefined1 *)(piVar5 + 0xc) = 0;
      *(undefined1 *)((int)piVar5 + 0x31) = 0;
      piVar5[0xb] = 0;
      piVar5[0xd] = 0;
      iVar3 = *(int *)(unaff_EBX + 0x468b5d /* &vtable for CINSBotActionHunt */);
      piVar5[0x10] = iVar2;
      piVar5[0x11] = 0;
      piVar5[1] = iVar3 + 0x1a4;
      *piVar5 = iVar3 + 8;
      pcVar1 = (code *)(unaff_EBX + -0x50d89b /* CountdownTimer::NetworkStateChanged */);
      (*pcVar1)(piVar5 + 0x10,piVar5 + 0x11);
      piVar5[0x12] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar5[0x10] + 4))(piVar5 + 0x10,piVar5 + 0x12);
      piVar5[0x13] = iVar2;
      piVar5[0x14] = 0;
      (*pcVar1)(piVar5 + 0x13,piVar5 + 0x14);
      piVar5[0x15] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar5[0x13] + 4))(piVar5 + 0x13,piVar5 + 0x15);
      piVar5[0x16] = iVar2;
      piVar5[0x17] = 0;
      (*pcVar1)(piVar5 + 0x16,piVar5 + 0x17);
      piVar5[0x18] = -0x40800000 /* -1.0f */;
      (**(code **)(piVar5[0x16] + 4))(piVar5 + 0x16,piVar5 + 0x18);
    }
  }
  return piVar5;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::Update
 * Address: 0073dfe0
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::Update(CINSNextBot*, float) */

void CINSBotGamemodeMonitor::Update(CINSNextBot *param_1,float param_2)

{
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::GetName
 * Address: 0073e960
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::GetName() const */

int CINSBotGamemodeMonitor::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x243eab /* "Gamemode" */;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor
 * Address: 0073e980
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor() */

void __thiscall CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor(CINSBotGamemodeMonitor *this)

{
  ~CINSBotGamemodeMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor
 * Address: 0073e990
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor() */

void __thiscall CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor(CINSBotGamemodeMonitor *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x45c013 /* vtable for CINSBotGamemodeMonitor+0x8 */;
  in_stack_00000004[1] = extraout_ECX + 0x45c1a3 /* vtable for CINSBotGamemodeMonitor+0x198 */;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x4687e3 /* &_DYNAMIC */));
  return;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor
 * Address: 0073e9c0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor() */

void __thiscall CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor(CINSBotGamemodeMonitor *this)

{
  ~CINSBotGamemodeMonitor(this);
  return;
}



/* ----------------------------------------
 * CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor
 * Address: 0073e9d0
 * ---------------------------------------- */

/* CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor() */

void __thiscall CINSBotGamemodeMonitor::~CINSBotGamemodeMonitor(CINSBotGamemodeMonitor *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x45bfca /* vtable for CINSBotGamemodeMonitor+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x45c15a /* vtable for CINSBotGamemodeMonitor+0x198 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



