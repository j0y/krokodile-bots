/*
 * CINSBotDead -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 7
 */

/* ----------------------------------------
 * CINSBotDead::OnStart
 * Address: 00717b30
 * ---------------------------------------- */

/* CINSBotDead::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * CINSBotDead::OnStart(CINSNextBot *param_1,Action *param_2)

{
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(param_2 + 0x3c) != (float)fVar1) {
    (**(code **)(*(int *)(param_2 + 0x38) + 8))(param_2 + 0x38,param_2 + 0x3c);
    *(float *)(param_2 + 0x3c) = (float)fVar1;
  }
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotDead::Update
 * Address: 00717bc0
 * ---------------------------------------- */

/* CINSBotDead::Update(CINSNextBot*, float) */

CINSNextBot * __thiscall CINSBotDead::Update(CINSBotDead *this,CINSNextBot *param_1,float param_2)

{
  undefined4 *puVar1;
  code *pcVar2;
  int iVar3;
  char cVar4;
  undefined4 uVar5;
  int *piVar6;
  int unaff_EBX;
  float10 fVar7;
  float fVar8;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar4 = (**(code **)(*in_stack_0000000c + 0x118))();
  if (cVar4 == '\0') {
    fVar7 = (float10)IntervalTimer::Now();
    fVar8 = (float)fVar7 - *(float *)((int)param_2 + 0x3c);
    if ((*(float *)(unaff_EBX + 0x20cb98) <= fVar8 && fVar8 != *(float *)(unaff_EBX + 0x20cb98)) &&
       ((*(byte *)(in_stack_0000000c + 0x8a5) & 0x20) != 0)) {
      puVar1 = *(undefined4 **)(unaff_EBX + 0x48ea54);
      pcVar2 = *(code **)(*(int *)*puVar1 + 0x94);
      uVar5 = (**(code **)(*(int *)*puVar1 + 0x40))(*puVar1,in_stack_0000000c[8]);
      uVar5 = UTIL_VarArgs((char *)(unaff_EBX + 0x261eb7),uVar5);
      (*pcVar2)(*puVar1,uVar5);
    }
    *(undefined4 *)param_1 = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
  }
  else {
    piVar6 = (int *)::operator_new(0x40);
    iVar3 = *(int *)(unaff_EBX + 0x48f26c);
    *(undefined4 *)param_1 = 1;
    piVar6[8] = 0;
    piVar6[9] = 0;
    piVar6[10] = 0;
    *(int **)(param_1 + 4) = piVar6;
    piVar6[3] = 0;
    piVar6[4] = 0;
    piVar6[5] = 0;
    piVar6[6] = 0;
    piVar6[7] = 0;
    piVar6[2] = 0;
    *(undefined1 *)(piVar6 + 0xc) = 0;
    *(undefined1 *)((int)piVar6 + 0x31) = 0;
    piVar6[0xb] = 0;
    piVar6[0xd] = 0;
    *piVar6 = iVar3 + 8;
    piVar6[1] = iVar3 + 0x1a4;
    *(int *)(param_1 + 8) = unaff_EBX + 0x269067;
  }
  return param_1;
}



/* ----------------------------------------
 * CINSBotDead::GetName
 * Address: 00717db0
 * ---------------------------------------- */

/* CINSBotDead::GetName() const */

int CINSBotDead::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x211484;
}



/* ----------------------------------------
 * CINSBotDead::~CINSBotDead
 * Address: 00717dd0
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotDead::~CINSBotDead() */

void __thiscall CINSBotDead::~CINSBotDead(CINSBotDead *this)

{
  ~CINSBotDead(this);
  return;
}



/* ----------------------------------------
 * CINSBotDead::~CINSBotDead
 * Address: 00717de0
 * ---------------------------------------- */

/* CINSBotDead::~CINSBotDead() */

void __thiscall CINSBotDead::~CINSBotDead(CINSBotDead *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x47e803;
  in_stack_00000004[1] = extraout_ECX + 0x47e993;
  Action<CINSNextBot>::~Action((Action<CINSNextBot> *)(extraout_ECX + 0x48f393));
  return;
}



/* ----------------------------------------
 * CINSBotDead::~CINSBotDead
 * Address: 00717e10
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotDead::~CINSBotDead() */

void __thiscall CINSBotDead::~CINSBotDead(CINSBotDead *this)

{
  ~CINSBotDead(this);
  return;
}



/* ----------------------------------------
 * CINSBotDead::~CINSBotDead
 * Address: 00717e20
 * ---------------------------------------- */

/* CINSBotDead::~CINSBotDead() */

void __thiscall CINSBotDead::~CINSBotDead(CINSBotDead *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x47e7ba;
  in_stack_00000004[1] = unaff_EBX + 0x47e94a;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



