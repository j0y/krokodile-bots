/*
 * CINSNextBotIntention -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 9
 */

/* ----------------------------------------
 * CINSNextBotIntention::CINSNextBotIntention
 * Address: 007484b0
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::CINSNextBotIntention(CINSNextBot*) */

void __thiscall
CINSNextBot::CINSNextBotIntention::CINSNextBotIntention
          (CINSNextBotIntention *this,CINSNextBot *param_1)

{
  int iVar1;
  int *piVar2;
  undefined4 *puVar3;
  CFmtStrN<32,false> *this_00;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  INextBotComponent::INextBotComponent
            ((INextBotComponent *)(in_stack_00000008 + 0x2060),(INextBot *)param_1);
  *(int *)param_1 = unaff_EBX + 0x452ccb /* vtable for CINSNextBot::CINSNextBotIntention+0x8 */ /* vtable for CINSNextBot::CINSNextBotIntention+0x8 */;
  *(int *)(param_1 + 0x14) = unaff_EBX + 0x452dcb /* vtable for CINSNextBot::CINSNextBotIntention+0x108 */ /* vtable for CINSNextBot::CINSNextBotIntention+0x108 */;
  piVar2 = (int *)::operator_new(0x40);
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
  iVar1 = *(int *)(unaff_EBX + 0x45e983 /* &vtable for CINSBotMainAction */ /* &vtable for CINSBotMainAction */);
  *piVar2 = iVar1 + 8;
  piVar2[1] = iVar1 + 0x1a4;
  puVar3 = (undefined4 *)::operator_new(0x50);
  *puVar3 = &UNK_004539cb + unaff_EBX;
  puVar3[1] = unaff_EBX + 0x453abb /* vtable for Behavior<CINSNextBot>+0xf8 */ /* vtable for Behavior<CINSNextBot>+0xf8 */;
  CFmtStrN<32,false>::CFmtStrN
            (this_00,(char *)(puVar3 + 3),&UNK_00230f37 + unaff_EBX,unaff_EBX + 0x2115be /* rodata:0x73250900 */ /* rodata:0x73250900 */);
  puVar3[0xf] = 0;
  puVar3[0x10] = 0;
  puVar3[0x11] = 0;
  puVar3[0x12] = 0;
  puVar3[0x13] = 0;
  puVar3[2] = piVar2;
  puVar3[0xe] = 0;
  *(undefined4 **)(param_1 + 0x18) = puVar3;
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::Update
 * Address: 0074c1e0
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::Update() */

void __thiscall CINSNextBot::CINSNextBotIntention::Update(CINSNextBotIntention *this)

{
  int iVar1;
  float fVar2;
  int *in_stack_00000004;
  
  iVar1 = (**(code **)(*in_stack_00000004 + 0xc4))();
  fVar2 = 0.0;
  if (iVar1 != 0) {
    fVar2 = (float)(iVar1 + -0x2060);
  }
  Behavior<CINSNextBot>::Update((CINSNextBot *)in_stack_00000004[6],fVar2);
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::FirstContainedResponder
 * Address: 0074c320
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::FirstContainedResponder() const */

undefined4 __thiscall
CINSNextBot::CINSNextBotIntention::FirstContainedResponder(CINSNextBotIntention *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x18);
}



/* ----------------------------------------
 * CINSNextBotIntention::NextContainedResponder
 * Address: 0074c330
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::NextContainedResponder(INextBotEventResponder*) const */

undefined4 __cdecl
CINSNextBot::CINSNextBotIntention::NextContainedResponder(INextBotEventResponder *param_1)

{
  return 0;
}



/* ----------------------------------------
 * CINSNextBotIntention::Reset
 * Address: 00748630
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::Reset() */

void __thiscall CINSNextBot::CINSNextBotIntention::Reset(CINSNextBotIntention *this)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  CFmtStrN<32,false> *this_00;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar2 = *(int **)(in_stack_00000004 + 0x18);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 4))(piVar2);
  }
  piVar2 = (int *)::operator_new(0x40);
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
  iVar1 = *(int *)(unaff_EBX + 0x45e805 /* &vtable for CINSBotMainAction */ /* &vtable for CINSBotMainAction */);
  *piVar2 = iVar1 + 8;
  piVar2[1] = iVar1 + 0x1a4;
  piVar3 = (int *)::operator_new(0x50);
  *piVar3 = unaff_EBX + 0x45384d /* vtable for Behavior<CINSNextBot>+0x8 */ /* vtable for Behavior<CINSNextBot>+0x8 */;
  piVar3[1] = unaff_EBX + 0x45393d /* vtable for Behavior<CINSNextBot>+0xf8 */ /* vtable for Behavior<CINSNextBot>+0xf8 */;
  CFmtStrN<32,false>::CFmtStrN
            (this_00,(char *)(piVar3 + 3),unaff_EBX + 0x230db9 /* "%s" */ /* "%s" */,unaff_EBX + 0x211440 /* rodata:0x73250900 */ /* rodata:0x73250900 */);
  piVar3[0xf] = 0;
  piVar3[0x10] = 0;
  piVar3[0x11] = 0;
  piVar3[0x12] = 0;
  piVar3[0x13] = 0;
  piVar3[2] = (int)piVar2;
  piVar3[0xe] = 0;
  *(int **)(in_stack_00000004 + 0x18) = piVar3;
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::~CINSNextBotIntention
 * Address: 00742e80
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention() */

void __thiscall CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention(CINSNextBotIntention *this)

{
  ~CINSNextBotIntention(this);
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::~CINSNextBotIntention
 * Address: 00742e90
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention() */

void __thiscall CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention(CINSNextBotIntention *this)

{
  int *piVar1;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4582ea /* vtable for CINSNextBot::CINSNextBotIntention+0x8 */ /* vtable for CINSNextBot::CINSNextBotIntention+0x8 */;
  in_stack_00000004[5] = unaff_EBX + 0x4583ea /* vtable for CINSNextBot::CINSNextBotIntention+0x108 */ /* vtable for CINSNextBot::CINSNextBotIntention+0x108 */;
  piVar1 = (int *)in_stack_00000004[6];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
  }
  in_stack_00000004[5] = unaff_EBX + 0x3e622a /* vtable for IContextualQuery+0x8 */ /* vtable for IContextualQuery+0x8 */;
  *in_stack_00000004 = unaff_EBX + 0x3e616a /* vtable for INextBotEventResponder+0x8 */ /* vtable for INextBotEventResponder+0x8 */;
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::~CINSNextBotIntention
 * Address: 007430b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention() */

void __thiscall CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention(CINSNextBotIntention *this)

{
  ~CINSNextBotIntention(this);
  return;
}



/* ----------------------------------------
 * CINSNextBotIntention::~CINSNextBotIntention
 * Address: 007430c0
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention() */

void __thiscall CINSNextBot::CINSNextBotIntention::~CINSNextBotIntention(CINSNextBotIntention *this)

{
  CINSNextBotIntention *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSNextBotIntention(this_00);
  operator_delete(in_stack_00000004);
  return;
}



