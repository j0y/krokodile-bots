/*
 * CINSBotFlashed -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 7
 */

/* ----------------------------------------
 * CINSBotFlashed::OnStart
 * Address: 0071fdf0
 * ---------------------------------------- */

/* CINSBotFlashed::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

CINSNextBot * __thiscall
CINSBotFlashed::OnStart(CINSBotFlashed *this,CINSNextBot *param_1,Action *param_2)

{
  CINSNextBot *this_00;
  int iVar1;
  float10 fVar2;
  int in_stack_0000000c;
  
  iVar1 = 0;
  __i686_get_pc_thunk_bx();
  do {
    fVar2 = (float10)RandomFloat(0x3dcccccd,0x3f800000);
    *(float *)(param_2 + iVar1 * 4 + 0x38) = (float)fVar2;
    iVar1 = iVar1 + 1;
  } while (iVar1 != 4);
  CINSNextBot::BotSpeakConceptIfAllowed
            (this_00,in_stack_0000000c,(char *)0x4b,(char *)0x0,0,(IRecipientFilter *)0x0);
  *(undefined4 *)param_1 = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * CINSBotFlashed::Update
 * Address: 0071fe80
 * ---------------------------------------- */

/* CINSBotFlashed::Update(CINSNextBot*, float) */

void __thiscall CINSBotFlashed::Update(CINSBotFlashed *this,CINSNextBot *param_1,float param_2)

{
  undefined4 *puVar1;
  int unaff_EBX;
  float10 fVar2;
  float fVar3;
  int in_stack_0000000c;
  
  fVar3 = 0.0;
  puVar1 = (undefined4 *)__i686_get_pc_thunk_bx();
  if (fVar3 < *(float *)(in_stack_0000000c + 0x1820)) {
    fVar2 = (float10)CountdownTimer::Now();
    if ((float)fVar2 < *(float *)(in_stack_0000000c + 0x1820) ||
        (float)fVar2 == *(float *)(in_stack_0000000c + 0x1820)) {
      *puVar1 = 0;
      puVar1[1] = 0;
      puVar1[2] = 0;
      return;
    }
  }
  *puVar1 = 3;
  puVar1[1] = 0;
  puVar1[2] = unaff_EBX + 0x261372 /* "No longer blind." */;
  return;
}



/* ----------------------------------------
 * CINSBotFlashed::GetName
 * Address: 00720030
 * ---------------------------------------- */

/* CINSBotFlashed::GetName() const */

int CINSBotFlashed::GetName(void)

{
  int extraout_ECX;
  
  __i686_get_pc_thunk_cx();
  return extraout_ECX + 0x2611cf /* "Flashed" */;
}



/* ----------------------------------------
 * CINSBotFlashed::~CINSBotFlashed
 * Address: 00720050
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFlashed::~CINSBotFlashed() */

void __thiscall CINSBotFlashed::~CINSBotFlashed(CINSBotFlashed *this)

{
  ~CINSBotFlashed(this);
  return;
}



/* ----------------------------------------
 * CINSBotFlashed::~CINSBotFlashed
 * Address: 00720060
 * ---------------------------------------- */

/* CINSBotFlashed::~CINSBotFlashed() */

void __thiscall CINSBotFlashed::~CINSBotFlashed(CINSBotFlashed *this)

{
  int extraout_ECX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_cx();
  *in_stack_00000004 = extraout_ECX + 0x476d63 /* vtable for CINSBotFlashed+0x8 */;
  in_stack_00000004[1] = (int)(&UNK_00476ef3 + extraout_ECX);
  Action<CINSNextBot>::~Action
            ((Action<CINSNextBot> *)(CTimedEventMgr::~CTimedEventMgr + extraout_ECX + 3));
  return;
}



/* ----------------------------------------
 * CINSBotFlashed::~CINSBotFlashed
 * Address: 00720090
 * ---------------------------------------- */

/* non-virtual thunk to CINSBotFlashed::~CINSBotFlashed() */

void __thiscall CINSBotFlashed::~CINSBotFlashed(CINSBotFlashed *this)

{
  ~CINSBotFlashed(this);
  return;
}



/* ----------------------------------------
 * CINSBotFlashed::~CINSBotFlashed
 * Address: 007200a0
 * ---------------------------------------- */

/* CINSBotFlashed::~CINSBotFlashed() */

void __thiscall CINSBotFlashed::~CINSBotFlashed(CINSBotFlashed *this)

{
  Action<CINSNextBot> *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x476d1a /* vtable for CINSBotFlashed+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x476eaa /* vtable for CINSBotFlashed+0x198 */;
  Action<CINSNextBot>::~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



