/*
 * Behavior_CINSNextBot -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 31
 */

/* ----------------------------------------
 * Behavior<CINSNextBot>::Update
 * Address: 007530b0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::Update(CINSNextBot*, float) */

void __cdecl Behavior<CINSNextBot>::Update(CINSNextBot *param_1,float param_2)

{
  int *piVar1;
  code *pcVar2;
  char cVar3;
  int iVar4;
  undefined4 uVar5;
  Action<CINSNextBot> *this;
  CFmtStrN<256,false> *this_00;
  int unaff_EBX;
  int iVar6;
  int local_134;
  undefined1 local_130;
  undefined1 local_12f;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x7530bb;
  __i686_get_pc_thunk_bx();
  if ((param_2 != 0.0) && (*(Behavior **)(param_1 + 8) != (Behavior *)0x0)) {
    *(float *)(param_1 + 0x38) = param_2;
    Action<CINSNextBot>::InvokeUpdate((CINSNextBot *)&local_28,*(Behavior **)(param_1 + 8),param_2);
    iVar4 = Action<CINSNextBot>::ApplyResult
                      (*(undefined4 *)(param_1 + 8),param_2,param_1,local_28,local_24,local_20);
    *(int *)(param_1 + 8) = iVar4;
    if (iVar4 != 0) {
      cVar3 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1);
      if (cVar3 != '\0') {
        local_134 = unaff_EBX + 0x3d036d /* vtable for CFmtStrN<256, false>+0x8 */;
        local_130 = 0;
        local_12f = 0;
        local_2c = 0;
        pcVar2 = *(code **)(*(int *)((int)param_2 + 0x2060) + 0x14c);
        uVar5 = Action<CINSNextBot>::DebugString(this);
        uVar5 = CFmtStrN<256,false>::sprintf
                          (this_00,(char *)&local_134,unaff_EBX + 0x22191c /* "%s: %s" */,param_1 + 0x11,uVar5);
        (*pcVar2)((int)param_2 + 0x2060,uVar5);
      }
    }
    iVar6 = 0;
    iVar4 = *(int *)(param_1 + 0x3c);
    if (0 < *(int *)(param_1 + 0x48)) {
      do {
        piVar1 = *(int **)(iVar4 + iVar6 * 4);
        if (piVar1 != (int *)0x0) {
          (**(code **)(*piVar1 + 4))(piVar1);
          iVar4 = *(int *)(param_1 + 0x3c);
        }
        iVar6 = iVar6 + 1;
      } while (iVar6 < *(int *)(param_1 + 0x48));
    }
    *(undefined4 *)(param_1 + 0x48) = 0;
    if (-1 < *(int *)(param_1 + 0x44)) {
      if (iVar4 != 0) {
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4537bd /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4537bd /* &GCSDK::GetPchTempTextBuffer */),iVar4);
        *(undefined4 *)(param_1 + 0x3c) = 0;
      }
      *(undefined4 *)(param_1 + 0x40) = 0;
      iVar4 = 0;
    }
    *(int *)(param_1 + 0x4c) = iVar4;
  }
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldHurry
 * Address: 0074cbb0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldHurry(INextBot const*) const */

void __thiscall Behavior<CINSNextBot>::ShouldHurry(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  ShouldHurry(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldHurry
 * Address: 0074cbc0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldHurry(INextBot const*) const */

int __thiscall Behavior<CINSNextBot>::ShouldHurry(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000008;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0xc))(iVar3 + 4,in_stack_00000008);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldRetreat
 * Address: 0074cc40
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldRetreat(INextBot const*) const */

void __thiscall Behavior<CINSNextBot>::ShouldRetreat(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  ShouldRetreat(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldRetreat
 * Address: 0074cc50
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldRetreat(INextBot const*) const */

int __thiscall Behavior<CINSNextBot>::ShouldRetreat(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000008;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x10))(iVar3 + 4,in_stack_00000008);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldAttack
 * Address: 0074ccd0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldAttack(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
Behavior<CINSNextBot>::ShouldAttack
          (Behavior<CINSNextBot> *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldAttack(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldAttack
 * Address: 0074cce0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldAttack(INextBot const*, CKnownEntity const*) const */

int __thiscall
Behavior<CINSNextBot>::ShouldAttack
          (Behavior<CINSNextBot> *this,INextBot *param_1,CKnownEntity *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_0000000c;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x14))(iVar3 + 4,param_2,in_stack_0000000c);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::SelectMoreDangerousThreat
 * Address: 0074cfe0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::SelectMoreDangerousThreat(INextBot const*,
   CBaseCombatCharacter const*, CKnownEntity const*, CKnownEntity const*) const */

void __thiscall
Behavior<CINSNextBot>::SelectMoreDangerousThreat
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseCombatCharacter *param_2,
          CKnownEntity *param_3,CKnownEntity *param_4)

{
  SelectMoreDangerousThreat(this,param_1 + -4,param_2,param_3,param_4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::SelectMoreDangerousThreat
 * Address: 0074cff0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::SelectMoreDangerousThreat(INextBot const*, CBaseCombatCharacter const*,
   CKnownEntity const*, CKnownEntity const*) const */

int __thiscall
Behavior<CINSNextBot>::SelectMoreDangerousThreat
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseCombatCharacter *param_2,
          CKnownEntity *param_3,CKnownEntity *param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000014;
  
  iVar2 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) == 0) {
    iVar2 = 0;
  }
  else {
    do {
      iVar3 = iVar2;
      iVar2 = *(int *)(iVar3 + 0x10);
    } while (iVar2 != 0);
    iVar2 = 0;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x24))
                          (iVar3 + 4,param_2,param_3,param_4,in_stack_00000014);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 0);
      iVar3 = iVar1;
    } while (iVar2 == 0);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::IsHindrance
 * Address: 0074cd60
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::IsHindrance(INextBot const*, CBaseEntity*) const */

void __thiscall
Behavior<CINSNextBot>::IsHindrance
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseEntity *param_2)

{
  IsHindrance(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::IsHindrance
 * Address: 0074cd70
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::IsHindrance(INextBot const*, CBaseEntity*) const */

int __thiscall
Behavior<CINSNextBot>::IsHindrance
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseEntity *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_0000000c;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x18))(iVar3 + 4,param_2,in_stack_0000000c);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldPickUp
 * Address: 0074cb20
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldPickUp(INextBot const*, CBaseEntity*) const */

void __thiscall
Behavior<CINSNextBot>::ShouldPickUp
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseEntity *param_2)

{
  ShouldPickUp(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldPickUp
 * Address: 0074cb30
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldPickUp(INextBot const*, CBaseEntity*) const */

int __thiscall
Behavior<CINSNextBot>::ShouldPickUp
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseEntity *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_0000000c;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 8))(iVar3 + 4,param_2,in_stack_0000000c);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::FirstContainedResponder
 * Address: 0074cb00
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::FirstContainedResponder() const */

undefined4 __thiscall Behavior<CINSNextBot>::FirstContainedResponder(Behavior<CINSNextBot> *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 8);
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::IsPositionAllowed
 * Address: 0074cf50
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::IsPositionAllowed(INextBot const*, Vector const&)
   const */

void __thiscall
Behavior<CINSNextBot>::IsPositionAllowed
          (Behavior<CINSNextBot> *this,INextBot *param_1,Vector *param_2)

{
  IsPositionAllowed(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::IsPositionAllowed
 * Address: 0074cf60
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::IsPositionAllowed(INextBot const*, Vector const&) const */

int __thiscall
Behavior<CINSNextBot>::IsPositionAllowed
          (Behavior<CINSNextBot> *this,INextBot *param_1,Vector *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_0000000c;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x20))(iVar3 + 4,param_2,in_stack_0000000c);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::NextContainedResponder
 * Address: 0074cb10
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::NextContainedResponder(INextBotEventResponder*) const */

undefined4 __cdecl Behavior<CINSNextBot>::NextContainedResponder(INextBotEventResponder *param_1)

{
  return 0;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::SelectTargetPoint
 * Address: 0074cdf0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::SelectTargetPoint(INextBot const*,
   CBaseCombatCharacter const*) const */

void __thiscall
Behavior<CINSNextBot>::SelectTargetPoint
          (Behavior<CINSNextBot> *this,INextBot *param_1,CBaseCombatCharacter *param_2)

{
  SelectTargetPoint(param_1,param_2 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::SelectTargetPoint
 * Address: 0074ce00
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::SelectTargetPoint(INextBot const*, CBaseCombatCharacter const*) const */

void Behavior<CINSNextBot>::SelectTargetPoint(INextBot *param_1,CBaseCombatCharacter *param_2)

{
  float *pfVar1;
  int iVar2;
  int iVar3;
  int unaff_EBX;
  undefined4 in_stack_0000000c;
  undefined4 in_stack_00000010;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x74ce0b;
  __i686_get_pc_thunk_bx();
  pfVar1 = *(float **)(unaff_EBX + 0x4597c1 /* &vec3_origin */);
  *(float *)param_1 = *pfVar1;
  *(float *)(param_1 + 4) = pfVar1[1];
  *(float *)(param_1 + 8) = pfVar1[2];
  iVar2 = *(int *)(param_2 + 8);
  if (*(int *)(param_2 + 8) != 0) {
    do {
      iVar3 = iVar2;
      iVar2 = *(int *)(iVar3 + 0x10);
    } while (*(int *)(iVar3 + 0x10) != 0);
    while (((*pfVar1 == *(float *)param_1 && (pfVar1[1] == *(float *)(param_1 + 4))) &&
           (pfVar1[2] == *(float *)(param_1 + 8)))) {
      iVar2 = *(int *)(iVar3 + 0xc);
      if (((*pfVar1 == *(float *)param_1) && (pfVar1[1] == *(float *)(param_1 + 4))) &&
         (pfVar1[2] == *(float *)(param_1 + 8))) {
        while( true ) {
          (**(code **)(*(int *)(iVar3 + 4) + 0x1c))
                    (&local_28,iVar3 + 4,in_stack_0000000c,in_stack_00000010);
          *(float *)param_1 = local_28;
          *(float *)(param_1 + 4) = local_24;
          *(float *)(param_1 + 8) = local_20;
          iVar3 = *(int *)(iVar3 + 0x14);
          if ((iVar3 == 0) || (local_28 != *pfVar1)) break;
          if ((local_24 != pfVar1[1]) || (local_20 != pfVar1[2])) break;
        }
      }
      iVar3 = iVar2;
      if (iVar2 == 0) {
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldIronsight
 * Address: 0074d100
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldIronsight(INextBot const*) const */

void __thiscall
Behavior<CINSNextBot>::ShouldIronsight(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  ShouldIronsight(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldIronsight
 * Address: 0074d110
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldIronsight(INextBot const*) const */

int __thiscall Behavior<CINSNextBot>::ShouldIronsight(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000008;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x2c))(iVar3 + 4,in_stack_00000008);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldProne
 * Address: 0074d190
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldProne(INextBot const*) const */

void __thiscall Behavior<CINSNextBot>::ShouldProne(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  ShouldProne(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldProne
 * Address: 0074d1a0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldProne(INextBot const*) const */

int __thiscall Behavior<CINSNextBot>::ShouldProne(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000008;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x30))(iVar3 + 4,in_stack_00000008);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldPursue
 * Address: 0074d220
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldPursue(INextBot const*, CKnownEntity const*)
   const */

void __thiscall
Behavior<CINSNextBot>::ShouldPursue
          (Behavior<CINSNextBot> *this,INextBot *param_1,CKnownEntity *param_2)

{
  ShouldPursue(this,param_1 + -4,param_2);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldPursue
 * Address: 0074d230
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldPursue(INextBot const*, CKnownEntity const*) const */

int __thiscall
Behavior<CINSNextBot>::ShouldPursue
          (Behavior<CINSNextBot> *this,INextBot *param_1,CKnownEntity *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_0000000c;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x34))(iVar3 + 4,param_2,in_stack_0000000c);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldWalk
 * Address: 0074d070
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::ShouldWalk(INextBot const*) const */

void __thiscall Behavior<CINSNextBot>::ShouldWalk(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  ShouldWalk(this,param_1 + -4);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::ShouldWalk
 * Address: 0074d080
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::ShouldWalk(INextBot const*) const */

int __thiscall Behavior<CINSNextBot>::ShouldWalk(Behavior<CINSNextBot> *this,INextBot *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 in_stack_00000008;
  
  iVar2 = 2;
  iVar1 = *(int *)(param_1 + 8);
  if (*(int *)(param_1 + 8) != 0) {
    do {
      iVar3 = iVar1;
      iVar1 = *(int *)(iVar3 + 0x10);
    } while (iVar1 != 0);
    iVar2 = 2;
    do {
      if (iVar3 == 0) {
        return iVar2;
      }
      iVar1 = *(int *)(iVar3 + 0xc);
      do {
        iVar2 = (**(code **)(*(int *)(iVar3 + 4) + 0x28))(iVar3 + 4,in_stack_00000008);
        iVar3 = *(int *)(iVar3 + 0x14);
        if (iVar3 == 0) break;
      } while (iVar2 == 2);
      iVar3 = iVar1;
    } while (iVar2 == 2);
  }
  return iVar2;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::~Behavior
 * Address: 00750bc0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::~Behavior() */

void __thiscall Behavior<CINSNextBot>::~Behavior(Behavior<CINSNextBot> *this)

{
  ~Behavior(this);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::~Behavior
 * Address: 00750bd0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::~Behavior() */

void __thiscall Behavior<CINSNextBot>::~Behavior(Behavior<CINSNextBot> *this)

{
  int *piVar1;
  int *piVar2;
  Action<CINSNextBot> *this_00;
  int iVar3;
  int unaff_EBX;
  int iVar4;
  Action *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(int *)in_stack_00000004 = unaff_EBX + 0x44b2ad /* vtable for Behavior<CINSNextBot>+0x8 */;
  *(int *)(in_stack_00000004 + 4) = unaff_EBX + 0x44b39d /* vtable for Behavior<CINSNextBot>+0xf8 */;
  if (*(Behavior **)(in_stack_00000004 + 0x38) == (Behavior *)0x0) {
LAB_00750c24:
    piVar1 = *(int **)(in_stack_00000004 + 8);
    if (piVar1 != (int *)0x0) {
      for (piVar2 = (int *)piVar1[5]; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[5]) {
        piVar1 = piVar2;
      }
      (**(code **)(*piVar1 + 4))(piVar1);
    }
  }
  else if (*(CINSNextBot **)(in_stack_00000004 + 8) != (CINSNextBot *)0x0) {
    Action<CINSNextBot>::InvokeOnEnd
              (this_00,*(CINSNextBot **)(in_stack_00000004 + 8),
               *(Behavior **)(in_stack_00000004 + 0x38),in_stack_00000004);
    *(undefined4 *)(in_stack_00000004 + 0x38) = 0;
    goto LAB_00750c24;
  }
  iVar3 = *(int *)(in_stack_00000004 + 0x3c);
  if (0 < *(int *)(in_stack_00000004 + 0x48)) {
    iVar4 = 0;
    do {
      piVar1 = *(int **)(iVar3 + iVar4 * 4);
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 4))(piVar1);
        iVar3 = *(int *)(in_stack_00000004 + 0x3c);
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < *(int *)(in_stack_00000004 + 0x48));
  }
  iVar4 = *(int *)(in_stack_00000004 + 0x44);
  *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
  if (iVar4 < 0) {
    *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
  }
  else {
    if (iVar3 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x455c9d /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x455c9d /* &GCSDK::GetPchTempTextBuffer */),iVar3);
      iVar4 = *(int *)(in_stack_00000004 + 0x44);
      *(undefined4 *)(in_stack_00000004 + 0x3c) = 0;
    }
    *(undefined4 *)(in_stack_00000004 + 0x40) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x4c) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
    if (-1 < iVar4) goto LAB_00750cce;
    iVar3 = 0;
  }
  *(int *)(in_stack_00000004 + 0x4c) = iVar3;
LAB_00750cce:
  *(int *)(in_stack_00000004 + 4) = unaff_EBX + 0x3d84ed /* vtable for IContextualQuery+0x8 */;
  *(int *)in_stack_00000004 = unaff_EBX + 0x3d842d /* vtable for INextBotEventResponder+0x8 */;
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::~Behavior
 * Address: 00750da0
 * ---------------------------------------- */

/* non-virtual thunk to Behavior<CINSNextBot>::~Behavior() */

void __thiscall Behavior<CINSNextBot>::~Behavior(Behavior<CINSNextBot> *this)

{
  ~Behavior(this);
  return;
}



/* ----------------------------------------
 * Behavior<CINSNextBot>::~Behavior
 * Address: 00750db0
 * ---------------------------------------- */

/* Behavior<CINSNextBot>::~Behavior() */

void __thiscall Behavior<CINSNextBot>::~Behavior(Behavior<CINSNextBot> *this)

{
  int *piVar1;
  int *piVar2;
  Action<CINSNextBot> *this_00;
  int iVar3;
  int unaff_EBX;
  int iVar4;
  Action *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(int *)in_stack_00000004 = unaff_EBX + 0x44b0cd /* vtable for Behavior<CINSNextBot>+0x8 */;
  *(int *)(in_stack_00000004 + 4) = unaff_EBX + 0x44b1bd /* vtable for Behavior<CINSNextBot>+0xf8 */;
  if (*(Behavior **)(in_stack_00000004 + 0x38) == (Behavior *)0x0) {
LAB_00750e04:
    piVar1 = *(int **)(in_stack_00000004 + 8);
    if (piVar1 != (int *)0x0) {
      for (piVar2 = (int *)piVar1[5]; piVar2 != (int *)0x0; piVar2 = (int *)piVar2[5]) {
        piVar1 = piVar2;
      }
      (**(code **)(*piVar1 + 4))(piVar1);
    }
  }
  else if (*(CINSNextBot **)(in_stack_00000004 + 8) != (CINSNextBot *)0x0) {
    Action<CINSNextBot>::InvokeOnEnd
              (this_00,*(CINSNextBot **)(in_stack_00000004 + 8),
               *(Behavior **)(in_stack_00000004 + 0x38),in_stack_00000004);
    *(undefined4 *)(in_stack_00000004 + 0x38) = 0;
    goto LAB_00750e04;
  }
  iVar3 = *(int *)(in_stack_00000004 + 0x3c);
  if (0 < *(int *)(in_stack_00000004 + 0x48)) {
    iVar4 = 0;
    do {
      piVar1 = *(int **)(iVar3 + iVar4 * 4);
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 4))(piVar1);
        iVar3 = *(int *)(in_stack_00000004 + 0x3c);
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < *(int *)(in_stack_00000004 + 0x48));
  }
  iVar4 = *(int *)(in_stack_00000004 + 0x44);
  *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
  if (iVar4 < 0) {
    *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
  }
  else {
    if (iVar3 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x455abd /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x455abd /* &GCSDK::GetPchTempTextBuffer */),iVar3);
      iVar4 = *(int *)(in_stack_00000004 + 0x44);
      *(undefined4 *)(in_stack_00000004 + 0x3c) = 0;
    }
    *(undefined4 *)(in_stack_00000004 + 0x40) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x4c) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x48) = 0;
    if (-1 < iVar4) goto LAB_00750eae;
    iVar3 = 0;
  }
  *(int *)(in_stack_00000004 + 0x4c) = iVar3;
LAB_00750eae:
  *(int *)(in_stack_00000004 + 4) = unaff_EBX + 0x3d830d /* vtable for IContextualQuery+0x8 */;
  *(int *)in_stack_00000004 = unaff_EBX + 0x3d824d /* vtable for INextBotEventResponder+0x8 */;
  operator_delete(in_stack_00000004);
  return;
}



