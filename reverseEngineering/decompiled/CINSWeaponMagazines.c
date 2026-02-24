/*
 * CINSWeaponMagazines -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 11
 */

/* ----------------------------------------
 * CINSWeaponMagazines::AddMags
 * Address: 00687a40  Size: 227 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::AddMags(int, int, int) */

CINSWeaponMagazines * __thiscall
CINSWeaponMagazines::AddMags(CINSWeaponMagazines *this,int param_1,int param_2,int param_3)

{
  int iVar1;
  CINSWeaponMagazines *pCVar2;
  CAmmoDef *this_00;
  CINSWeaponMagazines *pCVar3;
  CINSWeaponMagazines *this_01;
  CINSWeaponMagazines *extraout_ECX;
  int *piVar4;
  int in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  iVar1 = GetAmmoDef();
  iVar1 = CAmmoDef::GetAmmoOfIndex(this_00,iVar1);
  pCVar2 = (CINSWeaponMagazines *)0x0;
  if (iVar1 != 0) {
    if (param_3 < 1) {
      param_3 = *(int *)(iVar1 + 0x88);
    }
    if (in_stack_00000010 < 0) {
      in_stack_00000010 = *(int *)(iVar1 + 0x84);
    }
    pCVar2 = (CINSWeaponMagazines *)(in_stack_00000010 - *(int *)(param_1 + 0x14));
    pCVar3 = (CINSWeaponMagazines *)param_2;
    if ((int)pCVar2 <= param_2) {
      pCVar3 = pCVar2;
    }
    pCVar2 = (CINSWeaponMagazines *)0x0;
    if ((int)pCVar3 < 1) {
      if (0 < *(int *)(param_1 + 0x14)) {
        iVar1 = 0;
        do {
          piVar4 = (int *)(iVar1 * 4 + *(int *)(param_1 + 8));
          if (*piVar4 < param_3) {
            pCVar2 = pCVar2 + 1;
            *piVar4 = param_3;
            if (param_2 <= (int)pCVar2) {
              return pCVar2;
            }
          }
          iVar1 = iVar1 + 1;
        } while (iVar1 < *(int *)(param_1 + 0x14));
        return pCVar2;
      }
    }
    else {
      pCVar2 = (CINSWeaponMagazines *)0x0;
      this_01 = pCVar3;
      do {
        pCVar2 = pCVar2 + 1;
        StoreMagazine(this_01,param_1);
        this_01 = extraout_ECX;
      } while (pCVar2 != pCVar3);
    }
  }
  return pCVar2;
}



/* ----------------------------------------
 * CINSWeaponMagazines::CINSWeaponMagazines
 * Address: 00687660  Size: 228 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::CINSWeaponMagazines(CBasePlayer*, int) */

void __thiscall
CINSWeaponMagazines::CINSWeaponMagazines(CINSWeaponMagazines *this,CBasePlayer *param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  int unaff_EBX;
  CBaseCombatCharacter *in_stack_0000000c;
  
  uVar1 = __i686_get_pc_thunk_bx();
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  *(undefined4 *)param_1 = uVar1;
  if (param_2 != 0) {
    puVar2 = (undefined4 *)(**(code **)(*(int *)param_2 + 0xc))(param_2);
    *(undefined4 *)(param_1 + 4) = *puVar2;
  }
  iVar3 = GetAmmoDef();
  iVar3 = CAmmoDef::MaxCarry(iVar3,in_stack_0000000c);
  iVar3 = iVar3 + 1;
  if ((*(int *)(param_1 + 0xc) < iVar3) && (-1 < *(int *)(param_1 + 0x10))) {
    *(int *)(param_1 + 0xc) = iVar3;
    if (*(int *)(param_1 + 8) == 0) {
      uVar1 = (*(code *)**(undefined4 **)**(undefined4 **)(unaff_EBX + 0x51f1fb))
                        ((undefined4 *)**(undefined4 **)(unaff_EBX + 0x51f1fb),iVar3 * 4,param_2);
    }
    else {
      uVar1 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x51f1fb) + 4))
                        ((int *)**(undefined4 **)(unaff_EBX + 0x51f1fb),*(int *)(param_1 + 8),
                         iVar3 * 4);
    }
    *(undefined4 *)(param_1 + 8) = uVar1;
  }
  else {
    uVar1 = *(undefined4 *)(param_1 + 8);
  }
  *(undefined4 *)(param_1 + 0x18) = uVar1;
  UpdateCounter();
  return;
}



/* ----------------------------------------
 * CINSWeaponMagazines::GetMagazine
 * Address: 00687590  Size: 28 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::GetMagazine(int) */

undefined4 __thiscall CINSWeaponMagazines::GetMagazine(CINSWeaponMagazines *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 0x14))) {
    uVar1 = *(undefined4 *)(*(int *)(param_1 + 8) + in_stack_00000008 * 4);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeaponMagazines::HasMagazineMoreThan
 * Address: 00687820  Size: 60 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::HasMagazineMoreThan(int) const */

undefined4 __thiscall
CINSWeaponMagazines::HasMagazineMoreThan(CINSWeaponMagazines *this,int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int in_stack_00000008;
  
  uVar1 = 0;
  if (0 < *(int *)(param_1 + 0x14)) {
    uVar1 = 1;
    if (**(int **)(param_1 + 8) < in_stack_00000008) {
      iVar2 = 0;
      while (iVar2 = iVar2 + 1, iVar2 != *(int *)(param_1 + 0x14)) {
        if (in_stack_00000008 <= (*(int **)(param_1 + 8))[iVar2]) {
          return 1;
        }
      }
      uVar1 = 0;
    }
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeaponMagazines::PopRounds
 * Address: 006878d0  Size: 143 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::PopRounds(int) */

int __thiscall CINSWeaponMagazines::PopRounds(CINSWeaponMagazines *this,int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int in_stack_00000008;
  
  iVar3 = 0;
  if ((0 < in_stack_00000008) && (iVar1 = *(int *)(param_1 + 0x14), 0 < iVar1)) {
    iVar4 = iVar3;
    do {
      piVar2 = (int *)((iVar1 + -1) * 4 + *(int *)(param_1 + 8));
      iVar3 = *piVar2;
      iVar1 = iVar3 - iVar4;
      if (in_stack_00000008 < iVar3 - iVar4) {
        iVar1 = in_stack_00000008;
      }
      if (iVar1 < iVar3) {
        *piVar2 = iVar3 - iVar1;
      }
      else {
        CUtlVector<int,CUtlMemory<int,int>>::Remove(param_1 + 8);
      }
      iVar3 = iVar4 + iVar1;
      if (in_stack_00000008 <= iVar3) break;
      iVar3 = iVar4 + iVar1;
      iVar1 = *(int *)(param_1 + 0x14);
      iVar4 = iVar3;
    } while (0 < iVar1);
  }
  UpdateCounter();
  return iVar3;
}



/* ----------------------------------------
 * CINSWeaponMagazines::RemoveAll
 * Address: 00687800  Size: 19 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::RemoveAll() */

void __thiscall CINSWeaponMagazines::RemoveAll(CINSWeaponMagazines *this)

{
  int in_stack_00000004;
  
  *(undefined4 *)(in_stack_00000004 + 0x14) = 0;
  UpdateCounter();
  return;
}



/* ----------------------------------------
 * CINSWeaponMagazines::RoundCount
 * Address: 006875b0  Size: 37 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::RoundCount() */

int __thiscall CINSWeaponMagazines::RoundCount(CINSWeaponMagazines *this)

{
  int iVar1;
  int iVar2;
  int in_stack_00000004;
  
  iVar1 = 0;
  if (0 < *(int *)(in_stack_00000004 + 0x14)) {
    iVar2 = 0;
    do {
      iVar1 = iVar1 + *(int *)(*(int *)(in_stack_00000004 + 8) + iVar2 * 4);
      iVar2 = iVar2 + 1;
    } while (iVar2 != *(int *)(in_stack_00000004 + 0x14));
  }
  return iVar1;
}



/* ----------------------------------------
 * CINSWeaponMagazines::StoreMagazine
 * Address: 00687a00  Size: 56 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::StoreMagazine(int) */

void __thiscall CINSWeaponMagazines::StoreMagazine(CINSWeaponMagazines *this,int param_1)

{
  CUtlVector<int,CUtlMemory<int,int>> *in_stack_00000008;
  
  if (-1 < (int)in_stack_00000008) {
    CUtlVector<int,CUtlMemory<int,int>>::InsertBefore
              (in_stack_00000008,param_1 + 8,*(int **)(param_1 + 0x14));
    UpdateCounter();
  }
  return;
}



/* ----------------------------------------
 * CINSWeaponMagazines::SwitchToBest
 * Address: 00687970  Size: 133 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::SwitchToBest() */

undefined4 __thiscall CINSWeaponMagazines::SwitchToBest(CINSWeaponMagazines *this)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_stack_00000004;
  
  iVar1 = *(int *)(in_stack_00000004 + 0x14);
  if (iVar1 < 1) {
    return 0;
  }
  if (iVar1 == 1) {
    iVar3 = 0;
    iVar5 = *(int *)(in_stack_00000004 + 8);
  }
  else {
    iVar4 = 1;
    iVar3 = 0;
    iVar5 = *(int *)(in_stack_00000004 + 8);
    do {
      if (*(int *)(iVar5 + iVar3 * 4) < *(int *)(iVar5 + iVar4 * 4)) {
        iVar3 = iVar4;
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 != iVar1);
    if (iVar4 <= iVar3) {
      return 0;
    }
  }
  uVar2 = *(undefined4 *)(iVar5 + iVar3 * 4);
  CUtlVector<int,CUtlMemory<int,int>>::Remove(in_stack_00000004 + 8);
  UpdateCounter();
  return uVar2;
}



/* ----------------------------------------
 * CINSWeaponMagazines::UpdateCounter
 * Address: 006875e0  Size: 113 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::UpdateCounter() */

void CINSWeaponMagazines::UpdateCounter(void)

{
  uint uVar1;
  int iVar2;
  CBaseCombatCharacter *extraout_ECX;
  CBaseCombatCharacter *this;
  int iVar3;
  int unaff_EBX;
  
  iVar2 = __i686_get_pc_thunk_bx();
  uVar1 = *(uint *)(iVar2 + 4);
  iVar3 = 0;
  this = extraout_ECX;
  if ((uVar1 != 0xffffffff) &&
     (this = (CBaseCombatCharacter *)(**(int **)(unaff_EBX + 0x51f1e7) + (uVar1 & 0xffff) * 0x18),
     *(uint *)(this + 8) == uVar1 >> 0x10)) {
    iVar3 = *(int *)(this + 4);
  }
  CBaseCombatCharacter::SetAmmoCount(this,iVar3,*(int *)(iVar2 + 0x14));
  return;
}



/* ----------------------------------------
 * CINSWeaponMagazines::UpdateMagazine
 * Address: 00687870  Size: 71 bytes
 * ---------------------------------------- */

/* CINSWeaponMagazines::UpdateMagazine(int, int) */

void __thiscall
CINSWeaponMagazines::UpdateMagazine(CINSWeaponMagazines *this,int param_1,int param_2)

{
  int in_stack_0000000c;
  
  if ((-1 < param_2) && (param_2 < *(int *)(param_1 + 0x14))) {
    if (in_stack_0000000c < 1) {
      CUtlVector<int,CUtlMemory<int,int>>::Remove(param_1 + 8);
    }
    else {
      *(int *)(*(int *)(param_1 + 8) + param_2 * 4) = in_stack_0000000c;
    }
    UpdateCounter();
    return;
  }
  return;
}



