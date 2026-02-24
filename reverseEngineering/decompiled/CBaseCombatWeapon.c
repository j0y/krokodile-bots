/*
 * CBaseCombatWeapon -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 17
 */

/* ----------------------------------------
 * CBaseCombatWeapon::AbortReload
 * Address: 001d1180  Size: 50 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::AbortReload() */

void __thiscall CBaseCombatWeapon::AbortReload(CBaseCombatWeapon *this)

{
  void *in_stack_00000004;
  
  if (*(char *)((int)in_stack_00000004 + 0x505) != '\0') {
    CBaseEntity::NetworkStateChanged((CBaseEntity *)this,in_stack_00000004);
    *(undefined1 *)((int)in_stack_00000004 + 0x505) = 0;
  }
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::CanReload
 * Address: 001d7ce0  Size: 10 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::CanReload() */

undefined4 CBaseCombatWeapon::CanReload(void)

{
  return 1;
}



/* ----------------------------------------
 * CBaseCombatWeapon::CheckReload
 * Address: 001d3f30  Size: 580 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::CheckReload() */

void __thiscall CBaseCombatWeapon::CheckReload(CBaseCombatWeapon *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  CBaseCombatWeapon *this_00;
  CBaseEntity *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseCombatCharacter *this_02;
  CBaseEntity *this_03;
  CBaseCombatCharacter *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *pCVar5;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (*(char *)((int)in_stack_00000004 + 0x509) == '\0') {
    if (*(char *)((int)in_stack_00000004 + 0x505) == '\0') {
      return;
    }
    piVar2 = *(int **)(&DAT_009d295c + unaff_EBX);
    if (*(float *)(*piVar2 + 0xc) < (float)in_stack_00000004[0x12d]) {
      return;
    }
    (**(code **)(*in_stack_00000004 + 0x46c))();
    iVar3 = *(int *)(*piVar2 + 0xc);
    pCVar5 = this_01;
    if (in_stack_00000004[0x12d] != iVar3) {
      CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
      in_stack_00000004[0x12d] = iVar3;
      iVar3 = *(int *)(*piVar2 + 0xc);
      pCVar5 = extraout_ECX;
    }
    if (in_stack_00000004[0x12e] != iVar3) {
      CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
      in_stack_00000004[0x12e] = iVar3;
      pCVar5 = extraout_ECX_00;
    }
    if (*(char *)((int)in_stack_00000004 + 0x505) == '\0') {
      return;
    }
  }
  else {
    piVar2 = (int *)GetOwner(this_00);
    if (piVar2 == (int *)0x0) {
      return;
    }
    cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2);
    if (cVar1 == '\0') {
      return;
    }
    if (*(char *)((int)in_stack_00000004 + 0x505) == '\0') {
      return;
    }
    if (*(float *)(**(int **)(&DAT_009d295c + unaff_EBX) + 0xc) < (float)in_stack_00000004[0x12d]) {
      return;
    }
    if (((piVar2[0x3c9] & 0x60001U) == 0) ||
       (pCVar5 = (CBaseEntity *)this_02, in_stack_00000004[0x134] < 1)) {
      iVar3 = CBaseCombatCharacter::GetAmmoCount(this_02,(int)piVar2);
      if (iVar3 < 1) {
        (**(code **)(*in_stack_00000004 + 0x46c))();
        return;
      }
      iVar3 = in_stack_00000004[0x134];
      iVar4 = (**(code **)(*in_stack_00000004 + 0x510))();
      if (iVar3 < iVar4) {
        iVar3 = in_stack_00000004[0x134];
        CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
        in_stack_00000004[0x134] = iVar3 + 1;
        CBaseCombatCharacter::RemoveAmmo(this_04,(int)piVar2,1);
        (**(code **)(*in_stack_00000004 + 0x474))();
        return;
      }
      (**(code **)(*in_stack_00000004 + 0x46c))();
      iVar3 = *(int *)(**(int **)(&DAT_009d295c + unaff_EBX) + 0xc);
      pCVar5 = this_05;
      if (in_stack_00000004[0x12d] != iVar3) {
        CBaseEntity::NetworkStateChanged(this_05,in_stack_00000004);
        piVar2 = *(int **)(&DAT_009d295c + unaff_EBX);
        in_stack_00000004[0x12d] = iVar3;
        iVar3 = *(int *)(*piVar2 + 0xc);
        pCVar5 = extraout_ECX_01;
      }
      if (in_stack_00000004[0x12e] == iVar3) {
        return;
      }
      CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
      in_stack_00000004[0x12e] = iVar3;
      return;
    }
  }
  CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
  *(undefined1 *)((int)in_stack_00000004 + 0x505) = 0;
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::DefaultReload
 * Address: 001d5e10  Size: 728 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::DefaultReload(int, int, int) */

undefined4 __thiscall
CBaseCombatWeapon::DefaultReload(CBaseCombatWeapon *this,int param_1,int param_2,int param_3)

{
  int *piVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  CBaseCombatWeapon *this_00;
  CBaseCombatCharacter *this_01;
  CBaseCombatCharacter *this_02;
  CBaseCombatCharacter *this_03;
  CBaseAnimating *extraout_ECX;
  CBaseAnimating *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *this_06;
  CBaseCombatCharacter *this_07;
  CBaseCombatCharacter *this_08;
  CBaseAnimating *this_09;
  CBaseAnimating *extraout_ECX_03;
  int unaff_EBX;
  float fVar7;
  bool bVar8;
  float10 fVar9;
  float fVar10;
  undefined4 in_stack_00000010;
  undefined4 uVar11;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)GetOwner(this_00);
  if (piVar3 != (int *)0x0) {
    uVar11 = *(undefined4 *)(param_1 + 0x4c8);
    iVar4 = CBaseCombatCharacter::GetAmmoCount(this_01,(int)piVar3);
    if (iVar4 < 1) {
      return 0;
    }
    cVar2 = (**(code **)(*(int *)param_1 + 0x548))(param_1,uVar11);
    bVar8 = false;
    if (cVar2 != '\0') {
      uVar11 = *(undefined4 *)(param_1 + 0x4c8);
      iVar4 = *(int *)(param_1 + 0x4d0);
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_02,(int)piVar3);
      if (param_2 - iVar4 < iVar6) {
        iVar4 = param_2 - *(int *)(param_1 + 0x4d0);
      }
      else {
        uVar11 = *(undefined4 *)(param_1 + 0x4c8);
        iVar4 = CBaseCombatCharacter::GetAmmoCount(this_08,(int)piVar3);
      }
      bVar8 = iVar4 != 0;
    }
    cVar2 = (**(code **)(*(int *)param_1 + 0x54c))(param_1,uVar11);
    if (cVar2 != '\0') {
      iVar4 = *(int *)(param_1 + 0x4d4);
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_03,(int)piVar3);
      if (param_3 - iVar4 < iVar6) {
        iVar4 = param_3 - *(int *)(param_1 + 0x4d4);
      }
      else {
        iVar4 = CBaseCombatCharacter::GetAmmoCount(this_07,(int)piVar3);
      }
      if (iVar4 != 0) goto LAB_001d5e8f;
    }
    if (bVar8) {
LAB_001d5e8f:
      (**(code **)(*(int *)param_1 + 0x3f8))(param_1,in_stack_00000010);
      cVar2 = (**(code **)(*piVar3 + 0x158))(piVar3);
      if (cVar2 != '\0') {
        (**(code **)(*piVar3 + 0x650))(piVar3,7);
      }
      piVar1 = (int *)**(undefined4 **)(&DAT_009d132e + unaff_EBX);
      (**(code **)(*piVar1 + 0x80))(piVar1);
      fVar10 = *(float *)(**(int **)(&DAT_009d0a82 + unaff_EBX) + 0xc);
      if (*(char *)(param_1 + 0x32d) == '\0') {
        this_04 = *(CBaseAnimating **)(param_1 + 0x498);
        if ((this_04 == (CBaseAnimating *)0x0) &&
           (iVar4 = CBaseEntity::GetModel(), this_04 = this_09, iVar4 != 0)) {
          CBaseAnimating::LockStudioHdr(this_09);
          this_04 = extraout_ECX_03;
        }
        piVar5 = *(int **)(param_1 + 0x498);
        if ((piVar5 != (int *)0x0) && (*piVar5 == 0)) {
          piVar5 = (int *)0x0;
        }
      }
      else {
        piVar5 = (int *)0x0;
        this_04 = extraout_ECX;
      }
      fVar9 = (float10)CBaseAnimating::SequenceDuration(this_04,(CStudioHdr *)param_1,(int)piVar5);
      fVar10 = (float)fVar9 + fVar10;
      this_06 = this_05;
      if ((float)piVar3[0x1a9] != fVar10) {
        piVar5 = piVar3 + 0x1a9;
        CBaseEntity::NetworkStateChanged(this_05,piVar3);
        piVar3[0x1a9] = (int)fVar10;
        this_06 = extraout_ECX_00;
      }
      fVar7 = *(float *)(param_1 + 0x4b8);
      if (fVar10 != *(float *)(param_1 + 0x4b8)) {
        piVar5 = (int *)(param_1 + 0x4b8);
        CBaseEntity::NetworkStateChanged(this_06,(void *)param_1);
        *(float *)(param_1 + 0x4b8) = fVar10;
        this_06 = extraout_ECX_01;
        fVar7 = fVar10;
      }
      if (*(float *)(param_1 + 0x4b4) != fVar7) {
        piVar5 = (int *)(param_1 + 0x4b4);
        CBaseEntity::NetworkStateChanged(this_06,(void *)param_1);
        *(float *)(param_1 + 0x4b4) = fVar7;
        this_06 = extraout_ECX_02;
      }
      if (*(char *)(param_1 + 0x505) != '\x01') {
        piVar5 = (int *)(param_1 + 0x505);
        CBaseEntity::NetworkStateChanged(this_06,(void *)param_1);
        *(undefined1 *)(param_1 + 0x505) = 1;
      }
      (**(code **)(*piVar1 + 0x84))(piVar1,piVar5);
      return 1;
    }
  }
  return 0;
}



/* ----------------------------------------
 * CBaseCombatWeapon::DisplayReloadHudHint
 * Address: 001d29a0  Size: 105 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::DisplayReloadHudHint() */

void __thiscall CBaseCombatWeapon::DisplayReloadHudHint(CBaseCombatWeapon *this)

{
  int *piVar1;
  CBaseEntity *pCVar2;
  CBaseCombatWeapon *this_00;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  pCVar2 = (CBaseEntity *)GetOwner(this_00);
  UTIL_HudHintText(pCVar2,&UNK_00751848 + unaff_EBX);
  piVar1 = *(int **)(&DAT_009d3ef2 + unaff_EBX);
  *(undefined1 *)(in_stack_00000004 + 0x539) = 1;
  *(int *)(in_stack_00000004 + 0x534) = *(int *)(in_stack_00000004 + 0x534) + 1;
  *(float *)(in_stack_00000004 + 0x540) =
       *(float *)(unaff_EBX + 0x751dba) + *(float *)(*piVar1 + 0xc);
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::FinishReload
 * Address: 001d3d20  Size: 488 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::FinishReload() */

void __thiscall CBaseCombatWeapon::FinishReload(CBaseCombatWeapon *this)

{
  CBaseEntity *pCVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  CBaseCombatWeapon *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar8;
  CBaseCombatCharacter *this_01;
  CBaseCombatCharacter *this_02;
  CBaseEntity *extraout_ECX_00;
  CBaseCombatCharacter *this_03;
  CBaseCombatCharacter *this_04;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar4 = GetOwner(this_00);
  if (iVar4 != 0) {
    cVar3 = (**(code **)(*in_stack_00000004 + 0x548))(in_stack_00000004);
    if (cVar3 != '\0') {
      iVar5 = (**(code **)(*in_stack_00000004 + 0x510))(in_stack_00000004);
      iVar7 = in_stack_00000004[0x132];
      iVar2 = in_stack_00000004[0x134];
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_03,iVar4);
      if (iVar5 - iVar2 < iVar6) {
        iVar7 = (**(code **)(*in_stack_00000004 + 0x510))(in_stack_00000004,iVar7);
        pCVar8 = (CBaseEntity *)in_stack_00000004[0x134];
        iVar7 = iVar7 - (int)pCVar8;
      }
      else {
        iVar7 = CBaseCombatCharacter::GetAmmoCount(this_04,iVar4);
        pCVar8 = (CBaseEntity *)in_stack_00000004[0x134];
      }
      pCVar1 = pCVar8 + iVar7;
      if (pCVar1 != pCVar8) {
        CBaseEntity::NetworkStateChanged(pCVar1,in_stack_00000004);
        in_stack_00000004[0x134] = (int)pCVar1;
      }
      CBaseCombatCharacter::RemoveAmmo((CBaseCombatCharacter *)pCVar1,iVar4,iVar7);
    }
    cVar3 = (**(code **)(*in_stack_00000004 + 0x54c))(in_stack_00000004);
    pCVar8 = extraout_ECX;
    if (cVar3 != '\0') {
      iVar5 = (**(code **)(*in_stack_00000004 + 0x514))(in_stack_00000004);
      iVar7 = in_stack_00000004[0x133];
      iVar2 = in_stack_00000004[0x135];
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_01,iVar4);
      if (iVar5 - iVar2 < iVar6) {
        iVar7 = (**(code **)(*in_stack_00000004 + 0x514))(in_stack_00000004,iVar7);
        pCVar8 = (CBaseEntity *)in_stack_00000004[0x135];
        iVar7 = iVar7 - (int)pCVar8;
      }
      else {
        iVar7 = CBaseCombatCharacter::GetAmmoCount(this_02,iVar4);
        pCVar8 = (CBaseEntity *)in_stack_00000004[0x135];
      }
      pCVar1 = pCVar8 + iVar7;
      if (pCVar8 != pCVar1) {
        CBaseEntity::NetworkStateChanged(pCVar1,in_stack_00000004);
        in_stack_00000004[0x135] = (int)pCVar1;
      }
      CBaseCombatCharacter::RemoveAmmo((CBaseCombatCharacter *)pCVar1,iVar4,iVar7);
      pCVar8 = extraout_ECX_00;
    }
    if ((*(char *)((int)in_stack_00000004 + 0x509) != '\0') &&
       (*(char *)((int)in_stack_00000004 + 0x505) != '\0')) {
      CBaseEntity::NetworkStateChanged(pCVar8,in_stack_00000004);
      *(undefined1 *)((int)in_stack_00000004 + 0x505) = 0;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::GetMaxClip1
 * Address: 001cfac0  Size: 48 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::GetMaxClip1() const */

undefined4 __thiscall CBaseCombatWeapon::GetMaxClip1(CBaseCombatWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = GetFileWeaponInfoFromHandle(*(ushort *)(in_stack_00000004 + 0x528));
  return *(undefined4 *)(iVar1 + 0x160);
}



/* ----------------------------------------
 * CBaseCombatWeapon::GetMaxClip2
 * Address: 001cfa90  Size: 48 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::GetMaxClip2() const */

undefined4 __thiscall CBaseCombatWeapon::GetMaxClip2(CBaseCombatWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = GetFileWeaponInfoFromHandle(*(ushort *)(in_stack_00000004 + 0x528));
  return *(undefined4 *)(iVar1 + 0x164);
}



/* ----------------------------------------
 * CBaseCombatWeapon::HasAmmo
 * Address: 001d2c40  Size: 209 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::HasAmmo() const */

bool __thiscall CBaseCombatWeapon::HasAmmo(CBaseCombatWeapon *this)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  CBaseCombatWeapon *this_00;
  CBaseCombatCharacter *this_01;
  CBaseCombatCharacter *this_02;
  bool bVar5;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000004[0x132] != -1) || (bVar5 = true, in_stack_00000004[0x133] != -1)) {
    bVar5 = true;
    uVar2 = (**(code **)(*in_stack_00000004 + 0x52c))();
    if ((uVar2 & 1) == 0) {
      bVar5 = false;
      piVar3 = (int *)GetOwner(this_00);
      if ((((piVar3 != (int *)0x0) &&
           (cVar1 = (**(code **)(*piVar3 + 0x158))(piVar3), cVar1 != '\0')) &&
          (bVar5 = true, in_stack_00000004[0x134] < 1)) &&
         ((iVar4 = CBaseCombatCharacter::GetAmmoCount(this_01,(int)piVar3), iVar4 == 0 &&
          (in_stack_00000004[0x135] < 1)))) {
        iVar4 = CBaseCombatCharacter::GetAmmoCount(this_02,(int)piVar3);
        bVar5 = iVar4 != 0;
      }
    }
  }
  return bVar5;
}



/* ----------------------------------------
 * CBaseCombatWeapon::HasPrimaryAmmo
 * Address: 001d27a0  Size: 132 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::HasPrimaryAmmo() const */

bool __thiscall CBaseCombatWeapon::HasPrimaryAmmo(CBaseCombatWeapon *this)

{
  char cVar1;
  int iVar2;
  CBaseCombatWeapon *this_00;
  CBaseCombatCharacter *this_01;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_00000004 + 0x548))();
  if ((cVar1 != '\0') && (0 < in_stack_00000004[0x134])) {
    return true;
  }
  iVar2 = GetOwner(this_00);
  if (iVar2 != 0) {
    iVar2 = CBaseCombatCharacter::GetAmmoCount(this_01,iVar2);
    return 0 < iVar2;
  }
  return 0 < in_stack_00000004[0x13e];
}



/* ----------------------------------------
 * CBaseCombatWeapon::HasSecondaryAmmo
 * Address: 001d2720  Size: 115 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::HasSecondaryAmmo() const */

bool __thiscall CBaseCombatWeapon::HasSecondaryAmmo(CBaseCombatWeapon *this)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  CBaseCombatWeapon *this_00;
  CBaseCombatCharacter *this_01;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_00000004 + 0x54c))();
  if ((cVar1 == '\0') || (bVar2 = true, in_stack_00000004[0x135] < 1)) {
    iVar3 = GetOwner(this_00);
    bVar2 = false;
    if (iVar3 != 0) {
      iVar3 = CBaseCombatCharacter::GetAmmoCount(this_01,iVar3);
      return 0 < iVar3;
    }
  }
  return bVar2;
}



/* ----------------------------------------
 * CBaseCombatWeapon::Reload
 * Address: 001d6130  Size: 73 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::Reload() */

void __thiscall CBaseCombatWeapon::Reload(CBaseCombatWeapon *this)

{
  int iVar1;
  int iVar2;
  CBaseCombatWeapon *this_00;
  int *in_stack_00000004;
  
  iVar1 = (**(code **)(*in_stack_00000004 + 0x514))();
  iVar2 = (**(code **)(*in_stack_00000004 + 0x510))();
  DefaultReload(this_00,(int)in_stack_00000004,iVar2,iVar1);
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::ReloadOrSwitchWeapons
 * Address: 001d3350  Size: 399 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::ReloadOrSwitchWeapons() */

undefined4 __thiscall CBaseCombatWeapon::ReloadOrSwitchWeapons(CBaseCombatWeapon *this)

{
  char cVar1;
  int *piVar2;
  uint uVar3;
  CBaseCombatWeapon *this_00;
  CBaseEntity *this_01;
  undefined4 uVar4;
  int unaff_EBX;
  float fVar5;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar2 = (int *)GetOwner(this_00);
  if ((piVar2 == (int *)0x0) || (cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2), cVar1 == '\0')) {
    piVar2 = (int *)0x0;
  }
  *(undefined1 *)((int)in_stack_00000004 + 0x506) = 0;
  cVar1 = (**(code **)(*in_stack_00000004 + 0x410))(in_stack_00000004);
  if (((cVar1 != '\0') ||
      (fVar5 = *(float *)(**(int **)(&DAT_009d3542 + unaff_EBX) + 0xc),
      fVar5 < (float)in_stack_00000004[0x12d] || fVar5 == (float)in_stack_00000004[0x12d])) ||
     (fVar5 < (float)in_stack_00000004[0x12e] || fVar5 == (float)in_stack_00000004[0x12e])) {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x548))(in_stack_00000004);
    uVar4 = 0;
    if ((cVar1 != '\0') && (in_stack_00000004[0x134] == 0)) {
      uVar3 = (**(code **)(*in_stack_00000004 + 0x52c))(in_stack_00000004);
      uVar4 = 0;
      if (((uVar3 & 2) == 0) &&
         ((fVar5 = *(float *)(**(int **)(&DAT_009d3542 + unaff_EBX) + 0xc),
          (float)in_stack_00000004[0x12d] <= fVar5 && fVar5 != (float)in_stack_00000004[0x12d] &&
          ((float)in_stack_00000004[0x12e] <= fVar5 && fVar5 != (float)in_stack_00000004[0x12e]))))
      {
        uVar4 = (**(code **)(*in_stack_00000004 + 0x474))(in_stack_00000004);
      }
    }
  }
  else {
    uVar3 = (**(code **)(*in_stack_00000004 + 0x52c))(in_stack_00000004);
    uVar4 = 0;
    if ((uVar3 & 4) == 0) {
      cVar1 = (**(code **)(*(int *)**(undefined4 **)(&DAT_009d359a + unaff_EBX) + 0x6c))
                        ((int *)**(undefined4 **)(&DAT_009d359a + unaff_EBX),piVar2,
                         in_stack_00000004);
      uVar4 = 0;
      if (cVar1 != '\0') {
        uVar4 = 1;
        fVar5 = (float)((double)*(float *)(**(int **)(&DAT_009d3542 + unaff_EBX) + 0xc) +
                       *(double *)(unaff_EBX + 0x75141a));
        if ((float)in_stack_00000004[0x12d] != fVar5) {
          CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
          in_stack_00000004[0x12d] = (int)fVar5;
          return 1;
        }
      }
    }
  }
  return uVar4;
}



/* ----------------------------------------
 * CBaseCombatWeapon::RescindReloadHudHint
 * Address: 001d2950  Size: 76 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::RescindReloadHudHint() */

void __thiscall CBaseCombatWeapon::RescindReloadHudHint(CBaseCombatWeapon *this)

{
  CBaseEntity *pCVar1;
  CBaseCombatWeapon *this_00;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  pCVar1 = (CBaseEntity *)GetOwner(this_00);
  UTIL_HudHintText(pCVar1,(char *)(unaff_EBX + 0x78711d));
  *(undefined1 *)(in_stack_00000004 + 0x539) = 0;
  *(int *)(in_stack_00000004 + 0x534) = *(int *)(in_stack_00000004 + 0x534) + -1;
  return;
}



/* ----------------------------------------
 * CBaseCombatWeapon::ShouldDisplayReloadHUDHint
 * Address: 001d2a10  Size: 170 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::ShouldDisplayReloadHUDHint() */

bool __thiscall CBaseCombatWeapon::ShouldDisplayReloadHUDHint(CBaseCombatWeapon *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  bool bVar5;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  bVar5 = false;
  if (in_stack_00000004[0x14d] < 1) {
    piVar2 = (int *)GetOwner((CBaseCombatWeapon *)in_stack_00000004[0x14d]);
    if (piVar2 != (int *)0x0) {
      cVar1 = (**(code **)(*piVar2 + 0x158))(piVar2);
      if (cVar1 != '\0') {
        cVar1 = (**(code **)(*in_stack_00000004 + 0x548))();
        if (cVar1 != '\0') {
          iVar4 = in_stack_00000004[0x134];
          iVar3 = (**(code **)(*in_stack_00000004 + 0x510))();
          if (iVar4 < iVar3 / 2) {
            iVar4 = CBaseCombatCharacter::GetAmmoCount
                              ((CBaseCombatCharacter *)-(iVar3 >> 0x1f),(int)piVar2);
            bVar5 = 0 < iVar4;
          }
        }
      }
    }
  }
  return bVar5;
}



/* ----------------------------------------
 * CBaseCombatWeapon::UsesClipsForAmmo1
 * Address: 001cf2a0  Size: 28 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::UsesClipsForAmmo1() const */

bool __thiscall CBaseCombatWeapon::UsesClipsForAmmo1(CBaseCombatWeapon *this)

{
  int iVar1;
  int *in_stack_00000004;
  
  iVar1 = (**(code **)(*in_stack_00000004 + 0x510))();
  return iVar1 != -1;
}



/* ----------------------------------------
 * CBaseCombatWeapon::UsesClipsForAmmo2
 * Address: 001cf2c0  Size: 28 bytes
 * ---------------------------------------- */

/* CBaseCombatWeapon::UsesClipsForAmmo2() const */

bool __thiscall CBaseCombatWeapon::UsesClipsForAmmo2(CBaseCombatWeapon *this)

{
  int iVar1;
  int *in_stack_00000004;
  
  iVar1 = (**(code **)(*in_stack_00000004 + 0x514))();
  return iVar1 != -1;
}



