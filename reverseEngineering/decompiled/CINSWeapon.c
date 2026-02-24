/*
 * CINSWeapon -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 41
 */

/* ----------------------------------------
 * CINSWeapon::AbortReload
 * Address: 00310860  Size: 387 bytes
 * ---------------------------------------- */

/* CINSWeapon::AbortReload() */

void __thiscall CINSWeapon::AbortReload(CINSWeapon *this)

{
  int iVar1;
  char cVar2;
  void *pvVar3;
  int iVar4;
  CINSWeapon *this_00;
  CBaseEntity *this_01;
  CBaseEntity *extraout_ECX;
  CBaseEntity *pCVar5;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  pvVar3 = (void *)GetINSPlayerOwner();
  if (*(char *)((int)in_stack_00000004 + 0x505) == '\0') {
    return;
  }
  if (pvVar3 != (void *)0x0) {
    cVar2 = IsSingleReload(this_00);
    if (cVar2 == '\0') {
      pCVar5 = *(CBaseEntity **)(unaff_EBX + 0x896032);
      iVar1 = *(int *)(*(int *)pCVar5 + 0xc);
      iVar4 = in_stack_00000004[0x12e];
      if (in_stack_00000004[0x12e] != iVar1) {
        CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
        in_stack_00000004[0x12e] = iVar1;
        iVar4 = iVar1;
      }
      if (in_stack_00000004[0x12d] != iVar4) {
        CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
        in_stack_00000004[0x12d] = iVar4;
      }
      (**(code **)(*in_stack_00000004 + 0x408))
                (in_stack_00000004,*(undefined4 *)(*(int *)pCVar5 + 0xc));
      iVar1 = in_stack_00000004[0x12d];
      pCVar5 = this_01;
      if (*(int *)((int)pvVar3 + 0x6a4) != iVar1) {
        CBaseEntity::NetworkStateChanged(this_01,pvVar3);
        *(int *)((int)pvVar3 + 0x6a4) = iVar1;
        pCVar5 = extraout_ECX;
      }
      iVar1 = in_stack_00000004[0x1050];
    }
    else {
      (**(code **)(*in_stack_00000004 + 0x46c))(in_stack_00000004);
      iVar1 = in_stack_00000004[0x1050];
      pCVar5 = extraout_ECX_00;
    }
    if (iVar1 == 0) {
      cVar2 = *(char *)((int)in_stack_00000004 + 0x505);
    }
    else {
      CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
      cVar2 = *(char *)((int)in_stack_00000004 + 0x505);
      in_stack_00000004[0x1050] = 0;
      pCVar5 = extraout_ECX_01;
    }
    if (cVar2 != '\0') {
      CBaseEntity::NetworkStateChanged(pCVar5,in_stack_00000004);
      *(undefined1 *)((int)in_stack_00000004 + 0x505) = 0;
    }
    CINSPlayer::DoAnimationEvent();
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::CanReload
 * Address: 00304130  Size: 196 bytes
 * ---------------------------------------- */

/* CINSWeapon::CanReload() const */

uint __thiscall CINSWeapon::CanReload(CINSWeapon *this)

{
  char cVar1;
  CBaseCombatWeapon *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CINSPlayer *this_03;
  uint uVar2;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  uVar2 = 0;
  cVar1 = CBaseCombatWeapon::UsesPrimaryAmmo(this_00);
  if ((cVar1 != '\0') &&
     (cVar1 = (**(code **)(*in_stack_00000004 + 0x65c))(in_stack_00000004), cVar1 != '\0')) {
    GetINSPlayerOwner();
    cVar1 = (**(code **)(*in_stack_00000004 + 0x614))(in_stack_00000004);
    if ((cVar1 != '\0') || (cVar1 = CINSPlayer::IsSprinting(this_01), cVar1 == '\0')) {
      cVar1 = (**(code **)(*in_stack_00000004 + 0x618))(in_stack_00000004);
      if ((cVar1 == '\0') && (cVar1 = CINSPlayer::IsJumping(this_02), cVar1 != '\0')) {
        return 0;
      }
      uVar2 = 1;
      cVar1 = (**(code **)(*in_stack_00000004 + 0x61c))(in_stack_00000004);
      if (cVar1 == '\0') {
        uVar2 = CINSPlayer::IsFullyCrawling(this_03);
        uVar2 = uVar2 ^ 1;
      }
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSWeapon::CanReloadCrawl
 * Address: 00301330  Size: 27 bytes
 * ---------------------------------------- */

/* CINSWeapon::CanReloadCrawl() const */

undefined1 __thiscall CINSWeapon::CanReloadCrawl(CINSWeapon *this)

{
  undefined1 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    uVar1 = *(undefined1 *)(in_stack_00000004 + 0x160d);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeapon::CanReloadJump
 * Address: 00301310  Size: 27 bytes
 * ---------------------------------------- */

/* CINSWeapon::CanReloadJump() const */

undefined1 __thiscall CINSWeapon::CanReloadJump(CINSWeapon *this)

{
  undefined1 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    uVar1 = *(undefined1 *)(in_stack_00000004 + 0x160c);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeapon::CanReloadSprint
 * Address: 003012f0  Size: 27 bytes
 * ---------------------------------------- */

/* CINSWeapon::CanReloadSprint() const */

undefined1 __thiscall CINSWeapon::CanReloadSprint(CINSWeapon *this)

{
  undefined1 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    uVar1 = *(undefined1 *)(in_stack_00000004 + 0x160b);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeapon::ChamberRound
 * Address: 00301490  Size: 5 bytes
 * ---------------------------------------- */

/* CINSWeapon::ChamberRound() */

void CINSWeapon::ChamberRound(void)

{
  return;
}



/* ----------------------------------------
 * CINSWeapon::CheckCancelledReload
 * Address: 00310740  Size: 266 bytes
 * ---------------------------------------- */

/* CINSWeapon::CheckCancelledReload() */

void __thiscall CINSWeapon::CheckCancelledReload(CINSWeapon *this)

{
  float fVar1;
  byte bVar2;
  char cVar3;
  void *pvVar4;
  CINSWeapon *this_00;
  CBaseEntity *this_01;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if ((*(char *)((int)in_stack_00000004 + 0x505) != '\0') &&
     ((char)in_stack_00000004[0x1052] == '\0')) {
    pvVar4 = (void *)GetINSPlayerOwner();
    if (pvVar4 != (void *)0x0) {
      bVar2 = (**(code **)(*in_stack_00000004 + 0x658))();
      cVar3 = IsSingleReload(this_00);
      if (cVar3 == '\0') {
        if (((bVar2 ^ 1) != 0) &&
           (fVar1 = *(float *)(**(int **)(unaff_EBX + 0x89614c) + 0xc),
           (float)in_stack_00000004[0x1053] <= fVar1)) {
          if (*(float *)((int)pvVar4 + 0x6a4) != fVar1) {
            CBaseEntity::NetworkStateChanged(this_01,pvVar4);
            *(float *)((int)pvVar4 + 0x6a4) = fVar1;
          }
          (**(code **)(*in_stack_00000004 + 0x470))();
        }
      }
      else if ((((bVar2 ^ 1) != 0) || ((*(uint *)((int)pvVar4 + 0xf28) & 0x8060001) != 0)) &&
              ((char)in_stack_00000004[0x1052] != '\x01')) {
        CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
        *(undefined1 *)(in_stack_00000004 + 0x1052) = 1;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::CheckQueuedReload
 * Address: 003039b0  Size: 303 bytes
 * ---------------------------------------- */

/* CINSWeapon::CheckQueuedReload() */

void __thiscall CINSWeapon::CheckQueuedReload(CINSWeapon *this)

{
  float fVar1;
  int iVar2;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if ((*(char *)((int)in_stack_00000004 + 0x505) == '\0') &&
     (fVar1 = (float)in_stack_00000004[0x1051], 0.0 < fVar1)) {
    if (*(float *)(**(int **)(&DAT_008a2edc + unaff_EBX) + 0xc) <= fVar1) {
      iVar2 = GetINSPlayerOwner();
      if (iVar2 != 0) {
        if ((*(uint *)(iVar2 + 0xf24) & 0x20001) == 0) {
          fVar1 = (float)in_stack_00000004[0x1051];
          (**(code **)(*in_stack_00000004 + 0x474))();
          if ((0.0 < (float)in_stack_00000004[0x1051]) &&
             ((float)in_stack_00000004[0x1051] != fVar1)) {
            CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
            in_stack_00000004[0x1051] = (int)fVar1;
          }
        }
        else if (in_stack_00000004[0x1051] != 0) {
          CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
          in_stack_00000004[0x1051] = 0;
        }
      }
    }
    else if (fVar1 != 0.0) {
      CBaseEntity::NetworkStateChanged(this_00,in_stack_00000004);
      in_stack_00000004[0x1051] = 0;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::CheckReload
 * Address: 00310ba0  Size: 134 bytes
 * ---------------------------------------- */

/* CINSWeapon::CheckReload() */

void __thiscall CINSWeapon::CheckReload(CINSWeapon *this)

{
  float *pfVar1;
  char cVar2;
  int iVar3;
  CINSWeapon *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar3 = GetINSPlayerOwner();
  if (((iVar3 != 0) && (*(char *)((int)in_stack_00000004 + 0x505) != '\0')) &&
     (pfVar1 = (float *)(**(int **)(unaff_EBX + 0x895cf2) + 0xc),
     (float)in_stack_00000004[0x12d] < *pfVar1 || (float)in_stack_00000004[0x12d] == *pfVar1)) {
    cVar2 = IsSingleReload(this_00);
    if ((cVar2 == '\0') || ((char)in_stack_00000004[0x1052] != '\0')) {
      (**(code **)(*in_stack_00000004 + 0x46c))(in_stack_00000004);
      return;
    }
    (**(code **)(*in_stack_00000004 + 0x634))(in_stack_00000004);
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::DecrementAmmo
 * Address: 00303900  Size: 155 bytes
 * ---------------------------------------- */

/* CINSWeapon::DecrementAmmo() */

void __thiscall CINSWeapon::DecrementAmmo(CINSWeapon *this)

{
  char cVar1;
  int iVar2;
  CBaseCombatWeapon *this_00;
  CBaseEntity *this_01;
  CBaseCombatCharacter *this_02;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CBaseCombatWeapon::UsesPrimaryAmmo(this_00);
  if (cVar1 != '\0') {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x548))(in_stack_00000004);
    if (cVar1 != '\0') {
      iVar2 = in_stack_00000004[0x134];
      CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
      in_stack_00000004[0x134] = iVar2 + -1;
      return;
    }
    iVar2 = GetINSPlayerOwner();
    if (iVar2 != 0) {
      CBaseCombatCharacter::RemoveAmmo(this_02,iVar2,1);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::DefaultReload
 * Address: 002f9b80  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeapon::DefaultReload(int, int, int) */

undefined4 __cdecl CINSWeapon::DefaultReload(int param_1,int param_2,int param_3)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeapon::FinishReload
 * Address: 00310e20  Size: 1353 bytes
 * ---------------------------------------- */

/* CINSWeapon::FinishReload() */

void __thiscall CINSWeapon::FinishReload(CINSWeapon *this)

{
  float fVar1;
  float fVar2;
  code *pcVar3;
  CINSWeaponMagazines *this_00;
  char cVar4;
  bool bVar5;
  int iVar6;
  int *piVar7;
  CStudioHdr *pCVar8;
  int iVar9;
  CINSWeapon *this_01;
  CINSWeapon *this_02;
  CINSWeapon *this_03;
  CBaseAnimating *extraout_ECX;
  CBaseAnimating *this_04;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *pCVar10;
  CAmmoDef *this_05;
  CBaseEntity *this_06;
  CBaseCombatCharacter *this_07;
  CBaseCombatCharacter *this_08;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *extraout_ECX_03;
  CINSWeapon *this_09;
  CBaseEntity *this_10;
  CBaseEntity *extraout_ECX_04;
  CBaseEntity *extraout_ECX_05;
  CBaseEntity *extraout_ECX_06;
  CBaseEntity *extraout_ECX_07;
  CBaseEntity *extraout_ECX_08;
  CBaseEntity *extraout_ECX_09;
  CBaseEntity *this_11;
  CBaseEntity *extraout_ECX_10;
  CINSWeaponMagazines *this_12;
  CBaseEntity *extraout_ECX_11;
  CINSWeapon *extraout_ECX_12;
  CBaseAnimating *this_13;
  CBaseAnimating *extraout_ECX_13;
  int unaff_EBX;
  float10 fVar11;
  CStudioHdr *in_stack_00000004;
  CStudioHdr *pCVar12;
  undefined4 uVar13;
  float fVar14;
  undefined4 uVar15;
  
  __i686_get_pc_thunk_bx();
  iVar6 = GetINSPlayerOwner();
  if (iVar6 == 0) {
    return;
  }
  if (in_stack_00000004[0x505] != (CStudioHdr)0x0) {
    cVar4 = IsSingleReload(this_01);
    if (cVar4 == '\0') {
      pCVar12 = (CStudioHdr *)(**(code **)(*(int *)in_stack_00000004 + 0x558))(in_stack_00000004);
      iVar9 = GetAmmoDef();
      iVar9 = CAmmoDef::GetAmmoOfIndex(this_05,iVar9);
      if ((iVar9 == 0) || ((*(byte *)(iVar9 + 0x94) & 4) == 0)) {
        cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x644))(in_stack_00000004);
        pCVar10 = this_06;
        if ((cVar4 != '\0') && (*(int *)(in_stack_00000004 + 0x4d0) != 0)) {
          pCVar12 = in_stack_00000004 + 0x4d0;
          CBaseEntity::NetworkStateChanged(this_06,in_stack_00000004);
          *(undefined4 *)(in_stack_00000004 + 0x4d0) = 0;
          pCVar10 = (CBaseEntity *)extraout_ECX_12;
        }
        if ((*(int *)(in_stack_00000004 + 0x5a4) < 0) ||
           (in_stack_00000004[0x15ca] == (CStudioHdr)0x0)) {
          CBaseCombatWeapon::FinishReload((CBaseCombatWeapon *)pCVar10);
          bVar5 = false;
          pCVar10 = extraout_ECX_06;
        }
        else {
          pCVar8 = (CStudioHdr *)GetMagazineCapacity((CINSWeapon *)pCVar10);
          iVar9 = (**(code **)(*(int *)in_stack_00000004 + 0x560))(in_stack_00000004,pCVar12);
          bVar5 = false;
          pCVar10 = (CBaseEntity *)this_07;
          if (iVar9 <= (int)pCVar8) {
            iVar9 = CBaseCombatCharacter::GetAmmoCount(this_07,iVar6);
            if (iVar9 <= (int)pCVar8) {
              pCVar8 = (CStudioHdr *)CBaseCombatCharacter::GetAmmoCount(this_08,iVar6);
            }
            pCVar10 = (CBaseEntity *)(pCVar8 + (int)*(CBaseEntity **)(in_stack_00000004 + 0x4d0));
            if (*(CBaseEntity **)(in_stack_00000004 + 0x4d0) != pCVar10) {
              CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
              *(CBaseEntity **)(in_stack_00000004 + 0x4d0) = pCVar10;
            }
            CBaseCombatCharacter::RemoveAmmo((CBaseCombatCharacter *)pCVar10,iVar6,(int)pCVar8);
            bVar5 = false;
            pCVar10 = extraout_ECX_01;
            pCVar12 = pCVar8;
          }
        }
      }
      else {
        pCVar8 = (CStudioHdr *)
                 (**(code **)(*(int *)in_stack_00000004 + 0x558))(in_stack_00000004,pCVar12);
        iVar6 = CINSPlayer::GetMagazines(iVar6);
        bVar5 = false;
        pCVar10 = extraout_ECX_08;
        pCVar12 = pCVar8;
        if (iVar6 != 0) {
          this_00 = *(CINSWeaponMagazines **)(in_stack_00000004 + 0x5a4);
          pCVar12 = *(CStudioHdr **)(in_stack_00000004 + 0x4d0);
          if (((int)this_00 < 0) || (in_stack_00000004[0x15ca] == (CStudioHdr)0x0)) {
            iVar9 = CINSWeaponMagazines::SwitchToBest(this_00);
            pCVar10 = this_11;
            if (iVar9 != *(int *)(in_stack_00000004 + 0x4d0)) {
              pCVar8 = in_stack_00000004 + 0x4d0;
              CBaseEntity::NetworkStateChanged(this_11,in_stack_00000004);
              *(int *)(in_stack_00000004 + 0x4d0) = iVar9;
              pCVar10 = extraout_ECX_10;
            }
            if (((int)pCVar12 < 1) ||
               (cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x644))(in_stack_00000004,pCVar8),
               pCVar10 = (CBaseEntity *)this_12, cVar4 != '\0')) {
              pCVar12 = pCVar8;
              bVar5 = true;
            }
            else {
              CINSWeaponMagazines::StoreMagazine(this_12,iVar6);
              bVar5 = true;
              pCVar10 = extraout_ECX_11;
            }
          }
          else {
            iVar6 = CINSWeaponMagazines::SwitchToBest(this_00);
            pCVar10 = *(CBaseEntity **)(in_stack_00000004 + 0x4d0);
            bVar5 = true;
            pCVar12 = pCVar8;
            if (pCVar10 != pCVar10 + iVar6) {
              pCVar12 = in_stack_00000004 + 0x4d0;
              CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
              *(CBaseEntity **)(in_stack_00000004 + 0x4d0) = pCVar10 + iVar6;
              bVar5 = true;
              pCVar10 = extraout_ECX_09;
            }
          }
        }
      }
    }
    else {
      fVar11 = (float10)GetReloadSpeedModifier(this_02);
      fVar2 = (float)fVar11;
      bVar5 = (bool)(**(code **)(*(int *)in_stack_00000004 + 0x6f4))(in_stack_00000004);
      uVar15 = 0x3dcccccd /* 0.1f */;
      fVar14 = fVar2;
      SendWeaponAnimResetAttacks(this_03,(int)in_stack_00000004,bVar5,1.4013e-45,fVar2);
      uVar13 = *(undefined4 *)(in_stack_00000004 + 0x3d0);
      pcVar3 = *(code **)(*(int *)in_stack_00000004 + 0x408);
      fVar1 = *(float *)(**(int **)(unaff_EBX + 0x895a72) + 0xc);
      piVar7 = (int *)0x0;
      this_04 = extraout_ECX;
      if (in_stack_00000004[0x32d] == (CStudioHdr)0x0) {
        if ((*(int *)(in_stack_00000004 + 0x498) == 0) &&
           (iVar6 = CBaseEntity::GetModel(), this_04 = this_13, iVar6 != 0)) {
          CBaseAnimating::LockStudioHdr(this_13);
          this_04 = extraout_ECX_13;
        }
        piVar7 = *(int **)(in_stack_00000004 + 0x498);
        if ((piVar7 != (int *)0x0) && (this_04 = (CBaseAnimating *)0x0, *piVar7 == 0)) {
          piVar7 = (int *)0x0;
        }
      }
      fVar11 = (float10)CBaseAnimating::SequenceDuration(this_04,in_stack_00000004,(int)piVar7);
      (*pcVar3)(in_stack_00000004,(float)fVar11 / fVar2 + fVar1,uVar13,fVar14,uVar15);
      pCVar12 = (CStudioHdr *)0xe;
      CINSPlayer::DoAnimationEvent();
      bVar5 = false;
      pCVar10 = extraout_ECX_00;
    }
    if ((((*(int *)(in_stack_00000004 + 0x5a4) < 0) ||
         (in_stack_00000004[0x15ca] == (CStudioHdr)0x0)) ||
        (cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x658))(in_stack_00000004,pCVar12),
        pCVar10 = extraout_ECX_03, cVar4 == '\0')) ||
       (cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x414))(in_stack_00000004),
       pCVar10 = (CBaseEntity *)this_09, cVar4 == '\0')) {
      if (in_stack_00000004[0x505] != (CStudioHdr)0x0) {
        pCVar12 = in_stack_00000004 + 0x505;
        CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
        in_stack_00000004[0x505] = (CStudioHdr)0x0;
        pCVar10 = extraout_ECX_05;
      }
    }
    else {
      if (bVar5) {
        iVar6 = (**(code **)(*(int *)in_stack_00000004 + 0x510))(in_stack_00000004);
        iVar6 = (int)ROUND((float)iVar6 * *(float *)(unaff_EBX + 0x61392a));
      }
      else {
        iVar6 = GetMagazineCapacity(this_09);
      }
      iVar9 = (**(code **)(*(int *)in_stack_00000004 + 0x560))(in_stack_00000004);
      pCVar10 = this_10;
      if ((CStudioHdr)(iVar9 <= iVar6) != in_stack_00000004[0x505]) {
        pCVar12 = in_stack_00000004 + 0x505;
        CBaseEntity::NetworkStateChanged(this_10,in_stack_00000004);
        in_stack_00000004[0x505] = (CStudioHdr)(iVar9 <= iVar6);
        pCVar10 = extraout_ECX_04;
      }
    }
    if (in_stack_00000004[0x4148] != (CStudioHdr)0x0) {
      pCVar12 = in_stack_00000004 + 0x4148;
      CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
      in_stack_00000004[0x4148] = (CStudioHdr)0x0;
      pCVar10 = extraout_ECX_02;
    }
    if (in_stack_00000004[0x505] == (CStudioHdr)0x0) {
      if (*(int *)(in_stack_00000004 + 0x4140) != 0) {
        pCVar12 = in_stack_00000004 + 0x4140;
        CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
        *(undefined4 *)(in_stack_00000004 + 0x4140) = 0;
        pCVar10 = extraout_ECX_07;
      }
      if (*(int *)(in_stack_00000004 + 0x41b4) != -1) {
        pCVar12 = in_stack_00000004 + 0x41b4;
        CBaseEntity::NetworkStateChanged(pCVar10,in_stack_00000004);
        *(undefined4 *)(in_stack_00000004 + 0x41b4) = 0xffffffff;
      }
    }
    cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x744))(in_stack_00000004,pCVar12);
    if ((cVar4 != '\0') &&
       (cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x738))(in_stack_00000004), cVar4 == '\0'))
    {
      (**(code **)(*(int *)in_stack_00000004 + 0x73c))(in_stack_00000004);
    }
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::GetMagazineCapacity
 * Address: 003104a0  Size: 185 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetMagazineCapacity() const */

int __thiscall CINSWeapon::GetMagazineCapacity(CINSWeapon *this)

{
  int iVar1;
  int iVar2;
  CAmmoDef *this_00;
  int *in_stack_00000004;
  
  iVar1 = __i686_get_pc_thunk_bx();
  if (-1 < in_stack_00000004[0x169]) {
    iVar1 = GetUpgradeInSlot();
    if ((iVar1 == 0) || (iVar1 = *(int *)(iVar1 + 0x300), iVar1 < 1)) {
      iVar1 = GetUpgradeInSlot();
      if ((iVar1 == 0) || (iVar1 = *(int *)(iVar1 + 0x300), iVar1 < 1)) {
        (**(code **)(*in_stack_00000004 + 0x558))();
        iVar1 = GetAmmoDef();
        iVar2 = CAmmoDef::GetAmmoOfIndex(this_00,iVar1);
        if ((iVar2 == 0) || ((*(byte *)(iVar2 + 0x94) & 4) == 0)) {
          iVar1 = in_stack_00000004[0x57e];
        }
        else {
          iVar1 = in_stack_00000004[0x580];
          if (iVar1 < 1) {
            iVar1 = *(int *)(iVar2 + 0x88);
          }
        }
      }
    }
  }
  return iVar1;
}



/* ----------------------------------------
 * CINSWeapon::GetMaxClip1
 * Address: 003113a0  Size: 49 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetMaxClip1() const */

int __thiscall CINSWeapon::GetMaxClip1(CINSWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  if ((-1 < *(int *)(in_stack_00000004 + 0x5a4)) && (*(char *)(in_stack_00000004 + 0x15ca) != '\0'))
  {
    iVar1 = GetMagazineCapacity(this);
    return iVar1 * 2;
  }
  iVar1 = GetMagazineCapacity(this);
  return iVar1;
}



/* ----------------------------------------
 * CINSWeapon::GetPrimaryAmmoType
 * Address: 00310250  Size: 73 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetPrimaryAmmoType() const */

int __thiscall CINSWeapon::GetPrimaryAmmoType(CINSWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  iVar1 = GetUpgradeInSlot();
  if (((iVar1 == 0) || (iVar1 = *(int *)(iVar1 + 0x2fc), iVar1 < 1)) &&
     (iVar1 = -1, -1 < *(int *)(in_stack_00000004 + 0x5a4))) {
    return *(int *)(in_stack_00000004 + 0x15c0);
  }
  return iVar1;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadActivity
 * Address: 00310650  Size: 235 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadActivity() const */

int __thiscall CINSWeapon::GetReloadActivity(CINSWeapon *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int *in_stack_00000004;
  
  cVar1 = IsSingleReload(this);
  if (cVar1 != '\0') {
    (**(code **)(*in_stack_00000004 + 0x6ec))();
    cVar1 = HaveSequenceForActivity();
    if (cVar1 != '\0') {
      iVar3 = (**(code **)(*in_stack_00000004 + 0x6ec))();
      return iVar3;
    }
  }
  cVar1 = (**(code **)(*in_stack_00000004 + 0x740))();
  if (cVar1 != '\0') {
    (**(code **)(*in_stack_00000004 + 0x6e0))();
    cVar1 = HaveSequenceForActivity();
    if (cVar1 != '\0') {
      iVar3 = (**(code **)(*in_stack_00000004 + 0x6e0))();
      return iVar3;
    }
  }
  piVar2 = (int *)0x0;
  if (-1 < in_stack_00000004[0x169]) {
    piVar2 = in_stack_00000004 + 0x169;
  }
  if (in_stack_00000004[0x134] <= piVar2[0x430]) {
    (**(code **)(*in_stack_00000004 + 0x6e4))();
    cVar1 = HaveSequenceForActivity();
    if (cVar1 != '\0') {
      iVar3 = (**(code **)(*in_stack_00000004 + 0x6e4))();
      return iVar3;
    }
  }
  cVar1 = InBipod();
  return (-(uint)(cVar1 == '\0') & 0xffffffb7) + 0x109;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadCycleActivity
 * Address: 00305f00  Size: 31 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadCycleActivity() const */

int CINSWeapon::GetReloadCycleActivity(void)

{
  char cVar1;
  
  cVar1 = InBipod();
  return (-(uint)(cVar1 == '\0') & 0xfffffffe) + 0x11d;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadEmptyActivity
 * Address: 00305f40  Size: 31 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadEmptyActivity() const */

int CINSWeapon::GetReloadEmptyActivity(void)

{
  char cVar1;
  
  cVar1 = InBipod();
  return (-(uint)(cVar1 == '\0') & 0xfffffff4) + 0x10a;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadFinishActivity
 * Address: 00305e40  Size: 170 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadFinishActivity() const */

undefined4 __thiscall CINSWeapon::GetReloadFinishActivity(CINSWeapon *this)

{
  char cVar1;
  undefined4 uVar2;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x548))();
  if (cVar1 != '\0') {
    cVar1 = InBipod();
    if ((cVar1 != '\0') && (cVar1 = HaveSequenceForActivity(), cVar1 != '\0')) {
      return 0x120;
    }
    cVar1 = (**(code **)(*in_stack_00000004 + 0x744))();
    if (((cVar1 != '\0') && (cVar1 = (**(code **)(*in_stack_00000004 + 0x738))(), cVar1 == '\0')) &&
       (cVar1 = HaveSequenceForActivity(), cVar1 != '\0')) {
      return 0x11f;
    }
    cVar1 = HaveSequenceForActivity();
    if (cVar1 != '\0') {
      return 0x11e;
    }
  }
  uVar2 = (**(code **)(*in_stack_00000004 + 0x6c4))();
  return uVar2;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadNearEmptyActivity
 * Address: 00305f20  Size: 31 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadNearEmptyActivity() const */

int CINSWeapon::GetReloadNearEmptyActivity(void)

{
  char cVar1;
  
  cVar1 = InBipod();
  return (-(uint)(cVar1 == '\0') & 0xfffffff4) + 0x10b;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadSpeedModifier
 * Address: 0030f870  Size: 193 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadSpeedModifier() */

float10 __thiscall CINSWeapon::GetReloadSpeedModifier(CINSWeapon *this)

{
  int iVar1;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  int unaff_EBX;
  int iVar2;
  float10 fVar3;
  int in_stack_00000004;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  local_20 = *(float *)(unaff_EBX + 0x5a9299);
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    local_20 = *(float *)(in_stack_00000004 + 0x10d4);
    iVar2 = 0;
    do {
      iVar1 = GetUpgradeInSlot(in_stack_00000004,iVar2);
      if (iVar1 != 0) {
        local_20 = local_20 * *(float *)(iVar1 + 0x374);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 != 10);
    iVar2 = GetINSPlayerOwner();
    if (iVar2 != 0) {
      fVar3 = (float10)CINSPlayer::GetReloadSpeedBoost(this_00);
      if ((float)fVar3 != *(float *)(unaff_EBX + 0x5a9299)) {
        fVar3 = (float10)CINSPlayer::GetReloadSpeedBoost(this_01);
        return (float10)((float)fVar3 * local_20);
      }
    }
  }
  return (float10)local_20;
}



/* ----------------------------------------
 * CINSWeapon::GetReloadStartActivity
 * Address: 00305380  Size: 72 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadStartActivity() const */

int __thiscall CINSWeapon::GetReloadStartActivity(CINSWeapon *this)

{
  char cVar1;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x740))();
  if (cVar1 == '\0') {
    return 0x119;
  }
  cVar1 = HaveSequenceForActivity();
  return 0x11a - (uint)(cVar1 == '\0');
}



/* ----------------------------------------
 * CINSWeapon::GetReloadState
 * Address: 00304930  Size: 14 bytes
 * ---------------------------------------- */

/* CINSWeapon::GetReloadState() const */

undefined4 __thiscall CINSWeapon::GetReloadState(CINSWeapon *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x4140);
}



/* ----------------------------------------
 * CINSWeapon::GiveDefaultAmmo
 * Address: 00301980  Size: 161 bytes
 * ---------------------------------------- */

/* CINSWeapon::GiveDefaultAmmo() */

void __thiscall CINSWeapon::GiveDefaultAmmo(CINSWeapon *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  CBaseEntity *this_00;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x548))();
  if (cVar1 != '\0') {
    piVar2 = (int *)0x0;
    if (-1 < in_stack_00000004[0x169]) {
      piVar2 = in_stack_00000004 + 0x169;
    }
    if (*(char *)((int)piVar2 + 0x1025) != '\0') {
      if (in_stack_00000004[0x134] != 1) {
        CBaseEntity::NetworkStateChanged((CBaseEntity *)in_stack_00000004[0x169],in_stack_00000004);
        in_stack_00000004[0x134] = 1;
      }
      (**(code **)(*in_stack_00000004 + 0x73c))();
    }
    iVar3 = (**(code **)(*in_stack_00000004 + 0x510))();
    if (iVar3 != in_stack_00000004[0x134]) {
      CBaseEntity::NetworkStateChanged(this_00,in_stack_00000004);
      in_stack_00000004[0x134] = iVar3;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::HandleReloadNotifyEvent
 * Address: 003109f0  Size: 391 bytes
 * ---------------------------------------- */

/* CINSWeapon::HandleReloadNotifyEvent() */

void __thiscall CINSWeapon::HandleReloadNotifyEvent(CINSWeapon *this)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  CINSWeapon *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CINSWeapon *this_04;
  CBaseEntity *this_05;
  CINSWeapon *this_06;
  CBaseEntity *extraout_ECX;
  int *in_stack_00000004;
  
  iVar2 = GetINSPlayerOwner();
  if (iVar2 != 0) {
    cVar1 = IsSingleReload(this_00);
    if (cVar1 == '\0') {
      (**(code **)(*in_stack_00000004 + 0x46c))();
      return;
    }
    if (in_stack_00000004[0x1050] == 1) {
      cVar1 = (**(code **)(*in_stack_00000004 + 0x644))();
      if ((cVar1 != '\0') && (in_stack_00000004[0x134] != 0)) {
        CBaseEntity::NetworkStateChanged(this_02,in_stack_00000004);
        in_stack_00000004[0x134] = 0;
      }
      this_03 = (CBaseEntity *)in_stack_00000004[0x169];
      piVar3 = (int *)0x0;
      if (-1 < (int)this_03) {
        piVar3 = in_stack_00000004 + 0x169;
      }
      if (*(char *)((int)piVar3 + 0x1025) != '\0') {
        if (in_stack_00000004[0x134] < 1) {
          CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
          in_stack_00000004[0x134] = 1;
          (**(code **)(*in_stack_00000004 + 0x73c))();
          TakeAmmo(this_06,(int)in_stack_00000004);
          this_03 = extraout_ECX;
        }
        if (in_stack_00000004[0x1050] != 2) {
          CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
          in_stack_00000004[0x1050] = 2;
        }
      }
    }
    else if (in_stack_00000004[0x1050] == 3) {
      iVar2 = in_stack_00000004[0x134];
      CBaseEntity::NetworkStateChanged(this_01,in_stack_00000004);
      in_stack_00000004[0x134] = iVar2 + 1;
      TakeAmmo(this_04,(int)in_stack_00000004);
      if (in_stack_00000004[0x1050] != 4) {
        CBaseEntity::NetworkStateChanged(this_05,in_stack_00000004);
        in_stack_00000004[0x1050] = 4;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::HandleReloadOffscreenEvent
 * Address: 00304650  Size: 406 bytes
 * ---------------------------------------- */

/* CINSWeapon::HandleReloadOffscreenEvent() */

void __thiscall CINSWeapon::HandleReloadOffscreenEvent(CINSWeapon *this)

{
  ushort uVar1;
  ushort uVar2;
  uint *puVar3;
  ushort *puVar4;
  int *piVar5;
  ushort *puVar6;
  int iVar7;
  ushort *puVar8;
  int iVar9;
  CBaseEdict *this_00;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar7 = (**(code **)(*in_stack_00000004 + 0x510))();
  if (iVar7 != in_stack_00000004[0x106d]) {
    if ((char)in_stack_00000004[0x17] == '\0') {
      puVar3 = (uint *)in_stack_00000004[8];
      if ((puVar3 != (uint *)0x0) && ((*puVar3 & 0x100) == 0)) {
        *puVar3 = *puVar3 | 1;
        puVar8 = (ushort *)CBaseEdict::GetChangeAccessor(this_00);
        puVar4 = (ushort *)**(undefined4 **)(unaff_EBX + 0x8a2118);
        if (puVar8[1] == *puVar4) {
          uVar1 = *puVar8;
          uVar2 = puVar4[(uint)uVar1 * 0x14 + 0x14];
          if (uVar2 == 0) {
LAB_003047d6:
            puVar4[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x41b4;
            puVar4[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
          }
          else if (puVar4[(uint)uVar1 * 0x14 + 1] != 0x41b4) {
            iVar9 = 0;
            do {
              if (iVar9 == (uVar2 - 1 & 0xffff) * 2) {
                if (uVar2 == 0x13) goto LAB_00304740;
                goto LAB_003047d6;
              }
              iVar9 = iVar9 + 2;
            } while (*(short *)((int)puVar4 + iVar9 + (uint)uVar1 * 0x28 + 2) != 0x41b4);
          }
        }
        else if ((puVar4[0x7d1] == 100) || (puVar8[1] != 0)) {
LAB_00304740:
          puVar8[1] = 0;
          *puVar3 = *puVar3 | 0x100;
        }
        else {
          piVar5 = *(int **)(unaff_EBX + 0x8a2118);
          *puVar8 = puVar4[0x7d1];
          puVar6 = (ushort *)*piVar5;
          puVar4 = puVar6 + 0x7d1;
          *puVar4 = *puVar4 + 1;
          puVar8[1] = *puVar6;
          iVar9 = *piVar5 + (uint)*puVar8 * 0x28;
          *(undefined2 *)(iVar9 + 2) = 0x41b4;
          *(undefined2 *)(iVar9 + 0x28) = 1;
        }
      }
    }
    else {
      *(byte *)(in_stack_00000004 + 0x18) = *(byte *)(in_stack_00000004 + 0x18) | 1;
    }
    in_stack_00000004[0x106d] = iVar7;
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::HasChamberedRound
 * Address: 00301480  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeapon::HasChamberedRound() const */

undefined4 CINSWeapon::HasChamberedRound(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeapon::HasSecondaryAmmo
 * Address: 002f9b60  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeapon::HasSecondaryAmmo() const */

undefined4 CINSWeapon::HasSecondaryAmmo(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeapon::IsEmpty
 * Address: 00304310  Size: 218 bytes
 * ---------------------------------------- */

/* CINSWeapon::IsEmpty() const */

byte __thiscall CINSWeapon::IsEmpty(CINSWeapon *this)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  CBaseCombatWeapon *this_00;
  CAmmoDef *this_01;
  CBaseCombatCharacter *this_02;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  bVar2 = 0;
  cVar1 = CBaseCombatWeapon::UsesPrimaryAmmo(this_00);
  if (cVar1 != '\0') {
    iVar3 = GetINSPlayerOwner();
    cVar1 = (**(code **)(*in_stack_00000004 + 0x548))(in_stack_00000004);
    if (cVar1 == '\0') {
      bVar2 = 1;
      if (iVar3 != 0) {
        iVar4 = GetAmmoDef();
        cVar1 = CAmmoDef::IsValidAmmoIndex(this_01,iVar4);
        if (cVar1 != '\0') {
          iVar3 = CBaseCombatCharacter::GetAmmoCount(this_02,iVar3);
          bVar2 = iVar3 < 1;
        }
      }
    }
    else if (in_stack_00000004[0x134] < 1) {
      bVar2 = 1;
      cVar1 = (**(code **)(*in_stack_00000004 + 0x744))(in_stack_00000004);
      if (cVar1 != '\0') {
        bVar2 = (**(code **)(*in_stack_00000004 + 0x738))(in_stack_00000004);
        bVar2 = bVar2 ^ 1;
      }
    }
  }
  return bVar2;
}



/* ----------------------------------------
 * CINSWeapon::IsReloading
 * Address: 003013d0  Size: 15 bytes
 * ---------------------------------------- */

/* CINSWeapon::IsReloading() const */

undefined1 __thiscall CINSWeapon::IsReloading(CINSWeapon *this)

{
  int in_stack_00000004;
  
  return *(undefined1 *)(in_stack_00000004 + 0x505);
}



/* ----------------------------------------
 * CINSWeapon::IsSingleReload
 * Address: 00310560  Size: 219 bytes
 * ---------------------------------------- */

/* CINSWeapon::IsSingleReload() const */

undefined1 __thiscall CINSWeapon::IsSingleReload(CINSWeapon *this)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  CINSWeapon *this_00;
  CBaseCombatCharacter *this_01;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar2 = (**(code **)(*in_stack_00000004 + 0x760))();
  if (cVar2 != '\0') {
    return 0;
  }
  cVar2 = (**(code **)(*in_stack_00000004 + 0x760))();
  if (cVar2 != '\0') {
    iVar3 = GetINSPlayerOwner();
    if (iVar3 == 0) {
      return 0;
    }
    iVar4 = GetMagazineCapacity(this_00);
    iVar5 = (**(code **)(*in_stack_00000004 + 0x510))();
    iVar1 = in_stack_00000004[0x134];
    (**(code **)(*in_stack_00000004 + 0x558))();
    iVar3 = CBaseCombatCharacter::GetAmmoCount(this_01,iVar3);
    if ((iVar4 <= iVar3) && (iVar4 <= iVar5 - iVar1)) {
      return 0;
    }
  }
  if (in_stack_00000004[0x169] < 0) {
    return 0;
  }
  return (char)in_stack_00000004[0x572];
}



/* ----------------------------------------
 * CINSWeapon::PassesReloadRequirements
 * Address: 00310c30  Size: 448 bytes
 * ---------------------------------------- */

/* CINSWeapon::PassesReloadRequirements() const */

uint __thiscall CINSWeapon::PassesReloadRequirements(CINSWeapon *this)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  CINSWeapon *this_00;
  CBaseEntity *extraout_ECX;
  CINSWeapon *this_01;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *pCVar6;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *extraout_ECX_04;
  CBaseEntity *extraout_ECX_05;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar2 = GetINSPlayerOwner();
  if ((in_stack_00000004[0x169] < 0) || (iVar2 == 0)) {
    return 0;
  }
  cVar1 = IsSingleReload(this_00);
  pCVar6 = extraout_ECX;
  if (cVar1 == '\0') {
    if ((in_stack_00000004[0x169] < 0) || (*(char *)((int)in_stack_00000004 + 0x15ca) == '\0')) {
      uVar5 = in_stack_00000004[0x58b];
      if ((uVar5 & 0x20) != 0) {
        cVar1 = (**(code **)(*in_stack_00000004 + 0x740))(in_stack_00000004);
        if (cVar1 == '\0') {
          return 0;
        }
        uVar5 = in_stack_00000004[0x58b];
        pCVar6 = extraout_ECX_05;
      }
      if ((uVar5 & 0x80) == 0) goto LAB_00310ca6;
      iVar4 = (**(code **)(*in_stack_00000004 + 0x560))(in_stack_00000004);
      pCVar6 = extraout_ECX_01;
      if (0 < iVar4) {
        return 0;
      }
    }
    else {
      uVar5 = in_stack_00000004[0x58b];
      if ((uVar5 & 0xa0) == 0) goto LAB_00310ca6;
      iVar4 = (**(code **)(*in_stack_00000004 + 0x560))(in_stack_00000004);
      iVar3 = GetMagazineCapacity(this_01);
      pCVar6 = extraout_ECX_00;
      if (iVar3 < iVar4) {
        return 0;
      }
    }
  }
  else {
    uVar5 = in_stack_00000004[0x58b];
    if ((uVar5 & 0x40) != 0) {
      cVar1 = (**(code **)(*in_stack_00000004 + 0x740))(in_stack_00000004);
      if (cVar1 == '\0') {
        return 0;
      }
      uVar5 = in_stack_00000004[0x58b];
      pCVar6 = extraout_ECX_02;
    }
    if ((uVar5 & 0x100) == 0) goto LAB_00310ca6;
    iVar4 = (**(code **)(*in_stack_00000004 + 0x560))(in_stack_00000004);
    pCVar6 = extraout_ECX_04;
    if (iVar4 < 1) {
      return 0;
    }
  }
  uVar5 = in_stack_00000004[0x58b];
LAB_00310ca6:
  if ((uVar5 & 0x200) != 0) {
    cVar1 = InBipod();
    if (cVar1 == '\0') {
      return 0;
    }
    uVar5 = in_stack_00000004[0x58b];
    pCVar6 = extraout_ECX_03;
  }
  if ((uVar5 & 0x400) != 0) {
    if ((*(byte *)(iVar2 + 0xd1) & 0x10) != 0) {
      CBaseEntity::CalcAbsoluteVelocity(pCVar6);
    }
    uVar5 = UTIL_IsMoving((Vector *)(iVar2 + 0x1a8));
    return uVar5 ^ 1;
  }
  return 1;
}



/* ----------------------------------------
 * CINSWeapon::Reload
 * Address: 00311640  Size: 1562 bytes
 * ---------------------------------------- */

/* CINSWeapon::Reload() [clone .part.247] */

undefined1 CINSWeapon::Reload(void)

{
  float fVar1;
  code *pcVar2;
  bool bVar3;
  undefined1 uVar4;
  char cVar5;
  CStudioHdr *pCVar6;
  int *piVar7;
  int iVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  int *piVar13;
  char *pcVar14;
  CAmmoDef *this;
  CBaseCombatCharacter *this_00;
  CINSPlayerShared *this_01;
  CBaseEntity *this_02;
  CINSWeapon *this_03;
  CINSWeapon *this_04;
  CINSWeapon *extraout_ECX;
  CINSWeapon *pCVar15;
  CFmtStrN<256,false> *this_05;
  CBaseAnimating *this_06;
  CBaseAnimating *extraout_ECX_00;
  CBaseAnimating *this_07;
  CBaseEntity *this_08;
  CINSRules *extraout_ECX_01;
  CINSRules *this_09;
  CBaseEntity *this_10;
  CBaseEntity *extraout_ECX_02;
  CINSWeapon *extraout_ECX_03;
  CINSPlayer *this_11;
  CBaseAnimating *this_12;
  CBaseAnimating *extraout_ECX_04;
  CINSWeapon *extraout_ECX_05;
  CINSWeapon *pCVar16;
  int unaff_EBX;
  int iVar17;
  float10 fVar18;
  float fVar19;
  CStudioHdr *pCVar20;
  float fVar21;
  undefined4 uVar22;
  int local_130;
  char local_128 [280];
  
  pCVar6 = (CStudioHdr *)__i686_get_pc_thunk_bx();
  piVar7 = (int *)GetINSPlayerOwner();
  uVar4 = 0;
  if ((piVar7 != (int *)0x0) &&
     (iVar10 = *(int *)(pCVar6 + 0x4d0), iVar8 = (**(code **)(*(int *)pCVar6 + 0x510))(pCVar6),
     iVar10 < iVar8)) {
    uVar9 = (**(code **)(*(int *)pCVar6 + 0x558))(pCVar6);
    iVar10 = GetAmmoDef();
    iVar10 = CAmmoDef::GetAmmoOfIndex(this,iVar10);
    if (iVar10 != 0) {
      uVar9 = (**(code **)(*(int *)pCVar6 + 0x558))(pCVar6,uVar9);
      iVar8 = CBaseCombatCharacter::GetAmmoCount(this_00,(int)piVar7);
      if (iVar8 < 1) {
        EmitWeaponGameEvent(pCVar6,0x47,0);
        fVar19 = *(float *)(unaff_EBX + 0x613107) +
                 *(float *)(**(int **)(unaff_EBX + 0x89524f) + 0xc);
        if (*(float *)(pCVar6 + 0x4b4) != fVar19) {
          CBaseEntity::NetworkStateChanged(this_10,pCVar6);
          *(float *)(pCVar6 + 0x4b4) = fVar19;
        }
      }
      else if (((*(int *)(pCVar6 + 0x4d0) < 1) &&
               (cVar5 = (**(code **)(*(int *)pCVar6 + 0x738))(pCVar6,uVar9), cVar5 == '\0')) ||
              (uVar4 = 0, (piVar7[0x3c9] & 0x20001U) == 0)) {
        cVar5 = InBipodTransition();
        if (cVar5 == '\0') {
          cVar5 = InIronsights();
          if (cVar5 != '\0') {
            SetIronsights(this_03,SUB41(pCVar6,0),false);
          }
          uVar11 = (**(code **)(*(int *)pCVar6 + 0x740))(pCVar6);
          uVar9 = 0xc;
          uVar11 = uVar11 & 0xff;
          CINSPlayer::DoAnimationEvent();
          fVar18 = (float10)GetReloadSpeedModifier(this_04);
          fVar19 = (float)fVar18;
          pcVar2 = *(code **)(*(int *)pCVar6 + 0x6a8);
          uVar9 = (**(code **)(*(int *)pCVar6 + 0x6e8))(pCVar6,uVar9,uVar11);
          local_130 = (*pcVar2)(pCVar6,uVar9);
          iVar8 = GetUpgradeInSlot(pCVar6,2);
          pCVar15 = extraout_ECX;
          if ((iVar8 != 0) && (0 < *(int *)(iVar8 + 0x194))) {
            pCVar15 = (CINSWeapon *)0x0;
            iVar17 = 0;
            do {
              iVar12 = local_130;
              if (((iVar17 <= *(int *)(iVar8 + 0x1a8)) &&
                  (pCVar16 = pCVar15 + *(int *)(iVar8 + 400), *(int *)pCVar16 != iVar17)) &&
                 (pCVar16[0x154] != (CINSWeapon)0x0)) {
                uVar9 = ActivityList_NameForIndex(local_130);
                CFmtStrN<256,false>::CFmtStrN
                          (this_05,local_128,unaff_EBX + 0x67b858,uVar9,pCVar16 + 0x154);
                iVar12 = CBaseAnimating::LookupActivity(this_06,(char *)pCVar6);
                cVar5 = HaveSequenceForActivity(pCVar6,iVar12);
                if (cVar5 == '\0') {
                  iVar12 = local_130;
                }
              }
              local_130 = iVar12;
              iVar17 = iVar17 + 1;
              pCVar15 = pCVar15 + 0x1e0;
            } while (iVar17 < *(int *)(iVar8 + 0x194));
          }
          uVar22 = 0x3dcccccd /* 0.1f */;
          fVar21 = fVar19;
          SendWeaponAnimResetAttacks(pCVar15,(int)pCVar6,SUB41(local_130,0),1.4013e-45,fVar19);
          pcVar2 = *(code **)(*(int *)pCVar6 + 0x408);
          uVar9 = *(undefined4 *)(pCVar6 + 0x3d0);
          fVar1 = *(float *)(**(int **)(unaff_EBX + 0x89524f) + 0xc);
          piVar13 = (int *)0x0;
          this_07 = extraout_ECX_00;
          if (pCVar6[0x32d] == (CStudioHdr)0x0) {
            if ((*(int *)(pCVar6 + 0x498) == 0) &&
               (iVar8 = CBaseEntity::GetModel(), this_07 = this_12, iVar8 != 0)) {
              CBaseAnimating::LockStudioHdr(this_12);
              this_07 = extraout_ECX_04;
            }
            piVar13 = *(int **)(pCVar6 + 0x498);
            if ((piVar13 != (int *)0x0) && (this_07 = (CBaseAnimating *)0x0, *piVar13 == 0)) {
              piVar13 = (int *)0x0;
            }
          }
          fVar18 = (float10)CBaseAnimating::SequenceDuration(this_07,pCVar6,(int)piVar13);
          pCVar20 = (CStudioHdr *)((float)fVar18 / fVar19 + fVar1);
          (*pcVar2)(pCVar6,pCVar20,uVar9,fVar21,uVar22);
          this_09 = (CINSRules *)this_08;
          if (pCVar6[0x505] != (CStudioHdr)0x1) {
            pCVar20 = pCVar6 + 0x505;
            CBaseEntity::NetworkStateChanged(this_08,pCVar6);
            pCVar6[0x505] = (CStudioHdr)0x1;
            this_09 = (CINSRules *)extraout_ECX_02;
          }
          if (*(int *)(pCVar6 + 0x4140) != 1) {
            pCVar20 = pCVar6 + 0x4140;
            CBaseEntity::NetworkStateChanged((CBaseEntity *)this_09,pCVar6);
            *(undefined4 *)(pCVar6 + 0x4140) = 1;
            this_09 = extraout_ECX_01;
          }
          iVar8 = CINSRules::GetGameState(this_09);
          if (iVar8 == 4) {
            cVar5 = (**(code **)(*piVar7 + 0x7b0))(piVar7,pCVar20);
            bVar3 = true;
            pCVar15 = extraout_ECX_03;
            if (cVar5 != '\0') {
              fVar18 = (float10)RandomFloat(0,0x3f800000 /* 1.0f */);
              bVar3 = (float)fVar18 < *(float *)(CTriggerProximity::Spawn + unaff_EBX + 3) ||
                      (float)fVar18 == *(float *)(CTriggerProximity::Spawn + unaff_EBX + 3);
              pCVar15 = extraout_ECX_05;
            }
            if ((0 < piVar7[0x7a5]) && (bVar3)) {
              uVar11 = IsSingleReload(pCVar15);
              fVar19 = *(float *)(**(int **)(unaff_EBX + 0x89524f) + 0xc);
              if (*(float *)(pCVar6 + 0x420c) <= fVar19 && fVar19 != *(float *)(pCVar6 + 0x420c)) {
                pcVar14 = (char *)UTIL_VarArgs((char *)(unaff_EBX + 0x62ca17),uVar11 & 0xff,
                                               (uint)((*(uint *)(iVar10 + 0x94) & 4) != 0));
                uVar22 = 0;
                fVar21 = 0.0;
                CINSPlayer::SpeakConceptToTeam(this_11,(int)piVar7,(char *)0x40,pcVar14,0);
                *(float *)(pCVar6 + 0x420c) =
                     *(float *)(&DAT_00612b5f + unaff_EBX) +
                     *(float *)(**(int **)(unaff_EBX + 0x89524f) + 0xc);
              }
            }
          }
          EmitWeaponGameEvent(pCVar6,0x48,0,fVar21,uVar22);
          uVar4 = 1;
        }
        else {
          fVar19 = *(float *)(**(int **)(unaff_EBX + 0x89524f) + 0xc);
          fVar18 = (float10)CINSPlayerShared::GetBipodTransitionRemainingTime(this_01);
          fVar19 = (float)fVar18 + fVar19;
          uVar4 = 0;
          if (*(float *)(pCVar6 + 0x4144) != fVar19) {
            CBaseEntity::NetworkStateChanged(this_02,pCVar6);
            *(float *)(pCVar6 + 0x4144) = fVar19;
          }
        }
      }
    }
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSWeapon::Reload
 * Address: 00311c90  Size: 45 bytes
 * ---------------------------------------- */

/* CINSWeapon::Reload() */

undefined4 __thiscall CINSWeapon::Reload(CINSWeapon *this)

{
  char cVar1;
  undefined4 uVar2;
  int *in_stack_00000004;
  
  cVar1 = (**(code **)(*in_stack_00000004 + 0x658))();
  if (cVar1 == '\0') {
    return 0;
  }
  uVar2 = Reload();
  return uVar2;
}



/* ----------------------------------------
 * CINSWeapon::ReloadCycle
 * Address: 0030f940  Size: 691 bytes
 * ---------------------------------------- */

/* CINSWeapon::ReloadCycle() */

void __thiscall CINSWeapon::ReloadCycle(CINSWeapon *this)

{
  float fVar1;
  float fVar2;
  code *pcVar3;
  char cVar4;
  bool bVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  CStudioHdr *pCVar9;
  CINSWeapon *this_00;
  CINSWeapon *this_01;
  CBaseAnimating *extraout_ECX;
  CBaseAnimating *this_02;
  CBaseEntity *this_03;
  CBaseCombatCharacter *this_04;
  CINSWeapon *this_05;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_06;
  CBaseEntity *this_07;
  CINSWeapon *this_08;
  CBaseEntity *extraout_ECX_01;
  CBaseAnimating *this_09;
  CBaseAnimating *extraout_ECX_02;
  int unaff_EBX;
  float10 fVar10;
  CStudioHdr *pCVar11;
  CStudioHdr *in_stack_00000004;
  undefined4 uVar12;
  undefined4 uVar13;
  float fVar14;
  
  __i686_get_pc_thunk_bx();
  iVar6 = GetINSPlayerOwner();
  if (iVar6 == 0) {
    return;
  }
  cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x658))(in_stack_00000004);
  if (cVar4 == '\0') {
    (**(code **)(*(int *)in_stack_00000004 + 0x470))(in_stack_00000004);
    return;
  }
  uVar13 = 0;
  uVar12 = 0xd;
  CINSPlayer::DoAnimationEvent();
  fVar10 = (float10)GetReloadSpeedModifier(this_00);
  fVar2 = (float)fVar10;
  bVar5 = (bool)(**(code **)(*(int *)in_stack_00000004 + 0x6f0))(in_stack_00000004,uVar12,uVar13);
  uVar13 = 0x3dcccccd /* 0.1f */;
  fVar14 = fVar2;
  SendWeaponAnimResetAttacks(this_01,(int)in_stack_00000004,bVar5,1.4013e-45,fVar2);
  uVar12 = *(undefined4 *)(in_stack_00000004 + 0x3d0);
  pcVar3 = *(code **)(*(int *)in_stack_00000004 + 0x408);
  fVar1 = *(float *)(**(int **)(unaff_EBX + 0x896f55) + 0xc);
  piVar7 = (int *)0x0;
  this_02 = extraout_ECX;
  if (in_stack_00000004[0x32d] == (CStudioHdr)0x0) {
    if ((*(int *)(in_stack_00000004 + 0x498) == 0) &&
       (iVar8 = CBaseEntity::GetModel(), this_02 = this_09, iVar8 != 0)) {
      CBaseAnimating::LockStudioHdr(this_09);
      this_02 = extraout_ECX_02;
    }
    piVar7 = *(int **)(in_stack_00000004 + 0x498);
    if ((piVar7 != (int *)0x0) && (this_02 = (CBaseAnimating *)0x0, *piVar7 == 0)) {
      piVar7 = (int *)0x0;
    }
  }
  fVar10 = (float10)CBaseAnimating::SequenceDuration(this_02,in_stack_00000004,(int)piVar7);
  pCVar11 = (CStudioHdr *)((float)fVar10 / fVar2 + fVar1);
  (*pcVar3)(in_stack_00000004,pCVar11,uVar12,fVar14,uVar13);
  if (*(int *)(in_stack_00000004 + 0x4140) == 1) {
    cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x644))(in_stack_00000004);
    if (cVar4 == '\0') {
      this_06 = this_07;
      if (0 < *(int *)(in_stack_00000004 + 0x4d0)) goto LAB_0030fb17;
    }
    else if (*(int *)(in_stack_00000004 + 0x4d0) != 0) {
      pCVar11 = in_stack_00000004 + 0x4d0;
      CBaseEntity::NetworkStateChanged(this_07,in_stack_00000004);
      *(undefined4 *)(in_stack_00000004 + 0x4d0) = 0;
    }
    this_06 = *(CBaseEntity **)(in_stack_00000004 + 0x5a4);
    pCVar9 = (CStudioHdr *)0x0;
    if (-1 < (int)this_06) {
      pCVar9 = in_stack_00000004 + 0x5a4;
    }
    if (pCVar9[0x1025] == (CStudioHdr)0x0) goto LAB_0030fb17;
    pCVar11 = in_stack_00000004 + 0x4d0;
    CBaseEntity::NetworkStateChanged(this_06,in_stack_00000004);
    *(undefined4 *)(in_stack_00000004 + 0x4d0) = 1;
    (**(code **)(*(int *)in_stack_00000004 + 0x73c))(in_stack_00000004,pCVar11);
    pCVar11 = (CStudioHdr *)0x1;
    TakeAmmo(this_08,(int)in_stack_00000004);
    iVar8 = *(int *)(in_stack_00000004 + 0x4140);
    this_06 = extraout_ECX_01;
LAB_0030fb1d:
    if (iVar8 == 3) goto LAB_0030fa81;
  }
  else {
    this_06 = this_03;
    if (*(int *)(in_stack_00000004 + 0x4140) == 3) {
      iVar8 = *(int *)(in_stack_00000004 + 0x4d0);
      CBaseEntity::NetworkStateChanged(this_03,in_stack_00000004);
      *(int *)(in_stack_00000004 + 0x4d0) = iVar8 + 1;
      pCVar11 = (CStudioHdr *)0x1;
      TakeAmmo(this_05,(int)in_stack_00000004);
      this_06 = extraout_ECX_00;
LAB_0030fb17:
      iVar8 = *(int *)(in_stack_00000004 + 0x4140);
      goto LAB_0030fb1d;
    }
  }
  pCVar11 = in_stack_00000004 + 0x4140;
  CBaseEntity::NetworkStateChanged(this_06,in_stack_00000004);
  *(undefined4 *)(in_stack_00000004 + 0x4140) = 3;
LAB_0030fa81:
  uVar12 = (**(code **)(*(int *)in_stack_00000004 + 0x558))(in_stack_00000004,pCVar11);
  iVar6 = CBaseCombatCharacter::GetAmmoCount(this_04,iVar6);
  if ((iVar6 < 1) ||
     (iVar6 = *(int *)(in_stack_00000004 + 0x4d0),
     iVar8 = (**(code **)(*(int *)in_stack_00000004 + 0x510))(in_stack_00000004,uVar12),
     iVar8 <= iVar6)) {
    (**(code **)(*(int *)in_stack_00000004 + 0x46c))(in_stack_00000004);
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::ReloadOrSwitchWeapons
 * Address: 003013c0  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeapon::ReloadOrSwitchWeapons() */

undefined4 CINSWeapon::ReloadOrSwitchWeapons(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeapon::ShouldLoseAmmoOnReload
 * Address: 003013a0  Size: 27 bytes
 * ---------------------------------------- */

/* CINSWeapon::ShouldLoseAmmoOnReload() const */

undefined1 __thiscall CINSWeapon::ShouldLoseAmmoOnReload(CINSWeapon *this)

{
  undefined1 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    uVar1 = *(undefined1 *)(in_stack_00000004 + 0x1604);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSWeapon::ShouldReloadNearEmpty
 * Address: 003048e0  Size: 41 bytes
 * ---------------------------------------- */

/* CINSWeapon::ShouldReloadNearEmpty() const */

bool __thiscall CINSWeapon::ShouldReloadNearEmpty(CINSWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  iVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    iVar1 = in_stack_00000004 + 0x5a4;
  }
  return *(int *)(in_stack_00000004 + 0x4d0) <= *(int *)(iVar1 + 0x10c0);
}



/* ----------------------------------------
 * CINSWeapon::TakeAmmo
 * Address: 003070e0  Size: 183 bytes
 * ---------------------------------------- */

/* CINSWeapon::TakeAmmo(int) */

void __thiscall CINSWeapon::TakeAmmo(CINSWeapon *this,int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  CAmmoDef *this_00;
  CBaseCombatCharacter *this_01;
  CINSWeaponMagazines *this_02;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar1 = GetINSPlayerOwner();
  if (iVar1 != 0) {
    uVar2 = (**(code **)(*(int *)param_1 + 0x558))(param_1);
    iVar3 = GetAmmoDef();
    iVar3 = CAmmoDef::GetAmmoOfIndex(this_00,iVar3);
    if ((iVar3 == 0) || ((*(byte *)(iVar3 + 0x94) & 4) == 0)) {
      CBaseCombatCharacter::RemoveAmmo(this_01,iVar1,in_stack_00000008);
    }
    else {
      (**(code **)(*(int *)param_1 + 0x558))(param_1,uVar2);
      iVar1 = CINSPlayer::GetMagazines(iVar1);
      if (iVar1 != 0) {
        CINSWeaponMagazines::PopRounds(this_02,iVar1);
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSWeapon::UseChamberRound
 * Address: 002f9c00  Size: 7 bytes
 * ---------------------------------------- */

/* CINSWeapon::UseChamberRound() const */

undefined4 CINSWeapon::UseChamberRound(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSWeapon::UsesTacticalReload
 * Address: 00304940  Size: 34 bytes
 * ---------------------------------------- */

/* CINSWeapon::UsesTacticalReload() const */

undefined1 __thiscall CINSWeapon::UsesTacticalReload(CINSWeapon *this)

{
  int iVar1;
  int in_stack_00000004;
  
  iVar1 = 0;
  if (-1 < *(int *)(in_stack_00000004 + 0x5a4)) {
    iVar1 = in_stack_00000004 + 0x5a4;
  }
  return *(undefined1 *)(iVar1 + 0x1025);
}



