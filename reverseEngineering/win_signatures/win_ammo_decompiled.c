/*
 * Windows server.dll — Ammo/Magazine system decompilation
 * 92 functions decompiled
 */

/* ==================================================================
 * GetMagazines_caller_4 (weapon handling?)
 * Address: 0x103028b0  RVA: 0x3028b0  Size: 1308 bytes
 * ================================================================== */

void FUN_103028b0(void)

{
  bool bVar1;
  char cVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int *in_ECX;
  char *pcVar7;
  float10 fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  
  piVar3 = (int *)FUN_1006d660();
  if (piVar3 == (int *)0x0) {
    return;
  }
  cVar2 = (**(code **)(*piVar3 + 0x154))();
  if (cVar2 == '\0') {
    return;
  }
  if (*(char *)((int)in_ECX + 0x4f1) == '\0') {
    return;
  }
  bVar1 = false;
  cVar2 = FUN_103068c0();
  if (cVar2 == '\0') {
    uVar4 = (**(code **)(*in_ECX + 0x554))();
    FUN_102e4660(uVar4);
    iVar5 = FUN_10055cc0(uVar4);
    if ((iVar5 == 0) || ((*(byte *)(iVar5 + 0x94) & 4) == 0)) {
      cVar2 = (**(code **)(*in_ECX + 0x640))();
      if ((cVar2 != '\0') && (in_ECX[0x12f] != 0)) {
        if ((char)in_ECX[0x15] == '\0') {
          if (in_ECX[6] != 0) {
            FUN_10055020(0x4bc);
          }
        }
        else {
          *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        }
        in_ECX[0x12f] = 0;
      }
      if (((in_ECX[0x164] < 0) || (in_ECX == (int *)0xfffffa70)) ||
         (*(char *)((int)in_ECX + 0x15b6) == '\0')) {
        FUN_1006d290();
      }
      else {
        iVar6 = FUN_10303d10();
        iVar5 = (**(code **)(*in_ECX + 0x55c))();
        if (iVar5 <= iVar6) {
          iVar5 = FUN_10069320(in_ECX[0x12d]);
          if (iVar5 <= iVar6) {
            iVar6 = FUN_10069320(in_ECX[0x12d]);
          }
          iVar5 = in_ECX[0x12f] + iVar6;
          if (in_ECX[0x12f] != iVar5) {
            if ((char)in_ECX[0x15] == '\0') {
              if (in_ECX[6] != 0) {
                FUN_10055020(0x4bc);
              }
            }
            else {
              *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
            }
            in_ECX[0x12f] = iVar5;
          }
          FUN_1006a190(iVar6,in_ECX[0x12d]);
        }
      }
    }
    else {
      uVar4 = (**(code **)(*in_ECX + 0x554))();
      iVar5 = FUN_102acfd0(uVar4);
      if (iVar5 != 0) {
        iVar5 = in_ECX[0x12f];
        piVar3 = in_ECX + 0x12f;
        cVar2 = FUN_1030b7e0();
        if (cVar2 == '\0') {
          iVar6 = FUN_102a6760();
          if (*piVar3 != iVar6) {
            if ((char)in_ECX[0x15] == '\0') {
              if (in_ECX[6] != 0) {
                FUN_10055020((int)piVar3 - (int)in_ECX);
              }
            }
            else {
              *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
            }
            *piVar3 = iVar6;
          }
          if ((0 < iVar5) && (cVar2 = (**(code **)(*in_ECX + 0x640))(), cVar2 == '\0')) {
            FUN_102a6700(iVar5);
          }
        }
        else {
          iVar5 = FUN_102a6760();
          iVar5 = iVar5 + *piVar3;
          if (*piVar3 != iVar5) {
            if ((char)in_ECX[0x15] == '\0') {
              if (in_ECX[6] != 0) {
                FUN_10055020((int)piVar3 - (int)in_ECX);
              }
              *piVar3 = iVar5;
              bVar1 = true;
            }
            else {
              *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
              *piVar3 = iVar5;
              bVar1 = true;
            }
            goto LAB_10302bb3;
          }
        }
        bVar1 = true;
      }
    }
  }
  else {
    fVar8 = (float10)FUN_103043c0();
    fVar9 = (float)fVar8;
    uVar13 = 0x3dcccccd;
    uVar12 = 1;
    fVar10 = fVar9;
    uVar4 = (**(code **)(*in_ECX + 0x6f0))(1,fVar9,0x3dcccccd);
    FUN_103094d0(uVar4,uVar12,fVar10,uVar13);
    iVar5 = *in_ECX;
    fVar8 = (float10)FUN_1006f3b0();
    (**(code **)(iVar5 + 0x404))((float)fVar8 / fVar9 + *(float *)(DAT_106931a8 + 0xc));
    FUN_102c8640(0xe,0);
  }
LAB_10302bb3:
  pcVar7 = (char *)((int)in_ECX + 0x4f1);
  if (((in_ECX[0x164] < 0) || (in_ECX == (int *)0xfffffa70)) ||
     ((*(char *)((int)in_ECX + 0x15b6) == '\0' ||
      ((cVar2 = (**(code **)(*in_ECX + 0x654))(), cVar2 == '\0' ||
       (cVar2 = (**(code **)(*in_ECX + 0x410))(), cVar2 == '\0')))))) {
    if (*pcVar7 != '\0') {
      if ((char)in_ECX[0x15] == '\0') {
        if (in_ECX[6] != 0) {
          FUN_10055020(0x4f1);
        }
      }
      else {
        *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
      }
      *pcVar7 = '\0';
    }
  }
  else {
    if (bVar1) {
      iVar5 = (**(code **)(*in_ECX + 0x50c))();
      fVar10 = (float)iVar5 * 0.5;
      fVar11 = (float)((uint)fVar10 & 0x80000000);
      fVar9 = (float)(-(uint)((float)((uint)fVar10 ^ (uint)fVar11) < 8388608.0) & 0x4b000000 |
                     (uint)fVar11);
      fVar9 = (fVar10 + fVar9) - fVar9;
      iVar5 = (int)(fVar9 - (float)(-(uint)(fVar11 < fVar9 - fVar10) & 0x3f800000));
    }
    else {
      iVar5 = FUN_10303d10();
    }
    iVar6 = (**(code **)(*in_ECX + 0x55c))();
    bVar1 = iVar6 <= iVar5;
    if ((bool)*pcVar7 != bVar1) {
      if ((char)in_ECX[0x15] == '\0') {
        if (in_ECX[6] != 0) {
          FUN_10055020(0x4f1);
        }
        *pcVar7 = bVar1;
      }
      else {
        *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        *pcVar7 = bVar1;
      }
    }
  }
  if ((char)in_ECX[0x104d] != '\0') {
    if ((char)in_ECX[0x15] == '\0') {
      if (in_ECX[6] != 0) {
        FUN_10055020(0x4134);
      }
    }
    else {
      *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
    }
    *(undefined1 *)(in_ECX + 0x104d) = 0;
  }
  if (*pcVar7 == '\0') {
    if (in_ECX[0x104b] != 0) {
      if ((char)in_ECX[0x15] == '\0') {
        if (in_ECX[6] != 0) {
          FUN_10055020(0x412c);
        }
      }
      else {
        *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
      }
      in_ECX[0x104b] = 0;
    }
    if (in_ECX[0x1068] != -1) {
      if ((char)in_ECX[0x15] == '\0') {
        if (in_ECX[6] != 0) {
          FUN_10055020(0x41a0);
        }
      }
      else {
        *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
      }
      in_ECX[0x1068] = -1;
    }
  }
  cVar2 = (**(code **)(*in_ECX + 0x740))();
  if ((cVar2 != '\0') && (cVar2 = (**(code **)(*in_ECX + 0x734))(), cVar2 == '\0')) {
    (**(code **)(*in_ECX + 0x738))();
  }
  return;
}



/* ==================================================================
 * GetMagazines_caller_5 (ammo check?)
 * Address: 0x1030a190  RVA: 0x30a190  Size: 124 bytes
 * ================================================================== */

void FUN_1030a190(undefined4 param_1)

{
  char cVar1;
  int *piVar2;
  undefined4 uVar3;
  int iVar4;
  int *in_ECX;
  
  piVar2 = (int *)FUN_1006d660();
  if (piVar2 != (int *)0x0) {
    cVar1 = (**(code **)(*piVar2 + 0x154))();
    if (cVar1 != '\0') {
      uVar3 = (**(code **)(*in_ECX + 0x554))();
      FUN_102e4660(uVar3);
      iVar4 = FUN_10055cc0(uVar3);
      if ((iVar4 == 0) || ((*(byte *)(iVar4 + 0x94) & 4) == 0)) {
        FUN_1006a190(param_1,in_ECX[0x12d]);
      }
      else {
        uVar3 = (**(code **)(*in_ECX + 0x554))();
        iVar4 = FUN_102acfd0(uVar3);
        if (iVar4 != 0) {
          FUN_102a6640();
          return;
        }
      }
    }
  }
  return;
}



/* ==================================================================
 * GetMagazines_caller_1 (Resupply?)
 * Address: 0x1027e7c0  RVA: 0x27e7c0  Size: 409 bytes
 * ================================================================== */

undefined4 FUN_1027e7c0(void)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  float10 extraout_ST0;
  float10 fVar5;
  float local_8;
  
  piVar2 = (int *)FUN_102bda50();
  if (piVar2 != (int *)0x0) {
    cVar1 = FUN_1027e960();
    if (cVar1 != '\0') {
      return 1;
    }
    cVar1 = (**(code **)(*piVar2 + 0x654))();
    if ((cVar1 != '\0') && (cVar1 = (**(code **)(*piVar2 + 0x544))(), cVar1 != '\0')) {
      iVar3 = (**(code **)(*piVar2 + 0x52c))();
      if ((iVar3 != 0) && (iVar3 = (**(code **)(*piVar2 + 0x52c))(), iVar3 != 1)) {
        return 0;
      }
      (**(code **)(*piVar2 + 0x554))();
      iVar3 = FUN_10069320();
      if (0 < iVar3) {
        if (DAT_106df5cc == (int *)&DAT_106df5b0) {
          local_8 = (float)(DAT_106df5dc ^ 0x106df5b0);
        }
        else {
          fVar5 = (float10)(**(code **)(*DAT_106df5cc + 0x30))();
          local_8 = (float)fVar5;
        }
        FUN_1027dfc0();
        if ((float)extraout_ST0 < local_8) {
          (**(code **)(*piVar2 + 0x554))();
          FUN_102e4660();
          iVar3 = FUN_10055cc0();
          if ((iVar3 == 0) || ((*(byte *)(iVar3 + 0x94) & 4) == 0)) {
            return 1;
          }
          if (DAT_106df5cc == (int *)&DAT_106df5b0) {
            local_8 = (float)(DAT_106df5dc ^ 0x106df5b0);
          }
          else {
            fVar5 = (float10)(**(code **)(*DAT_106df5cc + 0x30))();
            local_8 = (float)fVar5;
          }
          iVar3 = (**(code **)(*piVar2 + 0x50c))();
          (**(code **)(*piVar2 + 0x554))();
          iVar4 = FUN_102acfd0();
          if (iVar4 != 0) {
            FUN_103fe200((double)((float)iVar3 * local_8));
            FUN_103fcb10();
            cVar1 = FUN_102a6610();
            if (cVar1 != '\0') {
              return 1;
            }
          }
        }
      }
    }
  }
  return 0;
}



/* ==================================================================
 * GetMagazines_caller_3 (GiveDefaultAmmo?)
 * Address: 0x102b7140  RVA: 0x2b7140  Size: 841 bytes
 * ================================================================== */

void FUN_102b7140(int *param_1)

{
  char cVar1;
  int iVar2;
  undefined4 *puVar3;
  int *piVar4;
  int *piVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  int in_ECX;
  int iVar12;
  int *local_18;
  int local_14;
  
  FUN_102be830();
  iVar2 = FUN_102df2d0();
  puVar3 = (undefined4 *)FUN_102be830();
  piVar4 = puVar3 + 0x15;
  if (*piVar4 != iVar2) {
    (**(code **)*puVar3)(piVar4);
    *piVar4 = iVar2;
  }
  piVar4 = (int *)FUN_102bda50();
  uVar8 = *(uint *)(in_ECX + 0x12fc);
  if ((((uVar8 == 0xffffffff) ||
       (*(uint *)(PTR_DAT_105e1078 + (uVar8 & 0xffff) * 0x18 + 8) != uVar8 >> 0x10)) ||
      (local_18 = *(int **)(PTR_DAT_105e1078 + (uVar8 & 0xffff) * 0x18 + 4), local_18 == (int *)0x0)
      ) || (cVar1 = (**(code **)(*local_18 + 0x16c))(), cVar1 == '\0')) {
    local_18 = (int *)0x0;
  }
  if ((piVar4 != (int *)0x0) && (*(char *)(in_ECX + 0x1850) == '\0')) {
    iVar2 = FUN_10160e50(0);
    piVar5 = (int *)FUN_10160e50(0);
    if ((iVar2 != 0) && (piVar5 != (int *)0x0)) {
      iVar12 = *piVar5;
      uVar7 = *(undefined4 *)(iVar2 + 0x3bc);
      uVar11 = *(undefined4 *)(iVar2 + 0x3b8);
      uVar6 = (**(code **)(*piVar4 + 0x500))(0,piVar4);
      (**(code **)(iVar12 + 0x3a8))(uVar6);
      FUN_1005e0c0(uVar7);
      FUN_103658f0(uVar11);
    }
  }
  FUN_10067100(0);
  local_14 = 0;
  do {
    piVar5 = (int *)FUN_10069360(local_14);
    if ((piVar5 != (int *)0x0) && (cVar1 = (**(code **)(*piVar5 + 0x16c))(), cVar1 != '\0')) {
      uVar7 = (**(code **)(*piVar5 + 0x554))();
      uVar11 = uVar7;
      FUN_102e4660(uVar7);
      uVar8 = FUN_10055c90(uVar11);
      if ((uVar8 & 4) == 0) {
        iVar2 = *param_1;
        uVar6 = 1;
        uVar11 = FUN_10069320(uVar7);
        (**(code **)(iVar2 + 0x448))(uVar11,uVar7,uVar6);
      }
      else {
        iVar2 = FUN_102acfd0(uVar7);
        if ((iVar2 != 0) && (iVar12 = 0, 0 < *(int *)(iVar2 + 0x14))) {
          do {
            iVar9 = FUN_102a65f0(iVar12);
            if (0 < iVar9) {
              uVar11 = uVar7;
              FUN_102e4660(uVar7);
              iVar10 = FUN_10055cc0(uVar11);
              if (iVar10 != 0) {
                if ((*(byte *)(iVar10 + 0x94) & 4) == 0) {
                  FUN_10065870(1,uVar7,1);
                }
                else {
                  FUN_102acfd0(uVar7);
                  FUN_102a6520(1,iVar9,0xffffffff);
                }
              }
            }
            iVar12 = iVar12 + 1;
          } while (iVar12 < *(int *)(iVar2 + 0x14));
        }
      }
      iVar2 = in_ECX + 0xaf8;
      if (*(int *)(iVar2 + local_14 * 4) != -1) {
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020((local_14 * 4 - in_ECX) + iVar2);
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *(undefined4 *)(iVar2 + local_14 * 4) = 0xffffffff;
      }
      FUN_1006f7a0(param_1);
      (**(code **)(*piVar5 + 0x44))(param_1);
      FUN_10083f60(param_1,1);
      piVar5 = (int *)(**(code **)(*piVar5 + 8))();
      iVar2 = *piVar5;
      if (param_1[local_14 + 0x2be] != iVar2) {
        if ((char)param_1[0x15] == '\0') {
          if (param_1[6] != 0) {
            FUN_10055020(local_14 * 4 + 0xaf8);
          }
        }
        else {
          *(byte *)(param_1 + 0x16) = *(byte *)(param_1 + 0x16) | 1;
        }
        param_1[local_14 + 0x2be] = iVar2;
      }
    }
    local_14 = local_14 + 1;
  } while (local_14 < 0x30);
  iVar2 = 0;
  if (0 < *(int *)(in_ECX + 0x1e4c)) {
    do {
      uVar8 = *(uint *)(*(int *)(in_ECX + 0x1e40) + iVar2 * 4);
      if ((((uVar8 != 0xffffffff) &&
           (*(uint *)(PTR_DAT_105e1078 + (uVar8 & 0xffff) * 0x18 + 8) == uVar8 >> 0x10)) &&
          (iVar12 = *(int *)(PTR_DAT_105e1078 + (uVar8 & 0xffff) * 0x18 + 4), iVar12 != 0)) &&
         (cVar1 = FUN_102abea0(iVar12), cVar1 == '\0')) {
        FUN_101d95d0(iVar12);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < *(int *)(in_ECX + 0x1e4c));
  }
  *(undefined4 *)(in_ECX + 0x1e4c) = 0;
  FUN_10067100(piVar4);
  (**(code **)(*param_1 + 0x5f4))(local_18);
  return;
}



/* ==================================================================
 * CINSPlayer::GetMagazines
 * Address: 0x102acfd0  RVA: 0x2acfd0  Size: 171 bytes
 * ================================================================== */

undefined4 FUN_102acfd0(undefined4 param_1)

{
  undefined4 uVar1;
  ushort uVar2;
  int iVar3;
  int in_ECX;
  uint uVar4;
  bool bVar5;
  undefined4 local_10 [2];
  undefined4 local_8;
  
  uVar1 = param_1;
  local_10[0] = param_1;
  uVar2 = FUN_10055c10(local_10);
  uVar4 = (uint)uVar2;
  if (((int)uVar4 < *(int *)(in_ECX + 0x17cc)) && (uVar2 <= *(ushort *)(in_ECX + 0x17da))) {
    bVar5 = uVar2 == 0xffff;
    if (!bVar5) {
      bVar5 = *(ushort *)(*(int *)(in_ECX + 0x17c8) + uVar4 * 0x10) == uVar2;
    }
    if (!bVar5) goto LAB_102ad063;
  }
  iVar3 = FUN_10121e50(0x1c);
  if (iVar3 == 0) {
    local_8 = 0;
  }
  else {
    local_8 = FUN_102a6440(in_ECX,uVar1);
  }
  uVar4 = FUN_10398cb0(&param_1,&local_8);
  uVar4 = uVar4 & 0xffff;
LAB_102ad063:
  return *(undefined4 *)(*(int *)(in_ECX + 0x17c8) + 0xc + uVar4 * 0x10);
}



/* ==================================================================
 * CINSPlayer::GiveAmmo
 * Address: 0x102ad670  RVA: 0x2ad670  Size: 201 bytes
 * ================================================================== */

int FUN_102ad670(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = param_2;
  FUN_102e4660(param_2);
  iVar1 = FUN_10055cc0(uVar2);
  if (iVar1 == 0) {
    return 0;
  }
  if ((*(byte *)(iVar1 + 0x94) & 4) != 0) {
    FUN_102acfd0(param_2);
    iVar1 = FUN_102a6520(param_1,param_3,param_5);
    if ((0 < iVar1) && ((char)param_4 == '\0')) {
      FUN_101a8910("BaseCombatCharacter.AmmoPickup",0,0);
    }
    return iVar1;
  }
  if (param_5 < 0) {
    iVar1 = FUN_10065870(param_1,param_2,param_4);
    return iVar1;
  }
  iVar1 = FUN_10069320(param_2);
  if (param_1 < 0) {
    iVar1 = FUN_10065870(0,param_2,param_4);
    return iVar1;
  }
  if (param_5 - iVar1 < param_1) {
    param_1 = param_5 - iVar1;
  }
  iVar1 = FUN_10065870(param_1,param_2,param_4);
  return iVar1;
}



/* ==================================================================
 * callee_d1 (RVA 0x55020, 237b, called by GetMagazines_caller_4)
 * Address: 0x10055020  RVA: 0x055020  Size: 237 bytes
 * ================================================================== */

void FUN_10055020(ushort param_1)

{
  ushort *puVar1;
  ushort *puVar2;
  ushort uVar3;
  uint *in_ECX;
  uint uVar4;
  ushort uVar5;
  
  if ((*in_ECX & 0x100) != 0) {
    return;
  }
  *in_ECX = *in_ECX | 1;
  puVar2 = (ushort *)FUN_100f9b30();
  puVar1 = DAT_1069315c;
  if (puVar2[1] == *DAT_1069315c) {
    uVar4 = (uint)*puVar2;
    uVar3 = 0;
    uVar5 = DAT_1069315c[uVar4 * 0x14 + 0x14];
    if (uVar5 != 0) {
      do {
        uVar5 = DAT_1069315c[uVar4 * 0x14 + 0x14];
        if (DAT_1069315c[uVar4 * 0x14 + uVar3 + 1] == param_1) {
          return;
        }
        uVar3 = uVar3 + 1;
      } while (uVar3 < uVar5);
    }
    if (uVar5 != 0x13) {
      DAT_1069315c[uVar4 * 0x14 + uVar5 + 1] = param_1;
      puVar1[uVar4 * 0x14 + 0x14] = puVar1[uVar4 * 0x14 + 0x14] + 1;
      return;
    }
  }
  else if ((DAT_1069315c[0x7d1] != 100) && (puVar2[1] == 0)) {
    *puVar2 = DAT_1069315c[0x7d1];
    DAT_1069315c[0x7d1] = DAT_1069315c[0x7d1] + 1;
    puVar2[1] = *DAT_1069315c;
    puVar1 = DAT_1069315c;
    uVar5 = *puVar2;
    DAT_1069315c[(uint)uVar5 * 0x14 + 1] = param_1;
    puVar1[(uint)uVar5 * 0x14 + 0x14] = 1;
    return;
  }
  puVar2[1] = 0;
  *in_ECX = *in_ECX | 0x100;
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x55cc0, 36b, called by GetMagazines_caller_4)
 * Address: 0x10055cc0  RVA: 0x055cc0  Size: 36 bytes
 * ================================================================== */

int FUN_10055cc0(int param_1)

{
  int in_ECX;
  
  if ((0 < param_1) && (param_1 < *(int *)(in_ECX + 4))) {
    return param_1 * 0xbc + 8 + in_ECX;
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x69320, 58b, called by GetMagazines_caller_4)
 * Address: 0x10069320  RVA: 0x069320  Size: 58 bytes
 * ================================================================== */

undefined4 FUN_10069320(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  int in_ECX;
  int iVar3;
  
  if (param_1 == -1) {
    return 0;
  }
  iVar3 = param_1;
  FUN_102e4660(param_1);
  cVar1 = FUN_10055b80(iVar3);
  uVar2 = 999;
  if (cVar1 == '\0') {
    uVar2 = *(undefined4 *)(in_ECX + 0x6f8 + param_1 * 4);
  }
  return uVar2;
}



/* ==================================================================
 * callee_d1 (RVA 0x6a190, 97b, called by GetMagazines_caller_4)
 * Address: 0x1006a190  RVA: 0x06a190  Size: 97 bytes
 * ================================================================== */

void FUN_1006a190(int param_1,int param_2)

{
  char cVar1;
  int *in_ECX;
  int iVar2;
  
  if ((0 < param_1) && (-1 < param_2)) {
    iVar2 = param_2;
    FUN_102e4660(param_2);
    cVar1 = FUN_10055b80(iVar2);
    if (cVar1 == '\0') {
      iVar2 = 0;
      if (0 < in_ECX[param_2 + 0x1be] - param_1) {
        iVar2 = in_ECX[param_2 + 0x1be] - param_1;
      }
      if (in_ECX[param_2 + 0x1be] != iVar2) {
        (**(code **)(*in_ECX + 0x560))(in_ECX + param_2 + 0x1be);
        in_ECX[param_2 + 0x1be] = iVar2;
      }
    }
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x6d290, 510b, called by GetMagazines_caller_4)
 * Address: 0x1006d290  RVA: 0x06d290  Size: 510 bytes
 * ================================================================== */

void FUN_1006d290(void)

{
  uint uVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *in_ECX;
  
  uVar1 = in_ECX[0x126];
  if ((((uVar1 != 0xffffffff) &&
       (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10)) &&
      (*(int **)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4) != (int *)0x0)) &&
     (iVar3 = (**(code **)(**(int **)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4) + 0x130))(),
     iVar3 != 0)) {
    cVar2 = (**(code **)(*in_ECX + 0x544))();
    if (cVar2 != '\0') {
      iVar4 = (**(code **)(*in_ECX + 0x50c))();
      iVar3 = in_ECX[0x12f];
      iVar5 = FUN_10069320(in_ECX[0x12d]);
      if (iVar4 - iVar3 < iVar5) {
        iVar3 = (**(code **)(*in_ECX + 0x50c))();
        iVar3 = iVar3 - in_ECX[0x12f];
      }
      else {
        iVar3 = FUN_10069320(in_ECX[0x12d]);
      }
      iVar5 = in_ECX[0x12f];
      iVar4 = iVar5 + iVar3;
      if (iVar5 != iVar4) {
        if ((char)in_ECX[0x15] == '\0') {
          if (in_ECX[6] != 0) {
            FUN_10055020(0x4bc);
          }
        }
        else {
          *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        }
        in_ECX[0x12f] = iVar4;
      }
      FUN_1006a190(iVar3,in_ECX[0x12d]);
    }
    cVar2 = (**(code **)(*in_ECX + 0x548))();
    if (cVar2 != '\0') {
      iVar4 = (**(code **)(*in_ECX + 0x510))();
      iVar3 = in_ECX[0x130];
      iVar5 = FUN_10069320(in_ECX[0x12e]);
      if (iVar4 - iVar3 < iVar5) {
        iVar3 = (**(code **)(*in_ECX + 0x510))();
        iVar3 = iVar3 - in_ECX[0x130];
      }
      else {
        iVar3 = FUN_10069320(in_ECX[0x12e]);
      }
      iVar5 = in_ECX[0x130];
      iVar4 = iVar5 + iVar3;
      if (iVar5 != iVar4) {
        if ((char)in_ECX[0x15] == '\0') {
          if (in_ECX[6] != 0) {
            FUN_10055020(0x4c0);
          }
        }
        else {
          *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        }
        in_ECX[0x130] = iVar4;
      }
      FUN_1006a190(iVar3,in_ECX[0x12e]);
    }
    if ((*(char *)((int)in_ECX + 0x4f5) != '\0') && (*(char *)((int)in_ECX + 0x4f1) != '\0')) {
      if ((char)in_ECX[0x15] != '\0') {
        *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        *(undefined1 *)((int)in_ECX + 0x4f1) = 0;
        return;
      }
      if (in_ECX[6] != 0) {
        FUN_10055020(0x4f1);
      }
      *(undefined1 *)((int)in_ECX + 0x4f1) = 0;
    }
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x6d660, 50b, called by GetMagazines_caller_4)
 * Address: 0x1006d660  RVA: 0x06d660  Size: 50 bytes
 * ================================================================== */

undefined4 FUN_1006d660(void)

{
  uint uVar1;
  undefined4 uVar2;
  int in_ECX;
  
  uVar1 = *(uint *)(in_ECX + 0x498);
  if (uVar1 != 0xffffffff) {
    if ((*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10) &&
       (*(int **)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4) != (int *)0x0)) {
                    /* WARNING: Could not recover jumptable at 0x1006d689. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar2 = (**(code **)(**(int **)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4) + 0x130))();
      return uVar2;
    }
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x6f3b0, 73b, called by GetMagazines_caller_4)
 * Address: 0x1006f3b0  RVA: 0x06f3b0  Size: 73 bytes
 * ================================================================== */

void FUN_1006f3b0(void)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  int in_ECX;
  
  uVar1 = *(undefined4 *)(in_ECX + 0x3bc);
  if (*(char *)(in_ECX + 0x319) == '\0') {
    if (*(int *)(in_ECX + 0x484) == 0) {
      iVar2 = FUN_1007aea0();
      if (iVar2 != 0) {
        FUN_1005ce90();
      }
    }
    piVar3 = *(int **)(in_ECX + 0x484);
    if ((piVar3 != (int *)0x0) && (*piVar3 != 0)) goto LAB_1006f3ed;
  }
  piVar3 = (int *)0x0;
LAB_1006f3ed:
  FUN_1005d790(piVar3,uVar1);
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6700, 88b, called by GetMagazines_caller_4)
 * Address: 0x102a6700  RVA: 0x2a6700  Size: 88 bytes
 * ================================================================== */

void FUN_102a6700(int param_1)

{
  uint uVar1;
  undefined4 *in_ECX;
  
  if (-1 < param_1) {
    FUN_101126a0(&param_1);
    uVar1 = in_ECX[1];
    if ((uVar1 != 0xffffffff) &&
       (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10)) {
      FUN_1006a200(in_ECX[5],*in_ECX);
      return;
    }
    FUN_1006a200(in_ECX[5],*in_ECX);
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6760, 231b, called by GetMagazines_caller_4)
 * Address: 0x102a6760  RVA: 0x2a6760  Size: 231 bytes
 * ================================================================== */

undefined4 FUN_102a6760(void)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *in_ECX;
  int iVar3;
  int iVar4;
  int iVar5;
  int local_c;
  int local_8;
  
  iVar5 = in_ECX[5];
  if (iVar5 < 1) {
    return 0;
  }
  iVar3 = 0;
  local_c = 0;
  iVar4 = 1;
  if (1 < iVar5) {
    local_8 = 0;
    do {
      if ((-1 < iVar4) && (iVar4 < (int)in_ECX[5])) {
        iVar5 = in_ECX[5];
        iVar3 = local_c;
        if (*(int *)(local_8 + in_ECX[2]) < *(int *)(in_ECX[2] + iVar4 * 4)) {
          iVar3 = iVar4;
          local_c = iVar4;
          local_8 = iVar4 * 4;
        }
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < iVar5);
    if (iVar3 < 0) {
      return 0;
    }
  }
  if (iVar5 <= iVar3) {
    return 0;
  }
  iVar5 = (in_ECX[5] - iVar3) + -1;
  uVar1 = *(undefined4 *)(in_ECX[2] + iVar3 * 4);
  if (0 < iVar5) {
    iVar4 = in_ECX[2] + iVar3 * 4;
    thunk_FUN_103fcbc0(iVar4,iVar4 + 4,iVar5 * 4);
  }
  in_ECX[5] = in_ECX[5] + -1;
  uVar2 = in_ECX[1];
  if ((uVar2 != 0xffffffff) &&
     (*(uint *)(PTR_DAT_105e1078 + (uVar2 & 0xffff) * 0x18 + 8) == uVar2 >> 0x10)) {
    FUN_1006a200(in_ECX[5],*in_ECX);
    return uVar1;
  }
  FUN_1006a200(in_ECX[5],*in_ECX);
  return uVar1;
}



/* ==================================================================
 * callee_d1 (RVA 0x2c8640, 43b, called by GetMagazines_caller_4)
 * Address: 0x102c8640  RVA: 0x2c8640  Size: 43 bytes
 * ================================================================== */

void FUN_102c8640(undefined4 param_1,undefined4 param_2)

{
  int in_ECX;
  
  (**(code **)(**(int **)(in_ECX + 0x1ba4) + 8))(param_1,param_2);
  FUN_102c8680();
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x2e4660, 6b, called by GetMagazines_caller_4)
 * Address: 0x102e4660  RVA: 0x2e4660  Size: 6 bytes
 * ================================================================== */

undefined4 * FUN_102e4660(void)

{
  return &DAT_106faa20;
}



/* ==================================================================
 * callee_d1 (RVA 0x303d10, 138b, called by GetMagazines_caller_4)
 * Address: 0x10303d10  RVA: 0x303d10  Size: 138 bytes
 * ================================================================== */

int FUN_10303d10(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int *in_ECX;
  
  if ((in_ECX[0x164] < 0) || (in_ECX == (int *)0xfffffa70)) {
    iVar1 = 0;
  }
  else {
    iVar1 = FUN_10304ec0(2);
    if ((iVar1 == 0) || (iVar1 = *(int *)(iVar1 + 0x300), iVar1 < 1)) {
      iVar1 = FUN_10304ec0(1);
      if ((iVar1 == 0) || (iVar1 = *(int *)(iVar1 + 0x300), iVar1 < 1)) {
        uVar2 = (**(code **)(*in_ECX + 0x554))();
        FUN_102e4660(uVar2);
        iVar3 = FUN_10055cc0(uVar2);
        if ((iVar3 == 0) || ((*(byte *)(iVar3 + 0x94) & 4) == 0)) {
          return in_ECX[0x579];
        }
        iVar1 = in_ECX[0x57b];
        if (iVar1 < 1) {
          return *(int *)(iVar3 + 0x88);
        }
      }
    }
  }
  return iVar1;
}



/* ==================================================================
 * callee_d1 (RVA 0x3043c0, 272b, called by GetMagazines_caller_4)
 * Address: 0x103043c0  RVA: 0x3043c0  Size: 272 bytes
 * ================================================================== */

float10 FUN_103043c0(void)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  int *piVar5;
  int in_ECX;
  int *piVar6;
  float10 fVar7;
  float fVar8;
  int local_18 [2];
  float local_10;
  int local_c;
  float local_8;
  
  if ((*(int *)(in_ECX + 0x590) < 0) || (in_ECX == -0x590)) {
    return (float10)1;
  }
  fVar8 = *(float *)(in_ECX + 0x10c0);
  piVar5 = (int *)(in_ECX + 0x1670);
  piVar6 = (int *)(in_ECX + 0x41a4);
  local_c = 10;
  local_8 = fVar8;
  do {
    if (-1 < *piVar6) {
      piVar4 = piVar5;
      if (*piVar5 < 0) {
        iVar1 = *(int *)(DAT_106faa1c + 0x18);
        if (iVar1 == 0) goto LAB_10304466;
        local_18[0] = *piVar6;
        iVar3 = FUN_103b6e10(local_18);
        fVar8 = local_8;
        if (iVar3 == -1) {
          piVar4 = (int *)0x0;
        }
        else {
          piVar4 = *(int **)(*(int *)(iVar1 + 8) + 0x14 + iVar3 * 0x18);
        }
      }
      if (piVar4 != (int *)0x0) {
        fVar8 = fVar8 * (float)piVar4[0xdd];
        local_8 = fVar8;
      }
    }
LAB_10304466:
    piVar6 = piVar6 + 1;
    piVar5 = piVar5 + 0x111;
    local_c = local_c + -1;
    if (local_c == 0) {
      piVar5 = (int *)FUN_1006d660();
      if ((piVar5 != (int *)0x0) && (cVar2 = (**(code **)(*piVar5 + 0x154))(), cVar2 != '\0')) {
        fVar7 = (float10)FUN_102bef00();
        local_10 = (float)fVar7;
        if (NAN(local_10) == (local_10 == 1.0)) {
          fVar7 = (float10)FUN_102bef00();
          return fVar7 * (float10)local_8;
        }
      }
      return (float10)local_8;
    }
  } while( true );
}



/* ==================================================================
 * callee_d1 (RVA 0x3068c0, 174b, called by GetMagazines_caller_4)
 * Address: 0x103068c0  RVA: 0x3068c0  Size: 174 bytes
 * ================================================================== */

undefined1 FUN_103068c0(void)

{
  int iVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int *in_ECX;
  
  cVar2 = (**(code **)(*in_ECX + 0x75c))(6);
  if (cVar2 != '\0') {
    return 0;
  }
  cVar2 = (**(code **)(*in_ECX + 0x75c))(7);
  if (cVar2 != '\0') {
    piVar3 = (int *)FUN_1006d660();
    if (piVar3 == (int *)0x0) {
      return 0;
    }
    cVar2 = (**(code **)(*piVar3 + 0x154))();
    if (cVar2 == '\0') {
      return 0;
    }
    iVar4 = FUN_10303d10();
    iVar5 = (**(code **)(*in_ECX + 0x50c))();
    iVar1 = in_ECX[0x12f];
    uVar6 = (**(code **)(*in_ECX + 0x554))();
    iVar7 = FUN_10069320(uVar6);
    if ((iVar4 <= iVar5 - iVar1) && (iVar4 <= iVar7)) {
      return 0;
    }
  }
  if ((-1 < in_ECX[0x164]) && (in_ECX + 0x164 != (int *)0x0)) {
    return (char)in_ECX[0x56d];
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x3094d0, 174b, called by GetMagazines_caller_4)
 * Address: 0x103094d0  RVA: 0x3094d0  Size: 174 bytes
 * ================================================================== */

char FUN_103094d0(undefined4 param_1,undefined4 param_2,float param_3,undefined4 param_4)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int *in_ECX;
  int *piVar4;
  float10 fVar5;
  
  cVar2 = FUN_10309580(param_1,param_3);
  if (cVar2 == '\0') {
    (**(code **)(*in_ECX + 0x67c))(param_4,param_2);
    return '\0';
  }
  iVar1 = in_ECX[0xef];
  if (*(char *)((int)in_ECX + 0x319) == '\0') {
    if (in_ECX[0x121] == 0) {
      iVar3 = FUN_1007aea0();
      if (iVar3 != 0) {
        FUN_1005ce90();
      }
    }
    piVar4 = (int *)in_ECX[0x121];
    if ((piVar4 != (int *)0x0) && (*piVar4 != 0)) goto LAB_1030952c;
  }
  piVar4 = (int *)0x0;
LAB_1030952c:
  fVar5 = (float10)FUN_1005d790(piVar4,iVar1);
  (**(code **)(*in_ECX + 0x67c))((float)fVar5 / param_3,param_2);
  return cVar2;
}



/* ==================================================================
 * callee_d1 (RVA 0x30b7e0, 25b, called by GetMagazines_caller_4)
 * Address: 0x1030b7e0  RVA: 0x30b7e0  Size: 25 bytes
 * ================================================================== */

undefined1 FUN_1030b7e0(void)

{
  int in_ECX;
  
  if ((-1 < *(int *)(in_ECX + 0x590)) && ((int *)(in_ECX + 0x590) != (int *)0x0)) {
    return *(undefined1 *)(in_ECX + 0x15b6);
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6640, 190b, called by GetMagazines_caller_5)
 * Address: 0x102a6640  RVA: 0x2a6640  Size: 190 bytes
 * ================================================================== */

int FUN_102a6640(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *in_ECX;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = 0;
  if (0 < param_1) {
    do {
      if ((int)in_ECX[5] < 1) break;
      iVar2 = in_ECX[5] + -1;
      iVar3 = iVar2 * 4;
      piVar4 = (int *)(iVar3 + in_ECX[2]);
      iVar5 = *piVar4;
      iVar7 = iVar5 - iVar6;
      if (param_1 < iVar5 - iVar6) {
        iVar7 = param_1;
      }
      if (iVar7 < iVar5) {
        *piVar4 = iVar5 - iVar7;
      }
      else {
        iVar5 = (in_ECX[5] - iVar2) + -1;
        if (0 < iVar5) {
          iVar3 = iVar3 + in_ECX[2];
          thunk_FUN_103fcbc0(iVar3,iVar3 + 4,iVar5 * 4);
        }
        in_ECX[5] = in_ECX[5] + -1;
      }
      iVar6 = iVar6 + iVar7;
    } while (iVar6 < param_1);
  }
  uVar1 = in_ECX[1];
  if ((uVar1 != 0xffffffff) &&
     (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10)) {
    FUN_1006a200(in_ECX[5],*in_ECX);
    return iVar6;
  }
  FUN_1006a200(in_ECX[5],*in_ECX);
  return iVar6;
}



/* ==================================================================
 * callee_d1 (RVA 0x27dfc0, 84b, called by GetMagazines_caller_1)
 * Address: 0x1027dfc0  RVA: 0x27dfc0  Size: 84 bytes
 * ================================================================== */

float10 FUN_1027dfc0(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  piVar1 = (int *)FUN_102bda50();
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(*piVar1 + 0x55c))();
    iVar3 = (**(code **)(*piVar1 + 0x50c))();
    return (float10)((float)iVar2 / (float)iVar3);
  }
  return (float10)0;
}



/* ==================================================================
 * callee_d1 (RVA 0x27e960, 137b, called by GetMagazines_caller_1)
 * Address: 0x1027e960  RVA: 0x27e960  Size: 137 bytes
 * ================================================================== */

undefined4 FUN_1027e960(void)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  
  piVar2 = (int *)FUN_102bda50();
  if (((piVar2 == (int *)0x0) || (cVar1 = (**(code **)(*piVar2 + 0x654))(), cVar1 == '\0')) ||
     (cVar1 = (**(code **)(*piVar2 + 0x544))(), cVar1 == '\0')) {
    return 0;
  }
  iVar3 = (**(code **)(*piVar2 + 0x52c))();
  if ((iVar3 != 0) && (iVar3 = (**(code **)(*piVar2 + 0x52c))(), iVar3 != 1)) {
    return 0;
  }
  uVar4 = (**(code **)(*piVar2 + 0x554))();
  iVar3 = FUN_10069320(uVar4);
  cVar1 = (**(code **)(*piVar2 + 0x73c))();
  if ((cVar1 != '\0') && (0 < iVar3)) {
    return 1;
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6610, 45b, called by GetMagazines_caller_1)
 * Address: 0x102a6610  RVA: 0x2a6610  Size: 45 bytes
 * ================================================================== */

uint FUN_102a6610(int param_1)

{
  int *in_EAX;
  int in_ECX;
  int iVar1;
  
  iVar1 = 0;
  if (0 < *(int *)(in_ECX + 0x14)) {
    in_EAX = *(int **)(in_ECX + 8);
    do {
      if (param_1 <= *in_EAX) {
        return CONCAT31((int3)((uint)in_EAX >> 8),1);
      }
      iVar1 = iVar1 + 1;
      in_EAX = in_EAX + 1;
    } while (iVar1 < *(int *)(in_ECX + 0x14));
  }
  return (uint)in_EAX & 0xffffff00;
}



/* ==================================================================
 * callee_d1 (RVA 0x2bda50, 36b, called by GetMagazines_caller_1)
 * Address: 0x102bda50  RVA: 0x2bda50  Size: 36 bytes
 * ================================================================== */

int * FUN_102bda50(void)

{
  char cVar1;
  int *piVar2;
  
  piVar2 = (int *)FUN_100692f0();
  if (piVar2 != (int *)0x0) {
    cVar1 = (**(code **)(*piVar2 + 0x16c))();
    if (cVar1 != '\0') {
      return piVar2;
    }
  }
  return (int *)0x0;
}



/* ==================================================================
 * callee_d1 (RVA 0x3fcb10, 145b, called by GetMagazines_caller_1)
 * Address: 0x103fcb10  RVA: 0x3fcb10  Size: 145 bytes
 * ================================================================== */

ulonglong FUN_103fcb10(void)

{
  ulonglong uVar1;
  uint uVar2;
  undefined4 in_EDX;
  float fVar3;
  float10 in_ST0;
  uint local_20;
  float fStack_1c;
  
  if (DAT_10743f38 == 0) {
    uVar1 = (ulonglong)ROUND(in_ST0);
    local_20 = (uint)uVar1;
    fStack_1c = (float)(uVar1 >> 0x20);
    fVar3 = (float)in_ST0;
    if ((local_20 != 0) || (fVar3 = fStack_1c, (uVar1 & 0x7fffffff00000000) != 0)) {
      if ((int)fVar3 < 0) {
        uVar1 = uVar1 + (0x80000000 < (uint)-(float)(in_ST0 - (float10)(longlong)uVar1));
      }
      else {
        uVar2 = (uint)(0x80000000 < (uint)(float)(in_ST0 - (float10)(longlong)uVar1));
        uVar1 = CONCAT44((int)fStack_1c - (uint)(local_20 < uVar2),local_20 - uVar2);
      }
    }
    return uVar1;
  }
  return CONCAT44(in_EDX,(int)in_ST0);
}



/* ==================================================================
 * callee_d1 (RVA 0x3fe200, 285b, called by GetMagazines_caller_1)
 * Address: 0x103fe200  RVA: 0x3fe200  Size: 285 bytes
 * ================================================================== */

float10 FUN_103fe200(double param_1,undefined2 param_2)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  ushort in_FPUControlWord;
  float10 fVar4;
  double dVar5;
  ulonglong uVar6;
  undefined4 uVar7;
  double dVar8;
  
  if ((DAT_10755f88 != 0) && ((MXCSR & 0x7f80) == 0x1f80 && (in_FPUControlWord & 0x7f) == 0x7f)) {
    uVar2 = (uint)((ulonglong)param_1 >> 0x20);
    uVar1 = uVar2 >> 0x14;
    uVar6 = (ulonglong)(0x433 - (uVar2 >> 0x14 & 0x7ff));
    if ((uVar1 & 0x800) == 0) {
      dVar5 = (double)(((ulonglong)param_1 >> uVar6) << uVar6);
      if (uVar1 < 0x3ff) {
        return (float10)(double)(-(ulonglong)(0.0 < param_1) & 0x3ff0000000000000);
      }
      if (uVar1 < 0x433) {
        return (float10)(dVar5 + (double)(-(ulonglong)(dVar5 < param_1) & 0x3ff0000000000000));
      }
    }
    else {
      if (uVar1 < 0xbff) {
        return (float10)-0.0;
      }
      if (uVar1 < 0xc33) {
        return (float10)(double)(((ulonglong)param_1 >> uVar6) << uVar6);
      }
    }
    if (NAN(param_1)) {
      FUN_1040b352(&param_1,&param_1,&param_1,0x3ec);
    }
    return (float10)(double)CONCAT26(param_1._6_2_,param_1._0_6_);
  }
  uVar2 = __ctrlfp(DAT_106372a0,0xffff);
  if ((param_1._6_2_ & 0x7ff0) == 0x7ff0) {
    iVar3 = __sptype();
    if (0 < iVar3) {
      if (iVar3 < 3) {
        __ctrlfp(uVar2,0xffff);
        return (float10)(double)CONCAT26(param_1._6_2_,param_1._0_6_);
      }
      if (iVar3 == 3) {
        fVar4 = (float10)__handle_qnan1();
        return fVar4;
      }
    }
    dVar8 = (double)CONCAT26(param_1._6_2_,param_1._0_6_);
    dVar5 = dVar8 + 1.0;
    uVar7 = 8;
  }
  else {
    fVar4 = (float10)FUN_10419c3a((int)param_1._0_6_,
                                  (int)(CONCAT26(param_1._6_2_,param_1._0_6_) >> 0x20));
    dVar5 = (double)fVar4;
    dVar8 = (double)CONCAT26(param_1._6_2_,param_1._0_6_);
    if (((NAN((float10)dVar8) || NAN(fVar4)) != ((float10)dVar8 == fVar4)) || ((uVar2 & 0x20) != 0))
    {
      __ctrlfp(uVar2,0xffff);
      return (float10)dVar5;
    }
    dVar5 = (double)fVar4;
    uVar7 = 0x10;
  }
  fVar4 = (float10)__except1(uVar7,0xc,dVar8,dVar5,uVar2);
  return fVar4;
}



/* ==================================================================
 * callee_d1 (RVA 0x55c90, 38b, called by GetMagazines_caller_3)
 * Address: 0x10055c90  RVA: 0x055c90  Size: 38 bytes
 * ================================================================== */

undefined4 FUN_10055c90(int param_1)

{
  int in_ECX;
  
  if ((-1 < param_1) && (param_1 < *(int *)(in_ECX + 4))) {
    return *(undefined4 *)(param_1 * 0xbc + 0x9c + in_ECX);
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x5e0c0, 100b, called by GetMagazines_caller_3)
 * Address: 0x1005e0c0  RVA: 0x05e0c0  Size: 100 bytes
 * ================================================================== */

void FUN_1005e0c0(int param_1)

{
  int iVar1;
  int *in_ECX;
  
  iVar1 = in_ECX[0xef];
  if (iVar1 != param_1) {
    if ((char)in_ECX[0x15] == '\0') {
      if (in_ECX[6] != 0) {
        FUN_10055020(0x3bc);
      }
    }
    else {
      *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
    }
    in_ECX[0xef] = param_1;
  }
  if (iVar1 != in_ECX[0xef]) {
    FUN_10084790(0x20);
    (**(code **)(*in_ECX + 0x324))(iVar1);
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x65870, 168b, called by GetMagazines_caller_3)
 * Address: 0x10065870  RVA: 0x065870  Size: 168 bytes
 * ================================================================== */

int FUN_10065870(int param_1,uint param_2,int param_3)

{
  char cVar1;
  int iVar2;
  int in_ECX;
  uint uVar3;
  
  if (param_1 < 1) {
    return 0;
  }
  cVar1 = (**(code **)(*DAT_106938a8 + 0x184))();
  if ((cVar1 != '\0') && (param_2 < 0x80)) {
    uVar3 = param_2;
    iVar2 = in_ECX;
    FUN_102e4660(param_2);
    iVar2 = FUN_100563b0(uVar3,iVar2);
    iVar2 = iVar2 - *(int *)(in_ECX + 0x6f8 + param_2 * 4);
    if (param_1 < iVar2) {
      iVar2 = param_1;
    }
    if (iVar2 < 1) {
      return 0;
    }
    if ((char)param_3 == '\0') {
      FUN_101a8910("BaseCombatCharacter.AmmoPickup",0,0);
    }
    param_3 = *(int *)(in_ECX + 0x6f8 + param_2 * 4) + iVar2;
    FUN_100670c0(param_2,&param_3);
    return iVar2;
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x67100, 99b, called by GetMagazines_caller_3)
 * Address: 0x10067100  RVA: 0x067100  Size: 99 bytes
 * ================================================================== */

int * FUN_10067100(int param_1)

{
  uint uVar1;
  int *piVar2;
  int *in_ECX;
  int iVar3;
  
  uVar1 = in_ECX[0x2ee];
  if ((uVar1 == 0xffffffff) ||
     (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) != uVar1 >> 0x10)) {
    iVar3 = 0;
  }
  else {
    iVar3 = *(int *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
  }
  piVar2 = in_ECX + 0x2ee;
  if (param_1 != iVar3) {
    FUN_10067040(param_1);
    piVar2 = (int *)(**(code **)(*in_ECX + 0x53c))(iVar3,param_1);
  }
  return piVar2;
}



/* ==================================================================
 * callee_d1 (RVA 0x69360, 52b, called by GetMagazines_caller_3)
 * Address: 0x10069360  RVA: 0x069360  Size: 52 bytes
 * ================================================================== */

undefined4 FUN_10069360(int param_1)

{
  uint uVar1;
  int in_ECX;
  
  uVar1 = *(uint *)(in_ECX + 0xaf8 + param_1 * 4);
  if (uVar1 != 0xffffffff) {
    if (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10) {
      return *(undefined4 *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
    }
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x6f7a0, 287b, called by GetMagazines_caller_3)
 * Address: 0x1006f7a0  RVA: 0x06f7a0  Size: 287 bytes
 * ================================================================== */

void FUN_1006f7a0(int *param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  int in_ECX;
  int iVar4;
  uint uVar5;
  
  if (param_1 == (int *)0x0) {
    if (*(int *)(in_ECX + 0x4b0) != 0) {
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020(0x4b0);
        }
      }
      else {
        *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      }
      *(undefined4 *)(in_ECX + 0x4b0) = 0;
    }
    FUN_10085b60(0,0,"BaseCombatWeapon_HideThink");
    uVar5 = 0xffffffff;
  }
  else {
    puVar2 = (uint *)(**(code **)(*param_1 + 8))();
    uVar5 = *puVar2;
    if ((uVar5 != 0xffffffff) &&
       (*(uint *)(PTR_DAT_105e1078 + (uVar5 & 0xffff) * 0x18 + 8) == uVar5 >> 0x10)) {
      iVar4 = *(int *)(PTR_DAT_105e1078 + (uVar5 & 0xffff) * 0x18 + 4);
      goto LAB_1006f835;
    }
  }
  iVar4 = 0;
LAB_1006f835:
  uVar1 = *(uint *)(in_ECX + 0x498);
  if ((uVar1 == 0xffffffff) ||
     (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) != uVar1 >> 0x10)) {
    iVar3 = 0;
  }
  else {
    iVar3 = *(int *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
  }
  puVar2 = (uint *)(in_ECX + 0x498);
  if (iVar3 != iVar4) {
    if (*(char *)(in_ECX + 0x54) != '\0') {
      *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      *puVar2 = uVar5;
      FUN_10078470();
      return;
    }
    if (*(int *)(in_ECX + 0x18) != 0) {
      FUN_10055020((int)puVar2 - in_ECX);
    }
    *puVar2 = uVar5;
  }
  FUN_10078470();
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x83f60, 174b, called by GetMagazines_caller_3)
 * Address: 0x10083f60  RVA: 0x083f60  Size: 174 bytes
 * ================================================================== */

void FUN_10083f60(int param_1,char param_2)

{
  uint uVar1;
  int *in_ECX;
  
  if (param_1 == 0) {
    FUN_10081da0();
    return;
  }
  (**(code **)(*in_ECX + 0x90))(param_1,0xffffffff);
  FUN_10080ff0(0,0);
  if ((param_2 != '\0') && (uVar1 = in_ECX[0x29], in_ECX[0x29] != (uVar1 | 1))) {
    if ((char)in_ECX[0x15] == '\0') {
      if (in_ECX[6] != 0) {
        FUN_10055020(0xa4);
      }
    }
    else {
      *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
    }
    in_ECX[0x29] = uVar1 | 1;
  }
  FUN_100a3180(*(ushort *)(in_ECX + 0x48) | 4);
  FUN_10080ad0(&DAT_10718258);
  FUN_10080750(&DAT_10718264);
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x160e50, 52b, called by GetMagazines_caller_3)
 * Address: 0x10160e50  RVA: 0x160e50  Size: 52 bytes
 * ================================================================== */

undefined4 FUN_10160e50(int param_1)

{
  uint uVar1;
  int in_ECX;
  
  uVar1 = *(uint *)(in_ECX + 0x11ec + param_1 * 4);
  if (uVar1 != 0xffffffff) {
    if (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10) {
      return *(undefined4 *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
    }
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x1d95d0, 24b, called by GetMagazines_caller_3)
 * Address: 0x101d95d0  RVA: 0x1d95d0  Size: 24 bytes
 * ================================================================== */

void FUN_101d95d0(int param_1)

{
  if (param_1 != 0) {
    FUN_101d95f0();
    return;
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6520, 208b, called by GetMagazines_caller_3)
 * Address: 0x102a6520  RVA: 0x2a6520  Size: 208 bytes
 * ================================================================== */

int FUN_102a6520(int param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 *in_ECX;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  
  uVar4 = *in_ECX;
  FUN_102e4660(uVar4);
  iVar1 = FUN_10055cc0(uVar4);
  if (iVar1 == 0) {
    return 0;
  }
  iVar3 = param_2;
  if (param_2 < 1) {
    iVar3 = *(int *)(iVar1 + 0x88);
  }
  iVar2 = param_3;
  if (param_3 < 0) {
    iVar2 = *(int *)(iVar1 + 0x84);
  }
  iVar1 = iVar2 - in_ECX[5];
  if (param_1 < iVar2 - in_ECX[5]) {
    iVar1 = param_1;
  }
  if (iVar1 < 1) {
    iVar1 = 0;
    iVar2 = 0;
    if (0 < (int)in_ECX[5]) {
      do {
        if (*(int *)(in_ECX[2] + iVar1 * 4) < iVar3) {
          iVar2 = iVar2 + 1;
          *(int *)(in_ECX[2] + iVar1 * 4) = iVar3;
          if (param_1 <= iVar2) {
            return iVar2;
          }
        }
        iVar1 = iVar1 + 1;
      } while (iVar1 < (int)in_ECX[5]);
    }
    return iVar2;
  }
  iVar2 = iVar1;
  param_2 = iVar3;
  if (0 < iVar1) {
    do {
      if (-1 < iVar3) {
        FUN_101126a0(&param_2);
        FUN_1006a200(in_ECX[5],*in_ECX);
      }
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  return iVar1;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a65f0, 31b, called by GetMagazines_caller_3)
 * Address: 0x102a65f0  RVA: 0x2a65f0  Size: 31 bytes
 * ================================================================== */

undefined4 FUN_102a65f0(int param_1)

{
  int in_ECX;
  
  if ((-1 < param_1) && (param_1 < *(int *)(in_ECX + 0x14))) {
    return *(undefined4 *)(*(int *)(in_ECX + 8) + param_1 * 4);
  }
  return 0;
}



/* ==================================================================
 * callee_d1 (RVA 0x2abea0, 223b, called by GetMagazines_caller_3)
 * Address: 0x102abea0  RVA: 0x2abea0  Size: 223 bytes
 * ================================================================== */

undefined4 FUN_102abea0(int *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int in_ECX;
  undefined4 local_10 [2];
  undefined4 local_8;
  
  piVar2 = param_1;
  iVar4 = FUN_102cb940();
  if (iVar4 == 0) {
    return 0;
  }
  local_8 = *(undefined4 *)(iVar4 + 8);
  param_1 = *(int **)(DAT_106faa1c + 0x20);
  local_10[0] = FUN_102bdf30(local_8);
  iVar5 = FUN_103b6e10(local_10);
  if (((iVar5 != -1) &&
      (puVar1 = *(undefined4 **)(*(int *)((int)param_1 + 8) + 0x14 + iVar5 * 0x18),
      puVar1 != (undefined4 *)0x0)) && (cVar3 = FUN_102b36c0(*puVar1), cVar3 == '\0')) {
    return 0;
  }
  if (0 < *(int *)(iVar4 + 4)) {
    FUN_10080ad0(in_ECX + 0x2f0);
    (**(code **)(*piVar2 + 0x3a4))();
    param_1 = (int *)(**(code **)(*piVar2 + 8))();
    param_1 = (int *)*param_1;
    FUN_102a92c0(&param_1);
  }
  iVar5 = *(int *)(iVar4 + 0x428);
  iVar6 = FUN_102bf250();
  FUN_102b48a0(iVar6 + iVar5);
  FUN_102b40a0(local_8,iVar4);
  return 1;
}



/* ==================================================================
 * callee_d1 (RVA 0x2be830, 7b, called by GetMagazines_caller_3)
 * Address: 0x102be830  RVA: 0x2be830  Size: 7 bytes
 * ================================================================== */

int FUN_102be830(void)

{
  int in_ECX;
  
  return in_ECX + 0x1dd8;
}



/* ==================================================================
 * callee_d1 (RVA 0x2df2d0, 27b, called by GetMagazines_caller_3)
 * Address: 0x102df2d0  RVA: 0x2df2d0  Size: 27 bytes
 * ================================================================== */

int FUN_102df2d0(void)

{
  int iVar1;
  int in_ECX;
  
  if (((DAT_106faa1c == 0) || (*(int *)(DAT_106faa1c + 0x24) == 0)) ||
     (iVar1 = *(int *)(in_ECX + 0x54), iVar1 == -1)) {
    iVar1 = *(int *)(in_ECX + 0x50);
  }
  return iVar1;
}



/* ==================================================================
 * callee_d1 (RVA 0x3658f0, 109b, called by GetMagazines_caller_3)
 * Address: 0x103658f0  RVA: 0x3658f0  Size: 109 bytes
 * ================================================================== */

void FUN_103658f0(int param_1)

{
  int *piVar1;
  int in_ECX;
  
  piVar1 = (int *)(in_ECX + 0x3b8);
  if (*(int *)(in_ECX + 0x3b8) != param_1) {
    if (*(char *)(in_ECX + 0x54) != '\0') {
      *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      *piVar1 = param_1;
      return;
    }
    if (*(int *)(in_ECX + 0x18) != 0) {
      FUN_10055020((int)piVar1 - in_ECX);
    }
    *piVar1 = param_1;
  }
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x55c10, 117b, called by CINSPlayer::GetMagazines)
 * Address: 0x10055c10  RVA: 0x055c10  Size: 117 bytes
 * ================================================================== */

ushort FUN_10055c10(undefined4 param_1)

{
  char cVar1;
  undefined4 *in_ECX;
  int iVar2;
  ushort uVar3;
  
  uVar3 = *(ushort *)(in_ECX + 4);
  if (uVar3 == 0xffff) {
    return 0xffff;
  }
  do {
    iVar2 = (uint)uVar3 * 0x10;
    cVar1 = (*(code *)*in_ECX)(param_1,in_ECX[1] + 8 + iVar2);
    if (cVar1 == '\0') {
      cVar1 = (*(code *)*in_ECX)(in_ECX[1] + 8 + iVar2,param_1);
      if (cVar1 == '\0') {
        return uVar3;
      }
      uVar3 = *(ushort *)(in_ECX[1] + 2 + iVar2);
    }
    else {
      uVar3 = *(ushort *)(iVar2 + in_ECX[1]);
    }
  } while (uVar3 != 0xffff);
  return 0xffff;
}



/* ==================================================================
 * callee_d1 (RVA 0x121e50, 20b, called by CINSPlayer::GetMagazines)
 * Address: 0x10121e50  RVA: 0x121e50  Size: 20 bytes
 * ================================================================== */

void FUN_10121e50(undefined4 param_1)

{
  (**(code **)(**(int **)g_pMemAlloc_exref + 4))(param_1);
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x2a6440, 222b, called by CINSPlayer::GetMagazines)
 * Address: 0x102a6440  RVA: 0x2a6440  Size: 222 bytes
 * ================================================================== */

void FUN_102a6440(int *param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 *in_ECX;
  
  in_ECX[1] = 0xffffffff;
  in_ECX[2] = 0;
  in_ECX[3] = 0;
  in_ECX[4] = 0;
  in_ECX[5] = 0;
  in_ECX[6] = in_ECX[2];
  *in_ECX = param_2;
  if (param_1 == (int *)0x0) {
    in_ECX[1] = 0xffffffff;
  }
  else {
    puVar2 = (undefined4 *)(**(code **)(*param_1 + 8))();
    in_ECX[1] = *puVar2;
  }
  FUN_102e4660(param_2,param_1);
  iVar3 = FUN_100563b0(param_2,param_1);
  iVar3 = iVar3 + 1;
  if (((int)in_ECX[3] < iVar3) && (-1 < (int)in_ECX[4])) {
    in_ECX[3] = iVar3;
    if (in_ECX[2] == 0) {
      uVar4 = FUN_10121e50(iVar3 * 4);
    }
    else {
      uVar4 = FUN_10121f20(in_ECX[2]);
    }
    in_ECX[2] = uVar4;
  }
  in_ECX[6] = in_ECX[2];
  uVar1 = in_ECX[1];
  if ((uVar1 != 0xffffffff) &&
     (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10)) {
    FUN_1006a200(in_ECX[5],*in_ECX);
    return;
  }
  FUN_1006a200(in_ECX[5],*in_ECX);
  return;
}



/* ==================================================================
 * callee_d1 (RVA 0x398cb0, 119b, called by CINSPlayer::GetMagazines)
 * Address: 0x10398cb0  RVA: 0x398cb0  Size: 119 bytes
 * ================================================================== */

undefined4 FUN_10398cb0(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  ushort uVar2;
  undefined4 *puVar3;
  int in_ECX;
  undefined4 local_c;
  undefined4 local_8;
  
  puVar1 = param_2;
  puVar3 = param_1;
  param_1 = (undefined4 *)((uint)param_1 & 0xffffff00);
  local_c = *puVar3;
  param_2 = (undefined4 *)0xffff;
  local_8 = *puVar1;
  FUN_102df210(&local_c,&param_2,&param_1);
  uVar2 = FUN_101a9ae0();
  FUN_101a9960((uint)uVar2,param_2,param_1);
  *(short *)(in_ECX + 0x12) = *(short *)(in_ECX + 0x12) + 1;
  puVar3 = (undefined4 *)(*(int *)(in_ECX + 4) + 8 + (uint)uVar2 * 0x10);
  if (puVar3 != (undefined4 *)0x0) {
    *puVar3 = local_c;
    puVar3[1] = local_8;
  }
  return CONCAT22((short)((uint)puVar3 >> 0x10),uVar2);
}



/* ==================================================================
 * callee_d1 (RVA 0x1a8910, 343b, called by CINSPlayer::GiveAmmo)
 * Address: 0x101a8910  RVA: 0x1a8910  Size: 343 bytes
 * ================================================================== */

undefined4 FUN_101a8910(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  bool bVar1;
  undefined4 uVar2;
  int in_ECX;
  int iVar3;
  undefined1 local_70 [4];
  undefined4 local_6c;
  undefined4 local_54;
  undefined4 local_50;
  undefined1 local_4a;
  int local_44;
  undefined4 local_40;
  int local_3c;
  undefined4 local_38;
  int local_34;
  undefined1 local_28 [34];
  char local_6;
  undefined1 local_5;
  
  local_6 = CVProfile::IsEnabled((CVProfile *)g_VProfCurrentProfile_exref);
  if ((bool)local_6) {
    CVProfile::EnterScope
              ((CVProfile *)g_VProfCurrentProfile_exref,"CBaseEntity::EmitSound",0,
               "CBaseEntity::EmitSound",false,4);
  }
  local_5 = DAT_105d4d7c;
  DAT_105d4d7c = 1;
  FUN_101a78b0(in_ECX,param_1);
  FUN_1008b6a0();
  local_6c = param_1;
  iVar3 = *(int *)(in_ECX + 0x18);
  local_54 = param_2;
  local_50 = param_3;
  local_4a = 1;
  if (iVar3 != 0) {
    iVar3 = iVar3 - *(int *)(DAT_106931a8 + 0x5c) >> 4;
  }
  bVar1 = CVProfile::IsEnabled((CVProfile *)g_VProfCurrentProfile_exref);
  if (bVar1) {
    CVProfile::EnterScope
              ((CVProfile *)g_VProfCurrentProfile_exref,"CBaseEntity::EmitSound",0,
               "CBaseEntity::EmitSound",false,4);
  }
  uVar2 = FUN_101a8c00(local_28,iVar3,local_70);
  if (bVar1) {
    CVProfile::ExitScope((CVProfile *)g_VProfCurrentProfile_exref);
  }
  local_38 = 0;
  if (-1 < local_3c) {
    if (local_44 != 0) {
      FUN_10121dc0(local_44);
      local_44 = 0;
    }
    local_40 = 0;
  }
  local_34 = local_44;
  if (-1 < local_3c) {
    if (local_44 != 0) {
      FUN_10121dc0(local_44);
      local_44 = 0;
    }
    local_40 = 0;
  }
  FUN_1018fdb0();
  DAT_105d4d7c = local_5;
  if (local_6 != '\0') {
    CVProfile::ExitScope((CVProfile *)g_VProfCurrentProfile_exref);
  }
  return uVar2;
}



/* ==================================================================
 * callee_d2 (RVA 0xf9b30, 16b, called by callee_d1)
 * Address: 0x100f9b30  RVA: 0x0f9b30  Size: 16 bytes
 * ================================================================== */

void FUN_100f9b30(void)

{
  (**(code **)(*DAT_1069369c + 0x180))();
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x55b80, 42b, called by callee_d1)
 * Address: 0x10055b80  RVA: 0x055b80  Size: 42 bytes
 * ================================================================== */

uint FUN_10055b80(uint param_1)

{
  int in_ECX;
  
  if ((-1 < (int)param_1) && ((int)param_1 < *(int *)(in_ECX + 4))) {
    return CONCAT31((int3)(param_1 * 0xbc >> 8),*(int *)(param_1 * 0xbc + 0x8c + in_ECX) == -1);
  }
  return param_1 & 0xffffff00;
}



/* ==================================================================
 * callee_d2 (RVA 0x5ce90, 259b, called by callee_d1)
 * Address: 0x1005ce90  RVA: 0x05ce90  Size: 259 bytes
 * ================================================================== */

int FUN_1005ce90(void)

{
  CThreadFastMutex *this;
  short sVar1;
  DWORD DVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int in_ECX;
  undefined4 uVar6;
  
  this = (CThreadFastMutex *)(in_ECX + 0x488);
  DVar2 = GetCurrentThreadId();
  if (DVar2 == *(DWORD *)this) {
LAB_1005cec6:
    *(int *)(in_ECX + 0x48c) = *(int *)(in_ECX + 0x48c) + 1;
  }
  else {
    LOCK();
    iVar3 = *(int *)this;
    if (iVar3 == 0) {
      *(DWORD *)this = DVar2;
      iVar3 = 0;
    }
    UNLOCK();
    if (iVar3 == 0) goto LAB_1005cec6;
    CThreadFastMutex::Lock(this,DVar2,0);
  }
  iVar3 = FUN_1007aea0();
  if (iVar3 == 0) goto LAB_1005cf7f;
  sVar1 = (**(code **)(*DAT_106936b4 + 0xc0))(iVar3);
  iVar3 = 0xffff;
  if (sVar1 == -1) goto LAB_1005cf7f;
  iVar3 = (**(code **)(*DAT_10717bac + 0xbc))(sVar1);
  piVar5 = *(int **)(in_ECX + 0x484);
  if (piVar5 == (int *)0x0) {
    piVar5 = (int *)0x0;
    if (iVar3 != 0) {
      iVar4 = FUN_10121e50(0x8c);
      if (iVar4 == 0) {
        piVar5 = (int *)0x0;
      }
      else {
        piVar5 = (int *)FUN_101b5230();
      }
      iVar3 = FUN_101b5da0(iVar3,DAT_10717bac);
      goto LAB_1005cf4c;
    }
  }
  else {
LAB_1005cf4c:
    if ((piVar5 != (int *)0x0) && (piVar5[1] != 0)) {
      iVar3 = *(int *)(*piVar5 + 400);
      if (iVar3 == 0) {
        uVar6 = 0;
      }
      else {
        uVar6 = *(undefined4 *)(iVar3 + 0x30 + *piVar5);
      }
      iVar3 = (**(code **)(*DAT_10717bac + 0xbc))(uVar6);
    }
  }
  *(int **)(in_ECX + 0x484) = piVar5;
LAB_1005cf7f:
  *(int *)(in_ECX + 0x48c) = *(int *)(in_ECX + 0x48c) + -1;
  if (*(int *)(in_ECX + 0x48c) == 0) {
    LOCK();
    iVar3 = *(int *)this;
    *(undefined4 *)this = 0;
    UNLOCK();
  }
  return iVar3;
}



/* ==================================================================
 * callee_d2 (RVA 0x5d790, 156b, called by callee_d1)
 * Address: 0x1005d790  RVA: 0x05d790  Size: 156 bytes
 * ================================================================== */

float10 FUN_1005d790(int *param_1,int param_2)

{
  char cVar1;
  int iVar2;
  int in_ECX;
  undefined1 *puVar3;
  float10 fVar4;
  
  if (param_1 == (int *)0x0) {
    puVar3 = &DAT_10437b75;
    if (*(undefined1 **)(in_ECX + 0x5c) != (undefined1 *)0x0) {
      puVar3 = *(undefined1 **)(in_ECX + 0x5c);
    }
    DevWarning(2,"CBaseAnimating::SequenceDuration( %d ) NULL pstudiohdr on %s!\n",param_2,puVar3);
    return (float10)0.1;
  }
  cVar1 = FUN_101b77d0();
  if (cVar1 != '\0') {
    if (param_1[1] == 0) {
      iVar2 = *(int *)(*param_1 + 0xbc);
    }
    else {
      iVar2 = FUN_101b5a90();
    }
    if ((param_2 < iVar2) && (-1 < param_2)) {
      fVar4 = (float10)FUN_10377040(param_1,param_2,in_ECX + 0x3c0);
      return fVar4;
    }
    DevWarning(2,"CBaseAnimating::SequenceDuration( %d ) out of range\n",param_2);
  }
  return (float10)0.1;
}



/* ==================================================================
 * callee_d2 (RVA 0x7aea0, 25b, called by callee_d1)
 * Address: 0x1007aea0  RVA: 0x07aea0  Size: 25 bytes
 * ================================================================== */

void FUN_1007aea0(void)

{
  int iVar1;
  undefined4 uVar2;
  int *in_ECX;
  
  iVar1 = *DAT_106936b4;
  uVar2 = (**(code **)(*in_ECX + 0x18))();
  (**(code **)(iVar1 + 4))(uVar2);
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x6a200, 43b, called by callee_d1)
 * Address: 0x1006a200  RVA: 0x06a200  Size: 43 bytes
 * ================================================================== */

void FUN_1006a200(int param_1,int param_2)

{
  int *piVar1;
  int *in_ECX;
  
  piVar1 = in_ECX + param_2 + 0x1be;
  if (*piVar1 != param_1) {
    (**(code **)(*in_ECX + 0x560))(piVar1);
    *piVar1 = param_1;
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1126a0, 95b, called by callee_d1)
 * Address: 0x101126a0  RVA: 0x1126a0  Size: 95 bytes
 * ================================================================== */

int FUN_101126a0(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  int *in_ECX;
  
  iVar3 = in_ECX[3];
  if (in_ECX[1] < iVar3 + 1) {
    FUN_102245b0((iVar3 - in_ECX[1]) + 1);
  }
  in_ECX[3] = in_ECX[3] + 1;
  iVar4 = (in_ECX[3] - iVar3) + -1;
  in_ECX[4] = *in_ECX;
  if (0 < iVar4) {
    iVar1 = *in_ECX + iVar3 * 4;
    thunk_FUN_103fcbc0(iVar1 + 4,iVar1,iVar4 * 4);
  }
  puVar2 = (undefined4 *)(*in_ECX + iVar3 * 4);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *param_1;
  }
  return iVar3;
}



/* ==================================================================
 * callee_d2 (RVA 0x39fa20, 5b, called by callee_d1)
 * Address: 0x1039fa20  RVA: 0x39fa20  Size: 5 bytes
 * ================================================================== */

/* WARNING: Control flow encountered bad instruction data */

undefined8 * thunk_FUN_103fcbc0(undefined8 *param_1,undefined8 *param_2,uint param_3)

{
  undefined8 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  int iVar14;
  undefined8 *puVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  undefined8 *puVar19;
  undefined4 *puVar20;
  undefined4 *puVar21;
  undefined4 uVar22;
  undefined4 uVar23;
  undefined4 uVar24;
  
  if ((param_2 < param_1) && (param_1 < (undefined8 *)(param_3 + (int)param_2))) {
    puVar20 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar21 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar21 & 3) == 0) {
      uVar16 = param_3 >> 2;
      param_3 = param_3 & 3;
      if (7 < uVar16) {
        for (; uVar16 != 0; uVar16 = uVar16 - 1) {
          *puVar21 = *puVar20;
          puVar20 = puVar20 + -1;
          puVar21 = puVar21 + -1;
        }
        switch(param_3) {
        case 0:
          return param_1;
        case 2:
          goto switchD_103fcf67_caseD_2;
        case 3:
          goto switchD_103fcf67_caseD_3;
        }
        goto switchD_103fcf67_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_103fcf67_caseD_0;
      case 1:
        goto switchD_103fcf67_caseD_1;
      case 2:
        goto switchD_103fcf67_caseD_2;
      case 3:
        goto switchD_103fcf67_caseD_3;
      default:
        uVar16 = param_3 - ((uint)puVar21 & 3);
        switch((uint)puVar21 & 3) {
        case 1:
          param_3 = uVar16 & 3;
          *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
          puVar20 = (undefined4 *)((int)puVar20 + -1);
          uVar16 = uVar16 >> 2;
          puVar21 = (undefined4 *)((int)puVar21 - 1);
          if (7 < uVar16) {
            for (; uVar16 != 0; uVar16 = uVar16 - 1) {
              *puVar21 = *puVar20;
              puVar20 = puVar20 + -1;
              puVar21 = puVar21 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_103fcf67_caseD_2;
            case 3:
              goto switchD_103fcf67_caseD_3;
            }
            goto switchD_103fcf67_caseD_1;
          }
          break;
        case 2:
          param_3 = uVar16 & 3;
          *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
          uVar16 = uVar16 >> 2;
          *(undefined1 *)((int)puVar21 + 2) = *(undefined1 *)((int)puVar20 + 2);
          puVar20 = (undefined4 *)((int)puVar20 + -2);
          puVar21 = (undefined4 *)((int)puVar21 - 2);
          if (7 < uVar16) {
            for (; uVar16 != 0; uVar16 = uVar16 - 1) {
              *puVar21 = *puVar20;
              puVar20 = puVar20 + -1;
              puVar21 = puVar21 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_103fcf67_caseD_2;
            case 3:
              goto switchD_103fcf67_caseD_3;
            }
            goto switchD_103fcf67_caseD_1;
          }
          break;
        case 3:
          param_3 = uVar16 & 3;
          *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
          *(undefined1 *)((int)puVar21 + 2) = *(undefined1 *)((int)puVar20 + 2);
          uVar16 = uVar16 >> 2;
          *(undefined1 *)((int)puVar21 + 1) = *(undefined1 *)((int)puVar20 + 1);
          puVar20 = (undefined4 *)((int)puVar20 + -3);
          puVar21 = (undefined4 *)((int)puVar21 - 3);
          if (7 < uVar16) {
            for (; uVar16 != 0; uVar16 = uVar16 - 1) {
              *puVar21 = *puVar20;
              puVar20 = puVar20 + -1;
              puVar21 = puVar21 + -1;
            }
            switch(param_3) {
            case 0:
              return param_1;
            case 2:
              goto switchD_103fcf67_caseD_2;
            case 3:
              goto switchD_103fcf67_caseD_3;
            }
            goto switchD_103fcf67_caseD_1;
          }
        }
      }
    }
    switch(uVar16) {
    case 7:
      puVar21[7 - uVar16] = puVar20[7 - uVar16];
    case 6:
      puVar21[6 - uVar16] = puVar20[6 - uVar16];
    case 5:
      puVar21[5 - uVar16] = puVar20[5 - uVar16];
    case 4:
      puVar21[4 - uVar16] = puVar20[4 - uVar16];
    case 3:
      puVar21[3 - uVar16] = puVar20[3 - uVar16];
    case 2:
      puVar21[2 - uVar16] = puVar20[2 - uVar16];
    case 1:
      puVar21[1 - uVar16] = puVar20[1 - uVar16];
      puVar20 = puVar20 + -uVar16;
      puVar21 = puVar21 + -uVar16;
    }
    switch(param_3) {
    case 1:
switchD_103fcf67_caseD_1:
      *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
      return param_1;
    case 2:
switchD_103fcf67_caseD_2:
      *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
      *(undefined1 *)((int)puVar21 + 2) = *(undefined1 *)((int)puVar20 + 2);
      return param_1;
    case 3:
switchD_103fcf67_caseD_3:
      *(undefined1 *)((int)puVar21 + 3) = *(undefined1 *)((int)puVar20 + 3);
      *(undefined1 *)((int)puVar21 + 2) = *(undefined1 *)((int)puVar20 + 2);
      *(undefined1 *)((int)puVar21 + 1) = *(undefined1 *)((int)puVar20 + 1);
      return param_1;
    }
switchD_103fcf67_caseD_0:
    return param_1;
  }
  puVar15 = param_1;
  if ((DAT_10743f3c >> 1 & 1) != 0) {
    for (; param_3 != 0; param_3 = param_3 - 1) {
      *(undefined1 *)puVar15 = *(undefined1 *)param_2;
      param_2 = (undefined8 *)((int)param_2 + 1);
      puVar15 = (undefined8 *)((int)puVar15 + 1);
    }
    return param_1;
  }
  if (param_3 < 0x80) {
LAB_103fcdcb:
    if (((uint)param_1 & 3) == 0) goto LAB_103fcdd3;
LAB_103fcde8:
    switch(param_3) {
    case 0:
      goto switchD_103fcde0_caseD_0;
    case 1:
      goto switchD_103fcde0_caseD_1;
    case 2:
      goto switchD_103fcde0_caseD_2;
    case 3:
      goto switchD_103fcde0_caseD_3;
    default:
      uVar16 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 0:
                    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
      case 1:
        param_3 = uVar16 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        *(undefined1 *)((int)param_1 + 1) = *(undefined1 *)((int)param_2 + 1);
        uVar16 = uVar16 >> 2;
        *(undefined1 *)((int)param_1 + 2) = *(undefined1 *)((int)param_2 + 2);
        param_2 = (undefined8 *)((int)param_2 + 3);
        puVar15 = (undefined8 *)((int)param_1 + 3);
        if (7 < uVar16) {
          for (; uVar16 != 0; uVar16 = uVar16 - 1) {
            *(undefined4 *)puVar15 = *(undefined4 *)param_2;
            param_2 = (undefined8 *)((int)param_2 + 4);
            puVar15 = (undefined8 *)((int)puVar15 + 4);
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_103fcde0_caseD_2;
          case 3:
            goto switchD_103fcde0_caseD_3;
          }
          goto switchD_103fcde0_caseD_1;
        }
        break;
      case 2:
        param_3 = uVar16 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        uVar16 = uVar16 >> 2;
        *(undefined1 *)((int)param_1 + 1) = *(undefined1 *)((int)param_2 + 1);
        param_2 = (undefined8 *)((int)param_2 + 2);
        puVar15 = (undefined8 *)((int)param_1 + 2);
        if (7 < uVar16) {
          for (; uVar16 != 0; uVar16 = uVar16 - 1) {
            *(undefined4 *)puVar15 = *(undefined4 *)param_2;
            param_2 = (undefined8 *)((int)param_2 + 4);
            puVar15 = (undefined8 *)((int)puVar15 + 4);
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_103fcde0_caseD_2;
          case 3:
            goto switchD_103fcde0_caseD_3;
          }
          goto switchD_103fcde0_caseD_1;
        }
        break;
      case 3:
        param_3 = uVar16 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        param_2 = (undefined8 *)((int)param_2 + 1);
        uVar16 = uVar16 >> 2;
        puVar15 = (undefined8 *)((int)param_1 + 1);
        if (7 < uVar16) {
          for (; uVar16 != 0; uVar16 = uVar16 - 1) {
            *(undefined4 *)puVar15 = *(undefined4 *)param_2;
            param_2 = (undefined8 *)((int)param_2 + 4);
            puVar15 = (undefined8 *)((int)puVar15 + 4);
          }
          switch(param_3) {
          case 0:
            return param_1;
          case 2:
            goto switchD_103fcde0_caseD_2;
          case 3:
            goto switchD_103fcde0_caseD_3;
          }
          goto switchD_103fcde0_caseD_1;
        }
      }
    }
  }
  else {
    if (((((uint)param_1 ^ (uint)param_2) & 0xf) == 0) && ((DAT_10636890 >> 1 & 1) != 0)) {
      if (((uint)param_2 & 0xf) != 0) {
        uVar17 = 0x10 - ((uint)param_2 & 0xf);
        param_3 = param_3 - uVar17;
        for (uVar16 = uVar17 & 3; uVar16 != 0; uVar16 = uVar16 - 1) {
          *(undefined1 *)puVar15 = *(undefined1 *)param_2;
          param_2 = (undefined8 *)((int)param_2 + 1);
          puVar15 = (undefined8 *)((int)puVar15 + 1);
        }
        for (uVar17 = uVar17 >> 2; uVar17 != 0; uVar17 = uVar17 - 1) {
          *(undefined4 *)puVar15 = *(undefined4 *)param_2;
          param_2 = (undefined8 *)((int)param_2 + 4);
          puVar15 = (undefined8 *)((int)puVar15 + 4);
        }
      }
      for (uVar16 = param_3 >> 7; uVar16 != 0; uVar16 = uVar16 - 1) {
        uVar22 = *(undefined4 *)((int)param_2 + 4);
        uVar23 = *(undefined4 *)(param_2 + 1);
        uVar24 = *(undefined4 *)((int)param_2 + 0xc);
        uVar2 = *(undefined4 *)(param_2 + 2);
        uVar3 = *(undefined4 *)((int)param_2 + 0x14);
        uVar4 = *(undefined4 *)(param_2 + 3);
        uVar5 = *(undefined4 *)((int)param_2 + 0x1c);
        uVar6 = *(undefined4 *)(param_2 + 4);
        uVar7 = *(undefined4 *)((int)param_2 + 0x24);
        uVar8 = *(undefined4 *)(param_2 + 5);
        uVar9 = *(undefined4 *)((int)param_2 + 0x2c);
        uVar10 = *(undefined4 *)(param_2 + 6);
        uVar11 = *(undefined4 *)((int)param_2 + 0x34);
        uVar12 = *(undefined4 *)(param_2 + 7);
        uVar13 = *(undefined4 *)((int)param_2 + 0x3c);
        *(undefined4 *)puVar15 = *(undefined4 *)param_2;
        *(undefined4 *)((int)puVar15 + 4) = uVar22;
        *(undefined4 *)(puVar15 + 1) = uVar23;
        *(undefined4 *)((int)puVar15 + 0xc) = uVar24;
        *(undefined4 *)(puVar15 + 2) = uVar2;
        *(undefined4 *)((int)puVar15 + 0x14) = uVar3;
        *(undefined4 *)(puVar15 + 3) = uVar4;
        *(undefined4 *)((int)puVar15 + 0x1c) = uVar5;
        *(undefined4 *)(puVar15 + 4) = uVar6;
        *(undefined4 *)((int)puVar15 + 0x24) = uVar7;
        *(undefined4 *)(puVar15 + 5) = uVar8;
        *(undefined4 *)((int)puVar15 + 0x2c) = uVar9;
        *(undefined4 *)(puVar15 + 6) = uVar10;
        *(undefined4 *)((int)puVar15 + 0x34) = uVar11;
        *(undefined4 *)(puVar15 + 7) = uVar12;
        *(undefined4 *)((int)puVar15 + 0x3c) = uVar13;
        uVar22 = *(undefined4 *)((int)param_2 + 0x44);
        uVar23 = *(undefined4 *)(param_2 + 9);
        uVar24 = *(undefined4 *)((int)param_2 + 0x4c);
        uVar2 = *(undefined4 *)(param_2 + 10);
        uVar3 = *(undefined4 *)((int)param_2 + 0x54);
        uVar4 = *(undefined4 *)(param_2 + 0xb);
        uVar5 = *(undefined4 *)((int)param_2 + 0x5c);
        uVar6 = *(undefined4 *)(param_2 + 0xc);
        uVar7 = *(undefined4 *)((int)param_2 + 100);
        uVar8 = *(undefined4 *)(param_2 + 0xd);
        uVar9 = *(undefined4 *)((int)param_2 + 0x6c);
        uVar10 = *(undefined4 *)(param_2 + 0xe);
        uVar11 = *(undefined4 *)((int)param_2 + 0x74);
        uVar12 = *(undefined4 *)(param_2 + 0xf);
        uVar13 = *(undefined4 *)((int)param_2 + 0x7c);
        *(undefined4 *)(puVar15 + 8) = *(undefined4 *)(param_2 + 8);
        *(undefined4 *)((int)puVar15 + 0x44) = uVar22;
        *(undefined4 *)(puVar15 + 9) = uVar23;
        *(undefined4 *)((int)puVar15 + 0x4c) = uVar24;
        *(undefined4 *)(puVar15 + 10) = uVar2;
        *(undefined4 *)((int)puVar15 + 0x54) = uVar3;
        *(undefined4 *)(puVar15 + 0xb) = uVar4;
        *(undefined4 *)((int)puVar15 + 0x5c) = uVar5;
        *(undefined4 *)(puVar15 + 0xc) = uVar6;
        *(undefined4 *)((int)puVar15 + 100) = uVar7;
        *(undefined4 *)(puVar15 + 0xd) = uVar8;
        *(undefined4 *)((int)puVar15 + 0x6c) = uVar9;
        *(undefined4 *)(puVar15 + 0xe) = uVar10;
        *(undefined4 *)((int)puVar15 + 0x74) = uVar11;
        *(undefined4 *)(puVar15 + 0xf) = uVar12;
        *(undefined4 *)((int)puVar15 + 0x7c) = uVar13;
        param_2 = param_2 + 0x10;
        puVar15 = puVar15 + 0x10;
      }
      if ((param_3 & 0x7f) != 0) {
        for (uVar16 = (param_3 & 0x7f) >> 4; uVar16 != 0; uVar16 = uVar16 - 1) {
          uVar22 = *(undefined4 *)((int)param_2 + 4);
          uVar23 = *(undefined4 *)(param_2 + 1);
          uVar24 = *(undefined4 *)((int)param_2 + 0xc);
          *(undefined4 *)puVar15 = *(undefined4 *)param_2;
          *(undefined4 *)((int)puVar15 + 4) = uVar22;
          *(undefined4 *)(puVar15 + 1) = uVar23;
          *(undefined4 *)((int)puVar15 + 0xc) = uVar24;
          param_2 = param_2 + 2;
          puVar15 = puVar15 + 2;
        }
        if ((param_3 & 0xf) != 0) {
          for (uVar16 = (param_3 & 0xf) >> 2; uVar16 != 0; uVar16 = uVar16 - 1) {
            *(undefined4 *)puVar15 = *(undefined4 *)param_2;
            param_2 = (undefined8 *)((int)param_2 + 4);
            puVar15 = (undefined8 *)((int)puVar15 + 4);
          }
          for (param_3 = param_3 & 3; param_3 != 0; param_3 = param_3 - 1) {
            *(undefined1 *)puVar15 = *(undefined1 *)param_2;
            param_2 = (undefined8 *)((int)param_2 + 1);
            puVar15 = (undefined8 *)((int)puVar15 + 1);
          }
        }
      }
      return param_1;
    }
    if ((DAT_10743f3c & 1) == 0) goto LAB_103fcdcb;
    if (((uint)param_1 & 3) != 0) goto LAB_103fcde8;
    if (((uint)param_2 & 3) == 0) {
      if (((uint)param_1 >> 2 & 1) != 0) {
        uVar22 = *(undefined4 *)param_2;
        param_3 = param_3 - 4;
        param_2 = (undefined8 *)((int)param_2 + 4);
        *(undefined4 *)param_1 = uVar22;
        param_1 = (undefined8 *)((int)param_1 + 4);
      }
      if (((uint)param_1 >> 3 & 1) != 0) {
        uVar1 = *param_2;
        param_3 = param_3 - 8;
        param_2 = param_2 + 1;
        *param_1 = uVar1;
        param_1 = param_1 + 1;
      }
      if (((uint)param_2 & 7) == 0) {
        puVar15 = param_2 + -1;
        uVar22 = *(undefined4 *)param_2;
        uVar23 = *(undefined4 *)((int)param_2 + 4);
        do {
          puVar19 = puVar15;
          uVar3 = *(undefined4 *)(puVar19 + 4);
          uVar4 = *(undefined4 *)((int)puVar19 + 0x24);
          param_3 = param_3 - 0x30;
          uVar5 = *(undefined4 *)(puVar19 + 3);
          uVar6 = *(undefined4 *)((int)puVar19 + 0x1c);
          uVar7 = *(undefined4 *)(puVar19 + 4);
          uVar8 = *(undefined4 *)((int)puVar19 + 0x24);
          uVar24 = *(undefined4 *)(puVar19 + 7);
          uVar2 = *(undefined4 *)((int)puVar19 + 0x3c);
          uVar9 = *(undefined4 *)(puVar19 + 5);
          uVar10 = *(undefined4 *)((int)puVar19 + 0x2c);
          uVar11 = *(undefined4 *)(puVar19 + 6);
          uVar12 = *(undefined4 *)((int)puVar19 + 0x34);
          *(undefined4 *)(param_1 + 1) = uVar22;
          *(undefined4 *)((int)param_1 + 0xc) = uVar23;
          *(undefined4 *)(param_1 + 2) = uVar3;
          *(undefined4 *)((int)param_1 + 0x14) = uVar4;
          *(undefined4 *)(param_1 + 3) = uVar5;
          *(undefined4 *)((int)param_1 + 0x1c) = uVar6;
          *(undefined4 *)(param_1 + 4) = uVar7;
          *(undefined4 *)((int)param_1 + 0x24) = uVar8;
          *(undefined4 *)(param_1 + 5) = uVar9;
          *(undefined4 *)((int)param_1 + 0x2c) = uVar10;
          *(undefined4 *)(param_1 + 6) = uVar11;
          *(undefined4 *)((int)param_1 + 0x34) = uVar12;
          param_1 = param_1 + 6;
          puVar15 = puVar19 + 6;
          uVar22 = uVar24;
          uVar23 = uVar2;
        } while (0x2f < (int)param_3);
        puVar19 = puVar19 + 7;
      }
      else if (((uint)param_2 >> 3 & 1) == 0) {
        iVar14 = (int)param_2 + -4;
        uVar22 = *(undefined4 *)param_2;
        uVar23 = *(undefined4 *)((int)param_2 + 4);
        uVar24 = *(undefined4 *)(param_2 + 1);
        do {
          iVar18 = iVar14;
          uVar5 = *(undefined4 *)(iVar18 + 0x20);
          param_3 = param_3 - 0x30;
          uVar6 = *(undefined4 *)(iVar18 + 0x14);
          uVar7 = *(undefined4 *)(iVar18 + 0x18);
          uVar8 = *(undefined4 *)(iVar18 + 0x1c);
          uVar9 = *(undefined4 *)(iVar18 + 0x20);
          uVar2 = *(undefined4 *)(iVar18 + 0x34);
          uVar3 = *(undefined4 *)(iVar18 + 0x38);
          uVar4 = *(undefined4 *)(iVar18 + 0x3c);
          uVar10 = *(undefined4 *)(iVar18 + 0x24);
          uVar11 = *(undefined4 *)(iVar18 + 0x28);
          uVar12 = *(undefined4 *)(iVar18 + 0x2c);
          uVar13 = *(undefined4 *)(iVar18 + 0x30);
          *(undefined4 *)((int)param_1 + 4) = uVar22;
          *(undefined4 *)(param_1 + 1) = uVar23;
          *(undefined4 *)((int)param_1 + 0xc) = uVar24;
          *(undefined4 *)(param_1 + 2) = uVar5;
          *(undefined4 *)((int)param_1 + 0x14) = uVar6;
          *(undefined4 *)(param_1 + 3) = uVar7;
          *(undefined4 *)((int)param_1 + 0x1c) = uVar8;
          *(undefined4 *)(param_1 + 4) = uVar9;
          *(undefined4 *)((int)param_1 + 0x24) = uVar10;
          *(undefined4 *)(param_1 + 5) = uVar11;
          *(undefined4 *)((int)param_1 + 0x2c) = uVar12;
          *(undefined4 *)(param_1 + 6) = uVar13;
          param_1 = param_1 + 6;
          iVar14 = iVar18 + 0x30;
          uVar22 = uVar2;
          uVar23 = uVar3;
          uVar24 = uVar4;
        } while (0x2f < (int)param_3);
        puVar19 = (undefined8 *)(iVar18 + 0x34);
      }
      else {
        iVar14 = (int)param_2 + -0xc;
        uVar22 = *(undefined4 *)param_2;
        do {
          iVar18 = iVar14;
          uVar24 = *(undefined4 *)(iVar18 + 0x20);
          uVar2 = *(undefined4 *)(iVar18 + 0x24);
          uVar3 = *(undefined4 *)(iVar18 + 0x28);
          param_3 = param_3 - 0x30;
          uVar4 = *(undefined4 *)(iVar18 + 0x1c);
          uVar5 = *(undefined4 *)(iVar18 + 0x20);
          uVar6 = *(undefined4 *)(iVar18 + 0x24);
          uVar7 = *(undefined4 *)(iVar18 + 0x28);
          uVar23 = *(undefined4 *)(iVar18 + 0x3c);
          uVar8 = *(undefined4 *)(iVar18 + 0x2c);
          uVar9 = *(undefined4 *)(iVar18 + 0x30);
          uVar10 = *(undefined4 *)(iVar18 + 0x34);
          uVar11 = *(undefined4 *)(iVar18 + 0x38);
          *(undefined4 *)((int)param_1 + 0xc) = uVar22;
          *(undefined4 *)(param_1 + 2) = uVar24;
          *(undefined4 *)((int)param_1 + 0x14) = uVar2;
          *(undefined4 *)(param_1 + 3) = uVar3;
          *(undefined4 *)((int)param_1 + 0x1c) = uVar4;
          *(undefined4 *)(param_1 + 4) = uVar5;
          *(undefined4 *)((int)param_1 + 0x24) = uVar6;
          *(undefined4 *)(param_1 + 5) = uVar7;
          *(undefined4 *)((int)param_1 + 0x2c) = uVar8;
          *(undefined4 *)(param_1 + 6) = uVar9;
          *(undefined4 *)((int)param_1 + 0x34) = uVar10;
          *(undefined4 *)(param_1 + 7) = uVar11;
          param_1 = param_1 + 6;
          iVar14 = iVar18 + 0x30;
          uVar22 = uVar23;
        } while (0x2f < (int)param_3);
        puVar19 = (undefined8 *)(iVar18 + 0x3c);
      }
      for (; 0xf < (int)param_3; param_3 = param_3 - 0x10) {
        uVar22 = *(undefined4 *)puVar19;
        uVar23 = *(undefined4 *)((int)puVar19 + 4);
        uVar24 = *(undefined4 *)(puVar19 + 1);
        uVar2 = *(undefined4 *)((int)puVar19 + 0xc);
        puVar19 = puVar19 + 2;
        *(undefined4 *)param_1 = uVar22;
        *(undefined4 *)((int)param_1 + 4) = uVar23;
        *(undefined4 *)(param_1 + 1) = uVar24;
        *(undefined4 *)((int)param_1 + 0xc) = uVar2;
        param_1 = param_1 + 2;
      }
      if ((param_3 >> 2 & 1) != 0) {
        uVar22 = *(undefined4 *)puVar19;
        param_3 = param_3 - 4;
        puVar19 = (undefined8 *)((int)puVar19 + 4);
        *(undefined4 *)param_1 = uVar22;
        param_1 = (undefined8 *)((int)param_1 + 4);
      }
      if ((param_3 >> 3 & 1) != 0) {
        param_3 = param_3 - 8;
        *param_1 = *puVar19;
      }
                    /* WARNING: Could not recover jumptable at 0x103fcdc9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      puVar15 = (undefined8 *)(*(code *)(&switchD_103fcde0::switchdataD_103fcef8)[param_3])();
      return puVar15;
    }
LAB_103fcdd3:
    uVar16 = param_3 >> 2;
    param_3 = param_3 & 3;
    if (7 < uVar16) {
      for (; uVar16 != 0; uVar16 = uVar16 - 1) {
        *(undefined4 *)puVar15 = *(undefined4 *)param_2;
        param_2 = (undefined8 *)((int)param_2 + 4);
        puVar15 = (undefined8 *)((int)puVar15 + 4);
      }
      switch(param_3) {
      case 0:
        return param_1;
      case 2:
        goto switchD_103fcde0_caseD_2;
      case 3:
        goto switchD_103fcde0_caseD_3;
      }
      goto switchD_103fcde0_caseD_1;
    }
  }
  switch(uVar16) {
  case 7:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -0x1c) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -0x1c);
  case 6:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -0x18) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -0x18);
  case 5:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -0x14) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -0x14);
  case 4:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -0x10) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -0x10);
  case 3:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -0xc) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -0xc);
  case 2:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -8) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -8);
  case 1:
    *(undefined4 *)((int)puVar15 + uVar16 * 4 + -4) =
         *(undefined4 *)((int)param_2 + uVar16 * 4 + -4);
    param_2 = (undefined8 *)((int)param_2 + uVar16 * 4);
    puVar15 = (undefined8 *)((int)puVar15 + uVar16 * 4);
  }
  switch(param_3) {
  case 0:
switchD_103fcde0_caseD_0:
    return param_1;
  case 2:
switchD_103fcde0_caseD_2:
    *(undefined1 *)puVar15 = *(undefined1 *)param_2;
    *(undefined1 *)((int)puVar15 + 1) = *(undefined1 *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_103fcde0_caseD_3:
    *(undefined1 *)puVar15 = *(undefined1 *)param_2;
    *(undefined1 *)((int)puVar15 + 1) = *(undefined1 *)((int)param_2 + 1);
    *(undefined1 *)((int)puVar15 + 2) = *(undefined1 *)((int)param_2 + 2);
    return param_1;
  }
switchD_103fcde0_caseD_1:
  *(undefined1 *)puVar15 = *(undefined1 *)param_2;
  return param_1;
}



/* ==================================================================
 * callee_d2 (RVA 0x2c8680, 186b, called by callee_d1)
 * Address: 0x102c8680  RVA: 0x2c8680  Size: 186 bytes
 * ================================================================== */

void FUN_102c8680(int *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  int *piVar2;
  uint *puVar3;
  undefined **local_30 [8];
  undefined1 local_10 [12];
  
  uVar1 = (**(code **)(*param_1 + 0x208))(local_10);
  FUN_1018fc70();
  local_30[0] = CPVSFilter::vftable;
  FUN_10190090(uVar1);
  if (DAT_106e6e20 != 0xffffffff) {
    if (*(uint *)(PTR_DAT_105e1078 + (DAT_106e6e20 & 0xffff) * 0x18 + 8) == DAT_106e6e20 >> 0x10) {
      piVar2 = *(int **)(PTR_DAT_105e1078 + (DAT_106e6e20 & 0xffff) * 0x18 + 4);
      goto LAB_102c86de;
    }
  }
  piVar2 = (int *)0x0;
LAB_102c86de:
  if (piVar2 != param_1) {
    puVar3 = (uint *)(**(code **)(*param_1 + 8))();
    DAT_106e6e20 = *puVar3;
  }
  if (DAT_106e6e24 != param_2) {
    DAT_106e6e24 = param_2;
  }
  if (DAT_106e6e28 != param_3) {
    DAT_106e6e28 = param_3;
  }
  FUN_103602d0(local_30,0);
  FUN_1018fdb0();
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x304ec0, 105b, called by callee_d1)
 * Address: 0x10304ec0  RVA: 0x304ec0  Size: 105 bytes
 * ================================================================== */

int * FUN_10304ec0(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int in_ECX;
  int local_c [2];
  
  local_c[0] = *(int *)(in_ECX + 0x41a4 + param_1 * 4);
  if (local_c[0] < 0) {
    return (int *)0x0;
  }
  piVar2 = (int *)(param_1 * 0x444 + 0x1670 + in_ECX);
  if (-1 < *piVar2) {
    return piVar2;
  }
  iVar1 = *(int *)(DAT_106faa1c + 0x18);
  if ((iVar1 != 0) && (iVar3 = FUN_103b6e10(local_c), iVar3 != -1)) {
    return *(int **)(*(int *)(iVar1 + 8) + 0x14 + iVar3 * 0x18);
  }
  return (int *)0x0;
}



/* ==================================================================
 * callee_d2 (RVA 0x2bef00, 7b, called by callee_d1)
 * Address: 0x102bef00  RVA: 0x2bef00  Size: 7 bytes
 * ================================================================== */

float10 FUN_102bef00(void)

{
  int in_ECX;
  
  return (float10)*(float *)(in_ECX + 0x1914);
}



/* ==================================================================
 * callee_d2 (RVA 0x3b6e10, 105b, called by callee_d1)
 * Address: 0x103b6e10  RVA: 0x3b6e10  Size: 105 bytes
 * ================================================================== */

int FUN_103b6e10(undefined4 param_1)

{
  char cVar1;
  undefined4 *in_ECX;
  int iVar2;
  int iVar3;
  
  iVar3 = in_ECX[4];
  if (iVar3 == -1) {
    return -1;
  }
  do {
    iVar2 = iVar3 * 0x18;
    cVar1 = (*(code *)*in_ECX)(param_1,in_ECX[1] + 0x10 + iVar2);
    if (cVar1 == '\0') {
      cVar1 = (*(code *)*in_ECX)(in_ECX[1] + 0x10 + iVar2,param_1);
      if (cVar1 == '\0') {
        return iVar3;
      }
      iVar3 = *(int *)(in_ECX[1] + 4 + iVar2);
    }
    else {
      iVar3 = *(int *)(iVar2 + in_ECX[1]);
    }
  } while (iVar3 != -1);
  return -1;
}



/* ==================================================================
 * callee_d2 (RVA 0x309580, 118b, called by callee_d1)
 * Address: 0x10309580  RVA: 0x309580  Size: 118 bytes
 * ================================================================== */

undefined4 FUN_10309580(undefined4 param_1,undefined4 param_2)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int *in_ECX;
  
  piVar2 = (int *)FUN_1006d660();
  if (piVar2 != (int *)0x0) {
    cVar1 = (**(code **)(*piVar2 + 0x154))();
    if (cVar1 != '\0') {
      cVar1 = (**(code **)(*in_ECX + 0x3f4))(param_1);
      if (cVar1 != '\0') {
        FUN_10057ad0(param_2);
        iVar3 = FUN_10160e50(0);
        if (iVar3 != 0) {
          FUN_10057ad0(param_2);
        }
        return 1;
      }
    }
  }
  return 0;
}



/* ==================================================================
 * callee_d2 (RVA 0x692f0, 39b, called by callee_d1)
 * Address: 0x100692f0  RVA: 0x0692f0  Size: 39 bytes
 * ================================================================== */

undefined4 FUN_100692f0(void)

{
  uint uVar1;
  int in_ECX;
  
  uVar1 = *(uint *)(in_ECX + 3000);
  if (uVar1 != 0xffffffff) {
    if (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10) {
      return *(undefined4 *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
    }
  }
  return 0;
}



/* ==================================================================
 * callee_d2 (RVA 0x40b352, 688b, called by callee_d1)
 * Address: 0x1040b352  RVA: 0x40b352  Size: 688 bytes
 * ================================================================== */

void FUN_1040b352(double *param_1,undefined8 *param_2,double *param_3,int param_4)

{
  code *pcVar1;
  int iVar2;
  int *piVar3;
  undefined4 local_2c;
  char *local_28;
  double local_24;
  undefined8 local_1c;
  double local_14;
  undefined4 local_c;
  undefined4 uStack_8;
  
  local_c = 0;
  uStack_8 = 0;
  if (DAT_1074434c == 0) {
    pcVar1 = FUN_10104920;
  }
  else {
    pcVar1 = (code *)DecodePointer(DAT_10755f8c);
  }
  if (param_4 < 0xa7) {
    if (param_4 == 0xa6) {
      local_2c = 3;
      local_28 = "exp10";
LAB_1040b3e8:
      local_24 = *param_1;
      local_1c = *param_2;
      local_14 = *param_3;
      iVar2 = (*pcVar1)(&local_2c);
      if (iVar2 == 0) {
        piVar3 = __errno();
        *piVar3 = 0x22;
      }
    }
    else {
      if (0x19 < param_4) {
        if (param_4 == 0x1a) {
          *param_3 = 1.0;
          return;
        }
        if (param_4 != 0x1b) {
          if (param_4 == 0x1c) goto switchD_1040b538_caseD_3ee;
          if (param_4 != 0x1d) {
            if (param_4 == 0x31) goto switchD_1040b538_caseD_3f5;
            if (param_4 != 0x3a) {
              if (param_4 != 0x3d) {
                return;
              }
              goto switchD_1040b538_caseD_3f1;
            }
            goto switchD_1040b538_caseD_3f0;
          }
          local_28 = "pow";
          goto LAB_1040b4e4;
        }
        local_2c = 2;
LAB_1040b3e1:
        local_28 = "pow";
        goto LAB_1040b3e8;
      }
      if (param_4 != 0x19) {
        local_2c = 2;
        if (param_4 == 2) {
          local_2c = 2;
          local_28 = "log";
        }
        else {
          if (param_4 == 3) {
            local_28 = "log";
            goto LAB_1040b5c9;
          }
          if (param_4 == 8) {
            local_28 = "log10";
          }
          else {
            if (param_4 == 9) {
              local_28 = "log10";
              goto LAB_1040b5c9;
            }
            if (param_4 != 0xe) {
              if (param_4 != 0xf) {
                if (param_4 != 0x18) {
                  return;
                }
                local_2c = 3;
                goto LAB_1040b3e1;
              }
              local_28 = "exp";
              goto LAB_1040b426;
            }
            local_2c = 3;
            local_28 = "exp";
          }
        }
        goto LAB_1040b3e8;
      }
      local_28 = "pow";
LAB_1040b426:
      local_2c = 4;
      local_24 = *param_1;
      local_1c = *param_2;
      local_14 = *param_3;
      (*pcVar1)(&local_2c);
    }
    goto LAB_1040b5f8;
  }
  switch(param_4) {
  case 1000:
    local_28 = "log";
    break;
  case 0x3e9:
    local_28 = "log10";
    break;
  case 0x3ea:
    local_28 = "exp";
    break;
  case 0x3eb:
    local_28 = "atan";
    break;
  case 0x3ec:
    local_28 = "ceil";
    break;
  case 0x3ed:
    local_28 = "floor";
    break;
  case 0x3ee:
switchD_1040b538_caseD_3ee:
    local_28 = "pow";
    goto LAB_1040b5c9;
  case 0x3ef:
    local_28 = "modf";
    break;
  case 0x3f0:
switchD_1040b538_caseD_3f0:
    local_28 = "acos";
    goto LAB_1040b5c9;
  case 0x3f1:
switchD_1040b538_caseD_3f1:
    local_28 = "asin";
    goto LAB_1040b5c9;
  case 0x3f2:
    local_28 = "sin";
    goto LAB_1040b58e;
  case 0x3f3:
    local_28 = "cos";
    goto LAB_1040b58e;
  case 0x3f4:
    local_28 = "tan";
LAB_1040b58e:
    local_14 = *param_1 * (double)CONCAT44(uStack_8,local_c);
    *param_3 = local_14;
    local_24 = *param_1;
    local_1c = *param_2;
    goto LAB_1040b5d8;
  case 0x3f5:
switchD_1040b538_caseD_3f5:
    local_28 = "sqrt";
    goto LAB_1040b5c9;
  default:
    goto switchD_1040b538_default;
  }
LAB_1040b4e4:
  *param_3 = *param_1;
LAB_1040b5c9:
  local_24 = *param_1;
  local_1c = *param_2;
  local_14 = *param_3;
LAB_1040b5d8:
  local_2c = 1;
  iVar2 = (*pcVar1)(&local_2c);
  if (iVar2 == 0) {
    piVar3 = __errno();
    *piVar3 = 0x21;
  }
LAB_1040b5f8:
  *param_3 = local_14;
switchD_1040b538_default:
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x84790, 362b, called by callee_d1)
 * Address: 0x10084790  RVA: 0x084790  Size: 362 bytes
 * ================================================================== */

/* WARNING: Removing unreachable block (ram,0x10084841) */

void FUN_10084790(uint param_1)

{
  uint *puVar1;
  uint uVar2;
  char cVar3;
  int *piVar4;
  int *in_ECX;
  undefined *puVar5;
  uint uVar6;
  int iVar7;
  bool bVar8;
  
  uVar6 = 0;
  bVar8 = false;
  if ((param_1 & 4) != 0) {
    uVar6 = 0x1000;
  }
  if ((param_1 & 1) != 0) {
    puVar1 = (uint *)in_ECX[6];
    uVar6 = uVar6 | 0x800;
    if (puVar1 != (uint *)0x0) {
      *puVar1 = *puVar1 | 0x80;
    }
    if ((in_ECX[6] != 0) && (in_ECX[6] - *(int *)(DAT_106931a8 + 0x5c) >> 4 != 0)) {
      FUN_100a24e0();
    }
  }
  if ((param_1 & 2) != 0) {
    uVar6 = uVar6 | 0x800;
    cVar3 = FUN_10083e80();
    bVar8 = cVar3 != '\0';
    if (bVar8) {
      FUN_100a2510();
    }
    param_1 = param_1 | 5;
  }
  if ((param_1 & 0x20) != 0) {
    if ((!bVar8) && (*(char *)((int)in_ECX + 0x12a) == '\a')) {
      FUN_100a2510();
    }
    param_1 = param_1 & 0xffffffdf;
  }
  in_ECX[0x32] = in_ECX[0x32] | uVar6;
  bVar8 = (param_1 & 0x18) != 0;
  uVar6 = param_1;
  if (bVar8) {
    uVar6 = 7;
  }
  uVar2 = in_ECX[0x38];
  if (uVar2 != 0xffffffff) {
    puVar5 = PTR_DAT_105e1078;
    if (*(uint *)(PTR_DAT_105e1078 + (uVar2 & 0xffff) * 0x18 + 8) == uVar2 >> 0x10) {
      iVar7 = *(int *)(PTR_DAT_105e1078 + (uVar2 & 0xffff) * 0x18 + 4);
    }
    else {
      iVar7 = 0;
    }
    while (iVar7 != 0) {
      if ((!bVar8 || (param_1 & 7) != 0) || (*(char *)(iVar7 + 0xd9) != '\0')) {
        FUN_10084790(uVar6);
        puVar5 = PTR_DAT_105e1078;
      }
      uVar2 = *(uint *)(iVar7 + 0xe4);
      if (uVar2 == 0xffffffff) break;
      if (*(uint *)(puVar5 + (uVar2 & 0xffff) * 0x18 + 8) == uVar2 >> 0x10) {
        iVar7 = *(int *)(puVar5 + (uVar2 & 0xffff) * 0x18 + 4);
      }
      else {
        iVar7 = 0;
      }
    }
  }
  if (((uVar6 & 0xb) != 0) &&
     (piVar4 = (int *)(**(code **)(*in_ECX + 0xd8))(), piVar4 != (int *)0x0)) {
    (**(code **)(*piVar4 + 0x370))();
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x563b0, 38b, called by callee_d1)
 * Address: 0x100563b0  RVA: 0x0563b0  Size: 38 bytes
 * ================================================================== */

undefined4 FUN_100563b0(int param_1)

{
  int in_ECX;
  
  if ((-1 < param_1) && (param_1 < *(int *)(in_ECX + 4))) {
    return *(undefined4 *)(param_1 * 0xbc + 0x8c + in_ECX);
  }
  return 0;
}



/* ==================================================================
 * callee_d2 (RVA 0x670c0, 49b, called by callee_d1)
 * Address: 0x100670c0  RVA: 0x0670c0  Size: 49 bytes
 * ================================================================== */

void FUN_100670c0(int param_1,int *param_2)

{
  int *piVar1;
  int in_ECX;
  
  piVar1 = (int *)(in_ECX + param_1 * 4);
  if (*piVar1 != *param_2) {
    (**(code **)(*(int *)(in_ECX + -0x6f8) + 0x560))(piVar1);
    *piVar1 = *param_2;
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x67040, 126b, called by callee_d1)
 * Address: 0x10067040  RVA: 0x067040  Size: 126 bytes
 * ================================================================== */

int * FUN_10067040(int *param_1)

{
  uint uVar1;
  int *piVar2;
  uint *puVar3;
  uint *in_ECX;
  
  uVar1 = *in_ECX;
  if (uVar1 != 0xffffffff) {
    if (*(uint *)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 8) == uVar1 >> 0x10) {
      piVar2 = *(int **)(PTR_DAT_105e1078 + (uVar1 & 0xffff) * 0x18 + 4);
      goto LAB_1006706a;
    }
  }
  piVar2 = (int *)0x0;
LAB_1006706a:
  if (piVar2 != param_1) {
    if ((char)in_ECX[-0x2d9] == '\0') {
      if (in_ECX[-0x2e8] != 0) {
        FUN_10055020(3000);
      }
    }
    else {
      *(byte *)(in_ECX + -0x2d8) = (byte)in_ECX[-0x2d8] | 1;
    }
    if (param_1 != (int *)0x0) {
      puVar3 = (uint *)(**(code **)(*param_1 + 8))();
      *in_ECX = *puVar3;
      return param_1;
    }
    *in_ECX = 0xffffffff;
  }
  return param_1;
}



/* ==================================================================
 * callee_d2 (RVA 0x78470, 40b, called by callee_d1)
 * Address: 0x10078470  RVA: 0x078470  Size: 40 bytes
 * ================================================================== */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_10078470(void)

{
  undefined4 uVar1;
  int *in_ECX;
  
  if ((char)in_ECX[0x36] == '\0') {
    _DAT_1064f700 = _DAT_1064f700 + 1;
    uVar1 = (**(code **)(*in_ECX + 0x4c))();
    _DAT_1064f700 = _DAT_1064f700 + -1;
    return uVar1;
  }
  if ((undefined4 *)in_ECX[6] != (undefined4 *)0x0) {
    return *(undefined4 *)in_ECX[6];
  }
  return 0;
}



/* ==================================================================
 * callee_d2 (RVA 0x85b60, 150b, called by callee_d1)
 * Address: 0x10085b60  RVA: 0x085b60  Size: 150 bytes
 * ================================================================== */

undefined4 FUN_10085b60(undefined4 param_1,float param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int in_ECX;
  
  if (param_3 == 0) {
    *(undefined4 *)(in_ECX + 8) = param_1;
    return param_1;
  }
  iVar1 = FUN_10084050(param_3);
  if (iVar1 == -1) {
    iVar1 = FUN_100853a0(param_3);
  }
  *(undefined4 *)(*(int *)(in_ECX + 0x74) + iVar1 * 0x10) = param_1;
  if (NAN(param_2) == (param_2 == 0.0)) {
    if (NAN(param_2) == (param_2 == -1.0)) {
      iVar2 = (int)(param_2 / *(float *)(DAT_106931a8 + 0x1c) + 0.5);
    }
    else {
      iVar2 = -1;
    }
    *(int *)(*(int *)(in_ECX + 0x74) + 8 + iVar1 * 0x10) = iVar2;
    FUN_10083bb0(iVar2 != -1);
  }
  return param_1;
}



/* ==================================================================
 * callee_d2 (RVA 0x80750, 670b, called by callee_d1)
 * Address: 0x10080750  RVA: 0x080750  Size: 670 bytes
 * ================================================================== */

void FUN_10080750(float *param_1)

{
  float *pfVar1;
  float *pfVar2;
  float fVar3;
  int iVar4;
  char cVar5;
  undefined4 uVar6;
  int in_ECX;
  float fVar7;
  float local_18;
  float fStack_14;
  
  fVar7 = -DAT_105d70bc;
  if (((((*param_1 <= fVar7) || (DAT_105d70bc <= *param_1)) || (param_1[1] <= fVar7)) ||
      ((DAT_105d70bc <= param_1[1] || (param_1[2] <= fVar7)))) || (DAT_105d70bc <= param_1[2])) {
    cVar5 = FUN_10083a10();
    if (cVar5 != '\0') {
      uVar6 = FUN_1007ac40();
      Warning("Bad SetLocalAngles(%f,%f,%f) on %s\n",(double)*param_1,(double)param_1[1],
              (double)param_1[2],uVar6);
      return;
    }
  }
  else {
    pfVar2 = (float *)(in_ECX + 0x2fc);
    local_18 = (float)*(undefined8 *)param_1;
    if ((((NAN(local_18) || NAN(*pfVar2)) == (local_18 == *pfVar2)) ||
        (fStack_14 = (float)((ulonglong)*(undefined8 *)param_1 >> 0x20),
        (NAN(fStack_14) || NAN(*(float *)(in_ECX + 0x300))) ==
        (fStack_14 == *(float *)(in_ECX + 0x300)))) ||
       ((NAN(param_1[2]) || NAN(*(float *)(in_ECX + 0x304))) ==
        (param_1[2] == *(float *)(in_ECX + 0x304)))) {
      FUN_10084790();
      fVar7 = *param_1;
      if ((NAN(*pfVar2) || NAN(fVar7)) == (*pfVar2 == fVar7)) {
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020();
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *pfVar2 = fVar7;
      }
      fVar7 = param_1[1];
      fVar3 = *(float *)(in_ECX + 0x300);
      if ((NAN(fVar3) || NAN(fVar7)) == (fVar3 == fVar7)) {
        if ((float *)(in_ECX + 0x300) != pfVar2) {
          if (*(char *)(in_ECX + 0x54) == '\0') {
            if (*(int *)(in_ECX + 0x18) != 0) {
              FUN_10055020();
            }
          }
          else {
            *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
          }
        }
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020();
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *(float *)(in_ECX + 0x300) = fVar7;
      }
      fVar7 = param_1[2];
      pfVar1 = (float *)(in_ECX + 0x304);
      if ((NAN(*pfVar1) || NAN(fVar7)) == (*pfVar1 == fVar7)) {
        if (pfVar1 != pfVar2) {
          if (*(char *)(in_ECX + 0x54) == '\0') {
            if (*(int *)(in_ECX + 0x18) != 0) {
              FUN_10055020();
            }
          }
          else {
            *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
          }
        }
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020();
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *pfVar1 = fVar7;
      }
      iVar4 = *(int *)(DAT_106931a8 + 0xc);
      if (*(int *)(in_ECX + 0x68) != iVar4) {
        if (*(char *)(in_ECX + 0x54) != '\0') {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
          *(int *)(in_ECX + 0x68) = iVar4;
          return;
        }
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020();
        }
        *(int *)(in_ECX + 0x68) = iVar4;
      }
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x80ad0, 488b, called by callee_d1)
 * Address: 0x10080ad0  RVA: 0x080ad0  Size: 488 bytes
 * ================================================================== */

void FUN_10080ad0(float *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  int in_ECX;
  float fVar5;
  float local_1c;
  float fStack_18;
  
  fVar5 = -DAT_105d70b8;
  if (((((*param_1 <= fVar5) || (DAT_105d70b8 <= *param_1)) || (param_1[1] <= fVar5)) ||
      ((DAT_105d70b8 <= param_1[1] || (param_1[2] <= fVar5)))) || (DAT_105d70b8 <= param_1[2])) {
    cVar3 = FUN_10083a10();
    if (cVar3 != '\0') {
      uVar4 = FUN_1007ac40();
      Warning("Bad SetLocalOrigin(%f,%f,%f) on %s\n",(double)*param_1,(double)param_1[1],
              (double)param_1[2],uVar4);
      return;
    }
  }
  else {
    local_1c = (float)*(undefined8 *)param_1;
    if ((((NAN(local_1c) || NAN(*(float *)(in_ECX + 0x2f0))) ==
          (local_1c == *(float *)(in_ECX + 0x2f0))) ||
        (fStack_18 = (float)((ulonglong)*(undefined8 *)param_1 >> 0x20),
        (NAN(fStack_18) || NAN(*(float *)(in_ECX + 0x2f4))) ==
        (fStack_18 == *(float *)(in_ECX + 0x2f4)))) ||
       ((NAN(param_1[2]) || NAN(*(float *)(in_ECX + 0x2f8))) ==
        (param_1[2] == *(float *)(in_ECX + 0x2f8)))) {
      FUN_10084790();
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020();
        }
      }
      else {
        *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      }
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020();
        }
      }
      else {
        *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      }
      piVar1 = (int *)(in_ECX + 0x68);
      *(float *)(in_ECX + 0x2f0) = *param_1;
      *(float *)(in_ECX + 0x2f4) = param_1[1];
      *(float *)(in_ECX + 0x2f8) = param_1[2];
      iVar2 = *(int *)(DAT_106931a8 + 0xc);
      if (*piVar1 != iVar2) {
        if (*(char *)(in_ECX + 0x54) != '\0') {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
          *piVar1 = iVar2;
          FUN_10082630();
          return;
        }
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020();
        }
        *piVar1 = iVar2;
      }
      FUN_10082630();
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x80ff0, 502b, called by callee_d1)
 * Address: 0x10080ff0  RVA: 0x080ff0  Size: 502 bytes
 * ================================================================== */

void FUN_10080ff0(uint param_1,char param_2)

{
  char cVar1;
  uint uVar2;
  char cVar3;
  int in_ECX;
  
  uVar2 = (uint)*(byte *)(in_ECX + 0xda);
  if (uVar2 == param_1) {
    if (*(char *)(in_ECX + 0xdb) != param_2) {
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020(0xdb);
        }
        *(char *)(in_ECX + 0xdb) = param_2;
        return;
      }
      *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      *(char *)(in_ECX + 0xdb) = param_2;
      return;
    }
  }
  else {
    if (*(byte *)(in_ECX + 0xda) == 8) {
      *(uint *)(in_ECX + 200) = *(uint *)(in_ECX + 200) & 0xfffffffb;
    }
    if ((((param_1 == 7) || (param_1 == 0)) || (param_1 == 6)) || (param_1 == 8)) {
      cVar3 = '\0';
    }
    else {
      cVar3 = '\x01';
    }
    if (((uVar2 == 7) || (uVar2 == 0)) || ((uVar2 == 6 || (uVar2 == 8)))) {
      cVar1 = '\0';
    }
    else {
      cVar1 = '\x01';
    }
    if (cVar3 != cVar1) {
      FUN_100a24e0();
    }
    if (*(char *)(in_ECX + 0xda) != (char)param_1) {
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020(0xda);
        }
      }
      else {
        *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      }
      *(char *)(in_ECX + 0xda) = (char)param_1;
    }
    if (*(char *)(in_ECX + 0xdb) != param_2) {
      if (*(char *)(in_ECX + 0x54) == '\0') {
        if (*(int *)(in_ECX + 0x18) != 0) {
          FUN_10055020(0xdb);
        }
      }
      else {
        *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      }
      *(char *)(in_ECX + 0xdb) = param_2;
    }
    FUN_10083c50();
    switch(*(undefined1 *)(in_ECX + 0xda)) {
    case 2:
      FUN_10081a40(1);
      FUN_10080550(1);
      break;
    case 3:
      FUN_10081a40(DAT_105fc00c != '\0');
      FUN_10080550(0);
      break;
    case 4:
    case 5:
      FUN_10146c90();
      break;
    default:
      if (*(char *)(in_ECX + 0x229) != '\x01') {
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020(0x229);
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *(undefined1 *)(in_ECX + 0x229) = 1;
      }
      if (*(char *)(in_ECX + 0x22a) != '\0') {
        if (*(char *)(in_ECX + 0x54) == '\0') {
          if (*(int *)(in_ECX + 0x18) != 0) {
            FUN_10055020(0x22a);
          }
        }
        else {
          *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
        }
        *(undefined1 *)(in_ECX + 0x22a) = 0;
      }
    }
    FUN_1013e620();
    FUN_10083b20();
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x81da0, 187b, called by callee_d1)
 * Address: 0x10081da0  RVA: 0x081da0  Size: 187 bytes
 * ================================================================== */

void FUN_10081da0(void)

{
  uint *puVar1;
  uint uVar2;
  int *in_ECX;
  
  puVar1 = (uint *)(in_ECX + 0x29);
  if ((((*(byte *)(in_ECX + 0x29) & 1) != 0) && (*(char *)((int)in_ECX + 0xda) == '\0')) &&
     (uVar2 = in_ECX[0x37], uVar2 != 0xffffffff)) {
    if ((*(uint *)(PTR_DAT_105e1078 + (uVar2 & 0xffff) * 0x18 + 8) == uVar2 >> 0x10) &&
       (*(int *)(PTR_DAT_105e1078 + (uVar2 & 0xffff) * 0x18 + 4) != 0)) {
      (**(code **)(*in_ECX + 0x90))(0,0xffffffff);
      uVar2 = *puVar1;
      if (*puVar1 != (uVar2 & 0xfffffffe)) {
        if ((char)in_ECX[0x15] == '\0') {
          if (in_ECX[6] != 0) {
            FUN_10055020((int)puVar1 - (int)in_ECX);
          }
        }
        else {
          *(byte *)(in_ECX + 0x16) = *(byte *)(in_ECX + 0x16) | 1;
        }
        *puVar1 = uVar2 & 0xfffffffe;
      }
      FUN_100a3180(*(ushort *)(in_ECX + 0x48) & 0xfffb);
      FUN_10080ff0(0,0);
      FUN_10083c50();
      return;
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0xa3180, 190b, called by callee_d1)
 * Address: 0x100a3180  RVA: 0x0a3180  Size: 190 bytes
 * ================================================================== */

void FUN_100a3180(ushort param_1)

{
  ushort *puVar1;
  ushort uVar2;
  int iVar3;
  char cVar4;
  undefined4 uVar5;
  int *in_ECX;
  
  puVar1 = (ushort *)(in_ECX + 0xe);
  uVar2 = *puVar1;
  if (*puVar1 != param_1) {
    (**(code **)(*in_ECX + 0x4c))(puVar1);
    *puVar1 = param_1;
  }
  if (uVar2 != *puVar1) {
    if (((*puVar1 ^ uVar2) & 0xc0) != 0) {
      FUN_100a2510();
    }
    if ((uVar2 & 0xc) != (*puVar1 & 0xc)) {
      FUN_10083c50();
    }
    if ((uVar2 & 0xc) != (*puVar1 & 0xc)) {
      if ((short)in_ECX[0x10] != -1) {
        iVar3 = *DAT_106936ac;
        uVar5 = FUN_100a1c00((short)in_ECX[0x10]);
        (**(code **)(iVar3 + 0x18))(0xffffffff,uVar5);
      }
      if (((*(char *)((int)in_ECX + 0x3a) == '\0') || ((*puVar1 & 4) != 0)) &&
         (((byte)*puVar1 >> 3 & 1) == 0)) {
        cVar4 = FUN_10143d90();
        if (cVar4 != '\0') {
          FUN_100805a0(1);
        }
      }
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1d95f0, 105b, called by callee_d1)
 * Address: 0x101d95f0  RVA: 0x1d95f0  Size: 105 bytes
 * ================================================================== */

void FUN_101d95f0(int *param_1)

{
  char cVar1;
  int *piVar2;
  
  if (param_1 != (int *)0x0) {
    cVar1 = FUN_101a5020();
    if (cVar1 == '\0') {
      cVar1 = FUN_10136fc0();
      if (cVar1 != '\0') {
        FUN_101362f0(param_1);
        return;
      }
      FUN_101a5030();
      piVar2 = (int *)(**(code **)(*param_1 + 0x1c))();
      if (piVar2 != (int *)0x0) {
        DAT_106c34a5 = 0;
        (**(code **)(*piVar2 + 0x1c0))();
        FUN_10081200(0);
      }
      FUN_100bab60(param_1);
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x2a92c0, 83b, called by callee_d1)
 * Address: 0x102a92c0  RVA: 0x2a92c0  Size: 83 bytes
 * ================================================================== */

undefined4 FUN_102a92c0(undefined4 *param_1)

{
  int iVar1;
  int *in_ECX;
  
  if (in_ECX[1] < in_ECX[3] + 1) {
    FUN_102245b0((in_ECX[3] - in_ECX[1]) + 1);
  }
  in_ECX[3] = in_ECX[3] + 1;
  iVar1 = *in_ECX;
  in_ECX[4] = iVar1;
  if (0 < in_ECX[3] + -1) {
    thunk_FUN_103fcbc0(iVar1 + 4,iVar1,(in_ECX[3] + -1) * 4);
  }
  if ((undefined4 *)*in_ECX != (undefined4 *)0x0) {
    *(undefined4 *)*in_ECX = *param_1;
  }
  return 0;
}



/* ==================================================================
 * callee_d2 (RVA 0x2b36c0, 369b, called by callee_d1)
 * Address: 0x102b36c0  RVA: 0x2b36c0  Size: 369 bytes
 * ================================================================== */

undefined4 FUN_102b36c0(undefined4 param_1)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int in_ECX;
  undefined4 local_c;
  undefined1 local_8 [4];
  
  iVar2 = *(int *)(DAT_106faa1c + 0x20);
  local_c = param_1;
  iVar5 = FUN_103b6e10(&local_c);
  if ((iVar5 == -1) || (iVar2 = *(int *)(*(int *)(iVar2 + 8) + 0x14 + iVar5 * 0x18), iVar2 == 0)) {
    return 0;
  }
  if (0 < *(int *)(iVar2 + 4)) {
    iVar5 = *(int *)(in_ECX + 0x1e4c);
    do {
      iVar5 = iVar5 + -1;
      if (iVar5 < 0) goto LAB_102b37a2;
      uVar3 = *(uint *)(*(int *)(in_ECX + 0x1e40) + iVar5 * 4);
    } while ((((uVar3 == 0xffffffff) ||
              (*(uint *)(PTR_DAT_105e1078 + (uVar3 & 0xffff) * 0x18 + 8) != uVar3 >> 0x10)) ||
             (piVar4 = *(int **)(PTR_DAT_105e1078 + (uVar3 & 0xffff) * 0x18 + 4),
             piVar4 == (int *)0x0)) ||
            (piVar6 = (int *)FUN_102cb980(local_8), *piVar6 != *(int *)(iVar2 + 0x10)));
    (**(code **)(*piVar4 + 0x3a8))();
    iVar7 = (*(int *)(in_ECX + 0x1e4c) - iVar5) + -1;
    if (0 < iVar7) {
      iVar5 = *(int *)(in_ECX + 0x1e40) + iVar5 * 4;
      thunk_FUN_103fcbc0(iVar5,iVar5 + 4,iVar7 * 4);
    }
    *(int *)(in_ECX + 0x1e4c) = *(int *)(in_ECX + 0x1e4c) + -1;
  }
LAB_102b37a2:
  iVar5 = *(int *)(iVar2 + 0x428);
  iVar2 = *(int *)(iVar2 + 8);
  iVar7 = FUN_102bf250();
  FUN_102b48a0(iVar7 - iVar5);
  iVar5 = in_ECX + 0x1e54;
  puVar1 = (undefined4 *)(iVar5 + iVar2 * 4);
  if (*(int *)(iVar5 + iVar2 * 4) != -1) {
    if (*(char *)(in_ECX + 0x54) != '\0') {
      *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      *puVar1 = 0xffffffff;
      return 1;
    }
    if (*(int *)(in_ECX + 0x18) != 0) {
      FUN_10055020((iVar2 * 4 - in_ECX) + iVar5);
    }
    *puVar1 = 0xffffffff;
  }
  return 1;
}



/* ==================================================================
 * callee_d2 (RVA 0x2b40a0, 89b, called by callee_d1)
 * Address: 0x102b40a0  RVA: 0x2b40a0  Size: 89 bytes
 * ================================================================== */

void FUN_102b40a0(int param_1,int *param_2)

{
  int *piVar1;
  int in_ECX;
  
  piVar1 = (int *)(in_ECX + param_1 * 4);
  if (*piVar1 != *param_2) {
    if (*(char *)(in_ECX + -0x1e00) != '\0') {
      *(byte *)(in_ECX + -0x1dfc) = *(byte *)(in_ECX + -0x1dfc) | 1;
      *piVar1 = *param_2;
      return;
    }
    if (*(int *)(in_ECX + -0x1e3c) != 0) {
      FUN_10055020(param_1 * 4 + 0x1e54);
    }
    *piVar1 = *param_2;
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x2b48a0, 122b, called by callee_d1)
 * Address: 0x102b48a0  RVA: 0x2b48a0  Size: 122 bytes
 * ================================================================== */

void FUN_102b48a0(int param_1)

{
  int *piVar1;
  int in_ECX;
  int iVar2;
  
  iVar2 = *(int *)(in_ECX + 0x1878);
  if ((*(int *)(in_ECX + 0x1878) <= param_1) &&
     (iVar2 = param_1, *(int *)(in_ECX + 0x1874) < param_1)) {
    iVar2 = *(int *)(in_ECX + 0x1874);
  }
  piVar1 = (int *)(in_ECX + 0x1e3c);
  if (*(int *)(in_ECX + 0x1e3c) != iVar2) {
    if (*(char *)(in_ECX + 0x54) != '\0') {
      *(byte *)(in_ECX + 0x58) = *(byte *)(in_ECX + 0x58) | 1;
      *piVar1 = iVar2;
      FUN_10230310(iVar2,iVar2);
      return;
    }
    if (*(int *)(in_ECX + 0x18) != 0) {
      FUN_10055020((int)piVar1 - in_ECX);
    }
    *piVar1 = iVar2;
    FUN_10230310(iVar2,iVar2);
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x2bdf30, 17b, called by callee_d1)
 * Address: 0x102bdf30  RVA: 0x2bdf30  Size: 17 bytes
 * ================================================================== */

undefined4 FUN_102bdf30(int param_1)

{
  int in_ECX;
  
  return *(undefined4 *)(in_ECX + 0x1e54 + param_1 * 4);
}



/* ==================================================================
 * callee_d2 (RVA 0x2bf250, 7b, called by callee_d1)
 * Address: 0x102bf250  RVA: 0x2bf250  Size: 7 bytes
 * ================================================================== */

undefined4 FUN_102bf250(void)

{
  int in_ECX;
  
  return *(undefined4 *)(in_ECX + 0x1e3c);
}



/* ==================================================================
 * callee_d2 (RVA 0x2cb940, 63b, called by callee_d1)
 * Address: 0x102cb940  RVA: 0x2cb940  Size: 63 bytes
 * ================================================================== */

undefined4 FUN_102cb940(void)

{
  int iVar1;
  int iVar2;
  int in_ECX;
  undefined4 local_c [2];
  
  iVar1 = *(int *)(DAT_106faa1c + 0x20);
  local_c[0] = *(undefined4 *)(in_ECX + 0x498);
  iVar2 = FUN_103b6e10(local_c);
  if (iVar2 == -1) {
    return 0;
  }
  return *(undefined4 *)(*(int *)(iVar1 + 8) + 0x14 + iVar2 * 0x18);
}



/* ==================================================================
 * callee_d2 (RVA 0x121f20, 23b, called by callee_d1)
 * Address: 0x10121f20  RVA: 0x121f20  Size: 23 bytes
 * ================================================================== */

void FUN_10121f20(undefined4 param_1,undefined4 param_2)

{
  (**(code **)(**(int **)g_pMemAlloc_exref + 0xc))(param_1,param_2);
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1a9960, 122b, called by callee_d1)
 * Address: 0x101a9960  RVA: 0x1a9960  Size: 122 bytes
 * ================================================================== */

void FUN_101a9960(uint param_1,ushort param_2,char param_3)

{
  undefined4 *puVar1;
  int in_ECX;
  undefined2 uVar2;
  
  puVar1 = (undefined4 *)((param_1 & 0xffff) * 0x10 + *(int *)(in_ECX + 4));
  *(ushort *)(puVar1 + 1) = param_2;
  *puVar1 = 0xffffffff;
  *(undefined2 *)((int)puVar1 + 6) = 0;
  uVar2 = (undefined2)param_1;
  if (param_2 == 0xffff) {
    *(undefined2 *)(in_ECX + 0x10) = uVar2;
    FUN_10022ae0(param_1);
    return;
  }
  if (param_3 != '\0') {
    *(undefined2 *)(*(int *)(in_ECX + 4) + (uint)param_2 * 0x10) = uVar2;
    FUN_10022ae0(param_1);
    return;
  }
  *(undefined2 *)(*(int *)(in_ECX + 4) + 2 + (uint)param_2 * 0x10) = uVar2;
  FUN_10022ae0(param_1);
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1a9ae0, 256b, called by callee_d1)
 * Address: 0x101a9ae0  RVA: 0x1a9ae0  Size: 256 bytes
 * ================================================================== */

uint FUN_101a9ae0(void)

{
  ushort uVar1;
  int in_ECX;
  int iVar2;
  
  uVar1 = *(ushort *)(in_ECX + 0x14);
  if (uVar1 == 0xffff) {
    iVar2 = *(int *)(in_ECX + 8);
    if ((int)(uint)*(ushort *)(in_ECX + 0x16) < iVar2) {
      uVar1 = *(short *)(in_ECX + 0x16) + 1;
      if (iVar2 <= (int)(uint)(ushort)(*(short *)(in_ECX + 0x16) + 1)) {
        uVar1 = 0xffff;
      }
    }
    else {
      iVar2 = *(int *)(in_ECX + 8);
      uVar1 = 0xffff;
      if (0 < iVar2) {
        uVar1 = 0;
      }
    }
    if (iVar2 <= (int)(uint)uVar1) {
      FUN_1014eb30(1);
      iVar2 = *(int *)(in_ECX + 8);
      if ((int)(uint)*(ushort *)(in_ECX + 0x16) < iVar2) {
        uVar1 = *(short *)(in_ECX + 0x16) + 1;
        if (iVar2 <= (int)(uint)(ushort)(*(short *)(in_ECX + 0x16) + 1)) {
          uVar1 = 0xffff;
        }
      }
      else {
        iVar2 = *(int *)(in_ECX + 8);
        uVar1 = 0xffff;
        if (0 < iVar2) {
          uVar1 = 0;
        }
      }
      if (iVar2 <= (int)(uint)uVar1) {
        Error("CUtlRBTree overflow!\n");
      }
    }
    *(ushort *)(in_ECX + 0x16) = uVar1;
    *(undefined4 *)(in_ECX + 0x18) = *(undefined4 *)(in_ECX + 4);
    return (uint)uVar1;
  }
  *(undefined2 *)(in_ECX + 0x14) = *(undefined2 *)(*(int *)(in_ECX + 4) + 2 + (uint)uVar1 * 0x10);
  *(undefined4 *)(in_ECX + 0x18) = *(undefined4 *)(in_ECX + 4);
  return (uint)uVar1;
}



/* ==================================================================
 * callee_d2 (RVA 0x2df210, 109b, called by callee_d1)
 * Address: 0x102df210  RVA: 0x2df210  Size: 109 bytes
 * ================================================================== */

void FUN_102df210(undefined4 param_1,ushort *param_2,undefined1 *param_3)

{
  ushort uVar1;
  char cVar2;
  undefined4 *in_ECX;
  int iVar3;
  
  uVar1 = *(ushort *)(in_ECX + 4);
  *param_2 = 0xffff;
  *param_3 = 0;
  while (uVar1 != 0xffff) {
    *param_2 = uVar1;
    iVar3 = (uint)uVar1 * 0x10;
    cVar2 = (*(code *)*in_ECX)(param_1,in_ECX[1] + 8 + iVar3);
    if (cVar2 == '\0') {
      *param_3 = 0;
      uVar1 = *(ushort *)(iVar3 + 2 + in_ECX[1]);
    }
    else {
      *param_3 = 1;
      uVar1 = *(ushort *)(iVar3 + in_ECX[1]);
    }
  }
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x8b6a0, 130b, called by callee_d1)
 * Address: 0x1008b6a0  RVA: 0x08b6a0  Size: 130 bytes
 * ================================================================== */

void FUN_1008b6a0(void)

{
  undefined4 *in_ECX;
  
  *in_ECX = 0;
  in_ECX[1] = 0;
  in_ECX[2] = 0x3f800000;
  in_ECX[3] = 0;
  in_ECX[4] = 0;
  in_ECX[5] = 100;
  in_ECX[6] = 0;
  in_ECX[7] = 0;
  in_ECX[8] = 0;
  *(undefined2 *)(in_ECX + 9) = 1;
  *(undefined1 *)((int)in_ECX + 0x26) = 0;
  in_ECX[10] = 0xffffffff;
  in_ECX[0xb] = 0;
  in_ECX[0xc] = 0;
  in_ECX[0xd] = 0;
  in_ECX[0xf] = in_ECX[0xb];
  in_ECX[0xe] = 0;
  in_ECX[0x10] = 0xffffffff;
  in_ECX[0x11] = 1;
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x121dc0, 20b, called by callee_d1)
 * Address: 0x10121dc0  RVA: 0x121dc0  Size: 20 bytes
 * ================================================================== */

void FUN_10121dc0(undefined4 param_1)

{
  (**(code **)(**(int **)g_pMemAlloc_exref + 0x14))(param_1);
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x18fdb0, 99b, called by callee_d1)
 * Address: 0x1018fdb0  RVA: 0x18fdb0  Size: 99 bytes
 * ================================================================== */

void FUN_1018fdb0(void)

{
  int iVar1;
  undefined4 *in_ECX;
  
  *in_ECX = CRecipientFilter::vftable;
  in_ECX[5] = 0;
  if (-1 < (int)in_ECX[4]) {
    if (in_ECX[2] != 0) {
      FUN_10121dc0(in_ECX[2]);
      in_ECX[2] = 0;
    }
    in_ECX[3] = 0;
  }
  iVar1 = in_ECX[2];
  in_ECX[6] = iVar1;
  if (-1 < (int)in_ECX[4]) {
    if (iVar1 != 0) {
      FUN_10121dc0(iVar1);
      in_ECX[2] = 0;
    }
    in_ECX[3] = 0;
  }
  *in_ECX = IRecipientFilter::vftable;
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1a78b0, 156b, called by callee_d1)
 * Address: 0x101a78b0  RVA: 0x1a78b0  Size: 156 bytes
 * ================================================================== */

void FUN_101a78b0(int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *in_ECX;
  float fVar3;
  undefined1 *puVar4;
  undefined1 local_10 [12];
  
  uVar1 = (**(code **)(*param_1 + 0x260))(local_10);
  FUN_1018fc70();
  *in_ECX = CPASFilter::vftable;
  FUN_10190030(uVar1);
  *in_ECX = CPASAttenuationFilter::vftable;
  iVar2 = (**(code **)(*DAT_10693178 + 0x48))(param_2);
  if (iVar2 < 0x33) {
    if (iVar2 == 0) {
      fVar3 = 0.0;
    }
    else {
      fVar3 = 4.0;
    }
  }
  else {
    fVar3 = 20.0 / (float)(iVar2 + -0x32);
  }
  puVar4 = local_10;
  uVar1 = (**(code **)(*param_1 + 0x260))(puVar4,fVar3);
  FUN_101901a0(uVar1,puVar4);
  return;
}



/* ==================================================================
 * callee_d2 (RVA 0x1a8c00, 152b, called by callee_d1)
 * Address: 0x101a8c00  RVA: 0x1a8c00  Size: 152 bytes
 * ================================================================== */

void FUN_101a8c00(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  char *pcVar3;
  
  pcVar3 = *(char **)(param_3 + 4);
  if (pcVar3 != (char *)0x0) {
    iVar1 = FUN_1039f5a0(pcVar3,&DAT_1050d240);
    if (iVar1 == 0) {
      iVar1 = FUN_1039f5a0(*(undefined4 *)(param_3 + 4),&DAT_1050d248);
      if (iVar1 == 0) {
        iVar1 = FUN_1039f5a0(*(undefined4 *)(param_3 + 4),&DAT_1050d250);
        if ((iVar1 == 0) && (pcVar3 = *(char **)(param_3 + 4), *pcVar3 != '!')) goto LAB_101a8c67;
      }
    }
    FUN_101a8f00(param_1,param_2,param_3);
    return;
  }
LAB_101a8c67:
  if (*(int *)(param_3 + 0x40) == -1) {
    uVar2 = (**(code **)(*DAT_10693178 + 0xc0))(pcVar3);
    *(undefined4 *)(param_3 + 0x40) = uVar2;
  }
  FUN_101a8ca0(param_1,param_2,param_3,(undefined4 *)(param_3 + 0x40));
  return;
}



