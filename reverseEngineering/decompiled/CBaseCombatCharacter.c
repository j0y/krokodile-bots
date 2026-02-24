/*
 * CBaseCombatCharacter -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 9
 */

/* ----------------------------------------
 * CBaseCombatCharacter::GetAmmoCount
 * Address: 001cc930  Size: 93 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::GetAmmoCount(int) const */

undefined4 __thiscall CBaseCombatCharacter::GetAmmoCount(CBaseCombatCharacter *this,int param_1)

{
  char cVar1;
  int iVar2;
  CAmmoDef *this_00;
  undefined4 extraout_EDX;
  undefined4 uVar3;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  uVar3 = extraout_EDX;
  if (in_stack_00000008 != -1) {
    iVar2 = GetAmmoDef();
    cVar1 = CAmmoDef::CanCarryInfiniteAmmo(this_00,iVar2);
    uVar3 = 999;
    if (cVar1 == '\0') {
      return *(undefined4 *)(param_1 + 0x70c + in_stack_00000008 * 4);
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CBaseCombatCharacter::GetAmmoCount
 * Address: 001cca90  Size: 72 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::GetAmmoCount(char*) const */

void __cdecl CBaseCombatCharacter::GetAmmoCount(char *param_1)

{
  char *pcVar1;
  CAmmoDef *this;
  CBaseCombatCharacter *this_00;
  
  __i686_get_pc_thunk_bx();
  pcVar1 = (char *)GetAmmoDef();
  CAmmoDef::Index(this,pcVar1);
  GetAmmoCount(this_00,(int)param_1);
  return;
}



/* ----------------------------------------
 * CBaseCombatCharacter::GiveAmmo
 * Address: 003b0380  Size: 323 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::GiveAmmo(int, int, bool) */

int __cdecl CBaseCombatCharacter::GiveAmmo(int param_1,int param_2,bool param_3)

{
  void *__s1;
  char cVar1;
  int iVar2;
  char extraout_CL;
  int extraout_EDX;
  int iVar3;
  int unaff_EBX;
  undefined3 in_stack_0000000d;
  int local_38;
  int local_2c [7];
  
  __i686_get_pc_thunk_bx();
  iVar3 = extraout_EDX;
  if (((0 < param_2) &&
      (cVar1 = (**(code **)(*(int *)**(undefined4 **)(&DAT_007f655e + unaff_EBX) + 0x184))
                         ((int *)**(undefined4 **)(&DAT_007f655e + unaff_EBX),param_1,_param_3),
      cVar1 != '\0')) && (_param_3 < (CBaseCombatCharacter *)0x80)) {
    iVar2 = GetAmmoDef();
    iVar2 = CAmmoDef::MaxCarry(iVar2,_param_3);
    local_38 = *(int *)(param_1 + 0x70c + (int)_param_3 * 4);
    iVar2 = iVar2 - local_38;
    if ((param_2 < iVar2) || (param_2 = iVar2, 0 < iVar2)) {
      iVar3 = param_2;
      if (extraout_CL == '\0') {
        CBaseEntity::EmitSound
                  ((CBaseEntity *)param_1,(char *)param_1,(float)(unaff_EBX + 0x59887a),(float *)0x0
                  );
        local_38 = *(int *)(param_1 + 0x70c + (int)_param_3 * 4);
      }
      __s1 = (void *)(param_1 + 0x70c + (int)_param_3 * 4);
      local_2c[0] = local_38 + iVar3;
      iVar2 = memcmp(__s1,local_2c,4);
      if (iVar2 != 0) {
        (**(code **)(*(int *)param_1 + 0x568))(param_1,__s1);
        *(int *)(param_1 + 0x70c + (int)_param_3 * 4) = local_38 + iVar3;
      }
    }
  }
  return iVar3;
}



/* ----------------------------------------
 * CBaseCombatCharacter::GiveAmmo
 * Address: 003b6d90  Size: 137 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::GiveAmmo(int, char const*, bool) */

undefined4 __cdecl CBaseCombatCharacter::GiveAmmo(int param_1,char *param_2,bool param_3)

{
  undefined1 uVar1;
  char *pcVar2;
  int iVar3;
  undefined4 uVar4;
  CAmmoDef *this;
  int unaff_EBX;
  undefined3 in_stack_0000000d;
  
  uVar1 = __i686_get_pc_thunk_bx();
  pcVar2 = (char *)GetAmmoDef();
  iVar3 = CAmmoDef::Index(this,pcVar2);
  if (iVar3 != -1) {
    uVar4 = (**(code **)(*(int *)param_1 + 0x44c))(param_1,param_2,iVar3,uVar1);
    return uVar4;
  }
  Msg(unaff_EBX + 0x591f32,_param_3);
  return 0;
}



/* ----------------------------------------
 * CBaseCombatCharacter::RemoveAmmo
 * Address: 001cc720  Size: 184 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::RemoveAmmo(int, int) */

void __thiscall CBaseCombatCharacter::RemoveAmmo(CBaseCombatCharacter *this,int param_1,int param_2)

{
  void *__s1;
  char cVar1;
  int iVar2;
  int iVar3;
  int extraout_ECX;
  CAmmoDef *this_00;
  int in_stack_0000000c;
  int local_2c [7];
  
  __i686_get_pc_thunk_bx();
  if ((0 < extraout_ECX) && (-1 < in_stack_0000000c)) {
    iVar2 = GetAmmoDef();
    cVar1 = CAmmoDef::CanCarryInfiniteAmmo(this_00,iVar2);
    if (cVar1 == '\0') {
      iVar2 = *(int *)(param_1 + 0x70c + in_stack_0000000c * 4) - extraout_ECX;
      if (iVar2 < 0) {
        iVar2 = 0;
      }
      __s1 = (void *)(param_1 + 0x70c + in_stack_0000000c * 4);
      local_2c[0] = iVar2;
      iVar3 = memcmp(__s1,local_2c,4);
      if (iVar3 != 0) {
        (**(code **)(*(int *)param_1 + 0x568))(param_1,__s1);
        *(int *)(param_1 + 0x70c + in_stack_0000000c * 4) = iVar2;
        return;
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CBaseCombatCharacter::RemoveAmmo
 * Address: 001cc7e0  Size: 84 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::RemoveAmmo(int, char const*) */

void __cdecl CBaseCombatCharacter::RemoveAmmo(int param_1,char *param_2)

{
  char *pcVar1;
  CAmmoDef *this;
  CBaseCombatCharacter *this_00;
  undefined4 uStack0000000c;
  
  __i686_get_pc_thunk_bx();
  pcVar1 = (char *)GetAmmoDef();
  uStack0000000c = CAmmoDef::Index(this,pcVar1);
  RemoveAmmo(this_00,param_1,(int)param_2);
  return;
}



/* ----------------------------------------
 * CBaseCombatCharacter::SetAmmoCount
 * Address: 001cc8c0  Size: 110 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::SetAmmoCount(int, int) */

void __thiscall
CBaseCombatCharacter::SetAmmoCount(CBaseCombatCharacter *this,int param_1,int param_2)

{
  void *__s1;
  void *__s2;
  int iVar1;
  int in_stack_0000000c;
  
  __s2 = (void *)__i686_get_pc_thunk_bx();
  __s1 = (void *)(param_1 + 0x70c + in_stack_0000000c * 4);
  iVar1 = memcmp(__s1,__s2,4);
  if (iVar1 != 0) {
    (**(code **)(*(int *)param_1 + 0x568))(param_1,__s1);
    *(int *)(param_1 + 0x70c + in_stack_0000000c * 4) = param_2;
  }
  return;
}



/* ----------------------------------------
 * CBaseCombatCharacter::Weapon_Equip
 * Address: 003b8d50  Size: 2619 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::Weapon_Equip(CBaseCombatWeapon*) */

void __thiscall
CBaseCombatCharacter::Weapon_Equip(CBaseCombatCharacter *this,CBaseCombatWeapon *param_1)

{
  ushort uVar1;
  ushort uVar2;
  uint uVar3;
  code *pcVar4;
  int *piVar5;
  ushort *puVar6;
  ushort *puVar7;
  char cVar8;
  undefined4 *puVar9;
  int iVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  int iVar13;
  ushort *puVar14;
  CBaseEntity *this_00;
  CBaseEdict *pCVar15;
  CBaseEdict *this_01;
  CBaseEdict *this_02;
  ushort uVar16;
  uint *puVar17;
  int unaff_EBX;
  int iVar18;
  int *in_stack_00000008;
  uint local_38;
  undefined4 local_2c [6];
  undefined4 uStack_14;
  
  iVar18 = 0;
  uStack_14 = 0x3b8d5d;
  __i686_get_pc_thunk_bx();
  do {
    uVar3 = *(uint *)(param_1 + iVar18 * 4 + 0xb0c);
    if (((uVar3 == 0xffffffff) ||
        (iVar10 = **(int **)(unaff_EBX + 0x7eda7b) + (uVar3 & 0xffff) * 0x18,
        *(uint *)(iVar10 + 8) != uVar3 >> 0x10)) || (*(int *)(iVar10 + 4) == 0)) {
      local_2c[0] = 0xffffffff;
      if (in_stack_00000008 != (int *)0x0) {
        puVar9 = (undefined4 *)(**(code **)(*in_stack_00000008 + 0xc))(in_stack_00000008);
        local_2c[0] = *puVar9;
      }
      iVar10 = memcmp(param_1 + iVar18 * 4 + 0xb0c,local_2c,4);
      if (iVar10 != 0) {
        if (param_1[0x5c] != (CBaseCombatWeapon)0x0) {
          param_1[0x60] = (CBaseCombatWeapon)((byte)param_1[0x60] | 1);
          goto LAB_003b9092;
        }
        pCVar15 = *(CBaseEdict **)(param_1 + 0x20);
        if ((pCVar15 == (CBaseEdict *)0x0) || ((*(uint *)pCVar15 & 0x100) != 0)) goto LAB_003b9092;
        uVar16 = (short)(param_1 + iVar18 * 4 + 0xb0c) - (short)param_1;
        *(uint *)pCVar15 = *(uint *)pCVar15 | 1;
        puVar14 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar15);
        puVar6 = (ushort *)**(undefined4 **)(unaff_EBX + 0x7eda1f);
        if (puVar14[1] == *puVar6) {
          uVar2 = *puVar14;
          uVar1 = puVar6[(uint)uVar2 * 0x14 + 0x14];
          if (uVar1 == 0) goto LAB_003b949d;
          if (uVar16 == puVar6[(uint)uVar2 * 0x14 + 1]) goto LAB_003b9092;
          iVar10 = 0;
          goto LAB_003b948a;
        }
        if ((puVar6[0x7d1] == 100) || (puVar14[1] != 0)) goto LAB_003b955e;
        piVar5 = *(int **)(unaff_EBX + 0x7eda1f);
        *puVar14 = puVar6[0x7d1];
        puVar7 = (ushort *)*piVar5;
        puVar6 = puVar7 + 0x7d1;
        *puVar6 = *puVar6 + 1;
        puVar14[1] = *puVar7;
        iVar10 = *piVar5 + (uint)*puVar14 * 0x28;
        *(ushort *)(iVar10 + 2) = uVar16;
        *(undefined2 *)(iVar10 + 0x28) = 1;
        goto LAB_003b9092;
      }
      break;
    }
    iVar18 = iVar18 + 1;
  } while (iVar18 != 0x30);
LAB_003b8e00:
  pcVar4 = *(code **)(*in_stack_00000008 + 0x188);
  uVar11 = CBaseEntity::GetTeamNumber((CBaseEntity *)param_1);
  (*pcVar4)(in_stack_00000008,uVar11);
  iVar18 = (**(code **)(*in_stack_00000008 + 0x510))(in_stack_00000008);
  if (iVar18 == -1) {
    iVar18 = in_stack_00000008[0x132];
    pcVar4 = *(code **)(*(int *)param_1 + 0x44c);
    uVar11 = (**(code **)(*in_stack_00000008 + 0x518))(in_stack_00000008);
    (*pcVar4)(param_1,uVar11,iVar18,0);
    iVar18 = (**(code **)(*in_stack_00000008 + 0x514))(in_stack_00000008);
    if (iVar18 != -1) goto LAB_003b8e64;
LAB_003b90fc:
    iVar18 = in_stack_00000008[0x133];
    pcVar4 = *(code **)(*(int *)param_1 + 0x44c);
    uVar11 = (**(code **)(*in_stack_00000008 + 0x51c))(in_stack_00000008);
    (*pcVar4)(param_1,uVar11,iVar18,0);
  }
  else {
    iVar18 = (**(code **)(*in_stack_00000008 + 0x518))(in_stack_00000008);
    iVar10 = (**(code **)(*in_stack_00000008 + 0x510))(in_stack_00000008);
    if (iVar10 < iVar18) {
      iVar18 = (**(code **)(*in_stack_00000008 + 0x510))(in_stack_00000008);
      if (iVar18 != in_stack_00000008[0x134]) {
        if ((char)in_stack_00000008[0x17] == '\0') {
          puVar17 = (uint *)in_stack_00000008[8];
          if ((puVar17 != (uint *)0x0) && ((*puVar17 & 0x100) == 0)) {
            *puVar17 = *puVar17 | 1;
            puVar14 = (ushort *)CBaseEdict::GetChangeAccessor(this_02);
            piVar5 = *(int **)(unaff_EBX + 0x7eda1f);
            puVar6 = (ushort *)*piVar5;
            if (puVar14[1] == *puVar6) {
              uVar16 = *puVar14;
              uVar2 = puVar6[(uint)uVar16 * 0x14 + 0x14];
              if (uVar2 == 0) {
LAB_003b9761:
                puVar6[(uint)uVar16 * 0x14 + uVar2 + 1] = 0x4d0;
                puVar6[(uint)uVar16 * 0x14 + 0x14] = uVar2 + 1;
              }
              else if (puVar6[(uint)uVar16 * 0x14 + 1] != 0x4d0) {
                iVar10 = 0;
                do {
                  if (iVar10 == (uVar2 - 1 & 0xffff) * 2) {
                    if (uVar2 != 0x13) goto LAB_003b9761;
                    puVar14[1] = 0;
                    *puVar17 = *puVar17 | 0x100;
                    break;
                  }
                  iVar10 = iVar10 + 2;
                } while (*(short *)((int)puVar6 + iVar10 + (uint)uVar16 * 0x28 + 2) != 0x4d0);
              }
            }
            else if ((puVar6[0x7d1] == 100) || (puVar14[1] != 0)) {
              puVar14[1] = 0;
              *puVar17 = *puVar17 | 0x100;
            }
            else {
              *puVar14 = puVar6[0x7d1];
              puVar7 = (ushort *)*piVar5;
              puVar6 = puVar7 + 0x7d1;
              *puVar6 = *puVar6 + 1;
              puVar14[1] = *puVar7;
              iVar10 = *piVar5 + (uint)*puVar14 * 0x28;
              *(undefined2 *)(iVar10 + 2) = 0x4d0;
              *(undefined2 *)(iVar10 + 0x28) = 1;
            }
          }
        }
        else {
          *(byte *)(in_stack_00000008 + 0x18) = *(byte *)(in_stack_00000008 + 0x18) | 1;
        }
        in_stack_00000008[0x134] = iVar18;
      }
      iVar18 = in_stack_00000008[0x132];
      pcVar4 = *(code **)(*(int *)param_1 + 0x44c);
      iVar10 = (**(code **)(*in_stack_00000008 + 0x518))(in_stack_00000008);
      iVar13 = (**(code **)(*in_stack_00000008 + 0x510))(in_stack_00000008);
      (*pcVar4)(param_1,iVar10 - iVar13,iVar18,0);
    }
    iVar18 = (**(code **)(*in_stack_00000008 + 0x514))(in_stack_00000008);
    if (iVar18 == -1) goto LAB_003b90fc;
LAB_003b8e64:
    iVar18 = (**(code **)(*in_stack_00000008 + 0x51c))(in_stack_00000008);
    iVar10 = (**(code **)(*in_stack_00000008 + 0x514))(in_stack_00000008);
    if (iVar10 < iVar18) {
      iVar18 = (**(code **)(*in_stack_00000008 + 0x514))(in_stack_00000008);
      if (iVar18 != in_stack_00000008[0x135]) {
        if ((char)in_stack_00000008[0x17] == '\0') {
          puVar17 = (uint *)in_stack_00000008[8];
          if ((puVar17 != (uint *)0x0) && ((*puVar17 & 0x100) == 0)) {
            *puVar17 = *puVar17 | 1;
            puVar14 = (ushort *)CBaseEdict::GetChangeAccessor(this_01);
            piVar5 = *(int **)(unaff_EBX + 0x7eda1f);
            puVar6 = (ushort *)*piVar5;
            if (puVar14[1] == *puVar6) {
              uVar16 = *puVar14;
              uVar2 = puVar6[(uint)uVar16 * 0x14 + 0x14];
              if (uVar2 == 0) {
LAB_003b96c3:
                puVar6[(uint)uVar16 * 0x14 + uVar2 + 1] = 0x4d4;
                puVar6[(uint)uVar16 * 0x14 + 0x14] = uVar2 + 1;
              }
              else if (puVar6[(uint)uVar16 * 0x14 + 1] != 0x4d4) {
                iVar10 = 0;
                do {
                  if (iVar10 == (uVar2 - 1 & 0xffff) * 2) {
                    if (uVar2 != 0x13) goto LAB_003b96c3;
                    puVar14[1] = 0;
                    *puVar17 = *puVar17 | 0x100;
                    break;
                  }
                  iVar10 = iVar10 + 2;
                } while (*(short *)((int)puVar6 + iVar10 + (uint)uVar16 * 0x28 + 2) != 0x4d4);
              }
            }
            else if ((puVar6[0x7d1] == 100) || (puVar14[1] != 0)) {
              puVar14[1] = 0;
              *puVar17 = *puVar17 | 0x100;
            }
            else {
              *puVar14 = puVar6[0x7d1];
              puVar7 = (ushort *)*piVar5;
              puVar6 = puVar7 + 0x7d1;
              *puVar6 = *puVar6 + 1;
              puVar14[1] = *puVar7;
              iVar10 = *piVar5 + (uint)*puVar14 * 0x28;
              *(undefined2 *)(iVar10 + 2) = 0x4d4;
              *(undefined2 *)(iVar10 + 0x28) = 1;
            }
          }
        }
        else {
          *(byte *)(in_stack_00000008 + 0x18) = *(byte *)(in_stack_00000008 + 0x18) | 1;
        }
        in_stack_00000008[0x135] = iVar18;
      }
      iVar18 = in_stack_00000008[0x133];
      pcVar4 = *(code **)(*(int *)param_1 + 0x44c);
      iVar10 = (**(code **)(*in_stack_00000008 + 0x51c))(in_stack_00000008);
      iVar13 = (**(code **)(*in_stack_00000008 + 0x514))(in_stack_00000008);
      (*pcVar4)(param_1,iVar10 - iVar13,iVar18,0);
    }
  }
  (**(code **)(*in_stack_00000008 + 0x3b4))(in_stack_00000008,param_1);
  cVar8 = (**(code **)(*(int *)param_1 + 0x158))(param_1);
  if (cVar8 != '\0') goto LAB_003b8fb5;
  uVar3 = *(uint *)(param_1 + 0xbcc);
  if (((uVar3 != 0xffffffff) &&
      (iVar18 = **(int **)(unaff_EBX + 0x7eda7b) + (uVar3 & 0xffff) * 0x18,
      *(uint *)(iVar18 + 8) == uVar3 >> 0x10)) &&
     (piVar5 = *(int **)(iVar18 + 4), piVar5 != (int *)0x0)) {
    (**(code **)(*piVar5 + 0x42c))(piVar5,0);
    this_00 = *(CBaseEntity **)(unaff_EBX + 0x7eda7b);
    uVar3 = *(uint *)(param_1 + 0xbcc);
    iVar18 = 0;
    if ((uVar3 != 0xffffffff) &&
       (this_00 = (CBaseEntity *)(*(int *)this_00 + (uVar3 & 0xffff) * 0x18),
       *(uint *)(this_00 + 8) == uVar3 >> 0x10)) {
      iVar18 = *(int *)(this_00 + 4);
    }
    CBaseEntity::AddEffects(this_00,iVar18);
  }
  iVar18 = 0;
  SetActiveWeapon((CBaseCombatCharacter *)param_1,param_1);
  uVar3 = *(uint *)(param_1 + 0xbcc);
  if ((uVar3 != 0xffffffff) &&
     (iVar10 = **(int **)(unaff_EBX + 0x7eda7b) + (uVar3 & 0xffff) * 0x18,
     *(uint *)(iVar10 + 8) == uVar3 >> 0x10)) {
    iVar18 = *(int *)(iVar10 + 4);
  }
  pCVar15 = (CBaseEdict *)((uint)*(CBaseEdict **)(iVar18 + 0xac) & 0xffffffdf);
  if (*(CBaseEdict **)(iVar18 + 0xac) == pCVar15) {
    puVar17 = *(uint **)(iVar18 + 0x20);
  }
  else {
    if (*(char *)(iVar18 + 0x5c) == '\0') {
      puVar17 = *(uint **)(iVar18 + 0x20);
      if ((puVar17 != (uint *)0x0) && ((*puVar17 & 0x100) == 0)) {
        *puVar17 = *puVar17 | 1;
        puVar14 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar15);
        piVar5 = *(int **)(unaff_EBX + 0x7eda1f);
        puVar6 = (ushort *)*piVar5;
        if (puVar14[1] == *puVar6) {
          uVar16 = *puVar14;
          uVar2 = puVar6[(uint)uVar16 * 0x14 + 0x14];
          local_38 = (uint)uVar2;
          if (uVar2 != 0) {
            if (puVar6[(uint)uVar16 * 0x14 + 1] != 0xac) {
              iVar10 = 0;
              do {
                if (iVar10 == (local_38 - 1 & 0xffff) * 2) {
                  if (uVar2 == 0x13) goto LAB_003b9572;
                  goto LAB_003b95fa;
                }
                iVar10 = iVar10 + 2;
              } while (*(short *)((int)puVar6 + iVar10 + (uint)uVar16 * 0x28 + 2) != 0xac);
            }
            goto LAB_003b9544;
          }
LAB_003b95fa:
          puVar6[(uint)uVar16 * 0x14 + local_38 + 1] = 0xac;
          puVar6[(uint)uVar16 * 0x14 + 0x14] = uVar2 + 1;
          puVar17 = *(uint **)(iVar18 + 0x20);
        }
        else if ((puVar6[0x7d1] == 100) || (puVar14[1] != 0)) {
LAB_003b9572:
          puVar14[1] = 0;
          *puVar17 = *puVar17 | 0x100;
          puVar17 = *(uint **)(iVar18 + 0x20);
        }
        else {
          *puVar14 = puVar6[0x7d1];
          puVar7 = (ushort *)*piVar5;
          puVar6 = puVar7 + 0x7d1;
          *puVar6 = *puVar6 + 1;
          puVar14[1] = *puVar7;
          iVar10 = *piVar5 + (uint)*puVar14 * 0x28;
          *(undefined2 *)(iVar10 + 2) = 0xac;
          *(undefined2 *)(iVar10 + 0x28) = 1;
LAB_003b9544:
          puVar17 = *(uint **)(iVar18 + 0x20);
        }
      }
    }
    else {
      *(byte *)(iVar18 + 0x60) = *(byte *)(iVar18 + 0x60) | 1;
      puVar17 = *(uint **)(iVar18 + 0x20);
    }
    *(CBaseEdict **)(iVar18 + 0xac) = pCVar15;
  }
  if (puVar17 != (uint *)0x0) {
    *puVar17 = *puVar17 | 0x80;
  }
  CBaseEntity::DispatchUpdateTransmitState((CBaseEntity *)pCVar15);
LAB_003b8fb5:
  uVar11 = (**(code **)(*(int *)param_1 + 0x51c))(param_1,in_stack_00000008);
  iVar18 = (**(code **)(**(int **)(unaff_EBX + 0x7eded7) + 0x40))(*(int **)(unaff_EBX + 0x7eded7));
  if (iVar18 != 0) {
    uVar12 = GetWeaponProficiencyName(uVar11);
    iVar18 = in_stack_00000008[0x19];
    if (in_stack_00000008[0x19] == 0) {
      iVar18 = unaff_EBX + 0x5a0d1e;
    }
    iVar10 = *(int *)(param_1 + 100);
    if (*(int *)(param_1 + 100) == 0) {
      iVar10 = unaff_EBX + 0x5a0d1e;
    }
    Msg(unaff_EBX + 0x58ffab,iVar10,iVar18,uVar12);
  }
  piVar5 = *(int **)(unaff_EBX + 0x7eda7b);
  *(undefined4 *)(param_1 + 0x6d8) = uVar11;
  uVar3 = *(uint *)(param_1 + 0x458);
  uVar11 = 0;
  if ((uVar3 != 0xffffffff) &&
     (iVar18 = *piVar5 + (uVar3 & 0xffff) * 0x18, *(uint *)(iVar18 + 8) == uVar3 >> 0x10)) {
    uVar11 = *(undefined4 *)(iVar18 + 4);
  }
  (**(code **)(*in_stack_00000008 + 0x3a0))(in_stack_00000008,uVar11);
  return;
LAB_003b948a:
  if (iVar10 != (uVar1 - 1 & 0xffff) * 2) goto LAB_003b9479;
  if (uVar1 == 0x13) {
LAB_003b955e:
    puVar14[1] = 0;
    *(uint *)pCVar15 = *(uint *)pCVar15 | 0x100;
  }
  else {
LAB_003b949d:
    puVar6[(uint)uVar2 * 0x14 + uVar1 + 1] = uVar16;
    puVar6[(uint)uVar2 * 0x14 + 0x14] = uVar1 + 1;
  }
LAB_003b9092:
  *(undefined4 *)(param_1 + iVar18 * 4 + 0xb0c) = local_2c[0];
  goto LAB_003b8e00;
LAB_003b9479:
  iVar10 = iVar10 + 2;
  if (uVar16 == *(ushort *)((int)puVar6 + iVar10 + (uint)uVar2 * 0x28 + 2)) goto LAB_003b9092;
  goto LAB_003b948a;
}



/* ----------------------------------------
 * CBaseCombatCharacter::Weapon_EquipAmmoOnly
 * Address: 003b30c0  Size: 1510 bytes
 * ---------------------------------------- */

/* CBaseCombatCharacter::Weapon_EquipAmmoOnly(CBaseCombatWeapon*) */

undefined4 __thiscall
CBaseCombatCharacter::Weapon_EquipAmmoOnly(CBaseCombatCharacter *this,CBaseCombatWeapon *param_1)

{
  ushort uVar1;
  ushort uVar2;
  CBaseEntity *this_00;
  uint uVar3;
  char *pcVar4;
  CBaseEdict *pCVar5;
  byte *pbVar6;
  code *pcVar7;
  ushort *puVar8;
  ushort *puVar9;
  char cVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  int *piVar14;
  ushort *puVar15;
  int iVar16;
  int iVar17;
  int unaff_EBX;
  int iVar18;
  byte *pbVar19;
  byte *pbVar20;
  bool bVar21;
  bool bVar22;
  int *in_stack_00000008;
  byte *local_24;
  
  iVar18 = 0;
  __i686_get_pc_thunk_bx();
  do {
    this_00 = (CBaseEntity *)**(undefined4 **)(unaff_EBX + 0x7f370b);
    uVar3 = *(uint *)(param_1 + iVar18 * 4 + 0xb0c);
    if (((uVar3 != 0xffffffff) &&
        (*(uint *)(this_00 + (uVar3 & 0xffff) * 0x18 + 8) == uVar3 >> 0x10)) &&
       (pcVar4 = *(char **)(this_00 + (uVar3 & 0xffff) * 0x18 + 4), pcVar4 != (char *)0x0)) {
      iVar11 = in_stack_00000008[0x19];
      if (in_stack_00000008[0x19] == 0) {
        iVar11 = unaff_EBX + 0x5a69ae;
      }
      if ((iVar11 == *(int *)(pcVar4 + 100)) ||
         (cVar10 = CBaseEntity::ClassMatchesComplex(this_00,pcVar4), cVar10 != '\0')) {
        cVar10 = (**(code **)(*in_stack_00000008 + 0x548))(in_stack_00000008);
        if (cVar10 == '\0') {
          iVar11 = in_stack_00000008[0x13e];
        }
        else {
          iVar11 = in_stack_00000008[0x134];
        }
        cVar10 = (**(code **)(*in_stack_00000008 + 0x54c))(in_stack_00000008);
        if (cVar10 == '\0') {
          iVar12 = in_stack_00000008[0x13f];
        }
        else {
          iVar12 = in_stack_00000008[0x135];
        }
        iVar11 = (**(code **)(*(int *)param_1 + 0x44c))(param_1,iVar11,in_stack_00000008[0x132],0);
        iVar12 = (**(code **)(*(int *)param_1 + 0x44c))(param_1,iVar12,in_stack_00000008[0x133],0);
        cVar10 = (**(code **)(*in_stack_00000008 + 0x548))(in_stack_00000008);
        if (cVar10 == '\0') {
          in_stack_00000008[0x13e] = in_stack_00000008[0x13e] - iVar11;
          goto LAB_003b322a;
        }
        iVar17 = in_stack_00000008[0x134] - iVar11;
        if (in_stack_00000008[0x134] == iVar17) goto LAB_003b322a;
        if ((char)in_stack_00000008[0x17] != '\0') {
          *(byte *)(in_stack_00000008 + 0x18) = *(byte *)(in_stack_00000008 + 0x18) | 1;
          goto LAB_003b3224;
        }
        pCVar5 = (CBaseEdict *)in_stack_00000008[8];
        if ((pCVar5 == (CBaseEdict *)0x0) || ((*(uint *)pCVar5 & 0x100) != 0)) goto LAB_003b3224;
        *(uint *)pCVar5 = *(uint *)pCVar5 | 1;
        puVar15 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar5);
        puVar8 = (ushort *)**(undefined4 **)(&DAT_007f36af + unaff_EBX);
        if (puVar15[1] != *puVar8) {
          if ((puVar8[0x7d1] == 100) || (puVar15[1] != 0)) goto LAB_003b355f;
          *puVar15 = puVar8[0x7d1];
          puVar9 = (ushort *)**(undefined4 **)(&DAT_007f36af + unaff_EBX);
          puVar8 = puVar9 + 0x7d1;
          *puVar8 = *puVar8 + 1;
          puVar15[1] = *puVar9;
          iVar16 = (uint)*puVar15 * 0x28 + **(int **)(&DAT_007f36af + unaff_EBX);
          *(undefined2 *)(iVar16 + 2) = 0x4d0;
          *(undefined2 *)(iVar16 + 0x28) = 1;
          goto LAB_003b3224;
        }
        uVar1 = *puVar15;
        uVar2 = puVar8[(uint)uVar1 * 0x14 + 0x14];
        if (uVar2 == 0) goto LAB_003b3602;
        if (puVar8[(uint)uVar1 * 0x14 + 1] == 0x4d0) goto LAB_003b3224;
        iVar16 = 0;
        break;
      }
    }
    iVar18 = iVar18 + 1;
    if (iVar18 == 0x30) {
      return 0;
    }
  } while( true );
LAB_003b35ef:
  if (iVar16 != (uVar2 - 1 & 0xffff) * 2) {
    iVar16 = iVar16 + 2;
    if (*(short *)((int)puVar8 + iVar16 + (uint)uVar1 * 0x28 + 2) == 0x4d0) goto LAB_003b3224;
    goto LAB_003b35ef;
  }
  if (uVar2 == 0x13) {
LAB_003b355f:
    puVar15[1] = 0;
    *(uint *)pCVar5 = *(uint *)pCVar5 | 0x100;
  }
  else {
LAB_003b3602:
    puVar8[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x4d0;
    puVar8[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
  }
LAB_003b3224:
  in_stack_00000008[0x134] = iVar17;
LAB_003b322a:
  cVar10 = (**(code **)(*in_stack_00000008 + 0x54c))(in_stack_00000008);
  if (cVar10 == '\0') {
    in_stack_00000008[0x13f] = in_stack_00000008[0x13f] - iVar12;
  }
  else {
    iVar17 = in_stack_00000008[0x135] - iVar12;
    if (in_stack_00000008[0x135] != iVar17) {
      if ((char)in_stack_00000008[0x17] == '\0') {
        pCVar5 = (CBaseEdict *)in_stack_00000008[8];
        if ((pCVar5 != (CBaseEdict *)0x0) && ((*(uint *)pCVar5 & 0x100) == 0)) {
          *(uint *)pCVar5 = *(uint *)pCVar5 | 1;
          puVar15 = (ushort *)CBaseEdict::GetChangeAccessor(pCVar5);
          puVar8 = (ushort *)**(undefined4 **)(&DAT_007f36af + unaff_EBX);
          if (puVar15[1] == *puVar8) {
            uVar1 = *puVar15;
            uVar2 = puVar8[(uint)uVar1 * 0x14 + 0x14];
            if (uVar2 == 0) {
LAB_003b3690:
              puVar8[(uint)uVar1 * 0x14 + uVar2 + 1] = 0x4d4;
              puVar8[(uint)uVar1 * 0x14 + 0x14] = uVar2 + 1;
            }
            else if (puVar8[(uint)uVar1 * 0x14 + 1] != 0x4d4) {
              iVar16 = 0;
              do {
                if (iVar16 == (uVar2 - 1 & 0xffff) * 2) {
                  if (uVar2 == 0x13) goto LAB_003b3576;
                  goto LAB_003b3690;
                }
                iVar16 = iVar16 + 2;
              } while (*(short *)((int)puVar8 + iVar16 + (uint)uVar1 * 0x28 + 2) != 0x4d4);
            }
          }
          else if ((puVar8[0x7d1] == 100) || (puVar15[1] != 0)) {
LAB_003b3576:
            puVar15[1] = 0;
            *(uint *)pCVar5 = *(uint *)pCVar5 | 0x100;
          }
          else {
            *puVar15 = puVar8[0x7d1];
            puVar9 = (ushort *)**(undefined4 **)(&DAT_007f36af + unaff_EBX);
            puVar8 = puVar9 + 0x7d1;
            *puVar8 = *puVar8 + 1;
            puVar15[1] = *puVar9;
            iVar16 = (uint)*puVar15 * 0x28 + **(int **)(&DAT_007f36af + unaff_EBX);
            *(undefined2 *)(iVar16 + 2) = 0x4d4;
            *(undefined2 *)(iVar16 + 0x28) = 1;
          }
        }
      }
      else {
        *(byte *)(in_stack_00000008 + 0x18) = *(byte *)(in_stack_00000008 + 0x18) | 1;
      }
      in_stack_00000008[0x135] = iVar17;
    }
  }
  if ((0 < iVar11) || (uVar13 = 0, 0 < iVar12)) {
    piVar14 = (int *)(**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x7f3e03) + 0x1c))
                               ((int *)**(undefined4 **)(unaff_EBX + 0x7f3e03),unaff_EBX + 0x5957ce,
                                0,0);
    uVar13 = 1;
    if (piVar14 != (int *)0x0) {
      pbVar6 = (byte *)in_stack_00000008[0x19];
      bVar21 = false;
      bVar22 = pbVar6 == (byte *)0x0;
      if (bVar22) {
        local_24 = (byte *)(unaff_EBX + 0x5a69ae);
      }
      else {
        iVar11 = 7;
        pbVar19 = pbVar6;
        pbVar20 = &DAT_0057651f + unaff_EBX;
        do {
          if (iVar11 == 0) break;
          iVar11 = iVar11 + -1;
          bVar21 = *pbVar19 < *pbVar20;
          bVar22 = *pbVar19 == *pbVar20;
          pbVar19 = pbVar19 + 1;
          pbVar20 = pbVar20 + 1;
        } while (bVar22);
        local_24 = pbVar6 + 7;
        if ((!bVar21 && !bVar22) != bVar21) {
          local_24 = pbVar6;
        }
      }
      pcVar7 = *(code **)(*piVar14 + 0x34);
      uVar13 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x7f355b) + 0x40))
                         ((int *)**(undefined4 **)(unaff_EBX + 0x7f355b),
                          *(undefined4 *)(param_1 + 0x20));
      (*pcVar7)(piVar14,unaff_EBX + 0x59fd3c,uVar13);
      (**(code **)(*piVar14 + 0x40))(piVar14,&UNK_00585d07 + unaff_EBX,local_24);
      uVar3 = *(uint *)(param_1 + iVar18 * 4 + 0xb0c);
      iVar18 = 0;
      if ((uVar3 != 0xffffffff) &&
         (iVar11 = **(int **)(unaff_EBX + 0x7f370b) + (uVar3 & 0xffff) * 0x18,
         *(uint *)(iVar11 + 8) == uVar3 >> 0x10)) {
        iVar18 = *(int *)(iVar11 + 4);
      }
      iVar11 = 0;
      if (*(int *)(iVar18 + 0x20) != 0) {
        iVar11 = *(int *)(iVar18 + 0x20) -
                 *(int *)(**(int **)(ConVar_PrintDescription + unaff_EBX + 3) + 0x5c) >> 4;
      }
      (**(code **)(*piVar14 + 0x34))(piVar14,unaff_EBX + 0x5e226b,iVar11);
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x7f3e03) + 0x20))
                ((int *)**(undefined4 **)(unaff_EBX + 0x7f3e03),piVar14,0);
      uVar13 = 1;
    }
  }
  return uVar13;
}



