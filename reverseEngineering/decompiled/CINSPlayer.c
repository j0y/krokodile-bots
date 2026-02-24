/*
 * CINSPlayer -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 10
 */

/* ----------------------------------------
 * CINSPlayer::CanResupplyNow
 * Address: 0069e3e0  Size: 241 bytes
 * ---------------------------------------- */

/* CINSPlayer::CanResupplyNow() */

undefined4 __thiscall CINSPlayer::CanResupplyNow(CINSPlayer *this)

{
  float fVar1;
  undefined4 uVar2;
  char *pcVar3;
  CINSPlayer *this_00;
  int unaff_EBX;
  float10 fVar4;
  CBasePlayer *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar4 = (float10)GetResupplyDelay(this_00);
  fVar1 = *(float *)(**(int **)(unaff_EBX + 0x5084b6) + 0xc);
  if ((float)fVar4 + *(float *)(in_stack_00000004 + 0x1bcc) <= fVar1) {
    uVar2 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x50850e) + 0x3f4))
                      ((int *)**(undefined4 **)(unaff_EBX + 0x50850e),in_stack_00000004);
    return uVar2;
  }
  pcVar3 = (char *)UTIL_VarArgs((char *)(unaff_EBX + 0x2cd259),
                                (int)ROUND((*(float *)(in_stack_00000004 + 0x1bcc) - fVar1) +
                                           (float)fVar4));
  ClientPrint(in_stack_00000004,3,(char *)(unaff_EBX + 0x2dbc94),pcVar3,(char *)0x0,(char *)0x0,
              (char *)0x0);
  return 0;
}



/* ----------------------------------------
 * CINSPlayer::GetMagazines
 * Address: 006b0e50  Size: 193 bytes
 * ---------------------------------------- */

/* CINSPlayer::GetMagazines(int) */

undefined4 __cdecl CINSPlayer::GetMagazines(int param_1)

{
  ushort uVar1;
  CBasePlayer *pCVar2;
  CUtlRBTree<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *this;
  CINSWeaponMagazines *this_00;
  CUtlRBTree<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *this_01;
  int iVar3;
  uint uVar4;
  
  __i686_get_pc_thunk_bx();
  uVar1 = CUtlRBTree<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
          ::Find(this,(Node_t *)(param_1 + 0x17d8));
  uVar4 = (uint)uVar1;
  if ((((*(int *)(param_1 + 0x17e0) <= (int)uVar4) || (*(ushort *)(param_1 + 0x17ee) < uVar1)) ||
      (uVar1 == 0xffff)) ||
     (iVar3 = *(int *)(param_1 + 0x17dc), uVar1 == *(ushort *)(iVar3 + uVar4 * 0x10))) {
    pCVar2 = (CBasePlayer *)::operator_new(0x1c);
    CINSWeaponMagazines::CINSWeaponMagazines(this_00,pCVar2,param_1);
    uVar4 = CUtlRBTree<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,CINSWeaponMagazines*,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
            ::Insert(this_01,(Node_t *)(param_1 + 0x17d8));
    iVar3 = *(int *)(param_1 + 0x17dc);
    uVar4 = uVar4 & 0xffff;
  }
  return *(undefined4 *)(iVar3 + 0xc + uVar4 * 0x10);
}



/* ----------------------------------------
 * CINSPlayer::GetResupplyDelay
 * Address: 0069de40  Size: 1291 bytes
 * ---------------------------------------- */

/* CINSPlayer::GetResupplyDelay() */

float10 __thiscall CINSPlayer::GetResupplyDelay(CINSPlayer *this)

{
  int *piVar1;
  int *piVar2;
  bool bVar3;
  char cVar4;
  int *piVar5;
  int *piVar6;
  float fVar7;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSRules *this_02;
  CINSRules *this_03;
  CINSPlayer *this_04;
  float fVar8;
  int unaff_EBX;
  float10 fVar9;
  int in_stack_00000004;
  undefined4 uVar10;
  float local_24;
  float local_20;
  
  fVar9 = (float10)__i686_get_pc_thunk_bx();
  piVar6 = *(int **)(unaff_EBX + 0x508aa8);
  if (*piVar6 == 0) {
    return fVar9;
  }
  cVar4 = CINSRules::IsTraining(this_00);
  if (cVar4 != '\0') {
    return (float10)(float)fVar9;
  }
  uVar10 = 4;
  cVar4 = CINSRules::IsGameState(this_01,*piVar6);
  if (cVar4 == '\0') {
    return (float10)*(float *)(unaff_EBX + 0x286908);
  }
  fVar9 = (float10)CINSRules::GetRoundElapsedTime(this_02);
  local_20 = *(float *)(**(int **)(unaff_EBX + 0x508a50) + 0xc) -
             *(float *)(in_stack_00000004 + 0x1db8);
  if ((float)fVar9 < local_20) {
    fVar9 = (float10)CINSRules::GetRoundElapsedTime(this_03);
    local_20 = (float)fVar9;
  }
  bVar3 = *(int *)(in_stack_00000004 + 0x1bd4) < 4;
  cVar4 = (**(code **)(*(int *)*piVar6 + 0x29c))((int *)*piVar6,uVar10);
  if (cVar4 == '\0') {
    cVar4 = HasLeftSpawn(this_04);
    if ((cVar4 == '\0') &&
       (cVar4 = (**(code **)(*(int *)*piVar6 + 0x438))((int *)*piVar6), cVar4 == '\0')) {
      piVar6 = *(int **)(unaff_EBX + 0x63566c);
      if (piVar6 == (int *)(&UNK_00635650 + unaff_EBX)) {
        fVar7 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x63567c));
      }
      else {
        fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
        fVar7 = (float)fVar9;
      }
      if (fVar7 < local_20) goto LAB_0069df28;
      if (bVar3) {
        return (float10)*(float *)(unaff_EBX + 0x286908);
      }
    }
    else {
LAB_0069df28:
      if (bVar3) {
        piVar6 = *(int **)(unaff_EBX + 0x6356cc);
        if (piVar6 == (int *)(unaff_EBX + 0x6356b0U)) {
          fVar7 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x6356dc));
        }
        else {
          fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
          fVar7 = (float)fVar9;
        }
        if (local_20 < fVar7) {
LAB_0069e102:
          return (float10)*(float *)(unaff_EBX + 0x286908);
        }
      }
    }
    piVar5 = *(int **)(unaff_EBX + 0x63554c);
    piVar6 = (int *)(unaff_EBX + 0x635530);
    if (piVar5 == piVar6) {
      local_24 = (float)(*(uint *)(unaff_EBX + 0x63555c) ^ (uint)piVar6);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
      local_24 = (float)fVar9;
    }
    piVar1 = *(int **)(&DAT_0063560c + unaff_EBX);
    piVar5 = (int *)(&UNK_006355f0 + unaff_EBX);
    if (piVar1 == piVar5) {
      fVar7 = (float)(*(uint *)(&DAT_0063561c + unaff_EBX) ^ (uint)piVar5);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
      fVar7 = (float)fVar9;
    }
    piVar2 = *(int **)(&DAT_006355ac + unaff_EBX);
    piVar1 = (int *)(&UNK_00635590 + unaff_EBX);
    if (piVar2 == piVar1) {
      fVar8 = (float)(*(uint *)(&DAT_006355bc + unaff_EBX) ^ (uint)piVar1);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
      fVar8 = (float)fVar9;
    }
    if (local_24 < (float)*(int *)(in_stack_00000004 + 0x1bd4) * fVar8 + fVar7) {
      piVar5 = *(int **)(unaff_EBX + 0x63554c);
      if (piVar5 == piVar6) {
        return (float10)(float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x63555c));
      }
LAB_0069dfd4:
      fVar9 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
      return fVar9;
    }
    piVar6 = *(int **)(&DAT_0063560c + unaff_EBX);
    if (piVar6 == piVar5) {
      fVar7 = (float)((uint)piVar5 ^ *(uint *)(&DAT_0063561c + unaff_EBX));
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
      fVar7 = (float)fVar9;
    }
    piVar6 = *(int **)(&DAT_006355ac + unaff_EBX);
    if (piVar6 == piVar1) {
      fVar8 = (float)((uint)piVar1 ^ *(uint *)(&DAT_006355bc + unaff_EBX));
      goto LAB_0069e225;
    }
  }
  else {
    cVar4 = HasLeftSpawn(this_04);
    if ((cVar4 == '\0') &&
       (cVar4 = (**(code **)(*(int *)*piVar6 + 0x438))((int *)*piVar6), cVar4 == '\0')) {
      piVar6 = *(int **)(unaff_EBX + 0x63542c);
      if (piVar6 == (int *)(unaff_EBX + 0x635410U)) {
        fVar7 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x63543c));
      }
      else {
        fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
        fVar7 = (float)fVar9;
      }
      if (fVar7 < local_20) goto LAB_0069e00e;
      if (bVar3) {
        return (float10)*(float *)(unaff_EBX + 0x286908);
      }
    }
    else {
LAB_0069e00e:
      if (bVar3) {
        piVar6 = *(int **)(unaff_EBX + 0x63548c);
        if (piVar6 == (int *)(unaff_EBX + 0x635470U)) {
          fVar7 = (float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x63549c));
        }
        else {
          fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
          fVar7 = (float)fVar9;
        }
        if (local_20 < fVar7) goto LAB_0069e102;
      }
    }
    piVar5 = *(int **)(unaff_EBX + 0x63530c);
    piVar6 = (int *)(unaff_EBX + 0x6352f0);
    if (piVar5 == piVar6) {
      local_24 = (float)(*(uint *)(unaff_EBX + 0x63531c) ^ (uint)piVar6);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
      local_24 = (float)fVar9;
    }
    piVar1 = *(int **)(unaff_EBX + 0x6353cc);
    piVar5 = (int *)(unaff_EBX + 0x6353b0);
    if (piVar1 == piVar5) {
      fVar7 = (float)(*(uint *)(unaff_EBX + 0x6353dc) ^ (uint)piVar5);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
      fVar7 = (float)fVar9;
    }
    piVar2 = *(int **)(unaff_EBX + 0x63536c);
    piVar1 = (int *)(unaff_EBX + 0x635350);
    if (piVar2 == piVar1) {
      fVar8 = (float)(*(uint *)(unaff_EBX + 0x63537c) ^ (uint)piVar1);
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
      fVar8 = (float)fVar9;
    }
    if (local_24 < (float)*(int *)(in_stack_00000004 + 0x1bd4) * fVar8 + fVar7) {
      piVar5 = *(int **)(unaff_EBX + 0x63530c);
      if (piVar5 == piVar6) {
        return (float10)(float)((uint)piVar6 ^ *(uint *)(unaff_EBX + 0x63531c));
      }
      goto LAB_0069dfd4;
    }
    piVar6 = *(int **)(unaff_EBX + 0x6353cc);
    if (piVar6 == piVar5) {
      fVar7 = (float)((uint)piVar5 ^ *(uint *)(unaff_EBX + 0x6353dc));
    }
    else {
      fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
      fVar7 = (float)fVar9;
    }
    piVar6 = *(int **)(unaff_EBX + 0x63536c);
    if (piVar6 == piVar1) {
      fVar8 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x63537c));
      goto LAB_0069e225;
    }
  }
  fVar9 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
  fVar8 = (float)fVar9;
LAB_0069e225:
  return (float10)((float)*(int *)(in_stack_00000004 + 0x1bd4) * fVar8 + fVar7);
}



/* ----------------------------------------
 * CINSPlayer::GiveAmmo
 * Address: 006b0f30  Size: 272 bytes
 * ---------------------------------------- */

/* CINSPlayer::GiveAmmo(int, int, int, bool, int) */

int __thiscall
CINSPlayer::GiveAmmo(CINSPlayer *this,int param_1,int param_2,int param_3,bool param_4,int param_5)

{
  int iVar1;
  CAmmoDef *this_00;
  CINSWeaponMagazines *this_01;
  CBaseEntity *this_02;
  char extraout_DL;
  int unaff_EBX;
  int iVar2;
  undefined3 in_stack_00000011;
  CBaseCombatCharacter *in_stack_00000018;
  
  __i686_get_pc_thunk_bx();
  iVar2 = 0;
  iVar1 = GetAmmoDef();
  iVar1 = CAmmoDef::GetAmmoOfIndex(this_00,iVar1);
  if (iVar1 != 0) {
    if ((*(byte *)(iVar1 + 0x94) & 4) == 0) {
      iVar1 = param_2;
      if (-1 < (int)in_stack_00000018) {
        iVar2 = CBaseCombatCharacter::GetAmmoCount(in_stack_00000018,param_1);
        if (param_2 < 0) {
          param_2 = 0;
          iVar1 = param_2;
        }
        else {
          iVar1 = (int)in_stack_00000018 - iVar2;
          if (param_2 <= (int)in_stack_00000018 - iVar2) {
            iVar1 = param_2;
          }
        }
      }
      param_2 = iVar1;
      iVar2 = CBaseCombatCharacter::GiveAmmo(param_1,param_2,SUB41(param_3,0));
    }
    else {
      iVar1 = GetMagazines(param_1);
      iVar2 = CINSWeaponMagazines::AddMags(this_01,iVar1,param_2,_param_4);
      if ((0 < iVar2) && (extraout_DL == '\0')) {
        CBaseEntity::EmitSound(this_02,(char *)param_1,(float)(unaff_EBX + 0x297cd2),(float *)0x0);
      }
    }
  }
  return iVar2;
}



/* ----------------------------------------
 * CINSPlayer::GiveAmmo
 * Address: 006b1050  Size: 57 bytes
 * ---------------------------------------- */

/* CINSPlayer::GiveAmmo(int, int, bool) */

void __thiscall CINSPlayer::GiveAmmo(CINSPlayer *this,int param_1,int param_2,bool param_3)

{
  undefined3 in_stack_0000000d;
  byte in_stack_00000010;
  
  GiveAmmo(this,param_1,param_2,_param_3,true,(uint)in_stack_00000010);
  return;
}



/* ----------------------------------------
 * CINSPlayer::IsResupplyDelayActive
 * Address: 0069e380  Size: 86 bytes
 * ---------------------------------------- */

/* CINSPlayer::IsResupplyDelayActive() */

bool __thiscall CINSPlayer::IsResupplyDelayActive(CINSPlayer *this)

{
  float fVar1;
  float fVar2;
  CINSPlayer *this_00;
  int unaff_EBX;
  float10 extraout_ST0;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar1 = *(float *)(**(int **)(unaff_EBX + 0x508517) + 0xc);
  fVar2 = *(float *)(in_stack_00000004 + 0x1bcc);
  GetResupplyDelay(this_00);
  return fVar1 < (float)extraout_ST0 + fVar2;
}



/* ----------------------------------------
 * CINSPlayer::Resupply
 * Address: 006abeb0  Size: 332 bytes
 * ---------------------------------------- */

/* CINSPlayer::Resupply(bool) */

undefined4 __cdecl CINSPlayer::Resupply(bool param_1)

{
  int iVar1;
  int *piVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  CINSPlayer *extraout_ECX;
  CINSPlayer *this;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  CINSRules *extraout_ECX_00;
  CINSRules *pCVar6;
  CINSPlayer *this_02;
  CINSPlayer *extraout_ECX_01;
  CINSRules *extraout_ECX_02;
  char extraout_DL;
  int unaff_EBX;
  undefined4 uVar7;
  float fVar8;
  undefined3 in_stack_00000005;
  
  __i686_get_pc_thunk_bx();
  uVar7 = 0;
  cVar4 = (**(code **)(*_param_1 + 0x118))(_param_1);
  if ((cVar4 != '\0') &&
     ((this = extraout_ECX, extraout_DL != '\0' ||
      ((cVar4 = (**(code **)(*_param_1 + 0x824))(_param_1), cVar4 != '\0' &&
       (cVar4 = CanResupplyNow(this_02), this = extraout_ECX_01, cVar4 != '\0')))))) {
    cVar4 = IsPossessing(this);
    if (cVar4 != '\0') {
      ClearPossessTarget(this_00,param_1);
    }
    (**(code **)(*_param_1 + 0x874))(_param_1);
    AssignedPlayerModel(this_01);
    iVar1 = _param_1[0x93];
    iVar5 = (**(code **)(*_param_1 + 0x1f0))(_param_1);
    pCVar6 = extraout_ECX_00;
    if (iVar1 < iVar5) {
      piVar2 = *(int **)(unaff_EBX + 0x4fa9d8);
      fVar8 = *(float *)(*piVar2 + 0xc);
      if (*(float *)(unaff_EBX + 0x27af00) <= fVar8 - (float)_param_1[0x6f4] &&
          fVar8 - (float)_param_1[0x6f4] != *(float *)(unaff_EBX + 0x27af00)) {
        pcVar3 = *(code **)(*_param_1 + 500);
        uVar7 = (**(code **)(*_param_1 + 0x1f0))(_param_1);
        (*pcVar3)(_param_1,uVar7);
        iVar1 = *piVar2;
        _param_1[0x6f3] = *(int *)(iVar1 + 0xc);
        fVar8 = *(float *)(iVar1 + 0xc);
        pCVar6 = extraout_ECX_02;
      }
    }
    else {
      fVar8 = *(float *)(**(int **)(unaff_EBX + 0x4fa9d8) + 0xc);
    }
    _param_1[0x6f3] = (int)fVar8;
    uVar7 = 1;
    cVar4 = CINSRules::IsRoundRunning(pCVar6);
    if (cVar4 != '\0') {
      _param_1[0x6f5] = _param_1[0x6f5] + 1;
    }
  }
  return uVar7;
}



/* ----------------------------------------
 * CINSPlayer::Weapon_Equip
 * Address: 0069ea60  Size: 421 bytes
 * ---------------------------------------- */

/* CINSPlayer::Weapon_Equip(CBaseCombatWeapon*, bool) */

void __thiscall CINSPlayer::Weapon_Equip(CINSPlayer *this,CBaseCombatWeapon *param_1,bool param_2)

{
  CBaseCombatWeapon *pCVar1;
  char cVar2;
  undefined4 *puVar3;
  int iVar4;
  uint uVar5;
  CINSWeapon *this_00;
  undefined4 uVar6;
  int unaff_EBX;
  int iVar7;
  undefined3 in_stack_00000009;
  char in_stack_0000000c;
  undefined4 local_2c [6];
  undefined4 uStack_14;
  
  uStack_14 = 0x69ea6b;
  __i686_get_pc_thunk_bx();
  if (((_param_2 != (int *)0x0) &&
      (cVar2 = (**(code **)(*_param_2 + 0x170))(_param_2), cVar2 != '\0')) &&
     (((**(code **)(*_param_2 + 0x530))(_param_2), in_stack_0000000c != '\0' ||
      ((cVar2 = CINSWeapon::IsAttached(this_00), cVar2 != '\0' ||
       (cVar2 = IsWeaponSlotFilled((CINSPlayer *)param_1,(int)param_1), cVar2 == '\0')))))) {
    iVar7 = 0;
    pCVar1 = param_1 + 0xb0c;
    uVar5 = *(uint *)pCVar1;
    if (uVar5 == 0xffffffff) {
      iVar7 = 0;
    }
    else {
      do {
        iVar4 = **(int **)(unaff_EBX + 0x507d6d) + (uVar5 & 0xffff) * 0x18;
        if ((*(uint *)(iVar4 + 8) != uVar5 >> 0x10) || (*(int *)(iVar4 + 4) == 0)) break;
        iVar7 = iVar7 + 1;
        if (iVar7 == 0x30) goto LAB_0069eb33;
        uVar5 = *(uint *)(pCVar1 + iVar7 * 4);
      } while (uVar5 != 0xffffffff);
    }
    puVar3 = (undefined4 *)(**(code **)(*_param_2 + 0xc))(_param_2);
    local_2c[0] = *puVar3;
    iVar4 = memcmp(pCVar1 + iVar7 * 4,local_2c,4);
    if (iVar4 != 0) {
      CBaseEntity::NetworkStateChanged((CBaseEntity *)param_1,param_1);
      *(undefined4 *)(param_1 + iVar7 * 4 + 0xb0c) = local_2c[0];
    }
LAB_0069eb33:
    (**(code **)(*_param_2 + 0x3b4))(_param_2,param_1);
    uVar6 = 0;
    uVar5 = *(uint *)(param_1 + 0x458);
    if ((uVar5 != 0xffffffff) &&
       (iVar7 = **(int **)(unaff_EBX + 0x507d6d) + (uVar5 & 0xffff) * 0x18,
       *(uint *)(iVar7 + 8) == uVar5 >> 0x10)) {
      uVar6 = *(undefined4 *)(iVar7 + 4);
    }
    (**(code **)(*_param_2 + 0x3a0))(_param_2,uVar6);
  }
  return;
}



/* ----------------------------------------
 * CINSPlayer::Weapon_Equip
 * Address: 0069ec20  Size: 34 bytes
 * ---------------------------------------- */

/* CINSPlayer::Weapon_Equip(CBaseCombatWeapon*) */

void __thiscall CINSPlayer::Weapon_Equip(CINSPlayer *this,CBaseCombatWeapon *param_1)

{
  bool in_stack_00000008;
  
  Weapon_Equip(this,param_1,in_stack_00000008);
  return;
}



/* ----------------------------------------
 * CINSPlayer::Weapon_EquipAmmoOnly
 * Address: 006945b0  Size: 10 bytes
 * ---------------------------------------- */

/* CINSPlayer::Weapon_EquipAmmoOnly(CBaseCombatWeapon*) */

undefined4 __cdecl CINSPlayer::Weapon_EquipAmmoOnly(CBaseCombatWeapon *param_1)

{
  return 1;
}



