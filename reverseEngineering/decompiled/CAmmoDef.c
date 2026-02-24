/*
 * CAmmoDef -- Decompiled ammo/reload functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 23
 */

/* ----------------------------------------
 * CAmmoDef::CAmmoDef
 * Address: 001c61e0  Size: 117 bytes
 * ---------------------------------------- */

/* CAmmoDef::CAmmoDef() */

void __thiscall CAmmoDef::CAmmoDef(CAmmoDef *this)

{
  Ammo_t *extraout_ECX;
  Ammo_t *extraout_ECX_00;
  Ammo_t *pAVar1;
  Ammo_t *extraout_ECX_01;
  int unaff_EBX;
  int *piVar2;
  int iVar3;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = (int)("CGamePlayerZone" + unaff_EBX + 8);
  piVar2 = in_stack_00000004 + 2;
  pAVar1 = extraout_ECX;
  do {
    piVar2 = piVar2 + 0x2f;
    Ammo_t::Ammo_t(pAVar1);
    pAVar1 = extraout_ECX_00;
  } while (piVar2 != in_stack_00000004 + 0x2f02);
  in_stack_00000004[1] = 0;
  iVar3 = 0;
  do {
    Ammo_t::init(pAVar1);
    iVar3 = iVar3 + 1;
    pAVar1 = extraout_ECX_01;
  } while (iVar3 != 0x100);
  return;
}



/* ----------------------------------------
 * CAmmoDef::CanCarryInfiniteAmmo
 * Address: 001c5d80  Size: 39 bytes
 * ---------------------------------------- */

/* CAmmoDef::CanCarryInfiniteAmmo(int) const */

bool __thiscall CAmmoDef::CanCarryInfiniteAmmo(CAmmoDef *this,int param_1)

{
  bool bVar1;
  int in_stack_00000008;
  
  bVar1 = false;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    bVar1 = *(int *)(param_1 + 0x8c + in_stack_00000008 * 0xbc) == -1;
  }
  return bVar1;
}



/* ----------------------------------------
 * CAmmoDef::CName
 * Address: 001c5c80  Size: 60 bytes
 * ---------------------------------------- */

/* CAmmoDef::CName(int) const */

int __thiscall CAmmoDef::CName(CAmmoDef *this,int param_1)

{
  int iVar1;
  int unaff_EBX;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar1 = unaff_EBX + 0x793df2;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    iVar1 = *(int *)(param_1 + 8 + in_stack_00000008 * 0xbc);
    if (iVar1 == 0) {
      iVar1 = unaff_EBX + 0x793df2;
    }
  }
  return iVar1;
}



/* ----------------------------------------
 * CAmmoDef::ComputeDamageModification
 * Address: 001c5f50  Size: 121 bytes
 * ---------------------------------------- */

/* CAmmoDef::ComputeDamageModification(int, int, float&) */

void __thiscall
CAmmoDef::ComputeDamageModification(CAmmoDef *this,int param_1,int param_2,float *param_3)

{
  Node_t *pNVar1;
  ushort uVar2;
  int iVar3;
  CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *this_00;
  float *in_stack_00000010;
  
  __i686_get_pc_thunk_bx();
  iVar3 = GetAmmoDef();
  if ((-1 < param_2) && (param_2 < *(int *)(iVar3 + 4))) {
    pNVar1 = (Node_t *)(param_1 + 0x70 + param_2 * 0xbc);
    uVar2 = CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
            ::Find(this_00,pNVar1);
    if (uVar2 != 0xffff) {
      *in_stack_00000010 =
           *in_stack_00000010 * *(float *)((uint)uVar2 * 0x10 + *(int *)(pNVar1 + 4) + 0xc);
    }
  }
  return;
}



/* ----------------------------------------
 * CAmmoDef::DamageType
 * Address: 001c5d00  Size: 32 bytes
 * ---------------------------------------- */

/* CAmmoDef::DamageType(int) const */

undefined4 __thiscall CAmmoDef::DamageType(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x1c + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::Flags
 * Address: 001c5e10  Size: 35 bytes
 * ---------------------------------------- */

/* CAmmoDef::Flags(int) const */

undefined4 __thiscall CAmmoDef::Flags(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x9c + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::GetAmmoOfIndex
 * Address: 001c5ba0  Size: 32 bytes
 * ---------------------------------------- */

/* CAmmoDef::GetAmmoOfIndex(int) */

int __thiscall CAmmoDef::GetAmmoOfIndex(CAmmoDef *this,int param_1)

{
  int iVar1;
  int in_stack_00000008;
  
  iVar1 = 0;
  if ((0 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    iVar1 = param_1 + 8 + in_stack_00000008 * 0xbc;
  }
  return iVar1;
}



/* ----------------------------------------
 * CAmmoDef::Index
 * Address: 001c5bc0  Size: 104 bytes
 * ---------------------------------------- */

/* CAmmoDef::Index(char const*) */

int __thiscall CAmmoDef::Index(CAmmoDef *this,char *param_1)

{
  int iVar1;
  int iVar2;
  char *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_00000008 != (char *)0x0) && (1 < *(int *)(param_1 + 4))) {
    iVar2 = 1;
    do {
      if ((*(char **)(param_1 + iVar2 * 0xbc + 8) != (char *)0x0) &&
         (iVar1 = _V_stricmp(in_stack_00000008,*(char **)(param_1 + iVar2 * 0xbc + 8)), iVar1 == 0))
      {
        return iVar2;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < *(int *)(param_1 + 4));
  }
  return -1;
}



/* ----------------------------------------
 * CAmmoDef::InstallAmmoFromKeyValues
 * Address: 001c6d60  Size: 381 bytes
 * ---------------------------------------- */

/* CAmmoDef::InstallAmmoFromKeyValues(KeyValues*) */

undefined4 __thiscall CAmmoDef::InstallAmmoFromKeyValues(CAmmoDef *this,KeyValues *param_1)

{
  char cVar1;
  Ammo_t *pAVar2;
  Ammo_t *pAVar3;
  int iVar4;
  CAmmoDef *this_00;
  KeyValues *this_01;
  KeyValues *extraout_ECX;
  KeyValues *pKVar5;
  KeyValues *extraout_ECX_00;
  KeyValues *this_02;
  CAmmoDef *this_03;
  KeyValues *extraout_ECX_01;
  KeyValues *extraout_ECX_02;
  int unaff_EBX;
  KeyValues *in_stack_00000008;
  Ammo_t *pAVar6;
  KeyValues *pKVar7;
  undefined4 local_20 [3];
  undefined4 uStack_14;
  
  uStack_14 = 0x1c6d6b;
  __i686_get_pc_thunk_bx();
  ResetAllAmmo(this_00);
  pAVar2 = (Ammo_t *)KeyValues::GetFirstSubKey(this_01);
  if (pAVar2 == (Ammo_t *)0x0) {
LAB_001c6ee0:
    return CONCAT31((int3)((uint)*(int *)(param_1 + 4) >> 8),0 < *(int *)(param_1 + 4));
  }
  if (*(int *)(param_1 + 4) != 0x100) {
    pKVar5 = extraout_ECX;
    do {
      pAVar3 = (Ammo_t *)KeyValues::GetName(pKVar5);
      pKVar5 = this_02;
      if (((pAVar3 != (Ammo_t *)0x0) && (*pAVar3 != (Ammo_t)0x0)) &&
         (iVar4 = KeyValues::GetInt(this_02,(char *)pAVar2,unaff_EBX + 0x75ce87),
         pKVar5 = (KeyValues *)this_03, iVar4 == 0)) {
        iVar4 = *(int *)(param_1 + 4);
        pAVar6 = pAVar2;
        pKVar7 = param_1 + iVar4 * 0xbc + 8;
        cVar1 = LoadBaseKeyValues(this_03,param_1,in_stack_00000008,pAVar2);
        if (cVar1 != '\0') {
          pKVar7 = (KeyValues *)0x0;
          pAVar6 = pAVar3;
          cVar1 = Ammo_t::InitFromKV(param_1 + iVar4 * 0xbc + 8,(char *)pAVar2,SUB41(pAVar3,0));
          if (cVar1 != '\0') {
            AllocPooledString((char *)local_20);
            *(undefined4 *)(param_1 + iVar4 * 0xbc + 8) = local_20[0];
            iVar4 = *(int *)(param_1 + 4);
            *(int *)(param_1 + 4) = iVar4 + 1;
            pKVar5 = extraout_ECX_02;
            if (iVar4 + 1 < 0x100) goto LAB_001c6db8;
            Warning(unaff_EBX + 0x75cea1,0x100,pAVar6,pKVar7);
            goto LAB_001c6ee0;
          }
        }
        Warning(unaff_EBX + 0x75ce8e,pAVar3,pAVar6,pKVar7);
        pKVar5 = extraout_ECX_01;
      }
LAB_001c6db8:
      pAVar2 = (Ammo_t *)KeyValues::GetNextKey(pKVar5);
      if (pAVar2 == (Ammo_t *)0x0) goto LAB_001c6ee0;
      pKVar5 = extraout_ECX_00;
    } while (*(int *)(param_1 + 4) != 0x100);
  }
  return 0x101;
}



/* ----------------------------------------
 * CAmmoDef::IsValidAmmoIndex
 * Address: 001c5c30  Size: 23 bytes
 * ---------------------------------------- */

/* CAmmoDef::IsValidAmmoIndex(int) const */

bool __thiscall CAmmoDef::IsValidAmmoIndex(CAmmoDef *this,int param_1)

{
  bool bVar1;
  int in_stack_00000008;
  
  bVar1 = false;
  if (-1 < in_stack_00000008) {
    bVar1 = in_stack_00000008 < *(int *)(param_1 + 4);
  }
  return bVar1;
}



/* ----------------------------------------
 * CAmmoDef::LoadBaseKeyValues
 * Address: 001c6c90  Size: 193 bytes
 * ---------------------------------------- */

/* CAmmoDef::LoadBaseKeyValues(KeyValues*, KeyValues*, Ammo_t*) */

undefined4 __thiscall
CAmmoDef::LoadBaseKeyValues(CAmmoDef *this,KeyValues *param_1,KeyValues *param_2,Ammo_t *param_3)

{
  KeyValues *pKVar1;
  char *pcVar2;
  Ammo_t *pAVar3;
  undefined4 uVar4;
  KeyValues *this_00;
  KeyValues *this_01;
  CAmmoDef *this_02;
  int unaff_EBX;
  KeyValues *in_stack_00000010;
  
  pKVar1 = (KeyValues *)__i686_get_pc_thunk_bx();
  pcVar2 = (char *)KeyValues::GetString(this_00,(char *)param_3,(char *)(unaff_EBX + 0x75cf4a));
  if ((pcVar2 != (char *)0x0) && (*pcVar2 != '\0')) {
    pAVar3 = (Ammo_t *)KeyValues::FindKey(this_01,(char *)param_2,SUB41(pcVar2,0));
    if (pAVar3 != (Ammo_t *)0x0) {
      LoadBaseKeyValues(this_02,pKVar1,param_2,pAVar3);
      uVar4 = Ammo_t::InitFromKV(in_stack_00000010,(char *)pAVar3,SUB41(pcVar2,0));
      return uVar4;
    }
  }
  return 1;
}



/* ----------------------------------------
 * CAmmoDef::MagazineCapacity
 * Address: 001c5d50  Size: 35 bytes
 * ---------------------------------------- */

/* CAmmoDef::MagazineCapacity(int) const */

undefined4 __thiscall CAmmoDef::MagazineCapacity(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x90 + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::MaxCarry
 * Address: 001c5d20  Size: 35 bytes
 * ---------------------------------------- */

/* CAmmoDef::MaxCarry(int, CBaseCombatCharacter const*) const */

undefined4 __cdecl CAmmoDef::MaxCarry(int param_1,CBaseCombatCharacter *param_2)

{
  undefined4 uVar1;
  
  uVar1 = 0;
  if ((-1 < (int)param_2) && ((int)param_2 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x8c + (int)param_2 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::MaxSplashSize
 * Address: 001c5de0  Size: 38 bytes
 * ---------------------------------------- */

/* CAmmoDef::MaxSplashSize(int) const */

undefined4 __thiscall CAmmoDef::MaxSplashSize(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 8;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x98 + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::MinSplashSize
 * Address: 001c5db0  Size: 38 bytes
 * ---------------------------------------- */

/* CAmmoDef::MinSplashSize(int) const */

undefined4 __thiscall CAmmoDef::MinSplashSize(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 4;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x94 + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::Name
 * Address: 001c5c50  Size: 47 bytes
 * ---------------------------------------- */

/* CAmmoDef::Name(int) const */

void CAmmoDef::Name(int param_1)

{
  int in_stack_00000008;
  int in_stack_0000000c;
  
  if ((-1 < in_stack_0000000c) && (in_stack_0000000c < *(int *)(in_stack_00000008 + 4))) {
    *(undefined4 *)param_1 = *(undefined4 *)(in_stack_00000008 + 8 + in_stack_0000000c * 0xbc);
    return;
  }
  *(undefined4 *)param_1 = 0;
  return;
}



/* ----------------------------------------
 * CAmmoDef::Precache
 * Address: 001c5b10  Size: 136 bytes
 * ---------------------------------------- */

/* CAmmoDef::Precache() */

void __thiscall CAmmoDef::Precache(CAmmoDef *this)

{
  int iVar1;
  char *pcVar2;
  int iVar3;
  int in_stack_00000004;
  
  iVar3 = 0;
  __i686_get_pc_thunk_bx();
  if (0 < *(int *)(in_stack_00000004 + 4)) {
LAB_001c5b30:
    iVar3 = iVar3 + 1;
    if (iVar3 < *(int *)(in_stack_00000004 + 4)) {
      while (iVar3 != 0) {
        iVar1 = in_stack_00000004 + 8 + iVar3 * 0xbc;
        pcVar2 = *(char **)(iVar1 + 0xa8);
        if ((pcVar2 != (char *)0x0) && (*pcVar2 != '\0')) {
          CBaseEntity::PrecacheModel(pcVar2,true);
        }
        pcVar2 = *(char **)(iVar1 + 0xb8);
        if ((pcVar2 == (char *)0x0) || (*pcVar2 == '\0')) break;
        iVar3 = iVar3 + 1;
        PrecacheEffect(pcVar2);
        if (*(int *)(in_stack_00000004 + 4) <= iVar3) {
          return;
        }
      }
      goto LAB_001c5b30;
    }
  }
  return;
}



/* ----------------------------------------
 * CAmmoDef::ResetAllAmmo
 * Address: 001c6190  Size: 68 bytes
 * ---------------------------------------- */

/* CAmmoDef::ResetAllAmmo() */

void __thiscall CAmmoDef::ResetAllAmmo(CAmmoDef *this)

{
  Ammo_t *extraout_ECX;
  int iVar1;
  int in_stack_00000004;
  
  *(undefined4 *)(in_stack_00000004 + 4) = 0;
  iVar1 = 1;
  do {
    iVar1 = iVar1 + 1;
    Ammo_t::init((Ammo_t *)this);
    this = (CAmmoDef *)extraout_ECX;
  } while (iVar1 != 0x100);
  return;
}



/* ----------------------------------------
 * CAmmoDef::SuppressionIncrement
 * Address: 001c5e40  Size: 37 bytes
 * ---------------------------------------- */

/* CAmmoDef::SuppressionIncrement(int) const */

float10 __thiscall CAmmoDef::SuppressionIncrement(CAmmoDef *this,int param_1)

{
  float10 fVar1;
  int in_stack_00000008;
  
  fVar1 = (float10)0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    fVar1 = (float10)*(float *)(param_1 + 0xa0 + in_stack_00000008 * 0xbc);
  }
  return fVar1;
}



/* ----------------------------------------
 * CAmmoDef::TracerFrequency
 * Address: 001c5ce0  Size: 32 bytes
 * ---------------------------------------- */

/* CAmmoDef::TracerFrequency(int) const */

undefined4 __thiscall CAmmoDef::TracerFrequency(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0x10 + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::TracerType
 * Address: 001c5cc0  Size: 32 bytes
 * ---------------------------------------- */

/* CAmmoDef::TracerType(int) const */

undefined4 __thiscall CAmmoDef::TracerType(CAmmoDef *this,int param_1)

{
  undefined4 uVar1;
  int in_stack_00000008;
  
  uVar1 = 0;
  if ((-1 < in_stack_00000008) && (in_stack_00000008 < *(int *)(param_1 + 4))) {
    uVar1 = *(undefined4 *)(param_1 + 0xc + in_stack_00000008 * 0xbc);
  }
  return uVar1;
}



/* ----------------------------------------
 * CAmmoDef::~CAmmoDef
 * Address: 001c6280  Size: 650 bytes
 * ---------------------------------------- */

/* CAmmoDef::~CAmmoDef() */

void __thiscall CAmmoDef::~CAmmoDef(CAmmoDef *this)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *extraout_ECX;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_00;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_01;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_02;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_03;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_04;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_05;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_06;
  CUtlMemory<DataRangeWithFactorPair_t,int> *pCVar4;
  CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *extraout_ECX_07;
  CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
  *this_00;
  CUtlMemory<DataRangeWithFactorPair_t,int> *extraout_ECX_08;
  int unaff_EBX;
  int *in_stack_00000004;
  int *local_20;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = (int)("MapEntity_ParseAllEntities_SpawnTransients" + unaff_EBX + 5);
  piVar1 = in_stack_00000004 + 0x2f02;
  this_00 = extraout_ECX;
  local_20 = piVar1;
  do {
    CUtlRBTree<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short,CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,float,unsigned_short,bool(*)(int_const&,int_const&)>::Node_t,unsigned_short>,unsigned_short>>
    ::Purge(this_00);
    pCVar4 = (CUtlMemory<DataRangeWithFactorPair_t,int> *)local_20[-0x12];
    if (-1 < (int)pCVar4) {
      pCVar4 = (CUtlMemory<DataRangeWithFactorPair_t,int> *)local_20[-0x14];
      if (pCVar4 != (CUtlMemory<DataRangeWithFactorPair_t,int> *)0x0) {
        (**(code **)(*(int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX) + 8))
                  ((int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX),pCVar4);
        *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbbb8 - (int)piVar1)) = 0;
        pCVar4 = extraout_ECX_08;
      }
      *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbbbc - (int)piVar1)) = 0;
    }
    local_20[-0x17] = 0;
    if (local_20[-0x18] < 0) {
      iVar2 = local_20[-0x1a];
    }
    else {
      if (local_20[-0x1a] != 0) {
        (**(code **)(*(int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX) + 8))
                  ((int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX),local_20[-0x1a]);
        *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbba0 - (int)piVar1)) = 0;
        pCVar4 = extraout_ECX_00;
      }
      *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbba4 - (int)piVar1)) = 0;
      iVar2 = 0;
    }
    *(int *)((int)in_stack_00000004 + (int)local_20 + (0xbbb0 - (int)piVar1)) = iVar2;
    CUtlMemory<DataRangeWithFactorPair_t,int>::~CUtlMemory(pCVar4);
    local_20[-0x1c] = 0;
    if (local_20[-0x1d] < 0) {
      uVar3 = *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb8c - (int)piVar1));
      pCVar4 = extraout_ECX_01;
    }
    else {
      pCVar4 = *(CUtlMemory<DataRangeWithFactorPair_t,int> **)
                ((int)in_stack_00000004 + (int)local_20 + (0xbb8c - (int)piVar1));
      if (pCVar4 != (CUtlMemory<DataRangeWithFactorPair_t,int> *)0x0) {
        (**(code **)(*(int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX) + 8))
                  ((int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX),pCVar4);
        *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb8c - (int)piVar1)) = 0;
        pCVar4 = extraout_ECX_02;
      }
      *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb90 - (int)piVar1)) = 0;
      uVar3 = 0;
    }
    *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb9c - (int)piVar1)) = uVar3;
    CUtlMemory<DataRangeWithFactorPair_t,int>::~CUtlMemory(pCVar4);
    local_20[-0x21] = 0;
    if (local_20[-0x22] < 0) {
      uVar3 = *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb78 - (int)piVar1));
      pCVar4 = extraout_ECX_03;
    }
    else {
      pCVar4 = *(CUtlMemory<DataRangeWithFactorPair_t,int> **)
                ((int)in_stack_00000004 + (int)local_20 + (0xbb78 - (int)piVar1));
      if (pCVar4 != (CUtlMemory<DataRangeWithFactorPair_t,int> *)0x0) {
        (**(code **)(*(int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX) + 8))
                  ((int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX),pCVar4);
        *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb78 - (int)piVar1)) = 0;
        pCVar4 = extraout_ECX_04;
      }
      *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb7c - (int)piVar1)) = 0;
      uVar3 = 0;
    }
    *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb88 - (int)piVar1)) = uVar3;
    CUtlMemory<DataRangeWithFactorPair_t,int>::~CUtlMemory(pCVar4);
    local_20[-0x26] = 0;
    if (local_20[-0x27] < 0) {
      uVar3 = *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb64 - (int)piVar1));
      pCVar4 = extraout_ECX_05;
    }
    else {
      pCVar4 = *(CUtlMemory<DataRangeWithFactorPair_t,int> **)
                ((int)in_stack_00000004 + (int)local_20 + (0xbb64 - (int)piVar1));
      if (pCVar4 != (CUtlMemory<DataRangeWithFactorPair_t,int> *)0x0) {
        (**(code **)(*(int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX) + 8))
                  ((int *)**(undefined4 **)(&DAT_009e05ed + unaff_EBX),pCVar4);
        *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb64 - (int)piVar1)) = 0;
        pCVar4 = extraout_ECX_06;
      }
      *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb68 - (int)piVar1)) = 0;
      uVar3 = 0;
    }
    *(undefined4 *)((int)in_stack_00000004 + (int)local_20 + (0xbb74 - (int)piVar1)) = uVar3;
    CUtlMemory<DataRangeWithFactorPair_t,int>::~CUtlMemory(pCVar4);
    local_20 = local_20 + -0x2f;
    this_00 = extraout_ECX_07;
  } while (in_stack_00000004 + 2 != local_20);
  return;
}



/* ----------------------------------------
 * CAmmoDef::~CAmmoDef
 * Address: 001c6610  Size: 52 bytes
 * ---------------------------------------- */

/* CAmmoDef::~CAmmoDef() */

void __thiscall CAmmoDef::~CAmmoDef(CAmmoDef *this)

{
  CAmmoDef *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CAmmoDef(this_00);
  operator_delete(in_stack_00000004);
  return;
}



