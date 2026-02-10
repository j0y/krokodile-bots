/*
 * CINSBotChatter -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 9
 */

/* ----------------------------------------
 * CINSBotChatter::CINSBotChatter
 * Address: 007590b0
 * ---------------------------------------- */

/* CINSBotChatter::CINSBotChatter(CINSNextBot*) */

void __thiscall CINSBotChatter::CINSBotChatter(CINSBotChatter *this,CINSNextBot *param_1)

{
  undefined4 in_stack_00000008;
  
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)param_1 = in_stack_00000008;
  Reset(this);
  return;
}



/* ----------------------------------------
 * CINSBotChatter::Update
 * Address: 00759670
 * ---------------------------------------- */

/* CINSBotChatter::Update() */

void __thiscall CINSBotChatter::Update(CINSBotChatter *this)

{
  uint *puVar1;
  float fVar2;
  BotStatement *pBVar3;
  BotStatement *this_00;
  char cVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int *piVar8;
  CINSBotChatter *extraout_ECX;
  CINSBotChatter *this_01;
  CINSBotChatter *extraout_ECX_00;
  BotStatement *extraout_ECX_01;
  BotStatement *this_02;
  BotStatement *extraout_ECX_02;
  BotStatement *extraout_ECX_03;
  CINSBotChatter *extraout_ECX_04;
  CINSBotChatter *extraout_ECX_05;
  CINSBotChatter *pCVar9;
  BotStatement *extraout_ECX_06;
  CINSBotChatter *extraout_ECX_07;
  CINSBotChatter *extraout_ECX_08;
  int unaff_EBX;
  bool bVar10;
  BotStatement *in_stack_00000004;
  BotStatement *pBVar11;
  BotStatement *pBVar12;
  undefined4 *local_30;
  
  __i686_get_pc_thunk_bx();
  pCVar9 = *(CINSBotChatter **)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x100c);
  bVar10 = pCVar9 != (CINSBotChatter *)0x0;
  if ((bVar10) &&
     (iVar7 = *(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x19b8), iVar5 = ThreadGetCurrentId(),
     pCVar9 = extraout_ECX, iVar7 == iVar5)) {
    piVar8 = *(int **)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1014);
    if (*piVar8 != unaff_EBX + 0x22a277 /* "CINSBotChatter::Update" */ /* "CINSBotChatter::Update" */) {
      piVar8 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar8,unaff_EBX + 0x22a277 /* "CINSBotChatter::Update" */ /* "CINSBotChatter::Update" */,(char *)0x0,
                                 unaff_EBX + 0x2275eb /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1014) = piVar8;
    }
    puVar1 = (uint *)(piVar8[0x1c] * 8 + *(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x10a0) + 4)
    ;
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    pCVar9 = *(CINSBotChatter **)(&LAB_0044d2f9 + unaff_EBX);
    pCVar9[0x1010] = (CINSBotChatter)0x0;
  }
  ReportEnemies(pCVar9);
  puVar6 = (undefined4 *)GetActiveStatement(this_01);
  pCVar9 = extraout_ECX_00;
  if (((puVar6 != (undefined4 *)0x0) &&
      (pCVar9 = (CINSBotChatter *)in_stack_00000004, *(int *)in_stack_00000004 == *(int *)*puVar6))
     && (cVar4 = BotStatement::Update(in_stack_00000004), pCVar9 = extraout_ECX_07, cVar4 == '\0'))
  {
    iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */) + 0x40))(*(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */));
    if (iVar7 != 0) {
      DevMsg(&UNK_0022a28e + unaff_EBX);
    }
    RemoveStatement((CINSBotChatter *)in_stack_00000004,in_stack_00000004);
    pCVar9 = extraout_ECX_08;
  }
  pBVar11 = in_stack_00000004;
  puVar6 = (undefined4 *)GetActiveStatement(pCVar9);
  local_30 = puVar6;
  if ((puVar6 != (undefined4 *)0x0) &&
     (local_30 = (undefined4 *)0x0, *(int *)in_stack_00000004 != *(int *)*puVar6)) {
    local_30 = puVar6;
  }
  pBVar3 = *(BotStatement **)(in_stack_00000004 + 4);
  this_00 = in_stack_00000004;
  while (pBVar12 = pBVar3, pBVar12 != (BotStatement *)0x0) {
    pBVar3 = *(BotStatement **)(pBVar12 + 4);
    pBVar11 = pBVar12;
    cVar4 = BotStatement::IsValid(this_00);
    if (cVar4 == '\0') {
      pBVar11 = in_stack_00000004;
      RemoveStatement((CINSBotChatter *)this_02,in_stack_00000004);
      this_00 = extraout_ECX_02;
    }
    else {
      this_00 = this_02;
      if (pBVar12[0x28] == (BotStatement)0x0) {
        fVar2 = *(float *)(**(int **)(unaff_EBX + 0x44d225 /* &gpGlobals */ /* &gpGlobals */) + 0xc);
        if (*(float *)(pBVar12 + 0x20) <= fVar2 && fVar2 != *(float *)(pBVar12 + 0x20)) {
          iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */) + 0x40))
                            (*(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */));
          if (iVar7 != 0) {
            DevMsg(&UNK_0022a2a2 + unaff_EBX);
          }
          pBVar11 = in_stack_00000004;
          RemoveStatement((CINSBotChatter *)in_stack_00000004,in_stack_00000004);
          this_00 = extraout_ECX_03;
        }
        else if ((local_30 != (undefined4 *)0x0) &&
                (puVar6 = local_30, cVar4 = BotStatement::IsRedundant(this_02,pBVar12),
                pBVar11 = pBVar12, this_00 = extraout_ECX_01, cVar4 != '\0')) {
          iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */) + 0x40))
                            (*(int **)(unaff_EBX + 0x44da6d /* &ins_debug_chatter */ /* &ins_debug_chatter */),puVar6);
          pCVar9 = extraout_ECX_04;
          if (iVar7 != 0) {
            DevMsg(&UNK_0022a331 + unaff_EBX);
            pCVar9 = extraout_ECX_05;
          }
          pBVar11 = in_stack_00000004;
          RemoveStatement(pCVar9,in_stack_00000004);
          this_00 = extraout_ECX_06;
        }
      }
    }
  }
  if ((bVar10) &&
     (((*(char *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1010) == '\0' ||
       (*(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x100c) != 0)) &&
      (iVar7 = *(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x19b8),
      iVar5 = ThreadGetCurrentId(pBVar11), iVar7 == iVar5)))) {
    cVar4 = CVProfNode::ExitScope();
    iVar7 = *(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1014);
    if (cVar4 != '\0') {
      iVar7 = *(int *)(iVar7 + 100);
      *(int *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1014) = iVar7;
    }
    *(bool *)(*(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1010) =
         iVar7 == *(int *)(&LAB_0044d2f9 + unaff_EBX) + 0x1018;
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSBotChatter::AddStatement
 * Address: 00758ee0
 * ---------------------------------------- */

/* CINSBotChatter::AddStatement(BotStatement*, bool) */

void __thiscall
CINSBotChatter::AddStatement(CINSBotChatter *this,BotStatement *param_1,bool param_2)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  BotStatement *extraout_ECX;
  BotStatement *this_00;
  BotStatement *extraout_ECX_00;
  int iVar4;
  undefined3 in_stack_00000009;
  char in_stack_0000000c;
  int local_20;
  
  __i686_get_pc_thunk_bx();
  cVar2 = (**(code **)(**(int **)param_1 + 0x118))(*(int **)param_1);
  if ((cVar2 == '\0') && (in_stack_0000000c == '\0')) {
    if (_param_2 == (BotStatement *)0x0) {
      return;
    }
  }
  else if (*(int *)(_param_2 + 0x68) != 0) {
    iVar3 = *(int *)(param_1 + 4);
    this_00 = extraout_ECX;
    iVar4 = iVar3;
    if (iVar3 == 0) {
      *(undefined4 *)(_param_2 + 4) = 0;
      *(undefined4 *)(_param_2 + 8) = 0;
      *(BotStatement **)(param_1 + 4) = _param_2;
      return;
    }
    do {
      cVar2 = BotStatement::IsRedundant(this_00,_param_2);
      if (cVar2 != '\0') goto LAB_00758f19;
      piVar1 = (int *)(iVar4 + 4);
      this_00 = extraout_ECX_00;
      iVar4 = *piVar1;
    } while (*piVar1 != 0);
    if (*(float *)(_param_2 + 0x1c) < *(float *)(iVar3 + 0x1c)) {
      *(undefined4 *)(_param_2 + 8) = 0;
      *(undefined4 *)(_param_2 + 4) = *(undefined4 *)(param_1 + 4);
      *(BotStatement **)(*(int *)(param_1 + 4) + 8) = _param_2;
      *(BotStatement **)(param_1 + 4) = _param_2;
      return;
    }
    do {
      local_20 = iVar3;
      iVar3 = *(int *)(local_20 + 4);
      if (iVar3 == 0) goto LAB_00758fa3;
    } while (*(float *)(iVar3 + 0x1c) <= *(float *)(_param_2 + 0x1c));
    *(BotStatement **)(iVar3 + 8) = _param_2;
    iVar3 = *(int *)(local_20 + 4);
LAB_00758fa3:
    *(int *)(_param_2 + 4) = iVar3;
    *(BotStatement **)(local_20 + 4) = _param_2;
    *(int *)(_param_2 + 8) = local_20;
    return;
  }
LAB_00758f19:
  piVar1 = *(int **)(_param_2 + 0x14);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
  }
  operator_delete(_param_2);
  return;
}



/* ----------------------------------------
 * CINSBotChatter::GetActiveStatement
 * Address: 007590d0
 * ---------------------------------------- */

/* CINSBotChatter::GetActiveStatement() */

int __thiscall CINSBotChatter::GetActiveStatement(CINSBotChatter *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int unaff_EBX;
  int iVar4;
  undefined4 *in_stack_00000004;
  int local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(**(int **)(unaff_EBX + 0x44d7c5 /* &gpGlobals */ /* &gpGlobals */) + 0x14) < 1) {
    local_24 = 0;
  }
  else {
    local_20 = *(float *)(unaff_EBX + 0x22a925 /* "(knNWhen to change bot difficulty, 1 = instantly, 0 = when new bots are added" */ /* "(knNWhen to change bot difficulty, 1 = instantly, 0 = when new bots are added" */);
    iVar4 = 1;
    local_24 = 0;
LAB_00759110:
    do {
      piVar2 = (int *)UTIL_PlayerByIndex(iVar4);
      if (piVar2 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar2 + 0x7b0 /* NextBotPlayer::IsBot */))(piVar2);
        if ((cVar1 == '\0') && (cVar1 = (**(code **)(*piVar2 + 0x118 /* CBaseEntity::IsAlive */))(piVar2), cVar1 == '\0')) {
          iVar4 = iVar4 + 1;
          iVar3 = **(int **)(unaff_EBX + 0x44d7c5 /* &gpGlobals */ /* &gpGlobals */);
          if (*(int *)(iVar3 + 0x14) < iVar4) break;
          goto LAB_00759110;
        }
        cVar1 = CBaseEntity::InSameTeam((CBaseEntity *)*in_stack_00000004);
        if ((cVar1 != '\0') &&
           (piVar2 = (int *)__dynamic_cast(piVar2,*(undefined4 *)(unaff_EBX + 0x44d6a9 /* &typeinfo for CBasePlayer */ /* &typeinfo for CBasePlayer */),
                                           *(undefined4 *)(unaff_EBX + 0x44d94d /* &typeinfo for CINSNextBot */ /* &typeinfo for CINSNextBot */),0),
           piVar2 != (int *)0x0)) {
          iVar3 = (**(code **)(*piVar2 + 0x978 /* CINSNextBot::GetChatter */))(piVar2);
          iVar3 = *(int *)(iVar3 + 4);
          if (iVar3 != 0) {
            cVar1 = *(char *)(iVar3 + 0x28);
            while( true ) {
              if (cVar1 != '\0') {
                return iVar3;
              }
              if (*(float *)(iVar3 + 0x1c) <= local_20 && local_20 != *(float *)(iVar3 + 0x1c)) {
                local_20 = *(float *)(iVar3 + 0x18);
                local_24 = iVar3;
              }
              iVar3 = *(int *)(iVar3 + 4);
              if (iVar3 == 0) break;
              cVar1 = *(char *)(iVar3 + 0x28);
            }
          }
        }
      }
      iVar4 = iVar4 + 1;
      iVar3 = **(int **)(unaff_EBX + 0x44d7c5 /* &gpGlobals */ /* &gpGlobals */);
    } while (iVar4 <= *(int *)(iVar3 + 0x14));
    if ((local_24 != 0) &&
       (*(float *)(iVar3 + 0xc) <= *(float *)(local_24 + 0x1c) &&
        *(float *)(local_24 + 0x1c) != *(float *)(iVar3 + 0xc))) {
      return 0;
    }
  }
  return local_24;
}



/* ----------------------------------------
 * CINSBotChatter::IdleChatter
 * Address: 00759950
 * ---------------------------------------- */

/* CINSBotChatter::IdleChatter() */

void __thiscall CINSBotChatter::IdleChatter(CINSBotChatter *this)

{
  uint *puVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  char cVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int *piVar10;
  BotStatement *this_00;
  CINSBotChatter *this_01;
  int unaff_EBX;
  bool bVar11;
  float10 fVar12;
  BotStatement *in_stack_00000004;
  BotStatement *pBVar13;
  
  __i686_get_pc_thunk_bx();
  iVar4 = *(int *)(unaff_EBX + 0x44d019 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar11 = *(int *)(iVar4 + 0x100c) != 0;
  if ((bVar11) && (iVar9 = *(int *)(iVar4 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar9 == iVar7))
  {
    piVar10 = *(int **)(iVar4 + 0x1014);
    if (*piVar10 != unaff_EBX + 0x229fd6 /* "CINSBotChatter::IdleChatter" */ /* "CINSBotChatter::IdleChatter" */) {
      piVar10 = (int *)CVProfNode::GetSubNode
                                 ((char *)piVar10,unaff_EBX + 0x229fd6 /* "CINSBotChatter::IdleChatter" */ /* "CINSBotChatter::IdleChatter" */,(char *)0x0,
                                  unaff_EBX + 0x22730b /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(iVar4 + 0x1014) = piVar10;
    }
    puVar1 = (uint *)(*(int *)(iVar4 + 0x10a0) + piVar10[0x1c] * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar4 + 0x1010) = 0;
  }
  pBVar13 = *(BotStatement **)in_stack_00000004;
  cVar6 = (**(code **)(*(int *)pBVar13 + 0x118))(pBVar13);
  if (cVar6 != '\0') {
    iVar9 = *(int *)in_stack_00000004;
    if (*(int *)(iVar9 + 0xb448) == 0) {
      pBVar13 = *(BotStatement **)(unaff_EBX + 0x44ced5 /* &nb_blind */ /* &nb_blind */);
      iVar9 = (**(code **)(*(int *)pBVar13 + 0x40))(pBVar13);
      if (iVar9 == 0) goto LAB_007599e8;
      iVar9 = *(int *)in_stack_00000004;
    }
    if (0.0 < *(float *)(iVar9 + 0x1820)) {
      pBVar13 = (BotStatement *)(iVar9 + 0x1818);
      fVar12 = (float10)CountdownTimer::Now();
      if ((float)fVar12 < *(float *)(iVar9 + 0x1820) || (float)fVar12 == *(float *)(iVar9 + 0x1820))
      goto LAB_007599e8;
    }
    puVar8 = (undefined4 *)::operator_new(0x6c);
    puVar8[1] = 0;
    fVar2 = *(float *)(unaff_EBX + 0x1cae11 /* 5.0f */ /* 5.0f */);
    puVar8[2] = 0;
    *puVar8 = in_stack_00000004;
    iVar9 = **(int **)(unaff_EBX + 0x44cf45 /* &gpGlobals */ /* &gpGlobals */);
    uVar5 = *(undefined4 *)(iVar9 + 0xc);
    puVar8[9] = 0;
    puVar8[3] = 2;
    puVar8[4] = 0xffffffff;
    puVar8[5] = 0;
    puVar8[6] = uVar5;
    puVar8[7] = *(undefined4 *)(iVar9 + 0xc);
    fVar3 = *(float *)(iVar9 + 0xc);
    *(undefined1 *)(puVar8 + 10) = 0;
    puVar8[0xb] = 0;
    puVar8[0x19] = 0xffffffff;
    puVar8[8] = fVar2 + fVar3;
    puVar8[0x1a] = 0;
    puVar8[0x14] = 1;
    puVar8[0x18] = 1;
    BotStatement::AppendConcept(this_00,(int)puVar8);
    AddStatement(this_01,in_stack_00000004,SUB41(puVar8,0));
    pBVar13 = in_stack_00000004;
  }
LAB_007599e8:
  if ((bVar11) &&
     (((*(char *)(iVar4 + 0x1010) == '\0' || (*(int *)(iVar4 + 0x100c) != 0)) &&
      (iVar9 = *(int *)(iVar4 + 0x19b8), iVar7 = ThreadGetCurrentId(pBVar13), iVar9 == iVar7)))) {
    cVar6 = CVProfNode::ExitScope();
    iVar9 = *(int *)(iVar4 + 0x1014);
    if (cVar6 != '\0') {
      iVar9 = *(int *)(iVar9 + 100);
      *(int *)(iVar4 + 0x1014) = iVar9;
    }
    *(bool *)(iVar4 + 0x1010) = iVar9 == iVar4 + 0x1018;
    return;
  }
  return;
}



/* ----------------------------------------
 * CINSBotChatter::RemoveStatement
 * Address: 00759000
 * ---------------------------------------- */

/* CINSBotChatter::RemoveStatement(BotStatement*) */

void __thiscall CINSBotChatter::RemoveStatement(CINSBotChatter *this,BotStatement *param_1)

{
  int *piVar1;
  undefined4 uVar2;
  BotStatement *pBVar3;
  void *in_stack_00000008;
  
  uVar2 = __i686_get_pc_thunk_bx();
  if (*(int *)((int)in_stack_00000008 + 4) != 0) {
    *(undefined4 *)(*(int *)((int)in_stack_00000008 + 4) + 8) =
         *(undefined4 *)((int)in_stack_00000008 + 8);
    uVar2 = *(undefined4 *)((int)in_stack_00000008 + 4);
  }
  pBVar3 = *(BotStatement **)((int)in_stack_00000008 + 8);
  if (*(BotStatement **)((int)in_stack_00000008 + 8) == (BotStatement *)0x0) {
    pBVar3 = param_1;
  }
  *(undefined4 *)(pBVar3 + 4) = uVar2;
  piVar1 = *(int **)((int)in_stack_00000008 + 0x14);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
  }
  operator_delete(in_stack_00000008);
  return;
}



/* ----------------------------------------
 * CINSBotChatter::ReportEnemies
 * Address: 00759240
 * ---------------------------------------- */

/* CINSBotChatter::ReportEnemies() */

void __thiscall CINSBotChatter::ReportEnemies(CINSBotChatter *this)

{
  uint *puVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  int iVar5;
  int *piVar6;
  int *piVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  BotStatement *this_02;
  CINSBotChatter *extraout_ECX;
  BotStatement *this_03;
  int unaff_EBX;
  int iVar12;
  bool bVar13;
  float10 fVar14;
  BotStatement *in_stack_00000004;
  code *pcVar15;
  undefined4 uVar16;
  
  __i686_get_pc_thunk_bx();
  bVar13 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bVar13) &&
     (iVar12 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar5 = ThreadGetCurrentId(),
     iVar12 == iVar5)) {
    piVar6 = *(int **)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar6 != unaff_EBX + 0x22a689 /* "CINSBotChatter::ReportEnemies" */ /* "CINSBotChatter::ReportEnemies" */) {
      piVar6 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar6,unaff_EBX + 0x22a689 /* "CINSBotChatter::ReportEnemies" */ /* "CINSBotChatter::ReportEnemies" */,(char *)0x0,
                                 (int)(&UNK_00227a1b + unaff_EBX));
      *(int **)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar6;
    }
    puVar1 = (uint *)(piVar6[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  pcVar15 = *(code **)in_stack_00000004;
  cVar4 = (**(code **)(*(int *)pcVar15 + 0x118))(pcVar15);
  if (cVar4 != '\0') {
    iVar12 = *(int *)in_stack_00000004;
    if (*(int *)(iVar12 + 0xb444) == 0) {
      in_stack_00000004[8] = (BotStatement)0x0;
    }
    else {
      if (0.0 < *(float *)(iVar12 + 0x1820)) {
        pcVar15 = (code *)(iVar12 + 0x1818);
        fVar14 = (float10)CountdownTimer::Now();
        if ((float)fVar14 < *(float *)(iVar12 + 0x1820) ||
            (float)fVar14 == *(float *)(iVar12 + 0x1820)) goto LAB_007592ac;
      }
      if (in_stack_00000004[8] == (BotStatement)0x0) {
        iVar12 = 1;
        in_stack_00000004[8] = (BotStatement)0x1;
        do {
          piVar6 = (int *)UTIL_PlayerByIndex(iVar12);
          if ((piVar6 != (int *)0x0) && (piVar7 = *(int **)in_stack_00000004, piVar6 != piVar7)) {
            piVar7 = (int *)(**(code **)(*piVar7 + 0x974 /* CINSNextBot::GetVisionInterface */))(piVar7);
            piVar7 = (int *)(**(code **)(*piVar7 + 0xe4 /* IVision::GetKnown */))(piVar7,piVar6);
            if ((piVar7 != (int *)0x0) &&
               (cVar4 = (**(code **)(*piVar7 + 0x4c /* CBasePlayer::ShouldTransmit */))(piVar7), cVar4 != '\0')) {
              fVar14 = (float10)(**(code **)(*piVar7 + 0x48 /* CBaseEntity::SetOwnerEntity */))(piVar7);
              iVar5 = CBaseEntity::GetTeamNumber(this_00);
              iVar8 = CBaseEntity::GetTeamNumber(this_01);
              if ((iVar5 != iVar8) && ((float)fVar14 <= *(float *)(unaff_EBX + 0x1cb521 /* 5.0f */ /* 5.0f */))) {
                puVar9 = (undefined4 *)::operator_new(0x6c);
                puVar9[1] = 0;
                puVar9[2] = 0;
                fVar2 = *(float *)(unaff_EBX + 0x15f8cd /* 8.0f */ /* 8.0f */);
                *puVar9 = in_stack_00000004;
                iVar12 = **(int **)(unaff_EBX + 0x44d655 /* &gpGlobals */ /* &gpGlobals */);
                uVar16 = *(undefined4 *)(iVar12 + 0xc);
                puVar9[9] = 0;
                puVar9[3] = 0;
                puVar9[4] = 0xffffffff;
                puVar9[5] = 0;
                puVar9[6] = uVar16;
                puVar9[7] = *(undefined4 *)(iVar12 + 0xc);
                iVar5 = 0;
                fVar3 = *(float *)(iVar12 + 0xc);
                *(undefined1 *)(puVar9 + 10) = 0;
                puVar9[0xb] = 0;
                puVar9[0x19] = 0xffffffff;
                puVar9[8] = fVar2 + fVar3;
                puVar9[0x1a] = 0;
                puVar9[0x18] = 0;
                if (piVar6[8] != 0) {
                  iVar5 = piVar6[8] - *(int *)(iVar12 + 0x5c) >> 4;
                }
                puVar9[4] = iVar5;
                puVar10 = (undefined4 *)::operator_new(8);
                puVar10[1] = 0xffffffff;
                *puVar10 = &UNK_00443ded + unaff_EBX;
                puVar11 = (undefined4 *)(**(code **)(*piVar6 + 0xc))(piVar6);
                puVar10[1] = *puVar11;
                puVar9[5] = puVar10;
                cVar4 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x44d6ad /* &g_pGameRules */ /* &g_pGameRules */) + 0xe0))
                                  ((int *)**(undefined4 **)(unaff_EBX + 0x44d6ad /* &g_pGameRules */ /* &g_pGameRules */));
                this_03 = this_02;
                if (cVar4 != '\0') {
                  BotStatement::AppendConcept(this_02,(int)puVar9);
                  this_03 = (BotStatement *)extraout_ECX;
                }
                uVar16 = 0;
                AddStatement((CINSBotChatter *)this_03,in_stack_00000004,SUB41(puVar9,0));
                if (!bVar13) {
                  return;
                }
                if ((*(char *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
                   (*(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
                  return;
                }
                iVar12 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
                iVar5 = ThreadGetCurrentId(in_stack_00000004,puVar9,uVar16);
                if (iVar12 != iVar5) {
                  return;
                }
                cVar4 = CVProfNode::ExitScope();
                iVar12 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
                if (cVar4 != '\0') {
                  iVar12 = *(int *)(iVar12 + 100);
                  *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar12;
                }
                goto LAB_00759484;
              }
            }
          }
          iVar12 = iVar12 + 1;
        } while (iVar12 != 0x32);
        pcVar15 = ::__tcf_0 + unaff_EBX + 5;
        Warning(pcVar15);
      }
    }
  }
LAB_007592ac:
  if ((!bVar13) ||
     (((*(char *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0' &&
       (*(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) ||
      (iVar12 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
      iVar5 = ThreadGetCurrentId(pcVar15), iVar12 != iVar5)))) {
    return;
  }
  cVar4 = CVProfNode::ExitScope();
  if (cVar4 == '\0') {
    iVar12 = *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
  }
  else {
    iVar12 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
    *(int *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar12;
  }
LAB_00759484:
  *(bool *)(*(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
       iVar12 == *(int *)(unaff_EBX + 0x44d729 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  return;
}



/* ----------------------------------------
 * CINSBotChatter::Reset
 * Address: 00759070
 * ---------------------------------------- */

/* CINSBotChatter::Reset() */

void __thiscall CINSBotChatter::Reset(CINSBotChatter *this)

{
  int iVar1;
  CINSBotChatter *extraout_ECX;
  BotStatement *in_stack_00000004;
  
  iVar1 = *(int *)(in_stack_00000004 + 4);
  while (iVar1 != 0) {
    iVar1 = *(int *)(iVar1 + 4);
    RemoveStatement(this,in_stack_00000004);
    this = extraout_ECX;
  }
  in_stack_00000004[8] = (BotStatement)0x0;
  return;
}



/* ----------------------------------------
 * CINSBotChatter::~CINSBotChatter
 * Address: 00758ed0
 * ---------------------------------------- */

/* CINSBotChatter::~CINSBotChatter() */

void __thiscall CINSBotChatter::~CINSBotChatter(CINSBotChatter *this)

{
  return;
}



