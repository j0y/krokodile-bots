/*
 * Action_CINSNextBot -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 109
 */

/* ----------------------------------------
 * Action<CINSNextBot>::OnStart
 * Address: 006f7cd0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnStart(CINSNextBot*, Action<CINSNextBot>*) */

void Action<CINSNextBot>::OnStart(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InitialContainedAction
 * Address: 006f7710
 * ---------------------------------------- */

/* Action<CINSNextBot>::InitialContainedAction(CINSNextBot*) */

undefined4 __cdecl Action<CINSNextBot>::InitialContainedAction(CINSNextBot *param_1)

{
  return 0;
}



/* ----------------------------------------
 * Action<CINSNextBot>::Update
 * Address: 006f7cf0
 * ---------------------------------------- */

/* Action<CINSNextBot>::Update(CINSNextBot*, float) */

void Action<CINSNextBot>::Update(CINSNextBot *param_1,float param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnEnd
 * Address: 006f7d10
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnEnd(CINSNextBot*, Action<CINSNextBot>*) */

void __cdecl Action<CINSNextBot>::OnEnd(CINSNextBot *param_1,Action *param_2)

{
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSuspend
 * Address: 006f7d20
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSuspend(CINSNextBot*, Action<CINSNextBot>*) */

void Action<CINSNextBot>::OnSuspend(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnResume
 * Address: 006f7d40
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnResume(CINSNextBot*, Action<CINSNextBot>*) */

void Action<CINSNextBot>::OnResume(CINSNextBot *param_1,Action *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnContact
 * Address: 006f7d60
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnContact(CINSNextBot*, CBaseEntity*, CGameTrace*) */

void Action<CINSNextBot>::OnContact(CINSNextBot *param_1,CBaseEntity *param_2,CGameTrace *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnContact
 * Address: 00703c50
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnContact(CBaseEntity*, CGameTrace*) */

void __thiscall
Action<CINSNextBot>::OnContact(Action<CINSNextBot> *this,CBaseEntity *param_1,CGameTrace *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  CBaseEntity *pCVar10;
  CGameTrace *pCVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x703c5b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a33a5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a33a5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a2c45 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27c03f /* "OnContact" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,&UNK_0027c0b1 + unaff_EBX,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x27c03f /* "OnContact" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pCVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0xe4))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a33a5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a33a5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a2c45 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27be40 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27c03f /* "OnContact" */);
            iVar4 = unaff_EBX + 0x27be4f /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x255e20 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27be1a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27be10 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27be26 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27be2b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x255e20 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pCVar11 = (CGameTrace *)(unaff_EBX + 0x255def /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,pCVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a34c5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a34c5 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pCVar11 = (CGameTrace *)(unaff_EBX + 0x27c03f /* "OnContact" */);
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a2c45 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27c07d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,pCVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x18 /* CBaseEntity::GetBaseEntity */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnMoveToSuccess
 * Address: 006f7d90
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnMoveToSuccess(CINSNextBot*, Path const*) */

void Action<CINSNextBot>::OnMoveToSuccess(CINSNextBot *param_1,Path *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnMoveToSuccess
 * Address: 007037b0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnMoveToSuccess(Path const*) */

void __thiscall Action<CINSNextBot>::OnMoveToSuccess(Action<CINSNextBot> *this,Path *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  undefined *puVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  Path *pPVar10;
  double dVar11;
  int in_stack_00000008;
  Path *pPVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7037bb;
  __i686_get_pc_thunk_bx();
  pPVar10 = param_1;
  if (param_1[0x30] != (Path)0x0) {
    do {
      piVar8 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar8 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar8 + 0x980 /* CINSNextBot::IsDebugging */))(piVar8,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a3845 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a3845 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pPVar10 + 0xc0))(pPVar10);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27c4cf /* "OnMoveToSuccess" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27c551 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a30e5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x27c4cf /* "OnMoveToSuccess" */));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pPVar12 = pPVar10;
      (**(code **)(*(int *)pPVar10 + 0xe8))(&local_44,pPVar10,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar8 = *(int **)(param_1 + 0x1c);
        if (piVar8 != (int *)0x0) {
          pPVar12 = (Path *)0x1;
          cVar1 = (**(code **)(*piVar8 + 0x980 /* CINSNextBot::IsDebugging */))(piVar8,1);
          if (((cVar1 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a3845 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a3845 /* &NextBotDebugHistory */)), iVar7 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a30e5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,
                       CINSRules_Survival::AwardTeamSupply + unaff_EBX,dVar11,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar11 >> 0x20);
            (**(code **)(*(int *)pPVar10 + 0xc0))(pPVar10);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x27c4cf /* "OnMoveToSuccess" */);
            iVar4 = unaff_EBX + 0x27c2ef /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x2562c0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar9,iVar4,uVar13);
            }
            puVar6 = &UNK_0027c2ba + unaff_EBX;
            if (local_44 != 2) {
              puVar6 = (undefined *)(unaff_EBX + 0x27c2b0 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar6 = &UNK_0027c2c6 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_0027c2cb + unaff_EBX,puVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25628f /* "%s
" */;
            puVar9 = &local_20;
            pPVar12 = (Path *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pPVar10 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pPVar12,puVar9,iVar4);
          }
        }
        else {
          if ((*(int *)(pPVar10 + 0x2c) == 3) &&
             (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a3965 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a3965 /* &developer */)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*(int *)pPVar10 + 0xb8))(pPVar10);
            iVar4 = unaff_EBX + 0x27c4cf /* "OnMoveToSuccess" */;
            pPVar12 = (Path *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a30e5 /* &gpGlobals */) + 0xc)
                              >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27c51d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar8 = *(int **)(pPVar10 + 0x24);
          if (piVar8 != (int *)0x0) {
            (**(code **)(*piVar8 + 4))(piVar8,pPVar12,puVar9,iVar4);
          }
          *(int *)(pPVar10 + 0x20) = local_44;
          *(int **)(pPVar10 + 0x24) = local_40;
          *(int *)(pPVar10 + 0x28) = local_3c;
          *(int *)(pPVar10 + 0x2c) = local_38;
        }
        break;
      }
      pPVar12 = pPVar10 + 0x14;
      pPVar10 = *(Path **)pPVar12;
    } while (*(Path **)pPVar12 != (Path *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x1c /* CBaseEntity::GetModelIndex */))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnMoveToFailure
 * Address: 006f7dc0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnMoveToFailure(CINSNextBot*, Path const*, MoveToFailureType) */

void Action<CINSNextBot>::OnMoveToFailure(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnMoveToFailure
 * Address: 00703300
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnMoveToFailure(Path const*, MoveToFailureType) */

void __thiscall
Action<CINSNextBot>::OnMoveToFailure
          (undefined4 param_1_00,int *param_1,int param_3,undefined4 param_4)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int *piVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x70330b;
  __i686_get_pc_thunk_bx();
  piVar8 = param_1;
  if ((char)param_1[0xc] != '\0') {
    do {
      uVar3 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar11 = (int *)param_1[7];
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a3cf5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a3cf5 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = (undefined1 *)param_1[7];
        }
        else {
          uVar3 = (**(code **)(*piVar8 + 0xc0))(piVar8);
          iVar5 = param_1[2];
          uVar4 = (**(code **)(*(int *)(param_1[7] + 0x2060) + 0x144))(param_1[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a3595 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27c96f /* "OnMoveToFailure" */),param_1[7] + 0x2060,0x80,&local_34,
                     unaff_EBX + 0x27ca01 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar10,uVar4,iVar5 + 0x11,uVar3,
                     (INextBot *)(unaff_EBX + 0x27c96f /* "OnMoveToFailure" */));
          uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
          puVar9 = (undefined1 *)param_1[7];
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar3,param_4);
      iVar5 = param_3;
      piVar11 = piVar8;
      (**(code **)(*piVar8 + 0xec))(&local_44,piVar8,puVar9,param_3,param_4);
      if (local_44 != 0) {
        piVar1 = (int *)param_1[7];
        if (piVar1 != (int *)0x0) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a3cf5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a3cf5 /* &NextBotDebugHistory */)), iVar7 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = param_1[2];
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(param_1[7] + 0x2060) + 0x144))(param_1[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a3595 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,param_1[7] + 0x2060,1,&local_30,unaff_EBX + 0x27c790 /* "%3.2f: %s:%s: " */,dVar10,pIVar6,
                       iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar8 + 0xc0))(piVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x27c96f /* "OnMoveToFailure" */);
            iVar5 = unaff_EBX + 0x27c79f /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x256770 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            iVar5 = unaff_EBX + 0x27c76a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27c760 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27c776 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,param_1[7] + 0x2060,1,&local_24,unaff_EBX + 0x27c77b /* "%s %s " */,iVar5,local_5c)
            ;
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            iVar5 = unaff_EBX + 0x256770 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar5 = local_3c;
            }
            local_1d = 0xff;
            in_stack_ffffff74 = CONCAT44(local_5c,iVar5);
            iVar5 = unaff_EBX + 0x25673f /* "%s
" */;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar8[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9,iVar5,in_stack_ffffff74);
          }
        }
        else {
          if ((piVar8[0xb] == 3) &&
             (iVar7 = (**(code **)(**(int **)(&DAT_004a3e15 + unaff_EBX) + 0x40))
                                (*(int **)(&DAT_004a3e15 + unaff_EBX)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar8 + 0xb8))(piVar8);
            iVar5 = unaff_EBX + 0x27c96f /* "OnMoveToFailure" */;
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a3595 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27c9cd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar8[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9,iVar5);
          }
          piVar8[8] = local_44;
          piVar8[9] = (int)local_40;
          piVar8[10] = local_3c;
          piVar8[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar8 + 5;
      piVar8 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    piVar8 = (int *)(**(code **)(*param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x20))(piVar8,param_3,param_4);
      piVar8 = (int *)(**(code **)(*param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnStuck
 * Address: 006f7df0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnStuck(CINSNextBot*) */

void Action<CINSNextBot>::OnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnStuck
 * Address: 00702e70
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnStuck() */

void __thiscall Action<CINSNextBot>::OnStuck(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x702e7b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4185 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a4185 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27cdf7 /* "OnStuck" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x27ce91 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(&DAT_004a3a25 + unaff_EBX) + 0xc),uVar4,
                     iVar5 + 0x11,uVar3,(INextBot *)(unaff_EBX + 0x27cdf7 /* "OnStuck" */));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0xf0))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4185 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a4185 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(&DAT_004a3a25 + unaff_EBX) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x27cc20 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,unaff_EBX + 0x27cdf7 /* "OnStuck" */);
            iVar5 = unaff_EBX + 0x27cc2f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(Path::NextSegment + unaff_EBX);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x27cbfa /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27cbf0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27cc06 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x27cc0b /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a42a5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a42a5 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)
                              (double)*(float *)(**(int **)(&DAT_004a3a25 + unaff_EBX) + 0xc) >>
                             0x20);
            DevMsg((char *)(unaff_EBX + 0x27ce5d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0x24))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnUnStuck
 * Address: 006f7780
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnUnStuck(CINSNextBot*) */

void Action<CINSNextBot>::OnUnStuck(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnUnStuck
 * Address: 007029e0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnUnStuck() */

void __thiscall Action<CINSNextBot>::OnUnStuck(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7029eb;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4615 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a4615 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27d27d /* "OnUnStuck" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x27d321 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a3eb5 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x27d27d /* "OnUnStuck" */));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0xf4))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4615 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a4615 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a3eb5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x27d0b0 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,unaff_EBX + 0x27d27d /* "OnUnStuck" */);
            iVar5 = unaff_EBX + 0x27d0bf /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(IIntention::~IIntention + unaff_EBX);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x27d08a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27d080 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27d096 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x27d09b /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4735 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a4735 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a3eb5 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27d2ed /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0x28))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnInjured
 * Address: 006f7e20
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnInjured(CINSNextBot*, CTakeDamageInfo const&) */

void Action<CINSNextBot>::OnInjured(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnInjured
 * Address: 00700e40
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnInjured(CTakeDamageInfo const&) */

void __thiscall Action<CINSNextBot>::OnInjured(Action<CINSNextBot> *this,CTakeDamageInfo *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  undefined *puVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CTakeDamageInfo *pCVar9;
  double dVar10;
  undefined *in_stack_00000008;
  CTakeDamageInfo *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x700e4b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CTakeDamageInfo)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a61b5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a61b5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27edd5 /* "OnInjured" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27eec1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a5a55 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x27edd5 /* "OnInjured" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar6 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x10c))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CTakeDamageInfo *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a61b5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a61b5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a5a55 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27ec50 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27edd5 /* "OnInjured" */);
            iVar4 = unaff_EBX + 0x27ec5f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x258c30 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            puVar6 = (undefined *)(unaff_EBX + 0x27ec2a /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar6 = (undefined *)(unaff_EBX + 0x27ec20 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar6 = &UNK_0027ec36 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27ec3b /* "%s %s " */,
                       puVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar6 = &UNK_00258bff + unaff_EBX;
            puVar8 = &local_20;
            pCVar11 = (CTakeDamageInfo *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,puVar6);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a62d5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a62d5 /* &developer */)), iVar4 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            puVar6 = (undefined *)(unaff_EBX + 0x27edd5 /* "OnInjured" */);
            pCVar11 = (CTakeDamageInfo *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a5a55 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27ee8d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,puVar6);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CTakeDamageInfo **)pCVar11;
    } while (*(CTakeDamageInfo **)pCVar11 != (CTakeDamageInfo *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x40 /* CBaseEntity::ComputeWorldSpaceSurroundingBox */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnKilled
 * Address: 006f78a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnKilled(CINSNextBot*, CTakeDamageInfo const&) */

void Action<CINSNextBot>::OnKilled(CINSNextBot *param_1,CTakeDamageInfo *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnKilled
 * Address: 007009a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnKilled(CTakeDamageInfo const&) */

void __thiscall Action<CINSNextBot>::OnKilled(Action<CINSNextBot> *this,CTakeDamageInfo *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CTakeDamageInfo *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CTakeDamageInfo *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7009ab;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CTakeDamageInfo)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6655 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a6655 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27774d /* "OnKilled" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27f361 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a5ef5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x27774d /* "OnKilled" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x110))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CTakeDamageInfo *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a6655 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a6655 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a5ef5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27f0f0 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27774d /* "OnKilled" */);
            iVar4 = unaff_EBX + 0x27f0ff /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x2590d0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27f0ca /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27f0c0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27f0d6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27f0db /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25909f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CTakeDamageInfo *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a6775 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a6775 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x27774d /* "OnKilled" */;
            pCVar11 = (CTakeDamageInfo *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a5ef5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27f32d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CTakeDamageInfo **)pCVar11;
    } while (*(CTakeDamageInfo **)pCVar11 != (CTakeDamageInfo *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x44 /* CINSPlayer::ShouldCollide */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnOtherKilled
 * Address: 006f7e50
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnOtherKilled(CINSNextBot*, CBaseCombatCharacter*, CTakeDamageInfo const&)
    */

void Action<CINSNextBot>::OnOtherKilled
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CTakeDamageInfo *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnOtherKilled
 * Address: 007004f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnOtherKilled(CBaseCombatCharacter*, CTakeDamageInfo const&) */

void __thiscall
Action<CINSNextBot>::OnOtherKilled
          (Action<CINSNextBot> *this,CBaseCombatCharacter *param_1,CTakeDamageInfo *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseCombatCharacter *pCVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  CBaseCombatCharacter *pCVar10;
  CTakeDamageInfo *pCVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7004fb;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseCombatCharacter)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6b05 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a6b05 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a63a5 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27f717 /* "OnOtherKilled" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27f811 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x27f717 /* "OnOtherKilled" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pCVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x114))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseCombatCharacter *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6b05 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a6b05 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a63a5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27f5a0 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27f717 /* "OnOtherKilled" */);
            iVar4 = unaff_EBX + 0x27f5af /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x259580 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27f57a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27f570 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27f586 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27f58b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x259580 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pCVar11 = (CTakeDamageInfo *)(unaff_EBX + 0x25954f /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CBaseCombatCharacter *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,pCVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6c25 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a6c25 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pCVar11 = (CTakeDamageInfo *)(unaff_EBX + 0x27f717 /* "OnOtherKilled" */);
            pCVar10 = (CBaseCombatCharacter *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a63a5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27f7dd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,pCVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseCombatCharacter **)pCVar10;
    } while (*(CBaseCombatCharacter **)pCVar10 != (CBaseCombatCharacter *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x48 /* CBaseEntity::SetOwnerEntity */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSight
 * Address: 006f7e80
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSight(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSight
 * Address: 00700050
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSight(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnSight(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined *in_stack_00000008;
  CBaseEntity *pCVar10;
  undefined *puVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x70005b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6fa5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a6fa5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_0027fbaf + unaff_EBX),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,&UNK_0027fcb1 + unaff_EBX,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a6845 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(&UNK_0027fbaf + unaff_EBX));
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar11 = in_stack_00000008;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x118))(&local_44,pCVar8,puVar7,in_stack_00000008);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a6fa5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a6fa5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a6845 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27fa40 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,&UNK_0027fbaf + unaff_EBX);
            iVar4 = unaff_EBX + 0x27fa4f /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)
                         (CUtlVector<CINSPlayer*,CUtlMemory<CINSPlayer*,int>>::Sort + unaff_EBX);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27fa1a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27fa10 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27fa26 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27fa2b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar11 = (undefined *)(unaff_EBX + 0x2599ef /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,puVar11);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a70c5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a70c5 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            puVar11 = &UNK_0027fbaf + unaff_EBX;
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a6845 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27fc7d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,puVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x4c /* CBasePlayer::ShouldTransmit */))(piVar6);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLostSight
 * Address: 006f7eb0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLostSight(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnLostSight(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLostSight
 * Address: 006ffbb0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLostSight(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnLostSight(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  undefined *puVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  CBaseEntity *pCVar10;
  double dVar11;
  int in_stack_00000008;
  CBaseEntity *pCVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6ffbbb;
  __i686_get_pc_thunk_bx();
  pCVar10 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar8 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar8 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar8 + 0x980 /* CINSNextBot::IsDebugging */))(piVar8,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a7445 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a7445 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar10 + 0xc0))(pCVar10);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x280043 /* "OnLostSight" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x280151 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a6ce5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x280043 /* "OnLostSight" */));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar12 = pCVar10;
      (**(code **)(*(int *)pCVar10 + 0x11c))(&local_44,pCVar10,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar8 = *(int **)(param_1 + 0x1c);
        if (piVar8 != (int *)0x0) {
          pCVar12 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar8 + 0x980 /* CINSNextBot::IsDebugging */))(piVar8,1);
          if (((cVar1 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a7445 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a7445 /* &NextBotDebugHistory */)), iVar7 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a6ce5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27fee0 /* "%3.2f: %s:%s: " */,
                       dVar11,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar11 >> 0x20);
            (**(code **)(*(int *)pCVar10 + 0xc0))(pCVar10);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x280043 /* "OnLostSight" */);
            iVar4 = unaff_EBX + 0x27feef /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x259ec0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar9,iVar4,uVar13);
            }
            puVar6 = (undefined *)(unaff_EBX + 0x27feba /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar6 = (undefined *)(unaff_EBX + 0x27feb0 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar6 = &UNK_0027fec6 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27fecb /* "%s %s " */,
                       puVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x259e8f /* "%s
" */;
            puVar9 = &local_20;
            pCVar12 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar10 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar12,puVar9,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar10 + 0x2c) == 3) &&
             (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a7565 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a7565 /* &developer */)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*(int *)pCVar10 + 0xb8))(pCVar10);
            iVar4 = unaff_EBX + 0x280043 /* "OnLostSight" */;
            pCVar12 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a6ce5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x28011d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar8 = *(int **)(pCVar10 + 0x24);
          if (piVar8 != (int *)0x0) {
            (**(code **)(*piVar8 + 4))(piVar8,pCVar12,puVar9,iVar4);
          }
          *(int *)(pCVar10 + 0x20) = local_44;
          *(int **)(pCVar10 + 0x24) = local_40;
          *(int *)(pCVar10 + 0x28) = local_3c;
          *(int *)(pCVar10 + 0x2c) = local_38;
        }
        break;
      }
      pCVar12 = pCVar10 + 0x14;
      pCVar10 = *(CBaseEntity **)pCVar12;
    } while (*(CBaseEntity **)pCVar12 != (CBaseEntity *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x50 /* CBasePlayer::UpdateTransmitState */))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSound
 * Address: 006f78d0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSound(CINSNextBot*, CBaseEntity*, Vector const&, KeyValues*) */

void Action<CINSNextBot>::OnSound
               (CINSNextBot *param_1,CBaseEntity *param_2,Vector *param_3,KeyValues *param_4)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSound
 * Address: 006ff6f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSound(CBaseEntity*, Vector const&, KeyValues*) */

void __thiscall
Action<CINSNextBot>::OnSound
          (Action<CINSNextBot> *this,CBaseEntity *param_1,Vector *param_2,KeyValues *param_3)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined4 in_stack_00000010;
  CBaseEntity *pCVar10;
  Vector *pVVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6ff6fb;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a7905 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a7905 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2804fb /* "OnSound" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x280611 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a71a5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x2804fb /* "OnSound" */));
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      uVar12 = CONCAT44(in_stack_00000010,param_3);
      pVVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x120))
                (&local_44,pCVar8,puVar7,param_2,param_3,in_stack_00000010);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a7905 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a7905 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a71a5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x2803a0 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x2804fb /* "OnSound" */);
            iVar4 = unaff_EBX + 0x2803af /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25a380 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x28037a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x280370 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x280386 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x28038b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25a380 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            uVar12 = CONCAT44(local_5c,iVar4);
            pVVar11 = (Vector *)(unaff_EBX + 0x25a34f /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,pVVar11,uVar12);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a7a25 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a7a25 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pVVar11 = (Vector *)(unaff_EBX + 0x2804fb /* "OnSound" */);
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a71a5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x2805dd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,pVVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x54 /* CBaseCombatCharacter::SetTransmit */))(piVar6,param_2,param_3,in_stack_00000010);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnWeaponFired
 * Address: 006f7930
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnWeaponFired(CINSNextBot*, CBaseCombatCharacter*, CBaseCombatWeapon*) */

void Action<CINSNextBot>::OnWeaponFired
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,CBaseCombatWeapon *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnWeaponFired
 * Address: 006fed50
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnWeaponFired(CBaseCombatCharacter*, CBaseCombatWeapon*) */

void __thiscall
Action<CINSNextBot>::OnWeaponFired
          (Action<CINSNextBot> *this,CBaseCombatCharacter *param_1,CBaseCombatWeapon *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  undefined *puVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseCombatCharacter *pCVar9;
  double dVar10;
  undefined4 in_stack_0000000c;
  CBaseCombatCharacter *pCVar11;
  CBaseCombatWeapon *pCVar12;
  undefined8 in_stack_ffffff74;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fed5b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseCombatCharacter)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(&DAT_004a82a5 + unaff_EBX) + 0x40))
                              (*(int **)(&DAT_004a82a5 + unaff_EBX)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a7b45 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x283fdd /* "OnWeaponFired" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x280fb1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar10,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x283fdd /* "OnWeaponFired" */));
          uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pCVar12 = param_2;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x128))(&local_44,pCVar9,puVar8,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseCombatCharacter *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(&DAT_004a82a5 + unaff_EBX) + 0x40))
                                 (*(int **)(&DAT_004a82a5 + unaff_EBX)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a7b45 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x280d40 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x283fdd /* "OnWeaponFired" */);
            iVar4 = unaff_EBX + 0x280d4f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25ad20 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar13);
            }
            puVar6 = (undefined *)(unaff_EBX + 0x280d1a /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar6 = (undefined *)(unaff_EBX + 0x280d10 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar6 = &UNK_00280d26 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_00280d2b + unaff_EBX,puVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            iVar4 = unaff_EBX + 0x25ad20 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            local_1d = 0xff;
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pCVar12 = (CBaseCombatWeapon *)(unaff_EBX + 0x25acef /* "%s
" */);
            puVar8 = &local_20;
            pCVar11 = (CBaseCombatCharacter *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,pCVar12,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a83c5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a83c5 /* &developer */)), iVar4 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            pCVar12 = (CBaseCombatWeapon *)(unaff_EBX + 0x283fdd /* "OnWeaponFired" */);
            pCVar11 = (CBaseCombatCharacter *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a7b45 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x280f7d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,pCVar12);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseCombatCharacter **)pCVar11;
    } while (*(CBaseCombatCharacter **)pCVar11 != (CBaseCombatCharacter *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x5c /* CINSNextBot::Spawn */))(piVar7,param_2,in_stack_0000000c);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnPickUp
 * Address: 006f7990
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnPickUp(CINSNextBot*, CBaseEntity*, CBaseCombatCharacter*) */

void Action<CINSNextBot>::OnPickUp
               (CINSNextBot *param_1,CBaseEntity *param_2,CBaseCombatCharacter *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnPickUp
 * Address: 006fdf60
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnPickUp(CBaseEntity*, CBaseCombatCharacter*) */

void __thiscall
Action<CINSNextBot>::OnPickUp
          (Action<CINSNextBot> *this,CBaseEntity *param_1,CBaseCombatCharacter *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  CBaseEntity *pCVar10;
  CBaseCombatCharacter *pCVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fdf6b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a9095 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a9095 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a8935 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x281c64 /* "OnPickUp" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x281da1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x281c64 /* "OnPickUp" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pCVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x134))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a9095 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a9095 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a8935 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x281b30 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x281c64 /* "OnPickUp" */);
            iVar4 = unaff_EBX + 0x281b3f /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25bb10 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x281b0a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x281b00 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x281b16 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x281b1b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            iVar4 = unaff_EBX + 0x25bb10 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            local_1d = 0xff;
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pCVar11 = (CBaseCombatCharacter *)(&UNK_0025badf + unaff_EBX);
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,pCVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a91b5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a91b5 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pCVar11 = (CBaseCombatCharacter *)(unaff_EBX + 0x281c64 /* "OnPickUp" */);
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a8935 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x281d6d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,pCVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x68 /* CBaseAnimating::OnNewModel */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnDrop
 * Address: 006f79c0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnDrop(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnDrop(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnDrop
 * Address: 006fdac0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnDrop(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnDrop(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fdacb;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a9535 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a9535 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2820fd /* "OnDrop" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x282241 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a8dd5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x2820fd /* "OnDrop" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x138))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a9535 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a9535 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a8dd5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,
                       CEntityFactory<CLogicTraining>::Create + unaff_EBX,dVar10,pIVar5,iVar4 + 0x11
                      );
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x2820fd /* "OnDrop" */);
            iVar4 = unaff_EBX + 0x281fdf /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25bfb0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x281faa /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x281fa0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x281fb6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x281fbb /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25bf7f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a9655 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a9655 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x2820fd /* "OnDrop" */;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a8dd5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg(&UNK_0028220d + unaff_EBX);
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x6c /* CBaseEntity::InitSharedVars */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandApproach
 * Address: 006f7a20
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandApproach(CINSNextBot*, Vector const&, float) */

void Action<CINSNextBot>::OnCommandApproach(CINSNextBot *param_1,Vector *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandApproach
 * Address: 006f7a50
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandApproach(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnCommandApproach(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandApproach
 * Address: 006fc820
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandApproach(CBaseEntity*) */

void __thiscall
Action<CINSNextBot>::OnCommandApproach(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined *in_stack_00000008;
  CBaseEntity *pCVar10;
  undefined *puVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fc82b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa7d5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4aa7d5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x28336d /* "OnCommandApproach" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x2834e1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4aa075 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x28336d /* "OnCommandApproach" */));
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar11 = in_stack_00000008;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x148))(&local_44,pCVar8,puVar7,in_stack_00000008);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa7d5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4aa7d5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4aa075 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x283270 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x28336d /* "OnCommandApproach" */);
            iVar4 = unaff_EBX + 0x28327f /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)
                         (CUtlRBTree<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,weaponUpgradeDefinition_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
                          ::Find + unaff_EBX);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x28324a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x283240 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x283256 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x28325b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar11 = &UNK_0025d21f + unaff_EBX;
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,puVar11);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa8f5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4aa8f5 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            puVar11 = (undefined *)(unaff_EBX + 0x28336d /* "OnCommandApproach" */);
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4aa075 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x2834ad /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,puVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x7c /* CBaseEntity::KeyValue */))(piVar6);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandApproach
 * Address: 006fccc0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandApproach(Vector const&, float) */

void __thiscall
Action<CINSNextBot>::OnCommandApproach(Action<CINSNextBot> *this,Vector *param_1,float param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  Vector *pVVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  Vector *pVVar10;
  undefined *puVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fcccb;
  __i686_get_pc_thunk_bx();
  pVVar8 = param_1;
  if (param_1[0x30] != (Vector)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa335 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4aa335 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pVVar8 + 0xc0))(pVVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(CEntityFactory<CLogicBranchList>::GetEntitySize +
                                               unaff_EBX + 5) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x282ecd /* "OnCommandApproach" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x283041 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x282ecd /* "OnCommandApproach" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      puVar11 = (undefined *)param_2;
      pVVar10 = pVVar8;
      (**(code **)(*(int *)pVVar8 + 0x144))(&local_44,pVVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pVVar10 = (Vector *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa335 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4aa335 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(CEntityFactory<CLogicBranchList>::GetEntitySize +
                                                 unaff_EBX + 5) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x282dd0 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pVVar8 + 0xc0))(pVVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x282ecd /* "OnCommandApproach" */);
            iVar4 = unaff_EBX + 0x282ddf /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25cdb0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x282daa /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x282da0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x282db6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x282dbb /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25cdb0 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            puVar11 = &UNK_0025cd7f + unaff_EBX;
            puVar7 = &local_20;
            pVVar10 = (Vector *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pVVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pVVar10,puVar7,puVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pVVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aa455 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4aa455 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pVVar8 + 0xb8))(pVVar8);
            puVar11 = (undefined *)(unaff_EBX + 0x282ecd /* "OnCommandApproach" */);
            pVVar10 = (Vector *)
                      ((ulonglong)
                       (double)*(float *)(**(int **)(CEntityFactory<CLogicBranchList>::GetEntitySize
                                                    + unaff_EBX + 5) + 0xc) >> 0x20);
            DevMsg(&UNK_0028300d + unaff_EBX);
          }
          piVar6 = *(int **)(pVVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pVVar10,puVar7,puVar11);
          }
          *(int *)(pVVar8 + 0x20) = local_44;
          *(int **)(pVVar8 + 0x24) = local_40;
          *(int *)(pVVar8 + 0x28) = local_3c;
          *(int *)(pVVar8 + 0x2c) = local_38;
        }
        break;
      }
      pVVar10 = pVVar8 + 0x14;
      pVVar8 = *(Vector **)pVVar10;
    } while (*(Vector **)pVVar10 != (Vector *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x78 /* CBaseEntity::OnParseMapDataFinished */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandString
 * Address: 006f7b10
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandString(CINSNextBot*, char const*) */

void Action<CINSNextBot>::OnCommandString(CINSNextBot *param_1,char *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandString
 * Address: 006fb580
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandString(char const*) */

void __thiscall Action<CINSNextBot>::OnCommandString(Action<CINSNextBot> *this,char *param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  undefined *in_stack_00000008;
  int *piVar10;
  undefined *puVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fb58b;
  __i686_get_pc_thunk_bx();
  piVar7 = (int *)param_1;
  if (param_1[0x30] != '\0') {
    do {
      piVar10 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4aba75 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4aba75 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar7 + 0xc0))(piVar7);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2845cd /* "OnCommandString" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x284781 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ab315 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x2845cd /* "OnCommandString" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar11 = in_stack_00000008;
      piVar10 = piVar7;
      (**(code **)(*piVar7 + 0x158))(&local_44,piVar7,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4aba75 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4aba75 /* &NextBotDebugHistory */)), iVar5 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ab315 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x284510 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar7 + 0xc0))(piVar7);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x2845cd /* "OnCommandString" */);
            iVar5 = unaff_EBX + 0x28451f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25e4f0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar12);
            }
            iVar5 = unaff_EBX + 0x2844ea /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x2844e0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x2844f6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x2844fb /* "%s %s " */,
                       iVar5,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar11 = &UNK_0025e4bf + unaff_EBX;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar7[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8,puVar11);
          }
        }
        else {
          if ((piVar7[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4abb95 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4abb95 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar7 + 0xb8))(piVar7);
            puVar11 = (undefined *)(unaff_EBX + 0x2845cd /* "OnCommandString" */);
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ab315 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x28474d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar7[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8,puVar11);
          }
          piVar7[8] = local_44;
          piVar7[9] = (int)local_40;
          piVar7[10] = local_3c;
          piVar7[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar7 + 5;
      piVar7 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x8c))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::ApplyResult
 * Address: 00752370
 * ---------------------------------------- */

/* Action<CINSNextBot>::ApplyResult(CINSNextBot*, Behavior<CINSNextBot>*, ActionResult<CINSNextBot>)
    */

Action<CINSNextBot> * __cdecl
Action<CINSNextBot>::ApplyResult
          (Action<CINSNextBot> *param_1,Behavior *param_2,Action<CINSNextBot> *param_3,int param_4,
          Behavior *param_5,INextBot *param_6)

{
  INextBot *pIVar1;
  char cVar2;
  undefined4 uVar3;
  Action<CINSNextBot> *pAVar4;
  int iVar5;
  int unaff_EBX;
  CINSNextBot *pCVar6;
  double dVar7;
  undefined4 uVar8;
  Behavior *pBVar9;
  undefined1 *puVar10;
  Behavior *pBVar11;
  undefined *puVar12;
  undefined8 in_stack_ffffff54;
  undefined8 uVar13;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  Action<CINSNextBot> *local_7c;
  undefined1 local_78;
  undefined1 local_77;
  undefined1 local_76;
  undefined1 local_75;
  undefined1 local_74;
  undefined1 local_73;
  undefined1 local_72;
  undefined1 local_71;
  undefined1 local_70;
  undefined1 local_6f;
  undefined1 local_6e;
  undefined1 local_6d;
  undefined1 local_6c;
  undefined1 local_6b;
  undefined1 local_6a;
  undefined1 local_69;
  undefined1 local_68;
  undefined1 local_67;
  undefined1 local_66;
  undefined1 local_65;
  undefined1 local_64;
  undefined1 local_63;
  undefined1 local_62;
  undefined1 local_61;
  undefined1 local_60;
  undefined1 local_5f;
  undefined1 local_5e;
  undefined1 local_5d;
  undefined1 local_5c;
  undefined1 local_5b;
  undefined1 local_5a;
  undefined1 local_59;
  undefined1 local_58;
  undefined1 local_57;
  undefined1 local_56;
  undefined1 local_55;
  undefined1 local_54;
  undefined1 local_53;
  undefined1 local_52;
  undefined1 local_51;
  undefined1 local_50;
  undefined1 local_4f;
  undefined1 local_4e;
  undefined1 local_4d;
  undefined1 local_4c;
  undefined1 local_4b;
  undefined1 local_4a;
  undefined1 local_49;
  undefined1 local_48;
  undefined1 local_47;
  undefined1 local_46;
  undefined1 local_45;
  undefined1 local_44;
  undefined1 local_43;
  undefined1 local_42;
  undefined1 local_41;
  undefined1 local_40;
  undefined1 local_3f;
  undefined1 local_3e;
  undefined1 local_3d;
  undefined1 local_3c;
  undefined1 local_3b;
  undefined1 local_3a;
  undefined1 local_39;
  undefined1 local_38;
  undefined1 local_37;
  undefined1 local_36;
  undefined1 local_35;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uVar3 = (undefined4)((ulonglong)in_stack_ffffff54 >> 0x20);
  uStack_14 = 0x75237b;
  __i686_get_pc_thunk_bx();
  pAVar4 = param_1;
  if (param_4 == 2) {
    do {
      pCVar6 = (CINSNextBot *)pAVar4;
      pAVar4 = (Action<CINSNextBot> *)*(CINSNextBot **)(pCVar6 + 0x18);
    } while (*(CINSNextBot **)(pCVar6 + 0x18) != (CINSNextBot *)0x0);
    cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1);
    if ((cVar2 != '\0') ||
       (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */) + 0x40))
                          (*(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */)), iVar5 != 0)) {
      pIVar1 = (INextBot *)(param_2 + 0x2060);
      uVar3 = (**(code **)(*(int *)(param_2 + 0x2060) + 0x144))(pIVar1);
      local_58 = 0xff;
      local_57 = 0xff;
      local_56 = 0x96;
      local_55 = 0xff;
      INextBot::DebugConColorMsg
                (pIVar1,pIVar1,1,&local_58,unaff_EBX + 0x22d720 /* "%3.2f: %s:%s: " */,
                 (double)*(float *)(**(int **)(unaff_EBX + 0x454525 /* &gpGlobals */) + 0xc),uVar3,param_3 + 0x11);
      uVar3 = (**(code **)(*(int *)param_1 + 0xb8))(param_1);
      local_54 = 0xff;
      local_53 = 0xff;
      local_52 = 0xff;
      local_51 = 0xff;
      INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_54,uVar3);
      local_50 = 0xff;
      iVar5 = unaff_EBX + 0x230b0e /* " caused " */;
      local_4f = 0;
      puVar10 = &local_50;
      local_4e = 0xff;
      local_4d = 0xff;
      uVar3 = 1;
      INextBot::DebugConColorMsg();
      uVar3 = (**(code **)(*(int *)pCVar6 + 0xb8))(pCVar6,uVar3,puVar10,iVar5);
      local_4c = 0xff;
      local_4b = 0xff;
      local_4a = 0xff;
      local_49 = 0xff;
      INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_4c,uVar3);
      local_48 = 0xff;
      iVar5 = unaff_EBX + 0x230b17 /* " to SUSPEND_FOR " */;
      local_47 = 0;
      puVar10 = &local_48;
      local_46 = 0xff;
      local_45 = 0xff;
      uVar3 = 1;
      INextBot::DebugConColorMsg();
      (**(code **)(*(int *)param_5 + 0xb8))(param_5,uVar3,puVar10,iVar5);
      local_44 = 0xff;
      local_43 = 0xff;
      local_42 = 0xff;
      local_41 = 0xff;
      INextBot::DebugConColorMsg();
      if (param_6 == (INextBot *)0x0) {
        local_3c = 0xff;
        local_3b = 0xff;
        local_3a = 0xff;
        local_39 = 0xff;
        INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_3c,unaff_EBX + 0x23c759 /* typeinfo name for CEntityFactory<CPropVehicle>+0x174 */);
      }
      else {
        local_40 = 0x96;
        local_3f = 0xff;
        local_3e = 0x96;
        local_3d = 0xff;
        INextBot::DebugConColorMsg(param_6,pIVar1,1,&local_40,unaff_EBX + 0x230b06 /* "  (%s)
" */,param_6);
      }
    }
    uVar3 = InvokeOnSuspend(param_3,pCVar6,param_2,(Action *)param_3);
    uVar13 = CONCAT44(uVar3,uVar3);
    pBVar11 = param_2;
    pAVar4 = param_3;
    InvokeOnStart((CINSNextBot *)&local_88,param_5,(Action *)param_2,(Action *)param_3);
    cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1,pBVar11,pAVar4,uVar13);
    if (cVar2 != '\0') {
      PrintStateToConsole();
    }
    pAVar4 = (Action<CINSNextBot> *)ApplyResult(param_5,param_2,param_3,local_88,local_84,local_80);
    return pAVar4;
  }
  if (param_4 == 3) {
    pBVar11 = *(Behavior **)(param_1 + 0x14);
    pAVar4 = param_3;
    pBVar9 = pBVar11;
    InvokeOnEnd(param_1,(CINSNextBot *)param_1,param_2,(Action *)param_3);
    cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1,pAVar4,pBVar9);
    if ((cVar2 != '\0') ||
       (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */) + 0x40))
                          (*(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */)), iVar5 != 0)) {
      pIVar1 = (INextBot *)(param_2 + 0x2060);
      uVar3 = (**(code **)(*(int *)(param_2 + 0x2060) + 0x144))(pIVar1);
      local_38 = 0xff;
      local_37 = 0xff;
      local_36 = 0x96;
      local_35 = 0xff;
      dVar7 = (double)*(float *)(**(int **)(unaff_EBX + 0x454525 /* &gpGlobals */) + 0xc);
      uVar8 = 1;
      pAVar4 = param_3 + 0x11;
      iVar5 = unaff_EBX + 0x22d720 /* "%3.2f: %s:%s: " */;
      puVar10 = &local_38;
      INextBot::DebugConColorMsg();
      (**(code **)(*(int *)param_1 + 0xb8))(param_1,uVar8,puVar10,iVar5,dVar7,uVar3,pAVar4);
      uVar3 = (undefined4)((ulonglong)dVar7 >> 0x20);
      local_34 = 0xff;
      local_33 = 0xff;
      local_32 = 0xff;
      local_31 = 0xff;
      INextBot::DebugConColorMsg();
      if (pBVar11 == (Behavior *)0x0) {
        local_28 = 0;
        local_27 = 0xff;
        local_26 = 0;
        local_25 = 0xff;
        INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_28,unaff_EBX + 0x230b37 /* " DONE." */);
      }
      else {
        local_30 = 0;
        local_2f = 0xff;
        local_2e = 0;
        local_2d = 0xff;
        INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_30,unaff_EBX + 0x230b28 /* " DONE, RESUME " */);
        (**(code **)(*(int *)pBVar11 + 0xb8))(pBVar11);
        local_2c = 0xff;
        local_2b = 0xff;
        local_2a = 0xff;
        local_29 = 0xff;
        INextBot::DebugConColorMsg();
      }
      if (param_6 == (INextBot *)0x0) {
        local_20 = 0xff;
        local_1f = 0xff;
        local_1e = 0xff;
        local_1d = 0xff;
        INextBot::DebugConColorMsg();
      }
      else {
        local_24 = 0x96;
        local_23 = 0xff;
        local_22 = 0x96;
        local_21 = 0xff;
        INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_24,unaff_EBX + 0x230b06 /* "  (%s)
" */,param_6);
      }
    }
    if (pBVar11 != (Behavior *)0x0) {
      uVar13 = CONCAT44(uVar3,param_1);
      pBVar9 = param_2;
      pAVar4 = param_3;
      InvokeOnResume((CINSNextBot *)&local_88,pBVar11,(Action *)param_2);
      cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1,pBVar9,pAVar4,uVar13);
      if (cVar2 != '\0') {
        PrintStateToConsole();
      }
      local_7c = param_1;
      CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>>::InsertBefore
                ((CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>> *)param_1,
                 (int)(param_3 + 0x3c),*(Action ***)(param_3 + 0x48));
      pAVar4 = (Action<CINSNextBot> *)
               ApplyResult(pBVar11,param_2,param_3,local_88,local_84,local_80);
      return pAVar4;
    }
    local_7c = param_1;
    CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>>::InsertBefore
              ((CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>> *)param_1,
               (int)(param_3 + 0x3c),*(Action ***)(param_3 + 0x48));
    param_1 = (Action<CINSNextBot> *)0x0;
  }
  else if (param_4 == 1) {
    if (param_5 != (Behavior *)0x0) {
      cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1);
      if ((cVar2 != '\0') ||
         (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */) + 0x40))
                            (*(int **)(unaff_EBX + 0x454c85 /* &NextBotDebugHistory */)), iVar5 != 0)) {
        uVar3 = (**(code **)(*(int *)(param_2 + 0x2060) + 0x144))(param_2 + 0x2060);
        local_78 = 0xff;
        local_77 = 0xff;
        local_76 = 0x96;
        local_75 = 0xff;
        dVar7 = (double)*(float *)(**(int **)(unaff_EBX + 0x454525 /* &gpGlobals */) + 0xc);
        uVar8 = 1;
        pAVar4 = param_3 + 0x11;
        iVar5 = unaff_EBX + 0x22d720 /* "%3.2f: %s:%s: " */;
        puVar10 = &local_78;
        INextBot::DebugConColorMsg();
        if (param_1 == (Action<CINSNextBot> *)param_5) {
          puVar12 = &UNK_00230af3 + unaff_EBX;
          local_74 = 0xff;
          puVar10 = &local_74;
          local_73 = 0;
          local_72 = 0;
          local_71 = 0xff;
          uVar8 = 1;
          INextBot::DebugConColorMsg();
          (**(code **)(*(int *)param_1 + 0xb8))(param_1,uVar8,puVar10,puVar12,dVar7,uVar3,pAVar4);
          local_70 = 0xff;
          local_6f = 0xff;
          local_6e = 0xff;
          local_6d = 0xff;
          INextBot::DebugConColorMsg();
        }
        else {
          (**(code **)(*(int *)param_1 + 0xb8))(param_1,uVar8,puVar10,iVar5);
          local_6c = 0xff;
          local_6b = 0xff;
          local_6a = 0xff;
          local_69 = 0xff;
          INextBot::DebugConColorMsg();
          puVar12 = &UNK_00230afa + unaff_EBX;
          local_68 = 0xff;
          puVar10 = &local_68;
          local_67 = 0;
          local_66 = 0;
          local_65 = 0xff;
          uVar3 = 1;
          INextBot::DebugConColorMsg();
          (**(code **)(*(int *)param_5 + 0xb8))(param_5,uVar3,puVar10,puVar12);
          local_64 = 0xff;
          local_63 = 0xff;
          local_62 = 0xff;
          local_61 = 0xff;
          INextBot::DebugConColorMsg();
        }
        if (param_6 == (INextBot *)0x0) {
          local_5c = 0xff;
          local_5b = 0xff;
          local_5a = 0xff;
          local_59 = 0xff;
          INextBot::DebugConColorMsg();
        }
        else {
          local_60 = 0x96;
          local_5f = 0xff;
          local_5e = 0x96;
          local_5d = 0xff;
          INextBot::DebugConColorMsg();
        }
      }
      InvokeOnEnd(param_1,(CINSNextBot *)param_1,param_2,(Action *)param_3);
      pBVar11 = param_2;
      InvokeOnStart((CINSNextBot *)&local_88,param_5,(Action *)param_2,(Action *)param_3);
      if (param_1 != (Action<CINSNextBot> *)param_5) {
        pBVar11 = (Behavior *)&local_7c;
        local_7c = param_1;
        CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>>::InsertBefore
                  ((CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>> *)param_1,
                   (int)(param_3 + 0x3c),*(Action ***)(param_3 + 0x48));
      }
      cVar2 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1,pBVar11);
      if (cVar2 != '\0') {
        PrintStateToConsole();
      }
      pAVar4 = (Action<CINSNextBot> *)
               ApplyResult(param_5,param_2,param_3,local_88,local_84,local_80);
      return pAVar4;
    }
    DevMsg((char *)(CINSBlockZoneBase::UpdateTransmitState + unaff_EBX + 1));
  }
  return param_1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::BuildDecoratedName
 * Address: 00751360
 * ---------------------------------------- */

/* Action<CINSNextBot>::BuildDecoratedName(char*, Action<CINSNextBot> const*) const */

Action * __thiscall
Action<CINSNextBot>::BuildDecoratedName(Action<CINSNextBot> *this,char *param_1,Action *param_2)

{
  char *pcVar1;
  Action<CINSNextBot> *this_00;
  Action<CINSNextBot> *this_01;
  int unaff_EBX;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  pcVar1 = (char *)(**(code **)(*in_stack_0000000c + 0xb8))();
  V_strncat((char *)param_2,pcVar1,0x100,-1);
  if (in_stack_0000000c[4] != 0) {
    V_strncat((char *)param_2,(char *)(unaff_EBX + 0x2319ff /* "( " */),0x100,-1);
    BuildDecoratedName(this_00,param_1,param_2);
    V_strncat((char *)param_2,(char *)(unaff_EBX + 0x23ebe4 /* " )" */),0x100,-1);
  }
  if (in_stack_0000000c[5] != 0) {
    V_strncat((char *)param_2,(char *)(unaff_EBX + 0x231a02 /* "<<" */),0x100,-1);
    BuildDecoratedName(this_01,param_1,param_2);
  }
  return param_2;
}



/* ----------------------------------------
 * Action<CINSNextBot>::DebugString
 * Address: 00751460
 * ---------------------------------------- */

/* Action<CINSNextBot>::DebugString() const */

void __thiscall Action<CINSNextBot>::DebugString(Action<CINSNextBot> *this)

{
  Action<CINSNextBot> *pAVar1;
  int unaff_EBX;
  Action<CINSNextBot> *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *(undefined1 *)(unaff_EBX + 0x59d377 /* Action<CINSNextBot>::DebugString */) = 0;
  pAVar1 = in_stack_00000004;
  do {
    pAVar1 = *(Action<CINSNextBot> **)(pAVar1 + 0xc);
  } while (pAVar1 != (Action<CINSNextBot> *)0x0);
  BuildDecoratedName(in_stack_00000004,(char *)in_stack_00000004,(Action *)(unaff_EBX + 0x59d377 /* Action<CINSNextBot>::DebugString */));
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::FirstContainedResponder
 * Address: 006f76f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::FirstContainedResponder() const */

undefined4 __thiscall Action<CINSNextBot>::FirstContainedResponder(Action<CINSNextBot> *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x10);
}



/* ----------------------------------------
 * Action<CINSNextBot>::GetFullName
 * Address: 006f7ff0
 * ---------------------------------------- */

/* Action<CINSNextBot>::GetFullName() const */

code * __thiscall Action<CINSNextBot>::GetFullName(Action<CINSNextBot> *this)

{
  int iVar1;
  char *pcVar2;
  int unaff_EBX;
  int iVar3;
  int *in_stack_00000004;
  char *local_11c [66];
  undefined4 uStack_14;
  
  uStack_14 = 0x6f7ffb;
  __i686_get_pc_thunk_bx();
  ::__tcf_0[unaff_EBX + 5] = (code)0x0;
  if (in_stack_00000004 != (int *)0x0) {
    iVar1 = 0;
    do {
      iVar3 = iVar1;
      pcVar2 = (char *)(**(code **)(*in_stack_00000004 + 0xb8))(in_stack_00000004);
      in_stack_00000004 = (int *)in_stack_00000004[3];
      local_11c[iVar3] = pcVar2;
      if (0x3f < iVar3 + 1) break;
      iVar1 = iVar3 + 1;
    } while (in_stack_00000004 != (int *)0x0);
    if (iVar3 != 0) {
      do {
        V_strncat((char *)(::__tcf_0 + unaff_EBX + 5),local_11c[iVar3],0x100,-1);
        V_strncat((char *)(::__tcf_0 + unaff_EBX + 5),(char *)(unaff_EBX + 0x298fcc /* CBitBuffer::s_nMaskTable+0xc7 */),0x100,-1);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  V_strncat((char *)(::__tcf_0 + unaff_EBX + 5),local_11c[0],0x100,-1);
  return ::__tcf_0 + unaff_EBX + 5;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InvokeOnEnd
 * Address: 007509b0
 * ---------------------------------------- */

/* Action<CINSNextBot>::InvokeOnEnd(CINSNextBot*, Behavior<CINSNextBot>*, Action<CINSNextBot>*) */

void __thiscall
Action<CINSNextBot>::InvokeOnEnd
          (Action<CINSNextBot> *this,CINSNextBot *param_1,Behavior *param_2,Action *param_3)

{
  CINSNextBot *pCVar1;
  CINSNextBot *pCVar2;
  char cVar3;
  undefined4 uVar4;
  Action *pAVar5;
  int iVar6;
  Action<CINSNextBot> *extraout_ECX;
  Action<CINSNextBot> *this_00;
  Action<CINSNextBot> *extraout_ECX_00;
  Action<CINSNextBot> *this_01;
  Action<CINSNextBot> *extraout_ECX_01;
  int unaff_EBX;
  double dVar7;
  undefined4 in_stack_00000010;
  undefined4 uVar8;
  undefined1 *puVar9;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7509bb;
  __i686_get_pc_thunk_bx();
  if (param_1[0x30] != (CINSNextBot)0x0) {
    cVar3 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1);
    if ((cVar3 != '\0') ||
       (iVar6 = (**(code **)(**(int **)(&DAT_00456645 + unaff_EBX) + 0x40))
                          (*(int **)(&DAT_00456645 + unaff_EBX)), this_00 = extraout_ECX_01,
       iVar6 != 0)) {
      uVar4 = (**(code **)(*(int *)(param_2 + 0x2060) + 0x144))(param_2 + 0x2060);
      dVar7 = (double)*(float *)(**(int **)(unaff_EBX + 0x455ee5 /* &gpGlobals */) + 0xc);
      pAVar5 = param_3 + 0x11;
      INextBot::DebugConColorMsg();
      iVar6 = unaff_EBX + 0x2323af /* " ENDING " */;
      puVar9 = &local_28;
      local_28 = 0xff;
      local_27 = 0;
      local_26 = 0;
      local_25 = 0xff;
      uVar8 = 1;
      INextBot::DebugConColorMsg();
      (**(code **)(*(int *)param_1 + 0xb8))(param_1,uVar8,puVar9,iVar6,dVar7,uVar4,pAVar5);
      local_24 = 0xff;
      local_23 = 0xff;
      local_22 = 0xff;
      local_21 = 0xff;
      INextBot::DebugConColorMsg();
      local_20 = 0xff;
      local_1f = 0xff;
      local_1e = 0xff;
      local_1d = 0xff;
      INextBot::DebugConColorMsg();
      this_00 = extraout_ECX;
    }
    param_1[0x30] = (CINSNextBot)0x0;
    pCVar2 = *(CINSNextBot **)(param_1 + 0x10);
    while (pCVar2 != (CINSNextBot *)0x0) {
      pCVar1 = *(CINSNextBot **)(pCVar2 + 0x14);
      InvokeOnEnd(this_00,pCVar2,param_2,param_3);
      pCVar2 = pCVar1;
      this_00 = extraout_ECX_00;
    }
    (**(code **)(*(int *)param_1 + 0xcc))(param_1,param_2,in_stack_00000010);
    if (*(CINSNextBot **)(param_1 + 0x18) != (CINSNextBot *)0x0) {
      InvokeOnEnd(this_01,*(CINSNextBot **)(param_1 + 0x18),param_2,param_3);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InvokeOnResume
 * Address: 007534a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::InvokeOnResume(CINSNextBot*, Behavior<CINSNextBot>*, Action<CINSNextBot>*)
    */

CINSNextBot *
Action<CINSNextBot>::InvokeOnResume(CINSNextBot *param_1,Behavior *param_2,Action *param_3)

{
  INextBot *pIVar1;
  char cVar2;
  undefined4 uVar3;
  int iVar4;
  int unaff_EBX;
  int in_stack_00000010;
  undefined4 in_stack_00000014;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7534ab;
  __i686_get_pc_thunk_bx();
  cVar2 = (**(code **)(*(int *)param_3 + 0x980 /* CINSNextBot::IsDebugging */))(param_3,1);
  if ((cVar2 != '\0') ||
     (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x453b55 /* &NextBotDebugHistory */) + 0x40))
                        (*(int **)(unaff_EBX + 0x453b55 /* &NextBotDebugHistory */)), iVar4 != 0)) {
    pIVar1 = (INextBot *)(param_3 + 0x2060);
    uVar3 = (**(code **)(*(int *)(param_3 + 0x2060) + 0x144))(pIVar1);
    local_2c = 0xff;
    local_2b = 0xff;
    local_2a = 0x96;
    local_29 = 0xff;
    INextBot::DebugConColorMsg
              (pIVar1,pIVar1,1,&local_2c,unaff_EBX + 0x22c5f0 /* "%3.2f: %s:%s: " */,
               (double)*(float *)(**(int **)(unaff_EBX + 0x4533f5 /* &gpGlobals */) + 0xc),uVar3,
               in_stack_00000010 + 0x11);
    local_28 = 0xff;
    local_27 = 0;
    local_26 = 0xff;
    local_25 = 0xff;
    INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_28,&UNK_0022fa4c + unaff_EBX);
    uVar3 = (**(code **)(*(int *)param_2 + 0xb8))(param_2);
    local_24 = 0xff;
    local_23 = 0xff;
    local_22 = 0xff;
    local_21 = 0xff;
    INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_24,uVar3);
    local_20 = 0xff;
    local_1f = 0xff;
    local_1e = 0xff;
    local_1d = 0xff;
    INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_20,unaff_EBX + 0x23b629 /* typeinfo name for CEntityFactory<CPropVehicle>+0x174 */);
  }
  if ((param_2[0x31] != (Behavior)0x0) && (2 < *(int *)(param_2 + 0x20) - 1U)) {
    param_2[0x31] = (Behavior)0x0;
    *(undefined4 *)(param_2 + 0x18) = 0;
    if (*(int *)(param_2 + 0xc) != 0) {
      *(Behavior **)(*(int *)(param_2 + 0xc) + 0x10) = param_2;
    }
    if (*(Behavior **)(param_2 + 0x10) != (Behavior *)0x0) {
      InvokeOnResume((CINSNextBot *)&local_44,*(Behavior **)(param_2 + 0x10),param_3);
      uVar3 = ApplyResult(*(undefined4 *)(param_2 + 0x10),param_3,in_stack_00000010,local_44,
                          local_40,local_3c);
      *(undefined4 *)(param_2 + 0x10) = uVar3;
    }
    (**(code **)(*(int *)param_2 + 0xd4))(&local_38,param_2,param_3,in_stack_00000014);
    *(undefined4 *)param_1 = local_38;
    *(undefined4 *)(param_1 + 4) = local_34;
    *(undefined4 *)(param_1 + 8) = local_30;
    return param_1;
  }
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return param_1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InvokeOnStart
 * Address: 00753250
 * ---------------------------------------- */

/* Action<CINSNextBot>::InvokeOnStart(CINSNextBot*, Behavior<CINSNextBot>*, Action<CINSNextBot>*,
   Action<CINSNextBot>*) */

CINSNextBot *
Action<CINSNextBot>::InvokeOnStart
          (CINSNextBot *param_1,Behavior *param_2,Action *param_3,Action *param_4)

{
  char cVar1;
  INextBot *pIVar2;
  int iVar3;
  int *piVar4;
  int unaff_EBX;
  int in_stack_00000014;
  int in_stack_00000018;
  undefined4 uVar5;
  undefined1 *puVar6;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x75325b;
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*(int *)param_3 + 0x980 /* CINSNextBot::IsDebugging */))(param_3,1);
  if (cVar1 == '\0') {
    iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x453da5 /* &NextBotDebugHistory */) + 0x40))(*(int **)(unaff_EBX + 0x453da5 /* &NextBotDebugHistory */));
    piVar4 = *(int **)(&DAT_00453645 + unaff_EBX);
    if (iVar3 == 0) goto LAB_0075339e;
  }
  pIVar2 = (INextBot *)(**(code **)(*(int *)(param_3 + 0x2060) + 0x144))(param_3 + 0x2060);
  piVar4 = *(int **)(&DAT_00453645 + unaff_EBX);
  local_2c = 0xff;
  local_2b = 0xff;
  local_2a = 0x96;
  local_29 = 0xff;
  INextBot::DebugConColorMsg
            (pIVar2,param_3 + 0x2060,1,&local_2c,unaff_EBX + 0x22c840 /* "%3.2f: %s:%s: " */,
             (double)*(float *)(*piVar4 + 0xc),pIVar2,param_4 + 0x11);
  iVar3 = unaff_EBX + 0x22fc7b /* " STARTING " */;
  local_28 = 0;
  puVar6 = &local_28;
  local_27 = 0xff;
  local_26 = 0;
  local_25 = 0xff;
  uVar5 = 1;
  INextBot::DebugConColorMsg();
  (**(code **)(*(int *)param_2 + 0xb8))(param_2,uVar5,puVar6,iVar3);
  local_24 = 0xff;
  local_23 = 0xff;
  local_22 = 0xff;
  local_21 = 0xff;
  INextBot::DebugConColorMsg();
  local_20 = 0xff;
  local_1f = 0xff;
  local_1e = 0xff;
  local_1d = 0xff;
  INextBot::DebugConColorMsg();
LAB_0075339e:
  iVar3 = *piVar4;
  param_2[0x30] = (Behavior)0x1;
  uVar5 = *(undefined4 *)(iVar3 + 0xc);
  *(Action **)(param_2 + 0x1c) = param_3;
  *(Action **)(param_2 + 8) = param_4;
  *(undefined4 *)(param_2 + 0x34) = uVar5;
  if (in_stack_00000014 == 0) {
    iVar3 = *(int *)(param_2 + 0xc);
  }
  else {
    iVar3 = *(int *)(in_stack_00000014 + 0xc);
    *(int *)(param_2 + 0xc) = iVar3;
  }
  if (iVar3 != 0) {
    *(Behavior **)(iVar3 + 0x10) = param_2;
  }
  *(int *)(param_2 + 0x14) = in_stack_00000018;
  if (in_stack_00000018 != 0) {
    *(Behavior **)(in_stack_00000018 + 0x18) = param_2;
  }
  *(undefined4 *)(param_2 + 0x18) = 0;
  iVar3 = (**(code **)(*(int *)param_2 + 0xd8))(param_2,param_3);
  *(int *)(param_2 + 0x10) = iVar3;
  if (iVar3 != 0) {
    *(Behavior **)(iVar3 + 0xc) = param_2;
    uVar5 = ApplyResult(*(undefined4 *)(param_2 + 0x10),param_3,param_4,1,
                        *(undefined4 *)(param_2 + 0x10),unaff_EBX + 0x22fc86 /* "Starting child Action" */);
    *(undefined4 *)(param_2 + 0x10) = uVar5;
  }
  (**(code **)(*(int *)param_2 + 0xc4))(param_1,param_2,param_3,in_stack_00000014);
  return param_1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InvokeOnSuspend
 * Address: 00752150
 * ---------------------------------------- */

/* Action<CINSNextBot>::InvokeOnSuspend(CINSNextBot*, Behavior<CINSNextBot>*, Action<CINSNextBot>*)
    */

CINSNextBot * __thiscall
Action<CINSNextBot>::InvokeOnSuspend
          (Action<CINSNextBot> *this,CINSNextBot *param_1,Behavior *param_2,Action *param_3)

{
  INextBot *pIVar1;
  CINSNextBot *pCVar2;
  char cVar3;
  undefined4 uVar4;
  int iVar5;
  int unaff_EBX;
  Action<CINSNextBot> *in_stack_00000010;
  undefined1 *puVar6;
  undefined *puVar7;
  int local_3c [3];
  CINSNextBot *local_30;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x75215b;
  __i686_get_pc_thunk_bx();
  cVar3 = (**(code **)(*(int *)param_2 + 0x980 /* CINSNextBot::IsDebugging */))(param_2,1);
  if ((cVar3 != '\0') ||
     (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x454ea5 /* &NextBotDebugHistory */) + 0x40))
                        (*(int **)(unaff_EBX + 0x454ea5 /* &NextBotDebugHistory */)), iVar5 != 0)) {
    pIVar1 = (INextBot *)(param_2 + 0x2060);
    uVar4 = (**(code **)(*(int *)(param_2 + 0x2060) + 0x144))(pIVar1);
    local_2c = 0xff;
    local_2b = 0xff;
    local_2a = 0x96;
    local_29 = 0xff;
    INextBot::DebugConColorMsg
              (pIVar1,pIVar1,1,&local_2c,unaff_EBX + 0x22d940 /* "%3.2f: %s:%s: " */,
               (double)*(float *)(**(int **)(unaff_EBX + 0x454745 /* &gpGlobals */) + 0xc),uVar4,param_3 + 0x11);
    puVar7 = &UNK_00230d06 + unaff_EBX;
    puVar6 = &local_28;
    local_28 = 0xff;
    local_27 = 0;
    local_26 = 0xff;
    local_25 = 0xff;
    uVar4 = 1;
    INextBot::DebugConColorMsg();
    uVar4 = (**(code **)(*(int *)param_1 + 0xb8))(param_1,uVar4,puVar6,puVar7);
    local_24 = 0xff;
    local_23 = 0xff;
    local_22 = 0xff;
    local_21 = 0xff;
    INextBot::DebugConColorMsg(pIVar1,pIVar1,1,&local_24,uVar4);
    local_20 = 0xff;
    local_1f = 0xff;
    local_1e = 0xff;
    local_1d = 0xff;
    INextBot::DebugConColorMsg();
  }
  if (*(CINSNextBot **)(param_1 + 0x10) != (CINSNextBot *)0x0) {
    uVar4 = InvokeOnSuspend(in_stack_00000010,*(CINSNextBot **)(param_1 + 0x10),param_2,param_3);
    *(undefined4 *)(param_1 + 0x10) = uVar4;
  }
  param_1[0x31] = (CINSNextBot)0x1;
  (**(code **)(*(int *)param_1 + 0xd0))(local_3c,param_1,param_2,in_stack_00000010);
  if (local_3c[0] == 3) {
    InvokeOnEnd((Action<CINSNextBot> *)param_3,param_1,param_2,param_3);
    local_30 = param_1;
    pCVar2 = *(CINSNextBot **)(param_1 + 0x14);
    CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>>::InsertBefore
              ((CUtlVector<Action<CINSNextBot>*,CUtlMemory<Action<CINSNextBot>*,int>> *)param_3,
               (int)(param_3 + 0x3c),*(Action ***)(param_3 + 0x48));
    return pCVar2;
  }
  return param_1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::InvokeUpdate
 * Address: 00752d80
 * ---------------------------------------- */

/* Action<CINSNextBot>::InvokeUpdate(CINSNextBot*, Behavior<CINSNextBot>*, float) */

CINSNextBot *
Action<CINSNextBot>::InvokeUpdate(CINSNextBot *param_1,Behavior *param_2,float param_3)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int unaff_EBX;
  undefined4 in_stack_00000010;
  undefined4 in_stack_00000014;
  undefined4 local_40;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x752d8b;
  __i686_get_pc_thunk_bx();
  iVar3 = *(int *)(param_2 + 0x14);
  if (iVar3 == 0) {
LAB_00752ddc:
    if (param_2[0x30] == (Behavior)0x0) {
      *(undefined4 *)param_1 = 1 /* ChangeTo */;
      *(Behavior **)(param_1 + 4) = param_2;
      *(int *)(param_1 + 8) = unaff_EBX + 0x23013b /* "Starting Action" */;
    }
    else {
      iVar5 = *(int *)(param_2 + 0x20);
      if (iVar5 - 1U < 3) {
        local_40 = *(undefined4 *)(param_2 + 0x28);
        *(undefined4 *)(param_2 + 0x20) = 0;
        uVar4 = *(undefined4 *)(param_2 + 0x24);
        *(undefined4 *)(param_2 + 0x28) = 0;
        *(undefined4 *)(param_2 + 0x24) = 0;
        *(undefined4 *)(param_2 + 0x2c) = 0;
      }
      else {
        while( true ) {
          if (iVar3 == 0) {
            if (*(Behavior **)(param_2 + 0x10) != (Behavior *)0x0) {
              InvokeUpdate((CINSNextBot *)&local_38,*(Behavior **)(param_2 + 0x10),param_3);
              uVar4 = ApplyResult(*(undefined4 *)(param_2 + 0x10),param_3,in_stack_00000010,local_38
                                  ,local_34,local_30);
              *(undefined4 *)(param_2 + 0x10) = uVar4;
            }
            local_2c = 0;
            local_28 = 0;
            local_24 = 0;
            iVar5 = (**(code **)(*(int *)param_2 + 0xb8))(param_2);
            iVar3 = *(int *)(&DAT_00453be9 + unaff_EBX);
            local_1d = *(int *)(iVar3 + 0x100c) != 0;
            if (((bool)local_1d) &&
               (iVar7 = *(int *)(iVar3 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar7 == iVar6)) {
              piVar8 = *(int **)(iVar3 + 0x1014);
              if (iVar5 != *piVar8) {
                piVar8 = (int *)CVProfNode::GetSubNode
                                          ((char *)piVar8,iVar5,(char *)0x0,
                                           (int)(&UNK_0022dede + unaff_EBX));
                *(int **)(iVar3 + 0x1014) = piVar8;
              }
              puVar1 = (uint *)(*(int *)(iVar3 + 0x10a0) + piVar8[0x1c] * 8 + 4);
              *puVar1 = *puVar1 | 4;
              CVProfNode::EnterScope();
              *(undefined1 *)(iVar3 + 0x1010) = 0;
            }
            (**(code **)(*(int *)param_2 + 200))(&local_2c,param_2,param_3,in_stack_00000014);
            if ((local_1d != '\0') &&
               (((*(char *)(iVar3 + 0x1010) == '\0' || (*(int *)(iVar3 + 0x100c) != 0)) &&
                (iVar5 = *(int *)(iVar3 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar5 == iVar7))))
            {
              cVar2 = CVProfNode::ExitScope();
              iVar5 = *(int *)(iVar3 + 0x1014);
              if (cVar2 != '\0') {
                iVar5 = *(int *)(iVar5 + 100);
                *(int *)(iVar3 + 0x1014) = iVar5;
              }
              *(bool *)(iVar3 + 0x1010) = iVar5 == iVar3 + 0x1018;
            }
            *(undefined4 *)param_1 = local_2c;
            *(undefined4 *)(param_1 + 4) = local_28;
            *(undefined4 *)(param_1 + 8) = local_24;
            return param_1;
          }
          if (*(int *)(iVar3 + 0x20) == 2) break;
          iVar3 = *(int *)(iVar3 + 0x14);
        }
        local_40 = *(undefined4 *)(iVar3 + 0x28);
        *(undefined4 *)(iVar3 + 0x20) = 0;
        iVar5 = 2;
        uVar4 = *(undefined4 *)(iVar3 + 0x24);
        *(undefined4 *)(iVar3 + 0x28) = 0;
        *(undefined4 *)(iVar3 + 0x24) = 0;
        *(undefined4 *)(iVar3 + 0x2c) = 0;
      }
      *(int *)param_1 = iVar5;
      *(undefined4 *)(param_1 + 4) = uVar4;
      *(undefined4 *)(param_1 + 8) = local_40;
    }
    return param_1;
  }
  if ((*(int *)(iVar3 + 0x20) != 1) && (iVar5 = iVar3, *(int *)(iVar3 + 0x20) != 3)) {
    do {
      iVar5 = *(int *)(iVar5 + 0x14);
      if (iVar5 == 0) goto LAB_00752ddc;
    } while ((*(int *)(iVar5 + 0x20) != 3) && (*(int *)(iVar5 + 0x20) != 1));
  }
  *(undefined4 *)param_1 = 3 /* Done */;
  *(int *)(param_1 + 8) = unaff_EBX + 0x23012e /* "Out of scope" */;
  *(undefined4 *)(param_1 + 4) = 0;
  return param_1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::IsAbleToBlockMovementOf
 * Address: 006f7cc0
 * ---------------------------------------- */

/* Action<CINSNextBot>::IsAbleToBlockMovementOf(INextBot const*) const */

undefined4 __cdecl Action<CINSNextBot>::IsAbleToBlockMovementOf(INextBot *param_1)

{
  return 1;
}



/* ----------------------------------------
 * Action<CINSNextBot>::IsNamed
 * Address: 006f80f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::IsNamed(char const*) const */

bool __thiscall Action<CINSNextBot>::IsNamed(Action<CINSNextBot> *this,char *param_1)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  bool bVar4;
  char *in_stack_00000008;
  
  piVar1 = (int *)__i686_get_pc_thunk_bx();
  pcVar2 = (char *)(**(code **)(*piVar1 + 0xb8))(piVar1);
  bVar4 = true;
  if (pcVar2 != in_stack_00000008) {
    iVar3 = _V_stricmp(pcVar2,in_stack_00000008);
    bVar4 = iVar3 == 0;
  }
  return bVar4;
}



/* ----------------------------------------
 * Action<CINSNextBot>::NextContainedResponder
 * Address: 006f7700
 * ---------------------------------------- */

/* Action<CINSNextBot>::NextContainedResponder(INextBotEventResponder*) const */

undefined4 __cdecl Action<CINSNextBot>::NextContainedResponder(INextBotEventResponder *param_1)

{
  return 0;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnActorEmoted
 * Address: 006f79f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnActorEmoted(CINSNextBot*, CBaseCombatCharacter*, int) */

void Action<CINSNextBot>::OnActorEmoted
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,int param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnActorEmoted
 * Address: 006fd610
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnActorEmoted(CBaseCombatCharacter*, int) */

void __thiscall
Action<CINSNextBot>::OnActorEmoted
          (Action<CINSNextBot> *this,CBaseCombatCharacter *param_1,int param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseCombatCharacter *pCVar9;
  double dVar10;
  undefined4 in_stack_0000000c;
  CBaseCombatCharacter *pCVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fd61b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseCombatCharacter)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a99e5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a99e5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a9285 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x28259f /* "OnActorEmoted" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,&UNK_002826f1 + unaff_EBX,dVar10,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x28259f /* "OnActorEmoted" */));
          uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      iVar4 = param_2;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x13c))(&local_44,pCVar9,puVar8,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseCombatCharacter *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a99e5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a99e5 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a9285 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x282480 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x28259f /* "OnActorEmoted" */);
            iVar4 = unaff_EBX + 0x28248f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25c460 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x28245a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x282450 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x282466 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_0028246b + unaff_EBX,iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25c460 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            iVar4 = unaff_EBX + 0x25c42f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseCombatCharacter *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a9b05 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a9b05 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x28259f /* "OnActorEmoted" */;
            pCVar11 = (CBaseCombatCharacter *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a9285 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x2826bd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseCombatCharacter **)pCVar11;
    } while (*(CBaseCombatCharacter **)pCVar11 != (CBaseCombatCharacter *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x70 /* CBaseMultiplayerPlayer::PostConstructor */))(piVar7,param_2,in_stack_0000000c);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationActivityComplete
 * Address: 006f77e0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationActivityComplete(CINSNextBot*, int) */

void Action<CINSNextBot>::OnAnimationActivityComplete(CINSNextBot *param_1,int param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationActivityComplete
 * Address: 007020b0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationActivityComplete(int) */

void __thiscall
Action<CINSNextBot>::OnAnimationActivityComplete(Action<CINSNextBot> *this,int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int in_stack_00000008;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7020bb;
  __i686_get_pc_thunk_bx();
  piVar8 = (int *)param_1;
  if (*(char *)(param_1 + 0x30) != '\0') {
    do {
      piVar11 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4f45 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a4f45 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar8 + 0xc0))(piVar8);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27db80 /* "OnAnimationActivityComplete" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27dc51 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a47e5 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x27db80 /* "OnAnimationActivityComplete" */));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar5 = in_stack_00000008;
      piVar11 = piVar8;
      (**(code **)(*piVar8 + 0xfc))(&local_44,piVar8,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a4f45 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a4f45 /* &NextBotDebugHistory */)), iVar7 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a47e5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27d9e0 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar8 + 0xc0))(piVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x27db80 /* "OnAnimationActivityComplete" */);
            iVar5 = unaff_EBX + 0x27d9ef /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x2579c0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            iVar5 = unaff_EBX + 0x27d9ba /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27d9b0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27d9c6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27d9cb /* "%s %s " */,
                       iVar5,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar5 = unaff_EBX + 0x25798f /* "%s
" */;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar8[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9,iVar5);
          }
        }
        else {
          if ((piVar8[0xb] == 3) &&
             (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a5065 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a5065 /* &developer */)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar8 + 0xb8))(piVar8);
            iVar5 = unaff_EBX + 0x27db80 /* "OnAnimationActivityComplete" */;
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a47e5 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27dc1d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar8[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9,iVar5);
          }
          piVar8[8] = local_44;
          piVar8[9] = (int)local_40;
          piVar8[10] = local_3c;
          piVar8[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar8 + 5;
      piVar8 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x30))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationActivityInterrupted
 * Address: 006f7810
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationActivityInterrupted(CINSNextBot*, int) */

void Action<CINSNextBot>::OnAnimationActivityInterrupted(CINSNextBot *param_1,int param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationActivityInterrupted
 * Address: 00701c10
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationActivityInterrupted(int) */

void __thiscall
Action<CINSNextBot>::OnAnimationActivityInterrupted(Action<CINSNextBot> *this,int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int in_stack_00000008;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x701c1b;
  __i686_get_pc_thunk_bx();
  piVar8 = (int *)param_1;
  if (*(char *)(param_1 + 0x30) != '\0') {
    do {
      piVar11 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(&DAT_004a53e5 + unaff_EBX) + 0x40))
                              (*(int **)(&DAT_004a53e5 + unaff_EBX)), iVar5 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar8 + 0xc0))(piVar8);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27e115 /* "OnAnimationActivityInterrupted" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27e0f1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a4c85 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x27e115 /* "OnAnimationActivityInterrupted" */));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar5 = in_stack_00000008;
      piVar11 = piVar8;
      (**(code **)(*piVar8 + 0x100))(&local_44,piVar8,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(&DAT_004a53e5 + unaff_EBX) + 0x40))
                                 (*(int **)(&DAT_004a53e5 + unaff_EBX)), iVar7 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a4c85 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27de80 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar8 + 0xc0))(piVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x27e115 /* "OnAnimationActivityInterrupted" */);
            iVar5 = unaff_EBX + 0x27de8f /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x257e60 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            iVar5 = unaff_EBX + 0x27de5a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27de50 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27de66 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27de6b /* "%s %s " */,
                       iVar5,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar5 = unaff_EBX + 0x257e2f /* "%s
" */;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar8[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9,iVar5);
          }
        }
        else {
          if ((piVar8[0xb] == 3) &&
             (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a5505 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a5505 /* &developer */)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar8 + 0xb8))(piVar8);
            iVar5 = unaff_EBX + 0x27e115 /* "OnAnimationActivityInterrupted" */;
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a4c85 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27e0bd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar8[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9,iVar5);
          }
          piVar8[8] = local_44;
          piVar8[9] = (int)local_40;
          piVar8[10] = local_3c;
          piVar8[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar8 + 5;
      piVar8 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x34))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationEvent
 * Address: 006f7840
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationEvent(CINSNextBot*, animevent_t*) */

void Action<CINSNextBot>::OnAnimationEvent(CINSNextBot *param_1,animevent_t *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnAnimationEvent
 * Address: 00701770
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnAnimationEvent(animevent_t*) */

void __thiscall
Action<CINSNextBot>::OnAnimationEvent(Action<CINSNextBot> *this,animevent_t *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  animevent_t *paVar9;
  double dVar10;
  int in_stack_00000008;
  animevent_t *paVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x70177b;
  __i686_get_pc_thunk_bx();
  paVar9 = param_1;
  if (param_1[0x30] != (animevent_t)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a5885 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a5885 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)paVar9 + 0xc0))(paVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27e4af /* "OnAnimationEvent" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27e591 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a5125 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x27e4af /* "OnAnimationEvent" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      paVar11 = paVar9;
      (**(code **)(*(int *)paVar9 + 0x104))(&local_44,paVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          paVar11 = (animevent_t *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a5885 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a5885 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a5125 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27e320 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)paVar9 + 0xc0))(paVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27e4af /* "OnAnimationEvent" */);
            iVar4 = unaff_EBX + 0x27e32f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x258300 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27e2fa /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27e2f0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27e306 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27e30b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x2582cf /* "%s
" */;
            puVar8 = &local_20;
            paVar11 = (animevent_t *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(paVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,paVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(paVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a59a5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a59a5 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)paVar9 + 0xb8))(paVar9);
            iVar4 = unaff_EBX + 0x27e4af /* "OnAnimationEvent" */;
            paVar11 = (animevent_t *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a5125 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27e55d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(paVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,paVar11,puVar8,iVar4);
          }
          *(int *)(paVar9 + 0x20) = local_44;
          *(int **)(paVar9 + 0x24) = local_40;
          *(int *)(paVar9 + 0x28) = local_3c;
          *(int *)(paVar9 + 0x2c) = local_38;
        }
        break;
      }
      paVar11 = paVar9 + 0x14;
      paVar9 = *(animevent_t **)paVar11;
    } while (*(animevent_t **)paVar11 != (animevent_t *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x38 /* CBaseAnimating::TestCollision */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnBlinded
 * Address: 006f7b70
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnBlinded(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnBlinded(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnBlinded
 * Address: 006fac40
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnBlinded(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnBlinded(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fac4b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4ac3b5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4ac3b5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x284efa /* "OnBlinded" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x2850c1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4abc55 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x284efa /* "OnBlinded" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x160))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4ac3b5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4ac3b5 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4abc55 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x284e50 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x284efa /* "OnBlinded" */);
            iVar4 = unaff_EBX + 0x284e5f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25ee30 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x284e2a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x284e20 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x284e36 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x284e3b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25edff /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4ac4d5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ac4d5 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x284efa /* "OnBlinded" */;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4abc55 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x28508d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x94 /* CBaseEntity::SetParent */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandAttack
 * Address: 006f7f10
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandAttack(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnCommandAttack(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandAttack
 * Address: 006fd170
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandAttack(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnCommandAttack(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  code *pcVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  undefined *in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined *puVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fd17b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(CEntityFactory<CLogicCompareInteger>::Destroy +
                                           unaff_EBX + 5) + 0x40))
                              (*(int **)(CEntityFactory<CLogicCompareInteger>::Destroy +
                                        unaff_EBX + 5)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_00282a2f + unaff_EBX),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x282b91 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a9725 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(&UNK_00282a2f + unaff_EBX));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar12 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x140))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(CEntityFactory<CLogicCompareInteger>::Destroy +
                                              unaff_EBX + 5) + 0x40))
                                 (*(int **)(CEntityFactory<CLogicCompareInteger>::Destroy +
                                           unaff_EBX + 5)), iVar4 != 0)) && (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a9725 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,
                       CINSRules_Vendetta::~CINSRules_Vendetta + unaff_EBX,dVar10,pIVar5,
                       iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,&UNK_00282a2f + unaff_EBX);
            puVar12 = &UNK_0028292f + unaff_EBX;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25c900 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,puVar12,uVar13);
            }
            pcVar6 = (code *)(&UNK_002828fa + unaff_EBX);
            if (local_44 != 2) {
              pcVar6 = CINSRules_Vendetta::GetReinforcementTimerStyleForTeam + unaff_EBX;
              if (local_44 == 3) {
                pcVar6 = (code *)(unaff_EBX + 0x282906 /* "DONE" */);
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_0028290b + unaff_EBX,pcVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar12 = (undefined *)(unaff_EBX + 0x25c8cf /* "%s
" */);
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,puVar12);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a9fa5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a9fa5 /* &developer */)), iVar4 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            puVar12 = &UNK_00282a2f + unaff_EBX;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a9725 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x282b5d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,puVar12);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x74 /* CBaseEntity::PostClientActive */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandPause
 * Address: 006f7ab0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandPause(CINSNextBot*, float) */

void Action<CINSNextBot>::OnCommandPause(CINSNextBot *param_1,float param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandPause
 * Address: 006fbeb0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandPause(float) */

void __thiscall Action<CINSNextBot>::OnCommandPause(Action<CINSNextBot> *this,float param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  undefined *in_stack_00000008;
  int *piVar10;
  undefined *puVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fbebb;
  __i686_get_pc_thunk_bx();
  piVar7 = (int *)param_1;
  if (*(char *)((int)param_1 + 0x30) != '\0') {
    do {
      piVar10 = *(int **)((int)param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(CLogicCase::~CLogicCase + unaff_EBX + 5) + 0x40))
                              (*(int **)(CLogicCase::~CLogicCase + unaff_EBX + 5)), iVar5 == 0)) {
          puVar8 = *(undefined1 **)((int)param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar7 + 0xc0))(piVar7);
          iVar5 = *(int *)((int)param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)((int)param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)((int)param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_00283cbd + unaff_EBX),*(int *)((int)param_1 + 0x1c) + 0x2060,
                     0x80,&local_34,unaff_EBX + 0x283e51 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4aa9e5 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(&UNK_00283cbd + unaff_EBX));
          puVar8 = *(undefined1 **)((int)param_1 + 0x1c);
        }
      }
      puVar11 = in_stack_00000008;
      piVar10 = piVar7;
      (**(code **)(*piVar7 + 0x150))(&local_44,piVar7,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)((int)param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar5 = (**(code **)(**(int **)(CLogicCase::~CLogicCase + unaff_EBX + 5) + 0x40))
                                 (*(int **)(CLogicCase::~CLogicCase + unaff_EBX + 5)), iVar5 != 0))
             && (local_44 - 1U < 3)) {
            iVar5 = *(int *)((int)param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)((int)param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)((int)param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4aa9e5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)((int)param_1 + 0x1c) + 0x2060,1,&local_30,
                       unaff_EBX + 0x283be0 /* "%3.2f: %s:%s: " */,dVar9,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar7 + 0xc0))(piVar7);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,&UNK_00283cbd + unaff_EBX);
            puVar11 = &UNK_00283bef + unaff_EBX;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25dbc0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,puVar11,uVar12);
            }
            iVar5 = unaff_EBX + 0x283bba /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x283bb0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x283bc6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)((int)param_1 + 0x1c) + 0x2060,1,&local_24,
                       unaff_EBX + 0x283bcb /* "%s %s " */,iVar5,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar11 = (undefined *)(unaff_EBX + 0x25db8f /* "%s
" */);
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar7[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8,puVar11);
          }
        }
        else {
          if ((piVar7[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ab265 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ab265 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar7 + 0xb8))(piVar7);
            puVar11 = &UNK_00283cbd + unaff_EBX;
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4aa9e5 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x283e1d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar7[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8,puVar11);
          }
          piVar7[8] = local_44;
          piVar7[9] = (int)local_40;
          piVar7[10] = local_3c;
          piVar7[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar7 + 5;
      piVar7 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x84))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandResume
 * Address: 006f7ae0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandResume(CINSNextBot*) */

void Action<CINSNextBot>::OnCommandResume(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandResume
 * Address: 006fba20
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandResume() */

void __thiscall Action<CINSNextBot>::OnCommandResume(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fba2b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(&DAT_004ab5d5 + unaff_EBX) + 0x40))
                              (*(int **)(&DAT_004ab5d5 + unaff_EBX)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x28413d /* "OnCommandResume" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x2842e1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(&DAT_004aae75 + unaff_EBX) + 0xc),uVar4,
                     iVar5 + 0x11,uVar3,(INextBot *)(unaff_EBX + 0x28413d /* "OnCommandResume" */));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0x154))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(&DAT_004ab5d5 + unaff_EBX) + 0x40))
                                (*(int **)(&DAT_004ab5d5 + unaff_EBX)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(&DAT_004aae75 + unaff_EBX) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x284070 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,unaff_EBX + 0x28413d /* "OnCommandResume" */);
            iVar5 = unaff_EBX + 0x28407f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25e050 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x28404a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x284040 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x284056 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x28405b /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ab6f5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ab6f5 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)
                              (double)*(float *)(**(int **)(&DAT_004aae75 + unaff_EBX) + 0xc) >>
                             0x20);
            DevMsg((char *)(unaff_EBX + 0x2842ad /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0x88))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandRetreat
 * Address: 006f7a80
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandRetreat(CINSNextBot*, CBaseEntity*, float) */

void Action<CINSNextBot>::OnCommandRetreat(CINSNextBot *param_1,CBaseEntity *param_2,float param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnCommandRetreat
 * Address: 006fc360
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnCommandRetreat(CBaseEntity*, float) */

void __thiscall
Action<CINSNextBot>::OnCommandRetreat(Action<CINSNextBot> *this,CBaseEntity *param_1,float param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseEntity *pCVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  CBaseEntity *pCVar10;
  float fVar11;
  undefined *puVar12;
  undefined8 in_stack_ffffff74;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fc36b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aac95 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4aac95 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4aa535 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x28381c /* "OnCommandRetreat" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x2839a1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x28381c /* "OnCommandRetreat" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      fVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x14c))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aac95 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4aac95 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4aa535 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x283730 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x28381c /* "OnCommandRetreat" */);
            puVar12 = &UNK_0028373f + unaff_EBX;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25d710 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,puVar12,uVar13);
            }
            iVar4 = unaff_EBX + 0x28370a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x283700 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x283716 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_0028371b + unaff_EBX,iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            iVar4 = unaff_EBX + 0x25d710 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            local_1d = 0xff;
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            fVar11 = (float)(unaff_EBX + 0x25d6df /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,fVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(&LAB_004aadb5 + unaff_EBX) + 0x40))
                                (*(int **)(&LAB_004aadb5 + unaff_EBX)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            fVar11 = (float)(unaff_EBX + 0x28381c /* "OnCommandRetreat" */);
            pCVar10 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4aa535 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x28396d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,fVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar10 = pCVar8 + 0x14;
      pCVar8 = *(CBaseEntity **)pCVar10;
    } while (*(CBaseEntity **)pCVar10 != (CBaseEntity *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x80 /* CBaseEntity::KeyValue */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnHeardFootsteps
 * Address: 006f7f40
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnHeardFootsteps(CINSNextBot*, CBaseCombatCharacter*, Vector const&) */

void Action<CINSNextBot>::OnHeardFootsteps
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnHeardFootsteps
 * Address: 006f9030
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnHeardFootsteps(CBaseCombatCharacter*, Vector const&) */

void __thiscall
Action<CINSNextBot>::OnHeardFootsteps
          (Action<CINSNextBot> *this,CBaseCombatCharacter *param_1,Vector *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CBaseCombatCharacter *pCVar8;
  float10 fVar9;
  double dVar10;
  undefined4 in_stack_0000000c;
  CBaseCombatCharacter *pCVar11;
  Vector *pVVar12;
  undefined8 in_stack_ffffff74;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f903b;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CBaseCombatCharacter)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4adfc5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4adfc5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ad865 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x286ab3 /* "OnHeardFootsteps" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x286cd1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar10,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x286ab3 /* "OnHeardFootsteps" */));
          uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pVVar12 = param_2;
      pCVar11 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 0x178))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar11 = (CBaseCombatCharacter *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4adfc5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4adfc5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ad865 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x286a60 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x286ab3 /* "OnHeardFootsteps" */);
            iVar4 = unaff_EBX + 0x286a6f /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x260a40 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar13);
            }
            iVar4 = unaff_EBX + 0x286a3a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x286a30 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x286a46 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x286a4b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x260a40 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pVVar12 = (Vector *)(&UNK_00260a0f + unaff_EBX);
            puVar7 = &local_20;
            pCVar11 = (CBaseCombatCharacter *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar7,pVVar12,in_stack_ffffff74);
            piVar6 = (int *)(*(int **)(unaff_EBX + 0x4ad6cd /* &ins_bot_ignore_human_triggers */))[7];
            if (piVar6 != *(int **)(unaff_EBX + 0x4ad6cd /* &ins_bot_ignore_human_triggers */)) goto LAB_006f9457;
            goto LAB_006f9480;
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4ae0e5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ae0e5 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pVVar12 = (Vector *)(unaff_EBX + 0x286ab3 /* "OnHeardFootsteps" */);
            pCVar11 = (CBaseCombatCharacter *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ad865 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x286c9d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar11,puVar7,pVVar12);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar8 + 0x14;
      pCVar8 = *(CBaseCombatCharacter **)pCVar11;
    } while (*(CBaseCombatCharacter **)pCVar11 != (CBaseCombatCharacter *)0x0);
    piVar6 = (int *)(*(int **)(unaff_EBX + 0x4ad6cd /* &ins_bot_ignore_human_triggers */))[7];
    if (piVar6 == *(int **)(unaff_EBX + 0x4ad6cd /* &ins_bot_ignore_human_triggers */)) {
LAB_006f9480:
      if (*(float *)(unaff_EBX + 0x1bfacd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)((uint)piVar6 ^ piVar6[0xb]) &&
          (float)((uint)piVar6 ^ piVar6[0xb]) != *(float *)(unaff_EBX + 0x1bfacd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    else {
LAB_006f9457:
      fVar9 = (float10)(**(code **)(*piVar6 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar6);
      if (*(float *)(unaff_EBX + 0x1bfacd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar9 &&
          (float)fVar9 != *(float *)(unaff_EBX + 0x1bfacd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    if (piVar6 != (int *)0x0) {
      do {
        (**(code **)(*piVar6 + 0xac /* CBasePlayer::DrawDebugGeometryOverlays */))(piVar6,param_2,in_stack_0000000c);
        piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
      } while (piVar6 != (int *)0x0);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnIgnite
 * Address: 006f7870
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnIgnite(CINSNextBot*) */

void Action<CINSNextBot>::OnIgnite(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnIgnite
 * Address: 007012e0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnIgnite() */

void __thiscall Action<CINSNextBot>::OnIgnite(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x7012eb;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a5d15 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a5d15 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x246f18 /* "OnIgnite" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x27ea21 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a55b5 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x246f18 /* "OnIgnite" */));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0x108))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a5d15 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a5d15 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a55b5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x27e7b0 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,unaff_EBX + 0x246f18 /* "OnIgnite" */);
            iVar5 = unaff_EBX + 0x27e7bf /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x258790 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x27e78a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27e780 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27e796 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x27e79b /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a5e35 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a5e35 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a55b5 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27e9ed /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0x3c))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLandOnGround
 * Address: 006f7750
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLandOnGround(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnLandOnGround(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLandOnGround
 * Address: 00704100
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLandOnGround(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnLandOnGround(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x70410b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(&DAT_004a2ef5 + unaff_EBX) + 0x40))
                              (*(int **)(&DAT_004a2ef5 + unaff_EBX)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27bb99 /* "OnLandOnGround" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27bc01 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a2795 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x27bb99 /* "OnLandOnGround" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0xe0))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(&DAT_004a2ef5 + unaff_EBX) + 0x40))
                                 (*(int **)(&DAT_004a2ef5 + unaff_EBX)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a2795 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x27b990 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27bb99 /* "OnLandOnGround" */);
            iVar4 = unaff_EBX + 0x27b99f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x255970 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x27b96a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x27b960 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x27b976 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x27b97b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25593f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(CEntityFactory<CLight>::Create + unaff_EBX + 5) + 0x40
                                  ))(*(int **)(CEntityFactory<CLight>::Create + unaff_EBX + 5)),
             iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x27bb99 /* "OnLandOnGround" */;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a2795 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x27bbcd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x14 /* CBaseEntity::GetNetworkable */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLeaveGround
 * Address: 006f7720
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLeaveGround(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnLeaveGround(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLeaveGround
 * Address: 006f81a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLeaveGround(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnLeaveGround(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined *puVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f81ab;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4aee55 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4aee55 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2878e2 /* "OnLeaveGround" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x287b61 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ae6f5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x2878e2 /* "OnLeaveGround" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0xdc))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4aee55 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4aee55 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ae6f5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x2878f0 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar2,unaff_EBX + 0x2878e2 /* "OnLeaveGround" */);
            puVar12 = &UNK_002878ff + unaff_EBX;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(CINSRules_Ambush::DisplayObjectiveLayout + unaff_EBX);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,puVar12,uVar13);
            }
            iVar4 = unaff_EBX + 0x2878ca /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x2878c0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x2878d6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x2878db /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x26189f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4aef75 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4aef75 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x2878e2 /* "OnLeaveGround" */;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ae6f5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x287b2d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x10 /* CBaseEntity::GetCollideable */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLose
 * Address: 006f7c60
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLose(CINSNextBot*) */

void Action<CINSNextBot>::OnLose(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnLose
 * Address: 006f9540
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnLose() */

void __thiscall Action<CINSNextBot>::OnLose(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined *puVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int *in_stack_00000004;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f954b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar11 = (int *)in_stack_00000004[7];
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4adab5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4adab5 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2865b4 /* "OnLose" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x2867c1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ad355 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x2865b4 /* "OnLose" */));
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar11 = piVar6;
      (**(code **)(*piVar6 + 0x174))(&local_44,piVar6,puVar9);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4adab5 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4adab5 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ad355 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x286550 /* "%3.2f: %s:%s: " */,dVar10,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x2865b4 /* "OnLose" */);
            iVar5 = unaff_EBX + 0x28655f /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x260530 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            puVar8 = &UNK_0028652a + unaff_EBX;
            if (local_44 != 2) {
              puVar8 = (undefined *)(unaff_EBX + 0x286520 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar8 = (undefined *)(unaff_EBX + 0x286536 /* "DONE" */);
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x28653b /* "%s %s " */,
                       puVar8,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4adbd5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4adbd5 /* &developer */)), iVar5 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ad355 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x28678d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar6 + 5;
      piVar6 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0xa8))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnModelChanged
 * Address: 006f7960
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnModelChanged(CINSNextBot*) */

void Action<CINSNextBot>::OnModelChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnModelChanged
 * Address: 006fe410
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnModelChanged() */

void __thiscall Action<CINSNextBot>::OnModelChanged(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined *puVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int *in_stack_00000004;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fe41b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar11 = (int *)in_stack_00000004[7];
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a8be5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a8be5 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x2817bd /* "OnModelChanged" */),in_stack_00000004[7] + 0x2060,0x80,&local_34
                     ,unaff_EBX + 0x2818f1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a8485 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(unaff_EBX + 0x2817bd /* "OnModelChanged" */));
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar11 = piVar6;
      (**(code **)(*piVar6 + 0x130))(&local_44,piVar6,puVar9);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a8be5 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a8be5 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a8485 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x281680 /* "%3.2f: %s:%s: " */,dVar10,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x2817bd /* "OnModelChanged" */);
            iVar5 = unaff_EBX + 0x28168f /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25b660 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            puVar8 = &UNK_0028165a + unaff_EBX;
            if (local_44 != 2) {
              puVar8 = (undefined *)(unaff_EBX + 0x281650 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar8 = (undefined *)(unaff_EBX + 0x281666 /* "DONE" */);
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x28166b /* "%s %s " */,
                       puVar8,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a8d05 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a8d05 /* &developer */)), iVar5 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a8485 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x2818bd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar6 + 5;
      piVar6 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 100))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnNavAreaChanged
 * Address: 006f7ee0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnNavAreaChanged(CINSNextBot*, CNavArea*, CNavArea*) */

void Action<CINSNextBot>::OnNavAreaChanged(CINSNextBot *param_1,CNavArea *param_2,CNavArea *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnNavAreaChanged
 * Address: 006fe8a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnNavAreaChanged(CNavArea*, CNavArea*) */

void __thiscall
Action<CINSNextBot>::OnNavAreaChanged(Action<CINSNextBot> *this,CNavArea *param_1,CNavArea *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int *piVar6;
  undefined1 *puVar7;
  int unaff_EBX;
  CNavArea *pCVar8;
  double dVar9;
  undefined4 in_stack_0000000c;
  CNavArea *pCVar10;
  CNavArea *pCVar11;
  undefined8 in_stack_ffffff74;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fe8ab;
  __i686_get_pc_thunk_bx();
  pCVar8 = param_1;
  if (param_1[0x30] != (CNavArea)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar6 = *(int **)(param_1 + 0x1c);
      puVar7 = (undefined1 *)0x0;
      if (piVar6 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a8755 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a8755 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a7ff5 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x27ba7b /* "OnNavAreaChanged" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x281461 /* "%3.2f: %s:%s: %s received EVENT %s
" */,dVar9,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x27ba7b /* "OnNavAreaChanged" */));
          uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
          puVar7 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pCVar11 = param_2;
      pCVar10 = pCVar8;
      (**(code **)(*(int *)pCVar8 + 300))(&local_44,pCVar8,puVar7,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar6 = *(int **)(param_1 + 0x1c);
        if (piVar6 != (int *)0x0) {
          pCVar10 = (CNavArea *)0x1;
          cVar1 = (**(code **)(*piVar6 + 0x980 /* CINSNextBot::IsDebugging */))(piVar6,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a8755 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a8755 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a7ff5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x2811f0 /* "%3.2f: %s:%s: " */,
                       dVar9,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*(int *)pCVar8 + 0xc0))(pCVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x27ba7b /* "OnNavAreaChanged" */);
            iVar4 = unaff_EBX + 0x2811ff /* "reponded to EVENT %s with " */;
            puVar7 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25b1d0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar7,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x2811ca /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x2811c0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x2811d6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x2811db /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25b1d0 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pCVar11 = (CNavArea *)(unaff_EBX + 0x25b19f /* "%s
" */);
            puVar7 = &local_20;
            pCVar10 = (CNavArea *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar8 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar10,puVar7,pCVar11,in_stack_ffffff74);
          }
        }
        else {
          if ((*(int *)(pCVar8 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4a8875 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a8875 /* &developer */)), iVar4 != 0)) {
            puVar7 = (undefined1 *)(**(code **)(*(int *)pCVar8 + 0xb8))(pCVar8);
            pCVar11 = (CNavArea *)(unaff_EBX + 0x27ba7b /* "OnNavAreaChanged" */);
            pCVar10 = (CNavArea *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a7ff5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg(&UNK_0028142d + unaff_EBX);
          }
          piVar6 = *(int **)(pCVar8 + 0x24);
          if (piVar6 != (int *)0x0) {
            (**(code **)(*piVar6 + 4))(piVar6,pCVar10,puVar7,pCVar11);
          }
          *(int *)(pCVar8 + 0x20) = local_44;
          *(int **)(pCVar8 + 0x24) = local_40;
          *(int *)(pCVar8 + 0x28) = local_3c;
          *(int *)(pCVar8 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar8 + 0x14;
      pCVar8 = *(CNavArea **)pCVar11;
    } while (*(CNavArea **)pCVar11 != (CNavArea *)0x0);
    piVar6 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar6 != (int *)0x0) {
      (**(code **)(*piVar6 + 0x60 /* CINSPlayer::Precache */))(piVar6,param_2,in_stack_0000000c);
      piVar6 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnOrderReceived
 * Address: 006f7c90
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnOrderReceived(CINSNextBot*) */

void Action<CINSNextBot>::OnOrderReceived(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnOrderReceived
 * Address: 006f8640
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnOrderReceived() */

void __thiscall Action<CINSNextBot>::OnOrderReceived(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined *puVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  float10 fVar10;
  double dVar11;
  int *in_stack_00000004;
  int *piVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f864b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar12 = (int *)in_stack_00000004[7];
      puVar9 = (undefined1 *)0x0;
      if (piVar12 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar12 + 0x980 /* CINSNextBot::IsDebugging */))(piVar12,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ae9b5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4ae9b5 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_0028747a + unaff_EBX),in_stack_00000004[7] + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x2876c1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ae255 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(&UNK_0028747a + unaff_EBX));
          puVar9 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar12 = piVar6;
      (**(code **)(*piVar6 + 0x180))(&local_44,piVar6,puVar9);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar12 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ae9b5 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ae9b5 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ae255 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,&UNK_00287450 + unaff_EBX,
                       dVar11,pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar11 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar3,&UNK_0028747a + unaff_EBX);
            puVar8 = &UNK_0028745f + unaff_EBX;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x261430 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,puVar8,uVar13);
            }
            puVar8 = (undefined *)(unaff_EBX + 0x28742a /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar8 = (undefined *)(unaff_EBX + 0x287420 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar8 = &UNK_00287436 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,&UNK_0028743b + unaff_EBX,
                       puVar8,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar9 = &local_20;
            piVar12 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar12,puVar9);
            piVar6 = (int *)(*(int **)(unaff_EBX + 0x4ae0bd /* &ins_bot_ignore_human_triggers */))[7];
            if (piVar6 == *(int **)(unaff_EBX + 0x4ae0bd /* &ins_bot_ignore_human_triggers */)) goto LAB_006f8870;
            goto LAB_006f8847;
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4aead5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4aead5 /* &developer */)), iVar5 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar12 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ae255 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x28768d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar12,puVar9);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar12 = piVar6 + 5;
      piVar6 = (int *)*piVar12;
    } while ((int *)*piVar12 != (int *)0x0);
    piVar6 = (int *)(*(int **)(unaff_EBX + 0x4ae0bd /* &ins_bot_ignore_human_triggers */))[7];
    if (piVar6 == *(int **)(unaff_EBX + 0x4ae0bd /* &ins_bot_ignore_human_triggers */)) {
LAB_006f8870:
      if (*(float *)(unaff_EBX + 0x1c04bd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)((uint)piVar6 ^ piVar6[0xb]) &&
          (float)((uint)piVar6 ^ piVar6[0xb]) != *(float *)(unaff_EBX + 0x1c04bd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    else {
LAB_006f8847:
      fVar10 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
      if (*(float *)(unaff_EBX + 0x1c04bd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar10 &&
          (float)fVar10 != *(float *)(unaff_EBX + 0x1c04bd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
    if (piVar6 != (int *)0x0) {
      do {
        (**(code **)(*piVar6 + 0xb4))(piVar6);
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6);
      } while (piVar6 != (int *)0x0);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnPostureChanged
 * Address: 006f77b0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnPostureChanged(CINSNextBot*) */

void Action<CINSNextBot>::OnPostureChanged(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnPostureChanged
 * Address: 00702550
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnPostureChanged() */

void __thiscall Action<CINSNextBot>::OnPostureChanged(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x70255b;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(&DAT_004a4aa5 + unaff_EBX) + 0x40))
                              (*(int **)(&DAT_004a4aa5 + unaff_EBX)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_0027d6fc + unaff_EBX),in_stack_00000004[7] + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x27d7b1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4a4345 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(&UNK_0027d6fc + unaff_EBX));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0xf8))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(&DAT_004a4aa5 + unaff_EBX) + 0x40))
                                (*(int **)(&DAT_004a4aa5 + unaff_EBX)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4a4345 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x27d540 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,&UNK_0027d6fc + unaff_EBX);
            iVar5 = unaff_EBX + 0x27d54f /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x257520 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x27d51a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x27d510 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x27d526 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x27d52b /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4a4bc5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a4bc5 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4a4345 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x27d77d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0x2c))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSeeSomethingSuspicious
 * Address: 006f7f70
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSeeSomethingSuspicious(CINSNextBot*, CBaseCombatCharacter*, Vector const&)
    */

void Action<CINSNextBot>::OnSeeSomethingSuspicious
               (CINSNextBot *param_1,CBaseCombatCharacter *param_2,Vector *param_3)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSeeSomethingSuspicious
 * Address: 006f8b20
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSeeSomethingSuspicious(CBaseCombatCharacter*, Vector const&) */

void __thiscall
Action<CINSNextBot>::OnSeeSomethingSuspicious
          (Action<CINSNextBot> *this,CBaseCombatCharacter *param_1,Vector *param_2)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  undefined *puVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseCombatCharacter *pCVar9;
  float10 fVar10;
  double dVar11;
  undefined4 in_stack_0000000c;
  CBaseCombatCharacter *pCVar12;
  Vector *pVVar13;
  undefined8 in_stack_ffffff74;
  undefined8 uVar14;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f8b2b;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseCombatCharacter)0x0) {
    do {
      uVar2 = (undefined4)((ulonglong)in_stack_ffffff74 >> 0x20);
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4ae4d5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4ae4d5 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          dVar11 = (double)*(float *)(**(int **)(unaff_EBX + 0x4add75 /* &gpGlobals */) + 0xc);
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x286faa /* "OnSeeSomethingSuspicious" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,&UNK_002871e1 + unaff_EBX,dVar11,uVar3,iVar4 + 0x11,uVar2,
                     (INextBot *)(unaff_EBX + 0x286faa /* "OnSeeSomethingSuspicious" */));
          uVar2 = (undefined4)((ulonglong)dVar11 >> 0x20);
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      in_stack_ffffff74 = CONCAT44(uVar2,in_stack_0000000c);
      pVVar13 = param_2;
      pCVar12 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x17c))(&local_44,pCVar9,puVar8,param_2,in_stack_0000000c);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar12 = (CBaseCombatCharacter *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4ae4d5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4ae4d5 /* &NextBotDebugHistory */)), iVar4 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(unaff_EBX + 0x4add75 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,
                       &UNK_00286f70 + unaff_EBX,dVar11,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar11 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar14 = CONCAT44(uVar2,unaff_EBX + 0x286faa /* "OnSeeSomethingSuspicious" */);
            puVar6 = &UNK_00286f7f + unaff_EBX;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x260f50 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,puVar6,uVar14);
            }
            puVar6 = &UNK_00286f4a + unaff_EBX;
            if (local_44 != 2) {
              puVar6 = (undefined *)(unaff_EBX + 0x286f40 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar6 = &UNK_00286f56 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_00286f5b + unaff_EBX,puVar6,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x260f50 /* typeinfo name for CGlobalState+0x5c */;
            if (local_3c != 0) {
              iVar4 = local_3c;
            }
            in_stack_ffffff74 = CONCAT44(local_5c,iVar4);
            pVVar13 = (Vector *)(unaff_EBX + 0x260f1f /* "%s
" */);
            puVar8 = &local_20;
            pCVar12 = (CBaseCombatCharacter *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar12,puVar8,pVVar13,in_stack_ffffff74);
            piVar7 = (int *)(*(int **)(unaff_EBX + 0x4adbdd /* &ins_bot_ignore_human_triggers */))[7];
            if (piVar7 != *(int **)(unaff_EBX + 0x4adbdd /* &ins_bot_ignore_human_triggers */)) goto LAB_006f8f47;
            goto LAB_006f8f70;
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4ae5f5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ae5f5 /* &developer */)), iVar4 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            pVVar13 = (Vector *)(unaff_EBX + 0x286faa /* "OnSeeSomethingSuspicious" */);
            pCVar12 = (CBaseCombatCharacter *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4add75 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg(&UNK_002871ad + unaff_EBX);
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar12,puVar8,pVVar13);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar12 = pCVar9 + 0x14;
      pCVar9 = *(CBaseCombatCharacter **)pCVar12;
    } while (*(CBaseCombatCharacter **)pCVar12 != (CBaseCombatCharacter *)0x0);
    piVar7 = (int *)(*(int **)(unaff_EBX + 0x4adbdd /* &ins_bot_ignore_human_triggers */))[7];
    if (piVar7 == *(int **)(unaff_EBX + 0x4adbdd /* &ins_bot_ignore_human_triggers */)) {
LAB_006f8f70:
      if (*(float *)(unaff_EBX + 0x1bffdd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)((uint)piVar7 ^ piVar7[0xb]) &&
          (float)((uint)piVar7 ^ piVar7[0xb]) != *(float *)(unaff_EBX + 0x1bffdd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    else {
LAB_006f8f47:
      fVar10 = (float10)(**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
      if (*(float *)(unaff_EBX + 0x1bffdd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */) <= (float)fVar10 &&
          (float)fVar10 != *(float *)(unaff_EBX + 0x1bffdd /* typeinfo name for CEntityFactory<CInfoElevatorFloor>+0x28 */)) {
        return;
      }
    }
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    if (piVar7 != (int *)0x0) {
      do {
        (**(code **)(*piVar7 + 0xb0 /* CBaseAnimating::DrawDebugTextOverlays */))(piVar7,param_2,in_stack_0000000c);
        piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
      } while (piVar7 != (int *)0x0);
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnShoved
 * Address: 006f7b40
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnShoved(CINSNextBot*, CBaseEntity*) */

void Action<CINSNextBot>::OnShoved(CINSNextBot *param_1,CBaseEntity *param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnShoved
 * Address: 006fb0e0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnShoved(CBaseEntity*) */

void __thiscall Action<CINSNextBot>::OnShoved(Action<CINSNextBot> *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  INextBot *pIVar5;
  int iVar6;
  int *piVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  CBaseEntity *pCVar9;
  double dVar10;
  int in_stack_00000008;
  CBaseEntity *pCVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fb0eb;
  __i686_get_pc_thunk_bx();
  pCVar9 = param_1;
  if (param_1[0x30] != (CBaseEntity)0x0) {
    do {
      piVar7 = *(int **)(param_1 + 0x1c);
      puVar8 = (undefined1 *)0x0;
      if (piVar7 != (int *)0x0) {
        cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,0x80);
        if ((cVar1 == '\0') &&
           (iVar4 = (**(code **)(**(int **)(unaff_EBX + 0x4abf15 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4abf15 /* &NextBotDebugHistory */)), iVar4 == 0)) {
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar2 = (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
          iVar4 = *(int *)(param_1 + 8);
          uVar3 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x284a64 /* "OnShoved" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x284c21 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ab7b5 /* &gpGlobals */) + 0xc),uVar3,iVar4 + 0x11,
                     uVar2,(INextBot *)(unaff_EBX + 0x284a64 /* "OnShoved" */));
          puVar8 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar4 = in_stack_00000008;
      pCVar11 = pCVar9;
      (**(code **)(*(int *)pCVar9 + 0x15c))(&local_44,pCVar9,puVar8,in_stack_00000008);
      if (local_44 != 0) {
        piVar7 = *(int **)(param_1 + 0x1c);
        if (piVar7 != (int *)0x0) {
          pCVar11 = (CBaseEntity *)0x1;
          cVar1 = (**(code **)(*piVar7 + 0x980 /* CINSNextBot::IsDebugging */))(piVar7,1);
          if (((cVar1 != '\0') ||
              (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4abf15 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4abf15 /* &NextBotDebugHistory */)), iVar6 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar4 = *(int *)(param_1 + 8);
            pIVar5 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ab7b5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar5,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x2849b0 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar5,iVar4 + 0x11);
            uVar2 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*(int *)pCVar9 + 0xc0))(pCVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar2,unaff_EBX + 0x284a64 /* "OnShoved" */);
            iVar4 = unaff_EBX + 0x2849bf /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar2 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25e990 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar2,puVar8,iVar4,uVar12);
            }
            iVar4 = unaff_EBX + 0x28498a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar4 = unaff_EBX + 0x284980 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar4 = unaff_EBX + 0x284996 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x28499b /* "%s %s " */,
                       iVar4,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar4 = unaff_EBX + 0x25e95f /* "%s
" */;
            puVar8 = &local_20;
            pCVar11 = (CBaseEntity *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < *(int *)(pCVar9 + 0x2c)) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,pCVar11,puVar8,iVar4);
          }
        }
        else {
          if ((*(int *)(pCVar9 + 0x2c) == 3) &&
             (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4ac035 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ac035 /* &developer */)), iVar6 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*(int *)pCVar9 + 0xb8))(pCVar9);
            iVar4 = unaff_EBX + 0x284a64 /* "OnShoved" */;
            pCVar11 = (CBaseEntity *)
                      ((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ab7b5 /* &gpGlobals */) + 0xc) >> 0x20
                      );
            DevMsg((char *)(unaff_EBX + 0x284bed /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar7 = *(int **)(pCVar9 + 0x24);
          if (piVar7 != (int *)0x0) {
            (**(code **)(*piVar7 + 4))(piVar7,pCVar11,puVar8,iVar4);
          }
          *(int *)(pCVar9 + 0x20) = local_44;
          *(int **)(pCVar9 + 0x24) = local_40;
          *(int *)(pCVar9 + 0x28) = local_3c;
          *(int *)(pCVar9 + 0x2c) = local_38;
        }
        break;
      }
      pCVar11 = pCVar9 + 0x14;
      pCVar9 = *(CBaseEntity **)pCVar11;
    } while (*(CBaseEntity **)pCVar11 != (CBaseEntity *)0x0);
    piVar7 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar7 != (int *)0x0) {
      (**(code **)(*piVar7 + 0x90 /* CBasePlayer::Activate */))(piVar7);
      piVar7 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSpokeConcept
 * Address: 006f7900
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSpokeConcept(CINSNextBot*, CBaseCombatCharacter*, CAI_Concept,
   ResponseRules::CRR_Response*) */

void Action<CINSNextBot>::OnSpokeConcept(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnSpokeConcept
 * Address: 006ff200
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnSpokeConcept(CBaseCombatCharacter*, CAI_Concept,
   ResponseRules::CRR_Response*) */

void __thiscall
Action<CINSNextBot>::OnSpokeConcept
          (undefined4 param_1_00,int *param_1,int param_3,undefined2 *param_4,undefined4 param_5)

{
  undefined2 uVar1;
  int *piVar2;
  char cVar3;
  undefined4 uVar4;
  undefined1 *puVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  code *pcVar9;
  int *piVar10;
  int unaff_EBX;
  double dVar11;
  int *piVar12;
  undefined8 uVar13;
  int local_6c;
  INextBot *local_54;
  int *local_50;
  int local_4c;
  int local_48;
  undefined2 local_44 [2];
  undefined4 local_40;
  undefined2 local_3c [2];
  undefined4 local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6ff20b;
  __i686_get_pc_thunk_bx();
  piVar10 = param_1;
  if ((char)param_1[0xc] != '\0') {
    do {
      piVar12 = (int *)param_1[7];
      puVar5 = (undefined1 *)0x0;
      if (piVar12 != (int *)0x0) {
        cVar3 = (**(code **)(*piVar12 + 0x980 /* CINSNextBot::IsDebugging */))(piVar12,0x80);
        if ((cVar3 == '\0') &&
           (iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x4a7df5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4a7df5 /* &NextBotDebugHistory */)), iVar6 == 0)) {
          puVar5 = (undefined1 *)param_1[7];
        }
        else {
          uVar8 = (**(code **)(*piVar10 + 0xc0))(piVar10);
          iVar6 = param_1[2];
          uVar4 = (**(code **)(*(int *)(param_1[7] + 0x2060) + 0x144))(param_1[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(iVar6 + 0x11),param_1[7] + 0x2060,0x80,&local_34,
                     unaff_EBX + 0x280b01 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(CTimerEntity::InputFireTimer + unaff_EBX + 5) +
                                       0xc),uVar4,(INextBot *)(iVar6 + 0x11),uVar8,
                     unaff_EBX + 0x2809dc /* "OnSpokeConcept" */);
          puVar5 = (undefined1 *)param_1[7];
        }
      }
      local_44[0] = *param_4;
      local_40 = *(undefined4 *)(param_4 + 2);
      uVar13 = CONCAT44(param_5,local_44);
      iVar6 = param_3;
      piVar12 = piVar10;
      (**(code **)(*piVar10 + 0x124))(&local_54,piVar10,puVar5,param_3,local_44,param_5);
      if (local_54 != (INextBot *)0x0) {
        piVar2 = (int *)param_1[7];
        if (piVar2 != (int *)0x0) {
          piVar12 = (int *)0x1;
          cVar3 = (**(code **)(*piVar2 + 0x980 /* CINSNextBot::IsDebugging */))(piVar2,1);
          if (((cVar3 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a7df5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4a7df5 /* &NextBotDebugHistory */)), iVar7 != 0)) &&
             (local_54 + -1 < (INextBot *)0x3)) {
            iVar7 = param_1[2] + 0x11;
            uVar8 = (**(code **)(*(int *)(param_1[7] + 0x2060) + 0x144))(param_1[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(CTimerEntity::InputFireTimer + unaff_EBX + 5) +
                                       0xc);
            iVar6 = unaff_EBX + 0x280890 /* "%3.2f: %s:%s: " */;
            puVar5 = &local_30;
            uVar4 = 1;
            INextBot::DebugConColorMsg();
            (**(code **)(*piVar10 + 0xc0))(piVar10,uVar4,puVar5,iVar6,dVar11,uVar8,iVar7);
            uVar8 = (undefined4)((ulonglong)dVar11 >> 0x20);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar8,unaff_EBX + 0x2809dc /* "OnSpokeConcept" */);
            iVar6 = unaff_EBX + 0x28089f /* "reponded to EVENT %s with " */;
            puVar5 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar8 = 1;
            INextBot::DebugConColorMsg();
            if (local_50 == (int *)0x0) {
              local_6c = unaff_EBX + 0x25a870 /* typeinfo name for CGlobalState+0x5c */;
            }
            else {
              local_6c = (**(code **)(*local_50 + 0xb8))(local_50,uVar8,puVar5,iVar6,uVar13);
            }
            pcVar9 = (code *)(unaff_EBX + 0x28086a /* "SUSPEND_FOR" */);
            if (local_54 != (INextBot *)0x2) {
              pcVar9 = CLogicTraining::InputSetSavePoint + unaff_EBX;
              if (local_54 == (INextBot *)0x3) {
                pcVar9 = (code *)(unaff_EBX + 0x280876 /* "DONE" */);
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_54,param_1[7] + 0x2060,1,&local_24,unaff_EBX + 0x28087b /* "%s %s " */,pcVar9,local_6c
                      );
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar6 = unaff_EBX + 0x25a870 /* typeinfo name for CGlobalState+0x5c */;
            if (local_4c != 0) {
              iVar6 = local_4c;
            }
            uVar13 = CONCAT44(local_6c,iVar6);
            iVar6 = unaff_EBX + 0x25a83f /* "%s
" */;
            puVar5 = &local_20;
            piVar12 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_48 < piVar10[0xb]) {
          if (local_50 != (int *)0x0) {
            (**(code **)(*local_50 + 4))(local_50,piVar12,puVar5,iVar6,uVar13);
          }
        }
        else {
          if ((piVar10[0xb] == 3) &&
             (iVar7 = (**(code **)(**(int **)(unaff_EBX + 0x4a7f15 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4a7f15 /* &developer */)), iVar7 != 0)) {
            puVar5 = (undefined1 *)(**(code **)(*piVar10 + 0xb8))(piVar10);
            iVar6 = unaff_EBX + 0x2809dc /* "OnSpokeConcept" */;
            piVar12 = (int *)((ulonglong)
                              (double)*(float *)(**(int **)(CTimerEntity::InputFireTimer +
                                                           unaff_EBX + 5) + 0xc) >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x280acd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar2 = (int *)piVar10[9];
          if (piVar2 != (int *)0x0) {
            (**(code **)(*piVar2 + 4))(piVar2,piVar12,puVar5,iVar6);
          }
          piVar10[8] = (int)local_54;
          piVar10[9] = (int)local_50;
          piVar10[10] = local_4c;
          piVar10[0xb] = local_48;
        }
        break;
      }
      piVar12 = piVar10 + 5;
      piVar10 = (int *)*piVar12;
    } while ((int *)*piVar12 != (int *)0x0);
    uVar1 = *param_4;
    uVar8 = *(undefined4 *)(param_4 + 2);
    piVar10 = (int *)(**(code **)(*param_1 + 8))(param_1);
    while (piVar10 != (int *)0x0) {
      local_3c[0] = uVar1;
      local_38 = uVar8;
      (**(code **)(*piVar10 + 0x58))(piVar10,param_3,local_3c,param_5);
      piVar10 = (int *)(**(code **)(*param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryCaptured
 * Address: 006f7bd0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryCaptured(CINSNextBot*, int) */

void Action<CINSNextBot>::OnTerritoryCaptured(CINSNextBot *param_1,int param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryCaptured
 * Address: 006fa300
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryCaptured(int) */

void __thiscall Action<CINSNextBot>::OnTerritoryCaptured(Action<CINSNextBot> *this,int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  undefined *puVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  undefined *in_stack_00000008;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fa30b;
  __i686_get_pc_thunk_bx();
  piVar8 = (int *)param_1;
  if (*(char *)(param_1 + 0x30) != '\0') {
    do {
      piVar11 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4accf5 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4accf5 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar8 + 0xc0))(piVar8);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_00285811 + unaff_EBX),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x285a01 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4ac595 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(&UNK_00285811 + unaff_EBX));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      puVar7 = in_stack_00000008;
      piVar11 = piVar8;
      (**(code **)(*piVar8 + 0x168))(&local_44,piVar8,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4accf5 /* &NextBotDebugHistory */) + 0x40))
                                 (*(int **)(unaff_EBX + 0x4accf5 /* &NextBotDebugHistory */)), iVar5 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(unaff_EBX + 0x4ac595 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x285790 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar8 + 0xc0))(piVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,&UNK_00285811 + unaff_EBX);
            iVar5 = unaff_EBX + 0x28579f /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25f770 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            puVar7 = (undefined *)(unaff_EBX + 0x28576a /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar7 = (undefined *)(unaff_EBX + 0x285760 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar7 = &UNK_00285776 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x28577b /* "%s %s " */,
                       puVar7,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar7 = (undefined *)(unaff_EBX + 0x25f73f /* "%s
" */);
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar8[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9,puVar7);
          }
        }
        else {
          if ((piVar8[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ace15 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ace15 /* &developer */)), iVar5 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar8 + 0xb8))(piVar8);
            puVar7 = &UNK_00285811 + unaff_EBX;
            piVar11 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4ac595 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x2859cd /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar8[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9,puVar7);
          }
          piVar8[8] = local_44;
          piVar8[9] = (int)local_40;
          piVar8[10] = local_3c;
          piVar8[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar8 + 5;
      piVar8 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x9c))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryContested
 * Address: 006f7ba0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryContested(CINSNextBot*, int) */

void Action<CINSNextBot>::OnTerritoryContested(CINSNextBot *param_1,int param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryContested
 * Address: 006fa7a0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryContested(int) */

void __thiscall Action<CINSNextBot>::OnTerritoryContested(Action<CINSNextBot> *this,int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  int iVar7;
  int *piVar8;
  undefined1 *puVar9;
  int unaff_EBX;
  double dVar10;
  int in_stack_00000008;
  int *piVar11;
  undefined8 uVar12;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6fa7ab;
  __i686_get_pc_thunk_bx();
  piVar8 = (int *)param_1;
  if (*(char *)(param_1 + 0x30) != '\0') {
    do {
      piVar11 = *(int **)(param_1 + 0x1c);
      puVar9 = (undefined1 *)0x0;
      if (piVar11 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar11 + 0x980 /* CINSNextBot::IsDebugging */))(piVar11,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(CEntityFactory<CLogicRelay>::GetEntitySize +
                                           unaff_EBX + 5) + 0x40))
                              (*(int **)(CEntityFactory<CLogicRelay>::GetEntitySize + unaff_EBX + 5)
                              ), iVar5 == 0)) {
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar8 + 0xc0))(piVar8);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x285385 /* "OnTerritoryContested" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x285561 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(&LAB_004ac0f5 + unaff_EBX) + 0xc),uVar4,
                     iVar5 + 0x11,uVar3,(INextBot *)(unaff_EBX + 0x285385 /* "OnTerritoryContested" */));
          puVar9 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar5 = in_stack_00000008;
      piVar11 = piVar8;
      (**(code **)(*piVar8 + 0x164))(&local_44,piVar8,puVar9,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar11 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar7 = (**(code **)(**(int **)(CEntityFactory<CLogicRelay>::GetEntitySize +
                                              unaff_EBX + 5) + 0x40))
                                 (*(int **)(CEntityFactory<CLogicRelay>::GetEntitySize +
                                           unaff_EBX + 5)), iVar7 != 0)) && (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar10 = (double)*(float *)(**(int **)(&LAB_004ac0f5 + unaff_EBX) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x2852f0 /* "%3.2f: %s:%s: " */,
                       dVar10,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar10 >> 0x20);
            (**(code **)(*piVar8 + 0xc0))(piVar8);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar12 = CONCAT44(uVar3,unaff_EBX + 0x285385 /* "OnTerritoryContested" */);
            iVar5 = unaff_EBX + 0x2852ff /* "reponded to EVENT %s with " */;
            puVar9 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25f2d0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar9,iVar5,uVar12);
            }
            iVar5 = unaff_EBX + 0x2852ca /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x2852c0 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x2852d6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,unaff_EBX + 0x2852db /* "%s %s " */,
                       iVar5,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar5 = unaff_EBX + 0x25f29f /* "%s
" */;
            puVar9 = &local_20;
            piVar11 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar8[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar11,puVar9,iVar5);
          }
        }
        else {
          if ((piVar8[0xb] == 3) &&
             (iVar7 = (**(code **)(**(int **)(&LAB_004ac975 + unaff_EBX) + 0x40))
                                (*(int **)(&LAB_004ac975 + unaff_EBX)), iVar7 != 0)) {
            puVar9 = (undefined1 *)(**(code **)(*piVar8 + 0xb8))(piVar8);
            iVar5 = unaff_EBX + 0x285385 /* "OnTerritoryContested" */;
            piVar11 = (int *)((ulonglong)
                              (double)*(float *)(**(int **)(&LAB_004ac0f5 + unaff_EBX) + 0xc) >>
                             0x20);
            DevMsg((char *)(unaff_EBX + 0x28552d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar8[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar11,puVar9,iVar5);
          }
          piVar8[8] = local_44;
          piVar8[9] = (int)local_40;
          piVar8[10] = local_3c;
          piVar8[0xb] = local_38;
        }
        break;
      }
      piVar11 = piVar8 + 5;
      piVar8 = (int *)*piVar11;
    } while ((int *)*piVar11 != (int *)0x0);
    piVar8 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 0x98))(piVar8);
      piVar8 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryLost
 * Address: 006f7c00
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryLost(CINSNextBot*, int) */

void Action<CINSNextBot>::OnTerritoryLost(CINSNextBot *param_1,int param_2)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnTerritoryLost
 * Address: 006f9e60
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnTerritoryLost(int) */

void __thiscall Action<CINSNextBot>::OnTerritoryLost(Action<CINSNextBot> *this,int param_1)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  INextBot *pIVar6;
  undefined *puVar7;
  int iVar8;
  int *piVar9;
  undefined1 *puVar10;
  int unaff_EBX;
  double dVar11;
  int in_stack_00000008;
  int *piVar12;
  undefined8 uVar13;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f9e6b;
  __i686_get_pc_thunk_bx();
  piVar9 = (int *)param_1;
  if (*(char *)(param_1 + 0x30) != '\0') {
    do {
      piVar12 = *(int **)(param_1 + 0x1c);
      puVar10 = (undefined1 *)0x0;
      if (piVar12 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar12 + 0x980 /* CINSNextBot::IsDebugging */))(piVar12,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(&LAB_004ad195 + unaff_EBX) + 0x40))
                              (*(int **)(&LAB_004ad195 + unaff_EBX)), iVar5 == 0)) {
          puVar10 = *(undefined1 **)(param_1 + 0x1c);
        }
        else {
          uVar3 = (**(code **)(*piVar9 + 0xc0))(piVar9);
          iVar5 = *(int *)(param_1 + 8);
          uVar4 = (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                            (*(int *)(param_1 + 0x1c) + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(unaff_EBX + 0x285ca1 /* "OnTerritoryLost" */),*(int *)(param_1 + 0x1c) + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x285ea1 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(CLogicEventListener::Spawn + unaff_EBX + 5) + 0xc
                                       ),uVar4,iVar5 + 0x11,uVar3,(INextBot *)(unaff_EBX + 0x285ca1 /* "OnTerritoryLost" */)
                    );
          puVar10 = *(undefined1 **)(param_1 + 0x1c);
        }
      }
      iVar5 = in_stack_00000008;
      piVar12 = piVar9;
      (**(code **)(*piVar9 + 0x16c))(&local_44,piVar9,puVar10,in_stack_00000008);
      if (local_44 != 0) {
        piVar1 = *(int **)(param_1 + 0x1c);
        if (piVar1 != (int *)0x0) {
          piVar12 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if (((cVar2 != '\0') ||
              (iVar8 = (**(code **)(**(int **)(&LAB_004ad195 + unaff_EBX) + 0x40))
                                 (*(int **)(&LAB_004ad195 + unaff_EBX)), iVar8 != 0)) &&
             (local_44 - 1U < 3)) {
            iVar5 = *(int *)(param_1 + 8);
            pIVar6 = (INextBot *)
                     (**(code **)(*(int *)(*(int *)(param_1 + 0x1c) + 0x2060) + 0x144))
                               (*(int *)(param_1 + 0x1c) + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar11 = (double)*(float *)(**(int **)(CLogicEventListener::Spawn + unaff_EBX + 5) + 0xc
                                       );
            INextBot::DebugConColorMsg
                      (pIVar6,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_30,unaff_EBX + 0x285c30 /* "%3.2f: %s:%s: " */,
                       dVar11,pIVar6,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar11 >> 0x20);
            (**(code **)(*piVar9 + 0xc0))(piVar9);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar13 = CONCAT44(uVar3,unaff_EBX + 0x285ca1 /* "OnTerritoryLost" */);
            iVar5 = unaff_EBX + 0x285c3f /* "reponded to EVENT %s with " */;
            puVar10 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x25fc10 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar10,iVar5,uVar13);
            }
            puVar7 = (undefined *)(unaff_EBX + 0x285c0a /* "SUSPEND_FOR" */);
            if (local_44 != 2) {
              puVar7 = (undefined *)(unaff_EBX + 0x285c00 /* "CHANGE_TO" */);
              if (local_44 == 3) {
                puVar7 = &UNK_00285c16 + unaff_EBX;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,*(int *)(param_1 + 0x1c) + 0x2060,1,&local_24,
                       &UNK_00285c1b + unaff_EBX,puVar7,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            iVar5 = unaff_EBX + 0x25fbdf /* "%s
" */;
            puVar10 = &local_20;
            piVar12 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar9[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar12,puVar10,iVar5);
          }
        }
        else {
          if ((piVar9[0xb] == 3) &&
             (iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x4ad2b5 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ad2b5 /* &developer */)), iVar8 != 0)) {
            puVar10 = (undefined1 *)(**(code **)(*piVar9 + 0xb8))(piVar9);
            iVar5 = unaff_EBX + 0x285ca1 /* "OnTerritoryLost" */;
            piVar12 = (int *)((ulonglong)
                              (double)*(float *)(**(int **)(CLogicEventListener::Spawn +
                                                           unaff_EBX + 5) + 0xc) >> 0x20);
            DevMsg((char *)(unaff_EBX + 0x285e6d /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
          }
          piVar1 = (int *)piVar9[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar12,puVar10,iVar5);
          }
          piVar9[8] = local_44;
          piVar9[9] = (int)local_40;
          piVar9[10] = local_3c;
          piVar9[0xb] = local_38;
        }
        break;
      }
      piVar12 = piVar9 + 5;
      piVar9 = (int *)*piVar12;
    } while ((int *)*piVar12 != (int *)0x0);
    piVar9 = (int *)(**(code **)(*(int *)param_1 + 8))(param_1);
    while (piVar9 != (int *)0x0) {
      (**(code **)(*piVar9 + 0xa0))(piVar9);
      piVar9 = (int *)(**(code **)(*(int *)param_1 + 0xc))(param_1);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnWin
 * Address: 006f7c30
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnWin(CINSNextBot*) */

void Action<CINSNextBot>::OnWin(CINSNextBot *param_1)

{
  *(undefined4 *)param_1 = 0 /* Continue */;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 0xc) = 1;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::OnWin
 * Address: 006f99d0
 * ---------------------------------------- */

/* Action<CINSNextBot>::OnWin() */

void __thiscall Action<CINSNextBot>::OnWin(Action<CINSNextBot> *this)

{
  int *piVar1;
  char cVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  INextBot *pIVar7;
  undefined1 *puVar8;
  int unaff_EBX;
  double dVar9;
  int *in_stack_00000004;
  int *piVar10;
  undefined8 uVar11;
  INextBot *local_5c;
  int local_44;
  int *local_40;
  int local_3c;
  int local_38;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined1 local_24;
  undefined1 local_23;
  undefined1 local_22;
  undefined1 local_21;
  undefined1 local_20;
  undefined1 local_1f;
  undefined1 local_1e;
  undefined1 local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x6f99db;
  __i686_get_pc_thunk_bx();
  piVar6 = in_stack_00000004;
  if ((char)in_stack_00000004[0xc] != '\0') {
    do {
      piVar10 = (int *)in_stack_00000004[7];
      puVar8 = (undefined1 *)0x0;
      if (piVar10 != (int *)0x0) {
        cVar2 = (**(code **)(*piVar10 + 0x980 /* CINSNextBot::IsDebugging */))(piVar10,0x80);
        if ((cVar2 == '\0') &&
           (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ad625 /* &NextBotDebugHistory */) + 0x40))
                              (*(int **)(unaff_EBX + 0x4ad625 /* &NextBotDebugHistory */)), iVar5 == 0)) {
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
        else {
          uVar3 = (**(code **)(*piVar6 + 0xc0))(piVar6);
          iVar5 = in_stack_00000004[2];
          uVar4 = (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                            (in_stack_00000004[7] + 0x2060);
          local_34 = 100;
          local_33 = 100;
          local_32 = 100;
          local_31 = 0xff;
          INextBot::DebugConColorMsg
                    ((INextBot *)(&UNK_0028612b + unaff_EBX),in_stack_00000004[7] + 0x2060,0x80,
                     &local_34,unaff_EBX + 0x286331 /* "%3.2f: %s:%s: %s received EVENT %s
" */,
                     (double)*(float *)(**(int **)(unaff_EBX + 0x4acec5 /* &gpGlobals */) + 0xc),uVar4,iVar5 + 0x11,
                     uVar3,(INextBot *)(&UNK_0028612b + unaff_EBX));
          puVar8 = (undefined1 *)in_stack_00000004[7];
        }
      }
      piVar10 = piVar6;
      (**(code **)(*piVar6 + 0x170))(&local_44,piVar6,puVar8);
      if (local_44 != 0) {
        piVar1 = (int *)in_stack_00000004[7];
        if ((piVar1 != (int *)0x0) && (local_44 - 1U < 3)) {
          piVar10 = (int *)0x1;
          cVar2 = (**(code **)(*piVar1 + 0x980 /* CINSNextBot::IsDebugging */))(piVar1,1);
          if ((cVar2 != '\0') ||
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ad625 /* &NextBotDebugHistory */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ad625 /* &NextBotDebugHistory */)), iVar5 != 0)) {
            iVar5 = in_stack_00000004[2];
            pIVar7 = (INextBot *)
                     (**(code **)(*(int *)(in_stack_00000004[7] + 0x2060) + 0x144))
                               (in_stack_00000004[7] + 0x2060);
            local_30 = 0xff;
            local_2f = 0xff;
            local_2e = 0;
            local_2d = 0xff;
            dVar9 = (double)*(float *)(**(int **)(unaff_EBX + 0x4acec5 /* &gpGlobals */) + 0xc);
            INextBot::DebugConColorMsg
                      (pIVar7,in_stack_00000004[7] + 0x2060,1,&local_30,unaff_EBX + 0x2860c0 /* "%3.2f: %s:%s: " */,dVar9,
                       pIVar7,iVar5 + 0x11);
            uVar3 = (undefined4)((ulonglong)dVar9 >> 0x20);
            (**(code **)(*piVar6 + 0xc0))(piVar6);
            local_2c = 0xff;
            local_2b = 0xff;
            local_2a = 0xff;
            local_29 = 0xff;
            INextBot::DebugConColorMsg();
            local_28 = 0xff;
            uVar11 = CONCAT44(uVar3,&UNK_0028612b + unaff_EBX);
            iVar5 = unaff_EBX + 0x2860cf /* "reponded to EVENT %s with " */;
            puVar8 = &local_28;
            local_27 = 0xff;
            local_26 = 0;
            local_25 = 0xff;
            uVar3 = 1;
            INextBot::DebugConColorMsg();
            if (local_40 == (int *)0x0) {
              local_5c = (INextBot *)(unaff_EBX + 0x2600a0 /* typeinfo name for CGlobalState+0x5c */);
            }
            else {
              local_5c = (INextBot *)
                         (**(code **)(*local_40 + 0xb8))(local_40,uVar3,puVar8,iVar5,uVar11);
            }
            iVar5 = unaff_EBX + 0x28609a /* "SUSPEND_FOR" */;
            if (local_44 != 2) {
              iVar5 = unaff_EBX + 0x286090 /* "CHANGE_TO" */;
              if (local_44 == 3) {
                iVar5 = unaff_EBX + 0x2860a6 /* "DONE" */;
              }
            }
            local_24 = 0xff;
            local_23 = 0;
            local_22 = 0;
            local_21 = 0xff;
            INextBot::DebugConColorMsg
                      (local_5c,in_stack_00000004[7] + 0x2060,1,&local_24,unaff_EBX + 0x2860ab /* "%s %s " */,iVar5
                       ,local_5c);
            local_20 = 0;
            local_1f = 0xff;
            local_1e = 0;
            local_1d = 0xff;
            puVar8 = &local_20;
            piVar10 = (int *)0x1;
            INextBot::DebugConColorMsg();
          }
        }
        if (local_38 < piVar6[0xb]) {
          if (local_40 != (int *)0x0) {
            (**(code **)(*local_40 + 4))(local_40,piVar10,puVar8);
          }
        }
        else {
          if ((piVar6[0xb] == 3) &&
             (iVar5 = (**(code **)(**(int **)(unaff_EBX + 0x4ad745 /* &developer */) + 0x40))
                                (*(int **)(unaff_EBX + 0x4ad745 /* &developer */)), iVar5 != 0)) {
            puVar8 = (undefined1 *)(**(code **)(*piVar6 + 0xb8))(piVar6);
            piVar10 = (int *)((ulonglong)(double)*(float *)(**(int **)(unaff_EBX + 0x4acec5 /* &gpGlobals */) + 0xc)
                             >> 0x20);
            DevMsg(&UNK_002862fd + unaff_EBX);
          }
          piVar1 = (int *)piVar6[9];
          if (piVar1 != (int *)0x0) {
            (**(code **)(*piVar1 + 4))(piVar1,piVar10,puVar8);
          }
          piVar6[8] = local_44;
          piVar6[9] = (int)local_40;
          piVar6[10] = local_3c;
          piVar6[0xb] = local_38;
        }
        break;
      }
      piVar10 = piVar6 + 5;
      piVar6 = (int *)*piVar10;
    } while ((int *)*piVar10 != (int *)0x0);
    for (piVar6 = (int *)(**(code **)(*in_stack_00000004 + 8))(in_stack_00000004);
        piVar6 != (int *)0x0;
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0xc))(in_stack_00000004,piVar6)) {
      (**(code **)(*piVar6 + 0xa4))(piVar6);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::PrintStateToConsole
 * Address: 007514b0
 * ---------------------------------------- */

/* Action<CINSNextBot>::PrintStateToConsole() const */

void Action<CINSNextBot>::PrintStateToConsole(void)

{
  char *pcVar1;
  char *pcVar2;
  char cVar3;
  Action<CINSNextBot> *this;
  char *pcVar4;
  int unaff_EBX;
  int iVar5;
  char *local_144;
  char local_13c;
  char local_13b [255];
  undefined1 local_3c;
  undefined1 local_3b;
  undefined1 local_3a;
  undefined1 local_39;
  undefined1 local_38;
  undefined1 local_37;
  undefined1 local_36;
  undefined1 local_35;
  undefined1 local_34;
  undefined1 local_33;
  undefined1 local_32;
  undefined1 local_31;
  undefined1 local_30;
  undefined1 local_2f;
  undefined1 local_2e;
  undefined1 local_2d;
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined1 local_26;
  undefined1 local_25;
  undefined4 uStack_14;
  
  uStack_14 = 0x7514bb;
  __i686_get_pc_thunk_bx();
  pcVar2 = (char *)DebugString(this);
  local_3c = 0xff;
  cVar3 = *pcVar2;
  local_3b = 0x96;
  local_3a = 0x96;
  local_39 = 0xff;
  local_38 = 0x96;
  local_37 = 0xff;
  local_36 = 0x96;
  local_35 = 0xff;
  local_34 = 0x96;
  local_33 = 0x96;
  local_32 = 0xff;
  local_31 = 0xff;
  local_30 = 0xff;
  local_2f = 0xff;
  local_2e = 0x96;
  local_2d = 0xff;
  local_2c = 0x32;
  local_2b = 0xff;
  local_2a = 0xff;
  local_29 = 0xff;
  local_28 = 0xff;
  local_27 = 0x96;
  local_26 = 0xff;
  local_25 = 0xff;
  if (cVar3 == '\0') {
    pcVar4 = &local_13c;
  }
  else {
    iVar5 = 0;
    pcVar1 = (char *)(unaff_EBX + 0x227f39 /* "%s" */);
    pcVar4 = &local_13c;
    do {
      while( true ) {
        *pcVar4 = cVar3;
        cVar3 = *pcVar2;
        if (cVar3 != '(') break;
        pcVar4[1] = '\0';
        iVar5 = (iVar5 + 1) - (uint)(iVar5 == 0);
        DevMsg(pcVar1);
        cVar3 = pcVar2[1];
        pcVar2 = pcVar2 + 1;
        pcVar4 = &local_13c;
        if (cVar3 == '\0') goto LAB_007515be;
      }
      if (cVar3 == ')') {
        *pcVar4 = '\0';
        iVar5 = iVar5 + -1 + (uint)(iVar5 == 0);
        DevMsg(pcVar1);
        local_13c = ')';
        pcVar4 = local_13b;
      }
      else if ((cVar3 == '<') && (iVar5 == 0)) {
        pcVar4[1] = '<';
        pcVar2 = pcVar2 + 1;
        iVar5 = 1;
        pcVar4[2] = '\0';
        DevMsg(pcVar1);
        pcVar4 = &local_13c;
      }
      else {
        pcVar4 = pcVar4 + 1;
      }
      cVar3 = pcVar2[1];
      pcVar2 = pcVar2 + 1;
    } while (cVar3 != '\0');
  }
LAB_007515be:
  local_144 = (char *)(unaff_EBX + 0x227f39 /* "%s" */);
  *pcVar4 = '\0';
  DevMsg(local_144);
  DevMsg((char *)(unaff_EBX + 0x23d618 /* "

" */));
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::StorePendingEventResult
 * Address: 0072e630
 * ---------------------------------------- */

/* Action<CINSNextBot>::StorePendingEventResult(EventDesiredResult<CINSNextBot> const&, char const*)
    */

void __cdecl Action<CINSNextBot>::StorePendingEventResult(EventDesiredResult *param_1,char *param_2)

{
  int *piVar1;
  int iVar2;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)param_2 != 0) {
    if (*(int *)(param_2 + 0xc) < *(int *)(param_1 + 0x2c)) {
      piVar1 = *(int **)(param_2 + 4);
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 4))(piVar1);
        return;
      }
    }
    else {
      if (*(int *)(param_1 + 0x2c) == 3) {
        iVar2 = (**(code **)(**(int **)(&DAT_00478adc + unaff_EBX) + 0x40))
                          (*(int **)(&DAT_00478adc + unaff_EBX));
        if (iVar2 != 0) {
          (**(code **)(*(int *)param_1 + 0xb8))(param_1);
          DevMsg((char *)(unaff_EBX + 0x251694 /* "%3.2f: WARNING: %s::%s() RESULT_CRITICAL collision
" */));
        }
      }
      piVar1 = *(int **)(param_1 + 0x24);
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 4))(piVar1);
      }
      *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)param_2;
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_2 + 4);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_2 + 8);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_2 + 0xc);
    }
  }
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::~Action
 * Address: 006f75e0
 * ---------------------------------------- */

/* non-virtual thunk to Action<CINSNextBot>::~Action() */

void __thiscall Action<CINSNextBot>::~Action(Action<CINSNextBot> *this)

{
  ~Action(this);
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::~Action
 * Address: 006f75f0
 * ---------------------------------------- */

/* Action<CINSNextBot>::~Action() */

void __thiscall Action<CINSNextBot>::~Action(Action<CINSNextBot> *this)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x49d22d /* vtable for Action<CINSNextBot>+0x8 */;
  in_stack_00000004[1] = unaff_EBX + 0x49d3bd /* vtable for Action<CINSNextBot>+0x198 */;
  iVar1 = in_stack_00000004[3];
  if ((iVar1 != 0) && (*(int **)(iVar1 + 0x10) == in_stack_00000004)) {
    *(int *)(iVar1 + 0x10) = in_stack_00000004[5];
  }
  piVar3 = (int *)in_stack_00000004[4];
  while (piVar3 != (int *)0x0) {
    piVar2 = (int *)piVar3[5];
    (**(code **)(*piVar3 + 4))(piVar3);
    piVar3 = piVar2;
  }
  if (in_stack_00000004[5] != 0) {
    *(undefined4 *)(in_stack_00000004[5] + 0x18) = 0;
  }
  piVar3 = (int *)in_stack_00000004[6];
  if (piVar3 != (int *)0x0) {
    (**(code **)(*piVar3 + 4))(piVar3);
  }
  piVar3 = (int *)in_stack_00000004[9];
  if (piVar3 != (int *)0x0) {
    (**(code **)(*piVar3 + 4))(piVar3);
  }
  in_stack_00000004[1] = unaff_EBX + 0x431acd /* vtable for IContextualQuery+0x8 */;
  *in_stack_00000004 = unaff_EBX + 0x431a0d /* vtable for INextBotEventResponder+0x8 */;
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::~Action
 * Address: 006f7fa0
 * ---------------------------------------- */

/* non-virtual thunk to Action<CINSNextBot>::~Action() */

void __thiscall Action<CINSNextBot>::~Action(Action<CINSNextBot> *this)

{
  ~Action(this);
  return;
}



/* ----------------------------------------
 * Action<CINSNextBot>::~Action
 * Address: 006f7fb0
 * ---------------------------------------- */

/* Action<CINSNextBot>::~Action() */

void __thiscall Action<CINSNextBot>::~Action(Action<CINSNextBot> *this)

{
  Action<CINSNextBot> *this_00;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~Action(this_00);
  operator_delete(in_stack_00000004);
  return;
}



