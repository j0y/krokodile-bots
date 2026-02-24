/*
 * CINSNextBot -- Decompiled bot AI functions
 * Source: server_srv.so (Insurgency 2014)
 * Decompiled by Ghidra unknown
 * Functions: 154
 */

/* ----------------------------------------
 * CINSNextBot::CINSNextBot
 * Address: 00748c00
 * ---------------------------------------- */

/* CINSNextBot::CINSNextBot() */

void __thiscall CINSNextBot::CINSNextBot(CINSNextBot *this)

{
  int iVar1;
  code *pcVar2;
  int *piVar3;
  int *piVar4;
  float fVar5;
  int iVar6;
  code *pcVar7;
  int *piVar8;
  int iVar9;
  INextBot *pIVar10;
  CINSNextBot *pCVar11;
  CINSPlayer *this_00;
  INextBot *this_01;
  CINSBotBody *this_02;
  CINSBotLocomotion *this_03;
  CINSBotChatter *this_04;
  CINSNextBotIntention *this_05;
  int unaff_EBX;
  float10 fVar12;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CINSPlayer::CINSPlayer(this_00);
  INextBot::INextBot(this_01);
  in_stack_00000004[0x835] = 0;
  *in_stack_00000004 = (int)(&UNK_0045345d + unaff_EBX);
  in_stack_00000004[0x59e] = unaff_EBX + 0x453d91 /* vtable for NextBotPlayer<CINSPlayer>+0x93c */ /* vtable for NextBotPlayer<CINSPlayer>+0x93c */ /* vtable for NextBotPlayer<CINSPlayer>+0x93c */;
  in_stack_00000004[0x818] = unaff_EBX + 0x453da5 /* vtable for NextBotPlayer<CINSPlayer>+0x950 */ /* vtable for NextBotPlayer<CINSPlayer>+0x950 */ /* vtable for NextBotPlayer<CINSPlayer>+0x950 */;
  iVar1 = unaff_EBX + 0x3df5ad /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  in_stack_00000004[0x831] = unaff_EBX + 0x453efd /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */ /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */ /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */;
  pcVar2 = (code *)(unaff_EBX + -0x51849b /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */ /* CountdownTimer::NetworkStateChanged */);
  in_stack_00000004[0x834] = iVar1; /* CountdownTimer timer_0 */
  (*pcVar2)(in_stack_00000004 + 0x834,in_stack_00000004 + 0x835);
  in_stack_00000004[0x836] = -0x40800000 /* -1.0f */; /* timer_0.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x834] + 4))(in_stack_00000004 + 0x834,in_stack_00000004 + 0x836); /* timer_0.NetworkStateChanged() */
  in_stack_00000004[0x837] = iVar1; /* CountdownTimer timer_1 */
  in_stack_00000004[0x838] = 0;
  (*pcVar2)(in_stack_00000004 + 0x837,in_stack_00000004 + 0x838);
  in_stack_00000004[0x839] = -0x40800000 /* -1.0f */; /* timer_1.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x837] + 4))(in_stack_00000004 + 0x837,in_stack_00000004 + 0x839); /* timer_1.NetworkStateChanged() */
  in_stack_00000004[0x83a] = iVar1; /* CountdownTimer timer_2 */
  in_stack_00000004[0x83b] = 0;
  (*pcVar2)(in_stack_00000004 + 0x83a,in_stack_00000004 + 0x83b);
  in_stack_00000004[0x83c] = -0x40800000 /* -1.0f */; /* timer_2.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x83a] + 4))(in_stack_00000004 + 0x83a,in_stack_00000004 + 0x83c); /* timer_2.NetworkStateChanged() */
  in_stack_00000004[0x83d] = iVar1; /* CountdownTimer timer_3 */
  in_stack_00000004[0x83e] = 0;
  (*pcVar2)(in_stack_00000004 + 0x83d,in_stack_00000004 + 0x83e);
  in_stack_00000004[0x83f] = -0x40800000 /* -1.0f */; /* timer_3.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x83d] + 4))(in_stack_00000004 + 0x83d,in_stack_00000004 + 0x83f); /* timer_3.NetworkStateChanged() */
  in_stack_00000004[0x840] = iVar1; /* CountdownTimer timer_4 */
  in_stack_00000004[0x841] = 0;
  (*pcVar2)(in_stack_00000004 + 0x840,in_stack_00000004 + 0x841);
  in_stack_00000004[0x842] = -0x40800000 /* -1.0f */; /* timer_4.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x840] + 4))(in_stack_00000004 + 0x840,in_stack_00000004 + 0x842); /* timer_4.NetworkStateChanged() */
  in_stack_00000004[0x843] = iVar1; /* CountdownTimer timer_5 */
  in_stack_00000004[0x844] = 0;
  (*pcVar2)(in_stack_00000004 + 0x843,in_stack_00000004 + 0x844);
  in_stack_00000004[0x845] = -0x40800000 /* -1.0f */; /* timer_5.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x843] + 4))(in_stack_00000004 + 0x843,in_stack_00000004 + 0x845); /* timer_5.NetworkStateChanged() */
  in_stack_00000004[0x846] = iVar1; /* CountdownTimer timer_6 */
  in_stack_00000004[0x847] = 0;
  (*pcVar2)(in_stack_00000004 + 0x846,in_stack_00000004 + 0x847);
  in_stack_00000004[0x848] = -0x40800000 /* -1.0f */; /* timer_6.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x846] + 4))(in_stack_00000004 + 0x846,in_stack_00000004 + 0x848); /* timer_6.NetworkStateChanged() */
  in_stack_00000004[0x849] = iVar1; /* CountdownTimer timer_7 */
  in_stack_00000004[0x84a] = 0;
  (*pcVar2)(in_stack_00000004 + 0x849,in_stack_00000004 + 0x84a);
  in_stack_00000004[0x84b] = -0x40800000 /* -1.0f */; /* timer_7.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x849] + 4))(in_stack_00000004 + 0x849,in_stack_00000004 + 0x84b); /* timer_7.NetworkStateChanged() */
  in_stack_00000004[0x84c] = iVar1; /* CountdownTimer timer_8 */
  in_stack_00000004[0x84d] = 0;
  (*pcVar2)(in_stack_00000004 + 0x84c,in_stack_00000004 + 0x84d);
  in_stack_00000004[0x84e] = -0x40800000 /* -1.0f */; /* timer_8.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x84c] + 4))(in_stack_00000004 + 0x84c,in_stack_00000004 + 0x84e); /* timer_8.NetworkStateChanged() */
  in_stack_00000004[0x84f] = iVar1; /* CountdownTimer timer_9 */
  in_stack_00000004[0x850] = 0;
  (*pcVar2)(in_stack_00000004 + 0x84f,in_stack_00000004 + 0x850);
  in_stack_00000004[0x851] = -0x40800000 /* -1.0f */; /* timer_9.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x84f] + 4))(in_stack_00000004 + 0x84f,in_stack_00000004 + 0x851); /* timer_9.NetworkStateChanged() */
  in_stack_00000004[0x852] = iVar1; /* CountdownTimer timer_10 */
  in_stack_00000004[0x853] = 0;
  (*pcVar2)(in_stack_00000004 + 0x852,in_stack_00000004 + 0x853);
  in_stack_00000004[0x854] = -0x40800000 /* -1.0f */; /* timer_10.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x852] + 4))(in_stack_00000004 + 0x852,in_stack_00000004 + 0x854); /* timer_10.NetworkStateChanged() */
  in_stack_00000004[0x855] = iVar1; /* CountdownTimer timer_11 */
  in_stack_00000004[0x856] = 0;
  (*pcVar2)(in_stack_00000004 + 0x855,in_stack_00000004 + 0x856);
  in_stack_00000004[0x857] = -0x40800000 /* -1.0f */; /* timer_11.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x855] + 4))(in_stack_00000004 + 0x855,in_stack_00000004 + 0x857); /* timer_11.NetworkStateChanged() */
  iVar6 = *(int *)(unaff_EBX + 0x45e045 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  in_stack_00000004[0x859] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x858] = iVar6 + 8;
  pcVar7 = *(code **)(iVar6 + 0x10);
  (*pcVar7)(in_stack_00000004 + 0x858,in_stack_00000004 + 0x859);
  in_stack_00000004[0x85c] = -1;
  in_stack_00000004[0x833] = 0;
  in_stack_00000004[0x832] = 0;
  if (in_stack_00000004[0x859] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x858] + 8))(in_stack_00000004 + 0x858,in_stack_00000004 + 0x859)
    ;
    in_stack_00000004[0x859] = -0x40800000 /* -1.0f */;
  }
  in_stack_00000004[0x85c] = -1;
  *in_stack_00000004 = unaff_EBX + 0x4526bd /* vtable for CINSNextBot+0x8 */ /* vtable for CINSNextBot+0x8 */ /* vtable for CINSNextBot+0x8 */;
  in_stack_00000004[0x59e] = (int)(&UNK_00453049 + unaff_EBX);
  in_stack_00000004[0x818] = unaff_EBX + 0x45305d /* vtable for CINSNextBot+0x9a8 */ /* vtable for CINSNextBot+0x9a8 */ /* vtable for CINSNextBot+0x9a8 */;
  in_stack_00000004[0x831] = unaff_EBX + 0x4531b5 /* vtable for CINSNextBot+0xb00 */ /* vtable for CINSNextBot+0xb00 */ /* vtable for CINSNextBot+0xb00 */;
  in_stack_00000004[0x85d] = 0;
  in_stack_00000004[0x85e] = 0;
  in_stack_00000004[0x85f] = 0;
  in_stack_00000004[0x860] = 0;
  in_stack_00000004[0x861] = 0;
  CINSPathFollower::CINSPathFollower((CINSPathFollower *)(in_stack_00000004 + 0x8a6));
  in_stack_00000004[0x1ac2] = iVar1; /* CountdownTimer timer_12 */
  in_stack_00000004[0x8a6] = unaff_EBX + 0x3e06bd /* vtable for ChasePath+0x8 */ /* vtable for ChasePath+0x8 */ /* vtable for ChasePath+0x8 */;
  piVar8 = in_stack_00000004 + 0x1ac2;
  in_stack_00000004[0x1ac3] = 0;
  (*pcVar2)(piVar8,in_stack_00000004 + 0x1ac3);
  in_stack_00000004[0x1ac4] = -0x40800000 /* -1.0f */; /* timer_12.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x1ac2] + 4))(piVar8,in_stack_00000004 + 0x1ac4); /* timer_12.NetworkStateChanged() */
  piVar3 = in_stack_00000004 + 0x1ac5;
  in_stack_00000004[0x1ac5] = iVar1; /* CountdownTimer timer_13 */
  in_stack_00000004[0x1ac6] = 0;
  (*pcVar2)(piVar3,in_stack_00000004 + 0x1ac6);
  in_stack_00000004[0x1ac7] = -0x40800000 /* -1.0f */; /* timer_13.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x1ac5] + 4))(piVar3,in_stack_00000004 + 0x1ac7); /* timer_13.NetworkStateChanged() */
  piVar4 = in_stack_00000004 + 0x1ac8;
  in_stack_00000004[0x1ac8] = iVar1; /* CountdownTimer timer_14 */
  in_stack_00000004[0x1ac9] = 0;
  (*pcVar2)(piVar4,in_stack_00000004 + 0x1ac9);
  in_stack_00000004[0x1aca] = -0x40800000 /* -1.0f */; /* timer_14.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x1ac8] + 4))(piVar4,in_stack_00000004 + 0x1aca); /* timer_14.NetworkStateChanged() */
  in_stack_00000004[0x1acb] = -1;
  if (in_stack_00000004[0x1ac4] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1ac2] + 4))(piVar8,in_stack_00000004 + 0x1ac4); /* timer_12.NetworkStateChanged() */
    in_stack_00000004[0x1ac4] = -0x40800000 /* -1.0f */; /* timer_12.m_timestamp = -1 (not running) */
  }
  if (in_stack_00000004[0x1ac7] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1ac5] + 4))(piVar3,in_stack_00000004 + 0x1ac7); /* timer_13.NetworkStateChanged() */
    in_stack_00000004[0x1ac7] = -0x40800000 /* -1.0f */; /* timer_13.m_timestamp = -1 (not running) */
  }
  if (in_stack_00000004[0x1aca] != -0x40800000 /* -1.0f */) {
    (**(code **)(in_stack_00000004[0x1ac8] + 4))(piVar4,in_stack_00000004 + 0x1aca); /* timer_14.NetworkStateChanged() */
    in_stack_00000004[0x1aca] = -0x40800000 /* -1.0f */; /* timer_14.m_timestamp = -1 (not running) */
  }
  in_stack_00000004[0x1acb] = -1;
  in_stack_00000004[0x1acc] = 1;
  PathFollower::PathFollower((PathFollower *)(in_stack_00000004 + 0x1acd));
  piVar8 = in_stack_00000004 + 0x2cc3;
  in_stack_00000004[0x2cc3] = iVar1; /* CountdownTimer timer_15 */
  in_stack_00000004[0x2cc4] = 0;
  (*pcVar2)(piVar8,in_stack_00000004 + 0x2cc4);
  in_stack_00000004[0x2cc5] = -0x40800000 /* -1.0f */; /* timer_15.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cc3] + 4))(piVar8,in_stack_00000004 + 0x2cc5); /* timer_15.NetworkStateChanged() */
  piVar3 = in_stack_00000004 + 0x2cc6;
  in_stack_00000004[0x2cc6] = iVar1; /* CountdownTimer timer_16 */
  in_stack_00000004[0x2cc7] = 0;
  (*pcVar2)(piVar3,in_stack_00000004 + 0x2cc7);
  in_stack_00000004[0x2cc8] = -0x40800000 /* -1.0f */; /* timer_16.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cc6] + 4))(piVar3,in_stack_00000004 + 0x2cc8); /* timer_16.NetworkStateChanged() */
  in_stack_00000004[0x2cd6] = iVar1; /* CountdownTimer timer_17 */
  in_stack_00000004[0x2cd7] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cd6,in_stack_00000004 + 0x2cd7);
  in_stack_00000004[0x2cd8] = -0x40800000 /* -1.0f */; /* timer_17.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cd6] + 4)) /* timer_17.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cd6,in_stack_00000004 + 0x2cd8);
  in_stack_00000004[0x2cd9] = iVar1; /* CountdownTimer timer_18 */
  in_stack_00000004[0x2cda] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cd9,in_stack_00000004 + 0x2cda);
  in_stack_00000004[0x2cdb] = -0x40800000 /* -1.0f */; /* timer_18.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cd9] + 4)) /* timer_18.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cd9,in_stack_00000004 + 0x2cdb);
  in_stack_00000004[0x2cdc] = iVar1; /* CountdownTimer timer_19 */
  in_stack_00000004[0x2cdd] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cdc,in_stack_00000004 + 0x2cdd);
  in_stack_00000004[0x2cde] = -0x40800000 /* -1.0f */; /* timer_19.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cdc] + 4)) /* timer_19.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cdc,in_stack_00000004 + 0x2cde);
  in_stack_00000004[0x2cdf] = iVar1; /* CountdownTimer timer_20 */
  in_stack_00000004[0x2ce0] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cdf,in_stack_00000004 + 0x2ce0);
  in_stack_00000004[0x2ce1] = -0x40800000 /* -1.0f */; /* timer_20.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cdf] + 4)) /* timer_20.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cdf,in_stack_00000004 + 0x2ce1);
  in_stack_00000004[0x2ce2] = iVar1; /* CountdownTimer timer_21 */
  in_stack_00000004[0x2ce3] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2ce2,in_stack_00000004 + 0x2ce3);
  in_stack_00000004[0x2ce4] = -0x40800000 /* -1.0f */; /* timer_21.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2ce2] + 4)) /* timer_21.NetworkStateChanged() */
            (in_stack_00000004 + 0x2ce2,in_stack_00000004 + 0x2ce4);
  in_stack_00000004[0x2ce5] = iVar1; /* CountdownTimer timer_22 */
  in_stack_00000004[0x2ce6] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2ce5,in_stack_00000004 + 0x2ce6);
  in_stack_00000004[0x2ce7] = -0x40800000 /* -1.0f */; /* timer_22.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2ce5] + 4)) /* timer_22.NetworkStateChanged() */
            (in_stack_00000004 + 0x2ce5,in_stack_00000004 + 0x2ce7);
  in_stack_00000004[0x2ce8] = iVar1; /* CountdownTimer timer_23 */
  in_stack_00000004[0x2ce9] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2ce8,in_stack_00000004 + 0x2ce9);
  in_stack_00000004[0x2cea] = -0x40800000 /* -1.0f */; /* timer_23.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2ce8] + 4)) /* timer_23.NetworkStateChanged() */
            (in_stack_00000004 + 0x2ce8,in_stack_00000004 + 0x2cea);
  in_stack_00000004[0x2ceb] = iVar1; /* CountdownTimer timer_24 */
  in_stack_00000004[0x2cec] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2ceb,in_stack_00000004 + 0x2cec);
  in_stack_00000004[0x2ced] = -0x40800000 /* -1.0f */; /* timer_24.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2ceb] + 4)) /* timer_24.NetworkStateChanged() */
            (in_stack_00000004 + 0x2ceb,in_stack_00000004 + 0x2ced);
  in_stack_00000004[0x2cee] = iVar1; /* CountdownTimer timer_25 */
  in_stack_00000004[0x2cef] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cee,in_stack_00000004 + 0x2cef);
  in_stack_00000004[0x2cf0] = -0x40800000 /* -1.0f */; /* timer_25.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cee] + 4)) /* timer_25.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cee,in_stack_00000004 + 0x2cf0);
  iVar6 = *(int *)(unaff_EBX + 0x45e045 /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */ /* &vtable for IntervalTimer */);
  in_stack_00000004[0x2cf2] = -0x40800000 /* -1.0f */;
  in_stack_00000004[0x2cf1] = iVar6 + 8;
  (*pcVar7)(in_stack_00000004 + 0x2cf1,in_stack_00000004 + 0x2cf2);
  in_stack_00000004[0x2cf3] = iVar1; /* CountdownTimer timer_26 */
  in_stack_00000004[0x2cf4] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cf3,in_stack_00000004 + 0x2cf4);
  in_stack_00000004[0x2cf5] = -0x40800000 /* -1.0f */; /* timer_26.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cf3] + 4)) /* timer_26.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cf3,in_stack_00000004 + 0x2cf5);
  in_stack_00000004[0x2cf6] = iVar1; /* CountdownTimer timer_27 */
  in_stack_00000004[0x2cf7] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cf6,in_stack_00000004 + 0x2cf7);
  in_stack_00000004[0x2cf8] = -0x40800000 /* -1.0f */; /* timer_27.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cf6] + 4)) /* timer_27.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cf6,in_stack_00000004 + 0x2cf8);
  in_stack_00000004[0x2cf9] = iVar1; /* CountdownTimer timer_28 */
  in_stack_00000004[0x2cfa] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cf9,in_stack_00000004 + 0x2cfa);
  in_stack_00000004[0x2cfb] = -0x40800000 /* -1.0f */; /* timer_28.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cf9] + 4)) /* timer_28.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cf9,in_stack_00000004 + 0x2cfb);
  in_stack_00000004[0x2cfc] = iVar1; /* CountdownTimer timer_29 */
  in_stack_00000004[0x2cfd] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cfc,in_stack_00000004 + 0x2cfd);
  in_stack_00000004[0x2cfe] = -0x40800000 /* -1.0f */; /* timer_29.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cfc] + 4)) /* timer_29.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cfc,in_stack_00000004 + 0x2cfe);
  in_stack_00000004[0x2cff] = iVar1; /* CountdownTimer timer_30 */
  in_stack_00000004[0x2d00] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2cff,in_stack_00000004 + 0x2d00);
  in_stack_00000004[0x2d01] = -0x40800000 /* -1.0f */; /* timer_30.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2cff] + 4)) /* timer_30.NetworkStateChanged() */
            (in_stack_00000004 + 0x2cff,in_stack_00000004 + 0x2d01);
  in_stack_00000004[0x2d02] = iVar1; /* CountdownTimer timer_31 */
  in_stack_00000004[0x2d03] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d02,in_stack_00000004 + 0x2d03);
  in_stack_00000004[0x2d04] = -0x40800000 /* -1.0f */; /* timer_31.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d02] + 4)) /* timer_31.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d02,in_stack_00000004 + 0x2d04);
  in_stack_00000004[0x2d05] = iVar1; /* CountdownTimer timer_32 */
  in_stack_00000004[0x2d06] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d05,in_stack_00000004 + 0x2d06);
  in_stack_00000004[0x2d07] = -0x40800000 /* -1.0f */; /* timer_32.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d05] + 4)) /* timer_32.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d05,in_stack_00000004 + 0x2d07);
  in_stack_00000004[0x2d08] = iVar1; /* CountdownTimer timer_33 */
  in_stack_00000004[0x2d09] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d08,in_stack_00000004 + 0x2d09);
  in_stack_00000004[0x2d0a] = -0x40800000 /* -1.0f */; /* timer_33.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d08] + 4)) /* timer_33.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d08,in_stack_00000004 + 0x2d0a);
  in_stack_00000004[0x2d0b] = iVar1; /* CountdownTimer timer_34 */
  in_stack_00000004[0x2d0c] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d0b,in_stack_00000004 + 0x2d0c);
  in_stack_00000004[0x2d0d] = -0x40800000 /* -1.0f */; /* timer_34.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d0b] + 4)) /* timer_34.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d0b,in_stack_00000004 + 0x2d0d);
  in_stack_00000004[0x2d0e] = iVar1; /* CountdownTimer timer_35 */
  in_stack_00000004[0x2d0f] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d0e,in_stack_00000004 + 0x2d0f);
  in_stack_00000004[0x2d10] = -0x40800000 /* -1.0f */; /* timer_35.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d0e] + 4)) /* timer_35.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d0e,in_stack_00000004 + 0x2d10);
  in_stack_00000004[0x2d14] = iVar1; /* CountdownTimer timer_36 */
  in_stack_00000004[0x2d15] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d14,in_stack_00000004 + 0x2d15);
  in_stack_00000004[0x2d16] = -0x40800000 /* -1.0f */; /* timer_36.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d14] + 4)) /* timer_36.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d14,in_stack_00000004 + 0x2d16);
  in_stack_00000004[0x2d21] = iVar1; /* CountdownTimer timer_37 */
  in_stack_00000004[0x2d17] = 0;
  in_stack_00000004[0x2d18] = 0;
  in_stack_00000004[0x2d19] = 0;
  in_stack_00000004[0x2d1a] = 0;
  in_stack_00000004[0x2d1b] = 0;
  in_stack_00000004[0x2d1c] = 0;
  in_stack_00000004[0x2d1d] = 0;
  in_stack_00000004[0x2d1e] = 0;
  in_stack_00000004[0x2d1f] = 0;
  in_stack_00000004[0x2d20] = 0;
  in_stack_00000004[0x2d22] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d21,in_stack_00000004 + 0x2d22);
  in_stack_00000004[0x2d23] = -0x40800000 /* -1.0f */; /* timer_37.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d21] + 4)) /* timer_37.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d21,in_stack_00000004 + 0x2d23);
  in_stack_00000004[0x2d28] = iVar1; /* CountdownTimer timer_38 */
  in_stack_00000004[0x2d29] = 0;
  (*pcVar2)(in_stack_00000004 + 0x2d28,in_stack_00000004 + 0x2d29);
  in_stack_00000004[0x2d2a] = -0x40800000 /* -1.0f */; /* timer_38.m_timestamp = -1 (not running) */
  (**(code **)(in_stack_00000004[0x2d28] + 4)) /* timer_38.NetworkStateChanged() */
            (in_stack_00000004 + 0x2d28,in_stack_00000004 + 0x2d2a);
  pIVar10 = (INextBot *)::operator_new(0x178);
  CINSBotBody::CINSBotBody(this_02,pIVar10);
  in_stack_00000004[0x2cd3] = (int)pIVar10;
  pIVar10 = (INextBot *)::operator_new(0x498c);
  CINSBotLocomotion::CINSBotLocomotion(this_03,pIVar10);
  in_stack_00000004[0x2cd2] = (int)pIVar10;
  pIVar10 = (INextBot *)::operator_new(0x280);
  CINSBotVision::CINSBotVision((CINSBotVision *)(in_stack_00000004 + 0x818),pIVar10);
  in_stack_00000004[0x2cd4] = (int)pIVar10;
  pCVar11 = (CINSNextBot *)::operator_new(0xc);
  CINSBotChatter::CINSBotChatter(this_04,pCVar11);
  in_stack_00000004[0x2cd5] = (int)pCVar11;
  pCVar11 = (CINSNextBot *)::operator_new(0x1c);
  CINSNextBotIntention::CINSNextBotIntention(this_05,pCVar11);
  in_stack_00000004[0x86e] = (int)pCVar11;
  in_stack_00000004[0x8a2] = 1;
  *(undefined1 *)((int)in_stack_00000004 + 0x228f) = 1;
  *(undefined1 *)(in_stack_00000004 + 0x8a4) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x2291) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x2292) = 0;
  *(undefined1 *)((int)in_stack_00000004 + 0x2293) = 0;
  fVar12 = (float10)CountdownTimer::Now();
  fVar5 = (float)in_stack_00000004[0x2cc4];
  if ((float)in_stack_00000004[0x2cc5] != (float)fVar12 + fVar5) {
    (**(code **)(in_stack_00000004[0x2cc3] + 4))(piVar8,in_stack_00000004 + 0x2cc5); /* timer_15.NetworkStateChanged() */
    in_stack_00000004[0x2cc5] = (int)((float)fVar12 + fVar5); /* timer_15.Start(...) */
  }
  fVar12 = (float10)CountdownTimer::Now();
  fVar5 = (float)in_stack_00000004[0x2cc7];
  if ((float)in_stack_00000004[0x2cc8] != (float)fVar12 + fVar5) {
    (**(code **)(in_stack_00000004[0x2cc6] + 4))(piVar3,in_stack_00000004 + 0x2cc8); /* timer_16.NetworkStateChanged() */
    in_stack_00000004[0x2cc8] = (int)((float)fVar12 + fVar5); /* timer_16.Start(...) */
  }
  piVar8 = *(int **)(unaff_EBX + 0x45d9c1 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  in_stack_00000004[0x2cc9] = 0;
  in_stack_00000004[0x8a5] = 0;
  in_stack_00000004[0x2ccb] = -1;
  in_stack_00000004[0x2cce] = -1;
  iVar1 = *piVar8;
  in_stack_00000004[0x2ccf] = 0;
  iVar6 = piVar8[1];
  in_stack_00000004[0x2cd0] = 0;
  iVar9 = piVar8[2];
  in_stack_00000004[0x2ccc] = 1;
  in_stack_00000004[0x2d11] = 0;
  in_stack_00000004[0x2d12] = 0;
  in_stack_00000004[0x2cca] = -1;
  in_stack_00000004[0x2cd1] = 0x41200000 /* 10.0f */;
  in_stack_00000004[0x869] = 0;
  in_stack_00000004[0x866] = iVar1;
  in_stack_00000004[0x867] = iVar6;
  in_stack_00000004[0x868] = iVar9;
  in_stack_00000004[0x86d] = 0;
  in_stack_00000004[0x86a] = iVar1;
  in_stack_00000004[0x86b] = iVar6;
  in_stack_00000004[0x86c] = iVar9;
  in_stack_00000004[0x8a0] = 0;
  in_stack_00000004[0x8a1] = 0;
  *(undefined1 *)(in_stack_00000004 + 0x2d27) = 0;
  return;
}



/* ----------------------------------------
 * CINSNextBot::Update
 * Address: 0074b430
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::Update() */

void __thiscall CINSNextBot::Update(CINSNextBot *this)

{
  Update(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::Update
 * Address: 0074b440
 * ---------------------------------------- */

/* CINSNextBot::Update() */

void __thiscall CINSNextBot::Update(CINSNextBot *this)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  CINSNextBot *pCVar7;
  CINSRules *this_00;
  CINSRules *this_01;
  INextBot *this_02;
  CINSNextBot *extraout_ECX;
  CBaseEntity *this_03;
  CBaseEntity *this_04;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *this_05;
  CINSBotChatter *this_06;
  CINSNextBot *this_07;
  int unaff_EBX;
  bool bVar8;
  float10 fVar9;
  float fVar10;
  int *in_stack_00000004;
  int *piVar11;
  int *piVar12;
  int local_30;
  
  __i686_get_pc_thunk_bx();
  piVar12 = (int *)0x4;
  piVar11 = *(int **)(unaff_EBX + 0x45b4ad /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
  cVar2 = CINSRules::IsGameState(this_00,*piVar11);
  if (cVar2 == '\0') {
    piVar12 = (int *)0x3;
    cVar2 = CINSRules::IsGameState(this_01,*piVar11);
    if (cVar2 == '\0') {
      return;
    }
    iVar3 = 0;
    if (in_stack_00000004[8] != 0) {
      iVar3 = in_stack_00000004[8] - *(int *)(**(int **)(unaff_EBX + 0x45b455 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4;
    }
    piVar4 = (int *)UTIL_PlayerByIndex(iVar3);
    if (((piVar4 != (int *)0x0) &&
        (cVar2 = (**(code **)(*piVar4 + 0x158))(piVar4,piVar12), cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*(int *)*piVar11 + 0x3a8))((int *)*piVar11,piVar4), piVar12 = piVar4,
       cVar2 == '\0')) {
      return;
    }
  }
  cVar2 = (**(code **)(*in_stack_00000004 + 0x118 /* CBaseEntity::IsAlive */))(in_stack_00000004,piVar12);
  if (((cVar2 != '\0') ||
      (cVar2 = (**(code **)(*in_stack_00000004 + 0x8bc /* CINSNextBot::IsDormantWhenDead */))(in_stack_00000004), cVar2 == '\0')) &&
     (iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x45ba0d /* &NextBotPlayerStop */ /* &NextBotPlayerStop */ /* &NextBotPlayerStop */) + 0x40))
                        (*(int **)(unaff_EBX + 0x45ba0d /* &NextBotPlayerStop */ /* &NextBotPlayerStop */ /* &NextBotPlayerStop */)), iVar3 == 0)) {
    INextBot::Update(this_02);
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2cf8] ||
      (float)fVar9 == (float)in_stack_00000004[0x2cf8]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x8000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2cfb] ||
      (float)fVar9 == (float)in_stack_00000004[0x2cfb]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x10000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2cfe] ||
      (float)fVar9 == (float)in_stack_00000004[0x2cfe]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 8;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2d01] ||
      (float)fVar9 == (float)in_stack_00000004[0x2d01]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x2000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2d04] ||
      (float)fVar9 == (float)in_stack_00000004[0x2d04]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x4000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2d07] ||
      (float)fVar9 == (float)in_stack_00000004[0x2d07]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x1000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2d0a] ||
      (float)fVar9 == (float)in_stack_00000004[0x2d0a]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x40000;
  }
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)fVar9 < (float)in_stack_00000004[0x2d0d] ||
      (float)fVar9 == (float)in_stack_00000004[0x2d0d]) {
    in_stack_00000004[0x832] = in_stack_00000004[0x832] | 0x20000;
  }
  piVar11 = in_stack_00000004 + 0x2d0e;
  piVar12 = piVar11;
  fVar9 = (float10)CountdownTimer::Now();
  this_05 = extraout_ECX;
  if ((float)in_stack_00000004[0x2d10] <= (float)fVar9 &&
      (float)fVar9 != (float)in_stack_00000004[0x2d10]) {
    bVar8 = *(int *)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
    if ((bVar8) &&
       (iVar3 = *(int *)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
       iVar5 = ThreadGetCurrentId(piVar12), iVar3 == iVar5)) {
      piVar12 = *(int **)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar12 != unaff_EBX + 0x2379fa /* "CINSNextBot::Nearby Players" */ /* "CINSNextBot::Nearby Players" */ /* "CINSNextBot::Nearby Players" */) {
        piVar12 = (int *)CVProfNode::GetSubNode
                                   ((char *)piVar12,unaff_EBX + 0x2379fa /* "CINSNextBot::Nearby Players" */ /* "CINSNextBot::Nearby Players" */ /* "CINSNextBot::Nearby Players" */,(char *)0x0,
                                    unaff_EBX + 0x23581b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
        *(int **)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar12;
      }
      puVar1 = (uint *)(piVar12[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
    }
    iVar3 = in_stack_00000004[0x2d11];
    local_30 = 1;
    in_stack_00000004[0x2d11] = 0;
    in_stack_00000004[0x2d12] = 0;
LAB_0074b6e6:
    do {
      piVar12 = (int *)UTIL_PlayerByIndex(local_30);
      if (((piVar12 != (int *)0x0) &&
          (cVar2 = (**(code **)(*piVar12 + 0x158))(piVar12), cVar2 != '\0')) &&
         (piVar12 != in_stack_00000004)) {
        piVar4 = (int *)(**(code **)(*in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000004);
        piVar12 = (int *)(**(code **)(*piVar4 + 0xe4 /* IVision::GetKnown */))(piVar4,piVar12);
        if ((piVar12 != (int *)0x0) &&
           (cVar2 = (**(code **)(*piVar12 + 0x4c))(piVar12), cVar2 != '\0')) {
          fVar9 = (float10)(**(code **)(*piVar12 + 0x48))(piVar12);
          iVar5 = CBaseEntity::GetTeamNumber(this_03);
          iVar6 = CBaseEntity::GetTeamNumber(this_04);
          if (iVar5 == iVar6) {
            if ((float)fVar9 < *(float *)(unaff_EBX + 0x1d8d65 /* 10.0f */ /* 10.0f */ /* 10.0f */)) {
              in_stack_00000004[0x2d12] = in_stack_00000004[0x2d12] + 1;
            }
          }
          else if ((float)fVar9 <= *(float *)(unaff_EBX + 0x1d9321 /* 5.0f */ /* 5.0f */ /* 5.0f */)) {
            local_30 = local_30 + 1;
            in_stack_00000004[0x2d11] = in_stack_00000004[0x2d11] + 1;
            if (local_30 == 0x31) break;
            goto LAB_0074b6e6;
          }
        }
      }
      local_30 = local_30 + 1;
    } while (local_30 != 0x31);
    if ((iVar3 == 0) && (0 < in_stack_00000004[0x2d11])) {
      in_stack_00000004[0x2d13] = *(int *)(**(int **)(unaff_EBX + 0x45b455 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
    }
    piVar12 = piVar11;
    fVar9 = (float10)CountdownTimer::Now();
    fVar10 = (float)fVar9 + *(float *)(unaff_EBX + 0x1d9d19 /* 1.5f */ /* 1.5f */ /* 1.5f */);
    this_05 = extraout_ECX_00;
    if ((float)in_stack_00000004[0x2d10] != fVar10) {
      piVar12 = piVar11;
      (**(code **)(in_stack_00000004[0x2d0e] + 4))(piVar11,in_stack_00000004 + 0x2d10); /* timer_35.NetworkStateChanged() */
      in_stack_00000004[0x2d10] = (int)fVar10; /* timer_35.Start(1.5f) */
      this_05 = extraout_ECX_01;
    }
    if (in_stack_00000004[0x2d0f] != 0x3fc00000 /* 1.5f */) {
      (**(code **)(in_stack_00000004[0x2d0e] + 4))(piVar11,in_stack_00000004 + 0x2d0f); /* timer_35.NetworkStateChanged() */
      in_stack_00000004[0x2d0f] = 0x3fc00000 /* 1.5f */;
      this_05 = extraout_ECX_02;
      piVar12 = piVar11;
    }
    if ((bVar8) &&
       (((this_05 = *(CINSNextBot **)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */), this_05[0x1010] == (CINSNextBot)0x0 ||
         (*(int *)(this_05 + 0x100c) != 0)) &&
        (iVar3 = *(int *)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
        iVar5 = ThreadGetCurrentId(piVar12), this_05 = extraout_ECX_03, iVar3 == iVar5)))) {
      cVar2 = CVProfNode::ExitScope();
      pCVar7 = *(CINSNextBot **)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (cVar2 != '\0') {
        pCVar7 = *(CINSNextBot **)(pCVar7 + 100);
        *(CINSNextBot **)(*(int *)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = pCVar7;
      }
      this_05 = *(CINSNextBot **)(unaff_EBX + 0x45b529 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
      this_05[0x1010] = (CINSNextBot)(pCVar7 == this_05 + 0x1018);
    }
  }
  UpdateIdleStatus(this_05);
  (**(code **)(*in_stack_00000004 + 0x978 /* CINSNextBot::GetChatter */))(in_stack_00000004);
  CINSBotChatter::Update(this_06);
  UpdateCover(this_07);
  fVar9 = (float10)RandomFloat(0x41200000 /* 10.0f */,0x42b40000 /* 90.0f */);
  fVar10 = (float)fVar9;
  fVar9 = (float10)CountdownTimer::Now();
  if ((float)in_stack_00000004[0x2d2a] != (float)fVar9 + fVar10) {
    (**(code **)(in_stack_00000004[0x2d28] + 4)) /* timer_38.NetworkStateChanged() */
              (in_stack_00000004 + 0x2d28,in_stack_00000004 + 0x2d2a);
    in_stack_00000004[0x2d2a] = (int)((float)fVar9 + fVar10); /* timer_38.Start(...) */
  }
  if ((float)in_stack_00000004[0x2d29] != fVar10) {
    (**(code **)(in_stack_00000004[0x2d28] + 4)) /* timer_38.NetworkStateChanged() */
              (in_stack_00000004 + 0x2d28,in_stack_00000004 + 0x2d29);
    in_stack_00000004[0x2d29] = (int)fVar10; /* timer_38.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::OnWeaponFired
 * Address: 00744290
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::OnWeaponFired(CBaseCombatCharacter*, CBaseCombatWeapon*) */

void __thiscall
CINSNextBot::OnWeaponFired
          (CINSNextBot *this,CBaseCombatCharacter *param_1,CBaseCombatWeapon *param_2)

{
  OnWeaponFired(this,param_1 + -0x2060,param_2);
  return;
}



/* ----------------------------------------
 * CINSNextBot::OnWeaponFired
 * Address: 007442a0
 * ---------------------------------------- */

/* CINSNextBot::OnWeaponFired(CBaseCombatCharacter*, CBaseCombatWeapon*) */

void __thiscall
CINSNextBot::OnWeaponFired
          (CINSNextBot *this,CBaseCombatCharacter *param_1,CBaseCombatWeapon *param_2)

{
  uint *puVar1;
  CBaseCombatCharacter *pCVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int unaff_EBX;
  bool bVar7;
  undefined4 in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  bVar7 = *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x100c) != 0;
  if (bVar7) {
    iVar6 = *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      piVar5 = *(int **)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1014);
      if ((code *)*piVar5 != CINSRules::ShouldCollide + unaff_EBX) {
        piVar5 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar5,(int)(CINSRules::ShouldCollide + unaff_EBX),
                                   (char *)0x0,unaff_EBX + 0x23c9bb /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
        *(int **)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1014) = piVar5;
      }
      puVar1 = (uint *)(piVar5[0x1c] * 8 + *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x10a0) +
                       4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1010) = 0;
    }
  }
  pCVar2 = param_1 + 0x2060;
  for (piVar5 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 8))(pCVar2); piVar5 != (int *)0x0;
      piVar5 = (int *)(**(code **)(*(int *)pCVar2 + 0xc))(pCVar2,piVar5)) {
    (**(code **)(*piVar5 + 0x5c))(piVar5,param_2,in_stack_0000000c);
  }
  if ((bVar7) &&
     ((*(char *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x100c) != 0)))) {
    iVar6 = *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    if (iVar6 == iVar4) {
      cVar3 = CVProfNode::ExitScope();
      if (cVar3 == '\0') {
        iVar6 = *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1014);
      }
      else {
        iVar6 = *(int *)(*(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1014) + 100);
        *(int *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1014) = iVar6;
      }
      *(bool *)(*(int *)(&DAT_004626c9 + unaff_EBX) + 0x1010) =
           iVar6 == *(int *)(&DAT_004626c9 + unaff_EBX) + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::AddInvestigation
 * Address: 0074ba60
 * ---------------------------------------- */

/* CINSNextBot::AddInvestigation(CNavArea*, InvestigatePriority) */

void __thiscall
CINSNextBot::AddInvestigation(undefined4 param_1_00,int param_1,int param_3,undefined4 param_4)

{
  int iVar1;
  CINSNextBot *this;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *extraout_ECX;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *extraout_ECX_00;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *extraout_ECX_01;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *this_00;
  CINSNextBot *extraout_ECX_02;
  int iVar2;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int local_4c;
  int local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  int local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x74ba6b;
  __i686_get_pc_thunk_bx();
  if (param_3 == 0) {
    Warning(unaff_EBX + 0x2378e1 /* "Unable to add NextBot investigation target, navmesh probably out of date...
" */ /* "Unable to add NextBot investigation target, navmesh probably out of date...
" */ /* "Unable to add NextBot investigation target, navmesh probably out of date...
" */);
    return;
  }
  CNavArea::GetRandomPoint();
  if (0 < (int)*(CINSNextBot **)(param_1 + 0xb468)) {
    this = (CINSNextBot *)0x0;
    iVar2 = 0;
    do {
      iVar1 = *(int *)(param_1 + 0xb45c) + iVar2;
      if ((param_3 == *(int *)(iVar1 + 0x18)) ||
         (fVar6 = *(float *)(iVar1 + 0xc) - local_28, fVar4 = *(float *)(iVar1 + 0x10) - local_24,
         fVar5 = *(float *)(iVar1 + 0x14) - local_20,
         fVar4 * fVar4 + fVar6 * fVar6 + fVar5 * fVar5 < *(float *)(unaff_EBX + 0x1dd745 /* 14400.0f */ /* 14400.0f */ /* 14400.0f */)))
      goto LAB_0074bc2a;
      this = this + 1;
      iVar2 = iVar2 + 0x24;
    } while (this != *(CINSNextBot **)(param_1 + 0xb468));
  }
  local_4c = unaff_EBX + 0x3dc74d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  local_48 = 0;
  CountdownTimer::NetworkStateChanged(&local_4c);
  local_44 = -1.0;
  (**(code **)(local_4c + 4))(&local_4c,&local_44);
  local_34 = param_3;
  local_40 = local_28;
  local_2c = param_4;
  local_3c = local_24;
  local_38 = local_20;
  fVar3 = (float10)CountdownTimer::Now();
  fVar4 = (float)fVar3 + *(float *)(unaff_EBX + 0x1d8745 /* 10.0f */ /* 10.0f */ /* 10.0f */);
  this_00 = extraout_ECX;
  if (local_44 != fVar4) {
    (**(code **)(local_4c + 4))(&local_4c,&local_44);
    this_00 = extraout_ECX_00;
    local_44 = fVar4;
  }
  if (local_48 != 0x41200000 /* 10.0f */) {
    (**(code **)(local_4c + 4))(&local_4c,&local_48);
    local_48 = 0x41200000 /* 10.0f */;
    this_00 = extraout_ECX_01;
  }
  local_30 = 0;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::InsertBefore
            (this_00,param_1 + 0xb45c,*(InvestigationData_t **)(param_1 + 0xb468));
  this = extraout_ECX_02;
LAB_0074bc2a:
  SortAndRemoveInvestigations(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::AddInvestigation
 * Address: 0074bc60
 * ---------------------------------------- */

/* CINSNextBot::AddInvestigation(Vector, InvestigatePriority) */

void __cdecl CINSNextBot::AddInvestigation(undefined4 param_1)

{
  int iVar1;
  CNavMesh *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  int unaff_EBX;
  undefined4 in_stack_00000014;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CNavMesh::GetNearestNavArea
                    (extraout_ECX,**(undefined4 **)(unaff_EBX + 0x45aa4f /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */),&stack0x00000008,0,
                     0x461c4000 /* 10000.0f */,0,1,0);
  if (iVar1 != 0) {
    AddInvestigation(extraout_ECX_00,param_1,iVar1,in_stack_00000014);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::AddInvestigation
 * Address: 0074bce0
 * ---------------------------------------- */

/* CINSNextBot::AddInvestigation(CBaseEntity*, InvestigatePriority) */

void __thiscall
CINSNextBot::AddInvestigation
          (undefined4 param_1_00,undefined4 param_1,int param_3,undefined4 param_4)

{
  CBaseEntity *this;
  
  __i686_get_pc_thunk_bx();
  if (param_3 != 0) {
    if ((*(byte *)(param_3 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    AddInvestigation(param_1,*(undefined4 *)(param_3 + 0x208),*(undefined4 *)(param_3 + 0x20c),
                     *(undefined4 *)(param_3 + 0x210),param_4);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::AddOrder
 * Address: 0074bd60
 * ---------------------------------------- */

/* CINSNextBot::AddOrder(eRadialCommands, int, Vector, OrderPriority, int, float) */

void __cdecl
CINSNextBot::AddOrder
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6,undefined4 param_7,undefined4 param_8,float param_9)

{
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *extraout_ECX;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *extraout_ECX_00;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *extraout_ECX_01;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *this;
  CINSNextBot *this_00;
  int unaff_EBX;
  float10 fVar1;
  int local_4c;
  float local_48;
  float local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x74bd6e;
  __i686_get_pc_thunk_bx();
  local_48 = 0.0;
  local_4c = unaff_EBX + 0x3dc44a /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
  CountdownTimer::NetworkStateChanged(&local_4c);
  local_44 = -1.0;
  (**(code **)(local_4c + 4))(&local_4c,&local_44);
  local_24 = *(undefined4 *)(**(int **)(unaff_EBX + 0x45ab32 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  local_40 = param_2;
  local_3c = param_3;
  local_38 = param_4;
  local_34 = param_5;
  local_30 = param_6;
  local_28 = param_7;
  local_2c = param_8;
  fVar1 = (float10)CountdownTimer::Now();
  this = extraout_ECX;
  if (local_44 != (float)fVar1 + param_9) {
    (**(code **)(local_4c + 4))(&local_4c,&local_44);
    this = extraout_ECX_00;
    local_44 = (float)fVar1 + param_9;
  }
  if (local_48 != param_9) {
    (**(code **)(local_4c + 4))(&local_4c,&local_48);
    local_48 = param_9;
    this = extraout_ECX_01;
  }
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>>::InsertBefore
            (this,param_1 + 0xb470,*(OrderData_t **)(param_1 + 0xb47c));
  SortAndRemoveOrders(this_00);
  return;
}



/* ----------------------------------------
 * CINSNextBot::AdjustCombatState
 * Address: 0076f3b0
 * ---------------------------------------- */

/* CINSNextBot::AdjustCombatState() */

void __thiscall CINSNextBot::AdjustCombatState(CINSNextBot *this)

{
  int *piVar1;
  CINSNextBot *this_00;
  CKnownEntity *in_stack_00000004;
  
  piVar1 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
  (**(code **)(*piVar1 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar1,0);
  ChooseBestWeapon(this_00,in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSNextBot::AllocatePlayerEntity
 * Address: 00743320
 * ---------------------------------------- */

/* CINSNextBot::AllocatePlayerEntity(edict_t*, char const*) */

void __cdecl CINSNextBot::AllocatePlayerEntity(edict_t *param_1,char *param_2)

{
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  **(undefined4 **)(&LAB_0046367f + unaff_EBX) = param_1;
  CreateEntityByName((char *)(unaff_EBX + 0x23f9f2 /* "ins_player_nbot" */ /* "ins_player_nbot" */ /* "ins_player_nbot" */),-1,true);
  return;
}



/* ----------------------------------------
 * CINSNextBot::ApplyAimPenalty
 * Address: 0075b9d0
 * ---------------------------------------- */

/* CINSNextBot::ApplyAimPenalty(CKnownEntity const*, Vector&) */

void __thiscall
CINSNextBot::ApplyAimPenalty(CINSNextBot *this,CKnownEntity *param_1,Vector *param_2)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  float *pfVar5;
  int iVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *extraout_ECX_04;
  CINSNextBot *extraout_ECX_05;
  CBaseEntity *this_00;
  CINSRules *this_01;
  CINSNextBot *extraout_ECX_06;
  CINSNextBot *pCVar10;
  CINSNextBot *this_02;
  CFmtStrN<256,false> *this_03;
  int unaff_EBX;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float *in_stack_0000000c;
  float local_1a8;
  float local_1a4;
  float local_1a0;
  char local_19c [5];
  char local_197 [263];
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_7c;
  float local_78;
  float local_74;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75b9db;
  __i686_get_pc_thunk_bx();
  if (param_2 == (Vector *)0x0) {
    return;
  }
  iVar3 = (**(code **)(*(int *)param_2 + 0x10))(param_2);
  if (iVar3 == 0) {
    return;
  }
  local_64 = *in_stack_0000000c;
  local_60 = in_stack_0000000c[1];
  local_5c = in_stack_0000000c[2];
  (**(code **)(*(int *)param_1 + 0x478 /* CINSPlayer::Weapon_ShootPosition */))((Vector *)&local_58,param_1);
  piVar4 = (int *)(**(code **)(*(int *)param_2 + 0x10))(param_2);
  pfVar5 = (float *)(**(code **)(*piVar4 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(piVar4);
  fVar13 = *pfVar5;
  fVar7 = pfVar5[1];
  fVar9 = pfVar5[2];
  local_48 = in_stack_0000000c[1] - local_54;
  local_44 = in_stack_0000000c[2] - local_50;
  local_4c = *in_stack_0000000c - local_58;
  VectorNormalize((Vector *)&local_4c);
  puVar1 = (uint *)(unaff_EBX + 0x1c9225 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */);
  local_8c = (float)((uint)local_48 ^ *puVar1);
  local_90 = (float)((uint)local_4c ^ *puVar1);
  local_88 = (float)((uint)local_44 ^ *puVar1);
  local_84 = local_8c * fVar7 + local_90 * fVar13 + local_88 * fVar9;
  fVar11 = (float10)IntersectRayWithPlane
                              ((Vector *)&local_58,(Vector *)&local_4c,(cplane_t *)&local_90);
  fVar12 = (float)fVar11;
  if (fVar12 <= 0.0) {
    return;
  }
  local_78 = (local_54 - fVar7) + local_48 * fVar12;
  local_74 = ((local_50 - fVar9) + local_44 * fVar12) * *(float *)(unaff_EBX + 0x1c8d7d /* 0.5f */ /* 0.5f */ /* 0.5f */);
  local_7c = (local_58 - fVar13) + local_4c * fVar12;
  VectorNormalize((Vector *)&local_7c);
  piVar4 = (int *)(*(int **)(unaff_EBX + 0x44ab25 /* &bot_attack_aimpenalty_amt_far */ /* &bot_attack_aimpenalty_amt_far */ /* &bot_attack_aimpenalty_amt_far */))[7];
  if (piVar4 == *(int **)(unaff_EBX + 0x44ab25 /* &bot_attack_aimpenalty_amt_far */ /* &bot_attack_aimpenalty_amt_far */ /* &bot_attack_aimpenalty_amt_far */)) {
    fVar13 = (float)((uint)piVar4 ^ piVar4[0xb]);
    pCVar10 = extraout_ECX;
  }
  else {
    fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
    fVar13 = (float)fVar11;
    pCVar10 = extraout_ECX_00;
  }
  piVar4 = (int *)(*(int **)(&DAT_0044accd + unaff_EBX))[7];
  if (piVar4 == *(int **)(&DAT_0044accd + unaff_EBX)) {
    local_1a0 = (float)((uint)piVar4 ^ piVar4[0xb]);
  }
  else {
    fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
    local_1a0 = (float)fVar11;
    pCVar10 = extraout_ECX_01;
  }
  fVar12 = fVar12 * *(float *)(unaff_EBX + 0x22af2d /* CSWTCH.663+0x3c */ /* CSWTCH.663+0x3c */ /* CSWTCH.663+0x3c */);
  piVar4 = (int *)(*(int **)(unaff_EBX + 0x44acfd /* &bot_attack_aimpenalty_time_far */ /* &bot_attack_aimpenalty_time_far */ /* &bot_attack_aimpenalty_time_far */))[7];
  local_1a0 = local_1a0 + (fVar13 - local_1a0) * fVar12;
  if (piVar4 == *(int **)(unaff_EBX + 0x44acfd /* &bot_attack_aimpenalty_time_far */ /* &bot_attack_aimpenalty_time_far */ /* &bot_attack_aimpenalty_time_far */)) {
    fVar13 = (float)((uint)piVar4 ^ piVar4[0xb]);
  }
  else {
    fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
    fVar13 = (float)fVar11;
    pCVar10 = extraout_ECX_02;
  }
  piVar4 = (int *)(*(int **)(unaff_EBX + 0x44af8d /* &bot_attack_aimpenalty_time_close */ /* &bot_attack_aimpenalty_time_close */ /* &bot_attack_aimpenalty_time_close */))[7];
  if (piVar4 == *(int **)(unaff_EBX + 0x44af8d /* &bot_attack_aimpenalty_time_close */ /* &bot_attack_aimpenalty_time_close */ /* &bot_attack_aimpenalty_time_close */)) {
    local_1a4 = (float)((uint)piVar4 ^ piVar4[0xb]);
  }
  else {
    fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
    local_1a4 = (float)fVar11;
    pCVar10 = extraout_ECX_03;
  }
  local_1a4 = local_1a4 + (fVar13 - local_1a4) * fVar12;
  iVar3 = GetDifficulty(pCVar10);
  if (iVar3 == 3) {
LAB_0075bcf1:
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x44ac15 /* &bot_attack_aimpenalty_amt_frac_impossible */ /* &bot_attack_aimpenalty_amt_frac_impossible */ /* &bot_attack_aimpenalty_amt_frac_impossible */))[7];
    if (piVar4 != *(int **)(unaff_EBX + 0x44ac15 /* &bot_attack_aimpenalty_amt_frac_impossible */ /* &bot_attack_aimpenalty_amt_frac_impossible */ /* &bot_attack_aimpenalty_amt_frac_impossible */)) goto LAB_0075bd08;
LAB_0075c0a8:
    fVar13 = (float)((uint)piVar4 ^ piVar4[0xb]);
LAB_0075bd1e:
    local_1a0 = fVar13 * local_1a0;
  }
  else {
    iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x44b0f1 /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */) + 0x40))(*(int **)(unaff_EBX + 0x44b0f1 /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */));
    pCVar10 = extraout_ECX_04;
    if ((((iVar3 != 0) && (piVar4 = (int *)**(int **)(unaff_EBX + 0x44af1d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */), piVar4 != (int *)0x0))
        && (cVar2 = (**(code **)(*piVar4 + 0x29c /* CBaseEntity::HasPhysicsAttacker */))(piVar4), pCVar10 = extraout_ECX_05, cVar2 != '\0'
           )) && (cVar2 = CINSRules::IsSoloMode(), pCVar10 = (CINSNextBot *)this_00, cVar2 != '\0'))
    {
      iVar3 = CBaseEntity::GetTeamNumber(this_00);
      iVar6 = CINSRules::GetHumanTeam(this_01);
      pCVar10 = extraout_ECX_06;
      if (iVar3 == iVar6) goto LAB_0075bcf1;
    }
    iVar3 = GetDifficulty(pCVar10);
    if (iVar3 == 2) {
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x44ab65 /* &bot_attack_aimpenalty_amt_frac_hard */ /* &bot_attack_aimpenalty_amt_frac_hard */ /* &bot_attack_aimpenalty_amt_frac_hard */))[7];
      if (piVar4 == *(int **)(unaff_EBX + 0x44ab65 /* &bot_attack_aimpenalty_amt_frac_hard */ /* &bot_attack_aimpenalty_amt_frac_hard */ /* &bot_attack_aimpenalty_amt_frac_hard */)) goto LAB_0075c0a8;
LAB_0075bd08:
      fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
      fVar13 = (float)fVar11;
      goto LAB_0075bd1e;
    }
    iVar3 = GetDifficulty(this_02);
    if (iVar3 == 0) {
      piVar4 = (int *)(*(int **)(unaff_EBX + 0x44b635 /* &bot_attack_aimpenalty_amt_frac_easy */ /* &bot_attack_aimpenalty_amt_frac_easy */ /* &bot_attack_aimpenalty_amt_frac_easy */))[7];
      if (piVar4 == *(int **)(unaff_EBX + 0x44b635 /* &bot_attack_aimpenalty_amt_frac_easy */ /* &bot_attack_aimpenalty_amt_frac_easy */ /* &bot_attack_aimpenalty_amt_frac_easy */)) goto LAB_0075c0a8;
      goto LAB_0075bd08;
    }
  }
  iVar3 = (**(code **)(*(int *)param_2 + 0x28))(param_2);
  local_1a8 = *(float *)(unaff_EBX + 0x15d139 /* 1.0f */ /* 1.0f */ /* 1.0f */);
  if (iVar3 != 0) {
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x44ac35 /* &bot_attack_aimpenalty_amt_frac_light */ /* &bot_attack_aimpenalty_amt_frac_light */ /* &bot_attack_aimpenalty_amt_frac_light */))[7];
    fVar13 = (*(float *)(iVar3 + 0xe4) + *(float *)(iVar3 + 0xe0) + *(float *)(iVar3 + 0xe8) +
             *(float *)(iVar3 + 0xec)) * *(float *)(unaff_EBX + 0x1c80b1 /* 0.25f */ /* 0.25f */ /* 0.25f */);
    if (piVar4 == *(int **)(unaff_EBX + 0x44ac35 /* &bot_attack_aimpenalty_amt_frac_light */ /* &bot_attack_aimpenalty_amt_frac_light */ /* &bot_attack_aimpenalty_amt_frac_light */)) {
      fVar7 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
      fVar7 = (float)fVar11;
    }
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x44aee1 /* &bot_attack_aimpenalty_amt_frac_dark */ /* &bot_attack_aimpenalty_amt_frac_dark */ /* &bot_attack_aimpenalty_amt_frac_dark */))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x44aee1 /* &bot_attack_aimpenalty_amt_frac_dark */ /* &bot_attack_aimpenalty_amt_frac_dark */ /* &bot_attack_aimpenalty_amt_frac_dark */)) {
      fVar9 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
      fVar9 = (float)fVar11;
    }
    local_1a8 = *(float *)(unaff_EBX + 0x15d139 /* 1.0f */ /* 1.0f */ /* 1.0f */);
    if (local_1a8 <= fVar13) {
      fVar13 = local_1a8;
    }
    if (fVar13 <= 0.0) {
      fVar13 = 0.0;
    }
    piVar4 = (int *)(*(int **)(unaff_EBX + 0x44ac55 /* &bot_attack_aimpenalty_time_frac_light */ /* &bot_attack_aimpenalty_time_frac_light */ /* &bot_attack_aimpenalty_time_frac_light */))[7];
    if (piVar4 == *(int **)(unaff_EBX + 0x44ac55 /* &bot_attack_aimpenalty_time_frac_light */ /* &bot_attack_aimpenalty_time_frac_light */ /* &bot_attack_aimpenalty_time_frac_light */)) {
      fVar12 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
      fVar12 = (float)fVar11;
    }
    piVar4 = (int *)(*(int **)(&DAT_0044b09d + unaff_EBX))[7];
    if (piVar4 == *(int **)(&DAT_0044b09d + unaff_EBX)) {
      fVar8 = (float)((uint)piVar4 ^ piVar4[0xb]);
    }
    else {
      fVar11 = (float10)(**(code **)(*piVar4 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar4);
      fVar8 = (float)fVar11;
    }
    local_1a0 = ((fVar7 - fVar9) * fVar13 + fVar9) * local_1a0;
    local_1a4 = ((fVar12 - fVar8) * fVar13 + fVar8) * local_1a4;
  }
  if (((byte)param_1[0x2294] & 0x10) == 0) {
    fVar11 = (float10)(**(code **)(*(int *)param_2 + 0x50))();
    fVar7 = (float)fVar11;
    if (local_1a4 == 0.0) {
      local_1a0 = (float)(~-(uint)(0.0 <= fVar7) & (uint)local_1a0);
      goto LAB_0075bf35;
    }
    fVar13 = (float)((uint)local_1a0 ^ *(uint *)(unaff_EBX + 0x1c9225 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */));
  }
  else {
    fVar11 = (float10)(**(code **)(*(int *)param_2 + 0x50))(param_2);
    local_1a4 = *(float *)(unaff_EBX + 0x1c8d89 /* 20.0f */ /* 20.0f */ /* 20.0f */);
    fVar7 = (float)fVar11;
    local_1a0 = *(float *)(unaff_EBX + 0x1cb1c5 /* 40.0f */ /* 40.0f */ /* 40.0f */);
    fVar13 = *(float *)(unaff_EBX + 0x22af29 /* CSWTCH.663+0x38 */ /* CSWTCH.663+0x38 */ /* CSWTCH.663+0x38 */);
  }
  fVar9 = fVar7 / local_1a4;
  if (local_1a8 <= fVar7 / local_1a4) {
    fVar9 = local_1a8;
  }
  if (fVar9 <= 0.0) {
    fVar9 = 0.0;
  }
  local_1a0 = fVar9 * fVar13 + local_1a0;
LAB_0075bf35:
  piVar4 = (int *)(**(code **)(*(int *)param_1 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_1);
  fVar11 = (float10)(**(code **)(*piVar4 + 0xe4 /* PlayerBody::GetHeadSteadyDuration */))(piVar4);
  fVar13 = (float)fVar11;
  if (local_1a8 <= (float)fVar11) {
    fVar13 = local_1a8;
  }
  if (fVar13 <= 0.0) {
    fVar13 = 0.0;
  }
  fVar13 = fVar13 * *(float *)(unaff_EBX + 0x1cb3f5 /* -50.0f */ /* -50.0f */ /* -50.0f */) +
           *(float *)(_GLOBAL__sub_I_te_bspdecal_cpp + unaff_EBX + 5);
  if (fVar13 <= local_1a0) {
    fVar13 = local_1a0;
  }
  iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x44b5c1 /* &bot_attack_aimpenalty_debug */ /* &bot_attack_aimpenalty_debug */ /* &bot_attack_aimpenalty_debug */) + 0x40))(*(int **)(unaff_EBX + 0x44b5c1 /* &bot_attack_aimpenalty_debug */ /* &bot_attack_aimpenalty_debug */ /* &bot_attack_aimpenalty_debug */));
  if (iVar3 != 0) {
    local_3c = local_78 * fVar13 + in_stack_0000000c[1];
    local_38 = local_74 * fVar13 + in_stack_0000000c[2];
    local_40 = local_7c * fVar13 + *in_stack_0000000c;
    NDebugOverlay::Cross((Vector *)&local_40,8.0,0,0xff,0,true,1.0);
    NDebugOverlay::Cross((Vector *)&local_64,8.0,0xff,0,0,true,1.0);
    local_30 = local_78 * fVar13 + in_stack_0000000c[1];
    local_2c = local_74 * fVar13 + in_stack_0000000c[2];
    local_34 = local_7c * fVar13 + *in_stack_0000000c;
    NDebugOverlay::Line((Vector *)&local_34,(Vector *)&local_64,0,0,0xff,true,1.0);
    CFmtStrN<256,false>::CFmtStrN(this_03,local_19c,unaff_EBX + 0x223221 /* "%.2f" */ /* "%.2f" */ /* "%.2f" */,(double)fVar13);
    local_24 = *(float *)(unaff_EBX + 0x1c8d7d /* 0.5f */ /* 0.5f */ /* 0.5f */) * local_78 * fVar13 + in_stack_0000000c[1];
    local_20 = *(float *)(unaff_EBX + 0x1c8d7d /* 0.5f */ /* 0.5f */ /* 0.5f */) * local_74 * fVar13 + in_stack_0000000c[2];
    local_28 = *(float *)(unaff_EBX + 0x1c8d7d /* 0.5f */ /* 0.5f */ /* 0.5f */) * local_7c * fVar13 + *in_stack_0000000c;
    NDebugOverlay::Text((Vector *)&local_28,local_197,false,1.0);
  }
  in_stack_0000000c[1] = local_78 * fVar13 + in_stack_0000000c[1];
  in_stack_0000000c[2] = local_74 * fVar13 + in_stack_0000000c[2];
  *in_stack_0000000c = fVar13 * local_7c + *in_stack_0000000c;
  return;
}



/* ----------------------------------------
 * CINSNextBot::AvoidPlayers
 * Address: 0074beb0
 * ---------------------------------------- */

/* CINSNextBot::AvoidPlayers(CUserCmd*) */

void __thiscall CINSNextBot::AvoidPlayers(CINSNextBot *this,CUserCmd *param_1)

{
  float *pfVar1;
  int iVar2;
  char cVar3;
  Vector *pVVar4;
  int iVar5;
  CBasePlayer *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  CBaseEntity *extraout_ECX;
  int unaff_EBX;
  float10 fVar6;
  float fVar7;
  int in_stack_00000008;
  int local_7c [8];
  float local_5c;
  float local_58;
  float local_54;
  float local_4c;
  float local_48;
  float local_44;
  float local_3c;
  float local_38;
  float local_34;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x74bebe;
  pVVar4 = (Vector *)__i686_get_pc_thunk_bx();
  CBasePlayer::EyeVectors(this_00,(Vector *)param_1,(Vector *)&local_5c,pVVar4);
  local_7c[0] = 0;
  local_7c[1] = 0;
  local_7c[2] = 0;
  local_7c[3] = 0;
  local_7c[4] = 0;
  iVar5 = CBaseEntity::GetTeamNumber(this_01);
  CollectPlayers<CINSPlayer>((CUtlVector *)local_7c,iVar5,true,false);
  pfVar1 = *(float **)(unaff_EBX + 0x45a70e /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  local_3c = *pfVar1;
  local_38 = pfVar1[1];
  local_34 = pfVar1[2];
  if (0 < local_7c[3]) {
    iVar5 = 0;
    do {
      while( true ) {
        iVar2 = *(int *)(local_7c[0] + iVar5 * 4);
        cVar3 = (**(code **)(*(int *)(param_1 + 0x2060) + 0xf0))(param_1 + 0x2060,iVar2);
        if (cVar3 == '\0') break;
LAB_0074bf68:
        iVar5 = iVar5 + 1;
        if (local_7c[3] <= iVar5) goto LAB_0074c090;
      }
      this_03 = this_02;
      if ((*(byte *)(iVar2 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_02);
        this_03 = extraout_ECX;
      }
      if (((byte)param_1[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_03);
      }
      local_2c = *(float *)(param_1 + 0x208) - *(float *)(iVar2 + 0x208);
      local_28 = *(float *)(param_1 + 0x20c) - *(float *)(iVar2 + 0x20c);
      local_24 = *(float *)(param_1 + 0x210) - *(float *)(iVar2 + 0x210);
      if (*(float *)(unaff_EBX + 0x2376d2 /* 5184.0f */ /* 5184.0f */ /* 5184.0f */) <=
          local_28 * local_28 + local_2c * local_2c + local_24 * local_24) goto LAB_0074bf68;
      fVar6 = (float10)VectorNormalize((Vector *)&local_2c);
      iVar5 = iVar5 + 1;
      fVar7 = *(float *)(unaff_EBX + 0x16cc56 /* 1.0f */ /* 1.0f */ /* 1.0f */) - (float)fVar6 * *(float *)(unaff_EBX + 0x2376d6 /* rodata:0x3C638E39 */ /* rodata:0x3C638E39 */ /* rodata:0x3C638E39 */);
      local_38 = local_28 * fVar7 + local_38;
      local_34 = local_24 * fVar7 + local_34;
      local_3c = fVar7 * local_2c + local_3c;
    } while (iVar5 < local_7c[3]);
  }
LAB_0074c090:
  VectorNormalize((Vector *)&local_3c);
  local_7c[3] = 0;
  fVar7 = *(float *)(_GLOBAL__sub_I_ins_nbot_cvars_cpp + unaff_EBX + 2);
  *(float *)(in_stack_00000008 + 0x28) =
       (local_48 * local_38 + local_4c * local_3c + local_44 * local_34) * fVar7 +
       *(float *)(in_stack_00000008 + 0x28);
  *(float *)(in_stack_00000008 + 0x24) =
       (local_38 * local_58 + local_3c * local_5c + local_34 * local_54) * fVar7 +
       *(float *)(in_stack_00000008 + 0x24);
  if ((-1 < local_7c[2]) && (local_7c[0] != 0)) {
    (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x45a9ba /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
              ((int *)**(undefined4 **)(unaff_EBX + 0x45a9ba /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_7c[0]);
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::BotSpeakConcept
 * Address: 007480b0
 * ---------------------------------------- */

/* CINSNextBot::BotSpeakConcept(ResponseRules::CRR_Response&, int) */

void __cdecl CINSNextBot::BotSpeakConcept(CRR_Response *param_1,int param_2)

{
  __i686_get_pc_thunk_bx();
  CBaseMultiplayerPlayer::SpeakConcept(param_1,param_2);
  return;
}



/* ----------------------------------------
 * CINSNextBot::BotSpeakConceptIfAllowed
 * Address: 007480f0
 * ---------------------------------------- */

/* CINSNextBot::BotSpeakConceptIfAllowed(int, char const*, char*, unsigned int, IRecipientFilter*)
    */

void __thiscall
CINSNextBot::BotSpeakConceptIfAllowed
          (CINSNextBot *this,int param_1,char *param_2,char *param_3,uint param_4,
          IRecipientFilter *param_5)

{
  (**(code **)(*(int *)param_1 + 0x800 /* CINSPlayer::SpeakConceptIfAllowed */))(param_1,param_2,param_3,param_4,param_5);
  return;
}



/* ----------------------------------------
 * CINSNextBot::BotSpeakIfAllowed
 * Address: 00748050
 * ---------------------------------------- */

/* CINSNextBot::BotSpeakIfAllowed(CAI_Concept, SpeechPriorityType, char const*, char*, unsigned int,
   IRecipientFilter*) */

void __thiscall
CINSNextBot::BotSpeakIfAllowed
          (undefined4 param_1,int *param_2,undefined2 *param_3,undefined4 param_4,undefined4 param_5
          ,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined2 local_14 [2];
  undefined4 local_10;
  
  local_14[0] = *param_3;
  local_10 = *(undefined4 *)(param_3 + 2);
  (**(code **)(*param_2 + 0x7fc /* CINSPlayer::SpeakIfAllowed */))(param_2,local_14,param_4,param_5,param_6,param_7,param_8);
  return;
}



/* ----------------------------------------
 * CINSNextBot::CanActiveWeaponFire
 * Address: 00744560
 * ---------------------------------------- */

/* CINSNextBot::CanActiveWeaponFire() const */

undefined4 CINSNextBot::CanActiveWeaponFire(void)

{
  return 1;
}



/* ----------------------------------------
 * CINSNextBot::CanAttackTarget
 * Address: 00759eb0
 * ---------------------------------------- */

/* CINSNextBot::CanAttackTarget(CKnownEntity const*) */

undefined4 __thiscall CINSNextBot::CanAttackTarget(CINSNextBot *this,CKnownEntity *param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  int unaff_EBX;
  undefined4 uVar4;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  uVar4 = 0;
  if (in_stack_00000008 != (int *)0x0) {
    iVar2 = (**(code **)(*in_stack_00000008 + 0x10))();
    if (iVar2 != 0) {
      piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x10))();
      cVar1 = (**(code **)(*piVar3 + 0x158))(piVar3);
      if (cVar1 != '\0') {
        cVar1 = (**(code **)(*in_stack_00000008 + 0x38))();
        if (cVar1 != '\0') {
          piVar3 = (int *)(**(code **)(*in_stack_00000008 + 0x10))();
          if (piVar3 != (int *)0x0) {
            cVar1 = (**(code **)(*piVar3 + 0x158))(piVar3);
            if (cVar1 != '\0') {
              uVar4 = CONCAT31((int3)((uint)**(int **)(unaff_EBX + 0x44c9dc /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) >> 8),
                               *(float *)(unaff_EBX + 0x1ca2ec /* 10.0f */ /* 10.0f */ /* 10.0f */) <=
                               *(float *)(**(int **)(unaff_EBX + 0x44c9dc /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc) -
                               (float)piVar3[0x76e]);
            }
          }
        }
      }
    }
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSNextBot::CanCheckRetreat
 * Address: 0075b8e0
 * ---------------------------------------- */

/* CINSNextBot::CanCheckRetreat() */

undefined4 __thiscall CINSNextBot::CanCheckRetreat(CINSNextBot *this)

{
  float fVar1;
  undefined4 uVar2;
  int unaff_EBX;
  float10 fVar3;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar3 = (float10)CountdownTimer::Now();
  uVar2 = 0;
  if (*(float *)(in_stack_00000004 + 0xb3b4) <= (float)fVar3 && /* timer_24.IsElapsed() */
      (float)fVar3 != *(float *)(in_stack_00000004 + 0xb3b4)) {
    fVar3 = (float10)CountdownTimer::Now();
    fVar1 = *(float *)(_GLOBAL__sub_I_te_bloodstream_cpp + unaff_EBX + 6);
    if (*(float *)(in_stack_00000004 + 0xb3b4) != (float)fVar3 + fVar1) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xb3ac) + 4)) /* timer_24.NetworkStateChanged() */
                (in_stack_00000004 + 0xb3ac,in_stack_00000004 + 0xb3b4);
      *(float *)(in_stack_00000004 + 0xb3b4) = (float)fVar3 + fVar1; /* timer_24.Start(...) */
    }
    uVar2 = 1;
    if (*(int *)(in_stack_00000004 + 46000) != 0x3f800000 /* 1.0f */) {
      (**(code **)(*(int *)(in_stack_00000004 + 0xb3ac) + 4)) /* timer_24.NetworkStateChanged() */
                (in_stack_00000004 + 0xb3ac,in_stack_00000004 + 46000);
      *(undefined4 *)(in_stack_00000004 + 46000) = 0x3f800000 /* 1.0f */;
      return 1;
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSNextBot::CanIAttack
 * Address: 0076f330
 * ---------------------------------------- */

/* CINSNextBot::CanIAttack() */

uint CINSNextBot::CanIAttack(void)

{
  char cVar1;
  int iVar2;
  CINSNextBot *this;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  int unaff_EBX;
  uint uVar3;
  
  __i686_get_pc_thunk_bx();
  uVar3 = 0;
  iVar2 = (**(code **)(*(int *)(unaff_EBX + 0x5833c2 /* bot_disable_attack */ /* bot_disable_attack */ /* bot_disable_attack */) + 0x40))(unaff_EBX + 0x5833c2 /* bot_disable_attack */ /* bot_disable_attack */ /* bot_disable_attack */);
  if (iVar2 == 0) {
    cVar1 = CINSPlayer::IsReloading();
    if (cVar1 == '\0') {
      cVar1 = CheckAnyAmmo(this);
      if (cVar1 != '\0') {
        uVar3 = 1;
        cVar1 = CINSPlayer::IsProned(this_00);
        if (cVar1 != '\0') {
          uVar3 = CINSPlayer::IsMoving(this_01);
          uVar3 = uVar3 ^ 1;
        }
      }
    }
  }
  return uVar3;
}



/* ----------------------------------------
 * CINSNextBot::ChangeDifficulty
 * Address: 00744570
 * ---------------------------------------- */

/* CINSNextBot::ChangeDifficulty(CINSNextBot::BotDifficulty_e) */

bool __thiscall CINSNextBot::ChangeDifficulty(undefined4 param_1,int *param_2,int param_3)

{
  code *pcVar1;
  int *piVar2;
  int *piVar3;
  float10 fVar4;
  
  if (param_3 < 4) {
    param_2[0x8a2] = param_3;
    piVar2 = (int *)(**(code **)(*param_2 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_2);
    pcVar1 = *(code **)(*piVar2 + 0x124);
    piVar3 = (int *)(**(code **)(*param_2 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_2);
    fVar4 = (float10)(**(code **)(*piVar3 + 0x11c /* CINSBotVision::GetDefaultFieldOfView */))(piVar3);
    (*pcVar1)(piVar2,(float)fVar4);
  }
  return param_3 < 4;
}



/* ----------------------------------------
 * CINSNextBot::ChargeTarget
 * Address: 00748360
 * ---------------------------------------- */

/* CINSNextBot::ChargeTarget(Vector, float) */

void __cdecl
CINSNextBot::ChargeTarget
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,float param_5)

{
  float10 fVar1;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)(param_1 + 0xb48c) != (float)fVar1 + param_5) {
    (**(code **)(*(int *)(param_1 + 0xb484) + 4))(param_1 + 0xb484,param_1 + 0xb48c); /* timer_37.NetworkStateChanged() */
    *(float *)(param_1 + 0xb48c) = (float)fVar1 + param_5; /* timer_37.Start(...) */
  }
  if (*(float *)(param_1 + 0xb488) != param_5) {
    (**(code **)(*(int *)(param_1 + 0xb484) + 4))(param_1 + 0xb484,param_1 + 0xb488); /* timer_37.NetworkStateChanged() */
    *(float *)(param_1 + 0xb488) = param_5; /* timer_37.m_duration */
  }
  *(undefined4 *)(param_1 + 0xb490) = param_2;
  *(undefined4 *)(param_1 + 0xb494) = param_3;
  *(undefined4 *)(param_1 + 0xb498) = param_4;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ChasePathInvalid
 * Address: 00759f90
 * ---------------------------------------- */

/* CINSNextBot::ChasePathInvalid() */

undefined4 __thiscall CINSNextBot::ChasePathInvalid(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0x669c)) {
    *(undefined4 *)(in_stack_00000004 + 0xb324) = 0;
    return 0;
  }
  *(int *)(in_stack_00000004 + 0xb324) = *(int *)(in_stack_00000004 + 0xb324) + 1;
  return 1;
}



/* ----------------------------------------
 * CINSNextBot::Chatter
 * Address: 007446e0
 * ---------------------------------------- */

/* CINSNextBot::Chatter(char*, Vector) */

void __cdecl CINSNextBot::Chatter(void)

{
  return;
}



/* ----------------------------------------
 * CINSNextBot::CheckAnyAmmo
 * Address: 0076df80
 * ---------------------------------------- */

/* CINSNextBot::CheckAnyAmmo() */

byte __thiscall CINSNextBot::CheckAnyAmmo(CINSNextBot *this)

{
  char cVar1;
  byte bVar2;
  int *piVar3;
  int *piVar4;
  int *piVar5;
  int iVar6;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CBaseCombatCharacter *this_03;
  CBaseCombatCharacter *this_04;
  CBaseCombatCharacter *this_05;
  int in_stack_00000004;
  undefined4 uVar7;
  undefined4 uVar8;
  
  __i686_get_pc_thunk_bx();
  piVar3 = (int *)CINSPlayer::GetWeaponInSlot(this_00,in_stack_00000004,false);
  piVar4 = (int *)CINSPlayer::GetWeaponInSlot(this_01,in_stack_00000004,true);
  uVar8 = 0;
  uVar7 = 3;
  piVar5 = (int *)CINSPlayer::GetWeaponInSlot(this_02,in_stack_00000004,true);
  if (piVar3 == (int *)0x0) {
LAB_0076e140:
    *(undefined1 *)(in_stack_00000004 + 0x228c) = 1;
  }
  else {
    cVar1 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3,uVar7,uVar8);
    if ((cVar1 != '\0') && (cVar1 = (**(code **)(*piVar3 + 0x740 /* CINSPlayer::CanSpeak */))(piVar3), cVar1 != '\0')) {
      uVar7 = (**(code **)(*piVar3 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar3);
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_05,in_stack_00000004);
      if (iVar6 < 1) goto LAB_0076e140;
    }
    *(undefined1 *)(in_stack_00000004 + 0x228c) = 0;
  }
  if (piVar4 == (int *)0x0) {
LAB_0076e0f8:
    *(undefined1 *)(in_stack_00000004 + 0x228d) = 1;
  }
  else {
    cVar1 = (**(code **)(*piVar4 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar4,uVar7);
    if ((cVar1 != '\0') && (cVar1 = (**(code **)(*piVar4 + 0x740 /* CINSPlayer::CanSpeak */))(piVar4), cVar1 != '\0')) {
      uVar7 = (**(code **)(*piVar4 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar4);
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_04,in_stack_00000004);
      if (iVar6 < 1) goto LAB_0076e0f8;
    }
    *(undefined1 *)(in_stack_00000004 + 0x228d) = 0;
  }
  if (piVar5 == (int *)0x0) {
LAB_0076e0b0:
    *(undefined1 *)(in_stack_00000004 + 0x228e) = 1;
  }
  else {
    cVar1 = (**(code **)(*piVar5 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar5,uVar7);
    if ((cVar1 != '\0') && (cVar1 = (**(code **)(*piVar5 + 0x740 /* CINSPlayer::CanSpeak */))(piVar5), cVar1 != '\0')) {
      (**(code **)(*piVar5 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar5);
      iVar6 = CBaseCombatCharacter::GetAmmoCount(this_03,in_stack_00000004);
      if (iVar6 < 1) goto LAB_0076e0b0;
    }
    *(undefined1 *)(in_stack_00000004 + 0x228e) = 0;
  }
  bVar2 = 1;
  if ((*(char *)(in_stack_00000004 + 0x228c) != '\0') &&
     (*(char *)(in_stack_00000004 + 0x228d) != '\0')) {
    bVar2 = *(byte *)(in_stack_00000004 + 0x228e) ^ 1;
  }
  return bVar2;
}



/* ----------------------------------------
 * CINSNextBot::ChooseBestWeapon
 * Address: 0076db70
 * ---------------------------------------- */

/* CINSNextBot::ChooseBestWeapon(CINSWeapon*, float) */

void __thiscall CINSNextBot::ChooseBestWeapon(CINSNextBot *this,CINSWeapon *param_1,float param_2)

{
  int iVar1;
  float10 fVar2;
  float in_stack_0000000c;
  
  iVar1 = __i686_get_pc_thunk_bx();
  if (iVar1 != 0) {
    (**(code **)(*(int *)param_1 + 0x474 /* CINSPlayer::Weapon_Switch */))(param_1,iVar1,0);
    fVar2 = (float10)CountdownTimer::Now();
    if (*(float *)(param_1 + 0xb3d4) != (float)fVar2 + in_stack_0000000c) {
      (**(code **)(*(int *)(param_1 + 0xb3cc) + 4))(param_1 + 0xb3cc,param_1 + 0xb3d4); /* timer_26.NetworkStateChanged() */
      *(float *)(param_1 + 0xb3d4) = (float)fVar2 + in_stack_0000000c; /* timer_26.Start(...) */
    }
    if (*(float *)(param_1 + 0xb3d0) != in_stack_0000000c) {
      (**(code **)(*(int *)(param_1 + 0xb3cc) + 4))(param_1 + 0xb3cc,param_1 + 0xb3d0); /* timer_26.NetworkStateChanged() */
      *(float *)(param_1 + 0xb3d0) = in_stack_0000000c; /* timer_26.m_duration */
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::ChooseBestWeapon
 * Address: 0076e540
 * ---------------------------------------- */

/* CINSNextBot::ChooseBestWeapon(CKnownEntity const*) */

void __thiscall CINSNextBot::ChooseBestWeapon(CINSNextBot *this,CKnownEntity *param_1)

{
  code *pcVar1;
  char cVar2;
  int iVar3;
  CINSNextBot *pCVar4;
  CINSNextBot *this_00;
  CINSNextBot *pCVar5;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CINSNextBot *this_03;
  CINSNextBot *this_04;
  int unaff_EBX;
  float10 fVar6;
  float10 fVar7;
  float fVar8;
  int *in_stack_00000008;
  undefined4 uVar9;
  CINSNextBot *pCVar10;
  undefined4 uVar11;
  CINSNextBot *local_24;
  
  __i686_get_pc_thunk_bx();
  fVar6 = (float10)CountdownTimer::Now();
  if ((float)fVar6 < *(float *)(param_1 + 0xb3d4) || (float)fVar6 == *(float *)(param_1 + 0xb3d4)) { /* !timer_26.IsElapsed() */
    return;
  }
  iVar3 = (**(code **)(**(int **)(&DAT_00437ffe + unaff_EBX) + 0x40))
                    (*(int **)(&DAT_00437ffe + unaff_EBX));
  if (iVar3 != 0) {
    pcVar1 = *(code **)(*(int *)param_1 + 0x474);
    uVar9 = CINSPlayer::GetWeaponInSlot(this_01,(int)param_1,true);
    (*pcVar1)(param_1,uVar9,0);
    return;
  }
  pCVar4 = (CINSNextBot *)CINSPlayer::GetWeaponInSlot(this_01,(int)param_1,false);
  uVar11 = 0;
  uVar9 = 1;
  this_00 = (CINSNextBot *)CINSPlayer::GetWeaponInSlot(this_02,(int)param_1,true);
  if ((this_00 != (CINSNextBot *)0x0) &&
     (iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x43875e /* &ins_bot_pistols_only */ /* &ins_bot_pistols_only */ /* &ins_bot_pistols_only */) + 0x40))
                        (*(int **)(unaff_EBX + 0x43875e /* &ins_bot_pistols_only */ /* &ins_bot_pistols_only */ /* &ins_bot_pistols_only */),uVar9,uVar11), iVar3 != 0)) {
LAB_0076e5f7:
    (**(code **)(*(int *)param_1 + 0x474 /* CINSPlayer::Weapon_Switch */))(param_1,this_00,0);
    return;
  }
  if (in_stack_00000008 == (int *)0x0) {
    if (pCVar4 != (CINSNextBot *)0x0) {
      (**(code **)(*(int *)param_1 + 0x474 /* CINSPlayer::Weapon_Switch */))(param_1,pCVar4,0);
      return;
    }
    if (this_00 == (CINSNextBot *)0x0) {
      return;
    }
    goto LAB_0076e5f7;
  }
  uVar9 = 0;
  pCVar10 = (CINSNextBot *)0x2;
  pCVar5 = (CINSNextBot *)CINSPlayer::GetWeaponInSlot((CINSPlayer *)this_00,(int)param_1,true);
  cVar2 = CheckAnyAmmo(this_03);
  if ((cVar2 == '\0') && (pCVar5 != (CINSNextBot *)0x0)) {
    uVar9 = 0;
    pCVar10 = pCVar5;
    (**(code **)(*(int *)param_1 + 0x474 /* CINSPlayer::Weapon_Switch */))(param_1,pCVar5,0);
  }
  local_24 = pCVar4;
  if ((pCVar4 != (CINSNextBot *)0x0) &&
     (local_24 = (CINSNextBot *)0x0, param_1[0x228c] == (CKnownEntity)0x0)) {
    local_24 = pCVar4;
  }
  if ((this_00 != (CINSNextBot *)0x0) && (param_1[0x228d] != (CKnownEntity)0x0)) {
    this_00 = (CINSNextBot *)0x0;
  }
  if (local_24 == (CINSNextBot *)0x0) {
    if (this_00 != (CINSNextBot *)0x0) goto LAB_0076e7a3;
    this_00 = pCVar5;
    if (pCVar5 == (CINSNextBot *)0x0) {
      return;
    }
LAB_0076e7aa:
    iVar3 = (**(code **)(**(int **)(&DAT_00437ffe + unaff_EBX) + 0x40))
                      (*(int **)(&DAT_00437ffe + unaff_EBX),pCVar10);
    if (iVar3 != 0) goto LAB_0076e7ce;
  }
  else {
    if ((this_00 != (CINSNextBot *)0x0) &&
       ((iVar3 = (**(code **)(*(int *)local_24 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(local_24,pCVar10,uVar9), iVar3 == 0xe ||
        (iVar3 = (**(code **)(*(int *)local_24 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(local_24), iVar3 == 0xb)))) {
      pcVar1 = *(code **)(*(int *)(param_1 + 0x2060) + 0x134);
      uVar9 = (**(code **)(*in_stack_00000008 + 0x14))(in_stack_00000008);
      fVar6 = (float10)(*pcVar1)(param_1 + 0x2060,uVar9);
      fVar8 = (float)fVar6;
      fVar6 = (float10)GetDesiredAttackRange(this_04,(CINSWeapon *)param_1);
      pCVar10 = this_00;
      fVar7 = (float10)GetDesiredAttackRange(this_00,(CINSWeapon *)param_1);
      if (((float)((uint)((float)fVar7 * *(float *)(unaff_EBX + 0x1b553e /* 0.25f */ /* 0.25f */ /* 0.25f */) - fVar8) &
                  *(uint *)(unaff_EBX + 0x1b6b02 /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */)) <=
           (float)((uint)((float)fVar6 - fVar8) & *(uint *)(unaff_EBX + 0x1b6b02 /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */ /* rodata:0x7FFFFFFF */))) &&
         (pCVar10 = this_00, fVar6 = (float10)GetMaxAttackRange(this_00,(CINSWeapon *)param_1),
         fVar8 <= (float)fVar6)) goto LAB_0076e7a3;
    }
    this_00 = local_24;
LAB_0076e7a3:
    if (pCVar5 != (CINSNextBot *)0x0) goto LAB_0076e7aa;
  }
  pCVar5 = this_00;
  if (pCVar5 == (CINSNextBot *)0x0) {
    return;
  }
LAB_0076e7ce:
  (**(code **)(*(int *)param_1 + 0x474 /* CINSPlayer::Weapon_Switch */))(param_1,pCVar5,0);
  fVar6 = (float10)CountdownTimer::Now();
  fVar8 = (float)fVar6 + *(float *)(unaff_EBX + 0x14aa2e /* 3.0f */ /* 3.0f */ /* 3.0f */);
  if (*(float *)(param_1 + 0xb3d4) != fVar8) {
    (**(code **)(*(int *)(param_1 + 0xb3cc) + 4))(param_1 + 0xb3cc,param_1 + 0xb3d4); /* timer_26.NetworkStateChanged() */
    *(float *)(param_1 + 0xb3d4) = fVar8; /* timer_26.Start(3.0f) */
  }
  if (*(int *)(param_1 + 0xb3d0) == 0x40400000 /* 3.0f */) {
    return;
  }
  (**(code **)(*(int *)(param_1 + 0xb3cc) + 4))(param_1 + 0xb3cc,param_1 + 0xb3d0); /* timer_26.NetworkStateChanged() */
  *(undefined4 *)(param_1 + 0xb3d0) = 0x40400000 /* 3.0f */;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ComputeChasePath
 * Address: 0075c600
 * ---------------------------------------- */

/* CINSNextBot::ComputeChasePath(CBaseEntity*) */

undefined4 __thiscall CINSNextBot::ComputeChasePath(CINSNextBot *this,CBaseEntity *param_1)

{
  Vector *pVVar1;
  int iVar2;
  char cVar3;
  bool bVar4;
  undefined4 uVar5;
  int *piVar6;
  PathFollower *extraout_ECX;
  PathFollower *extraout_ECX_00;
  PathFollower *extraout_ECX_01;
  PathFollower *this_00;
  CINSNextBot *this_01;
  CBaseEntity *this_02;
  CBaseEntity *this_03;
  Path *extraout_ECX_02;
  CBaseEntity *this_04;
  CINSRules *this_05;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *extraout_ECX_04;
  CINSNextBot *this_06;
  int unaff_EBX;
  float10 fVar7;
  int in_stack_00000008;
  undefined *local_40;
  Vector *local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75c60b;
  __i686_get_pc_thunk_bx();
  this_00 = extraout_ECX;
  if (*(int *)(param_1 + 0x6b1c) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(param_1 + 0x6b14) + 4))(param_1 + 0x6b14,param_1 + 0x6b1c); /* timer_13.NetworkStateChanged() */
    *(undefined4 *)(param_1 + 0x6b1c) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_00;
  }
  if (*(int *)(param_1 + 0x6b28) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(param_1 + 0x6b20) + 4))(param_1 + 0x6b20,param_1 + 0x6b28); /* timer_14.NetworkStateChanged() */
    *(undefined4 *)(param_1 + 0x6b28) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_01;
  }
  PathFollower::Invalidate(this_00);
  uVar5 = RandomInt(0,2);
  cVar3 = IsEscorting(this_01);
  local_38 = 1;
  if (cVar3 == '\0') {
    local_38 = uVar5;
  }
  if ((*(byte *)(in_stack_00000008 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_02);
  }
  pVVar1 = (Vector *)(param_1 + 0x2060);
  local_34 = *(undefined4 *)(in_stack_00000008 + 0x208);
  local_40 = &UNK_00437f35 + unaff_EBX;
  local_30 = *(undefined4 *)(in_stack_00000008 + 0x20c);
  local_2c = *(undefined4 *)(in_stack_00000008 + 0x210);
  local_3c = pVVar1;
  piVar6 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pVVar1);
  fVar7 = (float10)(**(code **)(*piVar6 + 0x14c))(piVar6);
  local_28 = (float)fVar7;
  piVar6 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pVVar1);
  fVar7 = (float10)(**(code **)(*piVar6 + 0x150))(piVar6);
  local_24 = (float)fVar7;
  piVar6 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pVVar1);
  fVar7 = (float10)(**(code **)(*piVar6 + 0x154))(piVar6);
  local_20 = (float)fVar7;
  fVar7 = (float10)MaxPathLength();
  this_04 = this_03;
  if ((*(byte *)(in_stack_00000008 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_03);
    fVar7 = (float10)(float)fVar7;
    this_04 = (CBaseEntity *)extraout_ECX_02;
  }
  bVar4 = Path::Compute<CINSNextBotChasePathCost>
                    ((Path *)this_04,(INextBot *)(param_1 + 0x2298),pVVar1,
                     (CINSNextBotChasePathCost *)(in_stack_00000008 + 0x208),(float)&local_40,
                     SUB41((float)fVar7,0));
  if (bVar4) {
    piVar6 = (int *)(*(int **)(unaff_EBX + 0x449edd /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */))[7];
    if (piVar6 == *(int **)(unaff_EBX + 0x449edd /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */)) {
      fVar7 = (float10)(float)((uint)piVar6 ^ piVar6[0xb]);
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar6 + 0x3c))(piVar6);
    }
    *(float *)(param_1 + 0x6a74) = (float)fVar7;
    uVar5 = 1;
    *(undefined4 *)(param_1 + 0xb324) = 0;
  }
  else {
    iVar2 = *(int *)(param_1 + 0xb324);
    *(int *)(param_1 + 0xb324) = iVar2 + 1;
    if (iVar2 + 1 < 5) {
      return 0;
    }
    Warning(unaff_EBX + 0x22a295 /* "Chase path failed generating, suiciding.
" */ /* "Chase path failed generating, suiciding.
" */ /* "Chase path failed generating, suiciding.
" */);
    cVar3 = CINSRules::IsOutpost(this_05);
    this_06 = extraout_ECX_03;
    if ((cVar3 == '\0') &&
       (cVar3 = CINSRules::IsEntrenchment(), this_06 = extraout_ECX_04, cVar3 == '\0')) {
      return 0;
    }
    KillSelf(this_06);
    uVar5 = 0;
  }
  return uVar5;
}



/* ----------------------------------------
 * CINSNextBot::ComputePartPositions
 * Address: 00746260
 * ---------------------------------------- */

/* CINSNextBot::ComputePartPositions(CINSPlayer*) */

void __thiscall CINSNextBot::ComputePartPositions(CINSNextBot *this,CINSPlayer *param_1)

{
  uint *puVar1;
  QAngle *pQVar2;
  float fVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  char cVar7;
  int iVar8;
  undefined4 *puVar9;
  int *piVar10;
  CBaseAnimating *this_00;
  CBaseAnimating *this_01;
  CBaseAnimating *this_02;
  int unaff_EBX;
  int iVar11;
  CBaseEntity *in_stack_00000008;
  CBaseAnimating local_44 [12];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x74626b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar11 = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar8 = ThreadGetCurrentId(),
     iVar11 == iVar8)) {
    piVar10 = *(int **)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar10 != unaff_EBX + 0x23d011 /* "CINSNextBot::ComputePartPositions" */ /* "CINSNextBot::ComputePartPositions" */ /* "CINSNextBot::ComputePartPositions" */) {
      piVar10 = (int *)CVProfNode::GetSubNode
                                 ((char *)piVar10,unaff_EBX + 0x23d011 /* "CINSNextBot::ComputePartPositions" */ /* "CINSNextBot::ComputePartPositions" */ /* "CINSNextBot::ComputePartPositions" */,(char *)0x0,
                                  unaff_EBX + 0x23a9fb /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar10;
    }
    puVar1 = (uint *)(piVar10[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  iVar11 = 0;
  if (*(int *)(in_stack_00000008 + 0x20) != 0) {
    iVar11 = (*(int *)(in_stack_00000008 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x460635 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c)
             >> 4) % 0x31;
  }
  if (((byte)in_stack_00000008[0xd1] & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(in_stack_00000008);
  }
  fVar3 = *(float *)(unaff_EBX + 0x1de501 /* 5.0f */ /* 5.0f */ /* 5.0f */);
  pQVar2 = (QAngle *)(unaff_EBX + 0x5a72f5 /* CINSNextBot::m_partInfo */ /* CINSNextBot::m_partInfo */ /* CINSNextBot::m_partInfo */ + iVar11 * 0x58);
  *(undefined4 *)(pQVar2 + 0x18) = *(undefined4 *)(in_stack_00000008 + 0x208);
  *(undefined4 *)(pQVar2 + 0x1c) = *(undefined4 *)(in_stack_00000008 + 0x20c);
  *(float *)(pQVar2 + 0x20) = fVar3 + *(float *)(in_stack_00000008 + 0x210);
  if (in_stack_00000008[0x32d] == (CBaseEntity)0x0) {
    if ((*(int *)(in_stack_00000008 + 0x498) == 0) &&
       (iVar11 = CBaseEntity::GetModel(), iVar11 != 0)) {
      CBaseAnimating::LockStudioHdr((CBaseAnimating *)in_stack_00000008);
    }
    piVar10 = *(int **)(in_stack_00000008 + 0x498);
    if ((piVar10 != (int *)0x0) && (*piVar10 != 0)) {
      iVar11 = CBaseAnimating::GetHitboxSet((CBaseAnimating *)in_stack_00000008);
      iVar11 = *piVar10 + iVar11 * 0xc + *(int *)(*piVar10 + 0xb0);
      if ((iVar11 != 0) && (0x11 < *(int *)(iVar11 + 4))) {
        CBaseAnimating::GetBonePosition
                  (this_00,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x220 + *(int *)(iVar11 + 8)),pQVar2 + 0xc);
        CBaseAnimating::GetBonePosition
                  (local_44,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x2ec + *(int *)(iVar11 + 8)),pQVar2);
        CBaseAnimating::GetBonePosition
                  ((CBaseAnimating *)in_stack_00000008,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x88 + *(int *)(iVar11 + 8)),pQVar2 + 0x3c);
        CBaseAnimating::GetBonePosition
                  (this_01,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x154 + *(int *)(iVar11 + 8)),pQVar2 + 0x48);
        AngleVectors((QAngle *)local_44,(Vector *)&local_38,(Vector *)&local_2c,(Vector *)0x0);
        fVar3 = *(float *)(unaff_EBX + 0x1de4f5 /* 4.0f */ /* 4.0f */ /* 4.0f */);
        *(float *)(pQVar2 + 4) = local_28 + local_28 + local_34 * fVar3 + *(float *)(pQVar2 + 4);
        *(float *)(pQVar2 + 8) = local_24 + local_24 + local_30 * fVar3 + *(float *)(pQVar2 + 8);
        *(float *)pQVar2 = local_2c + local_2c + fVar3 * local_38 + *(float *)pQVar2;
        CBaseAnimating::GetBonePosition
                  (this_02,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x3b8 + *(int *)(iVar11 + 8)),pQVar2 + 0x24);
        CBaseAnimating::GetBonePosition
                  (local_44,(int)in_stack_00000008,
                   *(Vector **)(iVar11 + 0x484 + *(int *)(iVar11 + 8)),pQVar2 + 0x30);
        if (local_1d == '\0') {
          return;
        }
        if ((*(char *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
           (*(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
          return;
        }
        iVar11 = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
        iVar8 = ThreadGetCurrentId();
        if (iVar11 != iVar8) {
          return;
        }
        cVar7 = CVProfNode::ExitScope();
        iVar11 = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
        if (cVar7 != '\0') {
          iVar11 = *(int *)(iVar11 + 100);
          *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar11;
        }
        goto LAB_007465e4;
      }
    }
  }
  puVar9 = (undefined4 *)(**(code **)(*(int *)in_stack_00000008 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_00000008);
  uVar4 = *puVar9;
  *(undefined4 *)pQVar2 = uVar4;
  uVar5 = puVar9[1];
  *(undefined4 *)(pQVar2 + 4) = uVar5;
  uVar6 = puVar9[2];
  *(undefined4 *)(pQVar2 + 0xc) = uVar4;
  *(undefined4 *)(pQVar2 + 0x10) = uVar5;
  *(undefined4 *)(pQVar2 + 0x24) = uVar4;
  *(undefined4 *)(pQVar2 + 0x28) = uVar5;
  *(undefined4 *)(pQVar2 + 8) = uVar6;
  *(undefined4 *)(pQVar2 + 0x14) = uVar6;
  *(undefined4 *)(pQVar2 + 0x2c) = uVar6;
  *(undefined4 *)(pQVar2 + 0x30) = uVar4;
  *(undefined4 *)(pQVar2 + 0x34) = uVar5;
  *(undefined4 *)(pQVar2 + 0x38) = uVar6;
  *(undefined4 *)(pQVar2 + 0x3c) = uVar4;
  *(undefined4 *)(pQVar2 + 0x40) = uVar5;
  *(undefined4 *)(pQVar2 + 0x44) = uVar6;
  *(undefined4 *)(pQVar2 + 0x48) = uVar4;
  *(undefined4 *)(pQVar2 + 0x4c) = uVar5;
  *(undefined4 *)(pQVar2 + 0x50) = uVar6;
  if ((local_1d == '\0') ||
     (((*(char *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0' &&
       (*(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) ||
      (iVar11 = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar8 = ThreadGetCurrentId(),
      iVar11 != iVar8)))) {
    return;
  }
  cVar7 = CVProfNode::ExitScope();
  if (cVar7 == '\0') {
    iVar11 = *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
  }
  else {
    iVar11 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
    *(int *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar11;
  }
LAB_007465e4:
  *(bool *)(*(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
       iVar11 == *(int *)(unaff_EBX + 0x460709 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ComputePathFollower
 * Address: 0075c880
 * ---------------------------------------- */

/* CINSNextBot::ComputePathFollower(Vector) */

undefined4 __cdecl
CINSNextBot::ComputePathFollower
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  Vector *pVVar1;
  bool bVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  CINSNavArea *this;
  CINSNavArea *this_00;
  Path *this_01;
  CINSRules *this_02;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_03;
  CINSNextBot *extraout_ECX_00;
  int unaff_EBX;
  float10 fVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  int local_44;
  Vector *local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75c88b;
  __i686_get_pc_thunk_bx();
  piVar5 = (int *)(*(int **)(unaff_EBX + 0x449c5d /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */))[7];
  if (piVar5 == *(int **)(unaff_EBX + 0x449c5d /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */)) {
    fVar6 = (float10)(float)((uint)piVar5 ^ piVar5[0xb]);
  }
  else {
    fVar6 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
  }
  local_44 = unaff_EBX + 0x437cc5 /* vtable for CINSNextBotPathCost+0x8 */ /* vtable for CINSNextBotPathCost+0x8 */ /* vtable for CINSNextBotPathCost+0x8 */;
  *(float *)(param_1 + 0xb290) = (float)fVar6;
  pVVar1 = (Vector *)(param_1 + 0x2060);
  uVar12 = 0;
  uVar11 = 1;
  uVar10 = 0;
  local_38 = param_2;
  uVar9 = 0x461c4000 /* 10000.0f */;
  uVar8 = 0;
  local_34 = param_3;
  local_3c = 1;
  local_2c = 0xffffffff;
  local_30 = param_4;
  puVar7 = &local_38;
  local_40 = pVVar1;
  iVar4 = CNavMesh::GetNearestNavArea();
  if ((iVar4 != 0) && (iVar4 = CINSNavArea::GetAssociatedControlPoint(this), iVar4 != -1)) {
    local_2c = CINSNavArea::GetAssociatedControlPoint(this_00);
  }
  piVar5 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))
                            (pVVar1,puVar7,uVar8,uVar9,uVar10,uVar11,uVar12);
  fVar6 = (float10)(**(code **)(*piVar5 + 0x14c))(piVar5);
  local_28 = (float)fVar6;
  piVar5 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pVVar1);
  fVar6 = (float10)(**(code **)(*piVar5 + 0x150))(piVar5);
  local_24 = (float)fVar6;
  piVar5 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pVVar1);
  fVar6 = (float10)(**(code **)(*piVar5 + 0x154))(piVar5);
  local_20 = (float)fVar6;
  fVar6 = (float10)MaxPathLength();
  bVar2 = Path::Compute<CINSNextBotPathCost>
                    (this_01,(INextBot *)(param_1 + 0x6b34),pVVar1,(CINSNextBotPathCost *)&param_2,
                     (float)&local_44,SUB41((float)fVar6,0));
  if (bVar2) {
    *(undefined4 *)(param_1 + 0xb324) = 0;
    return 1;
  }
  iVar4 = *(int *)(param_1 + 0xb324) + 1;
  *(int *)(param_1 + 0xb324) = iVar4;
  if (4 < iVar4) {
    Warning(unaff_EBX + 0x22a015 /* "Chase path failed generating, suiciding.
" */ /* "Chase path failed generating, suiciding.
" */ /* "Chase path failed generating, suiciding.
" */);
    cVar3 = CINSRules::IsOutpost(this_02);
    this_03 = extraout_ECX;
    if ((cVar3 == '\0') &&
       (cVar3 = CINSRules::IsEntrenchment(), this_03 = extraout_ECX_00, cVar3 == '\0')) {
      return 0;
    }
    KillSelf(this_03);
  }
  return 0;
}



/* ----------------------------------------
 * CINSNextBot::Event_Killed
 * Address: 00743e10
 * ---------------------------------------- */

/* CINSNextBot::Event_Killed(CTakeDamageInfo const&) */

void __thiscall CINSNextBot::Event_Killed(CINSNextBot *this,CTakeDamageInfo *param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  char cVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined4 *puVar11;
  CINSGrenadeTarget *pCVar12;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CINSNavArea *this_02;
  CINSPlayer *this_03;
  CINSRules *this_04;
  CINSRules *this_05;
  CBaseEntity *this_06;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *extraout_ECX_02;
  CBaseEntity *this_07;
  CINSNextBotManager *this_08;
  CBaseEntity *extraout_ECX_03;
  CBaseEntity *extraout_ECX_04;
  CBaseEntity *extraout_ECX_05;
  int unaff_EBX;
  float10 fVar13;
  float fVar14;
  double dVar15;
  int in_stack_00000008;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  if (((byte)param_1[0xd1] & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_00);
  }
  uVar1 = *(undefined4 *)(param_1 + 0x208);
  uVar2 = *(undefined4 *)(param_1 + 0x20c);
  uVar3 = *(undefined4 *)(param_1 + 0x210);
  iVar8 = (**(code **)(*(int *)param_1 + 0x548 /* CINSNextBot::GetLastKnownArea */))(param_1);
  if (iVar8 == 0) {
    iVar8 = 0;
    local_24 = 0.0;
  }
  else {
    iVar8 = __dynamic_cast(iVar8,*(undefined4 *)(unaff_EBX + 0x4627cd /* &typeinfo for CNavArea */ /* &typeinfo for CNavArea */ /* &typeinfo for CNavArea */),
                           *(undefined4 *)(unaff_EBX + 0x462e6d /* &typeinfo for CINSNavArea */ /* &typeinfo for CINSNavArea */ /* &typeinfo for CINSNavArea */),0);
    local_24 = 0.0;
    if (iVar8 != 0) {
      CBaseEntity::GetTeamNumber(this_01);
      fVar13 = (float10)CINSNavArea::GetDeathIntensity(this_02,iVar8);
      local_24 = (float)fVar13;
    }
  }
  (**(code **)(*(int *)(param_1 + 0x2060) + 0x44))(param_1 + 0x2060,in_stack_00000008);
  iVar10 = in_stack_00000008;
  CINSPlayer::Event_Killed(this_03,param_1);
  piVar9 = (int *)(**(code **)(*(int *)param_1 + 0x974 /* CINSNextBot::GetVisionInterface */))(param_1,iVar10);
  (**(code **)(*piVar9 + 0xf4 /* CINSBotVision::ForgetAllKnownEntities */))(piVar9);
  uVar5 = *(uint *)(in_stack_00000008 + 0x28);
  if ((((uVar5 != 0xffffffff) &&
       (iVar10 = **(int **)(unaff_EBX + 0x4629bd /* &g_pEntityList */ /* &g_pEntityList */ /* &g_pEntityList */) + (uVar5 & 0xffff) * 0x18,
       *(uint *)(iVar10 + 8) == uVar5 >> 0x10)) &&
      (piVar9 = *(int **)(iVar10 + 4), piVar9 != (int *)0x0)) &&
     ((cVar7 = (**(code **)(*piVar9 + 0x158))(piVar9), cVar7 != '\0' && (iVar8 != 0)))) {
    cVar7 = CINSRules::IsSoloMode();
    this_05 = this_04;
    if (cVar7 != '\0') {
      iVar8 = CINSRules::GetHumanTeam(this_04);
      iVar10 = CBaseEntity::GetTeamNumber(this_06);
      this_05 = (CINSRules *)extraout_ECX;
      if (iVar8 == iVar10) goto LAB_00743f78;
    }
    dVar15 = (double)local_24;
    if (*(double *)(unaff_EBX + 0x21082d /* rodata:0x33333333 */ /* rodata:0x33333333 */ /* rodata:0x33333333 */) <= dVar15 && dVar15 != *(double *)(unaff_EBX + 0x21082d /* rodata:0x33333333 */ /* rodata:0x33333333 */ /* rodata:0x33333333 */))
    {
      if ((*(byte *)((int)piVar9 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_05);
      }
      puVar11 = (undefined4 *)::operator_new(0x24);
      puVar6 = puVar11 + 1;
      puVar11[2] = 0;
      puVar11[1] = unaff_EBX + 0x3e439d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
      CountdownTimer::NetworkStateChanged(puVar6);
      puVar11[3] = 0xbf800000 /* -1.0f */;
      (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 3);
      puVar11[4] = uVar1;
      puVar11[5] = uVar2;
      puVar11[6] = uVar3;
      fVar13 = (float10)CountdownTimer::Now();
      fVar14 = (float)fVar13 + *(float *)(unaff_EBX + 0x1e0395 /* 10.0f */ /* 10.0f */ /* 10.0f */);
      this_07 = extraout_ECX_03;
      if ((float)puVar11[3] != fVar14) {
        (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 3);
        puVar11[3] = fVar14;
        this_07 = extraout_ECX_04;
      }
      if (puVar11[2] != 0x41200000 /* 10.0f */) {
        (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 2);
        puVar11[2] = 0x41200000 /* 10.0f */;
        this_07 = extraout_ECX_05;
      }
      *(undefined1 *)(puVar11 + 7) = 0;
      *(undefined1 *)((int)puVar11 + 0x1d) = 0;
      *puVar11 = 2;
    }
    else {
      if (dVar15 < *(double *)(unaff_EBX + 0x1e095d /* rodata:0x33333333 */ /* rodata:0x33333333 */ /* rodata:0x33333333 */) || dVar15 == *(double *)(unaff_EBX + 0x1e095d /* rodata:0x33333333 */ /* rodata:0x33333333 */ /* rodata:0x33333333 */))
      goto LAB_00743f78;
      if ((*(byte *)((int)piVar9 + 0xd1) & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_05);
      }
      puVar11 = (undefined4 *)::operator_new(0x24);
      puVar6 = puVar11 + 1;
      iVar8 = piVar9[0x82];
      iVar10 = piVar9[0x83];
      iVar4 = piVar9[0x84];
      puVar11[1] = unaff_EBX + 0x3e439d /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */ /* vtable for CountdownTimer+0x8 */;
      puVar11[2] = 0;
      CountdownTimer::NetworkStateChanged(puVar6);
      puVar11[3] = 0xbf800000 /* -1.0f */;
      (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 3);
      puVar11[4] = iVar8;
      puVar11[5] = iVar10;
      puVar11[6] = iVar4;
      fVar13 = (float10)CountdownTimer::Now();
      fVar14 = (float)fVar13 + *(float *)(unaff_EBX + 0x1e0395 /* 10.0f */ /* 10.0f */ /* 10.0f */);
      this_07 = extraout_ECX_00;
      if ((float)puVar11[3] != fVar14) {
        (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 3);
        puVar11[3] = fVar14;
        this_07 = extraout_ECX_01;
      }
      if (puVar11[2] != 0x41200000 /* 10.0f */) {
        (**(code **)(puVar11[1] + 4))(puVar6,puVar11 + 2);
        puVar11[2] = 0x41200000 /* 10.0f */;
        this_07 = extraout_ECX_02;
      }
      *(undefined1 *)(puVar11 + 7) = 0;
      *(undefined1 *)((int)puVar11 + 0x1d) = 0;
      *puVar11 = 0xd;
    }
    puVar11[8] = 0x42c80000 /* 100.0f */;
    pCVar12 = (CINSGrenadeTarget *)CBaseEntity::GetTeamNumber(this_07);
    iVar8 = TheINSNextBots();
    CINSNextBotManager::AddGrenadeTarget(this_08,iVar8,pCVar12);
  }
LAB_00743f78:
  *(undefined4 *)(param_1 + 0x21a4) = 0;
  puVar6 = *(undefined4 **)(unaff_EBX + 0x4627b1 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *(undefined4 *)(param_1 + 0x21b4) = 0;
  uVar1 = *puVar6;
  uVar2 = puVar6[1];
  uVar3 = puVar6[2];
  *(undefined4 *)(param_1 + 0x2198) = uVar1;
  *(undefined4 *)(param_1 + 0x219c) = uVar2;
  *(undefined4 *)(param_1 + 0x21a0) = uVar3;
  *(undefined4 *)(param_1 + 0x21a8) = uVar1;
  *(undefined4 *)(param_1 + 0x21ac) = uVar2;
  *(undefined4 *)(param_1 + 0x21b0) = uVar3;
  return;
}



/* ----------------------------------------
 * CINSNextBot::EyePosition
 * Address: 00759e70
 * ---------------------------------------- */

/* CINSNextBot::EyePosition() */

undefined4 __thiscall CINSNextBot::EyePosition(CINSNextBot *this)

{
  undefined4 in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  CINSPlayer::EyePosition();
  return in_stack_00000004;
}



/* ----------------------------------------
 * CINSNextBot::FindNearbyCoverPosition
 * Address: 00748b30
 * ---------------------------------------- */

/* CINSNextBot::FindNearbyCoverPosition(float) */

undefined4 __thiscall CINSNextBot::FindNearbyCoverPosition(CINSNextBot *this,float param_1)

{
  CNavArea *pCVar1;
  undefined4 uVar2;
  int iVar3;
  CBaseEntity *this_00;
  float in_stack_00000008;
  float local_42c [2];
  undefined4 auStack_424 [256];
  int local_24;
  
  __i686_get_pc_thunk_bx();
  pCVar1 = (CNavArea *)(**(code **)(*(int *)param_1 + 0x548 /* CINSNextBot::GetLastKnownArea */))(param_1);
  uVar2 = 0;
  if (pCVar1 != (CNavArea *)0x0) {
    local_42c[0] = param_1;
    local_24 = 0;
    if ((*(byte *)((int)param_1 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
    }
    SearchSurroundingAreas<CollectRetreatSpotsFunctor>
              (pCVar1,(Vector *)((int)param_1 + 0x208),(CollectRetreatSpotsFunctor *)local_42c,
               in_stack_00000008,0,-1);
    uVar2 = 0;
    if (local_24 != 0) {
      iVar3 = RandomInt(0,local_24 + -1);
      uVar2 = auStack_424[iVar3];
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSNextBot::FindNearbyRetreatArea
 * Address: 007451c0
 * ---------------------------------------- */

/* CINSNextBot::FindNearbyRetreatArea(float) */

undefined4 __thiscall CINSNextBot::FindNearbyRetreatArea(CINSNextBot *this,float param_1)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  CNavArea *this_00;
  CNavArea *extraout_ECX;
  CNavArea *extraout_ECX_00;
  CNavArea *extraout_ECX_01;
  CNavArea *this_01;
  int unaff_EBX;
  undefined4 uVar5;
  float fVar6;
  float in_stack_00000008;
  int local_3c;
  float local_38;
  int local_34;
  undefined4 local_30;
  int local_2c;
  int local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x7451cb;
  __i686_get_pc_thunk_bx();
  iVar3 = (**(code **)(*(int *)param_1 + 0x548 /* CINSNextBot::GetLastKnownArea */))(param_1);
  if (iVar3 == 0) {
    return 0;
  }
  local_38 = param_1;
  piVar1 = *(int **)(unaff_EBX + 0x461611 /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */);
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0;
  local_24 = 0;
  local_20 = 9999;
  iVar4 = 1;
  if (*piVar1 + 1 != 0) {
    iVar4 = *piVar1 + 1;
  }
  *piVar1 = iVar4;
  local_3c = unaff_EBX + 0x457a5d /* vtable for CINSSearchForCover+0x8 */ /* vtable for CINSSearchForCover+0x8 */ /* vtable for CINSSearchForCover+0x8 */;
  CNavArea::ClearSearchLists();
  CNavArea::AddToOpenList(this_00);
  iVar4 = *piVar1;
  *(undefined4 *)(iVar3 + 0x50) = 0;
  *(undefined4 *)(iVar3 + 0x54) = 0;
  piVar1 = *(int **)(unaff_EBX + 0x461b7d /* &CNavArea::m_openList */ /* &CNavArea::m_openList */ /* &CNavArea::m_openList */);
  *(undefined4 *)(iVar3 + 0x88) = 0;
  *(undefined4 *)(iVar3 + 0x8c) = 9;
  *(int *)(iVar3 + 100) = iVar4;
  this_01 = extraout_ECX;
  do {
    if (0.0 < in_stack_00000008) {
      do {
        iVar3 = *piVar1;
        if (iVar3 == 0) goto LAB_00745330;
        CNavArea::RemoveFromOpenList(this_01);
        fVar6 = *(float *)(iVar3 + 0x54);
        *(undefined4 *)(iVar3 + 0x5c) = 0;
        *(undefined4 *)(iVar3 + 0x58) = 0;
        this_01 = extraout_ECX_00;
      } while (in_stack_00000008 < fVar6);
    }
    else {
      iVar3 = *piVar1;
      if (iVar3 == 0) {
LAB_00745330:
        (**(code **)(local_3c + 0x14))(&local_3c);
        if (local_28 == 0) {
          uVar5 = 0;
        }
        else {
          iVar3 = 10;
          if (local_28 < 0xb) {
            iVar3 = local_28;
          }
          iVar3 = RandomInt(0,iVar3 + -1);
          uVar5 = *(undefined4 *)(local_34 + iVar3 * 4);
        }
        local_28 = 0;
        if (local_2c < 0) {
          return uVar5;
        }
        if (local_34 == 0) {
          return uVar5;
        }
        local_3c = unaff_EBX + 0x457a5d /* vtable for CINSSearchForCover+0x8 */ /* vtable for CINSSearchForCover+0x8 */ /* vtable for CINSSearchForCover+0x8 */;
        (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4616ad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                  ((int *)**(undefined4 **)(unaff_EBX + 0x4616ad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),local_34);
        return uVar5;
      }
      CNavArea::RemoveFromOpenList(this_01);
      *(undefined4 *)(iVar3 + 0x5c) = 0;
      fVar6 = *(float *)(iVar3 + 0x54);
      *(undefined4 *)(iVar3 + 0x58) = 0;
    }
    cVar2 = (**(code **)(local_3c + 8))(&local_3c,iVar3,*(undefined4 *)(iVar3 + 0x88),fVar6);
    if (cVar2 == '\0') goto LAB_00745330;
    (**(code **)(local_3c + 0x10))
              (&local_3c,iVar3,*(undefined4 *)(iVar3 + 0x88),*(undefined4 *)(iVar3 + 0x54));
    this_01 = extraout_ECX_01;
  } while( true );
}



/* ----------------------------------------
 * CINSNextBot::FindNearbyRetreatPosition
 * Address: 007453f0
 * ---------------------------------------- */

/* CINSNextBot::FindNearbyRetreatPosition(float) */

float __thiscall CINSNextBot::FindNearbyRetreatPosition(CINSNextBot *this,float param_1)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int iVar3;
  CINSNextBot *this_00;
  int unaff_EBX;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  iVar3 = FindNearbyRetreatArea(this_00,in_stack_00000008);
  if (iVar3 != 0) {
    *(undefined4 *)param_1 = *(undefined4 *)(iVar3 + 0x2c);
    uVar1 = *(undefined4 *)(iVar3 + 0x34);
    *(undefined4 *)((int)param_1 + 4) = *(undefined4 *)(iVar3 + 0x30);
    *(undefined4 *)((int)param_1 + 8) = uVar1;
    return param_1;
  }
  puVar2 = *(undefined4 **)(unaff_EBX + 0x4611cb /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *(undefined4 *)param_1 = *puVar2;
  uVar1 = puVar2[2];
  *(undefined4 *)((int)param_1 + 4) = puVar2[1];
  *(undefined4 *)((int)param_1 + 8) = uVar1;
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::FireActiveWeapon
 * Address: 0076ee60
 * ---------------------------------------- */

/* CINSNextBot::FireActiveWeapon(CINSNextBot*, CKnownEntity const*) */

void __thiscall
CINSNextBot::FireActiveWeapon(CINSNextBot *this,CINSNextBot *param_1,CKnownEntity *param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  code *pcVar5;
  char cVar6;
  int *piVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  CBaseEntity *this_00;
  CINSRules *this_01;
  CINSPlayer *this_02;
  int unaff_EBX;
  bool bVar13;
  float10 fVar14;
  float10 fVar15;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c == (int *)0x0) {
    return;
  }
  cVar6 = (**(code **)(*(int *)param_2 + 0x118))(param_2);
  if (cVar6 == '\0') {
    return;
  }
  piVar7 = (int *)(**(code **)(*in_stack_0000000c + 0x10))();
  if ((piVar7 != (int *)0x0) && (cVar6 = (**(code **)(*piVar7 + 0x118 /* CBaseEntity::IsAlive */))(piVar7), cVar6 == '\0')) {
    return;
  }
  piVar7 = (int *)CINSPlayer::GetActiveINSWeapon();
  if (piVar7 == (int *)0x0) {
    return;
  }
  puVar1 = *(undefined4 **)(unaff_EBX + 0x437752 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  uVar2 = *puVar1;
  uVar3 = puVar1[1];
  uVar4 = puVar1[2];
  uVar8 = (**(code **)(*in_stack_0000000c + 0x18))();
  uVar9 = (**(code **)(*(int *)this_02 + 0x974 /* CINSNextBot::GetVisionInterface */))(this_02);
  cVar6 = CINSBotVision::IsLineOfFireClear(uVar9,uVar8,uVar2,uVar3,uVar4);
  if (cVar6 == '\0') {
    (**(code **)(*(int *)this_02 + 0x8c4 /* NextBotPlayer::ReleaseFireButton */))(this_02);
    return;
  }
  iVar10 = (**(code **)(*piVar7 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar7);
  if ((iVar10 == 0xb) || (iVar10 == 0xe)) {
    uVar11 = CINSPlayer::GetPlayerFlags(this_02);
    if ((uVar11 & 1) == 0) {
      (**(code **)(*(int *)this_02 + 0x95c /* CINSNextBot::PressIronsightButton */))(this_02,0x3f800000 /* 1.0f */);
      return;
    }
  }
  else if (iVar10 == 7) {
    return;
  }
  cVar6 = CINSRules::IsSoloMode();
  bVar13 = false;
  if (cVar6 != '\0') {
    iVar10 = CBaseEntity::GetTeamNumber(this_00);
    iVar12 = CINSRules::GetHumanTeam(this_01);
    bVar13 = iVar10 == iVar12;
  }
  uVar11 = (**(code **)(*piVar7 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar7);
  if (uVar11 < 0xf) {
                    /* WARNING: Could not recover jumptable at 0x0076f071. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)(*(int *)(&UNK_002186e2 + uVar11 * 4 + unaff_EBX) + unaff_EBX + 0x4382fe /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */))();
    return;
  }
  pcVar5 = *(code **)(*(int *)this_02 + 0x8c0);
  if (bVar13) {
    piVar7 = *(int **)(unaff_EBX + 0x5837e2 /* bot_attack_burst_maxtime_solo+0x1c */ /* bot_attack_burst_maxtime_solo+0x1c */ /* bot_attack_burst_maxtime_solo+0x1c */);
    if (piVar7 == (int *)(unaff_EBX + 0x5837c6 /* bot_attack_burst_maxtime_solo */ /* bot_attack_burst_maxtime_solo */ /* bot_attack_burst_maxtime_solo */U)) {
      fVar14 = (float10)(float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x5837f2 /* bot_attack_burst_maxtime_solo+0x2c */ /* bot_attack_burst_maxtime_solo+0x2c */ /* bot_attack_burst_maxtime_solo+0x2c */));
    }
    else {
      fVar14 = (float10)(**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
    }
    piVar7 = *(int **)(unaff_EBX + 0x583842 /* bot_attack_burst_mintime_solo+0x1c */ /* bot_attack_burst_mintime_solo+0x1c */ /* bot_attack_burst_mintime_solo+0x1c */);
    if (piVar7 == (int *)(unaff_EBX + 0x583826 /* bot_attack_burst_mintime_solo */ /* bot_attack_burst_mintime_solo */ /* bot_attack_burst_mintime_solo */)) {
      fVar15 = (float10)(float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x583852 /* bot_attack_burst_mintime_solo+0x2c */ /* bot_attack_burst_mintime_solo+0x2c */ /* bot_attack_burst_mintime_solo+0x2c */));
      goto LAB_0076eff4;
    }
  }
  else {
    piVar7 = *(int **)(unaff_EBX + 0x583e42 /* bot_attack_burst_maxtime+0x1c */ /* bot_attack_burst_maxtime+0x1c */ /* bot_attack_burst_maxtime+0x1c */);
    if (piVar7 == (int *)(unaff_EBX + 0x583e26 /* bot_attack_burst_maxtime */ /* bot_attack_burst_maxtime */ /* bot_attack_burst_maxtime */U)) {
      fVar14 = (float10)(float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x583e52 /* bot_attack_burst_maxtime+0x2c */ /* bot_attack_burst_maxtime+0x2c */ /* bot_attack_burst_maxtime+0x2c */));
    }
    else {
      fVar14 = (float10)(**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
    }
    piVar7 = *(int **)(unaff_EBX + 0x583ea2 /* bot_attack_burst_mintime+0x1c */ /* bot_attack_burst_mintime+0x1c */ /* bot_attack_burst_mintime+0x1c */);
    if (piVar7 == (int *)(unaff_EBX + 0x583e86 /* bot_attack_burst_mintime */ /* bot_attack_burst_mintime */ /* bot_attack_burst_mintime */U)) {
      fVar15 = (float10)(float)((uint)piVar7 ^ *(uint *)(unaff_EBX + 0x583eb2 /* bot_attack_burst_mintime+0x2c */ /* bot_attack_burst_mintime+0x2c */ /* bot_attack_burst_mintime+0x2c */));
      goto LAB_0076eff4;
    }
  }
  fVar15 = (float10)(**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
  fVar14 = (float10)(float)fVar14;
LAB_0076eff4:
  fVar14 = (float10)RandomFloat((float)fVar15,(float)fVar14);
  (*pcVar5)(this_02,(float)fVar14);
  return;
}



/* ----------------------------------------
 * CINSNextBot::FireWeaponAtEnemy
 * Address: 0075ae70
 * ---------------------------------------- */

/* CINSNextBot::FireWeaponAtEnemy() */

void __thiscall CINSNextBot::FireWeaponAtEnemy(CINSNextBot *this)

{
  int *piVar1;
  code *pcVar2;
  bool bVar3;
  char cVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  float fVar9;
  int iVar10;
  float *pfVar11;
  CKnownEntity *pCVar12;
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  CINSPlayer *this_02;
  CountdownTimer *extraout_ECX;
  CINSNextBot *this_03;
  CINSNextBot *this_04;
  CBaseEntity *this_05;
  CBaseEntity *extraout_ECX_00;
  CINSPlayer *this_06;
  CINSPlayer *this_07;
  CINSPlayer *this_08;
  CINSPlayer *this_09;
  CINSRules *this_10;
  CINSNextBot *this_11;
  CINSNextBot *this_12;
  CINSPlayer *this_13;
  CINSNextBot *this_14;
  CBaseEntity *extraout_ECX_01;
  CBaseEntity *pCVar13;
  CBaseEntity *this_15;
  CBaseEntity *this_16;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *pCVar14;
  CINSNextBot *extraout_ECX_03;
  CINSPlayer *pCVar15;
  CountdownTimer *extraout_ECX_04;
  CountdownTimer *this_17;
  CountdownTimer *this_18;
  CINSNextBot *extraout_ECX_05;
  CINSNextBot *extraout_ECX_06;
  CINSNextBot *extraout_ECX_07;
  CINSPlayer *extraout_ECX_08;
  CINSNextBot *extraout_ECX_09;
  CINSBotVision *this_19;
  CBaseEntity *extraout_ECX_10;
  int unaff_EBX;
  float10 fVar16;
  float10 fVar17;
  float fVar18;
  CINSWeapon *pCVar19;
  float fVar20;
  float fVar21;
  double dVar22;
  CINSWeapon *in_stack_00000004;
  undefined8 uVar23;
  undefined4 uVar24;
  float local_60;
  float local_5c;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x118 /* CBaseEntity::IsAlive */))();
  if (cVar4 == '\0') {
    return;
  }
  if (((byte)in_stack_00000004[0x2294] & 2) != 0) {
    return;
  }
  if ((*(int *)(in_stack_00000004 + 0xb338) == -1) ||
     (iVar6 = UTIL_EntityByIndex(*(int *)(in_stack_00000004 + 0xb338)), iVar6 == 0)) {
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar7 = (int *)(**(code **)(*piVar7 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))();
    if (piVar7 == (int *)0x0) {
      return;
    }
    iVar6 = (**(code **)(*piVar7 + 0x10))();
    if (iVar6 == 0) {
      return;
    }
  }
  piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
  piVar7 = (int *)(**(code **)(*piVar7 + 0xe4 /* IVision::GetKnown */))();
  if (piVar7 == (int *)0x0) {
    return;
  }
  cVar4 = CINSPlayer::IsSprinting(this_00);
  if (cVar4 != '\0') {
    return;
  }
  cVar4 = CINSPlayer::IsInAir(this_01);
  if (cVar4 != '\0') {
    return;
  }
  cVar4 = CINSPlayer::HasPlayerFlag(this_02,(int)in_stack_00000004);
  if (cVar4 != '\0') {
    piVar7 = (int *)(*(int **)(&DAT_0044c11d + unaff_EBX))[7];
    this_17 = extraout_ECX;
    if (piVar7 != *(int **)(&DAT_0044c11d + unaff_EBX)) {
      (**(code **)(*piVar7 + 0x3c))();
      this_17 = extraout_ECX_04;
    }
    CountdownTimer::Start(this_17,(float)(in_stack_00000004 + 0xb3b8));
    return;
  }
  if ((0.0 < *(float *)(in_stack_00000004 + 0xb3c0)) &&
     (fVar16 = (float10)CountdownTimer::Now(),
     (float)fVar16 < *(float *)(in_stack_00000004 + 0xb3c0) || /* !timer_25.IsElapsed() */
     (float)fVar16 == *(float *)(in_stack_00000004 + 0xb3c0))) {
    return;
  }
  iVar6 = (**(code **)(*piVar7 + 0x10))();
  if (iVar6 == 0) {
    return;
  }
  cVar4 = CanAttackTarget(this_03,(CKnownEntity *)in_stack_00000004);
  if (cVar4 == '\0') {
    return;
  }
  fVar16 = (float10)CountdownTimer::Now();
  if (*(float *)(in_stack_00000004 + 0xb3a8) <= (float)fVar16 && /* timer_23.IsElapsed() */
      (float)fVar16 != *(float *)(in_stack_00000004 + 0xb3a8)) {
    ChooseBestWeapon(this_04,(CKnownEntity *)in_stack_00000004);
    CountdownTimer::Start(this_18,(float)(in_stack_00000004 + 0xb3a0));
  }
  cVar4 = CanIAttack();
  if (cVar4 == '\0') {
    return;
  }
  iVar6 = CINSPlayer::GetActiveINSWeapon();
  if (iVar6 == 0) {
    return;
  }
  fVar16 = (float10)(**(code **)(*piVar7 + 0x40))();
  uVar8 = (**(code **)(*piVar7 + 0x38))();
  fVar9 = (float)(uVar8 & 0xff);
  iVar10 = (**(code **)(*piVar7 + 0x10))();
  pCVar19 = *(CINSWeapon **)(unaff_EBX + 0x15dc89 /* -1.0f */ /* -1.0f */ /* -1.0f */);
  if (iVar10 != 0) {
    pCVar13 = this_05;
    if ((*(byte *)(iVar10 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_05);
      pCVar13 = extraout_ECX_00;
    }
    if (((byte)in_stack_00000004[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(pCVar13);
    }
    fVar21 = *(float *)(in_stack_00000004 + 0x208) - *(float *)(iVar10 + 0x208);
    fVar18 = *(float *)(in_stack_00000004 + 0x20c) - *(float *)(iVar10 + 0x20c);
    fVar20 = *(float *)(in_stack_00000004 + 0x210) - *(float *)(iVar10 + 0x210);
    pCVar19 = (CINSWeapon *)SQRT(fVar18 * fVar18 + fVar21 * fVar21 + fVar20 * fVar20);
  }
  fVar17 = (float10)GetAttackDelay((float)in_stack_00000004,pCVar19,SUB41(iVar6,0));
  if ((float)fVar16 <= (float)fVar17) {
    return;
  }
  fVar16 = (float10)CINSPlayer::GetSuppressionFrac(this_06);
  if (*(float *)(CBaseAchievement::~CBaseAchievement + unaff_EBX + 1) <= (float)fVar16 &&
      (float)fVar16 != *(float *)(CBaseAchievement::~CBaseAchievement + unaff_EBX + 1)) {
    fVar16 = (float10)CINSPlayer::GetSuppressionFrac(this_07);
    if ((float)fVar16 <= *(float *)(unaff_EBX + 0x1c98c5 /* 0.3f */ /* 0.3f */ /* 0.3f */)) {
      fVar16 = (float10)CINSPlayer::GetSuppressionFrac(this_08);
      local_5c = *(float *)(GetSequenceActivity + unaff_EBX + 1) - (float)fVar16;
      pCVar15 = extraout_ECX_08;
    }
    else {
      local_5c = *(float *)(unaff_EBX + 0x1c9d5d /* 0.2f */ /* 0.2f */ /* 0.2f */);
      pCVar15 = this_08;
    }
    fVar16 = (float10)CINSPlayer::GetSuppressionFrac(pCVar15);
    if ((float)fVar16 <= *(float *)(&DAT_0022ba6d + unaff_EBX)) {
      fVar16 = (float10)CINSPlayer::GetSuppressionFrac(this_09);
      local_60 = *(float *)(CBaseDetonator::GetDetonateSound + unaff_EBX + 1) - (float)fVar16;
      pCVar15 = (CINSPlayer *)extraout_ECX_05;
    }
    else {
      local_60 = *(float *)(unaff_EBX + 0x1ca181 /* 0.7f */ /* 0.7f */ /* 0.7f */);
      pCVar15 = this_09;
    }
    uVar8 = GetDifficulty((CINSNextBot *)pCVar15);
    if (uVar8 < 4) {
      fVar18 = *(float *)(unaff_EBX + 0x22ba45 /* CSWTCH.663 */ /* CSWTCH.663 */ /* CSWTCH.663 */ + uVar8 * 4);
    }
    else {
      fVar18 = *(float *)(unaff_EBX + 0x15dc8d /* 1.0f */ /* 1.0f */ /* 1.0f */);
    }
    piVar1 = *(int **)(unaff_EBX + 0x44ba71 /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
    if ((*piVar1 != 0) && (cVar4 = CINSRules::IsSurvival(this_10), cVar4 != '\0')) {
      fVar16 = (float10)RemapValClamped((float)*(int *)(*piVar1 + 1000),1.0,13.0,1.0,1.5);
      fVar18 = fVar18 * (float)fVar16;
    }
    iVar6 = 0x40400000 /* 3.0f */;
    fVar20 = local_5c * fVar18;
    fVar18 = fVar18 * local_60;
    fVar9 = fVar20;
    fVar16 = (float10)RemapValClamped(1.0,0.0,3.0,fVar20,fVar18);
    local_5c = (float)fVar16;
    iVar10 = GetDifficulty(this_11);
    if (iVar10 == 2) {
      iVar6 = 0x40400000 /* 3.0f */;
      fVar16 = (float10)RemapValClamped(2.0,0.0,3.0,fVar20,fVar18);
      local_5c = (float)fVar16;
      fVar9 = fVar20;
    }
    else if (iVar10 == 3) {
      iVar6 = 0x40400000 /* 3.0f */;
      fVar16 = (float10)RemapValClamped(3.0,0.0,3.0,fVar20,fVar18);
      local_5c = (float)fVar16;
      fVar9 = fVar20;
    }
    else if (iVar10 == 0) {
      iVar6 = 0x40400000 /* 3.0f */;
      fVar16 = (float10)RemapValClamped(0.0,0.0,3.0,fVar20,fVar18);
      local_5c = (float)fVar16;
      fVar9 = fVar20;
    }
    fVar16 = (float10)RandomFloat();
    if (local_5c < (float)fVar16) {
      return;
    }
  }
  pfVar11 = &local_4c;
  uVar23 = CONCAT44(iVar6,in_stack_00000004);
  (**(code **)(*(int *)in_stack_00000004 + 0x20c /* CINSNextBot::EyePosition */))();
  cVar4 = (**(code **)(*piVar7 + 0x38))(piVar7,pfVar11,uVar23,fVar9);
  uVar24 = (undefined4)((ulonglong)uVar23 >> 0x20);
  if (cVar4 == '\0') {
    uVar23 = CONCAT44(uVar24,piVar7);
    pCVar19 = in_stack_00000004;
    GetSuppressingOffset((CKnownEntity *)&local_34);
    pfVar11 = (float *)(**(code **)(*piVar7 + 0x14))(piVar7,pCVar19,uVar23);
    uVar24 = (undefined4)((ulonglong)uVar23 >> 0x20);
    local_40 = local_34 + *pfVar11;
    local_3c = local_30 + pfVar11[1];
    local_38 = local_2c + pfVar11[2];
  }
  else {
    GetEntityViewPosition((CBaseEntity *)&local_40);
  }
  local_24 = local_3c - local_48;
  local_20 = local_38 - local_44;
  local_28 = local_40 - local_4c;
  fVar16 = (float10)VectorNormalize((Vector *)&local_28);
  fVar9 = (float)fVar16;
  fVar16 = (float10)GetMaxAttackRange(this_12,in_stack_00000004);
  if ((float)fVar16 < fVar9) {
    return;
  }
  iVar6 = (**(code **)(**(int **)(unaff_EBX + 0x44b6c5 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */) + 0x40))(*(int **)(unaff_EBX + 0x44b6c5 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */));
  pCVar15 = this_13;
  if (iVar6 != 0) goto LAB_0075b56c;
  local_60._0_1_ = CINSPlayer::GetPlayerFlags(this_13);
  local_60._0_1_ = local_60._0_1_ & 1;
  pcVar2 = *(code **)(*(int *)in_stack_00000004 + 0x434);
  (**(code **)(*piVar7 + 0x14))(piVar7);
  uVar23 = CONCAT44(uVar24,0x3f666666 /* 0.9f */);
  cVar4 = (*pcVar2)();
  fVar16 = (float10)GetMaxHipFireAttackRange(this_14,in_stack_00000004);
  if ((float)fVar16 <= fVar9) {
    cVar5 = (**(code **)(*piVar7 + 0x38))(piVar7);
    pCVar14 = extraout_ECX_06;
    if ((cVar5 != '\0') && (cVar4 != '\0')) {
      (**(code **)(*(int *)in_stack_00000004 + 0x95c /* CINSNextBot::PressIronsightButton */))();
      pCVar14 = extraout_ECX_07;
    }
    fVar16 = (float10)GetMaxAttackRange(pCVar14,in_stack_00000004);
    if ((*(float *)(GetSequenceActivity + unaff_EBX + 1) <= fVar9 / (float)fVar16 &&
         fVar9 / (float)fVar16 != *(float *)(GetSequenceActivity + unaff_EBX + 1)) &&
       (local_60._0_1_ == 0)) {
      return;
    }
  }
  else if ((local_60._0_1_ == 0) && (cVar4 != '\0')) {
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x97c /* CINSNextBot::GetIntentionInterface */))();
    iVar6 = (**(code **)(*piVar7 + 0xec /* IIntention::ShouldIronsight */))(piVar7,in_stack_00000004 + 0x2060,uVar23);
    if (iVar6 == 1) {
      (**(code **)(*(int *)in_stack_00000004 + 0x95c /* CINSNextBot::PressIronsightButton */))();
    }
  }
  if (fVar9 < *(float *)(unaff_EBX + 0x1d27fd /* 500.0f */ /* 500.0f */ /* 500.0f */)) {
    fVar18 = *(float *)(unaff_EBX + 0x1c98c5 /* 0.3f */ /* 0.3f */ /* 0.3f */);
  }
  else if (*(float *)(unaff_EBX + 0x1fbefd /* 3000.0f */ /* 3000.0f */ /* 3000.0f */) <= fVar9 && fVar9 != *(float *)(unaff_EBX + 0x1fbefd /* 3000.0f */ /* 3000.0f */ /* 3000.0f */)) {
    fVar18 = *(float *)(unaff_EBX + 0x1c8c09 /* 0.75f */ /* 0.75f */ /* 0.75f */);
  }
  else {
    fVar18 = (fVar9 + *(float *)(unaff_EBX + 0x22ba75 /* CSWTCH.663+0x30 */ /* CSWTCH.663+0x30 */ /* CSWTCH.663+0x30 */)) * *(float *)(unaff_EBX + 0x22ba79 /* CSWTCH.663+0x34 */ /* CSWTCH.663+0x34 */ /* CSWTCH.663+0x34 */) +
             *(float *)(unaff_EBX + 0x1c98c5 /* 0.3f */ /* 0.3f */ /* 0.3f */);
  }
  if (fVar9 < *(float *)(unaff_EBX + 0x1ca199 /* 150.0f */ /* 150.0f */ /* 150.0f */)) {
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
    cVar4 = (**(code **)(*piVar7 + 0x118 /* IVision::IsInFieldOfView */))(piVar7);
    bVar3 = true;
    if (cVar4 == '\0') goto LAB_0075b40b;
  }
  else {
LAB_0075b40b:
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))();
    cVar4 = (**(code **)(*piVar7 + 0xe0 /* PlayerBody::IsHeadSteady */))(piVar7);
    if (cVar4 == '\0') {
      return;
    }
    piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))();
    fVar16 = (float10)(**(code **)(*piVar7 + 0xe4 /* PlayerBody::GetHeadSteadyDuration */))(piVar7);
    if ((float)fVar16 < fVar18) {
      return;
    }
    bVar3 = false;
  }
  iVar6 = TheINSNextBots();
  pCVar13 = extraout_ECX_01;
  if (*(char *)(iVar6 + 0x129) != '\0') {
    pCVar12 = (CKnownEntity *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
    cVar4 = CINSBotVision::CanReadSilhouette(this_19,pCVar12);
    pCVar13 = extraout_ECX_10;
    if (cVar4 == '\0') {
      return;
    }
  }
  pfVar11 = (float *)CBaseEntity::WorldAlignSize(pCVar13);
  fVar18 = *pfVar11;
  iVar6 = CBaseEntity::WorldAlignSize(this_15);
  if (fVar18 < *(float *)(iVar6 + 4) || fVar18 == *(float *)(iVar6 + 4)) {
    iVar6 = CBaseEntity::WorldAlignSize(this_16);
    fVar18 = *(float *)(iVar6 + 4);
    pCVar14 = extraout_ECX_09;
  }
  else {
    pfVar11 = (float *)CBaseEntity::WorldAlignSize(this_16);
    fVar18 = *pfVar11;
    pCVar14 = extraout_ECX_02;
  }
  fVar16 = (float10)GetAimToleranceBloat(pCVar14,(CKnownEntity *)in_stack_00000004);
  dVar22 = atan((double)(((float)fVar16 * fVar18 *
                         *(float *)(CGameRules::NumEntityClasses + unaff_EBX + 1)) / fVar9));
  dVar22 = cos(dVar22);
  piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))();
  pfVar11 = (float *)(**(code **)(*piVar7 + 0xd0 /* CINSBotBody::GetViewVector */))(piVar7);
  pCVar15 = (CINSPlayer *)extraout_ECX_03;
  if ((!bVar3) &&
     (local_24 * pfVar11[1] + local_28 * *pfVar11 + local_20 * pfVar11[2] < (float)dVar22)) {
    return;
  }
LAB_0075b56c:
  FireActiveWeapon((CINSNextBot *)pCVar15,(CINSNextBot *)in_stack_00000004,
                   (CKnownEntity *)in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetActiveWeaponAmmoRatio
 * Address: 0076dc40
 * ---------------------------------------- */

/* CINSNextBot::GetActiveWeaponAmmoRatio() */

float10 CINSNextBot::GetActiveWeaponAmmoRatio(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  
  __i686_get_pc_thunk_bx();
  piVar1 = (int *)CINSPlayer::GetActiveINSWeapon();
  fVar4 = 0.0;
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(*piVar1 + 0x560 /* CBaseCombatCharacter::OnPursuedBy */))(piVar1);
    iVar3 = (**(code **)(*piVar1 + 0x510 /* CBaseCombatCharacter::ExitVehicle */))(piVar1);
    fVar4 = (float)iVar2 / (float)iVar3;
  }
  return (float10)fVar4;
}



/* ----------------------------------------
 * CINSNextBot::GetAimToleranceBloat
 * Address: 0075aa50
 * ---------------------------------------- */

/* CINSNextBot::GetAimToleranceBloat(CKnownEntity const*) */

float10 __thiscall CINSNextBot::GetAimToleranceBloat(CINSNextBot *this,CKnownEntity *param_1)

{
  char cVar1;
  int iVar2;
  int *piVar3;
  float *pfVar4;
  int iVar5;
  float fVar6;
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  CINSRules *this_03;
  CBaseEntity *this_04;
  CINSRules *this_05;
  int unaff_EBX;
  float10 fVar7;
  float10 fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  int *in_stack_00000008;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  iVar2 = GetDifficulty(this_00);
  if (iVar2 == 1) {
LAB_0075aa9d:
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x44c6f5 /* &bot_attack_aimtolerance_frac_normal */ /* &bot_attack_aimtolerance_frac_normal */ /* &bot_attack_aimtolerance_frac_normal */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x44c6f5 /* &bot_attack_aimtolerance_frac_normal */ /* &bot_attack_aimtolerance_frac_normal */ /* &bot_attack_aimtolerance_frac_normal */)) {
LAB_0075ab41:
      local_24 = (float)((uint)piVar3 ^ piVar3[0xb]);
      goto LAB_0075aab9;
    }
  }
  else if (iVar2 < 2) {
    if (iVar2 != 0) {
LAB_0075aa8f:
      Warning(unaff_EBX + 0x22bded /* "GetFireBoxBloat - Unknown difficulty?
" */ /* "GetFireBoxBloat - Unknown difficulty?
" */ /* "GetFireBoxBloat - Unknown difficulty?
" */);
      goto LAB_0075aa9d;
    }
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x44bdd9 /* &bot_attack_aimtolerance_frac_easy */ /* &bot_attack_aimtolerance_frac_easy */ /* &bot_attack_aimtolerance_frac_easy */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x44bdd9 /* &bot_attack_aimtolerance_frac_easy */ /* &bot_attack_aimtolerance_frac_easy */ /* &bot_attack_aimtolerance_frac_easy */)) goto LAB_0075ab41;
  }
  else if (iVar2 == 2) {
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x44c631 /* &bot_attack_aimtolerance_frac_hard */ /* &bot_attack_aimtolerance_frac_hard */ /* &bot_attack_aimtolerance_frac_hard */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x44c631 /* &bot_attack_aimtolerance_frac_hard */ /* &bot_attack_aimtolerance_frac_hard */ /* &bot_attack_aimtolerance_frac_hard */)) goto LAB_0075ab41;
  }
  else {
    if (iVar2 != 3) goto LAB_0075aa8f;
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x44c2e1 /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x44c2e1 /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */)) goto LAB_0075ab41;
  }
  fVar7 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
  local_24 = (float)fVar7;
LAB_0075aab9:
  if (((byte)param_1[0x2294] & 0x10) != 0) {
    local_24 = *(float *)(unaff_EBX + 0x15e0b9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
  }
  iVar2 = (**(code **)(**(int **)(unaff_EBX + 0x44c071 /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */) + 0x40))(*(int **)(unaff_EBX + 0x44c071 /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */ /* &mp_coop_ai_teammates */));
  if ((((iVar2 != 0) && (piVar3 = (int *)**(int **)(unaff_EBX + 0x44be9d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */), piVar3 != (int *)0x0)) &&
      (cVar1 = (**(code **)(*piVar3 + 0x29c /* CBaseEntity::HasPhysicsAttacker */))(piVar3), cVar1 != '\0')) &&
     (cVar1 = CINSRules::IsSoloMode(), cVar1 != '\0')) {
    iVar2 = CBaseEntity::GetTeamNumber(this_01);
    iVar5 = CINSRules::GetHumanTeam(this_05);
    if (iVar2 == iVar5) {
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x44c2e1 /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x44c2e1 /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */ /* &bot_attack_aimtolerance_frac_impossible */)) {
        local_24 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_24 = (float)fVar7;
      }
    }
  }
  cVar1 = (**(code **)(*in_stack_00000008 + 0x4c))(in_stack_00000008);
  if (cVar1 != '\0') {
    fVar7 = (float10)(**(code **)(*in_stack_00000008 + 0x50))(in_stack_00000008);
    piVar3 = (int *)(*(int **)(unaff_EBX + 0x44bdb1 /* &bot_attack_aimtolerance_newthreat_time */ /* &bot_attack_aimtolerance_newthreat_time */ /* &bot_attack_aimtolerance_newthreat_time */))[7];
    if (piVar3 == *(int **)(unaff_EBX + 0x44bdb1 /* &bot_attack_aimtolerance_newthreat_time */ /* &bot_attack_aimtolerance_newthreat_time */ /* &bot_attack_aimtolerance_newthreat_time */)) {
      fVar6 = (float)((uint)piVar3 ^ piVar3[0xb]);
    }
    else {
      fVar8 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
      fVar6 = (float)fVar8;
    }
    if ((float)fVar7 <= fVar6) {
      cVar1 = CINSRules::IsSoloMode();
      if (cVar1 != '\0') {
        CBaseEntity::GetTeamNumber(this_02);
        CINSRules::GetHumanTeam(this_03);
      }
      piVar3 = (int *)(*(int **)(unaff_EBX + 0x44c3a5 /* &bot_attack_aimtolerance_newthreat_time_solo */ /* &bot_attack_aimtolerance_newthreat_time_solo */ /* &bot_attack_aimtolerance_newthreat_time_solo */))[7];
      if (piVar3 == *(int **)(unaff_EBX + 0x44c3a5 /* &bot_attack_aimtolerance_newthreat_time_solo */ /* &bot_attack_aimtolerance_newthreat_time_solo */ /* &bot_attack_aimtolerance_newthreat_time_solo */)) {
        local_28 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_28 = (float)fVar7;
      }
      piVar3 = (int *)(*(int **)(CEnvScreenEffect::InputStartEffect + unaff_EBX + 5))[7];
      if (piVar3 == *(int **)(CEnvScreenEffect::InputStartEffect + unaff_EBX + 5)) {
        local_20 = (float)((uint)piVar3 ^ piVar3[0xb]);
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar3 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar3);
        local_20 = (float)fVar7;
      }
      fVar7 = (float10)(**(code **)(*in_stack_00000008 + 0x50))(in_stack_00000008);
      if (local_28 == 0.0) {
        fVar6 = *(float *)(unaff_EBX + 0x15e0b9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
        fVar11 = fVar6 - local_20;
        fVar10 = local_20;
        if (0.0 <= (float)fVar7) {
          fVar10 = fVar6;
        }
      }
      else {
        fVar6 = *(float *)(unaff_EBX + 0x15e0b9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
        local_28 = (float)fVar7 / local_28;
        if (fVar6 <= local_28) {
          local_28 = fVar6;
        }
        fVar11 = fVar6 - local_20;
        if (local_28 <= 0.0) {
          local_28 = 0.0;
        }
        fVar10 = local_28 * fVar11 + local_20;
      }
      piVar3 = (int *)(**(code **)(*(int *)param_1 + 0x970 /* CINSNextBot::GetBodyInterface */))(param_1);
      fVar7 = (float10)(**(code **)(*piVar3 + 0xe4 /* PlayerBody::GetHeadSteadyDuration */))(piVar3);
      fVar9 = (float)fVar7 * *(float *)(CBaseGrenade::UsesGrenadeTimer + unaff_EBX + 1);
      if (fVar6 <= (float)fVar7 * *(float *)(CBaseGrenade::UsesGrenadeTimer + unaff_EBX + 1)) {
        fVar9 = fVar6;
      }
      if (fVar9 <= 0.0) {
        fVar9 = 0.0;
      }
      local_20 = fVar9 * fVar11 + local_20;
      if (local_20 <= fVar10) {
        local_20 = fVar10;
      }
      fVar11 = local_20;
      if (fVar6 <= local_20) {
        fVar11 = fVar6;
      }
      if (((byte)param_1[0xd1] & 8) != 0) {
        CBaseEntity::CalcAbsolutePosition(this_04);
      }
      pfVar4 = (float *)(**(code **)(*in_stack_00000008 + 0x14))(in_stack_00000008);
      fVar10 = SQRT((pfVar4[1] - *(float *)(param_1 + 0x20c)) *
                    (pfVar4[1] - *(float *)(param_1 + 0x20c)) +
                    (*pfVar4 - *(float *)(param_1 + 0x208)) *
                    (*pfVar4 - *(float *)(param_1 + 0x208)) +
                    (pfVar4[2] - *(float *)(param_1 + 0x210)) *
                    (pfVar4[2] - *(float *)(param_1 + 0x210))) * *(float *)(unaff_EBX + 0x22be95 /* CSWTCH.663+0x24 */ /* CSWTCH.663+0x24 */ /* CSWTCH.663+0x24 */);
      if (fVar6 <= fVar10) {
        fVar10 = fVar6;
      }
      if (fVar10 <= 0.0) {
        fVar10 = 0.0;
      }
      return (float10)((fVar10 * (local_20 - fVar11) + fVar11) * local_24);
    }
  }
  return (float10)local_24;
}



/* ----------------------------------------
 * CINSNextBot::GetAnyCover
 * Address: 007460f0
 * ---------------------------------------- */

/* CINSNextBot::GetAnyCover() */

undefined4 __thiscall CINSNextBot::GetAnyCover(CINSNextBot *this)

{
  float *pfVar1;
  bool bVar2;
  int unaff_EBX;
  undefined4 in_stack_00000004;
  float local_4c;
  float local_48;
  float local_44;
  float local_3c;
  float local_38;
  float local_34;
  float local_2c;
  float local_28;
  float local_24;
  
  bVar2 = (bool)__i686_get_pc_thunk_bx();
  GetHidingCover(bVar2);
  pfVar1 = *(float **)(unaff_EBX + 0x4604c8 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  bVar2 = SUB41(in_stack_00000004,0);
  if (((((*pfVar1 == local_4c) && (pfVar1[1] == local_48)) && (pfVar1[2] == local_44)) &&
      ((GetHidingCover(true), *pfVar1 == local_3c && (pfVar1[1] == local_38)))) &&
     (pfVar1[2] == local_34)) {
    GetAttackCover(true);
    if (((*pfVar1 == local_2c) && (pfVar1[1] == local_28)) && (pfVar1[2] == local_24)) {
      GetAttackCover(bVar2);
    }
    else {
      GetAttackCover(bVar2);
    }
  }
  else {
    GetHidingCover(bVar2);
  }
  return in_stack_00000004;
}



/* ----------------------------------------
 * CINSNextBot::GetAttackCover
 * Address: 00745b70
 * ---------------------------------------- */

/* CINSNextBot::GetAttackCover(bool) */

float * CINSNextBot::GetAttackCover(bool param_1)

{
  uint *puVar1;
  float *pfVar2;
  code *pcVar3;
  char cVar4;
  int iVar5;
  int *piVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  int *piVar9;
  int unaff_EBX;
  int iVar10;
  float10 fVar11;
  float fVar12;
  undefined3 in_stack_00000005;
  int *in_stack_00000008;
  char in_stack_0000000c;
  float local_58;
  float local_54;
  float local_50;
  int local_44;
  int local_40;
  undefined4 local_38;
  undefined4 local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x745b7b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bool)local_1d) {
    iVar10 = *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar10 == iVar5) {
      piVar6 = *(int **)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar6 != unaff_EBX + 0x23d6dd /* "CINSNextBot::GetForwardAttackCover" */ /* "CINSNextBot::GetForwardAttackCover" */ /* "CINSNextBot::GetForwardAttackCover" */) {
        piVar6 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar6,unaff_EBX + 0x23d6dd /* "CINSNextBot::GetForwardAttackCover" */ /* "CINSNextBot::GetForwardAttackCover" */ /* "CINSNextBot::GetForwardAttackCover" */,(char *)0x0,
                                   unaff_EBX + 0x23b0eb /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
        *(int **)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar6;
      }
      puVar1 = (uint *)(piVar6[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
    }
  }
  pfVar2 = *(float **)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (in_stack_00000008[0x860] == 0) {
    *_param_1 = *pfVar2;
    fVar12 = pfVar2[2];
    _param_1[1] = pfVar2[1];
    _param_1[2] = fVar12;
    goto LAB_00745d0b;
  }
  local_50 = *pfVar2;
  if (((local_50 != (float)in_stack_00000008[0x866]) ||
      (local_54 = pfVar2[1], local_54 != (float)in_stack_00000008[0x867])) ||
     (local_58 = pfVar2[2], local_58 != (float)in_stack_00000008[0x868])) {
    pfVar2 = (float *)(**(int **)(unaff_EBX + 0x460d25 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
    if (*pfVar2 <=
        *(float *)(CBaseEntity::SetWaterType + unaff_EBX + 1) + (float)in_stack_00000008[0x869] &&
        *(float *)(CBaseEntity::SetWaterType + unaff_EBX + 1) + (float)in_stack_00000008[0x869] !=
        *pfVar2) {
      *_param_1 = (float)in_stack_00000008[0x866];
      _param_1[1] = (float)in_stack_00000008[0x867];
      _param_1[2] = (float)in_stack_00000008[0x868];
      goto LAB_00745d0b;
    }
    local_58 = *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 8);
    local_54 = *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4);
  }
  piVar6 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
  piVar6 = (int *)(**(code **)(*piVar6 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar6,0);
  fVar12 = **(float **)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (((local_50 == fVar12) && (local_54 == *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4))) &&
     (local_58 == *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 8))) {
LAB_00745c6e:
    if ((local_54 != *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4)) ||
       (local_58 != *(float *)(*(int *)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 8))) goto LAB_00746002;
  }
  else {
    if (0 < in_stack_00000008[0x860]) {
      iVar10 = 0;
      local_40 = 0;
      local_44 = 0;
      do {
        if ((in_stack_0000000c == '\0') ||
           (*(char *)(in_stack_00000008[0x85d] + 10 + iVar10) != '\0')) {
          local_44 = local_44 + 1;
          if (piVar6 == (int *)0x0) {
            iVar10 = *(int *)(in_stack_00000008[0x85d] + local_40 * 0xc);
LAB_00745fd0:
            local_50 = *(float *)(iVar10 + 4);
            local_54 = *(float *)(iVar10 + 8);
            local_58 = *(float *)(iVar10 + 0xc);
            break;
          }
          puVar7 = (undefined4 *)(**(code **)(*piVar6 + 0x14))(piVar6);
          cVar4 = HidingSpot::HasAnyCoverToPoint
                            (*(undefined4 *)(in_stack_00000008[0x85d] + iVar10),*puVar7,puVar7[1],
                             puVar7[2]);
          if (cVar4 != '\0') {
            pcVar3 = *(code **)(in_stack_00000008[0x818] + 0x134);
            uVar8 = (**(code **)(*piVar6 + 0x14))(piVar6);
            fVar11 = (float10)(*pcVar3)(in_stack_00000008 + 0x818,uVar8);
            if (*(float *)(in_stack_00000008[0x85d] + 4 + iVar10) <= (float)fVar11) {
              puVar7 = (undefined4 *)(**(code **)(*piVar6 + 0x14))(piVar6);
              iVar5 = *(int *)(in_stack_00000008[0x85d] + iVar10);
              cVar4 = IsPointBetweenTargetAndSelf
                                (in_stack_00000008,*(undefined4 *)(iVar5 + 4),
                                 *(undefined4 *)(iVar5 + 8),*(undefined4 *)(iVar5 + 0xc),*puVar7,
                                 puVar7[1],puVar7[2]);
              if (cVar4 != '\0') {
                iVar5 = *(int *)(in_stack_00000008[0x85d] + iVar10);
                cVar4 = IsSpotOccupied(in_stack_00000008,*(undefined4 *)(iVar5 + 4),
                                       *(undefined4 *)(iVar5 + 8),*(undefined4 *)(iVar5 + 0xc));
                if (cVar4 == '\0') {
                  piVar9 = (int *)(**(code **)(*piVar6 + 0x10))(piVar6);
                  (**(code **)(*piVar9 + 0x20c /* CINSNextBot::EyePosition */))(&local_2c,piVar9);
                  iVar5 = *(int *)(in_stack_00000008[0x85d] + iVar10);
                  local_38 = *(undefined4 *)(iVar5 + 4);
                  local_30 = *(float *)(&DAT_002184fd + unaff_EBX) + *(float *)(iVar5 + 0xc);
                  local_34 = *(undefined4 *)(iVar5 + 8);
                  uVar8 = (**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
                  cVar4 = CINSBotVision::IsLineOfFireClear
                                    (uVar8,&local_38,local_2c,local_28,local_24);
                  if (cVar4 != '\0') {
                    iVar10 = *(int *)(in_stack_00000008[0x85d] + iVar10);
                    goto LAB_00745fd0;
                  }
                }
              }
            }
          }
        }
        local_40 = local_40 + 1;
        if (in_stack_00000008[0x860] <= local_40) {
          fVar12 = **(float **)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
          goto LAB_00745ff8;
        }
        iVar10 = iVar10 + 0xc;
      } while (local_44 < 0x14);
      fVar12 = **(float **)(unaff_EBX + 0x460a51 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    }
LAB_00745ff8:
    if (fVar12 == local_50) goto LAB_00745c6e;
LAB_00746002:
    piVar6 = *(int **)(unaff_EBX + 0x460d25 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */);
    in_stack_00000008[0x866] = (int)local_50;
    iVar10 = *piVar6;
    in_stack_00000008[0x867] = (int)local_54;
    in_stack_00000008[0x868] = (int)local_58;
    in_stack_00000008[0x869] = *(int *)(iVar10 + 0xc);
  }
  *_param_1 = local_50;
  _param_1[1] = local_54;
  _param_1[2] = local_58;
LAB_00745d0b:
  if ((local_1d != '\0') &&
     ((*(char *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)))) {
    iVar10 = *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar10 == iVar5) {
      cVar4 = CVProfNode::ExitScope();
      if (cVar4 == '\0') {
        iVar10 = *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      }
      else {
        iVar10 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
        *(int *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar10;
      }
      *(bool *)(*(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
           iVar10 == *(int *)(unaff_EBX + 0x460df9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
      return _param_1;
    }
  }
  return _param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetAttackDelay
 * Address: 0076ea60
 * ---------------------------------------- */

/* CINSNextBot::GetAttackDelay(float, CINSWeapon*, bool) */

float10 __cdecl CINSNextBot::GetAttackDelay(float param_1,CINSWeapon *param_2,bool param_3)

{
  char cVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  float fVar7;
  float fVar8;
  CBaseEntity *this;
  CINSNextBot *extraout_ECX;
  CINSNextBot *this_00;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *extraout_ECX_03;
  CINSNextBot *pCVar9;
  CINSNextBot *this_01;
  CINSRules *this_02;
  CBaseEntity *extraout_ECX_04;
  CINSNextBot *this_03;
  CINSNextBot *extraout_ECX_05;
  CINSNextBot *extraout_ECX_06;
  int unaff_EBX;
  float10 fVar10;
  float fVar11;
  float fVar12;
  undefined3 in_stack_0000000d;
  float local_24;
  
  cVar1 = __i686_get_pc_thunk_bx();
  piVar5 = *(int **)(unaff_EBX + 0x437e86 /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
  cVar2 = CINSRules::IsSoloMode();
  pCVar9 = (CINSNextBot *)this;
  if (cVar2 != '\0') {
    iVar4 = CBaseEntity::GetTeamNumber(this);
    iVar6 = CINSRules::GetHumanTeam(this_02);
    fVar11 = 0.0;
    pCVar9 = (CINSNextBot *)extraout_ECX_04;
    if (iVar4 == iVar6) goto LAB_0076eaaf;
  }
  fVar11 = 0.0;
  if ((_param_3 == 0) || (*(char *)((int)param_1 + 0xb49c) != '\0')) goto LAB_0076eaaf;
  piVar3 = *(int **)(unaff_EBX + 0x5847ea /* bot_attackdelay_base+0x1c */ /* bot_attackdelay_base+0x1c */ /* bot_attackdelay_base+0x1c */);
  if (piVar3 == (int *)(unaff_EBX + 0x5847ce /* bot_attackdelay_base */ /* bot_attackdelay_base */ /* bot_attackdelay_base */U)) {
    local_24 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x5847fa /* bot_attackdelay_base+0x2c */ /* bot_attackdelay_base+0x2c */ /* bot_attackdelay_base+0x2c */));
  }
  else {
    fVar10 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
    local_24 = (float)fVar10;
    pCVar9 = extraout_ECX;
  }
  iVar4 = _param_3;
  fVar10 = (float10)GetMaxAttackRange(pCVar9,(CINSWeapon *)param_1);
  if ((float)param_2 <= (float)fVar10) {
    iVar4 = _param_3;
    fVar10 = (float10)GetDesiredAttackRange(this_00,(CINSWeapon *)param_1);
    if ((float)param_2 <= (float)fVar10) {
      fVar10 = (float10)GetMaxHipFireAttackRange(this_03,(CINSWeapon *)param_1);
      pCVar9 = extraout_ECX_06;
      if ((float)param_2 <= (float)fVar10) {
        piVar3 = *(int **)(unaff_EBX + 0x58466a /* bot_attackdelay_frac_hipfirerange+0x1c */ /* bot_attackdelay_frac_hipfirerange+0x1c */ /* bot_attackdelay_frac_hipfirerange+0x1c */);
        if (piVar3 != (int *)(unaff_EBX + 0x58464e /* bot_attackdelay_frac_hipfirerange */ /* bot_attackdelay_frac_hipfirerange */ /* bot_attackdelay_frac_hipfirerange */)) goto LAB_0076eb20;
        fVar11 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58467a /* bot_attackdelay_frac_hipfirerange+0x2c */ /* bot_attackdelay_frac_hipfirerange+0x2c */ /* bot_attackdelay_frac_hipfirerange+0x2c */));
      }
      else {
        piVar3 = *(int **)(unaff_EBX + 0x5846ca /* bot_attackdelay_frac_desiredrange+0x1c */ /* bot_attackdelay_frac_desiredrange+0x1c */ /* bot_attackdelay_frac_desiredrange+0x1c */);
        if (piVar3 == (int *)(unaff_EBX + 0x5846ae /* bot_attackdelay_frac_desiredrange */ /* bot_attackdelay_frac_desiredrange */ /* bot_attackdelay_frac_desiredrange */)) {
          fVar11 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x5846da /* bot_attackdelay_frac_desiredrange+0x2c */ /* bot_attackdelay_frac_desiredrange+0x2c */ /* bot_attackdelay_frac_desiredrange+0x2c */));
        }
        else {
LAB_0076eb20:
          fVar10 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3,_param_3);
          fVar11 = (float)fVar10;
          pCVar9 = extraout_ECX_00;
        }
      }
    }
    else {
      piVar3 = *(int **)(unaff_EBX + 0x58472a /* bot_attackdelay_frac_maxrange+0x1c */ /* bot_attackdelay_frac_maxrange+0x1c */ /* bot_attackdelay_frac_maxrange+0x1c */);
      _param_3 = iVar4;
      if (piVar3 != (int *)(unaff_EBX + 0x58470e /* bot_attackdelay_frac_maxrange */ /* bot_attackdelay_frac_maxrange */ /* bot_attackdelay_frac_maxrange */)) goto LAB_0076eb20;
      fVar11 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58473a /* bot_attackdelay_frac_maxrange+0x2c */ /* bot_attackdelay_frac_maxrange+0x2c */ /* bot_attackdelay_frac_maxrange+0x2c */));
      pCVar9 = this_03;
    }
  }
  else {
    piVar3 = *(int **)(unaff_EBX + 0x58478a /* bot_attackdelay_frac_outofrange+0x1c */ /* bot_attackdelay_frac_outofrange+0x1c */ /* bot_attackdelay_frac_outofrange+0x1c */);
    _param_3 = iVar4;
    if (piVar3 != (int *)(unaff_EBX + 0x58476e /* bot_attackdelay_frac_outofrange */ /* bot_attackdelay_frac_outofrange */ /* bot_attackdelay_frac_outofrange */U)) goto LAB_0076eb20;
    fVar11 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58479a /* bot_attackdelay_frac_outofrange+0x2c */ /* bot_attackdelay_frac_outofrange+0x2c */ /* bot_attackdelay_frac_outofrange+0x2c */));
    pCVar9 = this_00;
  }
  fVar11 = fVar11 * local_24;
  if (cVar1 == '\0') {
    piVar3 = *(int **)(unaff_EBX + 0x58460a /* bot_attackdelay_frac_outsidefov+0x1c */ /* bot_attackdelay_frac_outsidefov+0x1c */ /* bot_attackdelay_frac_outsidefov+0x1c */);
    if (piVar3 == (int *)(unaff_EBX + 0x5845ee /* bot_attackdelay_frac_outsidefov */ /* bot_attackdelay_frac_outsidefov */ /* bot_attackdelay_frac_outsidefov */U)) {
      fVar8 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58461a /* bot_attackdelay_frac_outsidefov+0x2c */ /* bot_attackdelay_frac_outsidefov+0x2c */ /* bot_attackdelay_frac_outsidefov+0x2c */));
    }
    else {
      fVar10 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar8 = (float)fVar10;
      pCVar9 = extraout_ECX_05;
    }
    fVar11 = fVar11 * fVar8;
  }
  if ((*piVar5 != 0) &&
     (cVar1 = CINSRules::IsSurvival((CINSRules *)pCVar9), pCVar9 = extraout_ECX_01, cVar1 != '\0'))
  {
    piVar3 = *(int **)(unaff_EBX + 0x58442a /* bot_attackdelay_frac_survival_end+0x1c */ /* bot_attackdelay_frac_survival_end+0x1c */ /* bot_attackdelay_frac_survival_end+0x1c */);
    if (piVar3 == (int *)(unaff_EBX + 0x58440e /* bot_attackdelay_frac_survival_end */ /* bot_attackdelay_frac_survival_end */ /* bot_attackdelay_frac_survival_end */U)) {
      fVar8 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58443a /* bot_attackdelay_frac_survival_end+0x2c */ /* bot_attackdelay_frac_survival_end+0x2c */ /* bot_attackdelay_frac_survival_end+0x2c */));
    }
    else {
      fVar10 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar8 = (float)fVar10;
      pCVar9 = extraout_ECX_02;
    }
    piVar3 = *(int **)(unaff_EBX + 0x58448a /* bot_attackdelay_frac_survival_start+0x1c */ /* bot_attackdelay_frac_survival_start+0x1c */ /* bot_attackdelay_frac_survival_start+0x1c */);
    if (piVar3 == (int *)(unaff_EBX + 0x58446e /* bot_attackdelay_frac_survival_start */ /* bot_attackdelay_frac_survival_start */ /* bot_attackdelay_frac_survival_start */U)) {
      fVar7 = (float)((uint)piVar3 ^ *(uint *)(unaff_EBX + 0x58449a /* bot_attackdelay_frac_survival_start+0x2c */ /* bot_attackdelay_frac_survival_start+0x2c */ /* bot_attackdelay_frac_survival_start+0x2c */));
    }
    else {
      fVar10 = (float10)(**(code **)(*piVar3 + 0x3c))(piVar3);
      fVar7 = (float)fVar10;
      pCVar9 = extraout_ECX_03;
    }
    fVar12 = ((float)*(int *)(*piVar5 + 1000) + *(float *)(unaff_EBX + 0x14a09e /* -1.0f */ /* -1.0f */ /* -1.0f */)) *
             *(float *)(unaff_EBX + 0x1c50ce /* rodata:0x3DAAAAAB */ /* rodata:0x3DAAAAAB */ /* rodata:0x3DAAAAAB */);
    if (*(float *)(unaff_EBX + 0x14a0a2 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= fVar12) {
      fVar12 = *(float *)(unaff_EBX + 0x14a0a2 /* 1.0f */ /* 1.0f */ /* 1.0f */);
    }
    if (fVar12 <= *(float *)(unaff_EBX + 0x14a096 /* 0.0f */ /* 0.0f */ /* 0.0f */)) {
      fVar12 = *(float *)(unaff_EBX + 0x14a096 /* 0.0f */ /* 0.0f */ /* 0.0f */);
    }
    fVar11 = fVar11 * ((fVar8 - fVar7) * fVar12 + fVar7);
  }
  iVar4 = GetDifficulty(pCVar9);
  if (iVar4 == 1) goto LAB_0076eaaf;
  iVar4 = GetDifficulty(this_01);
  if (iVar4 == 2) {
    piVar5 = *(int **)(unaff_EBX + 0x58454a /* bot_attackdelay_frac_difficulty_hard+0x1c */ /* bot_attackdelay_frac_difficulty_hard+0x1c */ /* bot_attackdelay_frac_difficulty_hard+0x1c */);
    if (piVar5 == (int *)(unaff_EBX + 0x58452e /* bot_attackdelay_frac_difficulty_hard */ /* bot_attackdelay_frac_difficulty_hard */ /* bot_attackdelay_frac_difficulty_hard */)) {
      fVar8 = (float)((uint)piVar5 ^ *(uint *)(unaff_EBX + 0x58455a /* bot_attackdelay_frac_difficulty_hard+0x2c */ /* bot_attackdelay_frac_difficulty_hard+0x2c */ /* bot_attackdelay_frac_difficulty_hard+0x2c */));
    }
    else {
LAB_0076ec59:
      fVar10 = (float10)(**(code **)(*piVar5 + 0x3c))(piVar5);
      fVar8 = (float)fVar10;
    }
  }
  else if (iVar4 == 3) {
    piVar5 = *(int **)(unaff_EBX + 0x5844ea /* bot_attackdelay_frac_difficulty_impossible+0x1c */ /* bot_attackdelay_frac_difficulty_impossible+0x1c */ /* bot_attackdelay_frac_difficulty_impossible+0x1c */);
    if (piVar5 != (int *)(unaff_EBX + 0x5844ce /* bot_attackdelay_frac_difficulty_impossible */ /* bot_attackdelay_frac_difficulty_impossible */ /* bot_attackdelay_frac_difficulty_impossible */)) goto LAB_0076ec59;
    fVar8 = (float)((uint)piVar5 ^ *(uint *)(&DAT_005844fa + unaff_EBX));
  }
  else {
    if (iVar4 != 0) goto LAB_0076eaaf;
    piVar5 = *(int **)(&DAT_005845aa + unaff_EBX);
    if (piVar5 != (int *)(unaff_EBX + 0x58458e /* bot_attackdelay_frac_difficulty_easy */ /* bot_attackdelay_frac_difficulty_easy */ /* bot_attackdelay_frac_difficulty_easy */U)) goto LAB_0076ec59;
    fVar8 = (float)((uint)piVar5 ^ *(uint *)(unaff_EBX + 0x5845ba /* bot_attackdelay_frac_difficulty_easy+0x2c */ /* bot_attackdelay_frac_difficulty_easy+0x2c */ /* bot_attackdelay_frac_difficulty_easy+0x2c */));
  }
  fVar11 = fVar11 * fVar8;
LAB_0076eaaf:
  return (float10)fVar11;
}



/* ----------------------------------------
 * CINSNextBot::GetBodyInterface
 * Address: 0074c2d0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::GetBodyInterface() const */

void __thiscall CINSNextBot::GetBodyInterface(CINSNextBot *this)

{
  GetBodyInterface(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetBodyInterface
 * Address: 0074c2e0
 * ---------------------------------------- */

/* CINSNextBot::GetBodyInterface() const */

undefined4 __thiscall CINSNextBot::GetBodyInterface(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0xb34c);
}



/* ----------------------------------------
 * CINSNextBot::GetChatter
 * Address: 0074c310
 * ---------------------------------------- */

/* CINSNextBot::GetChatter() */

undefined4 __thiscall CINSNextBot::GetChatter(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0xb354);
}



/* ----------------------------------------
 * CINSNextBot::GetClosestPartialCover
 * Address: 00744d50
 * ---------------------------------------- */

/* CINSNextBot::GetClosestPartialCover() */

void CINSNextBot::GetClosestPartialCover(void)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  int unaff_EBX;
  int in_stack_00000008;
  
  puVar4 = (undefined4 *)__i686_get_pc_thunk_bx();
  puVar1 = *(undefined4 **)(unaff_EBX + 0x46186f /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *puVar4 = *puVar1;
  uVar2 = puVar1[2];
  puVar4[1] = puVar1[1];
  puVar4[2] = uVar2;
  if (((0 < *(int *)(in_stack_00000008 + 0x2180)) &&
      (*(int **)(in_stack_00000008 + 0x2174) != (int *)0x0)) &&
     (iVar3 = **(int **)(in_stack_00000008 + 0x2174), iVar3 != 0)) {
    *puVar4 = *(undefined4 *)(iVar3 + 4);
    uVar2 = *(undefined4 *)(iVar3 + 0xc);
    puVar4[1] = *(undefined4 *)(iVar3 + 8);
    puVar4[2] = uVar2;
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentInvestigation
 * Address: 00747e60
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentInvestigation() */

undefined4 __thiscall CINSNextBot::GetCurrentInvestigation(CINSNextBot *this)

{
  undefined4 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (0 < *(int *)(in_stack_00000004 + 0xb468)) {
    uVar1 = *(undefined4 *)(in_stack_00000004 + 0xb45c);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentInvestigationArea
 * Address: 00747de0
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentInvestigationArea() */

undefined4 __thiscall CINSNextBot::GetCurrentInvestigationArea(CINSNextBot *this)

{
  undefined4 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (0 < *(int *)(in_stack_00000004 + 0xb468)) {
    uVar1 = *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb45c) + 0x18);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentInvestigationLocation
 * Address: 00747e00
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentInvestigationLocation() */

void CINSNextBot::GetCurrentInvestigationLocation(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (0 < *(int *)(in_stack_00000008 + 0xb468)) {
    iVar1 = *(int *)(in_stack_00000008 + 0xb45c);
    *in_stack_00000004 = *(undefined4 *)(iVar1 + 0xc);
    uVar2 = *(undefined4 *)(iVar1 + 0x14);
    in_stack_00000004[1] = *(undefined4 *)(iVar1 + 0x10);
    in_stack_00000004[2] = uVar2;
    return;
  }
  puVar3 = *(undefined4 **)(unaff_EBX + 0x45e7c3 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *in_stack_00000004 = *puVar3;
  uVar2 = puVar3[2];
  in_stack_00000004[1] = puVar3[1];
  in_stack_00000004[2] = uVar2;
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentInvestigationPriority
 * Address: 00747ea0
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentInvestigationPriority() */

undefined4 __thiscall CINSNextBot::GetCurrentInvestigationPriority(CINSNextBot *this)

{
  undefined4 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (0 < *(int *)(in_stack_00000004 + 0xb468)) {
    uVar1 = *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb45c) + 0x20);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrder
 * Address: 00747ef0
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrder() */

undefined4 __thiscall CINSNextBot::GetCurrentOrder(CINSNextBot *this)

{
  undefined4 uVar1;
  int in_stack_00000004;
  
  uVar1 = 0;
  if (0 < *(int *)(in_stack_00000004 + 0xb47c)) {
    uVar1 = *(undefined4 *)(in_stack_00000004 + 0xb470);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrderIssuer
 * Address: 00747f40
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrderIssuer() */

undefined4 __thiscall CINSNextBot::GetCurrentOrderIssuer(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0xb47c)) {
    return *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb470) + 0x10);
  }
  return 0xffffffff;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrderMarkedObjective
 * Address: 00747fd0
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrderMarkedObjective() */

undefined4 __thiscall CINSNextBot::GetCurrentOrderMarkedObjective(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0xb47c)) {
    return *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb470) + 0x20);
  }
  return 0xffffffff;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrderPriority
 * Address: 00748000
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrderPriority() */

undefined4 __thiscall CINSNextBot::GetCurrentOrderPriority(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0xb47c)) {
    return *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb470) + 0x24);
  }
  return 0xffffffff;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrderRadialCommand
 * Address: 00747f10
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrderRadialCommand() */

undefined4 __thiscall CINSNextBot::GetCurrentOrderRadialCommand(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0xb47c)) {
    return *(undefined4 *)(*(int *)(in_stack_00000004 + 0xb470) + 0xc);
  }
  return 0xffffffff;
}



/* ----------------------------------------
 * CINSNextBot::GetCurrentOrderTarget
 * Address: 00747f70
 * ---------------------------------------- */

/* CINSNextBot::GetCurrentOrderTarget() */

void CINSNextBot::GetCurrentOrderTarget(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int unaff_EBX;
  undefined4 *in_stack_00000004;
  int in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (0 < *(int *)(in_stack_00000008 + 0xb47c)) {
    iVar1 = *(int *)(in_stack_00000008 + 0xb470);
    *in_stack_00000004 = *(undefined4 *)(iVar1 + 0x14);
    uVar2 = *(undefined4 *)(iVar1 + 0x1c);
    in_stack_00000004[1] = *(undefined4 *)(iVar1 + 0x18);
    in_stack_00000004[2] = uVar2;
    return;
  }
  puVar3 = *(undefined4 **)(unaff_EBX + 0x45e653 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  *in_stack_00000004 = *puVar3;
  uVar2 = puVar3[2];
  in_stack_00000004[1] = puVar3[1];
  in_stack_00000004[2] = uVar2;
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetDesiredAttackRange
 * Address: 0076e310
 * ---------------------------------------- */

/* CINSNextBot::GetDesiredAttackRange(CINSWeapon*) const */

float10 __thiscall CINSNextBot::GetDesiredAttackRange(CINSNextBot *this,CINSWeapon *param_1)

{
  int *piVar1;
  char cVar2;
  uint uVar3;
  CINSWeapon *this_00;
  int unaff_EBX;
  float10 fVar4;
  float fVar5;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (int *)0x0) {
    in_stack_00000008 = (int *)CINSPlayer::GetActiveINSWeapon();
    fVar5 = 0.0;
    if (in_stack_00000008 == (int *)0x0) goto LAB_0076e38d;
  }
  piVar1 = *(int **)(unaff_EBX + 0x584ac2 /* bot_range_frac_desiredrange+0x1c */ /* bot_range_frac_desiredrange+0x1c */ /* bot_range_frac_desiredrange+0x1c */);
  if (piVar1 == (int *)(unaff_EBX + 0x584aa6 /* bot_range_frac_desiredrange */ /* bot_range_frac_desiredrange */ /* bot_range_frac_desiredrange */U)) {
    fVar5 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x584ad2 /* bot_range_frac_desiredrange+0x2c */ /* bot_range_frac_desiredrange+0x2c */ /* bot_range_frac_desiredrange+0x2c */));
    uVar3 = (**(code **)(*in_stack_00000008 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(in_stack_00000008);
  }
  else {
    fVar4 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar5 = (float)fVar4;
    uVar3 = (**(code **)(*in_stack_00000008 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(in_stack_00000008);
  }
  if ((int)uVar3 < 1) {
    Warning(unaff_EBX + 0x218f16 /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */);
    return (float10)(fVar5 * *(float *)(unaff_EBX + 0x1eb59e /* 1500.0f */ /* 1500.0f */ /* 1500.0f */));
  }
  if (uVar3 < 0xf) {
                    /* WARNING: Could not recover jumptable at 0x0076e3a9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    fVar4 = (float10)(*(code *)(*(int *)(unaff_EBX + 0x2191e6 /* rodata:0xFFBC71E5 */ /* rodata:0xFFBC71E5 */ /* rodata:0xFFBC71E5 */ + uVar3 * 4) + unaff_EBX + 0x438e5e /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */))
                               ();
    return fVar4;
  }
  fVar5 = fVar5 * *(float *)(unaff_EBX + 0x219ce2 /* 480.0f */ /* 480.0f */ /* 480.0f */);
  cVar2 = (**(code **)(*in_stack_00000008 + 0x620 /* CINSPlayer::FlashlightIsOn */))(in_stack_00000008);
  if (cVar2 != '\0') {
    fVar4 = (float10)CINSWeapon::GetFOVWeaponScope(this_00);
    if ((float)fVar4 < *(float *)(unaff_EBX + 0x1b644a /* 20.0f */ /* 20.0f */ /* 20.0f */)) {
      return (float10)(fVar5 * *(float *)(unaff_EBX + 0x219ce6 /* 1.75f */ /* 1.75f */ /* 1.75f */));
    }
    return (float10)(fVar5 * *(float *)(unaff_EBX + 0x219cea /* 1.15f */ /* 1.15f */ /* 1.15f */));
  }
LAB_0076e38d:
  return (float10)fVar5;
}



/* ----------------------------------------
 * CINSNextBot::GetDesiredPathLookAheadRange
 * Address: 00745470
 * ---------------------------------------- */

/* CINSNextBot::GetDesiredPathLookAheadRange() const */

float10 __thiscall CINSNextBot::GetDesiredPathLookAheadRange(CINSNextBot *this)

{
  int *piVar1;
  float fVar2;
  int unaff_EBX;
  float10 fVar3;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  piVar1 = (int *)(*(int **)(unaff_EBX + 0x46106f /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */))[7];
  if (piVar1 == *(int **)(unaff_EBX + 0x46106f /* &bot_path_minlookahead */ /* &bot_path_minlookahead */ /* &bot_path_minlookahead */)) {
    fVar2 = (float)((uint)piVar1 ^ piVar1[0xb]);
  }
  else {
    fVar3 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar2 = (float)fVar3;
  }
  return (float10)(fVar2 * *(float *)(in_stack_00000004 + 0x3a0));
}



/* ----------------------------------------
 * CINSNextBot::GetDifficulty
 * Address: 007446d0
 * ---------------------------------------- */

/* CINSNextBot::GetDifficulty() const */

undefined4 __thiscall CINSNextBot::GetDifficulty(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x2288);
}



/* ----------------------------------------
 * CINSNextBot::GetEntityViewPosition
 * Address: 007479a0
 * ---------------------------------------- */

/* CINSNextBot::GetEntityViewPosition(CBaseEntity*) */

CBaseEntity * CINSNextBot::GetEntityViewPosition(CBaseEntity *param_1)

{
  char cVar1;
  CBaseEntity *this;
  int *in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_0000000c + 0x158))();
  if (cVar1 == '\0') {
    if ((*(byte *)((int)in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    GetViewPosition(param_1);
  }
  else {
    GetTargetPosition((CBaseCombatCharacter *)param_1);
  }
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetEscortTarget
 * Address: 00747c10
 * ---------------------------------------- */

/* CINSNextBot::GetEscortTarget() */

int __thiscall CINSNextBot::GetEscortTarget(CINSNextBot *this)

{
  int iVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(in_stack_00000004 + 0xb334) == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = 0;
    if (*(int *)(in_stack_00000004 + 0xb32c) != -1) {
      iVar1 = UTIL_EntityByIndex(*(int *)(in_stack_00000004 + 0xb32c));
      if (iVar1 == 0) {
        *(undefined4 *)(in_stack_00000004 + 0xb32c) = 0xffffffff;
        *(undefined4 *)(in_stack_00000004 + 0xb330) = 0;
      }
    }
  }
  return iVar1;
}



/* ----------------------------------------
 * CINSNextBot::GetHidingCover
 * Address: 00744790
 * ---------------------------------------- */

/* CINSNextBot::GetHidingCover(bool) */

float * CINSNextBot::GetHidingCover(bool param_1)

{
  uint *puVar1;
  int iVar2;
  float *pfVar3;
  undefined4 *puVar4;
  code *pcVar5;
  char cVar6;
  int iVar7;
  int *piVar8;
  int *piVar9;
  CNavMesh *pCVar10;
  int iVar11;
  char *pcVar12;
  CNavArea *this;
  int unaff_EBX;
  float10 fVar13;
  float fVar14;
  undefined3 in_stack_00000005;
  int *in_stack_00000008;
  char in_stack_0000000c;
  undefined4 uVar15;
  float local_6c;
  float local_68;
  float local_64;
  int local_58;
  int local_54;
  int local_50;
  int local_4c [2];
  Vector *local_44;
  CNavMesh *local_40;
  undefined4 local_3c;
  CNavArea *local_38;
  char local_34;
  CNavMesh *local_2c;
  undefined4 local_28;
  CNavArea *local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x74479b;
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x4621d9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  local_1d = *(int *)(iVar2 + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar11 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar11 == iVar7)) {
    pcVar12 = *(char **)(iVar2 + 0x1014);
    if (*(undefined **)pcVar12 != &UNK_0023ea79 + unaff_EBX) {
      pcVar12 = (char *)CVProfNode::GetSubNode
                                  (pcVar12,(int)(&UNK_0023ea79 + unaff_EBX),(char *)0x0,
                                   unaff_EBX + 0x23c4cb /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
      *(char **)(iVar2 + 0x1014) = pcVar12;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + *(int *)(pcVar12 + 0x70) * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
  }
  pfVar3 = *(float **)(unaff_EBX + 0x461e31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (in_stack_00000008[0x860] == 0) {
    *_param_1 = *pfVar3;
    fVar14 = pfVar3[2];
    _param_1[1] = pfVar3[1];
    _param_1[2] = fVar14;
    goto LAB_00744a4b;
  }
  local_64 = *pfVar3;
  if (((local_64 != (float)in_stack_00000008[0x86a]) ||
      (local_68 = pfVar3[1], local_68 != (float)in_stack_00000008[0x86b])) ||
     (local_6c = pfVar3[2], local_6c != (float)in_stack_00000008[0x86c])) {
    fVar14 = *(float *)(unaff_EBX + 0x1dffd1 /* 5.0f */ /* 5.0f */ /* 5.0f */) + (float)in_stack_00000008[0x86d];
    pfVar3 = (float *)(**(int **)(unaff_EBX + 0x462105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
    if (*pfVar3 <= fVar14 && fVar14 != *pfVar3) {
      *_param_1 = (float)in_stack_00000008[0x86a];
      _param_1[1] = (float)in_stack_00000008[0x86b];
      _param_1[2] = (float)in_stack_00000008[0x86c];
      goto LAB_00744a4b;
    }
    local_6c = *(float *)(*(int *)(unaff_EBX + 0x461e31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 8);
    local_68 = *(float *)(*(int *)(unaff_EBX + 0x461e31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */) + 4);
  }
  piVar8 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
  piVar8 = (int *)(**(code **)(*piVar8 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar8,0);
  pCVar10 = (CNavMesh *)&local_2c;
  iVar11 = *(int *)in_stack_00000008[0x85d];
  local_2c = *(CNavMesh **)(iVar11 + 4);
  local_28 = *(undefined4 *)(iVar11 + 8);
  local_24 = *(CNavArea **)(iVar11 + 0xc);
  local_4c[0] = unaff_EBX + 0x458455 /* vtable for INSBotSafeCoverTest+0x8 */ /* vtable for INSBotSafeCoverTest+0x8 */ /* vtable for INSBotSafeCoverTest+0x8 */;
  uVar15 = 0;
  local_44 = (Vector *)
             CNavMesh::GetNearestNavArea
                       (pCVar10,**(undefined4 **)(unaff_EBX + 0x461f1d /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */),pCVar10,0,0x461c4000 /* 10000.0f */,0,1,0);
  if (local_44 == (Vector *)0x0) {
LAB_007448e4:
    puVar4 = *(undefined4 **)(unaff_EBX + 0x461e31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    local_40 = (CNavMesh *)*puVar4;
    local_3c = puVar4[1];
    local_38 = (CNavArea *)puVar4[2];
  }
  else {
    pCVar10 = (CNavMesh *)&local_2c;
    uVar15 = 0;
    cVar6 = CNavArea::IsOverlapping(this,local_44,(float)pCVar10);
    if (cVar6 == '\0') goto LAB_007448e4;
    local_3c = local_28;
    local_40 = local_2c;
    local_38 = local_24;
    pCVar10 = local_2c;
    uVar15 = local_28;
    fVar13 = (float10)CNavArea::GetZ(local_24,(float)local_44,(float)local_2c);
    local_38 = (CNavArea *)((float)fVar13 + *(float *)(unaff_EBX + 0x2198dd /* 69.0f */ /* 69.0f */ /* 69.0f */));
  }
  if (0 < in_stack_00000008[0x860]) {
    local_50 = 0;
    local_54 = 0;
    local_58 = 0;
    if (in_stack_0000000c == '\0') {
      do {
        local_58 = local_58 + 1;
        if (piVar8 == (int *)0x0) goto LAB_00744d20;
        pcVar5 = *(code **)(in_stack_00000008[0x818] + 0x134);
        uVar15 = (**(code **)(*piVar8 + 0x14))(piVar8);
        fVar13 = (float10)(*pcVar5)(in_stack_00000008 + 0x818,uVar15);
        if ((float)((int *)(local_50 + in_stack_00000008[0x85d]))[1] <= (float)fVar13) {
          iVar11 = *(int *)(local_50 + in_stack_00000008[0x85d]);
          local_40 = *(CNavMesh **)(iVar11 + 4);
          local_3c = *(undefined4 *)(iVar11 + 8);
          local_38 = *(CNavArea **)(iVar11 + 0xc);
          local_34 = '\0';
          piVar9 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
          (**(code **)(*piVar9 + 200))(piVar9,local_4c);
          if (local_34 == '\0') goto LAB_00744b4d;
        }
        local_54 = local_54 + 1;
      } while ((local_54 < in_stack_00000008[0x860]) && (local_50 = local_50 + 0xc, local_58 < 0x14)
              );
    }
    else {
      do {
        if (*(char *)(in_stack_00000008[0x85d] + 10 + local_50) != '\0') {
          local_58 = local_58 + 1;
          if (piVar8 == (int *)0x0) goto LAB_00744d20;
          pcVar5 = *(code **)(in_stack_00000008[0x818] + 0x134);
          pCVar10 = (CNavMesh *)(**(code **)(*piVar8 + 0x14))(piVar8,pCVar10,uVar15);
          fVar13 = (float10)(*pcVar5)(in_stack_00000008 + 0x818);
          if ((float)((int *)(local_50 + in_stack_00000008[0x85d]))[1] <= (float)fVar13) {
            iVar11 = *(int *)(local_50 + in_stack_00000008[0x85d]);
            local_40 = *(CNavMesh **)(iVar11 + 4);
            local_3c = *(undefined4 *)(iVar11 + 8);
            local_38 = *(CNavArea **)(iVar11 + 0xc);
            local_34 = '\0';
            piVar9 = (int *)(**(code **)(*in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
            pCVar10 = (CNavMesh *)local_4c;
            (**(code **)(*piVar9 + 200))(piVar9);
            if (local_34 == '\0') goto LAB_00744b4d;
          }
        }
        local_54 = local_54 + 1;
      } while ((local_54 < in_stack_00000008[0x860]) && (local_50 = local_50 + 0xc, local_58 < 0x14)
              );
    }
  }
  goto LAB_00744b77;
LAB_00744d20:
  iVar11 = *(int *)(in_stack_00000008[0x85d] + local_54 * 0xc);
  goto LAB_00744b59;
LAB_00744b4d:
  iVar11 = *(int *)(in_stack_00000008[0x85d] + local_50);
LAB_00744b59:
  local_64 = *(float *)(iVar11 + 4);
  local_68 = *(float *)(iVar11 + 8);
  local_6c = *(float *)(iVar11 + 0xc);
LAB_00744b77:
  pfVar3 = *(float **)(unaff_EBX + 0x461e31 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (((local_64 != *pfVar3) || (local_68 != pfVar3[1])) || (local_6c != pfVar3[2])) {
    piVar8 = *(int **)(unaff_EBX + 0x462105 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */);
    in_stack_00000008[0x86a] = (int)local_64;
    iVar11 = *piVar8;
    in_stack_00000008[0x86b] = (int)local_68;
    in_stack_00000008[0x86c] = (int)local_6c;
    in_stack_00000008[0x86d] = *(int *)(iVar11 + 0xc);
  }
  *_param_1 = local_64;
  _param_1[1] = local_68;
  _param_1[2] = local_6c;
LAB_00744a4b:
  if (((local_1d != '\0') &&
      ((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)))) &&
     (iVar11 = *(int *)(iVar2 + 0x19b8), iVar7 = ThreadGetCurrentId(), iVar11 == iVar7)) {
    cVar6 = CVProfNode::ExitScope();
    iVar11 = *(int *)(iVar2 + 0x1014);
    if (cVar6 != '\0') {
      iVar11 = *(int *)(iVar11 + 100);
      *(int *)(iVar2 + 0x1014) = iVar11;
    }
    *(bool *)(iVar2 + 0x1010) = iVar11 == iVar2 + 0x1018;
    return _param_1;
  }
  return _param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetHumanSquadmate
 * Address: 0075a0d0
 * ---------------------------------------- */

/* CINSNextBot::GetHumanSquadmate() */

void __thiscall CINSNextBot::GetHumanSquadmate(CINSNextBot *this)

{
  CINSPlayer *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  UTIL_INSGetHumanSquadmate(in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetIdleDuration
 * Address: 00748290
 * ---------------------------------------- */

/* CINSNextBot::GetIdleDuration() */

float10 __thiscall CINSNextBot::GetIdleDuration(CINSNextBot *this)

{
  float10 fVar1;
  float fVar2;
  int in_stack_00000004;
  
  fVar2 = 0.0;
  __i686_get_pc_thunk_bx();
  if (fVar2 < *(float *)(in_stack_00000004 + 0xb3c8)) {
    fVar1 = (float10)IntervalTimer::Now();
    fVar2 = (float)fVar1 - *(float *)(in_stack_00000004 + 0xb3c8);
  }
  return (float10)fVar2;
}



/* ----------------------------------------
 * CINSNextBot::GetIntentionInterface
 * Address: 0074c340
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::GetIntentionInterface() const */

void __thiscall CINSNextBot::GetIntentionInterface(CINSNextBot *this)

{
  GetIntentionInterface(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetIntentionInterface
 * Address: 0074c350
 * ---------------------------------------- */

/* CINSNextBot::GetIntentionInterface() const */

undefined4 __thiscall CINSNextBot::GetIntentionInterface(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0x21b8);
}



/* ----------------------------------------
 * CINSNextBot::GetLastKnownArea
 * Address: 0074c2a0
 * ---------------------------------------- */

/* CINSNextBot::GetLastKnownArea() const */

undefined4 __thiscall CINSNextBot::GetLastKnownArea(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0xc14);
}



/* ----------------------------------------
 * CINSNextBot::GetLocomotionInterface
 * Address: 0074c2b0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::GetLocomotionInterface() const */

void __thiscall CINSNextBot::GetLocomotionInterface(CINSNextBot *this)

{
  GetLocomotionInterface(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetLocomotionInterface
 * Address: 0074c2c0
 * ---------------------------------------- */

/* CINSNextBot::GetLocomotionInterface() const */

undefined4 __thiscall CINSNextBot::GetLocomotionInterface(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0xb348);
}



/* ----------------------------------------
 * CINSNextBot::GetMaxAttackRange
 * Address: 0076e150
 * ---------------------------------------- */

/* CINSNextBot::GetMaxAttackRange(CINSWeapon*) const */

float10 __thiscall CINSNextBot::GetMaxAttackRange(CINSNextBot *this,CINSWeapon *param_1)

{
  int *piVar1;
  char cVar2;
  uint uVar3;
  CINSWeapon *this_00;
  int unaff_EBX;
  float10 fVar4;
  int *in_stack_00000008;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (int *)0x0) {
    in_stack_00000008 = (int *)CINSPlayer::GetActiveINSWeapon();
    local_20 = 0.0;
    if (in_stack_00000008 == (int *)0x0) goto LAB_0076e1fb;
  }
  piVar1 = *(int **)(unaff_EBX + 0x584cd8 /* bot_range_frac_maxrange+0x1c */ /* bot_range_frac_maxrange+0x1c */ /* bot_range_frac_maxrange+0x1c */);
  if (piVar1 == (int *)(&UNK_00584cbc + unaff_EBX)) {
    local_20 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x584ce8 /* bot_range_frac_maxrange+0x2c */ /* bot_range_frac_maxrange+0x2c */ /* bot_range_frac_maxrange+0x2c */));
  }
  else {
    fVar4 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    local_20 = (float)fVar4;
  }
  uVar3 = (**(code **)(*in_stack_00000008 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(in_stack_00000008);
  cVar2 = (**(code **)(*in_stack_00000008 + 0x620 /* CINSPlayer::FlashlightIsOn */))(in_stack_00000008);
  if ((cVar2 != '\0') &&
     (fVar4 = (float10)CINSWeapon::GetFOVWeaponScope(this_00),
     (float)fVar4 < *(float *)(unaff_EBX + 0x1b6600 /* 20.0f */ /* 20.0f */ /* 20.0f */))) {
    local_20 = local_20 * *(float *)(unaff_EBX + 0x1b8c54 /* 1.25f */ /* 1.25f */ /* 1.25f */);
  }
  if ((int)uVar3 < 1) {
    Warning(unaff_EBX + 0x2190cc /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */);
    local_20 = local_20 * *(float *)(unaff_EBX + 0x1ddb34 /* 2000.0f */ /* 2000.0f */ /* 2000.0f */);
  }
  else {
    if (uVar3 < 0xf) {
                    /* WARNING: Could not recover jumptable at 0x0076e1d9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      fVar4 = (float10)(*(code *)(*(int *)(unaff_EBX + 0x219360 /* rodata:0xFFBC7046 */ /* rodata:0xFFBC7046 */ /* rodata:0xFFBC7046 */ + uVar3 * 4) + unaff_EBX + 0x439014 /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */)
                       )();
      return fVar4;
    }
    local_20 = local_20 * *(float *)(unaff_EBX + 0x219e94 /* 3600.0f */ /* 3600.0f */ /* 3600.0f */);
  }
LAB_0076e1fb:
  return (float10)local_20;
}



/* ----------------------------------------
 * CINSNextBot::GetMaxHipFireAttackRange
 * Address: 0076e920
 * ---------------------------------------- */

/* CINSNextBot::GetMaxHipFireAttackRange(CINSWeapon*) const */

float10 __thiscall CINSNextBot::GetMaxHipFireAttackRange(CINSNextBot *this,CINSWeapon *param_1)

{
  int *piVar1;
  int iVar2;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000008 == (int *)0x0) {
    in_stack_00000008 = (int *)CINSPlayer::GetActiveINSWeapon();
    fVar4 = 0.0;
    if (in_stack_00000008 == (int *)0x0) goto _L743;
  }
  piVar1 = *(int **)(unaff_EBX + 0x584452 /* bot_range_frac_hipfirerange+0x1c */ /* bot_range_frac_hipfirerange+0x1c */ /* bot_range_frac_hipfirerange+0x1c */);
  if (piVar1 == (int *)(unaff_EBX + 0x584436 /* bot_range_frac_hipfirerange */ /* bot_range_frac_hipfirerange */ /* bot_range_frac_hipfirerange */U)) {
    fVar4 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x584462 /* bot_range_frac_hipfirerange+0x2c */ /* bot_range_frac_hipfirerange+0x2c */ /* bot_range_frac_hipfirerange+0x2c */));
  }
  else {
    fVar3 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar4 = (float)fVar3;
  }
  iVar2 = (**(code **)(*in_stack_00000008 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(in_stack_00000008);
  if (iVar2 < 1) {
    Warning(unaff_EBX + 0x218906 /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */ /* "WEAPON_CLASS_INVALID" */);
  }
  else if (iVar2 - 7U < 8) {
                    /* WARNING: Could not recover jumptable at 0x0076e9a9. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    fVar3 = (float10)(*(code *)(*(int *)(unaff_EBX + 0x218c12 /* rodata:0xFFBC7817 */ /* rodata:0xFFBC7817 */ /* rodata:0xFFBC7817 */ + (iVar2 - 7U) * 4) +
                               unaff_EBX + 0x43884e /* &_DYNAMIC */ /* &_DYNAMIC */ /* &_DYNAMIC */))();
    return fVar3;
  }
  fVar4 = fVar4 * *(float *)(unaff_EBX + 0x1b848a /* 200.0f */ /* 200.0f */ /* 200.0f */);
_L743:
  return (float10)fVar4;
}



/* ----------------------------------------
 * CINSNextBot::GetNearestEnemy
 * Address: 0075a100
 * ---------------------------------------- */

/* CINSNextBot::GetNearestEnemy() */

void __thiscall CINSNextBot::GetNearestEnemy(CINSNextBot *this)

{
  int iVar1;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CBaseEntity::GetTeamNumber(this_00);
  if ((*(byte *)(in_stack_00000004 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_01);
  }
  UTIL_INSGetClosestPlayer((Vector *)(in_stack_00000004 + 0x208),(iVar1 == 2) + 2,(float *)0x0);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetPartPosition
 * Address: 00746730
 * ---------------------------------------- */

/* CINSNextBot::GetPartPosition(CINSPlayer*, CINSNextBot::VisiblePartType) const */

int __thiscall
CINSNextBot::GetPartPosition(undefined4 param_1_00,CINSPlayer *param_1,int param_3,int param_4)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  CINSNextBot *this;
  int unaff_EBX;
  bool bVar8;
  int *local_34;
  
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(unaff_EBX + 0x460239 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar8 = *(int *)(iVar2 + 0x100c) != 0;
  if ((bVar8) && (iVar5 = *(int *)(iVar2 + 0x19b8), iVar4 = ThreadGetCurrentId(), iVar5 == iVar4)) {
    pcVar7 = *(char **)(iVar2 + 0x1014);
    if (*(undefined **)pcVar7 != &UNK_0023c60b + unaff_EBX) {
      pcVar7 = (char *)CVProfNode::GetSubNode
                                 (pcVar7,(int)(&UNK_0023c60b + unaff_EBX),(char *)0x0,
                                  unaff_EBX + 0x23a52b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
      *(char **)(iVar2 + 0x1014) = pcVar7;
    }
    puVar1 = (uint *)(*(int *)(iVar2 + 0x10a0) + *(int *)(pcVar7 + 0x70) * 8 + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(iVar2 + 0x1010) = 0;
    iVar5 = *(int *)(param_3 + 0x20);
    if (iVar5 != 0) goto LAB_0074677d;
LAB_0074691f:
    local_34 = *(int **)(unaff_EBX + 0x460165 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */);
    this = (CINSNextBot *)*local_34;
    iVar5 = 0;
  }
  else {
    iVar5 = *(int *)(param_3 + 0x20);
    if (iVar5 == 0) goto LAB_0074691f;
LAB_0074677d:
    local_34 = *(int **)(unaff_EBX + 0x460165 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */);
    this = (CINSNextBot *)*local_34;
    iVar5 = (iVar5 - *(int *)(this + 0x5c) >> 4) % 0x31;
  }
  iVar5 = unaff_EBX + 0x5a6e25 /* CINSNextBot::m_partInfo */ /* CINSNextBot::m_partInfo */ /* CINSNextBot::m_partInfo */ + iVar5 * 0x58;
  if (*(int *)(iVar5 + 0x54) < *(int *)(this + 4)) {
    ComputePartPositions(this,param_1);
    *(undefined4 *)(iVar5 + 0x54) = *(undefined4 *)(*local_34 + 4);
  }
  iVar4 = iVar5 + 0x30;
  if (param_4 != 8) {
    if (param_4 < 9) {
      iVar4 = iVar5;
      if ((param_4 == 2) || (iVar4 = iVar5 + 0x24, param_4 == 4)) goto LAB_007467f0;
    }
    else {
      iVar4 = iVar5 + 0x48;
      if ((param_4 == 0x20) ||
         ((iVar4 = iVar5 + 0x18, param_4 == 0x40 || (iVar4 = iVar5 + 0x3c, param_4 == 0x10))))
      goto LAB_007467f0;
    }
    iVar4 = iVar5 + 0xc;
  }
LAB_007467f0:
  if ((bVar8) &&
     (((*(char *)(iVar2 + 0x1010) == '\0' || (*(int *)(iVar2 + 0x100c) != 0)) &&
      (iVar5 = *(int *)(iVar2 + 0x19b8), iVar6 = ThreadGetCurrentId(), iVar5 == iVar6)))) {
    cVar3 = CVProfNode::ExitScope();
    iVar5 = *(int *)(iVar2 + 0x1014);
    if (cVar3 != '\0') {
      iVar5 = *(int *)(iVar5 + 100);
      *(int *)(iVar2 + 0x1014) = iVar5;
    }
    *(bool *)(iVar2 + 0x1010) = iVar5 == iVar2 + 0x1018;
    return iVar4;
  }
  return iVar4;
}



/* ----------------------------------------
 * CINSNextBot::GetPistolFireRate
 * Address: 0076dac0
 * ---------------------------------------- */

/* CINSNextBot::GetPistolFireRate() */

float10 CINSNextBot::GetPistolFireRate(void)

{
  int *piVar1;
  int iVar2;
  CINSNextBot *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this;
  int unaff_EBX;
  float10 fVar3;
  float fVar4;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(unaff_EBX + 0x5858b3 /* ins_bot_attack_pistol_fire_rate+0x1c */ /* ins_bot_attack_pistol_fire_rate+0x1c */ /* ins_bot_attack_pistol_fire_rate+0x1c */);
  if (piVar1 == (int *)(unaff_EBX + 0x585897 /* ins_bot_attack_pistol_fire_rate */ /* ins_bot_attack_pistol_fire_rate */ /* ins_bot_attack_pistol_fire_rate */U)) {
    fVar4 = (float)((uint)piVar1 ^ *(uint *)(unaff_EBX + 0x5858c3 /* ins_bot_attack_pistol_fire_rate+0x2c */ /* ins_bot_attack_pistol_fire_rate+0x2c */ /* ins_bot_attack_pistol_fire_rate+0x2c */));
    this = extraout_ECX;
  }
  else {
    fVar3 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1);
    fVar4 = (float)fVar3;
    this = extraout_ECX_00;
  }
  iVar2 = GetDifficulty(this);
  if (iVar2 == 2) {
LAB_0076db1a:
    fVar4 = fVar4 * *(float *)(unaff_EBX + 0x1b7537 /* 0.65f */ /* 0.65f */ /* 0.65f */);
  }
  else {
    if (iVar2 < 3) {
      if (iVar2 < 0) goto LAB_0076db2a;
      fVar4 = fVar4 * *(float *)(unaff_EBX + 0x1b931f /* 0.85f */ /* 0.85f */ /* 0.85f */);
      goto LAB_0076db1a;
    }
    if (iVar2 != 3) {
      return (float10)fVar4;
    }
  }
  fVar4 = fVar4 * *(float *)(unaff_EBX + 0x1c606f /* 0.45f */ /* 0.45f */ /* 0.45f */);
LAB_0076db2a:
  return (float10)fVar4;
}



/* ----------------------------------------
 * CINSNextBot::GetSuppressingOffset
 * Address: 0075a510
 * ---------------------------------------- */

/* CINSNextBot::GetSuppressingOffset(CKnownEntity const*) */

CKnownEntity * CINSNextBot::GetSuppressingOffset(CKnownEntity *param_1)

{
  float fVar1;
  float *pfVar2;
  CINSNextBot *this;
  CINSNextBot *this_00;
  int unaff_EBX;
  float10 fVar3;
  float10 fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  double dVar17;
  int *in_stack_00000008;
  int *in_stack_0000000c;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x75a51b;
  __i686_get_pc_thunk_bx();
  pfVar2 = (float *)(**(code **)(*in_stack_0000000c + 0x14))();
  fVar1 = *(float *)(unaff_EBX + 0x22c3c5 /* CSWTCH.663+0x14 */ /* CSWTCH.663+0x14 */ /* CSWTCH.663+0x14 */);
  fVar15 = pfVar2[2];
  fVar5 = *pfVar2;
  fVar6 = pfVar2[1];
  (**(code **)(*in_stack_00000008 + 0x20c /* CINSNextBot::EyePosition */))();
  local_48 = fVar6 - local_3c;
  local_4c = fVar5 - local_40;
  fVar14 = local_48 * local_48;
  local_44 = (fVar15 + fVar1) - local_38;
  fVar8 = local_4c * local_4c;
  fVar5 = local_44 * local_44;
  VectorVectors((Vector *)&local_4c,(Vector *)&local_34,(Vector *)&local_28);
  fVar15 = *(float *)(**(int **)(&DAT_0044c385 + unaff_EBX) + 0xc);
  dVar17 = sin((double)(*(float *)(unaff_EBX + 0x1ca245 /* 4.0f */ /* 4.0f */ /* 4.0f */) * fVar15));
  fVar6 = (float)(dVar17 * *(double *)(unaff_EBX + 0x22c3f5 /* CSWTCH.663+0x44 */ /* CSWTCH.663+0x44 */ /* CSWTCH.663+0x44 */));
  fVar10 = local_34 * fVar6;
  fVar11 = local_30 * fVar6;
  fVar6 = fVar6 * local_2c;
  dVar17 = cos((double)(fVar15 * *(float *)(unaff_EBX + 0x1c9575 /* 0.75f */ /* 0.75f */ /* 0.75f */)));
  fVar7 = (float)(dVar17 * *(double *)(unaff_EBX + 0x1ed90d /* 0.0f */ /* 0.0f */ /* 0.0f */));
  fVar9 = local_28 * fVar7;
  fVar12 = local_24 * fVar7;
  fVar7 = fVar7 * local_20;
  fVar3 = (float10)TransientlyConsistentRandomValue(this,(float)in_stack_00000008,0x3f000000 /* 0.5f */);
  fVar4 = (float10)TransientlyConsistentRandomValue(this_00,(float)in_stack_00000008,0x3f000000 /* 0.5f */);
  fVar16 = (float)fVar3 * *(float *)(unaff_EBX + 0x1c9c95 /* 10.0f */ /* 10.0f */ /* 10.0f */);
  fVar13 = (float)fVar4 * *(float *)(unaff_EBX + 0x1c9c95 /* 10.0f */ /* 10.0f */ /* 10.0f */);
  fVar15 = (SQRT(fVar14 + fVar8 + fVar5) + *(float *)(unaff_EBX + 0x22c3c9 /* CSWTCH.663+0x18 */ /* CSWTCH.663+0x18 */ /* CSWTCH.663+0x18 */)) *
           *(float *)(unaff_EBX + 0x22c3cd /* CSWTCH.663+0x1c */ /* CSWTCH.663+0x1c */ /* CSWTCH.663+0x1c */);
  if (*(float *)(unaff_EBX + 0x15e5f9 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= fVar15) {
    fVar15 = *(float *)(unaff_EBX + 0x15e5f9 /* 1.0f */ /* 1.0f */ /* 1.0f */);
  }
  if (fVar15 <= *(float *)(unaff_EBX + 0x15e5ed /* 0.0f */ /* 0.0f */ /* 0.0f */)) {
    fVar15 = *(float *)(unaff_EBX + 0x15e5ed /* 0.0f */ /* 0.0f */ /* 0.0f */);
  }
  *(float *)(param_1 + 4) = (local_24 * fVar13 + local_30 * fVar16 + fVar11 + fVar12) * fVar15;
  *(float *)param_1 = (fVar13 * local_28 + fVar16 * local_34 + fVar10 + fVar9) * fVar15;
  *(float *)(param_1 + 8) = (local_2c * fVar16 + local_20 * fVar13 + fVar1 + fVar6 + fVar7) * fVar15
  ;
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetTarget
 * Address: 00759f60
 * ---------------------------------------- */

/* CINSNextBot::GetTarget() */

void __thiscall CINSNextBot::GetTarget(CINSNextBot *this)

{
  int *piVar1;
  int *in_stack_00000004;
  
  piVar1 = (int *)(**(code **)(*in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
  (**(code **)(*piVar1 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar1,0);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetTargetNoise
 * Address: 0076f3f0
 * ---------------------------------------- */

/* CINSNextBot::GetTargetNoise(CBaseCombatCharacter const*) const */

CBaseCombatCharacter * CINSNextBot::GetTargetNoise(CBaseCombatCharacter *param_1)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  CBaseEntity *this;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CINSNextBot *extraout_ECX_00;
  CINSNextBot *this_01;
  CINSNextBot *this_02;
  CINSNextBot *this_03;
  CINSRules *this_04;
  uint uVar6;
  int unaff_EBX;
  float10 fVar7;
  float10 fVar8;
  float10 fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  CINSWeapon *in_stack_00000008;
  int in_stack_0000000c;
  float local_2c;
  float local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSRules::IsSoloMode();
  if (cVar1 == '\0') {
LAB_0076f425:
    piVar4 = *(int **)(unaff_EBX + 0x5837a1 /* bot_targeting_noise_x_base+0x1c */ /* bot_targeting_noise_x_base+0x1c */ /* bot_targeting_noise_x_base+0x1c */);
    if (piVar4 == (int *)(unaff_EBX + 0x583785 /* bot_targeting_noise_x_base */ /* bot_targeting_noise_x_base */ /* bot_targeting_noise_x_base */U)) {
      local_28 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x5837b1 /* bot_targeting_noise_x_base+0x2c */ /* bot_targeting_noise_x_base+0x2c */ /* bot_targeting_noise_x_base+0x2c */));
      piVar4 = *(int **)(unaff_EBX + 0x583621 /* bot_targeting_noise_y_base+0x1c */ /* bot_targeting_noise_y_base+0x1c */ /* bot_targeting_noise_y_base+0x1c */);
      if (piVar4 != (int *)(unaff_EBX + 0x583605 /* bot_targeting_noise_y_base */ /* bot_targeting_noise_y_base */ /* bot_targeting_noise_y_base */)) goto LAB_0076f458;
LAB_0076f7a0:
      local_2c = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583631 /* bot_targeting_noise_y_base+0x2c */ /* bot_targeting_noise_y_base+0x2c */ /* bot_targeting_noise_y_base+0x2c */));
      piVar2 = *(int **)(unaff_EBX + 0x5834a1 /* bot_targeting_noise_z_base+0x1c */ /* bot_targeting_noise_z_base+0x1c */ /* bot_targeting_noise_z_base+0x1c */);
      if (piVar2 != (int *)(unaff_EBX + 0x583485 /* bot_targeting_noise_z_base */ /* bot_targeting_noise_z_base */ /* bot_targeting_noise_z_base */)) {
LAB_0076f477:
        fVar7 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
        local_24 = (float)fVar7;
        goto LAB_0076f482;
      }
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      piVar4 = *(int **)(unaff_EBX + 0x583621 /* bot_targeting_noise_y_base+0x1c */ /* bot_targeting_noise_y_base+0x1c */ /* bot_targeting_noise_y_base+0x1c */);
      local_28 = (float)fVar7;
      if (piVar4 == (int *)(unaff_EBX + 0x583605 /* bot_targeting_noise_y_base */ /* bot_targeting_noise_y_base */ /* bot_targeting_noise_y_base */)) goto LAB_0076f7a0;
LAB_0076f458:
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      piVar2 = *(int **)(unaff_EBX + 0x5834a1 /* bot_targeting_noise_z_base+0x1c */ /* bot_targeting_noise_z_base+0x1c */ /* bot_targeting_noise_z_base+0x1c */);
      local_2c = (float)fVar7;
      if (piVar2 != (int *)(unaff_EBX + 0x583485 /* bot_targeting_noise_z_base */ /* bot_targeting_noise_z_base */ /* bot_targeting_noise_z_base */)) goto LAB_0076f477;
    }
    local_24 = (float)((uint)piVar2 ^ *(uint *)(unaff_EBX + 0x5834b1 /* bot_targeting_noise_z_base+0x2c */ /* bot_targeting_noise_z_base+0x2c */ /* bot_targeting_noise_z_base+0x2c */));
  }
  else {
    iVar3 = CBaseEntity::GetTeamNumber(this);
    iVar5 = CINSRules::GetHumanTeam(this_04);
    if (iVar3 != iVar5) goto LAB_0076f425;
    piVar2 = *(int **)(&DAT_00583201 + unaff_EBX);
    piVar4 = (int *)(unaff_EBX + 0x5831e5 /* bot_targeting_noise_x_base_solo */ /* bot_targeting_noise_x_base_solo */ /* bot_targeting_noise_x_base_solo */);
    if (piVar2 != piVar4) {
      fVar7 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
      piVar2 = *(int **)(&DAT_00583201 + unaff_EBX);
      local_28 = (float)fVar7;
      if (piVar2 == piVar4) {
        uVar6 = *(uint *)(&LAB_00583211 + unaff_EBX);
        goto LAB_0076f885;
      }
      fVar7 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
      piVar2 = *(int **)(&DAT_00583201 + unaff_EBX);
      local_2c = (float)fVar7;
      if (piVar2 == piVar4) {
        uVar6 = *(uint *)(&LAB_00583211 + unaff_EBX);
        goto LAB_0076f88c;
      }
      goto LAB_0076f477;
    }
    uVar6 = *(uint *)(&LAB_00583211 + unaff_EBX);
    local_28 = (float)((uint)piVar2 ^ uVar6);
LAB_0076f885:
    local_2c = (float)((uint)piVar2 ^ uVar6);
LAB_0076f88c:
    local_24 = (float)((uint)piVar2 ^ uVar6);
  }
LAB_0076f482:
  iVar3 = CINSPlayer::GetActiveINSWeapon();
  if (iVar3 == 0) goto LAB_0076f590;
  this_01 = (CINSNextBot *)this_00;
  if ((*(byte *)(in_stack_0000000c + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_00);
    this_01 = (CINSNextBot *)extraout_ECX;
  }
  if (((byte)in_stack_00000008[0xd1] & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_01);
    this_01 = extraout_ECX_00;
  }
  fVar12 = *(float *)(in_stack_00000008 + 0x208) - *(float *)(in_stack_0000000c + 0x208);
  fVar10 = *(float *)(in_stack_00000008 + 0x20c) - *(float *)(in_stack_0000000c + 0x20c);
  fVar11 = *(float *)(in_stack_00000008 + 0x210) - *(float *)(in_stack_0000000c + 0x210);
  fVar10 = SQRT(fVar10 * fVar10 + fVar12 * fVar12 + fVar11 * fVar11);
  iVar5 = iVar3;
  fVar7 = (float10)GetMaxAttackRange(this_01,in_stack_00000008);
  if ((float)fVar7 < fVar10) {
    piVar4 = *(int **)(unaff_EBX + 0x583681 /* bot_targeting_noise_x_frac_maxrange+0x1c */ /* bot_targeting_noise_x_frac_maxrange+0x1c */ /* bot_targeting_noise_x_frac_maxrange+0x1c */);
    if (piVar4 == (int *)(unaff_EBX + 0x583665 /* bot_targeting_noise_x_frac_maxrange */ /* bot_targeting_noise_x_frac_maxrange */ /* bot_targeting_noise_x_frac_maxrange */U)) {
      fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583691 /* bot_targeting_noise_x_frac_maxrange+0x2c */ /* bot_targeting_noise_x_frac_maxrange+0x2c */ /* bot_targeting_noise_x_frac_maxrange+0x2c */));
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4,iVar5);
      fVar10 = (float)fVar7;
    }
    piVar4 = *(int **)(unaff_EBX + 0x583501 /* bot_targeting_noise_y_frac_maxrange+0x1c */ /* bot_targeting_noise_y_frac_maxrange+0x1c */ /* bot_targeting_noise_y_frac_maxrange+0x1c */);
    local_28 = fVar10 * local_28;
    if (piVar4 == (int *)(unaff_EBX + 0x5834e5 /* bot_targeting_noise_y_frac_maxrange */ /* bot_targeting_noise_y_frac_maxrange */ /* bot_targeting_noise_y_frac_maxrange */U)) {
      fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583511 /* bot_targeting_noise_y_frac_maxrange+0x2c */ /* bot_targeting_noise_y_frac_maxrange+0x2c */ /* bot_targeting_noise_y_frac_maxrange+0x2c */));
    }
    else {
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      fVar10 = (float)fVar7;
    }
    piVar4 = *(int **)(unaff_EBX + 0x583381 /* bot_targeting_noise_z_frac_maxrange+0x1c */ /* bot_targeting_noise_z_frac_maxrange+0x1c */ /* bot_targeting_noise_z_frac_maxrange+0x1c */);
    local_2c = fVar10 * local_2c;
    if (piVar4 == (int *)(unaff_EBX + 0x583365 /* bot_targeting_noise_z_frac_maxrange */ /* bot_targeting_noise_z_frac_maxrange */ /* bot_targeting_noise_z_frac_maxrange */U)) {
      fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583391 /* bot_targeting_noise_z_frac_maxrange+0x2c */ /* bot_targeting_noise_z_frac_maxrange+0x2c */ /* bot_targeting_noise_z_frac_maxrange+0x2c */));
    }
    else {
LAB_0076f680:
      fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
      fVar10 = (float)fVar7;
    }
  }
  else {
    iVar5 = iVar3;
    fVar7 = (float10)GetDesiredAttackRange(this_02,in_stack_00000008);
    if ((float)fVar7 < fVar10) {
      piVar4 = *(int **)(unaff_EBX + 0x5836e1 /* bot_targeting_noise_x_frac_desiredrange+0x1c */ /* bot_targeting_noise_x_frac_desiredrange+0x1c */ /* bot_targeting_noise_x_frac_desiredrange+0x1c */);
      if (piVar4 == (int *)(unaff_EBX + 0x5836c5 /* bot_targeting_noise_x_frac_desiredrange */ /* bot_targeting_noise_x_frac_desiredrange */ /* bot_targeting_noise_x_frac_desiredrange */U)) {
        fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x5836f1 /* bot_targeting_noise_x_frac_desiredrange+0x2c */ /* bot_targeting_noise_x_frac_desiredrange+0x2c */ /* bot_targeting_noise_x_frac_desiredrange+0x2c */));
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4,iVar5);
        fVar10 = (float)fVar7;
      }
      piVar4 = *(int **)(unaff_EBX + 0x583561 /* bot_targeting_noise_y_frac_desiredrange+0x1c */ /* bot_targeting_noise_y_frac_desiredrange+0x1c */ /* bot_targeting_noise_y_frac_desiredrange+0x1c */);
      local_28 = fVar10 * local_28;
      if (piVar4 == (int *)(unaff_EBX + 0x583545 /* bot_targeting_noise_y_frac_desiredrange */ /* bot_targeting_noise_y_frac_desiredrange */ /* bot_targeting_noise_y_frac_desiredrange */U)) {
        fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583571 /* bot_targeting_noise_y_frac_desiredrange+0x2c */ /* bot_targeting_noise_y_frac_desiredrange+0x2c */ /* bot_targeting_noise_y_frac_desiredrange+0x2c */));
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
        fVar10 = (float)fVar7;
      }
      piVar4 = *(int **)(unaff_EBX + 0x5833e1 /* bot_targeting_noise_z_frac_desiredrange+0x1c */ /* bot_targeting_noise_z_frac_desiredrange+0x1c */ /* bot_targeting_noise_z_frac_desiredrange+0x1c */);
      local_2c = fVar10 * local_2c;
      if (piVar4 != (int *)(unaff_EBX + 0x5833c5 /* bot_targeting_noise_z_frac_desiredrange */ /* bot_targeting_noise_z_frac_desiredrange */ /* bot_targeting_noise_z_frac_desiredrange */)) goto LAB_0076f680;
      fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x5833f1 /* bot_targeting_noise_z_frac_desiredrange+0x2c */ /* bot_targeting_noise_z_frac_desiredrange+0x2c */ /* bot_targeting_noise_z_frac_desiredrange+0x2c */));
    }
    else {
      fVar7 = (float10)GetMaxHipFireAttackRange(this_03,in_stack_00000008);
      if (fVar10 <= (float)fVar7) goto LAB_0076f590;
      piVar4 = *(int **)(unaff_EBX + 0x583741 /* bot_targeting_noise_x_frac_hipfirerange+0x1c */ /* bot_targeting_noise_x_frac_hipfirerange+0x1c */ /* bot_targeting_noise_x_frac_hipfirerange+0x1c */);
      if (piVar4 == (int *)(unaff_EBX + 0x583725 /* bot_targeting_noise_x_frac_hipfirerange */ /* bot_targeting_noise_x_frac_hipfirerange */ /* bot_targeting_noise_x_frac_hipfirerange */U)) {
        fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583751 /* bot_targeting_noise_x_frac_hipfirerange+0x2c */ /* bot_targeting_noise_x_frac_hipfirerange+0x2c */ /* bot_targeting_noise_x_frac_hipfirerange+0x2c */));
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4,iVar3);
        fVar10 = (float)fVar7;
      }
      piVar4 = *(int **)(unaff_EBX + 0x5835c1 /* bot_targeting_noise_y_frac_hipfirerange+0x1c */ /* bot_targeting_noise_y_frac_hipfirerange+0x1c */ /* bot_targeting_noise_y_frac_hipfirerange+0x1c */);
      local_28 = fVar10 * local_28;
      if (piVar4 == (int *)(unaff_EBX + 0x5835a5 /* bot_targeting_noise_y_frac_hipfirerange */ /* bot_targeting_noise_y_frac_hipfirerange */ /* bot_targeting_noise_y_frac_hipfirerange */U)) {
        fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x5835d1 /* bot_targeting_noise_y_frac_hipfirerange+0x2c */ /* bot_targeting_noise_y_frac_hipfirerange+0x2c */ /* bot_targeting_noise_y_frac_hipfirerange+0x2c */));
      }
      else {
        fVar7 = (float10)(**(code **)(*piVar4 + 0x3c))(piVar4);
        fVar10 = (float)fVar7;
      }
      piVar4 = *(int **)(unaff_EBX + 0x583441 /* bot_targeting_noise_z_frac_hipfirerange+0x1c */ /* bot_targeting_noise_z_frac_hipfirerange+0x1c */ /* bot_targeting_noise_z_frac_hipfirerange+0x1c */);
      local_2c = fVar10 * local_2c;
      if (piVar4 != (int *)(unaff_EBX + 0x583425 /* bot_targeting_noise_z_frac_hipfirerange */ /* bot_targeting_noise_z_frac_hipfirerange */ /* bot_targeting_noise_z_frac_hipfirerange */)) goto LAB_0076f680;
      fVar10 = (float)((uint)piVar4 ^ *(uint *)(unaff_EBX + 0x583451 /* bot_targeting_noise_z_frac_hipfirerange+0x2c */ /* bot_targeting_noise_z_frac_hipfirerange+0x2c */ /* bot_targeting_noise_z_frac_hipfirerange+0x2c */));
    }
  }
  local_24 = fVar10 * local_24;
LAB_0076f590:
  fVar7 = (float10)RandomFloat((uint)local_24 ^ *(uint *)(unaff_EBX + 0x1b5805 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */),local_24);
  fVar8 = (float10)RandomFloat((uint)local_2c ^ *(uint *)(unaff_EBX + 0x1b5805 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */),local_2c);
  fVar9 = (float10)RandomFloat((uint)local_28 ^ *(uint *)(unaff_EBX + 0x1b5805 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */),local_28);
  *(float *)param_1 = (float)fVar9;
  *(float *)(param_1 + 4) = (float)fVar8;
  *(float *)(param_1 + 8) = (float)fVar7;
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetTargetPosition
 * Address: 00746a10
 * ---------------------------------------- */

/* CINSNextBot::GetTargetPosition(CBaseCombatCharacter const*) */

CBaseCombatCharacter * CINSNextBot::GetTargetPosition(CBaseCombatCharacter *param_1)

{
  uint *puVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  code *pcVar5;
  char cVar6;
  char cVar7;
  char cVar8;
  int *piVar9;
  int *piVar10;
  Vector *pVVar11;
  CKnownEntity *pCVar12;
  uint uVar13;
  int iVar14;
  undefined4 uVar15;
  float *pfVar16;
  undefined4 *puVar17;
  CINSPlayer *this;
  CINSWeapon *this_00;
  CINSPlayer *this_01;
  CINSNextBot *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CINSNextBot *extraout_ECX_01;
  CINSNextBot *extraout_ECX_02;
  CINSNextBot *this_02;
  int iVar18;
  int unaff_EBX;
  bool bVar19;
  bool bVar20;
  float10 fVar21;
  CKnownEntity *in_stack_00000008;
  int *in_stack_0000000c;
  CKnownEntity *pCVar22;
  float local_3c;
  int local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  __i686_get_pc_thunk_bx();
  pfVar16 = *(float **)(unaff_EBX + 0x45fbb1 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  local_28 = pfVar16[1];
  local_2c = *pfVar16;
  local_24 = pfVar16[2];
  if (in_stack_0000000c == (int *)0x0) {
    *(float *)param_1 = local_2c;
    *(float *)(param_1 + 8) = local_24;
    *(float *)(param_1 + 4) = local_28;
    return param_1;
  }
  cVar6 = (**(code **)(*in_stack_0000000c + 0x158 /* CBasePlayer::IsPlayer */))(in_stack_0000000c);
  if (cVar6 == '\0') {
    puVar17 = (undefined4 *)(**(code **)(*in_stack_0000000c + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_0000000c);
    *(undefined4 *)param_1 = *puVar17;
    uVar15 = puVar17[2];
    *(undefined4 *)(param_1 + 4) = puVar17[1];
    *(undefined4 *)(param_1 + 8) = uVar15;
    return param_1;
  }
  piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
  piVar9 = (int *)(**(code **)(*piVar9 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar9,1);
  piVar10 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
  pVVar11 = (Vector *)(**(code **)(*piVar10 + 0xe4 /* IVision::GetKnown */))(piVar10,in_stack_0000000c);
  if ((piVar9 == (int *)0x0) ||
     (piVar9 = (int *)(**(code **)(*piVar9 + 0x10))(piVar9), in_stack_0000000c != piVar9)) {
    cVar6 = pVVar11 != (Vector *)0x0;
  }
  else {
    cVar6 = '\x02';
  }
  pCVar22 = in_stack_00000008;
  pCVar12 = (CKnownEntity *)CINSPlayer::GetActiveINSWeapon();
  local_3c = *(float *)(unaff_EBX + 0x23cb71 /* 1800.0f */ /* 1800.0f */ /* 1800.0f */);
  this_01 = this;
  if (pCVar12 != (CKnownEntity *)0x0) {
    uVar13 = CINSPlayer::GetPlayerFlags(this);
    pCVar22 = pCVar12;
    cVar7 = (**(code **)(*(int *)pCVar12 + 0x620 /* CINSPlayer::FlashlightIsOn */))(pCVar12);
    this_01 = (CINSPlayer *)this_00;
    if ((cVar7 != '\0') && ((uVar13 & 1) != 0)) {
      fVar21 = (float10)CINSWeapon::GetFOVWeaponScope(this_00);
      uVar13 = -(uint)((float)fVar21 < *(float *)(unaff_EBX + 0x1ddd49 /* 20.0f */ /* 20.0f */ /* 20.0f */));
      local_3c = (float)(~uVar13 & *(uint *)(unaff_EBX + 0x23cb6d /* 2700.0f */ /* 2700.0f */ /* 2700.0f */) |
                        *(uint *)(unaff_EBX + 0x23cb69 /* 4500.0f */ /* 4500.0f */ /* 4500.0f */) & uVar13);
      this_01 = (CINSPlayer *)extraout_ECX_00;
      pCVar22 = pCVar12;
    }
  }
  if (((byte)in_stack_00000008[0xd1] & 8) != 0) {
    pCVar22 = in_stack_00000008;
    CBaseEntity::CalcAbsolutePosition((CBaseEntity *)this_01);
  }
  fVar2 = *(float *)(in_stack_00000008 + 0x208);
  fVar3 = *(float *)(in_stack_00000008 + 0x20c);
  fVar4 = *(float *)(in_stack_00000008 + 0x210);
  bVar19 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if ((bVar19) &&
     (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
     iVar14 = ThreadGetCurrentId(pCVar22), iVar18 == iVar14)) {
    piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
      piVar9 = (int *)CVProfNode::GetSubNode
                                ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                 unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
    }
    puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
  pcVar5 = *(code **)(*piVar9 + 0x108);
  uVar15 = GetPartPosition();
  cVar7 = (*pcVar5)(piVar9,uVar15,0);
  if ((bVar19) &&
     (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
       (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
      (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar14 = ThreadGetCurrentId(),
      iVar18 == iVar14)))) {
    piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    cVar8 = CVProfNode::ExitScope();
    if (cVar8 == '\0') {
      iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar18 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar18;
    }
    *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
         iVar18 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  }
  if (cVar7 == '\0') {
    bVar19 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
    if ((bVar19) &&
       (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
       iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
      piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
        piVar9 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                   unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
        *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
      }
      puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
    }
    piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
    pcVar5 = *(code **)(*piVar9 + 0x108);
    uVar15 = GetPartPosition();
    cVar7 = (*pcVar5)(piVar9,uVar15,0);
    if (((bVar19) &&
        ((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
         (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)))) &&
       (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar14 = ThreadGetCurrentId(),
       iVar18 == iVar14)) {
      piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      cVar8 = CVProfNode::ExitScope();
      if (cVar8 == '\0') {
        iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      }
      else {
        iVar18 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
        *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar18;
      }
      *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
           iVar18 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
    }
    if (cVar7 == '\0') {
      bVar19 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
      if ((bVar19) &&
         (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
         iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
        piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
        if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
          piVar9 = (int *)CVProfNode::GetSubNode
                                    ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                     unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
          *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
        }
        puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
        *puVar1 = *puVar1 | 4;
        CVProfNode::EnterScope();
        *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
      }
      piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
      pcVar5 = *(code **)(*piVar9 + 0x108);
      uVar15 = GetPartPosition();
      cVar7 = (*pcVar5)(piVar9,uVar15,0);
      if ((bVar19) &&
         (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
           (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
          (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar14 = ThreadGetCurrentId()
          , iVar18 == iVar14)))) {
        piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
        cVar8 = CVProfNode::ExitScope();
        if (cVar8 == '\0') {
          iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
        }
        else {
          iVar18 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
          *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar18;
        }
        *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
             iVar18 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
      }
      bVar19 = local_3c <=
               SQRT((fVar3 - local_28) * (fVar3 - local_28) +
                    (fVar2 - local_2c) * (fVar2 - local_2c) +
                    (fVar4 - local_24) * (fVar4 - local_24));
      if (((cVar7 == '\0') || (bVar19)) || (cVar6 == '\0')) {
        bVar20 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
        if ((bVar20) &&
           (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
           iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
          piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
          if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
            piVar9 = (int *)CVProfNode::GetSubNode
                                      ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                       unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
            *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
          }
          puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4
                           );
          *puVar1 = *puVar1 | 4;
          CVProfNode::EnterScope();
          *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
        }
        piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
        pcVar5 = *(code **)(*piVar9 + 0x108);
        uVar15 = GetPartPosition();
        cVar7 = (*pcVar5)(piVar9,uVar15,0);
        if ((bVar20) &&
           (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
             (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
            (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
            iVar14 = ThreadGetCurrentId(), iVar18 == iVar14)))) {
          piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
          cVar8 = CVProfNode::ExitScope();
          if (cVar8 == '\0') {
            iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
          }
          else {
            iVar18 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
            *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar18;
          }
          *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
               iVar18 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
        }
        if (((cVar7 == '\0') || (bVar19)) || (cVar6 == '\0')) {
          bVar20 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
          if ((bVar20) &&
             (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
             iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
            piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
            if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
              piVar9 = (int *)CVProfNode::GetSubNode
                                        ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                         unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
              *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
            }
            puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) +
                             4);
            *puVar1 = *puVar1 | 4;
            CVProfNode::EnterScope();
            *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
          }
          piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
          pcVar5 = *(code **)(*piVar9 + 0x108);
          uVar15 = GetPartPosition();
          cVar7 = (*pcVar5)(piVar9,uVar15,0);
          if ((bVar20) &&
             (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
               (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
              (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
              iVar14 = ThreadGetCurrentId(), iVar18 == iVar14)))) {
            piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
            cVar8 = CVProfNode::ExitScope();
            if (cVar8 == '\0') {
              iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
            }
            else {
              iVar18 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
              *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar18;
            }
            *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
                 iVar18 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
          }
          if (((cVar7 == '\0') || (bVar19)) || (cVar6 != '\x02')) {
            bVar20 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
            if ((bVar20) &&
               (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
               iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
              piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
              if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
                piVar9 = (int *)CVProfNode::GetSubNode
                                          ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                           unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
                *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
              }
              puVar1 = (uint *)(piVar9[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0)
                               + 4);
              *puVar1 = *puVar1 | 4;
              CVProfNode::EnterScope();
              *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
            }
            piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
            pcVar5 = *(code **)(*piVar9 + 0x108);
            uVar15 = GetPartPosition();
            cVar7 = (*pcVar5)(piVar9,uVar15,0);
            if ((bVar20) &&
               (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
                 (*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)) &&
                (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
                iVar14 = ThreadGetCurrentId(), iVar18 == iVar14)))) {
              piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
              cVar8 = CVProfNode::ExitScope();
              if (cVar8 == '\0') {
                local_30 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
              }
              else {
                local_30 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
                *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = local_30;
              }
              *(bool *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
                   local_30 == *(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
            }
            if (((cVar7 == '\0') || (bVar19)) || (cVar6 != '\x02')) {
              bVar19 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
              if ((bVar19) &&
                 (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
                 iVar14 = ThreadGetCurrentId(piVar9), iVar18 == iVar14)) {
                piVar9 = *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
                if (*piVar9 != unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */) {
                  piVar9 = (int *)CVProfNode::GetSubNode
                                            ((char *)piVar9,unaff_EBX + 0x23c885 /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */ /* "CINSNextBot::IsEnemyPartVisible" */,(char *)0x0,
                                             unaff_EBX + 0x23a24b /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
                  *(int **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar9;
                }
                puVar1 = (uint *)(piVar9[0x1c] * 8 +
                                  *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
                *puVar1 = *puVar1 | 4;
                CVProfNode::EnterScope();
                *(undefined1 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
              }
              piVar9 = (int *)(**(code **)(*(int *)in_stack_00000008 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000008);
              pcVar5 = *(code **)(*piVar9 + 0x108);
              uVar15 = GetPartPosition();
              cVar6 = (*pcVar5)(piVar9,uVar15,0);
              this_02 = extraout_ECX_01;
              if ((bVar19) &&
                 (((*(char *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
                   (this_02 = *(CINSNextBot **)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c),
                   this_02 != (CINSNextBot *)0x0)) &&
                  (iVar18 = *(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8),
                  iVar14 = ThreadGetCurrentId(), this_02 = extraout_ECX_02, iVar18 == iVar14)))) {
                cVar7 = CVProfNode::ExitScope();
                if (cVar7 != '\0') {
                  *(undefined4 *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) =
                       *(undefined4 *)(*(int *)(*(int *)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
                }
                this_02 = *(CINSNextBot **)(unaff_EBX + 0x45ff59 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
                this_02[0x1010] =
                     (CINSNextBot)(*(CINSNextBot **)(this_02 + 0x1014) == this_02 + 0x1018);
              }
              if (cVar6 == '\0') goto LAB_00746c4b;
            }
          }
        }
      }
    }
  }
  pfVar16 = (float *)GetPartPosition();
  local_2c = *pfVar16;
  local_28 = pfVar16[1];
  local_24 = pfVar16[2];
  this_02 = extraout_ECX;
LAB_00746c4b:
  pfVar16 = *(float **)(unaff_EBX + 0x45fbb1 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  if (((local_2c != *pfVar16) || (pfVar16[1] != local_28)) || (pfVar16[2] != local_24)) {
    ApplyAimPenalty(this_02,in_stack_00000008,pVVar11);
  }
  *(float *)param_1 = local_2c;
  *(float *)(param_1 + 4) = local_28;
  *(float *)(param_1 + 8) = local_24;
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetTravelDistance
 * Address: 00744f50
 * ---------------------------------------- */

/* CINSNextBot::GetTravelDistance(Vector, float) */

float10 __cdecl
CINSNextBot::GetTravelDistance
          (Vector *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  uint *puVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  Vector *pVVar6;
  int *piVar7;
  CNavArea *this;
  CBaseEntity *this_00;
  int unaff_EBX;
  bool bVar8;
  float10 fVar9;
  Vector *pVVar10;
  undefined4 *puVar11;
  int iVar12;
  undefined4 uVar13;
  undefined4 uVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  
  __i686_get_pc_thunk_bx();
  iVar3 = *(int *)(unaff_EBX + 0x461a19 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
  bVar8 = *(int *)(iVar3 + 0x100c) != 0;
  if (bVar8) {
    iVar12 = *(int *)(iVar3 + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar12 == iVar5) {
      piVar7 = *(int **)(iVar3 + 0x1014);
      if (*piVar7 != unaff_EBX + 0x23e2dd /* "CINSNextBot::GetTravelDistance" */ /* "CINSNextBot::GetTravelDistance" */ /* "CINSNextBot::GetTravelDistance" */) {
        piVar7 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar7,unaff_EBX + 0x23e2dd /* "CINSNextBot::GetTravelDistance" */ /* "CINSNextBot::GetTravelDistance" */ /* "CINSNextBot::GetTravelDistance" */,(char *)0x0,
                                   (int)(&UNK_0023bd0b + unaff_EBX));
        *(int **)(iVar3 + 0x1014) = piVar7;
      }
      puVar1 = (uint *)(*(int *)(iVar3 + 0x10a0) + piVar7[0x1c] * 8 + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      *(undefined1 *)(iVar3 + 0x1010) = 0;
    }
  }
  puVar11 = &param_2;
  uVar16 = 0;
  uVar15 = 1;
  uVar14 = 0;
  uVar13 = 0x461c4000 /* 10000.0f */;
  iVar12 = 0;
  pVVar10 = (Vector *)**(undefined4 **)(unaff_EBX + 0x46175d /* &TheNavMesh */ /* &TheNavMesh */ /* &TheNavMesh */);
  pVVar6 = (Vector *)CNavMesh::GetNearestNavArea();
  if (pVVar6 != (Vector *)0x0) {
    puVar11 = &param_2;
    iVar12 = 0;
    cVar4 = CNavArea::IsOverlapping(this,pVVar6,(float)puVar11);
    pVVar10 = pVVar6;
    if (cVar4 != '\0') {
      pVVar10 = param_1;
      iVar5 = (**(code **)(*(int *)param_1 + 0x548 /* CINSNextBot::GetLastKnownArea */))
                        (param_1,puVar11,iVar12,uVar13,uVar14,uVar15,uVar16);
      if (iVar5 != 0) {
        if (((byte)param_1[0xd1] & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_00);
        }
        puVar11 = *(undefined4 **)(param_1 + 0x208);
        iVar12 = *(int *)(param_1 + 0x20c);
        pVVar10 = (Vector *)**(undefined4 **)(unaff_EBX + 0x46199d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
        fVar9 = (float10)CINSRules::GetTravelDistanceBetweenPoints
                                   (pVVar10,puVar11,iVar12,*(int *)(param_1 + 0x210),param_2,param_3
                                    ,param_4);
        goto LAB_00744ff8;
      }
    }
  }
  fVar9 = -(float10)1;
LAB_00744ff8:
  if ((bVar8) && ((*(char *)(iVar3 + 0x1010) == '\0' || (*(int *)(iVar3 + 0x100c) != 0)))) {
    iVar5 = *(int *)(iVar3 + 0x19b8);
    fVar2 = (float)fVar9;
    iVar12 = ThreadGetCurrentId(pVVar10,puVar11,iVar12);
    fVar9 = (float10)fVar2;
    if (iVar5 == iVar12) {
      cVar4 = CVProfNode::ExitScope();
      iVar12 = *(int *)(iVar3 + 0x1014);
      if (cVar4 != '\0') {
        iVar12 = *(int *)(iVar12 + 100);
        *(int *)(iVar3 + 0x1014) = iVar12;
      }
      *(bool *)(iVar3 + 0x1010) = iVar12 == iVar3 + 0x1018;
      return (float10)fVar2;
    }
  }
  return fVar9;
}



/* ----------------------------------------
 * CINSNextBot::GetViewPosition
 * Address: 00746950
 * ---------------------------------------- */

/* CINSNextBot::GetViewPosition(Vector) */

undefined4 *
CINSNextBot::GetViewPosition
          (undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
          float param_5)

{
  char cVar1;
  CINSPlayer *this;
  CINSPlayer *this_00;
  int unaff_EBX;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSPlayer::IsCrouched(this);
  if ((cVar1 == '\0') && (cVar1 = CINSPlayer::IsProned(this_00), cVar1 == '\0')) {
    *param_1 = param_3;
    param_1[1] = param_4;
    param_1[2] = param_5 + *(float *)(unaff_EBX + 0x217715 /* 69.0f */ /* 69.0f */ /* 69.0f */);
    return param_1;
  }
  *param_1 = param_3;
  param_1[1] = param_4;
  param_1[2] = param_5 + *(float *)(unaff_EBX + 0x21773d /* 55.0f */ /* 55.0f */ /* 55.0f */);
  return param_1;
}



/* ----------------------------------------
 * CINSNextBot::GetVisionInterface
 * Address: 0074c2f0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::GetVisionInterface() const */

void __thiscall CINSNextBot::GetVisionInterface(CINSNextBot *this)

{
  GetVisionInterface(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::GetVisionInterface
 * Address: 0074c300
 * ---------------------------------------- */

/* CINSNextBot::GetVisionInterface() const */

undefined4 __thiscall CINSNextBot::GetVisionInterface(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined4 *)(in_stack_00000004 + 0xb350);
}



/* ----------------------------------------
 * CINSNextBot::HasExplosive
 * Address: 0076f920
 * ---------------------------------------- */

/* CINSNextBot::HasExplosive() */

undefined4 CINSNextBot::HasExplosive(void)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  CINSPlayer *this;
  int unaff_EBX;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  
  iVar1 = __i686_get_pc_thunk_bx();
  uVar4 = 0;
  uVar6 = 0;
  uVar5 = 3;
  piVar2 = (int *)CINSPlayer::GetWeaponInSlot(this,iVar1,true);
  if (piVar2 != (int *)0x0) {
    pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2,uVar5,uVar6);
    iVar1 = _V_strcmp((char *)(unaff_EBX + 0x217914 /* "weapon_rpg7" */ /* "weapon_rpg7" */ /* "weapon_rpg7" */),pcVar3);
    if (iVar1 != 0) {
      pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2);
      iVar1 = _V_strcmp((char *)(unaff_EBX + 0x217920 /* "weapon_at4" */ /* "weapon_at4" */ /* "weapon_at4" */),pcVar3);
      if (iVar1 != 0) {
        pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2);
        iVar1 = _V_strcmp((char *)(unaff_EBX + 0x21792b /* "weapon_c4_clicker" */ /* "weapon_c4_clicker" */ /* "weapon_c4_clicker" */),pcVar3);
        if (iVar1 != 0) {
          pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2);
          iVar1 = _V_strcmp((char *)(unaff_EBX + 0x21793d /* "weapon_c4_ied" */ /* "weapon_c4_ied" */ /* "weapon_c4_ied" */),pcVar3);
          if (iVar1 != 0) {
            pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2);
            iVar1 = _V_strcmp((char *)(unaff_EBX + 0x21794b /* "weapon_rgd5" */ /* "weapon_rgd5" */ /* "weapon_rgd5" */),pcVar3);
            if (iVar1 != 0) {
              pcVar3 = (char *)(**(code **)(*piVar2 + 0x538 /* CBaseCombatCharacter::AddFactionRelationship */))(piVar2);
              iVar1 = _V_strcmp((char *)(unaff_EBX + 0x217957 /* "weapon_m67" */ /* "weapon_m67" */ /* "weapon_m67" */),pcVar3);
              if (iVar1 != 0) {
                return 0;
              }
            }
          }
        }
      }
    }
    uVar4 = (**(code **)(*piVar2 + 0x3cc /* CBaseFlex::ScriptGetOldestScene */))(piVar2);
  }
  return uVar4;
}



/* ----------------------------------------
 * CINSNextBot::HasInvestigations
 * Address: 00747e80
 * ---------------------------------------- */

/* CINSNextBot::HasInvestigations() */

undefined4 __thiscall CINSNextBot::HasInvestigations(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return CONCAT31((int3)((uint)*(int *)(in_stack_00000004 + 0xb468) >> 8),
                  0 < *(int *)(in_stack_00000004 + 0xb468));
}



/* ----------------------------------------
 * CINSNextBot::HasOrders
 * Address: 00748030
 * ---------------------------------------- */

/* CINSNextBot::HasOrders() */

undefined4 __thiscall CINSNextBot::HasOrders(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return CONCAT31((int3)((uint)*(int *)(in_stack_00000004 + 0xb47c) >> 8),
                  0 < *(int *)(in_stack_00000004 + 0xb47c));
}



/* ----------------------------------------
 * CINSNextBot::IsDebugging
 * Address: 00743450
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::IsDebugging(unsigned int) const */

void __thiscall CINSNextBot::IsDebugging(CINSNextBot *this,uint param_1)

{
  IsDebugging(param_1 - 0x2060);
  return;
}



/* ----------------------------------------
 * CINSNextBot::IsDebugging
 * Address: 00743460
 * ---------------------------------------- */

/* CINSNextBot::IsDebugging(unsigned int) const */

bool __cdecl CINSNextBot::IsDebugging(uint param_1)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  INextBot *this;
  int unaff_EBX;
  bool bVar6;
  
  uVar2 = __i686_get_pc_thunk_bx();
  bVar6 = false;
  cVar1 = INextBot::IsDebugging(this,param_1 + 0x2060);
  if (cVar1 != '\0') {
    bVar6 = true;
    iVar3 = (**(code **)(**(int **)(unaff_EBX + 0x46314f /* &nb_debug_spectatefilter */ /* &nb_debug_spectatefilter */ /* &nb_debug_spectatefilter */) + 0x40))
                      (*(int **)(unaff_EBX + 0x46314f /* &nb_debug_spectatefilter */ /* &nb_debug_spectatefilter */ /* &nb_debug_spectatefilter */),uVar2);
    if (iVar3 != 0) {
      if (*(int *)(**(int **)(unaff_EBX + 0x46342f /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x14) < 2) {
        piVar4 = (int *)UTIL_GetLocalPlayer();
      }
      else {
        cVar1 = (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x4631b7 /* &engine */ /* &engine */ /* &engine */) + 8))
                          ((int *)**(undefined4 **)(unaff_EBX + 0x4631b7 /* &engine */ /* &engine */ /* &engine */));
        if (cVar1 != '\0') {
          return true;
        }
        piVar4 = (int *)UTIL_GetListenServerHost();
      }
      bVar6 = true;
      if ((piVar4 != (int *)0x0) && ((*(byte *)(piVar4 + 0x3e6) & 8) != 0)) {
        iVar3 = (**(code **)(*piVar4 + 0x678 /* CBasePlayer::GetObserverMode */))(piVar4);
        if ((iVar3 != 4) && (iVar3 = (**(code **)(*piVar4 + 0x678 /* CBasePlayer::GetObserverMode */))(piVar4), iVar3 != 5)) {
          return true;
        }
        uVar5 = (**(code **)(*piVar4 + 0x684 /* CBasePlayer::GetObserverTarget */))(piVar4);
        bVar6 = uVar5 == param_1;
      }
    }
  }
  return bVar6;
}



/* ----------------------------------------
 * CINSNextBot::IsDormantWhenDead
 * Address: 0074c360
 * ---------------------------------------- */

/* CINSNextBot::IsDormantWhenDead() const */

undefined4 CINSNextBot::IsDormantWhenDead(void)

{
  return 0;
}



/* ----------------------------------------
 * CINSNextBot::IsEntityBetweenTargetAndSelf
 * Address: 00745ab0
 * ---------------------------------------- */

/* CINSNextBot::IsEntityBetweenTargetAndSelf(CBaseEntity*, CBaseEntity*) */

undefined4 __thiscall
CINSNextBot::IsEntityBetweenTargetAndSelf
          (CINSNextBot *this,CBaseEntity *param_1,CBaseEntity *param_2)

{
  undefined4 uVar1;
  CBaseEntity *this_00;
  CBaseEntity *extraout_ECX;
  CBaseEntity *this_01;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if ((in_stack_0000000c != 0) && (param_2 != (CBaseEntity *)0x0)) {
    this_01 = this_00;
    if ((*(byte *)(in_stack_0000000c + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
      this_01 = extraout_ECX;
    }
    if (((byte)param_2[0xd1] & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_01);
    }
    uVar1 = IsPointBetweenTargetAndSelf
                      (param_1,*(undefined4 *)(param_2 + 0x208),*(undefined4 *)(param_2 + 0x20c),
                       *(undefined4 *)(param_2 + 0x210),*(undefined4 *)(in_stack_0000000c + 0x208),
                       *(undefined4 *)(in_stack_0000000c + 0x20c),
                       *(undefined4 *)(in_stack_0000000c + 0x210));
    return uVar1;
  }
  return 0;
}



/* ----------------------------------------
 * CINSNextBot::IsEscorting
 * Address: 00747ba0
 * ---------------------------------------- */

/* CINSNextBot::IsEscorting() */

undefined4 __thiscall CINSNextBot::IsEscorting(CINSNextBot *this)

{
  int iVar1;
  undefined4 extraout_EDX;
  undefined4 uVar2;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  uVar2 = extraout_EDX;
  if (*(int *)(in_stack_00000004 + 0xb32c) != -1) {
    iVar1 = UTIL_PlayerByIndex(*(int *)(in_stack_00000004 + 0xb32c));
    uVar2 = 1;
    if (iVar1 == 0) {
      *(undefined4 *)(in_stack_00000004 + 0xb32c) = 0xffffffff;
      *(undefined4 *)(in_stack_00000004 + 0xb330) = 0;
      return 0;
    }
  }
  return uVar2;
}



/* ----------------------------------------
 * CINSNextBot::IsFollowingOrder
 * Address: 00747ec0
 * ---------------------------------------- */

/* CINSNextBot::IsFollowingOrder() const */

undefined1 __thiscall CINSNextBot::IsFollowingOrder(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined1 *)(in_stack_00000004 + 0x2293);
}



/* ----------------------------------------
 * CINSNextBot::IsIdle
 * Address: 00748230
 * ---------------------------------------- */

/* CINSNextBot::IsIdle() */

undefined1 __thiscall CINSNextBot::IsIdle(CINSNextBot *this)

{
  undefined1 uVar1;
  int unaff_EBX;
  float10 extraout_ST0;
  float fVar2;
  int in_stack_00000004;
  
  fVar2 = 0.0;
  uVar1 = __i686_get_pc_thunk_bx();
  if (fVar2 < *(float *)(in_stack_00000004 + 0xb3c8)) {
    IntervalTimer::Now();
    fVar2 = (float)extraout_ST0 - *(float *)(in_stack_00000004 + 0xb3c8);
    uVar1 = *(float *)(unaff_EBX + 0x170d33 /* 3.0f */ /* 3.0f */ /* 3.0f */) <= fVar2 && fVar2 != *(float *)(unaff_EBX + 0x170d33 /* 3.0f */ /* 3.0f */ /* 3.0f */);
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::IsInCombat
 * Address: 0074db00
 * ---------------------------------------- */

/* CINSNextBot::IsInCombat() const */

bool __thiscall CINSNextBot::IsInCombat(CINSNextBot *this)

{
  int unaff_EBX;
  bool bVar1;
  float10 fVar2;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar2 = (float10)(**(code **)(*in_stack_00000004 + 0x8a4 /* CINSPlayer::GetTimeSinceWeaponFired */))();
  bVar1 = true;
  if (*(float *)(unaff_EBX + 0x1d6c58 /* 5.0f */ /* 5.0f */ /* 5.0f */) < (float)fVar2) {
    if ((0.0 < (float)in_stack_00000004[0x2ce1]) &&
       (fVar2 = (float10)CountdownTimer::Now(),
       (float)fVar2 < (float)in_stack_00000004[0x2ce1] ||
       (float)fVar2 == (float)in_stack_00000004[0x2ce1])) {
      return true;
    }
    bVar1 = in_stack_00000004[0x2cce] != -1;
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSNextBot::IsInCover
 * Address: 00744db0
 * ---------------------------------------- */

/* CINSNextBot::IsInCover() */

bool __thiscall CINSNextBot::IsInCover(CINSNextBot *this)

{
  float *pfVar1;
  CBaseEntity *this_00;
  CBaseEntity *pCVar2;
  CBaseEntity *extraout_ECX;
  int unaff_EBX;
  float fVar3;
  float fVar4;
  float fVar5;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar5 = *(float *)(in_stack_00000004 + 0x2198);
  pfVar1 = *(float **)(unaff_EBX + 0x46180e /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
  pCVar2 = this_00;
  if (((*pfVar1 == fVar5) && (pfVar1[1] == *(float *)(in_stack_00000004 + 0x219c))) &&
     (pfVar1[2] == *(float *)(in_stack_00000004 + 0x21a0))) {
    fVar5 = *(float *)(in_stack_00000004 + 0x21a8);
    if (fVar5 != *pfVar1) goto LAB_00744ec0;
  }
  else {
    if ((*(byte *)(in_stack_00000004 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this_00);
      fVar5 = *(float *)(in_stack_00000004 + 0x2198);
      pCVar2 = extraout_ECX;
    }
    fVar5 = *(float *)(in_stack_00000004 + 0x208) - fVar5;
    fVar3 = *(float *)(in_stack_00000004 + 0x20c) - *(float *)(in_stack_00000004 + 0x219c);
    fVar4 = *(float *)(in_stack_00000004 + 0x210) - *(float *)(in_stack_00000004 + 0x21a0);
    if (fVar3 * fVar3 + fVar5 * fVar5 + fVar4 * fVar4 < *(float *)(unaff_EBX + 0x23e7c2 /* 2304.0f */ /* 2304.0f */ /* 2304.0f */)) {
      return true;
    }
    fVar5 = *(float *)(in_stack_00000004 + 0x21a8);
    if (fVar5 != *pfVar1) goto LAB_00744ec0;
  }
  if ((pfVar1[1] == *(float *)(in_stack_00000004 + 0x21ac)) &&
     (pfVar1[2] == *(float *)(in_stack_00000004 + 0x21b0))) {
    return false;
  }
LAB_00744ec0:
  if ((*(byte *)(in_stack_00000004 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(pCVar2);
    fVar5 = *(float *)(in_stack_00000004 + 0x21a8);
  }
  fVar5 = *(float *)(in_stack_00000004 + 0x208) - fVar5;
  fVar3 = *(float *)(in_stack_00000004 + 0x20c) - *(float *)(in_stack_00000004 + 0x21ac);
  fVar4 = *(float *)(in_stack_00000004 + 0x210) - *(float *)(in_stack_00000004 + 0x21b0);
  return fVar3 * fVar3 + fVar5 * fVar5 + fVar4 * fVar4 < *(float *)(unaff_EBX + 0x23e7c2 /* 2304.0f */ /* 2304.0f */ /* 2304.0f */);
}



/* ----------------------------------------
 * CINSNextBot::IsInFormation
 * Address: 00747cc0
 * ---------------------------------------- */

/* CINSNextBot::IsInFormation() */

bool __thiscall CINSNextBot::IsInFormation(CINSNextBot *this)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  int unaff_EBX;
  int iVar8;
  float10 extraout_ST0;
  int in_stack_00000004;
  int local_28;
  int local_24;
  int local_20;
  undefined4 uStack_14;
  
  uStack_14 = 0x747ccb;
  __i686_get_pc_thunk_bx();
  iVar2 = *(int *)(in_stack_00000004 + 0xb334);
  bVar5 = true;
  if (iVar2 != 0) {
    iVar8 = 0;
    if (*(int *)(in_stack_00000004 + 0x20) != 0) {
      iVar8 = *(int *)(in_stack_00000004 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x45ebd5 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c)
              >> 4;
    }
    piVar3 = *(int **)(unaff_EBX + 0x45e901 /* &vec3_origin */ /* &vec3_origin */ /* &vec3_origin */);
    local_28 = *piVar3;
    local_24 = piVar3[1];
    local_20 = piVar3[2];
    if (0 < *(int *)(iVar2 + 0x2c)) {
      piVar4 = *(int **)(iVar2 + 0x20);
      iVar6 = 0;
      iVar7 = 0x18;
      iVar1 = *piVar4;
      piVar3 = piVar4;
      while (iVar8 != iVar1) {
        iVar6 = iVar6 + 1;
        if (iVar6 == *(int *)(iVar2 + 0x2c)) goto LAB_00747d52;
        piVar3 = (int *)((int)piVar4 + iVar7);
        iVar7 = iVar7 + 0x18;
        iVar1 = *piVar3;
      }
      local_28 = piVar3[3];
      local_24 = piVar3[4];
      local_20 = piVar3[5];
    }
LAB_00747d52:
    (**(code **)(*(int *)(in_stack_00000004 + 0x2060) + 0x134))
              (in_stack_00000004 + 0x2060,&local_28);
    bVar5 = (float)extraout_ST0 < *(float *)(unaff_EBX + 0x1dd36d /* 180.0f */ /* 180.0f */ /* 180.0f */);
  }
  return bVar5;
}



/* ----------------------------------------
 * CINSNextBot::IsInvestigating
 * Address: 00747db0
 * ---------------------------------------- */

/* CINSNextBot::IsInvestigating() const */

undefined1 __thiscall CINSNextBot::IsInvestigating(CINSNextBot *this)

{
  int in_stack_00000004;
  
  return *(undefined1 *)(in_stack_00000004 + 0x2292);
}



/* ----------------------------------------
 * CINSNextBot::IsLineOfFireClear
 * Address: 007454d0
 * ---------------------------------------- */

/* CINSNextBot::IsLineOfFireClear(Vector const&, Vector const&) const */

byte __thiscall CINSNextBot::IsLineOfFireClear(CINSNextBot *this,Vector *param_1,Vector *param_2)

{
  int *piVar1;
  byte bVar2;
  int iVar3;
  CTraceFilterSimple *this_00;
  IHandleEntity *extraout_EDX;
  float fVar4;
  int unaff_EBX;
  float *in_stack_0000000c;
  Vector local_dc [12];
  Vector local_d0 [32];
  float local_b0;
  char local_a6;
  byte local_a5;
  undefined4 local_90;
  float local_7c;
  float local_78;
  float local_74;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_3c;
  undefined1 local_38;
  undefined1 local_37;
  int local_2c;
  undefined4 uStack_14;
  
  uStack_14 = 0x7454de;
  __i686_get_pc_thunk_bx();
  local_90 = 0;
  CTraceFilterSimple::CTraceFilterSimple
            (this_00,extraout_EDX,0,(_func_bool_IHandleEntity_ptr_int *)0x0);
  local_7c = *(float *)param_2;
  local_2c = unaff_EBX + 0x44ee52 /* vtable for NextBotTraceFilterIgnoreActors+0x8 */ /* vtable for NextBotTraceFilterIgnoreActors+0x8 */ /* vtable for NextBotTraceFilterIgnoreActors+0x8 */;
  local_78 = *(float *)(param_2 + 4);
  local_3c = 0;
  local_6c = *in_stack_0000000c - local_7c;
  local_74 = *(float *)(param_2 + 8);
  local_68 = in_stack_0000000c[1] - local_78;
  local_38 = 1;
  local_64 = in_stack_0000000c[2] - local_74;
  local_44 = 0;
  local_48 = 0;
  local_4c = 0;
  local_37 = local_68 * local_68 + local_6c * local_6c + local_64 * local_64 != 0.0;
  local_54 = 0;
  local_58 = 0;
  local_5c = 0;
  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x46129a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
            ((int *)**(undefined4 **)(unaff_EBX + 0x46129a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_7c,0x400b,extraout_EDX,local_dc);
  piVar1 = *(int **)(unaff_EBX + 0x461562 /* &r_visualizetraces */ /* &r_visualizetraces */ /* &r_visualizetraces */);
  iVar3 = (**(code **)(*piVar1 + 0x40))(piVar1);
  if (iVar3 != 0) {
    iVar3 = (**(code **)(*piVar1 + 0x40))(piVar1);
    fVar4 = 0.5;
    if (iVar3 != 0) {
      fVar4 = -1.0;
    }
    DebugDrawLine(local_dc,local_d0,0xff,0,0,true,fVar4);
  }
  bVar2 = 0;
  if ((*(float *)(unaff_EBX + 0x173636 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= local_b0) && (local_a6 == '\0')) {
    bVar2 = local_a5 ^ 1;
  }
  return bVar2;
}



/* ----------------------------------------
 * CINSNextBot::IsLineOfFireClear
 * Address: 00745690
 * ---------------------------------------- */

/* CINSNextBot::IsLineOfFireClear(Vector const&) const */

void __cdecl CINSNextBot::IsLineOfFireClear(Vector *param_1)

{
  CINSNextBot *this;
  Vector local_18 [12];
  
  (**(code **)(*(int *)param_1 + 0x20c /* CINSNextBot::EyePosition */))(local_18,param_1);
  IsLineOfFireClear(this,param_1,local_18);
  return;
}



/* ----------------------------------------
 * CINSNextBot::IsLineOfFireClear
 * Address: 007456e0
 * ---------------------------------------- */

/* CINSNextBot::IsLineOfFireClear(Vector const&, CBaseEntity*) const */

bool __thiscall
CINSNextBot::IsLineOfFireClear(CINSNextBot *this,Vector *param_1,CBaseEntity *param_2)

{
  int *piVar1;
  float *pfVar2;
  int iVar3;
  CTraceFilterSimple *this_00;
  IHandleEntity *extraout_EDX;
  float fVar4;
  int unaff_EBX;
  int *in_stack_0000000c;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  Vector local_dc [12];
  Vector local_d0 [32];
  float local_b0;
  char local_a6;
  char local_a5;
  int *local_90;
  float local_7c;
  float local_78;
  float local_74;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_3c;
  undefined1 local_38;
  undefined1 local_37;
  int local_2c;
  undefined4 uStack_14;
  
  uStack_14 = 0x7456ee;
  __i686_get_pc_thunk_bx();
  uVar6 = 0;
  local_90 = (int *)0x0;
  uVar5 = 0;
  uVar7 = *(undefined4 *)(unaff_EBX + 0x4617a6 /* &IgnoreActorsTraceFilterFunction */ /* &IgnoreActorsTraceFilterFunction */ /* &IgnoreActorsTraceFilterFunction */);
  CTraceFilterSimple::CTraceFilterSimple
            (this_00,extraout_EDX,0,(_func_bool_IHandleEntity_ptr_int *)0x0);
  local_2c = unaff_EBX + 0x44ec42 /* vtable for NextBotTraceFilterIgnoreActors+0x8 */ /* vtable for NextBotTraceFilterIgnoreActors+0x8 */ /* vtable for NextBotTraceFilterIgnoreActors+0x8 */;
  pfVar2 = (float *)(**(code **)(*in_stack_0000000c + 0x260 /* CBaseEntity::WorldSpaceCenter */))(in_stack_0000000c,uVar5,uVar6,uVar7);
  local_3c = 0;
  local_7c = *(float *)param_2;
  local_78 = *(float *)(param_2 + 4);
  local_6c = *pfVar2 - local_7c;
  local_74 = *(float *)(param_2 + 8);
  local_68 = pfVar2[1] - local_78;
  local_38 = 1;
  local_64 = pfVar2[2] - local_74;
  local_44 = 0;
  local_48 = 0;
  local_4c = 0;
  local_37 = local_68 * local_68 + local_6c * local_6c + local_64 * local_64 != 0.0;
  local_54 = 0;
  local_58 = 0;
  local_5c = 0;
  (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x46108a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */) + 0x14))
            ((int *)**(undefined4 **)(unaff_EBX + 0x46108a /* &enginetrace */ /* &enginetrace */ /* &enginetrace */),&local_7c,0x400b,extraout_EDX,local_dc);
  piVar1 = *(int **)(unaff_EBX + 0x461352 /* &r_visualizetraces */ /* &r_visualizetraces */ /* &r_visualizetraces */);
  iVar3 = (**(code **)(*piVar1 + 0x40))(piVar1);
  if (iVar3 != 0) {
    iVar3 = (**(code **)(*piVar1 + 0x40))(piVar1);
    fVar4 = 0.5;
    if (iVar3 != 0) {
      fVar4 = -1.0;
    }
    DebugDrawLine(local_dc,local_d0,0xff,0,0,true,fVar4);
  }
  if (((*(float *)(unaff_EBX + 0x173426 /* 1.0f */ /* 1.0f */ /* 1.0f */) <= local_b0) && (local_a6 == '\0')) && (local_a5 == '\0'))
  {
    return true;
  }
  return in_stack_0000000c == local_90;
}



/* ----------------------------------------
 * CINSNextBot::IsLineOfFireClear
 * Address: 007458d0
 * ---------------------------------------- */

/* CINSNextBot::IsLineOfFireClear(CBaseEntity*) const */

void __cdecl CINSNextBot::IsLineOfFireClear(CBaseEntity *param_1)

{
  CINSNextBot *this;
  CBaseEntity local_18 [12];
  
  (**(code **)(*(int *)param_1 + 0x20c /* CINSNextBot::EyePosition */))(local_18,param_1);
  IsLineOfFireClear(this,(Vector *)param_1,local_18);
  return;
}



/* ----------------------------------------
 * CINSNextBot::IsLost
 * Address: 00759ff0
 * ---------------------------------------- */

/* CINSNextBot::IsLost() */

undefined4 __thiscall CINSNextBot::IsLost(CINSNextBot *this)

{
  undefined4 uVar1;
  int unaff_EBX;
  int in_stack_00000004;
  
  uVar1 = __i686_get_pc_thunk_bx();
  if (0x10 < *(int *)(in_stack_00000004 + 0xb324)) {
    Warning(unaff_EBX + 0x22c7a1 /* "!! NAV MESH ERROR !!
Bot failed to calculate path. Going to Guard state.
" */ /* "!! NAV MESH ERROR !!
Bot failed to calculate path. Going to Guard state.
" */ /* "!! NAV MESH ERROR !!
Bot failed to calculate path. Going to Guard state.
" */);
    uVar1 = 1;
  }
  return uVar1;
}



/* ----------------------------------------
 * CINSNextBot::IsPointBetweenTargetAndSelf
 * Address: 00745920
 * ---------------------------------------- */

/* CINSNextBot::IsPointBetweenTargetAndSelf(Vector, Vector) */

bool __cdecl
CINSNextBot::IsPointBetweenTargetAndSelf
          (int param_1,float param_2,float param_3,float param_4,float param_5,float param_6,
          float param_7)

{
  bool bVar1;
  CBaseEntity *this;
  CBaseEntity *this_00;
  int unaff_EBX;
  float10 fVar2;
  float10 fVar3;
  float fVar4;
  float local_2c;
  float local_28;
  float local_24;
  float local_1c;
  float local_18;
  float local_14;
  undefined4 uStack_10;
  
  uStack_10 = 0x74592a;
  __i686_get_pc_thunk_bx();
  if ((*(byte *)(param_1 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this);
  }
  local_2c = param_5 - *(float *)(param_1 + 0x208);
  local_28 = param_6 - *(float *)(param_1 + 0x20c);
  local_24 = param_7 - *(float *)(param_1 + 0x210);
  fVar2 = (float10)VectorNormalize((Vector *)&local_2c);
  if ((*(byte *)(param_1 + 0xd1) & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_00);
  }
  local_1c = param_2 - *(float *)(param_1 + 0x208);
  local_18 = param_3 - *(float *)(param_1 + 0x20c);
  local_14 = param_4 - *(float *)(param_1 + 0x210);
  fVar3 = (float10)VectorNormalize((Vector *)&local_1c);
  bVar1 = false;
  if ((float)fVar3 < (float)fVar2) {
    fVar4 = local_18 * local_28 + local_1c * local_2c + local_14 * local_24;
    bVar1 = *(float *)(unaff_EBX + 0x218786 /* 0.7071f */ /* 0.7071f */ /* 0.7071f */) <= fVar4 && fVar4 != *(float *)(unaff_EBX + 0x218786 /* 0.7071f */ /* 0.7071f */ /* 0.7071f */);
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSNextBot::IsPointBetweenTargetAndSelf
 * Address: 00745a30
 * ---------------------------------------- */

/* CINSNextBot::IsPointBetweenTargetAndSelf(Vector, CBaseEntity*) */

void __cdecl
CINSNextBot::IsPointBetweenTargetAndSelf
          (undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int param_5)

{
  CBaseEntity *this;
  
  __i686_get_pc_thunk_bx();
  if (param_5 != 0) {
    if ((*(byte *)(param_5 + 0xd1) & 8) != 0) {
      CBaseEntity::CalcAbsolutePosition(this);
    }
    IsPointBetweenTargetAndSelf
              (param_1,param_2,param_3,param_4,*(undefined4 *)(param_5 + 0x208),
               *(undefined4 *)(param_5 + 0x20c),*(undefined4 *)(param_5 + 0x210));
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::IsSpotOccupied
 * Address: 00745170
 * ---------------------------------------- */

/* CINSNextBot::IsSpotOccupied(Vector) */

bool __cdecl CINSNextBot::IsSpotOccupied(int param_1)

{
  bool bVar1;
  int iVar2;
  int unaff_EBX;
  float local_1c [4];
  undefined4 uStack_c;
  
  uStack_c = 0x745179;
  __i686_get_pc_thunk_bx();
  iVar2 = UTIL_INSGetClosestPlayer((Vector *)&stack0x00000008,local_1c);
  bVar1 = false;
  if ((iVar2 != param_1) && (iVar2 != 0)) {
    bVar1 = local_1c[0] < *(float *)(unaff_EBX + 0x173e07 /* 50.0f */ /* 50.0f */ /* 50.0f */);
  }
  return bVar1;
}



/* ----------------------------------------
 * CINSNextBot::IsSuppressed
 * Address: 0075b860
 * ---------------------------------------- */

/* CINSNextBot::IsSuppressed() */

bool __thiscall CINSNextBot::IsSuppressed(CINSNextBot *this)

{
  char cVar1;
  CINSPlayer *this_00;
  int unaff_EBX;
  float10 extraout_ST0;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_00000004 != (int *)0x0) {
    cVar1 = (**(code **)(*in_stack_00000004 + 0x158))();
    if (cVar1 != '\0') {
      CINSPlayer::GetSuppressionFrac(this_00);
      return *(double *)(unaff_EBX + 0x225aac /* rodata:0x66666666 */ /* rodata:0x66666666 */ /* rodata:0x66666666 */) <= (double)(float)extraout_ST0 &&
             (double)(float)extraout_ST0 != *(double *)(unaff_EBX + 0x225aac /* rodata:0x66666666 */ /* rodata:0x66666666 */ /* rodata:0x66666666 */);
    }
  }
  Warning(unaff_EBX + 0x22affc /* "Failed to determine suppression frac for AI.
" */ /* "Failed to determine suppression frac for AI.
" */ /* "Failed to determine suppression frac for AI.
" */);
  return false;
}



/* ----------------------------------------
 * CINSNextBot::KillSelf
 * Address: 0075a030
 * ---------------------------------------- */

/* CINSNextBot::KillSelf() */

void __thiscall CINSNextBot::KillSelf(CINSNextBot *this)

{
  CINSPlayer *this_00;
  CINSPlayer *this_01;
  CTakeDamageInfo *this_02;
  CBaseEntity *in_stack_00000004;
  CBaseEntity local_7c [108];
  
  __i686_get_pc_thunk_bx();
  CINSPlayer::GetDeathFlags(this_00);
  CINSPlayer::SetDeathFlags(this_01,(int)in_stack_00000004);
  CTakeDamageInfo::CTakeDamageInfo
            (this_02,local_7c,in_stack_00000004,(float)in_stack_00000004,0,0,0);
  (**(code **)(*(int *)in_stack_00000004 + 0x11c /* CINSNextBot::Event_Killed */))(in_stack_00000004,local_7c);
  (**(code **)(*(int *)in_stack_00000004 + 0x4e0 /* CINSPlayer::Event_Dying */))(in_stack_00000004);
  return;
}



/* ----------------------------------------
 * CINSNextBot::MaxPathLength
 * Address: 00747ae0
 * ---------------------------------------- */

/* CINSNextBot::MaxPathLength() */

float10 CINSNextBot::MaxPathLength(void)

{
  char cVar1;
  int *piVar2;
  CINSRules *this;
  CINSRules *this_00;
  CINSRules *this_01;
  CINSRules *this_02;
  int unaff_EBX;
  float10 fVar3;
  
  __i686_get_pc_thunk_bx();
  cVar1 = CINSRules::IsConquer(this);
  if (cVar1 == '\0') {
    cVar1 = CINSRules::IsHunt(this_00);
    if (cVar1 == '\0') {
      cVar1 = CINSRules::IsOutpost(this_01);
      if (cVar1 == '\0') {
        cVar1 = CINSRules::IsSurvival(this_02);
        if (cVar1 == '\0') {
          piVar2 = (int *)(*(int **)(unaff_EBX + 0x45eb6e /* &ins_bot_path_distance_max */ /* &ins_bot_path_distance_max */ /* &ins_bot_path_distance_max */))[7];
          if (piVar2 == *(int **)(unaff_EBX + 0x45eb6e /* &ins_bot_path_distance_max */ /* &ins_bot_path_distance_max */ /* &ins_bot_path_distance_max */)) {
LAB_00747b60:
            return (float10)(float)((uint)piVar2 ^ piVar2[0xb]);
          }
        }
        else {
          piVar2 = (int *)(*(int **)(unaff_EBX + 0x45e9fa /* &ins_bot_path_distance_survival */ /* &ins_bot_path_distance_survival */ /* &ins_bot_path_distance_survival */))[7];
          if (piVar2 == *(int **)(unaff_EBX + 0x45e9fa /* &ins_bot_path_distance_survival */ /* &ins_bot_path_distance_survival */ /* &ins_bot_path_distance_survival */)) goto LAB_00747b60;
        }
      }
      else {
        piVar2 = (int *)(*(int **)(&DAT_0045f266 + unaff_EBX))[7];
        if (piVar2 == *(int **)(&DAT_0045f266 + unaff_EBX)) goto LAB_00747b60;
      }
    }
    else {
      piVar2 = (int *)(*(int **)(unaff_EBX + 0x45ea9e /* &ins_bot_path_distance_hunt */ /* &ins_bot_path_distance_hunt */ /* &ins_bot_path_distance_hunt */))[7];
      if (piVar2 == *(int **)(unaff_EBX + 0x45ea9e /* &ins_bot_path_distance_hunt */ /* &ins_bot_path_distance_hunt */ /* &ins_bot_path_distance_hunt */)) goto LAB_00747b60;
    }
  }
  else {
    piVar2 = (int *)(*(int **)(unaff_EBX + 0x45f5ce /* &ins_bot_path_distance_conquer */ /* &ins_bot_path_distance_conquer */ /* &ins_bot_path_distance_conquer */))[7];
    if (piVar2 == *(int **)(unaff_EBX + 0x45f5ce /* &ins_bot_path_distance_conquer */ /* &ins_bot_path_distance_conquer */ /* &ins_bot_path_distance_conquer */)) goto LAB_00747b60;
  }
  fVar3 = (float10)(**(code **)(*piVar2 + 0x3c))(piVar2);
  return fVar3;
}



/* ----------------------------------------
 * CINSNextBot::OnNavAreaChanged
 * Address: 00743600
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::OnNavAreaChanged(CNavArea*, CNavArea*) */

void __thiscall CINSNextBot::OnNavAreaChanged(CINSNextBot *this,CNavArea *param_1,CNavArea *param_2)

{
  OnNavAreaChanged(this,param_1 + -0x2060,param_2);
  return;
}



/* ----------------------------------------
 * CINSNextBot::OnNavAreaChanged
 * Address: 00743610
 * ---------------------------------------- */

/* CINSNextBot::OnNavAreaChanged(CNavArea*, CNavArea*) */

void __thiscall CINSNextBot::OnNavAreaChanged(CINSNextBot *this,CNavArea *param_1,CNavArea *param_2)

{
  int *piVar1;
  CNavArea *pCVar2;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c != 0) {
    CINSNavArea::RemovePathingBot(in_stack_0000000c);
  }
  pCVar2 = param_1 + 0x2060;
  for (piVar1 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 8))(pCVar2); piVar1 != (int *)0x0;
      piVar1 = (int *)(**(code **)(*(int *)pCVar2 + 0xc))(pCVar2,piVar1)) {
    (**(code **)(*piVar1 + 0x60))(piVar1,param_2,in_stack_0000000c);
  }
  CINSPlayer::OnNavAreaChanged((CINSPlayer *)param_1,param_1,param_2);
  return;
}



/* ----------------------------------------
 * CINSNextBot::PathFollowerInvalid
 * Address: 00759fc0
 * ---------------------------------------- */

/* CINSNextBot::PathFollowerInvalid() */

undefined4 __thiscall CINSNextBot::PathFollowerInvalid(CINSNextBot *this)

{
  int in_stack_00000004;
  
  if (0 < *(int *)(in_stack_00000004 + 0xaf38)) {
    *(undefined4 *)(in_stack_00000004 + 0xb324) = 0;
    return 0;
  }
  *(int *)(in_stack_00000004 + 0xb324) = *(int *)(in_stack_00000004 + 0xb324) + 1;
  return 1;
}



/* ----------------------------------------
 * CINSNextBot::PressFiremodeButton
 * Address: 00743980
 * ---------------------------------------- */

/* CINSNextBot::PressFiremodeButton(float) */

void __thiscall CINSNextBot::PressFiremodeButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x1000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb41c) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb414) + 4))((int)param_1 + 0xb414,(int)param_1 + 0xb41c); /* timer_32.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb41c) = (float)fVar1 + in_stack_00000008; /* timer_32.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb418) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb414) + 4))((int)param_1 + 0xb414,(int)param_1 + 0xb418); /* timer_32.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb418) = in_stack_00000008; /* timer_32.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressIronsightButton
 * Address: 007438c0
 * ---------------------------------------- */

/* CINSNextBot::PressIronsightButton(float) */

void __thiscall CINSNextBot::PressIronsightButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x40000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb428) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb420) + 4))((int)param_1 + 0xb420,(int)param_1 + 0xb428); /* timer_33.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb428) = (float)fVar1 + in_stack_00000008; /* timer_33.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb424) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb420) + 4))((int)param_1 + 0xb420,(int)param_1 + 0xb424); /* timer_33.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb424) = in_stack_00000008; /* timer_33.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressLeanLeftButton
 * Address: 00743b00
 * ---------------------------------------- */

/* CINSNextBot::PressLeanLeftButton(float) */

void __thiscall CINSNextBot::PressLeanLeftButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x2000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb404) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3fc) + 4))((int)param_1 + 0xb3fc,(int)param_1 + 0xb404); /* timer_30.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb404) = (float)fVar1 + in_stack_00000008; /* timer_30.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb400) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3fc) + 4))((int)param_1 + 0xb3fc,(int)param_1 + 0xb400); /* timer_30.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb400) = in_stack_00000008; /* timer_30.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressLeanRightButton
 * Address: 00743a40
 * ---------------------------------------- */

/* CINSNextBot::PressLeanRightButton(float) */

void __thiscall CINSNextBot::PressLeanRightButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x4000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb410) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb408) + 4))((int)param_1 + 0xb408,(int)param_1 + 0xb410); /* timer_31.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb410) = (float)fVar1 + in_stack_00000008; /* timer_31.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb40c) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb408) + 4))((int)param_1 + 0xb408,(int)param_1 + 0xb40c); /* timer_31.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb40c) = in_stack_00000008; /* timer_31.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressProneButton
 * Address: 00743bc0
 * ---------------------------------------- */

/* CINSNextBot::PressProneButton(float) */

void __thiscall CINSNextBot::PressProneButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 8;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb3f8) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3f0) + 4))((int)param_1 + 0xb3f0,(int)param_1 + 0xb3f8); /* timer_29.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3f8) = (float)fVar1 + in_stack_00000008; /* timer_29.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb3f4) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3f0) + 4))((int)param_1 + 0xb3f0,(int)param_1 + 0xb3f4); /* timer_29.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3f4) = in_stack_00000008; /* timer_29.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressSprintButton
 * Address: 00743d50
 * ---------------------------------------- */

/* CINSNextBot::PressSprintButton(float) */

void __thiscall CINSNextBot::PressSprintButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x8000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb3e0) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3d8) + 4))((int)param_1 + 0xb3d8,(int)param_1 + 0xb3e0); /* timer_27.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3e0) = (float)fVar1 + in_stack_00000008; /* timer_27.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb3dc) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3d8) + 4))((int)param_1 + 0xb3d8,(int)param_1 + 0xb3dc); /* timer_27.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3dc) = in_stack_00000008; /* timer_27.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressTertiaryAttackButton
 * Address: 00743800
 * ---------------------------------------- */

/* CINSNextBot::PressTertiaryAttackButton(float) */

void __thiscall CINSNextBot::PressTertiaryAttackButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x20000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb434) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb42c) + 4))((int)param_1 + 0xb42c,(int)param_1 + 0xb434); /* timer_34.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb434) = (float)fVar1 + in_stack_00000008; /* timer_34.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb430) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb42c) + 4))((int)param_1 + 0xb42c,(int)param_1 + 0xb430); /* timer_34.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb430) = in_stack_00000008; /* timer_34.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressWalkButton
 * Address: 00743c80
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::PressWalkButton(float) */

void __thiscall CINSNextBot::PressWalkButton(CINSNextBot *this,float param_1)

{
  PressWalkButton(this,(float)((int)param_1 + -0x20c4));
  return;
}



/* ----------------------------------------
 * CINSNextBot::PressWalkButton
 * Address: 00743c90
 * ---------------------------------------- */

/* CINSNextBot::PressWalkButton(float) */

void __thiscall CINSNextBot::PressWalkButton(CINSNextBot *this,float param_1)

{
  float10 fVar1;
  float in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  *(uint *)((int)param_1 + 0x20c8) = *(uint *)((int)param_1 + 0x20c8) | 0x10000;
  fVar1 = (float10)CountdownTimer::Now();
  if (*(float *)((int)param_1 + 0xb3ec) != (float)fVar1 + in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3e4) + 4))((int)param_1 + 0xb3e4,(int)param_1 + 0xb3ec); /* timer_28.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3ec) = (float)fVar1 + in_stack_00000008; /* timer_28.Start(...) */
  }
  if (*(float *)((int)param_1 + 0xb3e8) != in_stack_00000008) {
    (**(code **)(*(int *)((int)param_1 + 0xb3e4) + 4))((int)param_1 + 0xb3e4,(int)param_1 + 0xb3e8); /* timer_28.NetworkStateChanged() */
    *(float *)((int)param_1 + 0xb3e8) = in_stack_00000008; /* timer_28.m_duration */
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseFiremodeButton
 * Address: 00742fa0
 * ---------------------------------------- */

/* CINSNextBot::ReleaseFiremodeButton() */

void __thiscall CINSNextBot::ReleaseFiremodeButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xffffefff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseIronsightButton
 * Address: 00742fc0
 * ---------------------------------------- */

/* CINSNextBot::ReleaseIronsightButton() */

void __thiscall CINSNextBot::ReleaseIronsightButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xfffbffff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseLeanLeftButton
 * Address: 00742f60
 * ---------------------------------------- */

/* CINSNextBot::ReleaseLeanLeftButton() */

void __thiscall CINSNextBot::ReleaseLeanLeftButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xffffdfff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseLeanRightButton
 * Address: 00742f80
 * ---------------------------------------- */

/* CINSNextBot::ReleaseLeanRightButton() */

void __thiscall CINSNextBot::ReleaseLeanRightButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xffffbfff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseProneButton
 * Address: 00742f50
 * ---------------------------------------- */

/* CINSNextBot::ReleaseProneButton() */

void __thiscall CINSNextBot::ReleaseProneButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xfffffff7;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseSprintButton
 * Address: 00742f00
 * ---------------------------------------- */

/* CINSNextBot::ReleaseSprintButton() */

void __thiscall CINSNextBot::ReleaseSprintButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xffff7fff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseTertiaryAttackButton
 * Address: 00742fe0
 * ---------------------------------------- */

/* CINSNextBot::ReleaseTertiaryAttackButton() */

void __thiscall CINSNextBot::ReleaseTertiaryAttackButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xfffdffff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseWalkButton
 * Address: 00742f20
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::ReleaseWalkButton() */

void __thiscall CINSNextBot::ReleaseWalkButton(CINSNextBot *this)

{
  ReleaseWalkButton(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::ReleaseWalkButton
 * Address: 00742f30
 * ---------------------------------------- */

/* CINSNextBot::ReleaseWalkButton() */

void __thiscall CINSNextBot::ReleaseWalkButton(CINSNextBot *this)

{
  int in_stack_00000004;
  
  *(uint *)(in_stack_00000004 + 0x20c8) = *(uint *)(in_stack_00000004 + 0x20c8) & 0xfffeffff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ResetChargeStatus
 * Address: 00748430
 * ---------------------------------------- */

/* CINSNextBot::ResetChargeStatus() */

void __thiscall CINSNextBot::ResetChargeStatus(CINSNextBot *this)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int unaff_EBX;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  if (*(int *)(in_stack_00000004 + 0xb48c) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb484) + 4)) /* timer_37.NetworkStateChanged() */
              (in_stack_00000004 + 0xb484,in_stack_00000004 + 0xb48c);
    *(undefined4 *)(in_stack_00000004 + 0xb48c) = 0xbf800000 /* -1.0f */;
  }
  puVar1 = *(undefined4 **)(unaff_EBX + 0x45eb38 /* &vec3_invalid */ /* &vec3_invalid */ /* &vec3_invalid */);
  *(undefined4 *)(in_stack_00000004 + 0xb490) = *puVar1;
  uVar2 = puVar1[2];
  *(undefined4 *)(in_stack_00000004 + 0xb494) = puVar1[1];
  *(undefined4 *)(in_stack_00000004 + 0xb498) = uVar2;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ResetIdleStatus
 * Address: 007482f0
 * ---------------------------------------- */

/* CINSNextBot::ResetIdleStatus() */

void __thiscall CINSNextBot::ResetIdleStatus(CINSNextBot *this)

{
  float10 fVar1;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  fVar1 = (float10)IntervalTimer::Now();
  if (*(float *)(in_stack_00000004 + 0xb3c8) != (float)fVar1) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb3c4) + 8))
              (in_stack_00000004 + 0xb3c4,in_stack_00000004 + 0xb3c8);
    *(float *)(in_stack_00000004 + 0xb3c8) = (float)fVar1;
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::SetEscortFormation
 * Address: 00747c80
 * ---------------------------------------- */

/* CINSNextBot::SetEscortFormation(INSBotEscortFormation*) */

void __thiscall CINSNextBot::SetEscortFormation(CINSNextBot *this,INSBotEscortFormation *param_1)

{
  int in_stack_00000008;
  
  if (in_stack_00000008 != 0) {
    *(int *)(param_1 + 0xb334) = in_stack_00000008;
    *(undefined4 *)(param_1 + 0xb32c) = *(undefined4 *)(in_stack_00000008 + 8);
    return;
  }
  *(undefined4 *)(param_1 + 0xb334) = 0;
  *(undefined4 *)(param_1 + 0xb32c) = 0xffffffff;
  return;
}



/* ----------------------------------------
 * CINSNextBot::SetFollowingOrder
 * Address: 00747ed0
 * ---------------------------------------- */

/* CINSNextBot::SetFollowingOrder(bool) */

void __thiscall CINSNextBot::SetFollowingOrder(CINSNextBot *this,bool param_1)

{
  undefined3 in_stack_00000005;
  undefined1 in_stack_00000008;
  
  *(undefined1 *)(_param_1 + 0x2293) = in_stack_00000008;
  return;
}



/* ----------------------------------------
 * CINSNextBot::SetInvestigating
 * Address: 00747dc0
 * ---------------------------------------- */

/* CINSNextBot::SetInvestigating(bool) */

void __thiscall CINSNextBot::SetInvestigating(CINSNextBot *this,bool param_1)

{
  undefined3 in_stack_00000005;
  undefined1 in_stack_00000008;
  
  *(undefined1 *)(_param_1 + 0x2292) = in_stack_00000008;
  return;
}



/* ----------------------------------------
 * CINSNextBot::ShouldOpportunisticReload
 * Address: 0076dd80
 * ---------------------------------------- */

/* CINSNextBot::ShouldOpportunisticReload() */

undefined4 __thiscall CINSNextBot::ShouldOpportunisticReload(CINSNextBot *this)

{
  int *piVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  float fVar6;
  CINSNextBot *this_00;
  CBaseCombatCharacter *this_01;
  CAmmoDef *this_02;
  ConVar *this_03;
  CINSWeaponMagazines *this_04;
  int unaff_EBX;
  undefined4 uVar7;
  float10 fVar8;
  float10 fVar9;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  uVar7 = 0;
  piVar3 = (int *)CINSPlayer::GetActiveINSWeapon();
  if (piVar3 != (int *)0x0) {
    uVar7 = 1;
    cVar2 = ShouldReload(this_00);
    if (cVar2 == '\0') {
      uVar7 = 0;
      cVar2 = (**(code **)(*piVar3 + 0x658 /* NextBotPlayer::OnMainActivityInterrupted */))(piVar3);
      if (((cVar2 != '\0') && (cVar2 = (**(code **)(*piVar3 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar3), cVar2 != '\0')) &&
         ((iVar4 = (**(code **)(*piVar3 + 0x530 /* CBaseCombatCharacter::RemoveEntityRelationship */))(piVar3), iVar4 == 0 ||
          (iVar4 = (**(code **)(*piVar3 + 0x530 /* CBaseCombatCharacter::RemoveEntityRelationship */))(piVar3), iVar4 == 1)))) {
        uVar7 = 0;
        uVar5 = (**(code **)(*piVar3 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar3);
        iVar4 = CBaseCombatCharacter::GetAmmoCount(this_01,in_stack_00000004);
        if (0 < iVar4) {
          fVar8 = (float10)GetActiveWeaponAmmoRatio();
          piVar1 = *(int **)(unaff_EBX + 0x58558b /* ins_bot_attack_reload_ratio+0x1c */ /* ins_bot_attack_reload_ratio+0x1c */ /* ins_bot_attack_reload_ratio+0x1c */);
          if (piVar1 == (int *)(unaff_EBX + 0x58556f /* ins_bot_attack_reload_ratio */ /* ins_bot_attack_reload_ratio */ /* ins_bot_attack_reload_ratio */U)) {
            fVar6 = (float)(*(uint *)(unaff_EBX + 0x58559b /* ins_bot_attack_reload_ratio+0x2c */ /* ins_bot_attack_reload_ratio+0x2c */ /* ins_bot_attack_reload_ratio+0x2c */) ^ unaff_EBX + 0x58556f /* ins_bot_attack_reload_ratio */ /* ins_bot_attack_reload_ratio */ /* ins_bot_attack_reload_ratio */U);
          }
          else {
            fVar9 = (float10)(**(code **)(*piVar1 + 0x3c))(piVar1,uVar5);
            fVar6 = (float)fVar9;
          }
          uVar7 = 0;
          if ((float)fVar8 < fVar6) {
            uVar5 = (**(code **)(*piVar3 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar3);
            iVar4 = GetAmmoDef();
            uVar7 = 1;
            iVar4 = CAmmoDef::GetAmmoOfIndex(this_02,iVar4);
            if ((iVar4 != 0) && ((*(byte *)(iVar4 + 0x94) & 4) != 0)) {
              (**(code **)(*piVar3 + 0x510 /* CBaseCombatCharacter::ExitVehicle */))(piVar3,uVar5);
              ConVar::GetFloat(this_03);
              uVar7 = 0;
              (**(code **)(*piVar3 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar3);
              iVar4 = CINSPlayer::GetMagazines(in_stack_00000004);
              if (iVar4 != 0) {
                uVar7 = CINSWeaponMagazines::HasMagazineMoreThan(this_04,iVar4);
              }
            }
          }
        }
      }
    }
  }
  return uVar7;
}



/* ----------------------------------------
 * CINSNextBot::ShouldReload
 * Address: 0076dcb0
 * ---------------------------------------- */

/* CINSNextBot::ShouldReload() */

bool __thiscall CINSNextBot::ShouldReload(CINSNextBot *this)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  CBaseCombatCharacter *this_00;
  bool bVar5;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  bVar5 = false;
  piVar2 = (int *)CINSPlayer::GetActiveINSWeapon();
  if ((((piVar2 != (int *)0x0) && (cVar1 = (**(code **)(*piVar2 + 0x658 /* NextBotPlayer::OnMainActivityInterrupted */))(piVar2), cVar1 != '\0'))
      && (cVar1 = (**(code **)(*piVar2 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar2), cVar1 != '\0')) &&
     ((iVar3 = (**(code **)(*piVar2 + 0x530 /* CBaseCombatCharacter::RemoveEntityRelationship */))(piVar2), iVar3 == 0 ||
      (iVar3 = (**(code **)(*piVar2 + 0x530 /* CBaseCombatCharacter::RemoveEntityRelationship */))(piVar2), iVar3 == 1)))) {
    uVar4 = (**(code **)(*piVar2 + 0x558 /* CINSNextBot::OnNavAreaChanged */))(piVar2);
    iVar3 = CBaseCombatCharacter::GetAmmoCount(this_00,in_stack_00000004);
    cVar1 = (**(code **)(*piVar2 + 0x740 /* CINSPlayer::CanSpeak */))(piVar2,uVar4);
    bVar5 = 0 < iVar3;
    if (cVar1 == '\0') {
      bVar5 = false;
    }
  }
  return bVar5;
}



/* ----------------------------------------
 * CINSNextBot::ShouldRushToCover
 * Address: 007446f0
 * ---------------------------------------- */

/* CINSNextBot::ShouldRushToCover() */

bool __thiscall CINSNextBot::ShouldRushToCover(CINSNextBot *this)

{
  int iVar1;
  int *piVar2;
  CINSBotVision *this_00;
  bool bVar3;
  int unaff_EBX;
  float10 fVar4;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar1 = CINSPlayer::GetTeamID();
  piVar2 = (int *)(**(code **)(*in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000004);
  iVar1 = (**(code **)(*piVar2 + 0xdc /* IVision::GetKnownCount */))(piVar2,(iVar1 == 2) + '\x02',0,0xbf800000 /* -1.0f */);
  bVar3 = true;
  if (iVar1 < 3) {
    (**(code **)(*in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000004);
    fVar4 = (float10)CINSBotVision::GetCombatIntensity(this_00);
    bVar3 = *(float *)(&DAT_001df38e + unaff_EBX) <= (float)fVar4 &&
            (float)fVar4 != *(float *)(&DAT_001df38e + unaff_EBX);
  }
  return bVar3;
}



/* ----------------------------------------
 * CINSNextBot::ShouldSuppressThreat
 * Address: 0075a800
 * ---------------------------------------- */

/* CINSNextBot::ShouldSuppressThreat(CKnownEntity const*) const */

bool __thiscall CINSNextBot::ShouldSuppressThreat(CINSNextBot *this,CKnownEntity *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  char cVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  float *pfVar11;
  float *pfVar12;
  float fVar13;
  int unaff_EBX;
  bool bVar14;
  float10 fVar15;
  float10 fVar16;
  float10 extraout_ST0;
  int *in_stack_00000008;
  
  __i686_get_pc_thunk_bx();
  fVar15 = (float10)(**(code **)(*in_stack_00000008 + 0x50))();
  piVar7 = (int *)(*(int **)(unaff_EBX + 0x44c954 /* &ins_bot_suppress_visible_requirement */ /* &ins_bot_suppress_visible_requirement */ /* &ins_bot_suppress_visible_requirement */))[7];
  if (piVar7 == *(int **)(unaff_EBX + 0x44c954 /* &ins_bot_suppress_visible_requirement */ /* &ins_bot_suppress_visible_requirement */ /* &ins_bot_suppress_visible_requirement */)) {
    fVar13 = (float)((uint)piVar7 ^ piVar7[0xb]);
  }
  else {
    fVar16 = (float10)(**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
    fVar13 = (float)fVar16;
  }
  bVar14 = false;
  if ((((fVar13 <= (float)fVar15) &&
       (piVar7 = (int *)CINSPlayer::GetActiveINSWeapon(), piVar7 != (int *)0x0)) &&
      (iVar8 = (**(code **)(*piVar7 + 0x5f0 /* CINSPlayer::RemoveAllItems */))(piVar7), iVar8 != 1)) &&
     (iVar8 = (**(code **)(**(int **)(unaff_EBX + 0x44bd38 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */) + 0x40))
                        (*(int **)(unaff_EBX + 0x44bd38 /* &ins_bot_knives_only */ /* &ins_bot_knives_only */ /* &ins_bot_knives_only */)), iVar8 == 0)) {
    cVar6 = (**(code **)(*in_stack_00000008 + 0x38))();
    if ((cVar6 == '\0') && (cVar6 = (**(code **)(*in_stack_00000008 + 0x3c))(), cVar6 != '\0')) {
      piVar10 = (int *)(**(code **)(*in_stack_00000008 + 0x10))();
      pfVar11 = (float *)(**(code **)(*piVar10 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(piVar10);
      pfVar12 = (float *)(**(code **)(*(int *)param_1 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(param_1);
      fVar13 = *pfVar12;
      fVar1 = pfVar12[1];
      fVar2 = pfVar12[2];
      fVar3 = *pfVar11;
      fVar4 = pfVar11[1];
      fVar5 = pfVar11[2];
      fVar15 = (float10)GetMaxHipFireAttackRange((CINSNextBot *)param_1,(CINSWeapon *)param_1);
      if (SQRT((fVar1 - fVar4) * (fVar1 - fVar4) + (fVar13 - fVar3) * (fVar13 - fVar3) +
               (fVar2 - fVar5) * (fVar2 - fVar5)) < (float)fVar15) {
        return false;
      }
    }
    iVar8 = (**(code **)(*piVar7 + 0x560 /* CBaseCombatCharacter::OnPursuedBy */))(piVar7);
    iVar9 = (**(code **)(*piVar7 + 0x510 /* CBaseCombatCharacter::ExitVehicle */))(piVar7);
    if ((((float)iVar8 / (float)iVar9 == *(float *)(unaff_EBX + 0x15e2f4 /* 0.0f */ /* 0.0f */ /* 0.0f */)) ||
        (cVar6 = (**(code **)(*piVar7 + 0x548 /* CINSNextBot::GetLastKnownArea */))(piVar7), cVar6 == '\0')) ||
       (bVar14 = true,
       *(float *)(CUtlMemory<int,int>::Grow + unaff_EBX) <= (float)iVar8 / (float)iVar9)) {
      fVar15 = (float10)(**(code **)(*in_stack_00000008 + 0x48))();
      piVar7 = (int *)(*(int **)(unaff_EBX + 0x44c2a0 /* &ins_bot_suppressing_fire_duration */ /* &ins_bot_suppressing_fire_duration */ /* &ins_bot_suppressing_fire_duration */))[7];
      if (piVar7 == *(int **)(unaff_EBX + 0x44c2a0 /* &ins_bot_suppressing_fire_duration */ /* &ins_bot_suppressing_fire_duration */ /* &ins_bot_suppressing_fire_duration */)) {
        fVar13 = (float)((uint)piVar7 ^ piVar7[0xb]);
      }
      else {
        (**(code **)(*piVar7 + 0x3c /* CINSPlayer::TestHitboxes */))(piVar7);
        fVar13 = (float)extraout_ST0;
      }
      bVar14 = (float)fVar15 < fVar13;
    }
  }
  return bVar14;
}



/* ----------------------------------------
 * CINSNextBot::SortAndRemoveInvestigations
 * Address: 0074a130
 * ---------------------------------------- */

/* CINSNextBot::SortAndRemoveInvestigations() */

void __thiscall CINSNextBot::SortAndRemoveInvestigations(CINSNextBot *this)

{
  int iVar1;
  CBaseEntity *extraout_ECX;
  CBaseEntity *extraout_ECX_00;
  CBaseEntity *this_00;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *this_01;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *this_02;
  CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *this_03;
  int unaff_EBX;
  int iVar2;
  float10 fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int in_stack_00000004;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  iVar1 = *(int *)(in_stack_00000004 + 0xb468);
  local_24 = iVar1 + -1;
  this_02 = (CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *)extraout_ECX;
  if (-1 < local_24) {
    this_00 = extraout_ECX;
    local_20 = local_24 * 0x24;
    do {
      while( true ) {
        iVar2 = local_20 + *(int *)(in_stack_00000004 + 0xb45c);
        iVar1 = iVar2;
        if ((*(byte *)(in_stack_00000004 + 0xd1) & 8) != 0) {
          CBaseEntity::CalcAbsolutePosition(this_00);
          iVar1 = local_20 + *(int *)(in_stack_00000004 + 0xb45c);
        }
        fVar6 = *(float *)(in_stack_00000004 + 0x208) - *(float *)(iVar2 + 0xc);
        fVar4 = *(float *)(in_stack_00000004 + 0x20c) - *(float *)(iVar2 + 0x10);
        fVar5 = *(float *)(in_stack_00000004 + 0x210) - *(float *)(iVar2 + 0x14);
        fVar4 = SQRT(fVar4 * fVar4 + fVar6 * fVar6 + fVar5 * fVar5);
        fVar3 = (float10)CountdownTimer::Now();
        if ((*(float *)(iVar1 + 8) <= (float)fVar3 && (float)fVar3 != *(float *)(iVar1 + 8)) ||
           (fVar4 < *(float *)(unaff_EBX + 0x1dcc85 /* 36.0f */ /* 36.0f */ /* 36.0f */))) break;
        local_24 = local_24 + -1;
        *(float *)(*(int *)(in_stack_00000004 + 0xb45c) + 0x1c + local_20) = fVar4;
        this_00 = (CBaseEntity *)this_01;
        this_02 = this_01;
        local_20 = local_20 + -0x24;
        if (local_24 == -1) goto LAB_0074a26e;
      }
      CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::ShiftElementsLeft
                (this_01,in_stack_00000004 + 0xb45c,local_24);
      local_24 = local_24 + -1;
      *(int *)(in_stack_00000004 + 0xb468) = *(int *)(in_stack_00000004 + 0xb468) + -1;
      local_20 = local_20 + -0x24;
      this_00 = extraout_ECX_00;
      this_02 = (CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>> *)
                extraout_ECX_00;
    } while (local_24 != -1);
LAB_0074a26e:
    iVar1 = *(int *)(in_stack_00000004 + 0xb468);
  }
  if (1 < iVar1) {
    CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::Sort
              (this_02,(_func_int_InvestigationData_t_ptr_InvestigationData_t_ptr *)
                       (in_stack_00000004 + 0xb45c));
    iVar1 = *(int *)(in_stack_00000004 + 0xb468);
    if (10 < iVar1) {
      CUtlVector<InvestigationData_t,CUtlMemory<InvestigationData_t,int>>::ShiftElementsLeft
                (this_03,in_stack_00000004 + 0xb45c,10);
      *(int *)(in_stack_00000004 + 0xb468) = *(int *)(in_stack_00000004 + 0xb468) - (iVar1 + -10);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::SortAndRemoveOrders
 * Address: 0074a2d0
 * ---------------------------------------- */

/* CINSNextBot::SortAndRemoveOrders() */

void __thiscall CINSNextBot::SortAndRemoveOrders(CINSNextBot *this)

{
  float *pfVar1;
  int iVar2;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *extraout_ECX;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *this_00;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *extraout_ECX_00;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *this_01;
  CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>> *this_02;
  int iVar3;
  int iVar4;
  float10 fVar5;
  int in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  iVar4 = *(int *)(in_stack_00000004 + 0xb47c);
  iVar3 = iVar4 + -1;
  this_01 = extraout_ECX;
  if (-1 < iVar3) {
    iVar4 = iVar3 * 0x2c;
    do {
      iVar2 = *(int *)(in_stack_00000004 + 0xb470);
      fVar5 = (float10)CountdownTimer::Now();
      pfVar1 = (float *)(iVar4 + iVar2 + 8);
      this_01 = this_00;
      if (*pfVar1 <= (float)fVar5 && (float)fVar5 != *pfVar1) {
        CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>>::ShiftElementsLeft
                  (this_00,in_stack_00000004 + 0xb470,iVar3);
        *(int *)(in_stack_00000004 + 0xb47c) = *(int *)(in_stack_00000004 + 0xb47c) + -1;
        this_01 = extraout_ECX_00;
      }
      iVar3 = iVar3 + -1;
      iVar4 = iVar4 + -0x2c;
    } while (iVar3 != -1);
    iVar4 = *(int *)(in_stack_00000004 + 0xb47c);
  }
  if (1 < iVar4) {
    CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>>::Sort
              (this_01,(_func_int_OrderData_t_ptr_OrderData_t_ptr *)(in_stack_00000004 + 0xb470));
    iVar4 = *(int *)(in_stack_00000004 + 0xb47c);
    if (5 < iVar4) {
      CUtlVector<OrderData_t,CUtlMemory<OrderData_t,int>>::ShiftElementsLeft
                (this_02,in_stack_00000004 + 0xb470,5);
      *(int *)(in_stack_00000004 + 0xb47c) = *(int *)(in_stack_00000004 + 0xb47c) - (iVar4 + -5);
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::Spawn
 * Address: 0074a3c0
 * ---------------------------------------- */

/* CINSNextBot::Spawn() */

void __thiscall CINSNextBot::Spawn(CINSNextBot *this)

{
  float fVar1;
  undefined4 *puVar2;
  int *piVar3;
  char *pcVar4;
  code *pcVar5;
  char cVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  INextBot *extraout_ECX;
  INextBot *extraout_ECX_00;
  INextBot *extraout_ECX_01;
  INextBot *extraout_ECX_02;
  INextBot *extraout_ECX_03;
  INextBot *extraout_ECX_04;
  INextBot *extraout_ECX_05;
  INextBot *extraout_ECX_06;
  INextBot *extraout_ECX_07;
  INextBot *extraout_ECX_08;
  INextBot *extraout_ECX_09;
  INextBot *extraout_ECX_10;
  INextBot *extraout_ECX_11;
  INextBot *extraout_ECX_12;
  INextBot *this_00;
  CINSPlayer *this_01;
  CINSBotChatter *this_02;
  CINSRules *this_03;
  CINSRules *this_04;
  CPlayerInventory *this_05;
  CUtlRBTree<CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
  *this_06;
  CINSRules *extraout_ECX_13;
  CINSRules *this_07;
  CBaseEntity *this_08;
  CBasePlayer *extraout_ECX_14;
  CINSRules *this_09;
  CINSPlayer *extraout_ECX_15;
  CINSRules *extraout_ECX_16;
  CINSRules *extraout_ECX_17;
  int unaff_EBX;
  Vector *in_stack_00000004;
  Vector *pVVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 uStack_14;
  
  uStack_14 = 0x74a3cb;
  __i686_get_pc_thunk_bx();
  puVar2 = *(undefined4 **)(unaff_EBX + 0x45c25d /* &engine */ /* &engine */ /* &engine */);
  iVar9 = unaff_EBX + 0x1da47e /* rodata:0x61740030 */ /* rodata:0x61740030 */ /* rodata:0x61740030 */;
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x238944 /* "cl_autohelp" */ /* "cl_autohelp" */ /* "cl_autohelp" */,iVar9);
  *(undefined4 *)(in_stack_00000004 + 0x20c8) = 0;
  *(undefined4 *)(in_stack_00000004 + 0x20cc) = 0;
  this_00 = extraout_ECX;
  if (*(int *)(in_stack_00000004 + 0x20d8) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x20d0) + 4)) /* timer_0.NetworkStateChanged() */
              (in_stack_00000004 + 0x20d0,in_stack_00000004 + 0x20d8);
    *(undefined4 *)(in_stack_00000004 + 0x20d8) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_00;
  }
  if (*(int *)(in_stack_00000004 + 0x20e4) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x20dc) + 4)) /* timer_1.NetworkStateChanged() */
              (in_stack_00000004 + 0x20dc,in_stack_00000004 + 0x20e4);
    *(undefined4 *)(in_stack_00000004 + 0x20e4) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_01;
  }
  if (*(int *)(in_stack_00000004 + 0x20f0) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x20e8) + 4)) /* timer_2.NetworkStateChanged() */
              (in_stack_00000004 + 0x20e8,in_stack_00000004 + 0x20f0);
    *(undefined4 *)(in_stack_00000004 + 0x20f0) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_02;
  }
  if (*(int *)(in_stack_00000004 + 0x20fc) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x20f4) + 4)) /* timer_3.NetworkStateChanged() */
              (in_stack_00000004 + 0x20f4,in_stack_00000004 + 0x20fc);
    *(undefined4 *)(in_stack_00000004 + 0x20fc) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_03;
  }
  if (*(int *)(in_stack_00000004 + 0x2108) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2100) + 4)) /* timer_4.NetworkStateChanged() */
              (in_stack_00000004 + 0x2100,in_stack_00000004 + 0x2108);
    *(undefined4 *)(in_stack_00000004 + 0x2108) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_04;
  }
  if (*(int *)(in_stack_00000004 + 0x2114) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x210c) + 4)) /* timer_5.NetworkStateChanged() */
              (in_stack_00000004 + 0x210c,in_stack_00000004 + 0x2114);
    *(undefined4 *)(in_stack_00000004 + 0x2114) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_05;
  }
  if (*(int *)(in_stack_00000004 + 0x2120) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2118) + 4)) /* timer_6.NetworkStateChanged() */
              (in_stack_00000004 + 0x2118,in_stack_00000004 + 0x2120);
    *(undefined4 *)(in_stack_00000004 + 0x2120) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_06;
  }
  if (*(int *)(in_stack_00000004 + 0x212c) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2124) + 4)) /* timer_7.NetworkStateChanged() */
              (in_stack_00000004 + 0x2124,in_stack_00000004 + 0x212c);
    *(undefined4 *)(in_stack_00000004 + 0x212c) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_07;
  }
  if (*(int *)(in_stack_00000004 + 0x2138) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2130) + 4)) /* timer_8.NetworkStateChanged() */
              (in_stack_00000004 + 0x2130,in_stack_00000004 + 0x2138);
    *(undefined4 *)(in_stack_00000004 + 0x2138) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_08;
  }
  if (*(int *)(in_stack_00000004 + 0x2144) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x213c) + 4)) /* timer_9.NetworkStateChanged() */
              (in_stack_00000004 + 0x213c,in_stack_00000004 + 0x2144);
    *(undefined4 *)(in_stack_00000004 + 0x2144) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_09;
  }
  if (*(int *)(in_stack_00000004 + 0x2150) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2148) + 4)) /* timer_10.NetworkStateChanged() */
              (in_stack_00000004 + 0x2148,in_stack_00000004 + 0x2150);
    *(undefined4 *)(in_stack_00000004 + 0x2150) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_10;
  }
  if (*(int *)(in_stack_00000004 + 0x215c) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2154) + 4)) /* timer_11.NetworkStateChanged() */
              (in_stack_00000004 + 0x2154,in_stack_00000004 + 0x215c);
    *(undefined4 *)(in_stack_00000004 + 0x215c) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_11;
  }
  *(undefined4 *)(in_stack_00000004 + 0x216c) = 0x3d23d70a /* 0.04f */;
  *(undefined4 *)(in_stack_00000004 + 0x2168) = 0x3d23d70a /* 0.04f */;
  if (*(int *)(in_stack_00000004 + 0x2164) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0x2160) + 8))
              (in_stack_00000004 + 0x2160,in_stack_00000004 + 0x2164);
    *(undefined4 *)(in_stack_00000004 + 0x2164) = 0xbf800000 /* -1.0f */;
    this_00 = extraout_ECX_12;
  }
  INextBot::Reset(this_00);
  CINSPlayer::Spawn(this_01);
  if (*(int *)(in_stack_00000004 + 0xb3e0) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb3d8) + 4)) /* timer_27.NetworkStateChanged() */
              (in_stack_00000004 + 0xb3d8,in_stack_00000004 + 0xb3e0);
    *(undefined4 *)(in_stack_00000004 + 0xb3e0) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb3ec) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb3e4) + 4)) /* timer_28.NetworkStateChanged() */
              (in_stack_00000004 + 0xb3e4,in_stack_00000004 + 0xb3ec);
    *(undefined4 *)(in_stack_00000004 + 0xb3ec) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb3f8) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb3f0) + 4)) /* timer_29.NetworkStateChanged() */
              (in_stack_00000004 + 0xb3f0,in_stack_00000004 + 0xb3f8);
    *(undefined4 *)(in_stack_00000004 + 0xb3f8) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb404) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb3fc) + 4)) /* timer_30.NetworkStateChanged() */
              (in_stack_00000004 + 0xb3fc,in_stack_00000004 + 0xb404);
    *(undefined4 *)(in_stack_00000004 + 0xb404) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb410) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb408) + 4)) /* timer_31.NetworkStateChanged() */
              (in_stack_00000004 + 0xb408,in_stack_00000004 + 0xb410);
    *(undefined4 *)(in_stack_00000004 + 0xb410) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb41c) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb414) + 4)) /* timer_32.NetworkStateChanged() */
              (in_stack_00000004 + 0xb414,in_stack_00000004 + 0xb41c);
    *(undefined4 *)(in_stack_00000004 + 0xb41c) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb428) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb420) + 4)) /* timer_33.NetworkStateChanged() */
              (in_stack_00000004 + 0xb420,in_stack_00000004 + 0xb428);
    *(undefined4 *)(in_stack_00000004 + 0xb428) = 0xbf800000 /* -1.0f */;
  }
  if (*(int *)(in_stack_00000004 + 0xb434) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb42c) + 4)) /* timer_34.NetworkStateChanged() */
              (in_stack_00000004 + 0xb42c,in_stack_00000004 + 0xb434);
    *(undefined4 *)(in_stack_00000004 + 0xb434) = 0xbf800000 /* -1.0f */;
  }
  piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))(in_stack_00000004);
  (**(code **)(*piVar7 + 0xf4 /* CINSBotVision::ForgetAllKnownEntities */))(piVar7);
  CINSBotChatter::Reset(this_02);
  *(undefined4 *)(in_stack_00000004 + 0xb444) = 0;
  *(undefined4 *)(in_stack_00000004 + 0xb448) = 0;
  if (*(int *)(in_stack_00000004 + 0xb440) != -0x40800000 /* -1.0f */) {
    (**(code **)(*(int *)(in_stack_00000004 + 0xb438) + 4)) /* timer_35.NetworkStateChanged() */
              (in_stack_00000004 + 0xb438,in_stack_00000004 + 0xb440);
    *(undefined4 *)(in_stack_00000004 + 0xb440) = 0xbf800000 /* -1.0f */;
  }
  piVar7 = (int *)*puVar2;
  iVar8 = unaff_EBX + 0x249278 /* Four_PointFives+0x4c3 */ /* Four_PointFives+0x4c3 */ /* Four_PointFives+0x4c3 */;
  *(undefined4 *)(in_stack_00000004 + 0x2294) = 0;
  *(undefined4 *)(in_stack_00000004 + 0xb32c) = 0xffffffff;
  *(undefined4 *)(in_stack_00000004 + 0xb468) = 0;
  *(undefined4 *)(in_stack_00000004 + 0x2280) = 0;
  *(undefined4 *)(in_stack_00000004 + 0x2284) = 0;
  (**(code **)(*piVar7 + 0x158))
            (piVar7,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x2389ae /* "cl_ironsight_hold" */ /* "cl_ironsight_hold" */ /* "cl_ironsight_hold" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x2389c0 /* "cl_bipod_hold" */ /* "cl_bipod_hold" */ /* "cl_bipod_hold" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x2389ce /* "cl_sprint_hold" */ /* "cl_sprint_hold" */ /* "cl_sprint_hold" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x2389dd /* "cl_crouch_hold" */ /* "cl_crouch_hold" */ /* "cl_crouch_hold" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x2389ec /* "cl_walk_hold" */ /* "cl_walk_hold" */ /* "cl_walk_hold" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x22fd5f /* "cl_grenade_auto_switch" */ /* "cl_grenade_auto_switch" */ /* "cl_grenade_auto_switch" */,iVar9);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x22fd51 /* "cl_bipod_auto" */ /* "cl_bipod_auto" */ /* "cl_bipod_auto" */,iVar8);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x22fd76 /* "cl_developer_status" */ /* "cl_developer_status" */ /* "cl_developer_status" */,iVar9);
  (**(code **)(*(int *)*puVar2 + 0x158))
            ((int *)*puVar2,*(undefined4 *)(in_stack_00000004 + 0x20),unaff_EBX + 0x22fd8a /* "cl_earlyaccess_status" */ /* "cl_earlyaccess_status" */ /* "cl_earlyaccess_status" */,iVar9);
  piVar7 = *(int **)(unaff_EBX + 0x45c52d /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
  this_07 = this_03;
  if (*piVar7 != 0) {
    cVar6 = CINSRules::IsCheckpoint(this_03);
    this_07 = this_04;
    if (((cVar6 != '\0') || (cVar6 = CINSRules::IsHunt(this_04), this_07 = this_09, cVar6 != '\0'))
       || (cVar6 = CINSRules::IsConquer(this_09), this_07 = (CINSRules *)extraout_ECX_15,
          cVar6 != '\0')) {
      piVar3 = *(int **)(unaff_EBX + 0x45cb0d /* &TheaterDirector */ /* &TheaterDirector */ /* &TheaterDirector */);
      iVar9 = *piVar3;
      if ((iVar9 != 0) && (*(int *)(iVar9 + 0x24) != 0)) {
        CINSPlayer::GetPlayerInventory((CINSPlayer *)this_07);
        local_24 = CPlayerInventory::GetClassTemplateHandle(this_05);
        iVar9 = *(int *)(*piVar3 + 0x24);
        iVar8 = CUtlRBTree<CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int,CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::CKeyLess,CUtlMemory<UtlRBTreeNode_t<CUtlMap<int,playerClassTemplate_t*,int,bool(*)(int_const&,int_const&)>::Node_t,int>,int>>
                ::Find(this_06,(Node_t *)(iVar9 + 4));
        this_07 = extraout_ECX_13;
        if (iVar8 != -1) {
          this_07 = *(CINSRules **)(iVar9 + 8);
          if (((*(int *)(this_07 + iVar8 * 0x18 + 0x14) != 0) &&
              (pcVar4 = *(char **)(*(int *)(this_07 + iVar8 * 0x18 + 0x14) + 4),
              pcVar4 != (char *)0x0)) &&
             ((*pcVar4 != '\0' &&
              (iVar9 = _V_strcmp(pcVar4,(char *)(unaff_EBX + 0x2389f9 /* "template_coop_sharpshooter" */ /* "template_coop_sharpshooter" */ /* "template_coop_sharpshooter" */)), this_07 = extraout_ECX_16,
              iVar9 == 0)))) {
            DevMsg((char *)(unaff_EBX + 0x238a14 /* "Making %s defensive.
" */ /* "Making %s defensive.
" */ /* "Making %s defensive.
" */));
            *(uint *)(in_stack_00000004 + 0x2294) = *(uint *)(in_stack_00000004 + 0x2294) | 4;
            this_07 = extraout_ECX_17;
          }
        }
      }
    }
    if ((*piVar7 != 0) &&
       (cVar6 = CINSRules::IsTraining(this_07), this_07 = (CINSRules *)this_08, cVar6 != '\0')) {
      iVar9 = CBaseEntity::GetTeamNumber(this_08);
      *(uint *)(in_stack_00000004 + 0x2294) =
           *(uint *)(in_stack_00000004 + 0x2294) | (uint)(iVar9 != 2) * 8 + 8;
      this_07 = (CINSRules *)extraout_ECX_14;
    }
  }
  pVVar10 = (Vector *)&local_48;
  uVar12 = 0;
  uVar11 = 0;
  CBasePlayer::EyeVectors((CBasePlayer *)this_07,in_stack_00000004,pVVar10,(Vector *)0x0);
  piVar7 = (int *)(**(code **)(*(int *)in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))
                            (in_stack_00000004,pVVar10,uVar11,uVar12);
  fVar1 = *(float *)(unaff_EBX + 0x1dedfd /* 64.0f */ /* 64.0f */ /* 64.0f */);
  pcVar5 = *(code **)(*piVar7 + 0xd4);
  (**(code **)(*(int *)in_stack_00000004 + 0x20c /* CINSNextBot::EyePosition */))(&local_3c,in_stack_00000004);
  local_30 = local_48 * fVar1 + local_3c;
  local_2c = local_44 * fVar1 + local_38;
  local_28 = fVar1 * local_40 + local_34;
  (*pcVar5)(piVar7,&local_30,5,0,0,unaff_EBX + 0x238a2a /* "Looking in spawn direction" */ /* "Looking in spawn direction" */ /* "Looking in spawn direction" */);
  return;
}



/* ----------------------------------------
 * CINSNextBot::Touch
 * Address: 007436d0
 * ---------------------------------------- */

/* CINSNextBot::Touch(CBaseEntity*) */

void __thiscall CINSNextBot::Touch(CINSNextBot *this,CBaseEntity *param_1)

{
  char cVar1;
  undefined4 *puVar2;
  CBasePlayer *extraout_ECX;
  CBasePlayer *extraout_ECX_00;
  CBasePlayer *this_00;
  undefined4 extraout_EDX;
  undefined4 in_stack_00000008;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined1 local_48;
  undefined1 local_47;
  undefined2 local_46;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined1 local_3a;
  undefined1 local_39;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined2 local_28;
  undefined2 local_26;
  undefined4 local_24;
  undefined4 local_20;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*(int *)(param_1 + 0x2060) + 0x100))(param_1 + 0x2060,extraout_EDX);
  this_00 = extraout_ECX;
  if (cVar1 != '\0') {
    local_24 = 0;
    puVar2 = (undefined4 *)CBaseEntity::GetTouchTrace();
    local_70 = *puVar2;
    local_6c = puVar2[1];
    local_68 = puVar2[2];
    local_64 = puVar2[3];
    local_60 = puVar2[4];
    local_5c = puVar2[5];
    local_58 = puVar2[6];
    local_54 = puVar2[7];
    local_50 = puVar2[8];
    local_4c = puVar2[9];
    local_48 = *(undefined1 *)(puVar2 + 10);
    local_47 = *(undefined1 *)((int)puVar2 + 0x29);
    local_46 = *(undefined2 *)((int)puVar2 + 0x2a);
    local_44 = puVar2[0xb];
    local_40 = puVar2[0xc];
    local_3c = *(undefined2 *)(puVar2 + 0xd);
    local_3a = *(undefined1 *)((int)puVar2 + 0x36);
    local_39 = *(undefined1 *)((int)puVar2 + 0x37);
    local_30 = puVar2[0x10];
    local_38 = puVar2[0xe];
    local_34 = puVar2[0xf];
    local_2c = puVar2[0x11];
    local_28 = *(undefined2 *)(puVar2 + 0x12);
    local_26 = *(undefined2 *)((int)puVar2 + 0x4a);
    local_24 = puVar2[0x13];
    local_20 = puVar2[0x14];
    (**(code **)(*(int *)(param_1 + 0x2060) + 0x18))(param_1 + 0x2060,in_stack_00000008,&local_70);
    this_00 = extraout_ECX_00;
  }
  CBasePlayer::Touch(this_00,param_1);
  return;
}



/* ----------------------------------------
 * CINSNextBot::TransientlyConsistentRandomValue
 * Address: 00747a50
 * ---------------------------------------- */

/* CINSNextBot::TransientlyConsistentRandomValue(float, int) const */

float10 __thiscall
CINSNextBot::TransientlyConsistentRandomValue(CINSNextBot *this,float param_1,int param_2)

{
  int iVar1;
  int unaff_EBX;
  float10 fVar2;
  int in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  iVar1 = 0;
  if (*(int *)((int)param_1 + 0x20) != 0) {
    iVar1 = ((int)(*(float *)(**(int **)(unaff_EBX + 0x45ee47 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc) / (float)param_2) + 1) *
            (*(int *)((int)param_1 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x45ee47 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c) >> 4)
    ;
  }
  fVar2 = (float10)FastCos((float)(iVar1 + in_stack_0000000c));
  return (float10)(float)(double)((ulonglong)(double)(float)fVar2 &
                                 *(ulonglong *)(unaff_EBX + 0x1710d7 /* NaN / -1 */ /* NaN / -1 */ /* NaN / -1 */));
}



/* ----------------------------------------
 * CINSNextBot::UpdateChasePath
 * Address: 0075c3a0
 * ---------------------------------------- */

/* CINSNextBot::UpdateChasePath(CBaseEntity*) */

void __thiscall CINSNextBot::UpdateChasePath(CINSNextBot *this,CBaseEntity *param_1)

{
  uint *puVar1;
  char cVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  CBaseEntity *this_00;
  ChasePath *extraout_ECX;
  ChasePath *extraout_ECX_00;
  ChasePath *this_01;
  CINSPathFollower *this_02;
  INextBot *pIVar6;
  int unaff_EBX;
  float10 fVar7;
  IPathCost *in_stack_00000008;
  CBaseEntity *pCVar8;
  Vector *pVVar9;
  undefined4 uVar10;
  int local_44;
  CBaseEntity *local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  float local_2c;
  float local_28;
  float local_24;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x75c3ab;
  __i686_get_pc_thunk_bx();
  if (((byte)in_stack_00000008[0xd1] & 8) != 0) {
    CBaseEntity::CalcAbsolutePosition(this_00);
  }
  local_38 = *(undefined4 *)(in_stack_00000008 + 0x208);
  pCVar8 = param_1 + 0x2060;
  local_3c = 1;
  local_34 = *(undefined4 *)(in_stack_00000008 + 0x20c);
  local_44 = unaff_EBX + 0x438195 /* vtable for CINSNextBotChasePathCost+0x8 */ /* vtable for CINSNextBotChasePathCost+0x8 */ /* vtable for CINSNextBotChasePathCost+0x8 */;
  local_30 = *(undefined4 *)(in_stack_00000008 + 0x210);
  local_40 = pCVar8;
  piVar3 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pCVar8);
  fVar7 = (float10)(**(code **)(*piVar3 + 0x14c))(piVar3);
  local_2c = (float)fVar7;
  piVar3 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pCVar8);
  fVar7 = (float10)(**(code **)(*piVar3 + 0x150))(piVar3);
  local_28 = (float)fVar7;
  piVar3 = (int *)(**(code **)(*(int *)(param_1 + 0x2060) + 0xd0))(pCVar8);
  fVar7 = (float10)(**(code **)(*piVar3 + 0x154))(piVar3);
  local_24 = (float)fVar7;
  pIVar6 = (INextBot *)(param_1 + 0x2298);
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  this_01 = extraout_ECX;
  if ((bool)local_1d) {
    iVar5 = *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar4 = ThreadGetCurrentId();
    this_01 = extraout_ECX_00;
    if (iVar5 == iVar4) {
      piVar3 = *(int **)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (*piVar3 != unaff_EBX + 0x1cd87b /* "ChasePath::Update" */ /* "ChasePath::Update" */ /* "ChasePath::Update" */) {
        piVar3 = (int *)CVProfNode::GetSubNode
                                  ((char *)piVar3,unaff_EBX + 0x1cd87b /* "ChasePath::Update" */ /* "ChasePath::Update" */ /* "ChasePath::Update" */,(char *)0x0,
                                   unaff_EBX + 0x2248be /* "NextBot" */ /* "NextBot" */ /* "NextBot" */);
        *(int **)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar3;
      }
      puVar1 = (uint *)(piVar3[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
      *puVar1 = *puVar1 | 4;
      CVProfNode::EnterScope();
      this_01 = *(ChasePath **)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
      this_01[0x1010] = (ChasePath)0x0;
    }
  }
  pVVar9 = (Vector *)&local_44;
  uVar10 = 0;
  ChasePath::RefreshPath(this_01,pIVar6,pCVar8,in_stack_00000008,pVVar9);
  CINSPathFollower::Update(this_02,pIVar6);
  if ((local_1d != '\0') &&
     ((*(char *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) == '\0' ||
      (*(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0)))) {
    iVar5 = *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar4 = ThreadGetCurrentId(pIVar6,pCVar8,in_stack_00000008,pVVar9,uVar10);
    if (iVar5 == iVar4) {
      cVar2 = CVProfNode::ExitScope();
      iVar5 = *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
      if (cVar2 != '\0') {
        iVar5 = *(int *)(iVar5 + 100);
        *(int *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar5;
      }
      *(bool *)(*(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
           iVar5 == *(int *)(unaff_EBX + 0x44a5c9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
      return;
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::UpdateCover
 * Address: 0074ac70
 * ---------------------------------------- */

/* WARNING: Restarted to delay deadcode elimination for space: stack */
/* CINSNextBot::UpdateCover() */

void __thiscall CINSNextBot::UpdateCover(CINSNextBot *this)

{
  uint *puVar1;
  Vector *pVVar2;
  undefined4 *puVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
  *this_00;
  CBaseEntity *this_01;
  CNavArea *this_02;
  CNavArea *this_03;
  CNavArea *extraout_ECX;
  CNavArea *extraout_ECX_00;
  CBasePlayer *this_04;
  CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
  *extraout_ECX_01;
  CBaseEntity *this_05;
  CBaseEntity *this_06;
  CBaseEntity *extraout_ECX_02;
  int iVar8;
  int unaff_EBX;
  Vector *pVVar9;
  int *piVar10;
  float10 fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  Vector *in_stack_00000004;
  undefined4 uVar20;
  int local_7c;
  float local_68;
  undefined **local_64;
  CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
  *local_60;
  undefined *local_5c;
  int local_58;
  undefined4 local_54;
  int local_50;
  int local_4c;
  int local_48;
  undefined4 local_44;
  float local_3c;
  float local_38;
  float local_34;
  int local_2c;
  float local_28;
  undefined1 local_22;
  char local_1d;
  undefined4 uStack_14;
  
  uStack_14 = 0x74ac7b;
  __i686_get_pc_thunk_bx();
  local_1d = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) != 0;
  if (((bool)local_1d) &&
     (iVar6 = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8), iVar5 = ThreadGetCurrentId(),
     iVar6 == iVar5)) {
    piVar10 = *(int **)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    if (*piVar10 != unaff_EBX + 0x2381b1 /* "CINSNextBot::UpdateCover" */ /* "CINSNextBot::UpdateCover" */ /* "CINSNextBot::UpdateCover" */) {
      piVar10 = (int *)CVProfNode::GetSubNode
                                 ((char *)piVar10,unaff_EBX + 0x2381b1 /* "CINSNextBot::UpdateCover" */ /* "CINSNextBot::UpdateCover" */ /* "CINSNextBot::UpdateCover" */,(char *)0x0,
                                  unaff_EBX + 0x235feb /* "INSNextBot" */ /* "INSNextBot" */ /* "INSNextBot" */);
      *(int **)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = piVar10;
    }
    puVar1 = (uint *)(piVar10[0x1c] * 8 + *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x10a0) + 4);
    *puVar1 = *puVar1 | 4;
    CVProfNode::EnterScope();
    *(undefined1 *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) = 0;
  }
  fVar18 = *(float *)(**(int **)(unaff_EBX + 0x45bc25 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0xc);
  if (fVar18 < *(float *)(unaff_EBX + 0x16de99 /* 1.0f */ /* 1.0f */ /* 1.0f */) + *(float *)(in_stack_00000004 + 0x2188)) {
    if (local_1d == '\0') {
      return;
    }
    if ((*(char *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
       (*(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
      return;
    }
    iVar6 = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
    iVar5 = ThreadGetCurrentId();
    if (iVar6 != iVar5) {
      return;
    }
    cVar4 = CVProfNode::ExitScope();
    if (cVar4 == '\0') {
      iVar6 = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
    }
    else {
      iVar6 = *(int *)(*(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) + 100);
      *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar6;
    }
    goto LAB_0074ae1d;
  }
  *(float *)(in_stack_00000004 + 0x2188) = fVar18;
  pVVar9 = in_stack_00000004;
  cVar4 = (**(code **)(*(int *)in_stack_00000004 + 0x8ac /* CINSNextBot::IsInCombat */))(in_stack_00000004);
  if (cVar4 == '\0') {
LAB_0074acfc:
    if (0 < *(int *)(in_stack_00000004 + 0x2180)) {
      local_60 = (CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
                  *)(*(int *)(in_stack_00000004 + 0x2180) + -1);
      local_7c = (int)local_60 * 0xc;
      do {
        piVar10 = (int *)(local_7c + *(int *)(in_stack_00000004 + 0x2174));
        iVar6 = *piVar10;
        if (iVar6 == 0) {
          iVar6 = *(int *)(in_stack_00000004 + 0x2180);
          iVar5 = (iVar6 - (int)local_60) + -1;
          if (0 < iVar5) {
            _V_memmove(piVar10,(void *)(*(int *)(in_stack_00000004 + 0x2174) + 0xc + local_7c),
                       iVar5 * 0xc);
            iVar6 = *(int *)(in_stack_00000004 + 0x2180);
            piVar10 = (int *)(local_7c + *(int *)(in_stack_00000004 + 0x2174));
          }
          *(int *)(in_stack_00000004 + 0x2180) = iVar6 + -1;
          iVar6 = *piVar10;
        }
        fVar11 = (float10)(**(code **)(*(int *)(in_stack_00000004 + 0x2060) + 0x134))
                                    (in_stack_00000004 + 0x2060,iVar6 + 4);
        local_60 = (CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
                    *)((int)local_60 + -1);
        piVar10[1] = (int)(float)fVar11;
        local_7c = local_7c + -0xc;
      } while (local_60 !=
               (CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
                *)0xffffffff);
      pVVar9 = in_stack_00000004 + 0x2174;
      CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
      ::Sort(this_00,(_func_int_INSBotCoverContainer_ptr_INSBotCoverContainer_ptr *)pVVar9);
    }
  }
  else {
    pVVar2 = in_stack_00000004 + 0x2060;
    pVVar9 = pVVar2;
    fVar11 = (float10)(**(code **)(*(int *)(in_stack_00000004 + 0x2060) + 0x134))
                                (pVVar2,in_stack_00000004 + 0x218c);
    if ((float)fVar11 < *(float *)(unaff_EBX + 0x1e2a09 /* 500.0f */ /* 500.0f */ /* 500.0f */) ||
        (float)fVar11 == *(float *)(unaff_EBX + 0x1e2a09 /* 500.0f */ /* 500.0f */ /* 500.0f */)) goto LAB_0074acfc;
    local_58 = 0;
    local_54 = 0;
    local_50 = 0;
    local_4c = 0;
    local_48 = 0;
    local_44 = 0x32;
    local_5c = &UNK_00451f2d + unaff_EBX;
    iVar6 = (**(code **)(*(int *)in_stack_00000004 + 0x548 /* CINSNextBot::GetLastKnownArea */))(in_stack_00000004);
    if (iVar6 != 0) {
      iVar8 = **(int **)(unaff_EBX + 0x45bb61 /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */) + 1;
      **(int **)(unaff_EBX + 0x45bb61 /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */) = iVar8;
      iVar5 = 1;
      if (iVar8 != 0) {
        iVar5 = iVar8;
      }
      **(int **)(unaff_EBX + 0x45bb61 /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */) = iVar5;
      CNavArea::ClearSearchLists();
      CNavArea::AddToOpenList(this_02);
      puVar3 = *(undefined4 **)(unaff_EBX + 0x45bb61 /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */ /* &CNavArea::m_masterMarker */);
      *(undefined4 *)(iVar6 + 0x50) = 0;
      *(undefined4 *)(iVar6 + 0x54) = 0;
      *(undefined4 *)(iVar6 + 0x88) = 0;
      *(undefined4 *)(iVar6 + 0x8c) = 9;
      *(undefined4 *)(iVar6 + 100) = *puVar3;
      this_03 = (CNavArea *)&local_5c;
      while (iVar6 = **(int **)(unaff_EBX + 0x45c0cd /* &CNavArea::m_openList */ /* &CNavArea::m_openList */ /* &CNavArea::m_openList */), iVar6 != 0) {
        while( true ) {
          CNavArea::RemoveFromOpenList(this_03);
          fVar18 = *(float *)(iVar6 + 0x54);
          *(undefined4 *)(iVar6 + 0x5c) = 0;
          *(undefined4 *)(iVar6 + 0x58) = 0;
          this_03 = extraout_ECX;
          if (*(float *)(unaff_EBX + 0x20101d /* 2000.0f */ /* 2000.0f */ /* 2000.0f */) <= fVar18 &&
              fVar18 != *(float *)(unaff_EBX + 0x20101d /* 2000.0f */ /* 2000.0f */ /* 2000.0f */)) break;
          cVar4 = (**(code **)(local_5c + 8))
                            ((CNavArea *)&local_5c,iVar6,*(undefined4 *)(iVar6 + 0x88),fVar18);
          if (cVar4 == '\0') goto LAB_0074b108;
          (**(code **)(local_5c + 0x10))
                    ((CNavArea *)&local_5c,iVar6,*(undefined4 *)(iVar6 + 0x88),
                     *(undefined4 *)(iVar6 + 0x54));
          iVar6 = **(int **)(unaff_EBX + 0x45c0cd /* &CNavArea::m_openList */ /* &CNavArea::m_openList */ /* &CNavArea::m_openList */);
          this_03 = extraout_ECX_00;
          if (iVar6 == 0) goto LAB_0074b108;
        }
      }
    }
LAB_0074b108:
    local_64 = &local_5c;
    (**(code **)(local_5c + 0x14))(local_64);
    local_60 = (CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
                *)this_04;
    if (0 < local_4c) {
      *(undefined4 *)(in_stack_00000004 + 0x2180) = 0;
      uVar20 = 0;
      piVar10 = (int *)0x0;
      CBasePlayer::EyeVectors(this_04,in_stack_00000004,(Vector *)&local_3c,(Vector *)0x0);
      local_34 = 0.0;
      local_3c = local_3c * *(float *)(unaff_EBX + 0x1d8e0d /* 16.0f */ /* 16.0f */ /* 16.0f */);
      local_38 = *(float *)(unaff_EBX + 0x1d8e0d /* 16.0f */ /* 16.0f */ /* 16.0f */) * local_38;
      local_60 = extraout_ECX_01;
      if (0 < local_4c) {
        local_60 = (CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
                    *)0x0;
        do {
          iVar6 = *(int *)(local_58 + (int)local_60 * 4);
          if (iVar6 != 0) {
            local_2c = iVar6;
            fVar11 = (float10)(**(code **)(*(int *)(in_stack_00000004 + 0x2060) + 0x134))
                                        (pVVar2,iVar6 + 4,piVar10,uVar20);
            uVar7 = *(uint *)(in_stack_00000004 + 0xd0);
            local_28 = (float)fVar11;
            this_05 = this_06;
            if ((uVar7 & 0x800) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_06);
              uVar7 = *(uint *)(in_stack_00000004 + 0xd0);
              this_05 = extraout_ECX_02;
            }
            local_68 = *(float *)(in_stack_00000004 + 0x210);
            fVar18 = *(float *)(iVar6 + 4);
            fVar16 = *(float *)(iVar6 + 8);
            fVar19 = *(float *)(in_stack_00000004 + 0x208);
            fVar17 = *(float *)(in_stack_00000004 + 0x20c);
            fVar15 = *(float *)(iVar6 + 0xc);
            fVar14 = fVar18 - fVar19;
            fVar12 = fVar16 - fVar17;
            fVar13 = fVar15 - local_68;
            if ((uVar7 & 0x800) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_05);
              local_68 = *(float *)(in_stack_00000004 + 0x210);
              fVar19 = *(float *)(in_stack_00000004 + 0x208);
              fVar17 = *(float *)(in_stack_00000004 + 0x20c);
              fVar18 = *(float *)(iVar6 + 4);
              fVar16 = *(float *)(iVar6 + 8);
              fVar15 = *(float *)(iVar6 + 0xc);
            }
            piVar10 = &local_2c;
            fVar19 = (fVar18 - local_3c) - fVar19;
            fVar17 = (fVar16 - local_38) - fVar17;
            local_68 = (fVar15 - local_34) - local_68;
            local_22 = SQRT(fVar17 * fVar17 + fVar19 * fVar19 + local_68 * local_68) <
                       SQRT(fVar12 * fVar12 + fVar14 * fVar14 + fVar13 * fVar13);
            CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
            ::InsertBefore((int)(in_stack_00000004 + 0x2174),
                           *(INSBotCoverContainer **)(in_stack_00000004 + 0x2180));
          }
          local_60 = local_60 + 1;
        } while ((int)local_60 < local_4c);
      }
    }
    pVVar9 = in_stack_00000004 + 0x2174;
    CUtlVector<CINSNextBot::INSBotCoverContainer,CUtlMemory<CINSNextBot::INSBotCoverContainer,int>>
    ::Sort(local_60,(_func_int_INSBotCoverContainer_ptr_INSBotCoverContainer_ptr *)pVVar9);
    if (((byte)in_stack_00000004[0xd1] & 8) != 0) {
      pVVar9 = in_stack_00000004;
      CBaseEntity::CalcAbsolutePosition(this_01);
    }
    *(undefined4 *)(in_stack_00000004 + 0x21a4) = 0;
    *(undefined4 *)(in_stack_00000004 + 0x21b4) = 0;
    local_4c = 0;
    *(undefined4 *)(in_stack_00000004 + 0x218c) = *(undefined4 *)(in_stack_00000004 + 0x208);
    *(undefined4 *)(in_stack_00000004 + 0x2190) = *(undefined4 *)(in_stack_00000004 + 0x20c);
    *(undefined4 *)(in_stack_00000004 + 0x2194) = *(undefined4 *)(in_stack_00000004 + 0x210);
    if (local_50 < 0) {
      local_48 = local_58;
    }
    else {
      if (local_58 != 0) {
        pVVar9 = (Vector *)**(undefined4 **)(unaff_EBX + 0x45bbfd /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */);
        local_5c = &UNK_00451f2d + unaff_EBX;
        (**(code **)(*(int *)pVVar9 + 8))(pVVar9,local_58);
        local_58 = 0;
      }
      local_54 = 0;
      local_48 = 0;
    }
    local_5c = &UNK_00451f0d + unaff_EBX;
  }
  if (local_1d == '\0') {
    return;
  }
  if ((*(char *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) != '\0') &&
     (*(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x100c) == 0)) {
    return;
  }
  iVar6 = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x19b8);
  iVar5 = ThreadGetCurrentId(pVVar9);
  if (iVar6 != iVar5) {
    return;
  }
  cVar4 = CVProfNode::ExitScope();
  iVar6 = *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014);
  if (cVar4 != '\0') {
    iVar6 = *(int *)(iVar6 + 100);
    *(int *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1014) = iVar6;
  }
LAB_0074ae1d:
  *(bool *)(*(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1010) =
       iVar6 == *(int *)(unaff_EBX + 0x45bcf9 /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 0x1018;
  return;
}



/* ----------------------------------------
 * CINSNextBot::UpdateIdleStatus
 * Address: 00748130
 * ---------------------------------------- */

/* CINSNextBot::UpdateIdleStatus() */

void __thiscall CINSNextBot::UpdateIdleStatus(CINSNextBot *this)

{
  char cVar1;
  CINSPlayer *this_00;
  float10 fVar2;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  cVar1 = (**(code **)(*in_stack_00000004 + 0x118 /* CBaseEntity::IsAlive */))();
  if ((((cVar1 == '\0') || (cVar1 = CINSPlayer::IsMoving(this_00), cVar1 != '\0')) ||
      (cVar1 = (**(code **)(*in_stack_00000004 + 0x8a8 /* CINSPlayer::IsFiringWeapon */))(), cVar1 != '\0')) ||
     (((char)in_stack_00000004[0x8a4] != '\0' || (cVar1 = CINSPlayer::IsReloading(), cVar1 != '\0'))
     )) {
    if (in_stack_00000004[0x2cf2] != -0x40800000 /* -1.0f */) {
      (**(code **)(in_stack_00000004[0x2cf1] + 8))
                (in_stack_00000004 + 0x2cf1,in_stack_00000004 + 0x2cf2);
      in_stack_00000004[0x2cf2] = -0x40800000 /* -1.0f */;
    }
    return;
  }
  if (0.0 < (float)in_stack_00000004[0x2cf2]) {
    return;
  }
  fVar2 = (float10)IntervalTimer::Now();
  if ((float)in_stack_00000004[0x2cf2] == (float)fVar2) {
    return;
  }
  (**(code **)(in_stack_00000004[0x2cf1] + 8))
            (in_stack_00000004 + 0x2cf1,in_stack_00000004 + 0x2cf2);
  in_stack_00000004[0x2cf2] = (int)(float)fVar2;
  return;
}



/* ----------------------------------------
 * CINSNextBot::UpdateLookingAroundForEnemies
 * Address: 0075a1e0
 * ---------------------------------------- */

/* CINSNextBot::UpdateLookingAroundForEnemies() */

void __thiscall CINSNextBot::UpdateLookingAroundForEnemies(CINSNextBot *this)

{
  code *pcVar1;
  float fVar2;
  float fVar3;
  char cVar4;
  int *piVar5;
  int *piVar6;
  int iVar7;
  undefined4 uVar8;
  float *pfVar9;
  CBaseEntity *this_00;
  CBaseEntity *this_01;
  CBaseEntity *this_02;
  int unaff_EBX;
  float10 fVar10;
  float10 fVar11;
  float fVar12;
  uint uVar13;
  int *in_stack_00000004;
  undefined4 uVar14;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  __i686_get_pc_thunk_bx();
  if ((*(byte *)(in_stack_00000004 + 0x8a5) & 2) == 0) {
    piVar5 = (int *)(**(code **)(*in_stack_00000004 + 0x974 /* CINSNextBot::GetVisionInterface */))();
    piVar5 = (int *)(**(code **)(*piVar5 + 0xd0 /* CINSBotVision::GetPrimaryKnownThreat */))(piVar5,0);
    piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0x97c /* CINSNextBot::GetIntentionInterface */))();
    iVar7 = (**(code **)(*piVar6 + 0xd4 /* IIntention::ShouldAttack */))(piVar6,in_stack_00000004 + 0x818,piVar5);
    if ((iVar7 != 0) && (piVar5 != (int *)0x0)) {
      cVar4 = (**(code **)(*piVar5 + 0x38 /* CBaseAnimating::TestCollision */))(piVar5);
      if (cVar4 == '\0') {
        fVar10 = (float10)(**(code **)(*piVar5 + 0x48 /* CBaseEntity::SetOwnerEntity */))(piVar5);
        if ((float)fVar10 < *(float *)(unaff_EBX + 0x15ed85 /* 3.0f */ /* 3.0f */ /* 3.0f */)) {
          pcVar1 = *(code **)(in_stack_00000004[0x818] + 0x130);
          uVar8 = (**(code **)(*piVar5 + 0x10 /* CBaseEntity::GetCollideable */))(piVar5);
          fVar10 = (float10)(*pcVar1)(in_stack_00000004 + 0x818,uVar8);
          if ((float)fVar10 < *(float *)(unaff_EBX + 0x1e1f99 /* 256.0f */ /* 256.0f */ /* 256.0f */)) {
            pcVar1 = *(code **)(*in_stack_00000004 + 0x444);
            iVar7 = (**(code **)(*piVar5 + 0x10 /* CBaseEntity::GetCollideable */))(piVar5);
            if ((*(byte *)(iVar7 + 0xd1) & 8) != 0) {
              CBaseEntity::CalcAbsolutePosition(this_00);
            }
            iVar7 = iVar7 + 0x208;
            uVar14 = 0;
            uVar8 = 1;
            cVar4 = (*pcVar1)();
            if (cVar4 != '\0') {
              if ((*(byte *)((int)in_stack_00000004 + 0xd1) & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition(this_01);
              }
              iVar7 = (**(code **)(*piVar5 + 0x10 /* CBaseEntity::GetCollideable */))(piVar5,iVar7,uVar8,uVar14);
              if ((*(byte *)(iVar7 + 0xd1) & 8) != 0) {
                CBaseEntity::CalcAbsolutePosition(this_02);
              }
              local_34 = *(float *)(iVar7 + 0x208) - (float)in_stack_00000004[0x82];
              local_30 = *(float *)(iVar7 + 0x20c) - (float)in_stack_00000004[0x83];
              local_2c = *(float *)(iVar7 + 0x210) - (float)in_stack_00000004[0x84];
              fVar10 = (float10)VectorNormalize((Vector *)&local_34);
              fcos((float10)*(float *)(unaff_EBX + 0x22c6e5 /* CSWTCH.663+0x10 */ /* CSWTCH.663+0x10 */ /* CSWTCH.663+0x10 */));
              fVar11 = (float10)fsin((float10)*(float *)(unaff_EBX + 0x22c6e5 /* CSWTCH.663+0x10 */ /* CSWTCH.663+0x10 */ /* CSWTCH.663+0x10 */));
              fVar12 = (float)fVar11 * (float)fVar10;
              piVar5 = (int *)(**(code **)(*piVar5 + 0x10 /* CBaseEntity::GetCollideable */))(piVar5);
              pfVar9 = (float *)(**(code **)(*piVar5 + 0x260 /* CBaseEntity::WorldSpaceCenter */))(piVar5);
              fVar2 = *pfVar9;
              uVar13 = *(uint *)(unaff_EBX + 0x1caa09 /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */ /* SIGN_BIT_MASK */) ^ (uint)fVar12;
              local_24 = pfVar9[1];
              local_20 = pfVar9[2];
              local_28 = fVar2;
              fVar10 = (float10)RandomFloat(uVar13,fVar12);
              fVar3 = local_24;
              local_28 = (float)fVar10 + fVar2;
              fVar10 = (float10)RandomFloat(uVar13,fVar12);
              local_24 = (float)fVar10 + fVar3;
              piVar5 = (int *)(**(code **)(*in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))();
              (**(code **)(*piVar5 + 0xd4 /* PlayerBody::AimHeadTowards */))(piVar5,&local_28,3,0x3f000000 /* 0.5f */,0,unaff_EBX + 0x22c621 /* "Turning around to find threat out of our FOV" */ /* "Turning around to find threat out of our FOV" */ /* "Turning around to find threat out of our FOV" */);
            }
          }
        }
      }
      else {
        piVar6 = (int *)(**(code **)(*in_stack_00000004 + 0x970 /* CINSNextBot::GetBodyInterface */))();
        pcVar1 = *(code **)(*piVar6 + 0xd8);
        uVar8 = (**(code **)(*piVar5 + 0x10 /* INextBotEventResponder::OnLeaveGround */))(piVar5);
        (*pcVar1)(piVar6,uVar8,3,0x3f000000 /* 0.5f */,0,unaff_EBX + 0x22607e /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */ /* "Aiming at a visible threat" */);
      }
    }
  }
  return;
}



/* ----------------------------------------
 * CINSNextBot::UpdateLookingAroundForIncomingPlayers
 * Address: 0075a170
 * ---------------------------------------- */

/* CINSNextBot::UpdateLookingAroundForIncomingPlayers(bool, bool) */

void __thiscall
CINSNextBot::UpdateLookingAroundForIncomingPlayers(CINSNextBot *this,bool param_1,bool param_2)

{
  int unaff_EBX;
  float10 fVar1;
  undefined3 in_stack_00000005;
  char in_stack_0000000c;
  
  __i686_get_pc_thunk_bx();
  if (in_stack_0000000c == '\0') {
    fVar1 = (float10)CountdownTimer::Now();
    if ((float)fVar1 < *(float *)(_param_1 + 0xb39c) || /* !timer_22.IsElapsed() */
        (float)fVar1 == *(float *)(_param_1 + 0xb39c)) {
      return;
    }
  }
  Warning(unaff_EBX + 0x22c66a /* "TODO: UpdateLookingAroundForIncomingPlayers
" */ /* "TODO: UpdateLookingAroundForIncomingPlayers
" */ /* "TODO: UpdateLookingAroundForIncomingPlayers
" */);
  return;
}



/* ----------------------------------------
 * CINSNextBot::UpdatePathFollower
 * Address: 0075ca70
 * ---------------------------------------- */

/* CINSNextBot::UpdatePathFollower(Vector) */

void __cdecl
CINSNextBot::UpdatePathFollower
          (int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  float fVar1;
  PathFollower *extraout_ECX;
  PathFollower *this;
  PathFollower *extraout_ECX_00;
  float10 fVar2;
  
  __i686_get_pc_thunk_bx();
  fVar2 = (float10)CountdownTimer::Now();
  this = extraout_ECX;
  if (*(float *)(param_1 + 0xb314) <= (float)fVar2 && (float)fVar2 != *(float *)(param_1 + 0xb314)) /* timer_15.IsElapsed() */
  {
    fVar2 = (float10)RandomFloat(0x3f800000 /* 1.0f */,0x40400000 /* 3.0f */);
    fVar1 = (float)fVar2;
    fVar2 = (float10)CountdownTimer::Now();
    if (*(float *)(param_1 + 0xb314) != (float)fVar2 + fVar1) {
      (**(code **)(*(int *)(param_1 + 0xb30c) + 4))(param_1 + 0xb30c,param_1 + 0xb314); /* timer_15.NetworkStateChanged() */
      *(float *)(param_1 + 0xb314) = (float)fVar2 + fVar1; /* timer_15.Start(...) */
    }
    if (*(float *)(param_1 + 0xb310) != fVar1) {
      (**(code **)(*(int *)(param_1 + 0xb30c) + 4))(param_1 + 0xb30c,param_1 + 0xb310); /* timer_15.NetworkStateChanged() */
      *(float *)(param_1 + 0xb310) = fVar1; /* timer_15.m_duration */
    }
    ComputePathFollower(param_1,param_2,param_3,param_4);
    this = extraout_ECX_00;
  }
  PathFollower::Update(this,(INextBot *)(param_1 + 0x6b34));
  return;
}



/* ----------------------------------------
 * CINSNextBot::Upkeep
 * Address: 00743370
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::Upkeep() */

void __thiscall CINSNextBot::Upkeep(CINSNextBot *this)

{
  Upkeep(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::Upkeep
 * Address: 00743380
 * ---------------------------------------- */

/* CINSNextBot::Upkeep() */

void __thiscall CINSNextBot::Upkeep(CINSNextBot *this)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  CINSRules *this_00;
  CINSRules *this_01;
  INextBot *extraout_ECX;
  INextBot *extraout_ECX_00;
  CINSRules *this_02;
  INextBot *extraout_ECX_01;
  int unaff_EBX;
  int in_stack_00000004;
  undefined4 uVar5;
  
  __i686_get_pc_thunk_bx();
  piVar1 = *(int **)(unaff_EBX + 0x46356a /* &g_pGameRules */ /* &g_pGameRules */ /* &g_pGameRules */);
  cVar2 = CINSRules::IsGameState(this_00,*piVar1);
  this_02 = this_01;
  if (cVar2 == '\0') {
    uVar5 = 3;
    cVar2 = CINSRules::IsGameState(this_01,*piVar1);
    if (cVar2 == '\0') {
      return;
    }
    iVar3 = 0;
    if (*(int *)(in_stack_00000004 + 0x20) != 0) {
      iVar3 = *(int *)(in_stack_00000004 + 0x20) - *(int *)(**(int **)(unaff_EBX + 0x463512 /* &gpGlobals */ /* &gpGlobals */ /* &gpGlobals */) + 0x5c)
              >> 4;
    }
    piVar4 = (int *)UTIL_PlayerByIndex(iVar3);
    this_02 = (CINSRules *)extraout_ECX;
    if (((piVar4 != (int *)0x0) &&
        (cVar2 = (**(code **)(*piVar4 + 0x158))(piVar4,uVar5),
        this_02 = (CINSRules *)extraout_ECX_00, cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*(int *)*piVar1 + 0x3a8))((int *)*piVar1,piVar4),
       this_02 = (CINSRules *)extraout_ECX_01, cVar2 == '\0')) {
      return;
    }
  }
  INextBot::Upkeep((INextBot *)this_02);
  return;
}



/* ----------------------------------------
 * CINSNextBot::~CINSNextBot
 * Address: 00749db0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::~CINSNextBot() */

void __thiscall CINSNextBot::~CINSNextBot(CINSNextBot *this)

{
  ~CINSNextBot(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::~CINSNextBot
 * Address: 00749dc0
 * ---------------------------------------- */

/* CINSNextBot::~CINSNextBot() */

void __thiscall CINSNextBot::~CINSNextBot(CINSNextBot *this)

{
  int *piVar1;
  void *pvVar2;
  int iVar3;
  CINSBotChatter *extraout_ECX;
  CINSBotChatter *extraout_ECX_00;
  CINSBotChatter *extraout_ECX_01;
  CINSBotChatter *extraout_ECX_02;
  CINSBotChatter *extraout_ECX_03;
  CINSBotChatter *extraout_ECX_04;
  CINSBotChatter *extraout_ECX_05;
  CINSBotChatter *this_00;
  CUtlMemory<InvestigationData_t,int> *extraout_ECX_06;
  CUtlMemory<InvestigationData_t,int> *this_01;
  PathFollower *this_02;
  CINSPathFollower *this_03;
  CUtlMemory<CINSNextBot::INSBotCoverContainer,int> *extraout_ECX_07;
  CUtlMemory<CINSNextBot::INSBotCoverContainer,int> *extraout_ECX_08;
  CUtlMemory<CINSNextBot::INSBotCoverContainer,int> *this_04;
  INextBot *this_05;
  CINSPlayer *this_06;
  int unaff_EBX;
  int *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  *in_stack_00000004 = unaff_EBX + 0x4514fd /* vtable for CINSNextBot+0x8 */ /* vtable for CINSNextBot+0x8 */ /* vtable for CINSNextBot+0x8 */;
  in_stack_00000004[0x59e] = unaff_EBX + 0x451e89 /* vtable for CINSNextBot+0x994 */ /* vtable for CINSNextBot+0x994 */ /* vtable for CINSNextBot+0x994 */;
  in_stack_00000004[0x831] = unaff_EBX + 0x451ff5 /* vtable for CINSNextBot+0xb00 */ /* vtable for CINSNextBot+0xb00 */ /* vtable for CINSNextBot+0xb00 */;
  piVar1 = (int *)in_stack_00000004[0x86e];
  in_stack_00000004[0x818] = unaff_EBX + 0x451e9d /* vtable for CINSNextBot+0x9a8 */ /* vtable for CINSNextBot+0x9a8 */ /* vtable for CINSNextBot+0x9a8 */;
  this_00 = extraout_ECX;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    in_stack_00000004[0x86e] = 0;
    this_00 = extraout_ECX_00;
  }
  piVar1 = (int *)in_stack_00000004[0x2cd3];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    in_stack_00000004[0x2cd3] = 0;
    this_00 = extraout_ECX_01;
  }
  piVar1 = (int *)in_stack_00000004[0x2cd2];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    in_stack_00000004[0x2cd2] = 0;
    this_00 = extraout_ECX_02;
  }
  piVar1 = (int *)in_stack_00000004[0x2cd4];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    in_stack_00000004[0x2cd4] = 0;
    this_00 = extraout_ECX_03;
  }
  pvVar2 = (void *)in_stack_00000004[0x2cd5];
  if (pvVar2 != (void *)0x0) {
    CINSBotChatter::~CINSBotChatter(this_00);
    operator_delete(pvVar2);
    in_stack_00000004[0x2cd5] = 0;
    this_00 = extraout_ECX_04;
  }
  in_stack_00000004[0x2d1f] = 0;
  iVar3 = in_stack_00000004[0x2d1c];
  if (-1 < in_stack_00000004[0x2d1e]) {
    if (iVar3 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar3);
      in_stack_00000004[0x2d1c] = 0;
      this_00 = extraout_ECX_05;
    }
    in_stack_00000004[0x2d1d] = 0;
    iVar3 = 0;
  }
  in_stack_00000004[0x2d20] = iVar3;
  CUtlMemory<OrderData_t,int>::~CUtlMemory((CUtlMemory<OrderData_t,int> *)this_00);
  in_stack_00000004[0x2d1a] = 0;
  this_01 = (CUtlMemory<InvestigationData_t,int> *)in_stack_00000004[0x2d19];
  iVar3 = in_stack_00000004[0x2d17];
  if (-1 < (int)this_01) {
    if (iVar3 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar3);
      in_stack_00000004[0x2d17] = 0;
      this_01 = extraout_ECX_06;
    }
    in_stack_00000004[0x2d18] = 0;
    iVar3 = 0;
  }
  in_stack_00000004[0x2d1b] = iVar3;
  CUtlMemory<InvestigationData_t,int>::~CUtlMemory(this_01);
  PathFollower::~PathFollower(this_02);
  in_stack_00000004[0x8a6] = unaff_EBX + 0x3df4fd /* vtable for ChasePath+0x8 */ /* vtable for ChasePath+0x8 */ /* vtable for ChasePath+0x8 */;
  CINSPathFollower::~CINSPathFollower(this_03);
  in_stack_00000004[0x860] = 0;
  iVar3 = in_stack_00000004[0x85d];
  this_04 = extraout_ECX_07;
  if (-1 < in_stack_00000004[0x85f]) {
    if (iVar3 != 0) {
      (**(code **)(*(int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */) + 8))
                ((int *)**(undefined4 **)(unaff_EBX + 0x45caad /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */ /* &GCSDK::GetPchTempTextBuffer */),iVar3);
      in_stack_00000004[0x85d] = 0;
      this_04 = extraout_ECX_08;
    }
    in_stack_00000004[0x85e] = 0;
    iVar3 = 0;
  }
  in_stack_00000004[0x861] = iVar3;
  CUtlMemory<CINSNextBot::INSBotCoverContainer,int>::~CUtlMemory(this_04);
  *in_stack_00000004 = unaff_EBX + 0x45229d /* vtable for NextBotPlayer<CINSPlayer>+0x8 */ /* vtable for NextBotPlayer<CINSPlayer>+0x8 */ /* vtable for NextBotPlayer<CINSPlayer>+0x8 */;
  in_stack_00000004[0x59e] = unaff_EBX + 0x452bd1 /* vtable for NextBotPlayer<CINSPlayer>+0x93c */ /* vtable for NextBotPlayer<CINSPlayer>+0x93c */ /* vtable for NextBotPlayer<CINSPlayer>+0x93c */;
  in_stack_00000004[0x831] = unaff_EBX + 0x452d3d /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */ /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */ /* vtable for NextBotPlayer<CINSPlayer>+0xaa8 */;
  in_stack_00000004[0x818] = unaff_EBX + 0x452be5 /* vtable for NextBotPlayer<CINSPlayer>+0x950 */ /* vtable for NextBotPlayer<CINSPlayer>+0x950 */ /* vtable for NextBotPlayer<CINSPlayer>+0x950 */;
  INextBot::~INextBot(this_05);
  CINSPlayer::~CINSPlayer(this_06);
  return;
}



/* ----------------------------------------
 * CINSNextBot::~CINSNextBot
 * Address: 0074a0e0
 * ---------------------------------------- */

/* non-virtual thunk to CINSNextBot::~CINSNextBot() */

void __thiscall CINSNextBot::~CINSNextBot(CINSNextBot *this)

{
  ~CINSNextBot(this);
  return;
}



/* ----------------------------------------
 * CINSNextBot::~CINSNextBot
 * Address: 0074a0f0
 * ---------------------------------------- */

/* CINSNextBot::~CINSNextBot() */

void __thiscall CINSNextBot::~CINSNextBot(CINSNextBot *this)

{
  CINSNextBot *this_00;
  CBaseEntity *this_01;
  void *in_stack_00000004;
  
  __i686_get_pc_thunk_bx();
  ~CINSNextBot(this_00);
  CBaseEntity::operator_delete(this_01,in_stack_00000004);
  return;
}



