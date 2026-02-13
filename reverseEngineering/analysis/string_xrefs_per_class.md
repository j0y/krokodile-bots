# String Cross-References per Bot Class
# Extracted from server_srv.so via PIC GOT-relative lea resolution
# 626 meaningful string references across 66 classes

## CINSBotActionAmbush (3 strings)

  **Action Names:**
    `Ambush` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Moving to capture` ← Update


## CINSBotActionCheckpoint (9 strings)

  **Action Names:**
    `Checkpoint` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Counter-attacking contested point` ← Update
    `Counter-attacking enemy directly` ← Update
    `Defending.` ← Update
    `Escorting nearest Human` ← Update
    `Guarding CP.` ← Update
    `It's a counter-attack and we're not hunting, re-cap` ← Update

  **General Keywords:**
    `Knifing a player` ← Update


## CINSBotActionConquer (7 strings)

  **Action Names:**
    `Conquer` ← GetName

  **Behavior Keywords:**
    `Approach Command` ← Update
    `Attacking nearby threats` ← Update
    `Attacking visible threat` ← Update
    `Escorting ` ← Update
    `I have something to investigate` ← Update
    `My Job is to Patrol` ← Update


## CINSBotActionFirefight (6 strings)

  **Action Names:**
    `Firefight` ← GetName

  **Behavior Keywords:**
    `Attacking enemy controlled point` ← Update
    `Attacking nearby threats` ← Update
    `Defending our CP` ← Update
    `Escorting ` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotActionFlashpoint (4 strings)

  **Action Names:**
    `Flashpoint` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update

  **Debug/Format Strings:**
    `Capturing %i` ← Update
    `Destroying %i` ← Update


## CINSBotActionHunt (6 strings)

  **Action Names:**
    `Hunt` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Escorting ` ← Update
    `I have something to investigate` ← Update
    `Moving to recently lost cache` ← Update
    `My Job is to Patrol` ← Update


## CINSBotActionInfiltrate (5 strings)

  **Action Names:**
    `Infiltrate` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Moving to capture flag.` ← Update

  **Debug/Format Strings:**
    `NAVMESH ERROR: Unable to find any navmesh areas for CP %i, navmesh probably out of date...
` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotActionOccupy (8 strings)

  **Action Names:**
    `Occupy` ← GetName

  **Behavior Keywords:**
    `Attacking enemy directly` ← Update
    `Attacking nearby threats` ← Update
    `Attacking point` ← Update
    `Defending point` ← Update
    `Escorting ` ← Update
    `[CINSBotActionOccupy] No objective areas!
` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotActionOutpost (6 strings)

  **Action Names:**
    `Outpost` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Bot is out of pathing range to point - how did this happen?` ← Update
    `Capturing our target` ← Update
    `Escorting ` ← Update

  **Debug/Format Strings:**
    `Destroying %i` ← Update


## CINSBotActionPush (6 strings)

  **Action Names:**
    `Push` ← GetName

  **Behavior Keywords:**
    `Attacking enemy controlled point` ← Update
    `Attacking nearby threats` ← Update
    `Escorting ` ← Update

  **Debug/Format Strings:**
    `NAVMESH ERROR: Unable to find any navmesh areas for CP %i, navmesh probably out of date...
` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotActionSkirmish (5 strings)

  **Action Names:**
    `Skirmish` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Escorting ` ← Update

  **Debug/Format Strings:**
    `Capturing %i` ← Update
    `Destroying %i` ← Update


## CINSBotActionStrike (4 strings)

  **Action Names:**
    `Strike` ← GetName

  **Behavior Keywords:**
    `Attacking a cache` ← Update
    `Attacking nearby threats` ← Update
    `Defending a cache` ← Update


## CINSBotActionSurvival (4 strings)

  **Action Names:**
    `Survival` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Escorting the nearest human` ← Update
    `Patrolling the world` ← Update


## CINSBotActionTraining (7 strings)

  **Action Names:**
    `Training` ← GetName

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `BOT GOT STUCK, CRITICAL
` ← OnStuck
    `Path::Compute(goal)` ← Update

  **Class/Type Names:**
    `NextBotSpiky` ← Update

  **Debug/Format Strings:**
    `BOT PATH FAILED, CRITICAL
` ← OnMoveToFailure

  **General Keywords:**
    `Watching the player.` ← Update


## CINSBotApproach (5 strings)

  **Action Names:**
    `Approach` ← GetName

  **Behavior Keywords:**
    `Found a threat!` ← Update
    `I'm Stuck` ← OnStuck
    `Received the order to attack` ← OnCommandAttack

  **Debug/Format Strings:**
    `Failed pathing to patrol target.` ← OnMoveToFailure


## CINSBotAttack (15 strings)

  **Action Names:**
    `Attacking` ← GetName

  **Behavior Keywords:**
    ` No Active Combat Target` ← OnStart
    `Aiming at active enemy` ← Update
    `Exiting attack to Reload` ← Update
    `I should not attack this threat` ← Update
    `Idle in attack` ← Update
    `Lost sight of my threat` ← Update
    `Our Active target has been killed!` ← OnOtherKilled
    `Retreating to cover` ← Update
    `Stuck in attack` ← OnStuck

  **Debug/Format Strings:**
    `Aiming at last known position of threat that i cannot see` ← Update
    `INSRules failed to initialize.` ← OnStart
    `Invalid Threat` ← OnStart, Update
    `Unable to determine active weapon.` ← OnStart
    `Unable to determine initial threat.` ← OnStart


## CINSBotAttackAdvance (6 strings)

  **Action Names:**
    `AttackAdvance` ← GetName

  **Behavior Keywords:**
    `Attacking in place in escort` ← OnStart
    `Continue aim at threat` ← Update
    `Lost aim on our threat!` ← Update
    `Should Not Attack This Threat` ← Update

  **General Keywords:**
    `Within good enough range` ← Update


## CINSBotAttackCQC (6 strings)

  **Behavior Keywords:**
    `Crawling From Suppression` ← Update
    `Crouching From Suppression` ← OnStart, Update
    `Sprinting At Target` ← Update
    `Walking At Target` ← OnStart, Update
    `Walking From Suppression` ← Update

  **Class/Type Names:**
    `CINSBotAttackCQC` ← GetName


## CINSBotAttackFromCover (10 strings)

  **Action Names:**
    `AttackFromCover` ← GetName

  **Behavior Keywords:**
    `Aiming towards enemy in fire from cover` ← Update
    `Aiming towards enemy in fire from cover start` ← OnStart
    `Crouching in fire from cover` ← Update
    `Crouching in fire from cover start` ← OnStart
    `I've been crouching here for too long` ← Update
    `Need to Reload` ← Update
    `Should Not Attack This Threat` ← Update
    `Standing to pop out in fire from cover` ← Update
    `we have shitty cover` ← Update


## CINSBotAttackInPlace (7 strings)

  **Action Names:**
    `AttackInPlace` ← GetName

  **Behavior Keywords:**
    `Advancing towards a lost target` ← Update
    `Aiming at a visible threat` ← OnStart
    `No Known Threat` ← Update
    `Should Not Attack This Threat` ← OnStart

  **Debug/Format Strings:**
    `INSRules failed to initialize.` ← OnStart
    `Unable to determine active weapon.` ← OnStart


## CINSBotAttackIntoCover (11 strings)

  **Action Names:**
    `AttackIntoCover` ← GetName

  **Behavior Keywords:**
    `Aiming at a visible threat` ← Update
    `Getting up from prone` ← Update
    `Made it, now reloading!` ← OnMoveToSuccess, Update
    `Non INS Player Enemy?` ← Update
    `Should Not Attack This Threat` ← Update
    `Sprinting to Cover` ← Update
    `Walking to Cover` ← Update
    `sprinting to cover position` ← Update
    `staying prone while attacking our enemy` ← Update

  **General Keywords:**
    `Rethink, i've been still here for more than 2 seconds` ← Update


## CINSBotAttackLMG (5 strings)

  **Behavior Keywords:**
    `CProne from aiming threat` ← OnStart, Update
    `Crouch for stability` ← OnStart, Update
    `Prone From Suppression` ← OnStart, Update
    `Walking At Target` ← OnStart, Update

  **Class/Type Names:**
    `CINSBotAttackLMG` ← GetName


## CINSBotAttackMelee (6 strings)

  **Action Names:**
    `AttackMelee` ← GetName

  **Behavior Keywords:**
    `Jog at Target` ← Update
    `Lost our threat.` ← Update
    `Non INS Player Enemy?` ← Update
    `Sprint at Target` ← Update

  **Debug/Format Strings:**
    `INSRules failed to initialize.` ← OnStart


## CINSBotAttackPistol (6 strings)

  **Behavior Keywords:**
    `Crawling From Suppression` ← Update
    `Crouching From Suppression` ← OnStart, Update
    `Sprinting At Target` ← Update
    `Walking At Target` ← OnStart, Update
    `Walking From Suppression` ← Update

  **Class/Type Names:**
    `CINSBotAttackPistol` ← GetName


## CINSBotAttackRifle (5 strings)

  **Behavior Keywords:**
    `CProne from aiming threat` ← OnStart, Update
    `Crouch for stability` ← OnStart, Update
    `Prone From Suppression` ← OnStart, Update
    `Walking At Target` ← OnStart, Update

  **Class/Type Names:**
    `CINSBotAttackRifle` ← GetName


## CINSBotAttackSniper (5 strings)

  **Behavior Keywords:**
    `CProne from aiming threat` ← OnStart, Update
    `Crouch for stability` ← OnStart, Update
    `Prone From Suppression` ← OnStart, Update
    `Walking At Target` ← OnStart, Update

  **Class/Type Names:**
    `CINSBotAttackSniper` ← GetName


## CINSBotBody (5 strings)

  **Action Names:**
    `Unknown` ← PostureType, INSBotPriority, float, char const*)

  **Debug/Format Strings:**
    ` cooldown:%3.2f, cur: %i , des %i , prio %i , exp: %3.1f` ← UpdatePosture
    `Arousal: %3.2f,%3.2f,%3.2f,%3.2f,` ← UpdateArousal
    `Stance Request: %s , type:%i , prio: %i , len: %3.2f` ← PostureType, INSBotPriority, float, char const*)

  **General Keywords:**
    `Looking at longest distance I can see` ← CheckBadViewTarget


## CINSBotCaptureCP (12 strings)

  **Behavior Keywords:**
    ` no cover` ← Update
    `Attacking nearby threats` ← Update
    `CP Contested, trying to find threat` ← Update
    `Capture Aiming` ← Update
    `Crouching at CP` ← Update
    `I'm Stuck` ← OnStuck
    `Point type is a Cache, blow it up!` ← Update
    `Successfully captured.` ← Update

  **Debug/Format Strings:**
    `Unable to find hiding spots at this control point` ← OnStart, Update
    `Unable to find hiding spots at this control point, falling back to investigate` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update
    `Bounding Update:` ← Update


## CINSBotCaptureFlag (2 strings)

  **Behavior Keywords:**
    `No goal position` ← Update

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotChatter (5 strings)

  **Class/Type Names:**
    `CINSBotChatter::IdleChatter` ← IdleChatter
    `CINSBotChatter::ReportEnemies` ← ReportEnemies
    `CINSBotChatter::ReportEnemies - Had an enemy and wanted to report but he wasn't available?
` ← ReportEnemies
    `CINSBotChatter::Update` ← Update

  **General Keywords:**
    `Teammate saying what we wanted to say!
` ← Update


## CINSBotCombat (34 strings)

  **Action Names:**
    `Combat` ← GetName

  **Behavior Keywords:**
    `Aiming at a new target in Combat` ← Update
    `Attacking a visible/HasLOS threat` ← Update
    `Bailing on Combat, no target` ← Update
    `Combat has timed out` ← Update
    `Combat no longer has a target 
` ← Update
    `Ending Combat in Update , Target ent is not a Known Entity` ← Update
    `First Threat of Combat` ← UpdateInternalInfo
    `I'm Stuck` ← OnStuck
    `Lost sight of my Escort Target` ← OnLostSight
    `New Primary is greater threat` ← UpdateInternalInfo
    `Our threat is gone` ← OnResume
    `Pistol Swap with primary empty for close target who is firing.` ← Update
    `Primary target is no longer known` ← OnResume
    `Pursuing a Lost Enemy` ← Update
    `Pursuing a new target that I just lost` ← Update
    `Reloading In Cover` ← Update
    `Reloading in place because of escort/formation` ← Update
    `Reloading in place because of escorting or formation` ← Update
    `Retreating BC behavior said to` ← Update
    `Retreating From Non-Player Target` ← Update
    `Retreating to Cover BC Scared` ← Update
    `Retreating to Cover to Reload` ← Update
    `Retreating to Reload` ← Update
    `Retreating without Cover BC Scared` ← Update
    `Should Not Attack This Threat` ← OnResume, Update
    `Stale Primary Target` ← UpdateInternalInfo
    `Suppressing a recently lost threat` ← Update
    `primary target and primary threat match, change our combat primary` ← UpdateInternalInfo

  **Debug/Format Strings:**
    `Ending Combat in Update, Unable to retrieve primary target` ← Update
    `INVALID Primary Target: %i` ← Update
    `NO Primary Target: threat %i ` ← Update
    `Primary Target: %s - %i` ← Update

  **General Keywords:**
    `Primary is not firing and at Distance` ← UpdateInternalInfo


## CINSBotDead (2 strings)

  **Action Names:**
    `Dead` ← GetName

  **Debug/Format Strings:**
    `kickid %d
` ← Update


## CINSBotDestroyCache (9 strings)

  **Behavior Keywords:**
    `Attacking nearby threats` ← Update
    `Attacking the cache` ← Update
    `Destroying cache` ← GetName
    `Idling in destroy cache` ← Update
    `Not a weapon cache, radio or misc target?
` ← Update

  **Class/Type Names:**
    `CINSBotDestroyCache::CanIDestroyCache` ← CanIDestroyCache

  **Debug/Format Strings:**
    `NAV MESH: Unable to find a random area around cache %i for a grenade target, navmesh probably out of date...
` ← Update
    `Unable to find hiding spots at this control point, falling back to investigate` ← OnStart

  **General Keywords:**
    `Bot is not on a playteam` ← Update


## CINSBotEscort (14 strings)

  **Action Names:**
    `Escort` ← GetName

  **Behavior Keywords:**
    `Combat time!` ← Update
    `Following escort stance` ← UpdateEscortPostures
    `Looking at whatever Escort Target is paying attention to` ← UpdateEscortLookaround
    `Looking in direction of enemy gun fire` ← OnWeaponFired

  **Debug/Format Strings:**
    `Bot%s Creating first formation for nearest player: %s` ← SetEscortTarget
    `Bot%s Creating formation for nearest player: %s` ← SetEscortTarget
    `Bot%s Joining nearest players formation: %s` ← SetEscortTarget
    `Bot:%s leaving old and joining new Formation` ← SetEscortTarget
    `Path compute failed. Let's go back to Game Mode` ← Update
    `Removing Formation: %i` ← UpdateEscortFormations
    `Unable to get escort Target` ← Update

  **General Keywords:**
    `Looking at where friendly shooter is aiming` ← OnWeaponFired
    `Resetting an immobile stance` ← UpdateEscortPostures


## CINSBotFireRPG (13 strings)

  **Behavior Keywords:**
    `Aiming at RPG target` ← OnStart
    `Firing RPG` ← GetName
    `Idle in fire rpg` ← Update
    `No Target to fire at` ← OnStart
    `No grenade...
` ← OnStart, Update

  **Class/Type Names:**
    `CINSBotFireRPG - Bailing, LoS not clear to our target (%.2f)
` ← Update
    `CINSBotFireRPG - Exiting (%.2f)
` ← Update
    `CINSBotFireRPG - Pressing fire button for %.2f (%.2f)
` ← Update
    `CINSBotFireRPG - RPG not out, switching... (%.2f)
` ← Update
    `CINSBotFireRPG - Still deploying (%.2f)
` ← Update
    `CINSBotFireRPG - Unable to attack (%.2f)
` ← Update
    `CINSBotFireRPG::HasRPGTarget` ← HasRPGTarget

  **Debug/Format Strings:**
    `Error acquiring RPG target` ← Update


## CINSBotFlashed (1 strings)

  **Action Names:**
    `Flashed` ← GetName


## CINSBotFollowCommand (1 strings)

  **Action Names:**
    `FollowCommand` ← GetName


## CINSBotGamemodeMonitor (1 strings)

  **Action Names:**
    `Gamemode` ← GetName


## CINSBotGuardCP (9 strings)

  **Behavior Keywords:**
    `Exiting guard state, enemy entering CP` ← Update
    `Finished guarding spot.` ← Update
    `Guard Aiming` ← Update
    `Guarding CP` ← GetName
    `LoS to an enemy.` ← Update
    `ins_spawnpoint` ← GetRandomHidingSpotForPoint
    `ins_spawnzone` ← GetRandomHidingSpotForPoint

  **Debug/Format Strings:**
    `Failed finding guard spots for CP %i, Team %i
` ← GetRandomHidingSpotForPoint
    `Failed move-to.` ← OnMoveToFailure


## CINSBotGuardDefensive (9 strings)

  **Behavior Keywords:**
    `Crouching at CP` ← Update
    `Defensive Guard` ← GetName
    `Exiting guard state, enemy entering CP` ← Update
    `Guard Aiming` ← Update
    `LoS to an enemy.` ← Update
    `Point we were guarding is inactive, relocating to new point.` ← Update

  **Debug/Format Strings:**
    `Bot hiding in spot %i
` ← GetRandomHidingSpotForPoint
    `Failed finding guard spots for CP %i, Team %i
` ← GetRandomHidingSpotForPoint
    `Failed move-to.` ← OnMoveToFailure


## CINSBotInvestigate (12 strings)

  **Action Names:**
    `Investigating` ← GetName

  **Behavior Keywords:**
    `Arrived at investigation target.` ← OnMoveToSuccess
    `Found a threat!` ← Update
    `Goal position no longer valid?` ← Update
    `I'm Stuck` ← OnStuck
    `Idle in Investigate` ← Update
    `No Place to investigate ` ← OnStart
    `No move investigations to worry about` ← Update

  **Debug/Format Strings:**
    `Bot can't do anything` ← Update
    `Failed pathing to investigation target.` ← OnMoveToFailure
    `Invalid investigation area?` ← OnResume, Update
    `Invalid investigation?` ← OnStart


## CINSBotInvestigateGunshot (6 strings)

  **Behavior Keywords:**
    `Arrived at investigation target.` ← OnMoveToSuccess
    `Goal position no longer valid?` ← Update
    `Gunshot Investigate` ← GetName
    `Leaving investigation, we changed targets.` ← Update
    `Not investigating, we have a threat.
` ← Update

  **Debug/Format Strings:**
    `Failed pathing to investigation target.` ← OnMoveToFailure


## CINSBotInvestigationMonitor (3 strings)

  **Action Names:**
    `Investigations` ← GetName

  **Behavior Keywords:**
    `Investigation state could not locate objective
` ← OnStart

  **General Keywords:**
    `Adding new investigation area for OnHeardFootsteps
` ← OnHeardFootsteps, OnSeeSomethingSuspicious


## CINSBotLocomotion (10 strings)

  **Behavior Keywords:**
    `PlayerLocomotion::Approach: No INextBotPlayerInput
 ` ← Approach

  **Debug/Format Strings:**
    `%3.1f , %3.1f 
` ← UpdateMovement
    `Bot %i - ADD Movement Request: %3.1f , %3.1f 
` ← AddMovementRequest
    `Bot %i - Applying Movement Request: %3.1f , %3.1f 
` ← ApplyMovementRequest
    `Bot %i - Completed Movement Request: %3.1f , %3.1f 
` ← OnCompletedMovementRequest
    `Bot %i - Failed Movement Request: %3.1f , %3.1f 
` ← OnFailedMovementRequest
    `Bot %i - Movement Request removed: ` ← UpdateMovement
    `Count:%i , Cur:  ` ← UpdateMovement
    `Failed - ` ← UpdateMovement

  **General Keywords:**
    `AVOID AREA
` ← AreAdjacentAreasOccupied


## CINSBotMainAction (8 strings)

  **Action Names:**
    `Dead` ← Update
    `Flashed` ← Update

  **Behavior Keywords:**
    `commiting suicide and respawning a stuck/Idle bot
` ← Update
    `prop_door*` ← OnContact

  **Class/Type Names:**
    `Behavior` ← GetName

  **Debug/Format Strings:**
    `   path_goal ( "%3.2f %3.2f %3.2f" )
` ← OnStuck
    `   path_goal ( "NULL" )
` ← OnStuck
    `"%s<%i><%s><%i>" stuck (position "%3.2f %3.2f %3.2f") (duration "%3.2f") ` ← OnStuck


## CINSBotPatrol (11 strings)

  **Action Names:**
    `Patrol` ← GetName

  **Behavior Keywords:**
    `Found a threat!` ← Update
    `Goal position no longer valid?` ← Update
    `I have things to investigate!` ← Update
    `I'm Stuck` ← OnStuck
    `Nothing to patrol` ← OnResume
    `Patrol expiry time reached.` ← Update
    `Received the order to attack` ← OnCommandAttack
    `We are in counterattack, time to go to the CP` ← Update

  **Debug/Format Strings:**
    `Failed pathing to patrol target.` ← OnMoveToFailure
    `Unable to find a valid patrol area.` ← OnStart


## CINSBotPursue (7 strings)

  **Behavior Keywords:**
    `Arrived at investigation target.` ← OnMoveToSuccess
    `I saw an enemy, attack!` ← Update
    `I should not be pursuing while escorting` ← OnStart
    `My Primary Target has changed` ← Update
    `No Known Threats` ← OnStart, Update
    `Pursue Threat` ← GetName

  **Debug/Format Strings:**
    `Failed pathing to investigation target.` ← OnMoveToFailure


## CINSBotReload (9 strings)

  **Action Names:**
    `Reloading` ← GetName

  **Behavior Keywords:**
    ` Crouching while reloading ` ← Update
    `Crouching to reload` ← OnStart
    `Finished reloading!` ← Update
    `Idle in reload` ← Update
    `No more ammo for this weapon` ← OnStart
    `No weapon.` ← Update
    `Prone to visible enemy while reloading` ← Update
    `Proning to reload` ← OnStart


## CINSBotRetreat (11 strings)

  **Behavior Keywords:**
    `CINSRetreatPath::Update` ← OnStart
    `Doing reload after OnMoveToFailure` ← OnMoveToFailure, OnMoveToSuccess, OnStuck
    `Idle in retreat` ← Update
    `Retreat timer elapsed, changing to reload` ← Update
    `Retreat timer elapsed.` ← Update
    `Retreating!` ← GetName
    `Sustaining retreat.` ← OnInjured
    `We couldn't get to target's position!` ← OnMoveToFailure

  **Class/Type Names:**
    `NextBot` ← OnStart

  **Debug/Format Strings:**
    `%3.2f: bot(#%d) Chase path threat changed (from %p to %p).
` ← OnStart
    `Unable to find a retreat area` ← Update


## CINSBotRetreatToCover (16 strings)

  **Behavior Keywords:**
    `Bailing on retreat to cover, unknown threat entity` ← OnStart
    `Doing given action now that I'm in cover` ← Update
    `Doing reload after OnMoveToFailure` ← OnMoveToFailure
    `Doing reload after OnMoveToSuccess` ← OnMoveToSuccess
    `Idle in retreat to cover` ← Update
    `Im Stuck, help!` ← OnStuck
    `In Cover` ← Update
    `Looking at threat while retreating to cover` ← Update
    `Retreat timer elapsed, changing to reload` ← Update
    `Retreat timer elapsed.` ← Update
    `Retreating to cover` ← GetName
    `Sustaining retreat.` ← OnInjured
    `We couldn't get to target's position!` ← OnMoveToFailure
    `We got to target's position!` ← OnMoveToSuccess
    `looking at our cover position while retreating` ← Update

  **Debug/Format Strings:**
    `Bailing on retreat to cover, no pos or threat is invalid` ← OnStart


## CINSBotRetreatToHidingSpot (11 strings)

  **Behavior Keywords:**
    `Doing reload after OnMoveToFailure` ← OnMoveToFailure, OnMoveToSuccess, OnStuck
    `Got to cover, couldn't find another.
` ← Update
    `No longer need to retreat` ← Update
    `Retreat timer elapsed.` ← Update
    `Retreating to hiding spot` ← GetName
    `Sustaining retreat from fire.` ← OnInjured
    `Timer elapsed, changing to reload action` ← Update
    `We couldn't get a path to our target after getting stuck` ← OnStuck
    `We couldn't get to target's position!` ← OnMoveToFailure

  **Debug/Format Strings:**
    `Failed finding another cover, doing reload.` ← Update
    `Failed finding cover nearby...
` ← OnStart


## CINSBotStuck (5 strings)

  **Action Names:**
    `Stuck` ← GetName

  **Behavior Keywords:**
    ` moved from our stuck position` ← Update
    `Bot stuck on non-existant nav mesh` ← OnStart
    `Successful move in stuck ` ← OnMoveToSuccess
    `Successful unstuck ` ← OnUnStuck


## CINSBotSuppressTarget (7 strings)

  **Action Names:**
    `Suppressing` ← GetName

  **Behavior Keywords:**
    `Aiming at suppression area` ← Update
    `Idle in suppress` ← Update
    `Our weapon is out of ammo.` ← Update
    `Spotted a threat while suppressing.` ← Update
    `We're done suppressing.` ← Update

  **Debug/Format Strings:**
    `Failed to init weapon entity` ← Update


## CINSBotSweepArea (4 strings)

  **Behavior Keywords:**
    `Looking at random visible areas` ← Update

  **General Keywords:**
    `No areas to sweep.` ← Update
    `No last known area when sweeping?` ← Update
    `Sweeping area` ← GetName


## CINSBotTacticalMonitor (15 strings)

  **Action Names:**
    `Tactics` ← GetName

  **Behavior Keywords:**
    `Crouching in response to Clear Silhouette` ← CheckPosture
    `Crouching in response to Dark Silhouette` ← CheckPosture
    `Crouching in response to Fuzzy Silhouette` ← CheckPosture
    `Crouching in response to dark silhouette` ← CheckPosture
    `Firing an RPG!` ← Update
    `Going Prone in response to dark silhouette` ← CheckPosture
    `Looking at Weapon Fire` ← OnWeaponFired
    `Looking at attacker who just injured me` ← OnInjured
    `Opportunistic reload in-place` ← Update
    `Prone in response to Clear Silhouette` ← CheckPosture
    `Prone in response to Dark Silhouette` ← CheckPosture
    `Prone in response to Fuzzy Silhouette` ← CheckPosture
    `Throwing a grenade!` ← Update
    `We're in fire, get out of here!` ← OnInjured


## CINSBotThrowGrenade (10 strings)

  **Action Names:**
    `Timeout` ← Update

  **Behavior Keywords:**
    `Aiming at grenade throw target` ← OnStart
    `Idle in throw grenade` ← Update
    `No grenade...
` ← OnStart, Update
    `No grenade? This is bad.` ← Update
    `Throwing Grenade` ← GetName

  **Class/Type Names:**
    `CINSBotThrowGrenade::AimVectorForGrenade` ← AimForGrenadeToss
    `CINSBotThrowGrenade::CanThrowGrenade` ← CanIThrowGrenade
    `CINSBotThrowGrenade::TraceTrajectory` ← TraceTrajectory

  **Debug/Format Strings:**
    `Error aiming grenade.` ← Update


## CINSBotVision (12 strings)

  **Class/Type Names:**
    `CINSBotVision::CollectPotentiallyVisibleEntities` ← CollectPotentiallyVisibleEntities
    `CINSBotVision::IsAbleToSee` ← FieldOfViewCheckType, Vector*) const
    `CINSBotVision::IsAbleToSee - Fog` ← FieldOfViewCheckType, Vector*) const
    `CINSBotVision::IsAbleToSee - Range/Fog/FOV` ← FieldOfViewCheckType, Vector*) const
    `CINSBotVision::IsLineOfFireClear - Smoke Check` ← IsLineOfFireClear
    `CINSBotVision::IsLineOfSightClearToEntity` ← IsLineOfSightClearToEntity
    `CINSBotVision::IsLineOfSightClearToEntity - Smoke Check` ← IsLineOfSightClear
    `CINSBotVision::UpdatePotentiallyVisibleNPCVector` ← UpdatePotentiallyVisibleNPCVector
    `NextBotExpensive` ← FieldOfViewCheckType, Vector*) const

  **Debug/Format Strings:**
    `Assessment: bot:%s , target: %s , score: %3.2f,dtm: %3.2f,dtd: %3.2f,looking: %3.2f` ← GetAssessmentScore
    `threat chosen:%s - %i, score: %3.2f , count: %i` ← Update

  **General Keywords:**
    `isAiming,` ← GetAssessmentScore


## CINSNavArea (15 strings)

  **Class/Type Names:**
    `CINSNavArea::AddPotentiallyVisibleActor` ← AddPotentiallyVisibleActor
    `CINSNavArea::CleanupPathingBots` ← CleanupPathingBots
    `CINSNavArea::ClearAllPotentiallyVisibleActors` ← OnRoundRestart, OnServerActivate
    `CINSNavArea::GetCombatIntensity` ← GetCombatIntensity
    `CINSNavArea::GetDeathIntensity` ← GetDeathIntensity
    `CINSNavArea::GetNearbyDeathIntensity` ← GetNearbyDeathIntensity
    `CINSNavArea::OnDeath - Invalid team (%i)
` ← OnDeath
    `CINSNavArea::OnRoundRestart` ← OnRoundRestart
    `CINSNavArea::ResetHidingSpotScores` ← ResetHidingSpotScores
    `CINSNavArea::UpdateCover` ← UpdateCover

  **Debug/Format Strings:**
    ` C1:%3.1f , C2:%3.1f` ← Draw
    ` S1:%3.1f , S2:%3.1f` ← Draw
    `%i:%3.2f ` ← Draw
    `Can't read INS-specific attributes
` ← Load

  **General Keywords:**
    `Unknown NavArea sub-version number
` ← Load


## CINSNavMesh (22 strings)

  **Action Names:**
    `CalculateDistancesToControlpoint` ← CalculateDistancesToControlPoint
    `SpawnSystem` ← CalculateDistancesToControlPoint

  **Behavior Keywords:**
    `** Walked off of the CNavMesh::m_grid in ForAllAreasOverlappingExtent()
` ← ComputeBlockedAreas
    `func_door*` ← ComputeBlockedAreas

  **Class/Type Names:**
    `CINSNavMesh::CleanupPathingBots` ← CleanupPathingBots
    `CINSNavMesh::CollectControlPointAreas` ← CollectControlPointAreas
    `CINSNavMesh::CollectControlPointAreas - Surrounding areas` ← CollectControlPointAreas
    `CINSNavMesh::ComputeBlockedAreas` ← ComputeBlockedAreas
    `CINSNavMesh::DecorateMesh` ← DecorateMesh
    `CINSNavMesh::OnBlockedAreasChanged` ← OnBlockedAreasChanged
    `CINSNavMesh::OnRoundRestart` ← OnRoundRestart
    `CINSNavMesh::RecomputeInternalData` ← RecomputeInternalData
    `CINSNavMesh::RemoveAllMeshDecoration` ← RemoveAllMeshDecoration
    `CINSNavMesh::ResetMeshAttributes` ← ResetMeshAttributes
    `CINSNavMesh::UpdateHidingSpots` ← UpdateHidingSpots

  **Debug/Format Strings:**
    `- Collecting areas for objective %i
` ← CollectControlPointAreas
    `Failed finding CP area for %i!
` ← CollectControlPointAreas
    `Failed finding hiding spots for CP %i
` ← GetControlPointHidingSpot
    `TEAM_ONE DEATH: %.2f` ← UpdateDebugDisplay
    `TEAM_TWO DEATH: %.2f` ← UpdateDebugDisplay
    `maps\%s.nav` ← NavMeshExists

  **General Keywords:**
    `filter_activator_tfteam` ← ComputeBlockedAreas


## CINSNextBot (33 strings)

  **Behavior Keywords:**
    `Aiming at a visible threat` ← UpdateLookingAroundForEnemies
    `ChasePath::Update` ← UpdateChasePath
    `GetFireBoxBloat - Unknown difficulty?
` ← GetAimToleranceBloat
    `Looking in spawn direction` ← Spawn
    `Turning around to find threat out of our FOV` ← UpdateLookingAroundForEnemies
    `cl_crouch_hold` ← Spawn
    `cl_grenade_auto_switch` ← Spawn
    `cl_ironsight_hold` ← Spawn
    `cl_sprint_hold` ← Spawn
    `cl_walk_hold` ← Spawn
    `weapon_at4` ← HasExplosive
    `weapon_c4_clicker` ← HasExplosive
    `weapon_c4_ied` ← HasExplosive
    `weapon_m67` ← HasExplosive
    `weapon_rgd5` ← HasExplosive
    `weapon_rpg7` ← HasExplosive

  **Class/Type Names:**
    `CINSNextBot::ComputePartPositions` ← ComputePartPositions
    `CINSNextBot::GetForwardAttackCover` ← GetAttackCover
    `CINSNextBot::GetForwardHidingCover` ← GetHidingCover
    `CINSNextBot::GetPartPosition` ← VisiblePartType) const
    `CINSNextBot::GetTravelDistance` ← GetTravelDistance
    `CINSNextBot::IsEnemyPartVisible` ← GetTargetPosition
    `CINSNextBot::Nearby Players` ← Update
    `CINSNextBot::OnWeaponFired` ← OnWeaponFired
    `CINSNextBot::UpdateCover` ← UpdateCover
    `NextBot` ← UpdateChasePath

  **Debug/Format Strings:**
    `!! NAV MESH ERROR !!
Bot failed to calculate path. Going to Guard state.
` ← IsLost
    `Chase path failed generating, suiciding.
` ← ComputeChasePath, ComputePathFollower
    `Failed to determine suppression frac for AI.
` ← IsSuppressed
    `Making %s defensive.
` ← Spawn
    `Unable to add NextBot investigation target, navmesh probably out of date...
` ← AddInvestigation

  **General Keywords:**
    `TODO: UpdateLookingAroundForIncomingPlayers
` ← UpdateLookingAroundForIncomingPlayers
    `ins_player_nbot` ← AllocatePlayerEntity


## CINSNextBotCPDistancePathCost (2 strings)

  **Class/Type Names:**
    `CINSNextBotCPDistancePathCost::operator()` ← operator
    `NextBot` ← operator


## CINSNextBotChasePathCost (2 strings)

  **Class/Type Names:**
    `CINSNextBotChasePathCost::operator()` ← operator
    `NextBot` ← operator


## CINSNextBotManager (16 strings)

  **Behavior Keywords:**
    `FLASH` ← UpdateGrenadeTargets
    `SMOKE` ← UpdateGrenadeTargets

  **Class/Type Names:**
    `CINSNextBotManager::GenerateCPGrenadeTargets` ← GenerateCPGrenadeTargets

  **Debug/Format Strings:**
    `%3.2f: OnWeaponFired( %s, %s )
` ← OnWeaponFired
    `Failed loading navmesh!
` ← BotAddCommand
    `Failed to load active Hunt objective
` ← GetDesiredHuntTypeObjective
    `Failed to load active Push / Checkpoint objective
` ← GetDesiredPushTypeObjective
    `Forcing a load, This is bad and will most likely cause a hitch. This should not happen in regular play.
` ← BotAddCommand
    `Generating grenade targets for CP %i
` ← GenerateCPGrenadeTargets
    `Grenade Target
Clear: %s
Used: %s
Types: %s %s %s %s` ← UpdateGrenadeTargets
    `INSNextBot - Unable to add bots, no navmesh exists.
` ← BotAddCommand
    `NULL grenade thrown?
` ← OnGrenadeThrown
    `Tried adding grenade target for invalid team %i
` ← AddGrenadeTarget
    `Tried to call GenerateCPGrenadeTargets with an invalid control point index (%d) - team %d
` ← GenerateCPGrenadeTargets
    `grenade == NULL
` ← OnGrenadeDetonate

  **General Keywords:**
    `team` ← FireGameEvent


## CINSNextBotPathCost (2 strings)

  **Class/Type Names:**
    `CINSNextBotPathCost::operator()` ← operator
    `NextBot` ← operator


## CINSPathFollower (24 strings)

  **Behavior Keywords:**
    `Fell off path` ← Update
    `INSPathFollower` ← ComputePath
    `Path::Compute(goal)` ← ComputePath

  **Class/Type Names:**
    `CINSPathFollower: OnMoveToFailure( FAIL_FELL_OFF )
` ← Update
    `CINSPathFollower: OnMoveToFailure( FAIL_STUCK ) because forward and left are ZERO
` ← Update
    `CINSPathFollower: OnMoveToSuccess
` ← CheckProgress
    `CINSPathFollower::Avoid` ← Avoid
    `CINSPathFollower::Climbing` ← Segment const*, Vector const&, Vector const&, float)
    `CINSPathFollower::ComputePath` ← ComputePath
    `CINSPathFollower::GapJumping` ← Segment const*, Vector const&, Vector const&, float)
    `CINSPathFollower::IsAtGoal` ← IsAtGoal
    `CINSPathFollower::JumpOverGaps` ← Segment const*, Vector const&, Vector const&, float)
    `CINSPathFollower::Update` ← Update
    `CINSPathFollower::Update - Climb check` ← Update
    `CINSPathFollower::Update - Fall Check` ← Update
    `CINSPathFollower::Update - Path Aim Ahead` ← Update
    `CINSPathFollower::Update - Progress` ← Update
    `CINSPathFollower::WaitToPass` ← WaitToPass
    `NextBot` ← IsAtGoal, Segment const*, Vector const&, Vector const&, float)
    `NextBotExpensive` ← Avoid, WaitToPass
    `NextBotSpiky` ← ComputePath, Update

  **Debug/Format Strings:**
    `%3.2f: %s ON STAIRS
` ← Segment const*, Vector const&, Vector const&, float)
    `%3.2f: GAP JUMP
` ← Segment const*, Vector const&, Vector const&, float)
    `%3.3f Bot:%i Compute %i segments in %2.2f 	 res:%i 	 vec dist 	 %3.2f 	 path dist 	 %3.2f
` ← ComputePath


## NextBotManager (5 strings)

  **Class/Type Names:**
    `NextBot tickrate changed from %d (%.3fms) to %d (%.3fms)
` ← Update

  **Debug/Format Strings:**
    `%3.2f: OnSpokeConcept( %s, %s )
` ← CRR_Response*)
    `%3.2f: OnWeaponFired( %s, %s )
` ← OnWeaponFired
    `Frame %8d/tick %8d: %3d run of %3d, %3d sliders, %3d blocked slides, scheduled %3d for next tick, %3d intentional sli...` ← Update
    `Frame %8d/tick %8d: frame out of budget (%.2fms > %.2fms)
` ← ShouldUpdate


