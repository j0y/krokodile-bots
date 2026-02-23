/**
 * sdkcalls.inc — SDKCall handle creation for SmartBots
 *
 * Creates handles for all SDKCalls used by the plugin:
 * - Signature-based: Approach, GetNearestNavArea, IsPotentiallyVisible, IsBlocked, IsCounterAttack
 * - VTable-based: GetLocomotionInterface, GetBodyInterface, GetVisionInterface,
 *                 AimHeadTowards, IsAbleToSee, GetPrimaryKnownThreat, SpeakConceptIfAllowed
 *
 * Depends on smartbots.txt gamedata.
 */

#if defined _smartbots_sdkcalls_included
#endinput
#endif
#define _smartbots_sdkcalls_included

// ---------------------------------------------------------------------------
// SDKCall handles
// ---------------------------------------------------------------------------

// VTable calls on bot entity (SDKCall_Entity)
static Handle g_hSDK_GetLocoInterface;
static Handle g_hSDK_GetBodyInterface;
static Handle g_hSDK_GetVisionInterface;
static Handle g_hSDK_SpeakConcept;

// Signature-based calls (SDKCall_Raw)
static Handle g_hSDK_Approach;
static Handle g_hSDK_GetNearestNavArea;
static Handle g_hSDK_IsPotentiallyVisible;
static Handle g_hSDK_NavIsBlocked;
static Handle g_hSDK_IsCounterAttack;

// VTable calls on raw interface addresses (SDKCall_Raw)
static Handle g_hSDK_AimHeadTowards;
static Handle g_hSDK_IsAbleToSee;
static Handle g_hSDK_GetPrimaryKnownThreat;

// ---------------------------------------------------------------------------
// Global address pointers (address of the global, NOT the object)
// ---------------------------------------------------------------------------

static Address g_ppTheNavMesh;    // &TheNavMesh   (dereference to get CNavMesh*)
static Address g_ppGameRules;     // &g_pGameRules (dereference to get CINSRules*)

// ===========================================================================
// Initialization
// ===========================================================================

/**
 * Create all SDKCall handles and resolve global addresses from gamedata.
 * Call from OnPluginStart after LoadGameConfigFile.
 *
 * @param hGamedata    Handle from LoadGameConfigFile("smartbots")
 * @return             true on success
 */
stock bool SmartBots_SDKCalls_Init(Handle hGamedata)
{
	// --- Resolve global addresses (pointer-to-pointer) ---

	g_ppTheNavMesh = GameConfGetAddress(hGamedata, "TheNavMesh");
	if (g_ppTheNavMesh == Address_Null)
	{
		LogError("[SmartBots] SDKCalls: failed to resolve TheNavMesh address");
		return false;
	}

	g_ppGameRules = GameConfGetAddress(hGamedata, "g_pGameRules");
	if (g_ppGameRules == Address_Null)
	{
		LogError("[SmartBots] SDKCalls: failed to resolve g_pGameRules address");
		return false;
	}

	// --- VTable-based SDKCalls on bot entity ---

	// CINSNextBot::GetLocomotionInterface() const → Address
	int offGetLoco = GameConfGetOffset(hGamedata, "GetLocomotionInterface");
	if (offGetLoco < 0) { LogError("[SmartBots] SDKCalls: missing GetLocomotionInterface offset"); return false; }

	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetVirtual(offGetLoco);
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_hSDK_GetLocoInterface = EndPrepSDKCall();
	if (g_hSDK_GetLocoInterface == null) { LogError("[SmartBots] SDKCalls: GetLocoInterface prep failed"); return false; }

	// CINSNextBot::GetBodyInterface() const → Address
	int offGetBody = GameConfGetOffset(hGamedata, "GetBodyInterface");
	if (offGetBody < 0) { LogError("[SmartBots] SDKCalls: missing GetBodyInterface offset"); return false; }

	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetVirtual(offGetBody);
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_hSDK_GetBodyInterface = EndPrepSDKCall();
	if (g_hSDK_GetBodyInterface == null) { LogError("[SmartBots] SDKCalls: GetBodyInterface prep failed"); return false; }

	// CINSNextBot::GetVisionInterface() const → Address
	int offGetVision = GameConfGetOffset(hGamedata, "GetVisionInterface");
	if (offGetVision < 0) { LogError("[SmartBots] SDKCalls: missing GetVisionInterface offset"); return false; }

	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetVirtual(offGetVision);
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_hSDK_GetVisionInterface = EndPrepSDKCall();
	if (g_hSDK_GetVisionInterface == null) { LogError("[SmartBots] SDKCalls: GetVisionInterface prep failed"); return false; }

	// CBaseEntity::SpeakConceptIfAllowed(int, const char*, char*, size_t, void*) → bool
	int offSpeak = GameConfGetOffset(hGamedata, "SpeakConceptIfAllowed");
	if (offSpeak < 0) { LogError("[SmartBots] SDKCalls: missing SpeakConceptIfAllowed offset"); return false; }

	StartPrepSDKCall(SDKCall_Entity);
	PrepSDKCall_SetVirtual(offSpeak);
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // concept id
	PrepSDKCall_AddParameter(SDKType_String, SDKPass_Pointer);      // modifiers
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // response buf (NULL)
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // response size (0)
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // filter (NULL)
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_SpeakConcept = EndPrepSDKCall();
	if (g_hSDK_SpeakConcept == null) { LogError("[SmartBots] SDKCalls: SpeakConcept prep failed"); return false; }

	// --- Signature-based SDKCalls ---

	// CINSBotLocomotion::Approach(const Vector &goal, float weight) — thiscall on loco address
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CINSBotLocomotion::Approach"))
	{ LogError("[SmartBots] SDKCalls: Approach signature not found"); return false; }
	PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);
	PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);
	g_hSDK_Approach = EndPrepSDKCall();
	if (g_hSDK_Approach == null) { LogError("[SmartBots] SDKCalls: Approach prep failed"); return false; }

	// CNavMesh::GetNearestNavArea(const Vector&, bool, float, bool, bool, int) → CNavArea*
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavMesh::GetNearestNavArea"))
	{ LogError("[SmartBots] SDKCalls: GetNearestNavArea signature not found"); return false; }
	PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // anyZ
	PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);         // maxDist
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // checkLOS
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // checkGround
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // team
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain);
	g_hSDK_GetNearestNavArea = EndPrepSDKCall();
	if (g_hSDK_GetNearestNavArea == null) { LogError("[SmartBots] SDKCalls: GetNearestNavArea prep failed"); return false; }

	// CNavArea::IsPotentiallyVisible(const CNavArea*) const → bool
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavArea::IsPotentiallyVisible"))
	{ LogError("[SmartBots] SDKCalls: IsPotentiallyVisible signature not found"); return false; }
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // CNavArea*
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_IsPotentiallyVisible = EndPrepSDKCall();
	if (g_hSDK_IsPotentiallyVisible == null) { LogError("[SmartBots] SDKCalls: IsPotentiallyVisible prep failed"); return false; }

	// CNavArea::IsBlocked(int teamID, bool ignoreBlockers) const → bool
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CNavArea::IsBlocked"))
	{ LogError("[SmartBots] SDKCalls: IsBlocked signature not found"); return false; }
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // teamID
	PrepSDKCall_AddParameter(SDKType_Bool, SDKPass_Plain);          // ignoreBlockers
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_NavIsBlocked = EndPrepSDKCall();
	if (g_hSDK_NavIsBlocked == null) { LogError("[SmartBots] SDKCalls: IsBlocked prep failed"); return false; }

	// CINSRules::IsCounterAttack() const → bool
	StartPrepSDKCall(SDKCall_Raw);
	if (!PrepSDKCall_SetFromConf(hGamedata, SDKConf_Signature, "CINSRules::IsCounterAttack"))
	{ LogError("[SmartBots] SDKCalls: IsCounterAttack signature not found"); return false; }
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_IsCounterAttack = EndPrepSDKCall();
	if (g_hSDK_IsCounterAttack == null) { LogError("[SmartBots] SDKCalls: IsCounterAttack prep failed"); return false; }

	// --- VTable-based SDKCalls on raw interface addresses ---

	// IBody::AimHeadTowards(const Vector&, int priority, float duration, INextBotReply*, const char*)
	int offAim = GameConfGetOffset(hGamedata, "IBody::AimHeadTowards");
	if (offAim < 0) { LogError("[SmartBots] SDKCalls: missing AimHeadTowards offset"); return false; }

	StartPrepSDKCall(SDKCall_Raw);
	PrepSDKCall_SetVirtual(offAim);
	PrepSDKCall_AddParameter(SDKType_Vector, SDKPass_ByRef);        // target pos
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // priority
	PrepSDKCall_AddParameter(SDKType_Float, SDKPass_Plain);         // duration
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // reply (NULL)
	PrepSDKCall_AddParameter(SDKType_String, SDKPass_Pointer);      // reason string
	g_hSDK_AimHeadTowards = EndPrepSDKCall();
	if (g_hSDK_AimHeadTowards == null) { LogError("[SmartBots] SDKCalls: AimHeadTowards prep failed"); return false; }

	// IVision::IsAbleToSee(CBaseEntity*, int checkFOV, Vector* visibleSpot) → bool
	int offSee = GameConfGetOffset(hGamedata, "IVision::IsAbleToSee_Entity");
	if (offSee < 0) { LogError("[SmartBots] SDKCalls: missing IsAbleToSee_Entity offset"); return false; }

	StartPrepSDKCall(SDKCall_Raw);
	PrepSDKCall_SetVirtual(offSee);
	PrepSDKCall_AddParameter(SDKType_CBaseEntity, SDKPass_Pointer); // target entity
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // checkFOV (0=USE_FOV)
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // visibleSpot (NULL)
	PrepSDKCall_SetReturnInfo(SDKType_Bool, SDKPass_Plain);
	g_hSDK_IsAbleToSee = EndPrepSDKCall();
	if (g_hSDK_IsAbleToSee == null) { LogError("[SmartBots] SDKCalls: IsAbleToSee prep failed"); return false; }

	// IVision::GetPrimaryKnownThreat(int onlyVisible) → CKnownEntity*
	int offThreat = GameConfGetOffset(hGamedata, "IVision::GetPrimaryKnownThreat");
	if (offThreat < 0) { LogError("[SmartBots] SDKCalls: missing GetPrimaryKnownThreat offset"); return false; }

	StartPrepSDKCall(SDKCall_Raw);
	PrepSDKCall_SetVirtual(offThreat);
	PrepSDKCall_AddParameter(SDKType_PlainOldData, SDKPass_Plain);  // onlyVisible
	PrepSDKCall_SetReturnInfo(SDKType_PlainOldData, SDKPass_Plain); // CKnownEntity* or NULL
	g_hSDK_GetPrimaryKnownThreat = EndPrepSDKCall();
	if (g_hSDK_GetPrimaryKnownThreat == null) { LogError("[SmartBots] SDKCalls: GetPrimaryKnownThreat prep failed"); return false; }

	PrintToServer("[SmartBots] SDKCalls: init OK (NavMesh=%x, GameRules=%x)",
		g_ppTheNavMesh, g_ppGameRules);
	return true;
}

// ===========================================================================
// Convenience wrappers
// ===========================================================================

/**
 * Dereference TheNavMesh global → CNavMesh*.
 * Returns Address_Null if not yet initialized (before map load).
 */
stock Address GetTheNavMesh()
{
	if (g_ppTheNavMesh == Address_Null)
		return Address_Null;
	return view_as<Address>(LoadFromAddress(g_ppTheNavMesh, NumberType_Int32));
}

/**
 * Dereference g_pGameRules global → CINSRules*.
 * Re-dereferenced each call since GameRules changes per map.
 */
stock Address GetGameRules()
{
	if (g_ppGameRules == Address_Null)
		return Address_Null;
	return view_as<Address>(LoadFromAddress(g_ppGameRules, NumberType_Int32));
}

stock Address SDKCall_GetLocoInterface(int client)
{
	return view_as<Address>(SDKCall(g_hSDK_GetLocoInterface, client));
}

stock Address SDKCall_GetBodyInterface(int client)
{
	return view_as<Address>(SDKCall(g_hSDK_GetBodyInterface, client));
}

stock Address SDKCall_GetVisionInterface(int client)
{
	return view_as<Address>(SDKCall(g_hSDK_GetVisionInterface, client));
}

stock void SDKCall_Approach(Address locoInterface, float goal[3], float weight)
{
	SDKCall(g_hSDK_Approach, locoInterface, goal, weight);
}

stock void SDKCall_AimHeadTowards(Address bodyInterface, float target[3], int priority, float duration)
{
	SDKCall(g_hSDK_AimHeadTowards, bodyInterface, target, priority, duration, 0, "SmartBots");
}

stock bool SDKCall_IsAbleToSee(Address visionInterface, int targetEntity)
{
	return SDKCall(g_hSDK_IsAbleToSee, visionInterface, targetEntity, 0, 0);
}

stock Address SDKCall_GetPrimaryKnownThreat(Address visionInterface, bool onlyVisible)
{
	return view_as<Address>(SDKCall(g_hSDK_GetPrimaryKnownThreat, visionInterface, onlyVisible ? 1 : 0));
}

stock Address SDKCall_GetNearestNavArea(float pos[3])
{
	Address navMesh = GetTheNavMesh();
	if (navMesh == Address_Null)
		return Address_Null;
	return view_as<Address>(SDKCall(g_hSDK_GetNearestNavArea, navMesh, pos, false, 10000.0, true, true, 0));
}

stock bool SDKCall_IsPotentiallyVisible(Address fromArea, Address toArea)
{
	return SDKCall(g_hSDK_IsPotentiallyVisible, fromArea, toArea);
}

stock bool SDKCall_IsAreaBlocked(Address area, int teamID)
{
	return SDKCall(g_hSDK_NavIsBlocked, area, teamID, false);
}

stock bool SDKCall_IsCounterAttack()
{
	Address rules = GetGameRules();
	if (rules == Address_Null)
		return false;
	return SDKCall(g_hSDK_IsCounterAttack, rules);
}

stock bool SDKCall_SpeakConcept(int client, int conceptId)
{
	return SDKCall(g_hSDK_SpeakConcept, client, conceptId, "", 0, 0, 0);
}

// ===========================================================================
// Compatibility aliases (used by flanking.inc / tactics.inc)
// ===========================================================================

// Flanking.inc references the raw handle for IsPotentiallyVisible SDKCalls
// and a flag indicating whether vis data is available.
static bool g_bHasVisData = true;
#define g_hIsPotentiallyVisible g_hSDK_IsPotentiallyVisible

/**
 * Generic GetNearestNavArea with configurable params.
 * Used by flanking.inc and tactics.inc.
 */
stock Address GetNearestNavArea(float pos[3], bool anyZ = false, float maxDist = 10000.0)
{
	Address navMesh = GetTheNavMesh();
	if (navMesh == Address_Null)
		return Address_Null;
	return view_as<Address>(SDKCall(g_hSDK_GetNearestNavArea, navMesh, pos, anyZ, maxDist, true, true, 0));
}

/**
 * Voice callout wrapper for flanking.inc.
 */
stock void SmartBots_Voice_Speak(int client, int voiceId)
{
	SDKCall_SpeakConcept(client, voiceId);
}
