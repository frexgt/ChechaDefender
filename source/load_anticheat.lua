-- ============================================================================
-- ЧечаДефендер — STAGE-1 LOADER
-- ============================================================================
-- This tiny bootstrap is baked into the DLL as CD_BUNDLE and run by
-- GMOD_MODULE_OPEN (module.cpp). It is the ONLY ЧечаДефендер Lua that exists on
-- the game server's disk (as a decoded-in-memory string, never written out).
--
-- Its single job: prove this machine's identity to the control plane exactly
-- once, and — only if the control plane binds & authorises us — pull the FULL
-- runtime (agent + detect engine + client push + glue) as a sealed bundle and
-- run it entirely in memory. Nothing detect-related ever touches the disk.
--
-- FAIL-CLOSED: if the control plane is unreachable, or the license is not bound
-- yet (pending admin approval), or killed — NOTHING loads. We just keep quietly
-- retrying activation on a timer, so once an admin approves the machine binding
-- the runtime comes up on its own without a server restart. Our silence (no
-- heartbeat) is itself the signal to the control plane.
--
-- The transport primitives are published on ZB_AC so the runtime bundle
-- (stage-2) reuses them instead of redefining the ed25519 wire crypto.
-- ============================================================================
if not SERVER then return end

RunConsoleCommand("sv_hibernate_think", "1")

ZB_AC = ZB_AC or {}

local AGENT_VERSION = "0.3.0-loader"

-- ---------------------------------------------------------------------------
-- Native core (gmsv_chechacore). Provides the machine-derived identity and the
-- ed25519/x25519/ChaCha20 primitives. The private key never leaves the DLL.
-- ---------------------------------------------------------------------------
local function core()
    local c = _G.chechacore
    if istable(c) then return c end
    return nil
end

local function coreReady()
    local c = core()
    return c ~= nil and isfunction(c.Sign) and c.KeysReady == true
        and isstring(c.license) and c.license ~= ""
        and isstring(c.api) and c.api ~= ""
end
ZB_AC.CoreReady = coreReady
ZB_AC.AgentReady = coreReady -- back-compat alias used across detect modules

local function machineFP()
    local c = core()
    return (c and c.MachineFP) or ""
end
ZB_AC.MachineFP = machineFP

function ZB_AC.Sign(msg)
    local c = core()
    if c and isfunction(c.Sign) then return c.Sign(msg or "") end
    return nil
end

ZB_AC.DISABLED = ZB_AC.DISABLED or false
ZB_AC.BundleVersion = ZB_AC.BundleVersion or 0
ZB_AC.ConfigVersion = ZB_AC.ConfigVersion or 0
ZB_AC.Config = ZB_AC.Config or {}

local function serverName()
    local h = GetConVar("hostname")
    return h and string.Trim(h:GetString() or "") or "GMod Server"
end
ZB_AC.ServerName = serverName

local function apiURL(path)
    local c = core()
    local base = (c and c.api) or ""
    if not string.find(base, "://", 1, true) then base = "https://" .. base end
    base = string.gsub(base, "/+$", "")
    return base .. path
end

local function genNonce()
    return string.sub(util.SHA256(tostring(SysTime()) .. tostring(math.random()) .. tostring({})), 1, 16)
end

-- Signed request headers: ed25519 over ts.nonce.body proves possession of the
-- machine-derived private key. nil if Sign refuses (tamper latched / no keys) —
-- the caller then simply does not talk to the control plane.
local function signedHeaders(body)
    local c = core()
    if not c then return nil end
    local ts = tostring(os.time())
    local nonce = genNonce()
    local sig = c.Sign(ts .. "." .. nonce .. "." .. (body or ""))
    if not isstring(sig) or sig == "" then return nil end
    return {
        ["X-CD-License"] = c.license,
        ["X-CD-Pubkey"] = c.PubKey or "",
        ["X-CD-Alg"] = "ed25519",
        ["X-CD-Timestamp"] = ts,
        ["X-CD-Nonce"] = nonce,
        ["X-CD-Signature"] = sig,
    }
end

-- Trusted endpoints answer with a signed envelope { payload, sig }; verify the
-- opaque payload string with the embedded server key BEFORE parsing. A hostile
-- host cannot forge a directive: bad/absent sig → verified=false → ignored.
local function parseResp(resp)
    local env = util.JSONToTable(resp or "") or {}
    if isstring(env.payload) and isstring(env.sig) then
        local c = core()
        if c and isfunction(c.Verify) and c.Verify(env.payload, env.sig) == true then
            return util.JSONToTable(env.payload) or {}, true
        end
        return {}, false
    end
    return env, false
end

local function agentPost(path, tbl, onDone)
    if not coreReady() then if onDone then onDone(false) end return end
    local body = util.TableToJSON(tbl or {})
    local headers = signedHeaders(body)
    if not headers then
        if onDone then onDone(false, { error = "sign_unavailable" }, false) end
        return
    end
    HTTP({
        url = apiURL(path),
        method = "POST",
        type = "application/json",
        body = body,
        headers = headers,
        success = function(code, resp)
            local data, verified = parseResp(resp)
            if onDone then onDone(code, data, verified) end
        end,
        failed = function(err)
            if onDone then onDone(false, { error = err }, false) end
        end,
    })
end

local function agentGet(path, onDone)
    if not coreReady() then if onDone then onDone(false) end return end
    local headers = signedHeaders("")
    if not headers then
        if onDone then onDone(false, { error = "sign_unavailable" }, false) end
        return
    end
    HTTP({
        url = apiURL(path),
        method = "GET",
        headers = headers,
        success = function(code, resp)
            local data, verified = parseResp(resp)
            if onDone then onDone(code, data, verified) end
        end,
        failed = function() if onDone then onDone(false, nil, false) end end,
    })
end

-- Publish transport for the runtime bundle (stage-2) to reuse.
ZB_AC.AgentPost = agentPost
ZB_AC.AgentGet = agentGet

-- ---------------------------------------------------------------------------
-- Runtime bootstrap
-- ---------------------------------------------------------------------------
local _activating = false
local _activated = false   -- server accepted our bound identity this session
local _runtimeUp = false   -- the full runtime bundle compiled and ran
local _bundleLoading = false

-- Pull the sealed runtime bundle and run it in memory. BundleOpen does
-- X25519+ChaCha20 decrypt AND verifies the ed25519 signature over
-- (version || plaintext) against the embedded server key, returning plaintext
-- only if authentic. The bundle is never plaintext on the wire and cannot be
-- forged/swapped by the host. Everything runs via CompileString — no disk.
local function loadRuntime()
    if _bundleLoading or _runtimeUp then return end
    _bundleLoading = true
    agentGet("/agent/bundle?since=" .. tostring(ZB_AC.BundleVersion), function(code, data)
        _bundleLoading = false
        if code ~= 200 or not istable(data) then return end
        if not data.epk or not data.ct then return end
        local c = core()
        if not c or not isfunction(c.BundleOpen) then return end
        local plain = c.BundleOpen(data.version or 0, data.epk, data.nonce or "", data.ct, data.sig or "")
        if not isstring(plain) or plain == "" then
            -- Signature/decrypt failed → refuse (fail-closed).
            return
        end
        local fn = CompileString(plain, "cd_runtime_v" .. tostring(data.version), false)
        if not isfunction(fn) then return end
        local _p = print
        _G.print = function() end
        local ok = pcall(fn)
        _G.print = _p
        if ok then
            ZB_AC.BundleVersion = data.version or 0
            _runtimeUp = true
            -- Hand off: the runtime bundle owns heartbeat/signatures/detect now.
            if isfunction(ZB_AC.OnRuntimeLoaded) then pcall(ZB_AC.OnRuntimeLoaded, ZB_AC.BundleVersion) end
        end
    end)
end
ZB_AC.LoadRuntime = loadRuntime

local function doActivate(challenge)
    local c = core()
    agentPost("/agent/activate", {
        challenge = challenge,
        fingerprint = machineFP(),
        machine_fp = machineFP(),
        pubkey = (c and c.PubKey) or "",
        pubkey_x = (c and c.PubKeyX) or "",
        platform = (c and c.platform) or "",
        debugger = (c and c.DebuggerDetected) or false,
        server_name = serverName(),
        hostname = serverName(),
        agent_version = AGENT_VERSION,
        self_hash = util.CRC(gmod.GetGamemode() and gmod.GetGamemode().FolderName or "gm"),
        modules = {},
    }, function(code, data, verified)
        _activating = false
        if code == 423 then
            -- Pending approval / drift / killed. Honor a disable directive only
            -- if the server actually signed it. Either way: nothing loads.
            if verified and data and data.enabled == false then
                ZB_AC.DISABLED = true
            end
            return
        end
        if code ~= 200 or not verified then return end
        -- Bound & authorised. Adopt any config the server signed, then pull the
        -- full runtime.
        _activated = true
        if istable(data) then
            if data.config then ZB_AC.Config = data.config end
            if data.config_version then ZB_AC.ConfigVersion = data.config_version end
            if data.enabled == false then ZB_AC.DISABLED = true return end
        end
        loadRuntime()
    end)
end

-- Challenge-response: fetch a fresh server nonce, then send the signed
-- activation bound to it. Stops replay of a captured activation and ties the
-- enrolling identity to this machine.
local function activate()
    if _activating or _runtimeUp then return end
    if not coreReady() then return end
    if ZB_AC.DISABLED then return end
    _activating = true
    agentGet("/agent/challenge", function(code, data)
        if code ~= 200 or not istable(data) or not isstring(data.challenge) then
            _activating = false
            return
        end
        doActivate(data.challenge)
    end)
end
ZB_AC.Activate = activate

-- Boot: the native core loads via require("chechacore") from a sibling autorun
-- file, so it may not be ready the instant this runs. Retry until the core is up
-- and activation binds. After the initial burst, keep retrying on a slow timer
-- so that an admin approving a pending binding brings the runtime up WITHOUT a
-- server restart.
local _tries = 0
local function boot()
    if _runtimeUp then return end
    _tries = _tries + 1
    if coreReady() and not ZB_AC.DISABLED then activate() end
    if not _runtimeUp then
        local delay = (_tries < 12) and 5 or 30
        timer.Simple(delay, boot)
    end
end

hook.Add("Initialize", "ChechaDefender_Boot", function() timer.Simple(3, boot) end)
timer.Simple(2, boot)
