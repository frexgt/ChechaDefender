--[[---------------------------------------------------------------------------
ЧечаДефендер — детект обхода бана (ban-evasion), КЛАСТЕРНЫЙ (общая MySQL)
---------------------------------------------------------------------------
Ловит заход с альт-аккаунта забаненного игрока по 4 векторам и банит ОБА
аккаунта на ВСЁМ кластере через ULX (ULib.addBan(...,0,...)).

Коды (причина бана = "ЧечаДефендер: Код N"):
  Код 5 — Family-share: альт запущен с перма-забаненного Steam-аккаунта
  Код 6 — IP: IP совпал с IP перма-забаненного (только свежие связи, см. окно)
  Код 7 — Отпечаток ПК (мягкий): ТОЛЬКО ОТЧЁТ в Discord, БЕЗ автобана (у пиратских
          «сборок» отпечаток общий — бан = массовый ложный).
  Код 8 — Привязка к ПК (machine-token): ОСНОВНОЙ детект по железу/ПК, автобан.

★ КЛАСТЕРНОСТЬ (новое): все идентификаторы (IP/отпечаток/токен/seen/pardon) и
  СЕКРЕТ подписи токена лежат в ЦЕНТРАЛЬНОЙ MySQL (money @ кластер, как ban-sync).
  Поэтому «забанили на сервере A → пытается зайти на B» ловится на B:
    • machine-token подписан ОБЩИМ секретом → токен с машины узнаётся на всех
      серверах (раньше секрет был свой на сервер → токен A не валиден на B);
    • IP/отпечаток видны со всех серверов сразу.
  Бан всё равно ставится через ULib.addBan → разносится ban-sync'ом по кластеру.

★ ЗАЩИТА ОТ ЛОЖНОГО БАНА (критично — был инцидент массового автобана):
    • БД недоступна ИЛИ статус помилования неизвестен → детект НЕ выполняется
      (никого не банит; работает только то, что не зависит от БД — ничего).
    • anti-«сборка»/anti-NAT: если идентификатор засветился у СЛИШКОМ многих
      разных аккаунтов — он общий (сборка/кафе/NAT), по нему НЕ банят.
    • IP-связи учитываются только свежие (окно), т.к. провайдеры переиспользуют IP.

NB: в Lua-песочнице GMod нет настоящего HWID (MAC/серийники), поэтому стойкий
мульти-стор подписанный machine-token — лучший доступный аналог привязки к ПК.

Интеграция с ULX/кластером:
  • Баним ИСКЛЮЧИТЕЛЬНО через ULib.addBan(sid32, 0, ...) → хук ULibPlayerBanned
    → sv_ban_sync пушит в центральную ulib_bans. Статус читаем из ULib.bans.
  • НИКОГДА не пишем в ulib_bans напрямую. Наша MySQL — только cd_*-таблицы.
---------------------------------------------------------------------------]]
if not SERVER then return end

if not mysqloo then
    local ok, err = pcall(require, "mysqloo")
    if not ok then
        ErrorNoHalt("[ЧечаДефендер-Evasion] require('mysqloo') упал: " .. tostring(err) .. "\n")
    end
end

util.AddNetworkString("cd_req")       -- S→C: запрос отпечатка + токена
util.AddNetworkString("cd_resp")      -- C→S: ответ (fp, token)
util.AddNetworkString("cd_setcookie") -- S→C: выдать новый machine-token

-- =============================================================================
-- КОНФИГ
-- =============================================================================
local DISCORD_WEBHOOK =
    "https://webhook.lewisakura.moe/api/webhooks/1510943252520501323/6LVjwDlIKZEPESEVFoYggvaCzCizA4pBgJenlHxr8d2c5dfQACxGjBv-BBEB2Xs1vF3i"

local ENABLE_FAMILY = true
local ENABLE_IP     = true
local ENABLE_FP     = true   -- только отчёт (Код 7), без бана
local ENABLE_COOKIE = true   -- machine-token (Код 8), автобан

-- IP, которые НЕ считаем признаком обхода
local IP_WHITELIST = {
    ["127.0.0.1"] = true,
    ["loopback"]  = true,
}

-- Группы, которые НЕ банятся автоматически (детект только в Discord)
local EXEMPT_GROUPS = {
    admin = true, superadmin = true, moderator = true, dmoderator = true,
    dadmin = true, dsuperadmin = true, operator = true,
}

local CODE      = { family = 5, ip = 6, fp = 7, cookie = 8 }
local CODE_NAME = { [5] = "Family-share", [6] = "IP", [7] = "Отпечаток ПК (мягкий)", [8] = "Привязка к ПК (machine-token)" }
local stats     = { [5] = 0, [6] = 0, [7] = 0, [8] = 0 }

-- Anti-«сборка»/anti-NAT: больше N разных SteamID на один идентификатор → общий,
-- по нему НЕ банят (иначе массовый ложный бан).
local TOKEN_SHARE_LIMIT = 6           -- machine-token (Код 8)
local FP_SHARE_LIMIT    = 4           -- отпечаток (Код 7)
local IP_SHARE_LIMIT    = 6           -- IP (Код 6)
local IP_MATCH_WINDOW   = 3 * 86400   -- IP-связи учитываем только за последние N секунд

-- Центральная MySQL кластера (тот же хост, что у ban-sync).
local DBCFG = {
    hostname  = "193.164.18.92",
    username  = "gmod",
    password  = "UGhsnBz05midJJ",
    database  = "money",
    port      = 3306,
    reconnect = 30,
}
local PREFIX = "[ЧечаДефендер-Evasion] "

-- =============================================================================
-- Лог
-- =============================================================================
local function logInfo(...)
    local p = { ... }
    for i, v in ipairs(p) do p[i] = tostring(v) end
    print(PREFIX .. table.concat(p, " "))
end
local function logErr(label, err)
    ErrorNoHalt(PREFIX .. tostring(label) .. ": " .. tostring(err) .. "\n")
end

-- Отладка токен-потока: cd_evasion_debug 1 (печатает обмен токеном/совпадения).
if not ConVarExists("cd_evasion_debug") then
    CreateConVar("cd_evasion_debug", "0", FCVAR_ARCHIVE, "ЧечаДефендер-Evasion: подробный лог (0/1)")
end
local function dbg(...)
    if GetConVar("cd_evasion_debug"):GetInt() == 0 then return end
    local p = { ... }
    for i, v in ipairs(p) do p[i] = tostring(v) end
    print(PREFIX .. "[DBG] " .. table.concat(p, " "))
end

-- =============================================================================
-- SteamID utils
-- =============================================================================
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

local function IsPermaBanned(sid32)
    if not sid32 or not ULib or not ULib.bans then return false end
    local b = ULib.bans[sid32]
    return b ~= nil and (tonumber(b.unban) or 0) == 0
end

local function IsExempt(ply)
    if not IsValid(ply) then return false end
    if ply:IsAdmin() then return true end
    return EXEMPT_GROUPS[ply:GetUserGroup()] == true
end

-- =============================================================================
-- Discord (ПОДРОБНОСТИ ДЕТЕКТА — ТОЛЬКО СЮДА). v8.1: raw JSON через HTTP()
-- =============================================================================
local function SendDiscord(title, message)
    if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "" then return end
    local payload = util.TableToJSON({
        content = "**" .. title .. "**\n" .. message,
        allowed_mentions = { parse = {} },
    })
    HTTP({
        url     = DISCORD_WEBHOOK,
        method  = "POST",
        type    = "application/json",
        body    = payload,
        success = function(code)
            if code and (code < 200 or code >= 300) then
                logInfo("Discord HTTP " .. tostring(code))
            end
        end,
        failed  = function(err) logInfo("Discord error: " .. tostring(err)) end,
    })
end

-- =============================================================================
-- Чистка ника (срез незавершённого UTF-8 хвоста — движок рубит Nick по 32 байтам)
-- =============================================================================
local function cleanName(s)
    s = tostring(s or "")
    if s == "" then return s end
    if utf8 and utf8.len then
        local n, badpos = utf8.len(s)
        if not n and tonumber(badpos) then s = string.sub(s, 1, tonumber(badpos) - 1) end
    end
    return string.Trim(s)
end

-- =============================================================================
-- СЛОЙ MySQL (асинхронный, центральная БД кластера)
-- =============================================================================
local DB            = nil
local COOKIE_SECRET = nil      -- ОБЩИЙ секрет подписи токена (из cd_meta)
local writeQueue    = {}       -- очередь записей, пока БД недоступна

local function isConn() return DB and mysqloo and DB:status() == mysqloo.DATABASE_CONNECTED end

-- Ручное экранирование (не требует коннекта — работает и для очереди оффлайн).
-- utf8mb4 безопасен: ' и \ никогда не встречаются как байты-продолжения.
local function Q(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\"):gsub("'", "\\'"):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\26", "\\Z")
    return s
end

-- SELECT → onData(rows). При оффлайне/ошибке → onErr(err) (детект тогда пропускается).
local function cdQuery(sqlStr, onData, onErr)
    if not isConn() then if onErr then onErr("offline") end return end
    local query = DB:query(sqlStr)
    function query:onSuccess(data) if onData then onData(data) end end
    function query:onError(err)
        logErr("query", err)
        if onErr then onErr(err) end
    end
    query:start()
end

-- Запись (fire-and-forget). Оффлайн/транзиент → в очередь (с лимитом).
local function cdExec(sqlStr)
    if isConn() then
        local query = DB:query(sqlStr)
        function query:onError(err)
            local e = tostring(err)
            if (e:find("gone away") or e:find("Lost connection") or e:find("Can't connect"))
               and #writeQueue < 2000 then
                writeQueue[#writeQueue + 1] = sqlStr
            end
            logErr("exec", err)
        end
        query:start()
    elseif #writeQueue < 2000 then
        writeQueue[#writeQueue + 1] = sqlStr
    end
end

local function flushQueue()
    if not isConn() or #writeQueue == 0 then return end
    local q = writeQueue
    writeQueue = {}
    for _, s in ipairs(q) do cdExec(s) end
end

-- последовательный прогон списка запросов (для DDL)
local function runSeq(list, done)
    local i = 0
    local function step()
        i = i + 1
        local s = list[i]
        if not s then if done then done() end return end
        cdQuery(s, step, function() step() end) -- идём дальше даже при ошибке (IF NOT EXISTS)
    end
    step()
end

local function ensureSchema(done)
    runSeq({
        [[CREATE TABLE IF NOT EXISTS cd_ip(
            ip    VARCHAR(64)  CHARACTER SET ascii NOT NULL,
            sid64 VARCHAR(20)  CHARACTER SET ascii NOT NULL,
            seen  INT NOT NULL,
            PRIMARY KEY(ip, sid64)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
        [[CREATE TABLE IF NOT EXISTS cd_fp(
            fp    VARCHAR(80)  CHARACTER SET ascii NOT NULL,
            sid64 VARCHAR(20)  CHARACTER SET ascii NOT NULL,
            seen  INT NOT NULL,
            PRIMARY KEY(fp, sid64)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
        [[CREATE TABLE IF NOT EXISTS cd_cookie(
            cookie VARCHAR(160) CHARACTER SET ascii NOT NULL,
            sid64  VARCHAR(20)  CHARACTER SET ascii NOT NULL,
            seen   INT NOT NULL,
            PRIMARY KEY(cookie, sid64)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
        [[CREATE TABLE IF NOT EXISTS cd_seen(
            sid64       VARCHAR(20)  CHARACTER SET ascii NOT NULL,
            name        VARCHAR(64),
            owner64     VARCHAR(20)  CHARACTER SET ascii,
            last_ip     VARCHAR(64)  CHARACTER SET ascii,
            last_fp     VARCHAR(80)  CHARACTER SET ascii,
            last_cookie VARCHAR(160) CHARACTER SET ascii,
            seen        INT,
            PRIMARY KEY(sid64)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
        [[CREATE TABLE IF NOT EXISTS cd_pardon(
            sid64 VARCHAR(20) CHARACTER SET ascii NOT NULL,
            since INT,
            PRIMARY KEY(sid64)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
        [[CREATE TABLE IF NOT EXISTS cd_meta(
            k VARCHAR(64) CHARACTER SET ascii NOT NULL,
            v TEXT,
            PRIMARY KEY(k)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;]],
    }, done)
end

-- общий секрет подписи токена: читаем; если нет — генерим и кладём (race-safe)
local function loadSecret()
    cdQuery("SELECT v FROM cd_meta WHERE k='cookie_secret' LIMIT 1;", function(data)
        if istable(data) and data[1] and isstring(data[1].v) and data[1].v ~= "" then
            COOKIE_SECRET = data[1].v
            logInfo("общий секрет токена загружен")
            return
        end
        local gen = util.SHA256(tostring(SysTime()) .. tostring(math.random(1, 1e9))
            .. tostring(os.time()) .. tostring(DBCFG.hostname))
        cdExec(("INSERT IGNORE INTO cd_meta(k,v) VALUES('cookie_secret','%s');"):format(Q(gen)))
        -- перечитываем — если кто-то вставил раньше, возьмём его значение
        cdQuery("SELECT v FROM cd_meta WHERE k='cookie_secret' LIMIT 1;", function(d2)
            if istable(d2) and d2[1] and isstring(d2[1].v) and d2[1].v ~= "" then
                COOKIE_SECRET = d2[1].v
                logInfo("общий секрет токена инициализирован")
            end
        end)
    end)
end

local connect
connect = function()
    if not mysqloo then
        ErrorNoHalt(PREFIX .. "mysqloo не загружен — положи gmsv_mysqloo_*.dll в lua/bin/\n")
        return
    end
    local ok, dbOrErr = pcall(mysqloo.connect, DBCFG.hostname, DBCFG.username,
        DBCFG.password, DBCFG.database, DBCFG.port)
    if not ok then
        logErr("mysqloo.connect", dbOrErr)
        timer.Simple(DBCFG.reconnect, connect)
        return
    end
    DB = dbOrErr
    function DB:onConnected()
        logInfo("подключено к " .. DBCFG.database .. " @ " .. DBCFG.hostname)
        ensureSchema(function()
            loadSecret()
            flushQueue()
        end)
    end
    function DB:onConnectionFailed(err)
        logErr("onConnectionFailed", err)
        timer.Simple(DBCFG.reconnect, connect)
    end
    DB:connect()
end

local _connected_once = false
local function safeConnect()
    if _connected_once then return end
    _connected_once = true
    connect()
end
hook.Add("Initialize",     "cd_evasion_db_init", function() timer.Simple(5, safeConnect) end)
hook.Add("InitPostEntity", "cd_evasion_db_ipe",  function() timer.Simple(3, safeConnect) end)
timer.Simple(10, safeConnect)

-- keepalive: переподключение при обрыве
timer.Create("cd_evasion_db_keepalive", 30, 0, function()
    if DB and mysqloo and DB:status() == mysqloo.DATABASE_NOT_CONNECTED then
        logInfo("реконнект к БД…")
        DB:connect()
    end
end)

-- =============================================================================
-- API хранилища (кластерное)
-- =============================================================================
local function RecordLink(tbl, col, key, sid64)
    if not key or key == "" or not sid64 or sid64 == "" then return end
    cdExec(("INSERT INTO %s (%s, sid64, seen) VALUES ('%s','%s',%d) "
        .. "ON DUPLICATE KEY UPDATE seen=VALUES(seen);")
        :format(tbl, col, Q(key), Q(sid64), os.time()))
end

local function RecordSeen(sid64, name, owner64, ip, fp, ck)
    if not isValidSid64(sid64) then return end
    local function nz(v)
        v = tostring(v or "")
        if v == "" then return "NULL" end
        return "'" .. Q(v) .. "'"
    end
    cdExec(("INSERT INTO cd_seen (sid64,name,owner64,last_ip,last_fp,last_cookie,seen) "
        .. "VALUES ('%s',%s,%s,%s,%s,%s,%d) ON DUPLICATE KEY UPDATE "
        .. "name=COALESCE(VALUES(name),name),owner64=COALESCE(VALUES(owner64),owner64),"
        .. "last_ip=COALESCE(VALUES(last_ip),last_ip),last_fp=COALESCE(VALUES(last_fp),last_fp),"
        .. "last_cookie=COALESCE(VALUES(last_cookie),last_cookie),seen=VALUES(seen);")
        :format(Q(sid64), nz(name), nz(owner64), nz(ip), nz(fp), nz(ck), os.time()))
end

-- найти все sid64, привязанные к идентификатору. sinceTs — учитывать только
-- связи свежее этого времени (для IP). cb(list|nil); nil = БД недоступна.
local function MatchVector(tbl, col, key, cb, sinceTs)
    if not key or key == "" then cb(nil) return end
    local where = ("%s='%s'"):format(col, Q(key))
    if sinceTs then where = where .. " AND seen > " .. math.floor(sinceTs) end
    cdQuery(("SELECT sid64 FROM %s WHERE %s;"):format(tbl, where),
        function(data)
            local out = {}
            if istable(data) then for _, r in ipairs(data) do out[#out + 1] = r.sid64 end end
            cb(out)
        end,
        function() cb(nil) end)
end

-- cb(true|false|nil); nil = БД неизвестно → детект НЕ выполнять
local function IsPardonedAsync(sid64, cb)
    cdQuery(("SELECT 1 FROM cd_pardon WHERE sid64='%s' LIMIT 1;"):format(Q(sid64)),
        function(data) cb(istable(data) and #data > 0) end,
        function() cb(nil) end)
end

local function AddPardon(sid64)
    if not isValidSid64(sid64) then return end
    cdExec(("INSERT INTO cd_pardon(sid64,since) VALUES('%s',%d) "
        .. "ON DUPLICATE KEY UPDATE since=VALUES(since);"):format(Q(sid64), os.time()))
end

local function RemovePardon(sid64)
    if not isValidSid64(sid64) then return end
    cdExec(("DELETE FROM cd_pardon WHERE sid64='%s';"):format(Q(sid64)))
end

-- =============================================================================
-- machine-token: подпись ОБЩИМ секретом (SHA1 — токен ≤128 символов)
-- =============================================================================
local function sign(nonce) return util.SHA1(COOKIE_SECRET .. ":" .. nonce) end

local function makeCookie(sid64)
    if not COOKIE_SECRET then return nil end
    local nonce = util.SHA1(sid64 .. tostring(SysTime()) .. tostring(math.random(1, 1e9)))
    return nonce .. "." .. sign(nonce)
end

local function validCookie(ck)
    if not COOKIE_SECRET or not isstring(ck) then return false end
    local nonce, sig = ck:match("^(%x+)%.(%x+)$")
    if not nonce or not sig then return false end
    return sign(nonce) == sig
end

-- =============================================================================
-- Бан
-- =============================================================================
local function banOne(sid32, name, code)
    if not sid32 then return end
    local reason = "ЧечаДефендер: Код " .. code
    if ULib and ULib.addBan then
        local ok, err = pcall(ULib.addBan, sid32, 0, reason, name or "", nil)
        if not ok then logErr("ULib.addBan", err) end
    end
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID() == sid32 then
            if ULib and ULib.kick then ULib.kick(p, reason) else p:Kick(reason) end
        end
    end
end

-- altPly — заходящий онлайн-игрок; mainSid64 — перма-забаненный связанный.
-- reportOnly=true → только отчёт в Discord, без бана (мягкий сигнал, Код 7).
local function Punish(altPly, mainSid64, code, vector, matchValue, reportOnly)
    if not IsValid(altPly) then return end
    local altSid32, altSid64 = altPly:SteamID(), altPly:SteamID64()
    local altName = cleanName(altPly:Nick())
    local mainSid32 = to32(mainSid64)

    -- имя основы берём из бан-записи ULib (хранит имя на момент бана)
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
            "Вектор: **%s**\nАльт: `%s` (`%s`)%s\nОснова (перма-бан): `%s` (`%s`)\nСовпадение: `%s`\nВремя: %s",
            CODE_NAME[code] or vector,
            altNameDisp, altSid64,
            note,
            mainNameDisp, mainSid64, tostring(matchValue or "?"),
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

-- =============================================================================
-- Детект
-- =============================================================================
-- Гейт помилования: пока статус неизвестен (БД offline) — НЕ детектим (без бана).
local function withPardonGate(ply, sid64, proceed)
    if ply.cd_pardoned == true then return end
    if ply.cd_pardoned == false then proceed() return end
    IsPardonedAsync(sid64, function(state)
        if state == nil then return end           -- неизвестно → не банить
        ply.cd_pardoned = state
        if state then ply.cd_evasion_done = true return end
        if IsValid(ply) then proceed() end
    end)
end

-- Код 5 (sync): family-share. true = забанено.
local function tryFamily(ply, sid64)
    if not ENABLE_FAMILY then return false end
    local owner64 = ply:OwnerSteamID64()
    if owner64 and owner64 ~= "0" and owner64 ~= sid64 then
        local o32 = to32(owner64)
        if o32 and IsPermaBanned(o32) then
            ply.cd_evasion_done = true
            Punish(ply, owner64, CODE.family, "family-share", owner64)
            return true
        end
    end
    return false
end

-- Код 6 (async): IP (свежие связи, лимит на «общий»/NAT IP)
local function tryIP(ply, sid64)
    if not ENABLE_IP then return end
    local ip = stripPort(ply:IPAddress())
    if ip == "" or IP_WHITELIST[ip] then return end
    MatchVector("cd_ip", "ip", ip, function(sids)
        if not sids or not IsValid(ply) or ply.cd_evasion_done then return end
        if #sids > IP_SHARE_LIMIT then return end -- общий/NAT IP — не банить
        for _, other in ipairs(sids) do
            if other ~= sid64 and IsPermaBanned(to32(other)) then
                ply.cd_evasion_done = true
                Punish(ply, other, CODE.ip, "ip", ip)
                return
            end
        end
    end, os.time() - IP_MATCH_WINDOW)
end

-- вход + периодика: family → IP
local function DetectFor(ply)
    if not IsValid(ply) or not ply:IsPlayer() or ply:IsBot() then return end
    if ply.cd_evasion_done then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end
    withPardonGate(ply, sid64, function()
        if not IsValid(ply) or ply.cd_evasion_done then return end
        if tryFamily(ply, sid64) then return end
        tryIP(ply, sid64)
    end)
end

-- по ответу клиента: отпечаток (отчёт) → machine-token (бан)
local function DetectResp(ply, fp, ck)
    if not IsValid(ply) or ply.cd_evasion_done then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end
    withPardonGate(ply, sid64, function()
        if not IsValid(ply) or ply.cd_evasion_done then return end

        -- Код 7: отпечаток — ТОЛЬКО отчёт, один раз за сессию
        if ENABLE_FP and fp ~= "" and not ply.cd_fp_reported then
            MatchVector("cd_fp", "fp", fp, function(sids)
                if not sids or not IsValid(ply) then return end
                if #sids > FP_SHARE_LIMIT then return end
                for _, other in ipairs(sids) do
                    if other ~= sid64 and IsPermaBanned(to32(other)) then
                        ply.cd_fp_reported = true
                        Punish(ply, other, CODE.fp, "fingerprint", fp, true)
                        return
                    end
                end
            end)
        end

        -- Код 8: machine-token — БАН
        if ENABLE_COOKIE and ck ~= "" then
            MatchVector("cd_cookie", "cookie", ck, function(sids)
                if not sids or not IsValid(ply) or ply.cd_evasion_done then return end
                dbg("token-проверка", sid64, "| аккаунтов на токене:", #sids,
                    "| лимит:", TOKEN_SHARE_LIMIT)
                if #sids > TOKEN_SHARE_LIMIT then
                    dbg("token ПРОПУЩЕН — общий (>лимита), бан отключён")
                    return
                end
                for _, other in ipairs(sids) do
                    if other ~= sid64 then
                        dbg("  связан аккаунт", other, "перма-бан:", IsPermaBanned(to32(other)))
                        if IsPermaBanned(to32(other)) then
                            ply.cd_evasion_done = true
                            Punish(ply, other, CODE.cookie, "machine-token", ck)
                            return
                        end
                    end
                end
            end)
        end
    end)
end

-- =============================================================================
-- Заход игрока
-- =============================================================================
local function onJoin(ply)
    if not IsValid(ply) or ply:IsBot() then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    local ip      = stripPort(ply:IPAddress())
    local owner64 = ply:OwnerSteamID64()

    if ip ~= "" and not IP_WHITELIST[ip] then RecordLink("cd_ip", "ip", ip, sid64) end
    RecordSeen(sid64, ply:Nick(),
        (owner64 and owner64 ~= "0") and owner64 or nil,
        (ip ~= "") and ip or nil, nil, nil)

    DetectFor(ply) -- family + IP

    -- запрос отпечатка + токена (fp/token детект — в cd_resp)
    timer.Simple(2, function()
        if IsValid(ply) and not ply.cd_evasion_done then
            net.Start("cd_req")
            net.Send(ply)
        end
    end)
end

hook.Add("PlayerInitialSpawn", "cd_evasion_join", function(ply)
    timer.Simple(1, function() if IsValid(ply) then onJoin(ply) end end)
end)

net.Receive("cd_resp", function(_, ply)
    if not IsValid(ply) or ply.cd_evasion_done then return end
    local sid64 = ply:SteamID64()
    if not isValidSid64(sid64) then return end

    local fp = net.ReadString()
    local ck = net.ReadString()
    fp = (isstring(fp) and #fp > 0 and #fp <= 64) and fp or ""
    ck = (isstring(ck) and #ck > 0 and #ck <= 128 and validCookie(ck)) and ck or ""

    dbg("cd_resp от", sid64, "| fp=", (fp ~= "") and "есть" or "НЕТ",
        "| token=", (ck ~= "") and ("валиден " .. ck:sub(1, 12) .. "…") or "НЕТ/невалиден")

    if fp ~= "" then RecordLink("cd_fp", "fp", fp, sid64) end
    if ck ~= "" then RecordLink("cd_cookie", "cookie", ck, sid64) end
    RecordSeen(sid64, ply:Nick(), nil, nil, (fp ~= "") and fp or nil, (ck ~= "") and ck or nil)

    DetectResp(ply, fp, ck)

    -- нет валидного токена → выдаём новый (подписан ОБЩИМ секретом)
    if ck == "" and COOKIE_SECRET then
        local newck = makeCookie(sid64)
        if newck then
            RecordLink("cd_cookie", "cookie", newck, sid64)
            RecordSeen(sid64, nil, nil, nil, nil, newck)
            net.Start("cd_setcookie")
            net.WriteString(newck)
            net.Send(ply)
            dbg("выдан НОВЫЙ token →", sid64, newck:sub(1, 12) .. "…")
        end
    elseif ck == "" and not COOKIE_SECRET then
        dbg("НЕ выдан token →", sid64, "— общий секрет ещё не загружен из БД!")
    end
end)

-- =============================================================================
-- Основной забанен, пока альт уже онлайн → ловим альтов немедленно
-- =============================================================================
hook.Add("ULibPlayerBanned", "cd_evasion_onban", function(steamid, banData)
    if not banData then return end
    if (tonumber(banData.unban) or 0) ~= 0 then return end           -- только перма
    local reason = tostring(banData.reason or "")
    if reason:find("ЧечаДефендер", 1, true) then return end          -- наши баны — без каскада

    local sid64 = to64(steamid)
    if sid64 then RemovePardon(sid64) end                            -- ручной бан снимает помилование

    timer.Simple(0.3, function()
        for _, p in ipairs(player.GetAll()) do
            if IsValid(p) and not p.cd_evasion_done and p:SteamID() ~= steamid then
                p.cd_pardoned = nil -- пере-проверить помилование
                DetectFor(p)
            end
        end
    end)
end)

-- =============================================================================
-- Ручной разбан → помилование (снимаем авто-перебан)
-- =============================================================================
hook.Add("ULibPlayerUnBanned", "cd_evasion_onunban", function(steamid, admin)
    local sid64 = to64(steamid)
    if not sid64 then return end
    AddPardon(sid64)
    logInfo(("Помилован (ручной разбан): %s — авто-перебан отключён"):format(steamid))
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID() == steamid then
            p.cd_evasion_done = true
            p.cd_pardoned = true
            break
        end
    end
end)

-- =============================================================================
-- Периодическая сверка онлайна (ловит баны, приехавшие reconcile'ом без хука)
-- =============================================================================
timer.Create("cd_evasion_periodic", 30, 0, function()
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and not p.cd_evasion_done then
            DetectFor(p)
        end
    end
end)

-- =============================================================================
-- Статус (суперадмин)
-- =============================================================================
concommand.Add("cd_evasion_status", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    tell(PREFIX .. "коды: 5=family 6=ip 7=отпечаток(ОТЧЁТ) 8=ПК-токен(БАН)")
    tell(("Бан-сработ.: 5=%d 6=%d 8=%d (Код 7 — только отчёт)"):format(stats[5], stats[6], stats[8]))
    tell(("Anti-сборка: токен≤%d отпечаток≤%d IP≤%d за %dд"):format(
        TOKEN_SHARE_LIMIT, FP_SHARE_LIMIT, IP_SHARE_LIMIT, IP_MATCH_WINDOW / 86400))
    tell(("БД: %s | секрет токена: %s | очередь записи: %d"):format(
        isConn() and ("подключена @ " .. DBCFG.hostname) or "НЕ подключена",
        COOKIE_SECRET and "загружен" or "нет", #writeQueue))
    if isConn() then
        cdQuery("SELECT (SELECT COUNT(*) FROM cd_ip) a,(SELECT COUNT(*) FROM cd_fp) b,"
            .. "(SELECT COUNT(*) FROM cd_cookie) c,(SELECT COUNT(*) FROM cd_seen) d,"
            .. "(SELECT COUNT(*) FROM cd_pardon) e;",
            function(data)
                local r = istable(data) and data[1]
                if r then
                    tell(("Записей (кластер): ip=%s fp=%s cookie=%s seen=%s pardon=%s"):format(
                        tostring(r.a), tostring(r.b), tostring(r.c), tostring(r.d), tostring(r.e)))
                end
            end)
    end
end)

-- =============================================================================
-- Ручное управление помилованием
-- =============================================================================
local function resolveToSid64(arg)
    arg = tostring(arg or "")
    if isValidSid64(arg) then return arg end
    if isValidSid32(arg) then return to64(arg) end
    local up = arg:upper()
    if isValidSid32(up) then return to64(up) end
    return nil
end

-- Первый аргумент команды. ВАЖНО: из dedicated-server консоли таблица args
-- бывает ПУСТОЙ, а аргумент приходит только в argStr — поэтому фоллбэк на него.
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
    AddPardon(sid64)
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID64() == sid64 then p.cd_evasion_done = true p.cd_pardoned = true break end
    end
    tell(PREFIX .. "Помилован вручную (кластер): " .. sid64)
end)

concommand.Add("cd_unpardon", function(ply, _, args, argStr)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local sid64 = resolveToSid64(firstArg(args, argStr))
    local function tell(m) if IsValid(ply) then ply:ChatPrint(m) else print(m) end end
    if not sid64 then tell(PREFIX .. "Использование: cd_unpardon <SteamID64 или STEAM_0:..>") return end
    RemovePardon(sid64)
    for _, p in ipairs(player.GetAll()) do
        if IsValid(p) and p:SteamID64() == sid64 then p.cd_pardoned = nil break end
    end
    tell(PREFIX .. "Помилование снято (кластер): " .. sid64 .. " (детект снова активен)")
end)

-- =============================================================================
-- ДИАГНОСТИКА: dry-run проверка (БЕЗ бана, ИГНОРИРУЯ exempt/pardon)
--   cd_evasion_test [SteamID64|STEAM_0:..]  (без аргумента — сам себя)
-- Показывает, какие идентификаторы записаны у игрока и совпадают ли они с
-- перма-забаненными. Так можно убедиться, что токен/отпечаток/IP пишутся и
-- матчатся, даже если реальный бан не применяется (стафф/помилование).
-- =============================================================================
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
    if not isConn() then tell(PREFIX .. "БД не подключена — тест невозможен") return end

    tell(PREFIX .. "=== ТЕСТ (dry-run, без бана) для " .. sid64 .. " ===")

    -- почему реальный бан мог бы не примениться
    IsPardonedAsync(sid64, function(p)
        tell(("  Помилован (pardon): %s%s"):format(tostring(p == true),
            (p == true) and "  → детект для него ПРОПУСКАЕТСЯ (cd_unpardon чтобы вернуть)" or ""))
    end)
    for _, pl in ipairs(player.GetAll()) do
        if IsValid(pl) and pl:SteamID64() == sid64 then
            tell(("  Стафф/exempt: %s%s  (группа: %s)"):format(tostring(IsExempt(pl)),
                IsExempt(pl) and "  → авто-бан НЕ применяется, только отчёт" or "",
                pl:GetUserGroup() or "?"))
        end
    end

    -- читаем записанные идентификаторы и проверяем совпадения
    cdQuery(("SELECT last_ip,last_fp,last_cookie FROM cd_seen WHERE sid64='%s' LIMIT 1;"):format(Q(sid64)),
        function(data)
            local r = istable(data) and data[1]
            if not r then
                tell("  В cd_seen НЕТ записи — игрок ещё не отдал идентификаторы (не заходил при этой версии / не прошло 2с после спавна)")
                return
            end
            local function checkVec(label, tbl, col, val, sinceTs)
                if not val or val == "" then tell(("  %s: (не записан)"):format(label)) return end
                MatchVector(tbl, col, val, function(sids)
                    if not sids then tell(("  %s: ошибка запроса"):format(label)) return end
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
                end, sinceTs)
            end
            checkVec("IP",    "cd_ip",     "ip",     r.last_ip, os.time() - IP_MATCH_WINDOW)
            checkVec("FP",    "cd_fp",     "fp",     r.last_fp)
            checkVec("TOKEN", "cd_cookie", "cookie", r.last_cookie)
        end)
end)

logInfo("загружен (КЛАСТЕРНЫЙ: MySQL " .. DBCFG.database .. "@" .. DBCFG.hostname
    .. "; family/IP/ПК-токен=бан, отпечаток=отчёт; общий секрет; anti-сборка)")
