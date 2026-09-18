--[[---------------------------------------------------------------------------
ЧечаДефендер — поведенческий детект (server-side, БЕЗ автобана)
---------------------------------------------------------------------------
Ловит читы по ЭФФЕКТУ на сервере (а не по сигнатурам в клиенте):
  • Aim-snap     — мгновенный «доворот» прицела точно на жертву в момент
                   попадания (характерно для аимбота).
  • Wallbang     — пуля попала в игрока сквозь сплошную мировую геометрию
                   (трейс по миру между стрелком и точкой попадания заблокирован).

★★★ ГЛАВНОЕ: ЭТОТ МОДУЛЬ НИКОГДА НЕ БАНИТ И НЕ КИКАЕТ. ★★★
В нём НЕТ кода бана/кика вообще. Поведенческие эвристики вероятностные и
дают ложные срабатывания (быстрые флики, лаг-компенсация, пробивные стволы).
Поэтому модуль ТОЛЬКО копит подозрения по консервативным порогам и шлёт
ОТЧЁТ В DISCORD для РУЧНОЙ проверки админом. Решение о бане — всегда человек.

Это прямо отвечает на прошлый инцидент с массовым ложным автобаном:
здесь автобан невозможен by design.
---------------------------------------------------------------------------]]
if not SERVER then return end

-- =============================================================================
-- КОНФИГ
-- =============================================================================
local ENABLE_AIMSNAP  = true
local ENABLE_WALLBANG = true
local ENABLE_DISCORD  = true

local DISCORD_WEBHOOK =
    "https://webhook.lewisakura.moe/api/webhooks/1510943252520501323/6LVjwDlIKZEPESEVFoYggvaCzCizA4pBgJenlHxr8d2c5dfQACxGjBv-BBEB2Xs1vF3i"

-- Aim-snap: насколько резко повернулся прицел за 1 тик (градусы) и насколько
-- точно после доворота смотрит на жертву (конус, градусы).
local AIM_SNAP_DEG  = 40   -- одно-тиковый доворот ≥ этого = кандидат
local AIM_CONE_DEG  = 4    -- после доворота прицел в пределах этого от жертвы
local AIM_EVENTS    = 8    -- столько инцидентов в окне → ОТЧЁТ (не бан!)

-- Wallbang: трейс по миру заблокирован раньше этой доли пути до жертвы.
local WALL_FRACTION = 0.92
local WALL_EVENTS   = 6    -- столько инцидентов в окне → ОТЧЁТ (не бан!)

local WINDOW        = 120  -- окно накопления инцидентов (сек)
local REPORT_CD     = 300  -- не чаще одного отчёта на игрока/тип (сек)

-- Группы, которых НЕ отслеживаем (админ-утилиты дают ложные эффекты)
local EXEMPT_GROUPS = {
    admin = true, superadmin = true, moderator = true, dmoderator = true,
    dadmin = true, dsuperadmin = true, operator = true,
}

-- =============================================================================
-- УТИЛИТЫ
-- =============================================================================
local function IsExempt(ply)
    if not IsValid(ply) then return true end
    if ply:IsAdmin() then return true end
    return EXEMPT_GROUPS[ply:GetUserGroup()] == true
end

-- угол (градусы) между forward-векторами двух Angle (корректно через wrap)
local function angBetween(a, b)
    local d = math.Clamp(a:Forward():Dot(b:Forward()), -1, 1)
    return math.deg(math.acos(d))
end

local function SendDiscord(title, message)
    if not ENABLE_DISCORD or not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "" then return end
    local payload = util.TableToJSON({
        content = "**" .. title .. "**\n" .. message,
        allowed_mentions = { parse = {} },
    })
    -- v8.1: raw JSON через HTTP() (через прокси form-payload_json не доходит, см. AC)
    HTTP({
        url     = DISCORD_WEBHOOK,
        method  = "POST",
        type    = "application/json",
        body    = payload,
        success = function(code)
            if code and (code < 200 or code >= 300) then
                print("[ЧечаДефендер-Behavior] Discord HTTP " .. tostring(code))
            end
        end,
        failed  = function(err)
            print("[ЧечаДефендер-Behavior] Discord error: " .. tostring(err))
        end,
    })
end

-- =============================================================================
-- ОТСЛЕЖИВАНИЕ УГЛОВ (ринг-буфер последних тиков)
-- =============================================================================
hook.Add("FinishMove", "cd_behavior_track", function(ply, mv)
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

-- =============================================================================
-- НАКОПЛЕНИЕ + ОТЧЁТ (НЕ БАН)
-- =============================================================================
local function bump(att, kind, detail, victim)
    att.cd_inc = att.cd_inc or { aim = {}, wall = {} }
    local list = att.cd_inc[kind]
    local now  = CurTime()

    list[#list + 1] = { t = now, d = detail }
    local cutoff = now - WINDOW
    while list[1] and list[1].t < cutoff do table.remove(list, 1) end

    local need = (kind == "aim") and AIM_EVENTS or WALL_EVENTS
    if #list < need then return end

    -- кулдаун отчёта
    att.cd_reportT = att.cd_reportT or {}
    if att.cd_reportT[kind] and (now - att.cd_reportT[kind]) < REPORT_CD then return end
    att.cd_reportT[kind] = now

    local kindName = (kind == "aim") and "Aim-snap (подозрение на аимбот)" or "Wallbang (попадания сквозь стену)"
    local samples = {}
    for i = math.max(1, #list - 4), #list do samples[#samples + 1] = list[i].d end

    SendDiscord(
        "ЧечаДефендер-Behavior: " .. kindName .. " — ТОЛЬКО ПРОВЕРКА (не бан)",
        string.format(
            "Игрок: `%s` (`%s`)\nИнцидентов за %dс: **%d** (порог %d)\nОружие: `%s`\nПримеры:\n%s\n_Это эвристика — проверьте вручную (демка/спектатор). Автобана НЕТ._\nВремя: %s",
            att:Nick(), att:SteamID(), WINDOW, #list, need,
            IsValid(att:GetActiveWeapon()) and att:GetActiveWeapon():GetClass() or "?",
            "• " .. table.concat(samples, "\n• "),
            os.date("%Y-%m-%d %H:%M:%S")
        )
    )
    print(("[ЧечаДефендер-Behavior] Отчёт (%s) по %s — на ручную проверку, без бана")
        :format(kind, att:Nick()))

    list = {} -- сброс после отчёта
    att.cd_inc[kind] = list
end

-- =============================================================================
-- ОБРАБОТКА ПОПАДАНИЙ
-- =============================================================================
hook.Add("EntityTakeDamage", "cd_behavior_dmg", function(victim, dmg)
    if not (IsValid(victim) and victim:IsPlayer()) then return end
    local att = dmg:GetAttacker()
    if not (IsValid(att) and att:IsPlayer()) then return end
    if att == victim or att:IsBot() then return end
    if IsExempt(att) then return end
    if not dmg:IsBulletDamage() then return end

    -- троттл: дробовик = много пеллет за тик; считаем 1 «инцидент-окно» на 0.1с
    if att.cd_lastDmgT and (CurTime() - att.cd_lastDmgT) < 0.1 then return end
    att.cd_lastDmgT = CurTime()

    local shootPos = att:GetShootPos()
    local hitPos   = dmg:GetDamagePosition()
    if not hitPos or hitPos == vector_origin then hitPos = victim:WorldSpaceCenter() end

    -- ---- AIM-SNAP ----
    if ENABLE_AIMSNAP then
        local snap = maxRecentSnap(att.cd_angbuf)
        if snap >= AIM_SNAP_DEG then
            local dir = hitPos - shootPos
            if dir:LengthSqr() > 1 then
                dir:Normalize()
                local cone = math.deg(math.acos(math.Clamp(att:EyeAngles():Forward():Dot(dir), -1, 1)))
                -- резкий доворот + точное наведение на жертву = признак аима
                if cone <= AIM_CONE_DEG then
                    bump(att, "aim", string.format("доворот %.0f° → прицел %.1f° от цели, дист %.0f",
                        snap, cone, shootPos:Distance(hitPos)), victim)
                end
            end
        end
    end

    -- ---- WALLBANG ----
    if ENABLE_WALLBANG then
        local tr = util.TraceLine({
            start  = shootPos,
            endpos = hitPos,
            mask   = MASK_SOLID_BRUSHONLY, -- только мировые брашы (стены/пол), не пропы/игроки
            filter = att,
        })
        -- мир перекрыл путь заметно раньше точки попадания → пуля «сквозь стену»
        if tr.Hit and tr.Fraction < WALL_FRACTION then
            bump(att, "wall", string.format("трейс по миру блок на %.0f%% пути, дист %.0f",
                tr.Fraction * 100, shootPos:Distance(hitPos)), victim)
        end
    end
end)

-- =============================================================================
-- Статус (суперадмин): текущие подозрения по онлайну
-- =============================================================================
concommand.Add("cd_behavior_status", function(ply)
    if IsValid(ply) and not ply:IsSuperAdmin() then return end
    local out = {
        "[ЧечаДефендер-Behavior] РЕЖИМ: только отчёт в Discord, БЕЗ бана.",
        ("Пороги: aim снап≥%d° конус≤%d° событий≥%d | wall frac<%.2f событий≥%d | окно %dс")
            :format(AIM_SNAP_DEG, AIM_CONE_DEG, AIM_EVENTS, WALL_FRACTION, WALL_EVENTS, WINDOW),
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
