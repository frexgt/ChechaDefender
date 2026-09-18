--[[---------------------------------------------------------------------------
ZCity RP — детектор клиентского чита (v9)
---------------------------------------------------------------------------
ИЗМЕНЕНИЯ v9 (новое поверх v8) — ДЕТЕКТ KEFIRKA v2 + ЗАЩИТА СКРИН-ГРАБА:
  Kefirka v2 — переработанный чит на чистом Lua (не D3D9-оверлей):
  ESP/aimbot/AA реализованы через hook.Add. Anti-screengrab: render.Capture
  заменяется Lua-обёрткой, которая при вызове рендерит чистый кадр
  (KEFIR.IsScreengrabbing=true подавляет ESP/overlays) и возвращает чистый
  JPEG. Параллельно — хук RenderScene рендерит в CleanRT для «живого» кадра.

  Добавлены 4 прецизионных сигнала:

   19. STRONG kefir_global(N)       — _G.KEFIR таблица с >=3 полями
                                      cfg/ui/IsScreengrabbing/aim_cache/…
                                      Основная структура kefirka; без неё чит
                                      не работает → убрать невозможно. FP≈0.
   20. STRONG kefir_antiscreengrab  — KEFIR.cfg.antiscreen == true.
                                      Означает что bypass скрина АКТИВЕН:
                                      все render.Capture возвращают чистый
                                      кадр. Детектирует НАМЕРЕНИЕ, а не
                                      механизм. FP=0.
   21. STRONG kefir_fonts(N>=2)     — 2+ шрифтов семейства kefir.* (kefir.main,
                                      kefir.main.small, kefir.icon.solid и т.д.)
                                      Созданы surface.CreateFont в kefirka.lua;
                                      ни один легитимный аддон/геймод не
                                      использует префикс "kefir.". FP≈0.
   22. STRONG kefir_named_hook(e/n) — именованные хуки kefirka: KEFIR_AntiScreengrab
                                      (RenderScene), kefirka_AspectRatioLerp
                                      (Think), kefirka_ASPECT_STRETCH
                                      (HUDPaintBackground), KEFIR_GTS_Bypass_*
                                      (PreRender/PostRender). Имена уникальны
                                      для kefirka. FP≈0.

  Бан по сигналам 19-22 → тот же пайплайн: файл-граб (bin/+lua/) + скрин
  + ULib.addBan. При bypass сигнал 20 гарантирует бан, даже если скрин
  пришёл «чистым».

ИЗМЕНЕНИЯ v8 (новое поверх v7) — ДЕТЕКТ И БАН ОБХОДА АНТИЧИТА:
  Поймали bypass-скрипт «KillChecha» (9f8a84.lua): он нейтрализует АЧ, ЗАМЕНЯЯ
  net.Receive/net.Start своими Lua-обёртками, которые гасят пакеты АЧ по имени
  канала (cd_req/cd_resp/checha_*/defender_*), плюс стрипает хуки/глобалы/cookie
  по подстрокам checha/defender/cd_. Против нашей текущей сборки он мажет мимо
  (боевые каналы рандомные zb_ac_*), но сам ПРИЁМ мы раньше не ловили. Закрыто:

   17. STRONG/WEAK ac_bypass_tamper — net.Start/net.SendToServer/net.Receive
                                      проверяются через debug.getinfo: в ванили
                                      они C-функции; если стали Lua — обёрнуты.
                                      >=2 net-функции Lua → STRONG (профиль
                                      KillChecha: net.Start+net.Receive). ==1 →
                                      WEAK. Контекст (timer.Create/concommand.Add/
                                      hook.Remove/debug.getinfo) — только в отчёт
                                      «подробности обхода», на порог не влияет
                                      (их легитимно оборачивают чатбоксы/либы).
                                      debug.getinfo в наборе recursion-proof.
                                      FP≈0: легит-клиент не заменяет net.Start Lua.
   18. ac_honeypot_block (ВЫКЛ v8.1) — приманка отключена по умолчанию: cd_resp у
                                      части честных клиентов не доходил → ложные
                                      баны. Включить для отладки: rp_silkware_honeypot 1.
                                      Описание механики ниже как было:
                                      HONEYPOT-приманка: сам check-скрипт в конце
                                      шлёт decoy-ответ на ПРЕДСКАЗУЕМЫЙ канал
                                      cd_resp (имя из блок-листа bypass'ов) с nonce
                                      проверки. Чистый клиент всегда отправит; обход,
                                      режущий АЧ по имени канала, заблокирует
                                      net.Start("cd_resp") → ответа нет. Детект ТОЛЬКО
                                      если на настоящий (рандомный) check клиент
                                      ОТВЕТИЛ, а приманку проглотил ДВАЖДЫ подряд →
                                      FP≈0 (лаг/выход не считаются). Ловит даже тех,
                                      кто НЕ оборачивает net.*, а блокирует иначе.
                                      ВАЖНО: decoy шлёт сам скрипт (НЕ отдельное
                                      сообщение cd_req) — иначе крошечный cd_req
                                      обгонял фрагментированный check-код и давал
                                      ложные «промахи» у чистых игроков.
   ОТЧЁТ: при ac_bypass_tamper/ac_honeypot_block — особый выделенный отчёт в тот
   же Discord-вебхук (🚨 ПОПЫТКА ОБХОДА АНТИЧИТА) с подробностями (какие функции
   подменены + их исходные файлы / какой канал заглушён). Бан штатный (перма +
   файл-граб выкачивает сам bypass-скрипт как доказательство). Админы — report-
   only с пометкой 🚨 ОБХОД (авто-бан админ-состава по возможному FP опасен).

ИЗМЕНЕНИЯ v7 (новое поверх v6):
  Добавлена сигнатура внешнего чита KEFIR (kefir.rip / kefir.vip).
  KEFIR — это ВНЕШНИЙ чит: D3D9-оверлей (своё меню/ESP мимо GMod surface) +
  kernel-драйвер \Device\KefirSecurityCore, читающий память gmod.exe из ядра.
  В Lua-стейте артефактов НЕТ (подтверждено декомпиляцией kvloader.exe: ни
  одного вызова GMod-Lua-API — нет глобалов/хуков/шрифтов/ConVar/файлов).
  Единственная Lua-зацепка: KEFIR перехватывает luaL_loadbuffer и снимает
  штатный запрет GMod на загрузку байткода (грузит свой \27LJ-блоб).

   13. STRONG kefir_bytecode_load — сервер дампит тривиальную функцию через
                                    string.dump (валидный байткод под эту же
                                    LuaJIT-сборку), встраивает в check; клиент
                                    пробует скомпилировать. Чистый GMod вернёт
                                    строку-ошибку (бинарный чанк запрещён); если
                                    вернулась function — luaL_loadbuffer расхукан
                                    (поведение KEFIR). FP≈0, функцию не вызываем.
   14. STRONG kefir_capture_hook  — render.Capture / render.CaptureToFile
                                    подменены Lua-обёрткой (debug.getinfo .what
                                    ~= "C"). KEFIR хукает скрин-капчу для своего
                                    anti-screengrab — пишет в консоль игрока
                                    "[kefir.vip] Screengrabed" + дамп getinfo
                                    вызывающего. Чистый GMod и штатный screengrab
                                    homigrad render.Capture лишь ВЫЗЫВАЮТ (она
                                    остаётся C-функцией) → FP≈0. Это самый
                                    надёжный из kefir-сигналов (прямой детект
                                    наблюдаемого поведения).
   16. STRONG kefir_anon_hooks    — ГЛАВНЫЙ сигнал (вскрыт kefir_tracer): один
                                    анонимный RunString-чанк (source [string
                                    "<rand>"]) держит хуки на >=3 РАЗНЫХ
                                    чувствительных событиях (CreateMove/CalcView/
                                    CalcViewModelView/HUDPaint/RenderScreenspace
                                    Effects/PostEntityFireBullets/…) ИЛИ >=6 хуков
                                    всего. Имена хуков/чанка рандомны у каждого —
                                    матчим ПАТТЕРН, не имена. Легит-код вешает
                                    хуки из ФАЙЛОВ — FP≈0. Не зависит от detour'ов/
                                    кэша print, ловит aim/ESP-ядро чита. Форензика:
                                    скан upvalue-строк чит-функций на маркеры
                                    (kefir/checha/chechensky/…) → в триггер как
                                    доказательство.
   15. STRONG kefir_console_capture — console-trap: render.Capture подменена
                                    НАТИВНЫМ detour'ом (Lua-ссылка не меняется,
                                    .what=="C" → сигнал 14 слеп). Клиент
                                    оборачивает print/Msg/MsgC/MsgN, дёргает
                                    render.Capture в PostRender → detour KEFIR
                                    синхронно печатает "[kefir.vip] Screengrabed";
                                    ловим слово "kefir" в выводе → STRONG.
                                    Отдельная async-проба (SendKefirProbe),
                                    свой пул каналов zb_ackp_, ответ nonce+bool.
   ОГРАНИЧЕНИЕ: внешний+ядерный чит почти не виден из серверного Lua. Сигналы
   14/15 ловят KEFIR пока он держит Lua-хук/печать на капче; 13 — пока расхукан
   loadbuffer. Если KEFIR уберёт Lua-часть и оставит только D3D9+kernel —
   серверный Lua-AC снова слепнет (нужен нативный клиентский/ядерный АЧ).

ИЗМЕНЕНИЯ v6 (новое поверх v5):
  Добавлены сигнатуры для трёх семейств читов, которые ходят по серверам
  (образцы изучены: amfetamin.lua, eschtz.loldev, zaluparecoil/DobroWare).
  Все сигнатуры подобраны так, чтобы НЕ пересекаться с легитимным кодом:
    - homigrad штатный screengrab (bScreenGrabStart, bScreengrabSendPart,
      ScreengrabInitCallback, bScreenGrabFailed, timer bScreengrabSendParts)
      намеренно НЕ детектится, иначе будут банить легитимный скрин.
    - homigrad ARC9 base "weapon_octo_base_" НЕ детектится.
    - Generic-паттерны (esp_, silk, aim_, chams) запрещены (см. v4).

  Что добавлено (только STRONG/WEAK высокой точности):

    7. STRONG amf_hooks(...)      — хотя бы один hook в hook.GetTable() с
                                    именем Amfetamin_ESP/Watermark/Aimbot/
                                    FakeTag/DrawFOV/Bhop/NoRecoil/
                                    BulletTracer/DrawTracers/ResetLock.
                                    Префикс «Amfetamin_» уникален.
    8. STRONG amf_cfg_file        — файл data/zxc/amfetamin_config.txt
                                    (Amfetamin_komigrad сохраняет туда настройки).
    9. STRONG dw_hooks(...)       — хотя бы один DW_NoRecoilSystem /
                                    DW_WeaponTracker / DW_NoRecoilHook /
                                    DW_AutoDetectMode в hook.GetTable().
                                    Префикс «DW_» здесь уникален для DobroWare,
                                    легитимный код не использует.
   10. STRONG nl_convars(N>=3)    — 3+ из специфичных eschtz/loldev ConVar:
                                    cfg_aimbot, cfg_antiaim, cfg_antiaim_power,
                                    cfg_aim_smooth, cfg_trigger_mode,
                                    cfg_speedhack, cfg_inventory_exploit,
                                    cfg_esp_dormant, cfg_override_fov,
                                    cfg_fov_value, cfg_esp_box_style.
                                    1 — может случайно, 3+ — однозначно чит.
   11. STRONG nl_fonts(N>=2)      — 2+ из NL_Logo / NL_Header / NL_Group /
                                    NL_Text / NL_Icon / NL_Icon_Small.
   12. STRONG nl_hitsound_hook    — Think-hook "HITSOUND_DETECT_SHOT"
                                    (eschtz hitsound через clip-tracking).

ИЗМЕНЕНИЯ v5 (для контекста):
  1. РАНДОМИЗАЦИЯ NET-КАНАЛОВ — per-check имя response/grab каналов
     инжектится в скрипт, читы не могут предсказать.
  2. WIPE-DETECT — если был детект, потом стало чисто → бан по track_wipe.
  3. АНТИ-SCREEN-GRAB — если детект был, скрин не пришёл → +reason.

ИЗМЕНЕНИЯ v4 (для контекста):
  Детектор урезан до high-precision сигналов. Удалены generic runtime-injection
  паттерны (string.dump, wrap_native, esp_/silk/aim_/chams) — они банили
  гейммод homigrad (PhysSilk, AS_ESP_Draw).

Что детектим всего (14 СИГНАЛОВ + 2 META):

  SilkWare (v4):
    1. STRONG sw_global(N>=3)    — _G.SilkWare с >=3 internal-полями
    2. STRONG sw_config_dir       — папка data/silkwarecfgs/ (банит и за старую/
                                    остаточную установку, даже если чит выгружен)
    3. STRONG sw_fonts(N>=2)      — шрифты SW_Title/SW_Tab/SW_Group/…
    4. STRONG sw_debug_patch      — поведенческий тест debug.getinfo

  Amfetamin/DobroWare/NL (v6):
    7. STRONG amf_hooks(...)
    8. STRONG amf_cfg_file
    9. STRONG dw_hooks(...)
   10. STRONG nl_convars(N>=3)
   11. STRONG nl_fonts(N>=2)
   12. STRONG nl_hitsound_hook

  META (поведенческие):
    5. STRONG track_wipe(prev)
    6. STRONG anti_screengrab

  ОБХОД АЧ (v8):
   17. STRONG/WEAK ac_bypass_tamper   (подмена net.* Lua-обёртками)
   18. STRONG      ac_honeypot_block  (глушение приманочного канала cd_resp)

  KEFIR v2 / kefirka.lua (v9):
   19. STRONG kefir_global(N)       (_G.KEFIR с >=3 полями)
   20. STRONG kefir_antiscreengrab  (KEFIR.cfg.antiscreen==true → bypass активен)
   21. STRONG kefir_fonts(N>=2)     (шрифты kefir.main/kefir.icon.*/… зарегистрированы)
   22. STRONG kefir_named_hook(e/n) (KEFIR_AntiScreengrab/kefirka_AspectRatioLerp/…)

Триггер бана: STRONG >= 1 или WEAK >= 2.

КОНФИГ:
  rp_silkware_action  log / kick / ban   (по умолчанию ban)
---------------------------------------------------------------------------]]
if not SERVER then return end

util.AddNetworkString("zb_ac_request")
util.AddNetworkString("zb_ac_response")
util.AddNetworkString("zb_ac_grab_request")
util.AddNetworkString("zb_ac_grab_chunk")

-- v8: HONEYPOT-приманка против обхода «по имени канала».
-- cd_resp — client→server decoy-ответ: его шлёт САМ check-скрипт (с nonce проверки),
-- а не отдельное сообщение (так нет гонки с фрагментированным check-кодом). Имя ВЗЯТО
-- ИЗ блок-листа bypass'ов (9f8a84.lua глушит ровно cd_req/cd_resp/…) и намеренно
-- ПРЕДСКАЗУЕМО: любой обход, режущий AC по имени канала, заблокирует net.Start("cd_resp")
-- → сервер не получит ответ → ac_honeypot_block. См. ScheduleHoneypotEval /
-- HandleHoneypotResponse ниже.
util.AddNetworkString("cd_resp")

-- =============================================================================
-- КОНФИГ
-- =============================================================================

local CVAR_ACTION = CreateConVar("rp_silkware_action", "ban",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Что делать при детекте чита: log / kick / ban")

-- v8.1: HONEYPOT-приманка (ac_honeypot_block) ВЫКЛЮЧЕНА по умолчанию.
-- Причина: decoy-ответ cd_resp у части честных клиентов не доходит до сервера
-- (подтверждено ложными банами 100% чистого игрока) — механизм оказался
-- ненадёжным. Детект обхода держит ac_bypass_tamper (подмена net.* через
-- debug.getinfo), он FP не даёт. Включать только для отладки: rp_silkware_honeypot 1.
local CVAR_HONEYPOT = CreateConVar("rp_silkware_honeypot", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Honeypot-приманка cd_resp (0=ВЫКЛ — давала ложные срабатывания; 1=вкл, отладка)")

-- v8.1: ac_bypass_tamper (детект подмены net.*) ВЫКЛЮЧЕН по умолчанию.
-- Причина: net.Receive в ванильном GMod реализован на Lua (includes/extensions/
-- net.lua → .what~="C"), а net.Start штатно оборачивают античиты (Nova Defender).
-- То есть «обёрнутость» net.* — норма, детектор ловил чистых игроков. Сервер
-- игнорирует этот сигнал в HandleResponse. Включать только для отладки: 1.
local CVAR_TAMPER = CreateConVar("rp_silkware_tamper", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Детект подмены net.* ac_bypass_tamper (0=ВЫКЛ — ложил чистых; 1=вкл, отладка)")

-- v8.1: KEFIR-байткод-проба (kefir_bytecode_load) ВЫКЛ по умолчанию.
-- Она шлёт клиенту байткод и пробует CompileString — честный GMod отказывается и
-- печатает в клиентскую консоль "Cannot run byte code! 1b" на КАЖДОЙ проверке у
-- ВСЕХ игроков (косметический шум, не детект). Прочие KEFIR-сигналы остаются
-- (kefir_capture_hook / kefir_anon_hooks / kefir_console_capture). Вернуть: 1.
local CVAR_KEFIR_BC = CreateConVar("rp_silkware_kefir_bc", "0",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "KEFIR байткод-проба (0=ВЫКЛ — шумит 'Cannot run byte code!' в консоли клиента; 1=вкл)")

-- Проверять ли админов (белый список) автоматически. По умолчанию ВКЛ:
-- админы ПРОВЕРЯЮТСЯ на входе/периодике, но при детекте их НЕ банят и НЕ кикают —
-- только отчёт DETECT-IGNORED в чат стаффу + Discord (см. HandleDetection).
-- Так читящий админ авто-палится, но ложный детект от админ-утилит не наказывает.
-- 0 = вернуть старое поведение (админов вообще не проверять).
local CVAR_CHECK_ADMINS = CreateConVar("rp_silkware_check_admins", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Авто-проверять админов (1) — детект только в отчёт, без бана; 0 — не проверять")

-- Discord-вебхук НЕ хранится в исходнике (файл в git, секрет утёк бы в репозиторий).
-- Источник (по приоритету):
--   1) ConVar rp_silkware_webhook (FCVAR_PROTECTED) — если задан непустым;
--   2) файл data/zb_ac_webhook.txt (папка data/ не в git, живёт только на сервере).
-- Чтобы сменить вебхук: отредактируй garrysmod/data/zb_ac_webhook.txt или
-- выполни в серверной консоли rp_silkware_webhook "<url>".
local CVAR_WEBHOOK = CreateConVar("rp_silkware_webhook", "",
    {FCVAR_PROTECTED},
    "Discord webhook для отчётов АЧ (пусто = брать из data/zb_ac_webhook.txt)")

local WEBHOOK_FILE = "zb_ac_webhook.txt"

local function LoadWebhook()
    local cv = string.Trim(CVAR_WEBHOOK:GetString() or "")
    if cv ~= "" then return cv end
    local f = file.Read(WEBHOOK_FILE, "DATA")
    if f then return string.Trim(f) end
    return ""
end

local DISCORD_WEBHOOK = LoadWebhook()
if DISCORD_WEBHOOK == "" then
    print("[AC] ВНИМАНИЕ: Discord-вебхук не задан — отчёты не будут отправляться. " ..
          "Создай garrysmod/data/" .. WEBHOOK_FILE .. " или задай rp_silkware_webhook.")
end
-- Горячая смена вебхука без рестарта
cvars.AddChangeCallback("rp_silkware_webhook", function()
    DISCORD_WEBHOOK = LoadWebhook()
end, "zb_ac_webhook_reload")

local DETECT_REASON   = "ЧечаДефендер: Код 4"
local SCREEN_DIR      = "zb_ac_screens"
local SCREEN_TIMEOUT  = 10
local CHECK_INTERVAL  = 30
local RESPONSE_TIMEOUT = 8

-- =============================================================================
-- ВЫКАЧКА ФАЙЛОВ КЛИЕНТА (доказательство перед баном)
-- =============================================================================
-- Перед применением бана выкачиваем у клиента:
--   1) bin/        — нативные модули gmcl_*.dll (типичное место бинарных читов);
--   2) локальную lua/ через MOD-путь (garrysmod/lua игрока) — минус стоковые
--      файлы движка (STOCK_LUA_LIST) и БЕЗ GAME-пути (геймод/аддоны сервера).
-- (Историческое имя «lua/bin» в переменных/каналах оставлено, но по факту
--  скан шире — bin/ + локальная lua/, см. BuildBinGrabClientCode.)
-- Файлы сохраняются как доказательство в data/zb_ac_bin/<sid>_<time>/.
-- Если игрок отключается до завершения выкачки — бан всё равно ставится по
-- SteamID (ULib.addBan работает оффлайн), как и для скрина.
local CVAR_BINGRAB = CreateConVar("rp_silkware_bingrab", "1",
    {FCVAR_ARCHIVE, FCVAR_PROTECTED},
    "Перед баном выкачивать файлы клиента (bin/ + локальная lua/) как доказательство: 1/0")

local BIN_DIR      = "zb_ac_bin"
-- Тайминг выкачки согласован с MAX_FILES (1500) и шагом помпы (0.06с):
-- 1500 файлов × 0.06с ≈ 90с базово + запас на многочанковые DLL → таймаут 120с.
local BIN_TIMEOUT  = 120                -- bin/ + локальная lua/ клиента; с запасом под крупные DLL
local BIN_MAX_FILE = 4 * 1024 * 1024    -- lua-файлы маленькие; DLL до 4МБ хватит

-- (v4: BAIT_SUFFIX удалён — использовался только для GTS bait Dobroware.)

-- =============================================================================
-- WHITELIST СТОКОВЫХ ФАЙЛОВ GMOD (не выкачивать в доказательства)
-- =============================================================================
-- Базовые lua-файлы движка GarrysMod (lua/derma, lua/includes, lua/vgui и т.д.)
-- одинаковы у всех игроков и не несут доказательной ценности. Раньше дамп
-- выкачивал их все (~290 файлов) на каждый бан — лишний трафик и мусор в
-- data/zb_ac_bin/. Список ниже встраивается в клиентский скрипт; scan_dir
-- пропускает файл ТОЛЬКО при точном совпадении пути. Поэтому если чит подбросит
-- НОВЫЙ файл в стоковую папку (например lua/vgui/dpanel_evil.lua) — он всё равно
-- попадёт в доказательства, исключаются лишь известные оригинальные файлы.
-- Пути — относительно lua/ (без префикса). Актуально для текущей сборки GMod.
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
]]

-- =============================================================================
-- v5: Per-session случайность для рандомизации net-каналов
-- =============================================================================
-- Salt создаётся один раз при старте сервера и подмешивается ко всем
-- генерируемым именам. Между рестартами сервера соль меняется → читовые
-- бинды на конкретное имя гарантированно сломаются.
local SESSION_SALT = util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9)) ..
                               tostring(os.time()))

local function GenChannelName(prefix)
    -- Каждый вызов даёт уникальное имя (12 hex-чаров после префикса).
    local seed = SESSION_SALT ..
                 tostring(SysTime()) ..
                 tostring(math.random()) ..
                 tostring(#tostring({}))
    return prefix .. string.sub(util.SHA1(seed), 1, 12)
end

-- =============================================================================
-- ИНФРАСТРУКТУРА
-- =============================================================================

if not file.IsDir(SCREEN_DIR, "DATA") then
    file.CreateDir(SCREEN_DIR)
end
if not file.IsDir(BIN_DIR, "DATA") then
    file.CreateDir(BIN_DIR)
end

local pendingChecks = {} -- [steamid] = {nonce=, deadline=, missCount=, respName=, grabReqName=, grabChunkName=}
local pendingGrabs  = {} -- [steamid] = {chunks={}, totalLen=, deadline=, reasons=, banFn=, chunkName=}
local pendingBin    = {} -- [steamid] = {dir=, files={[name]=chunks}, written=, manifest={}, deadline=, doneFn=, gotDone=}

-- =============================================================================
-- ФИКС УТЕЧКИ NETWORKSTRING (v6.1)
-- =============================================================================
-- ПРОБЛЕМА v5: на КАЖДУЮ проверку регистрировались НОВЫЕ уникальные
-- networkstring (respName + grabReqName per check, grabChunkName per grab).
-- util.AddNetworkString невозможно отменить → пул сетевых строк движка
-- (жёсткий лимит 4096) забивался за ~час аптайма. После переполнения ВЕСЬ
-- сервер переставал регистрировать строки: "Table networkstring is full,
-- can't add weapon_asval" и т.п. — ломалась сетевая часть оружия и аддонов.
--
-- РЕШЕНИЕ: фиксированный ПУЛ имён на каждый тип канала, зарегистрированный
-- ОДИН раз при старте (см. BuildChannelPools ниже). Per-check берём случайное
-- имя из пула. Непредсказуемость для читов сохраняется (имя по-прежнему
-- инжектится в RunString и меняется между рестартами через SESSION_SALT),
-- но общее число networkstring ограничено 3*POOL_SIZE навсегда.
-- Корректность при общих именах: HandleResponse/HandleGrabChunk различают
-- игроков по отправителю (ply) + nonce, поэтому если двум игрокам выпал один
-- канал — это безопасно.
local POOL_SIZE = 24
local respPool, grabReqPool, grabChunkPool = {}, {}, {}
local binChunkPool    = {} -- каналы для приёма файлов lua/bin от клиента
local testScreenPool  = {} -- каналы для тест-скрина (Nova-формат: numPkts/idx/size/data)
local pendingTestScr  = {} -- [sid] = {data={[idx]=chunk}, total=nil, received=0, cb=fn}
local kefirProbePool  = {} -- каналы для KEFIR console-trap (ответ: nonce + bool)
local pendingKefir    = {} -- [sid] = {nonce=, deadline=}
-- v8: honeypot-приманка (фиксированный канал cd_resp)
local pendingHoneypot = {} -- [sid] = {nonce=, deadline=} — ждём ответ на decoy-пробу
local honeypotMiss    = {} -- [sid] = N — счётчик подряд проглоченных приманок (бан на 2)
local realAnsweredAt  = {} -- [sid] = CurTime() последнего ответа на НАСТОЯЩИЙ check
                           -- (нужно, чтобы отличить «глушит приманку» от «лаг/выход»)
local reportedSession = {} -- [sid] = true — уже отчитались об этом игроке в сессии
                           -- (антиспам вебхука; сбрасывается на дисконнекте)

local function PickRandom(pool)
    return pool[math.random(1, #pool)]
end

-- Per-player history для wipe-detect:
-- {[sid] = {hadDetection=bool, lastSignals={...}, firstDetectionAt=ts}}
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

-- (v6.1: таймер очистки динамических каналов удалён — каналы больше не
-- создаются на лету, используется фиксированный пул из BuildChannelPools.)

-- =============================================================================
-- БЕЛЫЙ СПИСОК: ГРУППЫ ОСВОБОЖДЁННЫЕ ОТ ПРОВЕРКИ И АВТОБАНА
-- =============================================================================
-- Админы могут использовать утилиты которые создают глобалы / шрифты
-- совпадающие с эвристиками детектора. Чтобы избежать ложных банов всему
-- админ-составу, эти группы:
--   * НЕ получают периодических проверок
--   * НЕ получают первой проверки на InitialSpawn
--   * Если детект всё же сработал (например через rp_ac_check вручную) —
--     результат идёт в чат стаффу + Discord как info-only, БЕЗ скрина, кика
--     и бана.
-- Список синхронизирован с ZLogs (zcity_logs/sv_zlogs_net.lua → LOGS_ACCESS_GROUPS).
-- =============================================================================

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
    -- IsAdmin() = admin/superadmin и всё что от них наследуется
    if ply:IsAdmin() then return true end
    if EXEMPT_GROUPS[ply:GetUserGroup()] then return true end
    return false
end

-- =============================================================================
-- ВАЙТЛИСТ ПО STEAMID (персональные исключения)
-- =============================================================================
-- Игрок в вайтлисте ПОЛНОСТЬЮ игнорируется АЧ: не проверяется, не банится, не
-- репортится (сильнее, чем admin-exempt, который шлёт DETECT-IGNORED). Хранится
-- в data/zb_ac_whitelist.txt (один SteamID на строку), переживает рестарт.
-- Управление: rp_ac_whitelist_add / _remove / _list (суперадмин/консоль).
local WHITELIST_FILE = "zb_ac_whitelist.txt"
local WHITELIST = {}

local function NormalizeSteamID(s)
    return string.upper(string.Trim(s or ""))
end

local function LoadWhitelist()
    WHITELIST = {}
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

local function IsWhitelisted(plyOrSid)
    local sid
    if type(plyOrSid) == "string" then
        sid = NormalizeSteamID(plyOrSid)
    elseif IsValid(plyOrSid) then
        sid = plyOrSid:SteamID()
    end
    if not sid or sid == "" then return false end
    return WHITELIST[sid] == true
end

LoadWhitelist()

-- Стоит ли АВТО-проверять этого игрока (вход/периодика/check_all).
-- Вайтлист по SteamID — НИКОГДА (полное игнорирование). Не-админы — всегда.
-- Админы — если rp_silkware_check_admins=1 (детект уйдёт в отчёт без бана,
-- т.к. HandleDetection не наказывает exempt). При 0 — пропускаем.
local function ShouldAutoCheck(ply)
    if not IsValid(ply) then return false end
    if IsWhitelisted(ply) then return false end
    if not IsExempt(ply) then return true end
    return CVAR_CHECK_ADMINS:GetBool()
end

local function NotifyStaff(msg)
    print("[AC] " .. msg)
    for _, p in ipairs(player.GetAll()) do
        if p:IsAdmin() or p:IsSuperAdmin() then
            p:ChatPrint("[AC] " .. msg)
        end
    end
end

-- v8.1: шлём raw JSON через HTTP() (Content-Type: application/json), НЕ http.Post
-- с form-полем payload_json. Через прокси (lewisakura и т.п.) form-вариант не
-- проходит — Discord отдаёт 4xx, а http.Post коды ошибок не ловит → молча «успех»
-- и сообщение не доходит. raw-JSON через HTTP() = ровно то, что шлёт рабочий
-- ac_webhook_test (отвечает 204).
local function SendDiscord(title, message)
    if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "" then return end
    local payload = util.TableToJSON({
        content = "**" .. title .. ":** " .. message,
        allowed_mentions = { parse = {} },
    })
    HTTP({
        url     = DISCORD_WEBHOOK,
        method  = "POST",
        type    = "application/json",
        body    = payload,
        success = function(code, _, _)
            if code and (code < 200 or code >= 300) then
                print("[AC] Discord HTTP " .. tostring(code))
            end
        end,
        failed  = function(err)
            print("[AC] Discord error: " .. tostring(err))
        end,
    })
end

local function SendDiscordWithFile(title, message, filePath, displayName)
    if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "" then return end

    local content = filePath and file.Read(filePath, "DATA")
    if not content or content == "" then
        SendDiscord(title, message)
        return
    end

    local payload = util.TableToJSON({
        content = "**" .. title .. ":** " .. message,
        allowed_mentions = { parse = {} },
    })

    local boundary = "----ZBAC" .. tostring(math.random(1, 1e9)) ..
        tostring(SysTime()):gsub("[^%w]", "")

    local CRLF = "\r\n"
    local body =
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="payload_json"' .. CRLF ..
        "Content-Type: application/json" .. CRLF .. CRLF ..
        payload .. CRLF ..
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="files[0]"; filename="' ..
            (displayName or "screenshot.jpg") .. '"' .. CRLF ..
        "Content-Type: image/jpeg" .. CRLF .. CRLF ..
        content .. CRLF ..
        "--" .. boundary .. "--" .. CRLF

    HTTP({
        url     = DISCORD_WEBHOOK,
        method  = "POST",
        headers = {
            ["Content-Type"] = "multipart/form-data; boundary=" .. boundary,
        },
        body    = body,
        type    = "multipart/form-data; boundary=" .. boundary,
        success = function(code, _, _)
            if code and (code < 200 or code >= 300) then
                print("[AC] Discord upload HTTP " .. tostring(code))
            end
        end,
        failed  = function(err)
            print("[AC] Discord upload error: " .. tostring(err))
            SendDiscord(title, message)
        end,
    })
end

-- =============================================================================
-- ПРИМЕНЕНИЕ САНКЦИЙ
-- =============================================================================
-- Изменения v2:
--   * Сначала ВСЕГДА ставим бан через ULib.addBan (работает оффлайн)
--   * Затем Kick если игрок ещё на сервере
--   * Бан = 0 минут = ПЕРМА (новый sv_ban_sync защищает перму атомарно
--     через CASE WHEN unban=0)
--   * Бан синхронизируется на другие сервера кластера через MySQL pull
-- =============================================================================

local function ApplyAction(ply, sid, nick, reasons, screenPath, binDir, binCount, binComplete)
    local triggers = table.concat(reasons, ", ")

    -- Инфо о выкачке файлов (bin/ + lua/) для отчёта
    local binLine
    if binDir then
        binLine = string.format("\n**Файлы (bin/ + lua/):** собрано %d%s (data/%s)",
            tonumber(binCount) or 0,
            binComplete and "" or " — НЕПОЛНО (игрок вышел/таймаут)",
            binDir)
    else
        binLine = "\n**Файлы (bin/ + lua/):** не выкачивалось"
    end

    -- v8: распознаём ПОПЫТКУ ОБХОДА АЧ (ac_bypass_tamper / ac_honeypot_block) и
    -- оформляем особый выделенный отчёт. «Подробности обхода» парсим прямо из
    -- сигнала (он несёт перечень подменённых функций + их исходные файлы, либо
    -- какой канал заглушён). Заголовок и блок деталей — единственное отличие;
    -- дальше идёт штатный пайплайн (файл-граб уже выкачал сам bypass-скрипт).
    local bypassTitle, bypassDetail = nil, nil
    for _, r in ipairs(reasons) do
        -- r вида "S:ac_bypass_tamper(net.Start<-...; net.Receive<-...)"
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
            local chan = string.match(body, "%((.+)%)$") or "cd_resp"
            bypassTitle  = "🚨 ЧечаДефендер: ПОПЫТКА ОБХОДА АНТИЧИТА"
            bypassDetail = "**Подробности обхода (глушение канала по имени):**\n```\n" ..
                "Заглушён приманочный канал: " .. chan .. "\n```\n_Клиент ответил " ..
                "на настоящую проверку, но дважды проглотил decoy-пробу — значит " ..
                "режет АЧ по имени net-канала._"
            -- не break: если рядом есть ac_bypass_tamper, отдадим приоритет ему
        end
    end

    local reportTitle = bypassTitle or "ЧечаДефендер: автобан"
    local discordMsg = string.format(
        "%sИгрок: `%s` (`%s`)\n**Триггеры:** %s\n**Время:** %s%s",
        bypassDetail and (bypassDetail .. "\n\n") or "",
        nick, sid, triggers, os.date("%Y-%m-%d %H:%M:%S"), binLine)

    if screenPath then
        local displayName = string.gsub(sid, ":", "_") .. "_" ..
            os.date("%Y%m%d_%H%M%S") .. ".jpg"
        SendDiscordWithFile(reportTitle, discordMsg,
            screenPath, displayName)
    else
        SendDiscord(reportTitle,
            discordMsg .. "\n**Скрин:** не получен")
    end

    NotifyStaff(string.format("AUTOBAN %s (%s) — triggers: %s, screen: %s, файлы(bin/+lua/): %s",
        nick, sid, triggers, screenPath or "none",
        binDir and ((tonumber(binCount) or 0) .. " файлов" .. (binComplete and "" or " (неполно)")) or "off"))

    local action = string.lower(CVAR_ACTION:GetString() or "log")

    if action == "log" then
        return
    end

    if action == "ban" then
        -- Бан в ULib (всегда, даже если ply отключился к моменту grab)
        -- ULib.addBan(steamid, minutes, reason, name, admin)
        -- minutes = 0 → перма-бан
        -- admin = nil → console
        if ULib and ULib.addBan then
            local ok, err = pcall(ULib.addBan, sid, 0, DETECT_REASON, nick, nil)
            if not ok then
                print("[AC] ULib.addBan ошибка: " .. tostring(err))
            end
        else
            print("[AC] ULib.addBan недоступен — бан не записан")
        end
    end

    -- Кик: и для action=kick, и для action=ban (ULib.addBan не кикает offline-ну)
    if IsValid(ply) then
        -- ULib.kick корректно формирует bann message если есть
        if ULib and ULib.kick then
            ULib.kick(ply, DETECT_REASON)
        else
            ply:Kick(DETECT_REASON)
        end
    end
end

-- =============================================================================
-- СБОР СКРИНА ОТ КЛИЕНТА
-- =============================================================================
-- Не используем GTS напрямую: Dobroware патчит net.Receive и реагирует на
-- любое имя содержащее "GimmeThatScreen" — закрывает свои окна за 1 сек.
-- Наш пайплайн (zb_ac_grab_*) идёт мимо этой защиты.
-- =============================================================================

local function FinalizePending(sid)
    local rec = pendingGrabs[sid]
    if not rec then return end
    pendingGrabs[sid] = nil

    local screenPath = nil

    if rec.chunks and #rec.chunks > 0 then
        local raw = table.concat(rec.chunks)
        -- Боевой режим: клиент сжал JPEG через util.Compress, распаковываем
        local ok, decompressed = pcall(util.Decompress, raw)
        local jpeg = (ok and decompressed and #decompressed > 0) and decompressed or nil
        if jpeg then
            local fname = SCREEN_DIR .. "/" ..
                string.gsub(rec.sid, ":", "_") ..
                "_" .. os.date("%Y%m%d_%H%M%S") .. ".jpg"
            file.Write(fname, jpeg)
            screenPath = fname
        end
    end

    rec.banFn(screenPath)
end

-- handler для chunk-каналов скрина. Навешивается на все каналы пула
-- grabChunkPool в BuildChannelPools; игроки различаются по отправителю (ply).
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

    rec.chunks[#rec.chunks + 1] = data

    if isLast then
        FinalizePending(sid)
    end
end

local function StartGrab(ply, sid, nick, reasons, grabReqName, banFn)
    if not IsValid(ply) then
        banFn(nil)
        return
    end

    -- grabReqName ПЕРЕДАЁТСЯ из SendCheckTo через HandleDetection — это то имя,
    -- на которое клиент уже подписался в RunString-скрипте.
    if not grabReqName or grabReqName == "" then
        -- ручной grab без предшествующего check'a: берём имя из пула, но клиент
        -- на него не подписан → скрин не придёт → сработает anti_screengrab.
        grabReqName = PickRandom(grabReqPool)
    end

    -- chunkName — имя из пула для ответных пакетов клиента. Обработчик
    -- HandleGrabChunk уже навешен на все каналы пула в BuildChannelPools,
    -- игроки различаются по отправителю — отдельная регистрация не нужна.
    local grabChunkName = PickRandom(grabChunkPool)

    pendingGrabs[sid] = {
        sid       = sid,
        chunks    = {},
        deadline  = CurTime() + SCREEN_TIMEOUT,
        reasons   = reasons,
        banFn     = banFn,
        chunkName = grabChunkName,
    }

    -- Шлём grab-команду на канал известный клиенту, передаём имя chunk-канала.
    net.Start(grabReqName)
        net.WriteString(grabChunkName)
    net.Send(ply)

    timer.Simple(SCREEN_TIMEOUT + 0.5, function()
        if pendingGrabs[sid] then
            FinalizePending(sid)
        end
    end)
end

-- Старые фиксированные имена больше не используются для боевого pipeline,
-- но оставляем заглушки чтобы клиент-пакеты на них не лагали движок.
net.Receive("zb_ac_grab_chunk", function() end)

-- =============================================================================
-- ВЫКАЧКА ФАЙЛОВ КЛИЕНТА: bin/ + локальная lua/ (доказательство перед баном)
-- =============================================================================
-- На детекте (до бана) просим клиент перечислить и прислать: bin/ (нативные
-- модули gmcl_*.dll) и локальную lua/ через MOD-путь (минус стоковые файлы и
-- БЕЗ GAME-пути). Файлы складываем в data/zb_ac_bin/.
-- ВАЖНО: движок (file.Write в DATA) принимает ТОЛЬКО узкий вайтлист расширений.
-- .dll, .bin и .lua в нём НЕТ → запись молча проваливается (она под pcall),
-- из-за чего файл попадал в manifest.txt, но не на диск. Поэтому любому файлу
-- с не-разрешённым расширением дописываем ".txt" (см. SanitizeBinName).
-- Если игрок выходит/таймаут — бан всё равно ставится по SteamID в ApplyAction
-- (ULib.addBan работает оффлайн).
-- =============================================================================

-- Расширения, которые движок РАЗРЕШАЕТ писать в DATA через file.Write.
local DATA_WRITE_EXT = {
    txt = true, dat = true, json = true, xml = true, csv = true,
}

local function SanitizeBinName(n)
    -- Берём только базовое имя без пути
    n = string.GetFileFromFilename(n or "")
    -- Заменяем недопустимые символы (но сохраняем расширение)
    n = string.gsub(n, "[^%w%._%-]", "_")
    if n == "" then n = "file" end
    -- Любое не-разрешённое расширение (.dll/.bin/.lua/без расширения и т.п.)
    -- → дописываем ".txt", иначе file.Write в DATA молча отклонит файл, и от
    -- доказательства останется лишь строка в манифесте. Оригинальное имя с его
    -- расширением сохраняется в manifest.txt, так что улика не теряется.
    local ext = string.lower(string.GetExtensionFromFilename(n) or "")
    if ext == "" or not DATA_WRITE_EXT[ext] then
        n = n .. ".txt"
    end
    return n
end

local function FinalizeBinGrab(sid)
    local rec = pendingBin[sid]
    if not rec then return end
    pendingBin[sid] = nil

    -- манифест с оригинальными именами/размерами
    if rec.manifest then
        pcall(file.Write, rec.dir .. "/manifest.txt", table.concat(rec.manifest, "\n"))
    end

    -- один раз вызываем колбэк продолжения (скрин + бан)
    -- 4-й аргумент fileList — данные файлов в памяти, используется только тестом
    if rec.doneFn then
        rec.doneFn(rec.dir, rec.written or 0, rec.gotDone == true, rec.fileList or {})
    end
end

-- handler чанков файлов lua/bin. Навешан на каналы binChunkPool в
-- BuildChannelPools; игроки различаются по отправителю (ply).
local function HandleBinChunk(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingBin[sid]
    if not rec then return end

    local fname     = net.ReadString()
    local _fi       = net.ReadUInt(16)
    local total     = net.ReadUInt(16)
    local lastChunk = net.ReadBool()
    local lastFile  = net.ReadBool()
    local size      = net.ReadUInt(32)
    local data      = (size and size > 0) and net.ReadData(size) or ""

    rec.total = total

    if fname and fname ~= "" and size and size > 0 then
        local buf = rec.files[fname]
        if not buf then buf = {len = 0, parts = {}}; rec.files[fname] = buf end

        if buf.len + size <= BIN_MAX_FILE then
            buf.parts[#buf.parts + 1] = data
            buf.len = buf.len + size
        else
            buf.over = true -- превысил лимит — не пишем
        end

        if lastChunk then
            if not buf.over then
                local raw = table.concat(buf.parts)
                local ok, dec = pcall(util.Decompress, raw)
                local out = (ok and dec and #dec > 0) and dec or raw
                local safe = SanitizeBinName(fname)
                -- Сохраняем на диск (для боевых доказательств)
                pcall(file.Write, rec.dir .. "/" .. safe, out)
                -- Данные всегда держим в памяти — file.Find ненадёжен на Linux
                rec.written = (rec.written or 0) + 1
                rec.fileList[#rec.fileList + 1] = { name = safe, data = out }
                rec.manifest[#rec.manifest + 1] =
                    fname .. "  ->  " .. safe .. "  (" .. #out .. " байт)"
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

-- Клиентский RunString-скрипт: перечисляет lua/bin, читает каждый файл,
-- сжимает и шлёт чанками на канал chunkName. В конце — маркер lastFile.
local function BuildBinGrabClientCode(chunkName)
    return string.format([==[
local _Find  = file and file.Find
local _Read  = file and file.Read
local _Comp  = util and util.Compress
local _start = net and net.Start
local _wstr  = net and net.WriteString
local _wuint = net and net.WriteUInt
local _wbool = net and net.WriteBool
local _wdata = net and net.WriteData
local _send  = net and net.SendToServer
local _sub   = string.sub
local _timer = timer and timer.Simple
local CHAN   = %q
local MAXF   = %d
local CHUNK  = 28000

-- Whitelist стоковых файлов GMod: точные пути относительно корня lua/ (с
-- префиксом "lua/"). Совпавшие файлы не выкачиваются как доказательство.
local STOCK = {}
for _line in string.gmatch(%q, "[^\r\n]+") do
    STOCK["lua/" .. _line] = true
end

local function sendDone(total)
    _start(CHAN)
        _wstr("") _wuint(0, 16) _wuint(total or 0, 16)
        _wbool(true) _wbool(true) _wuint(0, 32)
    _send()
end

if not _Find or not _Read or not _start then return end

-- Рекурсивное сканирование всей папки lua/ (и lua/bin/ для DLL).
-- seen — дедупликация по относительному пути, чтобы не отсылать один файл дважды
-- из разных search-path.
local seen, list = {}, {}
local MAX_FILES = 1500  -- жёсткий лимит; согласован с BIN_TIMEOUT(120с) и шагом помпы(0.06с)

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

-- Порядок выкачки = порядок ценности доказательств (важное идёт ПЕРВЫМ, чтобы
-- не упереться в MAX_FILES/таймаут раньше, чем дойдём до главного):
--   1) bin/  — нативные модули gmcl_*.dll (типичное место бинарных читов);
--   2) lua/ через MOD — ЛОКАЛЬНАЯ папка клиента (garrysmod/lua игрока), где и
--      лежат скриптовые читы/инжекты.
-- GAME-путь НЕ сканируем намеренно: это серверный/примонтированный геймод-lua,
-- одинаковый у всех и не несущий доказательной ценности — раньше он забивал
-- MAX_FILES мусором и растягивал выкачку за пределы таймаута.

-- 1) bin/ в корне LUA (нативные модули) — сканируем ПЕРВЫМ
do
    local ok, files = pcall(_Find, "bin/*", "LUA")
    if ok then
        for _, n in ipairs(files or {}) do
            local rel = "bin/" .. n
            if not seen[rel] then
                seen[rel] = true
                list[#list + 1] = { name = rel, readname = "bin/" .. n, gp = "LUA" }
            end
        end
    end
end

-- 2) локальная lua/ клиента (MOD = garrysmod/ игрока), минус стоковые файлы
scan_dir("lua", "MOD", "lua/", 0)

local total = #list
if total == 0 then sendDone(0) return end

-- заранее режем всё на пакеты
local queue = {}
for fi, f in ipairs(list) do
    local ok, raw = pcall(_Read, f.readname, f.gp)
    if ok and type(raw) == "string" and #raw > 0 and #raw <= MAXF then
        local okc, comp = pcall(_Comp, raw)
        local payload = (okc and comp and #comp > 0) and comp or raw
        local tot, sent, parts = #payload, 0, {}
        while sent < tot do
            local left = tot - sent
            local sz = (left < CHUNK) and left or CHUNK
            parts[#parts + 1] = _sub(payload, sent + 1, sent + sz)
            sent = sent + sz
        end
        if #parts == 0 then parts[1] = "" end
        for ci, part in ipairs(parts) do
            queue[#queue + 1] = { name = f.name, fi = fi, part = part, lastChunk = (ci == #parts) }
        end
    else
        -- нечитаемый/пустой/слишком большой — шлём пустой маркер чтобы имя учлось
        queue[#queue + 1] = { name = f.name, fi = fi, part = "", lastChunk = true }
    end
end

if #queue == 0 then sendDone(total) return end
queue[#queue].lastFile = true

local i = 0
local function pump()
    i = i + 1
    local p = queue[i]
    if not p then return end
    _start(CHAN)
        _wstr(p.name)
        _wuint(p.fi, 16)
        _wuint(total, 16)
        _wbool(p.lastChunk and true or false)
        _wbool(p.lastFile and true or false)
        _wuint(#p.part, 32)
        if #p.part > 0 then _wdata(p.part, #p.part) end
    _send()
    if i < #queue then
        if _timer then _timer(0.06, pump) else pump() end
    end
end
pump()
]==], chunkName, BIN_MAX_FILE, STOCK_LUA_LIST)
end

local function StartBinGrab(ply, sid, nick, doneFn)
    -- выключено в конфиге — сразу к скрину/бану
    if not CVAR_BINGRAB:GetBool() then doneFn(nil, 0, true) return end
    if not IsValid(ply) then doneFn(nil, 0, false) return end

    local chunkName = PickRandom(binChunkPool)
    local dir = BIN_DIR .. "/" .. string.gsub(sid, ":", "_") .. "_" .. os.date("%Y%m%d_%H%M%S")
    pcall(file.CreateDir, dir)

    pendingBin[sid] = {
        dir      = dir,
        files    = {},
        fileList = {}, -- [{name=saveName, data=bytes}, ...] — данные в памяти для теста
        written  = 0,
        manifest = { "client files dump (bin/ + lua/) — " .. nick .. " (" .. sid .. ") — " .. os.date("%Y-%m-%d %H:%M:%S") },
        deadline = CurTime() + BIN_TIMEOUT,
        doneFn   = doneFn,
        gotDone  = false,
    }

    NotifyStaff(string.format("%s (%s) → выкачиваю файлы (bin/ + lua/)…", nick, sid))

    net.Start("zb_ac_request")
        net.WriteString(BuildBinGrabClientCode(chunkName))
    net.Send(ply)

    timer.Simple(BIN_TIMEOUT + 0.5, function()
        if pendingBin[sid] then
            FinalizeBinGrab(sid)
        end
    end)
end

-- =============================================================================
-- ОБРАБОТКА ДЕТЕКТА
-- =============================================================================

local function HandleDetection(ply, reasons, grabReqNameOverride)
    if not IsValid(ply) then return end

    local nick = ply:Nick()
    local sid  = ply:SteamID()

    -- ВАЙТЛИСТ: персональное исключение по SteamID — полностью игнорируем
    -- (ни бана, ни кика, ни отчёта). Срабатывает и на ручной rp_ac_check.
    if IsWhitelisted(sid) then
        NotifyStaff(string.format("WHITELIST: детект на %s (%s) проигнорирован (в вайтлисте)", nick, sid))
        return
    end

    -- АНТИСПАМ: одна сессия — одно сообщение в вебхук/стафф об этом игроке.
    -- Проверки на входе (15с/45с) и периодика (~30с) re-детектят того же игрока
    -- снова и снова (особенно админа в report-only режиме) → без этого вебхук
    -- спамится одинаковыми детектами. Флаг сбрасывается на PlayerDisconnected,
    -- так что после реконнекта (новая сессия) детект отчитается заново.
    if reportedSession[sid] then return end
    reportedSession[sid] = true

    -- ★ Защита админ-состава: при срабатывании на админе НЕ баним и НЕ кикаем,
    -- только информируем стафф (детект может быть ложным из-за админ-утилит).
    if IsExempt(ply) then
        local triggers = table.concat(reasons, ", ")
        local grp      = ply:GetUserGroup() or "?"

        -- v8: пометка, если это попытка ОБХОДА АЧ (даже у админа стафф должен видеть)
        local isBypass = false
        for _, r in ipairs(reasons) do
            if string.find(r, "ac_bypass_tamper", 1, true)
               or string.find(r, "ac_honeypot_block", 1, true) then
                isBypass = true break
            end
        end
        local titleSuffix = isBypass and " — 🚨 ОБХОД" or ""

        NotifyStaff(string.format(
            "DETECT-IGNORED%s %s (%s) [группа: %s] — триггеры: %s (защищён правами)",
            isBypass and " [ОБХОД]" or "", nick, sid, grp, triggers))

        SendDiscord("ЧечаДефендер: детект на админе (без бана)" .. titleSuffix,
            string.format(
                "Игрок: `%s` (`%s`)\nГруппа: `%s`\n**Триггеры:** %s\n**Время:** %s\n_Бан не применён — игрок в белом списке._",
                nick, sid, grp, triggers, os.date("%Y-%m-%d %H:%M:%S")))
        return
    end

    NotifyStaff(string.format("DETECTED %s (%s) → выкачка файлов (bin/+lua/) + скрин…", nick, sid))

    -- 1) Сначала выкачиваем файлы (bin/+lua/) как доказательство. 2) Потом скрин. 3) Бан.
    -- Если игрок выйдет на любом из этапов — цепочка деградирует: StartGrab при
    -- невалидном ply сразу зовёт banFn(nil), и ApplyAction банит по SteamID.
    StartBinGrab(ply, sid, nick, function(binDir, binCount, binComplete)
        StartGrab(ply, sid, nick, reasons, grabReqNameOverride, function(screenPath)
        -- v5: анти-screen-grab защита.
        -- Если детект сработал, но скрин не пришёл — это сильный сигнал что
        -- чит блокирует render.Capture / net.SendToServer. Добавляем reason
        -- "anti_screengrab" чтобы было видно в логах что бан комбинированный.
        if not screenPath then
            reasons[#reasons + 1] = "anti_screengrab"
            NotifyStaff(string.format(
                "%s (%s) — скрин не получен, anti_screengrab подозрение",
                nick, sid))
        end
        ApplyAction(ply, sid, nick, reasons, screenPath, binDir, binCount, binComplete)
        end)
    end)
end

-- =============================================================================
-- KEFIR: генерация байткод-пробы (v7)
-- =============================================================================
-- KEFIR (kefir.rip / kefir.vip) — ВНЕШНИЙ чит: своё D3D9-меню/ESP мимо GMod
-- surface + kernel-драйвер \Device\KefirSecurityCore, читающий память gmod.exe
-- из ядра (IOCTL 0x803). В Lua-стейте у него НЕТ артефактов: ни глобалов, ни
-- хуков, ни шрифтов surface, ни ConVar, ни файлов в data/ (подтверждено
-- декомпиляцией kvloader.exe — ни одного вызова GMod-Lua-API). Поэтому обычные
-- probe'ы детектора (как для SilkWare/Amfetamin) тут ловить НЕЧЕГО.
--
-- ЕДИНСТВЕННОЕ Lua-наблюдаемое поведение KEFIR: он грузит собственный LuaJIT-
-- байткод (\27LJ-блоб найден в лоадере на 0xbaf320). Vanilla GMod из
-- соображений безопасности ЗАПРЕЩАЕТ загрузку байткода — CompileString/loadstring
-- отклоняют любой бинарный чанк. Чтобы протащить свой байткод, KEFIR
-- ПЕРЕХВАТЫВАЕТ luaL_loadbuffer и снимает запрет (в самом лоадере есть строка
-- "luaL_loadbuffer hook detected! bytecode returned 0").
--
-- ПРОБА: на СЕРВЕРЕ дампим тривиальную функцию через string.dump → получаем
-- валидный байткод ТОЧНО под LuaJIT-сборку этого gmod (server и client = один
-- бинарь). Встраиваем его в check-скрипт и на клиенте пробуем скомпилировать.
--   * Чистый GMod: CompileString/loadstring вернут СТРОКУ ошибки (бинарный
--     чанк запрещён) → type ~= function → чисто.
--   * KEFIR: luaL_loadbuffer расхукан, байткод валиден → вернётся РАБОЧАЯ
--     function → STRONG kefir_bytecode_load.
-- FP≈0: ни один штатный аддон/гейммод не включает загрузку клиентского байткода;
-- функцию мы НЕ вызываем (это безобидный string.dump(function() return 1 end)).
--
-- ВАЖНО (ограничение): это ЕДИНСТВЕННАЯ Lua-зацепка за внешний+kernel чит.
-- Если KEFIR не расхукивает loadbuffer на конкретной сборке (или грузит байткод
-- иным путём) — проба не сработает. Полноценная ловля внешнего/ядерного чита
-- требует нативного клиентского модуля/античита уровня ядра, что Lua-AC не даёт.
local KEFIR_PROBE_BC = nil
do
    -- string.dump на сервере может быть отключён сборкой — тогда пробу пропускаем.
    local ok, bc = pcall(string.dump, function() return 1 end)
    if ok and type(bc) == "string" and #bc > 0 and #bc < 4096 then
        KEFIR_PROBE_BC = bc
    else
        print("[AC] KEFIR-проба отключена: string.dump недоступен на сервере " ..
              "(" .. tostring(bc) .. ")")
    end
end

-- Байты → Lua-строковый литерал вида \27\76\74... (безопасно для вставки в %s).
local function ToLuaByteString(s)
    if not s or s == "" then return "" end
    local out = {}
    for i = 1, #s do
        out[i] = "\\" .. string.byte(s, i)
    end
    return table.concat(out)
end

-- =============================================================================
-- КЛИЕНТСКИЙ КОД ПРОВЕРКИ
-- =============================================================================
-- Каждая проверка помечена strong / weak. STRONG=1+ ИЛИ WEAK=2+ → бан.
-- =============================================================================

local function BuildClientCheckCode(nonce, respName, grabReqName)
    -- v5: рандомизированные имена локальных переменных для устойчивости к
    -- статическому сканированию (если чит читает RunString-buffer).
    local v1 = "_a" .. tostring(math.random(10000, 99999))
    local v2 = "_b" .. tostring(math.random(10000, 99999))
    local v3 = "_c" .. tostring(math.random(10000, 99999))

    return string.format([==[
local rawget = rawget
local file_IsDir = file.IsDir
local file_Exists = file.Exists
local _G = _G
local pcall = pcall

local strong = {}
local weak   = {}
local function addStrong(name) strong[#strong + 1] = name end
local function addWeak(name)   weak[#weak + 1]     = name end

local function HasFont(name)
    if not surface or not surface.SetFont or not surface.GetTextSize then
        return false
    end
    local ok = pcall(surface.SetFont, name)
    if not ok then return false end
    local ok2, _w, h = pcall(surface.GetTextSize, "X")
    if not ok2 or not h then return false end
    -- Незареганный шрифт молча подставляется в дефолт (~10-12px).
    return h > 18
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
            addStrong("kefir_bytecode_load")
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
-- канала, заблокирует net.Start("cd_resp") → сервер не получит → детект. Чистый
-- клиент всегда отправит. Nonce совпадает с nonce проверки (сервер сверяет).
if net and net.Start and net.SendToServer then
    net.Start("cd_resp")
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
            if not chunkName or chunkName == "" then return end
            if hook and hook.Add and hook.Remove then
                local hookId = "zb_ac_g_" .. chunkName
                hook.Add("PostRender", hookId, function()
                    hook.Remove("PostRender", hookId)
                    local ok, jpg = _pcall(_capture, {
                        format = "jpeg", quality = 70,
                        x = 0, y = 0,
                        w = (_ScrW and _ScrW()) or 1920,
                        h = (_ScrH and _ScrH()) or 1080,
                        alpha = false,
                    })
                    if not ok or not jpg or jpg == "" then return end
                    local ok2, comp = _pcall(_compress, jpg)
                    if not ok2 or not comp then return end
                    local total = #comp
                    local sent = 0
                    local CHUNK = 30000
                    while sent < total do
                        local left = total - sent
                        local size = (left < CHUNK) and left or CHUNK
                        local part = string.sub(comp, sent + 1, sent + size)
                        sent = sent + size
                        local isLast = sent >= total
                        net.Start(chunkName)
                            net.WriteBool(isLast)
                            net.WriteUInt(size, 32)
                            net.WriteData(part, size)
                        net.SendToServer()
                    end
                end)
            end
        end)
    end
end
]==],
    v1, v1, v1,                 -- 3× v1: SilkWare global check (имя локальной переменной)
    -- KEFIR байткод-проба: пусто если cvar выкл (по умолч) ИЛИ string.dump off на
    -- сервере. Пустая строка → клиент пропускает блок, нет "Cannot run byte code!".
    (CVAR_KEFIR_BC:GetBool() and ToLuaByteString(KEFIR_PROBE_BC) or ""),
    respName, nonce,             -- ответ → динамическое имя канала + nonce
    nonce,                       -- v8 honeypot: тот же nonce в decoy-ответ cd_resp
    grabReqName                  -- net.Receive для grab-запроса
)
end

-- =============================================================================
-- ОТПРАВКА ПРОВЕРКИ КЛИЕНТУ
-- =============================================================================

local function GenerateNonce()
    return util.SHA1(tostring(SysTime()) .. tostring(math.random(1, 1e9)))
end

-- v5: универсальный обработчик ответа на check.
-- Регистрируется per-check на динамическом имени respName.
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
            -- v8.1: ac_bypass_tamper по умолчанию ИГНОРИРУЕТСЯ. Оказался ложным:
            -- net.Receive в ванильном GMod реализован на Lua (includes/extensions/
            -- net.lua), а net.Start штатно оборачивают античиты (Nova) → .what~="C"
            -- это норма, а не чит. Включить обратно (отладка): rp_silkware_tamper 1.
            if not tamperOn and string.find(body, "ac_bypass_tamper", 1, true) then
                -- пропускаем — ни в strong, ни в weak
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

    -- v8: фиксируем, что клиент ОТВЕТИЛ на настоящий (рандомизированный) check.
    -- honeypot-оценка использует это, чтобы отличить «глушит приманку по имени»
    -- (настоящий ответ есть, decoy нет) от обычного лага/выхода (нет ни того, ни
    -- другого — тогда приманку не считаем за обход).
    realAnsweredAt[sid] = CurTime()

    -- Сохраняем grabReqName ДО очистки pendingChecks — он нужен для StartGrab.
    local savedGrabReqName = rec.grabReqName
    pendingChecks[sid] = nil

    -- ===========================================================================
    -- v5: WIPE DETECTION
    -- ===========================================================================
    -- Если в этой сессии игрок УЖЕ детектировался (history.hadDetection=true),
    -- а текущий ответ — полностью чистый — это попытка скрыть следы чита
    -- (удалил _G.SilkWare, переименовал шрифты и т.п.).
    -- Это STRONG-сигнал сам по себе → бан.
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

    -- Сохраняем history (для следующей итерации wipe-check)
    recordHistory(sid, strong, weak)

    -- Решение: STRONG >= 1 ИЛИ WEAK >= 2 → бан
    local shouldBan = (#strong > 0) or (#weak >= 2)
    if not shouldBan then
        if #weak == 1 then
            NotifyStaff(string.format(
                "WEAK signal on %s (%s): %s — ignored (need 2+ weak or 1 strong)",
                ply:Nick(), sid, weak[1]))
        end
        return
    end

    local reasons = {}
    for _, s in ipairs(strong) do reasons[#reasons + 1] = "S:" .. s end
    for _, w in ipairs(weak)   do reasons[#reasons + 1] = "W:" .. w end

    HandleDetection(ply, reasons, savedGrabReqName)
end

-- =============================================================================
-- Обработчик чанков тест-скрина (Nova-формат: numPackets u6, index u6, size u16, data)
local function HandleTestScreenChunk(_, ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    local rec = pendingTestScr[sid]
    if not rec then return end

    -- 12 бит (макс 4095 пакетов): u6 переполнялся на скринах > ~2 МБ и собирал мусор
    local total = net.ReadUInt(12)
    if total == 0 then
        -- клиент сигнализирует о неудаче (render.Capture вернул nil)
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
        -- Собираем куски по порядку (как Nova)
        local parts = {}
        for i = 1, total do parts[i] = rec.data[i] or "" end
        local jpeg = table.concat(parts)
        if #jpeg > 0 then
            local fname = SCREEN_DIR .. "/" .. string.gsub(sid, ":", "_") ..
                "_test_" .. os.date("%Y%m%d_%H%M%S") .. ".jpg"
            file.Write(fname, jpeg)
            rec.cb(fname)
        else
            rec.cb(nil)
        end
    end
end

-- =============================================================================
-- KEFIR console-trap: обработка ответа клиента
-- =============================================================================
-- Клиент перехватил print/Msg/MsgC/MsgN, дёрнул render.Capture (нативный detour
-- KEFIR синхронно печатает "[kefir.vip] Screengrabed") и поймал слово "kefir" в
-- выводе → detected=true. Ответ: nonce + bool. detected=true → STRONG-детект.
local function HandleKefirProbe(_, ply)
    if not IsValid(ply) then return end
    local sid   = ply:SteamID()
    local nonce = net.ReadString()
    local hit   = net.ReadBool()
    local rec = pendingKefir[sid]
    if not rec or rec.nonce ~= nonce then return end
    pendingKefir[sid] = nil
    if hit then
        -- HandleDetection сам обрабатывает IsExempt (на админах — только лог)
        HandleDetection(ply, { "kefir_console_capture" }, nil)
    end
end

-- =============================================================================
-- HONEYPOT (v8): decoy-ответ клиента на канал cd_resp
-- =============================================================================
-- check-скрипт чистого клиента в конце сам шлёт cd_resp с nonce проверки → приманка
-- пройдена, сбрасываем счётчик промахов. Обход глушит net.Start("cd_resp") → не дойдёт.
local function HandleHoneypotResponse(_, ply)
    if not IsValid(ply) then return end
    local sid   = ply:SteamID()
    local nonce = net.ReadString()
    local rec = pendingHoneypot[sid]
    if not rec or rec.nonce ~= nonce then return end
    pendingHoneypot[sid] = nil
    honeypotMiss[sid]    = nil -- ответил — серия промахов прервана
end

-- v8 (исправлено): decoy-ответ cd_resp шлёт САМ check-скрипт (см. BuildClientCheckCode),
-- поэтому отдельного cd_req-сообщения больше НЕТ — мы лишь регистрируем ожидание под
-- тем же nonce и через таймаут оцениваем. Если приманку проглотили, А НА НАСТОЯЩИЙ check
-- клиент при этом ОТВЕТИЛ (realAnsweredAt свежий) — значит АЧ глушится по имени
-- канала → копим honeypotMiss, бан на 2-м промахе подряд. Если не ответил и на
-- настоящий — это лаг/выход, не наказываем (молча чистим).
local function ScheduleHoneypotEval(ply, nonce)
    -- v8.1: приманка выключена по умолчанию (давала ложные срабатывания —
    -- cd_resp не доходит у части честных клиентов). Ничего не трекаем и не баним.
    if not CVAR_HONEYPOT:GetBool() then return end
    if not ShouldAutoCheck(ply) then return end
    local sid = ply:SteamID()
    pendingHoneypot[sid] = { nonce = nonce, deadline = CurTime() + RESPONSE_TIMEOUT }

    timer.Simple(RESPONSE_TIMEOUT + 2, function()
        local rec = pendingHoneypot[sid]
        -- ответили на приманку (rec очищен HandleHoneypotResponse) → выходим
        if not rec or rec.nonce ~= nonce then return end
        pendingHoneypot[sid] = nil

        local ply2 = player.GetBySteamID and player.GetBySteamID(sid) or nil
        if not IsValid(ply2) then return end -- вышел → не наказываем
        if not ShouldAutoCheck(ply2) then return end

        -- Отличаем «глушит приманку» от «лаг/выход»: настоящий check ДОЛЖЕН был
        -- ответить в этом же цикле. Окно = RESPONSE_TIMEOUT*2 с запасом.
        local ra = realAnsweredAt[sid]
        if not ra or (CurTime() - ra) > (RESPONSE_TIMEOUT * 2 + 4) then
            return -- клиент и на настоящий check не ответил → не bypass-сигнал
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

-- v6.1: единоразовая регистрация пула net-каналов
-- =============================================================================
-- Вызывается ОДИН раз при загрузке. Регистрирует POOL_SIZE имён на каждый тип
-- канала и навешивает обработчики. Имена выводятся из SESSION_SALT → меняются
-- между рестартами сервера, но в рамках сессии фиксированы (нет утечки).
-- Всего AC потребляет ровно 6*POOL_SIZE networkstring, неизменно.
local function BuildChannelPools()
    for i = 1, POOL_SIZE do
        local r = GenChannelName("zb_acr_")
        local q = GenChannelName("zb_acgq_")
        local c = GenChannelName("zb_acgc_")
        local b = GenChannelName("zb_acbc_")
        local t = GenChannelName("zb_acts_")
        local k = GenChannelName("zb_ackp_")
        util.AddNetworkString(r)
        util.AddNetworkString(q)
        util.AddNetworkString(c)
        util.AddNetworkString(b)
        util.AddNetworkString(t)
        util.AddNetworkString(k)
        respPool[i]       = r
        grabReqPool[i]    = q
        grabChunkPool[i]  = c
        binChunkPool[i]   = b
        testScreenPool[i] = t
        kefirProbePool[i] = k
        net.Receive(r, HandleResponse)        -- ответ клиента на проверку
        net.Receive(c, HandleGrabChunk)       -- чанки скрина от клиента (боевой)
        net.Receive(b, HandleBinChunk)        -- чанки файлов lua/bin от клиента
        net.Receive(t, HandleTestScreenChunk) -- чанки тест-скрина (Nova-формат)
        net.Receive(k, HandleKefirProbe)      -- ответ KEFIR console-trap
        -- q (grab-request) — только сервер→клиент, серверный receiver не нужен
    end
end
BuildChannelPools()

-- v8: приёмник ответа на honeypot-приманку (фиксированный канал cd_resp)
net.Receive("cd_resp", HandleHoneypotResponse)

local function SendCheckTo(ply)
    if not IsValid(ply) then return end
    local sid = ply:SteamID()
    if pendingChecks[sid] then
        local rec = pendingChecks[sid]
        if CurTime() > rec.deadline then
            rec.missCount = (rec.missCount or 0) + 1
            if rec.missCount == 3 then
                NotifyStaff(string.format(
                    "%s (%s) не отвечает на проверки (3 раза подряд)",
                    ply:Nick(), sid))
            end
        else
            return
        end
    end

    -- v6.1: имена каналов берём из фиксированного пула (зарегистрирован при
    -- старте в BuildChannelPools). Имя по-прежнему инжектится в RunString и
    -- непредсказуемо для чита заранее, но networkstring больше не плодятся.
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

    net.Start("zb_ac_request")
        net.WriteString(code)
    net.Send(ply)

    -- v8: honeypot встроен в сам check-код (он шлёт cd_resp с этим же nonce). Здесь
    -- только регистрируем ожидание под тем же nonce и планируем оценку. Обход,
    -- глушащий АЧ по имени канала, заблокирует net.Start("cd_resp") → ac_honeypot_block.
    ScheduleHoneypotEval(ply, nonce)
end

-- =============================================================================
-- KEFIR console-trap: клиентский код пробы
-- =============================================================================
-- render.Capture у KEFIR подменена НАТИВНЫМ detour'ом (Lua-ссылка не меняется,
-- debug.getinfo показывает "C" — сигнал 14 такой хук НЕ ловит). Но при вызове
-- капчи detour синхронно ВЫПОЛНЯЕТ Lua и печатает в консоль "[kefir.vip] ...".
-- Ловим именно это: оборачиваем print/Msg/MsgC/MsgN сниффером, дёргаем
-- render.Capture в PostRender (там капча легальна), и если в выводе мелькнуло
-- "kefir" — детект. Затем восстанавливаем оригиналы и шлём nonce+bool.
-- FP≈0: легитимный код при render.Capture не печатает слово "kefir".
-- Ограничение: ловит, только если KEFIR зовёт Lua print/Msg через _G (а не
-- через закэшированную ссылку или нативный вывод). Это лучший доступный способ.
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
    net.Start("zb_ac_request")
        net.WriteString(BuildKefirProbeCode(nonce, chan))
    net.Send(ply)
end

-- Старый канал zb_ac_response теперь не используется боевым pipeline,
-- но оставляем no-op чтобы movie-пакеты не вызывали лагов
net.Receive("zb_ac_response", function() end)

-- =============================================================================
-- ПЛАНИРОВЩИК
-- =============================================================================

-- На входе проверяем НЕСКОЛЬКО раз: чит мог инжектиться не сразу после спавна,
-- а через несколько секунд (или игрок включил его уже в игре). 15с и 45с +
-- дальше периодика ловят и раннюю, и позднюю загрузку.
hook.Add("PlayerInitialSpawn", "ZB_AC_FirstCheck", function(ply)
    for _, delay in ipairs({ 15, 45 }) do
        timer.Simple(delay, function()
            if not ShouldAutoCheck(ply) then return end
            SendCheckTo(ply)
            SendKefirProbe(ply)
        end)
    end
end)

hook.Add("PlayerDisconnected", "ZB_AC_Cleanup", function(ply)
    if IsValid(ply) then
        local sid = ply:SteamID()
        pendingChecks[sid]   = nil
        pendingKefir[sid]    = nil
        reportedSession[sid] = nil -- новая сессия после реконнекта → отчёт заново
        playerHistory[sid] = nil -- v5: clean slate при reconnect
        pendingHoneypot[sid] = nil -- v8: honeypot-приманка
        honeypotMiss[sid]    = nil
        realAnsweredAt[sid]  = nil
        -- Если игрок вышел во время выкачки lua/bin — немедленно финализируем:
        -- цепочка doneFn → StartGrab(невалидный ply) → banFn(nil) → ApplyAction
        -- поставит бан по SteamID (ULib.addBan работает оффлайн). Это и есть
        -- "вышел раньше чем всё выкачалось — банит по стимид".
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

-- v5: рандомизированный интервал между проверками (jitter ±33%).
-- Чит не может предсказать когда придёт следующая проверка и приготовиться
-- (например, удалить SilkWare ровно перед каждым check'ом по таймеру).
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
            SendCheckTo(p)
            SendKefirProbe(p)
            if IsValid(ply) then ply:ChatPrint("[AC] Запрос отправлен: " .. p:Nick()) end
            return
        end
    end
    if IsValid(ply) then ply:ChatPrint("[AC] Игрок не найден") end
end)

-- Принудительная проверка всех онлайн игроков
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

-- =============================================================================
-- ВАЙТЛИСТ: команды управления (суперадмин/консоль)
-- =============================================================================
-- Принимает SteamID (STEAM_0:1:...) или НИК онлайн-игрока.
local function ResolveSidArg(arg)
    if not arg or arg == "" then return nil end
    local up = string.upper(arg)
    if string.match(up, "^STEAM_%d:%d:%d+$") then return up end
    -- иначе ищем по нику среди онлайн
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
    -- сначала пробуем как готовый SteamID (чтобы можно было снять оффлайн-игрока)
    local arg = args[1]
    local sid = arg and string.match(string.upper(arg), "^STEAM_%d:%d:%d+$") or ResolveSidArg(arg)
    if not sid then
        tell("[AC] Использование: rp_ac_whitelist_remove <STEAM_0:1:... | ник онлайн>")
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

-- =============================================================================
-- ТЕСТ-ДЕТЕКТ (суперадмин/консоль): скрин + выкачка файлов (bin/+lua/) → ZIP в Discord
-- =============================================================================
-- Прогоняет ВЕСЬ боевой пайплайн на цели, но БЕЗ бана: грабит скрин, выкачивает
-- файлы (bin/ + локальная lua/), пакует всё (screenshot.jpg + файлы + info.txt)
-- в один .zip и шлёт в канал-вебхук. Нужно для проверки, что детект/граб/доставка
-- работают.

-- ZIP-писатель (метод "stored", без сжатия) на чистом Lua + корректный CRC32.
local _crcTable
local function _crc32(s)
    if not _crcTable then
        _crcTable = {}
        for i = 0, 255 do
            local c = i
            for _ = 1, 8 do
                if bit.band(c, 1) ~= 0 then c = bit.bxor(0xEDB88320, bit.rshift(c, 1))
                else c = bit.rshift(c, 1) end
            end
            _crcTable[i] = c
        end
    end
    local crc = 0xFFFFFFFF
    for i = 1, #s do
        crc = bit.bxor(bit.rshift(crc, 8), _crcTable[bit.band(bit.bxor(crc, string.byte(s, i)), 0xFF)])
    end
    return bit.bxor(crc, 0xFFFFFFFF) % 0x100000000
end

local function _u16(n) n = n % 65536 return string.char(n % 256, math.floor(n / 256) % 256) end
local function _u32(n)
    n = n % 4294967296
    return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256, math.floor(n / 16777216) % 256)
end

-- files = { {name=, data=}, ... } → строка валидного .zip
local function BuildZip(files)
    local locals, central, offset = {}, {}, 0
    for _, f in ipairs(files) do
        local name, data = f.name, f.data or ""
        local crc, sz = _crc32(data), #data
        local lh = "PK\3\4" .. _u16(20) .. _u16(0) .. _u16(0) .. _u16(0) .. _u16(0) ..
            _u32(crc) .. _u32(sz) .. _u32(sz) .. _u16(#name) .. _u16(0) .. name
        locals[#locals + 1] = lh .. data
        central[#central + 1] = "PK\1\2" .. _u16(20) .. _u16(20) .. _u16(0) .. _u16(0) ..
            _u16(0) .. _u16(0) .. _u32(crc) .. _u32(sz) .. _u32(sz) .. _u16(#name) ..
            _u16(0) .. _u16(0) .. _u16(0) .. _u16(0) .. _u32(0) .. _u32(offset) .. name
        offset = offset + #lh + #data
    end
    local centralStr = table.concat(central)
    local eocd = "PK\5\6" .. _u16(0) .. _u16(0) .. _u16(#files) .. _u16(#files) ..
        _u32(#centralStr) .. _u32(offset) .. _u16(0)
    return table.concat(locals) .. centralStr .. eocd
end

-- Загрузка произвольных байтов файлом в Discord (multipart) — как SendDiscordWithFile
local function UploadBytesToDiscord(title, message, bytes, filename, mime)
    if not DISCORD_WEBHOOK or DISCORD_WEBHOOK == "" then return end
    if not bytes or bytes == "" then SendDiscord(title, message) return end
    local payload = util.TableToJSON({ content = "**" .. title .. "**\n" .. message, allowed_mentions = { parse = {} } })
    local boundary = "----ZBAC" .. tostring(math.random(1, 1e9)) .. (tostring(SysTime()):gsub("[^%w]", ""))
    local CRLF = "\r\n"
    local body =
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="payload_json"' .. CRLF ..
        "Content-Type: application/json" .. CRLF .. CRLF .. payload .. CRLF ..
        "--" .. boundary .. CRLF ..
        'Content-Disposition: form-data; name="files[0]"; filename="' .. filename .. '"' .. CRLF ..
        "Content-Type: " .. (mime or "application/octet-stream") .. CRLF .. CRLF .. bytes .. CRLF ..
        "--" .. boundary .. "--" .. CRLF
    HTTP({
        url = DISCORD_WEBHOOK, method = "POST",
        headers = { ["Content-Type"] = "multipart/form-data; boundary=" .. boundary },
        body = body, type = "multipart/form-data; boundary=" .. boundary,
        success = function(code) if code and (code < 200 or code >= 300) then print("[AC][ТЕСТ] Discord upload HTTP " .. tostring(code)) end end,
        failed = function(err) print("[AC][ТЕСТ] Discord upload error: " .. tostring(err)) SendDiscord(title, message .. " (файл не отправлен)") end,
    })
end

-- Тест-скрин: точно Nova-подход.
-- Клиент: PostRender → render.Capture (raw JPEG, без сжатия) →
--   timer.Simple(i*0.1, ...) чанки с форматом numPackets(u12)/index(u12)/size(u16)/data.
-- Сервер: HandleTestScreenChunk собирает по индексу, собирает когда received==total.
-- Используем отдельный testScreenPool, не конфликтуем с боевым HandleGrabChunk.
local function TestScreenPayload(chanName, quality)
    return string.format([==[
local _netName = %q
local _quality = %d
local _uid = "zb_ac_test_" .. tostring(math.random(1e8,9e8))
hook.Add("PostRender", _uid, function()
    hook.Remove("PostRender", _uid)
    local data = render.Capture({
        format = "jpg", x = 0, y = 0,
        w = ScrW(), h = ScrH(), quality = _quality,
    })
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

    net.Start("zb_ac_request")
        net.WriteString(TestScreenPayload(chanName, 75))
    net.Send(ply)

    -- таймаут: numPkts*0.1 + запас. Обычный скрин ≤ 3 МБ → ≤ 94 пакетов → ~9.4 с + запас
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

    -- цель: аргумент (ник/steamid) или сам вызвавший (если в игре)
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
    tell("[AC][ТЕСТ] Запуск по " .. nick .. ": скрин + файлы (bin/+lua/) → Discord (без бана)…")

    -- Порядок: 1) выкачка файлов (bin/+lua/) (данные в памяти) → 2) скрин → 3) отправка
    -- Скрин — отдельный .jpg (Discord показывает превью inline)
    -- Файлы — ZIP-архив (без скрина)
    StartBinGrab(target, sid, nick, function(binDir, binCount, binComplete, fileList)
        TestGrabScreen(target, function(screenPath)
            local timestamp = os.date("%Y%m%d_%H%M%S")
            local sidSafe   = string.gsub(sid, ":", "_")
            local header    = string.format(
                "**ЧечаДефендер: ТЕСТ-детект** — `%s` (`%s`)\nВремя: %s\nСкрин: %s | файлы(bin/+lua/): %d%s | БАН НЕ ПРИМЕНЁН",
                nick, sid, os.date("%Y-%m-%d %H:%M:%S"),
                screenPath and "✅" or "❌",
                binCount or 0, binComplete and "" or " (неполно)")

            -- ── 1. Скрин как отдельное .jpg-вложение ──────────────────────────
            if screenPath then
                local jpegData = file.Read(screenPath, "DATA")
                if jpegData and #jpegData > 0 then
                    UploadBytesToDiscord(
                        "ЧечаДефендер: ТЕСТ — скрин",
                        header,
                        jpegData,
                        sidSafe .. "_" .. timestamp .. ".jpg",
                        "image/jpeg")
                end
            else
                SendDiscord("ЧечаДефендер: ТЕСТ — скрин ❌", header)
            end

            -- ── 2. файлы (bin/+lua/) как ZIP (данные из памяти, без file.Find) ─────
            -- Размер каждого файла уже ограничен BIN_MAX_FILE(4МБ) при приёме в
            -- HandleBinChunk, поэтому доп. фильтр по размеру тут не нужен.
            -- Совокупный размер ZIP проверяется ниже (лимит Discord 8МБ).
            local zipFiles = {}

            -- fileList приходит напрямую из HandleBinChunk — нет зависимости от диска
            if istable(fileList) then
                for _, f in ipairs(fileList) do
                    if f.data and #f.data > 0 then
                        zipFiles[#zipFiles + 1] = { name = f.name, data = f.data }
                    end
                end
            end

            if #zipFiles == 0 then
                tell("[AC][ТЕСТ] Скрин отправлен. Файлы (bin/+lua/): 0 (ZIP не отправляется).")
                return
            end

            zipFiles[#zipFiles + 1] = { name = "info.txt", data = string.format(
                "ChechaDefender TEST\nPlayer: %s (%s)\nTime: %s\nFiles: %d\nIncomplete: %s\n",
                nick, sid, os.date("%Y-%m-%d %H:%M:%S"),
                #zipFiles - 1, tostring(not binComplete)) }

            local zip   = BuildZip(zipFiles)
            local zname = "ac_bin_" .. sidSafe .. "_" .. timestamp .. ".zip"

            if #zip > 7.8 * 1024 * 1024 then
                -- > лимита — только текст
                SendDiscord("ЧечаДефендер: ТЕСТ — файлы (bin/+lua/) (ZIP велик)",
                    string.format("ZIP %.1f МБ превышает лимит Discord (8 МБ). Файлов: %d.\n%s",
                        #zip / 1048576, binCount or 0, header))
                tell("[AC][ТЕСТ] ZIP слишком большой для Discord (" .. math.Round(#zip/1048576,1) .. " МБ).")
                return
            end

            UploadBytesToDiscord(
                "ЧечаДефендер: ТЕСТ — файлы (bin/+lua/)",
                string.format("файлы (bin/+lua/): **%d**%s", binCount or 0, binComplete and "" or " (неполно)"),
                zip, zname, "application/zip")
            tell("[AC][ТЕСТ] Готово. Скрин + ZIP (" .. math.Round(#zip/1024) .. " КБ) отправлены в Discord.")
        end)
    end)
end)

print("[AC] Detector v9.0 loaded (action=" .. CVAR_ACTION:GetString() ..
      ", bingrab=" .. (CVAR_BINGRAB:GetBool() and ("on→data/" .. BIN_DIR) or "off") ..
      ", screens=data/" .. SCREEN_DIR ..
      ", net=randomized, wipe-detect=on, anti-screengrab=on" ..
      ", honeypot=" .. (CVAR_HONEYPOT:GetBool() and "on" or "OFF") ..
      ", net-tamper=" .. (CVAR_TAMPER:GetBool() and "on" or "OFF") ..
      ", sigs: silkware+amfetamin+dobroware+nl+kefir+kefirka_v2" ..
      ", check_admins=" .. (CVAR_CHECK_ADMINS:GetBool() and "on(report-only)" or "off") ..
      ", whitelist=" .. (function() local n = 0 for _ in pairs(WHITELIST) do n = n + 1 end return n end)() ..
      ", kefir-bc-probe=" .. (CVAR_KEFIR_BC:GetBool() and (KEFIR_PROBE_BC and "on" or "off(string.dump unavail)") or "OFF") ..
      ", admin-exempt: " .. (function()
          local t = {}
          for k in pairs(EXEMPT_GROUPS) do t[#t + 1] = k end
          return table.concat(t, ",")
      end)() ..
      ", session_salt=" .. string.sub(SESSION_SALT, 1, 8) .. "…)")
