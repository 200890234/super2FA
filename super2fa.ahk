#Requires AutoHotkey v2.0

; Deliberately NOT Force/Prompt. With no directive, v2's default is Prompt:
; a second launch pops a confirmation dialog BEFORE any script code runs,
; which would also afflict a host script that includes this file. Ignore
; silences that check; standalone mode enforces single instance with a named
; mutex instead (see the entry point below). A host that wants its own
; duplicate policy can place its #SingleInstance directive AFTER the include.
#SingleInstance Ignore

;@Ahk2Exe-SetName Super 2FA
;@Ahk2Exe-SetDescription Super 2FA - TOTP hotstring helper
;@Ahk2Exe-SetVersion 1.0.0

; ============================================================================
;  Super 2FA
;  Store TOTP secrets once, then type a short trigger anywhere to insert
;  the current 2FA code at the caret position.
;
;  DUAL MODE
;  ---------
;  1. Standalone - run super2fa.ahk directly. Builds its own tray menu,
;     enforces single instance, "Exit" ends the process.
;
;  2. Included by a host script - #Include this file at global scope
;     (not inside a function). Detection is automatic: while the include's
;     top-level code runs, A_LineFile names this file while A_ScriptFullPath
;     names the host, so the standalone entry point below skips itself.
;
;  Host-facing API (all identifiers carry the S2FA_ prefix so a host cannot
;  collide with them, in either mode):
;
;     S2FA_Init()               load config, register hotstrings, start keepalive
;     S2FA_ShowSettings()       open the settings window
;     S2FA_QuickPickTest()      dialog listing the current code per entry
;     S2FA_ShowHelp()           the field reference
;     S2FA_ReloadConfig()       re-read the ini and re-register triggers
;     S2FA_AddTrayMenuItems()   optional: append a "Super 2FA" submenu to
;                               the current tray menu without touching the
;                               host's own items
;     S2FA_Shutdown()           unregister all hotstrings/hotkeys and stop
;                               the keepalive timer; the host keeps running
;
;  Behaviour differences when included:
;     - The tray menu and icon are NOT modified unless the host explicitly
;       calls S2FA_AddTrayMenuItems().
;     - The settings window has no "Exit" button (only Help/Save/Cancel),
;       because exiting the process would kill the host.
;     - The configuration lives in %APPDATA%\Super2FA\super2fa.ini in both
;       modes, so every host shares the same configuration and no secrets
;       sit inside the (git-publishable) project folder. A legacy ini next
;       to super2fa.ahk is moved there automatically on first start.
;
;  Note on lib\totp.ahk: it is included automatically and exposes the generic
;  crypto names TOTP, SHA1, HmacSha1, Base32Decode, Base32DecodedLength and
;  SecondsRemaining. A host that defines its own functions under those names
;  should not include super2fa.ahk (it can include lib\totp.ahk alone instead).
;
;  #SingleInstance is deliberately NOT set: it is a load-time directive that
;  would leak onto the host. Standalone mode enforces single instance with a
;  named mutex at runtime instead.
; ============================================================================

global S2FA_AppName    := "Super 2FA"
global S2FA_Version    := "1.0.0"
global S2FA_GuiTitle   := S2FA_AppName " " S2FA_Version " - Settings"

global S2FA_Cfg        := Map()   ; hotkey, triggerMode, trayTip
global S2FA_Entries    := []      ; array of Map: {name, secret, trigger}
global S2FA_Hotstrings := []      ; registered: {key, trigger, secret}
global S2FA_Capturing  := false   ; a settings hotkey is being captured
global S2FA_HotkeyCtrl := ""      ; currently registered settings hotkey
global S2FA_Rows       := []      ; settings window row controls
global S2FA_RowY0      := 0
global S2FA_RowDY      := 30
global S2FA_RowMax     := 10
global S2FA_Running    := false
global S2FA_ToastOpacity := 255

; The configuration lives OUTSIDE the project folder, in the per-user
; application-data directory: secrets can then never end up in a git
; repository created from the project folder, and on a multi-user machine
; every Windows account keeps its own entries. Created on first save.
global S2FA_IniFile    := A_AppData "\Super2FA\super2fa.ini"

; Standalone when this file IS the main script (run as .ahk or compiled to
; an exe); hosted when merged into another script via #Include. A_LineFile is
; the file the initializer line lives in (always super2fa.ahk), while
; A_ScriptFullPath is the main script. In a COMPILED exe A_LineFile is the
; resource reference "*#1" rather than a path, so treat a leading "*" as
; standalone too — otherwise the compiled build silently does nothing.
global S2FA_Standalone := (A_LineFile = A_ScriptFullPath)
     || (SubStr(A_LineFile, 1, 1) = "*")   ; "*#1" inside an Ahk2Exe build

; ---------------------------------------------------------------------------
;  Entry point - standalone only. Skipped entirely when included, so the
;  host decides when (and whether) to call S2FA_Init().
; ---------------------------------------------------------------------------
if (S2FA_Standalone) {
    ; Runtime single-instance guard. #SingleInstance is a load-time directive
    ; and would impose itself on any host that includes this file, so the
    ; standalone mode checks a named mutex instead.
    ;
    ; A_LastError must be read IMMEDIATELY after the DllCall: any intervening
    ; call that opens an existing file (FileAppend, IniRead, ...) sets it to
    ; 183 (ERROR_ALREADY_EXISTS) again and would fake a "duplicate" hit.
    S2FA_MutexHandle := DllCall("CreateMutexW", "Ptr", 0, "Int", 0
        , "Str", "Local\Super2FA_SingleInstance", "Ptr")
    if (A_LastError = 183) {   ; ERROR_ALREADY_EXISTS
        S2FA_Toast("Super 2FA is already running.")
        Sleep(3500)   ; let the toast display before exiting
        ExitApp()
    }
    S2FA_Init()
}

; Directory containing THIS file, in either mode.
S2FA_OwnDir() {
    SplitPath(A_LineFile, , &dir)
    return dir
}

; ===========================================================================
;  Public API
; ===========================================================================

; Loads the configuration, registers the hotstrings and applies the optional
; settings hotkey. Safe to call again after S2FA_Shutdown().
S2FA_Init() {
    global S2FA_Running, S2FA_Standalone

    if S2FA_Running
        return

    S2FA_MigrateConfig()
    S2FA_LoadConfig()

    ; Only a standalone build owns the tray menu; a host keeps its own.
    if S2FA_Standalone
        S2FA_BuildTray()

    S2FA_RegisterHotstrings()
    S2FA_ApplyHotkey()

    ; A tray menu on its own is not enough to keep an AHK script resident:
    ; with no hotkeys, hotstrings, timers or GUIs the process would exit as
    ; soon as startup finished. On a first run the config is empty, so that
    ; is exactly the situation. This idle timer is the script's reason to
    ; stay alive. It also guarantees residency for a host that has no other
    ; persistent hooks of its own.
    SetTimer(S2FA_KeepAlive, 60000)

    S2FA_Running := true
}

; Unregisters every hotstring and hotkey and stops the keepalive timer.
; Designed for hosted use: the host process stays alive afterwards.
; (Standalone mode simply exits the process instead.)
S2FA_Shutdown() {
    global S2FA_Hotstrings, S2FA_HotkeyCtrl, S2FA_Capturing
    global S2FA_Running, S2FA_Gui

    ; Dynamic hotstrings must be removed with the exact option string they
    ; were registered with - each entry remembers its own full key.
    for , hs in S2FA_Hotstrings
        try Hotstring(hs["key"], "")
    S2FA_Hotstrings := []

    if (S2FA_HotkeyCtrl != "") {
        try Hotkey(S2FA_HotkeyCtrl, "Off")
        S2FA_HotkeyCtrl := ""
    }

    S2FA_Capturing := false
    SetTimer(S2FA_WatchCapture, 0)
    SetTimer(S2FA_KeepAlive, 0)

    ; Hide rather than destroy: the window object stays valid, so a later
    ; S2FA_Init() + S2FA_ShowSettings() reuses it instead of crashing on a
    ; destroyed window.
    if IsSet(S2FA_Gui)
        try S2FA_Gui.Hide()

    S2FA_Running := false
}

; Optional convenience for hosted use: appends a "Super 2FA" submenu to the
; current tray menu. Existing host menu items are not touched.
S2FA_AddTrayMenuItems() {
    m := Menu()
    m.Add("&Settings...", (*) => S2FA_ShowSettings())
    m.Add("&Test current codes", (*) => S2FA_QuickPickTest())
    m.Add("&Reload config", (*) => S2FA_ReloadConfig())
    m.Add("&Help", (*) => S2FA_ShowHelp())
    A_TrayMenu.Add("Super &2FA", m)
}

; ===========================================================================
;  Configuration file handling
; ===========================================================================
; Reads any Super 2FA format ini file. Returns a Map with keys "cfg" and
; "entries", or false when the file does not exist. Used for the live
; configuration and by the Import button.
S2FA_ReadIniFile(path) {
    if !FileExist(path)
        return false

    cfg := Map(
        "hotkey",       IniRead(path, "General", "Hotkey", ""),
        "triggerMode",  IniRead(path, "General", "TriggerMode", "ending"),
        "trayTip",      IniRead(path, "General", "ShowTrayTip", "0")
    )

    entries := []
    count := Integer(IniRead(path, "Entries", "Count", "0"))
    loop count {
        i := A_Index
        sec := "Entry" i
        name := IniRead(path, sec, "Name", "")
        secret := IniRead(path, sec, "Secret", "")
        trigger := IniRead(path, sec, "Trigger", "")
        if (Trim(name) = "" && Trim(secret) = "" && Trim(trigger) = "")
            continue
        entries.Push(Map("name", name, "secret", secret, "trigger", trigger))
    }

    return Map("cfg", cfg, "entries", entries)
}

S2FA_LoadConfig() {
    global S2FA_Cfg, S2FA_Entries, S2FA_IniFile

    data := S2FA_ReadIniFile(S2FA_IniFile)
    if (data = false) {
        ; no file yet - start with defaults; SaveConfig creates it later
        S2FA_Cfg := Map("hotkey", "", "triggerMode", "ending", "trayTip", "0")
        S2FA_Entries := []
    } else {
        S2FA_Cfg := data["cfg"]
        S2FA_Entries := data["entries"]
    }

    if (S2FA_Entries.Length = 0)
        S2FA_Entries.Push(Map("name", "", "secret", "", "trigger", ""))
}

S2FA_SaveConfig() {
    global S2FA_Cfg, S2FA_Entries, S2FA_IniFile

    SplitPath(S2FA_IniFile, , &dir)
    DirCreate(dir)
    try FileDelete(S2FA_IniFile)

    IniWrite(S2FA_Cfg["hotkey"],      S2FA_IniFile, "General", "Hotkey")
    IniWrite(S2FA_Cfg["triggerMode"], S2FA_IniFile, "General", "TriggerMode")
    IniWrite(S2FA_Cfg["trayTip"],     S2FA_IniFile, "General", "ShowTrayTip")

    IniWrite(S2FA_Entries.Length, S2FA_IniFile, "Entries", "Count")
    for i, e in S2FA_Entries {
        sec := "Entry" i
        IniWrite(e["name"],    S2FA_IniFile, sec, "Name")
        IniWrite(e["secret"],  S2FA_IniFile, sec, "Secret")
        IniWrite(e["trigger"], S2FA_IniFile, sec, "Trigger")
    }
}

; One-time migration from the pre-1.2 location (next to super2fa.ahk) to the
; per-user application-data directory. Runs only when the new file does not
; exist yet, and removes the legacy copy only after a successful copy - after
; this, the project folder contains no secrets at all.
S2FA_MigrateConfig() {
    global S2FA_IniFile, S2FA_AppName

    legacy := S2FA_OwnDir() "\super2fa.ini"
    if !FileExist(legacy) || FileExist(S2FA_IniFile)
        return

    SplitPath(S2FA_IniFile, , &dir)
    DirCreate(dir)
    try {
        FileCopy(legacy, S2FA_IniFile, 0)
        FileDelete(legacy)
        S2FA_Toast("Configuration moved to " dir)
    }
}

; ===========================================================================
;  TOTP engine
;  Kept in a separate file so the self test can exercise the very same code.
;  NOTE: the functions in lib\totp.ahk keep their generic names on purpose -
;  a host that wants nothing but the crypto can include lib\totp.ahk alone.
; ===========================================================================
#Include lib\totp.ahk

; ===========================================================================
;  Hotstring management
; ===========================================================================
S2FA_RegisterHotstrings() {
    global S2FA_Entries, S2FA_Hotstrings, S2FA_Cfg, S2FA_AppName

    ; Unregister what we previously registered.
    ;
    ; A dynamic hotstring can only be removed by passing the exact same option
    ; string it was created with - anything else throws "Nonexistent hotstring"
    ; (and, unhelpfully, still destroys the entry). So remember the full
    ; "options + trigger" key for every registration instead of guessing it
    ; from the current trigger mode.
    for , hs in S2FA_Hotstrings {
        try Hotstring(hs["key"], "")
    }
    S2FA_Hotstrings := []

    ; Option mapping (verified empirically with a firing test):
    ;   immediate mode  :*?:  fires the instant the trigger is complete,
    ;                         even in the middle of another word
    ;   ending mode     :O:   requires an ending character (Space/Enter/
    ;                         Tab), fires only at a word boundary, and the
    ;                         ending character itself is NOT typed after
    ;                         the code
    ; (Both used to be ":*:" - which IS the "no ending character required"
    ; option, so ending mode fired instantly too. '*' means "no ending
    ; character needed"; it has nothing to do with word boundaries.)
    options := (S2FA_Cfg["triggerMode"] = "immediate") ? ":*?:" : ":O:"

    for , e in S2FA_Entries {
        trig := Trim(e["trigger"])
        secret := Trim(e["secret"])
        if (trig = "" || secret = "")
            continue

        key := options trig
        S2FA_Hotstrings.Push(Map("key", key, "trigger", trig, "secret", secret))

        runFn := S2FA_FireTotp.Bind(secret, e.Has("name") ? e["name"] : "")
        try
            Hotstring(key, runFn)
        catch Error as err
            S2FA_Toast("Could not register trigger '" trig "': " err.Message)
    }
}

S2FA_FireTotp(secret, name, *) {
    global S2FA_Cfg, S2FA_AppName

    try {
        code := TOTP(secret)
    } catch Error as err {
        S2FA_Toast("Failed to generate code: " err.Message)
        return
    }

    ; Insert the code at the caret via the clipboard, then put the user's
    ; original clipboard contents back.
    ;
    ; ClipboardAll() must be kept in a variable that stays referenced: setting
    ; it to "" (or letting it go out of scope) can free the underlying memory
    ; before it has been read back, which would wipe the clipboard.
    saved := ClipboardAll()

    A_Clipboard := code
    if !ClipWait(1) {
        ; The clipboard never received our text; leave the original alone.
        A_Clipboard := saved
        S2FA_Toast("Could not access the clipboard to insert the code.")
        return
    }

    Send("^v")
    Sleep(120)

    A_Clipboard := saved

    if (S2FA_Cfg["trayTip"] = "1") {
        label := (name = "") ? "2FA" : name
        S2FA_Toast(code "   (" SecondsRemaining() "s left)", label)
    }
}

; ===========================================================================
;  Toast notifications
;  System TrayTip is not used: Windows captions every toast with the source
;  application, and for a script that reads "AutoHotkey" - hardly
;  professional. This draws its own bottom-right popup instead: dark, styled,
;  non-activating, auto-fading.
; ===========================================================================
S2FA_Toast(text, title := "") {
    global S2FA_ToastGui, S2FA_ToastTitle, S2FA_ToastBody, S2FA_ToastHideTimer
    global S2FA_AppName

    if !IsSet(S2FA_ToastGui) {
        S2FA_ToastGui := Gui("+AlwaysOnTop -Caption +E0x08000000 +E0x80")
        S2FA_ToastGui.BackColor := "1F1F1F"
        S2FA_ToastGui.SetFont("s10 bold cFFFFFF", "Segoe UI")
        S2FA_ToastTitle := S2FA_ToastGui.Add("Text", "x16 y12 w370")
        S2FA_ToastGui.SetFont("s9 norm cD8D8D8", "Segoe UI")
        S2FA_ToastBody := S2FA_ToastGui.Add("Text", "x16 y+8 w370")
    }

    ; a fresh toast cancels any fade in progress and returns to full opacity
    SetTimer(S2FA_ToastFade, 0)
    S2FA_ToastOpacity := 255
    WinSetTransparent(255, S2FA_ToastGui)

    S2FA_ToastTitle.Text := (title != "") ? title : S2FA_AppName
    S2FA_ToastBody.Text := text

    ; auto-size, then dock to the bottom-right of the monitor the user is
    ; currently on (where they are typing), not always monitor 1. This keeps
    ; the toast visible on multi-monitor setups and regardless of taskbar
    ; placement.
    S2FA_ToastGui.Show("Hide")
    WinGetPos(, , &tw, &th, S2FA_ToastGui)
    mon := 1
    count := MonitorGetCount()
    WinGetPos(&ax, &ay, &aw, &ah, "A")
    if (IsSet(ax)) {
        acx := ax + aw // 2
        acy := ay + ah // 2
        i := 0
        Loop count {
            i++
            MonitorGetWorkArea(i, &l, &t, &r, &b)
            if (acx >= l && acx <= r && acy >= t && acy <= b) {
                mon := i
                break
            }
        }
    }
    MonitorGetWorkArea(mon, &wl, &wt, &wr, &wb)
    S2FA_ToastGui.Show("x" (wr - tw - 16) " y" (wb - th - 16) " NA")

    SetTimer(S2FA_ToastFade, -5000)
}

; Fade the toast out and hide it. The show call arms this once (-4000, the
; display time); every step re-arms itself (-30 ms) until fully transparent,
; then hides the window, restores full opacity and stops the timer. Without
; the re-arm the fade would run a single step and stall.
S2FA_ToastFade() {
    global S2FA_ToastGui, S2FA_ToastOpacity

    if !IsSet(S2FA_ToastGui) || !WinExist("ahk_id " S2FA_ToastGui.Hwnd) {
        SetTimer(S2FA_ToastFade, 0)
        return
    }

    S2FA_ToastOpacity -= 25
    if (S2FA_ToastOpacity <= 0) {
        S2FA_ToastGui.Hide()
        WinSetTransparent("Off", S2FA_ToastGui)
        S2FA_ToastOpacity := 255
        SetTimer(S2FA_ToastFade, 0)
    } else {
        WinSetTransparent(S2FA_ToastOpacity, S2FA_ToastGui)
        SetTimer(S2FA_ToastFade, -30)
    }
}

; ===========================================================================
;  Tray (standalone mode only)
; ===========================================================================
S2FA_BuildTray() {
    A_TrayMenu.Delete()
    A_TrayMenu.Add("&Settings...", (*) => S2FA_ShowSettings())
    A_TrayMenu.Add("&Test current code", (*) => S2FA_QuickPickTest())
    A_TrayMenu.Add()
    A_TrayMenu.Add("&Reload config", (*) => S2FA_ReloadConfig())
    A_TrayMenu.Add("&Help", (*) => S2FA_ShowHelp())
    A_TrayMenu.Add()
    A_TrayMenu.Add("E&xit", (*) => ExitApp())
    A_TrayMenu.Default := "&Settings..."
    TraySetIcon("shell32.dll", 44)
    A_IconTip := S2FA_AppName " - click for menu"
}

; Idle heartbeat - only purpose is to keep the process resident so the tray
; menu keeps working.
S2FA_KeepAlive() {
}

S2FA_ApplyHotkey() {
    global S2FA_Cfg, S2FA_HotkeyCtrl, S2FA_Gui, S2FA_AppName

    ; release whatever was registered before
    if (S2FA_HotkeyCtrl != "")
        try Hotkey(S2FA_HotkeyCtrl, "Off")
    S2FA_HotkeyCtrl := ""

    hk := Trim(S2FA_Cfg["hotkey"])
    if (hk = "")
        return

    try {
        Hotkey(hk, (*) => S2FA_ShowSettings(), "On")
        S2FA_HotkeyCtrl := hk
    } catch Error as err {
        ; The saved value is unusable - drop it so it cannot fail again on
        ; every start, and keep the dialog in sync when it is open.
        S2FA_Cfg["hotkey"] := ""
        S2FA_Toast("The hotkey '" hk "' could not be registered and was cleared."
            . "`n" err.Message)
        if IsSet(S2FA_Gui) && WinExist("ahk_id " S2FA_Gui.Hwnd) {
            S2FA_Gui.HotkeyBox.Value := ""
            S2FA_Gui.HotkeyBox.Opt("-cRed")
        }
    }
}

S2FA_ReloadConfig() {
    S2FA_LoadConfig()
    S2FA_RegisterHotstrings()
    S2FA_ApplyHotkey()
    S2FA_Toast("Configuration reloaded.")
}

; ===========================================================================
;  Settings GUI
; ===========================================================================
S2FA_ShowSettings() {
    ; S2FA_Gui MUST be declared global: it is assigned below, and without
    ; the declaration AHK would make it a local - the global would stay unset,
    ; S2FA_SaveSettings would crash on an unset variable, and every call
    ; would build a duplicate window instead of re-showing this one.
    global S2FA_Entries, S2FA_Cfg, S2FA_Rows, S2FA_RowY0, S2FA_RowDY, S2FA_RowMax
    global S2FA_GuiTitle, S2FA_Capturing, S2FA_Gui
    global S2FA_Standalone, S2FA_AppName

    if IsSet(S2FA_Gui) {
        try {
            S2FA_Gui.Show()
            WinActivate("ahk_id " S2FA_Gui.Hwnd)
            return
        }
    }

    ; load latest config from disk so external edits are picked up
    S2FA_LoadConfig()

    g := Gui("+Resize -MaximizeBox", S2FA_GuiTitle)
    g.SetFont("s9", "Segoe UI")
    g.MarginX := 10
    g.MarginY := 10

    ; Column layout for the client area (730 wide).
    ; Every right edge must stay inside the width set in Show() below:
    ; the Del column ends at 685+35=720, leaving a 10 px margin.
    colX := [10, 45, 240, 505, 625, 685]
    colW := [ 30, 190, 260, 115,  55,  35]

    ; --- header row ---
    hy := 10
    g.Add("Text", "x" colX[1] " y" hy " w" colW[1] " Center", "#")
    g.Add("Text", "x" colX[2] " y" hy " w" colW[2], "Name")
    g.Add("Text", "x" colX[3] " y" hy " w" colW[3], "Secret Key")
    g.Add("Text", "x" colX[4] " y" hy " w" colW[4], "Trigger")
    g.Add("Text", "x" colX[5] " y" hy " w" colW[5] " Center", "Test")
    g.Add("Text", "x" colX[6] " y" hy " w" colW[6] " Center", "Del")

    S2FA_RowY0 := 34
    S2FA_RowDY := 30
    S2FA_Rows := []

    ; --- entry rows ---
    loop S2FA_RowMax {
        i := A_Index
        y := S2FA_RowY0 + (i - 1) * S2FA_RowDY
        S2FA_RebuildRow(g, i, y, colX, colW)
    }

    ; --- mode + hotkey section ---
    baseY := S2FA_RowY0 + S2FA_RowMax * S2FA_RowDY + 14
    g.SetFont("s9 bold", "Segoe UI")
    g.Add("Text", "x10 y" baseY, "Trigger mode")
    g.SetFont("s9 norm", "Segoe UI")

    mode := S2FA_Cfg["triggerMode"]
    rb1 := g.Add("Radio", "x120 y" (baseY - 2) " vModeEnding"
        , "Ending character (type trigger, then Space / Enter)")
    rb2 := g.Add("Radio", "x120 y+4 vModeImmediate"
        , "Immediate (fires as soon as the trigger is complete)")
    if (mode = "immediate")
        rb2.Value := 1
    else
        rb1.Value := 1

    hy2 := baseY + 56
    g.SetFont("s9 bold", "Segoe UI")
    g.Add("Text", "x10 y" hy2, "Open settings hotkey")
    g.SetFont("s9 norm", "Segoe UI")
    ; The bold label above is ~130 px wide; the box starts at x150 so nothing
    ; overlaps, and Set/Clear/hint shift right accordingly.
    hkBox := g.Add("Edit", "x150 y" (hy2 - 3) " w200 ReadOnly vHotkeyBox", S2FA_Cfg["hotkey"])
    g.Add("Button", "x360 y" (hy2 - 4) " w60", "Set").OnEvent("Click", S2FA_SetHotkey)
    g.Add("Button", "x425 y" (hy2 - 4) " w60", "Clear").OnEvent("Click", S2FA_ClearHotkey)
    g.Add("Text", "x495 y" (hy2 + 1) " cGray", "(default: none)")

    ; --- bottom buttons ---
    ; No "Exit" button in hosted mode: exiting the process would kill the
    ; host script. Closing the window (Cancel / X / Esc) just hides it.
    by := hy2 + 44
    g.Add("Button", "x10 y" by " w80", "&Help").OnEvent("Click", S2FA_ShowHelp)
    g.Add("Button", "x100 y" by " w80", "&Import...").OnEvent("Click", S2FA_ImportConfig)
    g.Add("Button", "x190 y" by " w90", "Config &file").OnEvent("Click", S2FA_OpenConfigFile)
    g.Add("Button", "x285 y" by " w95", "Config &folder").OnEvent("Click", S2FA_OpenConfigFolder)
    g.Add("Button", "x450 y" by " w80 Default", "&Save").OnEvent("Click", S2FA_SaveSettings)
    g.Add("Button", "x540 y" by " w80", "&Cancel").OnEvent("Click", (*) => S2FA_Gui.Hide())
    if S2FA_Standalone
        g.Add("Button", "x630 y" by " w80", "E&xit").OnEvent("Click", (*) => ExitApp())

    S2FA_Gui := g
    S2FA_Gui.HotkeyBox := hkBox
    S2FA_Gui.ModeEnding := rb1
    S2FA_Gui.ModeImmediate := rb2

    g.OnEvent("Close", (*) => S2FA_Gui.Hide())
    g.OnEvent("Escape", (*) => S2FA_Gui.Hide())

    S2FA_Gui.Show("w730 h" (by + 50))
    WinActivate("ahk_id " S2FA_Gui.Hwnd)
}

S2FA_RebuildRow(g, i, y, colX, colW) {
    global S2FA_Entries, S2FA_Rows

    e := (i <= S2FA_Entries.Length) ? S2FA_Entries[i] : Map("name", "", "secret", "", "trigger", "")

    g.SetFont("s9 norm", "Segoe UI")
    num := g.Add("Text", "x" colX[1] " y" (y + 3) " w" colW[1] " Center", i)
    txtName := g.Add("Edit", "x" colX[2] " y" y " w" colW[2] " vName" i, e["name"])
    txtSecret := g.Add("Edit", "x" colX[3] " y" y " w" colW[3] " vSecret" i, e["secret"])
    txtTrigger := g.Add("Edit", "x" colX[4] " y" y " w" colW[4] " vTrigger" i, e["trigger"])
    btnTest := g.Add("Button", "x" colX[5] " y" (y - 1) " w" colW[5], "Test")
    btnDel := g.Add("Button", "x" colX[6] " y" (y - 1) " w" colW[6], "X")

    btnTest.OnEvent("Click", S2FA_TestRow.Bind(i))
    btnDel.OnEvent("Click", S2FA_DeleteRow.Bind(i))

    S2FA_Rows.Push(Map(
        "num", num, "name", txtName, "secret", txtSecret,
        "trigger", txtTrigger, "test", btnTest, "del", btnDel, "y", y
    ))
}

; --- collect GUI values into S2FA_Entries ------------------------------------
S2FA_CollectRows() {
    global S2FA_Rows

    out := []
    for i, r in S2FA_Rows {
        name := Trim(r["name"].Value)
        secret := Trim(r["secret"].Value)
        trigger := Trim(r["trigger"].Value)
        if (name = "" && secret = "" && trigger = "")
            continue
        out.Push(Map("name", name, "secret", secret, "trigger", trigger))
    }
    return out
}

; --- validation --------------------------------------------------------------
; Returns "" when every row is usable, otherwise a human-readable error.
; (A plain string return is used instead of an object so the result never
; needs to be unpacked by the caller.)
S2FA_ValidateRows(rows) {
    if (rows.Length = 0)
        return "Please add at least one entry."

    seen := Map()
    for idx, r in rows {
        if (r["name"] = "")
            return "Row " idx ": Name is required."
        if (r["secret"] = "")
            return "Row " idx ": Secret Key is required."
        if (r["trigger"] = "")
            return "Row " idx ": Trigger is required."

        if !RegExMatch(r["trigger"], "^[A-Za-z0-9]{3,}$")
            return "Row " idx ": Trigger must be at least 3 characters, letters and digits only."

        lt := StrLower(r["trigger"])
        if seen.Has(lt)
            return "Row " idx ": Trigger '" r["trigger"] "' is already used by row " seen[lt] "."
        seen[lt] := idx

        try
            TOTP(r["secret"])
        catch Error as err
            return "Row " idx ": Invalid Secret Key - " err.Message
    }
    return ""
}

S2FA_SaveSettings(*) {
    global S2FA_Entries, S2FA_Cfg, S2FA_Gui, S2FA_RowMax, S2FA_AppName

    rows := S2FA_CollectRows()

    errMsg := S2FA_ValidateRows(rows)
    if (errMsg != "") {
        MsgBox(errMsg, S2FA_AppName, "Icon! OK")
        return
    }

    if (rows.Length > S2FA_RowMax) {
        MsgBox("At most " S2FA_RowMax " entries are supported.", S2FA_AppName, "Icon! OK")
        return
    }

    S2FA_Entries := rows

    S2FA_Cfg["triggerMode"] := S2FA_Gui.ModeImmediate.Value ? "immediate" : "ending"

    hotkey := Trim(S2FA_Gui.HotkeyBox.Value)
    if (hotkey != "" && !S2FA_IsValidHotkey(hotkey)) {
        MsgBox("The hotkey '" hotkey "' is not valid.", S2FA_AppName, "Icon! OK")
        return
    }
    S2FA_Cfg["hotkey"] := hotkey

    S2FA_SaveConfig()
    S2FA_RegisterHotstrings()
    S2FA_ApplyHotkey()

    S2FA_Gui.Hide()
    S2FA_Toast("Saved. Hotstrings are now active.")
}

; Loads entries / trigger mode / settings hotkey from a chosen ini file INTO
; THE FORM. Nothing is written or activated until the user clicks Save, so an
; import stays reviewable and Cancel still discards it.
S2FA_ImportConfig(*) {
    global S2FA_Gui, S2FA_Rows, S2FA_RowMax, S2FA_Cfg, S2FA_Capturing, S2FA_AppName

    file := FileSelect(1, , "Select a Super 2FA configuration file"
        , "Configuration files (*.ini)|*.ini|All files (*.*)|*.*")
    if (file = "")
        return

    data := S2FA_ReadIniFile(file)
    if (data = false || data["entries"].Length = 0) {
        MsgBox("No entries found in:`n" file, S2FA_AppName, "Icon! OK")
        return
    }

    ; an in-progress hotkey capture would fight with filling the box
    S2FA_Capturing := false
    SetTimer(S2FA_WatchCapture, 0)
    S2FA_Gui.HotkeyBox.Opt("-cRed")

    entries := data["entries"]
    truncated := (entries.Length > S2FA_RowMax)
    if truncated {
        trimmed := []
        loop S2FA_RowMax
            trimmed.Push(entries[A_Index])
        entries := trimmed
    }

    loop S2FA_RowMax {
        i := A_Index
        r := S2FA_Rows[i]
        if (i <= entries.Length) {
            r["name"].Value := entries[i]["name"]
            r["secret"].Value := entries[i]["secret"]
            r["trigger"].Value := entries[i]["trigger"]
        } else {
            r["name"].Value := ""
            r["secret"].Value := ""
            r["trigger"].Value := ""
        }
    }

    if (data["cfg"]["triggerMode"] = "immediate")
        S2FA_Gui.ModeImmediate.Value := 1
    else
        S2FA_Gui.ModeEnding.Value := 1
    S2FA_Gui.HotkeyBox.Value := data["cfg"]["hotkey"]
    S2FA_Cfg["trayTip"] := data["cfg"]["trayTip"]

    ; count secrets that cannot produce a code, so the user knows what to fix
    bad := 0
    for , e in entries {
        try
            TOTP(e["secret"])
        catch
            bad++
    }

    msg := "Imported " entries.Length " entr" (entries.Length = 1 ? "y" : "ies")
        . " from:`n" file
        . "`n`nReview the values, then click Save to activate them."
    if truncated
        msg .= "`n`nNote: the file contains more than " S2FA_RowMax
            . " entries; only the first " S2FA_RowMax " were imported."
    if (bad > 0)
        msg .= "`n`nWarning: " bad " secret(s) do not look like valid Base32 - fix those rows before saving."
    MsgBox(msg, S2FA_AppName " - Import", "Iconi")
}

; Opens the configuration file with its default editor (Notepad on stock
; Windows), or explains that it does not exist yet.
S2FA_OpenConfigFile(*) {
    global S2FA_IniFile, S2FA_AppName

    if !FileExist(S2FA_IniFile) {
        MsgBox("No configuration file exists yet - it is created the first"
            . " time you click Save.`n`nExpected at:`n" S2FA_IniFile,
            S2FA_AppName, "Iconi")
        return
    }
    try
        Run(S2FA_IniFile)
    catch
        Run('notepad.exe "' S2FA_IniFile '"')
}

; Opens the configuration folder in Explorer with the ini pre-selected.
S2FA_OpenConfigFolder(*) {
    global S2FA_IniFile

    SplitPath(S2FA_IniFile, , &dir)
    DirCreate(dir)
    if FileExist(S2FA_IniFile)
        Run('explorer.exe /select,"' S2FA_IniFile '"')
    else
        Run('explorer.exe "' dir '"')
}

; Checks that AHK accepts the combination.
; Hotkey() needs a real function object as its second parameter - passing a
; string such as "Fn" throws, which would make every hotkey look invalid.
S2FA_IsValidHotkey(hk) {
    if (Trim(hk) = "")
        return false

    ; A usable shortcut must contain at least one non-modifier key.
    if !RegExMatch(hk, "[^!^+#]")
        return false

    try {
        Hotkey(hk, S2FA_NoopHotkey, "On")
        Hotkey(hk, "Off")
        return true
    } catch {
        return false
    }
}

S2FA_NoopHotkey(*) {
    return
}

S2FA_SetHotkey(*) {
    global S2FA_Capturing, S2FA_Gui

    if S2FA_Capturing
        return

    S2FA_Capturing := true
    S2FA_Gui.HotkeyBox.Value := "Press your shortcut now..."
    S2FA_Gui.HotkeyBox.Opt("cRed")
    SetTimer(S2FA_WatchCapture, 50)
}

S2FA_ClearHotkey(*) {
    global S2FA_Capturing, S2FA_Gui
    S2FA_Capturing := false
    SetTimer(S2FA_WatchCapture, 0)
    S2FA_Gui.HotkeyBox.Opt("-cRed")
    S2FA_Gui.HotkeyBox.Value := ""
}

; While capture is armed, poll the keyboard state. This is far more reliable
; than a key hook: it records whichever modifiers are held when a non-modifier
; key is pressed, and it never swallows the keystroke itself.
S2FA_WatchCapture() {
    global S2FA_Capturing, S2FA_Gui, S2FA_Cfg

    if !S2FA_Capturing {
        SetTimer(S2FA_WatchCapture, 0)
        return
    }

    ; Escape cancels without changing the stored hotkey
    if GetKeyState("Esc", "P") {
        S2FA_Capturing := false
        SetTimer(S2FA_WatchCapture, 0)
        S2FA_Gui.HotkeyBox.Opt("-cRed")
        S2FA_Gui.HotkeyBox.Value := S2FA_Cfg["hotkey"]
        return
    }

    key := S2FA_GetPressedKey()
    if (key = "")
        return

    S2FA_Capturing := false
    SetTimer(S2FA_WatchCapture, 0)
    S2FA_Gui.HotkeyBox.Opt("-cRed")

    mods := ""
    if GetKeyState("Ctrl", "P")
        mods .= "^"
    if GetKeyState("Alt", "P")
        mods .= "!"
    if GetKeyState("Shift", "P")
        mods .= "+"
    if GetKeyState("LWin", "P") || GetKeyState("RWin", "P")
        mods .= "#"

    candidate := mods key
    S2FA_Gui.HotkeyBox.Value := S2FA_IsValidHotkey(candidate) ? candidate : S2FA_Cfg["hotkey"]
}

; Returns the AHK name of the first non-modifier key that is currently down.
S2FA_GetPressedKey() {
    static keyList := [
        "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
        "Numpad0", "Numpad1", "Numpad2", "Numpad3", "Numpad4",
        "Numpad5", "Numpad6", "Numpad7", "Numpad8", "Numpad9",
        "NumpadMult", "NumpadAdd", "NumpadSub", "NumpadDiv", "NumpadDot",
        "Space", "Tab", "Enter", "Backspace", "Delete", "Insert",
        "Home", "End", "PgUp", "PgDn", "Up", "Down", "Left", "Right",
        "PrintScreen", "ScrollLock", "Pause", "CapsLock",
        "``", "-", "=", "[", "]", "\", ";", "'", ",", ".", "/"
    ]

    for , k in keyList {
        if GetKeyState(k, "P")
            return k
    }
    return ""
}

; --- per row actions ---------------------------------------------------------
S2FA_TestRow(i, *) {
    global S2FA_Rows, S2FA_AppName

    if (i > S2FA_Rows.Length)
        return

    r := S2FA_Rows[i]
    secret := Trim(r["secret"].Value)
    name := Trim(r["name"].Value)

    if (secret = "") {
        MsgBox("Please enter a Secret Key first.", S2FA_AppName, "Icon! OK")
        return
    }

    try {
        code := TOTP(secret)
        left := SecondsRemaining()
    } catch Error as err {
        MsgBox("Invalid Secret Key:`n`n" err.Message, S2FA_AppName, "Icon! OK")
        return
    }

    label := (name = "") ? "Entry " i : name
    MsgBox(label "`n`nCode:  " code "`nValid for:  " left " second(s)",
        S2FA_AppName " - Test", "Iconi")
}

S2FA_DeleteRow(i, *) {
    global S2FA_Rows

    if (i > S2FA_Rows.Length)
        return

    ; shift all values up by one, starting at row i
    loop S2FA_Rows.Length - i {
        src := i + A_Index
        S2FA_Rows[src - 1]["name"].Value := S2FA_Rows[src]["name"].Value
        S2FA_Rows[src - 1]["secret"].Value := S2FA_Rows[src]["secret"].Value
        S2FA_Rows[src - 1]["trigger"].Value := S2FA_Rows[src]["trigger"].Value
    }
    last := S2FA_Rows.Length
    S2FA_Rows[last]["name"].Value := ""
    S2FA_Rows[last]["secret"].Value := ""
    S2FA_Rows[last]["trigger"].Value := ""
}

S2FA_QuickPickTest() {
    global S2FA_Entries, S2FA_AppName

    if (S2FA_Entries.Length = 0) {
        MsgBox("No entries configured yet.", S2FA_AppName, "Icon! OK")
        return
    }

    lines := []
    for i, e in S2FA_Entries {
        if (Trim(e["secret"]) = "")
            continue

        ; {:2} right-aligns the index, {:-20s} left-aligns the name.
        ; Note: AHK v2's Format has no ">" flag - {:>2} would emit the literal
        ; text "{:>2}", so plain width is used for numeric right alignment.
        label := Format("{:2}. {:-20s}", i, e["name"])
        try {
            code := TOTP(e["secret"])
            lines.Push(label " " code "   (" SecondsRemaining() "s left)")
        } catch {
            lines.Push(label " <invalid secret>")
        }
    }

    if (lines.Length = 0) {
        MsgBox("No entry has a valid Secret Key.", S2FA_AppName, "Icon! OK")
        return
    }

    msg := "Current codes:`n`n" S2FA_JoinArray(lines, "`n")
    MsgBox(msg, S2FA_AppName " - Test", "Iconi")
}

S2FA_JoinArray(arr, sep) {
    out := ""
    for i, v in arr
        out .= (i = 1 ? "" : sep) v
    return out
}

; ===========================================================================
;  Help
; ===========================================================================
S2FA_ShowHelp(*) {
    global S2FA_AppName

    msg :=
    (
        S2FA_AppName " - Field reference`n"
        "=====================================`n`n"
        "Name`n"
        "    A label so you recognise the entry, e.g. 'GitHub' or 'AWS root'.`n"
        "    Shown in the Test dialog and the tray tip.`n`n"
        "Secret Key`n"
        "    The shared secret used to generate the 6-digit code.`n"
        "    - Base32 characters only: A-Z and 2-7 (case is ignored).`n"
        "    - Spaces and '=' padding are allowed and ignored.`n"
        "    - This is the value behind a QR code, NOT the 6-digit code.`n"
        "    - Usually 16, 26 or 32 characters long.`n`n"
        "Trigger`n"
        "    The text you type to insert a code.`n"
        "    - Letters and digits only, at least 3 characters.`n"
        "    - Example: with the trigger  '2fagh', typing  2fagh  then`n"
        "      Space or Enter replaces it with the current code.`n"
        "    - Avoid triggers that appear inside normal words, since any`n"
        "      match will be expanded.`n`n"
        "Trigger mode`n"
        "    Ending character - type the trigger then Space/Enter to fire;`n"
        "                       the ending character itself is not typed.`n"
        "                       (recommended, less accidental expansion)`n"
        "    Immediate        - fires the moment the trigger is complete.`n"
        "                       More convenient, but expands while you type`n"
        "                       whenever the trigger appears in a word.`n`n"
        "Open settings hotkey`n"
        "    Optional. Click Set and press a combination, e.g. Ctrl+Alt+2.`n"
        "    Left empty by default. Use Clear to remove it.`n`n"
        "Test button`n"
        "    Computes the code for the Secret Key on that row and shows how`n"
        "    many seconds it stays valid, so you can compare it with your`n"
        "    authenticator app before saving.`n`n"
        "Where codes are inserted`n"
        "    When a trigger fires, the code is placed at the caret in the`n"
        "    active window. Your clipboard contents are restored afterwards."
    )
    MsgBox(msg, S2FA_AppName " - Help", "Iconi")
}
