# EasyCheatDetector-RE — Full Technical Report

**Target:** FUNGUN EasyCheatDetector (eCD) v3.32 — free anti-cheat scanner for CS 1.6 / Minecraft / RUST (32-bit PE, ~10.4MB, fungun.net/fungun.top).

> This repo is a reverse-engineering effort.

---

## 1. HOW IT WORKS

### 1.1 Startup sequence
```
1.  OS check (>= Vista, otherwise suggests the WinXP build)
2.  CRC32 integrity: .text, .rdata, overlay (3 slots) — mismatch =
    "[SELF PROTECTION] Error 1/5/7" → exit(-1)
3.  EULA (registry EULA_22_02_2026, HKCU\Software\ecd)
4.  SeDebugPrivilege (activation + GetTokenInformation verification)
5.  ABOVE_NORMAL_PRIORITY_CLASS
6.  GDI+ init + UI animation (from ZIP in PE resources, ID 2001-2004)
7.  Mutex (5 attempts: 500/2000/3000/5000ms)
8.  Threads: UI (20ms redraw) + Watchdog (escalates to REALTIME if frozen)
9.  GameGuard check (acdrv/ggsvc services, QueryServiceStatusEx == RUNNING)
10. Game process search (hl.exe, cstrike.exe, cs.exe, csgo.exe, cs2.exe,
    java.exe, rustclient.exe, ...)
11. DebugActiveProcess(game_PID)  ← ECD DEBUGS THE GAME ITSELF! (monopolizes the
    only debugger slot) + DebugSetProcessKillOnExit(FALSE)
12. Firewall rule (COM INetFwPolicy2)
13. Root CA install (RCDATA #111 PFX with obfuscated password via
    PFXImportCertStore, CertAddCertificateContextToStore into Trusted Root)
14. WMI hardware fingerprint (CPU+Disk+BIOS+Motherboard → HWID)
15. Cheat DB load/download (SQLite, API key xWey5BsRh1e36 in URL)
16. 14 SCAN STAGES
17. JSON report → POST fungun.net/ska/ecd.php?method=report
    (offline: saved as %Y%m%d_%H%M%S.ecd in CWD)
18. ReportID display
```

### 1.2 Self-debugging engine
```
while running:
    WaitForDebugEvent(timeout=100ms)
    switch event:
        EXCEPTION_BREAKPOINT → scan hooks, restore byte, set TF (trap flag)
        SINGLE_STEP          → handle own HW BP, re-place INT3/HW BP
        ACCESS_VIOLATION     → analyze protected pages
        CREATE_THREAD        → set HW BP on new thread
    CheckRemoteDebuggerPresent()  → detach detection
```
HW BP manager: GetThreadContext/Wow64 → DR0-DR3/DR7, finds a free slot
(Local Enable bits 0,2,4,6), applies via SetThreadContext, verifies by re-reading. x64 + WOW64.
**This is why our DR registers were being cleared** — ECD manages its own 4 slots
and was clobbering ours (defeated with ScyllaHide).

### 1.3 Scan stages (14 — captured from runtime trace)
```
[650-654] Game detection (process enum)
[797] Search for mirrors...           (server mirrors)
[800] Get path list...                (scan roots)
[800] Check cheat db                  (SQLite DB matching engine)
[803] Scan modules 3/3
[803] Read game servers
[859] Prepare data 1/3 ... 3/3
[860] Write scan 25-55s
[860] Pings server                    (health check by/kz/ua.fungun.net)
+ loop: "Stage: Cheat [0xNNNN] — Scanning... Processed cheats NN%"
  (each [0xNNNN] = one signature record check from the DB — 419 IDs total)
+ Write access info
```

### 1.4 Scan subsystems
| Subsystem | Method |
|---|---|
| Process enum | CreateToolhelp32Snapshot + K32EnumProcessModulesEx + K32GetModuleFileNameExW (3 passes) |
| Memory scanner | VirtualQueryEx over the whole address space (skip MEM_FREE), **1024B overlap** chunks, RPM → "Injected_0x%I64x" marking |
| Inline hook detector | Steps through game code by pointer size, VQE PAGE_EXECUTE* check, reads 6 bytes before the address → prefix[0]==0xFF / [1]==0xE8 / [4]==0xFF = JMP/CALL trampoline → hooked/hookedaddr |
| HW BP manager | DR0-DR3/DR7, 4 slots, x64+WOW64 |
| Driver/service | OpenSCManagerW→QueryServiceStatusEx (acdrv, ggsvc), QueryDosDeviceW A-Z |
| Registry (2 passes) | BAM (EXE history!), DirectInput, AppSwitched (Alt-Tab!), MuiCache, SteamPath + snapshot compare |
| Browser history | Chrome History + Firefox places.sqlite → copy to temp → SQLite |
| Game files | Fake sprites (muzzIeflash5.spr!), obfuscated-name regex, engine.dll .text patch, **glVertex3fv hook (CS wallhack)**, recursive hashing |
| Network | GetExtendedTcpTable/UdpTable (PID-bound), checkIPsParallel (16 Cloudflare prefixes), named pipes |
| Other | Clipboard (CF_HDROP 512), exe.todel1 (%TEMP%), WinVerifyTrust+CertGetCertificateChain, DLL injection, parent process |

### 1.5 Encryption/obfuscation layers
1. **662+ XOR strings** (3 schemes: stack int16+key=code-addr, byte-lookup, word-table ~(A&B)&(A|B))
2. **Cheat DB**: SQLite (74MB, 18,103 pages, 33 tables) → 24B encrypted records → 100+ decoders, lazy-decode
3. **IAT obfuscation** (15 DLLs, import names encrypted)
4. **.text 94% NOACCESS** (self-protection)
5. **.ecd report**: deterministic (static key+nonce)
6. **RSA-2048** embedded public key (DB signature verification)
7. **XXH3** (96B default secret = v2_key96.bin) — whitelist hashing
8. **.fptable** section + asmjit (statically linked)

---

## 2. EVERYTHING OBTAINED WHILE REVERSING

### 2.1 Cheat signature list (REAL records decoded from the internal DB at runtime)

| Cheat File | Cheat Type | Signature |
|---|---|---|
| `../aimbot_undetectable.cfg` | aimbot (undetectable build) | DB record #0x1D |
| `limpid.dll` | limpid cheat DLL | DB record #0x1E |
| `../newhook.dll` | newhook cheat DLL | DB record |
| `../advhack v2/cvars.cfg` | advhack v2 (config check) | DB record |
| `super simple wall v2.6.dll` | Super Simple Wallhack v2.6 | DB record |
| `ninhook.dll` | ninhook cheat DLL | DB record |
| `vmhgs.dll` | vmhgs cheat DLL | DB record |
| `opengl32.dll` (system32 + SysWOW64 hook check) | OpenGL hook cheat (hooked copy of the legit DLL) | file hash check |
| `ods Cheat Defender Win8.exe` | Cheat Defender tool | file check |

Raw data: `ecd_cheat_files.txt` (283 unique cheat references)

### 2.2 Signature ID table (419 unique — FULL check list)
All signature record IDs checked during scan, extracted from a u16 array in memory:
```
Cheat [0x000530] - [0x00287C] — 419 UNIQUE IDs
Distribution: 124 (0x0xxx) + 187 (0x1xxx) + 108 (0x2xxx)
```
Full list: `ecd_signature_ids_full.txt`

Live-captured examples (scan trace): `Cheat [0x000161] [0x000568] [0x0005C9] [0x00060C] [0x00065F] [0x0082AE] [0x008399] [0x008436] [0x008482]`

### 2.3 Cheat Database structure (solved)
```
Format:        SQLite 3 (in-memory)
Size:          74MB (18,103 pages × 4096)
Tables:        33 (schema cookie)
Structure:     Game → Process → Module/DLL → Signature (hash, pattern, path)
Record size:   24 bytes (encrypted)
Decoder:       100+ functions, lazy-decode (decoded one by one per check)
Integrity:     CRC ("Internal db crc mismatch!") + RSA-2048 signature
Source:        RCDATA 103 (inside the exe, 68,544B base64 → 51,408B encrypted)
```

### 2.4 Tool/Debugger blacklist (COMPLETE — decoded)
```
Processes: ollydbg.exe, ida.exe, ida64.exe, idag.exe, idag64.exe, idaw.exe,
idaw64.exe, idaq.exe, idaq64.exe, idau.exe, idau64.exe, scylla.exe,
scylla_x64.exe, scylla_x86.exe, protection_id.exe, x64dbg.exe, x32dbg.exe,
windbg.exe, reshacker.exe, ImportREC.exe, IMMUNITYDEBUGGER.EXE, devenv.exe,
Procmon.exe, Procmon64.exe

Window titles: OLLYDBG, ida, disassembly, scylla, Debug, [CPU, Immunity,
WinDbg, x32dbg, x64dbg, Import reconstructor,
Process Monitor - Sysinternals: www.sysinternals.com, Zeta Debugger,
Rock Debugger, ObsidianGUI, WinDbgFrameClass, idawindow, tnavbox,
idaview, tgrzoom, PROCMON_WINDOW_CLASS

Anti-tamper API hook check: NtQuerySystemInformation, NtQueryVirtualMemory,
NtQueryInformationProcess, NtSetInformationThread, NtQueryInformationThread,
NtClose, NtCreateDebugObject, NtWriteVirtualMemory, NtCreateFile,
NtTerminateProcess, NtAllocateVirtualMemory, NtFreeVirtualMemory,
NtOpenProcess, NtOpenThread, NtCreateThread + DbgPrint, LdrAccessResource,
LdrGetProcedureAddress, LdrGetDllHandle, DbgBreakPoint, DbgUiRemoteBreakin
```

### 2.5 Report content (49 fields — captured as plaintext)
```
no_disk=0, spoof=0, mac=994B93992EB4, os_build=10.0.26200, scan=89c36c1d,
hw_id=1b0c336fb3c18f03cce2282f, parent=explorer.exe, hdd_id=0f1a4dcd,
scanner=3.32, steamid_reg=STEAM_0:1:23642595, win_id=1b48b519...,
xpbuild=0, gamefile=00000000, start_scan=1790235935, license=" at: 20260919",
gamename=Counter-Strike: 1.6(Steam), gameguard=0, bypassed=0, wine=0,
os=Microsoft Windows 11 Pro DESKTOP-46E378A(x64), gamestart=1790221230,
nick_cfg/nick_reg/nick_game, memorysize=192756620, scanned_fails=0,
gamecmd=-steam -game cstrike -windowed -w 800 -h 600, gamesteam=1,
gamepath=...\hl.exe, gamedir=...\Half-Life\, base=43e871fc,
pc_name=browser.pipe.aria.microsoft.com(luji), no_userdirs=0,
scanned_cheats=2483, signmode=0, gameclosed=0, end_scan=1790236500,
admin=1, system_utc=3, system_country=United Kingdom,
hwid=1b0c336f7ece-b3c18f0390c0-cce2282f32c0, debugger=3, badcounter=7,
system_langs=0809;0809;0409;
```

### 2.6 Scan inventory (13,253 unique paths — captured live)
```
Scan roots (top 5):
6250   C:\Program Files (x86)\Steam     ← game files (hash + cheat checks)
2124   C:\Users\luji                    ← user directories
1896   C:\Windows\System32              ← drivers/dlls
244    C:\Program Files\WindowsApps
242    C:\Windows\SysWOW64
+ ShareX, dotnet, Razer, Kaspersky, VSS shadow copies ($C:\Users\...),
  $Recycle.Bin, TeamSpeak, other user profiles

File types: .wav 2980, .dll 2560, .sys 787, .exe 759, .mdl 714,
.tga 631, .spr 496, .mp4 305, .txt 212, .bmp 194, .bsp 153, .lnk 150...

Whitelist checks (XXH3 — known-good):
valve\sound\x\*.wav (15: nih_die2, x_attack1-3, x_die1, x_laugh1-2,
x_pain1-3, x_recharge1-3, x_shoot1, x_teleattack1)
valve\sprites\hud_train_*, weapon_357_*, weapon_9mmhandgun*
valve\gfx\vgui\1600_arrowright.tga
```

### 2.7 Server/API information
```
Endpoints:  https://fungun.net/ecd/ (main), https://fungun.top/ (mirror)
            /ska/ecd.php?method=update | method=report
            /ecd/ajax/ecd_front.php (list/archive/remove)
API key:    xWey5BsRh1e36 (part of the DB-update URL path + offline .ecd)
Report JSON: injected/loaded/started/installed/downloaded/changer/
            hooked/hookedaddr/gamefile/demopath/path/browser/trash_path/time
Detection IDs: 32891 = antishield scan, 33625 = GameGuard driver bypass
Embedded RSA-2048 public key (PEM)
User-Agent: cpp-httplib/0.16.3
Cloudflare prefix scan: 103.21.244, 103.22.200, 104.16.0, ... (16 prefixes)
```

### 2.8 Process/module record formats (solved)
```
bmodules record:  [timestamp 8B][0x88][index u8][path UTF-16/ASCII]
report map:       [klen u8][key][vlen u16 LE][value]
process record:   [id 8B][0x88][idx] name|fullpath
```

---

## 3. ANTI-INJECT / ANTI-DEBUG METHODS AND THEIR BYPASSES

| # | ECD method | Mechanism | Our bypass | Result |
|---|---|---|---|---|
| 1 | **Image CRC32** (.text/.rdata/overlay) | Software BP (INT3) modifies code bytes → "damaged binary" | **Hardware BP** (code bytes untouched) | ✓ Bypassed |
| 2 | **DR register clearing** (own 4-slot HW BP manager) | Get/SetThreadContext clobbers our DRs | **ScyllaHide** NtSetContextThreadHook | ✓ Bypassed |
| 3 | **IsDebuggerPresent / CheckRemoteDebuggerPresent** | PEB BeingDebugged + DebugPort | ScyllaHide PebBeingDebugged + NtQueryInformationProcessHook | ✓ |
| 4 | **PEB HeapFlags / NtGlobalFlag** | debugger heap traces | ScyllaHide | ✓ |
| 5 | **NtClose invalid handle** | debugger detection | ScyllaHide NtCloseHook | ✓ |
| 6 | **ThreadHideFromDebugger** | hides debug events | ScyllaHide NtSetInformationThreadHook | ✓ |
| 7 | **NtQueryInformationProcess** (DebugPort/ObjectHandle) | port query | ScyllaHide hook | ✓ |
| 8 | **Anti-suspend watchdog** | escalates to REALTIME on freeze | NtSuspendProcess kept short (300ms) | ✓ ineffective in practice |
| 9 | **Anti-tamper timing** (7 sites, GetTickCount delta) | slowdown detection → "MENYA LOMAT' SUKING HACKER!" | we never patched code | ✓ |
| 10 | **Elevated self-relaunch** (ShellExecuteW "runas") | admin restart on Scan kills the debug session | **run x32dbg elevated** → ECD inherits the token | ✓ Bypassed |
| 11 | **Upload (method=report)** | POST to fungun.net | **Firewall + hosts + send BP** (3 layers) | ✓ Fully blocked |
| 12 | **String obfuscation** (662+ XOR) | blocks static analysis | decoder pattern solved statically (259) + runtime heap capture | ✓ Bypassed |
| 13 | **DB lazy-decode** (24B records, 100+ decoders) | plaintext DB never stored | post-scan heap keeps decoded entries → 12+ signatures | ✓ Partial |
| 14 | **Blacklist process names** | name scanning | **just rename the exe** (ECD itself says "Rename scanner to EasyCheatDetector.exe"!) | ✓ Trivial |
| 15 | **Blacklist window titles** | title scanning | rename the window | ✓ Trivial |
| 16 | **Authenticode verification** (per module) | WinVerifyTrust + INPLERON LTD issuer | broken on custom Windows builds (foreign repo note) | ✓ Weakness |

### Bypass (practical)
```
1. Run x32dbg ELEVATED (relaunch bypass) + ScyllaHide ECD profile
2. ONLY hardware BPs (bphws addr, x — CRC bypass)
3. Native debugger commands (bp/bphws/bc) — plugin tools fail silently
4. External watchers: NtSuspendProcess + ReadProcessMemory (elevated)
5. Cut the upload with firewall + hosts — independent of the debugger
6. Post-scan heap dump → decoded strings are still lying there
```

---

> **[ lujiangz ]**  
> *more updates when boredom strikes.*
