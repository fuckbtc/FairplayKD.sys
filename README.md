# FairplayKD.sys
# Analysis of FairplayKD.sys — MTA:SA Anti-Cheat Kernel Driver

---

## Identification

| Field | Value |
|-------|-------|
| **Type** | PE64 kernel driver (.sys), x86-64, AMD64 |
| **Project** | Multi Theft Auto: San Andreas (MTA:SA) — anti-cheat subsystem |
| **File location** | `C:\ProgramData\MTA San Andreas All\Common\temp\FairplayKD.sys` |
| **PDB path** | `c:\teamcity\buildagent\work\4c4bca432894da66\shared\tools\kerneldrivers\fairplay_7\objfre_win7_amd64\amd64\Fairplay_7.pdb` |
| **Build tag** | `fairplay_7` — 7th major revision of the Fairplay driver |
| **Timestamp** | Sun Dec 20 04:41:10 2015 |
| **IDA database** | 64-bit .i64 (IDA Pro 9.1) |
| **String obfuscation** | Custom XOR cipher: `decrypted[i] = (((3 - i) ^ (encrypted[i] & 0x7F)) - (i * i)) & 0x7F` |
| **API resolution** | All kernel routines resolved dynamically via `MmGetSystemRoutineAddress` — zero static imports for sensitive APIs |
| **Aux library** | `AuxKlib` (auxiliary kernel library) for module enumeration |
| **Multi-instance** | Supports up to 4 simultaneous instances (`FairplayKD0`–`FairplayKD3`), instance number read from registry modulo 4 |
| **Usermode partner** | `netc.dll` (the MTA network layer, documented separately) — sole IOCTL caller |

---

## Architecture

```
  netc.dll (usermode, MTA client)
       │
       │  DeviceIoControl(0x22E008)
       │  Magic: 363 (0x16B), + checksum
       v
  ┌──────────────────────────────────────────────────────────┐
  │  FairplayKD.sys (kernel, Ring-0)                          │
  │                                                            │
  │  DriverEntry                                               │
  │    ├── CheckWindowsVersion → dword_22E94 (OS ID)          │
  │    ├── ReadDeviceInstanceFromRegistry → g_DeviceInstance  │
  │    ├── ResolveKernelRoutines (15+ encrypted API names)    │
  │    ├── ResolveAllKernelRoutines (10+ more)                │
  │    ├── IoCreateDevice → \Device\FairplayKD{n}             │
  │    ├── IoCreateSymbolicLink → \DosDevices\FairplayKD{n}   │
  │    ├── PsSetCreateProcessNotifyRoutineEx → ProcessCreationNotifyCallback
  │    └── ObRegisterCallbacks → ObPreProcess + ObPreThread   │
  │                                                            │
  │  IRP_MJ_DEVICE_CONTROL → HandleDeviceIoControl            │
  │    └── ProcessIoctlCommand (dispatcher, cmds 1 + 120–143) │
  │                                                            │
  │  Process Tracking Table (g_ProcessTrackingTable)          │
  │    100 entries × 16 bytes: [HANDLE | DWORD type | DWORD flags]
  │                                                            │
  │  Log Buffer (qword_1E2A0)                                 │
  │    100 slots × 2 bytes (WORD), thread-safe via            │
  │    atomic increment on byte_22FF6                         │
  └──────────────────────────────────────────────────────────┘
       │
       │  Kernel callbacks
       ├── PsSetCreateProcessNotifyRoutineEx  → ProcessCreationNotifyCallback
       ├── PsSetLoadImageNotifyRoutine        → DLL injection monitoring
       └── ObRegisterCallbacks (process + thread) → ObPreProcessCallback / ObPreThreadCallback
```

---

## IOCTL Interface — Command Dispatcher

**IOCTL code:** `0x22E008` (decimal 2285576)  
**All commands require:**
- Magic number `363` (0x16B) in input buffer header
- Valid checksum computed by `ValidateInputBufferChecksum`
- Minimum input buffer size per-command (varies)

### Full Command Table

| Cmd (hex) | Cmd (dec) | Name / Purpose | Notes |
|-----------|-----------|----------------|-------|
| `0x01` | 1 | **Version handshake** | Returns `363` (0x16B) to netc.dll; protocol version check |
| `0x78` | 120 | **Read kernel memory** | Copies from kernel address to output buffer; used for scanning |
| `0x79` | 121 | **Get kernel module base** | Returns `ntoskrnl.exe` base + export table info; if `InputBuffer[2]==1` |
| `0x7A` | 122 | **Resolve kernel routine** | Calls `MmGetSystemRoutineAddress` on a user-supplied name; hook detection |
| `0x7C` | 124 | **Write kernel memory** | Patches kernel-mode memory; used for hooking operations |
| `0x7E` | 126 | **Get log buffer status** | Returns log length, max length, and full `CollectProcessTrackingInfo` output |
| `0x80` | 128 | **Validation ping** | Input length = 32; validates magic + checksum only; returns success |
| `0x81` | 129 | **Validation ping** | Input length = 12; same validation, different expected size |
| `0x82` | 130 | **Tag process as type 6** | Marks a process as "system/launcher" (GTA:SA) in tracking table, action=manual |
| `0x83` | 131 | **Tag process as type 5** | Marks a process as "user/protected" (MTA client) in tracking table, action=manual |
| `0x84` | 132 | **Query module/system info** | `type 0xBB8` → `AuxKlibQueryModuleInformation`; else → `ZwQuerySystemInformation` |
| `0x85` | 133 | **Monitor memory range (DLL inject)** | Registers `PsSetLoadImageNotifyRoutine` for every 4-byte-aligned addr in range |
| `0x86` | 134 | **Enumerate handles for HWID** | `ExEnumHandleTable` → collects all handles of current process for serial generation |
| `0x87` | 135 | **Open process by PID** | `PsLookupProcessByProcessId` + `ObOpenObjectByPointer`; returns handle |
| `0x88` | 136 | **Get process image name** | `GetProcessImageNameQuery`; copies full path to output buffer + checksum |
| `0x89` | 137 | **Write memory to thread** | `WriteMemoryToThread`; writes arbitrary data to thread context |
| `0x8A` | 138 | **Resume thread + inject** | Opens thread, writes shellcode/data to context, calls `ZwResumeThread` — **DLL injection primitive** |
| `0x8B` | 139 | **Query thread information** | `ThreadBasicInformation` (class 5, 24 bytes) + `ThreadContextInformation` (class 4, 40 bytes) |
| `0x8C` | 140 | **Read process memory** | `ReadMemoryFromProcess` via `PsLookupProcessByProcessId` callback; multi-thread support |
| `0x8D` | 141 | **Lookup by Client ID (CID)** | `PsLookupProcessThreadByCid`; returns process + thread objects |
| `0x8F` | 143 | **Lookup thread by TID** | `PsLookupThreadByThreadId`; returns thread object pointer |

---

## IOCTL Flow — Full Call Trace

```
netc.dll → DeviceIoControl(handle, 0x22E008, inputBuf, inputLen, outputBuf, outputLen)
  │
  └─ kernel IRP_MJ_DEVICE_CONTROL
       │
       └─ HandleDeviceIoControl(DeviceObject, Irp)
            │
            ├─ Extract IO stack location
            ├─ Get InputBuffer, OutputBuffer, lengths from IO_STACK_LOCATION
            ├─ Call ProcessIoctlCommand(...)
            │     │
            │     ├─ ValidateInputBuffer:
            │     │   ├─ Check InputBuffer[0] == 363 (magic)
            │     │   ├─ Check length >= minimum for command
            │     │   └─ ValidateInputBufferChecksum → reject if tampered
            │     │
            │     ├─ switch(command):
            │     │   ├─ cmd 1   → write 363 to OutputBuffer[0]
            │     │   ├─ cmd 0x78→ memmove(OutputBuffer, KernelAddr, len)
            │     │   ├─ cmd 0x79→ GetKernelModuleBase(ntoskrnl) → base + exports
            │     │   ├─ cmd 0x7A→ MmGetSystemRoutineAddress(RoutineName) → ptr
            │     │   ├─ cmd 0x7C→ write to KernelAddr
            │     │   ├─ cmd 0x7E→ CollectProcessTrackingInfo(OutputBuffer)
            │     │   ├─ cmd 0x85→ MonitorMemoryRange(start, end)
            │     │   │             for addr in range step 4:
            │     │   │               PsSetLoadImageNotifyRoutine(addr)
            │     │   ├─ cmd 0x86→ EnumerateProcessHandles(CurrentProcess)
            │     │   │             ExEnumHandleTable(CurrentProcess, callback)
            │     │   │               callback: if handle.process == CurrentProcess
            │     │   │                 append handle to OutputBuffer
            │     │   ├─ cmd 0x8A→ WriteAndResumeThread(ThreadId, Data, Len)
            │     │   │             OpenThreadByThreadId(ThreadId)
            │     │   │               → ZwCreateThreadEx (open mode, suspended=1)
            │     │   │             WriteMemoryToThread(ThreadHandle, Data)
            │     │   │             ZwResumeThread(ThreadHandle)  ← DLL injection
            │     │   └─ ...
            │     │
            │     └─ On failure: log "Command %d failed (uiParsedVersion:%d)"
            │
            ├─ Set Irp->IoStatus.Status and Irp->IoStatus.Information
            └─ IoCompleteRequest(Irp, IO_NO_INCREMENT)
```

---

## Process Tracking System

### Table Structure

```c
// g_ProcessTrackingTable = unk_20140
// Max 100 entries (dword_22FF0 = current count)
struct ProcessTableEntry {   // 16 bytes total
    HANDLE  ProcessHandle;   // offset 0x00 (8 bytes)
    DWORD   ProcessType;     // offset 0x08 (4 bytes)
    BYTE    FlagByte;        // offset 0x0C (1 byte) — special status
    BYTE    Padding[3];      // offset 0x0D
};
```

### Process Type Enum

| Type | Value | Process(es) | Role |
|------|-------|-------------|------|
| Unknown | 1 | (unclassified) | Auto-classified or blocked |
| CSRSS | 2 | `csrss.exe` | Windows Client/Server Runtime |
| LSASS | 3 | `lsass.exe` | Local Security Authority |
| SVCHOST | 4 | `svchost.exe` | Service Host |
| **MTA Client** | **5** | MTA.exe (usermode) | Protected/user process — **target** |
| **GTA:SA** | **6** | `gta_sa.exe`, `proxy_sa.exe` | Launcher/system process — **target** |
| RaidCall | 7 | `raidcall.exe` | VoIP app (monitored) |
| Logitech | 8 | `LVPrcSrv.exe`, `LWEMon.exe` | Gaming peripheral processes |
| Action! | 9 | `Action_x64.bin`, `Action_x86.bin` | Screen recording — **cheating tool** |

> Types 1–4 are system processes. Types 5 and 6 are the two halves of the MTA game stack.  
> Type 9 (Action!) is flagged as a cheat tool (screen capture for aimbot input).

### Classification Flow

```
ProcessCreationNotifyCallback(ParentPid, ChildPid, IsCreation)
  │
  ├─ IsCreation == false → RemoveProcessFromTable(ChildPid)
  │
  └─ IsCreation == true:
       ├─ GetProcessTypeFromTable(ChildPid)
       ├─ If type == 0 (unknown) → ClassifyProcessByImageName(ChildImageName)
       │     ├─ EndsWith "csrss.exe"        → return 2
       │     ├─ EndsWith "lsass.exe"        → return 3
       │     ├─ EndsWith "svchost.exe"      → return 4
       │     ├─ EndsWith "gta_sa.exe"       → return 6
       │     ├─ EndsWith "proxy_sa.exe"     → return 6
       │     ├─ EndsWith "raidcall.exe"     → return 7
       │     ├─ EndsWith "LVPrcSrv.exe"     → return 8
       │     ├─ EndsWith "LWEMon.exe"       → return 8
       │     ├─ EndsWith "Action_x64.bin"   → return 9
       │     ├─ EndsWith "Action_x86.bin"   → return 9
       │     └─ else                        → return 1 (unknown)
       │
       ├─ If classified type == 1 (allowed) → skip blocking, allow
       └─ Else → UpdateProcessTypeInTable(type, action=auto)
                 If parent is type 5 and count(type5) > 1:
                   Log "Launcher %d (%s) creating process %d (%s)"
                 If type != 1: return non-zero → BLOCK process creation
```

---

## HWID / Serial Generation Pipeline

Command `0x86` feeds data into a two-part HWID generation system used by `netc.dll` to produce MTA's unique game serial.

```
netc.dll:                           FairplayKD.sys:
                                    ┌───────────────────────────────────────┐
cmd 0x86 (EnumerateProcessHandles)  │ ExEnumHandleTable(CurrentProcess, cb) │
  ──────────────────────────────►   │   for each handle in process table:   │
                                    │     if handle.process == current:      │
                                    │       append HANDLE to OutputBuffer   │
                                    └───────────────────────────────────────┘
                  ◄──────────────── [ handle array ]

cmd 0x7E (CollectProcessTrackingInfo)
  ──────────────────────────────►   OutputBuffer layout:
                                    +0x10: g_ProcessThreadCallbacksRegistered
                                    +0x20: ptr to CollectProcessTrackingInfo (self-verify)
                                    +0x28: count of type 6 (GTA:SA) processes
                                    +0x2C: up to 3 handles of type 6
                                    +0x44: count of type 5 (MTA) processes
                                    +0x48: up to 3 handles of type 5
                  ◄──────────────── [ tracking snapshot ]

netc.dll hashes: { collected handles } + { tracking snapshot } + { other system identifiers }
  → unique HWID / serial for MTA game authentication server
```

---

## Kernel API Resolution — Obfuscation Layer

All sensitive kernel APIs are resolved at runtime using a custom two-step scheme:

### Decryption Algorithm
```c
// Applied to encrypted byte array stored in .data
decrypted[i] = (((3 - i) ^ (encrypted[i] & 0x7F)) - (i * i)) & 0x7F;
```

### Resolution Pattern (lazy + cached)
```c
// Every resolver follows this template:
PVOID ResolveFunctionXxx() {
    if (g_pFunctionXxx != NULL)          // check cache
        return g_pFunctionXxx;
    DecryptBytes(encrypted_buf, n);      // decrypt name in-place
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, decrypted);
    g_pFunctionXxx = MmGetSystemRoutineAddress(&us);  // resolve
    return g_pFunctionXxx;
}
```

### Full Encrypted API Inventory

| API Name | Usage |
|----------|-------|
| `ExEnumHandleTable` | Enumerate all handles of a process (HWID) |
| `PsLookupProcessByProcessId` | Get EPROCESS from PID |
| `ZwQuerySystemInformation` | System/module information queries |
| `PsRemoveCreateProcessNotifyRoutine` | Cleanup on unload |
| `PsSetCreateProcessNotifyRoutineEx2/3` | Register process creation callback |
| `ObGetObjectType` | Identify kernel object type |
| `ExfUnblockPushLock` | Get process object from handle (Win10 v61+) |
| `PsRemoveLoadImageNotifyRoutine` | Cleanup DLL injection monitoring |
| `ObfDereferenceObject` | Release object reference |
| `IoCreateDevice` | Create `\Device\FairplayKD{n}` |
| `IoCreateSymbolicLink` | Create `\DosDevices\FairplayKD{n}` |
| `IoDeleteSymbolicLink` | Cleanup on unload |
| `IoDeleteDevice` | Cleanup on unload |
| `IoCompleteRequest` | Complete IRP responses |
| `PsGetCurrentProcessId` | Self-identification |
| `PsGetCurrentThreadId` | Self-identification |
| `ZwOpenKey` | Registry access (instance number) |
| `ZwQueryValueKey` | Read instance number value |
| `ZwClose` | Close handles |
| `ZwOpenThread` | Open thread by TID |
| `ZwCreateThreadEx` | Used in "open existing" mode for thread access |
| `ZwResumeThread` | Resume thread after memory write (injection) |
| `AuxKlibInitialize` | Initialize auxiliary kernel library |
| `AuxKlibQueryModuleInformation` | List loaded kernel modules |
| `ObOpenObjectByPointer` | Open handle from object pointer |

---

## Kernel Callbacks

```
DriverEntry
  │
  ├─ PsSetCreateProcessNotifyRoutineEx(ProcessCreationNotifyCallback)
  │     Fires on every process creation/termination in the system
  │     → ClassifyProcessByImageName
  │     → UpdateProcessTrackingTable
  │     → Block non-type-1 child processes if parent is type 5
  │
  ├─ ObRegisterCallbacks:
  │     ├─ OB_OPERATION_HANDLE_CREATE  (process) → HandleObPreProcessCallback
  │     │     Logs: process open by launcher (type 6)
  │     │     Exception wrapper: LogObPreProcessCallbackException
  │     │
  │     └─ OB_OPERATION_HANDLE_CREATE  (thread)  → HandleObPreThreadCallback
  │           Checks PsThreadType, gets thread→process, verifies launcher
  │           Exception wrapper: LogObPreThreadCallbackException
  │
  └─ PsSetLoadImageNotifyRoutine (registered per-address by cmd 0x85)
        Fires when any image is loaded into monitored address range
        → DLL injection detection for MTA process space
```

---

## Windows Version Compatibility

| OS Version ID | OS Name | Notes |
|--------------|---------|-------|
| 51 (0x33) | Windows XP | Supported (handle offset -0x20) |
| 52 (0x34) | Windows Server 2003 | Supported |
| 60 (0x3C) | Windows Vista | Supported |
| 61 (0x3D) | Windows 7 | **Primary target**; pattern scan for PsLookupProcessByProcessId internals |
| 62 (0x3E) | Windows 8 | Supported; different handle-to-object path |
| 63 (0x3F) | Windows 8.1 | Supported |
| ≥ 62 | Win8+ | Uses `ExfUnblockPushLock` path instead of offset-0x20 |
| ≥ 64 | Windows 10+ | Explicitly **unsupported** — driver returns error |

> The driver was compiled in 2015 and predates Windows 10's mainstream adoption.  
> Win10 support ends at version ID `< 62`. Any client running Win10 would cause CheckWindowsVersion to fail.

---

## Path Normalization

`NormalizeThreadImagePath` standardizes all logged paths:

| Original | Normalized |
|----------|-----------|
| `\Device\HarddiskVolume3\...` | `C:\...` (actual drive letter) |
| `\Windows\System32` | `\WS32` |
| `\Program Files` | `\PF` |

---

## Log Buffer

```
g_LogBuffer = qword_1E2A0
  - 100 slots (0x64)
  - Each slot: 2 bytes (WORD), 0 = free
  - Thread-safe: atomic increment on byte_22FF6
  - If byte_22FF6 == 1 (first concurrent writer): update log length atomically
  - Free slot search: linear scan; if full → slot 0 (overwrite)
  - Messages: wide-char, max 300 characters (vsnwprintf)
```

Notable log strings (decrypted at runtime):
- `"Launcher %d (%s) creating process %d (%s)"`
- `"TableFullError"` — process table at 100 entries
- `"Command %d failed (uiParsedVersion:%d)"`
- `"ObPreProcessCallbackSafe caused exception"`
- `"ObPreThreadCallbackSafe caused exception"`
- `"Add"` — process type added/updated
- `"removing"` — process removed on termination

---

## Protection Mechanisms

1. **String encryption** — all sensitive strings (function names, device names, log messages) stored encrypted; decrypted inline at use site, no static strings visible in binary.

2. **Dynamic API resolution** — every kernel routine resolved via `MmGetSystemRoutineAddress` at runtime. Static analysis tools find zero `IMPORT` references for sensitive APIs. Also enables cross-version portability.

3. **Input buffer validation** — every IOCTL command validates magic number `363`, buffer size, and checksum before processing. Prevents crafted/replayed IOCTL attacks.

4. **Process creation blocking** — `PsSetCreateProcessNotifyRoutineEx` callback can return a blocking NTSTATUS for any process classified as non-type-1 spawned from MTA context.

5. **DLL injection detection (cmd 0x85)** — registers load-image callbacks on the entire target process address range; detects any image loaded into MTA memory.

6. **ObRegisterCallbacks** — pre-operation callbacks on process/thread handle creation; allows the driver to monitor (and potentially strip access rights from) any process attempting to open MTA or GTA:SA.

7. **Anti-screen-capture** — `Action_x64.bin` / `Action_x86.bin` (Action! recording software) classified as type 9 (implicitly treated as cheat tool); its process creation can be blocked.

8. **HWID binding** — serial generated from kernel-level handle enumeration; cannot be replicated from usermode alone.

9. **Self-verification pointer** — `CollectProcessTrackingInfo` stores its own function pointer in the output buffer at offset 0x20; `netc.dll` can verify the pointer matches the expected kernel address to detect tampering.

10. **Multi-instance isolation** — up to 4 driver instances (`FairplayKD0`–`FairplayKD3`) via registry; prevents name-squatting attacks against the device object.

---

## GetKernelModuleBase — Anti-Hook Technique

Used by command `0x79` and internally by hook-detection paths:

```c
// Walk backwards from ZwTerminateThread's known address
// searching for MZ PE header signature
PVOID GetKernelModuleBase() {
    PVOID addr = (PVOID)ZwTerminateThread;    // start from known export
    for (int page = 0; page < 0x2710; page++) {  // up to 10,000 pages = 40MB
        addr = (PVOID)((ULONG_PTR)addr & ~0xFFF);  // align to page
        if (*(USHORT*)addr == 0x5A4D) {            // 'MZ'
            // validate PE header at addr + *(DWORD*)(addr+0x3C)
            if (*(DWORD*)((char*)addr + *(DWORD*)((char*)addr+0x3C)) == 0x00004550)
                return addr;                        // 'PE\0\0'
        }
        addr = (PVOID)((ULONG_PTR)addr - 0x1000);  // previous page
    }
    return NULL;
}
```




