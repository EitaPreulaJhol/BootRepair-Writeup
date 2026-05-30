# BootRepair.sys — Full Driver Analysis w/ PoC.

> **Driver:** `BootRepair.sys`  
> **Version:** 2.5.30.11281  
> **Signed By:** Lenovo (Symantec time-stamped certificate)  
> **Build Date:** 2018-01-03  
> **Architecture:** x86-64 (PE32+, native NT driver)  
> **Compiler:** MSVC 14.0 (Visual Studio 2015)  
> **PDB:** `D:\Hud\jobs\pcmanager_trunk\workspace\Modules\lrtp\x64\Release\BootRepair.pdb`  
> **Source:** Part of the **Lenovo PcManager** suite (`pcmanager_trunk`)  
> **MD5:** 82699276b0f59a2304120a6baaf64a6b  
> **SHA256:** 5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946
---

## 1. Overview

`BootRepair.sys` is a Windows kernel-mode driver that acts as a **service installer and process terminator** for the Lenovo PcManager software suite. Despite its name, it contains significant functionality:

- Registers three system services by writing directly to the registry.
- Exposes an IOCTL that can **terminate an arbitrary process by PID** — a kill switch.
- Installation and service registration happen automatically at boot, before user logon.

The driver is digitally signed by Lenovo with a valid timestamp (Symantec CA chain), meaning it would load without issue on any x64 Windows system.

---

## 2. Driver Entry & Initialization (`DriverEntry`)

```
\Device\::BootRepair     -> device object
\DosDevices\BootRepair   -> symbolic link (accessible from user mode)
```

**Dispatch Table Setup:**

| MajorFunction | Handler | Purpose |
|---|---|---|
| 0 (IRP_MJ_CREATE) | `DispatchCreateClose` | Allow open |
| 2 (IRP_MJ_CLOSE)   | `DispatchCreateClose` | Allow close |
| 3 (IRP_MJ_READ)    | `DispatchCreateClose` | No-op |
| 4 (IRP_MJ_WRITE)   | `DispatchCreateClose` | No-op |
| 14 (IRP_MJ_DEVICE_CONTROL) | `DispatchDeviceControl` | IOCTL handler |
| 16 (IRP_MJ_SHUTDOWN) | `DispatchShutdown` | Triggers service install |

On load (`DriverEntry`):

1. Creates `\Device\::BootRepair` (a device with an unusual double-colon `::` name — this may be intentional to obscure it).
2. Spawns a **system thread** running `StartRoutine` — this is where the real work begins.
3. Creates a Win32-visible symbolic link `\DosDevices\BootRepair`.
4. Registers for shutdown notification (to install services on shutdown as a fallback).

---

## 3. Service Installation Engine

The core of the driver is the `InstallLenovoServices()` function. It:

1. **Reads the application install path** from the registry:
   ```
   HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
     \{A9861883-31C5-4324-BD9A-DC9527EEB675}_is1 -> InstallLocation
   ```
   This GUID corresponds to the Lenovo PcManager application installer (maybe InnoSetup, I think...).

2. **Constructs image paths** for three services by concatenating the install path with service EXE names.

3. **Creates registry keys** under `HKLM\SYSTEM\ControlSet001\Services\` for all three services.

4. **Writes detailed service configuration** including security descriptors.

### Services Registered

#### LenovoPcManagerService

| Field | Value |
|---|---|
| ImagePath | `<InstallPath>\LenovoPcManagerService.exe` |
| Start | `4` (SERVICE_DISABLED) |
| Type | `0x10` (SERVICE_WIN32_OWN_PROCESS) |
| ErrorControl | `0` (SERVICE_ERROR_IGNORE) |
| ObjectName | `LocalSystem` |
| DisplayName | `LenovoPcManagerService` |
| Description | (17 chars, stored in `descLenovoPcMgr`) |
| Security | Custom SDDL via `\Security` subkey |

#### LenovoDRS

| Field | Value |
|---|---|
| ImagePath | `<InstallPath>\LenovoDRS.exe` |
| Start | `4` (SERVICE_DISABLED) |
| Type | `0x10` (SERVICE_WIN32_OWN_PROCESS) |
| ErrorControl | `0` (SERVICE_ERROR_IGNORE) |
| ObjectName | `LocalSystem` |
| DisplayName | `LenovoDRS` |
| Description | (17 chars, stored in `descLenovoDRS`) |
| Security | Custom SDDL via `\Security` subkey |

#### LAVService

| Field | Value |
|---|---|
| ImagePath | `<InstallPath>\Security\service\LAVService.exe` |
| Start | `1` (SERVICE_AUTO_START) / delayed |
| Type | `0x10` (SERVICE_WIN32_OWN_PROCESS) |
| ErrorControl | `0` (SERVICE_ERROR_IGNORE) |
| ObjectName | `LocalSystem` |
| DisplayName | `LAVService` |
| DependOnService | `RPCSS` |
| DelayedAutostart | `1` (true) |
| Security | Custom SDDL via `\Security` subkey |

---

## 4. Installation Retry Logic (`StartRoutine`)

`StartRoutine` runs as a system thread invoked during `DriverEntry`:

```c
while (!g_InstallDone) {
    if (InstallLenovoServices() >= 0)
        break;
    if (retries > 3000)   // ~10 minutes total (3000 × 200ms)
        break;
    retries++;
    DelayMs(200);
}
g_InstallDone = 1;
PsTerminateSystemThread(0);
```

- Retries every **200 ms**, up to **3000 times** (~10 minutes total).
- This aggressive retry suggests the driver expects the registry/uninstall key to appear shortly after boot (i.e., the user-mode installer may still be running).

---

## 5. IOCTL Interface & Process Termination

### IOCTL 0x00222214 (`DispatchDeviceControl`)

The device control handler (`sub_140001020`) checks for a specific control code:

```c
CurrentStackLocation->Parameters.Read.ByteOffset.LowPart == 0x00222214
```

When triggered:

1. Validates the IRP has an **associated MasterIrp** (i.e., this is an IRP_MJ_DEVICE_CONTROL sent with `Irp->AssociatedIrp.MasterIrp`).
2. Checks that `CurrentStackLocation->Parameters.Create.Options == 4` (this is an unusual reuse of the `Create` union field — possible version negotiation or magic constant).
3. Calls `TerminateProcess(MasterIrp->Type)` — where `Type` is interpreted as a **PID**.

### TerminateProcess Function

```c
NTSTATUS TerminateProcess(HANDLE ProcessId) {
    PsLookupProcessByProcessId(ProcessId, &Process);
    ObOpenObjectByPointer(Process, ..., 0x1FFFFFu, ...);
    ZwTerminateProcess(ProcessHandle, 0);
    ObfDereferenceObject(Process);
    ZwClose(ProcessHandle);
    return STATUS_SUCCESS;
}
```

This is a **process-kill primitive** accessible from user mode through the `\\.\BootRepair` device handle.

**Security implication:** Any process (even running as Medium IL / non-admin, provided the driver is accessible) that can open the device can send an IOCTL to kill **any process on the system**, including critical system processes, anti-malware products, or EDR agents.

---

## 6. Shutdown Fallback (`DispatchShutdown`)

When the system shuts down (`IRP_MJ_SHUTDOWN`), the driver checks `KeGetCurrentIrql() == 0` and calls `InstallLenovoServices()` directly. This ensures the services are installed even if the system thread didn't complete the task earlier.

---

## 7. Complete Import Table

**`ntoskrnl.exe`** imports:

| Function | Purpose |
|---|---|
| `RtlInitUnicodeString` | String initialization |
| `KeDelayExecutionThread` | Sleep/delay |
| `ExFreePoolWithTag` | Memory deallocation |
| `PsCreateSystemThread` | Thread creation |
| `PsTerminateSystemThread` | Thread termination |
| `IofCompleteRequest` | IRP completion |
| `IoCreateDevice` | Device object creation |
| `IoCreateSymbolicLink` | DOS device symlink |
| `IoDeleteDevice` | Device cleanup |
| `IoDeleteSymbolicLink` | Symlink cleanup |
| `IoRegisterShutdownNotification` | Shutdown callback |
| `ZwCreateKey` | Registry key creation |
| `ZwOpenKey` | Registry key open |
| `ZwSetValueKey` | Write registry value |
| `ZwQueryValueKey` | Read registry value |
| `ZwFlushKey` | Flush registry |
| `ZwClose` | Close handle |
| `ZwTerminateProcess` | Process termination |
| `PsLookupProcessByProcessId` | Process lookup |
| `ObOpenObjectByPointer` | Get handle from object |
| `ObfDereferenceObject` | Dereference object |
| `ExAllocatePool` | Memory allocation |
| `RtlCompareMemory` | Memory comparison |

---

## 8. Security Analysis Summary

| Risk | Description |
|---|---|
| **Abusable IOCTL** | IOCTL 0x00222214 allows terminating any process if a user-mode component can open the device |
| **Permissive ACL** | No authentication or ACL check in the dispatch — any handle-holder can kill arbitrary PIDs |
| **Driver is signed** | Lenovo signing means it would load on (almost) any x64 Windows system |

---

## 9. Appendix — Reconstructed Function Map

| RVA | Function Name | Description |
|---|---|---|
| `0x1000` | `DispatchCreateClose` | No-op IRP handler |
| `0x1020` | `DispatchDeviceControl` | IOCTL dispatcher (kill process) |
| `0x1084` | `DispatchShutdown` | Shutdown handler (re-installs services) |
| `0x10B8` | `DelayMs` | KeDelayExecutionThread wrapper |
| `0x10E0` | `InstallLenovoServices` | Core service installation routine |
| `0x1930` | `StartRoutine` | System thread (retry loop) |
| `0x198C` | `TerminateProcess` | ZwTerminateProcess implementation |
| `0x1A20` | `RegWriteConditional` | Conditional registry write |
| `0x1AEC` | `CreateRegKey` | ZwCreateKey wrapper |
| `0x1BB4` | `RegReadValue` | ZwQueryValueKey wrapper |
| `0x1DC0` | `RegWriteValue` | ZwSetValueKey wrapper |
| `0x2440` | `fast_memset` | Optimized memset |
| `0x7000` | `DriverEntry` | Entry point |

---
