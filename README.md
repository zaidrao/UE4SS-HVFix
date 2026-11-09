# UE4SS-HVFix

A lightweight proxy DLL fix for RE-UE4SS (Unreal Engine 4/5 Scripting System) on games running with hypervisor-assisted or kernel-level virtualization loaders.

## The Problem

When running an Unreal Engine game that uses hypervisor or driver-based virtualization layers (such as certain anti-tamper or custom bypass loaders), UE4SS often fails on launch with this error in `UE4SS.log`:

```text
Fatal Error: Was unable to enumerate game modules. Error: [0x6] The handle is invalid.
```

### Why does this happen?
To perform signature scanning and initialize its hooks, UE4SS queries Windows using standard PSAPI functions:
* `K32EnumProcessModules`
* `K32GetModuleInformation`

Even though UE4SS passes the current process pseudo-handle, the underlying system queries are intercepted or restricted by the virtualization driver. Windows returns error code `0x6` (`ERROR_INVALID_HANDLE`), causing UE4SS to abort before loading any scripts or mods.

## The Fix

Instead of modifying the game executable or patching `UE4SS.dll` on disk, this fix replaces the proxy loader (`dwmapi.dll`):

1. **Clean Export Forwarding**: Forwards all 118 functions to the real `C:\Windows\System32\dwmapi.dll`. The game gets full, untouched windowing support.
2. **Loads Stock UE4SS**: Loads `ue4ss\UE4SS.dll` completely unmodified into memory.
3. **In-Memory IAT Hooking**: Intercepts `K32EnumProcessModules`, `K32GetModuleInformation`, and related module name calls inside `UE4SS.dll`'s memory.
4. **Self-Contained In-Process Fallback**: If the standard Windows call fails with error `0x6`, our hook catches it and builds the module list directly by reading the process's own loader list (`PEB->Ldr->InLoadOrderModuleList`) and PE headers. Because this memory already belongs to the process, no system calls or process handles are required.

The game files and `UE4SS.dll` remain 100% untouched on disk.

## Installation

If you do not want to compile from source, grab the prebuilt `dwmapi.dll` from the **Releases** tab.

1. Install UE4SS into your game folder next to the main executable as instructed by your game's modding guide (typically placing `dwmapi.dll` and the `ue4ss` folder in the same directory as the game `.exe`).
2. Replace the default `dwmapi.dll` with the `dwmapi.dll` from this project.
3. Launch the game normally.

### Verifying It Works
Check your `ue4ss` folder for:
* `UE4SS-HVFix.log`: Created by this proxy. It confirms the import hooks were applied and logs the fallback module enumeration.
* `UE4SS.log`: The "unable to enumerate game modules" error should be gone, and UE4SS should continue initializing its subsystems and loading mods.

## Tested Setup

This fix was developed and verified on the following setup:

* **Operating System**: Windows 11 64-bit (Build 26200)
* **Processor / Platform**: AMD x64 (AuthenticAMD)
* **Game**: Phantom Blade Zero
* **Virtualization Layer**: Kernel-level driver / hypervisor loader (`Artifact_AMD`)
* **UE4SS Version**: [UE4SS v3.0.1-1195-g1ceefac8](https://github.com/KintaroModding/ue4ss/releases/download/v3.0.1-1195-g1ceefac8/phantombladezero_ue4ss_v3.0.1-1195-g1ceefac8.zip)
* **Mod Verified**: [PBZTrainer v1.4.2](https://www.nexusmods.com/phantombladezero/mods/185) (verified with both Lua scripts and native C++ `PBZTProof\dlls\main.dll`)

## Using This On Other Games

If you are playing a different Unreal Engine game that fails with `Error: [0x6] The handle is invalid` under a hypervisor or custom driver setup, the same core fix should work.

A couple things to keep in mind:

1. **Proxy DLL Name**:
   This release is compiled as `dwmapi.dll`. If your game loads a different proxy DLL (for example, `dxgi.dll`, `version.dll`, or `xinput1_3.dll`), you will need to recompile the project under that name.
2. **Export Forwarding**:
   The proxy must forward all exports of that target system DLL to `C:\Windows\System32\<name>.dll`. The included Python script (`gen_exports.py`) can generate the required export forwarding table automatically from your system's DLL using dumpbin.

## Building from Source

Requirements:
* Visual Studio 2022 / Build Tools (MSVC C++ x64)
* Python 3.x (to generate the export forwarding header)

Run `build.bat` in the project root:
```cmd
build.bat
```
The compiled DLL will be generated in `build\dwmapi.dll`.


## Disclaimer

This project is shared for educational and research purposes only. It does not bypass, remove or modify any DRM, anti-tamper or game protection. It only helps UE4SS read the module list of the process it is already running in.

All credit for UE4SS goes to the RE-UE4SS team and the KintaroModding fork maintainers, and all credit for mods goes to their original authors. This project is not affiliated with them or with any game developer or publisher.

Please support the developers and always get your games from official sources. Use this at your own risk.
