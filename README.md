# Dagor Dumper

A runtime memory analyzer for games built on Gaijin's **Dagor Engine** (daECS). It injects into the game process, walks the engine's own registration data structures and RTTI, and dumps a structural map of the ECS: component types, component slots, archetypes, live entities, entity templates, native struct field offsets, and C++ class RTTI - in the spirit of what Il2CppDumper does for Unity IL2CPP.

## Why this exists

The [open-source DagorEngine tree](https://github.com/GaijinEntertainment/DagorEngine) tells you the *shape* of every ECS structure - field order, container semantics, invariants - but not the absolute offsets in a specific shipped build, since any fork adds or removes members. **Nothing in this tool hardcodes an offset.** Every address is *discovered* by matching a structural signature in live memory and then cross-validated against an independent invariant (e.g. an archetype table isn't accepted until the sum of its per-archetype entity counts matches the entity count computed independently from `entDescs`). See the comments at the top of [`include/ecs_runtime.h`](include/ecs_runtime.h), [`include/das_rtti.h`](include/das_rtti.h), and [`src/em_locator.cpp`](src/em_locator.cpp) for the discovery recipe used at each stage.

## What it dumps

| Source | What you get |
|---|---|
| ECS registration chains | Component type names, FNV-1a hashes, sizes, flags (`POD`/`BOXED`/`RES`/`NET`/...); component slot names; registered events |
| Runtime ECS layout | `EntityManager`, `entDescs`, archetype table, per-archetype component index/offset/size tables, live entity/archetype counts - all structurally discovered, not hardcoded |
| daScript RTTI | Native C++ struct **field offsets** for every struct bound to script (`StructInfo`/`VarInfo`), plus daScript enums |
| MSVC RTTI | Class names, vtable addresses, base-class chain length, and this-adjustment for every polymorphic class the compiler emitted RTTI for |
| Entity templates | Instantiated template names, and the full `TemplateDB` catalogue (every entity type the game can spawn, not just what's currently loaded) |
| Component name recovery | FNV-1a dictionary reversal for names never written as an `ECS_HASH` literal, plus derivation of daECS's `"X$"` netcode shadow components |

## Output

Written to `%TEMP%`:

- `dagor_dumper.log` - full trace log, flushed on every write (survives a crash)
- `dagor_ecs_dump.txt` - the human-readable dump, in the same style as the excerpt below
- `dagor_ecs_dump_offsets.hpp` - auto-generated C++ header of typed component hash constants, for use in other tools
- `dagor_ecs_dump_offsets.json` - the same data as structured JSON (RVAs, so it stays valid across ASLR-shuffled restarts; only `_addr` fields are specific to that run)

```text
// --- COMPONENT TYPES [Chain 1: CompileComponentTypeRegister] ---
// Total: 228
//  IDX   HASH        SIZE    FLAGS                NAME
  [0020] 0xD5EFE099  904     -                       Bullet
  [0045] 0x5F1ED526  8       BOXED                   FuelTanks

// --- COMPONENT SLOTS [Chain 2: CompileComponentRegister] ---
  0xBC84D211  0xD5EFE099  [NET  ]  Bullet : bullet_component
```

## Build

Requirements: CMake 3.20+, MSVC (x64), Visual Studio 2019/2022 or the Build Tools.

### Visual Studio (recommended)

The project ships a [`CMakeSettings.json`](CMakeSettings.json), so Visual Studio's native CMake support picks it up automatically:

1. **File > Open > Folder...** and select the `dagor_dumper` directory (or **File > Open > CMake...** on `CMakeLists.txt`).
2. Wait for CMake configuration to finish generating (status bar at the bottom).
3. Pick a configuration from the dropdown next to the run button - **x64-Release** for a dump run, **x64-Debug** if you're attaching a debugger to the game to step through the scanner.
4. **Build > Build All** (Ctrl+Shift+B), or right-click `dagor_dumper` in the CMake targets view and choose **Build**.

The compiled DLL lands in `out\build\<config>\dagor_dumper.dll`.

### Command line

```powershell
cmake -B build -A x64 .
cmake --build build --config Release
```

Both paths produce `dagor_dumper.dll` (x64). The build forces the release CRT (`/MD`) across all configurations - an injected DLL must match the host process's CRT or freeing memory across the DLL/game boundary corrupts the heap.

## Usage

1. Build `dagor_dumper.dll` (Release recommended).
2. Load the target game and get **in a match** - the ECS registration chains are available at the main menu, but the runtime layout discovery (entities, archetypes) needs an actual `EntityManager` populated with entities.
3. Inject `dagor_dumper.dll` with any standard `LoadLibrary`-based injector. For anti-cheat-protected targets, manual-map instead - see the note in [`src/dllmain.cpp`](src/dllmain.cpp).
4. The DLL waits 5 seconds (`DUMP_DELAY_MS` in `dllmain.cpp`) for static init to settle, then dumps and shows a message box with the output paths. Raise the delay, or re-inject after a level loads, if the runtime section comes back empty.

## Layout

```
include/    scanner.h, ecs_runtime.h, das_rtti.h, rtti_dump.h, ecs_structs.h, logger.h
src/        scanner.cpp       - pattern/signature scanning, section & region enumeration
            em_locator.cpp    - structural discovery of EntityManager/archetypes/cidx table
            chain_walker.cpp  - exhaustive walk of the ECS registration chains, writes the dump
            das_rtti.cpp      - daScript StructInfo/VarInfo decoding (field offsets)
            rtti_dump.cpp     - MSVC RTTI (RTTICompleteObjectLocator) decoding
            logger.cpp        - thread-safe file logger
            dllmain.cpp       - injection entry point
```

## Disclaimer

This project is not meant to be built to meet anyone's expectations - it exists as a personal learning/development effort, understanding component layout and building analysis tooling on top of it and is still very much a work in progress. Features, utilities and internals may change without notice, break, or be incomplete at any given time. Use at your own risk, and don't expect stability, support or a fixed roadmap. It is **not** a cheat and includes no gameplay-affecting code (no reads/writes to live combat state, no automation). Using it against a live multiplayer game may still violate that game's EULA/Terms of Service, independent of what the tool itself does - that's on you to check before you inject it into anything. Don't use it to build or distribute cheats for online games.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

Portions of this project's documentation and code were developed with assistance from Claude (Anthropic). Design decisions, architecture and direction are my own.
