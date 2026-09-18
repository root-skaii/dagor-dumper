// In-process memory scanning helpers.
#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <unordered_map>

struct SectionRange {
    uintptr_t base;
    size_t    size;
    bool      valid() const { return base != 0 && size != 0; }
};

// Named PE section of the main module, or {0,0}.
SectionRange get_section(const char* name);

bool is_valid_ptr(const void* p);
bool is_valid_string(const char* s, size_t max_len = 512);

// Exact NUL-terminated match in the main module's .rdata.
uintptr_t find_string(const char* str);
std::vector<uintptr_t> find_all_strings(const char* str);

// Addresses in the range that hold an 8-byte value equal to `target`.
std::vector<uintptr_t> find_ptr_to(uintptr_t target,
                                    uintptr_t range_start,
                                    size_t    range_size);

uintptr_t scan_pattern(uintptr_t base, size_t size,
                        const uint8_t* pattern, const char* mask, size_t pat_len);

// "48 8B 05 ?? ?? ?? ??" style; '?' / '??' are wildcards.
uintptr_t scan_ida_pattern(const char* pattern_str);

// target = instr + instr_size + *(int32_t*)(instr + 3)   (MOV r64,[rip+d32] form)
uintptr_t resolve_rip_rel(uintptr_t instruction_addr, int instr_size = 7);

// Returns the node whose name points at `anchor_str`. The chains are LIFO
// (ctor does `next = tail; tail = this`), so walking `next` from here only
// reaches nodes registered *before* the anchor — a suffix, not the full list.
uintptr_t find_chain_entry(const char* anchor_str,
                            size_t      name_field_offset = 0,
                            size_t      next_field_offset = 8);

struct ModuleRange {
    uintptr_t   base;
    size_t      size;
    std::string name;
};

std::vector<ModuleRange> enumerate_modules();

// Every readable, non-executable section that can hold statics. Registration
// objects can sit in .bss (merged into .data's virtual size), .data$*, or in
// any DLL that links daECS, so sections are enumerated rather than named.
std::vector<SectionRange> enumerate_data_sections(uintptr_t module_base);
std::vector<SectionRange> enumerate_all_data_sections();

// Committed, readable, non-image regions (heaps). Regions above `max_region`
// are skipped so texture arenas don't stall the scan.
std::vector<SectionRange> enumerate_private_regions(size_t max_region = 256u << 20);

bool is_in_any_module(const void* p);
bool in_main_image(uintptr_t v);   // bounds check only, no syscall

uint32_t fnv1a_str(const char* s);

// No-VirtualQuery string check for tight scan loops.
bool fast_module_string(uintptr_t ptr);

// Hash every identifier-like string in the module into `out`. Recovers names
// that never appear as an ECS_HASH literal (e.g. "eid", template-driven
// components). Never overwrites an existing entry.
void harvest_all_string_hashes(std::unordered_map<uint32_t, std::string>& out);

// daECS creates a shadow component "X$" for every replicated X, at runtime
// only — the name exists nowhere in the image or game data. Derive them by
// hashing known_name + "$". Pass `wanted` (the cidx table's hashes) to avoid
// shadowing every known name.
void derive_shadow_component_names(std::unordered_map<uint32_t, std::string>& out,
                                   const std::vector<uint32_t>* wanted = nullptr);
