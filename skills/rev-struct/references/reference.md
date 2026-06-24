# rev-struct — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the high-level four-phase method;
> come here for the full surface: the worked IDAPython collectors, the field-type
> inference table, the VTable extractor, the cross-reference validator, and the
> post-reconstruction workflow.

## Methodology

### Phase 1: Identify Structure Candidates

Find pointers with consistent offset access patterns:

```bash
# In IDA/Ghidra, look for:
# - Functions taking a single pointer arg accessed at multiple offsets
# - [reg + offset] patterns suggesting struct field access
# - malloc/calloc calls followed by offset-based initialization
```

### Phase 2: Collect Offset Accesses

For each candidate, record all offset accesses:

```python
# IDAPython: collect struct field accesses
import idautils, idc, ida_bytes

def collect_offsets(func_ea, struct_ptr_arg=0):
    """Collect all offset accesses to a struct pointer in a function."""
    offsets = set()
    # Walk function instructions
    func = ida_funcs.get_func(func_ea)
    for head in idautils.FuncItems(func_ea):
        disasm = idc.GetDisasm(head)
        # Look for [reg+0xNN] patterns
        # Parse offset from disassembly
    return sorted(offsets)
```

### Phase 3: Determine Field Types

Infer types from how offsets are used:

| Access Pattern | Inferred Type | Size |
|---------------|---------------|------|
| `mov reg, [ptr+offset]` | int/pointer | 4/8 bytes |
| `movsd xmm, [ptr+offset]` | double | 8 bytes |
| `movss xmm, [ptr+offset]` | float | 4 bytes |
| `cmp byte [ptr+offset], 0` | bool/flag | 1 byte |
| `lea reg, [ptr+offset]` | sub-struct/array | variable |
| String functions (strlen, strcpy) | char* | 8 bytes |

### Phase 4: Reconstruct Struct Definition

```c
// Example reconstructed struct
struct RecoveredStruct {
    /* 0x00 */ void* vtable;          // VTable pointer
    /* 0x08 */ int32_t ref_count;     // Reference count
    /* 0x0C */ int32_t flags;         // State flags
    /* 0x10 */ char* name;            // Name string
    /* 0x18 */ uint64_t timestamp;    // Last update time
    /* 0x20 */ float x, y, z;        // Position (3 floats)
    /* 0x2C */ uint8_t is_active;     // Active flag
    /* 0x2D */ uint8_t padding[3];    // Alignment padding
    /* 0x30 */ void* callback;        // Function pointer
};
```

## VTable Analysis

For C++ classes with virtual functions:

```python
# Extract VTable entries
def analyze_vtable(vtable_ea, count=20):
    entries = []
    for i in range(count):
        func_ptr = ida_bytes.get_qword(vtable_ea + i * 8)
        if func_ptr == 0:
            break
        name = idc.get_func_name(func_ptr)
        entries.append((i, func_ptr, name))
    return entries
```

## Cross-Reference Validation

Verify struct layout by checking multiple functions:

```python
# Validate offsets across all functions using the struct
def validate_struct(struct_offsets, all_functions):
    consistent = True
    for func_ea in all_functions:
        func_offsets = collect_offsets(func_ea)
        # Check if func_offsets are subset of struct_offsets
        if not set(func_offsets).issubset(set(struct_offsets)):
            consistent = False
    return consistent
```

## Post-Reconstruction

1. **Define in IDA** — Use `ida_struct.add_struc()` to create IDA struct
2. **Apply to database** — Apply struct type to all known instances
3. **Export as C header** — Generate .h file with struct definitions
4. **Validate dynamically** — Use `/rev-frida` to verify struct layout at runtime
5. **Combine with symbol analysis** — Use `/rev-symbol` for named references
