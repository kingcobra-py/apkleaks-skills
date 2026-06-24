# rev-unicorn-debug — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full surface: the complete emulation code catalog, the debugging-technique
> table, and the post-emulation chaining steps.

## Common Emulation Patterns

### Basic Function Emulation
```python
from unicorn import *
from unicorn.arm64_const import *
from capstone import *

# ARM64 function emulation
def emulate_arm64_function(code_bytes, arch_mode=UC_MODE_ARM):
    # Initialize emulator
    mu = Uc(UC_ARCH_ARM64, arch_mode)

    # Map memory
    CODE_ADDR = 0x1000
    STACK_ADDR = 0x7F000000
    STACK_SIZE = 0x100000
    mu.mem_map(CODE_ADDR, 0x10000)
    mu.mem_map(STACK_ADDR, STACK_SIZE)

    # Write code
    mu.mem_write(CODE_ADDR, code_bytes)

    # Setup stack pointer
    sp = STACK_ADDR + STACK_SIZE - 0x1000
    mu.reg_write(UC_ARM64_REG_SP, sp)

    # Instruction trace hook
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    def hook_code(mu, address, size, user_data):
        code = mu.mem_read(address, size)
        for insn in md.disasm(bytes(code), address):
            print(f"0x{address:x}: {insn.mnemonic} {insn.op_str}")

    mu.hook_add(UC_HOOK_CODE, hook_code)

    # Emulate
    try:
        mu.emu_start(CODE_ADDR, CODE_ADDR + len(code_bytes))
    except UcError as e:
        print(f"Emulation error: {e}")

    # Read results
    result = mu.reg_read(UC_ARM64_REG_X0)  # Return value in x0
    return result
```

### Memory Access Tracing
```python
def hook_mem_access(mu, access, address, size, value, user_data):
    access_type = {
        UC_MEM_READ: "READ",
        UC_MEM_WRITE: "WRITE",
        UC_MEM_FETCH: "FETCH",
    }.get(access, "UNKNOWN")

    if access == UC_MEM_WRITE:
        print(f"[MEM] {access_type} 0x{address:x} size={size} value=0x{value:x}")
    else:
        data = mu.mem_read(address, size)
        print(f"[MEM] {access_type} 0x{address:x} size={size} data={bytes(data).hex()}")

mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem_access)
```

### Anti-Debug Bypass
```python
# Emulate function that checks for debugger
# Patch out anti-debug checks before emulation
anti_debug_code = bytes.fromhex("...")

# Option 1: Patch the check instruction
# Option 2: Hook the check and return fake result
def hook_anti_debug(mu, address, size, user_data):
    if address == ANTI_DEBUG_CHECK_ADDR:
        mu.reg_write(UC_ARM64_REG_X0, 0)  # Return "no debugger"
        mu.reg_write(UC_ARM64_REG_PC, RETURN_ADDR)  # Skip check

mu.hook_add(UC_HOOK_CODE, hook_anti_debug)
```

### CTF Challenge Solver
```python
# Emulate a key validation function
def solve_key_check(code_bytes):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(0x1000, 0x10000)
    mu.mem_map(0x7FF00000, 0x10000)
    mu.mem_write(0x1000, code_bytes)
    mu.reg_write(UC_X86_REG_ESP, 0x7FF00000 + 0x8000)

    # Try different inputs
    for candidate in range(0x10000):
        mu.reg_write(UC_X86_REG_EAX, candidate)
        try:
            mu.emu_start(0x1000, 0x1000 + len(code_bytes))
            result = mu.reg_read(UC_X86_REG_EAX)
            if result == 1:  # Success condition
                return candidate
        except UcError:
            continue
    return None
```

## Debugging Techniques

| Technique | Use Case | Implementation |
|-----------|----------|---------------|
| **Instruction trace** | Understand execution flow | `UC_HOOK_CODE` hook |
| **Memory trace** | Find data access patterns | `UC_HOOK_MEM_*` hooks |
| **Register snapshots** | Track register state | Read regs at hook points |
| **Breakpoints** | Stop at specific address | `UC_HOOK_CODE` + address check |
| **Patch & continue** | Skip checks/loops | Write to memory mid-execution |
| **Single step** | Step through instructions | `emu_start(addr, addr+4)` loop |

## Post-Emulation

1. **Compare with dynamic** — Use `/rev-frida` to verify emulation results match runtime behavior
2. **Analyze anti-analysis** — Use emulation to safely bypass without detection
3. **Combine with struct analysis** — Use `/rev-struct` to understand data structures being accessed
4. **Symbol resolution** — Use `/rev-symbol` to identify function addresses for emulation targets
