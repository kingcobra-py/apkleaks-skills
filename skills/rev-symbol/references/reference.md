# rev-symbol — Deep Reference

> Loaded on demand. The lean `SKILL.md` covers the 90% path; come here for the
> full surface: the per-format command catalog, the symbol classification
> table, and stripped-binary recovery techniques.

## Commands by Format

### ELF (Linux)
```bash
readelf -s <binary>          # Symbol table
readelf --dyn-syms <binary>  # Dynamic symbols
readelf -r <binary>          # Relocation entries
nm -C <binary>               # Demangled symbols
objdump -T <binary>          # Dynamic symbol table
```

### Mach-O (macOS/iOS)
```bash
nm -g <binary>               # Global symbols
nm -m <binary>               # Mach-O specific format
otool -IV <binary>           # Import table
otool -tV <binary>           # Text section disassembly
```

### PE (Windows)
```bash
objdump -p <binary>          # PE headers
python3 -c "import pefile; pe=pefile.PE('<binary>'); pe.dump_info()"
```

### DEX (Android)
```bash
dexdump -l plain <file>.dex  # Class/method symbols
```

## Symbol Classification

| Symbol Type | Identification | Significance |
|-------------|---------------|-------------|
| **Exported (global)** | BIND_GLOBAL / STB_GLOBAL | Public API, hookable |
| **Imported** | NEEDED entries / imports | Dependencies, libraries |
| **Local (static)** | STB_LOCAL / BIND_LOCAL | Internal, not exported |
| **Weak** | STB_WEAK | Overridable, default impl |
| **Stripped** | Missing from symtab | Need recovery |
| **PLT/GOT** | .plt / .got sections | Indirect calls, hookable |

## Symbol Recovery for Stripped Binaries

### FLIRT Signature Matching
```bash
# IDA FLIRT signatures
# Apply signature files to identify known library functions
sigapply <binary> <sig_file>
```

### Pattern-Based Recovery
```python
# Match common function prologues
patterns = {
    "push_rbp": b"\x55\x48\x89\xe5",  # push rbp; mov rbp, rsp
    "push_rbp_simple": b"\x55\x8b\xec",  # push rbp; mov ebp, esp (32-bit)
}

# Search binary for known patterns and suggest function names
```

### String-Based Recovery
```bash
# Find error strings → trace back to function → name function
strings -t x <binary> | grep -i "error\|fail\|invalid"
# Then cross-reference string addresses to find containing function
```
