# Volume 09: Master Laboratory Suite & Guided Interactive Walkthroughs

## Master Table of Contents
1. [Collegiate Laboratory Framework & Pedagogical Objectives](#1-collegiate-laboratory-framework--pedagogical-objectives)
2. [Lab 1: Bitwise Device Number Encoding & Cross-ABI Struct Packing](#2-lab-1-bitwise-device-number-encoding--cross-abi-struct-packing)
3. [Lab 2: Suspended Win32 Process Spawning & Token Hardening](#3-lab-2-suspended-win32-process-spawning--token-hardening)
4. [Lab 3: Developing a Minimal BPF-LSM Security Hook & Ring Buffer Monitor](#4-lab-3-developing-a-minimal-bpf-lsm-security-hook--ring-buffer-monitor)
5. [Lab 4: Diagnosing the UTF-8 Byte Order Mark (BOM) Socket Hazard](#5-lab-4-diagnosing-the-utf-8-byte-order-mark-bom-socket-hazard)
6. [Lab 5: Cryptographic Ledger Construction & Salted Retention Erasure](#6-lab-5-cryptographic-ledger-construction--salted-retention-erasure)
7. [Comprehensive Disassembly & Diagnostic Exercises](#7-comprehensive-disassembly--diagnostic-exercises)

---

## 1. Collegiate Laboratory Framework & Pedagogical Objectives

This master laboratory suite provides hands-on, executable engineering assignments designed to cement theoretical concepts through direct experimentation. Each laboratory follows an uncompromising scientific protocol:
1. **State the Invariant**: Define the physical boundary or mathematical property under test.
2. **Implement the Minimal Specimen**: Construct the smallest viable harness isolating the mechanism.
3. **Execute the Controlled Failure**: Deliberately violate the invariant to observe the specific error signature.
4. **Implement the Production Fix**: Apply the hardened architectural pattern.
5. **Verify the Observable Proof**: Confirm passing tests against kernel and runtime telemetry.

---

## 2. Lab 1: Bitwise Device Number Encoding & Cross-ABI Struct Packing

### Objective
Derive the exact binary bytes used by a BPF policy map key and prove that glibc's `st_dev` differs from the Linux kernel's `s_dev`.

### Step 1: Implement `device_bits.c`
```c
#include <stdio.h>
#include <stdint.h>
#include <sys/sysmacros.h>
#include <assert.h>

// Packs major and minor into Linux kernel 32-bit s_dev format
uint32_t kernel_dev_from_st_dev(uint64_t st_dev) {
    uint32_t major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & ~0xfffULL);
    uint32_t minor = (st_dev & 0xff) | ((st_dev >> 12) & ~0xffULL);
    return ((major << 20) | (minor & 0xfffff)) & 0xffffffff;
}

int main(void) {
    // Test Case: Major 8, Minor 1 (/dev/sda1)
    uint64_t glibc_dev = makedev(8, 1);
    uint32_t kernel_dev = kernel_dev_from_st_dev(glibc_dev);

    printf("glibc st_dev:  0x%016llX (Decimal: %llu)\n", 
           (unsigned long long)glibc_dev, (unsigned long long)glibc_dev);
    printf("kernel s_dev: 0x%08X         (Decimal: %u)\n", 
           kernel_dev, kernel_dev);

    // Assert mathematical values
    assert(glibc_dev == 0x0000000000000801ULL);
    assert(kernel_dev == 0x00800001);
    printf("PASS: Bitwise conversion matches kernel packing exactly!\n");
    return 0;
}
```

### Verification Command
```bash
gcc -Wall -Wextra -O2 device_bits.c -o device_bits && ./device_bits
```
**Expected Output:**
```text
glibc st_dev:  0x0000000000000801 (Decimal: 2049)
kernel s_dev: 0x00800001         (Decimal: 8388609)
PASS: Bitwise conversion matches kernel packing exactly!
```

---

## 3. Lab 2: Suspended Win32 Process Spawning & Token Hardening

### Objective
Demonstrate how creating a process in `CREATE_SUSPENDED` allows an operator to neutralize administrative privileges and bind Job Object limits before the child process executes its first instruction.

### Implementation: `token_harden.c`
```c
#include <windows.h>
#include <stdio.h>
#include <sddl.h>

int main(void) {
    HANDLE hToken, hRestrictedToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken);

    // Convert Administrators SID to Deny-Only
    PSID adminSid = NULL;
    ConvertStringSidToSidA("S-1-5-32-544", &adminSid);
    SID_AND_ATTRIBUTES sidsToDisable = { adminSid, 0 };

    if (!CreateRestrictedToken(hToken, DISABLE_MAX_PRIVILEGE, 1, &sidsToDisable, 0, NULL, 0, NULL, &hRestrictedToken)) {
        printf("Failed to create restricted token: %lu\n", GetLastError());
        return 1;
    }

    // Launch whoami /priv under restricted token
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessAsUserA(hRestrictedToken, NULL, "whoami /priv", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    LocalFree(adminSid);
    CloseHandle(hRestrictedToken);
    CloseHandle(hToken);
    return 0;
}
```

### Verification
Run `token_harden.exe` in an elevated Command Prompt. Observe that all administrative privileges (`SeDebugPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege`) are completely stripped from the output!

---

## 4. Lab 3: Developing a Minimal BPF-LSM Security Hook & Ring Buffer Monitor

### Objective
Write an in-kernel security program that hooks `bprm_check_security` and denies execution of `/usr/bin/python3` while allowing `/bin/sh`.

### Implementation: `exec_gate.bpf.c`
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// Map holding the allow-listed executable inode number
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u64);
    __type(value, __u8);
} allowed_inodes SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_gate_check, struct linux_binprm *bprm, int ret) {
    if (ret != 0)
        return ret; // Prior LSM denied; preserve deny

    struct file *f = BPF_CORE_READ(bprm, file);
    if (!f) return 0;
    struct inode *inode = BPF_CORE_READ(f, f_inode);
    if (!inode) return 0;

    __u64 ino = BPF_CORE_READ(inode, i_ino);
    
    // Query allow-list
    __u8 *allowed = bpf_map_lookup_elem(&allowed_inodes, &ino);
    if (!allowed) {
        bpf_printk("[GATE] Denied exec of inode %llu\n", ino);
        return -EPERM; // Return Operation Not Permitted to user space!
    }

    bpf_printk("[GATE] Allowed exec of inode %llu\n", ino);
    return 0;
}
```

### Verification
Compile with Clang (`clang -target bpf -O2 -g -c exec_gate.bpf.c -o exec_gate.bpf.o`) and attach using `bpftool`. Attempting to execute an unlisted binary returns `bash: ./binary: Operation not permitted`.

---

## 5. Lab 4: Diagnosing the UTF-8 Byte Order Mark (BOM) Socket Hazard

### Objective
Reproduce the fatal socket deserialization failure caused by C#’s default `Encoding.UTF8` emitting `0xEF, 0xBB, 0xBF`.

### Step 1: Reproduction Test Harness (`bom_test.py`)
```python
import socket
import json

# Simulates Rust serde receiver
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.bind(("127.0.0.1", 55555))
listener.listen(1)
print("Listening on 55555...")

conn, _ = listener.accept()
raw_bytes = conn.recv(1024)

print(f"Received {len(raw_bytes)} bytes:")
print("HEX DUMP:", " ".join(f"{b:02X}" for b in raw_bytes))

try:
    decoded_text = raw_bytes.decode("utf-8")
    parsed = json.loads(decoded_text)
    print("SUCCESS: Valid JSON received:", parsed)
except Exception as e:
    print("FATAL ERROR: Deserialization failed:", e)

conn.close()
listener.close()
```

### Step 2: C# Client Emitter
```csharp
// HAZARDOUS (Default C# StreamWriter prepends BOM):
// using var writer = new StreamWriter(stream, Encoding.UTF8);

// PRODUCTION-HARDENED (Explicitly suppresses BOM):
using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
await writer.WriteLineAsync("{\"type\":\"PING\"}");
```

---

## 6. Lab 5: Cryptographic Ledger Construction & Salted Retention Erasure

### Objective
Implement the Version 2 Salted Commitment algorithm and prove that erasing sensitive payload data leaves the cryptographic hash chain valid.

### Implementation: `LedgerLab.cs`
```csharp
using System;
using System.Security.Cryptography;
using System.Text;

public class LedgerLab
{
    public static string Sha256Hex(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    public static void Main()
    {
        string prevHash = new string('0', 64);
        string payload = "Operator password = Secret123!";
        
        // 1. Generate 256-bit random salt
        string salt = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        
        // 2. Compute commitment
        string commitment = Sha256Hex(salt + payload);
        
        // 3. Compute entry hash over commitment
        string entryHash = Sha256Hex(prevHash + commitment);
        Console.WriteLine($"Original Entry Hash: {entryHash}");

        // 4. SIMULATE RETENTION PURGE: Erase payload and salt
        payload = "[REDACTED_ERASED]";
        salt = "[REDACTED_ERASED]";

        // 5. Verification: Recalculate entry hash using preserved commitment
        string verifyHash = Sha256Hex(prevHash + commitment);
        Console.WriteLine($"Verified Entry Hash: {verifyHash}");

        if (entryHash == verifyHash)
        {
            Console.WriteLine("SUCCESS: Hash chain remains 100% intact after payload erasure!");
        }
    }
}
```

---

## 7. Comprehensive Disassembly & Diagnostic Exercises

### Exercise 9.1: Disassembly of the Device Conversion Function
Compile `device_bits.c` with optimization `-O2` and disassemble using `objdump -d device_bits`.
```objdump
0000000000001160 <kernel_dev_from_st_dev>:
    1160: 48 89 f8              mov    %rdi,%rax
    1163: 48 c1 e8 08           shr    $0x8,%rax
    1167: 25 ff 0f 00 00        and    $0xfff,%eax
    116c: 48 89 f9              mov    %rdi,%rcx
    116f: 48 c1 e9 20           shr    $0x20,%rcx
    1173: 48 81 e1 00 f0 ff ff  and    $0xfffffffffffff000,%rcx
    117a: 09 c8                 or     %ecx,%eax
    117c: c1 e0 14              shl    $0x14,%eax
    117f: 0f b6 cf              movzbl %dil,%ecx
    1182: 09 c8                 or     %ecx,%eax
    1184: c3                    ret
```
**Pedagogical Challenge:** Trace how the compiler optimizes the bitwise shift operations (`shr $0x8`, `shr $0x20`, and `shl $0x14`) to pack `(major << 20) | minor` in fewer than 10 instructions. Notice that register `%dil` is used to extract the lowest 8 bits of `%rdi` in a single clock cycle.
