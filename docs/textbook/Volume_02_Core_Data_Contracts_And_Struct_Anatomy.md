# Volume 02: Core Data Contracts & Struct Anatomy

## Master Table of Contents
1. [The Binary Contract: Memory Layouts Across Language Boundaries](#1-the-binary-contract-memory-layouts-across-language-boundaries)
2. [C, Rust, and .NET Representation Models](#2-c-rust-and-net-representation-models)
3. [The Critical Device Encoding Defect: glibc `st_dev` vs. Kernel `s_dev`](#3-the-critical-device-encoding-defect-glibc-st_dev-vs-kernel-s_dev)
4. [Anatomy of In-Kernel Policy Structs](#4-anatomy-of-in-kernel-policy-structs)
5. [Anatomy of Windows Containment Structs](#5-anatomy-of-windows-containment-structs)
6. [Line-by-Line Code Breakdown: Struct Definitions](#6-line-by-line-code-breakdown-struct-definitions)
7. [Step-by-Step Numerical Walkthrough: Memory Offsets & Bitwise Calculations](#7-step-by-step-numerical-walkthrough-memory-offsets--bitwise-calculations)
8. [Interactive University Checkpoints & Debugging Puzzles](#8-interactive-university-checkpoints--debugging-puzzles)

---

## 1. The Binary Contract: Memory Layouts Across Language Boundaries

In a multi-language systems substrate bridging C, Rust, and .NET, high-level data models must eventually be serialized into raw, unmanaged memory buffers. When a BPF-LSM program running inside kernel space queries a BPF hash map, it does not evaluate struct field names, types, or object metadata. The BPF map lookup helper `bpf_map_lookup_elem(&map, &key)` performs a **pure byte-for-byte comparison** over a fixed memory buffer of length `N`.

If the user-space daemon compiling the policy key computes a memory layout with even a single misaligned padding byte, an inverted bit-field, or an incorrect integer width, the kernel's hash function (`jhash` or `murmur3`) will compute a completely different bucket and hash signature:

```
Hash_kernel(Key_kernel) != Hash_kernel(Key_userspace)
```

Consequently, every lookup against the map fails. In security systems, **the asymmetry of a map lookup miss is catastrophic**:
- For an **allow-list** (such as permitted executable inodes), a lookup miss fails **closed** (loud refusal: the permitted tool cannot run).
- For a **deny-list** (such as protected files like `/etc/shadow`), a lookup miss fails **OPEN** (silent failure: the protected resource is treated as unprotected, allowing unauthorized access).

---

## 2. C, Rust, and .NET Representation Models

Each language ecosystem manages struct layouts according to distinct compilation rules:

```
+─────────────────────────────────────────────────────────────────────────────+
| COMPILER STRUCT PACKING RULES & DIRECTIVES                                  |
+─────────────────────────────────────────────────────────────────────────────+
| 1. C (Clang / GCC / MSVC):                                                  |
|    - Default: Natural alignment (fields aligned to multiples of their size) |
|    - Explicit: #pragma pack(push, n) or __attribute__((packed))             |
|                                                                             |
| 2. Rust (rustc):                                                            |
|    - Default: #[repr(Rust)] (Compiler reorders fields arbitrarily to        |
|      minimize padding holes - FATAL FOR FFI / BPF MAPS)                     |
|    - Required: #[repr(C)] (Forces C-compatible ordering and natural padding)|
|                                                                             |
| 3. C# (.NET 10 CLR):                                                        |
|    - Default: [StructLayout(LayoutKind.Auto)] (CLR reorders fields)         |
|    - Required: [StructLayout(LayoutKind.Sequential)] (Sequential layout)    |
|    - Pack Parameter: Pack = 1, 4, 8 for explicit byte alignment             |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 3. The Critical Device Encoding Defect: glibc `st_dev` vs. Kernel `s_dev`

During the bring-up of the SPLAT Linux substrate on WSL2, an insidious defect was uncovered that demonstrates the extreme sensitivity of binary contracts.

### The Identity of a File
In Linux, an inode number (`ino`) is only unique within a specific filesystem. Across the entire operating system, a file is uniquely identified by the tuple:

```
File Identity = (Device ID, Inode Number)
```

### The Encoding Mismatch
When user space calls `stat("/bin/sh", &st)`, the GNU C Library (glibc) populates `st.st_dev`, which is defined as a **64-bit unsigned integer** (`unsigned long int`). However, inside the Linux kernel, the superblock device representation `inode->i_sb->s_dev` is packed into a **32-bit unsigned integer** using a legacy bitwise scheme:

```
GLIBC 64-BIT DEV_T PACKING:
+-----------------------------------------------------------------------------+
| Bits 63..32 (32 bits)       | Bits 31..8 (24 bits)      | Bits 7..0 (8 bits)|
| Major Upper (Bits 31..12)   | Minor Upper / Major Lower | Minor Lower       |
+-----------------------------------------------------------------------------+

KERNEL 32-BIT S_DEV PACKING:
+-----------------------------------------------------------------------------+
| Bits 31..20 (12 bits)       | Bits 19..0 (20 bits)                          |
| Major Device Number (0..4095)| Minor Device Number (0..1048575)              |
+-----------------------------------------------------------------------------+
```

### Bitwise Conversion Algorithms
To extract the standard major and minor device numbers from a glibc 64-bit `st_dev`:

```c
// 1. Extract major device number from glibc st_dev:
major = ((st_dev >> 8) & 0xFFF) | ((st_dev >> 32) & ~0xFFF);

// 2. Extract minor device number from glibc st_dev:
minor = (st_dev & 0xFF) | ((st_dev >> 12) & ~0xFF);
```

To pack these into the Linux kernel's internal 32-bit `s_dev` format expected by `BPF_CORE_READ(inode, i_sb, s_dev)`:

```c
// 3. Pack into Linux kernel internal 32-bit s_dev format:
s_dev = ((major << 20) | (minor & 0xFFFFF)) & 0xFFFFFFFF;
```

### Concrete Numerical Example
Consider `/bin/sh` on a standard WSL2 filesystem mount:
- **Major:** `8` (`0x008`, standard SCSI/SATA block device `/dev/sda`)
- **Minor:** `1` (`0x00001`, first partition `/dev/sda1`)

#### 1. What glibc `stat()` produces in user space:
```
st_dev = makedev(8, 1) 
       = (8 << 8) | 1 
       = 2048 + 1 
       = 2049
Hex:     0x0000000000000801
```

#### 2. What the Linux kernel reads in `inode->i_sb->s_dev`:
```
s_dev  = (8 << 20) | 1 
       = 8388608 + 1 
       = 8388609
Hex:     0x00800001
```

#### 3. The Resulting BPF Hash Map Miss:
```
User-Space Key Hash:   0x0000000000000801
Kernel-Space Key Hash: 0x0000000000800001
Status:                LOOKUP MISMATCH (Hash keys do not match!)
```

The BPF hook concludes that `/bin/sh` is not in the allow-list and returns `-EPERM`, aborting execution. Even worse, for `/etc/shadow`, the lookup in `protected_inodes` misses, causing the kernel to assume the file is unprotected!

---

## 4. Anatomy of In-Kernel Policy Structs

Every BPF policy map key in SPLAT incorporates the 64-bit cgroup identifier as its primary discriminant. This prevents cross-mission permission leakage:

### `struct lease_inode_key` (24 Bytes, 8-Byte Aligned)
```
BYTE OFFSET:
 0                   8                  16         20         24
+-------------------+-------------------+----------+----------+
|  cgroup_id (u64)  |     ino (u64)     | dev (u32)| _pad(u32)|
+-------------------+-------------------+----------+----------+
|      8 Bytes      |      8 Bytes      | 4 Bytes  | 4 Bytes  |
+-------------------+-------------------+----------+----------+
```

### `struct lease_ipv4_key` (16 Bytes, 8-Byte Aligned)
```
BYTE OFFSET:
 0                   8                  12    14   16
+-------------------+-------------------+-----+----+
|  cgroup_id (u64)  |    addr (u32)     |port |_pad|
+-------------------+-------------------+-----+----+
|      8 Bytes      | 4 Bytes (BE IPv4) |2B BE| 2B |
+-------------------+-------------------+-----+----+
```
*Note on Network Byte Order:* `addr` and `port` are stored in Big-Endian (Network Byte Order) format. When `lsm/socket_connect` intercepts `connect()`, the `sockaddr_in` struct presents `sin_addr.s_addr` and `sin_port` in network byte order. By storing keys pre-swapped, the BPF program compares memory fields directly without executing `bpf_ntohl()` or `bpf_ntohs()`.

### `struct violation_event` (36 Bytes, 8-Byte Aligned)
```
BYTE OFFSET:
 0                   8        12        16        20                  36
+-------------------+---------+---------+---------+--------------------+
|  cgroup_id (u64)  |pid (u32)|hook(u32)|dtl (u32)|     comm (16B)     |
+-------------------+---------+---------+---------+--------------------+
|      8 Bytes      | 4 Bytes | 4 Bytes | 4 Bytes |      16 Bytes      |
+-------------------+---------+---------+---------+--------------------+
```

---

## 5. Anatomy of Windows Containment Structs

On Windows, SPLAT relies on the Win32 subsystem to clamp processes and tokens.

### `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (112 Bytes on x64)
```
BYTE OFFSET (x64):
 0                                                                          64
+--------------------------------------------------------------------------+
| BasicLimitInformation (JOBOBJECT_BASIC_LIMIT_INFORMATION: 64 Bytes)       |
|  - PerProcessUserTimeLimit (i64)                                          |
|  - PerJobUserTimeLimit (i64)                                              |
|  - LimitFlags (u32)                                                       |
|  - MinimumWorkingSetSize (size_t)                                         |
|  - MaximumWorkingSetSize (size_t)                                         |
|  - ActiveProcessLimit (u32) -> Hardcoded to 32                            |
|  - Affinity (size_t)                                                      |
|  - PriorityClass (u32)                                                    |
|  - SchedulingClass (u32)                                                  |
+--------------------------------------------------------------------------+
 64                                                                         112
+--------------------------------------------------------------------------+
| IoInfo (IO_COUNTERS: 48 Bytes)                                            |
| ProcessMemoryLimit (size_t: 8 Bytes)                                      |
| JobMemoryLimit (size_t: 8 Bytes) -> Clamped to 256 MB                     |
| PeakProcessMemoryLimit (size_t: 8 Bytes)                                  |
| PeakJobMemoryLimit (size_t: 8 Bytes)                                      |
+--------------------------------------------------------------------------+
```

### `STARTUPINFOEX` (112 Bytes on x64)
```
BYTE OFFSET (x64):
 0                                                              104        112
+--------------------------------------------------------------+----------+
| StartupInfo (STARTUPINFO: 104 Bytes)                         |lpAttrList|
|  - cb (u32 = 112)                                            |  (8B)    |
|  - hStdInput, hStdOutput, hStdError (Native Handles)         |          |
+--------------------------------------------------------------+----------+
```

---

## 6. Line-by-Line Code Breakdown: Struct Definitions

### 6.1 BPF C Definitions (`native/splat-agent/src/bpf/lease_lsm.bpf.c`)

```c
// Lines 43-47: Basic Inode Key Definition
struct inode_key {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};
```
*Architectural Rationale:* The explicit `_pad` field ensures the struct is an even multiple of 8 bytes (16 bytes total). Without explicit padding, different C compilers might insert undefined uninitialized padding bytes, corrupting map hashing.

```c
// Lines 51-57: Cgroup-Scoped Inode Lease Key
struct lease_inode_key {
    __u64 cgroup_id;
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};
```
*Architectural Rationale:* Every entry in `allowed_exec_inodes` and `protected_inodes` is prefixed with `cgroup_id`. If keys omitted `cgroup_id`, two concurrently executing missions would share the union of their permissions: mission A granting `/bin/python3` would inadvertently grant `/bin/python3` to mission B.

---

### 6.2 Rust Struct Mirrors (`native/splat-agent/src/lease.rs`)

```rust
// Lines 30-37: Rust Representation of lease_inode_key
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeaseInodeKey {
    pub cgroup_id: u64,
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

// Lines 74-75: Compile-Time Static Size Assertions
const _: () = assert!(std::mem::size_of::<LeaseInodeKey>() == 24);
const _: () = assert!(std::mem::size_of::<LeaseIpv4Key>() == 16);
```
*Architectural Rationale:* The `#[repr(C)]` attribute mandates that `rustc` lay out fields exactly as a C compiler would. The `const _: () = assert!(...)` static assertion guarantees at compile time that the struct size matches the BPF C header. If a field type changes or padding slips, the build aborts before any code can run.

```rust
// Lines 83-87: The Bitwise Device Transformation Function
fn kernel_dev_from_st_dev(st_dev: u64) -> u32 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    (((major << 20) | (minor & 0xf_ffff)) & 0xffff_ffff) as u32
}
```
*Architectural Rationale:* This pure function performs the exact bitwise translation between glibc’s 64-bit device representation and the Linux kernel’s internal 32-bit `s_dev` representation.

---

## 7. Step-by-Step Numerical Walkthrough: Memory Offsets & Bitwise Calculations

Let us trace the conversion of a real device identity for `/bin/sh` located on `/dev/sdb2`:
- **Major Number:** `8` (`0x00000008`)
- **Minor Number:** `18` (`0x00000012`)
- **Inode Number:** `142512` (`0x0000000000022CB0`)
- **Cgroup ID:** `4096` (`0x0000000000001000`)

### Step 1: glibc `st_dev` Calculation
```
st_dev = (8 << 8) | 18 = 2048 + 18 = 2066  (Hex: 0x0000000000000812)
```

### Step 2: Extraction via `kernel_dev_from_st_dev`
```c
major = ((2066 >> 8) & 0xFFF) = 8 & 0xFFF = 8
minor = (2066 & 0xFF)         = 0x12     = 18
```

### Step 3: Kernel `s_dev` Packing
```c
s_dev = (8 << 20) | (18 & 0xFFFFF)
      = 0x00800000 | 0x00000012
      = 0x00800012 (Decimal: 8388626)
```

### Step 4: Memory Buffer Serialization (`LeaseInodeKey`)
The 24-byte buffer is written to memory at address `0x00007FFF1000`:

| Address Offset | Field | Value (Hex) | Raw Little-Endian Bytes |
| :---: | :--- | :--- | :--- |
| `+0x00` | `cgroup_id` | `0x0000000000001000` | `00 10 00 00 00 00 00 00` |
| `+0x08` | `ino` | `0x0000000000022CB0` | `B0 2C 02 00 00 00 00 00` |
| `+0x10` | `dev` | `0x00800012` | `12 00 80 00` |
| `+0x14` | `_pad` | `0x00000000` | `00 00 00 00` |

---

## 8. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 2.1: The Endianness Trap in Network Filters
**Scenario:** A developer modifies `LeaseIpv4Key` in Rust to store `addr` and `port` using host byte order (`u32::from_str("127.0.0.1").to_le()`). The BPF program in `lease_lsm.bpf.c` looks up incoming connections using:
```c
struct sockaddr_in *in = (struct sockaddr_in *)address;
__u32 daddr = BPF_CORE_READ(in, sin_addr.s_addr);
__u16 dport = BPF_CORE_READ(in, sin_port);
```
When an agent attempts to connect to `127.0.0.1:443`, the kernel blocks the connection with `-EPERM`.
- **Question:** What is the byte-level representation of `127.0.0.1:443` in the Rust key vs. the BPF key, and why did the lookup fail?
- **Solution:** `sin_addr.s_addr` and `sin_port` are in Big-Endian (Network Byte Order).
  - Port `443` (`0x01BB`) in Big-Endian is stored as `01 BB`.
  - In Host Byte Order (Little-Endian on x86), `443` is stored as `BB 01`.
  - IP `127.0.0.1` in Big-Endian is `7F 00 00 01`. In Little-Endian it is `01 00 00 7F`.
  Because the key was inserted using host byte order, the byte comparison failed. Keys must always be stored in network byte order to match socket structures directly.

### Checkpoint 2.2: The Uninitialized Padding Hole Vulnerability
**Scenario:** A C struct defined without explicit padding:
```c
struct bad_key {
    uint32_t a; // 4 bytes
    // 4 bytes implicit padding
    uint64_t b; // 8 bytes
};
```
is allocated on the stack in C: `struct bad_key k; k.a = 1; k.b = 2;` and passed directly to `bpf_map_update_elem`.
- **Question:** Why will lookups for this key intermittently fail, even when `k.a` and `k.b` are identical?
- **Solution:** Uninitialized stack memory contains whatever random junk previously occupied that stack frame. The 4 bytes of padding between `a` and `b` are never zeroed. When hashed by the kernel BPF map implementation, two keys with identical `a` and `b` values but different uninitialized padding bytes produce completely different hashes, causing intermittent lookup failures. Structs must always be zero-initialized (`memset` or `= {}`) or explicitly packed.
