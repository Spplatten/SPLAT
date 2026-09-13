# Week 1 — bytes become a running program

## Lesson A: the machine underneath C#

**Outcome:** distinguish bits, bytes, addresses, instructions and processes.

A bit has two states. Groups of bits encode numbers; their interpretation depends on width and signedness. A byte holds eight bits. A CPU executes instructions that move and transform values in registers and memory. Boolean operations used in flags and masks are software's direct connection to digital logic.

At the instruction-set level, a program counter identifies instructions to fetch and decode; arithmetic/logic units compute, and loads/stores move data. Real CPUs overlap work through pipelines and caches. x64 and ARM64 have different instruction sets and native calling conventions, so a managed assembly and a native binary have different portability constraints.

SPLAT expresses a memory ceiling as bytes, a port as a bounded integer, and a mission identity as a GUID. Those are different meanings even when all eventually become bits. Work out 256 × 1024 × 1024 = 268,435,456 bytes: 256 MiB, not 256 million bytes. A large signed value cast to an unsigned type may become a very different limit; validation belongs before conversion.

The CPU's MMU translates virtual addresses under operating-system control. Two processes can use the same numeric virtual address without referring to the same physical memory. WSL2 adds a guest machine boundary. These boundaries are not created by a managed class or by a policy label.

## Lesson B: source, intermediate code, native code

**Outcome:** identify three different compilation paths in this repository.

C# compilation produces an assembly containing intermediate language and metadata; the managed runtime commonly JIT-compiles methods into machine instructions. Platform interop still depends on the host OS. This is why a shared interface can build across targets while a Win32 implementation cannot execute everywhere. [Microsoft's managed execution reference](https://learn.microsoft.com/en-us/dotnet/standard/managed-execution-process).

Rust produces the native Linux daemon. Its build.rs invokes a BPF build step on lease_lsm.bpf.c and generates a skeleton used by the Rust loader. The BPF verifier checks the program before attachment; passing the verifier does not prove that the application's policy is complete.

Read the [Core project](../../src/MissionController.Core/MissionController.Core.csproj), [test project](../../tests/MissionController.Tests/MissionController.Tests.csproj) and [native build](../../native/splat-agent/build.rs). Draw source → compiler → artifact → loader/runtime for each. Never infer the currently selected SDK from a README badge.

## Lab: represent one request

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab -LabMode representation
rg -n 'TargetFramework|ProjectReference' src tests -g '*.csproj'
~~~

1. Open the representation branch of [Program.cs](../../coursework/Splat.CourseLab/Program.cs).
2. Predict the two network-order bytes of port 443 before running it.
3. Follow an argument containing spaces, an empty argument, a backslash and a Unicode character through JSON serialization and parsing.
4. Add a boundary case of your own and assert exact argument equality after decoding.
5. Explain why encoded byte length and string character count need different limits.

Expected: the representation checks pass; 443 encodes as 01 BB; the empty argument survives. The exercise does not launch a process.

**Cybersecurity case:** argument boundaries are authority boundaries. Splitting a quoted string on spaces changes the command the caller authorized. A zero exit from the wrong command can still be incorrect evidence.

**Repair practice:** study [ArgumentVectorContractTests](../../tests/MissionController.Tests/ArgumentVectorContractTests.cs). Keep the argv-array repair intact; add a Unicode/empty-argument regression instead of reintroducing the old string protocol.

**Submit:** the three compilation diagrams, byte calculation, and your new assertion.

**Check yourself:** Does compiling Core prove BPF attachment? Can a zero exit prove argv arrived correctly?

**Answer checkpoint:** no to both. The guest kernel must accept and attach its program; exact output or an argv echo must establish argument fidelity independently of exit status.
