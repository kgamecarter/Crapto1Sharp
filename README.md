[![Build status](https://ci.appveyor.com/api/projects/status/pk76r1bhc0rndub1?svg=true)](https://ci.appveyor.com/project/kgame/crapto1sharp)
[![AppVeyor tests](https://img.shields.io/appveyor/tests/kgame/crapto1sharp.svg)](https://ci.appveyor.com/project/kgame/crapto1sharp/build/tests)
[![NuGet](https://img.shields.io/nuget/v/Crapto1Sharp.svg)](https://www.nuget.org/packages/Crapto1Sharp/)

**English** | [繁體中文](README.zh-TW.md)

# Crapto1Sharp

Crapto1Sharp is a C# implementation of Crypto1 and MIFARE Classic state and
key-recovery operations. It provides:

- Crypto1 bit, byte, and word operations with rollback support.
- 32-bit and 64-bit LFSR state recovery.
- Same-NT and many-NT MfKey32 attacks, plus MfKey64.
- Reusable pooled recovery workspaces and streaming visitor APIs.
- Allocation-free `Span<T>` encryption and serialization APIs.
- A consistent public API from `netstandard1.1` through `net10.0`.

> [!IMPORTANT]
> Crypto1 is a legacy cipher with publicly known weaknesses and must not be used
> to protect new systems. This project is intended for interoperability research,
> testing, and analysis of systems you are authorized to access. Do not use it
> against cards or systems without permission.

## Supported frameworks

| Target framework | Intended use |
| --- | --- |
| `netstandard1.1` | Legacy and broadly compatible .NET implementations |
| `netstandard2.0` | General .NET and .NET Framework compatibility |
| `net462` | .NET Framework 4.6.2 |
| `net10.0` | Current .NET with hardware-accelerated parity paths |

NuGet resolves the required `System.Memory` and `System.Buffers` dependencies
for `net462` automatically.

## Installation

.NET CLI:

```shell
dotnet add package Crapto1Sharp
```

Visual Studio Package Manager:

```powershell
Install-Package Crapto1Sharp
```

Most applications only need these namespaces:

```csharp
using Crapto1Sharp;
using Crapto1Sharp.Extensions;
```

## Basic Crypto1 operations

`Crypto1State` represents the 48-bit Crypto1 LFSR state. It can be initialized
from a 48-bit key. Every bit, byte, or word operation advances the state.

```csharp
using Crapto1Sharp;

const ulong key = 0xFFFFFFFFFFFF;
const uint input = 0x12345678;

var state = new Crypto1State(key);

byte keyStreamBit = state.Crypto1Bit();
byte keyStreamByte = state.Crypto1Byte();
uint keyStreamWord = state.Crypto1Word(input);

ulong currentLfsr = state.Lfsr;
```

To reverse state transitions:

```csharp
byte previousBit = state.LfsrRollbackBit();
byte previousByte = state.LfsrRollbackByte();
uint previousWord = state.LfsrRollbackWord(input);
```

The `isEncrypted` and `isIn` arguments control whether input is included in the
Crypto1 feedback path. Select the value that matches whether the protocol value
being processed is plaintext input or encrypted input.

## Data and parity encryption

New code should prefer the allocation-free Span overload:

```csharp
using Crapto1Sharp;

var state = new Crypto1State(0xFFFFFFFFFFFF);
Span<byte> data = stackalloc byte[] { 0x01, 0x02, 0x03, 0x04 };
Span<byte> parity = stackalloc byte[data.Length];

state.Encrypt(data, parity, isIn: false);
```

The existing array/offset/length API remains available:

```csharp
byte[] data = { 0x01, 0x02, 0x03, 0x04 };
byte[] parity = new byte[data.Length];

state.Encrypt(data, parity, offset: 0, length: data.Length);
```

Both APIs produce identical encrypted data, parity values, and final state.

## LFSR state recovery

### List API

The original API returns all candidates at once in deterministic order:

```csharp
List<Crypto1State> states32 = Crapto1.LfsrRecovery32(ks2, input);
List<Crypto1State> states64 = Crapto1.LfsrRecovery64(ks2, ks3);
```

This is the most convenient API, but retaining the complete
`List<Crypto1State>` requires memory proportional to the candidate count.

### Reusable workspace

Applications that perform recovery repeatedly can reuse a
`Crypto1RecoveryWorkspace` to avoid repeatedly allocating large work buffers:

```csharp
using var workspace = new Crypto1RecoveryWorkspace();

var firstRun = Crapto1.LfsrRecovery32(ks2, input, workspace);
var secondRun = Crapto1.LfsrRecovery32(otherKs2, otherInput, workspace);
```

Workspace behavior:

- Buffers are rented lazily; odd, even, and table buffers are created only when
  needed.
- `Dispose()` clears only the used buffer regions before returning them to
  `ArrayPool<uint>`.
- A workspace is not thread-safe. Each concurrent recovery operation requires
  its own workspace.
- Using a workspace after `Dispose()` throws `ObjectDisposedException`.

### Streaming visitor API

When all candidates do not need to be retained, the visitor API processes
states immediately and reduces warmed-up allocation to nearly zero:

```csharp
using var workspace = new Crypto1RecoveryWorkspace();

Crypto1State firstState = default;
bool found = false;

RecoveryVisitResult result = Crapto1.VisitLfsrRecovery32(
    ks2,
    input,
    workspace,
    (in Crypto1State state) =>
    {
        firstState = state;
        found = true;

        // Returning false stops recovery immediately.
        return false;
    });

Console.WriteLine($"Visited: {result.VisitedCount}");
Console.WriteLine($"Completed: {result.Completed}");
```

`Completed` is `false` when the visitor returns `false`, and `true` when the
recovery search reaches its natural end. The same pattern is available for
64-bit recovery:

```csharp
RecoveryVisitResult result = Crapto1.VisitLfsrRecovery64(
    ks2,
    ks3,
    workspace,
    (in Crypto1State state) => Process(state));
```

## MfKey recovery

### MfKey32 with one tag nonce

For two reader challenge/response exchanges:

```csharp
ulong key = MfKey.MfKey32(
    uid,
    nt,
    nr0,
    ar0,
    nr1,
    ar1);
```

For multiple exchanges that share the same `nt`:

```csharp
Nonce[] nonces =
{
    new() { Nr = nr0, Ar = ar0 },
    new() { Nr = nr1, Ar = ar1 },
    new() { Nr = nr2, Ar = ar2 }
};

ulong key = MfKey.MfKey32(uid, nt, nonces);
```

### MfKey32 with different tag nonces

```csharp
Nonce[] nonces =
{
    new() { Nt = nt0, Nr = nr0, Ar = ar0 },
    new() { Nt = nt1, Nr = nr1, Ar = ar1 },
    new() { Nt = nt2, Nr = nr2, Ar = ar2 }
};

ulong key = MfKey.MfKey32(uid, nonces);
```

MfKey32 returns a key only when exactly one candidate validates. It returns
`ulong.MaxValue` when no candidate or multiple candidates validate:

```csharp
if (key == ulong.MaxValue)
{
    // The key could not be determined uniquely.
}
```

An empty nonce collection preserves the original behavior and throws
`InvalidOperationException`.

### MfKey64

```csharp
ulong key = MfKey.MfKey64(uid, nt, nr, ar, at);
```

MfKey64 recovers a state from 64 bits of keystream and rolls that state back to
the original key. It throws `InvalidOperationException` if recovery produces no
candidate.

### Execution options

Every MfKey overload has a corresponding overload that accepts
`MfKeyExecutionOptions`:

```csharp
using var cancellation = new CancellationTokenSource();
using var workspace = new Crypto1RecoveryWorkspace();

var options = new MfKeyExecutionOptions
{
    Workspace = workspace,
    MaxDegreeOfParallelism = -1,
    CancellationToken = cancellation.Token
};

ulong key = MfKey.MfKey32(uid, nonces, options);
```

| Option | Behavior |
| --- | --- |
| `Workspace` | Optional reusable recovery workspace |
| `MaxDegreeOfParallelism = -1` | Uses `max(1, ProcessorCount - 1)` validation workers |
| `MaxDegreeOfParallelism = 1` | Validates synchronously on the producer thread |
| `MaxDegreeOfParallelism > 1` | Uses the current thread for production and the remaining slots for validation workers |
| `CancellationToken` | Propagates cancellation to the producer, queue, and workers |

MfKey32 uses a bounded producer-consumer pipeline with pooled batches of 4,096
states. Recovery and validation stop after a second valid result is found. All
pooled batches are returned on success, cancellation, or failure.

## Integer and byte Span APIs

Integer conversion uses big-endian byte order:

```csharp
using Crapto1Sharp.Extensions;

Span<byte> uintBytes = stackalloc byte[4];
Span<byte> ulongBytes = stackalloc byte[8];

0x89ABCDEFu.WriteBytes(uintBytes);
0x0123456789ABCDEFul.WriteBytes(ulongBytes);

uint uintValue = ((ReadOnlySpan<byte>)uintBytes).ToUInt32();
ulong ulongValue = ((ReadOnlySpan<byte>)ulongBytes).ToUInt64();
```

Use the allocating helpers when a new array is required:

```csharp
byte[] uintBytes = 0x89ABCDEFu.GetBytes();
byte[] ulongBytes = 0x0123456789ABCDEFul.GetBytes();
```

## Performance

Benchmarks use BenchmarkDotNet with three warmup iterations, eight measurement
iterations, and `MemoryDiagnoser`. The following summary was measured on the
same Ryzen 9 5950X machine with a .NET 10 Release build:

| Benchmark | Before | After | Change |
| --- | ---: | ---: | ---: |
| `LfsrRecovery32(0, 0)` | 350.153 ms | 304.533 ms | -13.0% |
| `LfsrRecovery64(0, 0)` | 303.605 ms | 177.295 ms | -41.6% |
| MfKey32 same-NT, many nonces | 340.544 ms | 296.920 ms | -12.8% |
| MfKey32 many-NT, many nonces | 278.969 ms | 245.258 ms | -12.1% |
| MfKey64 | 105.894 ms | 3.199 ms | -97.0% |

Recovery32 managed allocation:

| API path | Allocation |
| --- | ---: |
| Cold public List path | 19,937,048 B |
| Warm public List path | 2,097,432 B |
| Warm reusable-workspace visitor path | 96 B |

See [PERFORMANCE.md](PERFORMANCE.md) for the complete environment, benchmark,
and allocation results.

> Benchmark results depend on the CPU, runtime, power configuration, and input
> candidate count. Measure again in your deployment environment.

Run all benchmarks:

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --filter '*' --join
```

Print the recovery correctness fingerprints:

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --characterize
```

Measure the allocation acceptance values:

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --allocation
```

## Build and test

```shell
dotnet restore Crapto1Sharp.sln
dotnet build Crapto1Sharp.sln -c Release --no-restore
dotnet test Crapto1Sharp.Test/Crapto1Sharp.Test.csproj \
  -c Release -f net10.0 --no-build
dotnet test Crapto1Sharp.Test/Crapto1Sharp.Test.csproj \
  -c Release -f net462 --no-build
```

The net10 and net462 suites currently contain 42 tests each, covering:

- The original 27 compatibility tests.
- Recovery candidate counts and ordered hashes.
- Exhaustive validation of all 20-bit filter-table inputs.
- Equivalence of List, visitor, and reused-workspace paths.
- Equivalence of Span and array APIs.
- Clearing of active pool regions and workspace disposal.
- Concurrent first initialization of `NonceDistance`.
- Cancellation, worker exceptions, and early stopping after a second result.
- Sorted, reverse-sorted, and random absolute-range sorting.

## Project structure

| Path | Contents |
| --- | --- |
| `Crapto1Sharp/` | Library and public APIs |
| `Crapto1Sharp.Test/` | MSTest compatibility and performance-contract tests |
| `Crapto1Sharp.Benchmarks/` | BenchmarkDotNet benchmarks and allocation tools |
| `PERFORMANCE.md` | Before/after performance results from the same machine |

## License

This project is licensed under the
[GNU General Public License v3.0](LICENSE).
