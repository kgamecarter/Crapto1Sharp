# Performance results

Measurements were taken on 2026-07-28 before and after the recovery/MfKey
refactor on the same machine and configuration:

- AMD Ryzen 9 5950X (16 physical / 32 logical cores)
- Windows 11 10.0.26200.8894
- .NET SDK 10.0.301, .NET runtime 10.0.9, x64 RyuJIT AVX2
- BenchmarkDotNet 0.14.0
- Release build, 3 warmup iterations, 8 measurement iterations
- `MemoryDiagnoser` enabled

The benchmark source is
`Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj`. The final run was
split into batches only to fit the command runner time limit; benchmark job
settings were unchanged.

## Before / after

Times below are BenchmarkDotNet means. A negative delta is faster.

| Benchmark | Before | After | Time delta | Before allocation | After allocation |
| --- | ---: | ---: | ---: | ---: | ---: |
| LfsrRecovery32(0, 0) | 350.153 ms | 304.533 ms | -13.0% | 69,206,320 B | 2,048.66 KiB |
| LfsrRecovery64(0, 0) | 303.605 ms | 177.295 ms | -41.6% | 262,624 B | 0 B |
| MfKey32 same-NT, two nonces | 333.245 ms | 266.011 ms | -20.2% | 69,217,848 B | 36.55 KiB |
| MfKey32 same-NT, many nonces | 340.544 ms | 296.920 ms | -12.8% | 92,557,904 B | 35.90 KiB |
| MfKey32 many-NT, two nonces | 282.482 ms | 289.600 ms | +2.5% | 69,215,560 B | 37,144 B |
| MfKey32 many-NT, many nonces | 278.969 ms | 245.258 ms | -12.1% | 87,187,104 B | 42,189 B |
| MfKey64 | 105.894 ms | 3.199 ms | -97.0% | 262,323 B | 202 B |
| NonceDistance, warm | 1.904 ns | 0.958 ns | -49.7% | 0 B | 0 B |

No benchmark regressed by more than 5%. `LfsrRecovery32` and both
many-nonce MfKey32 scenarios improved by more than 10%.

## Allocation acceptance checks

These values were measured in a fresh Release process with
`GC.GetAllocatedBytesForCurrentThread()`:

| Scenario | Allocated | Limit |
| --- | ---: | ---: |
| Cold public `LfsrRecovery32(0, 0)` List path | 19,937,048 B | 20 MiB |
| Warm public `LfsrRecovery32(0, 0)` List path | 2,097,432 B | 3 MiB |
| Warm reusable-workspace visitor path | 96 B | 128 KiB |

## Correctness characterization

The following recovery output fingerprints were captured before the core
refactor and remain covered by tests:

| Scenario | Candidate count | Ordered FNV-1a hash |
| --- | ---: | --- |
| LfsrRecovery32(0, 0) | 186,674 | `AF7765E0518350C9` |
| LfsrRecovery64(0, 0) | 1 | `08328807B4EB6FED` |

