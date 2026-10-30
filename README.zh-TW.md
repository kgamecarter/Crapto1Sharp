[![CI](https://github.com/kgamecarter/Crapto1Sharp/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/kgamecarter/Crapto1Sharp/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Crapto1Sharp.svg)](https://www.nuget.org/packages/Crapto1Sharp/)

[English](README.md) | **繁體中文**

# Crapto1Sharp

Crapto1Sharp 是以 C# 實作的 Crypto1／MIFARE Classic 狀態運算與金鑰
recovery 函式庫，提供：

- Crypto1 bit、byte、word 運算及 rollback。
- 32-bit、64-bit LFSR state recovery。
- same-NT 與 many-NT 的 MfKey32，以及 MfKey64。
- 可重用的 pooled recovery workspace 與 visitor 串流 API。
- `Span<T>` 加密、序列化 API。
- `netstandard1.1` 到 `net10.0` 的一致公開 API。

> [!IMPORTANT]
> Crypto1 是已被公開破解的舊式密碼系統，不應用於保護新系統。本專案適合相容性研究、測試與已取得授權的設備分析。請勿用於未經授權的卡片或系統。

## 支援框架

| Target framework | 用途 |
| --- | --- |
| `netstandard1.1` | 舊版、廣泛相容的 .NET 實作 |
| `netstandard2.0` | 一般 .NET／.NET Framework 相容 |
| `net462` | .NET Framework 4.6.2 |
| `net10.0` | 最新 .NET、使用硬體加速 parity 路徑 |

`net462` 所需的 `System.Memory` 與 `System.Buffers` 會由 NuGet 自動解析。

## 安裝

.NET CLI：

```shell
dotnet add package Crapto1Sharp
```

Visual Studio Package Manager：

```powershell
Install-Package Crapto1Sharp
```

程式通常只需要匯入：

```csharp
using Crapto1Sharp;
using Crapto1Sharp.Extensions;
```

## Crypto1 基本操作

`Crypto1State` 代表 Crypto1 的 48-bit LFSR 狀態。建構時可傳入 48-bit
key；每次 bit、byte 或 word 操作都會推進 state。

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

如需反向還原 state：

```csharp
byte previousBit = state.LfsrRollbackBit();
byte previousByte = state.LfsrRollbackByte();
uint previousWord = state.LfsrRollbackWord(input);
```

`isEncrypted`／`isIn` 參數用來表示輸入是否為 Crypto1 feedback 的一部分；
請依協定中資料是明文輸入或加密輸入來選擇。

## 資料與 parity 加密

建議新程式使用 allocation-free 的 Span overload：

```csharp
using Crapto1Sharp;

var state = new Crypto1State(0xFFFFFFFFFFFF);
Span<byte> data = stackalloc byte[] { 0x01, 0x02, 0x03, 0x04 };
Span<byte> parity = stackalloc byte[data.Length];

state.Encrypt(data, parity, isIn: false);
```

既有 array／offset／length API 仍然保留：

```csharp
byte[] data = { 0x01, 0x02, 0x03, 0x04 };
byte[] parity = new byte[data.Length];

state.Encrypt(data, parity, offset: 0, length: data.Length);
```

兩種 API 會產生相同的資料、parity 與最終 state。

## LFSR state recovery

### List API

原有 API 會一次回傳所有候選，候選順序保持穩定：

```csharp
List<Crypto1State> states32 = Crapto1.LfsrRecovery32(ks2, input);
List<Crypto1State> states64 = Crapto1.LfsrRecovery64(ks2, ks3);
```

這是最方便的介面，但建立完整 `List<Crypto1State>` 仍需要與候選數量成正比的
記憶體。

### 重用 workspace

重複執行 recovery 時，可重用 `Crypto1RecoveryWorkspace` 以避免反覆配置大型
工作緩衝區：

```csharp
using var workspace = new Crypto1RecoveryWorkspace();

var firstRun = Crapto1.LfsrRecovery32(ks2, input, workspace);
var secondRun = Crapto1.LfsrRecovery32(otherKs2, otherInput, workspace);
```

Workspace 的注意事項：

- 採 lazy rent；只有實際使用的 odd、even 或 table buffer 才會租用。
- `Dispose()` 時只清除曾使用的有效區域，再歸還 `ArrayPool<uint>`。
- instance 不是 thread-safe；每個並行 recovery 必須使用獨立 workspace。
- `Dispose()` 後再次使用會拋出 `ObjectDisposedException`。

### Visitor 串流 API

不需要保留所有候選時，visitor API 可以即時處理 state，並將暖機後的額外
配置降到接近零：

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

        // false 會立即停止 recovery。
        return false;
    });

Console.WriteLine($"Visited: {result.VisitedCount}");
Console.WriteLine($"Completed: {result.Completed}");
```

Visitor 回傳 `false` 時，`Completed` 為 `false`；完整走訪所有候選時則為
`true`。64-bit recovery 亦提供相同模式：

```csharp
RecoveryVisitResult result = Crapto1.VisitLfsrRecovery64(
    ks2,
    ks3,
    workspace,
    (in Crypto1State state) => Process(state));
```

## MfKey recovery

### MfKey32：相同 tag nonce

兩筆 reader challenge／response：

```csharp
ulong key = MfKey.MfKey32(
    uid,
    nt,
    nr0,
    ar0,
    nr1,
    ar1);
```

多筆相同 `nt` 的紀錄：

```csharp
Nonce[] nonces =
{
    new() { Nr = nr0, Ar = ar0 },
    new() { Nr = nr1, Ar = ar1 },
    new() { Nr = nr2, Ar = ar2 }
};

ulong key = MfKey.MfKey32(uid, nt, nonces);
```

### MfKey32：不同 tag nonce

```csharp
Nonce[] nonces =
{
    new() { Nt = nt0, Nr = nr0, Ar = ar0 },
    new() { Nt = nt1, Nr = nr1, Ar = ar1 },
    new() { Nt = nt2, Nr = nr2, Ar = ar2 }
};

ulong key = MfKey.MfKey32(uid, nonces);
```

MfKey32 只有在剛好找到一組有效結果時才回傳 key；找不到或找到多組結果時
回傳 `ulong.MaxValue`：

```csharp
if (key == ulong.MaxValue)
{
    // 無法唯一決定 key。
}
```

空的 nonce 集合會維持既有行為，拋出 `InvalidOperationException`。

### MfKey64

```csharp
ulong key = MfKey.MfKey64(uid, nt, nr, ar, at);
```

MfKey64 會從 64-bit keystream recovery 找到 state，再 rollback 回原始 key。
若 recovery 沒有任何候選，會拋出 `InvalidOperationException`。

### 執行選項

所有 MfKey overload 都有接受 `MfKeyExecutionOptions` 的版本：

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

| 選項 | 行為 |
| --- | --- |
| `Workspace` | 選用的可重用 recovery workspace |
| `MaxDegreeOfParallelism = -1` | 預設使用 `max(1, ProcessorCount - 1)` 個 validation workers |
| `MaxDegreeOfParallelism = 1` | 在 producer thread 同步驗證，不建立 worker |
| `MaxDegreeOfParallelism > 1` | producer 使用目前執行緒，其餘額度用於 validation workers |
| `CancellationToken` | 將取消傳播至 producer、queue 與 workers |

MfKey32 使用每批 4,096 個 state 的 bounded producer-consumer pipeline。找到第二
組有效結果後會停止 recovery 與 validation，且所有 pooled batch 都會在正常、
取消或例外路徑歸還。

## 整數與 byte Span API

轉換採 big-endian byte order：

```csharp
using Crapto1Sharp.Extensions;

Span<byte> uintBytes = stackalloc byte[4];
Span<byte> ulongBytes = stackalloc byte[8];

0x89ABCDEFu.WriteBytes(uintBytes);
0x0123456789ABCDEFul.WriteBytes(ulongBytes);

uint uintValue = ((ReadOnlySpan<byte>)uintBytes).ToUInt32();
ulong ulongValue = ((ReadOnlySpan<byte>)ulongBytes).ToUInt64();
```

需要新陣列時仍可使用：

```csharp
byte[] uintBytes = 0x89ABCDEFu.GetBytes();
byte[] ulongBytes = 0x0123456789ABCDEFul.GetBytes();
```

## 效能

效能測試使用 BenchmarkDotNet、3 次 warmup、8 次 measurement iteration 及
`MemoryDiagnoser`。以下為同一台 Ryzen 9 5950X、.NET 10 Release 環境的摘要：

| Benchmark | 優化前 | 優化後 | 變化 |
| --- | ---: | ---: | ---: |
| `LfsrRecovery32(0, 0)` | 350.153 ms | 304.533 ms | -13.0% |
| `LfsrRecovery64(0, 0)` | 303.605 ms | 177.295 ms | -41.6% |
| MfKey32 same-NT, many nonces | 340.544 ms | 296.920 ms | -12.8% |
| MfKey32 many-NT, many nonces | 278.969 ms | 245.258 ms | -12.1% |
| MfKey64 | 105.894 ms | 3.199 ms | -97.0% |

Recovery32 的 managed allocation：

| 使用方式 | Allocation |
| --- | ---: |
| 冷啟動 public List path | 19,937,048 B |
| 暖機 public List path | 2,097,432 B |
| 暖機 reusable workspace visitor path | 96 B |

完整環境、全部 benchmark 與 allocation 結果請參考
[PERFORMANCE.md](PERFORMANCE.md)。

> Benchmark 數字會受 CPU、runtime、電源設定與輸入候選數影響，請以自己的部署
> 環境重新量測。

執行 benchmark：

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --filter '*' --join
```

輸出 recovery 正確性 fingerprint：

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --characterize
```

量測 allocation 驗收值：

```shell
dotnet run --project Crapto1Sharp.Benchmarks/Crapto1Sharp.Benchmarks.csproj \
  -c Release -- --allocation
```

## 建置與測試

```shell
dotnet restore Crapto1Sharp.sln
dotnet build Crapto1Sharp.sln -c Release --no-restore
dotnet test Crapto1Sharp.Test/Crapto1Sharp.Test.csproj \
  -c Release -f net10.0 --no-build
dotnet test Crapto1Sharp.Test/Crapto1Sharp.Test.csproj \
  -c Release -f net462 --no-build
```

目前 net10 與 net462 各有 42 組測試，涵蓋：

- 原有 27 組相容性測試。
- Recovery candidate count 與 ordered hash。
- Filter table 的完整 20-bit 輸入驗證。
- List、visitor 與 workspace reuse 等價性。
- Span／array API 等價性。
- pool 有效區清除、workspace dispose。
- NonceDistance 並行初始化。
- 取消、worker exception 與第二組結果提早停止。
- sorted、reverse、random absolute range sorting。

## 專案結構

| 路徑 | 內容 |
| --- | --- |
| `Crapto1Sharp/` | 函式庫與公開 API |
| `Crapto1Sharp.Test/` | MSTest 相容性與效能契約測試 |
| `Crapto1Sharp.Benchmarks/` | BenchmarkDotNet benchmark 與 allocation 工具 |
| `PERFORMANCE.md` | 同機器 before／after 效能紀錄 |

## 授權

本專案使用 [GNU General Public License v3.0](LICENSE)。
