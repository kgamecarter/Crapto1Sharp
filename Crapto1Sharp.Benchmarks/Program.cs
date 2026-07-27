using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using Crapto1Sharp;
using System;
using System.Collections.Generic;
using System.Linq;

if (args.Contains("--characterize", StringComparer.Ordinal))
{
    Characterize();
    return;
}
if (args.Contains("--allocation", StringComparer.Ordinal))
{
    MeasureAllocations();
    return;
}

BenchmarkSwitcher.FromAssembly(typeof(Crapto1Benchmarks).Assembly).Run(args);

static void Characterize()
{
    PrintStates("LfsrRecovery32(0,0)", Crapto1.LfsrRecovery32(0, 0));
    PrintStates("LfsrRecovery64(0,0)", Crapto1.LfsrRecovery64(0, 0));
}

static void PrintStates(string name, IReadOnlyList<Crypto1State> states)
{
    const ulong offset = 14695981039346656037UL;
    const ulong prime = 1099511628211UL;
    var hash = offset;
    for (var i = 0; i < states.Count; i++)
    {
        hash = (hash ^ states[i].Odd) * prime;
        hash = (hash ^ states[i].Even) * prime;
    }
    Console.WriteLine($"{name}: count={states.Count}, fnv64=0x{hash:X16}");
}

static void MeasureAllocations()
{
    var before = GC.GetAllocatedBytesForCurrentThread();
    var cold = Crapto1.LfsrRecovery32(0, 0);
    var coldBytes = GC.GetAllocatedBytesForCurrentThread() - before;

    before = GC.GetAllocatedBytesForCurrentThread();
    var warm = Crapto1.LfsrRecovery32(0, 0);
    var warmBytes = GC.GetAllocatedBytesForCurrentThread() - before;

    using var workspace = new Crypto1RecoveryWorkspace();
    Crapto1.VisitLfsrRecovery32(0, 0, workspace, VisitAll);
    before = GC.GetAllocatedBytesForCurrentThread();
    var visit = Crapto1.VisitLfsrRecovery32(0, 0, workspace, VisitAll);
    var visitorBytes = GC.GetAllocatedBytesForCurrentThread() - before;

    Console.WriteLine($"cold-list={coldBytes} B ({cold.Count} states)");
    Console.WriteLine($"warm-list={warmBytes} B ({warm.Count} states)");
    Console.WriteLine(
        $"warm-workspace-visitor={visitorBytes} B ({visit.VisitedCount} states)");
}

static bool VisitAll(in Crypto1State state) => true;

[MemoryDiagnoser]
[SimpleJob(warmupCount: 3, iterationCount: 8)]
public class Crapto1Benchmarks
{
    private const uint Uid = 0x866285B1;
    private const uint Nt0 = 0xB830049B;
    private const uint Nt1 = 0xE9FAD974;
    private const ulong Key = 0xFFFFFFFFFFFF;

    private Nonce[] _sameNtMany = null!;
    private Nonce[] _manyNtMany = null!;
    private uint _sameNr0;
    private uint _sameAr0;
    private uint _sameNr1;
    private uint _sameAr1;
    private uint _manyNr0;
    private uint _manyAr0;
    private uint _manyNr1;
    private uint _manyAr1;

    [GlobalSetup]
    public void Setup()
    {
        _sameNtMany = CreateSameNtNonces(Uid, Nt0, Key, 123456, 10);
        _manyNtMany = CreateManyNtNonces(Uid, Key, 123456, 10);
        _sameNr0 = _sameNtMany[0].Nr;
        _sameAr0 = _sameNtMany[0].Ar;
        _sameNr1 = _sameNtMany[1].Nr;
        _sameAr1 = _sameNtMany[1].Ar;
        _manyNr0 = _manyNtMany[0].Nr;
        _manyAr0 = _manyNtMany[0].Ar;
        _manyNr1 = _manyNtMany[1].Nr;
        _manyAr1 = _manyNtMany[1].Ar;
        _ = Crapto1.NonceDistance(Nt0, Nt0);
    }

    [Benchmark]
    public List<Crypto1State> LfsrRecovery32() => Crapto1.LfsrRecovery32(0, 0);

    [Benchmark]
    public List<Crypto1State> LfsrRecovery64() => Crapto1.LfsrRecovery64(0, 0);

    [Benchmark]
    public ulong MfKey32SameNtTwo() =>
        MfKey.MfKey32(Uid, Nt0, _sameNr0, _sameAr0, _sameNr1, _sameAr1);

    [Benchmark]
    public ulong MfKey32SameNtMany() => MfKey.MfKey32(Uid, Nt0, _sameNtMany);

    [Benchmark]
    public ulong MfKey32ManyNtTwo() =>
        MfKey.MfKey32(
            Uid,
            _manyNtMany[0].Nt,
            _manyNr0,
            _manyAr0,
            _manyNtMany[1].Nt,
            _manyNr1,
            _manyAr1);

    [Benchmark]
    public ulong MfKey32ManyNtMany() => MfKey.MfKey32(Uid, _manyNtMany);

    [Benchmark]
    public ulong MfKey64()
    {
        var state = new Crypto1State(Key);
        state.Crypto1Word(Uid ^ Nt0);
        var nr = 0x8D37B58D;
        var encryptedNr = state.Crypto1Word(nr) ^ nr;
        var ar = Crypto1.PrngSuccessor(Nt0, 64) ^ state.Crypto1Word();
        var at = Crypto1.PrngSuccessor(Nt0, 96) ^ state.Crypto1Word();
        return MfKey.MfKey64(Uid, Nt0, encryptedNr, ar, at);
    }

    [Benchmark]
    public int NonceDistance() => Crapto1.NonceDistance(Nt0, Nt1);

    private static Nonce[] CreateSameNtNonces(
        uint uid,
        uint nt,
        ulong key,
        int seed,
        int count)
    {
        var result = new Nonce[count];
        var random = new Random(seed);
        var p64 = Crypto1.PrngSuccessor(nt, 64);
        for (var i = 0; i < result.Length; i++)
        {
            var state = new Crypto1State(key);
            state.Crypto1Word(uid ^ nt);
            var nr = (uint)random.Next();
            result[i] = new Nonce
            {
                Nr = state.Crypto1Word(nr) ^ nr,
                Ar = p64 ^ state.Crypto1Word()
            };
        }
        return result;
    }

    private static Nonce[] CreateManyNtNonces(uint uid, ulong key, int seed, int count)
    {
        var result = new Nonce[count];
        var random = new Random(seed);
        for (var i = 0; i < result.Length; i++)
        {
            var nt = (uint)random.Next();
            var state = new Crypto1State(key);
            state.Crypto1Word(uid ^ nt);
            var nr = (uint)random.Next();
            result[i] = new Nonce
            {
                Nt = nt,
                Nr = state.Crypto1Word(nr) ^ nr,
                Ar = Crypto1.PrngSuccessor(nt, 64) ^ state.Crypto1Word()
            };
        }
        return result;
    }
}
