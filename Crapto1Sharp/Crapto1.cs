using Crapto1Sharp.Extensions;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Crapto1Sharp;

/// <summary>
/// Provides reverse Crypto1 operations, LFSR state recovery, and nonce-distance
/// calculations.
/// </summary>
public static class Crapto1
{
    /// <summary>
    /// Number of entries in the exhaustive 20-bit recovery filter table.
    /// </summary>
    private const int FilterTableLength = 1 << 20;

    /// <summary>
    /// Mask used to select the low 20 bits for a filter-table lookup.
    /// </summary>
    private const uint FilterTableMask = FilterTableLength - 1;

    /// <summary>
    /// Thread-safe, lazily initialized filter lookup used only by recovery hot paths.
    /// </summary>
    private static readonly Lazy<byte[]> RecoveryFilters =
        new(CreateRecoveryFilterTable, isThreadSafe: true);

    /// <summary>
    /// Looks up the Crypto1 filter bit for a recovery candidate.
    /// </summary>
    /// <param name="value">The candidate value.</param>
    /// <returns>The cached filter output bit.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte RecoveryFilter(uint value) =>
        RecoveryFilters.Value[(int)(value & FilterTableMask)];

    /// <summary>
    /// Builds the exhaustive lookup table for all 20-bit filter inputs.
    /// </summary>
    /// <returns>The initialized one-byte-per-input lookup table.</returns>
    private static byte[] CreateRecoveryFilterTable()
    {
        var result = new byte[FilterTableLength];
        for (var i = 0; i < result.Length; i++)
            result[i] = Crypto1.Filter((uint)i);
        return result;
    }

    /// <summary>
    /// Exposes the recovery filter lookup to exhaustive contract tests.
    /// </summary>
    /// <param name="value">The candidate value.</param>
    /// <returns>The cached filter output bit.</returns>
    internal static byte GetRecoveryFilterForTesting(uint value) =>
        RecoveryFilter(value);

    /// <summary>
    /// Rolls a Crypto1 state back by one bit and returns the filter bit associated
    /// with the restored state.
    /// </summary>
    /// <param name="_state">The state to roll back.</param>
    /// <param name="in">The input bit used by the original forward operation.</param>
    /// <param name="isEncrypted">Whether the original input was encrypted.</param>
    /// <returns>The restored state's filter output bit.</returns>
    public static byte LfsrRollbackBit(this ref Crypto1State _state, byte @in = 0, bool isEncrypted = false)
    {
        uint @out;
        byte ret;

        _state.Odd &= 0xffffff;
        var t = _state.Odd;
        _state.Odd = _state.Even;
        _state.Even = t;

        @out = _state.Even & 1;
        @out ^= Crypto1.LF_POLY_EVEN & (_state.Even >>= 1);
        @out ^= Crypto1.LF_POLY_ODD & _state.Odd;
        @out ^= @in != 0 ? 1u : 0u;
        @out ^= (ret = Crypto1.Filter(_state.Odd)) & (isEncrypted ? 1u : 0u);

        _state.Even |= (uint)Crypto1.EvenParity32(@out) << 23;
        return ret;
    }

    /// <summary>
    /// Rolls a Crypto1 state back by one byte.
    /// </summary>
    /// <param name="_state">The state to roll back.</param>
    /// <param name="in">The input byte used by the original forward operation.</param>
    /// <param name="isEncrypted">Whether the original input was encrypted.</param>
    /// <returns>The filter output byte reconstructed while rolling back.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte LfsrRollbackByte(this ref Crypto1State _state, byte @in = 0, bool isEncrypted = false)
    {
        byte ret = 0;
        
        for (var i = 7; i >= 0; --i)
            ret |= (byte)(_state.LfsrRollbackBit(@in.Bit(i), isEncrypted) << i);

        return ret;
    }

    /// <summary>
    /// Rolls a Crypto1 state back by one protocol-ordered 32-bit word.
    /// </summary>
    /// <param name="_state">The state to roll back.</param>
    /// <param name="in">The input word used by the original forward operation.</param>
    /// <param name="isEncrypted">Whether the original input was encrypted.</param>
    /// <returns>The filter output word reconstructed while rolling back.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint LfsrRollbackWord(this ref Crypto1State _state, uint @in = 0, bool isEncrypted = false)
    {
        uint ret = 0;

        for (var i = 31; i >= 0; --i)
            ret |= (uint)_state.LfsrRollbackBit(@in.BeBit(i), isEncrypted) << (i ^ 24);

        return ret;
    }

    /// <summary>
    /// Calculates two partial linear-feedback contributions and stores them in
    /// the candidate's most-significant bits.
    /// </summary>
    /// <param name="item">The candidate state to update.</param>
    /// <param name="mask1">The first feedback polynomial mask.</param>
    /// <param name="mask2">The second feedback polynomial mask.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void UpdateContribution(ref uint item, uint mask1, uint mask2)
    {
        uint p = item >> 25;

        p = p << 1 | Crypto1.EvenParity32(item & mask1);
        p = p << 1 | Crypto1.EvenParity32(item & mask2);
        item = p << 24 | (item & 0xffffff);
    }

    /// <summary>
    /// Extends a candidate range by one keystream bit and updates its partial
    /// feedback contributions.
    /// </summary>
    /// <param name="table">The pooled candidate table.</param>
    /// <param name="start">The absolute first candidate index.</param>
    /// <param name="end">The absolute last candidate index, updated in place.</param>
    /// <param name="bit">The expected keystream bit.</param>
    /// <param name="m1">The first feedback contribution mask.</param>
    /// <param name="m2">The second feedback contribution mask.</param>
    /// <param name="in">The two input contribution bits.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtendTable(
        PooledBuffer<uint> table,
        int start,
        ref int end,
        uint bit,
        uint m1,
        uint m2,
        uint @in)
    {
        @in <<= 24;
        var i = start;
        while (i <= end)
        {
            var values = table.Array;
            values[i] <<= 1;
            var filter0 = RecoveryFilter(values[i]);
            var filter1 = RecoveryFilter(values[i] | 1);

            if ((filter0 ^ filter1) != 0)
            {
                values[i] |= filter0 ^ bit;
                UpdateContribution(ref values[i], m1, m2);
                values[i] ^= @in;
            }
            else if (filter0 == bit)
            {
                table.EnsureCapacity(end + 2);
                values = table.Array;
                values[++end] = values[i + 1];
                values[i + 1] = values[i] | 1;
                UpdateContribution(ref values[i], m1, m2);
                values[i++] ^= @in;
                UpdateContribution(ref values[i], m1, m2);
                values[i] ^= @in;
            }
            else
            {
                values[i--] = values[end--];
            }
            i++;
        }
        table.MarkUsed(end + 1);
    }

    /// <summary>
    /// Extends a candidate range by one keystream bit without calculating
    /// partial feedback contributions.
    /// </summary>
    /// <param name="table">The pooled candidate table.</param>
    /// <param name="start">The absolute first candidate index.</param>
    /// <param name="end">The absolute last candidate index, updated in place.</param>
    /// <param name="bit">The expected keystream bit.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtendTableSimple(
        PooledBuffer<uint> table,
        int start,
        ref int end,
        uint bit)
    {
        var i = start;
        while (i <= end)
        {
            var values = table.Array;
            values[i] <<= 1;
            var filter0 = RecoveryFilter(values[i]);
            var filter1 = RecoveryFilter(values[i] | 1);

            if ((filter0 ^ filter1) != 0)
            {
                values[i] |= filter0 ^ bit;
            }
            else if (filter0 == bit)
            {
                table.EnsureCapacity(end + 2);
                values = table.Array;
                values[++end] = values[++i];
                values[i] = values[i - 1] | 1;
            }
            else
            {
                values[i--] = values[end--];
            }
            i++;
        }
        table.MarkUsed(end + 1);
    }

    /// <summary>
    /// Extends the fixed Recovery64 table by one keystream bit using a directly
    /// cached filter array.
    /// </summary>
    /// <param name="values">The Recovery64 candidate table.</param>
    /// <param name="end">The last active table index, updated in place.</param>
    /// <param name="bit">The expected keystream bit.</param>
    /// <param name="filters">The exhaustive 20-bit filter lookup table.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtendRecovery64Table(
        uint[] values,
        ref int end,
        uint bit,
        byte[] filters)
    {
        var i = 0;
        while (i <= end)
        {
            values[i] <<= 1;
            var filter0 = filters[(int)(values[i] & FilterTableMask)];
            var filter1 = filters[(int)((values[i] | 1) & FilterTableMask)];

            if ((filter0 ^ filter1) != 0)
            {
                values[i] |= filter0 ^ bit;
            }
            else if (filter0 == bit)
            {
                values[++end] = values[++i];
                values[i] = values[i - 1] | 1;
            }
            else
            {
                values[i--] = values[end--];
            }
            i++;
        }
    }

    /// <summary>
    /// Recursively narrows paired odd/even candidate ranges four keystream bits
    /// at a time and emits completed Crypto1 states.
    /// </summary>
    /// <param name="odd">The pooled odd candidate buffer.</param>
    /// <param name="oddStart">The absolute first odd candidate index.</param>
    /// <param name="oddEnd">The absolute last odd candidate index.</param>
    /// <param name="oks">The remaining odd keystream bits.</param>
    /// <param name="even">The pooled even candidate buffer.</param>
    /// <param name="evenStart">The absolute first even candidate index.</param>
    /// <param name="evenEnd">The absolute last even candidate index.</param>
    /// <param name="eks">The remaining even keystream bits.</param>
    /// <param name="rem">The number of remaining recursive extension rounds.</param>
    /// <param name="emit">The sink that receives each completed state.</param>
    /// <param name="in">The remaining input contribution bits.</param>
    /// <returns><see langword="false"/> when the sink requests early termination.</returns>
    private static bool Recover(
        PooledBuffer<uint> odd,
        int oddStart,
        int oddEnd,
        uint oks,
        PooledBuffer<uint> even,
        int evenStart,
        int evenEnd,
        uint eks,
        int rem,
        Func<Crypto1State, bool> emit,
        uint @in)
    {
        if (rem == -1)
        {
            var evenValues = even.Array;
            for (var e = evenStart; e <= evenEnd; e++)
            {
                evenValues[e] =
                    evenValues[e] << 1 ^
                    Crypto1.EvenParity32(evenValues[e] & Crypto1.LF_POLY_EVEN) ^
                    ((@in & 4) != 0 ? 1u : 0u);
                var oddValues = odd.Array;
                for (var o = oddStart; o <= oddEnd; o++)
                {
                    var state = new Crypto1State(
                        even: oddValues[o],
                        odd: evenValues[e] ^
                             Crypto1.EvenParity32(oddValues[o] & Crypto1.LF_POLY_ODD));
                    if (!emit(state))
                        return false;
                }
            }
            return true;
        }

        for (var i = 0; i < 4 && rem-- != 0; i++)
        {
            oks >>= 1;
            eks >>= 1;
            @in >>= 2;
            ExtendTable(
                odd,
                oddStart,
                ref oddEnd,
                oks & 1,
                Crypto1.LF_POLY_EVEN << 1 | 1,
                Crypto1.LF_POLY_ODD << 1,
                0u);
            if (oddEnd < oddStart)
                return true;

            ExtendTable(
                even,
                evenStart,
                ref evenEnd,
                eks & 1,
                Crypto1.LF_POLY_ODD,
                Crypto1.LF_POLY_EVEN << 1 | 1,
                @in & 3);
            if (evenEnd < evenStart)
                return true;
        }

        SortRecoveryRange(odd.Array, oddStart, oddEnd - oddStart + 1);
        SortRecoveryRange(even.Array, evenStart, evenEnd - evenStart + 1);

        while (oddEnd >= oddStart && evenEnd >= evenStart)
        {
            var oddValues = odd.Array;
            var evenValues = even.Array;
            if (((oddValues[oddEnd] ^ evenValues[evenEnd]) >> 24) == 0)
            {
                var previousOddEnd = oddEnd;
                var previousEvenEnd = evenEnd;
                oddEnd = FindGroupStart(oddValues, oddStart, oddEnd);
                evenEnd = FindGroupStart(evenValues, evenStart, evenEnd);
                if (!Recover(
                        odd,
                        oddEnd,
                        previousOddEnd,
                        oks,
                        even,
                        evenEnd,
                        previousEvenEnd,
                        eks,
                        rem,
                        emit,
                        @in))
                    return false;
                oddEnd--;
                evenEnd--;
            }
            else if (oddValues[oddEnd] > evenValues[evenEnd])
            {
                oddEnd = FindGroupStart(oddValues, oddStart, oddEnd) - 1;
            }
            else
            {
                evenEnd = FindGroupStart(evenValues, evenStart, evenEnd) - 1;
            }
        }
        return true;
    }

    /// <summary>
    /// Sorts an absolute candidate range in ascending unsigned order.
    /// </summary>
    /// <param name="values">The candidate array.</param>
    /// <param name="offset">The absolute first index to sort.</param>
    /// <param name="length">The number of elements to sort.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void SortRecoveryRange(uint[] values, int offset, int length)
    {
        Array.Sort(values, offset, length);
    }

    /// <summary>
    /// Finds the first entry in the final high-byte group of a sorted candidate range.
    /// </summary>
    /// <param name="values">The sorted candidate array.</param>
    /// <param name="start">The first index in the search range.</param>
    /// <param name="end">The last index in the search range.</param>
    /// <returns>The first index whose high byte matches the entry at <paramref name="end"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindGroupStart(uint[] values, int start, int end)
    {
        var stop = end;
        var target = values[stop] & 0xff000000;
        while (start != stop)
        {
            var middle = (stop - start) >> 1;
            if (values[start + middle] > target)
                stop = start + middle;
            else
                start += middle + 1;
        }
        return start;
    }

    /// <summary>
    /// Recovers all Crypto1 states compatible with a 32-bit keystream word.
    /// </summary>
    /// <param name="ks2">The observed 32-bit keystream word.</param>
    /// <param name="in">The associated 32-bit input contribution.</param>
    /// <returns>All compatible states in deterministic recovery order.</returns>
    public static List<Crypto1State> LfsrRecovery32(uint ks2, uint @in)
    {
        using var workspace = new Crypto1RecoveryWorkspace();
        return LfsrRecovery32(ks2, @in, workspace);
    }

    /// <summary>
    /// Recovers all Crypto1 states compatible with a 32-bit keystream word using
    /// a reusable workspace.
    /// </summary>
    /// <param name="ks2">The observed 32-bit keystream word.</param>
    /// <param name="in">The associated 32-bit input contribution.</param>
    /// <param name="workspace">The non-thread-safe workspace used for candidate buffers.</param>
    /// <returns>All compatible states in deterministic recovery order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="workspace"/> is <see langword="null"/>.</exception>
    /// <exception cref="ObjectDisposedException"><paramref name="workspace"/> is disposed.</exception>
    public static List<Crypto1State> LfsrRecovery32(
        uint ks2,
        uint @in,
        Crypto1RecoveryWorkspace workspace)
    {
        if (workspace == null)
            throw new ArgumentNullException(nameof(workspace));

        var states = new List<Crypto1State>(1 << 18);
        workspace.Enter();
        try
        {
            Recover32Core(
                ks2,
                @in,
                workspace,
                state =>
                {
                    states.Add(state);
                    return true;
                });
            return states;
        }
        finally
        {
            workspace.Exit();
        }
    }

    /// <summary>
    /// Streams states compatible with a 32-bit keystream word to a visitor.
    /// </summary>
    /// <param name="ks2">The observed 32-bit keystream word.</param>
    /// <param name="in">The associated 32-bit input contribution.</param>
    /// <param name="workspace">The non-thread-safe workspace used for candidate buffers.</param>
    /// <param name="visitor">The callback that receives each compatible state.</param>
    /// <returns>The number of visited states and whether recovery completed.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="workspace"/> or <paramref name="visitor"/> is <see langword="null"/>.
    /// </exception>
    public static RecoveryVisitResult VisitLfsrRecovery32(
        uint ks2,
        uint @in,
        Crypto1RecoveryWorkspace workspace,
        Crypto1StateVisitor visitor)
    {
        if (workspace == null)
            throw new ArgumentNullException(nameof(workspace));
        if (visitor == null)
            throw new ArgumentNullException(nameof(visitor));

        var visited = 0;
        workspace.Enter();
        try
        {
            var completed = Recover32Core(
                ks2,
                @in,
                workspace,
                state =>
                {
                    visited++;
                    return visitor(in state);
                });
            return new RecoveryVisitResult(visited, completed);
        }
        finally
        {
            workspace.Exit();
        }
    }

    /// <summary>
    /// Executes the shared Recovery32 producer against an arbitrary candidate sink.
    /// </summary>
    /// <param name="ks2">The observed 32-bit keystream word.</param>
    /// <param name="in">The associated 32-bit input contribution.</param>
    /// <param name="workspace">The already-acquired recovery workspace.</param>
    /// <param name="emit">The sink that receives completed states.</param>
    /// <returns><see langword="false"/> when the sink requests early termination.</returns>
    internal static bool Recover32Core(
        uint ks2,
        uint @in,
        Crypto1RecoveryWorkspace workspace,
        Func<Crypto1State, bool> emit)
    {
        var oks = 0u;
        var eks = 0u;

        for (var i = 31; i >= 0; i -= 2)
            oks = oks << 1 | ks2.BeBit(i);
        for (var i = 30; i >= 0; i -= 2)
            eks = eks << 1 | ks2.BeBit(i);

        var odd = workspace.Odd;
        var even = workspace.Even;
        odd.EnsureCapacity(Crypto1RecoveryWorkspace.Recovery32BufferLength);
        even.EnsureCapacity(Crypto1RecoveryWorkspace.Recovery32BufferLength);
        var oddValues = odd.Array;
        var evenValues = even.Array;
        oddValues[0] = 0;
        evenValues[0] = 0;
        var oddEnd = 0;
        var evenEnd = 0;

        for (var i = 1u << 20; (int)i >= 0; --i)
        {
            var filter = RecoveryFilter(i);
            if (filter == (oks & 1))
                oddValues[++oddEnd] = i;
            if (filter == (eks & 1))
                evenValues[++evenEnd] = i;
        }
        odd.MarkUsed(oddEnd + 1);
        even.MarkUsed(evenEnd + 1);

        for (var i = 0; i < 4; i++)
        {
            ExtendTableSimple(odd, 0, ref oddEnd, (oks >>= 1) & 1);
            ExtendTableSimple(even, 0, ref evenEnd, (eks >>= 1) & 1);
        }

        @in = (@in >> 16 & 0xff) | (@in << 16) | (@in & 0xff00);
        return Recover(
            odd,
            0,
            oddEnd,
            oks,
            even,
            0,
            evenEnd,
            eks,
            11,
            emit,
            @in << 1);
    }

    /// <summary>
    /// Recovery64 masks used to derive the low linear contribution from the
    /// initial odd candidate.
    /// </summary>
    static readonly uint[] S1 = {
        0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A,
        0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D,
        0xB3C83, 0x59E41, 0xA8995,  0xD027F, 0x6813F, 0x3409F, 0x9E6FA };

    /// <summary>
    /// Recovery64 masks used to derive the low linear contribution from an
    /// extended table candidate.
    /// </summary>
    static readonly uint[] S2 = {
        0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60, 0x0BA557B0,
        0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8,
        0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48,
        0x7D8FDD20, 0x7EC7EE90, 0x7F63F748, 0x79117020 };

    /// <summary>
    /// Recovery64 masks used to precompute high linear contributions.
    /// </summary>
    static readonly uint[] T1 = {
        0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
        0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
        0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
        0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C };

    /// <summary>
    /// Recovery64 masks used to fold table candidates into the high linear
    /// contribution window.
    /// </summary>
    static readonly uint[] T2 = {
        0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0, 0x4A60A960,
        0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268,
        0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488,
        0x25CB11C0, 0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98,
        0x28DE96C8, 0x12CFC0E0, 0x4967E070, 0x64B3F038, 0x74F97398,
        0x7CDC3248, 0x38CE92A0, 0x1C674950, 0x0E33A4A8, 0x01B959D0,
        0x40DCACE8, 0x26CEDDF0 };

    /// <summary>
    /// Recovery64 masks for the final three odd-register extension bits.
    /// </summary>
    static readonly uint[] C1 = { 0x846B5, 0x4235A, 0x211AD };

    /// <summary>
    /// Recovery64 masks for the final three table contribution bits.
    /// </summary>
    static readonly uint[] C2 = { 0x1A822E0, 0x21A822E0, 0x21A822E0 };

    /// <summary>
    /// Recovers all Crypto1 states compatible with two consecutive 32-bit
    /// keystream words.
    /// </summary>
    /// <param name="ks2">The first observed keystream word.</param>
    /// <param name="ks3">The second observed keystream word.</param>
    /// <returns>All compatible states in deterministic recovery order.</returns>
    public static List<Crypto1State> LfsrRecovery64(uint ks2, uint ks3)
    {
        using var workspace = new Crypto1RecoveryWorkspace();
        return LfsrRecovery64(ks2, ks3, workspace);
    }

    /// <summary>
    /// Recovers all Crypto1 states compatible with two consecutive keystream
    /// words using a reusable workspace.
    /// </summary>
    /// <param name="ks2">The first observed keystream word.</param>
    /// <param name="ks3">The second observed keystream word.</param>
    /// <param name="workspace">The non-thread-safe workspace used for the recovery table.</param>
    /// <returns>All compatible states in deterministic recovery order.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="workspace"/> is <see langword="null"/>.</exception>
    public static List<Crypto1State> LfsrRecovery64(
        uint ks2,
        uint ks3,
        Crypto1RecoveryWorkspace workspace)
    {
        if (workspace == null)
            throw new ArgumentNullException(nameof(workspace));

        var states = new List<Crypto1State>(16);
        workspace.Enter();
        try
        {
            Recover64Core(
                ks2,
                ks3,
                workspace,
                state =>
                {
                    states.Add(state);
                    return true;
                });
            return states;
        }
        finally
        {
            workspace.Exit();
        }
    }

    /// <summary>
    /// Streams states compatible with two consecutive keystream words to a
    /// visitor.
    /// </summary>
    /// <param name="ks2">The first observed keystream word.</param>
    /// <param name="ks3">The second observed keystream word.</param>
    /// <param name="workspace">The non-thread-safe workspace used for the recovery table.</param>
    /// <param name="visitor">The callback that receives each compatible state.</param>
    /// <returns>The number of visited states and whether recovery completed.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="workspace"/> or <paramref name="visitor"/> is <see langword="null"/>.
    /// </exception>
    public static RecoveryVisitResult VisitLfsrRecovery64(
        uint ks2,
        uint ks3,
        Crypto1RecoveryWorkspace workspace,
        Crypto1StateVisitor visitor)
    {
        if (workspace == null)
            throw new ArgumentNullException(nameof(workspace));
        if (visitor == null)
            throw new ArgumentNullException(nameof(visitor));

        var visited = 0;
        workspace.Enter();
        try
        {
            var completed = Recover64Core(
                ks2,
                ks3,
                workspace,
                state =>
                {
                    visited++;
                    return visitor(in state);
                });
            return new RecoveryVisitResult(visited, completed);
        }
        finally
        {
            workspace.Exit();
        }
    }

    /// <summary>
    /// Executes the shared Recovery64 producer against an arbitrary candidate sink.
    /// </summary>
    /// <param name="ks2">The first observed keystream word.</param>
    /// <param name="ks3">The second observed keystream word.</param>
    /// <param name="workspace">The already-acquired recovery workspace.</param>
    /// <param name="emit">The sink that receives completed states.</param>
    /// <returns><see langword="false"/> when the sink requests early termination.</returns>
    internal static bool Recover64Core(
        uint ks2,
        uint ks3,
        Crypto1RecoveryWorkspace workspace,
        Func<Crypto1State, bool> emit)
    {
        Span<byte> oks = stackalloc byte[32];
        Span<byte> eks = stackalloc byte[32];
        Span<byte> hi = stackalloc byte[32];
        var low = 0u;
        var win = 0u;
        var table = workspace.Table;
        table.EnsureCapacity(Crypto1RecoveryWorkspace.Recovery64TableLength);
        var tableValues = table.Array;
        var filters = RecoveryFilters.Value;
        var maximumUsed = 0;

        for (var i = 30; i >= 0; i -= 2)
        {
            oks[i >> 1] = ks2.BeBit(i);
            oks[16 + (i >> 1)] = ks3.BeBit(i);
        }
        for (var i = 31; i >= 0; i -= 2)
        {
            eks[i >> 1] = ks2.BeBit(i);
            eks[16 + (i >> 1)] = ks3.BeBit(i);
        }


        for (var i = 0xfffffu; (int)i >= 0; i--)
        {
            if (filters[(int)i] != oks[0])
                continue;

            var tail = 0;
            tableValues[tail] = i;

            for (var j = 1; tail >= 0 && j < 29; j++)
                ExtendRecovery64Table(tableValues, ref tail, oks[j], filters);
            if (tail < 0)
                continue;

            maximumUsed = Math.Max(maximumUsed, tail + 1);

            for (var j = 0; j < 19; ++j)
                low = low << 1 | Crypto1.EvenParity32(i & S1[j]);
            for (var j = 0; j < 32; ++j)
                hi[j] = Crypto1.EvenParity32(i & T1[j]);


            for (; tail >= 0; --tail)
            {
                for (var j = 0; j < 3; j++)
                {
                    tableValues[tail] <<= 1;
                    tableValues[tail] |=
                        Crypto1.EvenParity32(
                            (i & C1[j]) ^ (tableValues[tail] & C2[j]));
                    if (filters[(int)(tableValues[tail] & FilterTableMask)] !=
                        oks[29 + j])
                        goto continue2;
                }

                for (var j = 0; j < 19; j++)
                    win = win << 1 |
                          Crypto1.EvenParity32(tableValues[tail] & S2[j]);

                win ^= low;
                for (var j = 0; j < 32; ++j)
                {
                    win = win << 1 ^
                          hi[j] ^
                          Crypto1.EvenParity32(tableValues[tail] & T2[j]);
                    if (filters[(int)(win & FilterTableMask)] != eks[j])
                        goto continue2;
                }

                tableValues[tail] =
                    tableValues[tail] << 1 |
                    Crypto1.EvenParity32(Crypto1.LF_POLY_EVEN & tableValues[tail]);
                var s = new Crypto1State(
                    odd: tableValues[tail] ^
                         Crypto1.EvenParity32(Crypto1.LF_POLY_ODD & win),
                    even: win
                );
                table.MarkUsed(maximumUsed);
                if (!emit(s))
                    return false;
            continue2:;
            }
        }
        table.MarkUsed(maximumUsed);
        return true;
    }

    /// <summary>
    /// Thread-safe, lazily initialized map from 16-bit PRNG states to cycle
    /// positions.
    /// </summary>
    private static readonly Lazy<ushort[]> DistanceTable =
        new(CreateDistanceTable, isThreadSafe: true);

    /// <summary>
    /// Calculates the number of MIFARE Classic nonce PRNG steps between two
    /// valid tag nonces.
    /// </summary>
    /// <param name="from">The starting tag nonce.</param>
    /// <param name="to">The target tag nonce.</param>
    /// <returns>
    /// A distance in the 65,535-state PRNG cycle such that advancing
    /// <paramref name="from"/> by the result reaches <paramref name="to"/>.
    /// </returns>
    public static int NonceDistance(uint from, uint to)
    {
        var distance = DistanceTable.Value;
        return (65535 + distance[to >> 16] - distance[from >> 16]) % 65535;
    }

    /// <summary>
    /// Builds the 16-bit nonce PRNG cycle-position table.
    /// </summary>
    /// <returns>A table indexed by the high 16 bits of a protocol-ordered nonce.</returns>
    private static ushort[] CreateDistanceTable()
    {
        var result = new ushort[1 << 16];
        for (ushort x = 1, i = 1; i != 0; ++i)
        {
            result[(x & 0xff) << 8 | x >> 8] = i;
            x = (ushort)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
        }
        return result;
    }
}
