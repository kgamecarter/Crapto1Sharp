using Crapto1Sharp.Extensions;
using System;
using System.Runtime.CompilerServices;
#if NET10
using System.Numerics;
#endif

namespace Crapto1Sharp;

/// <summary>
/// Provides forward Crypto1 cipher operations, filter/parity helpers, and the
/// MIFARE Classic nonce PRNG successor function.
/// </summary>
public static class Crypto1
{
    /// <summary>
    /// The feedback polynomial mask applied to the odd LFSR half.
    /// </summary>
    public const uint LF_POLY_ODD = 0x29CE5C;

    /// <summary>
    /// The feedback polynomial mask applied to the even LFSR half.
    /// </summary>
    public const uint LF_POLY_EVEN = 0x870804;

    /// <summary>
    /// Advances a Crypto1 state by one bit and returns the filter output bit.
    /// </summary>
    /// <param name="_state">The state to advance.</param>
    /// <param name="in">The input bit.</param>
    /// <param name="isEncrypted">
    /// <see langword="true"/> to feed the filter output back as encrypted input;
    /// otherwise, <see langword="false"/>.
    /// </param>
    /// <returns>The filter output bit produced before advancing the state.</returns>
    public static byte Crypto1Bit(this ref Crypto1State _state, byte @in = 0, bool isEncrypted = false)
    {
        uint feedin;
        byte ret = Filter(_state.Odd);

        feedin = ret & (isEncrypted ? 1u : 0u);
        feedin ^= @in != 0 ? 1u : 0u;
        feedin ^= LF_POLY_ODD & _state.Odd;
        feedin ^= LF_POLY_EVEN & _state.Even;
        _state.Even = _state.Even << 1 | EvenParity32(feedin);

        uint x = _state.Odd;
        _state.Odd = _state.Even;
        _state.Even = x;

        return ret;
    }

    /// <summary>
    /// Advances a Crypto1 state by eight bits and returns one keystream byte.
    /// </summary>
    /// <param name="_state">The state to advance.</param>
    /// <param name="in">The input byte.</param>
    /// <param name="isEncrypted">
    /// <see langword="true"/> when <paramref name="in"/> is encrypted input.
    /// </param>
    /// <returns>The generated keystream byte.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte Crypto1Byte(this ref Crypto1State _state, byte @in = 0, bool isEncrypted = false)
    {
        byte ret = 0;

        for (int i = 0; i < 8; ++i)
            ret |= (byte)(_state.Crypto1Bit(@in.Bit(i), isEncrypted) << i);

        return ret;
    }

    /// <summary>
    /// Advances a Crypto1 state by 32 bits and returns one protocol-ordered
    /// keystream word.
    /// </summary>
    /// <param name="_state">The state to advance.</param>
    /// <param name="in">The 32-bit input word.</param>
    /// <param name="isEncrypted">
    /// <see langword="true"/> when <paramref name="in"/> is encrypted input.
    /// </param>
    /// <returns>The generated keystream word.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Crypto1Word(this ref Crypto1State _state, uint @in = 0, bool isEncrypted = false)
    {
        uint ret = 0;

        for (int i = 0; i < 32; ++i)
            ret |= (uint)_state.Crypto1Bit(@in.BeBit(i), isEncrypted) << (i ^ 24);

        return ret;
    }

    /// <summary>
    /// Encrypts an array segment and writes its encrypted parity bits.
    /// </summary>
    /// <param name="_state">The state to advance while encrypting.</param>
    /// <param name="data">The data array to update in place.</param>
    /// <param name="parirty">The array that receives one parity bit per data byte.</param>
    /// <param name="offset">The zero-based start offset in both arrays.</param>
    /// <param name="length">The number of bytes to process.</param>
    /// <param name="isIn">Whether each plaintext byte is fed into the cipher state.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="data"/> or <paramref name="parirty"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">A selected array range is invalid.</exception>
    public static void Encrypt(this ref Crypto1State _state, byte[] data, byte[] parirty, int offset, int length, bool isIn = false)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));
        if (parirty == null)
            throw new ArgumentNullException(nameof(parirty));
        _state.Encrypt(
            data.AsSpan(offset, length),
            parirty.AsSpan(offset, length),
            isIn);
    }

    /// <summary>
    /// Encrypts data in place and writes one encrypted parity bit for each byte.
    /// </summary>
    /// <param name="_state">The state to advance while encrypting.</param>
    /// <param name="data">The data to update in place.</param>
    /// <param name="parity">The destination for encrypted parity bits.</param>
    /// <param name="isIn">Whether each plaintext byte is fed into the cipher state.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="parity"/> is shorter than <paramref name="data"/>.
    /// </exception>
    public static void Encrypt(
        this ref Crypto1State _state,
        Span<byte> data,
        Span<byte> parity,
        bool isIn = false)
    {
        if (parity.Length < data.Length)
            throw new ArgumentException(
                "The parity span must be at least as long as the data span.",
                nameof(parity));

        for (var i = 0; i < data.Length; i++)
        {
            // compute Parity
            parity[i] = OddParity8(data[i]);
            // encrypt data
            data[i] ^= _state.Crypto1Byte(isIn ? data[i] : (byte)0);
            // encrypt Parity
            parity[i] ^= _state.PeekCrypto1Bit;
        }
    }

    /// <summary>
    /// Evaluates the nonlinear Crypto1 filter function for the low 20 bits of a
    /// candidate LFSR half.
    /// </summary>
    /// <param name="x">The candidate LFSR value.</param>
    /// <returns>The filter output bit.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte Filter(uint x)
    {
        uint f;
        f = 0xf22c0u >> (int)(x & 0xf) & 16u;
        f |= 0x6c9c0u >> (int)(x >> 4 & 0xf) & 8u;
        f |= 0x3c8b0u >> (int)(x >> 8 & 0xf) & 4u;
        f |= 0x1e458u >> (int)(x >> 12 & 0xf) & 2u;
        f |= 0x0d938u >> (int)(x >> 16 & 0xf) & 1u;
        return (byte)(0xEC57E80A >> (int)f & 1);
    }

    /// <summary>
    /// Lookup table containing the odd parity bit for every possible byte.
    /// </summary>
    static readonly byte[] OddByteParity = [
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
        1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
    ];

    /// <summary>
    /// Calculates the odd parity bit required for an 8-bit value.
    /// </summary>
    /// <param name="x">The value whose parity is calculated.</param>
    /// <returns>The bit that makes the total number of set bits odd.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte OddParity8(byte x) => OddByteParity[x];

    /// <summary>
    /// Calculates the parity of an 8-bit value.
    /// </summary>
    /// <param name="x">The value whose parity is calculated.</param>
    /// <returns>One when <paramref name="x"/> has odd parity; otherwise, zero.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte EvenParity8(byte x) => (byte)(OddByteParity[x] ^ 1);

    /// <summary>
    /// Calculates the parity of a 32-bit value.
    /// </summary>
    /// <param name="x">The value whose parity is calculated.</param>
    /// <returns>One when <paramref name="x"/> has odd parity; otherwise, zero.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte EvenParity32(uint x)
    {
#if NET10
        return (byte)(BitOperations.PopCount(x) & 1);
#else
        x ^= x >> 16;
        x ^= x >> 8;
        return EvenParity8((byte)x);
#endif
    }

    /// <summary>
    /// Advances the MIFARE Classic 32-bit nonce PRNG by a specified number of
    /// steps.
    /// </summary>
    /// <param name="x">The starting PRNG value in protocol byte order.</param>
    /// <param name="n">The number of successor steps to apply.</param>
    /// <returns>The successor value in protocol byte order.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint PrngSuccessor(uint x, int n)
    {
        x.SwapEndian();
        while (n-- > 0)
            x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
        x.SwapEndian();
        return x;
    }
}
