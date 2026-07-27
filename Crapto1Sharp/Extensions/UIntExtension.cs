using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Crapto1Sharp.Extensions;

/// <summary>
/// Provides bit, endian, and big-endian integer conversion helpers used by
/// Crypto1 operations.
/// </summary>
public static class UIntExtension
{
    /// <summary>
    /// Extracts one bit from an 8-bit value.
    /// </summary>
    /// <param name="v">The source value.</param>
    /// <param name="n">The zero-based bit index, counted from the least significant bit.</param>
    /// <returns>The selected bit as either zero or one.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte Bit(this byte v, int n)
    {
        return (byte)(v >> n & 1);
    }

    /// <summary>
    /// Extracts one bit from a 32-bit value.
    /// </summary>
    /// <param name="v">The source value.</param>
    /// <param name="n">The zero-based bit index, counted from the least significant bit.</param>
    /// <returns>The selected bit as either zero or one.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte Bit(this uint v, int n)
    {
        return (byte)(v >> n & 1);
    }

    /// <summary>
    /// Extracts one bit from a 64-bit value.
    /// </summary>
    /// <param name="v">The source value.</param>
    /// <param name="n">The zero-based bit index, counted from the least significant bit.</param>
    /// <returns>The selected bit as either zero or one.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte Bit(this ulong v, int n)
    {
        return (byte)(v >> n & 1);
    }

    /// <summary>
    /// Extracts a bit using the byte-reversed bit numbering required by
    /// Crypto1 word operations.
    /// </summary>
    /// <param name="v">The source 32-bit value.</param>
    /// <param name="n">The protocol bit index in the range used by Crypto1.</param>
    /// <returns>The selected bit as either zero or one.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte BeBit(this uint v, int n)
    {
        return v.Bit(n ^ 24);
    }

    /// <summary>
    /// Reverses the byte order of a 32-bit unsigned integer in place.
    /// </summary>
    /// <param name="x">The value whose byte order is reversed.</param>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void SwapEndian(ref this uint x)
    {
        x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
        x = x >> 16 | x << 16;
    }

    /// <summary>
    /// Reads an unsigned 32-bit integer from a big-endian array segment.
    /// </summary>
    /// <param name="a">The source byte array.</param>
    /// <param name="offset">The zero-based start offset.</param>
    /// <param name="length">The number of bytes to consume.</param>
    /// <returns>The big-endian value represented by the selected bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="a"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The selected range is outside the array.</exception>
    public static uint ToUInt32(this byte[] a, int offset = 0, int length = 4)
    {
        if (a == null)
            throw new ArgumentNullException(nameof(a));
        return ToUInt32(a.AsSpan(offset, length));
    }

    /// <summary>
    /// Reads an unsigned 32-bit integer from big-endian bytes.
    /// </summary>
    /// <param name="bytes">The bytes to read from most significant to least significant.</param>
    /// <returns>The value represented by <paramref name="bytes"/>.</returns>
    public static uint ToUInt32(this ReadOnlySpan<byte> bytes)
    {
        uint result = 0;
        for (var i = 0; i < bytes.Length; i++)
            result = result << 8 | bytes[i];
        return result;
    }

    /// <summary>
    /// Reads an unsigned 64-bit integer from a big-endian array segment.
    /// </summary>
    /// <param name="a">The source byte array.</param>
    /// <param name="offset">The zero-based start offset.</param>
    /// <param name="length">The number of bytes to consume.</param>
    /// <returns>The big-endian value represented by the selected bytes.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="a"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The selected range is outside the array.</exception>
    public static ulong ToUInt64(this byte[] a, int offset = 0, int length = 8)
    {
        if (a == null)
            throw new ArgumentNullException(nameof(a));
        return ToUInt64(a.AsSpan(offset, length));
    }

    /// <summary>
    /// Reads an unsigned 64-bit integer from big-endian bytes.
    /// </summary>
    /// <param name="bytes">The bytes to read from most significant to least significant.</param>
    /// <returns>The value represented by <paramref name="bytes"/>.</returns>
    public static ulong ToUInt64(this ReadOnlySpan<byte> bytes)
    {
        ulong result = 0;
        for (var i = 0; i < bytes.Length; i++)
            result = result << 8 | bytes[i];
        return result;
    }

    /// <summary>
    /// Allocates and fills a big-endian byte representation of a 32-bit value.
    /// </summary>
    /// <param name="v">The value to encode.</param>
    /// <param name="length">The output array length.</param>
    /// <returns>A new array containing the big-endian representation.</returns>
    /// <exception cref="OverflowException"><paramref name="length"/> is negative.</exception>
    public static byte[] GetBytes(this uint v, int length = 4)
    {
        var result = new byte[length];
        v.WriteBytes(result);
        return result;
    }

    /// <summary>
    /// Writes a 32-bit value to a destination span in big-endian byte order.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <param name="destination">
    /// The destination. Longer spans are zero-padded; shorter spans receive the
    /// least-significant bytes.
    /// </param>
    public static void WriteBytes(this uint value, Span<byte> destination)
    {
        for (var i = destination.Length - 1; i >= 0; i--)
        {
            destination[i] = (byte)value;
            value >>= 8;
        }
    }

    /// <summary>
    /// Allocates and fills a big-endian byte representation of a 64-bit value.
    /// </summary>
    /// <param name="v">The value to encode.</param>
    /// <param name="length">The output array length.</param>
    /// <returns>A new array containing the big-endian representation.</returns>
    /// <exception cref="OverflowException"><paramref name="length"/> is negative.</exception>
    public static byte[] GetBytes(this ulong v, int length = 8)
    {
        var result = new byte[length];
        v.WriteBytes(result);
        return result;
    }

    /// <summary>
    /// Writes a 64-bit value to a destination span in big-endian byte order.
    /// </summary>
    /// <param name="value">The value to encode.</param>
    /// <param name="destination">
    /// The destination. Longer spans are zero-padded; shorter spans receive the
    /// least-significant bytes.
    /// </param>
    public static void WriteBytes(this ulong value, Span<byte> destination)
    {
        for (var i = destination.Length - 1; i >= 0; i--)
        {
            destination[i] = (byte)value;
            value >>= 8;
        }
    }
}
