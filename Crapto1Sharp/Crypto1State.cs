using Crapto1Sharp.Extensions;
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Crapto1Sharp;

/// <summary>
/// Represents the 48-bit odd/even linear-feedback shift register state used by
/// the Crypto1 cipher.
/// </summary>
public struct Crypto1State
{
    /// <summary>
    /// Gets or sets the 24-bit odd half of the Crypto1 shift register.
    /// </summary>
    public uint Odd;

    /// <summary>
    /// Gets or sets the 24-bit even half of the Crypto1 shift register.
    /// </summary>
    public uint Even;

    /// <summary>
    /// Initializes a state from its odd and even register halves.
    /// </summary>
    /// <param name="odd">The odd 24-bit register half.</param>
    /// <param name="even">The even 24-bit register half.</param>
    public Crypto1State(uint odd, uint even)
    {
        Odd = odd;
        Even = even;
    }

    /// <summary>
    /// Initializes a state from a 48-bit Crypto1 key.
    /// </summary>
    /// <param name="key">
    /// The key to interleave into the odd and even register halves. Bits above
    /// bit 47 are ignored.
    /// </param>
    public Crypto1State(ulong key)
    {
        Odd = 0;
        Even = 0;
        for (int i = 47; i > 0; i -= 2)
        {
            Odd = Odd << 1 | key.Bit((i - 1) ^ 7);
            Even = Even << 1 | key.Bit(i ^ 7);
        }
    }

    /// <summary>
    /// Gets the current odd/even register halves combined as a 48-bit Crypto1
    /// LFSR value.
    /// </summary>
    public ulong Lfsr
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            ulong lfsr = 0L;
            for (int i = 23; i >= 0; --i)
            {
                lfsr = lfsr << 1 | Odd.Bit(i ^ 3);
                lfsr = lfsr << 1 | Even.Bit(i ^ 3);
            }
            return lfsr;
        }
    }

    /// <summary>
    /// Gets the current Crypto1 filter output bit without advancing the state.
    /// </summary>
    public byte PeekCrypto1Bit
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => Crypto1.Filter(Odd);
    }
}
