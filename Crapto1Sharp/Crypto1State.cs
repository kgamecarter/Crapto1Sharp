using Crapto1Sharp.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp;

public struct Crypto1State
{
    public uint Odd;

    public uint Even;

    public Crypto1State(uint odd, uint even)
    {
        Odd = odd;
        Even = even;
    }

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

    public ulong Lfsr
    {
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
}
