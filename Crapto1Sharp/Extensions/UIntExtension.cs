using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Extensions
{
    public static class UIntExtension
    {
        public static byte Bit(this byte v, int n)
        {
            return (byte)(v >> n & 1);
        }

        public static byte Bit(this uint v, int n)
        {
            return (byte)(v >> n & 1);
        }

        public static byte Bit(this ulong v, int n)
        {
            return (byte)(v >> n & 1);
        }

        public static byte BeBit(this uint v, int n)
        {
            return v.Bit(n ^ 24);
        }

        public static uint SwapEndian(this uint x)
        {
            x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
            x = x >> 16 | x << 16;
            return x;
        }
    }
}
