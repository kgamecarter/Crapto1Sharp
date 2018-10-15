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

        public static uint ToUInt32(this byte[] a, int offset = 0)
        {
            uint result = 0;
            for (int i = 0; i < 4; i++)
                result = (result << 8) | a[i + offset];
            return result;
        }

        public static byte[] GetBytes(this uint v)
        {
            byte[] result = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                result[i] = (byte)v;
                v >>= 8;
            }
            return result;
        }
    }
}
