using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Crapto1Sharp.Extensions
{
    public static class UIntExtension
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte Bit(this byte v, int n)
        {
            return (byte)(v >> n & 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte Bit(this uint v, int n)
        {
            return (byte)(v >> n & 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte Bit(this ulong v, int n)
        {
            return (byte)(v >> n & 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte BeBit(this uint v, int n)
        {
            return v.Bit(n ^ 24);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void SwapEndian(ref this uint x)
        {
            x = (x >> 8 & 0xff00ff) | (x & 0xff00ff) << 8;
            x = x >> 16 | x << 16;
        }

        public static uint ToUInt32(this byte[] a, int offset = 0, int length = 4)
        {
            uint result = 0;
            for (int i = 0; i < length; i++)
                result = (result << 8) | a[i + offset];
            return result;
        }

        public static ulong ToUInt64(this byte[] a, int offset = 0, int length = 8)
        {
            ulong result = 0;
            for (int i = 0; i < length; i++)
                result = (result << 8) | a[i + offset];
            return result;
        }

        public static byte[] GetBytes(this uint v, int length = 4)
        {
            byte[] result = new byte[length];
            for (int i = length - 1; i >= 0; i--)
            {
                result[i] = (byte)v;
                v >>= 8;
            }
            return result;
        }

        public static byte[] GetBytes(this ulong v, int length = 8)
        {
            byte[] result = new byte[length];
            for (int i = length - 1; i >= 0; i--)
            {
                result[i] = (byte)v;
                v >>= 8;
            }
            return result;
        }
    }
}
