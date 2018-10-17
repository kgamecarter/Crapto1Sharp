using Crapto1Sharp.Extensions;

namespace Crapto1Sharp
{
    public class Crypto1
    {
        public const uint LF_POLY_ODD = 0x29CE5C;
        public const uint LF_POLY_EVEN = 0x870804;

        protected Crypto1State _state;

        public Crypto1State State
        {
            get
            { return _state; }
            set
            { _state = value; }
        }

        public ulong Lfsr
        {
            get
            {
                ulong lfsr = 0L;
                for (int i = 23; i >= 0; --i)
                {
                    lfsr = lfsr << 1 | _state.Odd.Bit(i ^ 3);
                    lfsr = lfsr << 1 | _state.Even.Bit(i ^ 3);
                }
                return lfsr;
            }
        }

        public Crypto1()
        { }

        public Crypto1(ulong key)
        {
            for (int i = 47; i > 0; i -= 2)
            {
                _state.Odd = _state.Odd << 1 | key.Bit((i - 1) ^ 7);
                _state.Even = _state.Even << 1 | key.Bit(i ^ 7);
            }
        }

        public byte Crypto1Bit(byte _in = 0, bool isEncrypted = false)
        {
            uint feedin;
            byte ret = Filter(_state.Odd);

            feedin = ret & (isEncrypted ? 1u : 0u);
            feedin ^= _in != 0 ? 1u : 0u;
            feedin ^= LF_POLY_ODD & _state.Odd;
            feedin ^= LF_POLY_EVEN & _state.Even;
            _state.Even = _state.Even << 1 | EvenParity32(feedin);

            uint x = _state.Odd;
            _state.Odd = _state.Even;
            _state.Even = x;

            return ret;
        }

        public byte Crypto1Byte(byte _in = 0, bool isEncrypted = false)
        {
            byte ret = 0;

            for (int i = 0; i < 8; ++i)
                ret |= (byte)(Crypto1Bit(_in.Bit(i), isEncrypted) << i);

            return ret;
        }

        public uint Crypto1Word(uint _in = 0, bool isEncrypted = false)
        {
            uint ret = 0;

            for (int i = 0; i < 32; ++i)
                ret |= (uint)Crypto1Bit(_in.BeBit(i), isEncrypted) << (i ^ 24);

            return ret;
        }

        public byte PeekCrypto1Bit()
        {
            return Filter(_state.Odd);
        }

        public void Encrypt(byte[] data, byte[] parirty, int offset, int length, bool isIn = false)
        {
            int end = offset + length;
            for (int i = offset; i < end; i++)
            {
                // compute Parity
                parirty[i] = OddParity8(data[i]);
                // encrypt data
                data[i] ^= Crypto1Byte(isIn ? data[i] : (byte)0);
                // encrypt Parity
                parirty[i] ^= PeekCrypto1Bit();
            }
        }
        
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

        static readonly byte[] OddByteParity = new byte[256] {
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
        };

        public static byte OddParity8(byte x) => OddByteParity[x];

        public static byte EvenParity8(byte x) => (byte)(OddByteParity[x] ^ 1);

        public static byte EvenParity32(uint x)
        {
            x ^= x >> 16;
            x ^= x >> 8;
            return EvenParity8((byte)x);
        }

        public static uint PrngSuccessor(uint x, int n)
        {
            x = x.SwapEndian();
            while (n-- > 0)
                x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
            return x.SwapEndian();
        }
    }
}
