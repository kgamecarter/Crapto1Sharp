using Crapto1Sharp.Extensions;
using System;
using System.Collections.Generic;
#if NET45
using Crapto1Sharp.Memory;
#endif

namespace Crapto1Sharp
{
    public class Crapto1 : Crypto1
    {
        public Crapto1(Crypto1State state) : base(state)
        { }

        /// <summary>
        /// Rollback the shift register in order to get previous states
        /// </summary>
        /// <param name="in"></param>
        /// <param name="isEncrypted"></param>
        /// <returns></returns>
        public byte LfsrRollbackBit(byte @in = 0, bool isEncrypted = false)
        {
	        uint @out;
	        byte ret;

	        _state.Odd &= 0xffffff;
            var t = _state.Odd;
            _state.Odd = _state.Even;
            _state.Even = t;

	        @out = _state.Even & 1;
	        @out ^= LF_POLY_EVEN & (_state.Even >>= 1);
	        @out ^= LF_POLY_ODD & _state.Odd;
	        @out ^= @in != 0 ? 1u : 0u;
	        @out ^= (ret = Filter(_state.Odd)) & (isEncrypted ? 1u : 0u);

            _state.Even |= (uint)EvenParity32(@out) << 23;
	        return ret;
        }

        public byte LfsrRollbackByte(byte @in = 0, bool isEncrypted = false)
        {
            byte ret = 0;

            for (var i = 7; i >= 0; --i)
                ret |= (byte)(LfsrRollbackBit(@in.Bit(i), isEncrypted) << i);

            return ret;
        }

        public uint LfsrRollbackWord(uint @in = 0, bool isEncrypted = false)
        {
            uint ret = 0;

            for (var i = 31; i >= 0; --i)
                ret |= (uint)LfsrRollbackBit(@in.BeBit(i), isEncrypted) << (i ^ 24);

            return ret;
        }

        /// <summary>
        /// helper, calculates the partial linear feedback contributions and puts in MSB
        /// </summary>
        /// <param name="item"></param>
        /// <param name="mask1"></param>
        /// <param name="mask2"></param>
        private static void UpdateContribution(ref uint item, uint mask1, uint mask2)
        {
            uint p = item >> 25;

            p = p << 1 | EvenParity32(item & mask1);
            p = p << 1 | EvenParity32(item & mask2);
            item = p << 24 | (item & 0xffffff);
        }

        /// <summary>
        /// using a bit of the keystream extend the table of possible lfsr states
        /// </summary>
        /// <param name="tbl"></param>
        /// <param name="end"></param>
        /// <param name="bit"></param>
        /// <param name="m1"></param>
        /// <param name="m2"></param>
        /// <param name="in"></param>
        private static void ExtendTable(Span<uint> tbl, ref int end, uint bit, uint m1, uint m2, uint @in)
        {
            @in <<= 24;
            var i = 0;
            for (tbl[i] <<= 1; i <= end; tbl[++i] <<= 1)
                if ((Filter(tbl[i]) ^ Filter(tbl[i] | 1)) != 0)
                {
                    tbl[i] |= Filter(tbl[i]) ^ bit;
                    UpdateContribution(ref tbl[i], m1, m2);
                    tbl[i] ^= @in;
                }
                else if (Filter(tbl[i]) == bit)
                {
                    tbl[++end] = tbl[1];
                    tbl[1] = tbl[0] | 1;
                    UpdateContribution(ref tbl[i], m1, m2);
                    tbl[i++] ^= @in;
                    UpdateContribution(ref tbl[i], m1, m2);
                    tbl[i] ^= @in;
                }
                else
                    tbl[i--] = tbl[end--];
        }

        /// <summary>
        /// using a bit of the keystream extend the table of possible lfsr states
        /// </summary>
        /// <param name="tbl"></param>
        /// <param name="end"></param>
        /// <param name="bit"></param>
        private static void ExtendTableSimple(uint[] tbl, ref int end, uint bit)
        {
            var i = 0;
            for (tbl[i] <<= 1; i <= end; tbl[++i] <<= 1)
            {
                if ((Filter(tbl[i]) ^ Filter(tbl[i] | 1)) != 0)
                {   // replace
                    tbl[i] |= Filter(tbl[i]) ^ bit;
                }
                else if (Filter(tbl[i]) == bit)
                {       // insert
                    tbl[++end] = tbl[++i];
                    tbl[i] = tbl[i - 1] | 1;
                }
                else
                {                               // drop
                    tbl[i--] = tbl[end--];
                }
            }
        }

        /// <summary>
        /// recursively narrow down the search space, 4 bits of keystream at a time
        /// </summary>
        /// <param name="odd"></param>
        /// <param name="oddTail"></param>
        /// <param name="oks"></param>
        /// <param name="even"></param>
        /// <param name="evenTail"></param>
        /// <param name="eks"></param>
        /// <param name="rem"></param>
        /// <param name="sl"></param>
        /// <param name="@in"></param>
        private static void Recover(Span<uint> odd, int oddTail, uint oks, Span<uint> even, int evenTail, uint eks, int rem, List<Crypto1State> sl, uint @in)
        {
            var o = 0;
            var e = 0;

            if (rem == -1)
            {
                for (e = 0; e <= evenTail; e++)
                {
                    even[e] = even[e] << 1 ^ EvenParity32(even[e] & LF_POLY_EVEN) ^ ((@in & 4) != 0 ? 1u : 0u);
                    for (o = 0; o <= oddTail; o++)
                    {
                        sl.Add(new Crypto1State()
                        {
                            Even = odd[o],
                            Odd = even[e] ^ EvenParity32(odd[o] & LF_POLY_ODD)
                        });
                    }
                }
                return;
            }

	        for (var i = 0; i < 4 && rem-- != 0; i++) {
		        oks >>= 1;
		        eks >>= 1;
		        @in >>= 2;
		        ExtendTable(odd, ref oddTail, oks & 1, LF_POLY_EVEN << 1 | 1, LF_POLY_ODD << 1, 0u);
		        if (0 > oddTail)
			        return;

                ExtendTable(even, ref evenTail, eks & 1, LF_POLY_ODD, LF_POLY_EVEN << 1 | 1, @in & 3);
		        if (0 > evenTail)
			        return;
	        }

            odd.Slice(0, oddTail + 1).Sort();
            even.Slice(0, evenTail + 1).Sort();

            while (oddTail >= 0 && evenTail >= 0)
                if (((odd[oddTail] ^ even[evenTail]) >> 24) == 0)
                {
                    oddTail = odd.Slice(0, o = oddTail).BinarySearch(odd[oddTail] & 0xff000000);
                    evenTail = even.Slice(0, e = evenTail).BinarySearch(even[evenTail] & 0xff000000);
                    Recover(odd.Slice(oddTail--), o, oks, even.Slice(evenTail--), e, eks, rem, sl, @in);
                }
                else if (odd[oddTail] > even[evenTail])
                    oddTail = odd.Slice(0, oddTail + 1).BinarySearch(odd[oddTail] & 0xff000000) - 1;
                else
                    evenTail = even.Slice(0, evenTail + 1).BinarySearch(even[evenTail] & 0xff000000) - 1;
        }

        public static List<Crypto1State> LfsrRecovery32(uint ks2, uint @in)
        {
            var oks = 0u;
            var eks = 0u;

            for (var i = 31; i >= 0; i -= 2)
                oks = oks << 1 | ks2.BeBit(i);
            for (var i = 30; i >= 0; i -= 2)
                eks = eks << 1 | ks2.BeBit(i);

            var odd = new uint[sizeof(uint) << 21];
            var even = new uint[sizeof(uint) << 21];
            var statelist = new List<Crypto1State>();
            var oddTail = 0;
            var evenTail = 0;

            for (var i = 1u << 20; (int)i >= 0; --i)
            {
                if (Filter(i) == (oks & 1))
                    odd[++oddTail] = i;
                if (Filter(i) == (eks & 1))
                    even[++evenTail] = i;
            }

            for (var i = 0; i < 4; i++)
            {
                ExtendTableSimple(odd, ref oddTail, (oks >>= 1) & 1);
                ExtendTableSimple(even, ref evenTail, (eks >>= 1) & 1);
            }

            @in = (@in >> 16 & 0xff) | (@in << 16) | (@in & 0xff00);
            Recover(odd, oddTail, oks, even, evenTail, eks, 11, statelist, @in << 1);

            return statelist;
        }

        static readonly uint[] S1 = {
            0x62141, 0x310A0, 0x18850, 0x0C428, 0x06214, 0x0310A,
            0x85E30, 0xC69AD, 0x634D6, 0xB5CDE, 0xDE8DA, 0x6F46D,
            0xB3C83, 0x59E41, 0xA8995,  0xD027F, 0x6813F, 0x3409F, 0x9E6FA };

        static readonly uint[] S2 = {
            0x3A557B00, 0x5D2ABD80, 0x2E955EC0, 0x174AAF60, 0x0BA557B0,
            0x05D2ABD8, 0x0449DE68, 0x048464B0, 0x42423258, 0x278192A8,
            0x156042D0, 0x0AB02168, 0x43F89B30, 0x61FC4D98, 0x765EAD48,
            0x7D8FDD20, 0x7EC7EE90, 0x7F63F748, 0x79117020 };
        static readonly uint[] T1 = {
            0x4F37D, 0x279BE, 0x97A6A, 0x4BD35, 0x25E9A, 0x12F4D, 0x097A6, 0x80D66,
            0xC4006, 0x62003, 0xB56B4, 0x5AB5A, 0xA9318, 0xD0F39, 0x6879C, 0xB057B,
            0x582BD, 0x2C15E, 0x160AF, 0x8F6E2, 0xC3DC4, 0xE5857, 0x72C2B, 0x39615,
            0x98DBF, 0xC806A, 0xE0680, 0x70340, 0x381A0, 0x98665, 0x4C332, 0xA272C };
        static readonly uint[] T2 = {
            0x3C88B810, 0x5E445C08, 0x2982A580, 0x14C152C0, 0x4A60A960,
            0x253054B0, 0x52982A58, 0x2FEC9EA8, 0x1156C4D0, 0x08AB6268,
            0x42F53AB0, 0x217A9D58, 0x161DC528, 0x0DAE6910, 0x46D73488,
            0x25CB11C0, 0x52E588E0, 0x6972C470, 0x34B96238, 0x5CFC3A98,
            0x28DE96C8, 0x12CFC0E0, 0x4967E070, 0x64B3F038, 0x74F97398,
            0x7CDC3248, 0x38CE92A0, 0x1C674950, 0x0E33A4A8, 0x01B959D0,
            0x40DCACE8, 0x26CEDDF0 };

        static readonly uint[] C1 = { 0x846B5, 0x4235A, 0x211AD };
        static readonly uint[] C2 = { 0x1A822E0, 0x21A822E0, 0x21A822E0 };

        /// <summary>
        /// Reverse 64 bits of keystream into possible cipher states
        /// Variation mentioned in the paper. Somewhat optimized version
        /// </summary>
        /// <param name="ks2"></param>
        /// <param name="ks3"></param>
        /// <returns></returns>
        public static List<Crypto1State> LfsrRecovery64(uint ks2, uint ks3)
        {
            var oks = new byte[32];
            var eks = new byte[32];
            var hi = new byte[32];
            var low = 0u;
            var win = 0u;
            var table = new uint[1 << 16];
            var statelist = new List<Crypto1State>();

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
                if (Filter(i) != oks[0])
                    continue;

                var tail = 0;
                table[tail] = i;

                for (var j = 1; tail >= 0 && j < 29; j++)
                    ExtendTableSimple(table, ref tail, oks[j]);
                if (tail < 0)
                    continue;

                for (var j = 0; j < 19; ++j)
                    low = low << 1 | EvenParity32(i & S1[j]);
                for (var j = 0; j < 32; ++j)
                    hi[j] = EvenParity32(i & T1[j]);


                for (; tail >= 0; --tail)
                {
                    for (var j = 0; j < 3; j++)
                    {
                        table[tail] = table[tail] << 1;
                        table[tail] |= EvenParity32((i & C1[j]) ^ (table[tail] & C2[j]));
                        if (Filter(table[tail]) != oks[29 + j])
                            goto continue2;
                    }

                    for (var j = 0; j < 19; j++)
                        win = win << 1 | EvenParity32(table[tail] & S2[j]);

                    win ^= low;
                    for (var j = 0; j < 32; ++j)
                    {
                        win = win << 1 ^ hi[j] ^ EvenParity32(table[tail] & T2[j]);
                        if (Filter(win) != eks[j])
                            goto continue2;
                    }

                    table[tail] = table[tail] << 1 | EvenParity32(LF_POLY_EVEN & table[tail]);
                    var s = new Crypto1State()
                    {
                        Odd = table[tail] ^ EvenParity32(LF_POLY_ODD & win),
                        Even = win
                    };
                    statelist.Add(s);
                continue2:;
                }
            }
            return statelist;
        }
        
        private static ushort[] dist;

        /// <summary>
        /// x,y valid tag nonces, then prng_successor(x, nonce_distance(x, y)) = y
        /// </summary>
        /// <param name="from"></param>
        /// <param name="to"></param>
        /// <returns></returns>
        public static int NonceDistance(uint from, uint to)
        {
            if (dist == null)
            {
                dist = new ushort[2 << 16];
                for (ushort x = 1, i = 1; i != 0; ++i)
                {
                    dist[(x & 0xff) << 8 | x >> 8] = i;
                    x = (ushort)(x >> 1 | (x ^ x >> 2 ^ x >> 3 ^ x >> 5) << 15);
                }
            }
            return (65535 + dist[to >> 16] - dist[from >> 16]) % 65535;
        }
    }
}
