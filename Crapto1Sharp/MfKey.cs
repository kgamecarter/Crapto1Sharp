using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp
{
    public static class MfKey
    {
        /// <summary>
        /// recover key from 2 different reader responses on same tag challenge
        /// </summary>
        /// <param name="uid"></param>
        /// <param name="nt"></param>
        /// <param name="nr0"></param>
        /// <param name="ar0"></param>
        /// <param name="nr1"></param>
        /// <param name="ar1"></param>
        /// <returns>return ulong.MaxValue if key not found</returns>
        public static ulong MfKey32(uint uid, uint nt, uint nr0, uint ar0, uint nr1, uint ar1)
        {
            var p64 = Crypto1.PrngSuccessor(nt, 64);
            byte counter = 0;
            var list = Crapto1.LfsrRecovery32(ar0 ^ p64, 0);
            var crapto1 = new Crapto1();
            var outKey = 0uL;
            foreach (var s in list)
            {
                crapto1.State = s;
                crapto1.LfsrRollbackWord();
                crapto1.LfsrRollbackWord(nr0, true);
                crapto1.LfsrRollbackWord(uid ^ nt);
                var key = crapto1.Lfsr;
                crapto1.Crypto1Word(uid ^ nt);
                crapto1.Crypto1Word(nr1, true);
                if (ar1 == (crapto1.Crypto1Word() ^ p64))
                {
                    outKey = key;
                    counter++;
                    if (counter == 20)
                        break;
                }
            }
            return counter == 1 ? outKey : ulong.MaxValue;
        }

        /// <summary>
        /// recover key from reader response and tag response of one authentication sequence
        /// </summary>
        /// <param name="uid"></param>
        /// <param name="nt"></param>
        /// <param name="nr"></param>
        /// <param name="ar"></param>
        /// <param name="at"></param>
        /// <returns></returns>
        public static ulong MfKey64(uint uid, uint nt, uint nr, uint ar, uint at)
        {
            // Extract the keystream from the messages
            var ks2 = ar ^ Crypto1.PrngSuccessor(nt, 64); // keystream used to encrypt reader response
            var ks3 = at ^ Crypto1.PrngSuccessor(nt, 96); // keystream used to encrypt tag response
            var revstate = Crapto1.LfsrRecovery64(ks2, ks3)[0];
            var crapto1 = new Crapto1(revstate);
            crapto1.LfsrRollbackWord();
            crapto1.LfsrRollbackWord();
            crapto1.LfsrRollbackWord(nr, true);
            crapto1.LfsrRollbackWord(uid ^ nt);
            return crapto1.Lfsr;
        }
    }
}
