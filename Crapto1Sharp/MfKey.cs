using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp
{
    public static class MfKey
    {
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
