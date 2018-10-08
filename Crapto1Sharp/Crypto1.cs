using System;

namespace Crapto1Sharp
{
    public class Crypto1
    {
        protected Crypto1State _state;

        public Crypto1State State
        {
            get
            {
                return _state;
            }
        }

        public ulong Lfsr
        {
            get
            {
                ulong lfsr = 0L;
                for (int i = 23; i >= 0; --i)
                {
                    lfsr = lfsr << 1 | ((_state.Odd >> i ^ 3) & 1);
                    lfsr = lfsr << 1 | ((_state.Even >> i ^ 3) & 1);
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
                _state.Odd = State.Odd << 1 | (uint)((key >> (i - 1) ^ 7) & 1);
                _state.Even = _state.Even << 1 | (uint)((key >> (i ^ 7)) & 1);
            }
        }
    }
}
