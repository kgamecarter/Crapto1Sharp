using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crapto1Sharp.Test;

[TestClass]
public class Crypto1Test
{
    [TestMethod]
    [DataRow(0xd73A52b491AAuL, 0x009E831Fu, 0x00F236A0u)]
    [DataRow(0x9D29AE25242AuL, 0x0056f22Eu, 0x00E84C40u)]
    [DataRow(0x1FA3E73CAC0AuL, 0x00CBB67Cu, 0x00E8D640u)]
    [DataRow(0xD1C9DB532E82uL, 0x0015D8E9u, 0x00B9BB40u)]
    [DataRow(0x239186C46E88uL, 0x00A191E5u, 0x008A4550u)]
    public void Crypto1State(ulong key, uint odd, uint even)
    {
        var state = new Crypto1State(key);
        Assert.AreEqual(odd, state.Odd);
        Assert.AreEqual(even, state.Even);
    }

    [TestMethod]
    [DataRow(0xd73A52b491AAuL)]
    [DataRow(0x9D29AE25242AuL)]
    [DataRow(0x1FA3E73CAC0AuL)]
    [DataRow(0xD1C9DB532E82uL)]
    [DataRow(0x239186C46E88uL)]
    public void Lfsr(ulong key)
    {
        var state = new Crypto1State(key);
        Assert.AreEqual(key, state.Lfsr);
    }

    [TestMethod]
    [DataRow(0xd73A52b491AAuL)]
    [DataRow(0x9D29AE25242AuL)]
    [DataRow(0x1FA3E73CAC0AuL)]
    [DataRow(0xD1C9DB532E82uL)]
    [DataRow(0x239186C46E88uL)]
    public void PeekCrypto1Bit(ulong key)
    {
        var state = new Crypto1State(key);
        Assert.AreEqual(Crypto1.Filter(state.Odd), state.PeekCrypto1Bit());
    }

    [TestMethod]
    public void OddParity8()
    {
        for (int i = 0; i <= 0xff; i++)
        {
            var count = 1;
            var v = i;
            while (v > 0)
            {
                count += v & 1;
                v >>= 1;
            }
            Assert.AreEqual((byte)(count % 2), Crypto1.OddParity8((byte)i));
        }
    }

    [TestMethod]
    public void EvenParity8()
    {
        for (int i = 0; i <= 0xff; i++)
        {
            var count = 0;
            var v = i;
            while (v > 0)
            {
                count += v & 1;
                v >>= 1;
            }
            Assert.AreEqual((byte)(count % 2), Crypto1.EvenParity8((byte)i));
        }
    }
}
