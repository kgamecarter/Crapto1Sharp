using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Crapto1Sharp.Test
{
    [TestClass]
    public class Crypto1Test
    {
        [TestMethod]
        public void Crypto1State()
        {
            var crypto1 = new Crypto1(0xd73A52b491AAuL);
            Assert.AreEqual(crypto1.State.Odd, 0x009E831Fu);
            Assert.AreEqual(crypto1.State.Even, 0x00F236A0u);

            crypto1 = new Crypto1(0x9D29AE25242AuL);
            Assert.AreEqual(crypto1.State.Odd, 0x0056f22Eu);
            Assert.AreEqual(crypto1.State.Even, 0x00E84C40u);

            crypto1 = new Crypto1(0x1FA3E73CAC0AuL);
            Assert.AreEqual(crypto1.State.Odd, 0x00CBB67Cu);
            Assert.AreEqual(crypto1.State.Even, 0x00E8D640u);

            crypto1 = new Crypto1(0xD1C9DB532E82uL);
            Assert.AreEqual(crypto1.State.Odd, 0x0015D8E9u);
            Assert.AreEqual(crypto1.State.Even, 0x00B9BB40u);

            crypto1 = new Crypto1(0x239186C46E88uL);
            Assert.AreEqual(crypto1.State.Odd, 0x00A191E5u);
            Assert.AreEqual(crypto1.State.Even, 0x008A4550u);
        }

        [TestMethod]
        [DataRow(0xd73A52b491AAuL)]
        [DataRow(0x9D29AE25242AuL)]
        [DataRow(0x1FA3E73CAC0AuL)]
        [DataRow(0xD1C9DB532E82uL)]
        [DataRow(0x239186C46E88uL)]
        public void Lfsr(ulong key)
        {
            var crypto1 = new Crypto1(key);
            Assert.AreEqual(crypto1.Lfsr, key);
        }
    }
}
