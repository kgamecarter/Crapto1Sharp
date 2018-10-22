using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Test
{
    [TestClass]
    public class MfKeyTest
    {
        [TestMethod]
        [DataRow(0x866285B1u, 0xB830049Bu, 0x8D369B4Du, 0x9248314Au, 0x9280E203u, 0xA0A1A2A3A4A5uL)]
        [DataRow(0x5C688618u, 0xE9FAD974u, 0xB37A0666u, 0xEE09C7C2u, 0x1F23E820u, 0xCCC6CCC69720uL)]
        public void MfKey64(uint uid, uint nt, uint nr, uint ar, uint at, ulong expectedKey)
        {
            var key = MfKey.MfKey64(uid, nt, nr, ar, at);
            Assert.AreEqual(key, expectedKey);
        }
    }
}
