using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Test
{
    [TestClass]
    public class MfKeyTest
    {
        //[TestMethod]
        //[DataRow(0x866285B1u, 0xB830049Bu, 0x8D369B4Du, 0x9248314Au, 0x9280E203u, 0xA0A1A2A3A4A5uL)]
        //[DataRow(0x5C688618u, 0xE9FAD974u, 0xB37A0666u, 0xEE09C7C2u, 0x1F23E820u, 0xCCC6CCC69720uL)]
        //public void MfKey32(uint uid, uint nt, uint nr0, uint ar0, uint nr1, uint ar1, ulong expectedKey)
        //{
        //    //var key = MfKey.MfKey32(uid, nt, nr0, ar0, nr1, ar1);
        //    //Assert.AreEqual(key, expectedKey);
        //}

        [TestMethod]
        [DataRow(0x12345678u, 0xB830049Bu, 0xFFFFFFFFFFFFuL)]
        public void MfKey2(uint uid, uint nt, ulong expectedKey)
        {
            var p64 = Crypto1.PrngSuccessor(nt, 64);
            var crypto1 = new Crypto1(expectedKey);
            crypto1.Crypto1Word(uid ^ nt);
            var nr0 = crypto1.Crypto1Word(0x14725836u) ^ 0x14725836u;
            var ar0 = p64 ^ crypto1.Crypto1Word();

            crypto1 = new Crypto1(expectedKey);
            crypto1.Crypto1Word(uid ^ nt);
            var nr1 = crypto1.Crypto1Word(0x96325874u) ^ 0x96325874u;
            var ar1 = p64 ^ crypto1.Crypto1Word();

            var key = MfKey.MfKey32(uid, nt, nr0, ar0, nr1, ar1);
            Assert.AreEqual(expectedKey, key);
        }

        [TestMethod]
        [DataRow(0x866285B1u, 0xB830049Bu, 0x8D369B4Du, 0x9248314Au, 0x9280E203u, 0xA0A1A2A3A4A5uL)]
        [DataRow(0x5C688618u, 0xE9FAD974u, 0xB37A0666u, 0xEE09C7C2u, 0x1F23E820u, 0xCCC6CCC69720uL)]
        public void MfKey64(uint uid, uint nt, uint nr, uint ar, uint at, ulong expectedKey)
        {
            var key = MfKey.MfKey64(uid, nt, nr, ar, at);
            Assert.AreEqual(expectedKey, key);
        }
    }
}
