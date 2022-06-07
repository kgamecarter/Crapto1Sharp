using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Test;

[TestClass]
public class MfKeyTest
{
    [TestMethod]
    [DataRow(0x866285B1u, 0xB830049Bu, 0x14725836u, 0x96325874u, 0xFFFFFFFFFFFFuL)]
    [DataRow(0x5C688618u, 0xE9FAD974u, 0x45698215u, 0x95123654u, 0x1234567890ABuL)]
    public void MfKey32_SameNtTwoNonce(uint uid, uint nt, uint nr0, uint nr1, ulong expectedKey)
    {
        var p64 = Crypto1.PrngSuccessor(nt, 64);
        var crypto1 = new Crypto1(expectedKey);
        crypto1.Crypto1Word(uid ^ nt);
        nr0 ^= crypto1.Crypto1Word(nr0);
        var ar0 = p64 ^ crypto1.Crypto1Word();

        crypto1 = new Crypto1(expectedKey);
        crypto1.Crypto1Word(uid ^ nt);
        nr1 ^= crypto1.Crypto1Word(nr1);
        var ar1 = p64 ^ crypto1.Crypto1Word();

        var key = MfKey.MfKey32(uid, nt, nr0, ar0, nr1, ar1);
        Assert.AreEqual(expectedKey, key);
    }

    [TestMethod]
    [DataRow(0x866285B1u, 0xB830049Bu, 123456, 10, 0xFFFFFFFFFFFFuL)]
    [DataRow(0x5C688618u, 0xE9FAD974u, 654321, 5, 0x1234567890ABuL)]
    public void MfKey32_SameNtManyNonce(uint uid, uint nt, int randomSeed, int nonceCount, ulong expectedKey)
    {
        var p64 = Crypto1.PrngSuccessor(nt, 64);
        var list = new List<Nonce>();
        Random rnd = new Random(randomSeed);
        for (int i = 0; i < nonceCount; i++)
        {
            var crypto1 = new Crypto1(expectedKey);
            crypto1.Crypto1Word(uid ^ nt);
            var nr = (uint)rnd.Next();
            list.Add(new Nonce()
            {
                Nr = crypto1.Crypto1Word(nr) ^ nr,
                Ar = p64 ^ crypto1.Crypto1Word()
            });
        }

        var key = MfKey.MfKey32(uid, nt, list);
        Assert.AreEqual(expectedKey, key);
    }

    [TestMethod]
    [DataRow(0x866285B1u, 0xB830049Bu, 0xE9FAD974u, 0x14725836u, 0x96325874u, 0xFFFFFFFFFFFFuL)]
    [DataRow(0x5C688618u, 0xE9FAD974u, 0xB830049Bu, 0x45698215u, 0x95123654u, 0x1234567890ABuL)]
    public void MfKey32_ManyNtTwoNonce(uint uid, uint nt0, uint nt1, uint nr0, uint nr1, ulong expectedKey)
    {
        var p64 = Crypto1.PrngSuccessor(nt0, 64);
        var crypto1 = new Crypto1(expectedKey);
        crypto1.Crypto1Word(uid ^ nt0);
        nr0 ^= crypto1.Crypto1Word(nr0);
        var ar0 = p64 ^ crypto1.Crypto1Word();

        p64 = Crypto1.PrngSuccessor(nt1, 64);
        crypto1 = new Crypto1(expectedKey);
        crypto1.Crypto1Word(uid ^ nt1);
        nr1 ^= crypto1.Crypto1Word(nr1);
        var ar1 = p64 ^ crypto1.Crypto1Word();

        var key = MfKey.MfKey32(uid, nt0, nr0, ar0, nt1, nr1, ar1);
        Assert.AreEqual(expectedKey, key);
    }

    [TestMethod]
    [DataRow(0x866285B1u, 123456, 10, 0xFFFFFFFFFFFFuL)]
    [DataRow(0x5C688618u, 654321, 5, 0x1234567890ABuL)]
    public void MfKey32_ManyNtManyNonce(uint uid, int randomSeed, int nonceCount, ulong expectedKey)
    {
        var list = new List<Nonce>();
        Random rnd = new Random(randomSeed);
        for (int i = 0; i < nonceCount; i++)
        {
            var crypto1 = new Crypto1(expectedKey);
            var nt = (uint)rnd.Next();
            var nr = (uint)rnd.Next();
            var p64 = Crypto1.PrngSuccessor(nt, 64);
            crypto1.Crypto1Word(uid ^ nt);
            list.Add(new Nonce()
            {
                Nt = nt,
                Nr = crypto1.Crypto1Word(nr) ^ nr,
                Ar = p64 ^ crypto1.Crypto1Word()
            });
        }

        var key = MfKey.MfKey32(uid, list);
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
