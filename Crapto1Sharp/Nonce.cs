using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp;

/// <summary>
/// Represents one MIFARE Classic authentication transcript used by MfKey
/// recovery.
/// </summary>
public struct Nonce
{
    /// <summary>
    /// Gets or sets the tag nonce (<c>Nt</c>).
    /// </summary>
    public uint Nt { get; set; }

    /// <summary>
    /// Gets or sets the encrypted reader nonce/challenge value (<c>Nr</c>).
    /// </summary>
    public uint Nr { get; set; }

    /// <summary>
    /// Gets or sets the encrypted reader authentication response (<c>Ar</c>).
    /// </summary>
    public uint Ar { get; set; }
}
