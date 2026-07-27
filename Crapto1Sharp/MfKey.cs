using System;
using System.Collections.Generic;
using System.Linq;

namespace Crapto1Sharp;

/// <summary>
/// Provides MfKey32 and MfKey64 attacks for recovering a MIFARE Classic
/// Crypto1 key from authorized authentication transcripts.
/// </summary>
public static class MfKey
{
    /// <summary>
    /// Immutable default execution settings used by compatibility overloads.
    /// </summary>
    private static readonly MfKeyExecutionOptions DefaultOptions = new();

    /// <summary>
    /// Recovers a key from two authentication exchanges that share one tag
    /// nonce, using default execution options.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The shared tag nonce.</param>
    /// <param name="nr0">The first encrypted reader nonce.</param>
    /// <param name="ar0">The first encrypted reader response.</param>
    /// <param name="nr1">The second encrypted reader nonce.</param>
    /// <param name="ar1">The second encrypted reader response.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    public static ulong MfKey32(
        uint uid,
        uint nt,
        uint nr0,
        uint ar0,
        uint nr1,
        uint ar1) =>
        MfKey32(uid, nt, nr0, ar0, nr1, ar1, DefaultOptions);

    /// <summary>
    /// Recovers a key from two authentication exchanges that share one tag nonce.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The shared tag nonce.</param>
    /// <param name="nr0">The first encrypted reader nonce.</param>
    /// <param name="ar0">The first encrypted reader response.</param>
    /// <param name="nr1">The second encrypted reader nonce.</param>
    /// <param name="ar1">The second encrypted reader response.</param>
    /// <param name="options">Workspace, parallelism, and cancellation settings.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException">Cancellation is requested.</exception>
    public static ulong MfKey32(
        uint uid,
        uint nt,
        uint nr0,
        uint ar0,
        uint nr1,
        uint ar1,
        MfKeyExecutionOptions options)
    {
        var p64 = Crypto1.PrngSuccessor(nt, 64);
        return RecoverKey32(
            ar0 ^ p64,
            options,
            (Crypto1State state, out ulong key) =>
            {
                state.LfsrRollbackWord();
                state.LfsrRollbackWord(nr0, true);
                state.LfsrRollbackWord(uid ^ nt);
                key = state.Lfsr;
                state.Crypto1Word(uid ^ nt);
                state.Crypto1Word(nr1, true);
                return ar1 == (state.Crypto1Word() ^ p64);
            });
    }

    /// <summary>
    /// Recovers a key from multiple authentication exchanges that share one tag
    /// nonce, using default execution options.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The shared tag nonce.</param>
    /// <param name="nonces">Reader nonce/response pairs to validate.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    public static ulong MfKey32(uint uid, uint nt, IEnumerable<Nonce> nonces) =>
        MfKey32(uid, nt, nonces, DefaultOptions);

    /// <summary>
    /// Recovers a key from multiple authentication exchanges that share one tag
    /// nonce.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The shared tag nonce.</param>
    /// <param name="nonces">Reader nonce/response pairs to validate.</param>
    /// <param name="options">Workspace, parallelism, and cancellation settings.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="nonces"/> or <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException"><paramref name="nonces"/> is empty.</exception>
    /// <exception cref="OperationCanceledException">Cancellation is requested.</exception>
    public static ulong MfKey32(
        uint uid,
        uint nt,
        IEnumerable<Nonce> nonces,
        MfKeyExecutionOptions options)
    {
        var values = Materialize(nonces);
        var first = values[0];
        var p64 = Crypto1.PrngSuccessor(nt, 64);
        return RecoverKey32(
            first.Ar ^ p64,
            options,
            (Crypto1State state, out ulong key) =>
            {
                state.LfsrRollbackWord();
                state.LfsrRollbackWord(first.Nr, true);
                state.LfsrRollbackWord(uid ^ nt);
                key = state.Lfsr;
                for (var i = 1; i < values.Length; i++)
                {
                    var candidate = state;
                    candidate.Crypto1Word(uid ^ nt);
                    candidate.Crypto1Word(values[i].Nr, true);
                    if (values[i].Ar != (candidate.Crypto1Word() ^ p64))
                        return false;
                }
                return true;
            });
    }

    /// <summary>
    /// Recovers a key from two authentication exchanges with different tag
    /// nonces, using default execution options.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt0">The first tag nonce.</param>
    /// <param name="nr0">The first encrypted reader nonce.</param>
    /// <param name="ar0">The first encrypted reader response.</param>
    /// <param name="nt1">The second tag nonce.</param>
    /// <param name="nr1">The second encrypted reader nonce.</param>
    /// <param name="ar1">The second encrypted reader response.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    public static ulong MfKey32(
        uint uid,
        uint nt0,
        uint nr0,
        uint ar0,
        uint nt1,
        uint nr1,
        uint ar1) =>
        MfKey32(uid, nt0, nr0, ar0, nt1, nr1, ar1, DefaultOptions);

    /// <summary>
    /// Recovers a key from two authentication exchanges with different tag nonces.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt0">The first tag nonce.</param>
    /// <param name="nr0">The first encrypted reader nonce.</param>
    /// <param name="ar0">The first encrypted reader response.</param>
    /// <param name="nt1">The second tag nonce.</param>
    /// <param name="nr1">The second encrypted reader nonce.</param>
    /// <param name="ar1">The second encrypted reader response.</param>
    /// <param name="options">Workspace, parallelism, and cancellation settings.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException">Cancellation is requested.</exception>
    public static ulong MfKey32(
        uint uid,
        uint nt0,
        uint nr0,
        uint ar0,
        uint nt1,
        uint nr1,
        uint ar1,
        MfKeyExecutionOptions options)
    {
        var p640 = Crypto1.PrngSuccessor(nt0, 64);
        var p641 = Crypto1.PrngSuccessor(nt1, 64);
        return RecoverKey32(
            ar0 ^ p640,
            options,
            (Crypto1State state, out ulong key) =>
            {
                state.LfsrRollbackWord();
                state.LfsrRollbackWord(nr0, true);
                state.LfsrRollbackWord(uid ^ nt0);
                key = state.Lfsr;
                state.Crypto1Word(uid ^ nt1);
                state.Crypto1Word(nr1, true);
                return ar1 == (state.Crypto1Word() ^ p641);
            });
    }

    /// <summary>
    /// Recovers a key from authentication exchanges with arbitrary tag nonces,
    /// using default execution options.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nonces">Tag nonce, reader nonce, and response transcripts.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    public static ulong MfKey32(uint uid, IEnumerable<Nonce> nonces) =>
        MfKey32(uid, nonces, DefaultOptions);

    /// <summary>
    /// Recovers a key from authentication exchanges with arbitrary tag nonces.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nonces">Tag nonce, reader nonce, and response transcripts.</param>
    /// <param name="options">Workspace, parallelism, and cancellation settings.</param>
    /// <returns>The unique 48-bit key, or <see cref="ulong.MaxValue"/> when the result is not unique.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="nonces"/> or <paramref name="options"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException"><paramref name="nonces"/> is empty.</exception>
    /// <exception cref="OperationCanceledException">Cancellation is requested.</exception>
    public static ulong MfKey32(
        uint uid,
        IEnumerable<Nonce> nonces,
        MfKeyExecutionOptions options)
    {
        var values = Materialize(nonces);
        var checks = new NonceCheck[values.Length];
        for (var i = 0; i < checks.Length; i++)
            checks[i] = new NonceCheck(
                values[i],
                Crypto1.PrngSuccessor(values[i].Nt, 64));

        var first = checks[0];
        return RecoverKey32(
            first.Nonce.Ar ^ first.P64,
            options,
            (Crypto1State state, out ulong key) =>
            {
                state.LfsrRollbackWord();
                state.LfsrRollbackWord(first.Nonce.Nr, true);
                state.LfsrRollbackWord(uid ^ first.Nonce.Nt);
                key = state.Lfsr;
                for (var i = 1; i < checks.Length; i++)
                {
                    var candidate = state;
                    candidate.Crypto1Word(uid ^ checks[i].Nonce.Nt);
                    candidate.Crypto1Word(checks[i].Nonce.Nr, true);
                    if (checks[i].Nonce.Ar !=
                        (candidate.Crypto1Word() ^ checks[i].P64))
                        return false;
                }
                return true;
            });
    }

    /// <summary>
    /// Recovers a key from a 64-bit authentication transcript using default
    /// execution options.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The tag nonce.</param>
    /// <param name="nr">The encrypted reader nonce.</param>
    /// <param name="ar">The encrypted reader response at PRNG successor 64.</param>
    /// <param name="at">The encrypted tag response at PRNG successor 96.</param>
    /// <returns>The recovered 48-bit key.</returns>
    public static ulong MfKey64(
        uint uid,
        uint nt,
        uint nr,
        uint ar,
        uint at) =>
        MfKey64(uid, nt, nr, ar, at, DefaultOptions);

    /// <summary>
    /// Recovers a key from a 64-bit authentication transcript.
    /// </summary>
    /// <param name="uid">The card UID used by authentication.</param>
    /// <param name="nt">The tag nonce.</param>
    /// <param name="nr">The encrypted reader nonce.</param>
    /// <param name="ar">The encrypted reader response at PRNG successor 64.</param>
    /// <param name="at">The encrypted tag response at PRNG successor 96.</param>
    /// <param name="options">Workspace and cancellation settings.</param>
    /// <returns>The recovered 48-bit key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">Recovery produces no candidate state.</exception>
    /// <exception cref="OperationCanceledException">Cancellation is requested.</exception>
    public static ulong MfKey64(
        uint uid,
        uint nt,
        uint nr,
        uint ar,
        uint at,
        MfKeyExecutionOptions options)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));
        options.CancellationToken.ThrowIfCancellationRequested();

        var ks2 = ar ^ Crypto1.PrngSuccessor(nt, 64);
        var ks3 = at ^ Crypto1.PrngSuccessor(nt, 96);
        var ownsWorkspace = options.Workspace == null;
        var workspace = options.Workspace ?? new Crypto1RecoveryWorkspace();
        workspace.Enter();
        try
        {
            var found = false;
            var state = default(Crypto1State);
            Crapto1.Recover64Core(
                ks2,
                ks3,
                workspace,
                candidate =>
                {
                    options.CancellationToken.ThrowIfCancellationRequested();
                    state = candidate;
                    found = true;
                    return false;
                });
            if (!found)
                throw new InvalidOperationException("Sequence contains no elements");

            state.LfsrRollbackWord();
            state.LfsrRollbackWord();
            state.LfsrRollbackWord(nr, true);
            state.LfsrRollbackWord(uid ^ nt);
            return state.Lfsr;
        }
        finally
        {
            workspace.Exit();
            if (ownsWorkspace)
                workspace.Dispose();
        }
    }

    /// <summary>
    /// Runs Recovery32 and validates its output through the bounded candidate
    /// pipeline.
    /// </summary>
    /// <param name="ks2">The 32-bit keystream word to recover.</param>
    /// <param name="options">Workspace, parallelism, and cancellation settings.</param>
    /// <param name="validator">The transcript-specific candidate validator.</param>
    /// <returns>The unique key, or <see cref="ulong.MaxValue"/> when zero or multiple states validate.</returns>
    private static ulong RecoverKey32(
        uint ks2,
        MfKeyExecutionOptions options,
        CandidateValidator validator)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));
        options.CancellationToken.ThrowIfCancellationRequested();

        var ownsWorkspace = options.Workspace == null;
        var workspace = options.Workspace ?? new Crypto1RecoveryWorkspace();
        workspace.Enter();
        try
        {
            using var pipeline = new CandidateValidationPipeline(validator, options);
            Crapto1.Recover32Core(ks2, 0, workspace, pipeline.Emit);
            pipeline.Finish();
            return pipeline.MatchCount == 1 ? pipeline.Key : ulong.MaxValue;
        }
        finally
        {
            workspace.Exit();
            if (ownsWorkspace)
                workspace.Dispose();
        }
    }

    /// <summary>
    /// Materializes a transcript sequence exactly once and preserves the
    /// historical empty-sequence failure behavior.
    /// </summary>
    /// <param name="nonces">The transcript sequence.</param>
    /// <returns>The original array or a newly materialized array.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="nonces"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="nonces"/> is empty.</exception>
    private static Nonce[] Materialize(IEnumerable<Nonce> nonces)
    {
        if (nonces == null)
            throw new ArgumentNullException(nameof(nonces));
        var values = nonces as Nonce[] ?? nonces.ToArray();
        if (values.Length == 0)
            throw new InvalidOperationException("Sequence contains no elements");
        return values;
    }

    /// <summary>
    /// Couples a transcript with its precomputed 64-step PRNG successor.
    /// </summary>
    private readonly struct NonceCheck
    {
        /// <summary>
        /// Initializes a precomputed transcript check.
        /// </summary>
        /// <param name="nonce">The authentication transcript.</param>
        /// <param name="p64">The transcript's 64-step PRNG successor.</param>
        internal NonceCheck(Nonce nonce, uint p64)
        {
            Nonce = nonce;
            P64 = p64;
        }

        /// <summary>
        /// Gets the authentication transcript.
        /// </summary>
        internal Nonce Nonce { get; }

        /// <summary>
        /// Gets the precomputed 64-step PRNG successor.
        /// </summary>
        internal uint P64 { get; }
    }
}
