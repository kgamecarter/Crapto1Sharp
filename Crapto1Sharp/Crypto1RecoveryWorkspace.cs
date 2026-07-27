using System;
using System.Buffers;
using System.Threading;

namespace Crapto1Sharp;

/// <summary>
/// Reusable pooled buffers for Crypto1 state recovery.
/// Instances are not thread-safe and must not be shared by concurrent operations.
/// </summary>
public sealed class Crypto1RecoveryWorkspace : IDisposable
{
    /// <summary>
    /// The initial element capacity of each Recovery32 odd/even buffer.
    /// </summary>
    internal const int Recovery32BufferLength = 1 << 21;

    /// <summary>
    /// The initial element capacity of the Recovery64 table buffer.
    /// </summary>
    internal const int Recovery64TableLength = 1 << 16;

    /// <summary>
    /// Lazily created buffer for odd Recovery32 candidates.
    /// </summary>
    private PooledBuffer<uint>? _odd;

    /// <summary>
    /// Lazily created buffer for even Recovery32 candidates.
    /// </summary>
    private PooledBuffer<uint>? _even;

    /// <summary>
    /// Lazily created table used by Recovery64.
    /// </summary>
    private PooledBuffer<uint>? _table;

    /// <summary>
    /// Pool from which all workspace buffers are rented.
    /// </summary>
    private readonly ArrayPool<uint> _pool;

    /// <summary>
    /// Indicates whether an operation currently owns this workspace.
    /// </summary>
    private int _busy;

    /// <summary>
    /// Indicates whether the workspace has returned its buffers.
    /// </summary>
    private bool _disposed;

    /// <summary>
    /// Initializes an empty workspace backed by <see cref="ArrayPool{T}.Shared"/>.
    /// Buffers are rented lazily on first use.
    /// </summary>
    public Crypto1RecoveryWorkspace() : this(ArrayPool<uint>.Shared)
    {
    }

    /// <summary>
    /// Initializes an empty workspace backed by a specified pool.
    /// </summary>
    /// <param name="pool">The pool used to rent recovery buffers.</param>
    internal Crypto1RecoveryWorkspace(ArrayPool<uint> pool)
    {
        _pool = pool ?? throw new ArgumentNullException(nameof(pool));
    }

    /// <summary>
    /// Gets or lazily creates the odd Recovery32 candidate buffer.
    /// </summary>
    internal PooledBuffer<uint> Odd
    {
        get
        {
            ThrowIfDisposed();
            return _odd ??= new PooledBuffer<uint>(
                _pool,
                Recovery32BufferLength);
        }
    }

    /// <summary>
    /// Gets or lazily creates the even Recovery32 candidate buffer.
    /// </summary>
    internal PooledBuffer<uint> Even
    {
        get
        {
            ThrowIfDisposed();
            return _even ??= new PooledBuffer<uint>(
                _pool,
                Recovery32BufferLength);
        }
    }

    /// <summary>
    /// Gets or lazily creates the Recovery64 table buffer.
    /// </summary>
    internal PooledBuffer<uint> Table
    {
        get
        {
            ThrowIfDisposed();
            return _table ??= new PooledBuffer<uint>(
                _pool,
                Recovery64TableLength);
        }
    }

    /// <summary>
    /// Acquires exclusive use of this non-thread-safe workspace.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The workspace is disposed.</exception>
    /// <exception cref="InvalidOperationException">Another operation is using the workspace.</exception>
    internal void Enter()
    {
        ThrowIfDisposed();
        if (Interlocked.Exchange(ref _busy, 1) != 0)
            throw new InvalidOperationException(
                "Crypto1RecoveryWorkspace cannot be used by concurrent operations.");
    }

    /// <summary>
    /// Releases exclusive use of this workspace.
    /// </summary>
    internal void Exit()
    {
        Volatile.Write(ref _busy, 0);
    }

    /// <summary>
    /// Throws when the workspace has already been disposed.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The workspace is disposed.</exception>
    internal void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Crypto1RecoveryWorkspace));
    }

    /// <summary>
    /// Clears the used portion of every rented buffer and returns the buffers to
    /// their pool.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A recovery operation is currently using the workspace.
    /// </exception>
    public void Dispose()
    {
        if (_disposed)
            return;
        if (Volatile.Read(ref _busy) != 0)
            throw new InvalidOperationException(
                "The workspace cannot be disposed while an operation is using it.");

        _disposed = true;
        _odd?.Dispose();
        _even?.Dispose();
        _table?.Dispose();
        _odd = null;
        _even = null;
        _table = null;
    }
}

/// <summary>
/// Receives recovered states. Return false to stop recovery early.
/// </summary>
/// <param name="state">The recovered candidate state.</param>
/// <returns>
/// <see langword="true"/> to continue recovery; <see langword="false"/> to stop.
/// </returns>
public delegate bool Crypto1StateVisitor(in Crypto1State state);

/// <summary>
/// Result of a visitor-based recovery operation.
/// </summary>
public readonly struct RecoveryVisitResult
{
    /// <summary>
    /// Initializes a visitor result.
    /// </summary>
    /// <param name="visitedCount">The number of candidates delivered.</param>
    /// <param name="completed">Whether recovery reached its natural end.</param>
    internal RecoveryVisitResult(int visitedCount, bool completed)
    {
        VisitedCount = visitedCount;
        Completed = completed;
    }

    /// <summary>
    /// Gets the number of candidate states delivered to the visitor.
    /// </summary>
    public int VisitedCount { get; }

    /// <summary>
    /// Gets a value indicating whether recovery completed without being stopped
    /// by the visitor.
    /// </summary>
    public bool Completed { get; }
}

/// <summary>
/// Owns a growable array rented from an <see cref="ArrayPool{T}"/> and tracks the
/// highest element that must be cleared before return.
/// </summary>
/// <typeparam name="T">The pooled element type.</typeparam>
internal sealed class PooledBuffer<T> : IDisposable
{
    /// <summary>
    /// Pool that owns the current array.
    /// </summary>
    private readonly ArrayPool<T> _pool;

    /// <summary>
    /// The currently rented array, or <see langword="null"/> after disposal.
    /// </summary>
    private T[]? _array;

    /// <summary>
    /// Exclusive upper bound of the region that has held active data.
    /// </summary>
    private int _highWaterMark;

    /// <summary>
    /// Rents a buffer with at least the requested capacity.
    /// </summary>
    /// <param name="pool">The source pool.</param>
    /// <param name="minimumLength">The required minimum element count.</param>
    internal PooledBuffer(ArrayPool<T> pool, int minimumLength)
    {
        _pool = pool;
        _array = pool.Rent(minimumLength);
    }

    /// <summary>
    /// Gets the currently rented array.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The buffer has been disposed.</exception>
    internal T[] Array =>
        _array ?? throw new ObjectDisposedException(nameof(PooledBuffer<T>));

    /// <summary>
    /// Records the exclusive end of a region that has contained active data.
    /// </summary>
    /// <param name="exclusiveEnd">The exclusive used-region end index.</param>
    internal void MarkUsed(int exclusiveEnd)
    {
        if (exclusiveEnd > _highWaterMark)
            _highWaterMark = exclusiveEnd;
    }

    /// <summary>
    /// Grows the pooled buffer when its current array is too small.
    /// </summary>
    /// <param name="requiredLength">The required minimum element count.</param>
    internal void EnsureCapacity(int requiredLength)
    {
        var array = Array;
        if (requiredLength <= array.Length)
            return;

        var newLength = array.Length;
        while (newLength < requiredLength)
            newLength = checked(newLength * 2);

        var replacement = _pool.Rent(newLength);
        System.Array.Copy(array, replacement, _highWaterMark);
        System.Array.Clear(array, 0, _highWaterMark);
        _pool.Return(array, clearArray: false);
        _array = replacement;
    }

    /// <summary>
    /// Clears the used region and returns the rented array to its pool.
    /// </summary>
    public void Dispose()
    {
        var array = _array;
        if (array == null)
            return;

        System.Array.Clear(array, 0, _highWaterMark);
        _pool.Return(array, clearArray: false);
        _array = null;
        _highWaterMark = 0;
    }
}
