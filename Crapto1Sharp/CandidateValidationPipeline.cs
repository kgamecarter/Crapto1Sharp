using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;

namespace Crapto1Sharp;

/// <summary>
/// Validates one recovered state and returns the corresponding key when valid.
/// </summary>
/// <param name="state">The recovered state to validate.</param>
/// <param name="key">Receives the recovered key when validation succeeds.</param>
/// <returns><see langword="true"/> when the state satisfies every transcript.</returns>
internal delegate bool CandidateValidator(Crypto1State state, out ulong key);

/// <summary>
/// Buffers recovered states into pooled batches and validates them either
/// synchronously or with a bounded set of background workers.
/// </summary>
internal sealed class CandidateValidationPipeline : IDisposable
{
    /// <summary>
    /// Number of states stored in each pooled validation batch.
    /// </summary>
    private const int BatchLength = 4096;

    /// <summary>
    /// Validation callback applied to each candidate.
    /// </summary>
    private readonly CandidateValidator _validator;

    /// <summary>
    /// Cancellation requested by the caller.
    /// </summary>
    private readonly CancellationToken _externalCancellation;

    /// <summary>
    /// Shared pool that owns validation batches.
    /// </summary>
    private readonly ArrayPool<Crypto1State> _pool = ArrayPool<Crypto1State>.Shared;

    /// <summary>
    /// Bounded worker queue, or <see langword="null"/> for synchronous validation.
    /// </summary>
    private readonly BlockingCollection<CandidateBatch>? _queue;

    /// <summary>
    /// Linked token source used to stop all workers after cancellation, failure,
    /// or a second valid result.
    /// </summary>
    private readonly CancellationTokenSource? _stopSource;

    /// <summary>
    /// Background validation workers, or <see langword="null"/> in synchronous mode.
    /// </summary>
    private readonly Task[]? _workers;

    /// <summary>
    /// Batch currently being filled by the recovery producer.
    /// </summary>
    private Crypto1State[]? _current;

    /// <summary>
    /// Number of active states in <see cref="_current"/>.
    /// </summary>
    private int _currentCount;

    /// <summary>
    /// First exception captured from a validation worker.
    /// </summary>
    private ExceptionDispatchInfo? _workerException;

    /// <summary>
    /// Number of candidates that passed validation.
    /// </summary>
    private int _matchCount;

    /// <summary>
    /// Bit-preserving signed storage for the most recently validated key.
    /// </summary>
    private long _keyBits;

    /// <summary>
    /// Indicates that at least two valid results have been observed.
    /// </summary>
    private int _stopForMultipleMatches;

    /// <summary>
    /// Indicates that producer completion and worker joining have run.
    /// </summary>
    private bool _finished;

    /// <summary>
    /// Creates a validation pipeline using the supplied execution options.
    /// </summary>
    /// <param name="validator">Callback used to validate each recovered state.</param>
    /// <param name="options">Parallelism and cancellation options.</param>
    internal CandidateValidationPipeline(
        CandidateValidator validator,
        MfKeyExecutionOptions options)
    {
        _validator = validator;
        _externalCancellation = options.CancellationToken;
        var workerCount = options.GetWorkerCount();
        _current = _pool.Rent(BatchLength);

        if (workerCount <= 1)
            return;

        _stopSource = CancellationTokenSource.CreateLinkedTokenSource(
            _externalCancellation);
        _queue = new BlockingCollection<CandidateBatch>(workerCount * 2);
        _workers = new Task[workerCount];
        for (var i = 0; i < _workers.Length; i++)
            _workers[i] = Task.Run(Consume);
    }

    /// <summary>
    /// Gets the number of candidates that have passed validation.
    /// </summary>
    internal int MatchCount => Volatile.Read(ref _matchCount);

    /// <summary>
    /// Gets the key reported by the most recent successful validation.
    /// </summary>
    internal ulong Key => unchecked((ulong)Interlocked.Read(ref _keyBits));

    /// <summary>
    /// Accepts one recovered state from the producer.
    /// </summary>
    /// <param name="state">The state to buffer or validate synchronously.</param>
    /// <returns>
    /// <see langword="true"/> to continue producing states; otherwise,
    /// <see langword="false"/> after multiple matches.
    /// </returns>
    internal bool Emit(Crypto1State state)
    {
        _externalCancellation.ThrowIfCancellationRequested();
        ThrowWorkerException();
        if (Volatile.Read(ref _stopForMultipleMatches) != 0)
            return false;

        if (_queue == null)
        {
            Validate(state);
            return Volatile.Read(ref _stopForMultipleMatches) == 0;
        }

        var current = _current!;
        current[_currentCount++] = state;
        if (_currentCount != BatchLength)
            return true;

        EnqueueCurrent();
        return Volatile.Read(ref _stopForMultipleMatches) == 0;
    }

    /// <summary>
    /// Publishes the final partial batch, waits for all workers, and propagates
    /// cancellation or worker failures.
    /// </summary>
    internal void Finish()
    {
        if (_finished)
            return;
        _finished = true;

        if (_queue == null)
        {
            ReturnCurrent();
            _externalCancellation.ThrowIfCancellationRequested();
            ThrowWorkerException();
            return;
        }

        try
        {
            if (_currentCount != 0 &&
                Volatile.Read(ref _stopForMultipleMatches) == 0)
                EnqueueCurrent();
            else
                ReturnCurrent();
        }
        catch (OperationCanceledException)
        {
            ReturnCurrent();
        }
        finally
        {
            _queue.CompleteAdding();
        }

        try
        {
            Task.WaitAll(_workers!);
        }
        catch (AggregateException) when (
            _workerException != null ||
            Volatile.Read(ref _stopForMultipleMatches) != 0 ||
            _externalCancellation.IsCancellationRequested)
        {
        }

        DrainQueue();
        _externalCancellation.ThrowIfCancellationRequested();
        ThrowWorkerException();
    }

    /// <summary>
    /// Enqueues the current producer batch and rents a replacement batch.
    /// </summary>
    /// <remarks>
    /// A second match cancels the stop token, possibly while the producer is
    /// waiting here for room in the bounded queue. That ends production like a
    /// second match seen in <see cref="Emit"/>: the batch is returned to the pool
    /// and no exception escapes. Caller cancellation and worker failures still
    /// propagate.
    /// </remarks>
    private void EnqueueCurrent()
    {
        var batch = new CandidateBatch(_current!, _currentCount);
        _current = null;
        _currentCount = 0;
        try
        {
            _queue!.Add(batch, _stopSource!.Token);
        }
        catch (OperationCanceledException)
        {
            Return(batch.States, batch.Count);
            _externalCancellation.ThrowIfCancellationRequested();
            ThrowWorkerException();
            if (Volatile.Read(ref _stopForMultipleMatches) == 0)
                throw;
        }
        _current = _pool.Rent(BatchLength);
    }

    /// <summary>
    /// Worker loop that validates queued batches and always returns their arrays.
    /// </summary>
    private void Consume()
    {
        try
        {
            foreach (var batch in _queue!.GetConsumingEnumerable(_stopSource!.Token))
            {
                try
                {
                    for (var i = 0; i < batch.Count; i++)
                    {
                        if (Volatile.Read(ref _stopForMultipleMatches) != 0)
                            break;
                        Validate(batch.States[i]);
                    }
                }
                finally
                {
                    Return(batch.States, batch.Count);
                }
            }
        }
        catch (OperationCanceledException) when (
            Volatile.Read(ref _stopForMultipleMatches) != 0 ||
            _externalCancellation.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Interlocked.CompareExchange(
                ref _workerException,
                ExceptionDispatchInfo.Capture(exception),
                null);
            _stopSource!.Cancel();
        }
    }

    /// <summary>
    /// Validates a candidate and atomically records successful results.
    /// </summary>
    /// <param name="state">The candidate state.</param>
    private void Validate(Crypto1State state)
    {
        if (!_validator(state, out var key))
            return;

        Interlocked.Exchange(ref _keyBits, unchecked((long)key));
        if (Interlocked.Increment(ref _matchCount) >= 2)
        {
            Volatile.Write(ref _stopForMultipleMatches, 1);
            _stopSource?.Cancel();
        }
    }

    /// <summary>
    /// Rethrows the first exception captured from any background worker.
    /// </summary>
    private void ThrowWorkerException()
    {
        Volatile.Read(ref _workerException)?.Throw();
    }

    /// <summary>
    /// Returns the producer's current batch when one is rented.
    /// </summary>
    private void ReturnCurrent()
    {
        var current = _current;
        if (current == null)
            return;
        Return(current, _currentCount);
        _current = null;
        _currentCount = 0;
    }

    /// <summary>
    /// Returns every batch left in the bounded queue.
    /// </summary>
    private void DrainQueue()
    {
        if (_queue == null)
            return;
        while (_queue.TryTake(out var batch))
            Return(batch.States, batch.Count);
    }

    /// <summary>
    /// Clears the active prefix of a batch and returns it to the shared pool.
    /// </summary>
    /// <param name="states">The batch array.</param>
    /// <param name="count">The number of active elements to clear.</param>
    private void Return(Crypto1State[] states, int count)
    {
        Array.Clear(states, 0, count);
        _pool.Return(states, clearArray: false);
    }

    /// <summary>
    /// Finishes outstanding work when necessary and releases queue resources and
    /// all pooled arrays.
    /// </summary>
    public void Dispose()
    {
        if (!_finished)
        {
            try
            {
                Finish();
            }
            catch
            {
                // Dispose must still release every rented buffer.
            }
        }
        ReturnCurrent();
        DrainQueue();
        _queue?.Dispose();
        _stopSource?.Dispose();
    }

    /// <summary>
    /// Describes the active prefix of one pooled validation batch.
    /// </summary>
    private readonly struct CandidateBatch
    {
        /// <summary>
        /// Initializes a batch descriptor.
        /// </summary>
        /// <param name="states">The pooled state array.</param>
        /// <param name="count">The number of active states.</param>
        internal CandidateBatch(Crypto1State[] states, int count)
        {
            States = states;
            Count = count;
        }

        /// <summary>
        /// Gets the pooled array containing candidate states.
        /// </summary>
        internal Crypto1State[] States { get; }

        /// <summary>
        /// Gets the number of active elements in <see cref="States"/>.
        /// </summary>
        internal int Count { get; }
    }
}
