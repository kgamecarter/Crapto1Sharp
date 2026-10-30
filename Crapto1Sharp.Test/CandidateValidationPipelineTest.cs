using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;

namespace Crapto1Sharp.Test;

[TestClass]
public class CandidateValidationPipelineTest
{
    private const int BatchLength = 4096;
    private const int WaitTimeoutMilliseconds = 10000;

    [TestMethod]
    public void ProducerBlockedOnFullQueue_StopsAfterSecondMatch()
    {
        using var workersReady = new CountdownEvent(2);
        using var queueFilled = new ManualResetEventSlim();
        using var releaseWorkers = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var calls = 0;
        using var pipeline = new CandidateValidationPipeline(
            (Crypto1State _, out ulong key) =>
            {
                if (Interlocked.Increment(ref calls) <= 2)
                    workersReady.Signal();
                releaseWorkers.Wait();
                key = 0x1234;
                return true;
            },
            new MfKeyExecutionOptions
            {
                MaxDegreeOfParallelism = 3,
                CancellationToken = cancellation.Token
            });
        Exception? producerException = null;
        var stopped = false;
        var producer = new Thread(() =>
        {
            try
            {
                // Two batches are held by workers; four occupy the bounded queue.
                for (var i = 0; i < BatchLength * 6; i++)
                    pipeline.Emit(default);
                queueFilled.Set();
                for (var i = 0; i < BatchLength; i++)
                {
                    if (!pipeline.Emit(default))
                    {
                        stopped = true;
                        break;
                    }
                }
                pipeline.Finish();
            }
            catch (Exception exception)
            {
                producerException = exception;
            }
        }) { IsBackground = true };
        producer.Start();
        try
        {
            Assert.IsTrue(workersReady.Wait(WaitTimeoutMilliseconds), "Both workers must hold a batch.");
            Assert.IsTrue(queueFilled.Wait(WaitTimeoutMilliseconds), "The four queue slots must be full.");
            // This thread has no other blocking operation before its seventh Add.
            WaitForBlockedProducer(producer);
            releaseWorkers.Set();
            Assert.IsTrue(producer.Join(WaitTimeoutMilliseconds), "The producer must stop after cancellation.");
            Assert.IsNull(producerException);
            Assert.IsTrue(stopped);
            Assert.IsGreaterThanOrEqualTo(2, pipeline.MatchCount);
        }
        finally
        {
            releaseWorkers.Set();
            cancellation.Cancel();
            JoinForCleanup(producer, pipeline);
        }
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void Finish_BlockedOnFullQueue_JoinsWorkersBeforePropagatingFailure(bool cancelExternally)
    {
        using var workersReady = new CountdownEvent(2);
        using var finishing = new ManualResetEventSlim();
        using var releaseFailure = new ManualResetEventSlim();
        using var releaseSlowWorker = new ManualResetEventSlim();
        using var slowWorkerExited = new ManualResetEventSlim();
        using var producerExited = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource();
        var expectedException = new InvalidOperationException("worker failure");
        var calls = 0;
        using var pipeline = new CandidateValidationPipeline(
            (Crypto1State _, out ulong key) =>
            {
                key = 0;
                var call = Interlocked.Increment(ref calls);
                if (call <= 2)
                    workersReady.Signal();
                if (call == 1)
                {
                    releaseFailure.Wait();
                    if (!cancelExternally)
                        throw expectedException;
                }
                if (call == 2)
                {
                    releaseSlowWorker.Wait();
                    slowWorkerExited.Set();
                }
                return false;
            },
            new MfKeyExecutionOptions
            {
                MaxDegreeOfParallelism = 3,
                CancellationToken = cancellation.Token
            });
        Exception? producerException = null;
        var joinedBeforeReturning = false;
        var queue = ReadField<object>(pipeline, "_queue");
        var isAddingCompleted = queue.GetType().GetProperty("IsAddingCompleted")!;
        var producer = new Thread(() =>
        {
            try
            {
                for (var i = 0; i < BatchLength * 6 + 1; i++)
                    pipeline.Emit(default);
                finishing.Set();
                pipeline.Finish();
            }
            catch (Exception exception)
            {
                producerException = exception;
            }
            finally
            {
                joinedBeforeReturning = slowWorkerExited.IsSet;
                producerExited.Set();
            }
        }) { IsBackground = true };
        producer.Start();
        try
        {
            Assert.IsTrue(workersReady.Wait(WaitTimeoutMilliseconds), "Both workers must hold a batch.");
            Assert.IsTrue(finishing.Wait(WaitTimeoutMilliseconds), "Finish must have a partial batch to enqueue.");
            WaitForBlockedProducer(producer);
            if (cancelExternally)
                cancellation.Cancel();
            releaseFailure.Set();

            // CompleteAdding runs after the canceled enqueue. The producer must
            // then wait for the slow worker, rather than exit with an exception.
            Assert.IsTrue(SpinWait.SpinUntil(
                () => (bool)isAddingCompleted.GetValue(queue)!
                    && (producerExited.IsSet || IsBlocked(producer)),
                WaitTimeoutMilliseconds), "Finish must reach worker joining or exit.");
            Assert.IsFalse(producerExited.IsSet, "Finish must wait for the remaining worker.");
            releaseSlowWorker.Set();
            Assert.IsTrue(producer.Join(WaitTimeoutMilliseconds), "Finish must complete once all workers exit.");
            Assert.IsTrue(joinedBeforeReturning);
            if (cancelExternally)
            {
                Assert.IsInstanceOfType<OperationCanceledException>(producerException);
                Assert.AreEqual(cancellation.Token, ((OperationCanceledException)producerException!).CancellationToken);
            }
            else
            {
                Assert.AreSame(expectedException, producerException);
            }
        }
        finally
        {
            releaseFailure.Set();
            releaseSlowWorker.Set();
            cancellation.Cancel();
            JoinForCleanup(producer, pipeline);
        }
    }

    private static bool IsBlocked(Thread thread) =>
        (thread.ThreadState & ThreadState.WaitSleepJoin) != 0;

    private static void WaitForBlockedProducer(Thread producer)
    {
        Assert.IsTrue(SpinWait.SpinUntil(
            () => IsBlocked(producer) || !producer.IsAlive,
            WaitTimeoutMilliseconds), "The producer must reach its blocking operation.");
        Assert.IsTrue(producer.IsAlive, "The producer must still be running.");
        Assert.IsTrue(IsBlocked(producer), "The producer must be blocked on the full queue.");
    }

    private static T ReadField<T>(CandidateValidationPipeline pipeline, string name) =>
        (T)typeof(CandidateValidationPipeline)
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(pipeline)!;

    private static void JoinForCleanup(Thread producer, CandidateValidationPipeline pipeline)
    {
        Assert.IsTrue(producer.Join(WaitTimeoutMilliseconds), "Producer cleanup timed out.");
        Assert.IsTrue(Task.WaitAll(ReadField<Task[]>(pipeline, "_workers"), WaitTimeoutMilliseconds),
            "Worker cleanup timed out.");
    }
}