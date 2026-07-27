using System.Threading;

namespace Crapto1Sharp;

/// <summary>
/// Controls workspace reuse, parallelism, and cancellation for key recovery.
/// </summary>
public sealed class MfKeyExecutionOptions
{
    /// <summary>
    /// Optional reusable recovery workspace. It must not be used concurrently.
    /// </summary>
    public Crypto1RecoveryWorkspace? Workspace { get; set; }

    /// <summary>
    /// Maximum validation parallelism. Use -1 for the default.
    /// </summary>
    public int MaxDegreeOfParallelism { get; set; } = -1;

    /// <summary>
    /// Gets or sets the token used to cancel recovery and candidate validation.
    /// </summary>
    public CancellationToken CancellationToken { get; set; }

    /// <summary>
    /// Validates the configured degree of parallelism and resolves the number of
    /// synchronous or background validation workers.
    /// </summary>
    /// <returns>The number of validation execution slots.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// <see cref="MaxDegreeOfParallelism"/> is neither -1 nor a positive value.
    /// </exception>
    internal int GetWorkerCount()
    {
        if (MaxDegreeOfParallelism != -1 && MaxDegreeOfParallelism <= 0)
            throw new System.ArgumentOutOfRangeException(
                nameof(MaxDegreeOfParallelism),
                "MaxDegreeOfParallelism must be -1 or a positive integer.");

        if (MaxDegreeOfParallelism == 1)
            return 1;
        if (MaxDegreeOfParallelism > 1)
            return MaxDegreeOfParallelism - 1;
        return System.Math.Max(1, System.Environment.ProcessorCount - 1);
    }
}
