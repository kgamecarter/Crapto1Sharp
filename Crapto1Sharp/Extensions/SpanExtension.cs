using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
#if NET462
using Crapto1Sharp.Memory;
#endif

namespace Crapto1Sharp.Extensions;

internal static class SpanExtension
{
#if !NET462 && !NET10
    /// <summary>
    /// Quick Sort - 直接在 Span 上排序，避免額外記憶體分配
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="span"></param>
    public static void Sort<T>(this Span<T> span) where T : IComparable<T>
    {
        if (span.Length <= 1)
            return;
        QuickSort(span, 0, span.Length - 1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuickSort<T>(Span<T> span, int low, int high) where T : IComparable<T>
    {
        if (low < high)
        {
            int pi = Partition(span, low, high);
            QuickSort(span, low, pi - 1);
            QuickSort(span, pi + 1, high);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Partition<T>(Span<T> span, int low, int high) where T : IComparable<T>
    {
        T pivot = span[high];
        int i = low - 1;
        T tmp;
        for (int j = low; j < high; j++)
        {
            if (span[j].CompareTo(pivot) < 0)
            {
                i++;
                tmp = span[i];
                span[i] = span[j];
                span[j] = tmp;
            }
        }
        tmp = span[i + 1];
        span[i + 1] = span[high];
        span[high] = tmp;
        return i + 1;
    }
#endif

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BinarySearch(this Span<uint> span)
    {
        int start = 0, stop = span.Length - 1, mid;
        uint val = span[stop] & 0xff000000;
        while (start != stop)
            if (span[start + (mid = (stop - start) >> 1)] > val)
                stop = start + mid;
            else
                start += mid + 1;
        return start;
    }
}
