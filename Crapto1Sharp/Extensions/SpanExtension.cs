using System;
using System.Collections.Generic;
using System.Text;
#if NET45
using Crapto1Sharp.Memory;
#endif

namespace Crapto1Sharp.Extensions
{
    internal static class SpanExtension
    {
#if !NET45
        // wait Span.Sort() implement https://github.com/dotnet/corefx/issues/15329
        /// <summary>
        /// Quick Sort
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="span"></param>
        public static void Sort<T>(this Span<T> span)
        {
            var a = span.ToArray();
            Array.Sort(a);
            a.CopyTo(span);
        }
#endif

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
}
