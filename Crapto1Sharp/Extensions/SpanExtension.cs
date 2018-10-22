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
        // wait Span.Sort() implement https://github.com/dotnet/corefx/issues/15329
        /// <summary>
        /// Quick Sort
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="span"></param>
        public static void Sort<T>(this Span<T> span)
        {
            if (span.Length <= 1)
                return;
            var it = 0;
            var rit = span.Length - 1;
            var comparer = Comparer<T>.Default;

            while (it < rit)
            {
                if (comparer.Compare(span[it], span[0]) <= 0)
                    ++it;
                else if (comparer.Compare(span[rit], span[0]) > 0)
                    --rit;
                else
                {
                    var t = span[it];
                    span[it] = span[rit];
                    span[rit] = t;
                }
            }

            if (comparer.Compare(span[rit], span[0]) >= 0)
                --rit;
            if (rit != 0)
            {
                var t = span[rit];
                span[rit] = span[0];
                span[0] = t;
            }
            
            span.Slice(0, rit).Sort();
            span.Slice(rit + 1).Sort();
        }
    }
}
