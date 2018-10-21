using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Extensions
{
    public static class SpanExtension
    {
        // wait Span.Sort() implement https://github.com/dotnet/corefx/issues/15329 
        public static void Sort<T>(this Span<T> span)
        {
            var array = span.ToArray();
            Array.Sort(array);
            array.CopyTo(span);
        }
    }
}
