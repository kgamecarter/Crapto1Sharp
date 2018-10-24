using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Crapto1Sharp.Memory
{
#if NET45
    internal readonly ref struct Span<T>
    {
        public T[] Array { get; }

        public int Offset { get; }

        public int Length { get; }

        public ref T this[int key]
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get
            {
                return ref Array[key + Offset];
            }
        }

        public Span(T[] array) : this(array, 0, array.Length)
        { }

        public Span(T[] array, int offset, int length)
        {
            Array = array;
            Offset = offset;
            Length = length;
        }

        public Span<T> Slice(int start)
        {
            return new Span<T>(Array, Offset + start, Length - start);
        }

        public Span<T> Slice(int start, int length)
        {
            return new Span<T>(Array, Offset + start, length);
        }

        public int BinarySearch(T value)
        {
            return System.Array.BinarySearch(Array, Offset, Length, value);
        }

        public void Sort()
        {
            System.Array.Sort(Array, Offset, Length);
        }

        public static implicit operator Span<T>(T[] array)
        {
            return new Span<T>(array);
        }
    }
#endif
}
