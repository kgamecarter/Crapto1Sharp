using System;
using System.Collections.Generic;
using System.Text;

namespace Crapto1Sharp.Memory
{
#if NET45
    internal struct Span<T>
    {
        public T[] Array { get; set; }

        public int Offset { get; set; }

        public int Length { get; set; }

        public ref T this[int key] => ref Array[key + Offset];

        public Span<T> Slice(int start)
        {
            return new Span<T>()
            {
                Array = Array,
                Offset = Offset + start,
                Length = Length - start
            };
        }

        public Span<T> Slice(int start, int length)
        {
            return new Span<T>()
            {
                Array = Array,
                Offset = Offset + start,
                Length = length
            };
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
            return new Span<T>()
            {
                Array = array,
                Offset = 0,
                Length = array.Length
            };
        }
    }
#endif
}
