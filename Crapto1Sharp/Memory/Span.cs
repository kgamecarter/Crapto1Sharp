using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Crapto1Sharp.Memory;
#if NET462
internal readonly ref struct Span<T>
{
    private readonly T[] _array;
    private readonly int _offset;
    private readonly int _length;
    
    public T[] Array { [MethodImpl(MethodImplOptions.AggressiveInlining)]get => _array; }

    public int Offset { [MethodImpl(MethodImplOptions.AggressiveInlining)]get => _offset; }
    
    public int Length { [MethodImpl(MethodImplOptions.AggressiveInlining)]get => _length; }

    public ref T this[int key]
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get
        {
            return ref _array[key + _offset];
        }
    }

    public Span(T[] array) : this(array, 0, array.Length)
    { }

    public Span(T[] array, int offset, int length)
    {
        _array = array;
        _offset = offset;
        _length = length;
    }

    public Span<T> Slice(int start)
    {
        return new Span<T>(_array, _offset + start, _length - start);
    }

    public Span<T> Slice(int start, int length)
    {
        return new Span<T>(_array, _offset + start, length);
    }

    public int BinarySearch(T value)
    {
        return System.Array.BinarySearch(_array, _offset, _length, value);
    }

    public void Sort()
    {
        System.Array.Sort(_array, _offset, _length);
    }

    public static implicit operator Span<T>(T[] array)
    {
        return new Span<T>(array);
    }
}
#endif
