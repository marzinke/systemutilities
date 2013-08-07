using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace System.Collections
{
	public static class BitArrayExtensions
	{
		public static byte[] ToByteArray(this BitArray bits)
		{
			var ret = new byte[(bits.Length - 1) / 8 + 1];
			bits.CopyTo(ret, 0);
			return ret;
		}
	}
}