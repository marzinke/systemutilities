using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System
{
	public class ConsoleEx
	{
		public bool IsInteractive { get; private set; }

		public ConsoleEx(bool IsInteractive = false)
		{
			this.IsInteractive = IsInteractive;
		}
	}
}