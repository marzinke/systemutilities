using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Console
{
	public abstract class ConsoleExModule
	{
		public string Verb { get; protected set; }

		protected ConsoleExModule(string Verb)
		{
			this.Verb = Verb;
		}
	}
}