using System;
using System.Collections.Generic;

namespace System.Text
{
	public class StringFormatter
	{
		public List<char> chrs;

		public StringFormatter()
		{
			chrs = new List<char>(1024);
		}

		public StringFormatter(string InitialValue)
		{
			chrs = new List<char>(InitialValue.ToCharArray());
		}

		public StringFormatter(int InitialCapacity)
		{
			chrs = new List<char>(InitialCapacity);
		}

		public override string ToString()
		{
			return new string(chrs.ToArray());
		}

		public string ToString(int Start, int Length)
		{
			return new string(chrs.GetRange(Start, Length).ToArray());
		}

		public void Append<T>(T value)
		{
			chrs.AddRange(value.ToString().ToCharArray());
		}

		public void AppendLine()
		{
			chrs.AddRange(Environment.NewLine.ToCharArray());
		}

		public void AppendLine<T>(T value)
		{
			chrs.AddRange(value.ToString().ToCharArray());
			chrs.AddRange(Environment.NewLine.ToCharArray());
		}

		public void AppendFormat(string Format, params object[] Values)
		{
			chrs.AddRange(string.Format(Format, Values).ToCharArray());
		}

		public void AppendFormatLine(string Format, params object[] Values)
		{
			chrs.AddRange(string.Format(Format, Values).ToCharArray());
			chrs.AddRange(Environment.NewLine.ToCharArray());
		}
		
		public void Insert<T>(int Index, T value)
		{
			chrs.InsertRange(Index, value.ToString().ToCharArray());
		}

		public void InsertLine<T>(int Index, T value)
		{
			chrs.InsertRange(Index, value.ToString().ToCharArray());
			chrs.AddRange(Environment.NewLine.ToCharArray());
		}

		public void InsertFormat(int Index, string Format, params object[] Values)
		{
			chrs.InsertRange(Index, string.Format(Format, Values).ToCharArray());
		}

		public void InsertFormatLine(int Index, string Format, params object[] Values)
		{
			chrs.InsertRange(Index, string.Format(Format, Values).ToCharArray());
			chrs.AddRange(Environment.NewLine.ToCharArray());
		}

		public void InsertAfterLine<T>(int Index, T value)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i < cc; i++)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }
			
			chrs.InsertRange(ic, value.ToString().ToCharArray());
		}

		public void InsertLineAfterLine<T>(int Index, T value)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i < cc; i++)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, (value + Environment.NewLine).ToCharArray());
		}

		public void InsertFormatAfterLine(int Index, string Format, params object[] Values)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i < cc; i++)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }
			
			chrs.InsertRange(ic, string.Format(Format, Values).ToCharArray());
		}

		public void InsertFormatLineAfterLine(int Index, string Format, params object[] Values)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i < cc; i++)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, string.Format(Format + Environment.NewLine, Values).ToCharArray());
		}

		public void InsertBeforeLine<T>(int Index, T value)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i >= 0; i--)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, value.ToString().ToCharArray());
		}

		public void InsertLineBeforeLine<T>(int Index, T value)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i >= 0; i--)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, (value + Environment.NewLine).ToCharArray());
		}

		public void InsertFormatBeforeLine(int Index, string Format, params object[] Values)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i >= 0; i--)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, string.Format(Format, Values).ToCharArray());
		}

		public void InsertFormatLineBeforeLine(int Index, string Format, params object[] Values)
		{
			int cc = chrs.Count;
			int ic = 0;
			int nlc = Environment.NewLine.Length;
			char[] nlca = Environment.NewLine.ToCharArray();
			for (int i = Index; i >= 0; i--)
				if (nlc == 2 && chrs[i] == nlca[0] && chrs[i + 1] == nlca[1]) { ic = i + nlc; break; }
				else if (nlc == 1 && chrs[i] == nlca[0]) { ic = i + nlc; break; }

			chrs.InsertRange(ic, string.Format(Format + Environment.NewLine, Values).ToCharArray());
		}

		public void Remove(int Index, int Length)
		{
			chrs.RemoveRange(Index, Length);
		}

		public void Replace(char OldValue, char NewValue)
		{
			var t = new string(chrs.ToArray());
			chrs = new List<char>(t.Replace(OldValue, NewValue).ToCharArray());
		}

		public void Replace(string OldValue, string NewValue)
		{
			var t = new string(chrs.ToArray());
			chrs = new List<char>(t.Replace(OldValue, NewValue).ToCharArray());
		}
	}
}