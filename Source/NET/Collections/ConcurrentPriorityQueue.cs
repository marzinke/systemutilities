/******************************************************************************
*	Copyright 2013 Prospective Software Inc.
*	Licensed under the Apache License, Version 2.0 (the "License");
*	you may not use this file except in compliance with the License.
*	You may obtain a copy of the License at
*
*		http://www.apache.org/licenses/LICENSE-2.0
*
*	Unless required by applicable law or agreed to in writing, software
*	distributed under the License is distributed on an "AS IS" BASIS,
*	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*	See the License for the specific language governing permissions and
*	limitations under the License.
******************************************************************************/

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;

namespace System.Collections.Concurrent
{
	/// <summary>
	/// An implementation of a concurrent priority queue
	/// </summary>
	/// <typeparam name="T">The type stored within the priority queue.</typeparam>
	public class ConcurrentPriorityQueue<T>
	{
		private readonly ConcurrentQueue<T>[] queues;

		/// <summary>
		/// Gets the number of priority queues contained in the ConcurrentPriorityQueue&lt;T&gt;.
		/// </summary>
		public ushort Queues { get; private set; }

		/// <summary>
		/// Gets the number of elements contained in the ConcurrentPriorityQueue&lt;T&gt;.
		/// </summary>
		public int Count
		{
			get
			{
				int c = 0;
				for (int i = 0; i < Queues; i++)
					c += queues[i].Count;
				return c;
			}
		}

		/// <summary>
		/// Gets a value that indicates whether the ConcurrentPriorityQueue&lt;T&gt; is empty.
		/// </summary>
		public bool IsEmpty
		{
			get
			{
				bool empty = false;
				for (int i = 0; i < Queues; i++)
					empty &= queues[i].IsEmpty;
				return empty;
			}
		}

		/// <summary>
		/// Constructor that takes a number of prioritized queues.
		/// </summary>
		/// <param name="Queues">The number of prioritized queues available in this instance</param>
		public ConcurrentPriorityQueue(ushort Queues)
		{
			this.Queues = Queues;
			queues = new ConcurrentQueue<T>[Queues];
		}

		/// <summary>
		/// Adds the item to the end of the specified priority queue.
		/// </summary>
		/// <param name="Priority">The priority queue to assign the item to.</param>
		/// <param name="Item">The item to add to the specified priority queue.</param>
		public void Enqueue(ushort Priority, T Item)
		{
			int p = Priority;
			if (Priority > Queues) p = Queues;
			queues[p].Enqueue(Item);
		}

		/// <summary>
		/// Tries to remove and return the object at the beginning of the each priority queue in descending priority until an object is found.
		/// </summary>
		/// <param name="Result">When this method returns, if the operation was successful, Result contains the object removed. If no object was available to be removed, the value is unspecified.</param>
		public bool TryDequeue(out T Result)
		{
			Result = default(T);
			for (int i = 0; i < Queues; i++)
				if (queues[i].TryDequeue(out Result)) return true;
			return false;
		}

		/// <summary>
		/// Tries to return the object at the beginning of the each priority queue in descending priority until an object is found.
		/// </summary>
		/// <param name="Result">When this method returns, if the operation was successful, Result contains the object removed. If no object was available to be removed, the value is unspecified.</param>
		public bool TryPeek(out T Result)
		{
			Result = default(T);
			for (int i = 0; i < Queues; i++)
				if (queues[i].TryPeek(out Result)) return true;
			return false;
		}

		/// <summary>
		/// Copies the ConcurrentPriorityQueue&lt;T&gt; elements to an existing one-dimensional Array, starting at the specified array index.
		/// </summary>
		/// <param name="array">The one-dimensional Array that is the destination of the elements copied from the ConcurrentPriorityQueue&lt;T&gt;. The Array must have zero-based indexing.</param>
		/// <param name="index">The zero-based index in array at which copying begins.</param>
		public void CopyTo(T[] array, int index)
		{
			var items = new List<T>();
			for (int i = 0; i < Queues; i++)
				items.AddRange(queues[i].ToArray());
			int ic = items.Count;
			for (int i = index; i < ic + index; i++)
				array[i] = items[i - index];
		}

		/// <summary>
		/// Copies the ConcurrentPriorityQueue&lt;T&gt; elements to a new Array.
		/// </summary>
		public T[] ToArray()
		{
			var items = new List<T>();
			for (int i = 0; i < Queues; i++)
				items.AddRange(queues[i].ToArray());
			return items.ToArray();
		}

		/// <summary>
		/// Returns an enumerator that iterates through the ConcurrentPriorityQueue&lt;T&gt;.
		/// </summary>
		public IEnumerator<T> GetEnumerator()
		{
			return ((IList<T>) (ToArray())).GetEnumerator();
		}
	}
}