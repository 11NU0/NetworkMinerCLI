using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
//using System.Web.UI.WebControls;

namespace SharedUtils {

    /// <summary>
    /// A hash set that uses little memory by only storing some of the most recently added items
    /// </summary>
    public class LuckyHashSet<T> {
        private readonly T[] items;

        public int Size => items.Length;
        
        public LuckyHashSet(int size) {
            this.items = new T[size];
        }

        public LuckyHashSet(int size, params T[] items) : this(size) {
            this.Add(items);
        }

        private uint GetIndex(T item) {
            return (uint)(((uint)item.GetHashCode()) % items.Length);
        }

        public void Add(T item) {
            this.items[this.GetIndex(item)] = item;
        }

        public void Add(params T[] items) {
            foreach (T item in items)
                this.Add(item);
        }

        public bool Contains(T item) {
            //https://stackoverflow.com/a/864860
            if (EqualityComparer<T>.Default.Equals(item, default))
                return false;//we can't tell
            else
                return this.items[this.GetIndex(item)]?.Equals(item) == true;
        }

        

    }
}
