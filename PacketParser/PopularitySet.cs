using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser {
    public class PopularitySet<T> {

        private readonly PopularityList<T, bool> popularityList;

        public int Count => this.popularityList.Count;

        public PopularitySet(int maxPoolSize) {
            this.popularityList = new PopularityList<T, bool>(maxPoolSize);
        }

        public void Add(T item) {
            this.popularityList.Add(item, true);
        }

        public void Clear() {
            this.popularityList.Clear();
        }

        public bool Contains(T item) {
            return this.popularityList.ContainsKey(item);
        }

        public IEnumerable<T> GetEnumerator() {
            return this.popularityList.GetKeyEnumerator();
        }

        public void Remove(T item) {
            this.popularityList.Remove(item);
        }


    }
}
