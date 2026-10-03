using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;

namespace SharedUtils {
    //http://en.wikipedia.org/wiki/Bloom_filter
    public class BloomFilter {
        private protected readonly BitArray bitArray;
        private protected readonly int nHashFunctions;
        private protected readonly int indexMask;

        private const int DEFAULT_BITS_PER_ELEMENT = 15;

        public bool CaseSensitive { get; }
        public long WordCount { get; private set; }

        public BloomFilter(ICollection<string> wordList, bool caseSensitive = false, int bitsPerElement = DEFAULT_BITS_PER_ELEMENT) : this(wordList.Count, caseSensitive, bitsPerElement) {
            foreach (string s in wordList)
                this.AddWord(s);
        }

        public BloomFilter(long wordListSizeEstimate, bool caseSensitive = false, int bitsPerElement = DEFAULT_BITS_PER_ELEMENT) {
            this.CaseSensitive = caseSensitive;
            this.WordCount = 0;
            //to acheive 1% error we need "array size"/"#elements" = 9.6
            int indexValueBits = 0;
            //while(1<<indexValueBits < 9.6*wordList.Count)
            while (1 << indexValueBits < bitsPerElement * wordListSizeEstimate)//14*wordList.Count gives 0.1% of false positives
                indexValueBits++;
            indexValueBits++;//since we started with one bit...
            int indexSize = 1 << (indexValueBits - 1);
            this.indexMask = indexSize - 1;

            this.bitArray = new BitArray(indexSize, false);//2^24 bits = 16MByte
            if (wordListSizeEstimate == 0)
                this.nHashFunctions = 1;
            else
                this.nHashFunctions = (int)(0.7 * indexSize / wordListSizeEstimate);
        }

        public double CalculateOverlap(BloomFilter other) {
            if (this.indexMask != other.indexMask || this.nHashFunctions != other.nHashFunctions)
                throw new Exception("Incompatible bloom filters");
            if (this.WordCount < other.WordCount)
                return other.CalculateOverlap(this);
            else if (other.WordCount == 0)
                return 0;
            else {
                long setBitCount = 0;
                long collisions = 0;
                for (int i = 0; i < this.bitArray.Count; i++) {
                    if (this.bitArray[i]) {
                        setBitCount++;
                        if (other.bitArray[i])
                            collisions++;
                    }
                }
                if (setBitCount >= this.bitArray.Count)
                    throw new Exception("Bloom filter is full");
                double fillRate = (1.0 * setBitCount) / this.bitArray.Count;
                double expectedRandomCollisions = other.WordCount * fillRate;
                //no collisions in bit array => 0% overlap
                //expectedRandomCollisions => 0% overlap
                //there is always a fillRate risk of collision in random data
                //all other in bit array in this bit array => 100% overlap
                if (collisions < expectedRandomCollisions)
                    return 0;
                return (collisions - expectedRandomCollisions) / (other.WordCount - expectedRandomCollisions);
            }
        }

        public void MergeWith(BloomFilter other) {
            this.bitArray.Xor(other.bitArray);
            this.WordCount += other.WordCount;
        }

        public virtual bool HasWord(string word) {
            int[] indexes = this.GetIndexes(word);
            foreach (int index in indexes)
                if (!this.bitArray[index])
                    return false;
            return true;
        }

        private protected virtual int[] GetIndexes(string word) {
            if (!this.CaseSensitive)
                word = word.ToLower();

            int[] indexes = new int[nHashFunctions];

            //simple hash method
            for (int i = 0; i < indexes.Length; i++) {
                //string.GetHashCode() can give different outputs on different systems
                int hash = (word + i.ToString()).GetHashCode();
                indexes[i] = (hash * i * 7) & this.indexMask;
            }
            return indexes;
        }

        /// <summary>
        /// Adds word unless the filter is full
        /// </summary>
        /// <param name="word"></param>
        /// <returns>True if word is added, false if the filter is full</returns>
        public bool TryAddWord(string word) {
            if (this.WordCount < this.bitArray.Count / 2) {
                this.AddWord(word);
                return true;
            }
            else
                return false;
        }

        public virtual void AddWord(string word) {
            int[] indexes= this.GetIndexes(word);
            foreach (int index in indexes)
                this.bitArray[index] = true;
            this.WordCount++;
        }

        public virtual void Clear() {
            this.bitArray.SetAll(false);
            this.WordCount = 0;
        }

    }
}
