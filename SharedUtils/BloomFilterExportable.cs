using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils
{

    /// <summary>
    /// An exportable version of BloomFilter, which has about the same hash performance as the original BloomFilter
    /// </summary>
    public class BloomFilterExportable : BloomFilter, IDisposable {

        //private Func<HashAlgorithm> hashCreator;
        private const int DEFAULT_BITS_PER_ELEMENT = 15;//changing this breaks imports of previous bloom filters
        private int hashOffsetMultiplicator = 4;
        private HashAlgorithm algo;

        public BloomFilterExportable(ICollection<string> wordList, bool caseSensitive = false) : base(wordList, caseSensitive, DEFAULT_BITS_PER_ELEMENT) {
            this.InitHashCreator();
        }

        public BloomFilterExportable(long wordListSizeEstimate, bool caseSensitive = false) : base(wordListSizeEstimate, caseSensitive, DEFAULT_BITS_PER_ELEMENT) {
            this.InitHashCreator();
        }

        private void InitHashCreator() {
            //MD5 => 16 bytes (4 ints)
            //SHA256 => 32 bytes (8 ints) : 31 is prime!
            //SHA384 => 48 bytes (12 ints) : 47 is prime!
            //SHA512 => 64 bytes (16 ints)
            if (base.nHashFunctions <= 4)//often 14 hash algorithms
                this.algo = MD5.Create();
            else if (base.nHashFunctions <= 8)
                this.algo = SHA256.Create();
            else if (base.nHashFunctions <= 12)
                this.algo = SHA384.Create();
            else if (base.nHashFunctions <= 16)
                this.algo = SHA512.Create();
            else if (base.nHashFunctions <= 64) {
                this.algo = SHA512.Create();
                this.hashOffsetMultiplicator = 5;//5 is relative prime to 64
            }
            else
                throw new Exception("Too many hash functions. Not enough hash data, SHA512 produces 64 bytes output.");
        }

        private protected override int[] GetIndexes(string word) {
            if (!this.CaseSensitive)
                word = word.ToLower();

            int[] indexes = new int[base.nHashFunctions];
            byte[] hash = this.algo.ComputeHash(Encoding.UTF8.GetBytes(word));
            for (int i = 0; i < indexes.Length; i++) {
                int hashIndex = i * this.hashOffsetMultiplicator;
                indexes[i] = (hash[hashIndex % hash.Length] << 24 | hash[(hashIndex + 1) % hash.Length] << 16 | hash[(hashIndex + 2) % hash.Length] << 8 | hash[(hashIndex + 3) % hash.Length]) & this.indexMask;
            }
            return indexes;
        }

        public string ExportAsBase64() {
            byte[] bytes = new byte[base.bitArray.Length/8];
            base.bitArray.CopyTo(bytes, 0);
            return Convert.ToBase64String(bytes);
        }

        public static BloomFilterExportable CreateFromBase64(string base64, long wordListSizeEstimate, bool caseSensitive = false) {
            byte[] bytes = Convert.FromBase64String(base64);
            BitArray importedBitArray = new BitArray(bytes);

            var filter = new BloomFilterExportable(wordListSizeEstimate, caseSensitive);
            filter.bitArray.Or(importedBitArray);
            return filter;
        }

        public void Dispose() {
            this.algo.Dispose();
        }
    }
}
