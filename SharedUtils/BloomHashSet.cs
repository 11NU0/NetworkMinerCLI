using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedUtils {

    /// <summary>
    /// A mix of Bloom filter and HashSet to get the best of both worlds, when possible
    /// </summary>
    public class BloomHashSet : BloomFilter {

        private const long MAX_WORDS_IN_HASH_SET = 100000;//100k
        private const long MAX_CHARS_IN_HASH_SET = 1000000;//1M

        private HashSet<string> hashSet = null;
        private long CharCount;

        public BloomHashSet(ICollection<string> wordList, bool caseSensitive = false) : base(wordList, caseSensitive) {
            this.hashSet = new HashSet<string>();
            this.CharCount = 0;
        }

        public BloomHashSet(long wordListSizeEstimate, bool caseSensitive = false) : base(wordListSizeEstimate, caseSensitive) {
            this.hashSet = new HashSet<string>();
            this.CharCount = 0;
        }

        public bool TryGetWords(out IReadOnlyCollection<string> wordCollection) {
            wordCollection = this.hashSet?.ToList();
            return this.hashSet != null;
        }

        public override void AddWord(string word) {
            if(this.hashSet != null) {
                if (base.WordCount > MAX_WORDS_IN_HASH_SET)
                    this.hashSet = null;
                else if(this.CharCount > MAX_CHARS_IN_HASH_SET)
                    this.hashSet = null;
                else {
                    if(base.CaseSensitive)
                        this.hashSet.Add(word);
                    else
                        this.hashSet.Add(word.ToLower());
                    this.CharCount += word.Length;
                }
            }
            
            base.AddWord(word);
        }

        public override void Clear() {
            base.Clear();
            this.CharCount = 0;
            if(this.hashSet == null)
                this.hashSet = new HashSet<string>();
            else
                this.hashSet.Clear();
        }

        public override bool HasWord(string word) {
            if (base.HasWord(word)) {
                if (hashSet == null)
                    return true;//we don't have a HashSet so we can't know for sure
                else if(base.CaseSensitive)
                    return hashSet.Contains(word);
                else
                    return hashSet.Contains(word.ToLower());
            }
            else
                return false;

        }
    }
}
