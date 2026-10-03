using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Utils {
    public static class Extensions {

        public static bool StartsWith(this byte[] self, byte[] signature, int offset = 0) {
            if (signature.Length > self.Length - offset)
                return false;
            else
                return self.Skip(offset).Take(signature.Length).SequenceEqual(signature);
        }

        public static int IndexOf(this byte[] self, byte[] signature, int offset = 0) {
            return BoyerMoore.IndexOf(self, signature, offset);
        }

        public static long ReadTo(this Stream stream, byte[] signature, out List<byte> readBytes) {
            return KnuthMorrisPratt.ReadTo(signature, stream, out readBytes);
        }
    }
}
