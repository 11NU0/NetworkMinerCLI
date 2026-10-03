using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class ContentRange {
        public long Start;
        public long End;//last index inside the content range, i.e. range length = end + 1 - start
        public long Total;
    }
}
