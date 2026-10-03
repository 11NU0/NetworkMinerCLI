using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
//using System.Web.UI.WebControls;
using System.Xml;
using System.Xml.Linq;
using PacketParser.Utils;

namespace PacketParser.Packets {
    public class RmsPacket : AbstractPacket, ISessionPacket {
        //Remote Manipulator System (RMS) developed by Russian organization TektonIT

        internal ulong? NextSegmentLength { get; private set; }

        public XDocument Payload { get; private set; } = null;

        public bool PacketHeaderIsComplete { get; private set; } = false;

        public int ParsedBytesCount { get; private set; }

        private static readonly byte[] UTF8_BYTE_ORDER_MARK = { 0xef, 0xbb, 0xbf };//Same as Encoding.UTF8.GetPreamble();
        private static readonly byte[] XML_HEADER = { 0x3c, 0x3f, 0x78, 0x6d };

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            if (packetEndIndex - packetStartIndex == 7) {
                try {
                    ulong nextSegmentLength = ByteConverter.ToUInt64(parentFrame.Data, packetStartIndex, true);
                    if (nextSegmentLength > 0 && nextSegmentLength < 1024 * 1024) { //max 1MB
                        result = new RmsPacket(parentFrame, packetStartIndex, packetEndIndex);
                        return true;
                    }
                }
                catch { }
            }
            else if (parentFrame.Data.StartsWith(UTF8_BYTE_ORDER_MARK, packetStartIndex) || parentFrame.Data.StartsWith(XML_HEADER, packetStartIndex)) {
                try {
                    result = new RmsPacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;

                }
                catch { }
            }
            result = null;
            return false;
        }


        private RmsPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "RMS") {
            if(this.PacketLength == 8) {
                //the first packet is an 8 byte length packet
                this.NextSegmentLength = Utils.ByteConverter.ToUInt64(parentFrame.Data, packetStartIndex, true);
                if (this.NextSegmentLength > 0 && this.NextSegmentLength < 1024 * 1024) { //max 1MB
                    this.PacketHeaderIsComplete = true;
                    this.ParsedBytesCount = 8;
                }
            }
            else if(parentFrame.Data.StartsWith(UTF8_BYTE_ORDER_MARK, packetStartIndex)) {
                string xmlPayload = Encoding.UTF8.GetString(parentFrame.Data, packetStartIndex, this.PacketLength);

                xmlPayload = Utils.StringManglerUtil.StripUtf8ByteMark(xmlPayload);
                this.Payload = XDocument.Parse(xmlPayload);
                this.PacketHeaderIsComplete = true;
                this.ParsedBytesCount = this.PacketLength;
            }
            else if(parentFrame.Data.StartsWith(XML_HEADER, packetStartIndex)) {
                string xmlPayload = Encoding.UTF8.GetString(parentFrame.Data, packetStartIndex, this.PacketLength);
                this.Payload = XDocument.Parse(xmlPayload);
                this.PacketHeaderIsComplete = true;
                this.ParsedBytesCount = this.PacketLength;
            }
            
        }
        

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
