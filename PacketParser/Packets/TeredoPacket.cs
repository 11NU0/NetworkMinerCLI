using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Packets {
    internal class TeredoPacket : AbstractPacket {

        private readonly int nextPacketIndex;
        private ushort? originPort = null;
        private IPAddress originIP = null;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out TeredoPacket teredoPacket) {
            teredoPacket = null;
            if (packetEndIndex - packetStartIndex < 13)
                return false;
            //Authentication header starts with 0x00 0x01
            if (parentFrame.Data[packetStartIndex] != 0x00)
                return false;
            if (parentFrame.Data[packetStartIndex+1] > 0x01)//must be 0 or 1
                return false;

            try {
                teredoPacket = new TeredoPacket(parentFrame, packetStartIndex, packetEndIndex);
                return true;
            }
            catch (Exception e) {
                SharedUtils.Logger.Log("Exception when parsing frame " + parentFrame.FrameNumber + " as Teredo packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                return false;
            }
        }


        private TeredoPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Teredo") {
            nextPacketIndex = packetStartIndex;

            if (parentFrame.Data[packetStartIndex] != 0x00)
                throw new Exception("Incorrect Teredo format");

            if (parentFrame.Data[packetStartIndex + 1] == 0x00) {
                /**
                 * 
                   +------+-----+-------------------+-------------+
                   | IPv4 | UDP | Origin indication | IPv6 packet |
                   +------+-----+-------------------+-------------+
                **/
                nextPacketIndex += this.ParseOriginHeader(parentFrame, nextPacketIndex);

            }
            if (parentFrame.Data[packetStartIndex + 1] == 0x01) {
                /**
                 *    +------+-----+----------------+-------------+
                      | IPv4 | UDP | Authentication | IPv6 packet |
                      +------+-----+----------------+-------------+
               */
                nextPacketIndex += this.ParseAuthenticationHeader(parentFrame, nextPacketIndex);
                /*
                      +------+-----+----------------+--------+-------------+
                      | IPv4 | UDP | Authentication | Origin | IPv6 packet |
                      +------+-----+----------------+--------+-------------+
                **/
                if (parentFrame.Data[nextPacketIndex] == 0x00 && parentFrame.Data[nextPacketIndex + 1] == 0x00)
                    nextPacketIndex += this.ParseOriginHeader(parentFrame, nextPacketIndex);
            }
            else
                throw new Exception("Incorrect Teredo format");
        }

        private int ParseOriginHeader(Frame parentFrame, int headerStartIndex) {
            /**
             * 
               +--------+--------+-----------------+
               |  0x00  | 0x00   | Origin port #   |
               +--------+--------+-----------------+
               |  Origin IPv4 address              |
               +-----------------------------------+
            */
            this.originPort = Utils.ByteConverter.ToUInt16(this.GetXorValues(parentFrame.Data, headerStartIndex + 2, 2));
            this.originIP = new IPAddress(this.GetXorValues(parentFrame.Data, headerStartIndex + 4, 4));
            return 8;
        }

        private byte[] GetXorValues(byte[] data, int offset, int length) {
            byte[] result = new byte[length];
            for (int i = 0; i < length; i++) {
                result[i] = (byte)(data[offset + i] ^ 0xff);
            }
            return result;
        }

        private int ParseAuthenticationHeader(Frame parentFrame, int headerStartIndex) { 

            /**
              *    +--------+--------+--------+--------+
                   |  0x00  | 0x01   | ID-len | AU-len |
                   +--------+--------+--------+--------+
                   |  Client identifier (ID-len        |
                   +-----------------+-----------------+
                   |  octets)        |  Authentication |
                   +-----------------+--------+--------+
                   | value (AU-len octets)    | Nonce  |
                   +--------------------------+--------+
                   | value (8 octets)                  |
                   +--------------------------+--------+
                   |                          | Conf.  |
                   +--------------------------+--------+
            **/


            byte clientIdentifierLength = parentFrame.Data[headerStartIndex + 2];
            byte authenticationValueLength = parentFrame.Data[headerStartIndex + 3];
            //skip identifier and authentication
            int headerLength = 4 + clientIdentifierLength + authenticationValueLength;
            //skip 8 bit nounce
            headerLength += 8;
            //skip confirmation byte
            headerLength += 1;
            return headerLength;
        }
        
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if(this.nextPacketIndex > this.PacketStartIndex) {
                yield return new IPv6Packet(this.ParentFrame, this.nextPacketIndex, this.PacketEndIndex);
            }
        }
    }
}
