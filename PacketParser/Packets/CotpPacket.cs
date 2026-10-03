using Microsoft.SqlServer.Server;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using static PacketParser.Packets.CotpPacket;

namespace PacketParser.Packets {
    public class CotpPacket : AbstractPacket{


        public enum PayloadProtocol { RDP, S7Comm }

        /*
        CR TPDU          Connection request TPDU        0xe
        CC TPDU          Connection confirm TPDU        0xd
        DR TPDU          Disconnect request TPDU        0x8
        DC TPDU          Disconnect confirm TPDU        0xa
        DT TPDU          Data TPDU                      0xf
        ED TPDU          Expedited data TPDU            0x1
        AK TPDU          Data acknowledge TPDU          0x6
        EA TPDU          Expedited acknowledge TPDU     0x2
        RJ TPDU          Reject TPDU                    0x5
        ER TPDU          Error TPDU                     0x7
        */
        public enum Tpdu : byte {
            ConnectionRequest = 0xe,
            ConnectionConfirm = 0xd,
            DisconnectRequest = 0x8,
            DisconnectConfirm = 0xa,
            Data = 0xf,
            ExpeditedData = 0x1,
            DataAcknowledge = 0x6,
            ExpeditedAcknowledge = 0x2,
            Reject = 0x5,
            Error = 0x7,

            UNKNOWN = 0xff
        }


        public enum ParameterCode : byte {
            ACK_TIME = 0x85,
            RES_ERROR = 0x86,
            PRIORITY = 0x87,
            TRANSIT_DEL = 0x88,
            THROUGHPUT = 0x89,
            SEQ_NR = 0x8a,
            REASSIGNMENT = 0x8b,
            FLOW_CNTL = 0x8c,
            TPDU_SIZE = 0xc0,
            SRC_TSAP = 0xc1,
            DST_TSAP = 0xc2,
            CHECKSUM = 0xc3,
            VERSION_NR = 0xc4,
            PROTECTION = 0xc5,
            OPT_SEL = 0xc6,
            PROTO_CLASS = 0xc7,
            CLEARING_INFO = 0xe0,
            PREF_MAX_TPDU_SIZE = 0xf0,
            INACTIVITY_TIMER = 0xf2,
            ATN_EC_32 = 0x08,
            ATN_EC_16 = 0x09,
        }

        private byte length;
        private byte pduType;
        private byte tpduNumber;
        public PayloadProtocol EncapsulatedProtocol;
        private byte pduClass;

        /// <summary>
        /// When set to ONE, indicates that the  current  DT
        /// TPDU is the last data unit of a complete DT TPDU
        /// sequence (End of TSDU).  EOT is bit 8 of octet 3
        /// in  class  0  and 1, bit 8 of octet 5 for normal
        /// formats for classes 2, 3 and  4  and  bit  8  of
        /// octet 8 for extended formats;
        /// </summary>
        public bool EndOfTsdu { get; private set; }//last segment

        public Tpdu GetTpdu() {
            if (Enum.IsDefined(typeof(Tpdu), (byte)(this.pduType >> 4)))
                return (Tpdu)(this.pduType >> 4);
            else
                return Tpdu.UNKNOWN;
        }

        //https://www.rfc-editor.org/rfc/rfc905.html
        internal CotpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, PayloadProtocol encapsulatedProtocol)
            : base(parentFrame, packetStartIndex, packetEndIndex, "ISO/IEC 8073/X.224 COTP") {


            this.EncapsulatedProtocol = encapsulatedProtocol;
            this.length = parentFrame.Data[packetStartIndex];
            this.pduType = parentFrame.Data[packetStartIndex + 1];
            this.tpduNumber = (byte)(parentFrame.Data[packetStartIndex + 2] & 0x7f);
            this.EndOfTsdu = parentFrame.Data[packetStartIndex + 2] >= 0x80;
            //TODO: Reassemble COTP segments
            if (EndOfTsdu && this.GetTpdu() != Tpdu.Data) {
                /**
                 * 
                 *    This field contains the TPDU code and is contained in octet 2  of
                 *     the  header.  It is used to define the structure of the remaining
                 *     header.  This field is a  full  octet  except  in  the  following
                 *     cases:
                 *            1110 xxxx     Connection Request      0xe
                 *            1101 xxxx     Connection Confirm      0xd
                 *            0101 xxxx     Reject                  0x5
                 *            0110 xxxx     Data Acknowledgement    0x6
                 */
                this.pduClass = (byte)(parentFrame.Data[packetStartIndex + 6] & 0xf0);
            }
        }

        //Handles fragmented segments
        public bool TryGetTsduData(out byte[] data) {
            if (this.GetTpdu()  == Tpdu.Data) {
                data = this.ParentFrame.Data.Skip(this.PacketStartIndex + 3).Take(this.PacketLength - 3).ToArray();
                return true;
            }
            data = null;
            return false;
        }

        public bool TryGetVariablePartIndex(out int variablePartIndex) {
            //https://www.rfc-editor.org/rfc/rfc905

            variablePartIndex = -1;

            Tpdu tpdu = this.GetTpdu();
            if (tpdu == Tpdu.ConnectionRequest) {
                /**
                 * The structure of the CR TPDU shall be as follows:
   
                  1    2        3        4       5   6    7    8    p  p+1...end
                 +--+------+---------+---------+---+---+------+-------+---------+
                 |LI|CR CDT|     DST - REF     |SRC-REF|CLASS |VARIAB.|USER     |
                 |  |1110  |0000 0000|0000 0000|   |   |OPTION|PART   |DATA     |
                 +--+------+---------+---------+---+---+------+-------+---------+
                        */
                variablePartIndex = this.PacketStartIndex + 7;
            }
            else if (tpdu == Tpdu.ConnectionConfirm) {
                /**
                 *    
                 The structure of the CC TPDU shall be as follows:
   
                   1      2     3   4   5   6     7     8     p   p+1 ...end
                 +---+----+---+---+---+---+---+-------+--------+-------------+
                 |LI | CC  CDT|DST-REF|SRC-REF| CLASS |VARIABLE| USER        |
                 |   |1101|   |   |   |   |   | OPTION|  PART  | DATA        |
                 +---+----+---+---+---+---+---+-------+--------+-------------+
                    */
                variablePartIndex = this.PacketStartIndex + 7;
            }
            else if (tpdu == Tpdu.DisconnectConfirm) {
                /**
                 *      The structure of DC TPDU shall be as follows:

                1       2         3     4     5     6    7        p
                +----+-----------+-----+-----+-----+-----+-------+--------+
                | LI |    DC     |  DST REF  |  SRC REF  | Variable Part  |
                |    | 1100 0000 |     |     |     |     |       |        |
                +----+-----------+-----+-----+-----+-----+-------+--------+
                */
                variablePartIndex = this.PacketStartIndex + 6;
            }
            else if(tpdu == Tpdu.Data) {
                /**
                 *      Depending on the class and the option the DT TPDU shall have  one
                of the following structures.

                a)  Normal format for Classes 0 and 1

                1       2         3          4       5             ... end
                +----+-----------+-----------+------------ - - - - - -------+
                | LI |    DT     |  TPDU-NR  | User Data                    |
                |    | 1111 0000 |  and EOT  |                              |
                +----+-----------+-----------+------------ - - - - - -------+


                b)  Normal format for Classes 2, 3 and 4

                1      2       3   4     5     6       p    p+1       ... end
                +----+---------+---+---+-------+-----+-------+----------- - - -+
                | LI |   DT    |DST-REF|TPDU-NR|Variable Part|User Data        |
                |    |1111 0000|   |   |and EOT|     |       |                 |
                +----+---------+---+---+-------+-----+-------+----------- - - -+

                c)  Extended Format for  use  in  Classes  2,  3  and  4  when
                selected during connection establishment.

                1      2       3   4   5,6 7,8  9     p  p+1      ... end
                +----+---------+---+---+---------+--------+---------- - - -+
                | LI |   DT    |DST-REF| TPDU-NR |Variable|User Data       |
                |    |1111 0000|   |   | and EOT |  Part  |                |
                +----+---------+---+---+---------+--------+---------- - - -+

                */
                if (this.pduClass >= 2 && this.pduClass < 5)
                    variablePartIndex = this.PacketStartIndex + 5;
            }
            return variablePartIndex > 0;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            if(includeSelfReference)
                yield return this;
        }
    }
}
