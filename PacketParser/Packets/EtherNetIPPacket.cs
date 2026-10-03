using SharedUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Packets {
    public class EtherNetIPPacket : AbstractPacket, ISessionPacket {

        //3.3.11. EtherNet/IP Encapsulation 
        //https://www.odva.org/wp-content/uploads/2020/06/PUB00123R1_Common-Industrial_Protocol_and_Family_of_CIP_Networks.pdf
        //https://www.programmersought.com/article/29767359290/
        //https://software-dl.ti.com/mcu-plus-sdk/esd/AM64X/08_03_00_18/exports/docs/industrial_protocol_docs/am64x/ethernetip_adapter/index.html
        //https://product-help.schneider-electric.com/ED/TeSysT/LTMR_Ethernet_Guide/EDMS/DOCA0129EN/TeSysT_LTMR_ModbusTCP_MotorManagementController_UsersManual/Using_the_Ethernet_Communication_Network/Using_the_Ethernet_Communication_Network-16.htm
        //https://www.odva.org/wp-content/uploads/2020/05/PUB00213R0_EtherNetIP_Developers_Guide.pdf
        //https://www.odva.org/wp-content/uploads/2024/04/PUB00138R8_Ethernet.pdf

        public enum EncapsulationCommand : ushort {
            NOP = 0x0000,
            //1-3 are reserved
            ListServices = 0x0004,
            ListIdentity = 0x0063,
            ListInterfaces = 0x0064,
            RegisterSession = 0x0065,
            UnRegisterSession = 0x0066,
            SendRRData = 0x006F,//used for CIP
            SendUnitData = 0x0070,//used for CIP
            IndicateStatus = 0x0072,
            Cancel = 0x0073,
        }

        public enum StatusCode : uint {
            Success = 0x0000,
            InvalidCommand = 0x0001,
            InsufficientMemoryResources = 0x0002,
            IncorrectData = 0x0003,
            InvalidSessionHandle = 0x0064,
            InvalidLength = 0x0065,
            UnsupportedProtocolRevision = 0x0069,
        }

        public enum ItemID : ushort {
            Address = 0x0000,
            ListIdentityResponse = 0x000C,
            ConnectionBased = 0x00A1,
            ConnectedTransportPacket = 0x00B1,
            UnconnectedMessage = 0x00B2,
            ListServicesResponse = 0x0100,
            SockAddrRequest = 0x8000,//originator-to-target 
            SockAddrResponse = 0x8001,//target-to-originator 
            SequencedAddressItem = 0x8002,
        }

        private const int ENCAPSULATION_HEADER_LENGTH = 24;
        public ushort Command { get; private set; }
        internal ushort CommandLength { get; private set; }
        public uint SessionHandle { get; private set; }
        internal uint Status {  get; private set; }
        public ulong SenderContext { get; private set; }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out EtherNetIPPacket ethernetIp) {
            ethernetIp = null;
            int ethernetIpDataLength = packetEndIndex - packetStartIndex + 1;
            //min length is 24 bytes (encapsulation header)
            if (ethernetIpDataLength < ENCAPSULATION_HEADER_LENGTH)
                return false;
            ushort commandLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, true);
            if (ENCAPSULATION_HEADER_LENGTH + commandLength > ethernetIpDataLength)
                return false;
            try {
                ethernetIp = new EtherNetIPPacket(parentFrame, packetStartIndex, packetEndIndex, sourcePort, destinationPort);
                return true;
            }
            catch (Exception ex) {
                Logger.Log("Error parsing EtherNet/IP packet in frame " + parentFrame.FrameNumber + ":" + ex.Message, Logger.EventLogEntryType.Error);
                return false;
            }
        }

        internal EtherNetIPPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort) : base(parentFrame, packetStartIndex, packetEndIndex, "EtherNet/IP") {
            this.Command = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, true);
            this.CommandLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, true);
            //Unsigned Double Int: https://support.industry.siemens.com/cs/mdm/109747174?c=85665065099&dl=pt&lc=en-US
            this.SessionHandle = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 4, true);
            this.Status = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8, 4, true);
            this.SenderContext = Utils.ByteConverter.ToUInt64(ParentFrame.Data, packetStartIndex + 12, true);
            uint optionsFlags = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 20, 4, true);
        }
        public bool PacketHeaderIsComplete {
            get {
                return this.ParsedBytesCount >= ENCAPSULATION_HEADER_LENGTH;
            }
        }

        public int ParsedBytesCount {
            get {
                if (this.PacketLength >= ENCAPSULATION_HEADER_LENGTH + this.CommandLength)
                    return ENCAPSULATION_HEADER_LENGTH + this.CommandLength;
                else
                    return 0;
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;

            AbstractPacket packet = null;

            if (this.Command == (ushort)EncapsulationCommand.SendRRData) {
                //4 bytes interface handle (shall be 0 for CIP)
                //2 bytes timeout
                packet = new CommonPacket(this.ParentFrame, this.PacketStartIndex + ENCAPSULATION_HEADER_LENGTH + 6, this.PacketStartIndex + ENCAPSULATION_HEADER_LENGTH + this.CommandLength);
            }
            else if (this.Command == (ushort)EncapsulationCommand.SendUnitData) {
                //4 bytes interface handle (shall be 0 for CIP)
                //2 bytes timeout
                packet = new CommonPacket(this.ParentFrame, this.PacketStartIndex + ENCAPSULATION_HEADER_LENGTH + 6, this.PacketStartIndex + ENCAPSULATION_HEADER_LENGTH + this.CommandLength);
            }

            if (packet != null) {
                yield return packet;
                foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }


        internal protected class CommonPacket : AbstractPacket {
            internal (int offset, ushort typeId, ushort length)[] DataItems;

            private EtherNetIPPacket parentEtherNetIPPacket = null;

            public CommonPacket(EtherNetIPPacket parentEtherNetIPPacket, int packetStartIndex, int packetEndIndex) : this(parentEtherNetIPPacket.ParentFrame, packetStartIndex, packetEndIndex) {
                this.parentEtherNetIPPacket = parentEtherNetIPPacket;
            }

            public CommonPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "Ethernet/IP Common Packet") {
                ushort itemCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, true);
                this.DataItems = new (int offset, ushort typeId, ushort length)[itemCount];

                int itemOffset = this.PacketStartIndex + 2;
                for (int i = 0; i < itemCount; i++) {
                    ushort itemTypeId = Utils.ByteConverter.ToUInt16(parentFrame.Data, itemOffset, true);
                    ushort itemLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, itemOffset + 2, true);
                    this.DataItems[i] = (itemOffset + 4, itemTypeId, itemLength);
                    itemOffset += 4 + itemLength;
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;

                foreach(var item in this.DataItems) {
                    if (item.typeId == (ushort)ItemID.UnconnectedMessage) {
                        var cip = new CipPacket(this.ParentFrame, item.offset, item.offset + item.length - 1);
                        yield return cip;
                        foreach (var embedded in cip.GetSubPackets(false))
                            yield return embedded;
                    }
                    else if (item.typeId == (ushort)ItemID.ConnectedTransportPacket) {
                        ushort cipSequenceCount = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, item.offset, true);
                        int startIndex = item.offset + 2;
                        if(cipSequenceCount > 0) {//only get the first one
                            var cip = new CipPacket(this.ParentFrame, startIndex, item.offset + item.length - 1);
                            yield return cip;
                            foreach (var embedded in cip.GetSubPackets(false))
                                yield return embedded;
                        }
                    }
                }
            }
        }
    }
}
