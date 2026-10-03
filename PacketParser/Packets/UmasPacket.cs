using SharedUtils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Frame;
using static PacketParser.Packets.ModbusTcpPacket;

namespace PacketParser.Packets {
    public class UmasPacket : AbstractPacket {

        public enum FC : byte {
          INIT_COMM = 0x01,
           READ_ID = 0x02,
           READ_PROJECT_INFO = 0x03,
           READ_PLC_INFO = 0x04,
           READ_CARD_INFO = 0x06,
           GetBlockInfo = 0x07,
           REPEAT = 0x0A,
           TAKE_PLC_RESERVATION = 0x10,
           RELEASE_PLC_RESERVATION = 0x11,
           KEEP_ALIVE = 0x12,
           READ_MEMORY_BLOCK = 0x20,
           WriteMemoryBlock = 0x21,
           READ_VARIABLES = 0x22,
           WRITE_VARIABLES = 0x23,
           READ_COILS_REGISTERS = 0x24,
           WRITE_COILS_REGISTERS = 0x25,
           READ_DATA_DICTIONARY = 0x26,
           DataDictionaryPreload = 0x27,
           ReadPhysicalAddress = 0x28,
           WritePhysicalAddress = 0x29,
           BrowseEvents = 0x2A,
           INITIALIZE_UPLOAD = 0x30,
           UPLOAD_BLOCK = 0x31,
           END_STRATEGY_UPLOAD = 0x32,
           INITIALIZE_DOWNLOAD = 0x33,
           DOWNLOAD_BLOCK = 0x34,
           END_STRATEGY_DOWNLOAD = 0x35,
           Backup_Restore = 0x36,
           PreLoadBlocks = 0x37,
           READ_ETH_MASTER_DATA = 0x39,
           START_PLC = 0x40,
           STOP_PLC = 0x41,
           MONITOR_PLC = 0x50,
           CHECK_PLC = 0x58,
           SET_BREAKPOINT = 0x60,//can be used to DoS a PLC as it will halt execution and stop answering on the network
           PRIVATE_MESSAGE = 0x6d,//Can be used for authentication bypass https://www.armis.com/research/modipwn/
           ENHANCED_RESERVATION = 0x6e,//https://www.armis.com/research/modipwn/
           READ_IO_OBJECT = 0x70,
           WRITE_IO_OBJECT = 0x71,
           //0x72 = ??
           GET_STATUS_MODULE = 0x73,
           //0x80 = ??
           //0x81 = ??
           Success = 0xFE,//response
           Error = 0xFD,//response
        }

       

        public ModbusTcpPacket ParentModbusPacket { get; private set; }
        public byte SessionKey { get; private set; }
        public FC? UmasFunctionCode { get; private set; } = null;
        public byte UmasFunctionCodeRaw;


        internal UmasPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, ModbusTcpPacket modbusTcpPacket)
            : base(parentFrame, packetStartIndex, packetEndIndex, "UMAS") {
            this.ParentModbusPacket = modbusTcpPacket;
            this.SessionKey = parentFrame.Data[packetStartIndex];
            this.UmasFunctionCodeRaw = parentFrame.Data[packetStartIndex + 1];
            if (Enum.IsDefined(typeof(FC), this.UmasFunctionCodeRaw)) {
                this.UmasFunctionCode = (FC)this.UmasFunctionCodeRaw;
            }
            else
                Logger.Log("Unknown UMAS Function Code 0x" + this.UmasFunctionCodeRaw.ToString("X2"), Logger.EventLogEntryType.Debug);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }
    }
}
