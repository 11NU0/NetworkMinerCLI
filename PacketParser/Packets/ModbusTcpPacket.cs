using PacketParser.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    public class ModbusTcpPacket : AbstractPacket, ISessionPacket{

        public enum AddressType : byte {
            Coil = 0,//00001 - 09999
            DiscreteInput = 1,//10001 - 19999
            InputRegister = 3,//30001 - 39999
            HoldingRegister = 4, //40001 - 49999
        }
        public static string ToModiconAddressNotaion(ushort addressZeroIndexed, AddressType type) {
            int addressOneIndexed = addressZeroIndexed + 1;
            if (addressOneIndexed <= 9999)
                return "(" + ((int)type) + ")" + addressOneIndexed.ToString("0000");
            else
                return "(" + ((int)type) + ")" + addressOneIndexed.ToString("00000");
        }

        public abstract class AbstractModbusMessage {
            protected FunctionCodeEnum functionCode;
            private protected List<string> anomalies = null;//lazy initialization

            public FunctionCodeEnum FunctionCode { get { return this.functionCode; } }

            protected AbstractModbusMessage(byte[] frameData, int functionCodeOffset) {
                this.functionCode = (FunctionCodeEnum)frameData[functionCodeOffset];
            }
            
            public abstract override string ToString();

            protected internal void AddAnomaly(string message) {
                if(this.anomalies == null)
                    this.anomalies = new List<string>();
                this.anomalies.Add(message);
            }

            protected internal string[] GetAnomalies() {
                if(this.anomalies == null)
                    return Array.Empty<string>();
                else
                    return this.anomalies.ToArray();
            }
        }


        /// <summary>
        /// Querys with function code 1,2,3,4
        /// </summary>
        public class GenericAddressAndInputCountRequest : AbstractModbusMessage {
            private ushort startAddress;//zero indexed
            private ushort inputCount;

            public GenericAddressAndInputCountRequest(byte[] frameData, int functionCodeOffset) : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.inputCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                AddressType addressType = AddressType.Coil;
                //https://www.csimn.com/CSI_pages/Modbus101.html
                /**
                    0x = Coil = 00001-09999
                    1x = Discrete Input = 10001-19999
                    3x = Input Register = 30001-39999
                    4x = Holding Register = 40001-49999
                */
                if (this.functionCode == FunctionCodeEnum.ReadCoils)
                    addressType = AddressType.Coil;
                else if (this.functionCode == FunctionCodeEnum.ReadDiscreteInputs)
                    addressType = AddressType.DiscreteInput;
                else if (this.functionCode == FunctionCodeEnum.ReadInputRegisters)
                    addressType = AddressType.InputRegister;
                else if (this.functionCode == FunctionCodeEnum.ReadHoldingRegisters)
                    addressType = AddressType.HoldingRegister;

                if (this.inputCount == 1)
                    return ToModiconAddressNotaion(this.startAddress, addressType);
                else if (this.inputCount > 1)
                    return ToModiconAddressNotaion(this.startAddress, addressType).ToString() + "-" + ToModiconAddressNotaion((ushort)(this.startAddress + this.inputCount - 1), addressType);
                else
                    return "";
            }
        }

        /// <summary>
        /// Responses with function code 1,2,3,4
        /// </summary>
        public class GenericByteCountRegisterValueResponse : AbstractModbusMessage {
            private string registerValuesHex;
            protected byte byteCount;

            public GenericByteCountRegisterValueResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                    this.byteCount = frameData[functionCodeOffset + 1];
                    this.registerValuesHex = Utils.ByteConverter.ToHexString(frameData, byteCount, functionCodeOffset + 2);
            }

            public override string ToString() {
                return this.registerValuesHex;
            }
        }

        /// <summary>
        /// Responses for function code 3 and 4
        /// </summary>
        public class ReadRegisterResponse : GenericByteCountRegisterValueResponse {

            private List<ushort> registerValues;

            public ReadRegisterResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.registerValues = new List<ushort>();
                for(int i=0; i<base.byteCount && frameData.Length > functionCodeOffset + 2 + i + 1; i+=2) {
                    this.registerValues.Add(Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 2 + i));
                }
            }

            public override string ToString() {
                return string.Join(", ", this.registerValues.Select(v => v.ToString()));
            }
        }

        /// <summary>
        /// Queries and Responses with function code 5
        /// </summary>
        public class WriteSingleCoil : AbstractModbusMessage {

            private ushort outputAddress;//0 indexed
            private ushort outputValue;

            public WriteSingleCoil(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                    this.outputAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                    this.outputValue = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }


            public override string ToString() {
                //int coilAddressOneIndexed = outputAddress + 1;
                if (this.outputValue == 0x0000)
                    return ToModiconAddressNotaion(outputAddress, AddressType.Coil) + "=OFF";
                else if (this.outputValue == 0xff00)
                    return ToModiconAddressNotaion(outputAddress, AddressType.Coil) + "=ON";
                else
                    return ToModiconAddressNotaion(outputAddress, AddressType.Coil) + "=invalid (" + this.outputValue.ToString("X4") + ")";
            }
        }


        /// <summary>
        /// Queries and responses with function code 6
        /// </summary>
        public class WriteSingleRegister : AbstractModbusMessage {

            private ushort outputAddress;//0 indexed
            private ushort outputValue;

            public WriteSingleRegister(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.outputAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.outputValue = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }


            public override string ToString() {
                return ToModiconAddressNotaion(outputAddress, AddressType.HoldingRegister) + "=" + this.outputValue;
            }
        }


        /// <summary>
        /// Diagnostic
        /// 00 Return Query Data
        /// 01 Restart Comm Option
        /// 02 Return Diagnostic Register
        /// 03 Change ASCII Input Delimiter
        /// 04 Force Listen Only Mode
        /// 05–09 Reserved
        /// 10 Clear Ctrs and Diagnostic Reg.
        /// 11 Return Bus Message Count
        /// 12 Return Bus Comm.Error Count
        /// 13 Return Bus Exception Error Cnt
        /// 14 Return Slave Message Count
        /// 15 Return Slave No Response Cnt
        /// 16 Return Slave NAK Count
        /// 17 Return Slave Busy Count
        /// 18 Return Bus Char.Overrun Cnt
        /// 19 Return Overrun Error Count
        /// 20 Clear Overrun Counter and Flag
        /// 21 Get/Clear Modbus Plus Statistics
        /// </summary>
        public class Diagnostic : AbstractModbusMessage {

            private ushort diagnosticCode;//0 indexed
            private ushort data;

            public Diagnostic(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.diagnosticCode = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.data = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                switch(diagnosticCode) {
                    case 0: return "Return Query Data : " + data.ToString("X2");
                    case 1: return "Restart Comm Option : " + data.ToString("X2");
                    case 2: return "Return Diagnostic Register : " + data.ToString("X2");
                    case 3: return "Change ASCII Input Delimiter : " + data.ToString("X2");
                    case 4: return "Force Listen Only Mode : " + data.ToString("X2");
                    case 10: return "Clear Ctrs and Diagnostic Reg. : " + data.ToString("X2");
                    case 11: return "Return Bus Message Count : " + data.ToString("X2");
                    case 12: return "Return Bus Comm.Error Count : " + data.ToString("X2");
                    case 13: return "Return Bus Exception Error Cnt : " + data.ToString("X2");
                    case 14: return "Return Slave Message Count : " + data.ToString("X2");
                    case 15: return "Return Slave No Response Cnt : " + data.ToString("X2");
                    case 16: return "Return Slave NAK Count : " + data.ToString("X2");
                    case 17: return "Return Slave Busy Count : " + data.ToString("X2");
                    case 18: return "Return Bus Char.Overrun Cnt : " + data.ToString("X2");
                    case 19: return "Return Overrun Error Count : " + data.ToString("X2");
                    case 20: return "Clear Overrun Counter and Flag : " + data.ToString("X2");
                    case 21: return "Get/Clear Modbus Plus Statistics : " + data.ToString("X2");
                    default: return diagnosticCode.ToString("X2") + data.ToString("X2");
                }
            }
        }

        /// <summary>
        /// Request function code 15
        /// </summary>
        public class WriteMultipleCoilsRequest : AbstractModbusMessage {
            private ushort startAddress;
            private System.Collections.BitArray values;

            public WriteMultipleCoilsRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                ushort outputCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                byte byteCount = frameData[functionCodeOffset + 5];

                byte[] bytes = new byte[byteCount];
                Array.Copy(frameData, functionCodeOffset + 6, bytes, 0, bytes.Length);
                System.Collections.BitArray mask = new System.Collections.BitArray(bytes);
                this.values = new System.Collections.BitArray(outputCount);
                for (int i = 0; i < outputCount; i++)
                    this.values[i] = mask[i];
            }

            public override string ToString() {
                List<string> valueStrings = new List<string>();
                foreach (bool v in this.values)
                    if (v)
                        valueStrings.Add("1");
                    else
                        valueStrings.Add("0");

                return "Coil " + ToModiconAddressNotaion(this.startAddress, AddressType.Coil) + "-" + ToModiconAddressNotaion((ushort)(this.startAddress + this.values.Count - 1), AddressType.Coil) + " = " + string.Join(",", valueStrings.ToArray());
            }
        }

        /// <summary>
        /// Response function code 15
        /// </summary>
        public class WriteMultipleCoilsResponse : AbstractModbusMessage {
            private ushort startAddress;
            private ushort outputsWritten;//count

            public WriteMultipleCoilsResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.outputsWritten = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                return "Forced nr. cols: " + this.outputsWritten.ToString();
            }
        }

        /// <summary>
        /// Response function code 16
        /// </summary>
        public class WriteMultipleRegistersResponse : AbstractModbusMessage {
            private ushort startAddress;
            private ushort outputsWritten;//count

            public WriteMultipleRegistersResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.startAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.outputsWritten = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
            }

            public override string ToString() {
                string startAddress = ToModiconAddressNotaion(this.startAddress, AddressType.HoldingRegister);
                string endAddress = ToModiconAddressNotaion((ushort)(this.startAddress + outputsWritten - 1), AddressType.HoldingRegister);
                if(this.outputsWritten > 1)
                    return startAddress + " - " + endAddress;
                else
                    return startAddress;
            }
        }

        /// <summary>
        /// Function code 16, request
        /// </summary>
        public class WriteMultipleHoldingRegistersRequest : AbstractModbusMessage {
            ushort referenceAddress;
            ushort registerCount;
            byte byteCount;
            List<ushort> registerValues;

            public WriteMultipleHoldingRegistersRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.referenceAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.registerCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                this.byteCount = frameData[functionCodeOffset + 5];//should be 2 x registerCount
                registerValues = new List<ushort>();
                if (this.byteCount != this.registerCount * 2)
                    this.AddAnomaly("Byte count (" + this.byteCount + ") is not 2 x register count (" + this.registerCount + ")");
                else {
                    int valuesOffset = functionCodeOffset + 6;
                    for (int i=0; i < this.registerCount; i++) {
                        ushort regValue = Utils.ByteConverter.ToUInt16(frameData, valuesOffset + 2*i);
                        this.registerValues.Add(regValue);
                    }
                }
            }

            public override string ToString() {
                List<string> parts = new List<string>();
                for(int i=0; i<this.registerValues.Count; i++) {
                    parts.Add(ToModiconAddressNotaion((ushort)(this.referenceAddress + i), AddressType.HoldingRegister) + "=" + this.registerValues[i].ToString());
                }
                return string.Join(", ", parts.ToArray());
            }
        }

        /// <summary>
        /// Queries with function code 20
        /// </summary>
        public class ReadFileRecordRequest : AbstractModbusMessage {

            private List<string> fileRequests;

            public ReadFileRecordRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {

                    this.fileRequests = new List<string>();

                byte byteCount = frameData[functionCodeOffset + 1];
                for (int i = 0; i < byteCount; i += 7) {
                    byte referenceType = frameData[functionCodeOffset + 2 + i];
                    ushort fileNumber = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3 + i);
                    ushort recordNumber = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5 + i);
                    ushort recordLength = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 7 + i);
                    string registerString = recordNumber.ToString();
                    if(recordLength > 1)
                        registerString = registerString + "-" + ((int)recordNumber + recordLength).ToString();
                    this.fileRequests.Add("File=" + fileNumber + " Register=" + registerString);
                }
            }

            public override string ToString() {
                return string.Join("; ", fileRequests.ToArray());
            }
        }

        /// <summary>
        /// Responses with function code 20
        /// </summary>
        public class ReadFileRecordResponse : AbstractModbusMessage {

            List<List<ushort>> fileList = new List<List<ushort>>();

            public ReadFileRecordResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                byte responseDataLength = frameData[functionCodeOffset + 1];
                int offset = functionCodeOffset + 2;
                while(offset < functionCodeOffset + 2 + responseDataLength) {
                    List<ushort> fileData = new List<ushort>();
                    byte fileResponseLength = frameData[offset++];
                    byte referenceType = frameData[offset];//should be 6
                    for(int i=1; i<fileResponseLength; i+=2)
                        fileData.Add(Utils.ByteConverter.ToUInt16(frameData, offset + i));
                    this.fileList.Add(fileData);
                    offset += fileResponseLength;
                }
            }

            public override string ToString() {
                List<string> fileDataStringList = new List<string>();
                for (int fileNr = 0; fileNr < fileList.Count; fileNr++) {
                    List<ushort> fileData = fileList[fileNr];
                    StringBuilder sb = new StringBuilder("Group " + fileNr + " :");
                    for (int i = 0; i < fileData.Count; i++)
                        sb.Append("  " + fileData[i].ToString("X4"));
                    fileDataStringList.Add(sb.ToString());
                }
                return string.Join(";", fileDataStringList.ToArray());
            }
        }

        /// <summary>
        /// Function code 22, request and reponse
        /// </summary>
        public class MaskWriteRegister : AbstractModbusMessage {
            ushort referenceAddress;
            ushort andMask;
            ushort orMask;

            public MaskWriteRegister(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.referenceAddress = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                this.andMask = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                this.orMask = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5);
            }

            public override string ToString() {
                return "Register=" + (referenceAddress + 1).ToString() + " AND=" + andMask.ToString("X4") + " OR=" + orMask.ToString("X4");
            }
        }

        /// <summary>
        /// Function code 24 - Request
        /// </summary>
        public class ReadFifoQueueRequest : AbstractModbusMessage {
            ushort address;

            public ReadFifoQueueRequest(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                this.address = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
            }

            public override string ToString() {
                return address.ToString();
            }
        }

        /// <summary>
        /// Function code 24 - Response
        /// </summary>
        public class ReadFifoQueueResponse : AbstractModbusMessage {
            ushort[] values;

            public ReadFifoQueueResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                ushort byteCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 1);
                ushort fifoCount = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 3);
                values = new ushort[fifoCount];

                for (int i = 0; i < fifoCount && i < byteCount / 2 - 1; i++) {
                    values[i] = Utils.ByteConverter.ToUInt16(frameData, functionCodeOffset + 5 + i * 2);
                }
            }

            public override string ToString() {
                StringBuilder sb = new StringBuilder();
                foreach (ushort value in this.values)
                    sb.Append(value.ToString("X4") + " ");
                return sb.ToString().TrimEnd();
            }
        }

        public class ReportSlaveIdResponse : AbstractModbusMessage {
            string slaveIdPrintable, slaveIdHex;

            public ReportSlaveIdResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                ushort byteCount = frameData[functionCodeOffset + 1];
                this.slaveIdHex = Utils.ByteConverter.ToHexString(frameData, byteCount, functionCodeOffset + 2);
                this.slaveIdPrintable = Utils.ByteConverter.ReadString(frameData, functionCodeOffset + 2, byteCount, "");
            }

            public override string ToString() {
                if (slaveIdPrintable.Length > 0)
                    return this.slaveIdPrintable + " (" + this.slaveIdHex + ")";
                else
                    return this.slaveIdHex;
            }
        }

        public class DeviceIdentificationResponse : AbstractModbusMessage {
            string deviceIdentification;

            public DeviceIdentificationResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                byte baseicDeviceId = frameData[functionCodeOffset + 2];
                byte conformityLevel = frameData[functionCodeOffset + 3];
                byte moreFollows = frameData[functionCodeOffset + 4];
                byte nextObjectId = frameData[functionCodeOffset + 5];
                byte numberOfObjects = frameData[functionCodeOffset + 6];
                int objectIndex = functionCodeOffset + 7;
                List<string> deviceIdParts = new List<string>();
                for(int i = 0; i < numberOfObjects; i++) {
                    byte objectId = frameData[objectIndex];
                    byte objectLength = frameData[objectIndex + 1];
                    /**
                        0x00 VendorName ASCII String Mandatory
                        0x01 ProductCode ASCII String Mandatory
                        0x02 MajorMinorRevision ASCII String Mandatory
                        0x03 VendorUrl ASCII String Optional
                        0x04 ProductName ASCII String Optional
                        0x05 ModelName ASCII String Optional
                        0x06 UserApplicationNamee ASCII String Optional
                    */
                if (objectLength > 0 && objectId < 7) {
                        if(StringManglerUtil.TryGet7BitAsciiString(frameData, objectIndex +2, objectLength, out string asciiString)) {
                            deviceIdParts.Add(asciiString);
                        }
                    }
                    objectIndex = objectIndex + 2 + objectLength;
                }
                if (deviceIdParts.Count > 0)
                    this.deviceIdentification = string.Join(" ", deviceIdParts);
                else
                    this.deviceIdentification = null;
            }

            public override string ToString() {
                return this.deviceIdentification;
            }
        }

        public class ExceptionResponse : AbstractModbusMessage {
            private byte exceptionCode;

            public ExceptionResponse(byte[] frameData, int functionCodeOffset)
                : base(frameData, functionCodeOffset) {
                if((int)base.functionCode > 0x80)
                    base.functionCode = (FunctionCodeEnum)(base.functionCode - 0x80);
                this.exceptionCode = frameData[functionCodeOffset + 1];
            }

            public override string ToString() {
                return ("Exception: " + (ExceptionCodeEnum)this.exceptionCode).ToString();
            }
        }

        public class UnknownFunction : AbstractModbusMessage {
            private string payloadHex;

            public UnknownFunction(byte[] frameData, int functionCodeOffset, ushort length)
                : base(frameData, functionCodeOffset) {
                int payloadLength = length - 2;//remove slave address and function code from payload
                if (length > 0 && payloadLength <= frameData.Length)
                    this.payloadHex = Utils.ByteConverter.ToHexString(frameData, payloadLength, functionCodeOffset + 1);
                else
                    this.payloadHex = "";
            }

            public override string ToString() {
                return this.payloadHex;
            }
        }

        

        public enum FunctionCodeEnum : byte {
	        ReadDiscreteInputs = 2,//single bit access
            ReadCoils = 1,//single bit access
            WriteSingleCoil = 5,//single bit access
            WriteMultipleCoils = 15,//single bit access

	        ReadInputRegisters = 4,//16-bit
            ReadHoldingRegisters = 3,//16-bit
            WriteSingleRegister = 6,//16-bit
            WriteMultipleRegisters = 16,//16-bit
            ReadWriteMultipleRegisters = 23,//16-bit
            MaskWriteRegister = 22,//16-bit
            ReadFIFOQueue = 24,//16-bit

            ReadFileRecord = 20,//file
            WriteFileRecord = 21,//file

            Read_Exception_Status = 7,//Diagnostics
            Diagnostic = 8,//Diagnostics
            GetComEventCounter = 11,//Diagnostics
            GetComEventLog = 12,//Diagnostics
            ReportSlaveID = 17,//Diagnostics
            ReadDeviceIdentification = 43,//Diagnostics

            Program484 = 9,
            Poll383 = 10,
            ProgramController = 13,
            PollController = 14,
            Program_884_M84 = 18,
            ResetCommLink = 19,

            UMAS = 90,

            Program584_984 = 126,

            EncapsulatedInterfaceTransport=43//other
        }
        public enum ExceptionCodeEnum : byte {
	        IllegalFunction                    = 1,
	        IllegalDataAddress                 = 2,
	        IllegalDataValue                   = 3,
	        ServerDeviceFailure                = 4,
	        Acknowledge                        = 5,
	        ServerDeviceBusy                   = 6,
	        MemoryParityError                  = 8,
	        GatewayPathUnavailable             = 10,
	        GatewayTargetDeviceFailedToRespond = 11
        }

        private const ushort MODBUS_TCP_PROTOCOL_ID = 0;
        private byte functionCode;
        public List<string> Anomalies;

        public const int MIN_FRAME_LENGTH = 7;

        public ushort TransactionID { get; }
        public byte SlaveAddress { get; }
        public byte FunctionCode {
            get {
                if (this.ModbusMessage != null)
                    return (byte)this.ModbusMessage.FunctionCode;//in order to handle exceptions where function code should be reduced by 0x80
                else
                    return this.functionCode;
            }
        }
        public FunctionCodeEnum FunctionCodeName { get { return (FunctionCodeEnum)this.FunctionCode; } }
        public ushort Length { get; }
        public bool IsResponse { get; } = false;
        public AbstractModbusMessage ModbusMessage { get; }



        [Obsolete("Please use overload with TCP port numbers instead", true)]
        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            throw new Exception("Not implemented");
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort, out AbstractPacket result) {
            result = null;
            try {
                if (packetEndIndex - packetStartIndex + 1 >= MIN_FRAME_LENGTH && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false) == MODBUS_TCP_PROTOCOL_ID) {
                    result = new ModbusTcpPacket(parentFrame, packetStartIndex, packetEndIndex, sourcePort, destinationPort);
                    return true;
                }
                else
                    return false;
            } catch(Exception e) {
                SharedUtils.Logger.Log("Exception when parsing frame " + parentFrame.FrameNumber + " as Modbus packet: " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                return false;
            }
        }

        internal ModbusTcpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, ushort sourcePort, ushort destinationPort)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Modbus/TCP") {
            this.Anomalies = new List<string>();

            if (packetEndIndex - packetStartIndex + 1 >= MIN_FRAME_LENGTH && Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false) == MODBUS_TCP_PROTOCOL_ID) {
                this.TransactionID = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, false);
                this.Length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4, false);
                //TODO check if the whole length fits inside the TCP packet's payload.
                if (Length + packetStartIndex + 4 > parentFrame.Data.Length)
                    this.Anomalies.Add("Modbus length is larger than the received frame");
                //There might also be several Modbus frames.
                if (sourcePort == 502 && destinationPort != 502)
                    this.IsResponse = true;
                else if (sourcePort == 502 && this.Length != 6)
                    this.IsResponse = true;
                else
                    this.IsResponse = false;//this is a query

                if (Length >= 2) {
                    this.SlaveAddress = parentFrame.Data[packetStartIndex + 6];
                    this.functionCode = parentFrame.Data[packetStartIndex + 7];

                    if (this.IsResponse) {

                        if (this.functionCode == 1 || this.functionCode == 2)
                            this.ModbusMessage = new GenericByteCountRegisterValueResponse(parentFrame.Data, packetStartIndex + 7);
                        if (this.functionCode == 3 || this.functionCode == 4)//2 or 3
                            this.ModbusMessage = new ReadRegisterResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.FunctionCode == (byte)FunctionCodeEnum.WriteSingleCoil)//5
                            this.ModbusMessage = new WriteSingleCoil(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.WriteSingleRegister)//6
                            this.ModbusMessage = new WriteSingleRegister(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.Diagnostic)//8
                            this.ModbusMessage = new Diagnostic(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.WriteMultipleCoils)//15
                            this.ModbusMessage = new WriteMultipleCoilsResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.WriteMultipleRegisters)
                            this.ModbusMessage = new WriteMultipleRegistersResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.ReportSlaveID)//17
                            this.ModbusMessage = new ReportSlaveIdResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.ReadFileRecord)//20
                            this.ModbusMessage = new ReadFileRecordResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.MaskWriteRegister)//22
                            this.ModbusMessage = new MaskWriteRegister(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.ReadFIFOQueue)//24
                            this.ModbusMessage = new ReadFifoQueueResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == 43 && parentFrame.Data[packetStartIndex + 8] == 14)//used for MEI 14 Device Identification
                            this.ModbusMessage = new DeviceIdentificationResponse(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode >= 0x80)//exception
                            this.ModbusMessage = new ExceptionResponse(parentFrame.Data, packetStartIndex + 7);
                        else
                            this.ModbusMessage = new UnknownFunction(parentFrame.Data, packetStartIndex + 7, Length);
                    }
                    else {//QUERY

                        if (functionCode >= 1 && functionCode <= 4)
                            this.ModbusMessage = new GenericAddressAndInputCountRequest(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.WriteSingleCoil)//5
                            this.ModbusMessage = new WriteSingleCoil(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.WriteSingleRegister)//6
                            this.ModbusMessage = new WriteSingleRegister(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.Diagnostic)//8
                            this.ModbusMessage = new Diagnostic(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.WriteMultipleCoils)//15
                            this.ModbusMessage = new WriteMultipleCoilsRequest(parentFrame.Data, packetStartIndex + 7);
                        else if (this.functionCode == (byte)FunctionCodeEnum.WriteMultipleRegisters)//16
                            this.ModbusMessage = new WriteMultipleHoldingRegistersRequest(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.ReadFileRecord)//20
                            this.ModbusMessage = new ReadFileRecordRequest(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.MaskWriteRegister)//22
                            this.ModbusMessage = new MaskWriteRegister(parentFrame.Data, packetStartIndex + 7);
                        else if (functionCode == (byte)FunctionCodeEnum.ReadFIFOQueue)//24
                            this.ModbusMessage = new ReadFifoQueueRequest(parentFrame.Data, packetStartIndex + 7);
                        else
                            this.ModbusMessage = new UnknownFunction(parentFrame.Data, packetStartIndex + 7, Length);
                    }
                    if (this.ModbusMessage != null)
                        this.Anomalies.AddRange(this.ModbusMessage.GetAnomalies());
                }

            }
        }

        
        

        public bool PacketHeaderIsComplete {
            get { throw new NotImplementedException(); }
        }

        public int ParsedBytesCount {
            get { throw new NotImplementedException(); }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else if (this.functionCode == (byte)FunctionCodeEnum.UMAS)
                yield return new UmasPacket(this.ParentFrame, this.PacketStartIndex + 8, this.PacketEndIndex, this);
            else
                yield break;
        }

    }
}
