using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting.Metadata;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Packets.McNmfPacket;

namespace PacketParser.Packets {
    public class McNmfPacket : AbstractPacket, ISessionPacket {

        //.NET Message Framing Protocol a.k.a. MC-NMF
        //https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/0aab922d-8023-48bb-8ba2-c4d3404cc69d
        //https://winprotocoldoc.z19.web.core.windows.net/MC-NMF/%5bMC-NMF%5d.pdf

        //.NET Binary XML MC-NBFSE
        //https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nbfx/94c66ea1-e79a-4364-af88-1fa7fef2cc33?redirectedfrom=MSDN
        //http://rfc.nop.hu/winprot4/MC-NBFX.pdf
        //https://winprotocoldoc.z19.web.core.windows.net/MC-NBFSE/%5bMC-NBFSE%5d.pdf
        //https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmldictionaryreader.createbinaryreader?view=netframework-4.8.1
        //https://stackoverflow.com/questions/70004124/servicebus-message-handler-using-windows-azure-servicebus-5-2-0-fails-to-deser

        private const uint MAX_NMF_PACKET_SIZE = 1500;

        public enum RecordType : byte {
            Version = 0x00,
            Mode = 0x01,
            Via = 0x02,
            KnownEncoding = 0x03,
            ExtensibleEncoding = 0x04,
            UnsizedEnvelope = 0x05,
            SizedEnvelope = 0x06,
            End = 0x07,
            Fault = 0x08,
            UpgradeRequest = 0x09,
            UpgradeResponse = 0x0A,
            PreambleAck = 0x0B,
            PreambleEnd = 0x0C,
        }

        internal enum Mode : byte {
            SingletonUnsized = 0x01,//The Initiating Stream for a single one-way message or for a pair of messages in a request-reply manner between two nodes.
            Duplex = 0x02,//The Initiating Stream for multiple bidirectional messages between two nodes.
            Simplex = 0x03,//The Initiating Stream for multiple one-way messages from a single source.
            SingletonSized = 0x04
        }

        public enum Encoding : byte {
            SOAP_1_1_UTF8 = 0x00,
            SOAP_1_1_UTF16 = 0x01,
            SOAP_1_1_UnicodeLittleEndian = 0x02,
            SOAP_1_2_UTF8 = 0x03,
            SOAP_1_2_UTF16 = 0x04,
            SOAP_1_2_UnicodeLittleEndian = 0x05,
            SOAP_1_2_MTOM = 0x06,
            SOAP_1_2_MC_NBFS = 0x07,//Binary, as specified in [MC-NBFS].
            SOAP_1_2_MC_NBFSE = 0x08,//Binary with in-band dictionary, as specified in [MC-NBFSE].
        }

        public class Record {
            public RecordType RecordType { get; }
            public string RecordStringValue { get; }

            internal int Size { get; }

            public byte[] Data { get; set; } = null;

            internal Record(RecordType recordType, string recordStringValue, int sizeIncludingType) {
                this.RecordType = recordType;
                this.RecordStringValue = recordStringValue;
                this.Size = sizeIncludingType;
            }
        }


        public bool PacketHeaderIsComplete => (this.Records.Length > 0 || TrailingData.HasValue);

        public int ParsedBytesCount { get; }


        public Record[] Records { get; }

        public (int offset, uint length)? TrailingData { get; }


        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            bool success = TryParse(parentFrame, packetStartIndex, packetEndIndex, out McNmfPacket mcNmf);
            result = mcNmf;
            return success;
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out McNmfPacket result) {
            if (parentFrame.Data[packetStartIndex] > 0x0c) {
                result = null;
                return false;
            }
            else {
                try {
                    result = new McNmfPacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                catch {
                    result = null;
                    return false;
                }
            }
        }

        public McNmfPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "MC-NMF") {
            //use XmlDictionaryReader.CreateBinaryReader to parse the data in type 6 records
            //with known encoding #8 = Binary with in-band dictionary, as specified in [MC-NBFSE]

            int index = packetStartIndex;
            List<Record> records = new List<Record>();
            while(index <= packetEndIndex) {
                //https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/9f8bc716-6b03-4c13-b683-47d740719b4e
                byte recordTypeRaw = parentFrame.Data[index++];
                if (recordTypeRaw > 0x0c)
                    throw new Exception("Invalid MC-NMF record type 0x" + recordTypeRaw.ToString("X2"));

                else if (recordTypeRaw == (byte)RecordType.Version) {
                    byte majorVersion = parentFrame.Data[index++];
                    byte minorVersion = parentFrame.Data[index++];
                    records.Add(new Record(RecordType.Version, "" + majorVersion + "." + minorVersion, 3));
                }
                else if (recordTypeRaw == (byte)RecordType.Mode) {
                    byte modeRaw = parentFrame.Data[index++];
                    if (Enum.IsDefined(typeof(Mode), modeRaw)) {
                        Mode mode = (Mode)modeRaw;
                        records.Add(new Record(RecordType.Mode, mode.ToString(), 2));
                    }
                }
                else if (recordTypeRaw == (byte)RecordType.Via) {
                    if (this.TryGetVariableUtf8StringRecord(parentFrame.Data, ref index, RecordType.Via, out Record r))
                        records.Add(r);
                    else
                        break;

                }
                else if (recordTypeRaw == (byte)RecordType.KnownEncoding) {
                    //Values of 0x09–0xFF are reserved for future use
                    byte encodingRaw = parentFrame.Data[index++];
                    if (Enum.IsDefined(typeof(Encoding), encodingRaw)) {
                        Encoding encoding = (Encoding)encodingRaw;
                        records.Add(new Record(RecordType.KnownEncoding, encoding.ToString(), 2));
                    }
                }
                //TODO RecordType.ExtensibleEncodingRecord https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/ac28de93-1842-4d66-8074-1c2a34e24720
                //TODO RecordType.UnsizedEnvelopeRecord https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/ac28de93-1842-4d66-8074-1c2a34e24720
                else if (recordTypeRaw == (byte)RecordType.SizedEnvelope) {
                    int recordStartIndex = index - 1;
                    uint envelopeLength = DecodeRecordSize(parentFrame.Data, ref index);
                    //The content of the message encoded using the encoding indicated by an Envelope Encoding Record.
                    if (parentFrame.Data.Length < index + envelopeLength) {

                        if(envelopeLength > MAX_NMF_PACKET_SIZE)
                            this.TrailingData = (index, envelopeLength);
                        break;
                    }
                    else {
                        Record dataRecord = new Record(RecordType.SizedEnvelope, null, (int)(index + envelopeLength - recordStartIndex));
                        dataRecord.Data = new byte[envelopeLength];
                        Array.Copy(parentFrame.Data, index, dataRecord.Data, 0, envelopeLength);
                        index += (int)envelopeLength;
                        records.Add(dataRecord);
                    }
                }
                else if (recordTypeRaw == (byte)RecordType.End) {
                    records.Add(new Record(RecordType.End, null, 1));
                }
                else if (recordTypeRaw == (byte)RecordType.Fault) {
                    //https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/337e8351-0854-48d2-864b-97520026c2c6
                    if (this.TryGetVariableUtf8StringRecord(parentFrame.Data, ref index, RecordType.Fault, out Record r))
                        records.Add(r);
                    else
                        break;
                }
                else if (recordTypeRaw == (byte)RecordType.UpgradeRequest) {
                    //known upgrade protocol names:
                    //"application/ssl-tls"
                    //"application/negotiate"

                    if (this.TryGetVariableUtf8StringRecord(parentFrame.Data, ref index, RecordType.UpgradeRequest, out Record r))
                        records.Add(r);
                    else
                        break;

                }
                else if (recordTypeRaw == (byte)RecordType.UpgradeResponse) {
                    records.Add(new Record(RecordType.UpgradeResponse, null, 1));
                }
                else if (recordTypeRaw == (byte)RecordType.PreambleAck) {
                    records.Add(new Record(RecordType.PreambleAck, null, 1));
                }
                else if (recordTypeRaw == (byte)RecordType.PreambleEnd) {
                    records.Add(new Record(RecordType.PreambleEnd, null, 1));
                }

            }
            this.Records = records.ToArray();
            //int totalSize = records.Sum(r => r.Size);
            //if (totalSize == 0)
            //    this.PacketHeaderIsComplete = false;
            if (this.TrailingData == null)
                this.ParsedBytesCount = records.Sum(r => r.Size);
            else
                this.ParsedBytesCount = this.TrailingData.Value.offset - this.PacketStartIndex;
            this.PacketEndIndex = this.PacketStartIndex + this.ParsedBytesCount - 1;
        }

        private bool TryGetVariableUtf8StringRecord(byte[] data, ref int index, RecordType recordType, out Record record) {
            int recordStartIndex = index - 1;
            int stringLength = (int)DecodeRecordSize(data, ref index);
            //The length MUST NOT be set to 0
            if (stringLength < 1)
                throw new Exception("Invalid MC-NMF string length");
            //MUST be encoded by using UTF-8, as specified in [RFC2279]
            if (data.Length < index + stringLength) {
                //more data needed
                record = null;
                return false;
            }
            else {
                string s = ASCIIEncoding.UTF8.GetString(data, index, stringLength);
                index += stringLength;
                record = new Record(recordType, s, index - recordStartIndex);
                return true;
            }
        }

        internal static uint DecodeRecordSize(byte[] data, ref int index) {
            //Returns a value from 0 to 0xffffffff (4 294 967 295)
            //Do the inverse of the encode algorithm described here:
            //https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-nmf/070844de-fda1-43e3-89a0-c9327f8f512e
            //Here's a decode implementation in Python from ERNW 
            //https://github.com/ernw/net.tcp-proxy/blob/40a009e3a4aae35e85679c34bf1b0ccf8cf5542c/nettcp/nmf.py#L60
            uint recordSize = 0;
            int offset = 0;
            byte b = 0;
            do {
                b = data[index + offset];
                recordSize |= (uint)(b & 0x7f)<<(offset * 7);
                offset++;
            } while (offset < 5 && b > 0x7f);
            index += offset;
            return recordSize;
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }
    }
}
