using PacketHandlerFramework;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using static PacketParser.Packets.ModbusTcpPacket;
using static PacketParser.Packets.UmasPacket;

namespace PacketHandlerFramework.PacketHandlers {
    class ModbusTcpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        private static readonly HashSet<FC> UMAS_REQUESTS_WITH_STRINGS = new HashSet<FC>() {
            FC.TAKE_PLC_RESERVATION,
        };

        private static readonly HashSet<FC> UMAS_REQUEST_RESPONSES_WITH_STRINGS = new HashSet<FC>() {
            FC.READ_ID,
            FC.READ_PROJECT_INFO,
        };

        private static readonly HashSet<char> ASCII_CHARS = new HashSet<char>();

        static ModbusTcpPacketHandler() {
            for (char c = 'a'; c < 'z'; c++)
                ASCII_CHARS.Add(c);
            for (char c = 'A'; c < 'Z'; c++)
                ASCII_CHARS.Add(c);
            for (char c = '0'; c < '9'; c++)
                ASCII_CHARS.Add(c);
            ASCII_CHARS.Add(' ');
            ASCII_CHARS.Add('-');
            ASCII_CHARS.Add('_');
            ASCII_CHARS.Add('.');
        }

        private PopularityList<(NetworkTcpSession, ushort), UmasPacket.FC> umasRequestsAwaitingResponse;

        public ModbusTcpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            
            this.umasRequestsAwaitingResponse = new PopularityList<(NetworkTcpSession, ushort), UmasPacket.FC>(100);
        }

        public override Type[] ParsedTypes { get; } = {
            typeof(ModbusTcpPacket),
            typeof(UmasPacket),
        };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.ModbusTCP; }
        }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            int parsedBytes = 0;
            foreach (AbstractPacket p in packetList) {
                if (p is ModbusTcpPacket modbus)
                    parsedBytes += this.ExtractData(tcpSession, transferIsClientToServer, modbus);
                if (p is UmasPacket umas) {
                    if (transferIsClientToServer)
                        this.ExtractUmas(tcpSession, umas, tcpSession.ClientHost, tcpSession.ServerHost);
                    else
                        this.ExtractUmas(tcpSession, umas, tcpSession.ServerHost, tcpSession.ClientHost);
                }
            }

            return parsedBytes;
        }

        private void ExtractUmas(NetworkTcpSession tcpSession, UmasPacket umas, NetworkHost sender, NetworkHost recipient) {
            NameValueCollection parameters = new NameValueCollection();
            string paramName;
            string paramValue = "0x" + umas.UmasFunctionCodeRaw.ToString("X2");
            if (umas.ParentModbusPacket.IsResponse)
                paramName = "UMAS Response";
            else
                paramName = "UMAS Request";

            if (umas.UmasFunctionCode.HasValue) {
                if (umas.SessionKey != 0)
                    parameters.Add("Session Key", "0x" + umas.SessionKey.ToString("X2"));
                if(umas.ParentModbusPacket.IsResponse) {
                    lock(this.umasRequestsAwaitingResponse) {
                        var key = (tcpSession, umas.ParentModbusPacket.TransactionID);
                        if(this.umasRequestsAwaitingResponse.ContainsKey(key)) {
                            var request = this.umasRequestsAwaitingResponse[key];
                            this.umasRequestsAwaitingResponse.Remove(key);
                            paramName = "UMAS " + request.ToString() + " Response";
                            if(request == FC.INIT_COMM) {
                                //extract firmware version
                                //https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
                                byte[] umasBytes = umas.GetPacketData();
                                if(umasBytes.Length > 5) {
                                    byte firmwareMinor = umasBytes[4];
                                    byte firmwareMajor = umasBytes[5];
                                    parameters.Add("Firmware Version", firmwareMajor + "." + firmwareMinor);
                                    if (umasBytes.Length > 15) {
                                        byte hostnameLength = umasBytes[14];
                                        if (hostnameLength > 0) {
                                            int stringIndex = 16;
                                            string hostname = PacketParser.Utils.ByteConverter.ReadNullTerminatedString(umasBytes, ref stringIndex, false, false, hostnameLength, false);
                                            hostname = hostname?.Trim(' ');
                                            if (hostname?.Length > 0) {
                                                parameters.Add("Hostname", hostname);
                                                sender.AddNumberedExtraDetail("UMAS Hostname", hostname);
                                            }
                                        }
                                    }
                                }
                            }
                            else if(request == FC.READ_ID) {
                                byte[] umasBytes = umas.GetPacketData();
                                if(umasBytes.Length > 25) {
                                    byte firmwareMinor = umasBytes[10];
                                    byte firmwareMajor = umasBytes[11];
                                    ushort patchVersion = PacketParser.Utils.ByteConverter.ToUInt16(umasBytes, 12, true);
                                    parameters.Add("Prod Version", firmwareMajor + "." + firmwareMinor + "." + patchVersion);
                                    byte textLength = umasBytes[24];
                                    if(textLength > 0) {
                                        int stringIndex = 25;
                                        string deviceIdName = PacketParser.Utils.ByteConverter.ReadNullTerminatedString(umasBytes, ref stringIndex, false, false, textLength, false);
                                        deviceIdName = deviceIdName?.Trim(' ');
                                        if (deviceIdName?.Length > 0) {
                                            parameters.Add("Device Name", deviceIdName);
                                            sender.AddNumberedExtraDetail("UMAS Device Name", deviceIdName);
                                        }
                                    }
                                }
                            }
                            else if(request == FC.TAKE_PLC_RESERVATION) {
                                if (umas.UmasFunctionCode == FC.Success) {
                                    //https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/
                                    byte newSessionKey = umas.ParentFrame.Data[umas.PacketStartIndex + 2];
                                    parameters.Add("PLC Reservation Session Key", "0x" + newSessionKey.ToString("X2"));
                                }
                            }
                            //READ_PROJECT_INFO here does not match other traffic https://lirasenlared.blogspot.com/2017/08/the-unity-umas-protocol-part-i.html
                            else if (UMAS_REQUEST_RESPONSES_WITH_STRINGS.Contains(request)) {
                                //try extract strings from the response
                                if (PacketParser.Utils.StringManglerUtil.TryFindLongestPascalString(umas.ParentFrame.Data, umas.PacketStartIndex + 2, umas.PacketLength - 2, 3, new[] { '\0', '\n', '\t', ' ' }, out string carved)) {
                                    parameters.Add(paramName + " String", carved.Trim());
                                }
                                else {
                                    foreach (string s in PacketParser.Utils.StringManglerUtil.GetAsciiStrings(umas.ParentFrame.Data, umas.PacketStartIndex + 2, umas.PacketLength - 2, ASCII_CHARS, 6)) {
                                        parameters.Add(paramName + " String", s.Trim());
                                    }
                                }
                            }
                        }
                    }
                    
                }
                else {
                    //request
                    lock (this.umasRequestsAwaitingResponse) {
                        //we have a new request
                        var key = (tcpSession, umas.ParentModbusPacket.TransactionID);
                        this.umasRequestsAwaitingResponse[key] = umas.UmasFunctionCode.Value;
                    }
                    if(umas.UmasFunctionCode == FC.TAKE_PLC_RESERVATION) {
                        //try extract username
                        byte[] umasBytes = umas.GetPacketData();
                        //username length is at offset 6
                        if(umasBytes.Length > 7) {
                            byte usernameLength = umasBytes[6];
                            if(usernameLength == 0) {
                                //try read null terminated string as here https://ics-cert.kaspersky.com/wp-content/uploads/sites/27/2022/09/image016-1.png
                                int _index = 7;
                                string username = PacketParser.Utils.ByteConverter.ReadNullTerminatedString(umasBytes, ref _index);
                                if (username?.Length > 0) {
                                    parameters.Add("UMAS Username", username);
                                    sender.AddNumberedExtraDetail("UMAS Username", username);
                                }
                            }
                            else if(usernameLength + 7 <= umasBytes.Length) {
                                string username = System.Text.ASCIIEncoding.ASCII.GetString(umasBytes, 7, usernameLength);
                                parameters.Add("UMAS Username", username);
                                sender.AddNumberedExtraDetail("UMAS Username", username);
                            }
                        }
                    }
                    else if(umas.UmasFunctionCode == FC.READ_MEMORY_BLOCK) {
                        ushort blockNumber = PacketParser.Utils.ByteConverter.ToUInt16(umas.ParentFrame.Data, umas.PacketStartIndex + 3, true);
                        ushort atOffset = PacketParser.Utils.ByteConverter.ToUInt16(umas.ParentFrame.Data, umas.PacketStartIndex + 5, true);
                        parameters.Add("Read Block [Offset]", blockNumber.ToString() + "[" + atOffset + "]");
                    }
                    else if(umas.UmasFunctionCode == FC.READ_COILS_REGISTERS) {
                        byte[] umasBytes = umas.GetPacketData();
                        byte objectType = umasBytes[4];
                        ushort startAddress = PacketParser.Utils.ByteConverter.ToUInt16(umasBytes, 5, true);

                        if(Enum.IsDefined(typeof(ModbusTcpPacket.AddressType), objectType)) {
                            ModbusTcpPacket.AddressType type = (ModbusTcpPacket.AddressType)objectType;
                            parameters.Add("Read " + type.ToString(), ModbusTcpPacket.ToModiconAddressNotaion(startAddress, type));
                        }
                    }
                    else if (umas.UmasFunctionCode == FC.WRITE_COILS_REGISTERS) {
                        byte[] umasBytes = umas.GetPacketData();
                        byte objectType = umasBytes[4];
                        ushort startAddress = PacketParser.Utils.ByteConverter.ToUInt16(umasBytes, 5, true);

                        if (Enum.IsDefined(typeof(ModbusTcpPacket.AddressType), objectType)) {
                            ModbusTcpPacket.AddressType type = (ModbusTcpPacket.AddressType)objectType;
                            parameters.Add("Write " + type.ToString(), ModbusTcpPacket.ToModiconAddressNotaion(startAddress, type));
                        }
                    }
                    else if (umas.UmasFunctionCode == FC.ReadPhysicalAddress) {
                        uint address = PacketParser.Utils.ByteConverter.ToUInt32(umas.ParentFrame.Data, umas.PacketStartIndex + 2, 4, true);
                        //next 2 bytes is the length
                        parameters.Add("Read Physical Address", "0x" + address.ToString("X8"));
                    }
                    else if(umas.UmasFunctionCode == FC.WritePhysicalAddress) {
                        uint address = PacketParser.Utils.ByteConverter.ToUInt32(umas.ParentFrame.Data, umas.PacketStartIndex + 2, 4, true);
                        //next 2 bytes is the length
                        parameters.Add("Write to Physical Address", "0x" + address.ToString("X8"));
                    }
                    else if (UMAS_REQUESTS_WITH_STRINGS.Contains(umas.UmasFunctionCode.Value)) {
                        //try to extract strings from the request
                        if (PacketParser.Utils.StringManglerUtil.TryFindLongestPascalString(umas.ParentFrame.Data, umas.PacketStartIndex + 2, umas.PacketLength - 2, 3, new[] { ' ', '\n', '\0', '\t' }, out string carved)) {
                            parameters.Add("UMAS Request String", carved);
                        }
                        else {
                            foreach (string s in PacketParser.Utils.StringManglerUtil.GetAsciiStrings(umas.ParentFrame.Data, umas.PacketStartIndex + 2, umas.PacketLength - 2, ASCII_CHARS, 6))
                                parameters.Add("UMAS Request String", s.Trim());
                        }
                    }

                }
                paramValue += " " + umas.UmasFunctionCode.ToString();
            }
            parameters.Add(paramName, paramValue);
            if (parameters.Count > 0) {
                //this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(umas.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, !umas.ParentModbusPacket.IsResponse, parameters, umas.ParentFrame.Timestamp, "UMAS TxID " + umas.ParentModbusPacket.TransactionID + " SessionKey 0x" + umas.SessionKey.ToString("X2")));
                if (this.TryGetPorts(sender, recipient, tcpSession, umas.ParentModbusPacket, out ushort sourcePort, out ushort destinationPort)) {
                    this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(umas.ParentFrame.FrameNumber, sender, recipient, RFC1700Protocol.TCP, sourcePort, destinationPort, parameters, umas.ParentFrame.Timestamp, "UMAS TxID " + umas.ParentModbusPacket.TransactionID + " SessionKey 0x" + umas.SessionKey.ToString("X2")));
                }
            }
        }

        private bool TryGetPorts(NetworkHost sender, NetworkHost recipient, NetworkTcpSession tcpSession, ModbusTcpPacket modbusPacket, out ushort sourcePort, out ushort destinationPort) {
            if (sender != recipient) {
                if (sender == tcpSession.ClientHost) {
                    sourcePort = tcpSession.ClientTcpPort;
                    destinationPort = tcpSession.ServerTcpPort;
                    return true;
                }
                else if (sender == tcpSession.ServerHost) {
                    sourcePort = tcpSession.ServerTcpPort;
                    destinationPort = tcpSession.ClientTcpPort;
                    return true;
                }
                else {
                    sourcePort = 0;
                    destinationPort = 0;
                    return false;
                }
            }

            //special case if src IP == dst IP
            foreach (AbstractPacket packet in modbusPacket.ParentFrame.PacketList) {
                if (packet is TcpPacket) {
                    TcpPacket tcpPacket = packet as TcpPacket;
                    sourcePort = tcpPacket.SourcePort;
                    destinationPort = tcpPacket.DestinationPort;
                    return true;
                }
            }
            //backup solution in case everything else fails
            if (modbusPacket.IsResponse) {
                sourcePort = tcpSession.ServerTcpPort;
                destinationPort = tcpSession.ClientTcpPort;
                return true;
            }
            else {
                sourcePort = tcpSession.ClientTcpPort;
                destinationPort = tcpSession.ServerTcpPort;
                return true;
            }
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, ModbusTcpPacket modbusPacket) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }

            foreach (string anomaly in modbusPacket.Anomalies)
                SharedUtils.Logger.Log(anomaly + " (frame " + modbusPacket.ParentFrame.FrameNumber + ")", SharedUtils.Logger.EventLogEntryType.Warning);

            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();

            StringBuilder pName = new StringBuilder();
            if (modbusPacket.IsResponse)
                pName.Append("RSP ");
            else
                pName.Append("QRY ");
            pName.Append("sa:" + modbusPacket.SlaveAddress.ToString().PadRight(4));
            pName.Append("fc:" + modbusPacket.FunctionCode.ToString() + " (" + modbusPacket.FunctionCodeName.ToString() + ")");

            if (modbusPacket.IsResponse) {
                if (modbusPacket.ModbusMessage == null)
                    parameters.Add(pName.ToString(), "");
                else
                    parameters.Add(pName.ToString(), modbusPacket.ModbusMessage.ToString());

                if (modbusPacket.FunctionCodeName == ModbusTcpPacket.FunctionCodeEnum.ReadDeviceIdentification) {
                    if (modbusPacket.ModbusMessage is DeviceIdentificationResponse deviceIDResponse) {
                        string deviceID = deviceIDResponse.ToString();
                        if (!string.IsNullOrEmpty(deviceID))
                            sourceHost.AddNumberedExtraDetail("Device ID", deviceID);
                    }
                }

            }
            else {//QUERY
                if (modbusPacket.ModbusMessage == null)
                    parameters.Add(pName.ToString(), "UNKNOWN");
                else {
                    parameters.Add(pName.ToString(), modbusPacket.ModbusMessage.ToString());
                }
            }

            if(this.TryGetPorts(sourceHost, destinationHost, tcpSession, modbusPacket, out ushort sourcePort, out ushort destinationPort)) {
                this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(modbusPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, RFC1700Protocol.TCP, sourcePort, destinationPort, parameters, modbusPacket.ParentFrame.Timestamp, "Modbus/TCP Transaction ID: " + modbusPacket.TransactionID.ToString()));
            }

            return Math.Min(modbusPacket.Length + 6, modbusPacket.PacketLength);
        }

        public void Reset() {
            this.umasRequestsAwaitingResponse.Clear();
        }
    }
}
