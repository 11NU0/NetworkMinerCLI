using PacketHandlerFramework.FileTransfer;
using PacketParser;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Packets.IEC_60870_5_104Packet;

namespace PacketHandlerFramework.PacketHandlers {
#if !OMIT_MALWARE_PROTOCOLS
    class RemcosPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        public RemcosPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler) {
        }

        public ApplicationLayerProtocol HandledProtocol {
            get => ApplicationLayerProtocol.Remcos;
        }

        public override Type[] ParsedTypes {
            get => new[] { typeof(PacketParser.Packets.RemcosPacket) };
        }

        private readonly DateTime EPOCH = new DateTime(1970, 1, 1);
        private const string TIMESPAN_FORMAT = "hh':'mm':'ss'.'fff";



        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            if (base.TryGetPacket(packetList, out RemcosPacket remcosPacket)) {

                NetworkHost sourceHost, destinationHost;
                ushort sourcePort, destinationPort;
                if (transferIsClientToServer) {
                    sourceHost = tcpSession.ClientHost;
                    sourcePort = tcpSession.ClientTcpPort;
                    destinationHost = tcpSession.ServerHost;
                    destinationPort = tcpSession.ServerTcpPort;
                }
                else {
                    sourceHost = tcpSession.ServerHost;
                    sourcePort = tcpSession.ServerTcpPort;
                    destinationHost = tcpSession.ClientHost;
                    destinationPort = tcpSession.ClientTcpPort;
                }

                NameValueCollection parameters = new NameValueCollection();


                bool fieldsParsed = false;
                int extraBytesProcessed = 0;
                if (remcosPacket.TryGetCommand(out var command)) {
                    parameters.Add("Remcos Command", command.ToString() + " (0x" + ((uint)command).ToString("x2") + ")");
                    if (transferIsClientToServer) {
                        if (command == RemcosPacket.RemcosCommand.SystemInfoFull) {
                            if (this.TryGetClientSystemInfoFullFields(remcosPacket, sourceHost, destinationHost, out var firstPacketNvc)) {
                                parameters.Add(firstPacketNvc);
                                fieldsParsed = true;
                            }
                        }
                        else if (command == RemcosPacket.RemcosCommand.SystemInfoUpdate) {
                            if (this.TryGetClientSystemInfoUpdateFields(remcosPacket, out var clientUpdateNvc)) {
                                parameters.Add(clientUpdateNvc);
                                fieldsParsed = true;
                            }
                        }
                        else if (command == RemcosPacket.RemcosCommand.GeoIP) {
                            if (this.TryGetClientGeoIP(remcosPacket, out var jsonNvc)) {
                                parameters.Add(jsonNvc);
                                string[] publicIPs = jsonNvc.GetValues("geoplugin_request");
                                if (publicIPs.Length > 0 && !string.IsNullOrEmpty(publicIPs[0]) && IPAddress.TryParse(publicIPs[0], out IPAddress publicIP)) {
                                    sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, publicIP.ToString());
                                }
                                fieldsParsed = true;
                            }
                        }
                        else if (command == RemcosPacket.RemcosCommand.HostnameAndUser) {
                            List<byte[]> fields = remcosPacket.GetFields(false).ToList();
                            if (fields.Count == 2) {
                                if (TryGetNumber(fields[0], out long number))
                                    parameters.Add("Remcos Number", number.ToString());
                                if (TryExtractHostnameAndUser(fields[1], parameters, sourceHost)) {
                                    fieldsParsed = true;
                                }
                            }
                        }
                        else if (command == RemcosPacket.RemcosCommand.ScreenCaptureData) {
                            List<byte[]> f = remcosPacket.GetFields(false, false).ToList();
                            if (f.Count == 2) {
                                if (TryGetNumber(f[0], out long number1)) {
                                    parameters.Add("Remcos Number", number1.ToString());
                                    int lengthOfNumbersAndDelimiters = f[0].Length + RemcosPacket.DELIMITER.Length;
                                    string filename = "screenshot-" + remcosPacket.ParentFrame.Timestamp.ToUniversalTime().ToString("yyMMddHHmmss");//same approach as in RfbPacketHandler.cs
                                    //check file header in f[1]
                                    if (f[1].Length > 3) {
                                        string extension = FileTransfer.FileStreamAssembler.GetExtensionFromHeader(f[1]);
                                        if (!string.IsNullOrEmpty(extension))
                                            filename = filename + "." + extension;
                                    }
                                    if (this.TryStartFileStreamAssembler(remcosPacket, lengthOfNumbersAndDelimiters, f[1], tcpSession, transferIsClientToServer, filename, out extraBytesProcessed)) {
                                        //YAY!
                                    }
                                }
                            }
                        }
                        else if(command == RemcosPacket.RemcosCommand.ActiveWindowUpdate) {
                            if(this.TryGetActiveWindowUpdateFields(remcosPacket, out var nvc)) {
                                parameters.Add(nvc);
                                fieldsParsed = true;
                            }
                        }
                        
                    }
                    else {
                        if (command == RemcosPacket.RemcosCommand.SendAndExecute) {
                            if (this.TryCreateToolFileStreamAssembler(remcosPacket, tcpSession, transferIsClientToServer, out var nvc, out extraBytesProcessed)) {
                                parameters.Add(nvc);

                            }
                        }
                        else if (command == RemcosPacket.RemcosCommand.SendNamedFile) {
                            if (remcosPacket.PacketHeaderIsComplete && this.TryAssembleNamedFile(remcosPacket, tcpSession, transferIsClientToServer, out string filename)) {
                                parameters.Add("Remcos Sent Filename", filename);
                                fieldsParsed = true;
                            }
                        }
                    }
                }
                else
                    parameters.Add("Remcos Unknown Command", "0x" + remcosPacket.CommandNumber.ToString("x8"));


                if (!fieldsParsed) {
                    foreach (byte[] field in remcosPacket.GetFields(true)) {
                        if (field.Length > 0) {
                            if (field[0] == '{') {
                                var jsonNvc = JsonUtils.GetParams(field, false, 30, out _);
                                parameters.Add(jsonNvc);
                            }
                            else if (TryGetNumber(field, out long number))
                                parameters.Add("Remcos Number", number.ToString());
                            else if (TryGetAscii(field, out string asciiString))
                                parameters.Add("Remcos ASCII string", asciiString);
                            else if (TryGetUnicode(field, true, out string unicodeString))
                                parameters.Add("Remcos Unicode string", unicodeString);
                            //TODO: Look for [00] 30 a7 ff [00] and extract Unicode string further ahead
                            else if (field.Length > 0)
                                parameters.Add("Remcos Data", string.Join("", field.Select(b => b.ToString("x2"))));
                        }
                    }
                }
                if (parameters.Count > 0) {
                    Events.ParametersEventArgs parametersEA = new Events.ParametersEventArgs(remcosPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parameters, remcosPacket.ParentFrame.Timestamp, "Remcos RAT Parameter");
                    this.MainPacketHandler.OnParametersDetected(parametersEA);
                }
                return remcosPacket.ParsedBytesCount + extraBytesProcessed;
            }
            else
                return 0;
        }

        private bool TryCreateToolFileStreamAssembler(RemcosPacket remcosPacket, NetworkTcpSession tcpSession, bool transferIsClientToServer, out NameValueCollection nvc, out int extraBytesProcessed) {
            //2 numbers
            //MZ binary file
            List<byte[]> f = remcosPacket.GetFields(false, false).ToList();
            if (f.Count == 3) {
                nvc = new NameValueCollection();
                if (TryGetNumber(f[0], out long number1)) {
                    nvc.Add("Remcos Number", number1.ToString());
                    if (TryGetNumber(f[1], out long number2)) {
                        nvc.Add("Remcos Number", number2.ToString());

                        int lengthOfNumbersAndDelimiters = f[0].Length + f[1].Length + 2 * RemcosPacket.DELIMITER.Length;
                        string filename = "REMCOS-TOOL.BIN";
                        if (this.TryStartFileStreamAssembler(remcosPacket, lengthOfNumbersAndDelimiters, f[2], tcpSession, transferIsClientToServer, filename, out extraBytesProcessed)) {
                            //YAY, file stream assembler started!
                            return true;
                        }
                        else if (f[2].Length > 0) {
                            //this code will only run if no file stream assembler was created
                            string headerHex = string.Join(" ", f[2].Take(4).Select(b => b.ToString("x2")));
                            nvc.Add("Remcos Download Header", headerHex);
                        }
                    }
                }
            }
            extraBytesProcessed = 0;
            nvc = null;
            return false;
        }

        private bool TryStartFileStreamAssembler(RemcosPacket remcosPacket, int lengthOfPreviousFieldsAndDelimiters, byte[] fieldDataSegment, NetworkTcpSession tcpSession, bool transferIsClientToServer, string filename, out int extraBytesProcessed) {
            FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.Remcos, filename, string.Empty, RemcosPacket.RemcosCommand.SendAndExecute.ToString(), remcosPacket.ParentFrame.FrameNumber, remcosPacket.ParentFrame.Timestamp);
            int fileSize = (int)(remcosPacket.RemcosPayloadLength - 4 - lengthOfPreviousFieldsAndDelimiters);
            assembler.FileContentLength = fileSize;
            assembler.FileSegmentRemainingBytes = fileSize;
            if (assembler.TryActivate()) {
                this.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                //TODO add special handling if Remcos header is complete
                if (remcosPacket.PacketHeaderIsComplete && fieldDataSegment.Length >= fileSize) {
                    assembler.AddData(fieldDataSegment, 0);
                    extraBytesProcessed = 0;
                }
                else {
                    extraBytesProcessed = 12 + lengthOfPreviousFieldsAndDelimiters;
                }
                return true;
            }
            else
                assembler.Dispose();
            extraBytesProcessed = 0;
            return false;
        }

        private bool TryAssembleNamedFile(RemcosPacket remcosPacket, NetworkTcpSession tcpSession, bool transferIsClientToServer, out string filename) {
            List<byte[]> fields = remcosPacket.GetFields(false).ToList();
            if(fields.Count > 4) {
                if (TryGetUnicode(fields[3], true, out filename)) {
                    if (!string.IsNullOrEmpty(filename)) {
                        if (fields[4].Length > 0) {
                            using (FileStreamAssembler assembler = new FileStreamAssembler(this.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileStreamTypes.Remcos, filename, string.Empty, RemcosPacket.RemcosCommand.SendNamedFile.ToString(), remcosPacket.ParentFrame.FrameNumber, remcosPacket.ParentFrame.Timestamp)) {
                                int fileSize = fields[4].Length;
                                assembler.FileContentLength = fileSize;
                                assembler.FileSegmentRemainingBytes = fileSize;
                                if (assembler.TryActivate()) {
                                    assembler.AddData(fields[4], 0);
                                    return true;
                                }
                            }
                            
                        }
                    }
                }
            }
            filename = null;
            return false;
        }

        private bool TryGetClientGeoIP(RemcosPacket remcosPacket, out NameValueCollection jsonNvc) {
            List<byte[]> fields = remcosPacket.GetFields(false).ToList();
            if (fields.Count == 1 && fields.First()[0] == '{') {
                jsonNvc = JsonUtils.GetParams(fields.First(), false, 30, out _);
                return true;
            }
            jsonNvc = null;
            return false;
        }

        private bool TryGetActiveWindowUpdateFields(RemcosPacket remcosPacket, out NameValueCollection nvc) {
            List<byte[]> fields = remcosPacket.GetFields(true).ToList();
            if (fields.Count == 1 && fields[0].Length > 17) {
                //skip 17 bytes of unknown data typically starting with 00 30 a7 ff
                /**
                 * 00 30 a7 ff 00 00 00 00 00 20 3c 7a 00 00 00 00
                 * 52 44 00 45 00 4d 00 41 00 4e 00 44 00 41 00 5f
                 * 00 35 00 2e 00 52 00 41 00 52 00 00 00
                 * 
                 * 
                 * 00 30 a7 ff 00 00 00 00 00 90 8f 7b 00 00 00 00
                 * 01 53 00 6f 00 70 00 6f 00 72 00 74 00 65 00 20
                 * 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20
                 * 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 46
                 * 00 6f 00 72 00 7a 00 61 00 64 00 6f 00 00 00

                 */
                fields[0].Skip(17).ToArray();
                if (TryGetUnicode(fields[0].Skip(17).ToArray(), true, out string activeWindow)) {
                    nvc = new NameValueCollection();
                    nvc.Add("Remcos Active Window", activeWindow);
                    return true;
                }
            }
            nvc = null;
            return false;
        }

        private bool TryGetClientSystemInfoUpdateFields(RemcosPacket remcosPacket, out NameValueCollection nvc) {
            List<byte[]> fields = remcosPacket.GetFields(false).ToList();
            if (fields.Count == 4) {
                nvc = new NameValueCollection();
                if (TryGetNumber(fields[0], out long number))
                    nvc.Add("Remcos Number", number.ToString());
                if (TryGetUnicode(fields[1], false, out string activeWindow))
                    nvc.Add("Remcos Active Window", activeWindow);
                if (TryGetNumber(fields[2], out long timespan1))
                    nvc.Add("Remcos Idle Time", TimeSpan.FromMilliseconds(timespan1).ToString(TIMESPAN_FORMAT));
                else
                    return false;
                if (TryGetNumber(fields[3], out long uptime))
                    nvc.Add("Remcos Uptime", TimeSpan.FromMilliseconds(uptime).ToString(TIMESPAN_FORMAT));
                else
                    return false;
                return true;
            }
            nvc = null;
            return false;
        }

        private bool TryGetClientSystemInfoFullFields(RemcosPacket remcosPacket, NetworkHost sourceHost, NetworkHost destinationHost, out NameValueCollection nvc) {
            List<byte[]> fields = remcosPacket.GetFields(false).ToList();

            if (fields.Count > 20) {
                nvc = new NameValueCollection();
                //Remcos assigned name
                if (TryGetAscii(fields[0], out string assignedName))
                    nvc.Add("Remcos Assigned Name", assignedName);
                else
                    return false;
                //Victim’s user name and computer name
                if (TryExtractHostnameAndUser(fields[1], nvc, sourceHost)) {
                    //nothing more needed
                }
                else
                    return false;
                //Country
                if (TryGetAscii(fields[2], out string country))
                    nvc.Add("Remcos country", country);
                //Windows edition
                if (TryGetAscii(fields[3], out string winVer)) {
                    nvc.Add("Remcos OS", winVer);
                    sourceHost.AddNumberedExtraDetail("OS", winVer);
                }
                //skip #4
                //total RAM(3757629400) in bytes
                if (TryGetNumber(fields[5], out long ramLong) && ramLong > 0)
                    nvc.Add("Remcos RAM", ((ramLong >> 20) / 1024.0).ToString("0.00", CultureInfo.InvariantCulture) + " GB");
                //Remcos version
                if (TryGetAscii(fields[6], out string remcosVer)) {
                    nvc.Add("Remcos Version", remcosVer);//5.1.1 Pro, 6.1.0 Pro
                    sourceHost.AddNumberedExtraDetail("Remcos version", remcosVer);
                }
                else
                    return false;
                //skip #7
                //The full path of current RegAsm.exe
                if (TryGetUnicode(fields[8], false, out string path))
                    nvc.Add("Remcos Path", path);
                //skip #8
                //the title of the currently active program(the victim’s using)
                if (TryGetUnicode(fields[10], false, out string activeWindow))
                    nvc.Add("Remcos Active Window", activeWindow);
                //else
                //    return false;
                //Victim’s idle time?
                if (TryGetNumber(fields[11], out long time1))
                    nvc.Add("Remcos Number", time1.ToString());
                else
                    return false;
                //Victim’s idle time? (ms)
                if (TryGetNumber(fields[12], out long time2))
                    nvc.Add("Remcos Idle Time", TimeSpan.FromMilliseconds(time2).ToString(TIMESPAN_FORMAT));
                else
                    return false;
                //Uptime (ms)
                if (TryGetNumber(fields[13], out long time3))
                    nvc.Add("Remcos Uptime", TimeSpan.FromMilliseconds(time3).ToString(TIMESPAN_FORMAT));
                else
                    return false;
                //skip #14
                //C2 server host
                if (TryGetAscii(fields[15], out string c2)) {
                    nvc.Add("Remcos C2", c2);
                    destinationHost.AddHostName(c2, "Remcos RAT");
                }
                else
                    return false;
                //unknown string
                if (TryGetAscii(fields[16], out string s1)) {
                    nvc.Add("Remcos Mutex", s1);
                }
                //unknown number #17
                if (TryGetUnicode(fields[18], false, out string cmd))
                    nvc.Add("Remcos Installation Path", cmd);
                //CPU
                if (TryGetAscii(fields[19], out string cpu)) {
                    nvc.Add("Remcos CPU", cpu);
                    sourceHost.AddNumberedExtraDetail("CPU", cpu);
                }
                else
                    return false;
                //Remcos payload type(EXE or DLL)
                if (TryGetAscii(fields[20], out string payloadType)) {
                    nvc.Add("Remcos Payload Type", payloadType.ToString());
                }
                else
                    return false;
                return true;
            }
            nvc = null;
            return false;
        }

        private static bool TryExtractHostnameAndUser(byte[] field, NameValueCollection nvc, NetworkHost sourceHost) {
            if (TryGetUnicode(field, true, out string hostAndUser)) {
                nvc.Add("Remcos Host/User", hostAndUser);
                if (hostAndUser.Contains("/")) {
                    var parts = hostAndUser.Split('/');
                    sourceHost.AddHostName(parts[0], "Remcos RAT");
                    sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.User, parts[1]);
                }
                return true;
            }
            return false;
        }

        private static bool TryGetUnicode(byte[] data, bool expectMostlyAscii, out string unicode) {
            if (data.Length % 2 == 0) {
                if (expectMostlyAscii) {
                    int zeroCount = data.Where((byte b, int index) => index % 2 == 1 && b == 0).Count();
                    if (zeroCount <= data.Length / 4) {
                        unicode = null;
                        return false;
                    }
                }
                return PacketParser.Utils.StringManglerUtil.TryGetUnicodeString(data, 0, data.Length, true, out unicode) && !string.IsNullOrEmpty(unicode);
            }
            else {
                unicode = null;
                return false;
            }
        }

        private static bool TryGetNumber(byte[] data, out long number) {
            if (TryGetAscii(data, out string ascii))
                return long.TryParse(ascii, out number);
            number = -1;
            return false;
        }

        private static bool TryGetAscii(byte[] data, out string ascii) {
            if (PacketParser.Utils.StringManglerUtil.TryGet7BitAsciiString(data, 0, data.Length, out ascii)) {
                ascii = ascii.Trim();
                return !string.IsNullOrEmpty(ascii);
            }
            else
                return false;

        }


        public void Reset() {
            //no context to reset
        }
    }
#endif
}
