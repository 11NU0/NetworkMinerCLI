using PacketParser.Utils;
using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Packets {

#if !OMIT_MALWARE_PROTOCOLS
    public class NjRatPacket : AbstractPacket, ISessionPacket {
        //There isn't any good publicly available protocol spec for njRAT, but here's some info:
        //https://github.com/csieteco/njRatActiveDefense/blob/master/njdetector.py
        //https://cybergeeks.tech/just-another-analysis-of-the-njrat-malware-a-step-by-step-approach/
        //https://faculty.cc.gatech.edu/~pearce/papers/rats_usenix_2018.pdf
        //Approach of an Active Defense Protocol to Deal with RAT Malware - A Colombian Case Study Against njRAT Campaigns (Quinterno et al)
        //https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Modules/Class7.vb
        //File Manager?: https://github.com/mwsrc/njRAT/blob/master/njRAT/NjRAT/Forms/Manager.vb

        #region Static

        private static readonly string[] DELIMITERS = {

        };

        private static readonly HashSet<string> KnownCommandsAndResponses = new HashSet<string> {
                "~" ,
                "act",
                "bla",
                "CAM",
                "CAP",//Screen Capture
                "CH",
                "ER",
                "Ex",//Execute Tool
                "FM",
                "get",
                "inf",//Get volume serial, C2 server, process name etc.
                "infn",
                "info",
                "INS",
                "inv",//?? invoke module
                "kla",
                "kl",//Get Key Logger data
                "li",
                "ll",
                "llv",
                "lv",
                "lvv",
                "MIC",
                "MSG",
                "pl",
                "PLG",
                "post",
                "post+",
                "P",//PING or just an empty message if length fields are used
                "proc",
                "prof",//?? Create registry key
                "ret",//Get Passwords (runs assembly pw.dll?)
                "RG",//Reads, writes or deletes registry keys
                "rn",//Run command
                "rs",
                "rsc",
                "rss",
                "sc~",
                "scPK",
                "srv",
                "STP",
                "tcp",
                "un",//Uninstall, kill or restart njRAT"
                "up",//?? Update njRAT from URL or archive data
                "WT"
            };


        public enum FieldEncoding {
            plaintext,
            base64,
            raw
        }
        public enum Plugins {
            rs,//Reverse Shell
            rsc,//kill reverse shell
            proc,//Process List
            tcp,//TCP connection request
            srv,//Services request
            fm//File Manager
        }

        public enum ProcActions {
            //'~' (tilde) => retrieve information about the current process and the other running processes
            //'!'
            k, //kill process
            kd,//kill and delete files
            re,//restart process
            rss,//run shell session
        }

        public enum FileManagerActions {
            dw,//Download
            up,//Upload
            cp,//Copy
            rn,//Run
            fl,//Run From Link
            rd//Read? Read and Delete?
        }

        public enum BotMessageType {
            ll,//Victim checkin. Can be any of: lv, llv, lvv or ll
            li,//alternative to ll with base64 encoded hostnames and usernames
            act,//active window
            inf,//Get volume serial, C2 server, process name etc.
            infn,//Get volume serial, C2 server, process name etc.
            CAP,//followed by [delimiter][JPEG]
            pl,
            PLG,
            sc_tilde,
            scPK,//delivers screenshot
            CH,//chat message
            FM,//File Manager
            rs,//Reverse Shell
            fun,
            sitel,
            WT,
            INS,//installed software
            STP,//list startup/autorun keys in registry
            proc,//process info
            srv,//service info
            tcp,//netstat info
            post,//file/data sent to C2 server
            get,//file downloaded from C2 server
            ret,//send credentials to C2 server
            kl,//keylogger
        }

        public static readonly Dictionary<string, BotMessageType> BotMsgDict = new Dictionary<string, BotMessageType> {
                { "lv", BotMessageType.ll },//Victim checkin
                { "llv", BotMessageType.ll },//Victim checkin (alternative)
                { "lvv", BotMessageType.ll },//Victim checkin (alternative #2)
                { "ll", BotMessageType.ll },//Victim checkin (alternative #3), typically <LEN><NULL>ll
                { "li", BotMessageType.li },//Victim checkin (alternative #4)
                { "act", BotMessageType.act },//active window
                { "inf", BotMessageType.inf },//Get volume serial, C2 server, process name etc.
                { "infn", BotMessageType.infn },//Get volume serial, C2 server, process name etc.
                { "CAP", BotMessageType.CAP },//followed by [delimiter][JPEG]
                { "pl", BotMessageType.pl },
                { "PLG", BotMessageType.PLG },
                { "sc~", BotMessageType.sc_tilde },//shows screen resolution
                { "scPK", BotMessageType.scPK },//Screen shot
                { "CH", BotMessageType.CH },//chat message
                { "FM", BotMessageType.FM },//File Manger
                { "rs", BotMessageType.rs },//output from Reverse Shell
                { "fun", BotMessageType.fun },
                { "site", BotMessageType.sitel },
                { "WT", BotMessageType.WT },
                { "INS", BotMessageType.INS },//installed software
                { "STP", BotMessageType.STP },//list startup/autorun keys in registry
                { "proc", BotMessageType.proc },//process info
                { "srv", BotMessageType.srv },//process info
                { "tcp", BotMessageType.tcp },//netstat info
                { "post", BotMessageType.post },//file sent to C2 server
                { "get", BotMessageType.get },//file downloaded from C2 server
                { "ret", BotMessageType.ret },//retrieve credentials
                { "kl", BotMessageType.kl }//keylogger
            };

        public const string HOSTNAME = "Hostname";
        public const string BOTNET_BOTID = "Botnet_BotID";
        public const string OS = "OS";
        public const string USER = "User";
        public const string VERSION = "Version";
        public const string FOREGROUND_WINDOW = "Foreground Window";//Retrieved through call to GetForegroundWindow()
        public const string INSTALL_DATE = "Install Date";
        public const string FILENAME = "Filename";//used in post
        public const string SIZE = "Size";//used in post
        public const string IP_COLON_PORT = "IP:port";
        public const string CREDENTIALS = "Credentials";
        public const string UNKNOWN_FIELD = "?";

        /**
         * ll|'|'|SGFjS2VkX0M0QkEzNjQ3|'|'|USER-PC|'|'|admin|'|'|21-05-19|'|'||'|'|Win 7 Professional SP1 x86|'|'|No|'|'|im523|'|'|..|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==|'|'|
         * inf|'|'|SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
        */
        public static readonly Dictionary<BotMessageType, (string name, FieldEncoding encoding)[]> BotMessageFieldInfo = new Dictionary<BotMessageType, (string name, FieldEncoding encoding)[]> {
                {
                    BotMessageType.ll, new[] {
                        (BOTNET_BOTID, FieldEncoding.base64),
                        (HOSTNAME, FieldEncoding.plaintext),
                        (USER, FieldEncoding.plaintext),
                        (INSTALL_DATE, FieldEncoding.plaintext),
                        ("Flag", FieldEncoding.plaintext),//""
                        (OS, FieldEncoding.plaintext),
                        ("Camera", FieldEncoding.plaintext),//No
                        (VERSION, FieldEncoding.plaintext),//im523 or 0.7NC
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),//..
                        (FOREGROUND_WINDOW, FieldEncoding.base64),
                        (UNKNOWN_FIELD, FieldEncoding.plaintext)//"" (empty)
                    }
                },
                {
                    BotMessageType.li, new[] {
                        (BOTNET_BOTID, FieldEncoding.base64),
                        (HOSTNAME, FieldEncoding.base64),
                        (USER, FieldEncoding.base64),
                        (INSTALL_DATE, FieldEncoding.plaintext),
                        ("Flag", FieldEncoding.plaintext),//""
                        (OS, FieldEncoding.plaintext),
                        ("Camera", FieldEncoding.plaintext),//No
                        (VERSION, FieldEncoding.plaintext),//im523 or 0.7NC
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),//..
                        (FOREGROUND_WINDOW, FieldEncoding.base64),
                        (UNKNOWN_FIELD, FieldEncoding.plaintext)//"" (empty)
                    }
                },
                {
                    BotMessageType.act, new[] {
                        (FOREGROUND_WINDOW, FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.inf, new[] {
                        ("Info Multiline", FieldEncoding.base64)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    BotMessageType.infn, new[] {
                        ("Info CSV", FieldEncoding.base64)//bG9ncyxsb2dzN3dhLmRkbnMubmV0OjExNzcsQWxsVXNlcnNQcm9maWxlLGR3bS5leGUsVHJ1ZSxUcnVlLFRydWUsVHJ1ZSxUcnVlLFRydWUs
                    }
                },
                {
                    BotMessageType.CAP, new[] {
                        ("Screenshot", FieldEncoding.raw)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    //45.pl|'|'|2681e81bb4c4b3e6338ce2a456fb93a7|'|'|0
                    BotMessageType.pl, new[] {
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),
                        (UNKNOWN_FIELD, FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.sc_tilde, new[] {
                        ("IP:port", FieldEncoding.plaintext),
                        ("width", FieldEncoding.plaintext),
                        ("height", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.scPK, new[] {
                        ("IP:port", FieldEncoding.plaintext),
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),
                        ("Screenshot", FieldEncoding.raw)
                    }
                },
                {
                    //CH|'|'|46.244.28.106:49374|'|'|!
                    //CH|'|'|46.244.28.106:49374|'|'|@|'|'|eW91IGdleQ==
                    BotMessageType.CH, new[] {
                        (IP_COLON_PORT, FieldEncoding.plaintext),
                        ("Type", FieldEncoding.plaintext)//'~', '!' or '@'
                        //("Message", FieldEncoding.base64)//when Type is @
                    }
                },
                {
                    BotMessageType.PLG, new (string name, FieldEncoding encoding)[0]
                },
                {
                    BotMessageType.rs, new[] {
                        ("Reverse Shell", FieldEncoding.base64)//SGFjS2VkDQo5NC40NS4xMTMuMTc5OjQ1NzcNCkFwcERhdGENCnN2aG9zdC5leGUNClRydWUNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNClRydWU=
                    }
                },
                {
                    BotMessageType.WT, new[] {
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),//!
                        ("WT", FieldEncoding.base64),
                        ("nr", FieldEncoding.plaintext)//9912
                    }
                },
                {
                    BotMessageType.INS, new[] {
                        ("Installed", FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.STP, new[] {
                        (UNKNOWN_FIELD, FieldEncoding.plaintext),//!
                        ("Autorun keys", FieldEncoding.base64),
                        (UNKNOWN_FIELD, FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.proc, new[] {
                        ("Type", FieldEncoding.plaintext),//!
                        ("Process Info", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.srv, new[] {
                        ("Type", FieldEncoding.plaintext),//!
                        ("Service Info", FieldEncoding.plaintext)
                    }
                }
                ,
                {
                    BotMessageType.tcp, new[] {
                        ("Type", FieldEncoding.plaintext),//~
                        ("Netstat Info", FieldEncoding.plaintext)
                    }
                },
                {
                    BotMessageType.post, new[] {
                        (FILENAME, FieldEncoding.base64),
                        (SIZE, FieldEncoding.plaintext),
                        (IP_COLON_PORT, FieldEncoding.plaintext)
                    }
                }
                ,
                {
                    BotMessageType.get, new[] {
                        (IP_COLON_PORT, FieldEncoding.plaintext),
                        (FILENAME, FieldEncoding.base64)
                    }
                },
                {
                    BotMessageType.kl, new[] {
                        ("KeyLog Data", FieldEncoding.base64)
                    }
                }
                /*
                ,
                {
                    BotMessageType.ret, new[] {
                        ("ID", FieldEncoding.plaintext),
                        (CREDENTIALS, FieldEncoding.base64)
                    }
                }
                */
            };


        public enum ServerMessageType {
            CAP,
            Ex,
            inv,
            kl,
            MIC,
            MSG,
            P,
            PLG,
            proc,
            ret,
            rn,
            ErorrMsg,
            OpenSite
        }

        public static readonly Dictionary<string, ServerMessageType?> ServerMsgDict = new Dictionary<string, ServerMessageType?> {
                { "~", null },
                { "!", null },
                { "act", null },
                { "bla", null },
                { "CAM", null },
                { "CAP", ServerMessageType.CAP },//Screen Capture
                { "CH", null },
                { "ER", null },
                { "Ex", ServerMessageType.Ex },//Execute Tool
                { "FM", null },
                { "fun", null },
                { "get", null },
                { "inf", null },//Get volume serial, C2 server, process name etc.
                
                { "inv", ServerMessageType.inv },//?? invoke module
                { "kla", null },
                { "kl", ServerMessageType.kl },//Get Key Logger data
                { "ll", null },
                { "lv", null },
                { "MIC", ServerMessageType.MIC },
                { "MSG", ServerMessageType.MSG },
                { "pl", null },
                { "PLG", ServerMessageType.PLG },
                { "post", null },
                { "post+", null },
                { "P", ServerMessageType.P },//PING or just an empty message if length fields are used
                { "proc", ServerMessageType.proc },
                { "prof", null },//?? Create registry key
                { "ret", ServerMessageType.ret },//Get Passwords (runs assembly pw.dll?)
                { "RG", null },//Reads, writes or deletes registry keys
                { "rn", ServerMessageType.rn },//Run command
                { "rs", null },
                { "rsc", null },
                { "rss", null },
                { "sc~", null },
                { "scPK", null },
                { "site", null },
                { "srv", null },
                { "tcp", null },
                { "un", null },//Uninstall, kill or restart njRAT"
                { "up", null },//?? Update njRAT from URL or archive data
                { "ErorrMsg", ServerMessageType.ErorrMsg },
                { "OpenSite", ServerMessageType.OpenSite },
            };

            public static readonly Dictionary<ServerMessageType, (string name, FieldEncoding encoding)[]> ServerMessageFieldInfo = new Dictionary<ServerMessageType, (string name, FieldEncoding encoding)[]> {
                {
                    //“inv|’|’|<RegistryValue>|’|’|<String1>|’|’|<String2>” command – njRAT has plugins that can be downloaded, saved in registry keys, and then executed
                    ServerMessageType.inv, new[] {
                        ("RegistryValue", FieldEncoding.plaintext),
                        ("param1", FieldEncoding.plaintext),
                        ("param2", FieldEncoding.raw)
                    }
                },
                {
                    //17.CAP|'|'|35|'|'|23
                    ServerMessageType.CAP, new[] {
                        ("width", FieldEncoding.plaintext),
                        ("height", FieldEncoding.plaintext)
                    }
                },
                {
                    ServerMessageType.PLG, new[] {
                        ("file", FieldEncoding.raw),
                    }
                }
                ,
                {
                    ServerMessageType.ErorrMsg, new[] {
                        ("?", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext),
                        ("?", FieldEncoding.plaintext),
                        ("Message", FieldEncoding.plaintext)
                    }
                },
                {
                    ServerMessageType.OpenSite, new[] {
                        ("URL", FieldEncoding.plaintext)
                    }
                }
            };

        private static readonly int MAX_COMMAND_LENGTH = 5;
        private static readonly HashSet<char> CommandChars;

        //private static readonly byte[] JPEG_HEADER = { 0xFF, 0xD8, 0xFF };

        static NjRatPacket() {//default static constructor
            //Add additional commands/responses in case there is any we missed
            foreach (string command in ServerMsgDict.Keys) {
                if (!KnownCommandsAndResponses.Contains(command))
                    KnownCommandsAndResponses.Add(command);
            }
            foreach (string response in BotMsgDict.Keys) {
                if (!KnownCommandsAndResponses.Contains(response))
                    KnownCommandsAndResponses.Add(response);
            }

            CommandChars = new HashSet<char>();
            foreach (string cmd in KnownCommandsAndResponses) {
                foreach (char c in cmd)
                    if (!CommandChars.Contains(c))
                        CommandChars.Add(c);
            }
            MAX_COMMAND_LENGTH = Math.Max(MAX_COMMAND_LENGTH, KnownCommandsAndResponses.OrderByDescending(c => c.Length).First().Length);
        }

        private static bool TryParseLengthField(byte[] data, ref int offset, int length, out int parsedMessageLength) {
            if (data.Length - offset > 1) {
                //check if the message starts with <$length><NULL><command> or a command
                if (data[offset] >= 0x30 && data[offset] <= 0x39) {
                    //first character is a digit
                    //read the null terminated length field
                    string lengthString = Utils.ByteConverter.ReadNullTerminatedString(data, ref offset, false, false, Math.Min(length, 9));
                    if (!string.IsNullOrEmpty(lengthString) && Int32.TryParse(lengthString, out int messageLength)) {
                        parsedMessageLength = messageLength;
                        return true;
                    }
                }
            }
            parsedMessageLength = 0;
            return false;
        }

        private static bool TryParseLength(byte[] data, int startIndex, int length, out int messageStartIndex, out int messageLength, out int totalLength) {
            int offset = startIndex;

            if (TryParseLengthField(data, ref offset, length, out messageLength)) {
                //Length is null terminated ASCII string, followed by the message
                messageStartIndex = offset;
                totalLength = offset + messageLength - startIndex;
                return true;
            }
            else {
                //read until end of frame or index of [endof]
                byte[] endofSequence = ASCIIEncoding.ASCII.GetBytes("[endof]");//5b 65 6e 64 6f 66 5d
                int endofIndex = Utils.BoyerMoore.IndexOf(data, endofSequence, startIndex);
                if (endofIndex > startIndex) {
                    messageStartIndex = startIndex;
                    messageLength = endofIndex - startIndex;
                    totalLength = messageLength + endofSequence.Length;
                    return true;
                }
            }
            messageStartIndex = startIndex;
            messageLength = -1;
            totalLength = -1;
            return false;
        }


        //private static bool TryParseCommandAndDelimiter(byte[] data, int messageOffset, int messageLength, out string command, out string possibleDelimiter, out int delimiterIndex) {
        private static bool TryParseCommand(byte[] data, int commandOffset, int messageLength, out string command) {
            if (messageLength < 0) {
                command = null;
                return false;
            }
            if (messageLength == 0) {
                command = String.Empty;//same as 'P' or PING
                return true;
            }
            else {
                StringBuilder commandBuilder = new StringBuilder();
                for (int i = 0; i < messageLength && i <= MAX_COMMAND_LENGTH; i++) {
                    byte b = data[commandOffset + i];
                    char c = (char)b;
                    if (char.IsLetter(c) || CommandChars.Contains(c))
                        commandBuilder.Append(c);
                    else
                        break;
                }
                if (commandBuilder.Length > 0) {
                    command = commandBuilder.ToString();
                    //reduce the command if it is not known but the first part of the string is a valid command
                    if (!KnownCommandsAndResponses.Contains(command)) {
                        for (int i = command.Length - 1; i >= 1; i--) {
                            if (KnownCommandsAndResponses.Contains(command.Substring(0, i))) {
                                command = command.Substring(0, i);
                                return true;
                            }
                        }
                    }
                    return true;
                }
            }
            command = null;
            return false;
        }

        private static bool TryParseSplitter(byte[] data, int splitterIndex, int messageEndIndex, out string splitterCandidate) {
            //==Examples of known delimiters==
            //|'|'| <-- original
            //|
            //|Kiler|
            //|Coringa|  <--this one triggers an AV alert if included as a string in the code!
            //|Hassan|
            //@!#&^%$
            //Y262SUCZ4UJJ

            //after the command is most likely a delimiter
            StringBuilder splitterBuilder = new StringBuilder();
            const int MAX_DELIMITER_LENGTH = 15;//I don't expect the delimiter to be more than 12 bytes (one known delimiter is "Y262SUCZ4UJJ")
            for (int i = 0; i < MAX_DELIMITER_LENGTH; i++) {
                if (splitterIndex + i > messageEndIndex || splitterIndex + i >= data.Length)
                    break;
                byte b = data[splitterIndex + i];
                if (b < 32)
                    break;
                if (b > 126)
                    break;
                char c = (char)b;
                if (char.IsControl(c))
                    break;
                splitterBuilder.Append(c);
            }
            splitterCandidate = splitterBuilder.ToString();
            return true;
        }



        #endregion

        private readonly int totalLength;//The full length of the njRAT packet data, including length fields or "[endof]" trailer

        public string CommandString { get; } = null;

        public readonly int MessageStartIndex;//index in Frame where the command is (after <len><NULL>)
        public readonly int MessageLength;//NOT including the <len><NULL> bytes
        public readonly string SplitterCandidate;
        public readonly int SplitterIndex = -1;
        public bool PacketHeaderIsComplete {
            get {
                throw new NotImplementedException();
            }
        }

        public int ParsedBytesCount { get; } = 0;

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out NjRatPacket njRatPacket) {
            if (TryParseLength(parentFrame.Data, packetStartIndex, packetEndIndex - packetStartIndex + 1, out _, out _, out _)) {
                try {
                    njRatPacket = new NjRatPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    return true;
                }
                catch { }
            }
            njRatPacket = null;
            return false;
        }

        public NjRatPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "njRAT") {

            if (TryParseLength(parentFrame.Data, packetStartIndex, base.PacketLength, out this.MessageStartIndex, out this.MessageLength, out this.totalLength)) {
                if (this.totalLength <= base.PacketLength) {
                    this.ParsedBytesCount = this.totalLength;
                    if (this.totalLength < base.PacketLength)
                        this.PacketEndIndex = this.MessageStartIndex + this.totalLength - 1;
                }
                if (this.MessageLength >= 0) {
                    if (TryParseCommand(parentFrame.Data, this.MessageStartIndex, this.MessageLength, out string command)) {
                        this.CommandString = command;
                        if (this.MessageLength > command.Length) {
                            if (TryParseSplitter(parentFrame.Data, this.MessageStartIndex + command.Length, this.PacketEndIndex, out this.SplitterCandidate)) {
                                //avoid splitters at the end of the frame because they might be truncated
                                if (this.MessageStartIndex + command.Length + this.SplitterCandidate.Length > this.PacketEndIndex) {
                                    this.SplitterCandidate = null;
                                }
                                this.SplitterIndex = this.MessageStartIndex + command.Length;
                            }
                        }
                    }
                }
            }
            else
                throw new Exception("Invalid njRAT packet");
        }




        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            else
                yield break;
        }




    }
#endif
}
