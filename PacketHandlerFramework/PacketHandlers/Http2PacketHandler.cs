using System;
using System.Collections.Generic;
using System.Text;
using PacketParser.Packets;
using System.Linq;
using System.Collections.Specialized;
using PacketHandlerFramework;
using PacketHandlerFramework.FileTransfer;
using PacketParser;
using static PacketHandlerFramework.PacketHandlers.HttpPacketHandler;
using PacketHandlerFramework.Fingerprints;

namespace PacketHandlerFramework.PacketHandlers {
    public class Http2PacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {


        public class H2UserAgentFingerprinter : Fingerprints.IOsFingerprinterInfo, IComparable<IOsFingerprinterInfo> {
            public double Confidence => 0.5;

            public string Name => "HTTP/2 User-Agent";

            public int CompareTo(IOsFingerprinterInfo other) {
                return this.Name.CompareTo(other.Name);
            }

            public int CompareTo(object obj) {
                if (obj is IOsFingerprinterInfo other)
                    return this.CompareTo(other);
                else
                    throw new NotImplementedException();
            }
        }

        //HTTP/2: https://tools.ietf.org/html/rfc7540
        //HPACK: https://tools.ietf.org/html/rfc7541
        //https://http2.github.io/http2-spec/compression.html#static.table.definition
        public class HPACK {


            public const string HEADER_NAME_ACCEPT_LANGUAGE = "accept-language";
            public const string HEADER_NAME_AUTHORITY = ":authority";
            public const string HEADER_NAME_CONTENT_DISPOSITION = "content-disposition";
            public const string HEADER_NAME_CONTENT_ENCODING = "content-encoding";
            public const string HEADER_NAME_CONTENT_LENGTH = "content-length";
            public const string HEADER_NAME_CONTENT_TYPE = "content-type";
            public const string HEADER_NAME_COOKIE = "cookie";
            public const string HEADER_NAME_LOCATION = "location";
            public const string HEADER_NAME_METHOD = ":method";
            public const string HEADER_NAME_PATH = ":path";
            public const string HEADER_NAME_REFERER = "referer";//nice to see the misspelling of the word "referrer" is preserved
            public const string HEADER_NAME_SCHEME = ":scheme";//typically "http" or "https"
            public const string HEADER_NAME_SERVER = "server";
            public const string HEADER_NAME_SET_COOKIE = "set-cookie";
            public const string HEADER_NAME_STATUS = ":status";
            public const string HEADER_NAME_TRANSFER_ENCODING = "transfer-encoding";
            public const string HEADER_NAME_USER_AGENT = "user-agent";

            //Another C# implementation of the Static Table: https://github.com/ringostarr80/hpack/blob/master/hpack/StaticTable.cs
            internal static readonly ValueTuple<string, string>[] STATIC_TABLE = {
                (string.Empty, string.Empty),                    /*  0 */
                (HEADER_NAME_AUTHORITY, string.Empty),                    /*  1 */
			    (HEADER_NAME_METHOD, "GET"),                              /*  2 */
			    (HEADER_NAME_METHOD, "POST"),                             /*  3 */
			    (HEADER_NAME_PATH, "/"),                                  /*  4 */
			    (HEADER_NAME_PATH, "/index.html"),                        /*  5 */
			    (HEADER_NAME_SCHEME, "http"),                             /*  6 */
			    (HEADER_NAME_SCHEME, "https"),                            /*  7 */
			    (HEADER_NAME_STATUS, "200"),                              /*  8 */
			    (HEADER_NAME_STATUS, "204"),                              /*  9 */
			    (HEADER_NAME_STATUS, "206"),                              /* 10 */
			    (HEADER_NAME_STATUS, "304"),                              /* 11 */
			    (HEADER_NAME_STATUS, "400"),                              /* 12 */
			    (HEADER_NAME_STATUS, "404"),                              /* 13 */
			    (HEADER_NAME_STATUS, "500"),                              /* 14 */
			    ("accept-charset", string.Empty),                /* 15 */
			    ("accept-encoding", "gzip, deflate"),            /* 16 */
			    (HEADER_NAME_ACCEPT_LANGUAGE, string.Empty),               /* 17 */
			    ("accept-ranges", string.Empty),                 /* 18 */
			    ("accept", string.Empty),                        /* 19 */
			    ("access-control-allow-origin", string.Empty),   /* 20 */
			    ("age", string.Empty),                           /* 21 */
			    ("allow", string.Empty),                         /* 22 */
			    ("authorization", string.Empty),                 /* 23 */
			    ("cache-control", string.Empty),                 /* 24 */
			    (HEADER_NAME_CONTENT_DISPOSITION, string.Empty),           /* 25 */
			    (HEADER_NAME_CONTENT_ENCODING, string.Empty),              /* 26 */
			    ("content-language", string.Empty),              /* 27 */
			    (HEADER_NAME_CONTENT_LENGTH, string.Empty),      /* 28 */
			    ("content-location", string.Empty),              /* 29 */
			    ("content-range", string.Empty),                 /* 30 */
			    (HEADER_NAME_CONTENT_TYPE, string.Empty),                  /* 31 */
			    (HEADER_NAME_COOKIE, string.Empty),                        /* 32 */
			    ("date", string.Empty),                          /* 33 */
			    ("etag", string.Empty),                          /* 34 */
			    ("expect", string.Empty),                        /* 35 */
			    ("expires", string.Empty),                       /* 36 */
			    ("from", string.Empty),                          /* 37 */
			    ("host", string.Empty),                          /* 38 */
			    ("if-match", string.Empty),                      /* 39 */
			    ("if-modified-since", string.Empty),             /* 40 */
			    ("if-none-match", string.Empty),                 /* 41 */
			    ("if-range", string.Empty),                      /* 42 */
			    ("if-unmodified-since", string.Empty),           /* 43 */
			    ("last-modified", string.Empty),                 /* 44 */
			    ("link", string.Empty),                          /* 45 */
			    (HEADER_NAME_LOCATION, string.Empty),                      /* 46 */
			    ("max-forwards", string.Empty),                  /* 47 */
			    ("proxy-authenticate", string.Empty),            /* 48 */
			    ("proxy-authorization", string.Empty),           /* 49 */
			    ("range", string.Empty),                         /* 50 */
			    (HEADER_NAME_REFERER, string.Empty),                       /* 51 */
			    ("refresh", string.Empty),                       /* 52 */
			    ("retry-after", string.Empty),                   /* 53 */
			    ("server", string.Empty),                        /* 54 */
			    (HEADER_NAME_SET_COOKIE, string.Empty),                    /* 55 */
			    ("strict-transport-security", string.Empty),     /* 56 */
			    (HEADER_NAME_TRANSFER_ENCODING, string.Empty),             /* 57 */
			    (HEADER_NAME_USER_AGENT, string.Empty),                    /* 58 */
			    ("vary", string.Empty),                          /* 59 */
			    ("via", string.Empty),                           /* 60 */
			    ("www-authenticate", string.Empty)               /* 61 */
            };

            private PacketParser.Utils.HuffmanDecoder huffmanDecoder;
            private PopularityList<(FiveTuple, bool), LinkedList<(string, string)>> dynamicTableCache;

            internal HPACK() {
                this.huffmanDecoder = new PacketParser.Utils.HuffmanDecoder();
                this.dynamicTableCache = new PopularityList<(FiveTuple, bool), LinkedList<(string, string)>>(1000);//maintain state of 1000 concurrent flows
            }

            private ValueTuple<string, string> GetLiteralHeader(ref IEnumerable<byte> data, byte prefixLength, ValueTuple<FiveTuple, bool> key) {
                int prefixModulo = 1 << prefixLength;
                byte mask = (byte)(prefixModulo - 1);
                long index = this.ReadInteger(ref data, mask);
                /*
                if ((data.First() & mask) == mask) {
                    data = data.Skip(1);
                    index = Utils.ByteConverter.DecodeULE128(ref data, mask);
                }
                else {
                    index = data.First() & mask;
                    data = data.Skip(1);
                }
                */
                string headerName;
                if (index == 0)                     //data = data.Skip(1);
                    headerName = this.GetFieldName(ref data);
                else if (index < STATIC_TABLE.Length) {
                    headerName = STATIC_TABLE[index].Item1;
                    //data = data.Skip(1);
                }
                else {
                    index -= STATIC_TABLE.Length;
                    lock (this.dynamicTableCache) {
                        if (this.dynamicTableCache.ContainsKey(key) && this.dynamicTableCache[key].Count > index)
                            headerName = this.dynamicTableCache[key].ElementAt((int)index).Item1;
                        else
                            headerName = string.Empty;
                    }
                }


                string headerValue = this.GetFieldName(ref data);
                return (headerName, headerValue);
            }

            public long ReadInteger(ref IEnumerable<byte> data, byte mask) {
                long value;
                if ((data.First() & mask) == mask) {
                    data = data.Skip(1);
                    value = PacketParser.Utils.ByteConverter.DecodeULE128(ref data, mask);
                }
                else {
                    value = data.First() & mask;
                    data = data.Skip(1);
                }
                return value;
            }

            public IEnumerable<(string name, string value)> GetHeaders(IEnumerable<byte> headerBlockFragment, ValueTuple<FiveTuple, bool> key) {
                while (headerBlockFragment.GetEnumerator().MoveNext()) {
                    var header = this.GetHeader(ref headerBlockFragment, key);
                    if (!header.Equals(STATIC_TABLE[0]))
                        yield return header;
                }
            }

            private (string name, string value) GetHeader(ref IEnumerable<byte> data, ValueTuple<FiveTuple, bool> key) {
                byte b = data.First();
                //An indexed header field starts with the '1' 1-bit pattern, followed
                //by the index of the matching header field, represented as an integer
                //with a 7 - bit prefix(see Section 5.1).
                if ((b & 0x80) == 0x80) {
                    //Indexed Header Field Representation
                    b &= 0x7f;
                    long index;
                    if (b == 0x7f) {
                        data = data.Skip(1);
                        index = PacketParser.Utils.ByteConverter.DecodeULE128(ref data, b);
                    }
                    else {
                        index = b;
                        data = data.Skip(1);
                    }

                    if (index < STATIC_TABLE.Length)
                        return STATIC_TABLE[index];
                    else {
                        index -= STATIC_TABLE.Length;
                        lock (this.dynamicTableCache)
                            return this.dynamicTableCache[key].ElementAt((int)index);
                    }

                }
                else if ((b & 0x40) == 0x40) {
                    // Literal Header Field with Incremental Indexing
                    /**
                     *      0   1   2   3   4   5   6   7
                     *    +---+---+---+---+---+---+---+---+
                     *    | 0 | 1 |      Index (6+)       |
                     *    +---+---+-----------------------+
                     *    | H |     Value Length (7+)     |
                     *    +---+---------------------------+
                     *    | Value String (Length octets)  |
                     *    +-------------------------------+
                     **/

                    //New name
                    /**
                     *      0   1   2   3   4   5   6   7
                     *    +---+---+---+---+---+---+---+---+
                     *    | 0 | 1 |           0           |
                     *    +---+---+-----------------------+
                     *    | H |     Name Length (7+)      |
                     *    +---+---------------------------+
                     *    |  Name String (Length octets)  |
                     *    +---+---------------------------+
                     *    | H |     Value Length (7+)     |
                     *    +---+---------------------------+
                     *    | Value String (Length octets)  |
                     *    +-------------------------------+
                     **/
                    ValueTuple<string, string> header = this.GetLiteralHeader(ref data, 6, key);
                    //var key = new ValueTuple<FiveTuple, bool>(fiveTuple, transferIsClientToServer);
                    lock (this.dynamicTableCache) {
                        LinkedList<(string, string)> flowDynamicTable;
                        if (this.dynamicTableCache.ContainsKey(key)) flowDynamicTable = this.dynamicTableCache[key];
                        else {
                            flowDynamicTable = new LinkedList<(string, string)>();
                            this.dynamicTableCache.Add(key, flowDynamicTable);
                        }
                        flowDynamicTable.AddFirst(header);
                        //TODO: dequeue entries if the queue is to long!
                        while (flowDynamicTable.Count > 100)
                            flowDynamicTable.RemoveLast();
                    }
                    return header;



                }
                else if ((b & 0x20) == 0x20) {
                    /**
                     *      0   1   2   3   4   5   6   7
                     *    +---+---+---+---+---+---+---+---+
                     *    | 0 | 0 | 1 |   Max size (5+)   |
                     *    +---+---------------------------+
                     *    Dynamic Table Size Update
                     **/
                    long headerTableSize = this.ReadInteger(ref data, 0x1f);
                    //data = data.Skip(1);
                    return STATIC_TABLE[0];
                }
                else {
                    // Literal Header Field without Indexing / never Indexed

                    /**
                     *      0   1   2   3   4   5   6   7
                     *    +---+---+---+---+---+---+---+---+
                     *    | 0 | 0 | 0 | 0 |  Index (4+)   |
                     *    +---+---+-----------------------+
                     *    | H |     Value Length (7+)     |
                     *    +---+---------------------------+
                     *    | Value String (Length octets)  |
                     *    +-------------------------------+
                     *    Figure 8: Literal Header Field without Indexing -- Indexed Name
                     **/

                    /**
                     * 
                     *      0   1   2   3   4   5   6   7
                     *    +---+---+---+---+---+---+---+---+
                     *    | 0 | 0 | 0 | 0 |       0       |
                     *    +---+---+-----------------------+
                     *    | H |     Name Length (7+)      |
                     *    +---+---------------------------+
                     *    |  Name String (Length octets)  |
                     *    +---+---------------------------+
                     *    | H |     Value Length (7+)     |
                     *    +---+---------------------------+
                     *    | Value String (Length octets)  |
                     *    +-------------------------------+
                     *    Figure 9: Literal Header Field without Indexing -- New Name
                     **/
                    return this.GetLiteralHeader(ref data, 4, key);

                }
            }

            private string GetFieldName(ref IEnumerable<byte> data) {
                /**
                    *      0   1   2   3   4   5   6   7
                    *    +---+---------------------------+
                    *    | H |     Value Length (7+)     |
                    *    +---+---------------------------+
                    *    | Value String (Length octets)  |
                    *    +-------------------------------+
                    **/
                bool huffman = (data.First() & 0x80) == 0x80;
                byte mask = 0x7f;
                /*
                long length;
                if ((data.First() & mask) == mask) {
                    data = data.Skip(1);
                    length = Utils.ByteConverter.DecodeULE128(ref data, mask);
                }
                else {
                    length = data.First() & mask;
                    data = data.Skip(1);
                }
                */
                long length = this.ReadInteger(ref data, mask);
                //byte length = (byte)(data.First() & 0x7f);
                byte[] bytes = data.Take((int)length).ToArray();
                data = data.Skip((int)length);

                if (huffman)
                    return Encoding.UTF8.GetString(this.huffmanDecoder.Decode(bytes));
                else
                    return Encoding.UTF8.GetString(bytes);
            }

        }//End of HPACK class

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.HTTP2;
            }
        }

        private HPACK hpack;
        private readonly H2UserAgentFingerprinter h2UserAgentFingerprinter;
        private readonly PopularityList<string, FileSegmentAssembler> fileSegmentAssemblerList;
        private readonly DnsPacketHandler dnsPacketHandler;//for DoH (RFC 8484)

        public override Type[] ParsedTypes { get; } = { typeof(Http2Packet) };

        public Http2PacketHandler(PacketHandler mainPacketHandler, DnsPacketHandler dnsPacketHandler)
            : base(mainPacketHandler) {
            this.hpack = new HPACK();
            this.h2UserAgentFingerprinter = new H2UserAgentFingerprinter();
            this.fileSegmentAssemblerList = new PopularityList<string, FileSegmentAssembler>(1000);
            this.fileSegmentAssemblerList.PopularityLost += (k, assembler) => assembler.AssembleAndClose();
            this.dnsPacketHandler = dnsPacketHandler;
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {

            bool successfulExtraction = false;

            Http2Packet http2Packet = null;
            TcpPacket tcpPacket = null;
            foreach (AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Http2Packet))
                    http2Packet = (Http2Packet)p;
                else if (p.GetType() == typeof(TcpPacket))
                    tcpPacket = (TcpPacket)p;
            }

            if (http2Packet != null && tcpPacket != null)
                if (http2Packet.PacketHeaderIsComplete)
                    successfulExtraction = this.ExtractHttpData(http2Packet, tcpPacket, tcpSession, transferIsClientToServer, MainPacketHandler);
            
            if (successfulExtraction)
                return http2Packet.ParsedBytesCount;
            else
                return 0;
        }

        private string GetUniqueFileId(NetworkTcpSession fiveTuple, int streamIdentifier, bool transferIsClientToServer) {
            return fiveTuple.GetFlowID() + "|" + streamIdentifier.ToString() + "|" + transferIsClientToServer.ToString();
        }

        private bool ExtractHttpData(Http2Packet http2Packet, TcpPacket tcpPacket, NetworkTcpSession tcpSession, bool transferIsClientToServer, PacketHandler mainPacketHandler) {
            FiveTuple fiveTuple = tcpSession.Flow.FiveTuple;
            string sentFileId = this.GetUniqueFileId(tcpSession, http2Packet.StreamIdentifier, transferIsClientToServer);
            string requestedFileId = this.GetUniqueFileId(tcpSession, http2Packet.StreamIdentifier, !transferIsClientToServer);

            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = fiveTuple.ClientHost;
                destinationHost = fiveTuple.ServerHost;
            }
            else {
                sourceHost = fiveTuple.ServerHost;
                destinationHost = fiveTuple.ClientHost;
            }

            if (http2Packet.Type == Http2Packet.FrameType.HEADERS) {
                /**
                 *     +---------------+
                 *     |Pad Length? (8)|
                 *     +-+-------------+-----------------------------------------------+
                 *     |E|                 Stream Dependency? (31)                     |
                 *     +-+-------------+-----------------------------------------------+
                 *     |  Weight? (8)  |
                 *     +-+-------------+-----------------------------------------------+
                 *     |                   Header Block Fragment (*)                 ...
                 *     +---------------------------------------------------------------+
                 *     |                           Padding (*)                       ...
                 *     +---------------------------------------------------------------+
                 **/
                byte padLength = 0;
                var payloadEnumerable = http2Packet.Payload;
                if (http2Packet.FlagPadded) {
                    padLength = payloadEnumerable.First();
                    payloadEnumerable = payloadEnumerable.Skip(1);
                }
                uint streamDependency = 0;
                byte weight = 0;
                if (http2Packet.FlagPriority) {
                    streamDependency = PacketParser.Utils.ByteConverter.ToUInt32(payloadEnumerable.Take(4).ToArray()) & 0x7fffffff;
                    payloadEnumerable = payloadEnumerable.Skip(4);
                    weight = payloadEnumerable.First();
                    payloadEnumerable = payloadEnumerable.Skip(1);
                }
                IEnumerable<byte> headerBlockFragment = payloadEnumerable;
                if (padLength > 0)
                    headerBlockFragment = payloadEnumerable.Reverse().Skip(padLength).Reverse();//slow??





                //HPACK = Header compression: https://www.rfc-editor.org/rfc/rfc7541.html
                //List<Tuple<string, string>> headers = new List<Tuple<string, string>>();
                NameValueCollection headers = new NameValueCollection();
                Dictionary<string, string> headerDict = new Dictionary<string, string>();
                foreach ((string name, string value) in this.hpack.GetHeaders(headerBlockFragment, (fiveTuple, transferIsClientToServer))) {
                    if (!headerDict.ContainsKey(name))
                        headerDict.Add(name, value);
                    if (!string.IsNullOrEmpty(name))
                        headers.Add(name, value);

                    if (name == HPACK.HEADER_NAME_AUTHORITY) tcpSession.ServerHost.AddHostName(value, http2Packet.PacketTypeDescription);
                    else if (name == HPACK.HEADER_NAME_USER_AGENT) {
                        tcpSession.ClientHost.AddHttpUserAgentBanner(value);
                        if (UserAgentFingerprinter.TryExtractUserAgentOS(value, out var osID))
                            sourceHost.AddProbableOs(osID.ToString(), this.h2UserAgentFingerprinter, 0.5);
                    }
                    else if (name == HPACK.HEADER_NAME_ACCEPT_LANGUAGE) {
                        sourceHost.AddNumberedExtraDetail(HPACK.HEADER_NAME_ACCEPT_LANGUAGE, value);
                    }
                    else if (name == "client") {
                        tcpSession.ClientHost.AddHttpUserAgentBanner(value);
                        if (UserAgentFingerprinter.TryExtractUserAgentOS(value, out var osID))
                            sourceHost.AddProbableOs(osID.ToString(), this.h2UserAgentFingerprinter, 0.5);
                    }
                    else if (name == "server") {
                        tcpSession.ServerHost.AddHttpServerBanner(value, tcpPacket.SourcePort);
                    }
                    else if (name == HPACK.HEADER_NAME_COOKIE || name == HPACK.HEADER_NAME_SET_COOKIE) {
                        var cookieParams = new NameValueCollection();
                        foreach ((string cookieName, string cookieValue) in HttpPacketHandler.GetCookieParts(value)) {
                            cookieParams.Add(name, value);
                        }
                        NetworkCredential inCookieCredential = NetworkCredential.GetNetworkCredential(cookieParams, tcpSession.ClientHost, tcpSession.ServerHost, "HTTP/2 Cookie parameter", http2Packet.ParentFrame.Timestamp);
                        if (inCookieCredential != null)
                            mainPacketHandler.AddCredential(inCookieCredential);

                        NetworkCredential credential;
                        if (headerDict.ContainsKey(HPACK.HEADER_NAME_AUTHORITY)) {
                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, cookieParams, http2Packet.ParentFrame.Timestamp, "HTTP/2 Cookie for " + headerDict[HPACK.HEADER_NAME_AUTHORITY]));
                            credential = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "HTTP/2 Cookie", value, "N/A", http2Packet.ParentFrame.Timestamp, headerDict[HPACK.HEADER_NAME_AUTHORITY]);
                        }
                        else {
                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, cookieParams, http2Packet.ParentFrame.Timestamp, "HTTP/2 Cookie"));
                            credential = new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, "HTTP/2 Cookie", value, "N/A", http2Packet.ParentFrame.Timestamp);
                        }
                        mainPacketHandler.AddCredential(credential);
                    }
                    else if (name == "X-Proxy-Origin") {
                        //193.235.19.252; 193.235.19.252; 538.bm-nginx-loadbalancer.mgmt.fra1; *.adnxs.com; 37.252.172.199:80
                        //207.154.239.150; 207.154.239.150; 258.bm-nginx-loadbalancer.mgmt.ams1; *.adnxs.com; 185.33.221.149:80
                        if (!string.IsNullOrEmpty(value) && System.Net.IPAddress.TryParse(value.Split(';')?.First(), out System.Net.IPAddress ip))
                            destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                    }
                    else if (name == "X-Akamai-Pragma-Client-IP") {
                        //X-Akamai-Pragma-Client-IP: 178.162.222.41, 178.162.222.41
                        foreach (string ipString in value?.Split(',')) {
                            if (!string.IsNullOrEmpty(ipString) && System.Net.IPAddress.TryParse(ipString.Trim(), out System.Net.IPAddress ip))
                                destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                        }
                    }
                    /**
                     * http://mobiforge.com/developing/blog/useful-x-headers
                     * http://nakedsecurity.sophos.com/2012/01/25/smartphone-website-telephone-number/
                     * http://www.nowsms.com/discus/messages/485/14998.html
                     * http://coding-talk.com/f46/check-isdn-10962/
                     **/
                    if (!HttpPacketHandler.BoringXHeaders.Contains(name)) {
                        if (name.StartsWith("X-", StringComparison.InvariantCultureIgnoreCase)) sourceHost.AddNumberedExtraDetail("HTTP/2 header: " + name, value);
                        else if (name.StartsWith("HTTP_X", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP/2 header: " + name, value);
                        }
                        else if (name.StartsWith("X_", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP/2 header: " + name, value);
                        }
                        else if (name.StartsWith("HTTP_MSISDN", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP/2 header: " + name, value);
                        }
                    }
                }
                /*
                while (headerBlockFragment.GetEnumerator().MoveNext()) {
                    var headerTuple = this.hpack.GetHeader(ref headerBlockFragment, (fiveTuple, transferIsClientToServer));
                    if (!string.IsNullOrEmpty(headerTuple.Item1))
                        headers.Add(headerTuple.Item1, headerTuple.Item2);
                }
                */
                MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(http2Packet.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, headers, http2Packet.ParentFrame.Timestamp, "HTTP/2 Header"));


                if (headerDict.ContainsKey(HPACK.HEADER_NAME_PATH)) {
                    string path = headerDict[HPACK.HEADER_NAME_PATH];
                    string authority = null;
                    if (headerDict.ContainsKey(HPACK.HEADER_NAME_AUTHORITY))
                        authority = headerDict[HPACK.HEADER_NAME_AUTHORITY];

                    //querystring
                    if (path.Contains('?')) {
                        NameValueCollection queryStringData = new NameValueCollection();
                        foreach ((string name, string value) in HttpPacket.GetUrlEncodedParts(path.Substring(path.IndexOf('?') + 1), false)) {
                            if (name == "utmsr")
                                sourceHost.AddNumberedExtraDetail("Screen resolution (Google Analytics)", value);
                            else if (name == "utmsc")
                                sourceHost.AddNumberedExtraDetail("Color depth (Google Analytics)", value);
                            else if (name == "utmul")
                                sourceHost.AddNumberedExtraDetail("Browser language (Google Analytics)", value);
                            else if (name == "utmfl")
                                sourceHost.AddNumberedExtraDetail("Flash version (Google Analytics)", value);


                            if (!string.IsNullOrEmpty(name))
                                queryStringData.Add(name, value);
                        }
                        if (queryStringData.Count > 0) {
                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, queryStringData, tcpPacket.ParentFrame.Timestamp, "HTTP/2 QueryString to " + authority));
                            NetworkCredential credential = NetworkCredential.GetNetworkCredential(queryStringData, sourceHost, destinationHost, "HTTP/2 GET QueryString", tcpPacket.ParentFrame.Timestamp, authority);
                            if (credential != null)
                                mainPacketHandler.AddCredential(credential);
                        }
                    }


                    //new file transfer
                    var (filename, fileLocation) = HttpPacketHandler.GetFilenameAndLocation(path);
                    if (headerDict.ContainsKey(HPACK.HEADER_NAME_METHOD) && (headerDict[HPACK.HEADER_NAME_METHOD] == "GET" || headerDict[HPACK.HEADER_NAME_METHOD] == "POST")) {
                        //GET or POST
                        string outputDir = System.IO.Path.GetDirectoryName(mainPacketHandler.OutputDirectory);

                        lock (this.fileSegmentAssemblerList) {
                            if (this.fileSegmentAssemblerList.ContainsKey(requestedFileId))
                                this.fileSegmentAssemblerList[requestedFileId].AssembleAndClose();
                            FileSegmentAssembler fileSegmentAssembler = new FileSegmentAssembler(outputDir, !transferIsClientToServer, fileLocation + "/" + filename, requestedFileId, MainPacketHandler.FileStreamAssemblerList, this.fileSegmentAssemblerList, FileStreamTypes.HTTP2, "HTTP/2 stream " + http2Packet.StreamIdentifier + " " + headerDict[HPACK.HEADER_NAME_METHOD] + " " + path, fiveTuple, authority);
                            this.fileSegmentAssemblerList.Add(requestedFileId, fileSegmentAssembler);
                        }

                        if (headerDict[HPACK.HEADER_NAME_METHOD] == "POST") {
                            //POST, let's see if there is any data sent
                            if (headerDict.ContainsKey(HPACK.HEADER_NAME_CONTENT_LENGTH) &&
                                long.TryParse(headerDict[HPACK.HEADER_NAME_CONTENT_LENGTH], out long contentLength) &&
                                contentLength > 0) {
                                lock (this.fileSegmentAssemblerList) {
                                    if (this.fileSegmentAssemblerList.ContainsKey(sentFileId))
                                        this.fileSegmentAssemblerList[sentFileId].AssembleAndClose();
                                    FileSegmentAssembler fileSegmentAssembler = new FileSegmentAssembler(outputDir, transferIsClientToServer, fileLocation + "/" + filename, sentFileId, MainPacketHandler.FileStreamAssemblerList, this.fileSegmentAssemblerList, FileStreamTypes.HTTP2, "HTTP/2 stream " + http2Packet.StreamIdentifier + " " + headerDict[HPACK.HEADER_NAME_METHOD] + " " + path, fiveTuple, authority);
                                    this.fileSegmentAssemblerList.Add(sentFileId, fileSegmentAssembler);
                                }
                            }
                        }

                    }


                }
                HashSet<string> interestingHeaders = new HashSet<string> {
                    HPACK.HEADER_NAME_CONTENT_LENGTH,
                    HPACK.HEADER_NAME_CONTENT_ENCODING,
                    HPACK.HEADER_NAME_CONTENT_TYPE
                };
                if (headerDict.Keys.Any(key => interestingHeaders.Contains(key))) {
                    lock (this.fileSegmentAssemblerList) {
                        if (headerDict.ContainsKey(HPACK.HEADER_NAME_CONTENT_LENGTH)) {
                            if (long.TryParse(headerDict[HPACK.HEADER_NAME_CONTENT_LENGTH], out long contentLength))
                                if (this.fileSegmentAssemblerList.ContainsKey(sentFileId))
                                    this.fileSegmentAssemblerList[sentFileId].SegmentSize = contentLength;
                        }
                        if (headerDict.ContainsKey(HPACK.HEADER_NAME_CONTENT_ENCODING)) {
                            string contentEncoding = headerDict[HPACK.HEADER_NAME_CONTENT_ENCODING];
                            if (this.fileSegmentAssemblerList.ContainsKey(sentFileId))
                                this.fileSegmentAssemblerList[sentFileId].ContentEncoding = contentEncoding;
                        }
                        if (headerDict.ContainsKey(HPACK.HEADER_NAME_CONTENT_TYPE)) {
                            if (this.fileSegmentAssemblerList.ContainsKey(sentFileId)) {
                                var assembler = this.fileSegmentAssemblerList[sentFileId];
                                assembler.ContentType = headerDict[HPACK.HEADER_NAME_CONTENT_TYPE];
                                assembler.FilePath = HttpPacketHandler.AppendMimeContentTypeAsExtension(assembler.FilePath, assembler.ContentType);
                            }
                        }

                    }
                }

                if (MainPacketHandler.ExtraHttpPacketHandler != null)
                    MainPacketHandler.ExtraHttpPacketHandler.ExtractHttpData(http2Packet, headerDict, tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, MainPacketHandler);
                //TODO: http2.headers.status == 206
            }
            else if (http2Packet.Type == Http2Packet.FrameType.DATA) {

                lock (this.fileSegmentAssemblerList) {

                    if (this.fileSegmentAssemblerList.ContainsKey(sentFileId)) {
                        var assembler = this.fileSegmentAssemblerList[sentFileId];
                        bool firstAssembledDataSegment = assembler.IsEmpty;
                        byte[] data = http2Packet.Payload.ToArray();
                        assembler.AddData(data, http2Packet.ParentFrame);
                        bool lastAssembledDataSegment = assembler.IsEmpty;
                        //check if "data" was the whole file
                        if (firstAssembledDataSegment && lastAssembledDataSegment) {
                            //DoH sepecial
                            if (assembler.ContentType == "application/dns-message") {

                                try {
                                    Frame virtualFrame = new Frame(http2Packet.ParentFrame.Timestamp, data, typeof(DnsPacket), http2Packet.ParentFrame.FrameNumber, false, false, data.Length);
                                    DnsPacket dnsPacket = new DnsPacket(virtualFrame, 0, data.Length - 1);
                                    List<AbstractPacket> virtualPacketList = new List<AbstractPacket>();
                                    virtualPacketList.AddRange(http2Packet.ParentFrame.PacketList);
                                    virtualPacketList.Add(dnsPacket);
                                    this.dnsPacketHandler.ExtractData(ref sourceHost, destinationHost, virtualPacketList);
                                }
                                catch (Exception e) {
                                    SharedUtils.Logger.Log("Error parsing DoH packet of " + http2Packet.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                                }
                            }
                            else if (assembler.ContentType?.ToLower(System.Globalization.CultureInfo.InvariantCulture).StartsWith("application/x-www-form-urlencoded") == true) {

                                PacketParser.Mime.MultipartPart mimeMultipart = new PacketParser.Mime.MultipartPart(HttpPacket.GetUrlEncodedNameValueCollection(PacketParser.Utils.ByteConverter.ReadString(data), true));
                                if (mimeMultipart?.Attributes != null) {
                                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, mimeMultipart.Attributes, http2Packet.ParentFrame.Timestamp, "HTTP/2 POST parameters"));

                                    NetworkCredential postedCredential = NetworkCredential.GetNetworkCredential(mimeMultipart.Attributes, tcpSession.ClientHost, tcpSession.ServerHost, "HTTP/2 POST", http2Packet.ParentFrame.Timestamp);
                                    if (postedCredential != null)
                                        mainPacketHandler.AddCredential(postedCredential);
                                    /*
                                    foreach (string key in mimeMultipart.Attributes.Keys) {
                                        string value = mimeMultipart.Attributes[key];

                                    }
                                    */
                                }
                            }
                            else if (assembler.ContentType == "application/json") {
                                NameValueCollection jsonParameters = JsonUtils.GetParams(data, assembler.ContentEncoding == "gzip", 5, out bool _);
                                if(jsonParameters.Count > 0)
                                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, jsonParameters, http2Packet.ParentFrame.Timestamp, "HTTP/2 JSON"));
                            }
                        }

                    }
                }

            }
            if (http2Packet.FlagEndStream) {
                lock (this.fileSegmentAssemblerList) {
                    if (this.fileSegmentAssemblerList.ContainsKey(sentFileId)) {
                        var assembler = this.fileSegmentAssemblerList[sentFileId];
                        assembler.AssembleAndClose();
                    }
                }
            }

            return true;

        }

        public void Reset() {
            this.hpack = new HPACK();

            List<FileSegmentAssembler> assemblers = new List<FileSegmentAssembler>(this.fileSegmentAssemblerList.GetValueEnumerator());
            foreach (FileSegmentAssembler fileSegmentAssembler in assemblers)
                fileSegmentAssembler.Close();
            fileSegmentAssemblerList.Clear();
        }
    }
}
