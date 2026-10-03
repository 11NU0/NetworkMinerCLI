//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
//using System.Web.UI.WebControls;

namespace PacketParser.Packets {

    /// <summary>
    /// A Transport Layer Security (TLS) Record
    /// </summary>
    public class TlsRecordPacket : AbstractPacket {
        //http://en.wikipedia.org/wiki/Transport_Layer_Security
        //http://tools.ietf.org/html/rfc2246

        //https://tools.ietf.org/html/draft-davidben-tls-grease-01
        public static readonly HashSet<ushort> GREASE_SET = new HashSet<ushort>(new ushort[] {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
            0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa
        });

        public enum ContentTypes : byte {
            ChangeCipherSpec = 0x14,
            Alert = 0x15,
            Handshake = 0x16,
            Application = 0x17,
        };

        //https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
        //https://www.rfc-editor.org/rfc/rfc5878.html#section-4
        //https://www.rfc-editor.org/rfc/rfc8446.html#page-85
        public enum AlertDescription : byte {
            close_notify = 0,
            unexpected_message = 10,
            bad_record_mac = 20,
            decryption_failed_RESERVED = 21,
            record_overflow = 22,
            decompression_failure_RESERVED = 30,
            handshake_failure = 40,
            no_certificate_RESERVED = 41,
            bad_certificate = 42,
            unsupported_certificate = 43,
            certificate_revoked = 44,
            certificate_expired = 45,
            certificate_unknown = 46,
            illegal_parameter = 47,
            unknown_ca = 48,
            access_denied = 49,
            decode_error = 50,
            decrypt_error = 51,
            too_many_cids_requested = 52,
            export_restriction_RESERVED = 60,
            protocol_version = 70,
            insufficient_security = 71,
            internal_error = 80,
            inappropriate_fallback = 86,
            user_canceled = 90,
            no_renegotiation_RESERVED = 100,
            missing_extension = 109,
            unsupported_extension = 110,
            certificate_unobtainable_RESERVED = 111,
            unrecognized_name = 112,
            bad_certificate_status_response = 113,
            bad_certificate_hash_value_RESERVED = 114,
            unknown_psk_identity = 115,
            certificate_required = 116,
            no_application_protocol = 120,//RFC 8447
            ech_required = 121,//expires 2025-12-12
        }

        private ContentTypes contentType;
        internal byte VersionMajor { get; }//MSB
        internal byte VersionMinor { get; }//LSB
        private ushort length;//MSB & LSB
        //private HandshakeProtocol handshakeProtocol;

        public bool TlsRecordIsComplete { get { return PacketEndIndex - PacketStartIndex + 1 == 5 + this.length; } }
        public ushort Length { get { return this.length; } }
        public ContentTypes ContentType { get { return this.contentType; } }

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            if (!Enum.IsDefined(typeof(ContentTypes), parentFrame.Data[packetStartIndex]))
                return false;

            //verify that the complete TLS record has been received
            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            if (length + 5 > packetEndIndex - packetStartIndex + 1)
                return false;

            try {
                result = new TlsRecordPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result = null;
            }

            if (result == null)
                return false;
            else
                return true;
        }

        internal TlsRecordPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "TLS Record") {
            this.contentType = (ContentTypes)parentFrame.Data[packetStartIndex];
            this.VersionMajor = parentFrame.Data[packetStartIndex + 1];
            this.VersionMinor = parentFrame.Data[packetStartIndex + 2];
            this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            this.PacketEndIndex = Math.Min(packetStartIndex + 5 + length - 1, this.PacketEndIndex);

            if (!this.ParentFrame.QuickParse) {
                this.Attributes.Add("Content Type", "" + this.contentType);
                this.Attributes.Add("TLS Version major", "" + this.VersionMajor);
                this.Attributes.Add("TLS Version minor", "" + this.VersionMinor);
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;

            //I only care about the hadshake protocol
            if (this.contentType == ContentTypes.Handshake) {
                if (this.PacketStartIndex + 5 < this.PacketEndIndex)
                    yield return new RawPacket(this.ParentFrame, this.PacketStartIndex + 5, this.PacketEndIndex);//data in chunks, aka opaque fragment[TLSPlaintext.length] in RFC 5246
            }//end handshake
        }

        public class HandshakePacket : AbstractPacket {

            public const string PACKET_TYPE_DESCRIPTION = "TLS Handshake Protocol";

            public enum MessageTypes : byte {
                HelloRequest = 0x00,
                ClientHello = 0x01,
                ServerHello = 0x02,
                Certificate = 0x0b,

                ServerKeyExchange = 0x0c,
                CertificateRequest = 0x0d,
                ServerHelloDone = 0x0e,
                CertificateVerify = 0x0f,

                ClientKeyExchange = 0x10,
                Finished = 0x14,
            };

            public static bool TryGetTlsVersionString(Tuple<byte, byte> sslVersion, out string tlsVersion) {
                if (sslVersion.Item1 == 3 && sslVersion.Item2 >= 1) {
                    tlsVersion = "1." + (sslVersion.Item2 - 1);
                    return true;
                }
                else {
                    tlsVersion = null;
                    return false;
                }
            }

            private List<Tuple<byte, byte>> supportedSslVersions;

            public uint ClientRandomTime { get; }
            public List<string> ApplicationLayerProtocolNegotiationStrings { get; }
            //internal byte VersionMajor { get; }//MSB
            //internal byte VersionMinor { get; }//LSB
            public List<ushort> CipherSuites { get; }
            //public List<ushort> ExtensionTypes { get; }
            public IEnumerable<ushort> ExtensionTypes => this.ExtensionTypeLengths.Select(tl => tl.type);
            public List<(ushort type, ushort length)> ExtensionTypeLengths { get; }
            public List<ushort> SupportedEllipticCurveGroups { get; }
            public List<byte> SupportedEllipticCurvePointFormats { get; }
            public List<ushort> SignatureHashAlgorithms { get; }


            public MessageTypes MessageType { get; }
            public uint MessageLength { get; }

            public byte SessionIdLength { get; }
            public ushort CipherSuiteLength { get; }
            public byte CompressionMethodsLength { get; }
            public ushort ExtensionsLength { get; }
            public System.Collections.Generic.List<byte[]> CertificateList { get; }
            public string ServerHostName { get; private set; } = null;


            

            public Tuple<byte, byte>[] GetSupportedSslVersions() {
                return this.supportedSslVersions.ToArray();
            }
            public string GetAlpnNextProtocolString() {
                return string.Join(", ", this.ApplicationLayerProtocolNegotiationStrings);
            }

            public static IEnumerable<HandshakePacket> GetHandshakes(IEnumerable<TlsRecordPacket> tlsRecordFragments) {
                using (System.IO.MemoryStream handshakeMessageData = new System.IO.MemoryStream()) {
                    Frame firstFrame = null;
                    foreach (TlsRecordPacket record in tlsRecordFragments) {
                        if (record.ContentType != TlsRecordPacket.ContentTypes.Handshake) {
                            yield break;
                        }
                        foreach (AbstractPacket recordData in record.GetSubPackets(false)) {
                            if (firstFrame == null)
                                firstFrame = recordData.ParentFrame;
                            handshakeMessageData.Write(recordData.ParentFrame.Data, recordData.PacketStartIndex, recordData.PacketLength);
                        }
                    }
                    if (handshakeMessageData.Length < 4) {//1 byte type, 3 bytes length
                        yield break;
                    }
                    handshakeMessageData.Position = 1;
                    byte[] lengthBytes = new byte[3];
                    handshakeMessageData.Read(lengthBytes, 0, 3);
                    uint messageLength = Utils.ByteConverter.ToUInt32(lengthBytes, 0, 3);
                    if (handshakeMessageData.Length < messageLength + 4) {
                        yield break;
                    }
                    handshakeMessageData.Position = 0;
                    Frame reassembledFrame = new Frame(firstFrame.Timestamp, handshakeMessageData.ToArray(), firstFrame.FrameNumber);

                    int nextHandshakeOffset = 0;
                    while (nextHandshakeOffset < reassembledFrame.Data.Length) {
                        
                        HandshakePacket handshake;
                        if (TryGetHandshake(reassembledFrame, nextHandshakeOffset, reassembledFrame.Data.Length - 1, out handshake))
                            nextHandshakeOffset = handshake.PacketEndIndex + 1;
                        else
                            yield break;

                        yield return handshake;
                    }
                }
            }

            public static bool TryGetHandshake(Frame parentFrame, int packetStartIndex, int packetEndIndex, out HandshakePacket handshakePacket) {
                handshakePacket = null;
                byte measageTypeValue = parentFrame.Data[packetStartIndex];
                if (!Enum.IsDefined(typeof(MessageTypes), measageTypeValue))
                    return false;//encrypted handshake message

                /* Check the length in the handshake message. Assume it's an
                 * encrypted handshake message if the message would pass
                 * the TLS record boundary. This is a workaround for the
                 * situation where the first octet of the encrypted handshake
                 * message is actually a known handshake message type.
                 */
                uint messageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 3);
                if (packetStartIndex + messageLength + 3 > packetEndIndex)
                    return false;//encrypted handshake message
                //Many encrypted handshakes start with 0x00, but the HelloRequest type (0x00) is typically not used
                if (measageTypeValue == 0 && packetStartIndex + messageLength + 3 != packetEndIndex)
                    return false;//encrypted handshake message
                try {
                    handshakePacket = new HandshakePacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Cannot parse TLS handshake in frame " + parentFrame.FrameNumber + ": " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    return false;
                }
            }

            //Use TryGetHandshake to create handshake packets!
            private HandshakePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, PACKET_TYPE_DESCRIPTION) {
                this.CertificateList = new List<byte[]>();
                this.supportedSslVersions = new List<Tuple<byte, byte>>();
                this.ApplicationLayerProtocolNegotiationStrings = new List<string>();
                this.CipherSuites = new List<ushort>();
                //this.ExtensionTypes = new List<ushort>();
                this.ExtensionTypeLengths = new List<(ushort type, ushort length)>();
                this.SupportedEllipticCurveGroups = new List<ushort>();
                this.SupportedEllipticCurvePointFormats = new List<byte>();
                this.SignatureHashAlgorithms = new List<ushort>();

                this.MessageType = (MessageTypes)parentFrame.Data[packetStartIndex];
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Message Type", "" + this.MessageType);
                this.MessageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 3);
                this.PacketEndIndex = (int)(packetStartIndex + 4 + this.MessageLength - 1);

                if (this.MessageType == MessageTypes.ClientHello) {
                    this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[this.PacketStartIndex + 4], parentFrame.Data[this.PacketStartIndex + 5]));
                    //RANDOM length is 32, but the first 4 bytes is an EPOCH timestamp according to RFC 5246, section 7.4.1.2
                    this.ClientRandomTime = Utils.ByteConverter.ToUInt32(parentFrame.Data, this.PacketStartIndex + 6);
                    int extensionIndex = this.PacketStartIndex + 6 + 32;
                    //SESSION ID length is typically 0 or 32
                    this.SessionIdLength = parentFrame.Data[extensionIndex];
                    extensionIndex += 1 + this.SessionIdLength;
                    this.CipherSuiteLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    for (int i = 0; i < this.CipherSuiteLength; i += 2) {
                        this.CipherSuites.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 2 + i));
                    }
                    extensionIndex += 2 + this.CipherSuiteLength;
                    this.CompressionMethodsLength = parentFrame.Data[extensionIndex];
                    extensionIndex += 1 + this.CompressionMethodsLength;
                    this.ExtensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    extensionIndex += 2;
                    this.ParseExtensions(parentFrame, extensionIndex, this.ExtensionsLength);
                    
                }
                else if (this.MessageType == MessageTypes.ServerHello) {
                    /**
                     * https://datatracker.ietf.org/doc/html/rfc2246
                     * struct {
                           ProtocolVersion server_version;
                           Random random;
                           SessionID session_id;
                           CipherSuite cipher_suite;
                           CompressionMethod compression_method;
                       }
                    **/
                    this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[this.PacketStartIndex + 4], parentFrame.Data[this.PacketStartIndex + 5]));
                    byte sessionIdLength = parentFrame.Data[this.PacketStartIndex + 38];
                    this.CipherSuites.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, this.PacketStartIndex + 39 + sessionIdLength));
                    ushort extensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, this.PacketStartIndex + 42 + sessionIdLength);
                    int extensionIndex = this.PacketStartIndex + 44 + sessionIdLength;
                    this.ParseExtensions(parentFrame, extensionIndex, extensionsLength);
                    

                }
                else if (this.MessageType == MessageTypes.Certificate) {
                    uint certificatesLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 3);
                    int certificateIndexBase = packetStartIndex + 7;
                    int certificateIndexOffset = 0;
                    while (certificateIndexOffset < certificatesLenght) {
                        //read 3 byte length
                        uint certificateLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, certificateIndexBase + certificateIndexOffset, 3);
                        certificateIndexOffset += 3;
                        //rest is a certificate
                        byte[] certificate = new byte[certificateLenght];
                        Array.Copy(parentFrame.Data, certificateIndexBase + certificateIndexOffset, certificate, 0, certificate.Length);
                        this.CertificateList.Add(certificate);
                        certificateIndexOffset += certificate.Length;
                    }
                }
            }
            //Server Certificate: http://tools.ietf.org/html/rfc2246 7.4.2

            private void ParseExtensions(PacketParser.Frame parentFrame, int extensionsStartIndex, ushort extensionsLength) {
                int extensionIndex = extensionsStartIndex;
                while (extensionIndex < this.PacketEndIndex && extensionIndex < extensionsStartIndex + extensionsLength) {
                    ushort extensionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    //this.ExtensionTypes.Add(extensionType);
                    ushort extensionLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 2);
                    this.ExtensionTypeLengths.Add((extensionType, extensionLength));
                    if (extensionLength > 0) {
                        if (extensionType == 0) {//Server Name Indication rfc6066
                            ushort serverNameListLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            while (offset < serverNameListLength) {
                                byte serverNameType = parentFrame.Data[extensionIndex + offset];
                                ushort serverNameLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + 1);
                                if (serverNameLength == 0)
                                    break;
                                else {
                                    if (serverNameType == 0) {//host_name(0)
                                        this.ServerHostName = Utils.ByteConverter.ReadString(parentFrame.Data, extensionIndex + offset + 3, serverNameLength);
                                    }
                                    offset += serverNameLength;
                                }
                            }

                        }
                        else if (extensionType == 10) {//Eliptic Curve Groups (for JA3)
                            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            for (int i = 0; i < length; i += 2) {
                                this.SupportedEllipticCurveGroups.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + i));
                            }
                        }
                        else if (extensionType == 11) {//Eliptic Curve Point Formats (for JA3)
                            byte length = parentFrame.Data[extensionIndex + 4];
                            int offset = 5;
                            for (int i = 0; i < length; i++) {
                                this.SupportedEllipticCurvePointFormats.Add(parentFrame.Data[extensionIndex + offset + i]);
                            }
                        }
                        else if(extensionType == 13) {//Signature Hash Algorithms
                            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            for (int i = 0; i < length; i += 2) {
                                this.SignatureHashAlgorithms.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + i));
                            }
                        }
                        else if (extensionType == 16) {//ALPN
                            int index = extensionIndex + 6;
                            while (index < extensionIndex + extensionLength + 4) {
                                this.ApplicationLayerProtocolNegotiationStrings.Add(Utils.ByteConverter.ReadLengthValueString(parentFrame.Data, ref index, 1));
                            }
                        }
                        else if (extensionType == 43) {//Supported versions
                            //the extensions length is typically an odd number because there's an additional length field before the version byte-tuples
                            int versionTupleStartOffset;
                            if ((extensionLength % 2) == 0)
                                versionTupleStartOffset = 4;
                            else
                                versionTupleStartOffset = 5;
                            for (int offset = versionTupleStartOffset; offset < extensionLength + versionTupleStartOffset - 1; offset += 2) {
                                this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[extensionIndex + offset], parentFrame.Data[extensionIndex + offset + 1]));
                            }
                        }
                    }
                    extensionIndex += 4 + extensionLength;
                }
            }

            public string GetJA3FingerprintFull() {
                /**
                 * https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41
                 * The field order is as follows:
                 * SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
                 * 
                 * Example:
                 * 769,47–53–5–10–49161–49162–49171–49172–50–56–19–4,0–10–11,23–24–25,0
                 **/

                var v = this.supportedSslVersions.First();
                ushort version = (ushort)((v.Item1 << 8) + v.Item2);

                StringBuilder sb = new StringBuilder();
                sb.Append(version.ToString());
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.SupportedEllipticCurveGroups.Where(ecg => !GREASE_SET.Contains(ecg))));
                sb.Append(",");
                sb.Append(String.Join<byte>("-", this.SupportedEllipticCurvePointFormats));
                return sb.ToString();
            }

            public string GetJA3SFingerprintFull() {
                /**
                 * Version, Accepted Cipher, and List of Extensions.
                 * It then concatenates those values together in order, using a “,” to delimit each field and a “-” to delimit each value in each field.
                 * The field order is as follows:
                 * TLSVersion,Cipher,Extensions
                 * Example:
                 * 769,47,65281–0–11–35–5–16
                 **/
                var v = this.supportedSslVersions.First();
                ushort version = (ushort)((v.Item1 << 8) + v.Item2);
                StringBuilder sb = new StringBuilder();
                sb.Append(version.ToString());
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et))));
                return sb.ToString();
            }

            public string GetJA3FingerprintHash() {
                return Utils.ByteConverter.ToMd5HashString(this.GetJA3FingerprintFull());
            }
            public string GetJA3SFingerprintHash() {
                return Utils.ByteConverter.ToMd5HashString(this.GetJA3SFingerprintFull());
            }

            public string GetJA4Fingerprint(char transportProtocol = 't') {
                
                /**
                 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
                 * https://blog.foxio.io/ja4-network-fingerprinting-9376fe9ca637
                 * JA4: TLS Client Fingerprinting is open-source, BSD 3-Clause, same as JA3. This allows any company or tool currently utilizing JA3 to immediately upgrade to JA4 without delay.
                 * 
                 * IcedID JA4=t13d201100_2b729b4bf6f3_9e7b989ebec8 
                 * 
                 * (QUIC=”q” or TCP=”t”)
                 * (2 character TLS version)
                 * (SNI=”d” or no SNI=”i”)
                 * (2 character count of ciphers)
                 * (2 character count of extensions)
                 * (first and last characters of first ALPN extension value)
                 * _
                 * (sha256 hash of the list of cipher hex codes sorted in hex order, truncated to 12 characters)
                 * _
                 * (sha256 hash of (the list of extension hex codes sorted in hex order)_(the list of signature algorithms), truncated to 12 characters)

                 **/

                
                StringBuilder sb = new StringBuilder(transportProtocol.ToString());
                //TLS version is shown in 3 different places. If extension 0x002b exists(supported_versions), then the version is the highest value in the extension.
                var v = this.supportedSslVersions.Select(t => (t.Item1 << 8) + t.Item2).Where(sv => !GREASE_SET.Contains((ushort)sv)).ToArray();
                Array.Sort(v);
                var version = v.Last();
                if (version == 0x0304)
                    sb.Append("13");
                else if (version == 0x0303)
                    sb.Append("12");
                else if (version == 0x0302)
                    sb.Append("11");
                else if (version == 0x0301)
                    sb.Append("10");
                else if (version == 0x0300)
                    sb.Append("s3");
                else if (version == 0x0200)//512
                    sb.Append("s2");
                else if (version == 0x0100)//256
                    sb.Append("s1");
                else if (version > 0x0304 && version < 0x030b) {
                    sb.Append("1");
                    sb.Append(((version & 0x0f) - 1).ToString());
                }
                else
                    sb.Append("00");
                //If the SNI extension (0x0000) exists, then the destination of the connection is a domain, or “d” in the fingerprint. If the SNI does not exist, then the destination is an IP address, or “i”.
                if (this.ExtensionTypes.Contains<ushort>(0))
                    sb.Append('d');
                else
                    sb.Append('i');
                //2 character number of cipher suites, so if there’s 6 cipher suites in the hello packet, then the value should be “06”. If there’s > 99, which there should never be, then output “99”. Remember, ignore GREASE values. They don’t count.
                int cipherCount = this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs)).Count();
                if (cipherCount > 99)
                    cipherCount = 99;
                sb.Append(cipherCount.ToString("D2"));
                //Same as counting ciphers. Ignore GREASE. Include SNI and ALPN.
                int extensionCount = this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et)).Count();
                if (extensionCount > 99)
                    extensionCount = 99;
                sb.Append(extensionCount.ToString("D2"));
                //The first and last characters of the ALPN (Application-Layer Protocol Negotiation) first value.
                //If there are no ALPN values or no ALPN extension then we print “00” as the value in the fingerprint.
                string firstALPN = this.ApplicationLayerProtocolNegotiationStrings.FirstOrDefault();
                if (string.IsNullOrEmpty(firstALPN))
                    sb.Append("00");
                else {
                    //https://github.com/FoxIO-LLC/ja4/issues/16
                    //for non-ASCII ALPN values, we could take the first high-nibble (A) and the last low-nibble (D). So the ALPN value in the JA4 string would be "ad".
                    char c = firstALPN.First();
                    if (c > 126 || char.IsControl(c)) {
                        string hex = Convert.ToString(c, 16).ToLower();
                        sb.Append(hex.First());
                    }
                    else
                        sb.Append(c);

                    c = firstALPN.Last();
                    if (c > 126 || char.IsControl(c)) {
                        string hex = Convert.ToString(c, 16).ToLower();
                        sb.Append(hex.Last());
                    }
                    else
                        sb.Append(c);
                }
                sb.Append('_');
                //A 12 character truncated sha256 hash of the list of ciphers sorted in hex order, first 12 characters. The list is created using the 4 character hex values of the ciphers, lower case, comma delimited, ignoring GREASE.
                var ciphers = this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs)).ToArray();
                if (ciphers.Length > 0) {
                    Array.Sort(ciphers);
                    string ciphersString = String.Join(",", ciphers.Select(c => c.ToString("x4")));
                    string ciphersHash = Utils.ByteConverter.ToHashString(System.Security.Cryptography.SHA256.Create(), ciphersString, false).Substring(0, 12);
                    sb.Append(ciphersHash);
                }
                else {
                    //If there are no ciphers in the sorted cipher list
                    //then the value of JA4_b is set to 000000000000
                    //https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
                    sb.Append("000000000000");
                }
                sb.Append('_');
                //A 12 character truncated sha256 hash of the list of extensions, sorted by hex value, followed by the list of signature algorithms, in the order that they appear (not sorted).
                var extensionsNotSniNotAlpn = this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et) && et != 0 && et != 16).ToArray();
                if (extensionsNotSniNotAlpn.Length > 0) {
                    Array.Sort(extensionsNotSniNotAlpn);
                    string extensionsAndSignaturesString = String.Join(",", extensionsNotSniNotAlpn.Select(s => s.ToString("x4")));
                    if (this.SignatureHashAlgorithms.Count > 0)
                        extensionsAndSignaturesString += "_" + String.Join(",", this.SignatureHashAlgorithms.Select(s => s.ToString("x4")));
                    string extensionsAndSignaturesHash = Utils.ByteConverter.ToHashString(System.Security.Cryptography.SHA256.Create(), extensionsAndSignaturesString, false).Substring(0, 12);
                    sb.Append(extensionsAndSignaturesHash);
                }
                else {
                    //If there are no extensions in the sorted extensions list
                    //then the value of JA4_c is set to 000000000000
                    //https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
                    sb.Append("000000000000");
                }
                return sb.ToString();
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
                yield break;//no sub packets
            }


        }



    }
}
