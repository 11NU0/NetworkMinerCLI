using PacketHandlerFramework.FileTransfer;
using PacketHandlerFramework.Fingerprints;
using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PacketHandlerFramework.PacketHandlers {
    public abstract class AbstractTlsHandshakePacketHandler : AbstractPacketHandler {
        internal class Ja4Fingerprinter : IOsFingerprinterInfo, IComparable<IOsFingerprinterInfo> {
            public double Confidence => 0.2;
            public string Name => "JA4";

            public int CompareTo(object obj) {
                if (obj is IOsFingerprinterInfo other)
                    return this.CompareTo(other);
                else
                    throw new NotImplementedException();
            }

            public int CompareTo(IOsFingerprinterInfo other) {
                return this.Name.CompareTo(other.Name);
            }
        }


        private List<Dictionary<string, string>> ja3Fingerprints;
        private Dictionary<string, IJa4Fingerprint> ja4Fingerprints;
        private Dictionary<string, string> abuseChX509CertificateFingerprints;
        private bool verifyX509Certificates = false;
        private Regex x509SubjectAndIssuerRegex;
        private Ja4Fingerprinter ja4Fingerprinter;
        

        internal AbstractTlsHandshakePacketHandler(PacketHandler mainPacketHandler, Dictionary<string, IJa4Fingerprint> ja4Fingerprints, bool verifyX509Certificates = false)
            : base(mainPacketHandler) {
            this.ja4Fingerprinter = new Ja4Fingerprinter();
            this.ja4Fingerprints = ja4Fingerprints;
            this.verifyX509Certificates = verifyX509Certificates;
            this.ja3Fingerprints = new List<Dictionary<string, string>> {
                DictionaryFactory.CreateDictionaryFromCsv(base.MainPacketHandler.FingerprintsPath + "ja3_fingerprints.csv", 0, 3),//https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
                DictionaryFactory.CreateDictionaryFromTrisulJa3Json(base.MainPacketHandler.FingerprintsPath + "ja3fingerprint.json")
            };
            this.abuseChX509CertificateFingerprints = DictionaryFactory.CreateDictionaryFromCsv(base.MainPacketHandler.FingerprintsPath + "sslblacklist.csv", 1, 2);//https://sslbl.abuse.ch/blacklist/sslblacklist.csv
            //Quotes escaped with '\"' should be used to parse the distinct values
            //"CN=GTE CyberTrust Global Root, OU=\"GTE CyberTrust Solutions, Inc.\", O=GTE Corporation, C=US"
            this.x509SubjectAndIssuerRegex = new Regex("(?<name>[A-Z]+)=(\\\")?(?<value>[\\w\\s\\d\\.\\,\\'\\*\\(\\)#:@_-]+)(\\\")?(,|$)");
        }


        internal void ExtractHandshakeData(ITransportLayerPacket transportPacket, FiveTuple fiveTuple, bool transferIsClientToServer, TlsRecordPacket.HandshakePacket handshake) {

            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = fiveTuple.ClientHost;
                destinationHost = fiveTuple.ServerHost;
            }
            else {
                sourceHost = fiveTuple.ServerHost;
                destinationHost = fiveTuple.ClientHost;
            }

            foreach (var version in handshake.GetSupportedSslVersions()) {
                //destinationHost.AddHostName(handshake.ServerHostName);
                string versionParamName = "TLS Handshake " + Enum.GetName(typeof(TlsRecordPacket.HandshakePacket.MessageTypes), handshake.MessageType) + " Supported Version";
                string versionParamValue;
                if (TlsRecordPacket.HandshakePacket.TryGetTlsVersionString(version, out string tlsVersion))
                    versionParamValue = "TLS " + tlsVersion + " (0x" + version.Item1.ToString("x2") + version.Item2.ToString("x2") + ")";
                else
                    versionParamValue = "SSL " + version.Item1.ToString() + "." + version.Item2.ToString() + " (0x" + version.Item1.ToString("x2") + version.Item2.ToString("x2") + ")";
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection {
                    { versionParamName, versionParamValue }
                };
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Handshake"));

            }
            if (!String.IsNullOrEmpty(handshake.GetAlpnNextProtocolString())) {
                //destinationHost.AddHostName(handshake.ServerHostName);
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection {
                            { "TLS ALPN", handshake.GetAlpnNextProtocolString() }
                        };
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Handshake"));

            }
            if (handshake.MessageType == TlsRecordPacket.HandshakePacket.MessageTypes.ClientHello) {
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection();
                param.Add("JA3 Signature", handshake.GetJA3FingerprintFull());
                string ja3Hash = handshake.GetJA3FingerprintHash();
                var matchingDict = this.ja3Fingerprints.Where(f => f.ContainsKey(ja3Hash)).FirstOrDefault();
                if (matchingDict != null)
                    sourceHost.AddJA3Hash(ja3Hash, matchingDict[ja3Hash]);
                else
                    sourceHost.AddJA3Hash(ja3Hash);
                //sourceHost.AddNumberedExtraDetail("JA3 Hash", ja3Hash);
                param.Add("JA3 Hash", ja3Hash);
                if (handshake.ServerHostName != null) {
                    destinationHost.AddHostName(handshake.ServerHostName, handshake.PacketTypeDescription, "SNI");
                    param.Add("TLS Server Name (SNI)", handshake.ServerHostName);
                }
                string ja4;
                if (transportPacket.TransportProtocol == RFC1700Protocol.TCP)
                    ja4 = handshake.GetJA4Fingerprint('t');
                if (transportPacket.TransportProtocol == RFC1700Protocol.UDP)
                    ja4 = handshake.GetJA4Fingerprint('q');
                else
                    ja4 = handshake.GetJA4Fingerprint();

                if (this.ja4Fingerprints?.TryGetValue(ja4, out IJa4Fingerprint ja4Fingerprint) == true) {
                    sourceHost.AddJA4Fingerprint(ja4Fingerprint.ToString());
                    param.Add("JA4 Fingerprint", ja4Fingerprint.ToString());
                    if(ja4Fingerprint.TryGetOS(out string os)) {
                        sourceHost.AddProbableOs(os, this.ja4Fingerprinter, 0.5);
                    }
                }
                else {
                    sourceHost.AddJA4Fingerprint(ja4);
                    param.Add("JA4 Fingerprint", ja4);
                }

                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Client Hello"));
            }
            else if (handshake.MessageType == TlsRecordPacket.HandshakePacket.MessageTypes.ServerHello) {
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection();
                param.Add("JA3S Signature", handshake.GetJA3SFingerprintFull());
                string ja3Hash = handshake.GetJA3SFingerprintHash();
                sourceHost.AddJA3SHash(ja3Hash);
                param.Add("JA3S Hash", ja3Hash);
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Server Hello"));
            }
            else if (handshake.MessageType == TlsRecordPacket.HandshakePacket.MessageTypes.Certificate)
                for (int certChainIndex = 0; certChainIndex < handshake.CertificateList.Count; certChainIndex++) {
                    byte[] certificate = handshake.CertificateList[certChainIndex];
                    string UNKNOWN_SUBJECT_STRING = "Unknown_x509_Certificate_Subject";
                    string x509CertSubject;
                    System.Security.Cryptography.X509Certificates.X509Certificate x509Cert = null;
                    try {
                        x509Cert = new System.Security.Cryptography.X509Certificates.X509Certificate(certificate);
                        x509CertSubject = x509Cert.Subject;
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Unable to parse X.509 Subject in " + transportPacket.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                        x509CertSubject = UNKNOWN_SUBJECT_STRING;
                        x509Cert = null;
                    }
                    if (x509CertSubject.Contains("CN="))
                        x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf("CN=") + 3);
                    else if (x509CertSubject.Contains("="))
                        x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf('=') + 1);
                    if (x509CertSubject.Length > 28)
                        x509CertSubject = x509CertSubject.Substring(0, 28);
                    if (x509CertSubject.Contains(","))
                        x509CertSubject = x509CertSubject.Substring(0, x509CertSubject.IndexOf(','));

                    x509CertSubject = x509CertSubject.Trim('.', ' ', '"');


                    string filename = x509CertSubject + ".cer";
                    if (string.IsNullOrEmpty(x509CertSubject) || x509CertSubject == "*" || x509CertSubject == UNKNOWN_SUBJECT_STRING) {
                        if (x509Cert != null)
                            filename = x509Cert.GetCertHashString() + ".cer";
                        else if (!string.IsNullOrEmpty(handshake.ServerHostName))
                            filename = handshake.ServerHostName + ".cer";
                    }

                    string fileLocation = "/";
                    string details;
                    if (x509Cert != null)
                        details = "TLS Certificate: " + x509Cert.Subject;
                    else
                        details = "TLS Certificate: Unknown x509 Certificate";


                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, fiveTuple, transferIsClientToServer, FileStreamTypes.TlsCertificate, filename, fileLocation, certificate.Length, certificate.Length, details, null, transportPacket.ParentFrame.FrameNumber, transportPacket.ParentFrame.Timestamp, FileTransfer.FileStreamAssembler.FileAssemblyRootLocation.source);
                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                    if (certChainIndex == 0 && x509CertSubject.Contains(".") && !x509CertSubject.Contains("*") && !x509CertSubject.Contains(" "))
                        sourceHost.AddHostName(x509CertSubject, handshake.PacketTypeDescription, "Subject");
                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    //parameters.Add("Certificate Subject", x509Cert.Subject);
                    const string CERTIFICATE_SUBJECT = "Certificate Subject";
                    this.AddSubjectOrIssuerParameters(parameters, x509Cert.Subject, CERTIFICATE_SUBJECT);
                    if (certChainIndex == 0) {
                        //check for CN parameter
                        if (parameters[CERTIFICATE_SUBJECT + " CN"] != null) {
                            foreach (string cn in parameters.GetValues(CERTIFICATE_SUBJECT + " CN")) {
                                sourceHost.AddNumberedExtraDetail("X.509 Certificate Subject CN", cn);
                                if (cn.Contains(".") && !cn.Contains(" ")) {
                                    if (cn.Contains("*")) {
                                        if (cn.StartsWith("*."))
                                            sourceHost.AddDomainName(cn.Substring(2));
                                    }
                                    else
                                        sourceHost.AddHostName(cn, handshake.PacketTypeDescription, "Subject");
                                }
                            }
                        }
                    }

                    this.AddSubjectOrIssuerParameters(parameters, x509Cert.Issuer, "Certificate Issuer");


                    string certHash = x509Cert.GetCertHashString().ToLower();
                    if (!string.IsNullOrEmpty(certHash) && this.abuseChX509CertificateFingerprints.ContainsKey(certHash)) {
                        string botnet = this.abuseChX509CertificateFingerprints[certHash];
                        sourceHost.AddNumberedExtraDetail("X.509 Certificate Hash", certHash + " = " + botnet + " (abuse.ch SSLBL)");
                    }
                    else if (certChainIndex == 0)
                        sourceHost.AddNumberedExtraDetail("X.509 Certificate Hash", certHash);

                    //parameters.Add("Certificate Issuer", x509Cert.Issuer);
                    parameters.Add("Certificate Hash", certHash);
                    parameters.Add("Certificate valid from", x509Cert.GetEffectiveDateString());
                    parameters.Add("Certificate valid to", x509Cert.GetExpirationDateString());
                    parameters.Add("Certificate Serial", x509Cert.GetSerialNumberString());
                    try {
                        System.Security.Cryptography.X509Certificates.X509Certificate2 cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
                        foreach (var ext in cert2.Extensions) {
                            string fn = ext.Oid.FriendlyName;
                            string oid = ext.Oid.Value;
                            string val = ext.Format(true);
                            System.IO.StringReader sr = new System.IO.StringReader(val);
                            string line = sr.ReadLine();
                            while (line != null) {
                                parameters.Add(oid + " " + fn, line);
                                if (certChainIndex == 0 && oid == "2.5.29.17") {
                                    sourceHost.AddNumberedExtraDetail("X.509 Certificate " + fn, line);
                                }
                                line = sr.ReadLine();
                            }
                        }

                        //verifying certificates is a slow call this might block the parser thread for some time!
                        if (this.verifyX509Certificates) {
                            if (cert2.Verify())
                                parameters.Add("Certificate valid", "TRUE");
                            else
                                parameters.Add("Certificate valid", "FALSE");
                        }
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Unable to parse X509Certificate2 in " + transportPacket.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                    }


                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(transportPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, parameters, transportPacket.ParentFrame.Timestamp, "X.509 Certificate"));

                    if (assembler.TryActivate()) {
                        if (transportPacket is TcpPacket tcpPacket)
                            assembler.AddData(certificate, tcpPacket.SequenceNumber);//this one should trigger FinnishAssembling()
                        else
                            assembler.AddData(certificate, (ushort)transportPacket.ParentFrame.FrameNumber);
                    }
                }
            //}
            //return true;
        }

        private void AddSubjectOrIssuerParameters(System.Collections.Specialized.NameValueCollection parameters, string x509Subject, string parameterName) {

            foreach (Match match in this.x509SubjectAndIssuerRegex.Matches(x509Subject)) {
                string name = match.Groups["name"].Value;
                string val = match.Groups["value"].Value;
                parameters.Add(parameterName + " " + name, val);
            }

        }

    }
}
