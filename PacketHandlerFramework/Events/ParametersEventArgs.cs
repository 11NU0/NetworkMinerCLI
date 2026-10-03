using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;
using PacketParser.Packets;

namespace PacketHandlerFramework.Events {
    public class ParametersEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {

        public long FrameNumber;
        public NetworkHost SourceHost, DestinationHost;
        public string SourcePort, DestinationPort;
        public System.Collections.Specialized.NameValueCollection Parameters;
        public DateTime Timestamp;
        public string Details;

        private ParametersEventArgs() { }//for serialization purposes

        public static ParametersEventArgs GetParametersEventArgs(PacketParser.Frame frame, NetworkTcpSession tcpSession, bool transferIsClientToServer, System.Collections.Specialized.NameValueCollection parameters, string details) {
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
            return new ParametersEventArgs(frame.FrameNumber, sourceHost, destinationHost, tcpSession.Flow.FiveTuple.Transport, sourcePort, destinationPort, parameters, frame.Timestamp, details);
        }
        public ParametersEventArgs(long frameNumber, NetworkHost sourceHost, NetworkHost destinationHost, FiveTuple.TransportProtocol transport, ushort sourcePort, ushort destinationPort, System.Collections.Specialized.NameValueCollection parameters, DateTime timestamp, string details) : this(frameNumber, sourceHost, destinationHost, (PacketParser.Packets.RFC1700Protocol) transport, sourcePort, destinationPort, parameters, timestamp, details) {
            //nothing more to add
        }
        public ParametersEventArgs(long frameNumber, NetworkHost sourceHost, NetworkHost destinationHost, PacketParser.Packets.RFC1700Protocol transport, ushort sourcePort, ushort destinationPort, System.Collections.Specialized.NameValueCollection parameters, DateTime timestamp, string details) : this(frameNumber, sourceHost, destinationHost, transport.ToString() + " " + sourcePort, transport.ToString() + " " + destinationPort, parameters, timestamp, details) {
            //nothing more to add
        }

        private ParametersEventArgs(long frameNumber, NetworkHost sourceHost, NetworkHost destinationHost, string sourcePort, string destinationPort, System.Collections.Specialized.NameValueCollection parameters, DateTime timestamp, string details) {
            this.FrameNumber=frameNumber;
            this.SourceHost=sourceHost;
            this.DestinationHost=destinationHost;
            this.SourcePort=sourcePort;
            this.DestinationPort=destinationPort;
            this.Parameters=parameters;
            this.Timestamp=timestamp;
            this.Details=details;
        }

        [Obsolete]
        public ParametersEventArgs(long frameNumber, NetworkHost sourceHost, NetworkHost destinationHost, string sourcePort, string destinationPort, IEnumerable<KeyValuePair<string, string>> parameters, DateTime timestamp, string details) {
            this.FrameNumber = frameNumber;
            this.SourceHost = sourceHost;
            this.DestinationHost = destinationHost;
            this.SourcePort = sourcePort;   
            this.DestinationPort = destinationPort;
            this.Parameters = new System.Collections.Specialized.NameValueCollection();
            foreach (KeyValuePair<string, string> kvp in parameters)
                this.Parameters.Add(kvp.Key, kvp.Value);
            this.Timestamp = timestamp;
            this.Details = details;
        }

        [Obsolete]
        public ParametersEventArgs(long frameNumber, FiveTuple fiveTuple, bool transferIsClientToServer, System.Collections.Specialized.NameValueCollection parameters, DateTime timestamp, string details) {
            this.FrameNumber = frameNumber;
            if (transferIsClientToServer) {
                this.SourceHost = fiveTuple.ClientHost;
                this.DestinationHost = fiveTuple.ServerHost;
                this.SourcePort = fiveTuple.Transport.ToString() + " " + fiveTuple.ClientPort;
                this.DestinationPort = fiveTuple.Transport.ToString() + " " + fiveTuple.ServerPort;
            }
            else {
                this.SourceHost = fiveTuple.ServerHost;
                this.DestinationHost = fiveTuple.ClientHost;
                this.SourcePort = fiveTuple.Transport.ToString() + " " + fiveTuple.ServerPort;
                this.DestinationPort = fiveTuple.Transport.ToString() + " " + fiveTuple.ClientPort;
            }
            this.Parameters = new System.Collections.Specialized.NameValueCollection();
            this.Parameters = parameters;
            this.Timestamp = timestamp;
            this.Details = details;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            
            writer.WriteElementString("FrameNumber", FrameNumber.ToString());
            writer.WriteElementString("SourceHost", SourceHost.IPAddress.ToString());
            writer.WriteElementString("DestinationHost", DestinationHost.IPAddress.ToString());
            writer.WriteElementString("SourcePort", SourcePort.ToString());
            writer.WriteElementString("DestinationPort", DestinationPort.ToString());
            writer.WriteElementString("Timestamp", Timestamp.ToString());
            writer.WriteElementString("Details", Details);

            
            foreach (string name in this.Parameters.Keys) {
                writer.WriteStartElement("Parameter");
                writer.WriteAttributeString("name", name);
                writer.WriteString(this.Parameters[name]);
                writer.WriteEndElement();
            }
        }
    }
}
