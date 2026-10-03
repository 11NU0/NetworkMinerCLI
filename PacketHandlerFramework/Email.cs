using PacketParser;
using PacketParser.Packets;
using PacketParser.Mime;
using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework {
    public class Email {

        /**
         * Moved into PacketParser/Mime/EmailHeaders.cs
         * 
        private const string HEADER_FROM = "From";
        private const string HEADER_TO = "To";
        private const string HEADER_SUBJECT = "Subject";
        private const string HEADER_MESSAGE_ID = "Message-ID";
        private const string HEADER_DATE = "Date";

        private const string HEADER_CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
        private const string HEADER_CONTENT_TYPE = "Content-Type";
        private const string HEADER_MIME_VERSION = "MIME-Version";
        private const string HEADER_RETURN_PATH = "Return-Path";
        private const string HEADER_DELIVERED_TO = "Delivered-To";
        private const string HEADER_RECEIVED = "Received";

        
        internal static readonly string[] COMMON_HEADERS = {
            HEADER_FROM,
            HEADER_TO,
            HEADER_SUBJECT,
            HEADER_MESSAGE_ID,
            HEADER_DATE,
            HEADER_CONTENT_TRANSFER_ENCODING,
            HEADER_CONTENT_TYPE,
            HEADER_MIME_VERSION,
            HEADER_RETURN_PATH,
            HEADER_DELIVERED_TO,
            HEADER_RECEIVED
        };
        */

        public static string GetMessageId(System.Collections.Specialized.NameValueCollection rootAttributes) {

            if (rootAttributes[EmailHeaders.HEADER_MESSAGE_ID] != null && rootAttributes[EmailHeaders.HEADER_MESSAGE_ID].Length > 0)
                return rootAttributes[EmailHeaders.HEADER_MESSAGE_ID];
            StringBuilder sb = new StringBuilder();
            if (rootAttributes[EmailHeaders.HEADER_SUBJECT] != null)
                sb.Append(rootAttributes[EmailHeaders.HEADER_SUBJECT]);
            if (rootAttributes[EmailHeaders.HEADER_DATE] != null)
                sb.Append(rootAttributes[EmailHeaders.HEADER_DATE]);
            return sb.ToString();
        }



        public string From { get; }
        public string To { get; }
        public string Subject { get; }
        public string MessageID { get; }
        public string DateString { get; }
        public IEnumerable<FileTransfer.ReconstructedFile> Attachments { get { return this.attachments; } }
        public System.Collections.Specialized.NameValueCollection RootAttributes { get; }

        internal readonly PacketHandler MainPacketHandler;
        private readonly FileTransfer.FileStreamTypes fileTransferProtocol;
        private readonly ApplicationLayerProtocol protocol;
        private readonly List<FileTransfer.ReconstructedFile> attachments;
        //private bool reassembleFileAtSourceHost;
        private readonly FileTransfer.FileStreamAssembler.FileAssemblyRootLocation fileAssmeblyRootLocation;
        private readonly FiveTuple fiveTuple;
        private readonly bool transferIsClientToServer;

        public Email(System.IO.MemoryStream emailMimeStream, PacketHandler mainPacketHandler, TcpPacket tcpPacket, bool transferIsClientToServer, NetworkTcpSession tcpSession, ApplicationLayerProtocol protocol, FileTransfer.FileStreamAssembler.FileAssemblyRootLocation fileAssmeblyRootLocation = FileTransfer.FileStreamAssembler.FileAssemblyRootLocation.destination) {
            SharedUtils.Logger.Log("Extracting Email from MIME data in " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            PacketParser.Mime.UnbufferedReader ur = new UnbufferedReader(emailMimeStream);
            this.MainPacketHandler = mainPacketHandler;
            this.protocol = protocol;
            if (this.protocol == ApplicationLayerProtocol.SMTP)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.SMTP;
            else if (this.protocol == ApplicationLayerProtocol.POP3)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.POP3;
            else if (this.protocol == ApplicationLayerProtocol.IMAP)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.IMAP;
            //this.reassembleFileAtSourceHost = reassembleFileAtSourceHost;
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;

            this.fiveTuple = tcpSession.Flow.FiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;

            this.attachments = new List<FileTransfer.ReconstructedFile>();
            this.From = null;
            this.To = null;
            this.Subject = null;
            this.MessageID = null;
            this.DateString = null;//Date: Fri, 1 Aug 2003 14:17:51 -0700
            Encoding customEncoding = null;
            this.RootAttributes = null;
            bool messageSentToPacketHandler = false;

            //The open source .NET implementation Mono can crash if the strings contain Unicode chracters
            //see KeePass bug: https://sourceforge.net/p/keepass/feature-requests/2254/
            foreach (PacketParser.Mime.MultipartPart multipart in PacketParser.Mime.PartBuilder.GetParts(ur, SharedUtils.SystemHelper.IsRunningOnMono(), null)) {//I might need to add "ref customEncoding" as a parameter here

                SharedUtils.Logger.Log("Extracting MIME part with attributes \"" + string.Join(",", multipart.Attributes.AllKeys) + "\" in " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);

                if (this.RootAttributes == null) {

                    this.From = multipart.Attributes[EmailHeaders.HEADER_FROM];
                    this.To = multipart.Attributes[EmailHeaders.HEADER_TO];
                    if (string.IsNullOrEmpty(this.To) && !string.IsNullOrEmpty(multipart.Attributes[EmailHeaders.HEADER_DELIVERED_TO]))
                        this.To = multipart.Attributes[EmailHeaders.HEADER_DELIVERED_TO];
                    this.Subject = multipart.Attributes[EmailHeaders.HEADER_SUBJECT];
                    this.MessageID = multipart.Attributes[EmailHeaders.HEADER_MESSAGE_ID];
                    this.DateString = multipart.Attributes[EmailHeaders.HEADER_DATE];
                    this.RootAttributes = multipart.Attributes;
                }
                if (multipart.Attributes["charset"] != null) {
                    try {
                        customEncoding = Encoding.GetEncoding(multipart.Attributes["charset"]);
                    }
                    catch (Exception e) {
                        SharedUtils.Logger.Log("Exception getting encoding for charset \"" + multipart.Attributes["charset"] + "\". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    }
                }

                this.parseMultipart(multipart, this.RootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, emailMimeStream.Length, From, To, Subject, MessageID);

            }

            if (!messageSentToPacketHandler && this.From != null && this.To != null) {
                //send message to PacketHandler with force
                if (this.transferIsClientToServer)
                    this.MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(this.protocol, this.fiveTuple.ClientHost, this.fiveTuple.ServerHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.From, this.To, this.Subject, "", customEncoding, this.RootAttributes, emailMimeStream.Length));
                else
                    this.MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(this.protocol, this.fiveTuple.ServerHost, this.fiveTuple.ClientHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.From, this.To, this.Subject, "", customEncoding, this.RootAttributes, emailMimeStream.Length));

                messageSentToPacketHandler = true;
            }

            //create an .eml file with the whole DATA portion
            string emlFilename = null;
            if (this.Subject != null && Subject.Length > 3) emlFilename = PacketParser.Utils.StringManglerUtil.ConvertToFilename(this.Subject, 10);
            if (emlFilename == null || emlFilename.Length == 0) {
                if (this.MessageID != null && this.MessageID.Length > 3) emlFilename = PacketParser.Utils.StringManglerUtil.ConvertToFilename(MessageID, 10);
                else
                    emlFilename = "message_" + tcpSession.GetHashCode().ToString("X8");
            }

            emlFilename += ".eml";

            if (this.RootAttributes != null) {
                string extendedFileId = GetMessageId(this.RootAttributes);
                using (FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, this.fiveTuple, this.transferIsClientToServer, this.fileTransferProtocol, emlFilename, "/", emailMimeStream.Length, emailMimeStream.Length, this.protocol.ToString() + " transcript From: " + From + " To: " + To + " Subject: " + Subject, extendedFileId, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.fileAssmeblyRootLocation)) {
                    if (assembler.TryActivate()) {
                        assembler.FileReconstructed += this.MainPacketHandler.OnMessageAttachmentDetected;
                        assembler.FileReconstructed += this.Assembler_FileReconstructed;
                        SharedUtils.Logger.Log("Adding emailMimeStream bytes: " + emailMimeStream.Length, SharedUtils.Logger.EventLogEntryType.Information);
                        assembler.AddData(emailMimeStream.ToArray(), tcpPacket.SequenceNumber);
                    }
                    else {
                        SharedUtils.Logger.Log("Unable to activate email assembler", SharedUtils.Logger.EventLogEntryType.Warning);
                        assembler.Clear();
                        assembler.FinishAssembling();
                    }
                }
            }
        }

        private void Assembler_FileReconstructed(string extendedFileId, FileTransfer.ReconstructedFile file) {
            this.attachments.Add(file);
        }

        private void parseMultipart(MultipartPart multipart, System.Collections.Specialized.NameValueCollection rootAttributes, TcpPacket tcpPacket, /*NetworkHost sourceHost, NetworkHost destinationHost, */
        ref bool messageSentToPacketHandler, Encoding customEncoding, long size, string from = null, string to = null, string subject = null, string messageId = null, bool attachment = false) {
            SharedUtils.Logger.Log("Parsing MIME part with root attributes \"" + string.Join(",", rootAttributes.AllKeys) + "\" in " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            if (multipart.Attributes.Count > 0) this.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, this.fiveTuple, this.transferIsClientToServer, multipart.Attributes, tcpPacket.ParentFrame.Timestamp, this.protocol + " packet"));
            string contentType = multipart.Attributes["Content-Type"];
            if (contentType == null)
                SharedUtils.Logger.Log("MIME part content type is null in " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            else
                SharedUtils.Logger.Log("MIME part content type is \"" + contentType + "\" in " + tcpPacket.ParentFrame.ToString(), SharedUtils.Logger.EventLogEntryType.Information);

            string charset = multipart.Attributes["charset"];
            if (charset != null && charset.Length > 0) {
                try {
                    customEncoding = Encoding.GetEncoding(charset);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Exception getting encoding for charset \"" + charset + "\". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                };
            }
            string contentDisposition = multipart.Attributes["Content-Disposition"];
            if (contentDisposition != null && contentDisposition.Contains("attachment"))
                attachment = true;
            if (contentType != null && (
                contentType.Equals("multipart/mixed", StringComparison.InvariantCultureIgnoreCase) ||
                contentType.Equals("multipart/alternative", StringComparison.InvariantCultureIgnoreCase) ||
                contentType.Equals("multipart/related", StringComparison.InvariantCultureIgnoreCase)
                )) {
                /**
                 * There are a variety of ways to attach images to an email.
                 * Content types are used to identify what is contained by each part of the email.
                 * As well as the various types of image, and text/plain and text/html for the text and HTML parts,
                 * there are various containers: 
                 * multipart/alternative as a container for parts containing the same information in different formats,
                 * multipart/related as a container for parts that are linked in some way, and
                 * multipart/mixed as a general container.
                 **/

                //Mime.MultipartPart mimeMultipart = new Mime.MultipartPart(multipart.Data);
                System.IO.Stream mixedStream = new System.IO.MemoryStream(multipart.Data);
                UnbufferedReader mixedReader = new UnbufferedReader(mixedStream);
                string boundary = mixedReader.ReadLine(200, customEncoding);
                if (boundary != null && boundary.Length == 0)//there was an empty line before the boundary, try to read it again
                    boundary = mixedReader.ReadLine(200, customEncoding);
                if (boundary != null && boundary.StartsWith("--")) {
                    boundary = boundary.Substring(2);
                    List<MultipartPart> innerParts = new List<MultipartPart>(PartBuilder.GetParts(mixedReader, boundary, SharedUtils.SystemHelper.IsRunningOnMono(), customEncoding));
                    foreach (MultipartPart innerPart in innerParts) {
                        //a bit of recursion here
                        this.parseMultipart(innerPart, rootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, size, from, to, subject, messageId);
                    }
                }
            }
            else if (!attachment && contentType == null ||
                !attachment && contentType != null &&
                (contentType.Equals("text/plain", StringComparison.InvariantCultureIgnoreCase) ||
                    contentType.Equals("text", StringComparison.InvariantCultureIgnoreCase) ||
                    !messageSentToPacketHandler && contentType.Equals("text/html", StringComparison.InvariantCultureIgnoreCase))) {
                //print the data as text
                //string textData = null;
                byte[] textDataBytes = null;
                if (multipart.Attributes["Content-Transfer-Encoding"] == "quoted-printable") textDataBytes = PacketParser.Utils.ByteConverter.ReadQuotedPrintable(multipart.Data).ToArray();
                else if (multipart.Attributes["Content-Transfer-Encoding"] == "base64") {
                    textDataBytes = Convert.FromBase64String(PacketParser.Utils.ByteConverter.ReadString(multipart.Data));
                    //textData = Utils.ByteConverter.ReadString();
                }
                else {
                    textDataBytes = multipart.Data;
                    //textData = Utils.ByteConverter.ReadString();
                }
                string textData = null;
                if (customEncoding == null)
                    textData = PacketParser.Utils.ByteConverter.ReadString(textDataBytes);
                else
                    textData = customEncoding.GetString(textDataBytes);
                if (textData != null) {
                    Dictionary<string, string> aggregatedAttributeDictionary = new Dictionary<string, string>();
                    System.Collections.Specialized.NameValueCollection aggregatedAttributes = new System.Collections.Specialized.NameValueCollection();
                    aggregatedAttributes.Add(rootAttributes);
                    foreach (string name in rootAttributes.Keys)
                        aggregatedAttributeDictionary.Add(name, rootAttributes[name]);
                    foreach (string name in multipart.Attributes)
                        if (!aggregatedAttributeDictionary.ContainsKey(name)) {
                            aggregatedAttributeDictionary.Add(name, multipart.Attributes[name]);
                            aggregatedAttributes.Add(name, multipart.Attributes[name]);
                        }
                    if (textData.Length > 0) {

                        //replace CR without LF with a NewLine of the local system
                        textData = System.Text.RegularExpressions.Regex.Replace(textData, @"\r(?!\n)", Environment.NewLine);

                        if (multipart.Attributes["format"]?.Equals("flowed", StringComparison.InvariantCultureIgnoreCase) == true)
                            /**
                             * rfc2646
                             * If the line ends in one or more spaces, the line is flowed.
                             * Otherwise it is fixed.  Trailing spaces are part of the line's
                             * content, but the CRLF of a soft line break is not.
                             **/
                            textData = System.Text.RegularExpressions.Regex.Replace(textData, @" \r\n?| \n", " ");

                        if (SharedUtils.SystemHelper.IsRunningOnMono())
                            textData = PacketParser.Utils.StringManglerUtil.ConvertToAsciiIfUnicode(textData);

                        if (this.transferIsClientToServer)
                            this.MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(this.protocol, this.fiveTuple.ClientHost, this.fiveTuple.ServerHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, from, to, subject, textData, customEncoding, aggregatedAttributes, size));
                        else
                            this.MainPacketHandler.OnMessageDetected(new Events.MessageEventArgs(this.protocol, this.fiveTuple.ServerHost, this.fiveTuple.ClientHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, from, to, subject, textData, customEncoding, aggregatedAttributes, size));

                        messageSentToPacketHandler = true;
                    }
                    //messageSentToPacketHandler = true;
                    if (contentType != null && contentType.Equals("text/html", StringComparison.InvariantCultureIgnoreCase))                         //re-parse the multipart so that it is also extracted to an HTML file
                        this.parseMultipart(multipart, rootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, size, from, to, subject, messageId, true);
                }
            }
            else {
                //store the stuff to disk
                string filename = multipart.Attributes["name"];
                if (string.IsNullOrEmpty(filename))
                    filename = multipart.Attributes["filename"];

                if (!string.IsNullOrEmpty(filename) && !PacketParser.Utils.StringManglerUtil.IsValidFilename(filename))
                    filename = PacketParser.Utils.StringManglerUtil.ConvertToFilename(filename, 30, true);

                if (string.IsNullOrEmpty(filename)) {
                    if (subject != null && subject.Length > 3) filename = PacketParser.Utils.StringManglerUtil.ConvertToFilename(subject, 10);
                    else if (messageId != null && messageId.Length > 3) {
                        filename = PacketParser.Utils.StringManglerUtil.ConvertToFilename(messageId, 10);
                    }
                    if (filename == null || filename.Length < 3)
                        filename = "email_" + multipart.GetHashCode() % 1000;

                    string extension = PacketParser.Utils.StringManglerUtil.GetExtension(contentType);
                    if (extension == null || extension.Length < 1)
                        extension = "dat";
                    filename = filename + "." + extension;
                }

                List<byte> fileData = new List<byte>();
                if (multipart.Attributes["Content-Transfer-Encoding"] == "base64") {
                    //decode base64 stuff
                    int index = 0;
                    while (index < multipart.Data.Length) {
                        string base64 = PacketParser.Utils.ByteConverter.ReadLine(multipart.Data, ref index);
                        if (base64 == null && index < multipart.Data.Length) {
                            //read the remaining data
                            base64 = PacketParser.Utils.ByteConverter.ReadString(multipart.Data, index, multipart.Data.Length - index, false, false);
                            index = multipart.Data.Length;
                        }
#if DEBUG
                        if (base64 == null)
                            System.Diagnostics.Debugger.Break();
#endif
                        //if (base64 != null && base64.Length > 0) {
                        try {
                            fileData.AddRange(Convert.FromBase64String(base64));
                        }
                        catch (FormatException e) {
                            SharedUtils.Logger.Log("FormatException decoding Base64 data in email: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        }
                    }
                }
                else if (multipart.Attributes["Content-Transfer-Encoding"] == "quoted-printable") {
                    //must be decoded according to http://www.ietf.org/rfc/rfc2045.txt
                    fileData = PacketParser.Utils.ByteConverter.ReadQuotedPrintable(multipart.Data);
                }
                else {
                    //Add the raw data
                    fileData.AddRange(multipart.Data);
                }

                if (fileData != null && fileData.Count > 0) {
                    string fileId = GetMessageId(rootAttributes);

                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, this.fiveTuple, this.transferIsClientToServer, this.fileTransferProtocol, filename, "/", fileData.Count, fileData.Count, "E-mail From: " + from + " To: " + to + " Subject: " + subject, fileId, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.fileAssmeblyRootLocation);
                    if (assembler.TryActivate()) {
                        assembler.FileReconstructed += MainPacketHandler.OnMessageAttachmentDetected;
                        assembler.FileReconstructed += Assembler_FileReconstructed;//added 200820
                        assembler.AddData(fileData.ToArray(), tcpPacket.SequenceNumber);
                        //assembler.FinishAssembling();
                    }
                    else {
                        assembler.Clear();
                        assembler.FinishAssembling();
                    }
                }

            }
        }
    }
}
