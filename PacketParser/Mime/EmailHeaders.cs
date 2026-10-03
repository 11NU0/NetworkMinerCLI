using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketParser.Mime {
    public static class EmailHeaders {
        public const string HEADER_FROM = "From";
        public const string HEADER_TO = "To";
        public const string HEADER_SUBJECT = "Subject";
        public const string HEADER_MESSAGE_ID = "Message-ID";
        public const string HEADER_DATE = "Date";

        public const string HEADER_CONTENT_TRANSFER_ENCODING = "Content-Transfer-Encoding";
        public const string HEADER_CONTENT_TYPE = "Content-Type";
        public const string HEADER_MIME_VERSION = "MIME-Version";
        public const string HEADER_RETURN_PATH = "Return-Path";
        public const string HEADER_DELIVERED_TO = "Delivered-To";
        public const string HEADER_RECEIVED = "Received";

        public static readonly string[] COMMON_HEADERS = {
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
    }
}
