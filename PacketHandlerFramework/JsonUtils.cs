using PacketParser.Packets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketHandlerFramework {
    internal static class JsonUtils {
        internal static System.Collections.Specialized.NameValueCollection GetParams(byte[] data, bool gzip, int maxChildrenPerItem, out bool elementsHaveBeenSkipped) {
            System.Collections.Specialized.NameValueCollection bodyJsonElements = null;
            if (gzip) {
                using (MemoryStream ms = new MemoryStream(data))
                using (System.IO.Compression.GZipStream decompressed = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                using (System.Xml.XmlReader jsonReader = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonReader(decompressed, new System.Xml.XmlDictionaryReaderQuotas())) {
                    bodyJsonElements = GetParams(jsonReader, maxChildrenPerItem, out elementsHaveBeenSkipped);
                }
            }
            else {
                using (System.Xml.XmlReader jsonReader = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonReader(data, new System.Xml.XmlDictionaryReaderQuotas())) {
                    bodyJsonElements = GetParams(jsonReader, maxChildrenPerItem, out elementsHaveBeenSkipped);
                }
            }
            return bodyJsonElements;
        }

        internal static System.Collections.Specialized.NameValueCollection GetParams(System.Xml.XmlReader jsonReader, int maxChildrenPerItem, out bool elementsHaveBeenSkipped) {
            System.Collections.Specialized.NameValueCollection jsonElements = new System.Collections.Specialized.NameValueCollection();

            foreach (KeyValuePair<string, List<string>> element in GetNameValues(jsonReader, maxChildrenPerItem, out elementsHaveBeenSkipped)) {
                foreach (string elementValue in element.Value) {
                    jsonElements.Add(element.Key, elementValue);
                }
            }

            return jsonElements;

        }

        private static Dictionary<string, List<string>> GetNameValues(System.Xml.XmlReader jsonReader, int maxChildrenPerItem, out bool elementsHaveBeenSkipped) {
            Dictionary<string, List<string>> elements = new Dictionary<string, List<string>>();

            System.Xml.Linq.XElement x = System.Xml.Linq.XElement.Load(jsonReader);
            if (!x.HasElements && !string.IsNullOrEmpty(x.Name.ToString()) && !string.IsNullOrEmpty(x.Value))
                elements.Add(x.Name.LocalName.ToString(), new List<string> { x.Value });
            elementsHaveBeenSkipped = false;
            foreach (System.Xml.Linq.XElement elem in x.Descendants()) {
                if (!elem.HasElements && !string.IsNullOrEmpty(elem.Name.ToString()) && !string.IsNullOrEmpty(elem.Value)) {
                    char[] jsonElementSplitters = { ',', '{', '[' };
                    int childCount = elem.Value.Count(c => jsonElementSplitters.Contains(c));
                    if (maxChildrenPerItem < 0 || childCount <= maxChildrenPerItem) {
                        //list names aren't propagated properly into children with XElement
                        string elementName = elem.Name.LocalName.ToString();
                        if (elementName == "item" && elem.Parent?.FirstAttribute.Value == "array")
                            elementName = elem.Parent.Name.LocalName.ToString();
                        if (elements.ContainsKey(elementName)) {
                            var list = elements[elementName];
                            if (!list.Contains(elem.Value)) //avoid duplicates
                                elements[elementName].Add(elem.Value);
                        }
                        else
                            elements.Add(elementName, new List<string> { elem.Value });
                    }
                    else
                        elementsHaveBeenSkipped = true;
                }

            }
            return elements;

        }
    }
}
