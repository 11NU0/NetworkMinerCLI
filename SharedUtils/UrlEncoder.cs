using System;
using System.Collections.Specialized;

namespace SharedUtils {
    public static class UrlEncoder {
        public static string UrlEncode(string s) {
            if (s == null) return null;
            return System.Net.WebUtility.UrlEncode(s);
        }

        public static string UrlDecode(string s) {
            if (s == null) return null;
            return System.Net.WebUtility.UrlDecode(s.Replace('+', ' '));
        }

        public static NameValueCollection ParseQueryString(string query) {
            var nvc = new NameValueCollection();
            if (string.IsNullOrEmpty(query))
                return nvc;
            foreach (string pair in query.Split('&')) {
                int eq = pair.IndexOf('=');
                if (eq >= 0) {
                    string key = UrlDecode(pair.Substring(0, eq));
                    string val = UrlDecode(pair.Substring(eq + 1));
                    nvc.Add(key, val);
                }
                else if (pair.Length > 0) {
                    nvc.Add(UrlDecode(pair), "");
                }
            }
            return nvc;
        }
    }
}
