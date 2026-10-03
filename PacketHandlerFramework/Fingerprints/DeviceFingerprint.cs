using System;
using System.Collections.Generic;
using System.Text;

namespace PacketHandlerFramework.Fingerprints {
    public class DeviceFingerprint {
        private string os;
        private string category;
        private string family;

        public string OS { get { return this.os; } }
        public string Category { get { return this.category; } }
        public string Family { get { return this.family; } }


        internal DeviceFingerprint(string os, string category = null, string family = null) {
            this.os = os;
            this.category = category;
            this.family = family;
        }

        public override string ToString() {
            StringBuilder osString = new StringBuilder(this.os);

            if (this.category != null && this.category.Length > 0)
                osString.Append(" [" + this.category + "]");
            if (this.family != null && this.family.Length > 0)
                osString.Append(" [" + this.family + "]");
            return osString.ToString();
        }
    }
}
