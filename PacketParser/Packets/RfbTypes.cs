using System;

namespace PacketParser.Packets {
    public struct RfbColor {
        public readonly byte R, G, B;
        public readonly int Argb;
        public RfbColor(byte r, byte g, byte b) {
            R = r; G = g; B = b;
            Argb = (255 << 24) | (r << 16) | (g << 8) | b;
        }
        public RfbColor(int argb) {
            Argb = argb;
            R = (byte)((argb >> 16) & 0xff);
            G = (byte)((argb >> 8) & 0xff);
            B = (byte)(argb & 0xff);
        }
#if NETFRAMEWORK
        public System.Drawing.Color ToDrawingColor() => System.Drawing.Color.FromArgb(Argb);
#endif
    }

    public struct RfbSize {
        public readonly int Width, Height;
        public RfbSize(int width, int height) { Width = width; Height = height; }
        public override string ToString() => Width + "x" + Height;
#if NETFRAMEWORK
        public System.Drawing.Size ToDrawingSize() => new System.Drawing.Size(Width, Height);
#endif
    }
}
