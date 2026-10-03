using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using static PacketParser.Packets.RfbPacket.VncCommandPacket;
using static PacketParser.Packets.RfbPacket.VncResponsePacket;
using PacketParser.Packets;
using PacketParser.Utils;

namespace PacketParser.Packets
{
    public class RfbPacket : AbstractPacket {
        //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst

        public enum SecurityType : byte {
            Invalid = 0,
            None = 1,
            VncAuth = 2,
            RSA_AES = 5,
            RSA_AES_Unencrypted = 6,
            SSPI = 7,
            SSPIne = 8,
            Tight = 16,
            Ultra = 17,
            TLS = 18,
            VeNCrypt = 19,
            GTK_VNC_SASL = 20,
            MD5 = 21,
            XVP = 22,
            MAC_OSX_SECTYPE_30 = 30,
            MAC_OSX_SECTYPE_35 = 35,
            ARD = 30,
            //Tight
            TIGHT_AUTH_TGHT_ULGNAUTH = 119,
            TIGHT_AUTH_TGHT_XTRNAUTH = 130,
        }

        protected const int MAX_SCREEN_WIDTH = 8000;
        protected const int MAX_SCREEN_HEIGHT = 8000;



        private static readonly Encoding ISO_8859 = Encoding.GetEncoding("ISO-8859-1");

        //https://raw.githubusercontent.com/xkbcommon/libxkbcommon/master/src/keysym-utf.c
        private static readonly Dictionary<uint, ushort> KEYSYM_2_UNICODE = new Dictionary<uint, ushort>() {
            { 0x01a1, 0x0104 }, /*                     Aogonek Ą LATIN CAPITAL LETTER A WITH OGONEK */
            { 0x01a2, 0x02d8 }, /*                       breve ˘ BREVE */
            { 0x01a3, 0x0141 }, /*                     Lstroke Ł LATIN CAPITAL LETTER L WITH STROKE */
            { 0x01a5, 0x013d }, /*                      Lcaron Ľ LATIN CAPITAL LETTER L WITH CARON */
            { 0x01a6, 0x015a }, /*                      Sacute Ś LATIN CAPITAL LETTER S WITH ACUTE */
            { 0x01a9, 0x0160 }, /*                      Scaron Š LATIN CAPITAL LETTER S WITH CARON */
            { 0x01aa, 0x015e }, /*                    Scedilla Ş LATIN CAPITAL LETTER S WITH CEDILLA */
            { 0x01ab, 0x0164 }, /*                      Tcaron Ť LATIN CAPITAL LETTER T WITH CARON */
            { 0x01ac, 0x0179 }, /*                      Zacute Ź LATIN CAPITAL LETTER Z WITH ACUTE */
            { 0x01ae, 0x017d }, /*                      Zcaron Ž LATIN CAPITAL LETTER Z WITH CARON */
            { 0x01af, 0x017b }, /*                   Zabovedot Ż LATIN CAPITAL LETTER Z WITH DOT ABOVE */
            { 0x01b1, 0x0105 }, /*                     aogonek ą LATIN SMALL LETTER A WITH OGONEK */
            { 0x01b2, 0x02db }, /*                      ogonek ˛ OGONEK */
            { 0x01b3, 0x0142 }, /*                     lstroke ł LATIN SMALL LETTER L WITH STROKE */
            { 0x01b5, 0x013e }, /*                      lcaron ľ LATIN SMALL LETTER L WITH CARON */
            { 0x01b6, 0x015b }, /*                      sacute ś LATIN SMALL LETTER S WITH ACUTE */
            { 0x01b7, 0x02c7 }, /*                       caron ˇ CARON */
            { 0x01b9, 0x0161 }, /*                      scaron š LATIN SMALL LETTER S WITH CARON */
            { 0x01ba, 0x015f }, /*                    scedilla ş LATIN SMALL LETTER S WITH CEDILLA */
            { 0x01bb, 0x0165 }, /*                      tcaron ť LATIN SMALL LETTER T WITH CARON */
            { 0x01bc, 0x017a }, /*                      zacute ź LATIN SMALL LETTER Z WITH ACUTE */
            { 0x01bd, 0x02dd }, /*                 doubleacute ˝ DOUBLE ACUTE ACCENT */
            { 0x01be, 0x017e }, /*                      zcaron ž LATIN SMALL LETTER Z WITH CARON */
            { 0x01bf, 0x017c }, /*                   zabovedot ż LATIN SMALL LETTER Z WITH DOT ABOVE */
            { 0x01c0, 0x0154 }, /*                      Racute Ŕ LATIN CAPITAL LETTER R WITH ACUTE */
            { 0x01c3, 0x0102 }, /*                      Abreve Ă LATIN CAPITAL LETTER A WITH BREVE */
            { 0x01c5, 0x0139 }, /*                      Lacute Ĺ LATIN CAPITAL LETTER L WITH ACUTE */
            { 0x01c6, 0x0106 }, /*                      Cacute Ć LATIN CAPITAL LETTER C WITH ACUTE */
            { 0x01c8, 0x010c }, /*                      Ccaron Č LATIN CAPITAL LETTER C WITH CARON */
            { 0x01ca, 0x0118 }, /*                     Eogonek Ę LATIN CAPITAL LETTER E WITH OGONEK */
            { 0x01cc, 0x011a }, /*                      Ecaron Ě LATIN CAPITAL LETTER E WITH CARON */
            { 0x01cf, 0x010e }, /*                      Dcaron Ď LATIN CAPITAL LETTER D WITH CARON */
            { 0x01d0, 0x0110 }, /*                     Dstroke Đ LATIN CAPITAL LETTER D WITH STROKE */
            { 0x01d1, 0x0143 }, /*                      Nacute Ń LATIN CAPITAL LETTER N WITH ACUTE */
            { 0x01d2, 0x0147 }, /*                      Ncaron Ň LATIN CAPITAL LETTER N WITH CARON */
            { 0x01d5, 0x0150 }, /*                Odoubleacute Ő LATIN CAPITAL LETTER O WITH DOUBLE ACUTE */
            { 0x01d8, 0x0158 }, /*                      Rcaron Ř LATIN CAPITAL LETTER R WITH CARON */
            { 0x01d9, 0x016e }, /*                       Uring Ů LATIN CAPITAL LETTER U WITH RING ABOVE */
            { 0x01db, 0x0170 }, /*                Udoubleacute Ű LATIN CAPITAL LETTER U WITH DOUBLE ACUTE */
            { 0x01de, 0x0162 }, /*                    Tcedilla Ţ LATIN CAPITAL LETTER T WITH CEDILLA */
            { 0x01e0, 0x0155 }, /*                      racute ŕ LATIN SMALL LETTER R WITH ACUTE */
            { 0x01e3, 0x0103 }, /*                      abreve ă LATIN SMALL LETTER A WITH BREVE */
            { 0x01e5, 0x013a }, /*                      lacute ĺ LATIN SMALL LETTER L WITH ACUTE */
            { 0x01e6, 0x0107 }, /*                      cacute ć LATIN SMALL LETTER C WITH ACUTE */
            { 0x01e8, 0x010d }, /*                      ccaron č LATIN SMALL LETTER C WITH CARON */
            { 0x01ea, 0x0119 }, /*                     eogonek ę LATIN SMALL LETTER E WITH OGONEK */
            { 0x01ec, 0x011b }, /*                      ecaron ě LATIN SMALL LETTER E WITH CARON */
            { 0x01ef, 0x010f }, /*                      dcaron ď LATIN SMALL LETTER D WITH CARON */
            { 0x01f0, 0x0111 }, /*                     dstroke đ LATIN SMALL LETTER D WITH STROKE */
            { 0x01f1, 0x0144 }, /*                      nacute ń LATIN SMALL LETTER N WITH ACUTE */
            { 0x01f2, 0x0148 }, /*                      ncaron ň LATIN SMALL LETTER N WITH CARON */
            { 0x01f5, 0x0151 }, /*                odoubleacute ő LATIN SMALL LETTER O WITH DOUBLE ACUTE */
            { 0x01f8, 0x0159 }, /*                      rcaron ř LATIN SMALL LETTER R WITH CARON */
            { 0x01f9, 0x016f }, /*                       uring ů LATIN SMALL LETTER U WITH RING ABOVE */
            { 0x01fb, 0x0171 }, /*                udoubleacute ű LATIN SMALL LETTER U WITH DOUBLE ACUTE */
            { 0x01fe, 0x0163 }, /*                    tcedilla ţ LATIN SMALL LETTER T WITH CEDILLA */
            { 0x01ff, 0x02d9 }, /*                    abovedot ˙ DOT ABOVE */
            { 0x02a1, 0x0126 }, /*                     Hstroke Ħ LATIN CAPITAL LETTER H WITH STROKE */
            { 0x02a6, 0x0124 }, /*                 Hcircumflex Ĥ LATIN CAPITAL LETTER H WITH CIRCUMFLEX */
            { 0x02a9, 0x0130 }, /*                   Iabovedot İ LATIN CAPITAL LETTER I WITH DOT ABOVE */
            { 0x02ab, 0x011e }, /*                      Gbreve Ğ LATIN CAPITAL LETTER G WITH BREVE */
            { 0x02ac, 0x0134 }, /*                 Jcircumflex Ĵ LATIN CAPITAL LETTER J WITH CIRCUMFLEX */
            { 0x02b1, 0x0127 }, /*                     hstroke ħ LATIN SMALL LETTER H WITH STROKE */
            { 0x02b6, 0x0125 }, /*                 hcircumflex ĥ LATIN SMALL LETTER H WITH CIRCUMFLEX */
            { 0x02b9, 0x0131 }, /*                    idotless ı LATIN SMALL LETTER DOTLESS I */
            { 0x02bb, 0x011f }, /*                      gbreve ğ LATIN SMALL LETTER G WITH BREVE */
            { 0x02bc, 0x0135 }, /*                 jcircumflex ĵ LATIN SMALL LETTER J WITH CIRCUMFLEX */
            { 0x02c5, 0x010a }, /*                   Cabovedot Ċ LATIN CAPITAL LETTER C WITH DOT ABOVE */
            { 0x02c6, 0x0108 }, /*                 Ccircumflex Ĉ LATIN CAPITAL LETTER C WITH CIRCUMFLEX */
            { 0x02d5, 0x0120 }, /*                   Gabovedot Ġ LATIN CAPITAL LETTER G WITH DOT ABOVE */
            { 0x02d8, 0x011c }, /*                 Gcircumflex Ĝ LATIN CAPITAL LETTER G WITH CIRCUMFLEX */
            { 0x02dd, 0x016c }, /*                      Ubreve Ŭ LATIN CAPITAL LETTER U WITH BREVE */
            { 0x02de, 0x015c }, /*                 Scircumflex Ŝ LATIN CAPITAL LETTER S WITH CIRCUMFLEX */
            { 0x02e5, 0x010b }, /*                   cabovedot ċ LATIN SMALL LETTER C WITH DOT ABOVE */
            { 0x02e6, 0x0109 }, /*                 ccircumflex ĉ LATIN SMALL LETTER C WITH CIRCUMFLEX */
            { 0x02f5, 0x0121 }, /*                   gabovedot ġ LATIN SMALL LETTER G WITH DOT ABOVE */
            { 0x02f8, 0x011d }, /*                 gcircumflex ĝ LATIN SMALL LETTER G WITH CIRCUMFLEX */
            { 0x02fd, 0x016d }, /*                      ubreve ŭ LATIN SMALL LETTER U WITH BREVE */
            { 0x02fe, 0x015d }, /*                 scircumflex ŝ LATIN SMALL LETTER S WITH CIRCUMFLEX */
            { 0x03a2, 0x0138 }, /*                         kra ĸ LATIN SMALL LETTER KRA */
            { 0x03a3, 0x0156 }, /*                    Rcedilla Ŗ LATIN CAPITAL LETTER R WITH CEDILLA */
            { 0x03a5, 0x0128 }, /*                      Itilde Ĩ LATIN CAPITAL LETTER I WITH TILDE */
            { 0x03a6, 0x013b }, /*                    Lcedilla Ļ LATIN CAPITAL LETTER L WITH CEDILLA */
            { 0x03aa, 0x0112 }, /*                     Emacron Ē LATIN CAPITAL LETTER E WITH MACRON */
            { 0x03ab, 0x0122 }, /*                    Gcedilla Ģ LATIN CAPITAL LETTER G WITH CEDILLA */
            { 0x03ac, 0x0166 }, /*                      Tslash Ŧ LATIN CAPITAL LETTER T WITH STROKE */
            { 0x03b3, 0x0157 }, /*                    rcedilla ŗ LATIN SMALL LETTER R WITH CEDILLA */
            { 0x03b5, 0x0129 }, /*                      itilde ĩ LATIN SMALL LETTER I WITH TILDE */
            { 0x03b6, 0x013c }, /*                    lcedilla ļ LATIN SMALL LETTER L WITH CEDILLA */
            { 0x03ba, 0x0113 }, /*                     emacron ē LATIN SMALL LETTER E WITH MACRON */
            { 0x03bb, 0x0123 }, /*                    gcedilla ģ LATIN SMALL LETTER G WITH CEDILLA */
            { 0x03bc, 0x0167 }, /*                      tslash ŧ LATIN SMALL LETTER T WITH STROKE */
            { 0x03bd, 0x014a }, /*                         ENG Ŋ LATIN CAPITAL LETTER ENG */
            { 0x03bf, 0x014b }, /*                         eng ŋ LATIN SMALL LETTER ENG */
            { 0x03c0, 0x0100 }, /*                     Amacron Ā LATIN CAPITAL LETTER A WITH MACRON */
            { 0x03c7, 0x012e }, /*                     Iogonek Į LATIN CAPITAL LETTER I WITH OGONEK */
            { 0x03cc, 0x0116 }, /*                   Eabovedot Ė LATIN CAPITAL LETTER E WITH DOT ABOVE */
            { 0x03cf, 0x012a }, /*                     Imacron Ī LATIN CAPITAL LETTER I WITH MACRON */
            { 0x03d1, 0x0145 }, /*                    Ncedilla Ņ LATIN CAPITAL LETTER N WITH CEDILLA */
            { 0x03d2, 0x014c }, /*                     Omacron Ō LATIN CAPITAL LETTER O WITH MACRON */
            { 0x03d3, 0x0136 }, /*                    Kcedilla Ķ LATIN CAPITAL LETTER K WITH CEDILLA */
            { 0x03d9, 0x0172 }, /*                     Uogonek Ų LATIN CAPITAL LETTER U WITH OGONEK */
            { 0x03dd, 0x0168 }, /*                      Utilde Ũ LATIN CAPITAL LETTER U WITH TILDE */
            { 0x03de, 0x016a }, /*                     Umacron Ū LATIN CAPITAL LETTER U WITH MACRON */
            { 0x03e0, 0x0101 }, /*                     amacron ā LATIN SMALL LETTER A WITH MACRON */
            { 0x03e7, 0x012f }, /*                     iogonek į LATIN SMALL LETTER I WITH OGONEK */
            { 0x03ec, 0x0117 }, /*                   eabovedot ė LATIN SMALL LETTER E WITH DOT ABOVE */
            { 0x03ef, 0x012b }, /*                     imacron ī LATIN SMALL LETTER I WITH MACRON */
            { 0x03f1, 0x0146 }, /*                    ncedilla ņ LATIN SMALL LETTER N WITH CEDILLA */
            { 0x03f2, 0x014d }, /*                     omacron ō LATIN SMALL LETTER O WITH MACRON */
            { 0x03f3, 0x0137 }, /*                    kcedilla ķ LATIN SMALL LETTER K WITH CEDILLA */
            { 0x03f9, 0x0173 }, /*                     uogonek ų LATIN SMALL LETTER U WITH OGONEK */
            { 0x03fd, 0x0169 }, /*                      utilde ũ LATIN SMALL LETTER U WITH TILDE */
            { 0x03fe, 0x016b }, /*                     umacron ū LATIN SMALL LETTER U WITH MACRON */
            { 0x047e, 0x203e }, /*                    overline ‾ OVERLINE */
            { 0x04a1, 0x3002 }, /*               kana_fullstop 。 IDEOGRAPHIC FULL STOP */
            { 0x04a2, 0x300c }, /*         kana_openingbracket 「 LEFT CORNER BRACKET */
            { 0x04a3, 0x300d }, /*         kana_closingbracket 」 RIGHT CORNER BRACKET */
            { 0x04a4, 0x3001 }, /*                  kana_comma 、 IDEOGRAPHIC COMMA */
            { 0x04a5, 0x30fb }, /*            kana_conjunctive ・ KATAKANA MIDDLE DOT */
            { 0x04a6, 0x30f2 }, /*                     kana_WO ヲ KATAKANA LETTER WO */
            { 0x04a7, 0x30a1 }, /*                      kana_a ァ KATAKANA LETTER SMALL A */
            { 0x04a8, 0x30a3 }, /*                      kana_i ィ KATAKANA LETTER SMALL I */
            { 0x04a9, 0x30a5 }, /*                      kana_u ゥ KATAKANA LETTER SMALL U */
            { 0x04aa, 0x30a7 }, /*                      kana_e ェ KATAKANA LETTER SMALL E */
            { 0x04ab, 0x30a9 }, /*                      kana_o ォ KATAKANA LETTER SMALL O */
            { 0x04ac, 0x30e3 }, /*                     kana_ya ャ KATAKANA LETTER SMALL YA */
            { 0x04ad, 0x30e5 }, /*                     kana_yu ュ KATAKANA LETTER SMALL YU */
            { 0x04ae, 0x30e7 }, /*                     kana_yo ョ KATAKANA LETTER SMALL YO */
            { 0x04af, 0x30c3 }, /*                    kana_tsu ッ KATAKANA LETTER SMALL TU */
            { 0x04b0, 0x30fc }, /*              prolongedsound ー KATAKANA-HIRAGANA PROLONGED SOUND MARK */
            { 0x04b1, 0x30a2 }, /*                      kana_A ア KATAKANA LETTER A */
            { 0x04b2, 0x30a4 }, /*                      kana_I イ KATAKANA LETTER I */
            { 0x04b3, 0x30a6 }, /*                      kana_U ウ KATAKANA LETTER U */
            { 0x04b4, 0x30a8 }, /*                      kana_E エ KATAKANA LETTER E */
            { 0x04b5, 0x30aa }, /*                      kana_O オ KATAKANA LETTER O */
            { 0x04b6, 0x30ab }, /*                     kana_KA カ KATAKANA LETTER KA */
            { 0x04b7, 0x30ad }, /*                     kana_KI キ KATAKANA LETTER KI */
            { 0x04b8, 0x30af }, /*                     kana_KU ク KATAKANA LETTER KU */
            { 0x04b9, 0x30b1 }, /*                     kana_KE ケ KATAKANA LETTER KE */
            { 0x04ba, 0x30b3 }, /*                     kana_KO コ KATAKANA LETTER KO */
            { 0x04bb, 0x30b5 }, /*                     kana_SA サ KATAKANA LETTER SA */
            { 0x04bc, 0x30b7 }, /*                    kana_SHI シ KATAKANA LETTER SI */
            { 0x04bd, 0x30b9 }, /*                     kana_SU ス KATAKANA LETTER SU */
            { 0x04be, 0x30bb }, /*                     kana_SE セ KATAKANA LETTER SE */
            { 0x04bf, 0x30bd }, /*                     kana_SO ソ KATAKANA LETTER SO */
            { 0x04c0, 0x30bf }, /*                     kana_TA タ KATAKANA LETTER TA */
            { 0x04c1, 0x30c1 }, /*                    kana_CHI チ KATAKANA LETTER TI */
            { 0x04c2, 0x30c4 }, /*                    kana_TSU ツ KATAKANA LETTER TU */
            { 0x04c3, 0x30c6 }, /*                     kana_TE テ KATAKANA LETTER TE */
            { 0x04c4, 0x30c8 }, /*                     kana_TO ト KATAKANA LETTER TO */
            { 0x04c5, 0x30ca }, /*                     kana_NA ナ KATAKANA LETTER NA */
            { 0x04c6, 0x30cb }, /*                     kana_NI ニ KATAKANA LETTER NI */
            { 0x04c7, 0x30cc }, /*                     kana_NU ヌ KATAKANA LETTER NU */
            { 0x04c8, 0x30cd }, /*                     kana_NE ネ KATAKANA LETTER NE */
            { 0x04c9, 0x30ce }, /*                     kana_NO ノ KATAKANA LETTER NO */
            { 0x04ca, 0x30cf }, /*                     kana_HA ハ KATAKANA LETTER HA */
            { 0x04cb, 0x30d2 }, /*                     kana_HI ヒ KATAKANA LETTER HI */
            { 0x04cc, 0x30d5 }, /*                     kana_FU フ KATAKANA LETTER HU */
            { 0x04cd, 0x30d8 }, /*                     kana_HE ヘ KATAKANA LETTER HE */
            { 0x04ce, 0x30db }, /*                     kana_HO ホ KATAKANA LETTER HO */
            { 0x04cf, 0x30de }, /*                     kana_MA マ KATAKANA LETTER MA */
            { 0x04d0, 0x30df }, /*                     kana_MI ミ KATAKANA LETTER MI */
            { 0x04d1, 0x30e0 }, /*                     kana_MU ム KATAKANA LETTER MU */
            { 0x04d2, 0x30e1 }, /*                     kana_ME メ KATAKANA LETTER ME */
            { 0x04d3, 0x30e2 }, /*                     kana_MO モ KATAKANA LETTER MO */
            { 0x04d4, 0x30e4 }, /*                     kana_YA ヤ KATAKANA LETTER YA */
            { 0x04d5, 0x30e6 }, /*                     kana_YU ユ KATAKANA LETTER YU */
            { 0x04d6, 0x30e8 }, /*                     kana_YO ヨ KATAKANA LETTER YO */
            { 0x04d7, 0x30e9 }, /*                     kana_RA ラ KATAKANA LETTER RA */
            { 0x04d8, 0x30ea }, /*                     kana_RI リ KATAKANA LETTER RI */
            { 0x04d9, 0x30eb }, /*                     kana_RU ル KATAKANA LETTER RU */
            { 0x04da, 0x30ec }, /*                     kana_RE レ KATAKANA LETTER RE */
            { 0x04db, 0x30ed }, /*                     kana_RO ロ KATAKANA LETTER RO */
            { 0x04dc, 0x30ef }, /*                     kana_WA ワ KATAKANA LETTER WA */
            { 0x04dd, 0x30f3 }, /*                      kana_N ン KATAKANA LETTER N */
            { 0x04de, 0x309b }, /*                 voicedsound ゛ KATAKANA-HIRAGANA VOICED SOUND MARK */
            { 0x04df, 0x309c }, /*             semivoicedsound ゜ KATAKANA-HIRAGANA SEMI-VOICED SOUND MARK */
            { 0x05ac, 0x060c }, /*                Arabic_comma ، ARABIC COMMA */
            { 0x05bb, 0x061b }, /*            Arabic_semicolon ؛ ARABIC SEMICOLON */
            { 0x05bf, 0x061f }, /*        Arabic_question_mark ؟ ARABIC QUESTION MARK */
            { 0x05c1, 0x0621 }, /*                Arabic_hamza ء ARABIC LETTER HAMZA */
            { 0x05c2, 0x0622 }, /*          Arabic_maddaonalef آ ARABIC LETTER ALEF WITH MADDA ABOVE */
            { 0x05c3, 0x0623 }, /*          Arabic_hamzaonalef أ ARABIC LETTER ALEF WITH HAMZA ABOVE */
            { 0x05c4, 0x0624 }, /*           Arabic_hamzaonwaw ؤ ARABIC LETTER WAW WITH HAMZA ABOVE */
            { 0x05c5, 0x0625 }, /*       Arabic_hamzaunderalef إ ARABIC LETTER ALEF WITH HAMZA BELOW */
            { 0x05c6, 0x0626 }, /*           Arabic_hamzaonyeh ئ ARABIC LETTER YEH WITH HAMZA ABOVE */
            { 0x05c7, 0x0627 }, /*                 Arabic_alef ا ARABIC LETTER ALEF */
            { 0x05c8, 0x0628 }, /*                  Arabic_beh ب ARABIC LETTER BEH */
            { 0x05c9, 0x0629 }, /*           Arabic_tehmarbuta ة ARABIC LETTER TEH MARBUTA */
            { 0x05ca, 0x062a }, /*                  Arabic_teh ت ARABIC LETTER TEH */
            { 0x05cb, 0x062b }, /*                 Arabic_theh ث ARABIC LETTER THEH */
            { 0x05cc, 0x062c }, /*                 Arabic_jeem ج ARABIC LETTER JEEM */
            { 0x05cd, 0x062d }, /*                  Arabic_hah ح ARABIC LETTER HAH */
            { 0x05ce, 0x062e }, /*                 Arabic_khah خ ARABIC LETTER KHAH */
            { 0x05cf, 0x062f }, /*                  Arabic_dal د ARABIC LETTER DAL */
            { 0x05d0, 0x0630 }, /*                 Arabic_thal ذ ARABIC LETTER THAL */
            { 0x05d1, 0x0631 }, /*                   Arabic_ra ر ARABIC LETTER REH */
            { 0x05d2, 0x0632 }, /*                 Arabic_zain ز ARABIC LETTER ZAIN */
            { 0x05d3, 0x0633 }, /*                 Arabic_seen س ARABIC LETTER SEEN */
            { 0x05d4, 0x0634 }, /*                Arabic_sheen ش ARABIC LETTER SHEEN */
            { 0x05d5, 0x0635 }, /*                  Arabic_sad ص ARABIC LETTER SAD */
            { 0x05d6, 0x0636 }, /*                  Arabic_dad ض ARABIC LETTER DAD */
            { 0x05d7, 0x0637 }, /*                  Arabic_tah ط ARABIC LETTER TAH */
            { 0x05d8, 0x0638 }, /*                  Arabic_zah ظ ARABIC LETTER ZAH */
            { 0x05d9, 0x0639 }, /*                  Arabic_ain ع ARABIC LETTER AIN */
            { 0x05da, 0x063a }, /*                Arabic_ghain غ ARABIC LETTER GHAIN */
            { 0x05e0, 0x0640 }, /*              Arabic_tatweel ـ ARABIC TATWEEL */
            { 0x05e1, 0x0641 }, /*                  Arabic_feh ف ARABIC LETTER FEH */
            { 0x05e2, 0x0642 }, /*                  Arabic_qaf ق ARABIC LETTER QAF */
            { 0x05e3, 0x0643 }, /*                  Arabic_kaf ك ARABIC LETTER KAF */
            { 0x05e4, 0x0644 }, /*                  Arabic_lam ل ARABIC LETTER LAM */
            { 0x05e5, 0x0645 }, /*                 Arabic_meem م ARABIC LETTER MEEM */
            { 0x05e6, 0x0646 }, /*                 Arabic_noon ن ARABIC LETTER NOON */
            { 0x05e7, 0x0647 }, /*                   Arabic_ha ه ARABIC LETTER HEH */
            { 0x05e8, 0x0648 }, /*                  Arabic_waw و ARABIC LETTER WAW */
            { 0x05e9, 0x0649 }, /*          Arabic_alefmaksura ى ARABIC LETTER ALEF MAKSURA */
            { 0x05ea, 0x064a }, /*                  Arabic_yeh ي ARABIC LETTER YEH */
            { 0x05eb, 0x064b }, /*             Arabic_fathatan ً ARABIC FATHATAN */
            { 0x05ec, 0x064c }, /*             Arabic_dammatan ٌ ARABIC DAMMATAN */
            { 0x05ed, 0x064d }, /*             Arabic_kasratan ٍ ARABIC KASRATAN */
            { 0x05ee, 0x064e }, /*                Arabic_fatha َ ARABIC FATHA */
            { 0x05ef, 0x064f }, /*                Arabic_damma ُ ARABIC DAMMA */
            { 0x05f0, 0x0650 }, /*                Arabic_kasra ِ ARABIC KASRA */
            { 0x05f1, 0x0651 }, /*               Arabic_shadda ّ ARABIC SHADDA */
            { 0x05f2, 0x0652 }, /*                Arabic_sukun ْ ARABIC SUKUN */
            { 0x06a1, 0x0452 }, /*                 Serbian_dje ђ CYRILLIC SMALL LETTER DJE */
            { 0x06a2, 0x0453 }, /*               Macedonia_gje ѓ CYRILLIC SMALL LETTER GJE */
            { 0x06a3, 0x0451 }, /*                 Cyrillic_io ё CYRILLIC SMALL LETTER IO */
            { 0x06a4, 0x0454 }, /*                Ukrainian_ie є CYRILLIC SMALL LETTER UKRAINIAN IE */
            { 0x06a5, 0x0455 }, /*               Macedonia_dse ѕ CYRILLIC SMALL LETTER DZE */
            { 0x06a6, 0x0456 }, /*                 Ukrainian_i і CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I */
            { 0x06a7, 0x0457 }, /*                Ukrainian_yi ї CYRILLIC SMALL LETTER YI */
            { 0x06a8, 0x0458 }, /*                 Cyrillic_je ј CYRILLIC SMALL LETTER JE */
            { 0x06a9, 0x0459 }, /*                Cyrillic_lje љ CYRILLIC SMALL LETTER LJE */
            { 0x06aa, 0x045a }, /*                Cyrillic_nje њ CYRILLIC SMALL LETTER NJE */
            { 0x06ab, 0x045b }, /*                Serbian_tshe ћ CYRILLIC SMALL LETTER TSHE */
            { 0x06ac, 0x045c }, /*               Macedonia_kje ќ CYRILLIC SMALL LETTER KJE */
            { 0x06ad, 0x0491 }, /*   Ukrainian_ghe_with_upturn ґ CYRILLIC SMALL LETTER GHE WITH UPTURN */
            { 0x06ae, 0x045e }, /*         Byelorussian_shortu ў CYRILLIC SMALL LETTER SHORT U */
            { 0x06af, 0x045f }, /*               Cyrillic_dzhe џ CYRILLIC SMALL LETTER DZHE */
            { 0x06b0, 0x2116 }, /*                  numerosign № NUMERO SIGN */
            { 0x06b1, 0x0402 }, /*                 Serbian_DJE Ђ CYRILLIC CAPITAL LETTER DJE */
            { 0x06b2, 0x0403 }, /*               Macedonia_GJE Ѓ CYRILLIC CAPITAL LETTER GJE */
            { 0x06b3, 0x0401 }, /*                 Cyrillic_IO Ё CYRILLIC CAPITAL LETTER IO */
            { 0x06b4, 0x0404 }, /*                Ukrainian_IE Є CYRILLIC CAPITAL LETTER UKRAINIAN IE */
            { 0x06b5, 0x0405 }, /*               Macedonia_DSE Ѕ CYRILLIC CAPITAL LETTER DZE */
            { 0x06b6, 0x0406 }, /*                 Ukrainian_I І CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I */
            { 0x06b7, 0x0407 }, /*                Ukrainian_YI Ї CYRILLIC CAPITAL LETTER YI */
            { 0x06b8, 0x0408 }, /*                 Cyrillic_JE Ј CYRILLIC CAPITAL LETTER JE */
            { 0x06b9, 0x0409 }, /*                Cyrillic_LJE Љ CYRILLIC CAPITAL LETTER LJE */
            { 0x06ba, 0x040a }, /*                Cyrillic_NJE Њ CYRILLIC CAPITAL LETTER NJE */
            { 0x06bb, 0x040b }, /*                Serbian_TSHE Ћ CYRILLIC CAPITAL LETTER TSHE */
            { 0x06bc, 0x040c }, /*               Macedonia_KJE Ќ CYRILLIC CAPITAL LETTER KJE */
            { 0x06bd, 0x0490 }, /*   Ukrainian_GHE_WITH_UPTURN Ґ CYRILLIC CAPITAL LETTER GHE WITH UPTURN */
            { 0x06be, 0x040e }, /*         Byelorussian_SHORTU Ў CYRILLIC CAPITAL LETTER SHORT U */
            { 0x06bf, 0x040f }, /*               Cyrillic_DZHE Џ CYRILLIC CAPITAL LETTER DZHE */
            { 0x06c0, 0x044e }, /*                 Cyrillic_yu ю CYRILLIC SMALL LETTER YU */
            { 0x06c1, 0x0430 }, /*                  Cyrillic_a а CYRILLIC SMALL LETTER A */
            { 0x06c2, 0x0431 }, /*                 Cyrillic_be б CYRILLIC SMALL LETTER BE */
            { 0x06c3, 0x0446 }, /*                Cyrillic_tse ц CYRILLIC SMALL LETTER TSE */
            { 0x06c4, 0x0434 }, /*                 Cyrillic_de д CYRILLIC SMALL LETTER DE */
            { 0x06c5, 0x0435 }, /*                 Cyrillic_ie е CYRILLIC SMALL LETTER IE */
            { 0x06c6, 0x0444 }, /*                 Cyrillic_ef ф CYRILLIC SMALL LETTER EF */
            { 0x06c7, 0x0433 }, /*                Cyrillic_ghe г CYRILLIC SMALL LETTER GHE */
            { 0x06c8, 0x0445 }, /*                 Cyrillic_ha х CYRILLIC SMALL LETTER HA */
            { 0x06c9, 0x0438 }, /*                  Cyrillic_i и CYRILLIC SMALL LETTER I */
            { 0x06ca, 0x0439 }, /*             Cyrillic_shorti й CYRILLIC SMALL LETTER SHORT I */
            { 0x06cb, 0x043a }, /*                 Cyrillic_ka к CYRILLIC SMALL LETTER KA */
            { 0x06cc, 0x043b }, /*                 Cyrillic_el л CYRILLIC SMALL LETTER EL */
            { 0x06cd, 0x043c }, /*                 Cyrillic_em м CYRILLIC SMALL LETTER EM */
            { 0x06ce, 0x043d }, /*                 Cyrillic_en н CYRILLIC SMALL LETTER EN */
            { 0x06cf, 0x043e }, /*                  Cyrillic_o о CYRILLIC SMALL LETTER O */
            { 0x06d0, 0x043f }, /*                 Cyrillic_pe п CYRILLIC SMALL LETTER PE */
            { 0x06d1, 0x044f }, /*                 Cyrillic_ya я CYRILLIC SMALL LETTER YA */
            { 0x06d2, 0x0440 }, /*                 Cyrillic_er р CYRILLIC SMALL LETTER ER */
            { 0x06d3, 0x0441 }, /*                 Cyrillic_es с CYRILLIC SMALL LETTER ES */
            { 0x06d4, 0x0442 }, /*                 Cyrillic_te т CYRILLIC SMALL LETTER TE */
            { 0x06d5, 0x0443 }, /*                  Cyrillic_u у CYRILLIC SMALL LETTER U */
            { 0x06d6, 0x0436 }, /*                Cyrillic_zhe ж CYRILLIC SMALL LETTER ZHE */
            { 0x06d7, 0x0432 }, /*                 Cyrillic_ve в CYRILLIC SMALL LETTER VE */
            { 0x06d8, 0x044c }, /*           Cyrillic_softsign ь CYRILLIC SMALL LETTER SOFT SIGN */
            { 0x06d9, 0x044b }, /*               Cyrillic_yeru ы CYRILLIC SMALL LETTER YERU */
            { 0x06da, 0x0437 }, /*                 Cyrillic_ze з CYRILLIC SMALL LETTER ZE */
            { 0x06db, 0x0448 }, /*                Cyrillic_sha ш CYRILLIC SMALL LETTER SHA */
            { 0x06dc, 0x044d }, /*                  Cyrillic_e э CYRILLIC SMALL LETTER E */
            { 0x06dd, 0x0449 }, /*              Cyrillic_shcha щ CYRILLIC SMALL LETTER SHCHA */
            { 0x06de, 0x0447 }, /*                Cyrillic_che ч CYRILLIC SMALL LETTER CHE */
            { 0x06df, 0x044a }, /*           Cyrillic_hardsign ъ CYRILLIC SMALL LETTER HARD SIGN */
            { 0x06e0, 0x042e }, /*                 Cyrillic_YU Ю CYRILLIC CAPITAL LETTER YU */
            { 0x06e1, 0x0410 }, /*                  Cyrillic_A А CYRILLIC CAPITAL LETTER A */
            { 0x06e2, 0x0411 }, /*                 Cyrillic_BE Б CYRILLIC CAPITAL LETTER BE */
            { 0x06e3, 0x0426 }, /*                Cyrillic_TSE Ц CYRILLIC CAPITAL LETTER TSE */
            { 0x06e4, 0x0414 }, /*                 Cyrillic_DE Д CYRILLIC CAPITAL LETTER DE */
            { 0x06e5, 0x0415 }, /*                 Cyrillic_IE Е CYRILLIC CAPITAL LETTER IE */
            { 0x06e6, 0x0424 }, /*                 Cyrillic_EF Ф CYRILLIC CAPITAL LETTER EF */
            { 0x06e7, 0x0413 }, /*                Cyrillic_GHE Г CYRILLIC CAPITAL LETTER GHE */
            { 0x06e8, 0x0425 }, /*                 Cyrillic_HA Х CYRILLIC CAPITAL LETTER HA */
            { 0x06e9, 0x0418 }, /*                  Cyrillic_I И CYRILLIC CAPITAL LETTER I */
            { 0x06ea, 0x0419 }, /*             Cyrillic_SHORTI Й CYRILLIC CAPITAL LETTER SHORT I */
            { 0x06eb, 0x041a }, /*                 Cyrillic_KA К CYRILLIC CAPITAL LETTER KA */
            { 0x06ec, 0x041b }, /*                 Cyrillic_EL Л CYRILLIC CAPITAL LETTER EL */
            { 0x06ed, 0x041c }, /*                 Cyrillic_EM М CYRILLIC CAPITAL LETTER EM */
            { 0x06ee, 0x041d }, /*                 Cyrillic_EN Н CYRILLIC CAPITAL LETTER EN */
            { 0x06ef, 0x041e }, /*                  Cyrillic_O О CYRILLIC CAPITAL LETTER O */
            { 0x06f0, 0x041f }, /*                 Cyrillic_PE П CYRILLIC CAPITAL LETTER PE */
            { 0x06f1, 0x042f }, /*                 Cyrillic_YA Я CYRILLIC CAPITAL LETTER YA */
            { 0x06f2, 0x0420 }, /*                 Cyrillic_ER Р CYRILLIC CAPITAL LETTER ER */
            { 0x06f3, 0x0421 }, /*                 Cyrillic_ES С CYRILLIC CAPITAL LETTER ES */
            { 0x06f4, 0x0422 }, /*                 Cyrillic_TE Т CYRILLIC CAPITAL LETTER TE */
            { 0x06f5, 0x0423 }, /*                  Cyrillic_U У CYRILLIC CAPITAL LETTER U */
            { 0x06f6, 0x0416 }, /*                Cyrillic_ZHE Ж CYRILLIC CAPITAL LETTER ZHE */
            { 0x06f7, 0x0412 }, /*                 Cyrillic_VE В CYRILLIC CAPITAL LETTER VE */
            { 0x06f8, 0x042c }, /*           Cyrillic_SOFTSIGN Ь CYRILLIC CAPITAL LETTER SOFT SIGN */
            { 0x06f9, 0x042b }, /*               Cyrillic_YERU Ы CYRILLIC CAPITAL LETTER YERU */
            { 0x06fa, 0x0417 }, /*                 Cyrillic_ZE З CYRILLIC CAPITAL LETTER ZE */
            { 0x06fb, 0x0428 }, /*                Cyrillic_SHA Ш CYRILLIC CAPITAL LETTER SHA */
            { 0x06fc, 0x042d }, /*                  Cyrillic_E Э CYRILLIC CAPITAL LETTER E */
            { 0x06fd, 0x0429 }, /*              Cyrillic_SHCHA Щ CYRILLIC CAPITAL LETTER SHCHA */
            { 0x06fe, 0x0427 }, /*                Cyrillic_CHE Ч CYRILLIC CAPITAL LETTER CHE */
            { 0x06ff, 0x042a }, /*           Cyrillic_HARDSIGN Ъ CYRILLIC CAPITAL LETTER HARD SIGN */
            { 0x07a1, 0x0386 }, /*           Greek_ALPHAaccent Ά GREEK CAPITAL LETTER ALPHA WITH TONOS */
            { 0x07a2, 0x0388 }, /*         Greek_EPSILONaccent Έ GREEK CAPITAL LETTER EPSILON WITH TONOS */
            { 0x07a3, 0x0389 }, /*             Greek_ETAaccent Ή GREEK CAPITAL LETTER ETA WITH TONOS */
            { 0x07a4, 0x038a }, /*            Greek_IOTAaccent Ί GREEK CAPITAL LETTER IOTA WITH TONOS */
            { 0x07a5, 0x03aa }, /*         Greek_IOTAdiaeresis Ϊ GREEK CAPITAL LETTER IOTA WITH DIALYTIKA */
            { 0x07a7, 0x038c }, /*         Greek_OMICRONaccent Ό GREEK CAPITAL LETTER OMICRON WITH TONOS */
            { 0x07a8, 0x038e }, /*         Greek_UPSILONaccent Ύ GREEK CAPITAL LETTER UPSILON WITH TONOS */
            { 0x07a9, 0x03ab }, /*       Greek_UPSILONdieresis Ϋ GREEK CAPITAL LETTER UPSILON WITH DIALYTIKA */
            { 0x07ab, 0x038f }, /*           Greek_OMEGAaccent Ώ GREEK CAPITAL LETTER OMEGA WITH TONOS */
            { 0x07ae, 0x0385 }, /*        Greek_accentdieresis ΅ GREEK DIALYTIKA TONOS */
            { 0x07af, 0x2015 }, /*              Greek_horizbar ― HORIZONTAL BAR */
            { 0x07b1, 0x03ac }, /*           Greek_alphaaccent ά GREEK SMALL LETTER ALPHA WITH TONOS */
            { 0x07b2, 0x03ad }, /*         Greek_epsilonaccent έ GREEK SMALL LETTER EPSILON WITH TONOS */
            { 0x07b3, 0x03ae }, /*             Greek_etaaccent ή GREEK SMALL LETTER ETA WITH TONOS */
            { 0x07b4, 0x03af }, /*            Greek_iotaaccent ί GREEK SMALL LETTER IOTA WITH TONOS */
            { 0x07b5, 0x03ca }, /*          Greek_iotadieresis ϊ GREEK SMALL LETTER IOTA WITH DIALYTIKA */
            { 0x07b6, 0x0390 }, /*    Greek_iotaaccentdieresis ΐ GREEK SMALL LETTER IOTA WITH DIALYTIKA AND TONOS */
            { 0x07b7, 0x03cc }, /*         Greek_omicronaccent ό GREEK SMALL LETTER OMICRON WITH TONOS */
            { 0x07b8, 0x03cd }, /*         Greek_upsilonaccent ύ GREEK SMALL LETTER UPSILON WITH TONOS */
            { 0x07b9, 0x03cb }, /*       Greek_upsilondieresis ϋ GREEK SMALL LETTER UPSILON WITH DIALYTIKA */
            { 0x07ba, 0x03b0 }, /* Greek_upsilonaccentdieresis ΰ GREEK SMALL LETTER UPSILON WITH DIALYTIKA AND TONOS */
            { 0x07bb, 0x03ce }, /*           Greek_omegaaccent ώ GREEK SMALL LETTER OMEGA WITH TONOS */
            { 0x07c1, 0x0391 }, /*                 Greek_ALPHA Α GREEK CAPITAL LETTER ALPHA */
            { 0x07c2, 0x0392 }, /*                  Greek_BETA Β GREEK CAPITAL LETTER BETA */
            { 0x07c3, 0x0393 }, /*                 Greek_GAMMA Γ GREEK CAPITAL LETTER GAMMA */
            { 0x07c4, 0x0394 }, /*                 Greek_DELTA Δ GREEK CAPITAL LETTER DELTA */
            { 0x07c5, 0x0395 }, /*               Greek_EPSILON Ε GREEK CAPITAL LETTER EPSILON */
            { 0x07c6, 0x0396 }, /*                  Greek_ZETA Ζ GREEK CAPITAL LETTER ZETA */
            { 0x07c7, 0x0397 }, /*                   Greek_ETA Η GREEK CAPITAL LETTER ETA */
            { 0x07c8, 0x0398 }, /*                 Greek_THETA Θ GREEK CAPITAL LETTER THETA */
            { 0x07c9, 0x0399 }, /*                  Greek_IOTA Ι GREEK CAPITAL LETTER IOTA */
            { 0x07ca, 0x039a }, /*                 Greek_KAPPA Κ GREEK CAPITAL LETTER KAPPA */
            { 0x07cb, 0x039b }, /*                Greek_LAMBDA Λ GREEK CAPITAL LETTER LAMDA */
            { 0x07cc, 0x039c }, /*                    Greek_MU Μ GREEK CAPITAL LETTER MU */
            { 0x07cd, 0x039d }, /*                    Greek_NU Ν GREEK CAPITAL LETTER NU */
            { 0x07ce, 0x039e }, /*                    Greek_XI Ξ GREEK CAPITAL LETTER XI */
            { 0x07cf, 0x039f }, /*               Greek_OMICRON Ο GREEK CAPITAL LETTER OMICRON */
            { 0x07d0, 0x03a0 }, /*                    Greek_PI Π GREEK CAPITAL LETTER PI */
            { 0x07d1, 0x03a1 }, /*                   Greek_RHO Ρ GREEK CAPITAL LETTER RHO */
            { 0x07d2, 0x03a3 }, /*                 Greek_SIGMA Σ GREEK CAPITAL LETTER SIGMA */
            { 0x07d4, 0x03a4 }, /*                   Greek_TAU Τ GREEK CAPITAL LETTER TAU */
            { 0x07d5, 0x03a5 }, /*               Greek_UPSILON Υ GREEK CAPITAL LETTER UPSILON */
            { 0x07d6, 0x03a6 }, /*                   Greek_PHI Φ GREEK CAPITAL LETTER PHI */
            { 0x07d7, 0x03a7 }, /*                   Greek_CHI Χ GREEK CAPITAL LETTER CHI */
            { 0x07d8, 0x03a8 }, /*                   Greek_PSI Ψ GREEK CAPITAL LETTER PSI */
            { 0x07d9, 0x03a9 }, /*                 Greek_OMEGA Ω GREEK CAPITAL LETTER OMEGA */
            { 0x07e1, 0x03b1 }, /*                 Greek_alpha α GREEK SMALL LETTER ALPHA */
            { 0x07e2, 0x03b2 }, /*                  Greek_beta β GREEK SMALL LETTER BETA */
            { 0x07e3, 0x03b3 }, /*                 Greek_gamma γ GREEK SMALL LETTER GAMMA */
            { 0x07e4, 0x03b4 }, /*                 Greek_delta δ GREEK SMALL LETTER DELTA */
            { 0x07e5, 0x03b5 }, /*               Greek_epsilon ε GREEK SMALL LETTER EPSILON */
            { 0x07e6, 0x03b6 }, /*                  Greek_zeta ζ GREEK SMALL LETTER ZETA */
            { 0x07e7, 0x03b7 }, /*                   Greek_eta η GREEK SMALL LETTER ETA */
            { 0x07e8, 0x03b8 }, /*                 Greek_theta θ GREEK SMALL LETTER THETA */
            { 0x07e9, 0x03b9 }, /*                  Greek_iota ι GREEK SMALL LETTER IOTA */
            { 0x07ea, 0x03ba }, /*                 Greek_kappa κ GREEK SMALL LETTER KAPPA */
            { 0x07eb, 0x03bb }, /*                Greek_lambda λ GREEK SMALL LETTER LAMDA */
            { 0x07ec, 0x03bc }, /*                    Greek_mu μ GREEK SMALL LETTER MU */
            { 0x07ed, 0x03bd }, /*                    Greek_nu ν GREEK SMALL LETTER NU */
            { 0x07ee, 0x03be }, /*                    Greek_xi ξ GREEK SMALL LETTER XI */
            { 0x07ef, 0x03bf }, /*               Greek_omicron ο GREEK SMALL LETTER OMICRON */
            { 0x07f0, 0x03c0 }, /*                    Greek_pi π GREEK SMALL LETTER PI */
            { 0x07f1, 0x03c1 }, /*                   Greek_rho ρ GREEK SMALL LETTER RHO */
            { 0x07f2, 0x03c3 }, /*                 Greek_sigma σ GREEK SMALL LETTER SIGMA */
            { 0x07f3, 0x03c2 }, /*       Greek_finalsmallsigma ς GREEK SMALL LETTER FINAL SIGMA */
            { 0x07f4, 0x03c4 }, /*                   Greek_tau τ GREEK SMALL LETTER TAU */
            { 0x07f5, 0x03c5 }, /*               Greek_upsilon υ GREEK SMALL LETTER UPSILON */
            { 0x07f6, 0x03c6 }, /*                   Greek_phi φ GREEK SMALL LETTER PHI */
            { 0x07f7, 0x03c7 }, /*                   Greek_chi χ GREEK SMALL LETTER CHI */
            { 0x07f8, 0x03c8 }, /*                   Greek_psi ψ GREEK SMALL LETTER PSI */
            { 0x07f9, 0x03c9 }, /*                 Greek_omega ω GREEK SMALL LETTER OMEGA */
            { 0x08a1, 0x23b7 }, /*                 leftradical ⎷ ??? */
            { 0x08a2, 0x250c }, /*              topleftradical ┌ BOX DRAWINGS LIGHT DOWN AND RIGHT */
            { 0x08a3, 0x2500 }, /*              horizconnector ─ BOX DRAWINGS LIGHT HORIZONTAL */
            { 0x08a4, 0x2320 }, /*                 topintegral ⌠ TOP HALF INTEGRAL */
            { 0x08a5, 0x2321 }, /*                 botintegral ⌡ BOTTOM HALF INTEGRAL */
            { 0x08a6, 0x2502 }, /*               vertconnector │ BOX DRAWINGS LIGHT VERTICAL */
            { 0x08a7, 0x23a1 }, /*            topleftsqbracket ⎡ ??? */
            { 0x08a8, 0x23a3 }, /*            botleftsqbracket ⎣ ??? */
            { 0x08a9, 0x23a4 }, /*           toprightsqbracket ⎤ ??? */
            { 0x08aa, 0x23a6 }, /*           botrightsqbracket ⎦ ??? */
            { 0x08ab, 0x239b }, /*               topleftparens ⎛ ??? */
            { 0x08ac, 0x239d }, /*               botleftparens ⎝ ??? */
            { 0x08ad, 0x239e }, /*              toprightparens ⎞ ??? */
            { 0x08ae, 0x23a0 }, /*              botrightparens ⎠ ??? */
            { 0x08af, 0x23a8 }, /*        leftmiddlecurlybrace ⎨ ??? */
            { 0x08b0, 0x23ac }, /*       rightmiddlecurlybrace ⎬ ??? */
            /*  0x08b1                        topleftsummation ? ??? */
            /*  0x08b2                        botleftsummation ? ??? */
            /*  0x08b3               topvertsummationconnector ? ??? */
            /*  0x08b4               botvertsummationconnector ? ??? */
            /*  0x08b5                       toprightsummation ? ??? */
            /*  0x08b6                       botrightsummation ? ??? */
            /*  0x08b7                    rightmiddlesummation ? ??? */
            { 0x08bc, 0x2264 }, /*               lessthanequal ≤ LESS-THAN OR EQUAL TO */
            { 0x08bd, 0x2260 }, /*                    notequal ≠ NOT EQUAL TO */
            { 0x08be, 0x2265 }, /*            greaterthanequal ≥ GREATER-THAN OR EQUAL TO */
            { 0x08bf, 0x222b }, /*                    integral ∫ INTEGRAL */
            { 0x08c0, 0x2234 }, /*                   therefore ∴ THEREFORE */
            { 0x08c1, 0x221d }, /*                   variation ∝ PROPORTIONAL TO */
            { 0x08c2, 0x221e }, /*                    infinity ∞ INFINITY */
            { 0x08c5, 0x2207 }, /*                       nabla ∇ NABLA */
            { 0x08c8, 0x223c }, /*                 approximate ∼ TILDE OPERATOR */
            { 0x08c9, 0x2243 }, /*                similarequal ≃ ASYMPTOTICALLY EQUAL TO */
            { 0x08cd, 0x21d4 }, /*                    ifonlyif ⇔ LEFT RIGHT DOUBLE ARROW */
            { 0x08ce, 0x21d2 }, /*                     implies ⇒ RIGHTWARDS DOUBLE ARROW */
            { 0x08cf, 0x2261 }, /*                   identical ≡ IDENTICAL TO */
            { 0x08d6, 0x221a }, /*                     radical √ SQUARE ROOT */
            { 0x08da, 0x2282 }, /*                  includedin ⊂ SUBSET OF */
            { 0x08db, 0x2283 }, /*                    includes ⊃ SUPERSET OF */
            { 0x08dc, 0x2229 }, /*                intersection ∩ INTERSECTION */
            { 0x08dd, 0x222a }, /*                       union ∪ UNION */
            { 0x08de, 0x2227 }, /*                  logicaland ∧ LOGICAL AND */
            { 0x08df, 0x2228 }, /*                   logicalor ∨ LOGICAL OR */
            { 0x08ef, 0x2202 }, /*           partialderivative ∂ PARTIAL DIFFERENTIAL */
            { 0x08f6, 0x0192 }, /*                    function ƒ LATIN SMALL LETTER F WITH HOOK */
            { 0x08fb, 0x2190 }, /*                   leftarrow ← LEFTWARDS ARROW */
            { 0x08fc, 0x2191 }, /*                     uparrow ↑ UPWARDS ARROW */
            { 0x08fd, 0x2192 }, /*                  rightarrow → RIGHTWARDS ARROW */
            { 0x08fe, 0x2193 }, /*                   downarrow ↓ DOWNWARDS ARROW */
        /*  0x09df                                     blank ? ??? */
            { 0x09e0, 0x25c6 }, /*                soliddiamond ◆ BLACK DIAMOND */
            { 0x09e1, 0x2592 }, /*                checkerboard ▒ MEDIUM SHADE */
            { 0x09e2, 0x2409 }, /*                          ht ␉ SYMBOL FOR HORIZONTAL TABULATION */
            { 0x09e3, 0x240c }, /*                          ff ␌ SYMBOL FOR FORM FEED */
            { 0x09e4, 0x240d }, /*                          cr ␍ SYMBOL FOR CARRIAGE RETURN */
            { 0x09e5, 0x240a }, /*                          lf ␊ SYMBOL FOR LINE FEED */
            { 0x09e8, 0x2424 }, /*                          nl ␤ SYMBOL FOR NEWLINE */
            { 0x09e9, 0x240b }, /*                          vt ␋ SYMBOL FOR VERTICAL TABULATION */
            { 0x09ea, 0x2518 }, /*              lowrightcorner ┘ BOX DRAWINGS LIGHT UP AND LEFT */
            { 0x09eb, 0x2510 }, /*               uprightcorner ┐ BOX DRAWINGS LIGHT DOWN AND LEFT */
            { 0x09ec, 0x250c }, /*                upleftcorner ┌ BOX DRAWINGS LIGHT DOWN AND RIGHT */
            { 0x09ed, 0x2514 }, /*               lowleftcorner └ BOX DRAWINGS LIGHT UP AND RIGHT */
            { 0x09ee, 0x253c }, /*               crossinglines ┼ BOX DRAWINGS LIGHT VERTICAL AND HORIZONTAL */
            { 0x09ef, 0x23ba }, /*              horizlinescan1 ⎺ HORIZONTAL SCAN LINE-1 (Unicode 3.2 draft) */
            { 0x09f0, 0x23bb }, /*              horizlinescan3 ⎻ HORIZONTAL SCAN LINE-3 (Unicode 3.2 draft) */
            { 0x09f1, 0x2500 }, /*              horizlinescan5 ─ BOX DRAWINGS LIGHT HORIZONTAL */
            { 0x09f2, 0x23bc }, /*              horizlinescan7 ⎼ HORIZONTAL SCAN LINE-7 (Unicode 3.2 draft) */
            { 0x09f3, 0x23bd }, /*              horizlinescan9 ⎽ HORIZONTAL SCAN LINE-9 (Unicode 3.2 draft) */
            { 0x09f4, 0x251c }, /*                       leftt ├ BOX DRAWINGS LIGHT VERTICAL AND RIGHT */
            { 0x09f5, 0x2524 }, /*                      rightt ┤ BOX DRAWINGS LIGHT VERTICAL AND LEFT */
            { 0x09f6, 0x2534 }, /*                        bott ┴ BOX DRAWINGS LIGHT UP AND HORIZONTAL */
            { 0x09f7, 0x252c }, /*                        topt ┬ BOX DRAWINGS LIGHT DOWN AND HORIZONTAL */
            { 0x09f8, 0x2502 }, /*                     vertbar │ BOX DRAWINGS LIGHT VERTICAL */
            { 0x0aa1, 0x2003 }, /*                     emspace   EM SPACE */
            { 0x0aa2, 0x2002 }, /*                     enspace   EN SPACE */
            { 0x0aa3, 0x2004 }, /*                    em3space   THREE-PER-EM SPACE */
            { 0x0aa4, 0x2005 }, /*                    em4space   FOUR-PER-EM SPACE */
            { 0x0aa5, 0x2007 }, /*                  digitspace   FIGURE SPACE */
            { 0x0aa6, 0x2008 }, /*                  punctspace   PUNCTUATION SPACE */
            { 0x0aa7, 0x2009 }, /*                   thinspace   THIN SPACE */
            { 0x0aa8, 0x200a }, /*                   hairspace   HAIR SPACE */
            { 0x0aa9, 0x2014 }, /*                      emdash — EM DASH */
            { 0x0aaa, 0x2013 }, /*                      endash – EN DASH */
            { 0x0aac, 0x2423 }, /*                 signifblank ␣ OPEN BOX */
            { 0x0aae, 0x2026 }, /*                    ellipsis … HORIZONTAL ELLIPSIS */
            { 0x0aaf, 0x2025 }, /*             doubbaselinedot ‥ TWO DOT LEADER */
            { 0x0ab0, 0x2153 }, /*                    onethird ⅓ VULGAR FRACTION ONE THIRD */
            { 0x0ab1, 0x2154 }, /*                   twothirds ⅔ VULGAR FRACTION TWO THIRDS */
            { 0x0ab2, 0x2155 }, /*                    onefifth ⅕ VULGAR FRACTION ONE FIFTH */
            { 0x0ab3, 0x2156 }, /*                   twofifths ⅖ VULGAR FRACTION TWO FIFTHS */
            { 0x0ab4, 0x2157 }, /*                 threefifths ⅗ VULGAR FRACTION THREE FIFTHS */
            { 0x0ab5, 0x2158 }, /*                  fourfifths ⅘ VULGAR FRACTION FOUR FIFTHS */
            { 0x0ab6, 0x2159 }, /*                    onesixth ⅙ VULGAR FRACTION ONE SIXTH */
            { 0x0ab7, 0x215a }, /*                  fivesixths ⅚ VULGAR FRACTION FIVE SIXTHS */
            { 0x0ab8, 0x2105 }, /*                      careof ℅ CARE OF */
            { 0x0abb, 0x2012 }, /*                     figdash ‒ FIGURE DASH */
            { 0x0abc, 0x27e8 }, /*            leftanglebracket ⟨ MATHEMATICAL LEFT ANGLE BRACKET */
            { 0x0abd, 0x002e }, /*                decimalpoint . FULL STOP */
            { 0x0abe, 0x27e9 }, /*           rightanglebracket ⟩ MATHEMATICAL RIGHT ANGLE BRACKET */
            /*  0x0abf                                  marker ? ??? */
            { 0x0ac3, 0x215b }, /*                   oneeighth ⅛ VULGAR FRACTION ONE EIGHTH */
            { 0x0ac4, 0x215c }, /*                threeeighths ⅜ VULGAR FRACTION THREE EIGHTHS */
            { 0x0ac5, 0x215d }, /*                 fiveeighths ⅝ VULGAR FRACTION FIVE EIGHTHS */
            { 0x0ac6, 0x215e }, /*                seveneighths ⅞ VULGAR FRACTION SEVEN EIGHTHS */
            { 0x0ac9, 0x2122 }, /*                   trademark ™ TRADE MARK SIGN */
            { 0x0aca, 0x2613 }, /*               signaturemark ☓ SALTIRE */
            /*  0x0acb                       trademarkincircle ? ??? */
            { 0x0acc, 0x25c1 }, /*            leftopentriangle ◁ WHITE LEFT-POINTING TRIANGLE */
            { 0x0acd, 0x25b7 }, /*           rightopentriangle ▷ WHITE RIGHT-POINTING TRIANGLE */
            { 0x0ace, 0x25cb }, /*                emopencircle ○ WHITE CIRCLE */
            { 0x0acf, 0x25af }, /*             emopenrectangle ▯ WHITE VERTICAL RECTANGLE */
            { 0x0ad0, 0x2018 }, /*         leftsinglequotemark ‘ LEFT SINGLE QUOTATION MARK */
            { 0x0ad1, 0x2019 }, /*        rightsinglequotemark ’ RIGHT SINGLE QUOTATION MARK */
            { 0x0ad2, 0x201c }, /*         leftdoublequotemark “ LEFT DOUBLE QUOTATION MARK */
            { 0x0ad3, 0x201d }, /*        rightdoublequotemark ” RIGHT DOUBLE QUOTATION MARK */
            { 0x0ad4, 0x211e }, /*                prescription ℞ PRESCRIPTION TAKE */
            { 0x0ad5, 0x2030 }, /*                    permille ‰ PER MILLE SIGN */
            { 0x0ad6, 0x2032 }, /*                     minutes ′ PRIME */
            { 0x0ad7, 0x2033 }, /*                     seconds ″ DOUBLE PRIME */
            { 0x0ad9, 0x271d }, /*                  latincross ✝ LATIN CROSS */
            /*  0x0ada                                hexagram ? ??? */
            { 0x0adb, 0x25ac }, /*            filledrectbullet ▬ BLACK RECTANGLE */
            { 0x0adc, 0x25c0 }, /*         filledlefttribullet ◀ BLACK LEFT-POINTING TRIANGLE */
            { 0x0add, 0x25b6 }, /*        filledrighttribullet ▶ BLACK RIGHT-POINTING TRIANGLE */
            { 0x0ade, 0x25cf }, /*              emfilledcircle ● BLACK CIRCLE */
            { 0x0adf, 0x25ae }, /*                emfilledrect ▮ BLACK VERTICAL RECTANGLE */
            { 0x0ae0, 0x25e6 }, /*            enopencircbullet ◦ WHITE BULLET */
            { 0x0ae1, 0x25ab }, /*          enopensquarebullet ▫ WHITE SMALL SQUARE */
            { 0x0ae2, 0x25ad }, /*              openrectbullet ▭ WHITE RECTANGLE */
            { 0x0ae3, 0x25b3 }, /*             opentribulletup △ WHITE UP-POINTING TRIANGLE */
            { 0x0ae4, 0x25bd }, /*           opentribulletdown ▽ WHITE DOWN-POINTING TRIANGLE */
            { 0x0ae5, 0x2606 }, /*                    openstar ☆ WHITE STAR */
            { 0x0ae6, 0x2022 }, /*          enfilledcircbullet • BULLET */
            { 0x0ae7, 0x25aa }, /*            enfilledsqbullet ▪ BLACK SMALL SQUARE */
            { 0x0ae8, 0x25b2 }, /*           filledtribulletup ▲ BLACK UP-POINTING TRIANGLE */
            { 0x0ae9, 0x25bc }, /*         filledtribulletdown ▼ BLACK DOWN-POINTING TRIANGLE */
            { 0x0aea, 0x261c }, /*                 leftpointer ☜ WHITE LEFT POINTING INDEX */
            { 0x0aeb, 0x261e }, /*                rightpointer ☞ WHITE RIGHT POINTING INDEX */
            { 0x0aec, 0x2663 }, /*                        club ♣ BLACK CLUB SUIT */
            { 0x0aed, 0x2666 }, /*                     diamond ♦ BLACK DIAMOND SUIT */
            { 0x0aee, 0x2665 }, /*                       heart ♥ BLACK HEART SUIT */
            { 0x0af0, 0x2720 }, /*                maltesecross ✠ MALTESE CROSS */
            { 0x0af1, 0x2020 }, /*                      dagger † DAGGER */
            { 0x0af2, 0x2021 }, /*                doubledagger ‡ DOUBLE DAGGER */
            { 0x0af3, 0x2713 }, /*                   checkmark ✓ CHECK MARK */
            { 0x0af4, 0x2717 }, /*                 ballotcross ✗ BALLOT X */
            { 0x0af5, 0x266f }, /*                musicalsharp ♯ MUSIC SHARP SIGN */
            { 0x0af6, 0x266d }, /*                 musicalflat ♭ MUSIC FLAT SIGN */
            { 0x0af7, 0x2642 }, /*                  malesymbol ♂ MALE SIGN */
            { 0x0af8, 0x2640 }, /*                femalesymbol ♀ FEMALE SIGN */
            { 0x0af9, 0x260e }, /*                   telephone ☎ BLACK TELEPHONE */
            { 0x0afa, 0x2315 }, /*           telephonerecorder ⌕ TELEPHONE RECORDER */
            { 0x0afb, 0x2117 }, /*         phonographcopyright ℗ SOUND RECORDING COPYRIGHT */
            { 0x0afc, 0x2038 }, /*                       caret ‸ CARET */
            { 0x0afd, 0x201a }, /*          singlelowquotemark ‚ SINGLE LOW-9 QUOTATION MARK */
            { 0x0afe, 0x201e }, /*          doublelowquotemark „ DOUBLE LOW-9 QUOTATION MARK */
            /*  0x0aff                                  cursor ? ??? */
            { 0x0ba3, 0x003c }, /*                   leftcaret < LESS-THAN SIGN */
            { 0x0ba6, 0x003e }, /*                  rightcaret > GREATER-THAN SIGN */
            { 0x0ba8, 0x2228 }, /*                   downcaret ∨ LOGICAL OR */
            { 0x0ba9, 0x2227 }, /*                     upcaret ∧ LOGICAL AND */
            { 0x0bc0, 0x00af }, /*                     overbar ¯ MACRON */
            { 0x0bc2, 0x22a4 }, /*                    downtack ⊤ DOWN TACK */
            { 0x0bc3, 0x2229 }, /*                      upshoe ∩ INTERSECTION */
            { 0x0bc4, 0x230a }, /*                   downstile ⌊ LEFT FLOOR */
            { 0x0bc6, 0x005f }, /*                    underbar _ LOW LINE */
            { 0x0bca, 0x2218 }, /*                         jot ∘ RING OPERATOR */
            { 0x0bcc, 0x2395 }, /*                        quad ⎕ APL FUNCTIONAL SYMBOL QUAD (Unicode 3.0) */
            { 0x0bce, 0x22a5 }, /*                      uptack ⊥ UP TACK */
            { 0x0bcf, 0x25cb }, /*                      circle ○ WHITE CIRCLE */
            { 0x0bd3, 0x2308 }, /*                     upstile ⌈ LEFT CEILING */
            { 0x0bd6, 0x222a }, /*                    downshoe ∪ UNION */
            { 0x0bd8, 0x2283 }, /*                   rightshoe ⊃ SUPERSET OF */
            { 0x0bda, 0x2282 }, /*                    leftshoe ⊂ SUBSET OF */
            { 0x0bdc, 0x22a3 }, /*                    lefttack ⊣ LEFT TACK */
            { 0x0bfc, 0x22a2 }, /*                   righttack ⊢ RIGHT TACK */
            { 0x0cdf, 0x2017 }, /*        hebrew_doublelowline ‗ DOUBLE LOW LINE */
            { 0x0ce0, 0x05d0 }, /*                hebrew_aleph א HEBREW LETTER ALEF */
            { 0x0ce1, 0x05d1 }, /*                  hebrew_bet ב HEBREW LETTER BET */
            { 0x0ce2, 0x05d2 }, /*                hebrew_gimel ג HEBREW LETTER GIMEL */
            { 0x0ce3, 0x05d3 }, /*                hebrew_dalet ד HEBREW LETTER DALET */
            { 0x0ce4, 0x05d4 }, /*                   hebrew_he ה HEBREW LETTER HE */
            { 0x0ce5, 0x05d5 }, /*                  hebrew_waw ו HEBREW LETTER VAV */
            { 0x0ce6, 0x05d6 }, /*                 hebrew_zain ז HEBREW LETTER ZAYIN */
            { 0x0ce7, 0x05d7 }, /*                 hebrew_chet ח HEBREW LETTER HET */
            { 0x0ce8, 0x05d8 }, /*                  hebrew_tet ט HEBREW LETTER TET */
            { 0x0ce9, 0x05d9 }, /*                  hebrew_yod י HEBREW LETTER YOD */
            { 0x0cea, 0x05da }, /*            hebrew_finalkaph ך HEBREW LETTER FINAL KAF */
            { 0x0ceb, 0x05db }, /*                 hebrew_kaph כ HEBREW LETTER KAF */
            { 0x0cec, 0x05dc }, /*                hebrew_lamed ל HEBREW LETTER LAMED */
            { 0x0ced, 0x05dd }, /*             hebrew_finalmem ם HEBREW LETTER FINAL MEM */
            { 0x0cee, 0x05de }, /*                  hebrew_mem מ HEBREW LETTER MEM */
            { 0x0cef, 0x05df }, /*             hebrew_finalnun ן HEBREW LETTER FINAL NUN */
            { 0x0cf0, 0x05e0 }, /*                  hebrew_nun נ HEBREW LETTER NUN */
            { 0x0cf1, 0x05e1 }, /*               hebrew_samech ס HEBREW LETTER SAMEKH */
            { 0x0cf2, 0x05e2 }, /*                 hebrew_ayin ע HEBREW LETTER AYIN */
            { 0x0cf3, 0x05e3 }, /*              hebrew_finalpe ף HEBREW LETTER FINAL PE */
            { 0x0cf4, 0x05e4 }, /*                   hebrew_pe פ HEBREW LETTER PE */
            { 0x0cf5, 0x05e5 }, /*            hebrew_finalzade ץ HEBREW LETTER FINAL TSADI */
            { 0x0cf6, 0x05e6 }, /*                 hebrew_zade צ HEBREW LETTER TSADI */
            { 0x0cf7, 0x05e7 }, /*                 hebrew_qoph ק HEBREW LETTER QOF */
            { 0x0cf8, 0x05e8 }, /*                 hebrew_resh ר HEBREW LETTER RESH */
            { 0x0cf9, 0x05e9 }, /*                 hebrew_shin ש HEBREW LETTER SHIN */
            { 0x0cfa, 0x05ea }, /*                  hebrew_taw ת HEBREW LETTER TAV */
            { 0x0da1, 0x0e01 }, /*                  Thai_kokai ก THAI CHARACTER KO KAI */
            { 0x0da2, 0x0e02 }, /*                Thai_khokhai ข THAI CHARACTER KHO KHAI */
            { 0x0da3, 0x0e03 }, /*               Thai_khokhuat ฃ THAI CHARACTER KHO KHUAT */
            { 0x0da4, 0x0e04 }, /*               Thai_khokhwai ค THAI CHARACTER KHO KHWAI */
            { 0x0da5, 0x0e05 }, /*                Thai_khokhon ฅ THAI CHARACTER KHO KHON */
            { 0x0da6, 0x0e06 }, /*             Thai_khorakhang ฆ THAI CHARACTER KHO RAKHANG */
            { 0x0da7, 0x0e07 }, /*                 Thai_ngongu ง THAI CHARACTER NGO NGU */
            { 0x0da8, 0x0e08 }, /*                Thai_chochan จ THAI CHARACTER CHO CHAN */
            { 0x0da9, 0x0e09 }, /*               Thai_choching ฉ THAI CHARACTER CHO CHING */
            { 0x0daa, 0x0e0a }, /*               Thai_chochang ช THAI CHARACTER CHO CHANG */
            { 0x0dab, 0x0e0b }, /*                   Thai_soso ซ THAI CHARACTER SO SO */
            { 0x0dac, 0x0e0c }, /*                Thai_chochoe ฌ THAI CHARACTER CHO CHOE */
            { 0x0dad, 0x0e0d }, /*                 Thai_yoying ญ THAI CHARACTER YO YING */
            { 0x0dae, 0x0e0e }, /*                Thai_dochada ฎ THAI CHARACTER DO CHADA */
            { 0x0daf, 0x0e0f }, /*                Thai_topatak ฏ THAI CHARACTER TO PATAK */
            { 0x0db0, 0x0e10 }, /*                Thai_thothan ฐ THAI CHARACTER THO THAN */
            { 0x0db1, 0x0e11 }, /*          Thai_thonangmontho ฑ THAI CHARACTER THO NANGMONTHO */
            { 0x0db2, 0x0e12 }, /*             Thai_thophuthao ฒ THAI CHARACTER THO PHUTHAO */
            { 0x0db3, 0x0e13 }, /*                  Thai_nonen ณ THAI CHARACTER NO NEN */
            { 0x0db4, 0x0e14 }, /*                  Thai_dodek ด THAI CHARACTER DO DEK */
            { 0x0db5, 0x0e15 }, /*                  Thai_totao ต THAI CHARACTER TO TAO */
            { 0x0db6, 0x0e16 }, /*               Thai_thothung ถ THAI CHARACTER THO THUNG */
            { 0x0db7, 0x0e17 }, /*              Thai_thothahan ท THAI CHARACTER THO THAHAN */
            { 0x0db8, 0x0e18 }, /*               Thai_thothong ธ THAI CHARACTER THO THONG */
            { 0x0db9, 0x0e19 }, /*                   Thai_nonu น THAI CHARACTER NO NU */
            { 0x0dba, 0x0e1a }, /*               Thai_bobaimai บ THAI CHARACTER BO BAIMAI */
            { 0x0dbb, 0x0e1b }, /*                  Thai_popla ป THAI CHARACTER PO PLA */
            { 0x0dbc, 0x0e1c }, /*               Thai_phophung ผ THAI CHARACTER PHO PHUNG */
            { 0x0dbd, 0x0e1d }, /*                   Thai_fofa ฝ THAI CHARACTER FO FA */
            { 0x0dbe, 0x0e1e }, /*                Thai_phophan พ THAI CHARACTER PHO PHAN */
            { 0x0dbf, 0x0e1f }, /*                  Thai_fofan ฟ THAI CHARACTER FO FAN */
            { 0x0dc0, 0x0e20 }, /*             Thai_phosamphao ภ THAI CHARACTER PHO SAMPHAO */
            { 0x0dc1, 0x0e21 }, /*                   Thai_moma ม THAI CHARACTER MO MA */
            { 0x0dc2, 0x0e22 }, /*                  Thai_yoyak ย THAI CHARACTER YO YAK */
            { 0x0dc3, 0x0e23 }, /*                  Thai_rorua ร THAI CHARACTER RO RUA */
            { 0x0dc4, 0x0e24 }, /*                     Thai_ru ฤ THAI CHARACTER RU */
            { 0x0dc5, 0x0e25 }, /*                 Thai_loling ล THAI CHARACTER LO LING */
            { 0x0dc6, 0x0e26 }, /*                     Thai_lu ฦ THAI CHARACTER LU */
            { 0x0dc7, 0x0e27 }, /*                 Thai_wowaen ว THAI CHARACTER WO WAEN */
            { 0x0dc8, 0x0e28 }, /*                 Thai_sosala ศ THAI CHARACTER SO SALA */
            { 0x0dc9, 0x0e29 }, /*                 Thai_sorusi ษ THAI CHARACTER SO RUSI */
            { 0x0dca, 0x0e2a }, /*                  Thai_sosua ส THAI CHARACTER SO SUA */
            { 0x0dcb, 0x0e2b }, /*                  Thai_hohip ห THAI CHARACTER HO HIP */
            { 0x0dcc, 0x0e2c }, /*                Thai_lochula ฬ THAI CHARACTER LO CHULA */
            { 0x0dcd, 0x0e2d }, /*                   Thai_oang อ THAI CHARACTER O ANG */
            { 0x0dce, 0x0e2e }, /*               Thai_honokhuk ฮ THAI CHARACTER HO NOKHUK */
            { 0x0dcf, 0x0e2f }, /*              Thai_paiyannoi ฯ THAI CHARACTER PAIYANNOI */
            { 0x0dd0, 0x0e30 }, /*                  Thai_saraa ะ THAI CHARACTER SARA A */
            { 0x0dd1, 0x0e31 }, /*             Thai_maihanakat ั THAI CHARACTER MAI HAN-AKAT */
            { 0x0dd2, 0x0e32 }, /*                 Thai_saraaa า THAI CHARACTER SARA AA */
            { 0x0dd3, 0x0e33 }, /*                 Thai_saraam ำ THAI CHARACTER SARA AM */
            { 0x0dd4, 0x0e34 }, /*                  Thai_sarai ิ THAI CHARACTER SARA I */
            { 0x0dd5, 0x0e35 }, /*                 Thai_saraii ี THAI CHARACTER SARA II */
            { 0x0dd6, 0x0e36 }, /*                 Thai_saraue ึ THAI CHARACTER SARA UE */
            { 0x0dd7, 0x0e37 }, /*                Thai_sarauee ื THAI CHARACTER SARA UEE */
            { 0x0dd8, 0x0e38 }, /*                  Thai_sarau ุ THAI CHARACTER SARA U */
            { 0x0dd9, 0x0e39 }, /*                 Thai_sarauu ู THAI CHARACTER SARA UU */
            { 0x0dda, 0x0e3a }, /*                Thai_phinthu ฺ THAI CHARACTER PHINTHU */
            { 0x0dde, 0x0e3e }, /*      Thai_maihanakat_maitho ฾ ??? */
            { 0x0ddf, 0x0e3f }, /*                   Thai_baht ฿ THAI CURRENCY SYMBOL BAHT */
            { 0x0de0, 0x0e40 }, /*                  Thai_sarae เ THAI CHARACTER SARA E */
            { 0x0de1, 0x0e41 }, /*                 Thai_saraae แ THAI CHARACTER SARA AE */
            { 0x0de2, 0x0e42 }, /*                  Thai_sarao โ THAI CHARACTER SARA O */
            { 0x0de3, 0x0e43 }, /*          Thai_saraaimaimuan ใ THAI CHARACTER SARA AI MAIMUAN */
            { 0x0de4, 0x0e44 }, /*         Thai_saraaimaimalai ไ THAI CHARACTER SARA AI MAIMALAI */
            { 0x0de5, 0x0e45 }, /*            Thai_lakkhangyao ๅ THAI CHARACTER LAKKHANGYAO */
            { 0x0de6, 0x0e46 }, /*               Thai_maiyamok ๆ THAI CHARACTER MAIYAMOK */
            { 0x0de7, 0x0e47 }, /*              Thai_maitaikhu ็ THAI CHARACTER MAITAIKHU */
            { 0x0de8, 0x0e48 }, /*                  Thai_maiek ่ THAI CHARACTER MAI EK */
            { 0x0de9, 0x0e49 }, /*                 Thai_maitho ้ THAI CHARACTER MAI THO */
            { 0x0dea, 0x0e4a }, /*                 Thai_maitri ๊ THAI CHARACTER MAI TRI */
            { 0x0deb, 0x0e4b }, /*            Thai_maichattawa ๋ THAI CHARACTER MAI CHATTAWA */
            { 0x0dec, 0x0e4c }, /*            Thai_thanthakhat ์ THAI CHARACTER THANTHAKHAT */
            { 0x0ded, 0x0e4d }, /*               Thai_nikhahit ํ THAI CHARACTER NIKHAHIT */
            { 0x0df0, 0x0e50 }, /*                 Thai_leksun ๐ THAI DIGIT ZERO */
            { 0x0df1, 0x0e51 }, /*                Thai_leknung ๑ THAI DIGIT ONE */
            { 0x0df2, 0x0e52 }, /*                Thai_leksong ๒ THAI DIGIT TWO */
            { 0x0df3, 0x0e53 }, /*                 Thai_leksam ๓ THAI DIGIT THREE */
            { 0x0df4, 0x0e54 }, /*                  Thai_leksi ๔ THAI DIGIT FOUR */
            { 0x0df5, 0x0e55 }, /*                  Thai_lekha ๕ THAI DIGIT FIVE */
            { 0x0df6, 0x0e56 }, /*                 Thai_lekhok ๖ THAI DIGIT SIX */
            { 0x0df7, 0x0e57 }, /*                Thai_lekchet ๗ THAI DIGIT SEVEN */
            { 0x0df8, 0x0e58 }, /*                Thai_lekpaet ๘ THAI DIGIT EIGHT */
            { 0x0df9, 0x0e59 }, /*                 Thai_lekkao ๙ THAI DIGIT NINE */
            { 0x0ea1, 0x3131 }, /*               Hangul_Kiyeog ㄱ HANGUL LETTER KIYEOK */
            { 0x0ea2, 0x3132 }, /*          Hangul_SsangKiyeog ㄲ HANGUL LETTER SSANGKIYEOK */
            { 0x0ea3, 0x3133 }, /*           Hangul_KiyeogSios ㄳ HANGUL LETTER KIYEOK-SIOS */
            { 0x0ea4, 0x3134 }, /*                Hangul_Nieun ㄴ HANGUL LETTER NIEUN */
            { 0x0ea5, 0x3135 }, /*           Hangul_NieunJieuj ㄵ HANGUL LETTER NIEUN-CIEUC */
            { 0x0ea6, 0x3136 }, /*           Hangul_NieunHieuh ㄶ HANGUL LETTER NIEUN-HIEUH */
            { 0x0ea7, 0x3137 }, /*               Hangul_Dikeud ㄷ HANGUL LETTER TIKEUT */
            { 0x0ea8, 0x3138 }, /*          Hangul_SsangDikeud ㄸ HANGUL LETTER SSANGTIKEUT */
            { 0x0ea9, 0x3139 }, /*                Hangul_Rieul ㄹ HANGUL LETTER RIEUL */
            { 0x0eaa, 0x313a }, /*          Hangul_RieulKiyeog ㄺ HANGUL LETTER RIEUL-KIYEOK */
            { 0x0eab, 0x313b }, /*           Hangul_RieulMieum ㄻ HANGUL LETTER RIEUL-MIEUM */
            { 0x0eac, 0x313c }, /*           Hangul_RieulPieub ㄼ HANGUL LETTER RIEUL-PIEUP */
            { 0x0ead, 0x313d }, /*            Hangul_RieulSios ㄽ HANGUL LETTER RIEUL-SIOS */
            { 0x0eae, 0x313e }, /*           Hangul_RieulTieut ㄾ HANGUL LETTER RIEUL-THIEUTH */
            { 0x0eaf, 0x313f }, /*          Hangul_RieulPhieuf ㄿ HANGUL LETTER RIEUL-PHIEUPH */
            { 0x0eb0, 0x3140 }, /*           Hangul_RieulHieuh ㅀ HANGUL LETTER RIEUL-HIEUH */
            { 0x0eb1, 0x3141 }, /*                Hangul_Mieum ㅁ HANGUL LETTER MIEUM */
            { 0x0eb2, 0x3142 }, /*                Hangul_Pieub ㅂ HANGUL LETTER PIEUP */
            { 0x0eb3, 0x3143 }, /*           Hangul_SsangPieub ㅃ HANGUL LETTER SSANGPIEUP */
            { 0x0eb4, 0x3144 }, /*            Hangul_PieubSios ㅄ HANGUL LETTER PIEUP-SIOS */
            { 0x0eb5, 0x3145 }, /*                 Hangul_Sios ㅅ HANGUL LETTER SIOS */
            { 0x0eb6, 0x3146 }, /*            Hangul_SsangSios ㅆ HANGUL LETTER SSANGSIOS */
            { 0x0eb7, 0x3147 }, /*                Hangul_Ieung ㅇ HANGUL LETTER IEUNG */
            { 0x0eb8, 0x3148 }, /*                Hangul_Jieuj ㅈ HANGUL LETTER CIEUC */
            { 0x0eb9, 0x3149 }, /*           Hangul_SsangJieuj ㅉ HANGUL LETTER SSANGCIEUC */
            { 0x0eba, 0x314a }, /*                Hangul_Cieuc ㅊ HANGUL LETTER CHIEUCH */
            { 0x0ebb, 0x314b }, /*               Hangul_Khieuq ㅋ HANGUL LETTER KHIEUKH */
            { 0x0ebc, 0x314c }, /*                Hangul_Tieut ㅌ HANGUL LETTER THIEUTH */
            { 0x0ebd, 0x314d }, /*               Hangul_Phieuf ㅍ HANGUL LETTER PHIEUPH */
            { 0x0ebe, 0x314e }, /*                Hangul_Hieuh ㅎ HANGUL LETTER HIEUH */
            { 0x0ebf, 0x314f }, /*                    Hangul_A ㅏ HANGUL LETTER A */
            { 0x0ec0, 0x3150 }, /*                   Hangul_AE ㅐ HANGUL LETTER AE */
            { 0x0ec1, 0x3151 }, /*                   Hangul_YA ㅑ HANGUL LETTER YA */
            { 0x0ec2, 0x3152 }, /*                  Hangul_YAE ㅒ HANGUL LETTER YAE */
            { 0x0ec3, 0x3153 }, /*                   Hangul_EO ㅓ HANGUL LETTER EO */
            { 0x0ec4, 0x3154 }, /*                    Hangul_E ㅔ HANGUL LETTER E */
            { 0x0ec5, 0x3155 }, /*                  Hangul_YEO ㅕ HANGUL LETTER YEO */
            { 0x0ec6, 0x3156 }, /*                   Hangul_YE ㅖ HANGUL LETTER YE */
            { 0x0ec7, 0x3157 }, /*                    Hangul_O ㅗ HANGUL LETTER O */
            { 0x0ec8, 0x3158 }, /*                   Hangul_WA ㅘ HANGUL LETTER WA */
            { 0x0ec9, 0x3159 }, /*                  Hangul_WAE ㅙ HANGUL LETTER WAE */
            { 0x0eca, 0x315a }, /*                   Hangul_OE ㅚ HANGUL LETTER OE */
            { 0x0ecb, 0x315b }, /*                   Hangul_YO ㅛ HANGUL LETTER YO */
            { 0x0ecc, 0x315c }, /*                    Hangul_U ㅜ HANGUL LETTER U */
            { 0x0ecd, 0x315d }, /*                  Hangul_WEO ㅝ HANGUL LETTER WEO */
            { 0x0ece, 0x315e }, /*                   Hangul_WE ㅞ HANGUL LETTER WE */
            { 0x0ecf, 0x315f }, /*                   Hangul_WI ㅟ HANGUL LETTER WI */
            { 0x0ed0, 0x3160 }, /*                   Hangul_YU ㅠ HANGUL LETTER YU */
            { 0x0ed1, 0x3161 }, /*                   Hangul_EU ㅡ HANGUL LETTER EU */
            { 0x0ed2, 0x3162 }, /*                   Hangul_YI ㅢ HANGUL LETTER YI */
            { 0x0ed3, 0x3163 }, /*                    Hangul_I ㅣ HANGUL LETTER I */
            { 0x0ed4, 0x11a8 }, /*             Hangul_J_Kiyeog ᆨ HANGUL JONGSEONG KIYEOK */
            { 0x0ed5, 0x11a9 }, /*        Hangul_J_SsangKiyeog ᆩ HANGUL JONGSEONG SSANGKIYEOK */
            { 0x0ed6, 0x11aa }, /*         Hangul_J_KiyeogSios ᆪ HANGUL JONGSEONG KIYEOK-SIOS */
            { 0x0ed7, 0x11ab }, /*              Hangul_J_Nieun ᆫ HANGUL JONGSEONG NIEUN */
            { 0x0ed8, 0x11ac }, /*         Hangul_J_NieunJieuj ᆬ HANGUL JONGSEONG NIEUN-CIEUC */
            { 0x0ed9, 0x11ad }, /*         Hangul_J_NieunHieuh ᆭ HANGUL JONGSEONG NIEUN-HIEUH */
            { 0x0eda, 0x11ae }, /*             Hangul_J_Dikeud ᆮ HANGUL JONGSEONG TIKEUT */
            { 0x0edb, 0x11af }, /*              Hangul_J_Rieul ᆯ HANGUL JONGSEONG RIEUL */
            { 0x0edc, 0x11b0 }, /*        Hangul_J_RieulKiyeog ᆰ HANGUL JONGSEONG RIEUL-KIYEOK */
            { 0x0edd, 0x11b1 }, /*         Hangul_J_RieulMieum ᆱ HANGUL JONGSEONG RIEUL-MIEUM */
            { 0x0ede, 0x11b2 }, /*         Hangul_J_RieulPieub ᆲ HANGUL JONGSEONG RIEUL-PIEUP */
            { 0x0edf, 0x11b3 }, /*          Hangul_J_RieulSios ᆳ HANGUL JONGSEONG RIEUL-SIOS */
            { 0x0ee0, 0x11b4 }, /*         Hangul_J_RieulTieut ᆴ HANGUL JONGSEONG RIEUL-THIEUTH */
            { 0x0ee1, 0x11b5 }, /*        Hangul_J_RieulPhieuf ᆵ HANGUL JONGSEONG RIEUL-PHIEUPH */
            { 0x0ee2, 0x11b6 }, /*         Hangul_J_RieulHieuh ᆶ HANGUL JONGSEONG RIEUL-HIEUH */
            { 0x0ee3, 0x11b7 }, /*              Hangul_J_Mieum ᆷ HANGUL JONGSEONG MIEUM */
            { 0x0ee4, 0x11b8 }, /*              Hangul_J_Pieub ᆸ HANGUL JONGSEONG PIEUP */
            { 0x0ee5, 0x11b9 }, /*          Hangul_J_PieubSios ᆹ HANGUL JONGSEONG PIEUP-SIOS */
            { 0x0ee6, 0x11ba }, /*               Hangul_J_Sios ᆺ HANGUL JONGSEONG SIOS */
            { 0x0ee7, 0x11bb }, /*          Hangul_J_SsangSios ᆻ HANGUL JONGSEONG SSANGSIOS */
            { 0x0ee8, 0x11bc }, /*              Hangul_J_Ieung ᆼ HANGUL JONGSEONG IEUNG */
            { 0x0ee9, 0x11bd }, /*              Hangul_J_Jieuj ᆽ HANGUL JONGSEONG CIEUC */
            { 0x0eea, 0x11be }, /*              Hangul_J_Cieuc ᆾ HANGUL JONGSEONG CHIEUCH */
            { 0x0eeb, 0x11bf }, /*             Hangul_J_Khieuq ᆿ HANGUL JONGSEONG KHIEUKH */
            { 0x0eec, 0x11c0 }, /*              Hangul_J_Tieut ᇀ HANGUL JONGSEONG THIEUTH */
            { 0x0eed, 0x11c1 }, /*             Hangul_J_Phieuf ᇁ HANGUL JONGSEONG PHIEUPH */
            { 0x0eee, 0x11c2 }, /*              Hangul_J_Hieuh ᇂ HANGUL JONGSEONG HIEUH */
            { 0x0eef, 0x316d }, /*     Hangul_RieulYeorinHieuh ㅭ HANGUL LETTER RIEUL-YEORINHIEUH */
            { 0x0ef0, 0x3171 }, /*    Hangul_SunkyeongeumMieum ㅱ HANGUL LETTER KAPYEOUNMIEUM */
            { 0x0ef1, 0x3178 }, /*    Hangul_SunkyeongeumPieub ㅸ HANGUL LETTER KAPYEOUNPIEUP */
            { 0x0ef2, 0x317f }, /*              Hangul_PanSios ㅿ HANGUL LETTER PANSIOS */
            { 0x0ef3, 0x3181 }, /*    Hangul_KkogjiDalrinIeung ㆁ HANGUL LETTER YESIEUNG */
            { 0x0ef4, 0x3184 }, /*   Hangul_SunkyeongeumPhieuf ㆄ HANGUL LETTER KAPYEOUNPHIEUPH */
            { 0x0ef5, 0x3186 }, /*          Hangul_YeorinHieuh ㆆ HANGUL LETTER YEORINHIEUH */
            { 0x0ef6, 0x318d }, /*                Hangul_AraeA ㆍ HANGUL LETTER ARAEA */
            { 0x0ef7, 0x318e }, /*               Hangul_AraeAE ㆎ HANGUL LETTER ARAEAE */
            { 0x0ef8, 0x11eb }, /*            Hangul_J_PanSios ᇫ HANGUL JONGSEONG PANSIOS */
            { 0x0ef9, 0x11f0 }, /*  Hangul_J_KkogjiDalrinIeung ᇰ HANGUL JONGSEONG YESIEUNG */
            { 0x0efa, 0x11f9 }, /*        Hangul_J_YeorinHieuh ᇹ HANGUL JONGSEONG YEORINHIEUH */
            { 0x0eff, 0x20a9 }, /*                  Korean_Won ₩ WON SIGN */
            { 0x13bc, 0x0152 }, /*                          OE Œ LATIN CAPITAL LIGATURE OE */
            { 0x13bd, 0x0153 }, /*                          oe œ LATIN SMALL LIGATURE OE */
            { 0x13be, 0x0178 }, /*                  Ydiaeresis Ÿ LATIN CAPITAL LETTER Y WITH DIAERESIS */
            { 0x20ac, 0x20ac }, /*                    EuroSign € EURO SIGN */
        };


        /// <summary>
        /// VncPixelFormat is 16 bytes
        /// </summary>
        public readonly struct VncPixelFormat
        {
            //VNC Pixel Format is defined here:
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#732serverinit
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#741setpixelformat

            /// <summary>
            /// Bits-per-pixel is the number of bits used for each pixel value on the wire. This must be greater than or equal to depth, which is the number of useful bits in the pixel value. Currently bits-per-pixel must be 8, 16 or 32. Less than 8-bit pixels are not yet supported. Big-endian-flag is non-zero (true) if multi-byte pixels are interpreted as big endian. Of course this is meaningless for 8 bits-per-pixel.
            /// </summary>
            public readonly byte BitsPerPixel;

            public int BytesPerPixel {
                get {
                    return (this.BitsPerPixel + 7) / 8;
                }
            }
            /// <summary>
            /// Depth should be the sum of bits used according to red-max, green-max, and blue-max, or the number of bits needed for indices in the colour map, depending on the value of true-color-flag. Note that some servers will send a depth that is identical to bits-per-pixel for historical reasons.
            /// </summary>
            public readonly byte Depth;
            /// <summary>
            /// If true-colour-flag is non-zero (true): Swap the pixel value according to big-endian-flag (e.g. if big-endian-flag is zero (false) and host byte order is big endian, then swap).
            /// </summary>
            public readonly bool BigEndian;
            /// <summary>
            /// If true-colour-flag is non-zero (true) then the last six items specify how to extract the red, green and blue intensities from the pixel value. Red-max is the maximum red value (= 2^n - 1 where n is the number of bits used for red). Note this value is always in big endian order. Red-shift is the number of shifts needed to get the red value in a pixel to the least significant bit. Green-max, green-shift and blue-max, blue-shift are similar for green and blue.
            /// If true-colour-flag is zero (false) then the server uses pixel values which are not directly composed from the red, green and blue intensities, but which serve as indices into a colour map. Entries in the colour map are set by the server using the SetColourMapEntries message (SetColourMapEntries).
            /// </summary>
            public readonly bool TrueColour;
            public readonly ushort RedMax;
            public readonly ushort GreenMax;
            public readonly ushort BlueMax;
            public readonly byte RedShift;
            public readonly byte GreenShift;
            public readonly byte BlueShift;

            public VncPixelFormat(byte[] data, int offset)
            {

                /**
                 * +--------------+--------------+-----------------+
                 * | No. of bytes | Type [Value] | Description     |
                 * +--------------+--------------+-----------------+
                 * | 1            | U8           | bits-per-pixel  |
                 * | 1            | U8           | depth           |
                 * | 1            | U8           | big-endian-flag |
                 * | 1            | U8           | true-color-flag |
                 * | 2            | U16          | red-max         |
                 * | 2            | U16          | green-max       |
                 * | 2            | U16          | blue-max        |
                 * | 1            | U8           | red-shift       |
                 * | 1            | U8           | green-shift     |
                 * | 1            | U8           | blue-shift      |
                 * | 3            |              | padding         |
                 * +--------------+--------------+-----------------+
                */

                BitsPerPixel = data[offset + 0];
                Depth = data[offset + 1];
                BigEndian = data[offset + 2] != 0;
                TrueColour = data[offset + 3] != 0;
                RedMax = (ushort)(data[offset + 5] | data[offset + 4] << 8);
                GreenMax = (ushort)(data[offset + 7] | data[offset + 6] << 8);
                BlueMax = (ushort)(data[offset + 9] | data[offset + 8] << 8);
                RedShift = data[offset + 10];
                GreenShift = data[offset + 11];
                BlueShift = data[offset + 12];
                //3 bytes padding should be all zeroes
            }

            public VncPixelFormat(VncPixelFormat original, bool swithcRedAndBlue) {
                BitsPerPixel = original.BitsPerPixel;
                Depth = original.Depth;
                BigEndian = original.BigEndian;
                TrueColour = original.TrueColour;
                RedMax = original.RedMax;
                GreenMax = original.GreenMax;
                BlueMax = original.BlueMax;
                if(swithcRedAndBlue) {
                    RedShift = original.BlueShift;
                    BlueShift = original.RedShift;
                }
                else {
                    RedShift = original.RedShift;
                    BlueShift = original.BlueShift;
                }
                
                GreenShift = original.GreenShift;
                
            }

            public bool TryGetColor(byte[] data, int offset, out RfbColor color) {
                uint colorValue = Utils.ByteConverter.ToUInt32(data, offset, this.BytesPerPixel, !this.BigEndian);
                return this.TryGetColor(colorValue, out color);
            }

            public bool TryGetColor(uint colorValue, out RfbColor color) {
                if (this.TrueColour) {
                    byte red = GetColorIntensity(colorValue, this.RedShift, this.RedMax);
                    byte green = GetColorIntensity(colorValue, this.GreenShift, this.GreenMax);
                    byte blue = GetColorIntensity(colorValue, this.BlueShift, this.BlueMax);
                    color = new RfbColor(red, green, blue);
                    
                    return true;
                }
                else {
                    color = new RfbColor((int)colorValue);
                    return false;
                }
            }

            private static byte GetColorIntensity(uint colorValue, byte shift, ushort max) {
                int intensityCorrectionShift = 8 - SharedUtils.MathUtils.CountBitsInMask(max);
                return (byte)(((colorValue >> shift) & max) << intensityCorrectionShift);
            }

            public override string ToString()
            {
                return BitsPerPixel.ToString() + " bits per pixel";
            }

            
        }

        #region Static functions
        public static bool TryParseVncPixelFormat(byte[] data, int offset, out VncPixelFormat vncPixelFormat)
        {
            if (data.Length >= offset + 16)
            {
                //check that padding is zeroes
                if (data[offset + 13] == 0 && data[offset + 14] == 0 && data[offset + 15] == 0)
                {
                    //check that bits per pixel > 0 and <= 32 and depth <= 32
                    if (data[offset] > 0 && data[offset] <= 32 && data[offset + 1] <= 32)
                    {
                        vncPixelFormat = new VncPixelFormat(data, offset);
                        return true;
                    }
                }
            }
            vncPixelFormat = default;
            return false;
        }

        public static bool TryGetCutTextPacketLength(Frame parentFrame, int packetStartIndex, int packetEndIndex, out int cutTextPacketLength)
        {
            cutTextPacketLength = -1;
            if (packetEndIndex < packetStartIndex + 7)
                return false;
            int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            if (length < 0)
            {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                //A negative value of length indicates that the extended message format is used and abs(length) is the total number of following bytes.
                length = -length;
                if (length < 4)
                    return false;//there must be space for the flags
            }
            if (length >= 0)
            {
                if (packetEndIndex < packetStartIndex + 7 + length)
                    return false;
                cutTextPacketLength = 8 + length;
            }
            return cutTextPacketLength > 7;
        }

        public static bool TryParseHandshake(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out RfbPacket rfbPacket) {
            rfbPacket = null;
            int offset = packetStartIndex;
            if (TryParseProtocolVersion(parentFrame, packetStartIndex, packetEndIndex, out string protocolVersionString, out int bytesParsed)) {
                //ProtocolVersion
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                rfbPacket.ProtocolVersionString = protocolVersionString;
            }
            else if (!clientToServer && TryGetServerSecurityTypes(parentFrame, packetStartIndex, packetEndIndex, out byte[] securityTypes, out bytesParsed)) {
                //Security server
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                rfbPacket.SecurityTypes = securityTypes.Where(st => Enum.IsDefined(typeof(SecurityType), st)).Select(st => (SecurityType)st).ToArray();
            }
            else if (clientToServer && TryGetClientSecurityType(parentFrame, packetStartIndex, packetEndIndex, out byte securityType, out bytesParsed)) {
                //Security client
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetStartIndex + bytesParsed - 1, clientToServer);
                if (Enum.IsDefined(typeof(SecurityType), securityType)) {
                    rfbPacket.SecurityTypes = new[] { (SecurityType)securityType };
                }
            }
            else if(!clientToServer && packetStartIndex + 3 == packetEndIndex) {
                //Security Result
                //0 = OK, 1 = failed, 2 = failed, too many attempts
                if (parentFrame.Data[packetStartIndex] == 0 && parentFrame.Data[packetStartIndex + 1] == 0 && parentFrame.Data[packetStartIndex + 2] == 0 && parentFrame.Data[packetStartIndex + 3] < 3) {
                    rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                }
            }
            else if(packetStartIndex + 15 == packetEndIndex && SharedUtils.MathUtils.GetEntropy(parentFrame.Data, packetStartIndex, 16) > 3.2) {
                //16 bytes of high-entropy data might indicate that this is an auth challange or response
                //The maximum entropy here is 4.0 because the input is only 16 bytes long
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);

            }
            else if(clientToServer && packetStartIndex == packetEndIndex) {
                //Client Init
                byte sharedFlag = parentFrame.Data[packetStartIndex];
                if (sharedFlag == 0 || sharedFlag == 1)//this flag can in theory have any value, but most implementations use 1 for true
                    rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
            }
            else if(!clientToServer && TryParseServerInit(parentFrame.Data, ref offset, out ushort width, out ushort height, out VncPixelFormat pf, out string desktopName)) {
                //ServerInit
                rfbPacket = new RfbPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                rfbPacket.PixelFormat = pf;
                rfbPacket.ScreenSize = new RfbSize(width, height);
                rfbPacket.VncDesktopName = desktopName;
            }
            return rfbPacket != null;
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out RfbPacket rfbPacket) {
            rfbPacket = null;
            int offset = packetStartIndex;

            try
            {
                if (clientToServer)
                {
                    /*
                    //VNC Command from viewer
                    if (packetStartIndex == packetEndIndex && (parentFrame.Data[packetEndIndex] == 0x06 || parentFrame.Data[packetEndIndex] == 0x0a))
                    {
                        //ClientInit??
                        var vncCommandPacket = new VncCommandPacket(parentFrame, packetStartIndex, packetEndIndex, true);
                        rfbPacket = new RfbPacket(vncCommandPacket);
                    }
                    else 
                    */
                    if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.SetPixelFormat)
                    {
                        if (SetPixelFormatPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out SetPixelFormatPacket setPixelFormatPacket, false))
                            rfbPacket = new RfbPacket(setPixelFormatPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.SetEncodings)
                    {
                        if (SetEncodingsPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out SetEncodingsPacket setEncodingPacket))
                            rfbPacket = new RfbPacket(setEncodingPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.FramebufferUpdateRequest)
                    {
                        if (FrameBufferUpdateRequestPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out FrameBufferUpdateRequestPacket frameBufferUpdateRequestPacket))
                            rfbPacket = new RfbPacket(frameBufferUpdateRequestPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.PointerEvent)
                    {
                        /***
                         * Bytes    Value   Field Name
                         * 1        0x05    message-type
                         * 1                button-mask
                         * 2                x-position
                         * 2                y-position
                         **/
                        if (packetStartIndex + 5 <= packetEndIndex)
                        {
                            var pointerEventPacket = new VncCommandPacket(parentFrame, packetStartIndex, packetStartIndex + 5, clientToServer);
                            rfbPacket = new RfbPacket(pointerEventPacket);
                        }
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.ClientCutText)
                    {
                        if (ClientCutTextPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out ClientCutTextPacket clientCutTextPacket))
                            rfbPacket = new RfbPacket(clientCutTextPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.KeyEvent)
                    {
                        var keyPacket = new KeyEventPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        rfbPacket = new RfbPacket(keyPacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncCommand.FixColourMapEntries)
                    {
                        //https://www.dei.isep.ipp.pt/~asc/normas/rfbproto.pdf
                        //https://xvm.scripts.mit.edu/browser/trunk/packages/invirt-vnc-client/RfbProto.java?rev=1588#L889
                        //https://libvnc.github.io/doc/html/structrfb_set_colour_map_entries_msg.html
                        if (FixColorMapPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out FixColorMapPacket cmPacket))
                        {
                            rfbPacket = new RfbPacket(cmPacket);
                        }
                    }
#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif
                }
                else
                {
                    //VNC response data to viewer
                    if (parentFrame.Data[packetStartIndex] == (byte)VncResponseCode.FramebufferUpdate)
                    {
                        if (FrameBufferUpdatePacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, true, out FrameBufferUpdatePacket updatePacket))
                            rfbPacket = new RfbPacket(updatePacket);
                        else if (FrameBufferUpdatePacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, false, out updatePacket))
                            rfbPacket = new RfbPacket(updatePacket);
                    }
                    else if (parentFrame.Data[packetStartIndex] == (byte)VncResponseCode.ServerCutText) {
                        if (ServerCutTextPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, clientToServer, out ServerCutTextPacket cutText)) {
                            rfbPacket = new RfbPacket(cutText);
                        }
                    }
                    else if (!Enum.IsDefined(typeof(VncResponseCode), parentFrame.Data[packetStartIndex]))
                    {
                        //something's wrong, there might be missing packets in the PCAP
                        var unknownPacket = new VncResponsePacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        rfbPacket = new RfbPacket(unknownPacket);
                    }

#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif
                }
            }
            catch (Exception e)
            {
                return false;
            }
            return rfbPacket != null;
        }

        private static bool TryParseProtocolVersion(Frame parentFrame, int packetStartIndex, int packetEndIndex, out string protocolVersionString, out int bytesParsed) {
            //12 bytes "RFB 003.0xx\n"
            if (packetEndIndex > packetStartIndex + 10) {
                if (parentFrame.Data[packetStartIndex + 11] == 0x0a) {
                    byte[] firstBytes = Encoding.ASCII.GetBytes("RFB 00");
                    if (parentFrame.Data.Skip(packetStartIndex).Take(firstBytes.Length).SequenceEqual(firstBytes)) {
                        protocolVersionString = Encoding.ASCII.GetString(parentFrame.Data, packetStartIndex, 12).TrimEnd();
                        bytesParsed = 12;
                        return true;
                    }
                }
            }
            protocolVersionString = null;
            bytesParsed = 0;
            return false;

        }

        private static bool TryGetServerSecurityTypes(Frame parentFrame, int packetStartIndex, int packetEndIndex, out byte[] securityTypes, out int bytesParsed) {
            if(packetStartIndex + 3 == packetEndIndex && parentFrame.Data[packetStartIndex] == 0 && parentFrame.Data[packetStartIndex + 1] == 0 && parentFrame.Data[packetStartIndex + 2] == 0 && parentFrame.Data[packetStartIndex + 3] != 0) {
                //The server decides the security type and sends a single word
                if (Enum.IsDefined(typeof(SecurityType), parentFrame.Data[packetStartIndex + 3])) {
                    securityTypes = new byte[] { parentFrame.Data[packetStartIndex + 3] };
                    bytesParsed = 4;
                    return true;
                }
            }
            else if(packetEndIndex > packetStartIndex) {
                byte numberOfTypes = parentFrame.Data[packetStartIndex];
                if(numberOfTypes > 0 && numberOfTypes < 10 && packetEndIndex == packetStartIndex + numberOfTypes) {
                    //we have at least one security type
                    securityTypes = new byte[numberOfTypes];
                    Array.Copy(parentFrame.Data, packetStartIndex + 1, securityTypes, 0, securityTypes.Length);
                    if (!securityTypes.Any(st => st == 0)) {
                        //verify that the majority of the types are known to reduce false positives
                        int knownTypes = securityTypes.Where(st => Enum.IsDefined(typeof(SecurityType), st)).Count();
                        if (knownTypes * 2 > securityTypes.Length) {
                            bytesParsed = 1 + numberOfTypes;
                            return true;
                        }
                    }
                }
            }
            bytesParsed = 0;
            securityTypes = null;
            return false;
        }
        private static bool TryGetClientSecurityType(Frame parentFrame, int packetStartIndex, int packetEndIndex, out byte securityType, out int bytesParsed) {
            if (packetStartIndex == packetEndIndex) {
                //The server decides the security type and sends a single word
                if (parentFrame.Data[packetStartIndex] != 0 && Enum.IsDefined(typeof(SecurityType), parentFrame.Data[packetStartIndex])) {
                    securityType = parentFrame.Data[packetStartIndex];
                    bytesParsed = 1;
                    return true;
                }
            }
            bytesParsed = 0;
            securityType = 0;
            return false;
        }

        #endregion

        public readonly VncCommandPacket CommandPacket = null;
        public readonly VncResponsePacket ResponsePacket = null;
        public string ProtocolVersionString = null;
        public SecurityType[] SecurityTypes = null;
        public VncPixelFormat? PixelFormat { get; set; } = null;
        public RfbSize? ScreenSize { get; set; } = null;
        public string VncDesktopName { get; set; } = null;

        public RfbPacket(VncCommandPacket commandPacket) : base(commandPacket.ParentFrame, commandPacket.PacketStartIndex, commandPacket.PacketEndIndex, "RFB")
        {
            CommandPacket = commandPacket;
        }

        public RfbPacket(VncResponsePacket responsePacket) : base(responsePacket.ParentFrame, responsePacket.PacketStartIndex, responsePacket.PacketEndIndex, "RFB")
        {
            ResponsePacket = responsePacket;
        }

        [Obsolete]
        protected internal RfbPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool transferIsClientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "RFB")
        {

        }

        //https://www.rfc-editor.org/rfc/rfc6143.html
        //Remote Framebuffer Protocol
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
        {
            if (includeSelfReference)
                yield return this;
            if (CommandPacket != null)
                yield return CommandPacket;
            if (ResponsePacket != null)
                yield return ResponsePacket;
        }

        #region VNC respones to viewer

        public class VncResponsePacket : AbstractPacket
        {


            public enum VncResponseCode : byte
            { //sent to viewer
                FramebufferUpdate = 0,
                SetColourMapEntries = 1,
                Bell = 2,
                ServerCutText = 3
            }


            public static bool TryParseServerInit(byte[] data, ref int offset, out ushort width, out ushort height, out VncPixelFormat pixelFormat, out string desktopName)
            {
                //ServerInit

                /**
                 *  +--------------+--------------+------------------------------+
                 *  | No. of bytes | Type [Value] | Description                  |
                 *  +--------------+--------------+------------------------------+
                 *  | 2            | U16          | framebuffer-width in pixels  |
                 *  | 2            | U16          | framebuffer-height in pixels |
                 *  | 16           | PIXEL_FORMAT | server-pixel-format          |
                 *  | 4            | U32          | name-length                  |
                 *  | name-length  | U8 array     | name-string                  |
                 *  +--------------+--------------+------------------------------+
                */
                //minimum length is 24 bytes (2 + 2 + 16 + 4 + ?)
                if (data.Length >= offset + 24)
                {
                    int stringLength = (int)Utils.ByteConverter.ToUInt32(data, offset + 20, 4, false);//big endian
                    if (stringLength < 100 && data.Length >= offset + 24 + stringLength)
                    {
                        width = Utils.ByteConverter.ToUInt16(data, offset);
                        height = Utils.ByteConverter.ToUInt16(data, offset + 2);
                        //this code allows 0x0 and 1x1 frame buffer sizes as well as anything between 16 and MAX_SCREEN_*
                        if ((width == height || (width > 15 && height > 15)) && width < MAX_SCREEN_WIDTH && height < MAX_SCREEN_HEIGHT) { 
                            if (TryParseVncPixelFormat(data, offset + 4, out pixelFormat))
                            {
                                try
                                {
                                    desktopName = Encoding.ASCII.GetString(data, offset + 24, stringLength);
                                    offset += 24 + stringLength;
                                    return true;
                                }
                                catch
                                {
                                    desktopName = null;
                                    return false;
                                }
                            }
                        }
                    }
                }

                width = 0;
                height = 0;
                pixelFormat = default;
                desktopName = null;
                return false;
            }

            

            public VncResponseCode ResponseCode { get; }

            public VncResponsePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool isClientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "VNC Response")
            {
                byte responseCode = parentFrame.Data[packetStartIndex];
                if (Enum.IsDefined(typeof(VncResponseCode), responseCode))
                    ResponseCode = (VncResponseCode)responseCode;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
            {
                if (includeSelfReference)
                    yield return this;
            }

        }

        #endregion

        #region VNC commands from viewer

        public class VncCommandPacket : AbstractPacket
        {
            //https://www.rfc-editor.org/rfc/rfc6143.html

            public enum VncCommand : byte
            { //sent from viewer
                SetPixelFormat = 0,
                FixColourMapEntries = 1,
                SetEncodings = 2,
                FramebufferUpdateRequest = 3,
                KeyEvent = 4,
                PointerEvent = 5,
                ClientCutText = 6,
            }



            public VncCommand Command { get; }

            public VncPixelFormat? PixelFormat { get; internal set; } = null;

            public VncCommandPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, "BackConnect Reverse VNC")
            {
                byte command = parentFrame.Data[packetStartIndex];
                if (Enum.IsDefined(typeof(VncCommand), command))
                    Command = (VncCommand)command;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference)
            {
                if (includeSelfReference)
                    yield return this;
            }

        }

        public class KeyEventPacket : VncCommandPacket
        {


            public enum SpecialKeys : uint
            {
                BackSpace = 0xff08,
                Tab = 0xff09,
                Return = 0xff0d,
                Escape = 0xff1b,
                Insert = 0xff63,
                Delete = 0xffff,
                Home = 0xff50,
                End = 0xff57,
                Page_Up = 0xff55,
                Page_Down = 0xff56,
                Left = 0xff51,
                Up = 0xff52,
                Right = 0xff53,
                Down = 0xff54,
                F1 = 0xffbe,
                F2 = 0xffbf,
                F3 = 0xffc0,
                F4 = 0xffc1,
                F5 = 0xffc1,
                F6 = 0xffc2,
                F7 = 0xffc3,
                F8 = 0xffc4,
                F9 = 0xffc5,
                F10 = 0xffc6,
                F11 = 0xffc7,
                F12 = 0xffc9,
                Shift_left = 0xffe1,
                Shift_right = 0xffe2,
                Control_left = 0xffe3,
                Control_right = 0xffe4,
                Meta_left = 0xffe7,
                Meta_right = 0xffe8,
                Alt_left = 0xffe9,
                Alt_right = 0xffea,
                //https://github.com/RaiMan/sikulix2tigervnc/blob/682ba518bc1f4d9f790c0bd92d19582249507ea4/src/main/java/com/tigervnc/rfb/Keysyms.java#L110
                KeyPad_Enter = 0xFF8D,
                KeyPad_Home = 0xFF95,
                KeyPad_Left = 0xFF96,
                KeyPad_Up = 0xFF97,
                KeyPad_Right = 0xFF98,
                KeyPad_Down = 0xFF99,
                KeyPad_Page_Up = 0xFF9A,
                KeyPad_Page_Down = 0xFF9B,
                KeyPad_End = 0xFF9C,
                KeyPad_Begin = 0xFF9D,
                KeyPad_Insert = 0xFF9E,
                KeyPad_Delete = 0xFF9F,
                KeyPad_Equal = 0xFFBD,
                KeyPad_0 = 0xFFB0,
                KeyPad_1 = 0xFFB1,
                KeyPad_2 = 0xFFB2,
                KeyPad_3 = 0xFFB3,
                KeyPad_4 = 0xFFB4,
                KeyPad_5 = 0xFFB5,
                KeyPad_6 = 0xFFB6,
                KeyPad_7 = 0xFFB7,
                KeyPad_8 = 0xFFB8,
                KeyPad_9 = 0xFFB9,
                KeyPad_Decimal = 0xFFAE,
                KeyPad_Add = 0xFFAB,
                KeyPad_Subtract = 0xFFAD,
                KeyPad_Multiply = 0xFFAA,
                KeyPad_Divide = 0xFFAF,
                //https://github.com/RaiMan/sikulix2tigervnc/blob/682ba518bc1f4d9f790c0bd92d19582249507ea4/src/main/java/com/tigervnc/rfb/Keysyms.java#L94
                Select = 0xFF60,
                Print = 0xFF61,
                Execute = 0xFF62,
                //Insert = 0xFF63,
                Undo = 0xFF65,
                Redo = 0xFF66,
                Menu = 0xFF67,
                Find = 0xFF68,
                Cancel = 0xFF69,
                Help = 0xFF6A,
                Break = 0xFF6B,
                Mode_switch = 0xFF7E,
                script_switch = 0xFF7E,
                Num_Lock = 0xFF7F,
            }

            public string Key { get; }
            public bool Down { get; }

            public KeyEventPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                /***
                 * +--------------+--------------+--------------+
                 * | No. of bytes | Type [Value] | Description  |
                 * +--------------+--------------+--------------+
                 * | 1            | U8 [4]       | message-type |
                 * | 1            | U8           | down-flag    |
                 * | 2            |              | padding      |
                 * | 4            | U32          | key          |
                 * +--------------+--------------+--------------+
                 **/
                this.PacketEndIndex = packetStartIndex + 7;
                this.Down = parentFrame.Data[PacketStartIndex + 1] != 0;
                uint key = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (Enum.IsDefined(typeof(SpecialKeys), key)) {
                    this.Key = "[" + (SpecialKeys)key + "]";
                }
                else if (char.IsControl((char)key))
                    this.Key = "[0x" + key.ToString("x8") + "]";
                else if (key > 0 && key < 127)
                    this.Key = "" + (char)key;
                else if(key >= 0x01000100 && key < 0x01110000) {
                    // represent the ISO 10646 / Unicode characters U+0100 to U+10FFFF, respective
                    //https://www.cl.cam.ac.uk/~mgk25/ucs/keysyms.pdf
                    this.Key = UnicodeEncoding.Unicode.GetString(parentFrame.Data, packetStartIndex + 5, 3);
                }
                else if(KEYSYM_2_UNICODE.ContainsKey(key)) {
                    //https://raw.githubusercontent.com/xkbcommon/libxkbcommon/master/src/keysym-utf.c
                    this.Key = "" + (char)KEYSYM_2_UNICODE[key];
                    //var ba = Utils.ByteConverter.ToByteArray(unicodeChar, true);
                    //this.Key = UnicodeEncoding.Unicode.GetString(ba);
                }
                else {
                    try {
                        this.Key = ISO_8859.GetString(parentFrame.Data, packetStartIndex + 4, 4);
                    }
                    catch {
                        this.Key = "" + (char)key + " [0x" + key.ToString("x8") + "]";
                    }
                }
            }

            public override string ToString()
            {
                if (Down)
                    return Key + " pressed";
                else
                    return Key + " released";
            }
        }

        public class FixColorMapPacket : VncCommandPacket
        {

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out FixColorMapPacket cmPacket)
            {
                cmPacket = null;
                if (packetStartIndex + 5 > packetEndIndex)
                    return false;
                ushort numberOfColors = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                int length = 6 + 6 * numberOfColors;
                if (packetStartIndex + length > packetEndIndex + 1)
                    return false;
                else
                    cmPacket = new FixColorMapPacket(parentFrame, packetStartIndex, packetStartIndex + length - 1, clientToServer);

                return cmPacket != null;
            }

            public ushort NumberOfColors { get; }
            //https://www.dei.isep.ipp.pt/~asc/normas/rfbproto.pdf
            //https://xvm.scripts.mit.edu/browser/trunk/packages/invirt-vnc-client/RfbProto.java?rev=1588#L889
            //https://libvnc.github.io/doc/html/structrfb_set_colour_map_entries_msg.html
            /**
             * No. of bytes Type [Value] Description
             * 1 message-type
             * 1 padding
             * 2 first-colour
             * 2 number-of-colours
             * [number-of-colours] {
             *      2 red
             *      2 green
             *      2 blue
             *  }
             * */
            private FixColorMapPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                //read length
                NumberOfColors = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                PacketEndIndex = packetStartIndex + 6 + 6 * NumberOfColors - 1;
            }
        }


        public class SetPixelFormatPacket : VncCommandPacket
        {

            /**
             * +--------------+--------------+--------------+
             * | No. of bytes | Type [Value] | Description  |
             * +--------------+--------------+--------------+
             * | 1            | U8 [0]       | message-type |
             * | 3            |              | padding      |
             * | 16           | PIXEL_FORMAT | pixel-format |
             * +--------------+--------------+--------------+
            */

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out SetPixelFormatPacket packet, bool requireZeroValuePadding = true)
            {
                packet = null;
                if (parentFrame.Data[packetStartIndex] != (byte)VncCommand.SetPixelFormat)
                    return false;

                if (packetEndIndex < packetStartIndex + 19)
                    return false;

                if (requireZeroValuePadding) {
                    for (int i = 1; i < 4; i++) {
                        //padding
                        if (parentFrame.Data[packetStartIndex + i] != 0)
                            return false;
                    }
                }


                if (TryParseVncPixelFormat(parentFrame.Data, packetStartIndex + 4, out _))
                {
                    packet = new SetPixelFormatPacket(parentFrame, packetStartIndex, packetStartIndex + 19, clientToServer);
                    return true;
                }
                else
                    return false;
            }
            private SetPixelFormatPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                if (TryParseVncPixelFormat(parentFrame.Data, packetStartIndex + 4, out VncPixelFormat pf))
                {
                    PixelFormat = pf;
                    PacketEndIndex = packetStartIndex + 19;
                }
                else
                    throw new Exception("Unable to parse PixelFormat");
            }

            public new VncCommand? Command
            {
                get { return VncCommand.SetPixelFormat; }
            }

        }

        public class SetEncodingsPacket : VncCommandPacket
        {

            List<uint> Encodings = new List<uint>();

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out SetEncodingsPacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 3)//min 4 bytes
                    return false;
                if (parentFrame.Data[packetStartIndex] != (byte)VncCommand.SetEncodings)
                    return false;
                //one byte padding
                //if (parentFrame.Data[packetStartIndex + 1] != 0)
                //    return false;
                ushort encodingCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                int realPacketEndIndex = packetStartIndex + 3 + encodingCount * 4;
                if (packetEndIndex < realPacketEndIndex)
                    return false;
                //encoding count is a 16 bit number, big endian
                //each encoding is 32 bits (4 bytes)
                packet = new SetEncodingsPacket(parentFrame, packetStartIndex, realPacketEndIndex, clientToServer);
                return true;
            }

            private SetEncodingsPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                ushort encodingCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                for (int i = 0; i < encodingCount; i++)
                {
                    Encodings.Add(Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4 + 4 * i));
                }
            }

            public new VncCommand? Command
            {
                get { return VncCommand.SetEncodings; }
            }
        }

        public class FrameBufferUpdateRequestPacket : VncCommandPacket
        {
            public readonly byte Incremental;
            public readonly ushort X;
            public readonly ushort Y;
            public readonly ushort Width;
            public readonly ushort Height;

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out FrameBufferUpdateRequestPacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 9)
                    return false;
                var x = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                var y = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                var width = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                var height = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
                if (width == 0 || height == 0)
                    return false;
                if (width > MAX_SCREEN_WIDTH || height > MAX_SCREEN_HEIGHT)
                    return false;
                if (x > MAX_SCREEN_WIDTH || y > MAX_SCREEN_HEIGHT)
                    return false;

                packet = new FrameBufferUpdateRequestPacket(parentFrame, packetStartIndex, packetStartIndex + 9, clientToServer);
                return true;
            }

            private FrameBufferUpdateRequestPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                PacketEndIndex = packetStartIndex + 9;//lenth is 10 bytes
                Incremental = parentFrame.Data[packetStartIndex];
                X = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                Y = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
                Width = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                Height = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
            }

        }

        public class ClientCutTextPacket : VncCommandPacket
        {

            public string Text { get; }

            public uint FormatFlags { get; }


            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ClientCutTextPacket clientCutTextPacket)
            {
                clientCutTextPacket = null;

                if (TryGetCutTextPacketLength(parentFrame, packetStartIndex, packetEndIndex, out int cutTextPacketLength))
                {
                    int newPacketEndIndex = packetStartIndex + cutTextPacketLength - 1;
                    clientCutTextPacket = new ClientCutTextPacket(parentFrame, packetStartIndex, newPacketEndIndex, clientToServer);
                }

                return clientCutTextPacket != null;
            }


            private ClientCutTextPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                /**
                 * +--------------+--------------+--------------+
                 * | No. of bytes | Type [Value] | Description  |
                 * +--------------+--------------+--------------+
                 * | 1            | U8 [6]       | message-type |
                 * | 3            |              | padding      |
                 * | 4            | U32          | length       |
                 * | length       | U8 array     | text         |
                 * +--------------+--------------+--------------+
                 * */
                int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (length >= 0)
                {
                    PacketEndIndex = packetStartIndex + 7 + length;
                    Text = ISO_8859.GetString(parentFrame.Data, packetStartIndex + 8, length);
                }
                else
                {
                    //Extended Clipboard Pseudo-Encoding
                    //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                    length = -length;
                    PacketEndIndex = packetStartIndex + 7 + length;
                    /*
                     * 0   text
                     * 1   rtf
                     * 2   html
                     * 3   dib
                     * 4   files
                     * 5 - 15    Reserved for future formats
                     * 16 - 23   Reserved
                     * 24  caps
                     * 25  request
                     * 26  peek
                     * 27  notify
                     * 28  provide
                     * 29 - 31   Reserved for future actions
                     * */
                    FormatFlags = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
                    //skipping the clipboard data here
                }
            }
        }

        public class Rectangle
        {



            /**
             * Example Packet Header:
             * 0000 0001 0000 0000 0040 0040 0000 0006 ???? ???? ???? 
             * t p   1   \ X   Y    w    h   encoding  data         /
             * y a count  `----one rectangle-----------------------´
             * p d
             * e
             */

            /**
             *  +--------+-----------------------------+
             *  | Number | Name                        |
             *  +--------+-----------------------------+
             *  | 0      | Raw                         |
             *  | 1      | CopyRect                    |
             *  | 2      | RRE                         |
             *  | 5      | Hextile                     |
             *  | 15     | TRLE                        |
             *  | 16     | ZRLE                        |
             *  | -239   | Cursor pseudo-encoding      |
             *  | -223   | DesktopSize pseudo-encoding |
             *  +--------+-----------------------------+
             *  
             *  https://en.wikipedia.org/wiki/RFB_protocol#Encoding_types
             *  0x00000000 	Raw
             *  0x00000001 	CopyRect
             *  0x00000002 	RRE (Rising Rectangle Run-length)
             *  0x00000004 	CoRRE (Compact RRE)
             *  0x00000005 	Hextile (RRE Variant)
             *  0x00000006 	Zlib
             *  0x00000007 	Tight
             *  0x00000008 	ZlibHex (Zlib + Hextile)
             *  0x00000009 	Ultra
             *  0x00000010 	ZRLE (Zlib Run-length)
             *  0x00000011 	ZYWRLE
             *  0x00000014 	H.264
             *  0x00000032 	Open H.264
             *  0xFFFF0001 	CacheEnable
             *  0xFFFF0006 	XOREnable
             *  0xFFFF8000 	ServerState (UltraVNC)
             *  0xFFFF8001 	EnableKeepAlive (UltraVNC)
             *  0xFFFF8002 	FTProtocolVersion (File Transfer Protocol Version - UltraVNC)
             *  0xFFFFFEC7 	ContinuousUpdates
             *  0xFFFFFEC8 	Fence
             *  0xFFFFFECC 	ExtendedDesktopSize
             *  0xFFFFFECF 	General Input Interface (GII)
             *  0xFFFFFF00–0xFFFFFF09 	CompressLevel (Tight encoding)
             *  0xFFFFFF10 	XCursor
             *  0xFFFFFF11 	RichCursor
             *  0xFFFFFF18 	PointerPos
             *  0xFFFFFF20 	LastRect
             *  0xFFFFFF21 	NewFBSize
             *  0xFFFFFF74 	Tight PNG
             *  0xFFFFFFE0–0xFFFFFFE9 	QualityLevel (Tight encoding)   
             *  
            */
            public enum FrameBufferEncoding : int {
                Raw = 0,
                CopyRect = 1,
                RRE = 2,
                Hextile = 5,
                Zlib = 6,
                Tight = 7,
                ZlibHex = 8,
                Ultra = 9,

                TRLE = 15,
                ZRLE = 16,
                JPEG = 21,
                
                ExtendedDesktopSize = -308,//ffff fecc
                XCursor = -240,//ffff ff10
                Cursor = -239,//ffff ff11
                PointerPosition = -232,//FFFF FF18
                LastRect = -224,//FFFF FF20 Used in Tight encoding to denote that there are no more rectangles
                DesktopSize = -223,//ffff ff21 = NewFBSize
                
            }

            /**
             * #define VNC_ENCODING_TYPE_DESKTOP_SIZE       0xFFFFFF21
#define VNC_ENCODING_TYPE_LAST_RECT          0xFFFFFF20
#define VNC_ENCODING_TYPE_POINTER_POS        0xFFFFFF18
#define VNC_ENCODING_TYPE_RICH_CURSOR        0xFFFFFF11
#define VNC_ENCODING_TYPE_X_CURSOR           0xFFFFFF10
#define VNC_ENCODING_TYPE_RAW                0
#define VNC_ENCODING_TYPE_COPY_RECT          1
#define VNC_ENCODING_TYPE_RRE                2
#define VNC_ENCODING_TYPE_CORRE              4
#define VNC_ENCODING_TYPE_HEXTILE            5
#define VNC_ENCODING_TYPE_ZLIB	             6
#define VNC_ENCODING_TYPE_TIGHT	             7
#define VNC_ENCODING_TYPE_ZLIBHEX            8
#define VNC_ENCODING_TYPE_ULTRA	             9
#define VNC_ENCODING_TYPE_TRLE	             15
#define VNC_ENCODING_TYPE_RLE	             16
#define VNC_ENCODING_TYPE_HITACHI_ZYWRLE     17
#define VNC_ENCODING_TYPE_JPEG_0             -32
#define VNC_ENCODING_TYPE_JPEG_1             -31
#define VNC_ENCODING_TYPE_JPEG_2             -30
#define VNC_ENCODING_TYPE_JPEG_3             -29
#define VNC_ENCODING_TYPE_JPEG_4             -28
#define VNC_ENCODING_TYPE_JPEG_5             -27
#define VNC_ENCODING_TYPE_JPEG_6             -26
#define VNC_ENCODING_TYPE_JPEG_7             -25
#define VNC_ENCODING_TYPE_JPEG_8             -24
#define VNC_ENCODING_TYPE_JPEG_9             -23
#define VNC_ENCODING_TYPE_COMPRESSION_0      0xFFFFFF00
#define VNC_ENCODING_TYPE_COMPRESSION_1      0xFFFFFF01
#define VNC_ENCODING_TYPE_COMPRESSION_2      0xFFFFFF02
#define VNC_ENCODING_TYPE_COMPRESSION_3      0xFFFFFF03
#define VNC_ENCODING_TYPE_COMPRESSION_4      0xFFFFFF04
#define VNC_ENCODING_TYPE_COMPRESSION_5      0xFFFFFF05
#define VNC_ENCODING_TYPE_COMPRESSION_6      0xFFFFFF06
#define VNC_ENCODING_TYPE_COMPRESSION_7      0xFFFFFF07
#define VNC_ENCODING_TYPE_COMPRESSION_8      0xFFFFFF08
#define VNC_ENCODING_TYPE_COMPRESSION_9      0xFFFFFF09
#define VNC_ENCODING_TYPE_WMVi               0x574D5669
#define VNC_ENCODING_TYPE_CACHE              0xFFFF0000
#define VNC_ENCODING_TYPE_CACHE_ENABLE       0xFFFF0001
#define VNC_ENCODING_TYPE_XOR_ZLIB           0xFFFF0002
#define VNC_ENCODING_TYPE_XOR_MONO_ZLIB      0xFFFF0003
#define VNC_ENCODING_TYPE_XOR_MULTI_ZLIB     0xFFFF0004
#define VNC_ENCODING_TYPE_SOLID_COLOR        0xFFFF0005
#define VNC_ENCODING_TYPE_XOR_ENABLE         0xFFFF0006
#define VNC_ENCODING_TYPE_CACHE_ZIP          0xFFFF0007
#define VNC_ENCODING_TYPE_SOL_MONO_ZIP       0xFFFF0008
#define VNC_ENCODING_TYPE_ULTRA_ZIP          0xFFFF0009
#define VNC_ENCODING_TYPE_SERVER_STATE       0xFFFF8000
#define VNC_ENCODING_TYPE_ENABLE_KEEP_ALIVE  0xFFFF8001
#define VNC_ENCODING_TYPE_FTP_PROTO_VER      0xFFFF8002
#define VNC_ENCODING_TYPE_POINTER_CHANGE     -257
#define VNC_ENCODING_TYPE_EXT_KEY_EVENT      -258
#define VNC_ENCODING_TYPE_AUDIO               259
#define VNC_ENCODING_TYPE_DESKTOP_NAME       -307
#define VNC_ENCODING_TYPE_EXTENDED_DESK_SIZE -308
#define VNC_ENCODING_TYPE_KEYBOARD_LED_STATE 0XFFFE0000
#define VNC_ENCODING_TYPE_SUPPORTED_MESSAGES 0XFFFE0001
#define VNC_ENCODING_TYPE_SUPPORTED_ENCODINGS 0XFFFE0002
#define VNC_ENCODING_TYPE_SERVER_IDENTITY    0XFFFE0003
#define VNC_ENCODING_TYPE_MIRRORLINK         0xFFFFFDF5
#define VNC_ENCODING_TYPE_CONTEXT_INFORMATION 0xFFFFFDF4
#define VNC_ENCODING_TYPE_SLRLE              0xFFFFFDF3
#define VNC_ENCODING_TYPE_TRANSFORM          0xFFFFFDF2
#define VNC_ENCODING_TYPE_HSML               0xFFFFFDF1
#define VNC_ENCODING_TYPE_H264               0X48323634
            */

            public const int HEADER_LENGTH = 12;

            public readonly ushort X;
            public readonly ushort Y;
            public readonly ushort Width;
            public readonly ushort Height;
            public readonly int Encoding;

            public int ParsedBytes
            {
                get
                {
                    if (this.RectangleData == null)
                    {
                        return HEADER_LENGTH;
                    }
                    else
                        return HEADER_LENGTH + this.RectangleData.Length;
                }
            }

            private IRectangleData rectangleData = null;
            public IRectangleData RectangleData
            {
                get
                {
                    return rectangleData;
                }
                private set
                {
                    rectangleData = value;
                    if (value != null)
                        this.RectangleDataLength = value.Length;
                }
            }

            public int RectangleDataLength { get; private set; } = -1;//unknown

            public int TotalLenght {
                get {
                    if (this.RectangleData == null) {
                        if (this.RectangleDataLength < 0)
                            return -1;
                        else
                            return HEADER_LENGTH + this.RectangleDataLength;
                    }
                    else
                        return HEADER_LENGTH + this.RectangleData.Length;
                }
            }

            public bool TryGetEncoding(out FrameBufferEncoding encoding)
            {
                if (Enum.IsDefined(typeof(FrameBufferEncoding), Encoding))
                {
                    encoding = (FrameBufferEncoding)Encoding;
                    return true;
                }
                else
                {
                    encoding = default;
                    return false;
                }
            }

            private Rectangle(byte[] data, int offset)
            {
                X = Utils.ByteConverter.ToUInt16(data, offset);
                Y = Utils.ByteConverter.ToUInt16(data, offset + 2);
                Width = Utils.ByteConverter.ToUInt16(data, offset + 4);
                Height = Utils.ByteConverter.ToUInt16(data, offset + 6);
                Encoding = (int)Utils.ByteConverter.ToUInt32(data, offset + 8);
            }

            [Obsolete]
            internal static bool TryParse(byte[] data, int offset, out Rectangle rectangle) {
                return TryParse(data, offset, null, false, out rectangle);
            }

            public static bool TryParse(byte[] data, int offset, VncPixelFormat? pixelFormat, bool requireFullParseout, out Rectangle rectangle) { 
                rectangle = null;
                if (data.Length < offset + HEADER_LENGTH)
                    return false;

                rectangle = new Rectangle(data, offset);
                if (rectangle.Width > MAX_SCREEN_WIDTH || rectangle.Height > MAX_SCREEN_HEIGHT)
                    return false;
                if (rectangle.X > MAX_SCREEN_WIDTH || rectangle.Y > MAX_SCREEN_HEIGHT)
                    return false;

                if(rectangle.TryGetEncoding(out FrameBufferEncoding encoding)) { 
                    //if (Enum.IsDefined(typeof(FrameBufferEncoding), rectangle.Encoding)) {
                    //FrameBufferEncoding encoding = (FrameBufferEncoding)rectangle.Encoding;
                    if (encoding == FrameBufferEncoding.Zlib) {
                        //00 00 00 06
                        if (ZlibRectangleData.TryGetZlibRectangleDataLength(data, offset + HEADER_LENGTH, out int length)) {
                            rectangle.RectangleDataLength = length;
                            if (requireFullParseout || length < 5000) {
                                if (ZlibRectangleData.TryParse(data, offset + HEADER_LENGTH, out ZlibRectangleData rectangleData)) {
                                    rectangle.RectangleData = rectangleData;

                                    return true;
                                }
                                else
                                    return false;
                            }
                            else {
                                return true;//leave RectangleData as null to trigger a file reassembly
                            }
                        }
                        return false;
                    }
                    else if(encoding == FrameBufferEncoding.Tight) {
                        //00 00 00 07
                        rectangle.RectangleDataLength = 2;
                        if (data.Length >= offset + HEADER_LENGTH + 2) {
                            if(TightRectangleData.TryParse(data, offset + HEADER_LENGTH, pixelFormat, out TightRectangleData rectangleData)) {
                                rectangle.RectangleData = rectangleData;
                                return true;
                            }
                            else
                                return false;
                        }
                        else if (requireFullParseout)
                            return false;
                        else
                            return true;
                    }
                    else if (encoding == FrameBufferEncoding.XCursor) {
                        //ff ff ff 10
                        if (XCursorRectangleData.TryParse(data, offset + HEADER_LENGTH, data.Length - HEADER_LENGTH - offset, rectangle.Width, rectangle.Height, out XCursorRectangleData xCursor)) {
                            rectangle.RectangleData = xCursor;
                            return true;
                        }
                        else
                            return false;
                    }
                    else if (encoding == FrameBufferEncoding.Cursor) {
                        //ff ff ff 11
                        if (pixelFormat.HasValue) {
                            int bitsPerPixel = pixelFormat.Value.BitsPerPixel;
                            if (CursorRectangleData.TryParse(data, offset + HEADER_LENGTH, data.Length - offset - HEADER_LENGTH, rectangle.Width, rectangle.Height, bitsPerPixel, out CursorRectangleData cursorData)) {
                                rectangle.RectangleData = cursorData;
                                return true;
                            }
                            else
                                return false;
                        }
                        else if (requireFullParseout)
                            return false;
                        else {
                            //bits per pixel is unknown here but known at PacketParser. Requiring a file reassembly will trigger the PacketParser to read the rectangle data instead
                            return true;//leave RectangleData as null to trigger a file reassembly
                        }
                    }
                    else if(encoding == FrameBufferEncoding.PointerPosition) {
                        //ff ff ff 18
                        rectangle.rectangleData = new BasicRectangleData(new byte[0]);//there is no data
                        rectangle.RectangleDataLength = 0;
                        return true;
                    }
                    else if (encoding == FrameBufferEncoding.LastRect) {
                        //ff ff ff 20
                        rectangle.rectangleData = new BasicRectangleData(new byte[0]);//there is no data
                        rectangle.RectangleDataLength = 0;
                        return true;
                    }
                }
                return false;//encoding is not implemented
            }

            public override string ToString()
            {
                string xywh = "x=" + X + " y=" + Y + " w=" + Width + " h=" + Height;

                if (TryGetEncoding(out FrameBufferEncoding fbEncoding))
                    return xywh + " encoding=" + fbEncoding.ToString() + "(" + Encoding + ")";
                else
                    return xywh + " encoding=" + Encoding;
            }

            #region RectangleData

            public interface IRectangleData
            {
                int Length { get; }

                byte[] ImageBytes { get; }
            }

            public class BasicRectangleData : IRectangleData {
                public int Length {
                    get {
                        return this.ImageBytes.Length;
                    }
                }

                public byte[] ImageBytes { get; }

                internal BasicRectangleData(byte[] imageBytes) {
                    this.ImageBytes = imageBytes;
                }
            }

            public class XCursorRectangleData : IRectangleData
            {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#x-cursor-pseudo-encoding
                public int Length
                {
                    get;
                }

                public byte[] ImageBytes
                {
                    get;
                }

                private static int CountBitmapBytes(int width, int height)
                {
                    return (width + 7) / 8 * height;
                }

                internal static bool TryParse(byte[] data, int offset, int maxLength, int width, int height, out XCursorRectangleData xCursorData)
                {
                    xCursorData = null;
                    int bitmapBytes = CountBitmapBytes(width, height);
                    int maskBytes = CountBitmapBytes(width, height);
                    int length = 6 + bitmapBytes + maskBytes;
                    if (length > maxLength)
                        return false;
                    else if (offset + length > data.Length)
                        return false;
                    else
                        xCursorData = new XCursorRectangleData(data, offset, length);
                    return xCursorData != null;
                }

                XCursorRectangleData(byte[] data, int offset, int length) : this(length)
                {
                    this.ImageBytes = new byte[length];
                    Array.Copy(data, offset, ImageBytes, 0, length);
                }
                XCursorRectangleData(int length)
                {
                    this.Length = length;
                }
            }

            public class CursorRectangleData : IRectangleData
            {
                public int Length
                {
                    get;
                }

                public byte[] ImageBytes
                {
                    get;
                }

                public static int GetLength(int width, int height, int bitsPerPixel)
                {
                    int pixelBytes = width * height * (bitsPerPixel / 8);
                    int maskBytes = (width + 7) / 8 * height;
                    return pixelBytes + maskBytes;
                }

                internal static bool TryParse(byte[] data, int offset, int maxLength, int width, int height, int bitsPerPixel, out CursorRectangleData cursorData)
                {
                    cursorData = null;
                    /*
                    int pixelBytes = width * height * (bitsPerPixel/8);
                    int maskBytes = ((width + 7) / 8) * height;
                    int length =  pixelBytes + maskBytes;
                    */
                    int length = GetLength(width, height, bitsPerPixel);
                    if (length > maxLength || offset + length > data.Length)
                        return false;
                    else
                    {
                        //cursorData = new CursorRectangleData(length);
                        cursorData = new CursorRectangleData(data, offset, length);
                    }
                    return cursorData != null;
                }


                CursorRectangleData(byte[] data, int offset, int length) : this(length)
                {
                    ImageBytes = new byte[length];
                    Array.Copy(data, offset, ImageBytes, 0, length);
                }
                private CursorRectangleData(int length)
                {
                    Length = length;
                }
            }

            public class ZlibRectangleData : IRectangleData
            {
                //argh! ZLibStream requires .NET 7 or later!
                //But zlib can be parsed as gzip by replacing the first 2 bytes (78 01) with:
                //1f8b 0800 0000 0000 0000

                /** Example rectangle data (Zlib = 6):
                 * 0000 0027 7801 ecc0 310d 0000 00c2 b0cc 
                 * bf69 64f0 b405 0000 0000 0000 0000 0000 
                 * 0000 0000 00bc 0d00 00ff ff   
                 * 
                 * Or (concated with another header):
                 * 0000 0027 7801 ecc0 310d 0000 00c2 b0cc  
                 * bf69 64f0 b405 0000 0000 0000 0000 0000  
                 * 0000 0000 00bc 0d00 00ff ff
                 * 
                 *                            00 0000 0100  
                 * 4000 0000 4000 4000 0000 0600 0000 24ec  
                 * c021 0100 0000 80a0 ffaf 9d61 0100 0000  
                 * 0000 0000 0000 0000 0000 0000 e017 0000  
                 * 00ff ff00 0000 0100 8000 0000 4000 4000  
                 * 0000 0600 0000 24ec c021 0100 0000 80a0  
                 * ffaf 9d61 0100 0000 0000 0000 0000 0000  
                 * 0000 0000 e017 0000 00ff ff00 0000 0100  
                 * c000 0000 4000 4000 0000 0600 0000 24ec  
                 * c021 0100 0000 80a0 ffaf 9d61 0100 0000  
                 * 0000 0000 0000 0000 0000 0000 e017 0000  
                 * 00ff ff  
                 * 
                 **/

                public int Length { get; }

                public byte[] ImageBytes
                {
                    get;
                }

                internal ZlibRectangleData(byte[] data, int dataOffset)
                {
                    int imageByteLength = (int)Utils.ByteConverter.ToUInt32(data, dataOffset);
                    this.Length = imageByteLength + 4;
                    this.ImageBytes = new byte[imageByteLength];
                    Array.Copy(data, dataOffset + 4, this.ImageBytes, 0, imageByteLength);
                }

                public static bool TryGetZlibRectangleDataLength(byte[] data, int offset, out int length)
                {
                    if (data.Length < offset + 4)
                    {
                        length = 0;
                        return false;
                    }
                    else
                    {
                        length = 4 + (int)Utils.ByteConverter.ToUInt32(data, offset);
                        return true;
                    }
                }

                internal static bool TryParse(byte[] data, int dataOffset, out ZlibRectangleData result)
                {
                    result = null;

                    if (TryGetZlibRectangleDataLength(data, dataOffset, out int dataLength))
                    {
                        if (data.Length < dataOffset + dataLength)
                            return false;
                        else
                        {
                            result = new ZlibRectangleData(data, dataOffset);
                            return true;
                        }
                    }
                    else
                        return false;
                }
            }

            public class TightRectangleData : IRectangleData {
                //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#767tight-encoding

                public enum CompressionMethod : byte {
                    Basic_s0 = 0,//b0000
                    Basic_s1 = 1,//b0001
                    Basic_s2 = 2,//b0010
                    Basic_s3 = 3,//b0011
                    Basic_read_filter_s0 = 4,//b0100
                    Basic_read_filter_s1 = 5,//b0101
                    Basic_read_filter_s2 = 6,//b0110
                    Basic_read_filter_s3 = 7,//b0111
                    Fill = 8,//b1000
                    Jpeg = 9,//b1001
                }

                private static bool TryGetCompactLength(byte[] data, int offset, out int imageLength, out int parsedBytes) {
                    /**
                     * 0xxxxxxx 	for values 0..127
                     * 1xxxxxxx 0yyyyyyy 	for values 128..16383
                     * 1xxxxxxx 1yyyyyyy zzzzzzzz 	for values 16384..4194303
                     * 
                     * 10.000 (0x2710) (b0010011100010000) is represented as:
                     * (0x904E)  10010000 01001110
                     **/
                    if (data.Length > offset) {
                        parsedBytes = 1;
                        byte x = data[offset];
                        imageLength = (x & 0x7f);//xxxxxxx are the least significant 7 bits
                        if (x < 128)
                            return true;
                        else if(data.Length > offset + 1) {
                            parsedBytes = 2;
                            byte y = data[offset + 1];
                            imageLength += (y & 0x7f) << 7;//yyyyyyy are bits 7-13
                            if (y < 128)
                                return true;
                            else if(data.Length > offset + 2) {
                                parsedBytes = 3;
                                byte z = data[offset + 2];
                                imageLength += z << 14;//zzzzzzzz are the most significant 8 bits (bits 14-21)
                                return true;
                            }
                        }
                    }
                    else {
                        imageLength = 0;
                        parsedBytes = 0;
                    }
                    return false;
                }

                private readonly byte resetStreamFlags;

                public int Length { get; }

                public byte Compression { get; }

                public CompressionMethod? CompressionMethodOrNull { get; }

                public RfbColor[] PaletteColors { get; } = null;
                public byte[] ImageBytes { get; }

                
                public IEnumerable<int> GetResetStreams() { 
                    for(int i = 0; i < 4; i++)
                        if(((this.resetStreamFlags >> i) & 0x01) == 0x01)
                            yield return i;
                }

                internal static bool TryParse(byte[] data, int dataOffset, VncPixelFormat? pixelFormat, out TightRectangleData result) {
                    result = null;

                    if (data.Length >= dataOffset + 2) {
                        byte compression = (byte)(data[dataOffset] >> 4);
                        
                        if (Enum.IsDefined(typeof(CompressionMethod), compression)) {
                            CompressionMethod cm = (CompressionMethod)compression;
                            if(cm == CompressionMethod.Fill) {
                                //one pixel
                                if(pixelFormat.HasValue) {
                                    if (data.Length > dataOffset + pixelFormat.Value.BytesPerPixel) {
                                        result = new TightRectangleData(data, dataOffset, pixelFormat.Value);
                                        return true;
                                    }
                                }
                                return false;
                            }
                            else if(TryGetLengthOffset(data, dataOffset, cm, pixelFormat, out int lengthOffset)) {
                                if (TryGetCompactLength(data, lengthOffset, out int imageLength, out int parsedBytes)) {
                                    if (data.Length >= lengthOffset + parsedBytes + imageLength) {
                                        result = new TightRectangleData(data, dataOffset, pixelFormat);
                                        return true;
                                    }
                                }
                            }
                            
                        }
                        else if (compression < 8) {
                            //will this code ever run??
                            //If the bit 7 (the most significant bit) of the compression-control byte is 0, then the compression type is BasicCompression
                            result = new TightRectangleData(data, dataOffset, pixelFormat);
                            return true;
                        }
                    }
                    return false;
                }

                private static bool TryGetLengthOffset(byte[] data, int dataOffset, CompressionMethod cm, VncPixelFormat? pixelFormat, out int lengthOffset) {
                    //dataOffset typically points to the encoding/compression byte
                    if (cm == CompressionMethod.Fill) {
                        lengthOffset = -1;
                        return false;//no length
                    }

                    lengthOffset = dataOffset + 1;
                    if (cm == CompressionMethod.Basic_read_filter_s0 ||
                        cm == CompressionMethod.Basic_read_filter_s1 ||
                        cm == CompressionMethod.Basic_read_filter_s2 ||
                        cm == CompressionMethod.Basic_read_filter_s3) {
                        if (data.Length <= dataOffset + 1)
                            return false;

                        //one byte filter ID
                        byte filterID = data[dataOffset + 1];
                        lengthOffset++;
                        if (filterID == 1) {
                            //palette filter
                            if (pixelFormat.HasValue) {
                                lengthOffset++;
                                if (data.Length <= dataOffset + 2)
                                    return false;
                                int colors = 1 + data[dataOffset + 2];
                                lengthOffset += colors * pixelFormat.Value.BytesPerPixel;
                            }
                            else
                                return false;
                        }
                    }
                    return true;
                }

                private TightRectangleData(byte[] data, int dataOffset, VncPixelFormat? pixelFormat) {
                    this.Compression = (byte)(data[dataOffset] >> 4);
                    this.resetStreamFlags = (byte)(data[dataOffset] & 0x0f);


                    if (Enum.IsDefined(typeof(CompressionMethod), this.Compression)) {
                        this.CompressionMethodOrNull = (CompressionMethod)this.Compression;
                        if (this.CompressionMethodOrNull.Value == CompressionMethod.Fill) {
                            //we need to know the pixelFormat
                            //int bytesPerPixel = (pixelFormat.Value.BitsPerPixel + 7) /8;
                            this.Length = 1 + pixelFormat.Value.BytesPerPixel;
                            this.ImageBytes = data.Skip(dataOffset).Take(this.Length).ToArray();
                        }
                        else if(TryGetLengthOffset(data, dataOffset, this.CompressionMethodOrNull.Value, pixelFormat, out int lengthOffset)) {

                            if (this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s0 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s1 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s2 ||
                                this.CompressionMethodOrNull.Value == CompressionMethod.Basic_read_filter_s3) {

                                //one byte filter ID
                                byte filterID = data[dataOffset + 1];
                                
                                if (filterID == 1) {
                                    //palette filter
                                    if (pixelFormat.HasValue) {
                                        
                                        int colors = 1 + data[dataOffset + 2];
                                        this.PaletteColors = new RfbColor[colors];
                                        for(int i = 0; i < colors; i++) {
                                            if(pixelFormat.Value.TryGetColor(data, dataOffset + 3 + i * pixelFormat.Value.BytesPerPixel, out RfbColor color))
                                                this.PaletteColors[i] = color;
                                        }
                                    }
                                }
                            }

                            if (TryGetCompactLength(data, lengthOffset, out int dataLength, out int parsedLengthBytes)) {
                                this.Length = lengthOffset - dataOffset + parsedLengthBytes + dataLength;
                                this.ImageBytes = data.Skip(lengthOffset + parsedLengthBytes).Take(dataLength).ToArray();
                            }
                            else
                                throw new IndexOutOfRangeException("Incomplete TightRectangleData Length");
                        }
                        else
                            throw new IndexOutOfRangeException("Incomplete TightRectangleData");
                    }
                    else if (this.Compression < 8) {
                        //will this code ever run?
                        //If the bit 7 (the most significant bit) of the compression-control byte is 0, then the compression type is BasicCompression
                        this.Length = 2;
                        this.ImageBytes = data.Skip(dataOffset).Take(2).ToArray();
                    }
                }
            }


            #endregion

        }

        public class ServerCutTextPacket : VncResponsePacket
        {

            public string Text { get; }

            public uint FormatFlags { get; }

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out ServerCutTextPacket serverCutTextPacket)
            {
                serverCutTextPacket = null;

                if (TryGetCutTextPacketLength(parentFrame, packetStartIndex, packetEndIndex, out int cutTextPacketLength))
                {
                    int newPacketEndIndex = packetStartIndex + cutTextPacketLength - 1;
                    serverCutTextPacket = new ServerCutTextPacket(parentFrame, packetStartIndex, newPacketEndIndex, clientToServer);
                }

                return serverCutTextPacket != null;
            }

            /**
             *  +--------------+--------------+--------------+
             *  | No. of bytes | Type [Value] | Description  |
             *  +--------------+--------------+--------------+
             *  | 1            | U8 [3]       | message-type |
             *  | 3            |              | padding      |
             *  | 4            | U32          | length       |
             *  | length       | U8 array     | text         |
             *  +--------------+--------------+--------------+
             * 
             * */
                    public ServerCutTextPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                int length = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
                if (length >= 0)
                {
                    this.PacketEndIndex = packetStartIndex + 7 + length;
                    this.Text = ISO_8859.GetString(parentFrame.Data, packetStartIndex + 8, length);
                }
                else
                {
                    //Extended Clipboard Pseudo-Encoding
                    //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#extended-clipboard-pseudo-encoding
                    length = -length;
                    this.PacketEndIndex = packetStartIndex + 7 + length;
                    /*
                     * 0        text
                     * 1        rtf
                     * 2        html
                     * 3        dib
                     * 4        files
                     * 5 - 15   Reserved for future formats
                     * 16 - 23  Reserved
                     * 24       caps
                     * 25       request
                     * 26       peek
                     * 27       notify
                     * 28       provide
                     * 29 - 31  Reserved for future actions
                     * */
                    this.FormatFlags = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
                }

            }
        }


        public class FrameBufferUpdatePacket : VncResponsePacket
        {
            //https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst
            //https://www.iana.org/assignments/rfb/rfb.xml#rfb-4
            //https://github.com/ultravnc/UltraVNC/blob/ee9954b90ab6b52a2332b349d55f6a98af3f7424/rfb/rfbproto.h#L460-L503

            /**
             * Example Packet Header:
             * 0000 0001 0000 0000 0040 0040 0000 0006 ???? ???? ???? 
             * t p   1   \ X   Y    w    h   encoding  data         /
             * y a count  `----one rectangle-----------------------´
             * p d
             * e
             * 
             * 0000 0001 0002 0002 0020 0020 ffff ff10
             * t p   1    X     Y    w   h   enc  data
             */

            public readonly Rectangle[] Rectangles = null;
            
            public ushort RectangleCount { get; }

            public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, bool parseRectangles, out FrameBufferUpdatePacket packet)
            {
                packet = null;
                if (packetEndIndex < packetStartIndex + 3)
                    return false;
                ushort rectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if(rectangleCount == 0)
                    return false;
                if (parseRectangles) {
                    if (rectangleCount == 0xffff) {
                        //number of rectangles is unknown
                    }
                    else {
                        var minPacketEndIndex = packetStartIndex + 3 + Rectangle.HEADER_LENGTH * rectangleCount;
                        if (minPacketEndIndex > packetEndIndex)
                            return false;
                    }
                    try {
                        //verify that we have enough data to parse all rectangles
                        //uint rectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                        int index = packetStartIndex + 4;
                        for (int i = 0; i < rectangleCount; i++) {
                            if (Rectangle.TryParse(parentFrame.Data, index, null, true, out Rectangle rectangle)) {
                                if (rectangle.TryGetEncoding(out var enc) && enc == Rectangle.FrameBufferEncoding.LastRect) {
                                    rectangleCount = (ushort)(i + 1);
                                    break;
                                }
                                if (rectangle.ParsedBytes < 1)
                                    return false;//to prevent an infinite loop
                                index += rectangle.TotalLenght;
                            }
                            else
                                return false;
                        }
                        packet = new FrameBufferUpdatePacket(parentFrame, packetStartIndex, index - 1, clientToServer, true);
                        return true;
                    }
                    catch { return false; }
                }
                else {
                    packet = new FrameBufferUpdatePacket(parentFrame, packetStartIndex, packetStartIndex + 3, clientToServer, false);
                    return true;
                }
            }

            private FrameBufferUpdatePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, bool parseRectangles) : base(parentFrame, packetStartIndex, packetEndIndex, clientToServer)
            {
                this.RectangleCount = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if (parseRectangles) {
                    //Rectangles = new Rectangle[this.RectangleCount];
                    List<Rectangle> rectangleList = new List<Rectangle>();
                    int index = packetStartIndex + 4;
                    for (int i = 0; i < this.RectangleCount; i++) {
                        if (Rectangle.TryParse(parentFrame.Data, index, null, true, out Rectangle rectangle)) {
                            rectangleList.Add(rectangle);
                            index += rectangle.TotalLenght;
                            if (rectangle.TryGetEncoding(out var enc) && enc == Rectangle.FrameBufferEncoding.LastRect) {
                                this.RectangleCount = (ushort)rectangleList.Count();
                                break;
                            }
                        }
                        else
                            throw new Exception("Cannot parse rectangle " + i);
                    }
                    if (rectangleList.Count > 0)
                        this.Rectangles = rectangleList.ToArray();
                    this.PacketEndIndex = index - 1;
                }
                else {
                    //don't parse rectangles
                    this.PacketEndIndex = packetStartIndex + 3;
                }
            }
        }
        #endregion
    }



}
