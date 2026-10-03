//  NetworkMiner CLI - a headless command-line interface to the NetworkMiner engine
//  Copyright: Erik Hjelmvik, NETRESEC (original NetworkMiner)
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Threading;
using PacketParser;
using PacketHandlerFramework;
using PacketHandlerFramework.Events;
using PacketHandlerFramework.FileTransfer;
using SharedUtils.Pcap;

namespace NetworkMinerCLI {
    internal static class Program {

        private sealed class Options {
            public string PcapPath;
            public string OutputDir;
            public bool Csv;
            public bool Verbose;
            public bool Quiet;
            public bool NoFiles;
            public bool ShowHelp;
        }

        private static int Main(string[] args) {
            Options opts = ParseArgs(args);
            if (opts.ShowHelp || opts.PcapPath == null) {
                PrintUsage();
                return opts.ShowHelp ? 0 : 1;
            }

            if (!File.Exists(opts.PcapPath)) {
                Console.Error.WriteLine("Error: file not found: " + opts.PcapPath);
                return 2;
            }

            string exePath = GetExecutablePath();
            string outputDir = opts.OutputDir;
            if (string.IsNullOrEmpty(outputDir)) {
                string pcapDir = Path.GetDirectoryName(Path.GetFullPath(opts.PcapPath));
                outputDir = Path.Combine(pcapDir, "NetworkMinerCLI-Output");
            }
            Directory.CreateDirectory(outputDir);
            string assembledFilesDir = Path.Combine(outputDir, "AssembledFiles");
            Directory.CreateDirectory(assembledFilesDir);
            Directory.CreateDirectory(Path.Combine(assembledFilesDir, "cache"));

            if (!opts.Quiet) {
                Console.WriteLine("NetworkMiner CLI 3.1.0");
                Console.WriteLine("Input  : " + Path.GetFullPath(opts.PcapPath));
                Console.WriteLine("Output : " + Path.GetFullPath(outputDir));
                Console.WriteLine();
            }

            var hosts = new ConcurrentQueue<NetworkHost>();
            var sessions = new ConcurrentQueue<SessionEventArgs>();
            var credentials = new ConcurrentQueue<NetworkCredential>();
            var files = new ConcurrentQueue<ReconstructedFile>();
            var dnsRecords = new ConcurrentQueue<DnsRecordEventArgs>();
            var messages = new ConcurrentQueue<MessageEventArgs>();

            PacketHandler packetHandler;
            try {
                packetHandler = new PacketHandler(
                    exePath,
                    outputDir,
                    null,
                    true,
                    d => d.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                    false,
                    false,
                    10,
                    null);
            }
            catch (Exception ex) {
                Console.Error.WriteLine("Error initializing PacketHandler: " + ex.Message);
                return 3;
            }

            packetHandler.NetworkHostDetected += (s, he) => hosts.Enqueue(he.Host);
            packetHandler.SessionDetected += (s, se) => sessions.Enqueue(se);
            packetHandler.CredentialDetected += (s, ce) => credentials.Enqueue(ce.Credential);
            packetHandler.FileReconstructed += (s, fe) => files.Enqueue(fe.File);
            packetHandler.DnsRecordDetected += (s, de) => dnsRecords.Enqueue(de);
            packetHandler.MessageDetected += (s, me) => messages.Enqueue(me);

            packetHandler.StartBackgroundThreads();

            DateTime startTime = DateTime.Now;
            long frameCount = 0;
            try {
                using (var pcapReader = new PcapFileReader(opts.PcapPath)) {
                    if (!opts.Quiet)
                        Console.Write("Parsing... ");
                    foreach (PcapFrame pcapFrame in pcapReader.PacketEnumerator()) {
                        try {
                            Frame frame = packetHandler.GetFrame(
                                pcapFrame.Timestamp,
                                pcapFrame.Data,
                                pcapFrame.DataLinkType,
                                pcapFrame.Tag);
                            packetHandler.AddFrameToFrameParsingQueue(frame);
                            frameCount++;
                            if (opts.Verbose && frameCount % 1000 == 0)
                                Console.Error.Write("\rFrames: {0}  Queue: {1}  ", frameCount, packetHandler.FramesInQueue);
                        }
                        catch (Exception ex) {
                            if (opts.Verbose)
                                Console.Error.WriteLine("\nFrame {0} error: {1}", frameCount, ex.Message);
                        }
                    }
                    while (packetHandler.FramesInQueue > 0 || packetHandler.PacketsInQueue > 0) {
                        Thread.Sleep(50);
                        if (opts.Verbose)
                            Console.Error.Write("\rWaiting: frames={0} packets={1}  ", packetHandler.FramesInQueue, packetHandler.PacketsInQueue);
                    }
                }
            }
            catch (Exception ex) {
                Console.Error.WriteLine("Error reading pcap: " + ex.Message);
                packetHandler.AbortBackgroundThreads();
                return 4;
            }

            Thread.Sleep(500);

            packetHandler.SetUndecidedProtocolsToUnknown();

            foreach (var h in packetHandler.NetworkHostList.Hosts) {
                if (!hosts.Contains(h))
                    hosts.Enqueue(h);
            }

            packetHandler.AbortBackgroundThreads();

            TimeSpan elapsed = DateTime.Now - startTime;
            if (opts.Verbose)
                Console.Error.WriteLine();

            if (!opts.Quiet) {
                Console.WriteLine("Parsed {0} frames in {1:F2}s", frameCount, elapsed.TotalSeconds);
                Console.WriteLine();
            }

            if (opts.Csv)
                PrintCsv(hosts, sessions, credentials, files, dnsRecords, messages, opts);
            else
                PrintTables(hosts, sessions, credentials, files, dnsRecords, messages, opts);

            return 0;
        }

        private static Options ParseArgs(string[] args) {
            var opts = new Options();
            for (int i = 0; i < args.Length; i++) {
                string a = args[i];
                switch (a) {
                    case "-h":
                    case "--help":
                        opts.ShowHelp = true;
                        break;
                    case "-o":
                    case "--output":
                        if (i + 1 < args.Length) opts.OutputDir = args[++i];
                        break;
                    case "--csv":
                        opts.Csv = true;
                        break;
                    case "-v":
                    case "--verbose":
                        opts.Verbose = true;
                        break;
                    case "-q":
                    case "--quiet":
                        opts.Quiet = true;
                        break;
                    case "--no-files":
                        opts.NoFiles = true;
                        break;
                    default:
                        if (!a.StartsWith("-") && opts.PcapPath == null)
                            opts.PcapPath = a;
                        break;
                }
            }
            return opts;
        }

        private static void PrintUsage() {
            Console.WriteLine("NetworkMiner CLI 3.1.0 - headless network forensics for PCAP files");
            Console.WriteLine();
            Console.WriteLine("Usage: NetworkMinerCLI <pcap-file> [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  -o, --output <dir>   Output directory (default: <pcap-dir>/NetworkMinerCLI-Output)");
            Console.WriteLine("      --csv            Output results as CSV instead of tables");
            Console.WriteLine("  -v, --verbose        Verbose progress output to stderr");
            Console.WriteLine("  -q, --quiet          Minimal output (errors only)");
            Console.WriteLine("      --no-files       Don't list extracted files");
            Console.WriteLine("  -h, --help           Show this help");
            Console.WriteLine();
            Console.WriteLine("Extracted files are written to <output>/AssembledFiles/");
            Console.WriteLine("Supported formats: libpcap (.pcap/.cap), ETL (.etl)");
        }

        private static string GetExecutablePath() {
            string loc = typeof(Program).Assembly.Location;
            if (!string.IsNullOrEmpty(loc) && File.Exists(loc))
                return loc;
            return AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar) + ".exe";
        }

        private static void PrintTables(
            ConcurrentQueue<NetworkHost> hosts,
            ConcurrentQueue<SessionEventArgs> sessions,
            ConcurrentQueue<NetworkCredential> credentials,
            ConcurrentQueue<ReconstructedFile> files,
            ConcurrentQueue<DnsRecordEventArgs> dnsRecords,
            ConcurrentQueue<MessageEventArgs> messages,
            Options opts) {

            PrintHosts(hosts);
            PrintSessions(sessions);
            PrintCredentials(credentials);
            if (!opts.NoFiles)
                PrintFiles(files);
            PrintDns(dnsRecords);
            PrintMessages(messages);
        }

        private static void PrintHosts(ConcurrentQueue<NetworkHost> hosts) {
            var list = hosts.ToList();
            list.Sort((a, b) => string.Compare(a.IPAddress?.ToString(), b.IPAddress?.ToString(), StringComparison.Ordinal));
            Console.WriteLine("=== Hosts ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-18} {1,-19} {2,-24} {3,-12} {4,4}", "IP", "MAC", "Hostname", "OS", "TTL");
            foreach (var h in list) {
                string ip = h.IPAddress?.ToString() ?? "?";
                string mac = h.MacAddress != null ? FormatMac(h.MacAddress) : "";
                string name = h.HostName ?? "";
                string os = h.OS.ToString();
                byte ttl = h.TtlDistance;
                Console.WriteLine("{0,-18} {1,-19} {2,-24} {3,-12} {4,4}", ip, mac, Truncate(name, 24), os, ttl);
            }
            Console.WriteLine();
        }

        private static void PrintSessions(ConcurrentQueue<SessionEventArgs> sessions) {
            var list = sessions.ToList();
            Console.WriteLine("=== Sessions ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-14} {1,-16} {2,5}  {3,-16} {4,5}  {5}", "Protocol", "Client", "Port", "Server", "Port", "Trans");
            foreach (var s in list) {
                string proto = s.Protocol.ToString();
                string client = s.Client?.IPAddress?.ToString() ?? "?";
                string server = s.Server?.IPAddress?.ToString() ?? "?";
                Console.WriteLine("{0,-14} {1,-16} {2,5}  {3,-16} {4,5}  {5}", proto, client, s.ClientPort, server, s.ServerPort, s.Tcp ? "TCP" : "UDP");
            }
            Console.WriteLine();
        }

        private static void PrintCredentials(ConcurrentQueue<NetworkCredential> credentials) {
            var list = credentials.ToList();
            Console.WriteLine("=== Credentials ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-10} {1,-16} {2,-16} {3,-24} {4}", "Protocol", "Client", "Server", "Username", "Password");
            foreach (var c in list) {
                string proto = c.ProtocolString ?? "";
                string client = c.Client?.IPAddress?.ToString() ?? "?";
                string server = c.Server?.IPAddress?.ToString() ?? "?";
                string user = c.Username ?? "";
                string pass = c.Password ?? "";
                Console.WriteLine("{0,-10} {1,-16} {2,-16} {3,-24} {4}", proto, client, server, Truncate(user, 24), pass);
            }
            Console.WriteLine();
        }

        private static void PrintFiles(ConcurrentQueue<ReconstructedFile> files) {
            var list = files.ToList();
            Console.WriteLine("=== Files ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-32} {1,12}  {2,-14} {3,-16} {4,-16}", "Filename", "Size", "Type", "Source", "Destination");
            foreach (var f in list) {
                string name = Path.GetFileName(f.FilePath) ?? f.Filename ?? "";
                string src = f.SourceHost?.IPAddress?.ToString() ?? "?";
                string dst = f.DestinationHost?.IPAddress?.ToString() ?? "?";
                Console.WriteLine("{0,-32} {1,12}  {2,-14} {3,-16} {4,-16}", Truncate(name, 32), f.FileSize, f.FileStreamType, src, dst);
            }
            Console.WriteLine();
        }

        private static void PrintDns(ConcurrentQueue<DnsRecordEventArgs> dnsRecords) {
            var list = dnsRecords.ToList();
            Console.WriteLine("=== DNS Records ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-40} {1,-6} {2,-40} {3}", "Query", "Type", "Result", "TTL");
            foreach (var d in list) {
                string query = d.Record?.DNS ?? "";
                string result = d.Record?.IP?.ToString() ?? d.Record?.PrimaryName ?? "";
                string type = d.Record?.Type.ToString() ?? "";
                long ttl = (long)(d.Record?.TimeToLive.TotalSeconds ?? 0);
                Console.WriteLine("{0,-40} {1,-6} {2,-40} {3}", Truncate(query, 40), type, Truncate(result, 40), ttl);
            }
            Console.WriteLine();
        }

        private static void PrintMessages(ConcurrentQueue<MessageEventArgs> messages) {
            var list = messages.ToList();
            Console.WriteLine("=== Messages ({0}) ===", list.Count);
            if (list.Count == 0) { Console.WriteLine(); return; }
            Console.WriteLine("{0,-10} {1,-30} {2,-30} {3}", "Protocol", "From", "To", "Subject");
            foreach (var m in list) {
                string proto = m.Protocol.ToString();
                string from = m.From ?? "";
                string to = m.To ?? "";
                string subject = m.Subject ?? "";
                Console.WriteLine("{0,-10} {1,-30} {2,-30} {3}", proto, Truncate(from, 30), Truncate(to, 30), subject);
            }
            Console.WriteLine();
        }

        private static void PrintCsv(
            ConcurrentQueue<NetworkHost> hosts,
            ConcurrentQueue<SessionEventArgs> sessions,
            ConcurrentQueue<NetworkCredential> credentials,
            ConcurrentQueue<ReconstructedFile> files,
            ConcurrentQueue<DnsRecordEventArgs> dnsRecords,
            ConcurrentQueue<MessageEventArgs> messages,
            Options opts) {

            Console.WriteLine("# Hosts");
            Console.WriteLine("IP,MAC,Hostname,OS,TtlDistance");
            foreach (var h in hosts) {
                Console.WriteLine("{0},{1},{2},{3},{4}",
                    Csv(h.IPAddress?.ToString()),
                    Csv(h.MacAddress != null ? FormatMac(h.MacAddress) : ""),
                    Csv(h.HostName),
                    Csv(h.OS.ToString()),
                    h.TtlDistance);
            }
            Console.WriteLine();

            Console.WriteLine("# Sessions");
            Console.WriteLine("Protocol,ClientIP,ClientPort,ServerIP,ServerPort,Transport");
            foreach (var s in sessions) {
                Console.WriteLine("{0},{1},{2},{3},{4},{5}",
                    Csv(s.Protocol.ToString()),
                    Csv(s.Client?.IPAddress?.ToString()),
                    s.ClientPort,
                    Csv(s.Server?.IPAddress?.ToString()),
                    s.ServerPort,
                    s.Tcp ? "TCP" : "UDP");
            }
            Console.WriteLine();

            Console.WriteLine("# Credentials");
            Console.WriteLine("Protocol,ClientIP,ServerIP,Username,Password,Domain");
            foreach (var c in credentials) {
                Console.WriteLine("{0},{1},{2},{3},{4},{5}",
                    Csv(c.ProtocolString),
                    Csv(c.Client?.IPAddress?.ToString()),
                    Csv(c.Server?.IPAddress?.ToString()),
                    Csv(c.Username),
                    Csv(c.Password),
                    Csv(c.Domain));
            }
            Console.WriteLine();

            if (!opts.NoFiles) {
                Console.WriteLine("# Files");
                Console.WriteLine("Filename,Size,Type,SourceIP,DestinationIP,MD5");
                foreach (var f in files) {
                    Console.WriteLine("{0},{1},{2},{3},{4},{5}",
                        Csv(Path.GetFileName(f.FilePath)),
                        f.FileSize,
                        Csv(f.FileStreamType.ToString()),
                        Csv(f.SourceHost?.IPAddress?.ToString()),
                        Csv(f.DestinationHost?.IPAddress?.ToString()),
                        Csv(f.MD5Sum));
                }
                Console.WriteLine();
            }

            Console.WriteLine("# DNS");
            Console.WriteLine("Query,Type,Result,TTL");
            foreach (var d in dnsRecords) {
                Console.WriteLine("{0},{1},{2},{3}",
                    Csv(d.Record?.DNS),
                    Csv(d.Record?.Type.ToString()),
                    Csv(d.Record?.IP?.ToString() ?? d.Record?.PrimaryName),
                    (long)(d.Record?.TimeToLive.TotalSeconds ?? 0));
            }
            Console.WriteLine();

            Console.WriteLine("# Messages");
            Console.WriteLine("Protocol,From,To,Subject");
            foreach (var m in messages) {
                Console.WriteLine("{0},{1},{2},{3}",
                    Csv(m.Protocol.ToString()),
                    Csv(m.From),
                    Csv(m.To),
                    Csv(m.Subject));
            }
        }

        private static string FormatMac(PhysicalAddress mac) {
            byte[] bytes = mac.GetAddressBytes();
            if (bytes.Length != 6) return mac.ToString();
            return string.Format("{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}",
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        }

        private static string Truncate(string s, int max) {
            if (s == null) return "";
            return s.Length <= max ? s : s.Substring(0, max - 3) + "...";
        }

        private static string Csv(string s) {
            if (s == null) return "";
            if (s.Contains(",") || s.Contains("\"") || s.Contains("\n") || s.Contains("\r")) {
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            }
            return s;
        }
    }
}
