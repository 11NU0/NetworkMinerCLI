# NetworkMiner CLI

A headless command-line interface to the [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) packet analysis engine. This is an unofficial CLI wrapper around the open-source NetworkMiner 3.1 core libraries (PacketHandlerFramework, PacketParser, SharedUtils), providing the same host identification, session detection, credential extraction, file carving, DNS parsing, and message reconstruction as the GUI — but without any GUI dependencies.

## Build

Requires the .NET SDK (10.0+) or Visual Studio 2022 with the .NET Framework 4.8 targeting pack.

```bash
dotnet build NetworkMinerCLI.sln -c Release
```

The solution multi-targets `net48` and `net8.0`, producing two builds:

```
NetworkMinerCLI/bin/Release/net48/NetworkMinerCLI.exe   # Windows .NET Framework 4.8
NetworkMinerCLI/bin/Release/net8.0/NetworkMinerCLI.dll  # Cross-platform .NET 8 (Windows, Linux, macOS)
```

## Platform Support

| Target | Platform | VNC/RAT screenshot extraction |
|--------|----------|-------------------------------|
| `net48` | Windows only (.NET Framework 4.8) | Yes (System.Drawing) |
| `net8.0` | Windows, Linux, macOS (.NET 8 runtime) | No (disabled via `#if NETFRAMEWORK`) |

The `net8.0` target runs on any platform with the .NET 8 runtime installed. All core analysis
features (hosts, sessions, credentials, file carving, DNS, messages) work identically on both
targets. Only VNC/RAT desktop screenshot reconstruction is disabled on `net8.0` because it
depends on `System.Drawing` (GDI+), which is Windows-only.

### Running on Linux

```bash
# Install .NET 8 runtime (if not already installed)
dotnet NetworkMinerCLI/bin/Release/net8.0/NetworkMinerCLI.dll capture.pcap

# Or publish a self-contained Linux binary
dotnet publish NetworkMinerCLI/NetworkMinerCLI.csproj -c Release -f net8.0 -r linux-x64 --self-contained
./bin/Release/net8.0/linux-x64/publish/NetworkMinerCLI capture.pcap
```

## Usage

```
NetworkMinerCLI <pcap-file> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-o, --output <dir>` | Output directory (default: `<pcap-dir>/NetworkMinerCLI-Output`) |
| `--csv` | Output results as CSV instead of formatted tables |
| `-v, --verbose` | Verbose progress output to stderr |
| `-q, --quiet` | Minimal output (errors only) |
| `--no-files` | Don't list extracted files |
| `-h, --help` | Show help |

### Examples

```bash
# Basic analysis
NetworkMinerCLI capture.pcap

# Save output to a specific directory
NetworkMinerCLI capture.pcap -o ./results

# CSV output for piping into other tools
NetworkMinerCLI capture.pcap --csv > results.csv

# Quiet mode, just extract files
NetworkMinerCLI capture.pcap -q
```

### Supported Input Formats

- **libpcap** (`.pcap`, `.cap`) — the standard pcap format
- **ETL** (`.etl`) — Event Trace Log files (Windows)

> pcapNG (`.pcapng`) is only supported by NetworkMiner Professional, not the open-source engine.

### Output

The CLI prints nine sections to stdout:

1. **Hosts** — IP, MAC, hostname, OS guess, TTL distance
2. **Sessions** — application-layer protocol sessions (client/server/ports)
3. **Credentials** — extracted usernames/passwords (FTP, HTTP, SMTP, etc.)
4. **Files** — reconstructed files transferred over the network
5. **DNS Records** — DNS queries and responses
6. **Messages** — emails, chat messages, etc.
7. **Parameters** — protocol-specific fields (HTTP headers, FTP commands, VNC clipboard, etc.)
8. **HTTP Clients** — HTTP client session identifiers
9. **Keywords** — detected/flagged keyword matches

Extracted files are written to `<output>/AssembledFiles/`.

## Project Structure

```
NetworkMinerCLI/
├── NetworkMinerCLI.sln
├── NetworkMinerCLI/           # CLI console application (new)
│   ├── NetworkMinerCLI.csproj
│   └── Program.cs
├── PacketHandlerFramework/    # Core analysis engine (from NetworkMiner)
├── PacketParser/              # Packet parsing library (from NetworkMiner)
├── SharedUtils/               # Shared utilities + PCAP reader (from NetworkMiner)
└── LICENSE.txt                # GPL v2
```

## License

GPL v2 — same as NetworkMiner. See [LICENSE.txt](LICENSE.txt).

NetworkMiner is Copyright (c) Erik Hjelmvik, NETRESEC.
