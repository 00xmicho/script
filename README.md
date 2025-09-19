# SSRFRecon - Advanced SSRF Reconnaissance Scanner

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen)

SSRFRecon is an advanced Server-Side Request Forgery (SSRF) reconnaissance scanner designed to efficiently discover and validate URLs with potential SSRF parameters from multiple sources. It combines intelligent filtering with smart de-duplication to provide security researchers with high-quality results.

## Features

- **Multi-Source Collection**: Gathers URLs from Wayback Machine and Katana crawler
- **Smart SSRF Filtering**: Uses extended keyword matching and pattern recognition
- **Live URL Validation**: Verifies URL accessibility using HTTPX
- **Intelligent De-duplication**: Eliminates redundant URLs while preserving unique endpoints
- **Parameter Analysis**: Generates detailed reports on SSRF parameter frequency
- **Pattern Recognition**: Identifies common URL structures and parameter patterns
- **Comprehensive Error Handling**: Detailed error codes with recovery suggestions
- **Parallel Processing**: Efficient batch processing for large-scale scanning

## Installation

### Prerequisites

- Python 3.7+
- Go tools (required for underlying utilities):
  - [waybackurls](https://github.com/tomnomnom/waybackurls)
  - [katana](https://github.com/projectdiscovery/katana)
  - [httpx](https://github.com/projectdiscovery/httpx)

### Install Required Tools

```bash
# Install Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH (if not already)
export PATH=$PATH:$(go env GOPATH)/bin
```

### Clone Repository

```bash
git clone https://github.com/00xmicho/script.git
```

## Usage

### Basic Usage

```bash
python3 ssrfrecon.py example.com
```

### Advanced Options

```bash
# Custom output file
python3 ssrfrecon.py example.com -o results.txt

# Increase threads and timeout
python3 ssrfrecon.py example.com -t 100 -to 180

# Custom batch size for HTTPX
python3 ssrfrecon.py example.com -bs 200

# Verbose output and force mode
python3 ssrfrecon.py example.com -v -f

# Comprehensive scanning
python3 ssrfrecon.py example.com --comprehensive
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to scan | Required |
| `-o, --output` | Output file for SSRF URLs | `ssrf_urls.txt` |
| `-t, --threads` | Number of threads for httpx | `50` |
| `-to, --timeout` | Timeout for commands (seconds) | `120` |
| `-bs, --batch-size` | Batch size for HTTPX processing | `250` |
| `-v, --verbose` | Enable verbose output | `False` |
| `-f, --force` | Skip confirmation prompts | `False` |
| `--comprehensive` | Use comprehensive URL collection | `False` |

## Output Files

The tool generates several outphttpsles:

1. **Main Results** (`ssrf_urls.txt` or custom name): Contains unique, live URLs with SSRF parameters
2. **Parameter Count** (`count-param.txt`): Lists SSRF parameters and their frequency
3. **Pattern Analysis** (`pattern-analysis-{domain}.txt`): Analyzes common URL structures and parameter patterns

## How It Works

1. **URL Collection**: Gathers URLs from multiple sources (Wayback Machine, Katana crawler)
2. **SSRF Filtering**: Identifies URLs with potential SSRF parameters using extended keyword matching
3. **Live Verification**: Checks which URLs are accessible using HTTPX
4. **De-duplication**: Applies smart filtering to eliminate redundant URLs
5. **Analysis**: Generates detailed reports on parameters and patterns
6. **Output**: Saves results to specified files

## Error Codes

SSRFRecon uses a comprehensive error code system:

### 1xx - Tool & Dependency Errors
- **`ERROR 101`**: `waybackurls` tool not found
- **`ERROR 102`**: `katana` tool not found  
- **`ERROR 103`**: `httpx` tool not found
- **`ERROR 104`**: Multiple tools missing

### 2xx - Execution & Timeout Errors
- **`ERROR 201`**: Waybackurls execution timeout
- **`ERROR 202`**: Katana execution timeout
- **`ERROR 203`**: HTTPX execution timeout
- **`ERROR 204`**: Subprocess general timeout

### 3xx - File & I/O Operations Errors
- **`ERROR 301`**: Temporary file creation failed
- **`ERROR 302`**: Output file write permission denied
- **`ERROR 303`**: File not found during processing
- **`ERROR 304`**: Disk space exhausted

### 4xx - Network & Connection Errors
- **`ERROR 401`**: DNS resolution failed
- **`ERROR 402`**: Connection refused by target
- **`ERROR 403`**: SSL certificate validation failed
- **`ERROR 404`**: Network unreachable
- **`ERROR 405`**: Too many redirects

### 5xx - URL Processing & Parsing Errors
- **`ERROR 501`**: URL parsing failed (malformed URLs)
- **`ERROR 502`**: Query parameter parsing error
- **`ERROR 503`**: URL normalization failed
- **`ERROR 504`**: Invalid URL encoding

### 6xx - Resource & System Errors
- **`ERROR 601`**: Memory allocation failed
- **`ERROR 602`**: Thread pool exhaustion
- **`ERROR 603`**: Too many open files
- **`ERROR 604`**: System resource limitation

### 7xx - Configuration & Input Errors
- **`ERROR 701`**: Invalid domain format
- **`ERROR 702`**: Invalid thread count specified
- **`ERROR 703`**: Invalid timeout value
- **`ERROR 704`**: Output directory not writable

### 8xx - Application Logic Errors
- **`ERROR 801`**: No URLs discovered from sources
- **`ERROR 802`**: No live URLs found after filtering
- **`ERROR 803`**: Empty results after normalization
- **`ERROR 804`**: Critical URL detection failed

### 9xx - Unknown & Unexpected Errors
- **`ERROR 901`**: Unhandled exception occurred
- **`ERROR 902`**: Unknown error type
- **`ERROR 903`**: Unexpected behavior detected

## Error Handling Flow

1. **Tool Errors (1xx)**: Prompt user to install missing tools or continue
2. **Timeout Errors (2xx)**: Retry with increased timeout or skip operation  
3. **File Errors (3xx)**: Check permissions and disk space, suggest alternatives
4. **Network Errors (4xx)**: Verify target availability and network connectivity
5. **Parsing Errors (5xx)**: Skip problematic URLs and continue processing
6. **Resource Errors (6xx)**: Reduce thread count and retry
7. **Input Errors (7xx)**: Validate user input and provide suggestions
8. **Logic Errors (8xx)**: Adjust parameters and retry scanning
9. **Unknown Errors (9xx)**: Log detailed information for debugging

Each error code includes:
- ✅ **Error message** explaining what went wrong
- ✅ **Recovery suggestions** for the user
- ✅ **Automatic fallback** where possible
- ✅ **Clear exit codes** for script automation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Disclaimer

This tool is designed for security research and authorized testing only. The user is responsible for ensuring they have proper authorization before scanning any targets. The authors are not responsible for any misuse or damage caused by this program.

## Acknowledgments

- Thanks to the creators of [waybackurls](https://github.com/tomnomnom/waybackurls), [katana](https://github.com/projectdiscovery/katana), and [httpx](https://github.com/projectdiscovery/httpx)
- Inspired by various SSRF research and methodologies in the security community
