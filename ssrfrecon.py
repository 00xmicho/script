#!/usr/bin/env python3
"""
SSRFRecon - Advanced SSRF Reconnaissance Scanner
Focused on collecting and verifying URLs with SSRF parameters from multiple sources.
"""

import subprocess
import sys
import os
import shlex
import shutil
import tempfile
import time
import argparse
import logging
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urldefrag
from collections import Counter
import re

# ASCII Banner (Updated)
BANNER = r"""
 ____ ____  ____  _____   ____  _____ ____ ___  _   _
/ ___/ ___||  _ \|  ___| |  _ \| ____/ ___/ _ \| \ | |
\___ \___ \| |_) | |_    | |_) |  _|| |  | | | |  \| |
 ___) |__) |  _ <|  _|   |  _ <| |__| |__| |_| | |\  |
|____/____/|_| \_\_|     |_| \_\_____\____\___/|_| \_|
                               SSRF RECON
"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Extended SSRF parameter keywords. These are the strings we look for.
SSRF_PARAM_KEYWORDS = [
    "url", "target", "redirect", "next", "callback", "return", "page",
    "data", "link", "image", "img", "file", "host", "site", "domain",
    "view", "download", "path", "dest", "uri", "load", "source", "fetch",
    "request", "api", "endpoint", "proxy", "remote", "external", "internal",
    "admin", "debug", "config", "json", "xml", "path", "port", "service",
    "callback", "forward", "forwarder", "redirect_uri", "redirect_url",
    "download", "upload", "delete", "post", "put", "patch", "get", "action",
    "open", "show", "read", "retrieve", "include", "require", "import",
    "document", "content", "body", "response", "request", "form", "query",
    "search", "filter", "sort", "order", "limit", "offset", "count",
    "page", "size", "from", "to", "date", "time", "year", "month", "day",
    "id", "key", "token", "auth", "auth_token", "access", "access_token",
    "secret", "password", "pass", "passwd", "pwd", "username", "user",
    "account", "email", "mail", "address", "phone", "mobile", "tel",
    "name", "firstname", "lastname", "fullname", "nickname", "alias",
    "title", "subject", "description", "desc", "message", "msg", "text",
    "comment", "feedback", "rating", "score", "vote", "like", "share",
    "subscribe", "unsubscribe", "register", "signup", "signin", "login",
    "logout", "logout", "session", "sess", "cookie", "tracking", "track",
    "ref", "referrer", "referer", "source", "campaign", "medium", "content",
    "term", "keyword", "adgroup", "ad_id", "placement", "device", "network",
    "click_id", "session_id", "user_id", "version", "api_key", "api_version",
    "view", "type", "category", "sort", "order", "page", "page_size",
    "limit", "offset", "start", "end", "time", "date", "day", "month", "year",
    "status", "mode", "action", "callback", "jsonp", "token", "auth", "key",
    "id", "pid", "product_id", "item_id", "sku", "model", "brand", "price",
    "discount", "promo", "coupon", "code", "voucher", "currency", "language",
    "locale", "country", "region", "city", "zip", "postal", "address", "email",
    "phone", "name", "firstname", "lastname", "username", "password", "login",
    "register", "submit", "reset", "update", "delete", "create", "edit", "save",
    "cancel", "confirm", "accept", "agree", "disagree", "vote", "like", "share",
    "comment", "review", "rating", "score", "vote", "poll", "survey", "feedback",
    "help", "support", "contact", "about", "privacy", "terms", "conditions",
    "policy", "copyright", "dmca", "legal", "license", "rights", "permissions"
]

# Common, noisy parameters we want to ignore during smart de-duplication.
USELESS_PARAMS = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'w', 'q', 'width', 'quality', 's', 't', 'timestamp', 'cache', 'hash', 'format'
]

# Error codes and their meanings with solutions
ERROR_CODES = {
    101: "waybackurls tool not found - Install with: go install github.com/tomnomnom/waybackurls@latest",
    102: "katana tool not found - Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest",
    103: "httpx tool not found - Install with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    104: "Multiple tools missing - Install required tools",
    201: "Waybackurls execution timeout - Increase timeout with -to parameter",
    202: "Katana execution timeout - Increase timeout with -to parameter",
    203: "HTTPX execution timeout - Increase timeout with -to parameter or reduce batch size",
    204: "Subprocess general timeout - Increase timeout with -to parameter",
    301: "Temporary file creation failed - Check disk space and permissions",
    302: "Output file write permission denied - Check directory permissions",
    303: "File not found during processing - File was removed during processing",
    304: "Disk space exhausted - Free up disk space",
    401: "DNS resolution failed - Check network connectivity and DNS settings",
    402: "Connection refused by target - Target may be blocking requests",
    403: "SSL certificate validation failed - Target may have SSL issues",
    404: "Network unreachable - Check network connectivity",
    405: "Too many redirects - Target may have redirect loops",
    501: "URL parsing failed (malformed URLs) - URLs may be incorrectly formatted",
    502: "Query parameter parsing error - URL query parameters may be malformed",
    503: "URL normalization failed - URL normalization process failed",
    504: "Invalid URL encoding - URL contains invalid encoding",
    601: "Memory allocation failed - System may be out of memory",
    602: "Thread pool exhaustion - Reduce number of threads with -t parameter",
    603: "Too many open files - Increase system file limit",
    604: "System resource limitation - System resources may be exhausted",
    701: "Invalid domain format - Provide a valid domain name",
    702: "Invalid thread count specified - Use a reasonable thread count (1-200)",
    703: "Invalid timeout value - Use a reasonable timeout value",
    704: "Output directory not writable - Check directory permissions",
    801: "No URLs discovered from sources - Target may have no accessible URLs",
    802: "No live URLs found after filtering - No URLs responded with valid status codes",
    803: "Empty results after normalization - All URLs were filtered out during normalization",
    804: "Critical URL detection failed - SSRF parameter detection failed",
    901: "Unhandled exception occurred - Check verbose output for details",
    902: "Unknown error type - Check verbose output for details",
    903: "Unexpected behavior detected - Script encountered unexpected behavior"
}

def print_banner():
    """Prints the tool's ASCII banner."""
    print(BANNER)

def check_required_tools():
    """Checks if all required command-line tools are installed and in the PATH."""
    return [tool for tool in ['waybackurls', 'katana', 'httpx'] if not shutil.which(tool)]

def prompt_user(question):
    """Asks the user a 'y/n' question."""
    while True:
        response = input(f"{question} (y/n): ").lower().strip()
        if response in ['y', 'yes']: return True
        if response in ['n', 'no']: return False
        print("Please enter 'y' or 'n'.")

def handle_error(error_code, message=None, fatal=False):
    """Logs errors and exits if the error is fatal."""
    error_msg = f"ERROR {error_code}: {ERROR_CODES.get(error_code, 'Unknown error')}"
    if message: error_msg += f" - {message}"
    if fatal:
        logger.error(error_msg)
        sys.exit(error_code)
    else:
        logger.warning(error_msg)
        return error_code

def run_command(cmd, is_pipe=False, timeout=120):
    """Executes a shell command and captures its output."""
    try:
        if is_pipe:
            process = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', timeout=timeout)
        else:
            process = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='ignore', timeout=timeout)

        if process.returncode != 0 and process.stderr:
            tool_name = cmd.split()[0] if not is_pipe else cmd.split('|')[-1].strip().split()[0]
            logger.warning(f"Tool '{tool_name}' returned an error: {process.stderr.strip()}")
            return None
        return process.stdout.splitlines()
    except subprocess.TimeoutExpired:
        handle_error(201 if "waybackurls" in cmd else 202 if "katana" in cmd else 203, f"Command timed out: {cmd}")
        return None
    except Exception as e:
        handle_error(901, f"Unexpected error executing command: {e}")
        return None

def smart_ssrf_filter(urls):
    """
    Improved SSRF filter that uses multiple techniques to identify potential SSRF parameters
    """
    ssrf_urls = []
    
    for url in urls:
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Check if URL has any parameters at all
            if not query_params:
                continue
                
            # Check for SSRF parameters in parameter names
            has_ssrf_param = any(
                any(keyword in key.lower() for keyword in SSRF_PARAM_KEYWORDS) 
                for key in query_params.keys()
            )
            
            # Check for URL-like values in parameters
            has_url_value = any(
                any(url_indicator in value.lower() for url_indicator in ['http://', 'https://', 'ftp://', '//'])
                for param_values in query_params.values()
                for value in param_values
            )
            
            # Check path for potential SSRF indicators
            path_indicators = any(
                indicator in parsed_url.path.lower() 
                for indicator in ['proxy', 'fetch', 'redirect', 'callback', 'api', 'webhook']
            )
            
            if has_ssrf_param or has_url_value or path_indicators:
                ssrf_urls.append(url)
                
        except Exception as e:
            # Fallback for malformed URLs - use simple keyword matching
            url_lower = url.lower()
            if any(f"{k}=" in url_lower for k in SSRF_PARAM_KEYWORDS) or any(
                indicator in url_lower for indicator in ['http://', 'https://', 'url=', 'redirect=']):
                ssrf_urls.append(url)
    
    return ssrf_urls

def generate_endpoint_signature(url):
    """
    This is the smart de-duplication logic.
    It creates a unique "signature" for a URL based on its path and the *names*
    of its SSRF parameters, ignoring parameter values and non-SSRF parameters.
    """
    try:
        url = urldefrag(url).url
        parts = urlparse(url)
        query_params = parse_qs(parts.query)

        # Find only the SSRF-related parameter keys
        ssrf_param_keys = sorted([key for key in query_params if key.lower() in SSRF_PARAM_KEYWORDS])

        # The unique signature is a combination of the path and the sorted SSRF keys.
        unique_key = (parts.path, tuple(ssrf_param_keys))
        return unique_key
    except Exception:
        # If the URL is malformed, treat it as a unique case.
        return url

def check_urls_with_httpx(urls, batch_size=250, threads=50):
    """Checks URL liveness in parallel batches to be efficient and avoid timeouts."""
    if not urls: return set()
    all_live_urls = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        # Create batches of URLs to process
        batches = [urls[i:i + batch_size] for i in range(0, len(urls), batch_size)]
        futures = [executor.submit(process_batch, batch, i + 1, threads) for i, batch in enumerate(batches)]

        for future in concurrent.futures.as_completed(futures):
            if result := future.result():
                all_live_urls.update(result)
    return all_live_urls

def process_batch(batch, batch_num, threads=50):
    """Processes a single batch of URLs with httpx."""
    try:
        # Use a temporary file to pass the list of URLs to httpx
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt', encoding='utf-8') as tmp:
            tmp.write("\n".join(batch))
            temp_file = tmp.name

        httpx_cmd = f"httpx -l {temp_file} -silent -mc 200,301,302,307,400,403,405,429,500 -t {threads} -timeout 10 -retries 2"
        alive_urls_output = run_command(httpx_cmd)
        os.unlink(temp_file) # Clean up the temp file

        if not alive_urls_output:
            logger.debug(f"No live URLs found in batch {batch_num}")
            return set()

        # httpx can sometimes add status codes, so we strip them.
        batch_live_urls = {u.split(' ')[0].strip() for u in alive_urls_output}
        logger.info(f"Batch {batch_num}: Found {len(batch_live_urls)} live URLs")
        return batch_live_urls
    except Exception as e:
        handle_error(301, f"Error processing batch {batch_num}: {e}")
        return set()

def collect_all_urls(domain, timeout=120):
    """Collects all URLs from available sources without filtering"""
    all_urls = set()
    
    # Wayback URLs
    wayback_cmd = f"echo {shlex.quote(domain)} | waybackurls"
    logger.info("Collecting URLs from waybackurls...")
    wayback_urls = run_command(wayback_cmd, is_pipe=True, timeout=timeout)
    if wayback_urls:
        all_urls.update(wayback_urls)
        logger.info(f"Waybackurls found {len(wayback_urls)} URLs")
    
    # Katana
    katana_cmd = f"katana -u https://{shlex.quote(domain)} -silent -d 3 -jc -kf all -c 25 -p 15 -system-chrome"
    logger.info("Collecting URLs from katana...")
    katana_urls = run_command(katana_cmd, timeout=timeout)
    if katana_urls:
        all_urls.update(katana_urls)
        logger.info(f"Katana found {len(katana_urls)} URLs")
    
    return all_urls

def generate_param_count_file(urls, filename="count-param.txt"):
    """
    Analyzes the final URLs and creates a file that counts
    how many times each SSRF parameter appeared.
    """
    logger.info(f"Generating parameter count file: {filename}")
    param_counts = Counter()

    for url in urls:
        try:
            params = parse_qs(urlparse(url).query)
            for param in params:
                if any(keyword in param.lower() for keyword in SSRF_PARAM_KEYWORDS):
                    param_counts[param] += 1
        except Exception:
            continue

    if not param_counts:
        logger.warning("No relevant parameters found to generate count file.")
        return

    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write("--- SSRF Parameter Counts ---\n")
            # Sort by most common
            for param, count in param_counts.most_common():
                f.write(f"{param}: {count}\n")
        logger.info(f"Parameter count file saved to {filename}")
    except Exception as e:
        handle_error(302, f"Failed to write parameter count file: {e}")

def analyze_url_patterns(urls, domain):
    """Analyze URL patterns to identify common structures"""
    path_patterns = Counter()
    param_patterns = Counter()
    
    for url in urls:
        try:
            parsed = urlparse(url)
            # Extract path patterns
            path_segments = [seg for seg in parsed.path.split('/') if seg]
            if path_segments:
                path_patterns[parsed.path] += 1
            
            # Extract parameter patterns
            params = parse_qs(parsed.query)
            for param in params:
                if any(keyword in param.lower() for keyword in SSRF_PARAM_KEYWORDS):
                    param_patterns[param] += 1
                    
        except Exception as e:
            logger.debug(f"Error analyzing URL pattern: {e}")
    
    # Save pattern analysis
    with open(f"pattern-analysis-{domain}.txt", "w") as f:
        f.write("=== Path Patterns ===\n")
        for pattern, count in path_patterns.most_common(20):
            f.write(f"{pattern}: {count}\n")
        
        f.write("\n=== Parameter Patterns ===\n")
        for param, count in param_patterns.most_common(20):
            f.write(f"{param}: {count}\n")
    
    return path_patterns, param_patterns

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="SSRFRecon - SSRF Reconnaissance Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ssrfrecon.py example.com
  python3 ssrfrecon.py example.com -o results.txt
  python3 ssrfrecon.py example.com -t 100 -to 180 -bs 200
  python3 ssrfrecon.py example.com -v -f
    """)
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", default="ssrf_urls.txt", help="Output file for SSRF URLs")
    parser.add_argument("-t", "--threads", default=50, type=int, help="Number of threads for httpx")
    parser.add_argument("-to", "--timeout", default=120, type=int, help="Timeout for commands")
    parser.add_argument("-bs", "--batch-size", default=250, type=int, help="Batch size for HTTPX processing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-f", "--force", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--comprehensive", action="store_true", help="Use comprehensive URL collection and filtering")
    
    if len(sys.argv) == 1: 
        parser.print_help()
        sys.exit(0)
        
    args = parser.parse_args()
    if args.verbose: 
        logger.setLevel(logging.DEBUG)

    missing_tools = check_required_tools()
    if missing_tools:
        error_msg = f"Missing required tools: {', '.join(missing_tools)}"
        if not args.force and not prompt_user(f"{error_msg}. Continue anyway?"):
            handle_error(104, error_msg, fatal=True)
        else:
            logger.warning("Continuing despite missing tools.")

    # --- Step 1: Collect URLs from all sources ---
    logger.info(f"Starting comprehensive URL collection for {args.domain}")
    all_urls = collect_all_urls(args.domain, args.timeout)
    
    if not all_urls:
        logger.warning("No URLs found from any source. Exiting.")
        return
    
    logger.info(f"Total URLs collected: {len(all_urls)}")
    
    # --- Step 2: Filter for SSRF parameters ---
    logger.info("Filtering URLs for potential SSRF parameters...")
    ssrf_urls = smart_ssrf_filter(all_urls)
    
    if not ssrf_urls:
        logger.warning("No URLs with SSRF parameters found. Exiting.")
        return
        
    logger.info(f"Found {len(ssrf_urls)} URLs with potential SSRF parameters")
    
    # --- Step 3: Check which of them are live ---
    logger.info("Checking which URLs are live...")
    live_ssrf_urls = check_urls_with_httpx(list(ssrf_urls), args.batch_size, args.threads)

    if not live_ssrf_urls:
        logger.warning("No live URLs found. Exiting.")
        return
        
    logger.info(f"Found {len(live_ssrf_urls)} live URLs with SSRF parameters")

    # --- Step 4: Apply the smart de-duplication ---
    logger.info("Applying smart de-duplication to find unique endpoints...")
    unique_endpoints = {}
    for url in live_ssrf_urls:
        signature = generate_endpoint_signature(url)
        if signature not in unique_endpoints:
            unique_endpoints[signature] = url

    final_urls = sorted(list(unique_endpoints.values()))
    logger.info(f"After de-duplication: {len(final_urls)} unique URLs")

    # --- Step 5: Analyze patterns ---
    logger.info("Analyzing URL patterns...")
    analyze_url_patterns(final_urls, args.domain)

    # --- Step 6: Write the final results and the parameter count file ---
    try:
        with open(args.output, "w", encoding='utf-8') as f:
            f.write("\n".join(final_urls))

        logger.info("Process completed successfully!")
        logger.info(f"Saved {len(final_urls)} unique, live SSRF URLs to: {args.output}")

        # Generate parameter count file
        generate_param_count_file(final_urls, "count-param.txt")

    except Exception as e:
        handle_error(302, f"Error writing output file: {e}", fatal=True)

if __name__ == "__main__":
    main()
