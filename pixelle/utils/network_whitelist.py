import socket
import re
from typing import Set, List
from urllib.parse import urlparse

from pixelle.settings import settings
from pixelle.logger import logger

_allowed_hosts_cache: Set[str] = set()
_allowed_ips_cache: Set[str] = set()

def _load_whitelist_from_settings():
    """Load allowed hosts and IPs from settings into cache."""
    global _allowed_hosts_cache, _allowed_ips_cache
    _allowed_hosts_cache = set()
    _allowed_ips_cache = set()

    raw_hosts = settings.allowed_hosts.split(',')
    for host_entry in raw_hosts:
        host_entry = host_entry.strip()
        if not host_entry:
            continue
        _allowed_hosts_cache.add(host_entry)
        
        # Attempt to resolve IP for hostnames
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_entry):
            _allowed_ips_cache.add(host_entry)
        else:
            try:
                ip = socket.gethostbyname(host_entry)
                _allowed_ips_cache.add(ip)
            except socket.gaierror:
                logger.warning(f"Could not resolve IP for allowed host: {host_entry}")

def is_host_allowed(target_host: str) -> bool:
    """
    Check if a target host is allowed based on the configured whitelist.
    Automatically loads whitelist from settings if not already loaded.
    """
    if not _allowed_hosts_cache and not _allowed_ips_cache:
        _load_whitelist_from_settings()

    if not target_host:
        return True # Allow empty host (e.g. for local file paths)

    # Check against allowed hostnames directly
    if target_host in _allowed_hosts_cache:
        return True

    # Attempt to resolve target host to IP
    try:
        target_ip = socket.gethostbyname(target_host)
        if target_ip in _allowed_ips_cache:
            return True
    except socket.gaierror:
        # If DNS resolution fails, and it's not a whitelisted hostname, deny access
        logger.warning(f"DNS resolution failed for {target_host} and it's not in allowed hosts. Blocking.")
        return False
    except Exception as e:
        logger.error(f"Error during host allowance check for {target_host}: {e}")
        return False

    return False

def is_url_allowed(url: str) -> bool:
    """
    Check if a target URL is allowed based on the configured whitelist.
    Extracts hostname from URL and calls is_host_allowed.
    """
    if not url:
        return True # Allow empty URL (e.g. for local file paths)

    parsed_url = urlparse(url)
    target_host = parsed_url.hostname

    if target_host is None:
        # If there's no hostname (e.g., relative URL or local file path), allow.
        return True
    
    # Special handling for localhost/127.0.0.1 if not explicitly in settings but implied as local
    if target_host in ["localhost", "127.0.0.1"]:
        return True

    return is_host_allowed(target_host)

# Reload whitelist if settings change (e.g., during CLI init)
def reload_whitelist():
    """Force reload the whitelist cache from current settings."""
    _load_whitelist_from_settings()
    logger.info("Network whitelist reloaded.")
