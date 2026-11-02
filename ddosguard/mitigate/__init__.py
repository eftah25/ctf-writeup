"""Automated mitigation: rate limiting and firewall rule generation."""
from .ratelimit import RateLimiter, TokenBucket
from .firewall import FirewallManager
from .policy import MitigationPolicy, severity_to_stage, stage_to_severity
