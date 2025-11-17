# CVE Enrichment Module

This module provides CVE (Common Vulnerabilities and Exposures) enrichment capabilities for DMARRSS threat scoring. It integrates vulnerability severity intelligence using CVE and CVSS data from the NIST NVD (National Vulnerability Database) API.

## Features

### 1. CVE Detection
- Automatically scans event logs and alert metadata for CVE identifiers
- Uses regex pattern: `\bCVE-\d{4}-\d+\b`
- Detects CVEs in signatures, categories, and raw event data

### 2. CVSS Data Fetching
- Fetches CVSS v3.1 (preferred) or v3.0 scores from NIST NVD API
- Extracts comprehensive vulnerability metrics:
  - `baseScore` - CVSS base score (0.0-10.0)
  - `severity` - Severity level (CRITICAL, HIGH, MEDIUM, LOW, NONE)
  - `exploitabilityScore` - Exploitability metric
  - `attackVector` - Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)
  - `attackComplexity` - Attack complexity
  - `description` - Vulnerability description

### 3. Caching Layer
- **In-memory cache**: Fast lookups with TTL-based expiration
- **Persistent cache**: Optional JSON file storage for cache persistence across sessions
- **Configurable TTL**: Default 24 hours, customizable via config
- Cache reduces API calls and improves performance

### 4. Scoring Augmentation
The CVE enrichment integrates with DMARRSS's threat scoring engine:

```python
adjusted_score = original_score + (base_score / 10.0) * cve_weight
```

Where:
- `original_score`: Baseline composite threat score (0.0-1.0)
- `base_score`: CVSS base score (0.0-10.0)
- `cve_weight`: Configurable weight (default: 0.3)

### 5. CVSS to Severity Mapping

| CVSS Score | Severity |
|------------|----------|
| 9.0 - 10.0 | CRITICAL |
| 7.0 - 8.9  | HIGH     |
| 4.0 - 6.9  | MEDIUM   |
| 0.1 - 3.9  | LOW      |
| 0.0        | NONE     |

### 6. Classification Override
For critical vulnerabilities:
- If severity is CRITICAL or HIGH AND baseScore >= 9.0
- Override model classification and force threat score to >= 0.9
- Ensures critical vulnerabilities are always prioritized

### 7. Enrichment Output
Events are enriched with the following metadata:

```json
{
  "cve_enrichment": {
    "cves": [
      {
        "cve_id": "CVE-2023-12345",
        "cvss_base_score": 9.8,
        "cvss_severity": "CRITICAL",
        "cve_summary": "Critical remote code execution vulnerability..."
      }
    ],
    "max_cvss_score": 9.8,
    "max_severity": "CRITICAL",
    "enrichment_timestamp": "2024-01-01T12:00:00"
  }
}
```

Additionally, CVE tags are added to the event:
```python
event.tags = ["cve:CVE-2023-12345", ...]
```

### 8. Fault Tolerance
The enricher handles failures gracefully:
- **API timeouts**: Returns cached data if available, otherwise continues without enrichment
- **API errors**: Falls back to cached data or baseline scoring
- **Missing CVEs**: Continues processing without disruption
- **Malformed data**: Handles parsing errors silently
- Pipeline never halts due to enrichment failures

## Configuration

Add the following to `config/dmarrss_config.yaml`:

```yaml
scoring:
  # CVE enrichment settings
  cve_weight: 0.30                           # Weight for CVSS contribution (0.0-1.0)
  cve_cache_file: "./data/cache/cve_cache.json"  # Persistent cache file path
  cve_timeout: 10.0                         # API request timeout in seconds
  cve_cache_ttl_hours: 24                   # Cache TTL in hours
```

## Usage

### Basic Usage

```python
from dmarrss.enrichment import CVEEnricher

# Initialize enricher
enricher = CVEEnricher(
    cache_file="./data/cache/cve_cache.json",
    timeout=10.0,
    cache_ttl_hours=24
)

# Detect CVEs in text
text = "Critical vulnerability CVE-2023-12345 detected"
cve_ids = enricher.detect_cves(text)
# Returns: ["CVE-2023-12345"]

# Fetch CVE data
cve_data = enricher.fetch_cve_data("CVE-2023-12345")
# Returns: {
#   "base_score": 9.8,
#   "severity": "CRITICAL",
#   "attack_vector": "NETWORK",
#   ...
# }

# Enrich event
event = {
    "signature": "Exploit for CVE-2023-12345",
    "source_ip": "10.0.0.1",
    ...
}
enriched = enricher.enrich_event(event)
# Event now contains cve_enrichment field
```

### Integration with ThreatScorer

The CVE enricher is automatically integrated into the ThreatScorer:

```python
from dmarrss.scoring import ThreatScorer
from dmarrss.schemas import Event

# ThreatScorer automatically initializes CVEEnricher
scorer = ThreatScorer(config, store)

# Score event with CVE enrichment
event = Event(...)
enriched_event, components, final_score = scorer.enrich_and_score_event(event)

# Event is now enriched and scored
print(f"Threat score: {final_score}")
print(f"CVE tags: {enriched_event.tags}")
```

## API Reference

### CVEEnricher

#### `__init__(cache_file=None, timeout=10.0, cache_ttl_hours=24)`
Initialize the CVE enricher.

**Parameters:**
- `cache_file` (str, optional): Path to persistent cache file
- `timeout` (float): HTTP request timeout in seconds
- `cache_ttl_hours` (int): Cache TTL in hours

#### `detect_cves(text: str) -> list[str]`
Detect CVE identifiers in text.

**Returns:** List of unique CVE identifiers found

#### `fetch_cve_data(cve_id: str) -> dict | None`
Fetch CVE data from NVD API or cache.

**Returns:** Dictionary with CVSS data or None if not found

#### `enrich_event(event: dict) -> dict`
Enrich event with CVE and CVSS data.

**Returns:** Enriched event dictionary

#### `get_severity_mapping(cvss_score: float) -> str`
Map CVSS base score to severity level.

**Returns:** Severity level string (CRITICAL, HIGH, MEDIUM, LOW, NONE)

#### `clear_cache() -> None`
Clear in-memory and persistent cache.

## Testing

The module includes comprehensive unit tests:

```bash
# Run CVE enricher tests
pytest tests/test_cve_enricher.py -v

# Run integration tests
pytest tests/test_cve_scoring_integration.py -v

# Run all tests
pytest tests/test_cve*.py -v
```

Test coverage:
- CVE detection and parsing (5 tests)
- API data fetching (4 tests)
- Caching mechanisms (4 tests)
- Event enrichment (3 tests)
- Severity mapping (5 tests)
- Scoring integration (6 tests)

Total: 27 tests with 91% coverage

## Performance Considerations

1. **Caching**: First API call for a CVE incurs ~1-2s latency. Subsequent calls are instant (in-memory cache).
2. **TTL**: Default 24-hour TTL balances freshness and performance.
3. **Parallel Processing**: Consider rate limiting for batch processing to avoid NVD API throttling.
4. **Persistent Cache**: Use file-based cache for production to persist across restarts.

## Limitations

1. **NVD API Rate Limits**: NIST NVD API has rate limits. Use caching to minimize API calls.
2. **CVE Coverage**: Only CVEs in NVD database are enriched. Zero-day vulnerabilities won't be found.
3. **CVSS Version**: Prefers CVSS v3.1, falls back to v3.0. Older CVSS v2 scores are not used.
4. **Network Dependency**: Requires internet access to NVD API (unless fully cached).

## Future Enhancements

Potential improvements for future versions:
- [ ] Batch API requests for multiple CVEs
- [ ] Integration with additional vulnerability databases (CVE Details, Vulners, etc.)
- [ ] Webhook notifications for newly detected critical CVEs
- [ ] Historical CVE trend analysis
- [ ] Custom severity scoring rules
- [ ] Database backend for cache (Redis, SQLite)

## References

- [NIST NVD API Documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CVE Program](https://www.cve.org/)
