# Universal API Endpoint Discovery & Analysis Prompt

## Overview
A domain-agnostic methodology for discovering business logic API endpoints through browser-based interaction, with integrated data enrichment via MCP servers.

---

## PROMPT

```
TASK: Perform a comprehensive API endpoint discovery and traffic analysis for [TARGET_DOMAIN].

═══════════════════════════════════════════════════════════════════════════════
PHASE 1: SITE RECONNAISSANCE
═══════════════════════════════════════════════════════════════════════════════

1.1 INITIAL NAVIGATION
    └─> Navigate to https://[TARGET_DOMAIN]
    └─> Capture accessibility snapshot
    └─> Identify site type (SaaS, E-commerce, Media, API service, etc.)
    └─> Document primary navigation elements
    
1.2 SITEMAP DISCOVERY
    └─> Check /sitemap.xml
    └─> Check /robots.txt for disallowed paths (often reveal API routes)
    └─> Identify all major sections from navigation
    └─> List all tool/feature pages
    
1.3 CATEGORIZE SITE FUNCTIONALITY
    For each discovered page, classify as:
    □ Content page (static, no API interaction)
    □ Tool page (user input → processing → output)
    □ Account page (auth required)
    □ Transaction page (payment/checkout)
    □ Dashboard page (data display)

═══════════════════════════════════════════════════════════════════════════════
PHASE 2: USER FLOW MAPPING
═══════════════════════════════════════════════════════════════════════════════

For EACH tool/feature page identified:

2.1 IDENTIFY USER JOURNEY
    └─> What is the user trying to accomplish?
    └─> What inputs does the user provide?
    └─> What outputs does the user receive?
    └─> What intermediate steps exist?

2.2 MAP INTERACTION POINTS
    □ Text inputs (textareas, input fields)
    □ File uploads
    □ Dropdowns/selects (modes, options, languages)
    □ Buttons (submit, process, generate, analyze)
    □ Toggles (features on/off)
    □ Sliders (intensity, length, parameters)
    
2.3 DOCUMENT USER FLOW SEQUENCE
    Step 1: User lands on page → [Initial API calls]
    Step 2: User enters data → [Validation/preview API calls]
    Step 3: User clicks action → [Main processing API call]
    Step 4: User receives result → [Result/analytics API calls]
    Step 5: User performs secondary action → [Follow-up API calls]

═══════════════════════════════════════════════════════════════════════════════
PHASE 3: ENDPOINT DISCOVERY (Browser-Based)
═══════════════════════════════════════════════════════════════════════════════

3.1 PASSIVE OBSERVATION
    └─> Open Browser DevTools → Network tab
    └─> Enable "Preserve log"
    └─> Filter by: XHR/Fetch
    └─> Navigate to page and observe requests during:
        • Page load
        • Idle state (background polling)
        • Scroll events
        
3.2 ACTIVE INTERACTION
    For each interaction point from Phase 2:
    
    a) TEXT INPUT INTERACTION:
       └─> Click input area
       └─> Type sample text: "The quick brown fox jumps over the lazy dog. 
           This sentence contains multiple clauses for thorough testing."
       └─> Wait 3 seconds (capture debounced calls)
       └─> Document triggered requests
       
    b) FORM SUBMISSION:
       └─> Fill all required fields with valid test data
       └─> Click submit/action button
       └─> Capture POST/PUT request details:
           • Full URL path
           • HTTP method
           • Request headers (especially custom X-* headers)
           • Request body (JSON structure)
           • Response structure
           
    c) DROPDOWN/SELECT CHANGE:
       └─> Change each option
       └─> Document if selection triggers API call
       └─> Note parameter changes in subsequent requests
       
    d) SECONDARY ACTIONS:
       └─> After receiving result, interact with output
       └─> Copy, download, share, save buttons
       └─> Modification/editing of result

3.3 JAVASCRIPT SOURCE ANALYSIS
    └─> Network tab → Filter by "JS"
    └─> Identify core application bundles (usually largest .js files)
    └─> For each bundle, search Response content for:
        • "/api/"
        • "api/"
        • "endpoint"
        • "fetch("
        • ".post("
        • ".get("
        • "axios"
        • "XMLHttpRequest"
        • Domain-specific terms identified in Phase 1
    └─> Extract all URL patterns found

3.4 WEBSOCKET DISCOVERY
    └─> Network tab → Filter by "WS"
    └─> Document WebSocket connections:
        • URL (ws:// or wss://)
        • Query parameters
        • Message types (send sample input, observe messages)
        
3.5 ERROR STATE PROBING
    └─> Submit empty form → capture validation endpoint
    └─> Submit invalid data → capture error response format
    └─> Submit oversized data → capture limit errors
    └─> Rapid submissions → capture rate limit responses

═══════════════════════════════════════════════════════════════════════════════
PHASE 4: ENDPOINT CLASSIFICATION
═══════════════════════════════════════════════════════════════════════════════

Classify each discovered endpoint:

TIER 1 - CORE BUSINESS LOGIC (User directly triggers)
    └─> Main product functionality
    └─> Revenue-generating features
    └─> Primary user actions

TIER 2 - SUPPORTING FEATURES (Auto-triggered)
    └─> Validation endpoints
    └─> Preview/suggestion endpoints
    └─> Analytics/tracking
    └─> Background sync

TIER 3 - REAL-TIME/STREAMING
    └─> WebSocket connections
    └─> Server-sent events
    └─> Long-polling endpoints

TIER 4 - CONFIGURATION/SUPPORT
    └─> Feature flags
    └─> User preferences
    └─> Localization

TIER 5 - AUTHENTICATION/SESSION
    └─> Login/logout
    └─> Token refresh
    └─> Session validation

═══════════════════════════════════════════════════════════════════════════════
PHASE 5: DATA ENRICHMENT VIA MCP SERVERS
═══════════════════════════════════════════════════════════════════════════════

5.1 POSTGRES MCP - Zone & Traffic Data
    
    Step 1: Find zone ID for domain
    ```sql
    SELECT DISTINCT zone_id, name 
    FROM cloudflare_raw_dns_records_history 
    WHERE name = '[TARGET_DOMAIN]' 
       OR name LIKE '%.[TARGET_DOMAIN]'
    LIMIT 10;
    ```
    
    Step 2: Get zone information
    ```sql
    SELECT name, status, plan_name, type, paused
    FROM cloudflare_raw_zones_history
    WHERE cf_id = '[ZONE_ID]'
    ORDER BY modification_date DESC LIMIT 1;
    ```
    
    Step 3: Get aggregate traffic (last 24h)
    ```sql
    SELECT 
        SUM(metric_value) as total_requests,
        MIN(metric_timestamp) as period_start,
        MAX(metric_timestamp) as period_end
    FROM cloudflare_raw_zone_metrics_history
    WHERE zone_id = '[ZONE_ID]'
    AND metric_timestamp >= NOW() - INTERVAL '24 hours';
    ```
    
    Step 4: Security action breakdown
    ```sql
    SELECT security_action, SUM(metric_value) as count
    FROM cloudflare_raw_zone_metrics_history
    WHERE zone_id = '[ZONE_ID]'
    AND metric_timestamp >= NOW() - INTERVAL '24 hours'
    GROUP BY security_action
    ORDER BY count DESC;
    ```
    
    Step 5: WAF rule activity
    ```sql
    SELECT 
        COALESCE(r.description, 'Unknown') as rule,
        rm.action,
        SUM(rm.metric_value) as hits
    FROM cloudflare_raw_rules_metrics_history rm
    LEFT JOIN cloudflare_raw_rulesets_rules r ON rm.rule_id = r.id
    WHERE rm.zone_id = '[ZONE_ID]'
    AND rm.metric_timestamp >= NOW() - INTERVAL '24 hours'
    GROUP BY r.description, rm.action
    HAVING SUM(rm.metric_value) > 0
    ORDER BY hits DESC
    LIMIT 20;
    ```
    
    Step 6: DNS records (subdomains)
    ```sql
    SELECT DISTINCT name, type
    FROM cloudflare_raw_dns_records_history
    WHERE zone_id = '[ZONE_ID]'
    ORDER BY name;
    ```

5.2 TRINO MCP - Endpoint-Level Traffic (if available)
    
    ```sql
    -- Request path distribution
    SELECT 
        request_path,
        COUNT(*) as request_count,
        AVG(response_time_ms) as avg_latency
    FROM cloudflare_logs.requests
    WHERE zone_id = '[ZONE_ID]'
    AND request_path LIKE '/api/%'
    AND timestamp >= NOW() - INTERVAL '24' HOUR
    GROUP BY request_path
    ORDER BY request_count DESC
    LIMIT 50;
    
    -- Status code distribution per endpoint
    SELECT 
        request_path,
        status_code,
        COUNT(*) as count
    FROM cloudflare_logs.requests
    WHERE zone_id = '[ZONE_ID]'
    AND request_path LIKE '/api/%'
    AND timestamp >= NOW() - INTERVAL '24' HOUR
    GROUP BY request_path, status_code
    ORDER BY request_path, count DESC;
    ```

5.3 VIRUSTOTAL MCP - Security Analysis
    
    └─> Get domain report:
        mcp_virustotal_get_domain_report(domain="[TARGET_DOMAIN]")
        
    └─> Check for malicious activity:
        • Security vendor analysis
        • DNS history
        • SSL certificate info
        • Related threat actors
        
    └─> Check subdomains:
        mcp_virustotal_get_domain_relationship(
            domain="[TARGET_DOMAIN]",
            relationship="subdomains"
        )

5.4 BROWSER MCP - Live Interaction
    
    └─> browser_navigate(url="https://[TARGET_DOMAIN]")
    └─> browser_snapshot() - Get page structure
    └─> browser_network_requests() - Capture API calls
    └─> browser_click(element, ref) - Interact with elements
    └─> browser_type(element, ref, text) - Input data
    └─> browser_console_messages() - Check for errors/debug info

═══════════════════════════════════════════════════════════════════════════════
PHASE 6: DOCUMENTATION
═══════════════════════════════════════════════════════════════════════════════

6.1 ENDPOINT INVENTORY TABLE
    For each endpoint, document:
    
    | Field | Value |
    |-------|-------|
    | Path | /api/... |
    | Method | POST/GET/PUT/DELETE |
    | Tier | 1-5 |
    | User Trigger | What action causes this call |
    | Request Headers | Custom headers required |
    | Request Body | JSON schema |
    | Response Format | JSON schema |
    | Auth Required | Yes/No/Session |
    | Rate Limited | Yes/No/Unknown |
    | Business Purpose | What this accomplishes |

6.2 USER FLOW DIAGRAMS
    ```
    User Action → API Call → Response → Next Action
    ```

6.3 SECURITY POSTURE
    └─> Total traffic volume
    └─> Blocked attack types
    └─> WAF rules protecting endpoints
    └─> Rate limiting evidence

6.4 INFRASTRUCTURE MAP
    └─> Subdomains discovered
    └─> CDN structure
    └─> Third-party integrations
    └─> WebSocket servers

═══════════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════════════════════════════════

Create a markdown document with:

1. Executive Summary
   - Domain type
   - Total endpoints discovered
   - Key findings

2. Methodology
   - Crawl flow diagram
   - Tools used (Browser MCP, Postgres MCP, etc.)

3. Endpoint Inventory
   - Tier 1 (Core Business Logic)
   - Tier 2 (Supporting)
   - Tier 3 (Real-time)
   - Tier 4 (Configuration)
   - Tier 5 (Auth)

4. User Flow Analysis
   - Per-feature journey maps
   - API call sequences

5. Traffic Analysis (from Postgres)
   - Zone information
   - Aggregate metrics
   - Security posture

6. Security Analysis (from VirusTotal)
   - Domain reputation
   - Threat intelligence

7. Queries Used
   - All SQL queries with explanations
   - Reusable for future analysis

```

---

## QUICK START CHECKLIST

```
□ 1. Navigate to target domain via Browser MCP
□ 2. Take snapshot, identify site type
□ 3. List all feature/tool pages
□ 4. For each page:
    □ Map user journey
    □ Interact with all inputs
    □ Capture network requests
    □ Document API calls
□ 5. Analyze JavaScript bundles for hidden endpoints
□ 6. Check WebSocket connections
□ 7. Query Postgres for zone data
□ 8. Query VirusTotal for security intel
□ 9. Classify endpoints by tier
□ 10. Generate documentation
```

---

## MCP SERVER REFERENCE

### Browser MCP
| Function | Purpose |
|----------|---------|
| `browser_navigate(url)` | Go to page |
| `browser_snapshot()` | Get page accessibility tree |
| `browser_network_requests()` | List all captured requests |
| `browser_click(element, ref)` | Click element |
| `browser_type(element, ref, text)` | Type into field |
| `browser_take_screenshot(filename)` | Visual capture |
| `browser_console_messages()` | Get console output |

### Postgres MCP
| Table | Contains |
|-------|----------|
| `cloudflare_raw_zones_history` | Zone info (plan, status) |
| `cloudflare_raw_zone_metrics_history` | Aggregate traffic |
| `cloudflare_raw_rules_metrics_history` | WAF rule hits |
| `cloudflare_raw_rulesets_rules` | Rule definitions |
| `cloudflare_raw_dns_records_history` | DNS/subdomains |

### VirusTotal MCP
| Function | Purpose |
|----------|---------|
| `get_domain_report(domain)` | Full domain analysis |
| `get_domain_relationship(domain, relationship)` | Subdomains, DNS, etc. |
| `get_url_report(url)` | Specific URL analysis |
| `get_ip_report(ip)` | IP intelligence |

### Trino MCP (if available)
| Table | Contains |
|-------|----------|
| `cloudflare_logs.requests` | Individual HTTP requests |
| `cloudflare_logs.firewall_events` | WAF events with URLs |

---

## SITE TYPE ADAPTATIONS

### SaaS/Tool Sites (like QuillBot)
- Focus on: Tool pages, processing APIs
- Look for: Mode selectors, strength sliders, language dropdowns
- Key endpoints: Processing, validation, suggestions

### E-commerce Sites
- Focus on: Product pages, cart, checkout
- Look for: Add to cart, inventory check, payment processing
- Key endpoints: Cart API, checkout API, inventory API

### Content/Media Sites
- Focus on: Search, recommendations, personalization
- Look for: Infinite scroll, related content
- Key endpoints: Search API, recommendation API, tracking

### API-First Services
- Focus on: Documentation pages, API playground
- Look for: API keys, rate limits, versioning
- Key endpoints: The documented API itself

### Social/Community Sites
- Focus on: Posts, comments, reactions, notifications
- Look for: Real-time updates, WebSockets
- Key endpoints: Feed API, notification API, messaging API

### Dashboard/Analytics Sites
- Focus on: Data visualization, export, filtering
- Look for: Date ranges, filters, aggregations
- Key endpoints: Data query API, export API, filter API

---

## ANTI-DETECTION NOTES

1. **Use real browser** - Browser MCP operates actual Chromium
2. **Natural timing** - Don't spam interactions
3. **Complete flows** - Start from page load, follow user journey
4. **Maintain session** - Let cookies persist
5. **Avoid suspicious patterns** - Don't enumerate URLs programmatically
6. **Respect robots.txt** - Note disallowed paths but don't abuse

---

## EXAMPLE INVOCATION

```
Perform endpoint discovery for example.com:

1. Browser: Navigate to https://example.com
2. Browser: Snapshot and identify features
3. Browser: For each feature, interact and capture APIs
4. Postgres: Find zone ID for example.com
5. Postgres: Get traffic metrics
6. VirusTotal: Get domain security report
7. Document all findings
```
