"""
intelligence/attack_vectors.py — map discovered technologies and open ports
to concrete attack vectors for ethical testing.

This module contains NO exploit code — it only surfaces known attack surfaces
so a tester knows where to look next.
"""

from __future__ import annotations

from typing import Any

# ── Technology → attack surface map ───────────────────────────────────────────

_TECH_VECTORS: dict[str, list[dict[str, str]]] = {
    "wordpress": [
        {"vector": "Admin panel brute force",          "path": "/wp-login.php",                     "severity": "medium"},
        {"vector": "XMLRPC exploitation (DoS/bruteforce)", "path": "/xmlrpc.php",                   "severity": "high"},
        {"vector": "REST API user enumeration",        "path": "/wp-json/wp/v2/users",              "severity": "medium"},
        {"vector": "Plugin vulnerabilities",           "path": "/wp-content/plugins/",              "severity": "high"},
        {"vector": "Theme vulnerabilities",            "path": "/wp-content/themes/",               "severity": "medium"},
        {"vector": "Backup/config file exposure",      "path": "/wp-config.php.bak",                "severity": "critical"},
        {"vector": "Debug log exposure",               "path": "/wp-content/debug.log",             "severity": "medium"},
        {"vector": "Upload directory listing",         "path": "/wp-content/uploads/",              "severity": "low"},
    ],
    "drupal": [
        {"vector": "Drupalgeddon RCE check",           "path": "/?q=admin/views/ajax/autocomplete/user/a", "severity": "critical"},
        {"vector": "Default admin",                    "path": "/user/login",                       "severity": "medium"},
        {"vector": "JSON:API endpoint",               "path": "/jsonapi/",                          "severity": "medium"},
        {"vector": "Install page exposed",             "path": "/install.php",                      "severity": "high"},
    ],
    "joomla": [
        {"vector": "Admin panel",                      "path": "/administrator/",                   "severity": "medium"},
        {"vector": "REST API",                         "path": "/api/index.php/v1/config/application?public=true", "severity": "high"},
        {"vector": "Config backup",                    "path": "/configuration.php.bak",            "severity": "critical"},
    ],
    "laravel": [
        {"vector": ".env file exposure",               "path": "/.env",                             "severity": "critical"},
        {"vector": "Laravel Telescope (debug UI)",     "path": "/telescope",                        "severity": "high"},
        {"vector": "Laravel Horizon (queue dashboard)","path": "/horizon",                          "severity": "high"},
        {"vector": "Debug bar assets",                 "path": "/_debugbar/open",                   "severity": "medium"},
        {"vector": "Storage link exposure",            "path": "/storage/",                         "severity": "medium"},
    ],
    "django": [
        {"vector": "Admin panel",                      "path": "/admin/",                           "severity": "medium"},
        {"vector": "DEBUG=True check (verbose errors)","path": "/this-should-404",                  "severity": "high"},
        {"vector": "Static file exposure",             "path": "/static/",                          "severity": "low"},
    ],
    "rails": [
        {"vector": "Rails debug info",                 "path": "/rails/info/properties",            "severity": "high"},
        {"vector": "Routes exposure",                  "path": "/rails/info/routes",                "severity": "medium"},
        {"vector": "Spring-style health check",        "path": "/health",                           "severity": "low"},
    ],
    "spring": [
        {"vector": "Actuator root (lists all endpoints)", "path": "/actuator",                      "severity": "high"},
        {"vector": "Environment variables dump",       "path": "/actuator/env",                     "severity": "critical"},
        {"vector": "Heap dump (memory disclosure)",    "path": "/actuator/heapdump",                "severity": "critical"},
        {"vector": "Beans / mappings disclosure",      "path": "/actuator/mappings",                "severity": "medium"},
        {"vector": "Logfile exposure",                 "path": "/actuator/logfile",                 "severity": "high"},
        {"vector": "Spring Boot Admin",                "path": "/admin",                            "severity": "high"},
    ],
    "express": [
        {"vector": "Debug/status endpoint",            "path": "/status",                           "severity": "low"},
        {"vector": "Stack trace on error",             "path": "/this-should-error",                "severity": "medium"},
    ],
    "fastapi": [
        {"vector": "OpenAPI schema exposure",          "path": "/openapi.json",                     "severity": "medium"},
        {"vector": "Swagger UI",                       "path": "/docs",                             "severity": "medium"},
        {"vector": "ReDoc",                            "path": "/redoc",                            "severity": "low"},
    ],
    "flask": [
        {"vector": "Debug mode Werkzeug console",      "path": "/console",                          "severity": "critical"},
        {"vector": "Debugger PIN bypass",              "path": "/__debugger__/",                    "severity": "critical"},
    ],
    "nginx": [
        {"vector": "Off-by-slash path traversal",      "path": "/api../",                           "severity": "medium"},
        {"vector": "Nginx status page",                "path": "/nginx_status",                     "severity": "low"},
        {"vector": "Stub status page",                 "path": "/stub_status",                      "severity": "low"},
    ],
    "apache": [
        {"vector": "Server status page",               "path": "/server-status",                    "severity": "low"},
        {"vector": "Server info page",                 "path": "/server-info",                      "severity": "low"},
        {"vector": ".htaccess exposure",               "path": "/.htaccess",                        "severity": "medium"},
        {"vector": "mod_status remote IPs",            "path": "/server-status?auto",               "severity": "low"},
    ],
    "iis": [
        {"vector": "Trace.axd debug info",             "path": "/trace.axd",                        "severity": "high"},
        {"vector": "ELMAH error logs",                 "path": "/elmah.axd",                        "severity": "high"},
        {"vector": "WebResource.axd",                  "path": "/WebResource.axd",                  "severity": "low"},
        {"vector": "ViewState CSRF / MAC bypass",      "path": "/",                                 "severity": "medium"},
    ],
    "tomcat": [
        {"vector": "Manager web UI (RCE via WAR upload)", "path": "/manager/html",                  "severity": "critical"},
        {"vector": "Host manager",                     "path": "/host-manager/html",                "severity": "critical"},
        {"vector": "Default credential check",         "path": "/manager/text/list",                "severity": "high"},
    ],
    "graphql": [
        {"vector": "Introspection query (schema disclosure)", "path": "/graphql",                   "severity": "medium"},
        {"vector": "GraphQL playground / explorer",   "path": "/graphiql",                          "severity": "low"},
        {"vector": "Batching / nested query DoS",     "path": "/graphql",                           "severity": "medium"},
    ],
    "elasticsearch": [
        {"vector": "Unauthenticated index access",     "path": "/_cat/indices?v",                   "severity": "critical"},
        {"vector": "Cluster health info",              "path": "/_cluster/health",                  "severity": "high"},
        {"vector": "Node stats",                       "path": "/_nodes/stats",                     "severity": "medium"},
    ],
    "kibana": [
        {"vector": "Kibana dashboard (no auth)",       "path": "/app/kibana",                       "severity": "high"},
        {"vector": "Console RCE check",                "path": "/api/console/proxy",                "severity": "critical"},
    ],
    "jenkins": [
        {"vector": "Script console RCE",               "path": "/script",                           "severity": "critical"},
        {"vector": "Credential dumping",               "path": "/credentials/",                     "severity": "high"},
        {"vector": "Job/build secrets",                "path": "/job/",                             "severity": "high"},
        {"vector": "Unauthenticated API",              "path": "/api/json",                         "severity": "medium"},
    ],
    "gitlab": [
        {"vector": "Public project enumeration",       "path": "/explore/projects",                 "severity": "medium"},
        {"vector": "GraphQL endpoint",                 "path": "/api/graphql",                      "severity": "medium"},
        {"vector": "Snippets / gists exposure",        "path": "/explore/snippets",                 "severity": "medium"},
    ],
    "prometheus": [
        {"vector": "Metrics endpoint (data disclosure)", "path": "/metrics",                        "severity": "medium"},
        {"vector": "Admin API",                        "path": "/api/v1/targets",                   "severity": "medium"},
    ],
    "grafana": [
        {"vector": "Default credentials (admin:admin)", "path": "/login",                           "severity": "high"},
        {"vector": "API key exposure",                 "path": "/api/org/users",                    "severity": "medium"},
        {"vector": "Snapshot exposure",                "path": "/dashboard/snapshot/",              "severity": "low"},
    ],
    "phpmyadmin": [
        {"vector": "Direct admin access",              "path": "/phpmyadmin/",                      "severity": "high"},
        {"vector": "Alternate paths",                  "path": "/pma/",                             "severity": "high"},
    ],
    "php": [
        {"vector": "phpinfo() exposure",               "path": "/phpinfo.php",                      "severity": "medium"},
        {"vector": "PHP-FPM status",                   "path": "/status",                           "severity": "low"},
        {"vector": ".php~ backup files",               "path": "/index.php~",                       "severity": "medium"},
    ],
    "next.js": [
        {"vector": "Source map exposure",              "path": "/_next/static/chunks/",             "severity": "medium"},
        {"vector": "API routes enumeration",           "path": "/api/",                             "severity": "medium"},
        {"vector": "__NEXT_DATA__ secrets",            "path": "/",                                 "severity": "medium"},
    ],
    "react": [
        {"vector": "Source map exposure",              "path": "/static/js/main.chunk.js.map",      "severity": "medium"},
        {"vector": "ENV variables in bundle",          "path": "/static/js/main.chunk.js",          "severity": "high"},
    ],
    "vue": [
        {"vector": "Source map exposure",              "path": "/js/app.js.map",                    "severity": "medium"},
    ],
    "angular": [
        {"vector": "Source map exposure",              "path": "/main.js.map",                      "severity": "medium"},
        {"vector": "environment.ts in bundle",         "path": "/main.js",                          "severity": "medium"},
    ],
    "swagger": [
        {"vector": "Full API spec exposure",           "path": "/swagger.json",                     "severity": "medium"},
        {"vector": "Swagger UI",                       "path": "/swagger-ui.html",                  "severity": "medium"},
        {"vector": "OpenAPI v3",                       "path": "/openapi.yaml",                     "severity": "medium"},
    ],
    "kubernetes": [
        {"vector": "K8s API server",                   "path": "/api/v1/namespaces",                "severity": "critical"},
        {"vector": "Dashboard exposure",               "path": "/api/v1/namespaces/kube-system/services", "severity": "critical"},
    ],
    "docker": [
        {"vector": "Docker daemon API",                "path": "/containers/json",                  "severity": "critical"},
        {"vector": "Docker registry API",              "path": "/v2/_catalog",                      "severity": "high"},
    ],
    "woocommerce": [
        {"vector": "REST API (order/customer data)",   "path": "/wp-json/wc/v3/products",           "severity": "medium"},
        {"vector": "Consumer key brute force",         "path": "/wp-json/wc/v3/system_status",      "severity": "high"},
    ],
}

# ── Open port → attack surface map ────────────────────────────────────────────

_PORT_VECTORS: dict[int, list[dict[str, str]]] = {
    21:    [{"vector": "FTP — anonymous login or brute force",         "severity": "high"}],
    22:    [{"vector": "SSH — brute force or key abuse",               "severity": "medium"}],
    23:    [{"vector": "Telnet — plaintext credentials",               "severity": "high"}],
    25:    [{"vector": "SMTP — open relay or user enumeration",        "severity": "medium"}],
    53:    [{"vector": "DNS — zone transfer (AXFR)",                   "severity": "medium"}],
    80:    [{"vector": "HTTP — no TLS, potential downgrade",           "severity": "low"}],
    110:   [{"vector": "POP3 — plaintext mail access",                 "severity": "medium"}],
    143:   [{"vector": "IMAP — plaintext mail access",                 "severity": "medium"}],
    389:   [{"vector": "LDAP — anonymous bind / information leak",     "severity": "high"}],
    443:   [{"vector": "HTTPS — check TLS version and cipher suites",  "severity": "info"}],
    445:   [{"vector": "SMB — EternalBlue, credential relay (NTLM)",   "severity": "critical"}],
    1433:  [{"vector": "MSSQL — brute force, sa account, xp_cmdshell","severity": "high"}],
    1521:  [{"vector": "Oracle DB — default credentials, TNS poison",  "severity": "high"}],
    2375:  [{"vector": "Docker API (unauthenticated — remote RCE)",    "severity": "critical"}],
    2376:  [{"vector": "Docker TLS API — cert abuse",                  "severity": "high"}],
    3000:  [{"vector": "Dev server / Grafana — default creds",         "severity": "medium"}],
    3306:  [{"vector": "MySQL — exposed publicly, brute force",        "severity": "high"}],
    3389:  [{"vector": "RDP — brute force, BlueKeep (CVE-2019-0708)",  "severity": "critical"}],
    4848:  [{"vector": "GlassFish admin — default creds",              "severity": "high"}],
    5000:  [{"vector": "Flask/dev server or Docker registry",          "severity": "medium"}],
    5432:  [{"vector": "PostgreSQL — exposed publicly, brute force",   "severity": "high"}],
    5601:  [{"vector": "Kibana — unauthenticated access",              "severity": "high"}],
    5900:  [{"vector": "VNC — no authentication or weak password",     "severity": "critical"}],
    6379:  [{"vector": "Redis — no auth (unauthenticated RCE via SLAVEOF)", "severity": "critical"}],
    7001:  [{"vector": "WebLogic — deserialisation RCE",               "severity": "critical"}],
    8080:  [{"vector": "HTTP alt — admin panels, Tomcat, Jenkins",     "severity": "medium"}],
    8443:  [{"vector": "HTTPS alt — admin panels, Kubernetes API",     "severity": "medium"}],
    8888:  [{"vector": "Jupyter Notebook — unauthenticated RCE",       "severity": "critical"}],
    9000:  [{"vector": "SonarQube / PHP-FPM — access control bypass",  "severity": "high"}],
    9090:  [{"vector": "Prometheus — metrics and API exposure",        "severity": "medium"}],
    9200:  [{"vector": "Elasticsearch — unauthenticated data access",  "severity": "critical"}],
    9300:  [{"vector": "Elasticsearch transport — cluster join attack", "severity": "high"}],
    11211: [{"vector": "Memcached — no auth, data leak, DDoS amplification", "severity": "high"}],
    27017: [{"vector": "MongoDB — no auth, full database access",      "severity": "critical"}],
    27018: [{"vector": "MongoDB shard — no auth",                      "severity": "high"}],
    50000: [{"vector": "SAP Message Server — CVE-2020-6207",           "severity": "critical"}],
}

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def suggest(
    technologies: list[str],
    open_ports: list[int],
) -> list[dict[str, Any]]:
    """
    Return suggested attack vectors for a host based on its tech stack
    and open ports.

    Args:
        technologies: Technology strings detected by httpx (case-insensitive).
        open_ports:   Open port numbers detected by naabu.

    Returns:
        Deduplicated list of vector dicts sorted by severity (critical first).
        Each dict has keys: ``vector``, ``severity``, and either ``path``
        (tech-based) or ``port`` (port-based).
    """
    vectors: list[dict[str, Any]] = []
    seen: set[str] = set()

    # Technology-based vectors
    for tech in technologies:
        tech_lower = tech.lower()
        for key, tech_vectors in _TECH_VECTORS.items():
            if key in tech_lower or tech_lower.startswith(key):
                for v in tech_vectors:
                    if v["vector"] not in seen:
                        seen.add(v["vector"])
                        vectors.append({"source": "technology", "technology": tech, **v})

    # Port-based vectors
    for port in open_ports:
        if port in _PORT_VECTORS:
            for v in _PORT_VECTORS[port]:
                if v["vector"] not in seen:
                    seen.add(v["vector"])
                    vectors.append({"source": "port", "port": port, **v})

    vectors.sort(key=lambda v: _SEV_ORDER.get(v["severity"], 0), reverse=True)
    return vectors
