"""KG protocol + fact schema + default graph builder.

The rest of the codebase talks to the KG through the :class:`KG`
Protocol (a typing Protocol, so we don't need inheritance). Both
:class:`InMemoryKG` and :class:`Neo4jKG` satisfy it.

We model the graph using a deliberately small, vulnerability-centric
schema (taken from :file:`infra/neo4j/init/001_schema.cypher`):

- Nodes: ``CVE``, ``Framework``, ``Sink``, ``Source``, ``Payload``,
  ``Endpoint``, ``Parameter``, ``CWE``.
- Edges: ``AFFECTS``, ``CLASSIFIED_AS``, ``EXPLOITS``, ``TARGETS``,
  ``HAS_PARAM``, ``FLOWS_TO``, ``READS``, ``RUNS_ON``.

Each node has an ``id`` string (unique per node type) and arbitrary
string/number properties. Each edge carries its verb in ``rel`` and
optional metadata as properties.

The :func:`build_default_kg` helper seeds the in-memory graph with a
tiny corpus of CVE / payload / framework triples derived from the
three scaffold fixtures (IDOR, SSRF, SQLi). Real datasets land in
Sprint 8 (corpus distillation); the default builder exists so the
Dispatcher's `query_kg` tool has something useful to return today.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple


@dataclass(frozen=True)
class KGFact:
    """A single subject-predicate-object triple with metadata."""
    subject: str                 # "CVE:CVE-2023-12345"
    predicate: str               # "EXPLOITS"
    obj: str                     # "Sink:unsafe_sql_format"
    props: Dict[str, Any] = field(default_factory=dict)

    def to_text(self, max_prop_chars: int = 120) -> str:
        if not self.props:
            return f"{self.subject} -[{self.predicate}]-> {self.obj}"
        prop_text = ", ".join(
            f"{k}={_short(v, max_prop_chars)}" for k, v in self.props.items()
        )
        return f"{self.subject} -[{self.predicate} {{{prop_text}}}]-> {self.obj}"


class KG(Protocol):
    """Minimal interface every KG implementation must satisfy."""

    def add_node(self, node_type: str, node_id: str, **props: Any) -> None: ...
    def add_edge(self, src: str, rel: str, dst: str, **props: Any) -> None: ...
    def query_by_family(self, attack_family: str, limit: int = 10) -> List[KGFact]: ...
    def query_by_framework(self, framework: str, limit: int = 10) -> List[KGFact]: ...
    def query_triples(
        self,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        obj: Optional[str] = None,
        limit: int = 10,
    ) -> List[KGFact]: ...
    def neighbours(self, node_id: str, *, depth: int = 1, limit: int = 20) -> List[KGFact]: ...
    def size(self) -> Tuple[int, int]: ...
    def close(self) -> None: ...


def build_default_kg(kg: KG) -> None:
    """Seed ``kg`` with a minimal IDOR/SSRF/SQLi corpus + commonly-confused classes.

    Keeps the Dispatcher's ``query_kg`` tool useful out-of-the-box when
    no real corpus has been loaded yet (Sprint 8 brings the ~5k-entry
    CVE + writeup corpus per the plan).

    The seed deliberately covers vuln classes that benchmark fixtures
    have shown the LLM frequently *mis*-classifies (effect-instead-of-
    mechanism mistakes), so ``query_kg`` can disambiguate by returning a
    canonical triple for each class:

      - SQLi via login form is **SQLi**, not Auth Bypass
      - Mass Assignment via request-body fields is **Mass Assignment**, not IDOR
      - Session-cookie forgery (HMAC/JWT-none) is **Session Forgery** (JWT is the encoding)
      - File operation between stat/open on attacker path is **TOCTOU / Race Condition**, not RCE
    """
    # Frameworks
    kg.add_node("Framework", "Framework:flask", language="python")
    kg.add_node("Framework", "Framework:express", language="node")
    kg.add_node("Framework", "Framework:spring", language="java")
    kg.add_node("Framework", "Framework:django", language="python")
    kg.add_node("Framework", "Framework:rails", language="ruby")
    kg.add_node("Framework", "Framework:passport", language="node")

    # CWEs (canonical mapping vuln_class → CWE)
    kg.add_node("CWE", "CWE:639", label="Authorization Bypass Through User-Controlled Key")
    kg.add_node("CWE", "CWE:918", label="Server-Side Request Forgery")
    kg.add_node("CWE", "CWE:89", label="SQL Injection")
    kg.add_node("CWE", "CWE:915", label="Mass Assignment (Improperly Controlled Modification of Attributes)")
    kg.add_node("CWE", "CWE:284", label="Improper Access Control / Auth Bypass")
    kg.add_node("CWE", "CWE:287", label="Improper Authentication")
    kg.add_node("CWE", "CWE:384", label="Session Fixation / Session Forgery")
    kg.add_node("CWE", "CWE:367", label="TOCTOU Race Condition (Time-of-check Time-of-use)")
    kg.add_node("CWE", "CWE:362", label="Concurrent Execution using Shared Resource (Race Condition)")
    kg.add_node("CWE", "CWE:377", label="Insecure Temporary File")
    kg.add_node("CWE", "CWE:444", label="HTTP Request/Response Smuggling")
    kg.add_node("CWE", "CWE:22", label="Path Traversal / Directory Traversal")
    kg.add_node("CWE", "CWE:77", label="Command Injection")
    kg.add_node("CWE", "CWE:78", label="OS Command Injection")
    kg.add_node("CWE", "CWE:79", label="Cross-site Scripting (XSS)")
    kg.add_node("CWE", "CWE:94", label="Code Injection (incl. SSTI eval)")
    kg.add_node("CWE", "CWE:1321", label="Prototype Pollution")
    kg.add_node("CWE", "CWE:943", label="NoSQL Injection")

    # Sinks — the *mechanism* indicators used to disambiguate from effects
    kg.add_node("Sink", "Sink:unsafe_sql_format", lang="python", kind="raw_sql")
    kg.add_node("Sink", "Sink:unsafe_sql_in_login", lang="python", kind="raw_sql",
                hint="login form interpolating username/password into SQL — SQLi, NOT auth bypass")
    kg.add_node("Sink", "Sink:server_side_fetch", lang="python", kind="http_out")
    kg.add_node("Sink", "Sink:direct_object_lookup", lang="python", kind="dao")
    kg.add_node("Sink", "Sink:bulk_attr_assign", lang="python", kind="orm",
                hint="setattr(user, k, v) loop over request.body — Mass Assignment, NOT IDOR")
    kg.add_node("Sink", "Sink:weak_session_signer", lang="python", kind="auth",
                hint="custom HMAC/JWT cookie verifier accepting alg=none or weak secret")
    kg.add_node("Sink", "Sink:tempfile_predict", lang="python", kind="fs",
                hint="tempfile.mktemp / NamedTemporaryFile(delete=False) — Insecure Temp File")
    kg.add_node("Sink", "Sink:stat_then_open", lang="python", kind="fs",
                hint="os.path.exists/stat THEN open on attacker path — TOCTOU race")
    kg.add_node("Sink", "Sink:double_redeem", lang="python", kind="logic",
                hint="check balance, then decrement — concurrent requests reuse same row → Race Condition")
    kg.add_node("Sink", "Sink:nginx_error_page_smuggling", lang="config", kind="proxy",
                hint="nginx `error_page` with `proxy_pass` + keep-alive — CVE-2019-20372 class smuggling")
    kg.add_node("Sink", "Sink:nosql_injection", lang="node", kind="dao",
                hint="MongoDB find({user: req.body.user}) with $-operator in object → NoSQLi")

    # Payloads — each carries vuln_class explicitly so the model copies the label
    kg.add_node(
        "Payload", "Payload:idor_sibling_id",
        vuln_class="IDOR", template="GET /api/<resource>/<sibling_id>",
        oracle="response_contains_other_user_data",
        disambiguator="IDOR = read/access another id; Mass Assignment = mutate fields",
    )
    kg.add_node(
        "Payload", "Payload:ssrf_metadata",
        vuln_class="SSRF", template="POST {url: 'http://169.254.169.254/latest/meta-data/'}",
        oracle="server_fetches_internal_resource",
    )
    kg.add_node(
        "Payload", "Payload:sqli_auth_bypass",
        vuln_class="SQLi", template="username=admin' --",
        oracle="auth_bypass_via_injection",
        disambiguator=(
            "Login form bypass *via* SQL is SQLi (mechanism), not Auth Bypass (effect). "
            "Label by the injection mechanism."
        ),
    )
    kg.add_node(
        "Payload", "Payload:sqli_blocklist_comment",
        vuln_class="SQLi", template="db=information_schema/**/&table=tables",
        oracle="bypassed_blocklist_returns_blocked_db",
        disambiguator=(
            "Blocklist check on a raw SQL fragment is SQLi (comment/whitespace evasion). "
            "Do not call this an 'Auth Bypass' — the effect is data exfil via SQL parsing."
        ),
    )
    kg.add_node(
        "Payload", "Payload:mass_assignment_role",
        vuln_class="Mass Assignment",
        template='POST /signup {"name":"x","password":"y","is_admin":true}',
        oracle="created_user_has_unauthorized_role_attribute",
        disambiguator=(
            "Adding a body field that mutates a model attribute the client should not control = Mass Assignment. "
            "If you are only reading another id, that's IDOR; if you are *writing*, it's Mass Assignment."
        ),
    )
    kg.add_node(
        "Payload", "Payload:mass_assignment_string_slice",
        vuln_class="Mass Assignment",
        template="GET /resource?user=<sliced>X — bypassing string-slice sanitisation",
        oracle="modifies_other_users_field_not_just_read",
    )
    kg.add_node(
        "Payload", "Payload:session_forgery_none_alg",
        vuln_class="Session Forgery",
        template='Cookie: session=<base64({"alg":"none"}.payload.)>',
        oracle="server_accepts_unsigned_session_cookie",
        disambiguator=(
            "JWT 'none-alg' is one *technique*. Label by what's forged. "
            "If the cookie is an opaque server-issued session, call it Session Forgery. "
            "If the application explicitly uses JWT spec headers, JWT Forgery is fine — but "
            "still ask: is the JWT a *session container*? then Session Forgery."
        ),
    )
    kg.add_node(
        "Payload", "Payload:auth_bypass_logic",
        vuln_class="Auth Bypass",
        template="bypass via missing isAuthenticated() guard, case-mix /Profile vs deny /profile, etc.",
        oracle="reaches_protected_endpoint_without_credentials",
        disambiguator=(
            "Pure 'Auth Bypass' = no injection, no token forgery, no mass assignment — "
            "the auth check itself is structurally wrong (missing, case-sensitive, weak compare)."
        ),
    )
    kg.add_node(
        "Payload", "Payload:race_double_redeem",
        vuln_class="Race Condition",
        template="parallel POST /redeem with same coupon_id N times",
        oracle="balance_decremented_only_once_but_credited_N_times",
        disambiguator=(
            "Concurrency-based replay/double-spend = Race Condition (CWE-362). "
            "Do NOT call this RCE — there is no code execution."
        ),
    )
    kg.add_node(
        "Payload", "Payload:toctou_symlink_swap",
        vuln_class="TOCTOU",
        template="ln -s /etc/shadow /tmp/xxx between check() and open()",
        oracle="server_reads_file_outside_intended_path",
        disambiguator=(
            "TOCTOU = filesystem race between check and use. CWE-367. "
            "Sibling of Race Condition; pick TOCTOU when there is a stat+open pair."
        ),
    )
    kg.add_node(
        "Payload", "Payload:insecure_temp_file",
        vuln_class="Insecure Temp File",
        template="tempfile.mktemp() → predictable /tmp/foo<pid>",
        oracle="attacker_pre_creates_temp_path_to_redirect_or_overwrite",
    )
    kg.add_node(
        "Payload", "Payload:smuggle_error_page",
        vuln_class="HTTP Request Smuggling",
        template=(
            "GET /flag HTTP/1.1\\r\\nContent-Length: 56\\r\\n\\r\\n"
            "GET /flag.txt HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n"
        ),
        oracle="pipelined_smuggled_request_executed_on_same_keepalive_conn",
        disambiguator=(
            "nginx <1.17.7 `error_page` + `proxy_pass` + keep-alive → CVE-2019-20372. "
            "This is *Request Smuggling*, NOT Auth Bypass — the body of one request is "
            "reinterpreted as the next request on the same upstream connection."
        ),
    )
    kg.add_node(
        "Payload", "Payload:nosql_injection_op",
        vuln_class="NoSQLi",
        template='{"user":{"$ne":null},"password":{"$ne":null}}',
        oracle="bypassed_login_via_mongo_operator_injection",
    )
    kg.add_node(
        "Payload", "Payload:cmd_injection_shell",
        vuln_class="Command Injection",
        template="param=foo; cat /flag",
        oracle="shell_metachar_executed_as_separate_command",
    )
    kg.add_node(
        "Payload", "Payload:ssti_jinja",
        vuln_class="SSTI",
        template="{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
        oracle="server_renders_template_with_attacker_python_eval",
    )
    kg.add_node(
        "Payload", "Payload:xss_reflected",
        vuln_class="XSS",
        template="?q=<script>document.cookie</script>",
        oracle="response_reflects_unescaped_attacker_html",
    )
    kg.add_node(
        "Payload", "Payload:path_traversal_lfi",
        vuln_class="Path Traversal",
        template="?file=../../../../etc/passwd",
        oracle="response_includes_outside_root_file",
    )

    # Relations
    kg.add_edge("Payload:idor_sibling_id", "TARGETS", "Sink:direct_object_lookup")
    kg.add_edge("Payload:idor_sibling_id", "CLASSIFIED_AS", "CWE:639")
    kg.add_edge("Payload:ssrf_metadata", "TARGETS", "Sink:server_side_fetch")
    kg.add_edge("Payload:ssrf_metadata", "CLASSIFIED_AS", "CWE:918")
    kg.add_edge("Payload:sqli_auth_bypass", "TARGETS", "Sink:unsafe_sql_in_login")
    kg.add_edge("Payload:sqli_auth_bypass", "CLASSIFIED_AS", "CWE:89")
    kg.add_edge("Payload:sqli_blocklist_comment", "TARGETS", "Sink:unsafe_sql_format")
    kg.add_edge("Payload:sqli_blocklist_comment", "CLASSIFIED_AS", "CWE:89")
    kg.add_edge("Payload:mass_assignment_role", "TARGETS", "Sink:bulk_attr_assign")
    kg.add_edge("Payload:mass_assignment_role", "CLASSIFIED_AS", "CWE:915")
    kg.add_edge("Payload:mass_assignment_string_slice", "TARGETS", "Sink:bulk_attr_assign")
    kg.add_edge("Payload:mass_assignment_string_slice", "CLASSIFIED_AS", "CWE:915")
    kg.add_edge("Payload:session_forgery_none_alg", "TARGETS", "Sink:weak_session_signer")
    kg.add_edge("Payload:session_forgery_none_alg", "CLASSIFIED_AS", "CWE:384")
    kg.add_edge("Payload:auth_bypass_logic", "CLASSIFIED_AS", "CWE:287")
    kg.add_edge("Payload:race_double_redeem", "TARGETS", "Sink:double_redeem")
    kg.add_edge("Payload:race_double_redeem", "CLASSIFIED_AS", "CWE:362")
    kg.add_edge("Payload:toctou_symlink_swap", "TARGETS", "Sink:stat_then_open")
    kg.add_edge("Payload:toctou_symlink_swap", "CLASSIFIED_AS", "CWE:367")
    kg.add_edge("Payload:insecure_temp_file", "TARGETS", "Sink:tempfile_predict")
    kg.add_edge("Payload:insecure_temp_file", "CLASSIFIED_AS", "CWE:377")
    kg.add_edge("Payload:smuggle_error_page", "TARGETS", "Sink:nginx_error_page_smuggling")
    kg.add_edge("Payload:smuggle_error_page", "CLASSIFIED_AS", "CWE:444")
    kg.add_edge("Payload:nosql_injection_op", "TARGETS", "Sink:nosql_injection")
    kg.add_edge("Payload:nosql_injection_op", "CLASSIFIED_AS", "CWE:943")
    kg.add_edge("Payload:cmd_injection_shell", "CLASSIFIED_AS", "CWE:78")
    kg.add_edge("Payload:ssti_jinja", "CLASSIFIED_AS", "CWE:94")
    kg.add_edge("Payload:xss_reflected", "CLASSIFIED_AS", "CWE:79")
    kg.add_edge("Payload:path_traversal_lfi", "CLASSIFIED_AS", "CWE:22")

    # Cross-framework hints
    kg.add_edge("Sink:unsafe_sql_format", "OBSERVED_IN", "Framework:flask")
    kg.add_edge("Sink:unsafe_sql_in_login", "OBSERVED_IN", "Framework:passport")
    kg.add_edge("Sink:server_side_fetch", "OBSERVED_IN", "Framework:flask")
    kg.add_edge("Sink:direct_object_lookup", "OBSERVED_IN", "Framework:express")
    kg.add_edge("Sink:bulk_attr_assign", "OBSERVED_IN", "Framework:flask")
    kg.add_edge("Sink:bulk_attr_assign", "OBSERVED_IN", "Framework:rails")
    kg.add_edge("Sink:weak_session_signer", "OBSERVED_IN", "Framework:express")
    kg.add_edge("Sink:nosql_injection", "OBSERVED_IN", "Framework:express")


def _short(value: Any, limit: int) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
