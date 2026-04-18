// DACN Knowledge Graph — schema bootstrap (idempotent).
//
// Run once after the container is healthy:
//   docker exec -i dacn-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" < init/001_schema.cypher
//
// Sprint 5 will populate the graph from input (HTTP transcript, source code,
// CVE feeds, researcher writeups). Sprint 2 only declares the schema so the
// graph is queryable from day one and constraints prevent dupes.

// ── unique-key constraints ─────────────────────────────────────────────────
CREATE CONSTRAINT cve_id           IF NOT EXISTS FOR (c:CVE)        REQUIRE c.id          IS UNIQUE;
CREATE CONSTRAINT endpoint_path    IF NOT EXISTS FOR (e:Endpoint)   REQUIRE e.path        IS UNIQUE;
CREATE CONSTRAINT framework_name   IF NOT EXISTS FOR (f:Framework)  REQUIRE f.name        IS UNIQUE;
CREATE CONSTRAINT sink_signature   IF NOT EXISTS FOR (s:Sink)       REQUIRE s.signature   IS UNIQUE;
CREATE CONSTRAINT source_signature IF NOT EXISTS FOR (s:Source)     REQUIRE s.signature   IS UNIQUE;
CREATE CONSTRAINT param_unique     IF NOT EXISTS FOR (p:Parameter)  REQUIRE (p.endpoint, p.name) IS UNIQUE;
CREATE CONSTRAINT payload_id       IF NOT EXISTS FOR (p:Payload)    REQUIRE p.id          IS UNIQUE;
CREATE CONSTRAINT cwe_id           IF NOT EXISTS FOR (w:CWE)        REQUIRE w.id          IS UNIQUE;

// ── lookup indexes for common agent queries ────────────────────────────────
CREATE INDEX framework_lang        IF NOT EXISTS FOR (f:Framework)  ON (f.language);
CREATE INDEX cve_class             IF NOT EXISTS FOR (c:CVE)        ON (c.vuln_class);
CREATE INDEX payload_class         IF NOT EXISTS FOR (p:Payload)    ON (p.vuln_class);
CREATE INDEX endpoint_method       IF NOT EXISTS FOR (e:Endpoint)   ON (e.method);

// ── relationship types (for documentation; Neo4j is schema-flexible on rels):
//   (CVE)-[:AFFECTS]->(Framework)
//   (CVE)-[:CLASSIFIED_AS]->(CWE)
//   (CVE)-[:EXPLOITS]->(Sink)
//   (Payload)-[:TARGETS]->(Sink)
//   (Payload)-[:BYPASSES]->(Defense)
//   (Endpoint)-[:HAS_PARAM]->(Parameter)
//   (Parameter)-[:FLOWS_TO]->(Sink)
//   (Source)-[:READS]->(Parameter)
//   (Endpoint)-[:RUNS_ON]->(Framework)
