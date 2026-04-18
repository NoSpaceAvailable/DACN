# Neo4j Knowledge Graph

Used by the RAG layer (Sprint 5+) to store entity-relation facts extracted
from inputs and the CVE/writeup corpus. Agents query it via Cypher to get
small, structured triples instead of dumping raw text into the prompt
(token saver — see `architecture-v2.md` §3.4 C3).

## Bring it up (dev machine or VPS)

```bash
cd infra/neo4j

# 1. Pick a password (KEEP THIS SECRET; do not commit .env)
echo "NEO4J_PASSWORD=$(openssl rand -hex 16)" > .env

# 2. Start the container
docker compose up -d

# 3. Wait for the healthcheck to pass
docker compose ps      # STATUS should say "healthy" in ~20s

# 4. Apply the schema (idempotent)
NEO4J_PASSWORD=$(grep NEO4J_PASSWORD .env | cut -d= -f2)
docker exec -i dacn-neo4j cypher-shell -u neo4j -p "$NEO4J_PASSWORD" \
    < init/001_schema.cypher
```

## Connect from Python (Sprint 5)

```python
from neo4j import GraphDatabase

driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", PASSWORD))
with driver.session() as session:
    result = session.run(
        "MATCH (c:CVE)-[:EXPLOITS]->(s:Sink) "
        "WHERE s.framework = $fw RETURN c.id AS cve, c.payload AS payload",
        fw="Spring",
    )
    for record in result:
        print(record["cve"], record["payload"])
```

## Browser UI

http://127.0.0.1:7474 (only bound to 127.0.0.1, never expose to the internet).

## Reset

```bash
docker compose down -v   # WARNING: drops the graph volume
docker compose up -d
# re-apply schema as in step 4 above
```

## Limitations
- Only port-forwarded on `127.0.0.1`. To use from another machine, tunnel
  via SSH (`ssh -L 7687:127.0.0.1:7687 user@vps`) — do NOT bind 0.0.0.0.
- Heap capped at 1G, page cache 256M — tuned for a small dev corpus
  (≤100k nodes). Bump in `docker-compose.yml` for larger imports.
- Schema constraints assume idempotent `MERGE` writes; Sprint 5 must use
  `MERGE`, not `CREATE`, when populating.
