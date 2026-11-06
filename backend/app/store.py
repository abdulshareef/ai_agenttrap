"""Append-only, hash-chained event store. SQLite for local/dev, Firestore for production."""
import hashlib, json, sqlite3, threading, time

GENESIS = "0" * 64

def canon(ev: dict) -> str:
    return json.dumps({k: v for k, v in ev.items() if k != "hash"}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def chain_hash(ev: dict) -> str:
    return hashlib.sha256(canon(ev).encode()).hexdigest()

def verify_events(events) -> dict:
    """events: iterable in ascending seq order."""
    prev, n = GENESIS, 0
    for ev in events:
        n += 1
        if ev.get("prev") != prev:
            return {"ok": False, "checked": n, "broken_at": ev.get("seq"), "reason": "prev-hash mismatch (gap, deletion or reorder)"}
        if chain_hash(ev) != ev.get("hash"):
            return {"ok": False, "checked": n, "broken_at": ev.get("seq"), "reason": "content hash mismatch (record altered)"}
        prev = ev["hash"]
    return {"ok": True, "checked": n, "head": prev}


class SqliteStore:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript("""
            create table if not exists events(seq integer primary key, ip text, body text not null);
            create index if not exists ix_ip on events(ip);
            create table if not exists intel(ip text primary key, body text not null);""")

    def append(self, ev: dict) -> dict:
        with self.lock:
            row = self.db.execute("select seq, body from events order by seq desc limit 1").fetchone()
            seq, prev = (row[0] + 1, json.loads(row[1])["hash"]) if row else (1, GENESIS)
            ev = {**ev, "seq": seq, "prev": prev}
            ev["hash"] = chain_hash(ev)
            self.db.execute("insert into events(seq, ip, body) values (?,?,?)", (seq, ev.get("ip"), json.dumps(ev)))
            self.db.commit()
            return ev

    def _rows(self, sql, args=()):
        with self.lock:
            return [json.loads(r[0]) for r in self.db.execute(sql, args).fetchall()]

    def recent(self, limit=5000):
        return list(reversed(self._rows("select body from events order by seq desc limit ?", (limit,))))

    def by_ip(self, ip):
        return self._rows("select body from events where ip=? order by seq", (ip,))

    def all_ascending(self):
        return self._rows("select body from events order by seq")

    def get_intel(self, ip):
        r = self._rows("select body from intel where ip=?", (ip,))
        return r[0] if r else None

    def set_intel(self, ip, data):
        with self.lock:
            self.db.execute("insert or replace into intel(ip, body) values (?,?)", (ip, json.dumps(data)))
            self.db.commit()


class FirestoreStore:
    """Collections: agenttrap_events/{seq:012d}, agenttrap_meta/head, agenttrap_intel/{ip}. Chain append is one Firestore transaction."""
    def __init__(self, client=None, transactional=None):
        if client is None:
            from google.cloud import firestore
            client = firestore.Client()
            transactional = firestore.transactional
        self.c, self._transactional = client, transactional
        self.events = client.collection("agenttrap_events")
        self.head = client.collection("agenttrap_meta").document("head")

    def append(self, ev: dict) -> dict:
        def work(tx):
            snap = self.head.get(transaction=tx)
            h = snap.to_dict() if snap.exists else {"seq": 0, "hash": GENESIS}
            out = {**ev, "seq": h["seq"] + 1, "prev": h["hash"]}
            out["hash"] = chain_hash(out)
            tx.set(self.events.document(f"{out['seq']:012d}"), out)
            tx.set(self.head, {"seq": out["seq"], "hash": out["hash"]})
            return out
        for attempt in range(6):
            try:
                return self._transactional(work)(self.c.transaction())
            except Exception:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def recent(self, limit=5000):
        from google.cloud import firestore
        docs = self.events.order_by("seq", direction=firestore.Query.DESCENDING).limit(limit).stream()
        return sorted((d.to_dict() for d in docs), key=lambda e: e["seq"])

    def by_ip(self, ip):
        return sorted((d.to_dict() for d in self.events.where("ip", "==", ip).stream()), key=lambda e: e["seq"])

    def all_ascending(self):
        return [d.to_dict() for d in self.events.order_by("seq").stream()]

    def get_intel(self, ip):
        d = self.c.collection("agenttrap_intel").document(ip.replace("/", "_")).get()
        return d.to_dict() if d.exists else None

    def set_intel(self, ip, data):
        self.c.collection("agenttrap_intel").document(ip.replace("/", "_")).set(data)


def make_store(settings):
    return FirestoreStore() if settings.store == "firestore" else SqliteStore(settings.sqlite_path)
