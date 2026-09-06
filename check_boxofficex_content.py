import json
import urllib.request
import urllib.error
import urllib.parse
from collections import Counter

BASE = "https://boxofficex-1.onrender.com"
TIMEOUT = 35

def fetch_json(path):
    req = urllib.request.Request(
        BASE + path,
        headers={"User-Agent": "BoxOfficeX-Content-Audit/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return None, {"error": str(e)}

issues = []
warnings = []
passed = []

def issue(msg): issues.append(msg)
def warn(msg): warnings.append(msg)
def ok(msg): passed.append(msg)

def blank(v):
    return v is None or (isinstance(v, str) and not v.strip())

print("=" * 70)
print("BOXOFFICEX CONTENT & DATA QUALITY AUDIT")
print("READ-ONLY — no database changes")
print("Base:", BASE)
print("=" * 70)

# Movies
status, payload = fetch_json("/movies")
movies = payload.get("movies", []) if isinstance(payload, dict) else []
if status == 200:
    ok(f"Movies API loaded ({len(movies)} movies)")
else:
    issue(f"Movies API failed: {payload}")

movie_titles = []
for m in movies:
    mid = m.get("id")
    title = m.get("title")
    movie_titles.append(str(title or "").strip().lower())

    for field, label in [
        ("title", "title"),
        ("release_date", "release date"),
        ("language", "language"),
        ("director", "director"),
        ("poster", "poster"),
    ]:
        if blank(m.get(field)):
            issue(f"Movie id={mid}: missing {label}")

    # Read full movie record when possible.
    st, full = fetch_json(f"/movies/{mid}")
    if st != 200:
        issue(f"Movie id={mid}: detail API failed")
        continue

    data = full.get("movie", full) if isinstance(full, dict) else {}
    india = data.get("india_collection_crore")
    overseas = data.get("overseas_collection_crore")
    worldwide = data.get("worldwide_collection_crore")

    try:
        if india is not None and overseas is not None and worldwide is not None:
            expected = float(india) + float(overseas)
            if abs(expected - float(worldwide)) > 0.11:
                warn(
                    f"Movie id={mid} {title!r}: India ({india}) + Overseas "
                    f"({overseas}) != Worldwide ({worldwide})"
                )
    except Exception:
        warn(f"Movie id={mid} {title!r}: collection values are not numeric")

for title, count in Counter(movie_titles).items():
    if title and count > 1:
        warn(f"Duplicate movie title: {title!r} appears {count} times")

# Actors
status, payload = fetch_json("/actors")
if isinstance(payload, dict):
    actors = payload.get("actors", [])
elif isinstance(payload, list):
    actors = payload
else:
    actors = []

if status == 200:
    ok(f"Actors API loaded ({len(actors)} actors)")
else:
    issue(f"Actors API failed: {payload}")

actor_names = []
for a in actors:
    aid = a.get("id")
    name = a.get("name")
    actor_names.append(str(name or "").strip().lower())

    if blank(name):
        issue(f"Actor id={aid}: missing name")

    # Image key names differ across versions, so check detail record too.
    st, full = fetch_json(f"/actors/{aid}")
    if st != 200:
        issue(f"Actor id={aid}: detail API failed")
        continue

    data = full.get("actor", full) if isinstance(full, dict) else {}
    image = (
        data.get("image")
        or data.get("photo")
        or data.get("image_url")
        or data.get("actor_image")
    )
    if blank(image):
        warn(f"Actor id={aid} {name!r}: no actor image detected")

for name, count in Counter(actor_names).items():
    if name and count > 1:
        warn(f"Duplicate actor name: {name!r} appears {count} times")

# Articles
status, payload = fetch_json("/articles/latest?limit=100")
articles = payload.get("articles", []) if isinstance(payload, dict) else []

if status == 200:
    ok(f"Published articles API loaded ({len(articles)} articles)")
else:
    issue(f"Latest Articles API failed: {payload}")

slugs = []
article_titles = []
for a in articles:
    slug = str(a.get("slug") or "").strip()
    title = str(a.get("title") or "").strip()
    slugs.append(slug.lower())
    article_titles.append(title.lower())

    if not slug:
        issue(f"Published article {title!r}: missing slug")
        continue
    if not title:
        issue(f"Article slug={slug}: missing title")

    st, full = fetch_json("/articles/" + urllib.parse.quote(slug))
    if st != 200:
        issue(f"Article {slug!r}: detail API failed")
        continue

    data = full.get("article", full) if isinstance(full, dict) else {}

    if blank(data.get("subtitle")):
        warn(f"Article {slug!r}: missing subtitle")
    if blank(data.get("category")):
        warn(f"Article {slug!r}: missing category")
    if blank(data.get("author")):
        warn(f"Article {slug!r}: missing author")
    if blank(data.get("hero_image")):
        warn(f"Article {slug!r}: missing hero image")
    if blank(data.get("meta_title")):
        warn(f"Article {slug!r}: missing custom SEO meta title")
    if blank(data.get("meta_description")):
        warn(f"Article {slug!r}: missing custom SEO meta description")

for slug, count in Counter(slugs).items():
    if slug and count > 1:
        issue(f"Duplicate article slug: {slug!r} appears {count} times")

for title, count in Counter(article_titles).items():
    if title and count > 1:
        warn(f"Duplicate published article title: {title!r} appears {count} times")

print("\nSUMMARY")
print("-" * 70)
for msg in passed:
    print("[PASS]", msg)

if warnings:
    print("\nWARNINGS")
    for msg in warnings:
        print("[WARN]", msg)

if issues:
    print("\nISSUES")
    for msg in issues:
        print("[FAIL]", msg)

print("\n" + "=" * 70)
print(f"PASS GROUPS: {len(passed)} | WARNINGS: {len(warnings)} | ISSUES: {len(issues)}")
if not issues and not warnings:
    print("CONTENT AUDIT CLEAN.")
elif not issues:
    print("NO CRITICAL DATA FAILURES. Review warnings before launch.")
else:
    print("FIX THE FAIL ITEMS BEFORE LAUNCH.")
print("=" * 70)
