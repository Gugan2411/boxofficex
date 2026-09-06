import json
import urllib.request
import urllib.error
from urllib.parse import quote

BASE = "https://boxofficex-1.onrender.com"
TIMEOUT = 35

PASS = "PASS"
FAIL = "FAIL"

def get(path):
    url = BASE + path
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "BoxOfficeX-Launch-Checker/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read()
            return r.status, body, r.headers.get("content-type", "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body, e.headers.get("content-type", "")
    except Exception as e:
        return None, str(e).encode(), ""

def check(path, label=None):
    status, body, ctype = get(path)
    ok = status is not None and 200 <= status < 400
    print(f"[{PASS if ok else FAIL}] {label or path}  status={status}")
    if not ok:
        preview = body.decode("utf-8", errors="replace")[:180].replace("\n", " ")
        print("       ", preview)
    return ok, status, body, ctype

print("=" * 66)
print("BOXOFFICEX PRE-LAUNCH PUBLIC ROUTE CHECK")
print("Base:", BASE)
print("=" * 66)

public_pages = [
    ("/", "Homepage"),
    ("/index.html", "Homepage /index.html"),
    ("/new-movies.html", "New Movies"),
    ("/movie-rankings.html", "Movie Rankings"),
    ("/actors.html", "Actors"),
    ("/articles.html", "Articles"),
    ("/compare-select.html", "Actor Compare Select"),
    ("/movie-compare-select.html", "Movie Compare Select"),
    ("/about.html", "About"),
    ("/contact.html", "Contact"),
    ("/privacy.html", "Privacy"),
    ("/terms.html", "Terms"),
    ("/disclaimer.html", "Disclaimer"),
    ("/robots.txt", "robots.txt"),
    ("/sitemap.xml", "sitemap.xml"),
]

results = []

print("\nPUBLIC PAGES")
for path, label in public_pages:
    ok, *_ = check(path, label)
    results.append((label, ok))

print("\nCORE PUBLIC APIs")
api_paths = [
    ("/movies", "Movies API"),
    ("/actors", "Actors API"),
    ("/articles/latest?limit=10", "Latest Articles API"),
]
api_cache = {}

for path, label in api_paths:
    ok, status, body, ctype = check(path, label)
    results.append((label, ok))
    if ok:
        try:
            api_cache[path] = json.loads(body.decode("utf-8"))
        except Exception:
            pass

print("\nDYNAMIC DETAIL ROUTES")

# First movie
movies = api_cache.get("/movies", {}).get("movies", [])
if movies:
    movie_id = movies[0].get("id")
    if movie_id is not None:
        for path, label in [
            (f"/movie.html?id={movie_id}", f"Movie page id={movie_id}"),
            (f"/movies/{movie_id}", f"Movie API id={movie_id}"),
        ]:
            ok, *_ = check(path, label)
            results.append((label, ok))
else:
    print("[SKIP] No movie found from /movies")

# First actor
actors_data = api_cache.get("/actors", {})
actors = actors_data.get("actors", actors_data if isinstance(actors_data, list) else [])
if actors:
    actor_id = actors[0].get("id")
    if actor_id is not None:
        for path, label in [
            (f"/actor.html?id={actor_id}", f"Actor page id={actor_id}"),
            (f"/actors/{actor_id}", f"Actor API id={actor_id}"),
        ]:
            ok, *_ = check(path, label)
            results.append((label, ok))
else:
    print("[SKIP] No actor found from /actors")

# First published article
articles = api_cache.get("/articles/latest?limit=10", {}).get("articles", [])
if articles:
    slug = articles[0].get("slug")
    if slug:
        for path, label in [
            (f"/article/{quote(str(slug))}", f"Article pretty URL: {slug}"),
            (f"/articles/{quote(str(slug))}", f"Article API: {slug}"),
        ]:
            ok, *_ = check(path, label)
            results.append((label, ok))
else:
    print("[SKIP] No published article found from latest-articles API")

print("\n" + "=" * 66)
failed = [name for name, ok in results if not ok]
passed = len(results) - len(failed)

print(f"RESULT: {passed} passed / {len(results)} checked")
if failed:
    print("FAILED:")
    for name in failed:
        print(" -", name)
    print("\nSend this failed section to ChatGPT.")
else:
    print("ALL CHECKED ROUTES PASSED.")
print("=" * 66)
