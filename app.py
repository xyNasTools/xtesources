"""
xtesource — xyNasTools Plugin Registry Server

Serves a catalog of .xte plugin files so that Core instances can discover
and install plugins without manual file transfer.

Security model:
  - Catalog (GET /catalog.json) requires the key when AUTH_TOKEN is set.
  - Plugin downloads (GET /plugins/<file>) are protected by an optional
    Bearer token (AUTH_TOKEN env var). Set it to restrict who can download.
  - File serving is locked to the PLUGINS_DIR directory; path traversal is
    blocked by both filename regex and Path.resolve() containment check.
  - No user-supplied input reaches the filesystem except through the strict
    regex match on the filename segment.
  - SHA-256 checksums are published in the catalog so downloaders can verify
    integrity after transfer.
"""

import atexit
import hashlib
import ipaddress
import json
import logging
import mimetypes
import os
import re
import threading
import time
import zipfile
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template_string, request, send_from_directory

# ── Config ────────────────────────────────────────────────────────────────────

PLUGINS_DIR    = Path(os.environ.get('PLUGINS_DIR',    '/app/plugins')).resolve()
BACKGROUND_DIR = Path(os.environ.get('BACKGROUND_DIR', '/app/background')).resolve()
ICON_DIR       = Path(os.environ.get('ICON_DIR',       '/app/icon')).resolve()
SOURCE_NAME    = os.environ.get('SOURCE_NAME', 'xyNasTools Plugin Registry')
SOURCE_URL     = os.environ.get('SOURCE_URL', '')
AUTH_TOKEN     = os.environ.get('AUTH_TOKEN', '')       # empty = no download auth
CATALOG_TTL    = int(os.environ.get('CATALOG_TTL', '60'))  # seconds
ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', '')   # empty = no CORS header

_BG_EXTS = frozenset({'.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif'})
_BG_MIME = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.png': 'image/png',  '.webp': 'image/webp',
    '.gif': 'image/gif',  '.avif': 'image/avif',
}


def _find_background() -> Path | None:
    """Return the first image file found in BACKGROUND_DIR, or None."""
    if not BACKGROUND_DIR.exists():
        return None
    for f in sorted(BACKGROUND_DIR.iterdir()):
        if f.is_file() and f.suffix.lower() in _BG_EXTS:
            return f
    return None

# Strict: only {id}-{version}.xte filenames are served
_FILENAME_RE   = re.compile(r'^[a-z][a-z0-9_]*-\d+\.\d+\.\d+\.xte$')
_PLUGIN_ID_RE  = re.compile(r'^[a-z][a-z0-9_]*$')

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# ── In-memory catalog cache ───────────────────────────────────────────────────

_cache: dict | None = None
_cache_ts: float = 0.0
_cache_lock = threading.Lock()
_build_lock = threading.Lock()   # prevents thundering herd on cache miss

# Background cache: resolved once, invalidated by watchdog
_bg_cache: Path | None = None
_bg_cache_valid = False
_bg_lock = threading.Lock()

# Icon cache: plugin_id → (bytes, mime) — avoids re-extracting ZIP per request
_icon_cache: dict[str, tuple[bytes, str]] = {}
_icon_lock = threading.Lock()


def _invalidate_cache() -> None:
    global _cache, _cache_ts, _bg_cache, _bg_cache_valid
    with _cache_lock:
        _cache = None
        _cache_ts = 0.0
    with _bg_lock:
        _bg_cache_valid = False
    with _icon_lock:
        _icon_cache.clear()


def _get_catalog() -> dict:
    global _cache, _cache_ts
    now = time.monotonic()
    with _cache_lock:
        if _cache is not None and (now - _cache_ts) <= CATALOG_TTL:
            return _cache  # fast path — cache is fresh

    # Cache miss: only one thread rebuilds, others wait and reuse the result
    with _build_lock:
        # Re-check after acquiring build lock — another thread may have built it
        with _cache_lock:
            now = time.monotonic()
            if _cache is not None and (now - _cache_ts) <= CATALOG_TTL:
                return _cache
        built = _build_catalog()
        with _cache_lock:
            _cache = built
            _cache_ts = time.monotonic()
        return built


def _get_background() -> Path | None:
    global _bg_cache, _bg_cache_valid
    with _bg_lock:
        if _bg_cache_valid:
            return _bg_cache
        result = _find_background()
        _bg_cache = result
        _bg_cache_valid = True
        return result


# ── Watchdog — real-time folder monitoring ────────────────────────────────────

def _start_dir_watcher() -> None:
    """Watch PLUGINS_DIR for .xte file changes and invalidate the catalog cache."""
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        class _XteWatcher(FileSystemEventHandler):
            def on_any_event(self, event):
                if not event.is_directory and str(event.src_path).endswith('.xte'):
                    log.info('Plugin dir change (%s: %s) — invalidating catalog',
                             getattr(event, 'event_type', '?'), Path(event.src_path).name)
                    _invalidate_cache()

        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
        obs = Observer()
        obs.schedule(_XteWatcher(), str(PLUGINS_DIR), recursive=False)
        obs.daemon = True
        obs.start()
        atexit.register(obs.stop)
        log.info('Watching %s for .xte changes', PLUGINS_DIR)
    except ImportError:
        log.warning('watchdog not installed — catalog refreshes every %ds (TTL fallback)', CATALOG_TTL)
    except Exception as exc:
        log.warning('Could not start directory watcher: %s', exc)


_start_dir_watcher()


# ── Catalog builder ───────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _read_manifest(path: Path) -> dict | None:
    if not zipfile.is_zipfile(path):
        return None
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            if 'manifest.json' not in zf.namelist():
                return None
            return json.loads(zf.read('manifest.json').decode('utf-8'))
    except Exception as exc:
        log.warning('Cannot read manifest from %s: %s', path.name, exc)
        return None


def _build_catalog() -> dict:
    plugins = []
    for f in sorted(PLUGINS_DIR.glob('*.xte')):
        if not f.is_file():
            continue
        if not _FILENAME_RE.match(f.name):
            log.warning('Skipping %s — filename does not match safe pattern', f.name)
            continue
        manifest = _read_manifest(f)
        if not manifest:
            log.warning('Skipping %s — not a valid .xte archive', f.name)
            continue
        try:
            sha256 = _sha256(f)
        except OSError as exc:
            log.error('Cannot hash %s: %s', f.name, exc)
            continue

        plugin_id = manifest.get('id', '')
        plugins.append({
            'id':               plugin_id,
            'name':             manifest.get('name', ''),
            'version':          manifest.get('version', ''),
            'description':      manifest.get('description', ''),
            'long_description': manifest.get('long_description', ''),
            'plugin_type':      manifest.get('plugin_type', ''),
            'dependencies':     manifest.get('dependencies', []),
            'tags':             manifest.get('tags', []),
            'developer':        manifest.get('developer', {}),
            'license':          manifest.get('license', ''),
            'platform_min_version': manifest.get('platform_min_version', ''),
            'integration_check': manifest.get('integration_check', {}),
            'market':           manifest.get('market', {}),
            'icon_file':        manifest.get('icon_file', ''),
            'filename':         f.name,
            'download_path':    f'/plugins/{f.name}',
            'size_bytes':       f.stat().st_size,
            'sha256':           sha256,
            # Convenience URL for consumers — always valid; falls back to platform icon if
            # no icon_file is embedded in the archive.
            'icon_url':         f'/plugin-icons/{plugin_id}',
        })
    return {
        'schema_version': '1',
        'source_name':    SOURCE_NAME,
        'source_url':     SOURCE_URL,
        'updated_at':     datetime.now(tz=timezone.utc).isoformat(),
        'plugin_count':   len(plugins),
        'plugins':        plugins,
    }


# ── Auth decorator ────────────────────────────────────────────────────────────

def _require_token(f):
    """Enforce key auth when AUTH_TOKEN is configured.

    Accepts the key in either of two ways:
      - Query parameter:  GET /plugins/foo.xte?key=<AUTH_TOKEN>
      - Header (raw):     Authorization: <AUTH_TOKEN>   (no Bearer prefix needed)
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        if AUTH_TOKEN:
            provided = (
                request.args.get('key', '')
                or request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
            )
            if provided != AUTH_TOKEN:
                abort(401, 'Unauthorized.')
        return f(*args, **kwargs)
    return wrapped


# ── CORS helper ───────────────────────────────────────────────────────────────

@app.after_request
def _add_cors(resp: Response) -> Response:
    if ALLOWED_ORIGIN:
        resp.headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type'
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return resp


# ── Homepage template ─────────────────────────────────────────────────────────

_HOMEPAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<link rel="icon" type="image/png" href="/market.png"/>
<link rel="apple-touch-icon" href="/market.png"/>
<title>xyNasTools Plugins</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg0:         #03060f;
    --border:      rgba(37,99,235,0.22);
    --border-glow: rgba(37,99,235,0.35);
    --accent:      #3b82f6;
    --accent-bright: #60a5fa;
    --accent-dim:  #1d4ed8;
    --purple:      #818cf8;
    --text:        #e2e8f0;
    --muted:       #64748b;
    --tag-bg:      rgba(30,58,95,0.70);
    --tag-text:    #93c5fd;
    --glass-card:  rgba(10,22,46,0.55);
    --glass-stats: rgba(5,12,28,0.55);
  }

  html, body { min-height: 100vh; color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; }

  /* Base dark background; user image (if any) sits beneath */
  body {
    background-color: var(--bg0);
    {% if has_bg %}
    background-image: url('/bg');
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
    background-repeat: no-repeat;
    {% endif %}
  }

  /* Full-screen glass overlay — dims background image and adds blue accents */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    {% if has_bg %}
    /* Dark glass base covers the whole viewport, then blue accents layer on top */
    background:
      radial-gradient(ellipse 70% 50% at 15% 0%,  rgba(10,31,77,0.50) 0%, transparent 60%),
      radial-gradient(ellipse 50% 40% at 85% 10%, rgba(13,45,110,0.45) 0%, transparent 55%),
      radial-gradient(ellipse 35% 35% at 50% 95%, rgba(6,15,36, 0.60) 0%, transparent 60%),
      linear-gradient(rgba(3,6,15,0.68), rgba(3,6,15,0.68));
    backdrop-filter: blur(3px) saturate(70%);
    -webkit-backdrop-filter: blur(3px) saturate(70%);
    {% else %}
    background:
      radial-gradient(ellipse 80% 60% at 20% 0%,  rgba(10,31,77,1) 0%, transparent 60%),
      radial-gradient(ellipse 60% 50% at 80% 10%, rgba(13,45,110,1) 0%, transparent 55%),
      radial-gradient(ellipse 40% 40% at 50% 90%, rgba(6,15,36, 1) 0%, transparent 60%);
    {% endif %}
  }

  /* All content sits above the gradient overlay */
  .hero, .stats, .section, footer { position: relative; z-index: 1; }

  /* ── Header ── */
  .hero { text-align: center; padding: 72px 24px 56px; }
  .hero::after {
    content: '';
    position: absolute;
    bottom: 0; left: 10%; right: 10%;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--border), rgba(37,99,235,0.45), var(--border), transparent);
  }
  .logo-wrap {
    display: inline-flex; align-items: center; justify-content: center;
    width: 88px; height: 88px; border-radius: 22px;
    background: linear-gradient(135deg, rgba(13,45,110,0.80) 0%, rgba(26,58,143,0.70) 50%, rgba(10,31,77,0.80) 100%);
    border: 1.5px solid rgba(37,99,235,0.45);
    box-shadow: 0 0 24px rgba(37,99,235,0.30), 0 0 60px rgba(29,78,216,0.15), inset 0 1px 0 rgba(255,255,255,0.08);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    margin-bottom: 28px;
  }
  .logo-wrap img { width: 56px; height: 56px; border-radius: 12px; object-fit: contain; }
  .hero-title {
    font-size: 2.6rem; font-weight: 700; letter-spacing: -0.5px;
    background: linear-gradient(135deg, #93c5fd 0%, #e2e8f0 45%, #818cf8 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    margin-bottom: 10px;
  }
  .hero-sub { font-size: 1.05rem; color: var(--muted); margin-bottom: 32px; }
  .hero-actions { display: flex; gap: 12px; justify-content: center; flex-wrap: wrap; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px;
    padding: 10px 22px; border-radius: 8px; font-size: 0.9rem; font-weight: 500;
    text-decoration: none; transition: all 0.18s; cursor: pointer; border: none;
  }
  .btn-primary { background: var(--accent); color: #fff; box-shadow: 0 0 18px rgba(59,130,246,0.40); }
  .btn-primary:hover { background: var(--accent-bright); box-shadow: 0 0 28px rgba(96,165,250,0.50); transform: translateY(-1px); }
  .btn-outline {
    background: rgba(255,255,255,0.04);
    color: var(--accent-bright);
    border: 1px solid var(--border);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }
  .btn-outline:hover { border-color: rgba(96,165,250,0.50); background: rgba(255,255,255,0.08); transform: translateY(-1px); }

  /* ── Stats — glass band ── */
  .stats {
    display: flex; justify-content: center; gap: 0;
    padding: 32px 24px;
    background: var(--glass-stats);
    backdrop-filter: blur(16px) saturate(140%);
    -webkit-backdrop-filter: blur(16px) saturate(140%);
    border-top: 1px solid var(--border);
    border-bottom: 1px solid var(--border);
  }
  .stat { text-align: center; padding: 0 40px; border-right: 1px solid var(--border); }
  .stat:last-child { border-right: none; }
  .stat-value { font-size: 2rem; font-weight: 700; color: var(--accent-bright); display: block; }
  .stat-label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; }

  /* ── Section ── */
  .section { max-width: 1100px; margin: 0 auto; padding: 48px 24px; }
  .section-title { font-size: 1.1rem; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 24px; }

  /* ── Plugin grid — glass cards ── */
  .plugin-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 20px; }
  .plugin-card {
    background: var(--glass-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 24px;
    transition: all 0.22s;
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(18px) saturate(150%);
    -webkit-backdrop-filter: blur(18px) saturate(150%);
  }
  /* subtle shimmer top edge */
  .plugin-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(96,165,250,0.30), transparent);
    opacity: 0;
    transition: opacity 0.2s;
  }
  .plugin-card:hover {
    border-color: rgba(96,165,250,0.45);
    background: rgba(13,28,58,0.72);
    box-shadow: 0 8px 32px rgba(37,99,235,0.18), 0 0 0 1px rgba(96,165,250,0.12);
    transform: translateY(-2px);
  }
  .plugin-card:hover::before { opacity: 1; }

  .plugin-header { display: flex; align-items: flex-start; gap: 14px; margin-bottom: 10px; }
  .plugin-icon {
    width: 42px; height: 42px; border-radius: 10px; flex-shrink: 0;
    background: linear-gradient(135deg, rgba(26,58,143,0.80), rgba(15,32,87,0.80));
    border: 1px solid rgba(37,99,235,0.35);
    display: flex; align-items: center; justify-content: center;
    overflow: hidden;
  }
  .plugin-icon img { width: 28px; height: 28px; object-fit: contain; display: block; }
  .plugin-name { font-size: 1.05rem; font-weight: 600; color: var(--text); }
  .plugin-version {
    font-size: 0.72rem; font-weight: 500;
    background: var(--tag-bg); color: var(--tag-text);
    border-radius: 4px; padding: 1px 6px;
    display: inline-block; margin-top: 4px;
  }
  .plugin-desc {
    font-size: 0.87rem; color: var(--muted); margin: 12px 0;
    display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;
  }
  .plugin-meta { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 14px; }
  .tag { font-size: 0.72rem; background: var(--tag-bg); color: var(--tag-text); border-radius: 4px; padding: 2px 8px; }
  .tag-type { background: rgba(30,27,75,0.70); color: var(--purple); }
  .plugin-footer {
    display: flex; align-items: center; justify-content: space-between;
    margin-top: 16px; padding-top: 14px;
    border-top: 1px solid var(--border);
    font-size: 0.78rem; color: var(--muted);
  }
  .plugin-size { font-family: monospace; }
  .dep-badge {
    font-size: 0.72rem;
    background: rgba(28,31,26,0.70); color: #86efac;
    border: 1px solid rgba(22,101,52,0.60); border-radius: 4px; padding: 2px 7px;
  }
  .no-plugins {
    text-align: center; padding: 60px; color: var(--muted); font-size: 0.95rem;
    border: 1px dashed var(--border); border-radius: 14px;
    background: rgba(5,12,28,0.45);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
  }

  /* ── Footer — glass ── */
  footer {
    position: relative; z-index: 1;
    background: rgba(3,6,15,0.60);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
    border-top: 1px solid var(--border);
    padding: 28px 24px;
    text-align: center; font-size: 0.82rem; color: var(--muted);
  }
  footer a { color: var(--accent-bright); text-decoration: none; }
  footer a:hover { text-decoration: underline; }

  @media (max-width: 600px) {
    .hero-title { font-size: 1.9rem; }
    .stat { padding: 0 20px; }
    .stat-value { font-size: 1.5rem; }
  }
</style>
</head>
<body>

<!-- Hero -->
<div class="hero">
  <div class="logo-wrap">
    <img src="/market.png" alt="xyNasTools"/>
  </div>
  <h1 class="hero-title">xyNasTools Plugins</h1>
  <p class="hero-sub">Official Plugins Market</p>
  <div class="hero-actions">
    <a href="https://github.com/xyseer/xyNasTools" target="_blank" rel="noopener" class="btn btn-primary">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      GitHub
    </a>
    <a href="/catalog.json" class="btn btn-outline">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      catalog.json
    </a>
    <a href="/health" class="btn btn-outline">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      Health
    </a>
  </div>
</div>

<!-- Stats -->
<div class="stats">
  <div class="stat">
    <span class="stat-value">{{ plugin_count }}</span>
    <span class="stat-label">Plugins</span>
  </div>
  <div class="stat">
    <span class="stat-value">{{ total_size }}</span>
    <span class="stat-label">Total Size</span>
  </div>
  <div class="stat">
    <span class="stat-value">{{ auth_label }}</span>
    <span class="stat-label">Auth Required</span>
  </div>
</div>

<!-- Plugin cards -->
<div class="section">
  <div class="section-title">Available Plugins</div>
  {% if plugins %}
  <div class="plugin-grid">
    {% for p in plugins %}
    <div class="plugin-card">
      <div class="plugin-header">
        <div class="plugin-icon">
          <img src="{{ p.icon_url }}" alt="{{ p.name }}" onerror="this.src='/default.png'"/>
        </div>
        <div>
          <div class="plugin-name">{{ p.name or p.id }}</div>
          <div class="plugin-version">v{{ p.version }}</div>
        </div>
      </div>
      <div class="plugin-desc">{{ p.description or 'No description provided.' }}</div>
      <div class="plugin-meta">
        {% if p.plugin_type %}<span class="tag tag-type">{{ p.plugin_type }}</span>{% endif %}
        {% for tag in p.tags[:4] %}<span class="tag">{{ tag }}</span>{% endfor %}
      </div>
      <div class="plugin-footer">
        <span class="plugin-size">{{ '%.1f' % (p.size_bytes / 1024) }} KB</span>
        {% if p.dependencies %}
          <span class="dep-badge">{{ p.dependencies | length }} dep{{ 's' if p.dependencies | length != 1 }}</span>
        {% endif %}
        {% if p.developer and p.developer.name %}
          <span>by {{ p.developer.name }}</span>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="no-plugins">No plugins found in {{ plugins_dir }}.<br>Drop <code>.xte</code> files there to make them available.</div>
  {% endif %}
</div>

<footer>
  <p>
    <a href="https://github.com/xyseer/xyNasTools" target="_blank" rel="noopener">xyseer/xyNasTools</a>
    &nbsp;&mdash;&nbsp; xyNasTools Plugin Registry &nbsp;&mdash;&nbsp;
    Catalog updated {{ updated_at }}
  </p>
</footer>

</body>
</html>"""


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f'{n} B'
    if n < 1024 * 1024:
        return f'{n / 1024:.1f} KB'
    return f'{n / 1024 / 1024:.1f} MB'


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/default.png')
def serve_icon():
    return send_from_directory(str(ICON_DIR), 'default.png', mimetype='image/png')


@app.route('/market.png')
def serve_market_icon():
    return send_from_directory(str(ICON_DIR), 'market.png', mimetype='image/png')


@app.route('/bg')
def serve_background():
    """Serve the background image from BACKGROUND_DIR if one exists."""
    bg = _get_background()
    if not bg:
        abort(404)
    mime = _BG_MIME.get(bg.suffix.lower(), 'image/jpeg')
    return send_from_directory(str(BACKGROUND_DIR), bg.name, mimetype=mime)


@app.route('/plugin-icons/<plugin_id>')
def plugin_icon(plugin_id: str):
    """
    Serve a plugin's embedded icon, with in-memory caching to avoid re-extracting
    the ZIP on every request.  Falls back to the platform icon when none is found.
    """
    if not _PLUGIN_ID_RE.match(plugin_id):
        abort(404)

    with _icon_lock:
        if plugin_id in _icon_cache:
            data, mime = _icon_cache[plugin_id]
            return Response(data, content_type=mime, headers={'Cache-Control': 'public, max-age=3600'})

    # Cache miss — extract from archive (outside lock to avoid holding it during I/O)
    candidates = sorted(
        (f for f in PLUGINS_DIR.glob(f'{plugin_id}-*.xte')
         if f.is_file() and _FILENAME_RE.match(f.name)),
        reverse=True,
    )
    for xte_path in candidates:
        manifest = _read_manifest(xte_path)
        if not manifest:
            continue
        icon_file = manifest.get('icon_file', '').strip()
        if not icon_file:
            break
        try:
            with zipfile.ZipFile(xte_path, 'r') as zf:
                if icon_file in zf.namelist():
                    data = zf.read(icon_file)
                    mime = mimetypes.guess_type(icon_file)[0] or 'image/png'
                    with _icon_lock:
                        _icon_cache[plugin_id] = (data, mime)
                    return Response(data, content_type=mime, headers={'Cache-Control': 'public, max-age=3600'})
        except Exception as exc:
            log.warning('Cannot extract icon %s from %s: %s', icon_file, xte_path.name, exc)
        break

    return send_from_directory(str(ICON_DIR), 'default.png', mimetype='image/png')


@app.route('/')
def homepage():
    catalog = _get_catalog()
    plugins = catalog.get('plugins', [])
    total = sum(p.get('size_bytes', 0) for p in plugins)
    updated = catalog.get('updated_at', '')
    if updated:
        try:
            dt = datetime.fromisoformat(updated.replace('Z', '+00:00'))
            updated = dt.strftime('%Y-%m-%d %H:%M UTC')
        except ValueError:
            pass
    return render_template_string(
        _HOMEPAGE,
        plugins=plugins,
        plugin_count=len(plugins),
        total_size=_fmt_bytes(total),
        auth_label='Yes' if AUTH_TOKEN else 'No',
        source_name=SOURCE_NAME,
        plugins_dir=str(PLUGINS_DIR),
        updated_at=updated,
        has_bg=bool(_get_background()),
    )


@app.route('/health')
def health():
    # Use cached catalog count — avoids a filesystem scan on every liveness poll
    with _cache_lock:
        count = len(_cache.get('plugins', [])) if _cache else None
    if count is None:
        count = sum(1 for f in PLUGINS_DIR.glob('*.xte') if f.is_file())
    return jsonify({
        'status': 'ok',
        'plugins_dir': str(PLUGINS_DIR),
        'plugin_count': count,
        'auth_required_for_download': bool(AUTH_TOKEN),
    })


@app.route('/catalog.json')
@_require_token
def catalog():
    """Returns all available plugins with SHA-256 checksums. Requires key when AUTH_TOKEN is set."""
    data = _get_catalog()
    resp = jsonify(data)
    resp.headers['Cache-Control'] = 'private, no-store'
    return resp


@app.route('/plugins/<filename>')
@_require_token
def download_plugin(filename: str):
    """
    Download a single .xte file.

    Protected by Bearer token if AUTH_TOKEN is set.
    Filename is strictly validated before any filesystem access.
    """
    if not _FILENAME_RE.match(filename):
        abort(400, 'Invalid filename format.')

    # Resolve and check containment — defence-in-depth against traversal
    target = (PLUGINS_DIR / filename).resolve()
    if not str(target).startswith(str(PLUGINS_DIR) + os.sep) and target != PLUGINS_DIR:
        abort(403, 'Path traversal detected.')

    if not target.is_file():
        abort(404, 'Plugin not found.')

    log.info('Serving %s to %s', filename, request.remote_addr)
    return send_from_directory(
        str(PLUGINS_DIR),
        filename,
        as_attachment=True,
        mimetype='application/octet-stream',
    )


@app.route('/admin/refresh', methods=['POST'])
@_require_token
def admin_refresh():
    """Force-rebuild the catalog cache. Requires AUTH_TOKEN."""
    _invalidate_cache()
    data = _get_catalog()
    log.info('Catalog refreshed by %s — %d plugins', request.remote_addr, data['plugin_count'])
    return jsonify({'refreshed': True, 'plugin_count': data['plugin_count'], 'updated_at': data['updated_at']})


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '12139'))
    debug = os.environ.get('FLASK_DEBUG', '').lower() in ('1', 'true', 'yes')
    PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    log.info('Starting xtesource — serving from %s', PLUGINS_DIR)
    app.run(host=host, port=port, debug=debug)
