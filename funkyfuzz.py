#!/usr/bin/env python3
"""
Medium-level web scanner: crawling + XSS/HTML injection detection + sensitive file checks.
Outputs: JSON and HTML report + summary printed to stdout.

Enhancement: when an XSS or HTML injection is found, the report now includes the exact vulnerable URL(s) in a dedicated `vulns` list and inside each page entry.

Usage:
  python xss_htmli_sensitive_scanner.py --url https://example.com --output-dir reports
  python xss_htmli_sensitive_scanner.py --input-file targets.txt --output-dir reports --concurrency 10

Dependencies:
  pip install httpx[http2] beautifulsoup4 tldextract aiofiles

Notes / ethics:
  Only run against targets you own or have explicit written permission to test.
"""

import argparse
import asyncio
import json
import os
import time
from collections import defaultdict
from html import escape
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

import httpx
import tldextract
from bs4 import BeautifulSoup

# --- Configuration ---
SENSITIVE_PATHS = [
    '.git/', '.env', '.DS_Store', 'config.php', 'wp-config.php', 'backup.zip', 'backup.tar',
    'database.sql', 'id_rsa', 'id_rsa.pub', 'robots.txt', 'sitemap.xml', '.htaccess', 'error.log'
]

XSS_PAYLOADS = [
    '<XSS_TEST_ANKUR>',
    '"\'><XSS_TEST_ANKUR>',
    "'><img src=x onerror=alert(1)>",
]

CRAWL_LIMIT = 200  # max pages per target by default
TIMEOUT = 15.0

# --- Helpers ---

def same_origin(u1, u2):
    p1, p2 = urlparse(u1), urlparse(u2)
    return (p1.scheme, p1.hostname, p1.port) == (p2.scheme, p2.hostname, p2.port)


def normalize_url(base, link):
    try:
        return urljoin(base, link.split('#', 1)[0])
    except Exception:
        return None


class Scanner:
    def __init__(self, concurrency=6, crawl_limit=CRAWL_LIMIT, timeout=TIMEOUT, follow_subdomains=False):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(timeout))
        self.semaphore = asyncio.Semaphore(concurrency)
        self.crawl_limit = crawl_limit
        self.follow_subdomains = follow_subdomains

    async def close(self):
        await self.client.aclose()

    async def fetch(self, url, method='GET', data=None, headers=None):
        async with self.semaphore:
            try:
                if method == 'GET':
                    r = await self.client.get(url, headers=headers)
                else:
                    r = await self.client.post(url, data=data, headers=headers)
                return r
            except Exception:
                return None

    async def check_sensitive(self, target_base):
        findings = []
        for p in SENSITIVE_PATHS:
            url = urljoin(target_base, p)
            r = await self.fetch(url)
            if r and r.status_code == 200:
                text = r.text
                # heuristic: if size > 10 bytes and not just 404 page
                if len(text) > 10:
                    findings.append({'path': p, 'url': url, 'status': r.status_code, 'length': len(text)})
        return findings

    async def check_reflection(self, url, param_name=None):
        reflections = []
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))

        # If there are query params, inject into each; else append one
        targets = []
        if qs:
            for pname in list(qs.keys()):
                for payload in XSS_PAYLOADS:
                    q = qs.copy()
                    q[pname] = payload
                    new_q = urlencode(q)
                    new_url = urlunparse(parsed._replace(query=new_q))
                    targets.append((new_url, payload, pname))
        else:
            for payload in XSS_PAYLOADS:
                new_q = urlencode({'q': payload})
                new_url = urlunparse(parsed._replace(query=new_q))
                targets.append((new_url, payload, 'q'))

        for new_url, payload, pname in targets:
            r = await self.fetch(new_url)
            if r and payload in r.text:
                # include url, param and payload in the finding
                reflections.append({'url': new_url, 'param': pname, 'payload': payload, 'status': r.status_code})
        return reflections

    async def scan_forms(self, base_url, text):
        soup = BeautifulSoup(text, 'html.parser')
        forms = []
        for form in soup.find_all('form'):
            try:
                action = form.get('action') or base_url
                method = (form.get('method') or 'get').lower()
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if not name:
                        continue
                    inputs.append({'name': name, 'type': inp.get('type', 'text')})
                forms.append({'action': urljoin(base_url, action), 'method': method, 'inputs': inputs})
            except Exception:
                continue

        findings = []
        for f in forms:
            for payload in XSS_PAYLOADS:
                data = {inp['name']: payload for inp in f['inputs']}
                # prepare a target url for reporting purposes
                if f['method'] == 'get':
                    target = f['action']
                    # construct a GET URL with query for visibility
                    delimiter = '&' if '?' in target else '?'
                    target_with_q = target + (delimiter + urlencode(data) if data else '')
                    r = await self.fetch(target_with_q)
                else:
                    target_with_q = f['action']
                    r = await self.fetch(f['action'], method='POST', data=data)

                if r and payload in r.text:
                    findings.append({'url': target_with_q, 'form_action': f['action'], 'method': f['method'], 'inputs': f['inputs'], 'payload': payload, 'status': r.status_code})
        return findings

    async def crawl_and_scan(self, start_url):
        to_crawl = [start_url]
        seen = set()
        results = {'start_url': start_url, 'pages': {}, 'sensitive': [], 'vulns': [], 'summary': defaultdict(int)}
        parsed_start = urlparse(start_url)
        base_domain = tldextract.extract(start_url).registered_domain

        while to_crawl and len(seen) < self.crawl_limit:
            url = to_crawl.pop(0)
            if url in seen:
                continue
            seen.add(url)

            r = await self.fetch(url)
            page_entry = {'url': url, 'status': None, 'xss': [], 'forms': [], 'sensitive': [], 'links': []}
            if not r:
                page_entry['status'] = 'error'
                results['pages'][url] = page_entry
                continue

            page_entry['status'] = r.status_code
            content_type = r.headers.get('Content-Type', '')
            text = r.text

            # check for reflected params on this exact URL
            refl = await self.check_reflection(url)
            if refl:
                page_entry['xss'].extend(refl)
                results['summary']['xss_positive'] += len(refl)
                # add to global vuln list with clear url
                for f in refl:
                    results['vulns'].append({'type': 'reflected', 'url': f['url'], 'param': f.get('param'), 'payload': f.get('payload'), 'status': f.get('status')})

            # scan forms for reflection
            forms_found = await self.scan_forms(url, text)
            if forms_found:
                page_entry['forms'].extend(forms_found)
                results['summary']['forms_xss'] += len(forms_found)
                for ff in forms_found:
                    results['vulns'].append({'type': 'form', 'url': ff.get('url'), 'form_action': ff.get('form_action'), 'method': ff.get('method'), 'payload': ff.get('payload'), 'status': ff.get('status')})

            # find links to crawl
            if 'html' in content_type or '<html' in text.lower():
                soup = BeautifulSoup(text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    link = normalize_url(url, a['href'])
                    if not link:
                        continue
                    # restrict to same origin or subdomain depending on config
                    if same_origin(start_url, link) or (self.follow_subdomains and tldextract.extract(link).registered_domain == base_domain):
                        if link not in seen and link not in to_crawl:
                            to_crawl.append(link)
                    page_entry['links'].append(link)

            results['pages'][url] = page_entry

        # after crawl, check sensitive paths at root
        results['sensitive'] = await self.check_sensitive(start_url)
        results['summary']['sensitive_found'] = len(results['sensitive'])
        return results


# --- Report generation ---

def make_html_report(json_data, outpath):
    now = time.strftime('%Y-%m-%d %H:%M:%S')
    title = f"Scan report for {escape(json_data['start_url'])}"
    rows = []
    for url, page in json_data['pages'].items():
        xss_count = len(page.get('xss', [])) + len(page.get('forms', []))
        rows.append(f"<tr><td><a href=\"{escape(url)}\">{escape(url)}</a></td><td>{page.get('status')}</td><td>{xss_count}</td></tr>")

    sensitive_html = ''.join([f"<li><a href=\"{escape(s['url'])}\">{escape(s['url'])}</a> ({s['path']})</li>" for s in json_data.get('sensitive', [])])

    vulns_html = ''
    if json_data.get('vulns'):
        lines = []
        for v in json_data['vulns']:
            if v['type'] == 'reflected':
                lines.append(f"<li>[Reflected] <a href=\"{escape(v['url'])}\">{escape(v['url'])}</a> param={escape(str(v.get('param')))} payload={escape(v.get('payload'))}</li>")
            else:
                lines.append(f"<li>[Form] <a href=\"{escape(v['url'])}\">{escape(v['url'])}</a> action={escape(str(v.get('form_action')))} payload={escape(v.get('payload'))}</li>")
        vulns_html = '<ul>' + '\n'.join(lines) + '</ul>'
    else:
        vulns_html = '<p>None found</p>'

    html = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body{{font-family:system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial; max-width:1100px;margin:2rem auto;padding:1rem}}
table{{width:100%;border-collapse:collapse}}
th,td{{padding:8px;border:1px solid #ddd;text-align:left}}
.summary{{background:#f7f7f9;padding:10px;border-radius:8px;margin-bottom:1rem}}
</style>
</head>
<body>
<h1>{title}</h1>
<p class=summary>Generated: {now} &nbsp; | &nbsp; Pages scanned: {len(json_data['pages'])} &nbsp; | &nbsp; XSS positives: {json_data['summary'].get('xss_positive',0)} &nbsp; | &nbsp; Sensitive files: {json_data['summary'].get('sensitive_found',0)}</p>
<h2>Summary table</h2>
<table>
<thead><tr><th>URL</th><th>Status</th><th>XSS hits</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>

<h2>Vulnerabilities found</h2>
{vulns_html}

<h2>Sensitive files</h2>
<ul>
{sensitive_html or '<li>None found</li>'}
</ul>

<h2>Raw JSON</h2>
<pre>{escape(json.dumps(json_data, indent=2))}</pre>
</body>
</html>
"""
    with open(outpath, 'w', encoding='utf-8') as f:
        f.write(html)


# --- CLI / Orchestration ---

async def scan_target(scanner, target, output_dir):
    print(f"[+] Scanning {target}")
    result = await scanner.crawl_and_scan(target)
    filename_safe = target.replace('://', '_').replace('/', '_')[:200]
    json_path = os.path.join(output_dir, f"{filename_safe}.json")
    html_path = os.path.join(output_dir, f"{filename_safe}.html")
    os.makedirs(output_dir, exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    make_html_report(result, html_path)
    print(f"[+] Saved JSON -> {json_path}")
    print(f"[+] Saved HTML  -> {html_path}")
    return result


async def main(args):
    targets = []
    if args.url:
        targets = [args.url.strip()]
    elif args.input_file:
        with open(args.input_file, 'r') as f:
            for line in f:
                s = line.strip()
                if s:
                    targets.append(s)

    if not targets:
        print("No targets provided. Use --url or --input-file")
        return

    scanner = Scanner(concurrency=args.concurrency, crawl_limit=args.crawl_limit, follow_subdomains=args.follow_subdomains)
    try:
        tasks = [scan_target(scanner, t, args.output_dir) for t in targets]
        results = await asyncio.gather(*tasks)
    finally:
        await scanner.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Medium-level XSS/HTMLi + sensitive file scanner (crawler)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--url', help='Single target URL (e.g. https://example.com)')
    group.add_argument('--input-file', help='File with newline-separated target URLs')
    parser.add_argument('--output-dir', default='reports', help='Directory to save JSON and HTML reports')
    parser.add_argument('--concurrency', type=int, default=6, help='Concurrent requests')
    parser.add_argument('--crawl-limit', type=int, default=CRAWL_LIMIT, help='Max pages to crawl per target')
    parser.add_argument('--follow-subdomains', action='store_true', help='Allow crawling across subdomains of the same registered domain')
    args = parser.parse_args()
    asyncio.run(main(args))
