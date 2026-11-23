import argparse
import asyncio
import json
import re
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

import httpx
import yaml
from bs4 import BeautifulSoup, Comment, NavigableString


@dataclass(frozen=True)
class InjectionPoint:
    url: str
    method: str
    target_param: str
    base_params: tuple[tuple[str, str], ...] = field(default_factory=tuple)


@dataclass
class Finding:
    vuln_type: str
    url: str
    method: str
    param: str
    payload: str
    evidence: str


@dataclass
class YamlTemplate:
    template_id: str
    name: str
    severity: str
    method: str
    path: str | None
    inject_param: bool
    payloads: list[str]
    matcher_type: str
    matcher_condition: str
    matcher_part: str
    words: list[str]
    regex_patterns: list[str]
    statuses: list[int]


def normalize_url(url: str) -> str:
    """Убирает фрагмент (#) и приводит схему/хост к нижнему регистру."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower() or "http"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def build_injected_request(
    point: InjectionPoint, payload: str
) -> tuple[str, dict[str, str] | None, dict[str, str] | None]:
    """Подставляет payload в целевой параметр, сохраняя остальные поля/параметры."""
    data_map = dict(point.base_params)
    data_map[point.target_param] = payload

    if point.method == "GET":
        parsed = urlparse(point.url)
        clean_url = urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path or "/", "", "", "")
        )
        return clean_url, data_map, None

    return point.url, None, data_map


def load_yaml_templates(templates_dir: str | Path) -> list[YamlTemplate]:
    """Загружает и валидирует простые YAML-шаблоны из директории."""
    path_obj = Path(templates_dir)
    if not path_obj.exists() or not path_obj.is_dir():
        return []

    loaded: list[YamlTemplate] = []
    template_files = sorted(path_obj.glob("*.yaml")) + sorted(path_obj.glob("*.yml"))
    for file_path in template_files:
        try:
            raw = yaml.safe_load(file_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue

        if not isinstance(raw, dict) or "id" not in raw:
            continue

        matchers = raw.get("matchers") or {}
        if not isinstance(matchers, dict):
            matchers = {}

        raw_statuses = matchers.get("statuses") or []
        statuses = [int(s) for s in raw_statuses if str(s).isdigit()]

        loaded.append(
            YamlTemplate(
                template_id=str(raw["id"]),
                name=str(raw.get("name") or raw["id"]),
                severity=str(raw.get("severity") or "info").lower(),
                method=str(raw.get("method") or "GET").strip().upper(),
                path=raw.get("path"),
                inject_param=bool(raw.get("inject_param", False)),
                payloads=[str(p) for p in (raw.get("payloads") or [])],
                matcher_type=str(matchers.get("type") or "word").lower(),
                matcher_condition=str(matchers.get("condition") or "or").lower(),
                matcher_part=str(matchers.get("part") or "body").lower(),
                words=[str(w) for w in (matchers.get("words") or [])],
                regex_patterns=[str(r) for r in (matchers.get("regex") or [])],
                statuses=statuses,
            )
        )
    return loaded


def match_response(
    tpl: YamlTemplate, status_code: int, headers: httpx.Headers, body: str
) -> tuple[bool, str]:
    """Проверяет ответ по правилам matcher из YAML-шаблона."""
    if tpl.matcher_part == "header":
        target_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    elif tpl.matcher_part == "status":
        target_text = str(status_code)
    else:
        target_text = body

    checks: list[tuple[bool, str]] = []

    if tpl.matcher_type == "status" or tpl.statuses:
        matched = status_code in tpl.statuses
        checks.append((matched, f"status={status_code}"))

    if tpl.matcher_type == "word" and tpl.words:
        for w in tpl.words:
            checks.append((w in target_text, f"word '{w}'"))

    if tpl.matcher_type == "regex" and tpl.regex_patterns:
        for pat in tpl.regex_patterns:
            matched = bool(re.search(pat, target_text, flags=re.MULTILINE))
            checks.append((matched, f"regex /{pat}/"))

    if not checks:
        return False, ""

    if tpl.matcher_condition == "and":
        ok = all(flag for flag, _ in checks)
    else:
        ok = any(flag for flag, _ in checks)

    matched_labels = [label for flag, label in checks if flag]
    return ok, ", ".join(matched_labels)


async def crawl(
    client: httpx.AsyncClient, start_url: str, max_depth: int = 2
) -> tuple[list[str], list[InjectionPoint]]:
    """Асинхронно обходит страницы в рамках домена и собирает точки инъекций."""
    start_norm = normalize_url(start_url)
    base_domain = urlparse(start_norm).netloc
    visited: set[str] = set()
    seen_points: set[tuple[str, str, str]] = set()
    queue: deque[tuple[str, int]] = deque([(start_norm, 0)])
    discovered_urls: list[str] = []
    injection_points: list[InjectionPoint] = []

    while queue:
        url, depth = queue.popleft()
        if depth > max_depth or url in visited:
            continue
        visited.add(url)
        discovered_urls.append(url)

        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue

        query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
        for key, _ in query_pairs:
            p = urlparse(url)
            sig = (
                urlunparse((p.scheme, p.netloc, p.path or "/", "", "", "")),
                "GET",
                key,
            )
            if sig not in seen_points:
                seen_points.add(sig)
                injection_points.append(
                    InjectionPoint(
                        url=url,
                        method="GET",
                        target_param=key,
                        base_params=tuple(query_pairs),
                    )
                )

        content_type = resp.headers.get("content-type", "")
        if "text/html" not in content_type.lower():
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        for a in soup.find_all("a", href=True):
            candidate = normalize_url(urljoin(url, a["href"]))
            if urlparse(candidate).netloc == base_domain and candidate not in visited:
                queue.append((candidate, depth + 1))

        for form in soup.find_all("form"):
            action = normalize_url(urljoin(url, form.get("action", "") or url))
            method = (form.get("method") or "get").strip().lower()
            if method not in ("get", "post"):
                method = "get"

            fields: list[tuple[str, str]] = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                val = tag.get("value", "test")
                if isinstance(val, list):
                    val = val[0] if val else "test"
                fields.append((name, str(val)))

            for name, _ in fields:
                sig = (action, method, name)
                if sig not in seen_points:
                    seen_points.add(sig)
                    injection_points.append(
                        InjectionPoint(
                            url=action,
                            method=method,
                            target_param=name,
                            base_params=tuple(fields),
                        )
                    )

    return discovered_urls, injection_points


async def measure_request(
    client: httpx.AsyncClient, point: InjectionPoint, payload: str
) -> tuple[float, str, int, httpx.Headers]:
    """Отправляет запрос и возвращает (длительность_сек, текст_ответа, статус, заголовки)."""
    req_url, params, data = build_injected_request(point, payload)
    start = time.perf_counter()
    try:
        if point.method == "GET":
            resp = await client.get(req_url, params=params)
        else:
            resp = await client.post(req_url, data=data)
        elapsed = time.perf_counter() - start
        return elapsed, resp.text, resp.status_code, resp.headers
    except httpx.HTTPError as exc:
        elapsed = time.perf_counter() - start
        return elapsed, f"__ERR__:{exc}", 0, httpx.Headers()


def detect_reflection_contexts(html: str, marker: str) -> set[str]:
    """Определяет контексты отражения маркера: 'attribute', 'html_text', 'comment'."""
    contexts: set[str] = set()
    if marker not in html:
        return contexts

    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(True):
        for attr_val in tag.attrs.values():
            values = attr_val if isinstance(attr_val, list) else [attr_val]
            if any(marker in str(v) for v in values):
                contexts.add("attribute")

    for node in soup.descendants:
        if isinstance(node, Comment):
            if marker in str(node):
                contexts.add("comment")
        elif isinstance(node, NavigableString):
            if marker in str(node):
                contexts.add("html_text")

    return contexts


def verify_xss_payload(html: str, token: str, context: str) -> bool:
    """Проверяет, появился ли в распарсенном HTML реальный узел/атрибут с токеном."""
    soup = BeautifulSoup(html, "html.parser")
    if context == "attribute":
        for tag in soup.find_all(True):
            if token in tag.name:
                return True
            for attr_name, attr_val in tag.attrs.items():
                vals = attr_val if isinstance(attr_val, list) else [attr_val]
                if token in str(attr_name) or any(token in str(v) for v in vals):
                    if str(attr_name).lower().startswith("on"):
                        return True
        return False

    if context == "html_text":
        for tag in soup.find_all(True):
            if token in tag.name:
                return True
            for attr_name, attr_val in tag.attrs.items():
                vals = attr_val if isinstance(attr_val, list) else [attr_val]
                if any(token in str(v) for v in vals) and str(attr_name).lower().startswith("on"):
                    return True
        return False

    return False


async def check_xss(
    client: httpx.AsyncClient,
    point: InjectionPoint,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Детектор отражённого XSS с определением контекста в HTML и атрибутах."""
    findings: list[Finding] = []
    marker = f"xprobe{uuid.uuid4().hex[:8]}"

    async with sem:
        _, html_body, status, headers = await measure_request(client, point, marker)

    ctype = headers.get("content-type", "")
    if status == 0 or "text/html" not in ctype.lower():
        return findings

    contexts = detect_reflection_contexts(html_body, marker)
    if not contexts:
        return findings

    if "attribute" in contexts:
        token_attr = f"xattr{uuid.uuid4().hex[:6]}"
        attr_payloads = [
            f'" autofocus onfocus="{token_attr}(1)',
            f"' autofocus onfocus='{token_attr}(1)",
            f'"><svg onload={token_attr}(1)>',
        ]
        for payload in attr_payloads:
            async with sem:
                _, resp_html, _, _ = await measure_request(client, point, payload)
            if verify_xss_payload(resp_html, token_attr, "attribute"):
                findings.append(
                    Finding(
                        vuln_type="Reflected XSS (Attribute context)",
                        url=point.url,
                        method=point.method.upper(),
                        param=point.target_param,
                        payload=payload,
                        evidence=f"Unencoded attribute/event reflection verified with token '{token_attr}'",
                    )
                )
                break

    if "html_text" in contexts:
        token_html = f"xhtml{uuid.uuid4().hex[:6]}"
        html_payloads = [
            f"<svg onload={token_html}(1)>",
            f"<img src=x onerror={token_html}(1)>",
        ]
        for payload in html_payloads:
            async with sem:
                _, resp_html, _, _ = await measure_request(client, point, payload)
            if verify_xss_payload(resp_html, token_html, "html_text"):
                findings.append(
                    Finding(
                        vuln_type="Reflected XSS (HTML context)",
                        url=point.url,
                        method=point.method.upper(),
                        param=point.target_param,
                        payload=payload,
                        evidence=f"Unencoded tag/event reflection verified with token '{token_html}'",
                    )
                )
                break

    return findings


async def check_sqli(
    client: httpx.AsyncClient,
    point: InjectionPoint,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Базовая проверка SQLi: error-based и замер времени относительно baseline."""
    sql_errors = (
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "postgresql",
        "sqlite3",
        "unclosed quotation mark",
    )
    findings: list[Finding] = []
    orig_val = dict(point.base_params).get(point.target_param, "1")

    async with sem:
        base_time, _, _, _ = await measure_request(client, point, orig_val)

    err_payload = "'"
    async with sem:
        _, err_body, _, _ = await measure_request(client, point, err_payload)

    if any(sig in err_body.lower() for sig in sql_errors):
        findings.append(
            Finding(
                vuln_type="SQLi (Error-based)",
                url=point.url,
                method=point.method.upper(),
                param=point.target_param,
                payload=err_payload,
                evidence="Matched database error signature in response",
            )
        )

    time_payload = "' OR SLEEP(4)-- "
    async with sem:
        delay_time, _, _, _ = await measure_request(client, point, time_payload)

    if delay_time - base_time > 3.5 and delay_time > base_time * 2:
        findings.append(
            Finding(
                vuln_type="SQLi (Time-based)",
                url=point.url,
                method=point.method.upper(),
                param=point.target_param,
                payload=time_payload,
                evidence=f"Response took {delay_time:.2f}s vs baseline {base_time:.2f}s",
            )
        )

    return findings


async def run_template_path(
    client: httpx.AsyncClient,
    tpl: YamlTemplate,
    target_url: str,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Проверяет статический путь из YAML-шаблона один раз для целевого хоста."""
    if not tpl.path:
        return []

    probe_url = urljoin(target_url.rstrip("/") + "/", tpl.path.lstrip("/"))
    async with sem:
        try:
            resp = await client.request(tpl.method, probe_url)
            matched, info = match_response(tpl, resp.status_code, resp.headers, resp.text)
            if matched:
                return [
                    Finding(
                        vuln_type=f"YAML [{tpl.severity}]: {tpl.name}",
                        url=probe_url,
                        method=tpl.method,
                        param="-",
                        payload=tpl.path,
                        evidence=f"Template '{tpl.template_id}' matched ({info})",
                    )
                ]
        except httpx.HTTPError:
            pass

    return []


async def run_template_on_point(
    client: httpx.AsyncClient,
    tpl: YamlTemplate,
    point: InjectionPoint,
    sem: asyncio.Semaphore,
) -> list[Finding]:
    """Выполняет YAML-шаблон для одной конкретной точки инъекции."""
    if not (tpl.inject_param and tpl.payloads):
        return []
    if tpl.method != "ANY" and point.method.upper() != tpl.method:
        return []

    findings: list[Finding] = []
    for payload in tpl.payloads:
        async with sem:
            _, body, status, headers = await measure_request(client, point, payload)

        if status == 0:
            continue

        matched, info = match_response(tpl, status, headers, body)
        if matched:
            findings.append(
                Finding(
                    vuln_type=f"YAML [{tpl.severity}]: {tpl.name}",
                    url=point.url,
                    method=point.method.upper(),
                    param=point.target_param,
                    payload=payload,
                    evidence=f"Template '{tpl.template_id}' matched ({info})",
                )
            )
            break

    return findings


def build_template_tasks(
    client: httpx.AsyncClient,
    templates: list[YamlTemplate],
    target_url: str,
    points: list[InjectionPoint],
    sem: asyncio.Semaphore,
) -> list[Any]:
    """Формирует независимые задачи для каждого пути и каждой пары (шаблон, точка)."""
    tasks: list[Any] = []
    for tpl in templates:
        if tpl.path:
            tasks.append(run_template_path(client, tpl, target_url, sem))
        if tpl.inject_param and tpl.payloads:
            for point in points:
                if tpl.method == "ANY" or point.method.upper() == tpl.method:
                    tasks.append(run_template_on_point(client, tpl, point, sem))
    return tasks


async def run_scan(
    target_url: str,
    templates_dir: str | Path = "./templates",
    max_depth: int = 2,
    concurrency: int = 8,
) -> dict[str, Any]:
    limits = httpx.Limits(
        max_connections=concurrency * 2,
        max_keepalive_connections=concurrency,
    )
    sem = asyncio.Semaphore(concurrency)
    templates = load_yaml_templates(templates_dir)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0),
        follow_redirects=True,
        limits=limits,
        headers={"User-Agent": "AsyncScanner/1.0"},
    ) as client:
        urls, points = await crawl(client, target_url, max_depth=max_depth)

        template_tasks = build_template_tasks(client, templates, target_url, points, sem)
        scanner_tasks: list[Any] = [
            coro
            for pt in points
            for coro in (check_xss(client, pt, sem), check_sqli(client, pt, sem))
        ]
        all_tasks = scanner_tasks + template_tasks
        results = await asyncio.gather(*all_tasks)

    findings = [item for sublist in results for item in sublist]
    return {
        "target": target_url,
        "urls_count": len(urls),
        "injection_points_count": len(points),
        "templates_loaded": len(templates),
        "template_tasks_scheduled": len(template_tasks),
        "findings": [f.__dict__ for f in findings],
    }


def print_report(report: dict[str, Any]) -> None:
    """Выводит человекочитаемую сводку и найденные уязвимости в терминал."""
    print("\n=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===")
    print(f"Цель:                 {report['target']}")
    print(f"Найдено URL:          {report['urls_count']}")
    print(f"Точек инъекций:       {report['injection_points_count']}")
    print(
        f"YAML-шаблонов:        {report['templates_loaded']} "
        f"(задач в пуле: {report.get('template_tasks_scheduled', 0)})"
    )
    print(f"Всего срабатываний:   {len(report['findings'])}")

    findings = report.get("findings") or []
    if not findings:
        print("\nУязвимостей по текущим проверкам и шаблонам не найдено.")
        return

    print("\n--- Список находок ---")
    for idx, item in enumerate(findings, start=1):
        print(
            f"[{idx}] {item['vuln_type']}\n"
            f"    URL:      {item['method']} {item['url']}\n"
            f"    Параметр: {item['param']}\n"
            f"    Payload:  {item['payload']}\n"
            f"    Пруф:     {item['evidence']}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Асинхронный веб-сканер (краулер, XSS, SQLi, YAML-шаблоны)."
    )
    parser.add_argument(
        "target_url",
        help="Целевой URL для проверки (например, http://testphp.vulnweb.com/)",
    )
    parser.add_argument(
        "-t",
        "--templates",
        default="./templates",
        help="Путь к директории с YAML-шаблонами (по умолчанию: ./templates)",
    )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=2,
        help="Максимальная глубина обхода краулера (по умолчанию: 2)",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=8,
        help="Число одновременных задач/запросов (по умолчанию: 8)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Путь для сохранения полного JSON-отчёта (опционально)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Вывести только чистый JSON без текстовой сводки",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    scan_report = asyncio.run(
        run_scan(
            target_url=args.target_url,
            templates_dir=args.templates,
            max_depth=args.depth,
            concurrency=args.concurrency,
        )
    )

    if args.output:
        Path(args.output).write_text(
            json.dumps(scan_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    if args.json:
        print(json.dumps(scan_report, indent=2, ensure_ascii=False))
    else:
        print_report(scan_report)
