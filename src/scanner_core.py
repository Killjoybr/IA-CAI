import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from typing import List, Dict, Set
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SimpleWebScanner:
    """
    Scanner web bem simples para fins didáticos.
    - Faz crawl superficial (mesmo domínio, GET links <a>).
    - Procura parâmetros em URLs.
    - Testa XSS e SQLi básicos.
    - Verifica alguns headers de segurança.
    """

    def __init__(self, base_url: str, max_pages: int = 20, timeout: int = 5):
        if not base_url.startswith("http"):
            base_url = "http://" + base_url
        self.base_url = base_url.rstrip("/")
        self.max_pages = max_pages
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.session = requests.Session()
        self.session.verify = False  # ambiente de teste

        # payloads bem simples para XSS/SQLi
        self.xss_payloads = ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>"]
        self.sqli_payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "';--"]

    def same_domain(self, url: str) -> bool:
        base = urlparse(self.base_url)
        target = urlparse(url)
        return base.netloc == target.netloc or target.netloc == ""

    def get_links(self, url: str) -> List[str]:
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except Exception:
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            full = urljoin(url, href)
            if self.same_domain(full):
                links.append(full.split("#")[0])
        return links

    def crawl(self) -> List[str]:
        """
        Crawl em largura, limitado por max_pages.
        """
        to_visit = [self.base_url]
        discovered = []

        while to_visit and len(self.visited) < self.max_pages:
            current = to_visit.pop(0)
            if current in self.visited:
                continue
            self.visited.add(current)
            discovered.append(current)
            for link in self.get_links(current):
                if link not in self.visited and link not in to_visit:
                    to_visit.append(link)

        return discovered

    def extract_params(self, url: str) -> Dict[str, List[str]]:
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def check_security_headers(self, url: str) -> List[Dict]:
        """
        Checa se alguns headers de segurança básicos estão ausentes.
        """
        findings = []
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except Exception:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        required = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
        ]

        for h in required:
            if h not in headers:
                findings.append({
                    "type": "missing_header",
                    "header": h,
                    "url": url,
                    "detail": f"Header de segurança ausente: {h}",
                })
        return findings

    def test_reflected_xss(self, url: str) -> List[Dict]:
        """
        Testa XSS refletido inserindo payloads simples em parâmetros GET.
        """
        findings = []
        params = self.extract_params(url)
        if not params:
            return findings

        for payload in self.xss_payloads:
            for p in params.keys():
                try:
                    # recria query com um parâmetro modificado
                    new_params = {k: (payload if k == p else v[0]) for k, v in params.items()}
                    resp = self.session.get(url, params=new_params, timeout=self.timeout)
                    if payload in resp.text:
                        findings.append({
                            "type": "xss_reflected",
                            "url": resp.url,
                            "param": p,
                            "payload": payload,
                            "detail": f"Possível XSS refletido no parâmetro {p}",
                        })
                except Exception:
                    continue
        return findings

    def test_basic_sqli(self, url: str) -> List[Dict]:
        """
        Testes muito simples de SQLi por padrão de erro.
        """
        findings = []
        params = self.extract_params(url)
        if not params:
            return findings

        error_signatures = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "sql syntax",
            "odbc sql server driver",
        ]

        for payload in self.sqli_payloads:
            for p in params.keys():
                try:
                    new_params = {k: (payload if k == p else v[0]) for k, v in params.items()}
                    resp = self.session.get(url, params=new_params, timeout=self.timeout)
                    body_lower = resp.text.lower()
                    if any(sig in body_lower for sig in error_signatures):
                        findings.append({
                            "type": "sqli_error_based",
                            "url": resp.url,
                            "param": p,
                            "payload": payload,
                            "detail": f"Possível SQLi (mensagem de erro SQL) em {p}",
                        })
                except Exception:
                    continue
        return findings

    def scan(self) -> List[Dict]:
        """
        Coordena o scan: crawl -> para cada URL, testa headers, XSS e SQLi.
        """
        all_findings: List[Dict] = []
        urls = self.crawl()
        for url in urls:
            # headers
            all_findings.extend(self.check_security_headers(url))

            # só testa XSS/SQLi se tiver parâmetros
            if self.extract_params(url):
                all_findings.extend(self.test_reflected_xss(url))
                all_findings.extend(self.test_basic_sqli(url))

        return all_findings
