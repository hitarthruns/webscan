# crawler.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

class WebCrawler:
    def __init__(self, base_url, session=None, max_pages=50):
        self.base_url = base_url
        self.session = session or requests.Session()
        self.max_pages = max_pages
        self.visited = set()
        self.discovered = {
            'urls': [],
            'forms': [],       # (action_url, method, inputs)
            'params': []       # (url, param_name)
        }

    def crawl(self):
        """Start crawling from the base URL."""
        self._crawl_page(self.base_url)
        return self.discovered

    def _crawl_page(self, url):
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return
        self.visited.add(url)

        try:
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return
            self.discovered['urls'].append(url)
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action') or ''
                method = form.get('method', 'get').lower()
                action_url = urljoin(url, action)
                
                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if name:
                        inp_type = inp.get('type', 'text')
                        inputs.append({'name': name, 'type': inp_type})
                
                self.discovered['forms'].append((action_url, method, inputs))
            
            # Extract URL parameters from links
            for link in soup.find_all('a', href=True):
                href = urljoin(url, link['href'])
                
                # Check for query parameters
                parsed = urlparse(href)
                if parsed.query:
                    params = re.findall(r'([^&=]+)=', parsed.query)
                    for param in params:
                        self.discovered['params'].append((href, param))
                
                # Recursively crawl same-domain links
                if self.base_url in href and href not in self.visited:
                    self._crawl_page(href)
                    
        except Exception as e:
            print(f"[!] Error crawling {url}: {e}")