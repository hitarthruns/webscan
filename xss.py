# xss.py
import requests
from urllib.parse import quote

class XSSDetector:
    def __init__(self, session):
        self.session = session

    def test_url_params(self, url, params, payloads):
        findings = []
        for param in params:
            for payload in payloads[:8]:
                result = self._test_param_reflected(url, param, payload)
                if result:
                    findings.append({
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'type': result,
                        'location': 'url_param'
                    })
                    break
        return findings

    def test_form_fields(self, form_data, payloads):
        findings = []
        action_url, method, inputs = form_data
        
        for inp in inputs:
            if inp['type'] in ('text', 'search', 'textarea', None):
                for payload in payloads[:5]:
                    result = self._test_form_reflected(action_url, method, inputs, inp['name'], payload)
                    if result:
                        findings.append({
                            'url': action_url,
                            'param': inp['name'],
                            'payload': payload,
                            'type': result,
                            'location': 'form_field'
                        })
                        break
        return findings

    def _test_param_reflected(self, url, param, payload):
        """Check if the payload is reflected in the response."""
        encoded_payload = quote(payload)
        test_url = url.replace(f'{param}=', f'{param}={encoded_payload}')
        
        try:
            resp = self.session.get(test_url, timeout=10)
            
            # Check if the payload appears unmodified in the response
            # We use a distinctive marker to be sure
            if payload in resp.text:
                # Check context — is it inside a script tag, attribute, etc.?
                context = self._detect_context(resp.text, payload)
                return f'reflected_{context}' if context else 'reflected'
            
        except Exception:
            pass
        return None

    def _test_form_reflected(self, action_url, method, inputs, target_field, payload):
        data = {}
        for inp in inputs:
            data[inp['name']] = payload if inp['name'] == target_field else 'test'
        
        try:
            if method == 'post':
                resp = self.session.post(action_url, data=data, timeout=10)
            else:
                resp = self.session.get(action_url, params=data, timeout=10)
            
            if payload in resp.text:
                return 'stored' if resp.url == action_url else 'reflected'
                
        except Exception:
            pass
        return None

    def _detect_context(self, html, payload):
        """Determine where the payload lands in the HTML."""
        import re
        
        # Inside a <script> tag
        if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', html, re.DOTALL):
            return 'script_context'
        
        # Inside an HTML attribute value
        if re.search(r'<[^>]+=["\'].*' + re.escape(payload) + r'.*["\']', html):
            return 'attribute_context'
        
        # Inside an HTML event handler
        if re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), html, re.IGNORECASE):
            return 'event_handler'
        
        # Raw HTML context
        return 'html_context'