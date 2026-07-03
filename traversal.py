# traversal.py
import requests

class TraversalDetector:
    def __init__(self, session):
        self.session = session
        self.success_indicators = {
            'linux': ['root:x:', 'bin:x:', 'daemon:x:', '/bin/bash', '/usr/sbin/nologin'],
            'windows': ['[fonts]', '[extensions]', 'for 16-bit app support'],
        }

    def test_url_params(self, url, params, payloads):
        findings = []
        for param in params:
            for payload in payloads:
                result = self._test_param(url, param, payload)
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
                # Check if the parameter looks file-related (filename, path, page, etc.)
                file_keywords = ['file', 'path', 'page', 'doc', 'pdf', 'image', 'img', 'load', 'read', 'include', 'template']
                is_file_param = any(kw in inp['name'].lower() for kw in file_keywords)
                
                if is_file_param:
                    for payload in payloads:
                        result = self._test_form_field(action_url, method, inputs, inp['name'], payload)
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

    def _test_param(self, url, param, payload):
        test_url = url.replace(f'{param}=', f'{param}={payload}')
        
        try:
            resp = self.session.get(test_url, timeout=10)
            content = resp.text
            
            # Check for Linux file content
            for indicator in self.success_indicators['linux']:
                if indicator in content:
                    return 'linux_traversal'
            
            # Check for Windows file content
            for indicator in self.success_indicators['windows']:
                if indicator in content:
                    return 'windows_traversal'
            
            # Generic check — file is much larger than expected
            if len(content) > 500:
                # Check if it has common file signatures
                if 'root:' in content or 'nobody:' in content or 'daemon:' in content:
                    return 'linux_traversal'
                    
        except Exception:
            pass
        return None

    def _test_form_field(self, action_url, method, inputs, target_field, payload):
        data = {}
        for inp in inputs:
            data[inp['name']] = payload if inp['name'] == target_field else 'test'
        
        try:
            if method == 'post':
                resp = self.session.post(action_url, data=data, timeout=10)
            else:
                resp = self.session.get(action_url, params=data, timeout=10)
            
            content = resp.text
            if 'root:x:' in content or '[fonts]' in content:
                return 'linux_traversal' if 'root:x:' in content else 'windows_traversal'
                
        except Exception:
            pass
        return None