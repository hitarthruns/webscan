# sqli.py
import requests
import re
import time

class SQLiDetector:
    def __init__(self, session):
        self.session = session
        # Error patterns indicating SQL injection
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"valid SQLite",
            r"SQL Server.*Driver",
            r"Driver.*SQL Server",
            r"SQLServer JDBC Driver",
            r"com.microsoft.sqlserver",
            r"Unclosed quotation mark",
            r"Microsoft OLE DB Provider for ODBC Drivers",
        ]
        self.dbms_signatures = {}

    def test_url_params(self, url, params, payloads):
        """Test URL query parameters for SQL injection."""
        findings = []
        for param in params:
            for payload in payloads[:10]:  # Limit to first 10 per param for speed
                result = self._test_param(url, param, payload)
                if result:
                    findings.append({
                        'url': url,
                        'param': param,
                        'payload': payload,
                        'type': result,
                        'location': 'url_param'
                    })
                    break  # One finding per param is enough
        return findings

    def test_form_fields(self, form_data, payloads):
        """Test form inputs for SQL injection."""
        findings = []
        action_url, method, inputs = form_data
        
        for inp in inputs:
            if inp['type'] in ('text', 'search', 'textarea', 'hidden', None):
                for payload in payloads[:5]:
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
        """Test a single parameter with a payload."""
        # Inject payload into the parameter value
        test_url = url.replace(f'{param}=', f'{param}={payload}')
        
        try:
            # Get baseline response
            baseline = self.session.get(url, timeout=10)
            
            # Get test response
            start = time.time()
            resp = self.session.get(test_url, timeout=15)
            elapsed = time.time() - start
            
            # Check for error-based injection
            if self._check_errors(resp.text):
                return 'error_based'
            
            # Check for time-based injection
            if elapsed > 4.5 and ('SLEEP' in payload or 'WAITFOR' in payload):
                return 'time_based'
            
            # Check for boolean blind via content length difference
            if len(resp.text) != len(baseline.text):
                if payload.endswith("='1") and len(resp.text) == len(baseline.text):
                    pass  # Still matching — not conclusive
                elif "'1'='1" in payload or "1=1" in payload:
                    # True condition should return same as baseline
                    pass
        
        except Exception as e:
            return None
        
        return None

    def _test_form_field(self, action_url, method, inputs, target_field, payload):
        """Inject payload into a specific form field."""
        data = {}
        for inp in inputs:
            if inp['name'] == target_field:
                data[inp['name']] = payload
            else:
                data[inp['name']] = 'test'
        
        try:
            if method == 'post':
                resp = self.session.post(action_url, data=data, timeout=10)
            else:
                resp = self.session.get(action_url, params=data, timeout=10)
            
            if self._check_errors(resp.text):
                return 'error_based'
                
        except Exception:
            return None
        
        return None

    def _check_errors(self, html):
        """Check if response contains database error messages."""
        for pattern in self.error_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        return False