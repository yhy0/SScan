from lib.common.utils import save_script_result


def do_check(self, url):
    if url == '/':
        if self.session and self.index_status in (301, 302):
            for keyword in ['admin', 'login', 'manage', 'backend']:
                if self.index_headers.get('location', '').find(keyword) >= 0:
                    save_script_result(self, self.index_status, self.base_url + '/', 'Admin Site')
                    break
