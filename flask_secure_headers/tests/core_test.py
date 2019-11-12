import unittest
from flask import Flask
from flask_secure_headers.core import Secure_Headers
from flask_secure_headers.headers import CSP


class TestCSPHeaderCreation(unittest.TestCase):
	def test_CSP_pass(self):
		sh = Secure_Headers()
		defaultCSP = sh.defaultPolicies['CSP']
		""" test CSP policy update """
		h = CSP({'script-src':['self','code.jquery.com']}).update_policy(defaultCSP)
		self.assertEqual(h['script-src'],['self', 'code.jquery.com'])
		self.assertEqual(h['default-src'],['self'])
		self.assertEqual(h['img-src'],[])
		""" test CSP policy rewrite """
		h = CSP({'default-src':['none']}).rewrite_policy(defaultCSP)
		self.assertEqual(h['script-src'],[])
		self.assertEqual(h['default-src'],['none'])
		self.assertEqual(h['report-uri'],[])
		""" test CSP header creation """
		h = CSP({'default-src':['none']}).create_header()
		self.assertEqual(h['Content-Security-Policy'],"default-src 'none'")
		""" test CSP -report-only header creation """
		h = CSP({'default-src':['none'],'report-only':True}).create_header()
		self.assertEqual(h['Content-Security-Policy-Report-Only'],"default-src 'none'")

	def test_CSP_fail(self):
		""" test invalid paramter for CSP update """
		with self.assertRaises(Exception):
			h = CSP({'test-src':['self','code.jquery.com']}).update_policy()

class TestAppUseCase(unittest.TestCase):
	""" test header creation in flask app """

	def setUp(self):
		self.app = Flask(__name__)
		self.sh = Secure_Headers()

	def test_defaults(self):
		""" test header wrapper with default headers """
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('X-XSS-Protection'),'1; mode=block')
			self.assertEqual(result.headers.get('Strict-Transport-Security'),'includeSubDomains; max-age=31536000')
			self.assertEqual(result.headers.get('Public-Key-Pins'),'includeSubDomains; report-uri=/hpkp_report; max-age=5184000')
			self.assertEqual(result.headers.get('X-Content-Type-Options'),'nosniff')
			self.assertEqual(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEqual(result.headers.get('X-Download-Options'),'noopen')
			self.assertEqual(result.headers.get('X-Frame-Options'),'sameorigin')
			self.assertEqual(result.headers.get('Content-Security-Policy'),"report-uri /csp_report; default-src 'self'")

	def test_update_function(self):
		""" test config update function """
		self.sh.update(
			{
				'X_Permitted_Cross_Domain_Policies':{'value':'all'},
				'CSP':{'script-src':['self','code.jquery.com']},
				'HPKP':{'pins':[{'sha256':'test123'},{'sha256':'test2256'}]}
			}
		)
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('X-Permitted-Cross-Domain-Policies'),'all')
			self.assertEqual(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com; report-uri /csp_report; default-src 'self'")
			self.assertEqual(result.headers.get('Public-Key-Pins'),"pin-sha256=test123; pin-sha256=test2256; includeSubDomains; report-uri=/hpkp_report; max-age=5184000")

	def test_rewrite_function(self):
		""" test config rewrite function """
		self.sh.rewrite(
			{
				'CSP':{'default-src':['none']},
				'HPKP':{'pins':[{'sha256':'test123'}]}
			}
		)
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('Content-Security-Policy'),"default-src 'none'")
			self.assertEqual(result.headers.get('Public-Key-Pins'),"pin-sha256=test123")

	def test_wrapper_update_function(self):
		""" test updating policies from wrapper """
		self.sh.rewrite(
			{
				'CSP':{'default-src':['none']},
				'HPKP':{'pins':[{'sha256':'test123'}]}
			}
		)
		@self.app.route('/')
		@self.sh.wrapper(
			{
				'CSP':{'script-src':['self','code.jquery.com']},
				'X_Permitted_Cross_Domain_Policies':{'value':'none'},
				'X-XSS-Protection':{'value':1,'mode':False},
				'HPKP':{'pins':[{'sha256':'test2256'}]},
			}
		)
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEqual(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com; default-src 'none'")
			self.assertEqual(result.headers.get('X-XSS-Protection'),'1')
			self.assertEqual(result.headers.get('Public-Key-Pins'),"pin-sha256=test2256; pin-sha256=test123")
		@self.app.route('/test')
		@self.sh.wrapper({'CSP':{'script-src':['nonce-1234']}})
		def test(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/test')
			self.assertEqual(result.headers.get('Content-Security-Policy'),"script-src 'self' code.jquery.com 'nonce-1234'; default-src 'none'")

	def test_passing_none_value_rewrite(self):
		""" test removing header from update/rewrite """
		self.sh.rewrite({'CSP':None,'X_XSS_Protection':None})
		@self.app.route('/')
		@self.sh.wrapper()
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEqual(result.headers.get('CSP'),None)
			self.assertEqual(result.headers.get('X-XSS-Protection'),None)

	def test_passing_none_value_wrapper(self):
		""" test removing policy from wrapper """
		@self.app.route('/')
		@self.sh.wrapper({'CSP':None,'X-XSS-Protection':None})
		def index(): return "hi"
		with self.app.test_client() as c:
			result = c.get('/')
			self.assertEqual(result.headers.get('X-Permitted-Cross-Domain-Policies'),'none')
			self.assertEqual(result.headers.get('CSP'),None)
			self.assertEqual(result.headers.get('X-XSS-Protection'),None)

if __name__ == '__main__':
    unittest.main()
