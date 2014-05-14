#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from urlparse import urlparse
from urlparse import urlsplit
import logging
import sys
import webapp2
import os
import jinja2
import time
import re
from google.appengine.ext import db
from difflib import SequenceMatcher
from hash import *
from database import *
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #	

# jinja stuff
	
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = False)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#tricky stuff to get the stupid creole library to work

sys.path.append(os.path.join(os.path.dirname(__file__),'lib'))
import creole

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

def strip_url(url):
	"""strip the preliminary paths of the url"""
	urllist = url.split('/')
	last_bit = urllist[-1]
	if '?' in last_bit:
		q_index = last_bit.index('?')
		name = last_bit[:q_index]
		return name
	return last_bit

def similar(a,b):
	return SequenceMatcher(None,a,b).ratio()
	
def first(the_iterable, condition = lambda x: True):
    for i in the_iterable:
        if condition(i):
            return i
			
def delete_page(url):
	query_str = "SELECT * FROM Page WHERE url = '%s'" % (url)
	all_versions = db.GqlQuery(query_str)
	
	for page in all_versions:
		page.delete()
			
def fetch_page(url,version):
		if version:
			query_str = "SELECT * FROM Page WHERE url = '%s' AND version = %s" % (url,version)
			logging.info('fetch page: '+ query_str)
			return db.GqlQuery(query_str).get()
			
def name_to_url(name):
	newstr = ''
	for c in name:
		if c == ' ':
			newstr += '_'
		else:
			newstr += c
	return newstr
	
def url_to_name(url):
	newstr = ''
	for c in url:
		if c == '_':
			newstr += ' '
		else:
			newstr += c
	return newstr
		
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# basic request handler abstraction
class Handler(webapp2.RequestHandler):

	# tool for checking http requests
	def write_request(self):
		self.response.headers['Content-Type'] = 'text/plain'
		self.write(self.request)
	
	# methods for writing out page content
	def write(self, *a, **kw):
		self.response.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
		
	#methods for handling cookies
	def set_cookie(self,name,val,exp):
		"""set cookie after format 'name=val'"""
		cookie_str = str('%s=%s; expires=%s;'%(name,val,exp)) 
		logging.info('cookie: %s' % cookie_str)
		self.response.headers.add_header('Set-Cookie',cookie_str)
		
	
	def set_secure_cookie(self,name,val,exp):
		secure_val = make_secure_val(val)
		self.set_cookie(name,secure_val,exp)
		
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)
	
	def delete_cookie(self,name):
		self.response.delete_cookie(name)
	
	def get_url(self):
		path = urlsplit(self.request.url).path
		params = urlsplit(self.request.url).query
		return path + '?' + params
	
	#login, logout
	def login(self,user):
		uid_string = str(user.key().id())
		date = 'Sat, 03 May 2025 17:44:22 GMT'
		self.set_secure_cookie('user_id',uid_string,date)
		self.user = user
	
	def logout(self):
		self.delete_cookie('user_id')
		self.user = None
	
	#this function will be called before any other method in the handler,
	#checking for the user_id cookie.  If it finds one, it will set a user 
	#variable to the appropriate User object
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		user_id = self.read_secure_cookie('user_id')     #string or None
		if user_id:
			self.user = User.by_id( int(user_id) )
		else:
			self.user = None

			
class Signup(Handler):

    def get(self):
        self.render('signup.html')
		
    def post(self):
		has_error = False
		error_msg = ''
		
		name = self.request.get('name')
		password = self.request.get('password')
		cpassword = self.request.get('cpassword')
		email = self.request.get('email')
		
		# error handling
		if name and password and cpassword and email:
			if password != cpassword:
				has_error = True
				error_msg = 'your passwords do not match!'
				
			u = User.by_name(name)
			if u:
				has_error = True
				error_msg = 'that username already exists!'
		else:
			has_error = True
			error_msg = 'please fill all forms'
			
		if has_error:
			self.render('signup.html', name=name, password=password, cpassword=cpassword, error=error_msg)
		else:
			u = User(name=name,
					 password=hash_pw(password),
					 email=email)
			u.put()
			self.login(u)
			
			
			self.redirect('/')

			
class Login(Handler):
	def get(self):
		self.render('login.html')
	def post(self):
		subname = self.request.get('name')
		subpassword = self.request.get('password')
		
		u = User.by_name(subname)
		
		#error handling
		if u and hash_pw(subpassword) == u.password:
			#the r parameter in the url is to signify a page to be redirected
			#to after a successful login.  This is to ensure that users who sign in from
			#other pages will be returned to the corrct page after sign-in.
			return_address = self.request.get('r')
			self.login(u)
			if return_address:
				self.redirect(return_address)
			else:
				self.redirect('/')
		else:
			msg = 'incorrect username or password'
			self.render('login.html',error=msg)

			
class Home(Handler):
	def get(self):
			self.render('home.html',name='', user=self.user)
			
	def post(self):
		name = self.request.get('name')
		self.redirect('/edit/%s' % (name_to_url(name)) )

class Delete(Handler):
	def get(self,page_url):
		delete_page(page_url)
		self.redirect('/')

class Logout(Handler):
	def get(self):
	
		self.logout()

		return_address = self.request.get('r')
		if return_address:
			self.redirect(return_address)
		else:
			self.redirect('/')

		
class WikiPage(Handler):

	def get(self,page_url):
		#get data
		url = self.get_url()
		page_name = url_to_name(page_url)
		version = self.request.get('v')
		
		#extract name and version from url and query the appropriate page
		#make sure that a version exists
		if not version:
			version = '0'
		
		p = fetch_page(page_url,version)
		
		#assuming that the page even exists. . .
		if p:
			# now convert the source into html.  Creole is sure handy!
			creole_text = creole.creole2html(p.content)
			#query the datapase to find all versions of the page for the history div
			query_str = "SELECT * FROM Page WHERE url = '%s' ORDER BY version ASC LIMIT 10" % (page_url)
			versions = db.GqlQuery(query_str)
			#render the page.  Duh!
			self.render('wiki_page.html',
						user=self.user,
						content=creole_text,
						url = p.url,
						page_name=p.name,
						created = p.created.date(),
						author_name = p.author_name,
						version_no = int(version),
						versions = versions)
						
		#if their is no matching page,redirect 
		#to an edit page where that page can be 
		#created and saved
		else:
			self.redirect('/edit/%s?' % ( page_url ) ) 
 
class NewPage(Handler):
	def get(self):
		name = self.request.get('name')
		self.redirect('/edit/%s' % name)

			
class EditPage(Handler):
	def get(self, page_url):
		#grab the name and version number from the url and 
		#use them to fetch the right page
		name = url_to_name(page_url)
		v = self.request.get('v')
		
		if self.user:
			if v:
				p = fetch_page(page_url,v)
			else:
				p = fetch_page(page_url,'0')
			#if such a page exists, render its contents in the textarea to be modified.
			#else, render the textarea empty
			if p:
				self.render('edit.html',
							user=self.user,
							page_name=p.name,
							page_url = p.url,
							content=p.content)
			else:
				self.render('edit.html',
							user=self.user,
							page_name = name,
							page_url = page_url,
							content = '')
		else:
			self.redirect('/login?r=/edit/%s?v=%s' % (name,v) )
	
	def post(self, page_url):
		#grab data from the request and logged in user to pass to the page object
		page_name = url_to_name(page_url)
		content = self.request.get('content')
		comment = self.request.get('comment')
		a_name = self.user.name
		a_id = self.user.key().id()
		
		query_str = "SELECT * FROM Page WHERE url = '%s'" % (page_url)
		query = db.GqlQuery(query_str)
		for page in query:
			page.version += 1
			page.put()
		
		p = Page(name=page_name,
				url=page_url,
				content=content,
				comment=comment,
				author_id=a_id,
				author_name=a_name,
				version=0)
		p.put()
		# # # # # # # #  # # # # # # # # # # # # # # # #  # # # # # # # # # # # # # # # #  # # # # # # # #
		#redirect home
		time.sleep(.25)
		self.redirect('/' + name_to_url(page_name)+"?v=0")
		
		
class Search(Handler):
	def get(self):
		q = self.request.get('q')
		url = self.get_url()
		
		#run a page query, checking for each page with a new version
		page_query = db.GqlQuery("SELECT * FROM Page WHERE version = 0")
		
		#turn the page query into a list.		
		lst = list(page_query)

		lst.sort(key=lambda i: similar(i.name,q),reverse=True)
		self.render("search.html",
					user=self.user,
					q=q, lst=lst)
					
class History(Handler):
	def get(self,url):
		querystr = "SELECT * FROM Page WHERE url = '%s'" % (url)
		pages = list(db.GqlQuery(querystr))
		pages.sort(key=lambda page: page.version)
		
		name = url_to_name(url)
		
		self.render('history.html',
					name = name,
					pages = pages,
					user = self.user)
		
class Test(Handler):
	def get(self):
		self.render('this is a string')
			
PAGE_RE = r'(?:[a-zA-Z0-9_-]+/?)*'			
app = webapp2.WSGIApplication([
	('/signup', Signup),
	('/login', Login),
	('/test',Test),
	('/logout',Logout),
	('/search',Search),
	('/newpage',NewPage),
	('/',Home),
	('/delete/('+PAGE_RE+')',Delete),
	('/history/(' + PAGE_RE + ')',History),
	('/edit/(' + PAGE_RE + ')', EditPage),
	('/(' + PAGE_RE + ')', WikiPage)
], debug=True)
