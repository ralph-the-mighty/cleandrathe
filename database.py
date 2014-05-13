
from google.appengine.ext import db

class User(db.Model):
	name = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = True)		
	
	@classmethod
	def by_id(cls,uid):
		return cls.get_by_id(uid)
		
	@classmethod
	def by_name(cls,name):
		u = cls.all().filter('name =',name).get()
		return u
		
	@classmethod
	def register(cls, name, pw, email):
		return User(name = name,
					password = pw,
					email = email)
					
class Page(db.Model):
	name = db.StringProperty(required = True)
	url = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	author_id = db.IntegerProperty(required = True)
	author_name = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	version = db.IntegerProperty(required = True)
	comment = db.StringProperty()
	
	@classmethod
	def by_id(cls,uid):
		return cls.get_by_id(uid)
		
	@classmethod
	def by_name(cls,name):
		u = cls.all().filter('name =',name).get()
		return u