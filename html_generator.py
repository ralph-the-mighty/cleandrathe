def section(text,_class):
	"""return an html section element.
	_class is used because class is a reserved word"""
        
	return "<section class='%s'>%s</section>" % (_class,text)

def header_section(title):
	text = "<h1>title</h1>"
	return section(text,"article-header")


        
