import re

import re

class Transform(object):
  """Abstraction for a regular expression transform.

  Transform subclasses have two properties:
     regexp: the regular expression defining what will be replaced
     replace(MatchObject): returns a string replacement for a regexp match

  We iterate over all matches for that regular expression, calling replace()
  on the match to determine what text should replace the matched text.

  The Transform class is more expressive than regular expression replacement
  because the replace() method can execute arbitrary code to, e.g., look
  up a WikiWord to see if the page exists before determining if the WikiWord
  should be a link.
  """
  def run(self, content):
    """Runs this transform over the given content.

    Args:
      content: The string data to apply a transformation to.

    Returns:
      A new string that is the result of this transform.
    """
    parts = []
    offset = 0
    for match in self.regexp.finditer(content):
      parts.append(content[offset:match.start(0)])
      parts.append(self.replace(match))
      offset = match.end(0)
    parts.append(content[offset:])
    return ''.join(parts)


class WikiWords(Transform):
  """Translates WikiWords to links. """
  def __init__(self):
    self.regexp = re.compile(r'<<[A-Za-z]+>>')

  def replace(self, match):
    wikiword = match.group(0)
    return '<a class="wikiword" href="/%s">%s</a>' % (wikiword[2:-2], wikiword[2:-2])
	
class WikiWords2(Transform):
	"""translates the specialized wikiwords"""
	def __init__(self):
		self.regexp = re.compile(r'<<[A-za-z]+>[A-Za-z]+>')
	
	def replace(self, match):
		start = wikiword.find('>')
		wikiword = match.group(0)
		
		name = wikiword[3:start]
		target = wikiword[start+1:]
		
		return '<a class = "wikiword" href="/%s">%s</a>' % (target, name)

