#
# hash stuff
#
import hashlib
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# hash stuff
# NOTE: secure val => "val|H(val)"

SECRET = "AK$&KRf92kg}2[v'c/si29a-70^89gBq"

def hash_str(str):
	return hashlib.md5(str).hexdigest()

def make_secure_val(s):
	""" secure val format: 'val|H(val)' """
	hashed_cookie = '%s|%s' %(s,hash_str(s))
	return hashed_cookie
	
def check_secure_val(h):
    split_hash = h.split('|')                        
    if split_hash[1] == hash_str(split_hash[0]):
        return split_hash[0]
    else:
        return None

def hash_pw(pw,salt=SECRET):
	return hash_str(pw + salt)