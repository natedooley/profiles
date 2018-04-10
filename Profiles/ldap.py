import hashlib, requests, ldap


from functools import lru_cache
from Profiles import _ldap
from csh_ldap import CSHMember



def _ldap_get_group_members(group):
    return _ldap.get_group(group).get_members()


def _ldap_is_member_of_group(member, group):
    group_list = member.get("memberOf")
    for group_dn in group_list:
        if group == group_dn.split(",")[0][3:]:
            return True
    return False


def _ldap_add_member_to_group(account, group):
    if not _ldap_is_member_of_group(account, group):
        _ldap.get_group(group).add_member(account, dn=False)


def _ldap_remove_member_from_group(account, group):
    if _ldap_is_member_of_group(account, group):
        _ldap.get_group(group).del_member(account, dn=False)


@lru_cache(maxsize=1024)
def _ldap_is_member_of_directorship(account, directorship):
    directors = _ldap.get_directorship_heads(directorship)
    for director in directors:
        if director.uid == account.uid:
            return True
    return False


#Getters 


def ldap_get_member(username):
    return _ldap.get_member(username, uid=True)


@lru_cache(maxsize=1024)
def ldap_get_active_members():
    return _ldap_get_group_members("active")


@lru_cache(maxsize=1024)
def ldap_get_intro_members():
    return _ldap_get_group_members("intromembers")


@lru_cache(maxsize=1024)
def ldap_get_onfloor_members():
    return _ldap_get_group_members("onfloor")


@lru_cache(maxsize=1024)
def ldap_get_current_students():
    return _ldap_get_group_members("current_student")


@lru_cache(maxsize=1024)
def ldap_get_all_members():
    return _ldap_get_group_members("member")


@lru_cache(maxsize=1024)
def ldap_get_groups(account):
    group_list = account.get("memberOf")
    groups = []
    for group_dn in group_list:
        groups.append(group_dn.split(",")[0][3:])
    return groups


@lru_cache(maxsize=1024)
def ldap_get_eboard():
    members = _ldap_get_group_members("eboard-chairman") + _ldap_get_group_members("eboard-evaluations") + _ldap_get_group_members("eboard-financial") + _ldap_get_group_members("eboard-history") + _ldap_get_group_members("eboard-imps") + _ldap_get_group_members("eboard-opcomm") + _ldap_get_group_members("eboard-research") + _ldap_get_group_members("eboard-social") + _ldap_get_group_members("eboard-secretary")

    return members



# Status checkers

def ldap_is_active(account):
    return _ldap_is_member_of_group(account, 'active')


def ldap_is_alumni(account):
    # If the user is not active, they are an alumni.
    return not _ldap_is_member_of_group(account, 'active')


def ldap_is_eboard(account):
    return _ldap_is_member_of_group(account, 'eboard')


def ldap_is_rtp(account):
    return _ldap_is_member_of_group(account, 'rtp')


def ldap_is_intromember(account):
    return _ldap_is_member_of_group(account, 'intromembers')


def ldap_is_onfloor(account):
    return _ldap_is_member_of_group(account, 'onfloor')


def ldap_is_current_student(account):
    return _ldap_is_member_of_group(account, 'current_student')


# Directorships

def ldap_is_financial_director(account):
    return _ldap_is_member_of_directorship(account, 'financial')


def ldap_is_eval_director(account):
    return _ldap_is_member_of_directorship(account, 'evaluations')


def ldap_is_chairman(account):
    return _ldap_is_member_of_directorship(account, 'chairman')


def ldap_is_history(account):
    return _ldap_is_member_of_directorship(account, 'history')


def ldap_is_imps(account):
    return _ldap_is_member_of_directorship(account, 'imps')


def ldap_is_social(account):
    return _ldap_is_member_of_directorship(account, 'Social')


def ldap_is_rd(account):
    return _ldap_is_member_of_directorship(account, 'research')


# Setters

def ldap_set_housingpoints(account, housing_points):
    account.housingPoints = housing_points
    ldap_get_current_students.cache_clear()
    ldap_get_member.cache_clear()


def ldap_set_roomnumber(account, room_number):
    if room_number == "":
        room_number = None
    account.roomNumber = room_number
    ldap_get_current_students.cache_clear()
    ldap_get_member.cache_clear()


def ldap_set_active(account):
    _ldap_add_member_to_group(account, 'active')
    ldap_get_active_members.cache_clear()
    ldap_get_member.cache_clear()


def ldap_set_inactive(account):
    _ldap_remove_member_from_group(account, 'active')
    ldap_get_active_members.cache_clear()
    ldap_get_member.cache_clear()


def ldap_set_current_student(account):
    _ldap_add_member_to_group(account, 'current_student')
    ldap_get_current_students.cache_clear()
    ldap_get_member.cache_clear()


def ldap_set_non_current_student(account):
    _ldap_remove_member_from_group(account, 'current_student')
    ldap_get_current_students.cache_clear()
    ldap_get_member.cache_clear()


def ldap_update_profile(dict, uid):
	account = _ldap.get_member(uid, uid=True)

	

	if not dict["name"] == account.cn or dict["name"] == None or dict["name"] == "None":
		account.cn = dict["name"]
	elif dict["name"] ==  None or dict["name"] == "None":
		account.cn = None

	if not dict["birthday"] == account.birthday or dict["birthday"] == None or dict["birthday"] == "None":
		account.birthday = dict["birthday"]
	elif dict["birthday"] ==  None or dict["birthday"] == "None":
		account.birthday = None

	if not dict["phone"] == account.mobile or dict["phone"] ==None or dict["phone"] == "None":
		account.mobile = dict["phone"]
	elif dict["phone"] ==  None or dict["phone"] == "None":
		account.mobile = None

	if not dict["plex"] == account.plex or dict["plex"] == None or dict["plex"] ==  "None":
		account.plex = dict["plex"]
	elif dict["plex"] ==  None or dict["plex"] ==  "None":
		account.plex = None

	if not dict["major"] == account.major or dict["major"] == None or dict["major"] == "None":
		account.major = dict["major"]
	elif dict["major"] ==  None or dict["major"] == "None":
		account.major = None

	if not dict["ritYear"] == account.ritYear or dict["ritYear"] == None  or dict["ritYear"] == "None":
		account.ritYear = dict["ritYear"]
	elif dict["ritYear"] ==  None or  dict["ritYear"] =="None":
		account.ritYear = None

	if not dict["website"] == account.homepageURL or dict["website"] ==None or dict["website"] == "None":
		account.homepageURL = dict["website"]
	elif dict["website"] ==  None or dict["website"] ==  "None":
		account.homepageURL = None

	if not dict["github"] == account.github or dict["github"] ==None  or dict["github"] ==  "None":
		account.github = dict["github"]
	elif dict["github"] ==  None or dict["github"] ==  "None":
		account.github = None

	if not dict["twitter"] == account.twitterName or dict["twitter"] ==None or dict["twitter"] == "None":
		account.twitterName = dict["twitter"]
	elif dict["twitter"] ==  None or dict["twitter"] == "None":
		account.twitterName = None

	if not dict["blog"] == account.blogURL or dict["blog"] ==None or dict["blog"] == "None":
		account.blogURL = dict["blog"]
	elif dict["blog"] ==  None or dict["blog"] == "None":
		account.blogURL = None

	if not dict["google"] == account.googleScreenName or dict["google"] == None  or dict["google"] == "None":
		account.googleScreenName = dict["google"]
	elif dict["google"] ==  None or dict["google"] == "None":
		account.googleScreenName = None

	account.blogURL = None

	con = _ldap.get_con()
	ldap_mod = ldap.MOD_DELETE
	key = blogURL

	mod = (ldap_mod, key)

	mod_attrs = [mod]

	con.modify_s(account.get_dn(), mod_attrs)
	

def ldap_get_roomnumber(account):
    try:
        return account.roomNumber
    except AttributeError:
        return ""


@lru_cache(maxsize=1024)
def ldap_search_members(query):
    con = _ldap.get_con()
    filt = str("(|(description=*{0}*)(displayName=*{0}*)(mail=*{0}*)(nickName=*{0}*)(plex=*{0}*)(sn=*{0}*)(uid=*{0}*)(mobile=*{0}*)(twitterName=*{0}*)(github=*{0}*))").format(query)

    res= con.search_s(
		"dc=csh,dc=rit,dc=edu",
		ldap.SCOPE_SUBTREE,
		filt,
		['uid'])

    ret = []

    for uid in res:
    	try:
    		mem = (str(uid[1]).split('\'')[3])
    		ret.append(ldap_get_member(mem))
    	except IndexError:
    		continue

    return ret


# @lru_cache(maxsize=1024)
def get_image(uid):
	return ldap_get_member(uid).jpegPhoto


@lru_cache(maxsize=1024)
def get_gravatar(uid):
	addr = uid + "@csh.rit.edu"
	url = "https://gravatar.com/avatar/" + hashlib.md5(addr.encode('utf8')).hexdigest() +".jpg?d=mm&s=250"

	return url

