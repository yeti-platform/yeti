from core.logger import userLogger
from core.group import Group
from mongoengine import NotUniqueError

def create_group(groupname):
    try:
        return Group(groupname=groupname).save()
    except NotUniqueError:
        return False
