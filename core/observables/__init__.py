from mongoengine import *

connect('malcom-v2')

from core.observables.tag import Tag
from core.observables.observable import Observable, LinkHistory, Link
from core.observables.ip import Ip
from core.observables.url import Url
from core.observables.hostname import Hostname
from core.observables.hash import Hash
from core.observables.file import File
