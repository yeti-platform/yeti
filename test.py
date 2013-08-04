import os
from feeds import feed

def import_feeds():
	
	globals_, locals_ = globals(), locals()

	file = os.path.abspath(__file__)
	directory = os.path.dirname(file)
	
	package_name = 'feeds'
	feeds_dir = directory + '/' + package_name

	print "current dir: ", directory
	print "feeds dir: ", feeds_dir
	

	for filename in os.listdir(feeds_dir):
		export_names = []
		export_classes = []

		modulename, ext = os.path.splitext(filename)
		if modulename[0] != "_" and ext in ['.py']:
			subpackage = '%s.%s' % (package_name, modulename)
			print "Loading %s" % subpackage, modulename
			module = __import__(subpackage, globals_, locals_, [modulename])

			modict = module.__dict__

			names = [name for name in modict if name[0] != '_']

			for n in names:
				class_n = modict.get(n)
				# print n, class_n
			 	try:
			 		if issubclass(class_n, feed.Feed) and class_n not in globals_:
			 			export_names.append(n)
			 			export_classes.append(class_n)
			 	except Exception, e:
			 		pass

	globals_.update((export_names[i], c) for i, c in enumerate(export_classes))

	return export_names, export_classes

if __name__ == '__main__':
    n, c = import_feeds()
    print "Imported:"
    for name in n:
    	print name

