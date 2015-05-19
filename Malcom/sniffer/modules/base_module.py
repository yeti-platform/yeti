from ConfigParser import ConfigParser
import os


class Module(object):
    """docstring for Module"""
    def __init__(self):
        self.load_conf()

    def static(self, args):
        filename = args.get('filename')
        if not filename:
            return None
        try:
            full_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.name, 'static', filename)
            with open(full_path, 'r') as _file:
                file_contents = _file.read()
            return str(file_contents)
        except IOError, e:
            print "File not found: {}".format(e)
            return None

    def bootstrap(self, args):
        raise NotImplementedError("You must implement a bootstrap method")

    def js_tag(self, filename):
        string = '<script src="/api/sniffer/module/{}/{}/static/?filename={}"></script>'.format(self.session.id, self.name, filename)
        return string

    def css_tag(self, filename):
        string = '<link href="/api/sniffer/module/{}/{}/static/?filename={}" type="text/css" rel="stylesheet">'.format(self.session.id, self.name, filename)
        return string

    def on_packet(self, pkt):
        raise NotImplementedError("You must implement a on_packet(pkt) method")

    def load_conf(self):
        self.config = {}
        config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.name, '{}.conf'.format(self.name))

        cfp = ConfigParser()
        if os.path.isfile(config_file):
            cfp.readfp(open(config_file))
            for section in cfp.sections():
                self.config[section] = {}
                for option in cfp.options(section):
                    self.config[section][option] = cfp.get(section, option)
