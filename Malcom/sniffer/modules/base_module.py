from ConfigParser import ConfigParser
import os
import re

class Module(object):
    """docstring for Module"""
    def __init__(self):
        self.load_conf()

    def add_static_tags(self, content):
        add = ""
        static_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.name, 'static')
        if os.path.exists(static_dir):
            files = [f for f in os.listdir(static_dir) if (f.lower().endswith('.css') or f.lower().endswith('.js')) and not f.lower().startswith('.')]
            for f in files:
                if f.lower().endswith(".css"):
                    add += self.css_tag(f)
                elif f.lower().endswith(".js"):
                    add += self.js_tag(f)
        add += content

        return add

    def static(self, args):
        filename = args.get('filename')
        if not filename or re.match('\w+\.\w+', filename) is None:
            return False
        try:
            full_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.name, 'static', filename)
            with open(full_path, 'r') as _file:
                file_contents = _file.read()
            return str(file_contents)
        except IOError, e:
            print "File not found: {}".format(e)
            return False

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
