import magic
import pdfkit
import requests
from os import path
from shutil import rmtree
from tempfile import mkdtemp
from StringIO import StringIO

from plugins.import_methods.html import import_html
from core.database import AttachedFile
from core.investigation import ImportMethod
from core.config.config import yeti_config


class ImportURL(ImportMethod):

    default_values = {
        "name": "import_url",
        "description": "Perform investigation import from an URL.",
        "acts_on": "url"
    }

    def save_as_pdf(self, results, url):
        tmpdir = mkdtemp()

        try:
            options = {
                "load-error-handling": "ignore"
            }

            pdfkit.from_url(url, path.join(tmpdir, 'out.pdf'), options=options)

            with open(path.join(tmpdir, 'out.pdf'), 'rb') as pdf:
                pdf_import = AttachedFile.from_content(pdf, 'import.pdf', 'application/pdf')

            results.investigation.update(import_document=pdf_import)
        except Exception, e:
            print e

        rmtree(tmpdir)

    def do_import(self, results, url):
        response = requests.get(url, proxies=yeti_config.proxy)
        content_type = magic.from_buffer(response.content, mime=True)

        if content_type == "text/html":
            import_html(results, response.content)
            self.save_as_pdf(results, url)
        else:
            target = AttachedFile.from_content(StringIO(response.content), url, content_type)
            results.investigation.update(import_document=target)
            try:
                method = ImportMethod.objects.get(acts_on=content_type)
                method.do_import(results, target.filepath)
            except:
                raise ValueError("unsupported file type: '{}'".format(content_type))
