import pdfkit
import requests
from os import path
from shutil import rmtree
from tempfile import mkdtemp
from StringIO import StringIO
from readability.readability import Document
from html2text import HTML2Text

from core.database import AttachedFile
from core.investigation import ImportMethod


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
        except Exception, e:
            print e

        with open(path.join(tmpdir, 'out.pdf'), 'rb') as pdf:
            pdf_import = AttachedFile.from_content(pdf, 'import.pdf', 'application/pdf')

        results.investigation.update(import_document=pdf_import)

        rmtree(tmpdir)

    def do_import(self, results, url):
        response = requests.get(url)
        content_type = response.headers['content-type'].split(';')[0]

        if content_type == "text/html":
            content = Document(response.content)
            converter = HTML2Text()
            converter.body_width = 0

            results.investigation.update(name=content.short_title(), import_text=converter.handle(content.summary()))

            self.save_as_pdf(results, url)
        else:
            target = AttachedFile.from_content(StringIO(response.content), url, content_type)
            results.investigation.update(import_document=target)
            method = ImportMethod.objects.get(acts_on=content_type)
            method.do_import(results, target.filepath)
