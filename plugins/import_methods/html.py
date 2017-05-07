from readability.readability import Document
from html2text import HTML2Text

from core.investigation import ImportMethod


class ImportHTML(ImportMethod):

    default_values = {
        "name": "import_html",
        "description": "Perform investigation import from a HTML document.",
        "acts_on": "text/html"
    }

    def do_import(self, results, filepath):
        html_file = open(filepath, "r")
        html = html_file.read()
        html_file.close()
        content = Document(html)

        converter = HTML2Text()
        converter.body_width = 0

        results.investigation.update(name=content.short_title(), import_text=converter.handle(content.summary()))
