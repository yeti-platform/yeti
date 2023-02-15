from readability.readability import Document
from html2text import HTML2Text
from bs4 import BeautifulSoup

from core.investigation import ImportMethod


def import_html(results, content):
    content = Document(content)

    converter = HTML2Text()
    converter.body_width = 0

    body = content.summary()
    text = BeautifulSoup(body).get_text(" ")

    results.investigation.update(
        name=content.short_title(), import_md=converter.handle(body), import_text=text
    )


class ImportHTML(ImportMethod):
    default_values = {
        "name": "import_html",
        "description": "Perform investigation import from a HTML document.",
        "acts_on": "text/html",
    }

    def do_import(self, results, filepath):
        html_file = open(filepath, "r")
        html = html_file.read()
        html_file.close()

        import_html(results, html)
