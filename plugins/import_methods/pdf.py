from cStringIO import StringIO
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.pdfpage import PDFPage

from core.investigation import ImportMethod


class ImportPDF(ImportMethod):

    default_values = {
        "name": "import_pdf",
        "description": "Perform investigation import from a PDF document.",
        "acts_on": "application/pdf"
    }

    def do_import(self, results, filepath):
        buff = StringIO()
        fp = open(filepath, 'rb')

        rsrcmgr = PDFResourceManager()
        device = TextConverter(rsrcmgr, buff)
        interpreter = PDFPageInterpreter(rsrcmgr, device)

        for page in PDFPage.get_pages(fp, set()):
            interpreter.process_page(page)

        results.investigation.update(import_text=buff.getvalue())

        fp.close()
        buff.close()
