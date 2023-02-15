from core.investigation import ImportMethod


class ImportText(ImportMethod):
    def do_import(self, results, filepath):
        with open(filepath, "r") as f:
            content = f.read()

        results.investigation.update(import_text=content)


class ImportTextPlain(ImportText):
    default_values = {
        "name": "import_text",
        "description": "Perform investigation import from a text document.",
        "acts_on": "text/plain",
    }


class ImportXML(ImportText):
    default_values = {
        "name": "import_xml",
        "description": "Perform investigation import from an XML document.",
        "acts_on": "text/xml",
    }
