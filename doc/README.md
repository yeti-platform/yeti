# Building `doc`

   cd doc
   make html

`make` in turn calls `sphinx-build`.

## Build Failures

### `sphinxcontrib.autohttp.flask`

If `sphinx-build` fails looking for this module you need to install `sphinxcontrib.httpdomain`.