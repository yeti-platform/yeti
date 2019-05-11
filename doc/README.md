# Building `doc`

## `make`

### If you've edited a file

```
   cd doc
   make html
```
`make` in turn calls `sphinx-build`.

### Adding a file and getting it to show up in the table of contents

1. Edit `index.rst`. At the bottom is the table of contents directive, `toctree`. Add your filename, minus the `.rst` extension.
1. `make clean`, then `make html`

## Build Failures

### `sphinxcontrib.autohttp.flask`

If `sphinx-build` fails looking for this module you need to install `sphinxcontrib-httpdomain`.
