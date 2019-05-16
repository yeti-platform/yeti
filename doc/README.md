# Building `doc`

The "standard documentation" is an HTML tree which is under this directory as `_build/html/`.

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

This _should_ add the new file to all pages. Be sure to review `_build/html/index.html` and verify that it was added.

## Build Failures

### `sphinxcontrib.autohttp.flask`

If `sphinx-build` fails looking for this module you need to install `sphinxcontrib-httpdomain`. With `pip`:

```
pip install sphinxcontrib-httpdomain
```

