# seshquic

Python bindings for libquic.

## Building

From the repository root:

    pip install .

For development, an in-tree build puts the extension module next to the package sources so that
`PYTHONPATH=python` is enough to import it:

    cmake -B build-py -DLIBQUIC_BUILD_PYTHON=ON -DLIBQUIC_BUILD_TESTS=OFF
    make -C build-py seshquic_core
    PYTHONPATH=python python3 -c 'import seshquic; print(seshquic.__version__)'

## Tests

    PYTHONPATH=python python3 -m pytest python/tests
