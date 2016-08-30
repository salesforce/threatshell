threatshell
===========

Threatshell is a python-based command line shell aimed at providing security
researchers with a single, integrated environment for gathering open source
information from various intelligence APIs, running analysis scripts, and
storing all the obtained information into one or more elasticsearch instances
to provide researchers the ability of historical analysis search, or even
automatic information correlation (comming soon™)

Please see the docs for install and usage details.

Building the Docs
=================

    python setup.py build_sphix
    cd docs/build/html

    # OR

    cd docs
    make html

Now open index.html in a browser to navigate around the built documentation.
