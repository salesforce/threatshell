threatshell
===========

Threatshell is a python-based command line shell aimed at providing security
researchers with a single, integrated environment for gathering information
from various intelligence APIs and analysis scripts, and storing all of the
obtained information into one or more elasticsearch instances. The goal of
keeping the results in elasticsearch being to provide a historical search
mechanism for all of the gathered information, and to start building a clever
event analyzer to assist in hunting and analysis activities.


Notes
=======

Please see the docs for installation help and for threatshell usage details.

I recommend using python virtual environments (virtualenvs) if you don't
already. If you'd like to use a virtualenv, I detail (roughly) how to set one
up in the install section of the docs, and there are plenty of awesome
tutorials for setting up and using virtualenvs out there already if you still
have questions.


Building the Docs
=================

(Eventually, I'll get these docs up on a proper documentation site)

    # make sure pip is up to date if you want
    pip install --upgrade pip

    # you will need sphinx at least
    pip install sphinx

    # you can also install everything with
    # pip install -r requirements.txt
    # or
    # python setup.py install

    # you can build and view the
    # docs this way
    python setup.py build_sphix
    cd docs/build/html

    # or this way
    cd docs
    make html
    cd build/html

Now you should be able to open index.html in a browser to navigate around
the built documentation.
