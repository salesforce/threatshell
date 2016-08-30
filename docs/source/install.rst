Installation
============
The installation process for most operating systems follows
the same set of steps for the most part. I prefer to keep
things maintained in a python virtual environment. These install
steps will guide you through setting up a virtual environment for
each OS which you may skip if you don't want.

OS X
-----


Virtualenv Setup
^^^^^^^^^^^^^^^^

Before You Begin
++++++++++++++++

First up, you'll need Xcode. You can find it in the app store,
but it's huge (like 4GB) so it'll take a while to download. Once
you have it, install the command line tools with
::

    xcode-select --install

Once Xcode is all taken care of, get homebrew
::

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

You should already have python, but if you'd like a different
version, you may install one from brew.

Setting up the Virtualenv
+++++++++++++++++++++++++

::

    pip install virtualenv
    pip install virtualenvwrapper
    echo 'export WORKON_HOME="$HOME/.virtualenvs"' >> ~/.bash_profile
    echo 'source $(which virtualenvwrapper.sh)' >> ~/.bash_profile
    source ~/.bash_profile

Now you will have a bunch of bash helper functions for
using/managing virtual environments. The one's you will use most
are:
::

    mkvirtualenv <env name> # creates a new virtual env
    rmvirtualenv <env name> # deletes a virtual env
    mktmpenv # creates a virtual env that is deleted when `deactivate` is run
    workon <env name> # sets the current virtual env
    deactivate # unsets the current virtual env

Setting up ThreatShell
++++++++++++++++++++++

Installing the requirements for ThreatShell is as simple as
::

    python setup.py install

You can run tests with
::

    python setup.py test

    # or with coverage included like so
    python setup.py test --pytest-args="--cov=threatshell"

To begin using it
::

    python threatshell.py

Running ThreatShell for the first time will trigger some
setup/configuration prompts. Just follow along and you'll be
hunting in no time.

Readline Caveat!
++++++++++++++++

OS X doesn't ship with libreadline. Instead, you get libedit which kinda sucks.
The main issue with libedit is that it doesn't honor the libreadline escape
characters, therefore, it will fail to properly read the shell line with its
color sequences, and scrolling through history causes buggy command display
issues.

This can be solved by simply using `easy_install` to install readline, or by
using brew to install the GNU readline and force linking it in. I recommend
just using the `easy_install readline`. You will know when you have the right
readline library working because Threatshell won't complain about libedit being
detected ;)
