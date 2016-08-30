Development
===========

Foreword
--------

Being able to easily develop against Threatshell is my ultimate goal. Feel
free to open issues or email me if something isn't clear or isn't working, or
if python isn't really your thing but you'd like to see something cool added to
Threatshell.

Threatshell is built on top of the python cmd module's `Cmd class`_. It will be
just as useful of a source as anything I'd write to explain how things integrate into the
main command loop, like adding your `def do_<function name>` which you'll see
later.

For now, all you need to do to integrate your favorite analysis scripts into
Threatshell is follow a few easy steps (which will change in the near future).
Before jumping into the steps, there are a couple of prerequisites:

Prerequisites
-------------

    * make your script a module containing a class that has all the functions you want to put in Threatshell

    * decide if you want to store your data in elasticsearch or not
        - This will be expanded later to include additional output sinks


Integration
-----------

Threatshell commands are currently split up into two parts -- the functions that
go in the command module, and the functions that use the functions that go in
the command module. Sounds confusing, I know, but let's look at an example.
Let's pretend we have a script named `example.py` and we want to make it a
Threatshell module with a corresponding elasitcsearch document definition,
and for extra awesome sauce, we want our example function to run with the
magic "q" function.

`threatshell.commands.example`

.. code-block:: python
   :linenos:

    # here is the example.py module that goes in threatshell.commands
    from threatshell.commands.q import AutoQuery  # for q function
    from threatshell.doctypes import example as example_docs # we'll get to this

    import logging
    import requests

    log = logging.getLogger(__name__)


    class Example:

        # If you have sensitive information like API keys, user/pass, etc.
        # they will go into the Threatshell config which can then be passed
        # to your module's init function. No need to worry about the security
        # of your keys - that's already been taken care of
        def __init__(self, config):
            self.url = "http://some.api.com"
            self.user = config.get("Example", "user")
            self.passwd = config.get("Example", "pass")


        # This will set our example.request_intel() function to be used on
        # q --domain dom1 dom2 domN
        #
        # If the function works for multiple types of indicators, simply add
        # them to the array passed to the use_on decorator
        # (e.g. ["domain", "ip", "url"])
        #
        # Reference the threatshell.commands.q module for the list of supported
        # auto-query types, or add your own type to it
        #
        @AutoQuery.use_on(["domain"])
        def request_intel(self, domains):

            # This part is important - if you want this funtion to use q
            # correctly, it will need to be able to iterate over a list of
            # queries or it will need to be able to process the list all at
            # once (like with a bulk API). Plus it's nice to be able to do
            # multiple lookups in one command
            if not isinstance(domains, list):
                domains = [domains]

            docs = []
            for domain in domains:
                url = "%s/%s" % (self.url, domain)
                resp = requests.get(url, auth=(self.user, self.passwd))

                # assuming things went well with the request

                doc = example_docs.ExampleIntelDoc(resp.json())
                docs.append(doc)

            return docs


For the elasticsearch document definition, all you have to do is create a simple
class containing a mapping of what each key--value pair is and how it should be
handled by elasticsearch. So, let's say our magic intel API we use in
`threatshell.commands.example` returns a json document that looks like this
::

    {
        "domain": "somedomain.com",
        "malicious": false,
        "contact": "someone@somedomain.com",
        "timestamp": "2016-04-20 12:00:00"
    }

A simple, short, sweet json document. To turn that document into a Threatshell
elasticsearch document you would create a class that looks like the following

`threatshell.doctypes.example`

.. code-block:: python
   :linenos:

    #
    # GenericDoc is a base class I created to help with managing serialization,
    # Additional Threatshell fields, and other stuff coming in the future.
    # All Threatshell elasticsearch doctypes should extend this class.
    #
    # There are also some analyzers, filters, etc. in this module which you
    # may find helpful but the other really key thing to include is the
    # ThreatshellIndex decorator. You'll see why shortly.
    #
    from threatshell.doctypes.generic import (
        GenericDoc,
        email_analyzer,
        ThreatshellIndex
    )
    from elasticsearch_dsl import (
        String,
        Boolean
    )

    #
    # Here's that magical decorator. It's important because of how the
    # elasticsearch_dsl module works. When Threatshell starts, all of the
    # document decorators are collected and their respective mappings and
    # settings are sent to whatever elasticsearch servers are in your config
    #
    # In short, no decorator == no ES mapping. This doesn't guarantee a failure,
    # oh no, it's much more sneaky than that. You'll get partial docs generated
    # by the dynamic mapping and fields could end up being improperly configured
    # or behave unexpectedly when searching and whatnot.
    #
    @ThreatshellIndex.doc_type
    class ExampleIntelDoc(GenericDoc):

        #
        # This is to set the name of this document type in
        # elasticsearch
        #
        # (e.g. http://localhost:9200/threatshell/example_intel_doc/{doc_id})
        #
        class Meta:
            doc_type = "example_intel_doc"

        # Notice that these are defined just like in the json. That's because
        # of how the elasticsearch_dsl DocType class works with how it manages
        # attributes.

        domain = String()
        malicious = Boolean()
        contact = String(analyzer=email_analyzer)
        timestamp = Date()

        def __init__(self, jdata={}):
            GenericDoc.__init__(self)
            for k, v in jdata.items():

                # elasticsearch_dsl non-sense
                if v is None:
                    v = {}

                setattr(self, k, v)

            # Notice how we directly bind the json doc to this
            # class instance with setattr. You can achieve the
            # same effect with self.<attr> = <value> or with
            # ExampleIntelDoc().<attr> = <value>


That's about all you need to get started with elasticsearch_dsl documents. It
can get a bit challenging to define some of these docs. The better you define
them though, the better ES can do at indexing and searching, which means you can get
better correlation tips and stuff when the web interface side of Threatshell
gets built out more. So do try to do a good job, and, as always, feel free to
ask for help. You can also look at other doctypes I have made to see how more
complicated things were achieved. The `elasticsearch_dsl ReadTheDocs`_ is also a
good place for learning tricks to defining documents


That is almost all you need to know to get a Threatshell module working. All
that needs to be done now is to open up threatshell.py and add a few lines of
code use the command module. To do so, follow these easy steps:

    * open `threatshell.py` and add the import statement for your module

    .. code-block:: python

        from threatshell.commands.example import Example

    * add the instantiation of your module to the MyPrompt.__init__
        - Don't forget to pass it the config if you need it

    .. code-block:: python

        class MyPrompt(Cmd):

            def __init__(self, args):

                ...

                self.example_api = Example()

    * add a method that follows the name schema of "do_<command name>" which uses the function in your example module

    .. code-block:: python

        def do_exmpl_request_intel(self, cmd_args):
            """
            This is a doc string which becomes the help string
            for this function in the CLI. So now you can type
            "help exmpl_request_intel" and see this doc string
            when you are using the shell
            """

            # do argument parsing config

            split_args = shlex.split(cmd_args)
            args = parser.parse_args(args=split_args)
            docs = self.example_api.request_intel(args.domains)

            # Currently a function to handle output and ES document saving
            # but will be changed later to incorporate connectors to
            # other things and output formatting modules
            self._handle_response(docs)

.. _elasticsearch_dsl ReadTheDocs: https://elasticsearch-dsl.readthedocs.org/en/latest/
.. _Cmd class: https://docs.python.org/2/library/cmd.html
