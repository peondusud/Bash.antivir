Bash.antivir
============

Project objectives
==================
The objective of the project is to write a "usefull" shell script.

The idea behing the project is both a challenge and a joke: write an antivirus using Bash and standard Unix commands such as grep, od, awk, sed, find...

The "antivirus" that will be programmed is a very limited and simple one, that will only scan fixed signatures in files.
The given test files will use signatures coming from the ClamAV signature base.
Project description
===================

Functionalities
===============

The script will scan files or directories given in the script options, to check if files contain one of the signatures given in a signature database.

The signature database will use ClamAV extended signature database format, which allows for speciﬁcation of additional informationsuch as a target ﬁle type, virus offset or engine version:

The format of each line is:

MalwareName:TargetType:Offset:HexSignature[:MinFL:[MaxFL]]

where:

    TargetType is one of the following numbers specifying the type of the target ﬁle
        0 = any ﬁle
        1 = Portable Executable, both 32- and 64-bit
        2 = ﬁle inside OLE2 container
        3 = HTML
        4 = Mail ﬁle
        5 = Graphics
        6 = ELF
        7 = ASCII text ﬁle (normalized)
        8 = Unused
        9 = Mach-O ﬁles
    Offset is an offset inside the target file (* means anywhere in the target file)
    HexSignature is the signature itself
    other arguments can be ignored

A complete description of ClamAV signature database format can be found here: 
http://www.clamav.net/doc/latest/signatures.pdf

In a first version, the TargetType can be safely ignored.

Langage
=======

The script must use exclusively the Bash shell scripting langage. Any other langage is forbiden, like a C helper.
Script structure

The use of bash functions is mandatory.

The script must at least accept the following options:

    -v (verbose): output messages describing script actions
    -r (recursive): recurse into directories
    -s DATABASE (signature): give signature database

Options parsing must use getopt.

Milestones
==========

It is highly recommended to build your script incrementaly, using for instance the following milestones:

    scan a file for a given signature
    read the database, extract signature and scan files for each signature
    scan directories recursively
    improve performance

Performance comparison
======================

Making a performance comparison with ClamAV will be a plus.

The performance is expected to be bad, but can be improved. It can be noted for instance that instead of launching an instance of 'grep' for each signature, several signatures can be merged into a single regular expression passed to a single instance of grep.

Testing your script
===================

Several test sets will be provided, each containing a signature database and a set of files, some of them being infected :

    the simplest one will contain only the EICAR test signature
    several sets of increasing sizes will be provided,
    with a database extracted from ClamAV signature database and a set of infected files
    
