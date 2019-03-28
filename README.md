# oath++

This is a complete C++ wrapper for the C-language [oath-toolkit][1] [liboath library][2]
providing generation and validation for TOTP and HOTP one-time-passwords or OTPs.

These tokens are mobile two-factor authentication mechanisms that do not require any
communication between the personal security device and the server. Their standards are
some years old now.

General documentation may be found at the above link, and specific documntation within
[oath++.hpp](oath++.hpp).  Only one or two functions are needed to use the library for
authentication, either hotpGenerate and hotpValidate, or totpGenerate and totpValidate.

Installation:

    $ git clone https://github.com/xloem/oathpp.git oath++
    $ cd oath++
    $ mkdir build
    $ cd build
    $ cmake .. # requires liboath-devel
    $ make
    $ make test # optional, requires datefudge
    $ sudo make install

[1]: https://www.nongnu.org/oath-toolkit
[2]: https://www.nongnu.org/oath-toolkit/liboath-api/liboath-oath.html

