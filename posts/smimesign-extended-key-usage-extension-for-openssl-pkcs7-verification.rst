.. title: OpenSSL PKCS7 verification and certificate "Extended Key Usage" extension
.. slug: smimesign-extended-key-usage-extension-for-openssl-pkcs7-verification
.. date: 2016-12-31 22:34:22 UTC+02:00
.. tags: openssl, x.509, pkcs#7
.. category: 
.. link: 
.. description: 
.. type: text

Problem
=======

You verify a signature of ``PKCS#7`` structure with OpenSSL and get error

  unsupported certificate purpose


Background
==========

What means "to verify a signature"? Different things in different contexts.
An interpretation you may be expecting is:

1. The signature itself (e.g. RSA block) taken over the corresponding
   data (or its digest) validates against the **signing certificate**.
2. Two sets of certificates are available, which we'd call
   "**trusted certificates**" and "**chaining certificates**" 
   (how they are obtained is another question).
   A chain from the **signing certificate** up to at
   least one of the **trusted certificates** can be built with the
   **chaining certificates**.
3. Every certificate in this chain has "suitable" X.509v3 extensions.

The first requirement is clear.

The second one is clear when the sets are defined.
OpenSSL API does not solve the question how to define them for the
user, but requires them to be passed as parameters for the
verification.

The last requirement relies on X.509v3 extensions, which are 
`a terrible mess`_.

.. _a terrible mess: http://www.cypherpunks.to/~peter/T2a_X509_Certs.pdf

It's hard to provide a non-messy solution for a messy requirement.
Section ``CERTIFICATE EXTENSIONS`` in the OpenSSL manual for ``x509``
subcommand has passage:

    The actual checks done are rather complex and include various hacks and
    workarounds to handle broken certificates and software.

It looks like PKCS7 verification fell victim of these "hacks and workarounds".

OpenSSL certificate verification and X.509v3 extensions
=======================================================

Before getting to the topic (verifying PKCS#7 structures), look at
how **certificates** can be verified. Both command-line ``openssl verify``
and C API ``X509_verify_cert()`` have a notion of ``purpose``, explained
in the section ``CERTIFICATE EXTENSIONS`` of ``man x509``.
This notion seems to be particular to OpenSSL.
If ``purpose`` is not specified, then OpenSSL does not check the certificate
extensions at all. Otherwise, OpenSSL allows certain combinations
of the extensions for each ``purpose``.

The correspondence between
OpenSSL's "purposes" and X509v3 extensions is nothing like one-to-one.
For example, purpose ``S/MIME Signing`` (or in short variant ``smimesign``)
requires that:

1. "Common S/MIME Client Tests" pass (description of how they translate
   to X.509 extension takes a long paragraph in `man x509`).
2. Either ``KeyUsage`` extension is **not present**, or it is present and
   ``digigalSignature`` bit is set.

For another example, there seems to be no OpenSSL option for ``verify``
to require presense of Extended Key Usage bits like ``codeSigning``.
For that, C API allows to separately check every extension bit. 

So far, this sounds logical - at least about as logical as it could be
to somehow handle The Terrible Mess of X509v3 extensions.

OpenSSL PKCS#7 verification and X.509v3 extensions
==================================================

By reason unknown yet to the author, OpenSSL uses **different** strategy
when verifying PKCS#7.

There are two command-line utilities which can do that:
``openssl smime -verify`` and ``openssl cms -verify`` 
(S/MIME and CMS are PKCS#7).
Both accept ``-purpose`` option, which according to manual pages
has the same meaning as for certificate verification.
**But it does not.** These are the differences:

1. If no ``-purpose`` option is passed, both commands behave as though
   they received ``-purpose smimesign``.

2. It is possible to disable purpose checking by passing
   ``-purpose any``.


On the C API side, one is supposed to use ``PKCS7_verify()`` for PKCS#7
verification. This function also behaves as though it verifies with
``smimesign`` purpose. 
(see setting ``X509_PURPOSE_SMIME_SIGN`` in ``pk7_doit.c:919``).
This again means that verification fails unless your **signing certificate**
satisfies the two conditions referred to in the example above:

#. **If** the "Extended Key Usage" extension is present, **then** it
   must include "email protection" OID.
#. **If** the "Key Usage" extension is present, **then** it must include
   the "digitalSignature" bit.

Similarly as with the command-line, it is possible to disable checking
the extensions, although with more typing.
In C API, the verification "purpose" is a property of ``X509_STORE``,
passed to ``PKCS7_verify()``, which plays the role of the 
**trusted certificate set**. 
(Manipulation of the parameters directly
on the store was added only to OpenSSL 1.1.0 
with ``X509_STORE_get0_param(X509_STORE *store)``.
In earlier versions, an ``X509_STORE_CTX`` must have been created from
the store and parameters manipulates with ``X509_STORE_CTX_get0_param()``.
BTW support for OpenSSL v1.0.1 has ended just on the day of this writing.)

.. code:: C

  verify_params = X509_STORE_get0_param(trusted_store);
  X509_VERIFY_PARAM_set_purpose(verify_params, X509_PURPOSE_ANY);

 
Demo
====

Prepare the files
-----------------

Create a chain of certificates: self-signed "**root**",
then an "**intermediate**" signed by the root,
then a "**signing**" signed by the intermediate.

Write appropriate OpenSSL config files:


Create requests for all the three::

  $ openssl req -config openssl-CA.cnf -new -x509 -nodes -outform pem -out root.pem -keyout root-key.pem
  $ openssl req -config openssl-CA.cnf -new -nodes -out intermediate.csr -keyout intermediate-key.pem
  $ openssl req -config openssl-signing.cnf -new -nodes -outform pem -out signing.csr -keyout signing-key.pem

Sign the **intermediate** and the **signing** certificates::

  $ mkdir -p demoCA/newcerts
  $ touch demoCA/index.txt
  $ echo '01' > demoCA/serial
  $ openssl ca -config openssl-CA.cnf -in intermediate.csr -out intermediate.pem -keyfile root-key.pem -cert root.pem
  $ openssl ca -config openssl-signing.cnf -in signing.csr -out signing.pem -keyfile intermediate-key.pem -cert intermediate.pem

Create some PKCS7 structure, signed with the **signing** certificate. 
The **chain certificates** must be provided during the verification, or
embedded into the signature. Let's embed the intermediate certificate.
(If there had been more than one certificate in the chain, they would
need to be simply placed in one ``.pem`` file)::
 
  $ echo 'Hello, world!' > data.txt
  $ openssl smime -sign -in data.txt -inkey signing-crlsign-key.pem -signer signing-crlsign.pem -certfile intermediate.pem -nodetach > signed-crlsign.pkcs7

We have everything ready for verifying.

Verification with command-line OpenSSL tools
--------------------------------------------

Attempt to verify it::

  $ openssl smime -verify -CAfile root.pem -in signed-crlsign.pkcs7 -out /dev/null -signer signing-crlsign.pem 
  Verification failure
  139944505955992:error:21075075:PKCS7 routines:PKCS7_verify:certificate verify error:pk7_smime.c:336:Verify error:unsupported certificate purpose

Attempt to verify, skipping extension checks::

  $ openssl smime -verify -CAfile root.pem -in signed-crlsign.pkcs7 -out /dev/null -signer signing-crlsign.pem -purpose any
  Verification successful

Attempt to verify it, specifying the OpenSSL "purpose" which the signing certificate satisfies::

  $ openssl smime -verify -CAfile root.pem -in signed-crlsign.pkcs7 -out /dev/null -signer signing-crlsign.pem -purpose crlsign
  Verification successful

Verification with the C API
---------------------------

The code below is "demo", any real application would have at least to
check return codes of all system calls and free any allocated resources.
But you can see how the verification of PKCS#7 structure (unexpectedly)
fails, and succeeds after setting the "purpose" which the signing
certificate satisfies:

.. raw:: html

	<pre> 
	#include <stdlib.h>
	#include <stdio.h>
	#include <fcntl.h>              /* open() */

	#include <openssl/bio.h>
	#include <openssl/err.h>
	#include <openssl/ssl.h>
	#include <openssl/pkcs7.h>
	#include <openssl/safestack.h>
	#include <openssl/x509.h>
	#include <openssl/x509v3.h>     /* X509_PURPOSE_ANY */
	#include <openssl/x509_vfy.h>

	int main(int argc, char* argv[]) {
	  X509_STORE *trusted_store;
	  X509_STORE_CTX *ctx;
	  STACK_OF(X509) *cert_chain;
	  X509 *root, *intermediate, *signing;
	  BIO *in;
	  int purpose, ret;
	  X509_VERIFY_PARAM *verify_params;
	  PKCS7 *p7;
	  FILE *fp;
	  int fd;

	  SSL_library_init();
	  SSL_load_error_strings();

	  fd = open("signed-ext-no-smimesign.pkcs7", O_RDONLY);
	  in = BIO_new_fd(fd, BIO_NOCLOSE);
	  p7 = SMIME_read_PKCS7(in, NULL);

	  cert_chain = sk_X509_new_null();

	  fp = fopen("root.pem", "r");
	  root = PEM_read_X509(fp, NULL, NULL, NULL);
	  sk_X509_push(cert_chain, root);

	  fp = fopen("intermediate.pem", "r");
	  intermediate = PEM_read_X509(fp, NULL, NULL, NULL);
	  sk_X509_push(cert_chain, intermediate);

	  trusted_store = X509_STORE_new();
	  X509_STORE_add_cert(trusted_store, root);

	  fp = fopen("signing-ext-no-smimesign.pem", "r");
	  signing = PEM_read_X509(fp, NULL, NULL, NULL);

	  ret = PKCS7_verify(p7, cert_chain, trusted_store, NULL, NULL, 0);
	  printf("Verification without specifying params: %s\n", ret ? "OK" : "failure");

	  /* Now set a suitable OpenSSL's "purpose", or disable its checking.
	   * Note: since OpenSSL 1.1.0, we'd not need `ctx`, but could just use:
	   * verify_params = X509_STORE_get0_param(trusted_store); */

	  ctx = X509_STORE_CTX_new();
	  X509_STORE_CTX_init(ctx, trusted_store, signing, cert_chain);
	  verify_params = X509_STORE_CTX_get0_param(ctx);
	  purpose = X509_PURPOSE_get_by_sname("crlsign"); /* Or: purpose = X509_PURPOSE_ANY */
	  X509_VERIFY_PARAM_set_purpose(verify_params, purpose);
	  X509_STORE_set1_param(trusted_store, verify_params);

	  ret = PKCS7_verify(p7, cert_chain, trusted_store, NULL, NULL, 0);
	  printf("Verification with 'crlsign' purpose: %s\n", ret ? "OK" : "failure");
	  return 0;
	}
	</pre>

If our policy requires ``crlSign`` Key Usage, then we can
use this example code. What if the policy needs some extension
combination for which there is no suitable OpenSSL "purpose" - for example,
``CodeSigning`` Extended Key Usage? In that case it would not be possible
to do it with just one call to ``PKCS7_verify``, but the extensions
need to be checked separately.


Conclusion
==========

If you use OpenSSL for verifying PKCS#7 signatures, you should check
whether either the following holds:

1. Your signing certificate has ``Extended Key Usage`` extension,
   but no ``emailProtection`` bit.
2. Your signing certificate has ``KeyUsage`` extension, but no
   ``digitalSignature`` OID.

If this is the case, then verification with OpenSSL fails even if your
signature "should" verify correctly.

For checking signatures with command-line ``openssl smime -verify``,
a partial workaround can be adding option ``-purpose any``.
In this case OpenSSL will not check Extended Key Usage extensions at all.
This can be acceptable or not by your verification policy.

``-purpose`` option allows to check only for certain
(although probably common) x509v3 extension combinations.
OpenSSL defines a number of what it calls "purposes".
If you need to check a combination which does not correspond to any
of these "purposes", it must be done in a separate operation.

For checking signatures with C API ``PKCS7_verify()``, the algorithm
can be the following:

1. Check X509v3 extensions of the signing certificate as required by your policy
   (example_).
2. Either set your verification parameters to ``X509_PURPOSE_ANY``,
   or set a custom verification callback, which would ignore the
   "unsupported certificate purpose" error, i.e. 
   ``X509_V_ERR_INVALID_PURPOSE``.

.. _example: https://zakird.com/2013/10/13/certificate-parsing-with-openssl#other-x509-extensions

