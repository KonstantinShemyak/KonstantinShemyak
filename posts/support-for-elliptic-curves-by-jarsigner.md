.. title: Support for elliptic curves by jarsigner
.. slug: support-for-elliptic-curves-by-jarsigner
.. date: 2014-12-21 21:45:00
.. tags: elliptic curves,openssl,jarsigner
.. description: 

**Summary:** Support for cryptography features by jarsigner depends on available Java crypto providers.

Suppose you are defining a PKI profile. You naturally want to use the
stronger algorithms with better performance, which (as of year 2014)
means elliptic curves. Besides bit strength and performance,
you want to be sure that the curve is supported by your software.
If the latter includes **jarsigner**, you'll be surprised to find that 
[Oracle documentation](http://docs.oracle.com/javase/7/docs/technotes/tools/windows/jarsigner.html)
seems to not mention at all, 
*which elliptic curves does jarsigner support*.

Signing a JAR means adding digests of the JAR entries to the *manifest file*
(`META-INF/*.MF),
adding digest of the latter to the *manifest signature file*
(`META-INF/*.EC`, in case `E`lliptic `C`urve is used),
and then creating the
[JAR signature block file](link://slug/jar-signature-block-file-format).
The last step involves two operations:

1. calculating a digest over the *manifest signature file*;
2. signing (i.e. encrypting with the private key) that digest.

Jarsigner has an option `-sigalg`,
which is supposed to specify the two algorithms used in these two steps.
(There is also `-digestalg`' option, but it is not used for the signature
block file; it defines the algorithm used in the two initial steps.)
Well, this option is irrelevant for our question: the curve is in fact
defined by the provided private key. So jarsigner will either do the job
or choke on the key which comes from an unsupported curve.

A curve may "not work" because it is unknown to jarsigner itself, or to
an underlying crypto provider. (The latter case was a reason to a
[bug 1006776](https://bugs.launchpad.net/ubuntu/+source/openjdk-6/+bug/1006776),
a setup where only three curves actually worked.) Attempt to sign the JAR 
with `jarsigner` using a non-supported private key would result in a
not very helpful error message:

```
certificate exception: java.io.IOException: subject key, Could not create EC public key
```

To be on the safe side, it's best to test. For curves, supported by OpenSSL,
the test can be done by creating the keypair on each curve and attempting
the signing:

* Create the list of curves with 
```
openssl ecparam -list_curves
```
* remove manually some extra words openssl puts there in the beginning
* and feed it to the stdin:

```shell
  #!/bin/bash
  # Test, which OpenSSL-supported elliptic curves from the list are supported also by jarsigner.
  result="supported- curves.txt"
  source_data="data.txt"
  jar="data.jar"
  key="key.pem"
  cert="cert.pem"
  pfx="keystore.pfx"
  key_alias="foo"         # Identificator of the key in the keystore
  storepass="123456"      # jarsigner requires some

  touch $source_data
  while read curve; do
    # Generate an ECDSA private key for the selected curve:
    openssl ecparam -name $curve -genkey -out $key
    # Generate the certificate for the key; give some dummy subject:
    openssl req -new -x509 -nodes -key $key -out $cert -subj /CN=foo
    # Wrap key+cert in a PKCS12, so that jarsigner can use it:
    openssl pkcs12 -export -in $cert -inkey $key -passout pass:$storepass -out $pfx -name $key_alias
    # Create a fresh jar and attempt to sign it
    jar cf $jar $source_data
    jarsigner -keystore $pfx -storetype PKCS12 -storepass $storepass $jar $key_alias
    [ $? -eq 0 ] && echo $curve >> $result
  done
  rm $source_data $key $cert $pfx $jar
```

And enjoy the list in `supported-curves.txt`.

**Summary:** 

* support of elliptic curves by <b>jarsigner</b> depends on jarsigner itself and on the used JRE.
* There is no command-line option to list all supported curves.
* For a particular system, support for curves known by <b>OpenSSL</b> can be easily tested.
