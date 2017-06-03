.. title: JAR signature block file format
.. slug: jar-signature-block-file-format
.. date: 2014-12-08 14:18:00
.. tags: jar,openssl,jarsigner,pkcs#7
.. description: 

**Summary:** this post explains the content of the **JAR signature block file** - 
that is, the file `META-INF/*.RSA`, `META-INF/*.DSA`, `META-INF/*.EC`
or `SIG-*` inside the JAR.

## Oracle does not document it

**Signed JAR file** contains the following additions over a non-signed JAR:

1. Checksums over the JAR content, stored in text files
  `META-INF/MANIFEST.MF` and `META-INF/*.SF`
2. The actual cryptographic signature (created with the private key
  of the signer) over the checksums in a binary **signature block file**.

Surprisingly, format of the latter does not seem to be documented by Oracle. [JAR file specification](http://docs.oracle.com/javase/7/docs/technotes/guides/jar/jar.html#Digital_Signatures)
provides only a useful knowledge that
*"These are binary files not intended to be interpreted by humans"*.

Here, the content of this "signature block file" is explained.
We show how it can be created and verified with non-Java tool: OpenSSL.

## Create a sample signature block file

For our investigation, generate such file by signing some data with **jarsigner**:

* Make an RSA private key (and store it unencrypted), corresponding
  self-signed certificate, pack them in a format jarsigner understands:
```shell
openssl genrsa -out key.pem
openssl req -x509 -new -key key.pem -out cert.pem -subj '/CN=foo'
openssl pkcs12 -export -in cert.pem -inkey key.pem -out keystore.pfx -passout pass:123456 -name SEC_PAD
```

* Create the data, jar it, sign the JAR, and unpack the "META-INF" directory:

```shell
echo 'Hello, world!' > data
jar cf data.jar data
jarsigner -keystore keystore.pfx -storetype PKCS12 -storepass 123456 data.jar SEC_PAD
unzip data.jar META-INF/*
```

The "signature block file" is `META-INF/SEC_PAD.RSA`.

## What does this block contain

The file appears to be a [DER-encoded](http://www.herongyang.com/Cryptography/Certificate-Format-DER-Distinguished-Encoding-Rules.html)
[ASN.1](https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One)
[PKCS#7](https://tools.ietf.org/html/rfc2315) data structure.
DER-encoded ASN.1 file can be examined with `asn1parse` subcommand of the OpenSSL:

```shell
openssl asn1parse -in META-INF/SEC_PAD.RSA -inform der -i > jarsigner.txt
```

For more verbosity, you may use some ASN.1 decoder such as one at
[lapo.it](http://lapo.it/asn1js/).

You'll see that the two top-level components are:

* The certificate.
* 256-byte RSA signature.

You can extract the signature bytes from the binary data and
[verify](http://qistoph.blogspot.com/2012/01/manual-verify-pkcs7-signed-data-with.html) (=decrypt with the public key) them with `openssl rsautl`.
That includes some "low-level" operations and brings you one more step down 
to understanding the file's content.
A simple "high-level" verification command, not involving manual byte
manipulation, would be:

```shell
openssl cms -verify -noverify -content META-INF/SEC_PAD.SF -in META-INF/SEC_PAD.RSA -inform der
```

This command tells: *"Check that the CMS structure in `META-INF/SEC_PAD.RSA`
is really a signature of `META-INF/SEC_PAD.SF`; do not attempt to validate
the certificate"*. Congratulations, we have verified the JAR signature
without Java tools.

## Creating the signature block file with OpenSSL

For this example, we created the signature block file with **jarsigner**. 
There are at least two OpenSSL commands which can produce similar 
structures: `openssl cms` and `openssl smime`, with the options given below:

```shell
openssl cms -sign -binary -noattr -in META-INF/SEC_PAD.SF -outform der -out openssl-cms.der -signer cert.pem -inkey key.pem -md sha256
openssl smime -sign -noattr -in META-INF/SEC_PAD.SF -outform der -out openssl-smime.der -signer cert.pem -inkey key.pem -md sha256
```

Let's decode the created files and compare them to what has been produced
with `jarsigner`:

```shell
openssl asn1parse -inform der -in openssl-cms.der -i > openssl-cms.txt
openssl asn1parse -inform der -in openssl-smime.der -i > openssl-smime.txt
```

## Testing the "DIY signature"

Underlying ASN.1 structures are, in both **cms** and **smime** cases,
very close but not identical to those made by `jarsigner`. 
As the format of the signature block file is not specified,
we can only do tests to have some ground to say that "it works".
Just replace the original signature block file with our signature
created by OpenSSL:

```shell
cp openssl-cms.der META-INF/SEC_PAD.RSA
zip -u data.jar META-INF/SEC_PAD.RSA
jarsigner -verify -keystore keystore.pfx -storetype PKCS12 -storepass 123456 data.jar SEC_PAD
```

Lucky strike: a signature produced by `openssl cms` is recognized by
`jarsigner` (that is, at least "it worked for me").

Note that the **data** which is signed is `SEC_PAD.SF`, and it was 
itself created by jarsigner. If not using the latter, you'll need to
produce that file in some way.

## What's the use for this knowledge?

Besides better understanding your data, one can think of at least two
reasons to sign JARs with non-native tools. Both are somewhat untypical,
but not completely irrelevant:

1. The signature must be produced in a system, where native Java tools are not available. 
Such system must have access to private key, and security administrators
may like the idea of not having such overbloated software as JRE in a
tightly controlled environment.

2. The signature must be produced or verified in a system, where available tools do not support the required signature algorithm.
Examples "why" include compliance with regulations or compatibility with
legacy systems. There are systems where [testing which elliptic curves are supported by jarsigner](http://securitypad.blogspot.fi/2014/12/support-for-elliptic-curves-by-jarsigner.html)
reveals just three curves (which is not much).


## Summary (again)

* **JAR signature block file** is a DER-encoded PKCS#7 structure.
* Its exact content can be viewed with any ASN.1 decoder, e.g. with `openssl asn1parse`.
* OpenSSL can verify signatures in signature block files and create almost
  identical structures, which have been reported to be accepted by Java
  tools.

