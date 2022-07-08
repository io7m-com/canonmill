/*
 * Copyright © 2022 Mark Raynsford <code@io7m.com> https://www.io7m.com
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
 * IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


package com.io7m.canonmill.tests;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

public final class CMGenerateKeys
{
  private CMGenerateKeys()
  {

  }

  public record SerializedKeyPair(
    KeyPair keyPair,
    Path publicKeyFile,
    Path secretKeyFile)
  {

  }

  public static SerializedKeyPair generateKeyPair(
    final String name,
    final Path directory)
    throws Exception
  {
    final var generator =
      KeyPairGenerator.getInstance("RSA");

    final var keyPair =
      generator.generateKeyPair();

    final var options = new OpenOption[]{CREATE, TRUNCATE_EXISTING, WRITE};
    final var publicKeyFile = directory.resolve(name + ".pub");
    try (var writer =
           Files.newBufferedWriter(publicKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPublic());
        pemWriter.flush();
      }
    }

    final var secretKeyFile = directory.resolve(name + ".sec");
    try (var writer =
           Files.newBufferedWriter(secretKeyFile, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.flush();
      }
    }

    return new SerializedKeyPair(
      keyPair,
      publicKeyFile,
      secretKeyFile
    );
  }

  public record SerializedCertificate(
    X509Certificate certificate,
    Path certificateFile)
  {

  }

  public static SerializedCertificate generateCertificate(
    final KeyPair keyPair,
    final Path directory,
    final String name)
    throws Exception
  {
    final var cert =
      generate(keyPair, "SHA256withRSA", name, 3650);

    final var options = new OpenOption[]{CREATE, TRUNCATE_EXISTING, WRITE};
    final var file = directory.resolve(name + ".pem");
    try (var writer =
           Files.newBufferedWriter(file, options)) {
      try (var pemWriter = new JcaPEMWriter(writer)) {
        pemWriter.writeObject(cert);
        pemWriter.flush();
      }
    }

    return new SerializedCertificate(cert, file);
  }

  private static X509Certificate generate(
    final KeyPair keyPair,
    final String hashAlgorithm,
    final String cn,
    final int days)
    throws OperatorCreationException, CertificateException, CertIOException
  {
    final var now =
      Instant.now();
    final var notBefore =
      Date.from(now);
    final var notAfter =
      Date.from(now.plus(Duration.ofDays(days)));
    final var contentSigner =
      new JcaContentSignerBuilder(hashAlgorithm)
        .build(keyPair.getPrivate());

    final var x500Name =
      new X500Name("CN=" + cn);
    final var certificateBuilder =
      new JcaX509v3CertificateBuilder(
        x500Name,
        BigInteger.valueOf(now.toEpochMilli()),
        notBefore,
        notAfter,
        x500Name,
        keyPair.getPublic())
        .addExtension(
          Extension.subjectKeyIdentifier,
          false,
          createSubjectKeyId(keyPair.getPublic()))
        .addExtension(
          Extension.authorityKeyIdentifier,
          false,
          createAuthorityKeyId(keyPair.getPublic()))
        .addExtension(
          Extension.basicConstraints,
          true,
          new BasicConstraints(true));

    return new JcaX509CertificateConverter()
      .getCertificate(certificateBuilder.build(contentSigner));
  }

  private static SubjectKeyIdentifier createSubjectKeyId(
    final PublicKey publicKey)
    throws OperatorCreationException
  {
    final var publicKeyInfo =
      SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    final var digCalc =
      new BcDigestCalculatorProvider()
        .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    return new X509ExtensionUtils(digCalc)
      .createSubjectKeyIdentifier(publicKeyInfo);
  }

  private static AuthorityKeyIdentifier createAuthorityKeyId(
    final PublicKey publicKey)
    throws OperatorCreationException
  {
    final var publicKeyInfo =
      SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
    final var digCalc =
      new BcDigestCalculatorProvider()
        .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

    return new X509ExtensionUtils(digCalc)
      .createAuthorityKeyIdentifier(publicKeyInfo);
  }
}
