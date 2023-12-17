/*
 * Copyright © 2023 Mark Raynsford <code@io7m.com> https://www.io7m.com
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

package com.io7m.canonmill.core.internal;

import com.io7m.jdeferthrow.core.ExceptionTracker;
import net.jcip.annotations.Immutable;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * <p>A POJO keystore instance.</p>
 *
 * <p>Instances are immutable and thread-safe.</p>
 */

@Immutable
public final class CMKeyStoreInstance
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CMKeyStoreInstance.class);

  private final Map<String, CMKeyStoreEntryKey> keyEntries;
  private final Map<String, CMKeyStoreEntryCertificate> certEntriesByAlias;
  private final Set<CMKeyStoreEntryCertificate> certificates;
  private final Map<String, CMKeyStoreEntryCertificate> certEntriesByCN;

  private CMKeyStoreInstance(
    final Map<String, CMKeyStoreEntryKey> inKeyEntries,
    final Map<String, CMKeyStoreEntryCertificate> inCertEntriesByAlias,
    final Map<String, CMKeyStoreEntryCertificate> inCertEntriesByCN,
    final Set<CMKeyStoreEntryCertificate> inCertificates)
  {
    this.keyEntries =
      Objects.requireNonNull(inKeyEntries, "keyEntries");
    this.certEntriesByAlias =
      Objects.requireNonNull(inCertEntriesByAlias, "certEntries");
    this.certEntriesByCN =
      Objects.requireNonNull(inCertEntriesByCN, "certEntries");
    this.certificates =
      Objects.requireNonNull(inCertificates, "certificates");

    for (final var c : inCertEntriesByAlias.values()) {
      if (!inCertificates.contains(c)) {
        throw new IllegalStateException("All certificate entries must exist.");
      }
    }
    for (final var c : inCertEntriesByCN.values()) {
      if (!inCertificates.contains(c)) {
        throw new IllegalStateException("All certificate entries must exist.");
      }
    }
  }

  /**
   * @return An empty instance
   */

  public static CMKeyStoreInstance empty()
  {
    return new CMKeyStoreInstance(
      Map.of(),
      Map.of(),
      Map.of(),
      Set.of()
    );
  }

  /**
   * Create an instance from a description.
   *
   * @param description The input description
   *
   * @return An instance
   *
   * @throws IOException On errors
   */

  public static CMKeyStoreInstance create(
    final CMKeyStoreDescription description)
    throws IOException
  {
    Objects.requireNonNull(description, "description");

    final var keyEntries =
      new HashMap<String, CMKeyStoreEntryKey>();
    final var certEntriesByAlias =
      new HashMap<String, CMKeyStoreEntryCertificate>();
    final var certEntriesByCN =
      new HashMap<String, CMKeyStoreEntryCertificate>();
    final var certEntries =
      new HashSet<CMKeyStoreEntryCertificate>();

    final var exceptions =
      new ExceptionTracker<IOException>();

    for (final var e : description.keys().entrySet()) {
      final var alias = e.getKey();
      final var keyFile = e.getValue();

      try {
        final var privateKey =
          loadPrivateKey(keyFile);
        final var fileDate =
          fileDate(keyFile);
        final var entry =
          new CMKeyStoreEntryKey(alias, keyFile, privateKey, fileDate);

        LOG.trace("Private Key [{}]: {}", alias, keyFile);
        keyEntries.put(alias, entry);
      } catch (final IOException ex) {
        exceptions.addException(ex);
      }
    }

    for (final var e : description.certificates().entrySet()) {
      final var alias = e.getKey();
      final var certFile = e.getValue();

      try {
        final var certificates =
          loadCertificates(certFile);

        {
          final var certificate =
            certificates.get(0);
          final var name =
            certificate.getSubjectX500Principal().getName();
          final var fileDate =
            fileDate(certFile);
          final var entry =
            new CMKeyStoreEntryCertificate(
              alias,
              certFile,
              certificate,
              fileDate
            );

          LOG.trace("Certificate [{}]: {} ({})", alias, name, certFile);
          certEntriesByAlias.put(alias, entry);
          certEntriesByCN.put(name, entry);
          certEntries.add(entry);
        }

        for (int index = 1; index < certificates.size(); ++index) {
          final var certificate =
            certificates.get(index);
          final var fileDate =
            fileDate(certFile);

          final var name =
            certificate.getSubjectX500Principal().getName();
          final var entry =
            new CMKeyStoreEntryCertificate(
              name,
              certFile,
              certificate,
              fileDate
            );

          LOG.trace("Certificate [{}]: ({})", name, certFile);
          certEntriesByCN.put(name, entry);
          certEntries.add(entry);
        }

      } catch (final IOException ex) {
        exceptions.addException(ex);
      } catch (final CertificateException ex) {
        exceptions.addException(new IOException(ex));
      }
    }

    exceptions.throwIfNecessary();
    return new CMKeyStoreInstance(
      Map.copyOf(keyEntries),
      Map.copyOf(certEntriesByAlias),
      Map.copyOf(certEntriesByCN),
      Set.copyOf(certEntries)
    );
  }

  private static OffsetDateTime fileDate(
    final Path file)
    throws IOException
  {
    final var attributes =
      Files.getFileAttributeView(file, BasicFileAttributeView.class);

    final var time =
      attributes.readAttributes()
        .creationTime()
        .toInstant();

    return OffsetDateTime.ofInstant(time, ZoneId.systemDefault());
  }

  private static List<X509Certificate> loadCertificates(
    final Path certFile)
    throws CertificateException, IOException
  {
    final var results = new LinkedList<X509Certificate>();
    try (var stream = Files.newInputStream(certFile)) {
      final var factory =
        CertificateFactory.getInstance("X.509");

      try (var reader = new PEMParser(new InputStreamReader(stream, UTF_8))) {
        while (true) {
          final var object = reader.readObject();
          if (object == null) {
            break;
          }

          if (object instanceof X509CertificateHolder) {
            final var certHolder = (X509CertificateHolder) object;
            results.add(
              (X509Certificate)
                factory.generateCertificate(
                  new ByteArrayInputStream(certHolder.getEncoded())
                )
            );
            continue;
          }

          throw new IOException(
            "Expected an X.509 certificate, received: %s".formatted(object)
          );
        }
      }
    }

    if (results.isEmpty()) {
      throw new IOException(
        "Could not load anything from file '%s'".formatted(certFile)
      );
    }

    return List.copyOf(results);
  }

  private static PrivateKey loadPrivateKey(
    final Path keyFile)
    throws IOException
  {
    final var converter =
      new JcaPEMKeyConverter();

    try (var stream = Files.newInputStream(keyFile)) {
      try (var reader = new PEMParser(new InputStreamReader(stream, UTF_8))) {
        final var object = reader.readObject();
        if (object == null) {
          throw new IOException(
            "Could not load anything from file '%s'".formatted(keyFile)
          );
        }

        if (object instanceof final PEMKeyPair pair) {
          final var keyPair = converter.getKeyPair(pair);
          return keyPair.getPrivate();
        }

        if (object instanceof final PrivateKeyInfo keyInfo) {
          return converter.getPrivateKey(keyInfo);
        }

        throw new IOException(
          "Expected a private key, received: %s".formatted(object)
        );
      }
    }
  }

  /**
   * @return A read-only view of the key entries
   */

  public Map<String, CMKeyStoreEntryKey> keyEntries()
  {
    return this.keyEntries;
  }

  /**
   * @return A read-only view of the certificate entries by alias
   */

  public Map<String, CMKeyStoreEntryCertificate> certEntriesByAlias()
  {
    return this.certEntriesByAlias;
  }

  /**
   * @return A read-only view of the certificate entries by common name
   */

  public Map<String, CMKeyStoreEntryCertificate> certEntriesByCN()
  {
    return this.certEntriesByCN;
  }
}
