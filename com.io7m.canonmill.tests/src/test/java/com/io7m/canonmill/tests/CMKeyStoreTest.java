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

import com.io7m.canonmill.core.CMKeyStoreProvider;
import com.io7m.canonmill.core.CMKeyStoreSchemas;
import com.io7m.canonmill.core.internal.CMKeyStoreDescription;
import com.io7m.canonmill.core.internal.CMKeyStoreDescriptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import static com.io7m.canonmill.core.CMKeyStoreProvider.providerName;
import static com.io7m.canonmill.tests.CMGenerateKeys.generateCertificate;
import static com.io7m.canonmill.tests.CMGenerateKeys.generateKeyPair;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CMKeyStoreTest
{
  private CMKeyStoreDescriptions descriptions;
  private Path directory;

  @BeforeEach
  public void setup()
    throws IOException
  {
    this.directory =
      CMTestDirectories.createTempDirectory();
    this.descriptions =
      new CMKeyStoreDescriptions();
  }

  @AfterEach
  public void tearDown()
  {

  }

  @Test
  public void testEmpty()
    throws Exception
  {
    final var description =
      new CMKeyStoreDescription(
        CMKeyStoreSchemas.schemaIdentifierV1(),
        this.directory,
        Map.of(),
        Map.of()
      );

    final var file = this.directory.resolve("keystore.cmks");
    Files.write(file, this.descriptions.serialize(description));

    final var ks =
      KeyStore.getInstance(providerName(), new CMKeyStoreProvider());

    try (var stream = Files.newInputStream(file)) {
      ks.load(stream, new char[0]);
    }

    assertEquals(0, ks.size());
  }

  @Test
  public void testBasic()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);
    final var kp1 =
      generateKeyPair("k1", this.directory);
    final var c0 =
      generateCertificate(kp0.keyPair(), this.directory, "c0");
    final var c1 =
      generateCertificate(kp0.keyPair(), this.directory, "c1");
    final var c2 =
      generateCertificate(kp1.keyPair(), this.directory, "c2");

    final var description =
      new CMKeyStoreDescription(
        CMKeyStoreSchemas.schemaIdentifierV1(),
        this.directory.toAbsolutePath(),
        Map.ofEntries(
          Map.entry("k0", kp0.secretKeyFile().getFileName()),
          Map.entry("k1", kp1.secretKeyFile().getFileName())
        ),
        Map.ofEntries(
          Map.entry("c0", c0.certificateFile().getFileName()),
          Map.entry("c1", c1.certificateFile().getFileName()),
          Map.entry("c2", c2.certificateFile().getFileName())
        )
      );

    final var file = this.directory.resolve("keystore.cmks");
    Files.write(file, this.descriptions.serialize(description));

    final var ks =
      KeyStore.getInstance(providerName(), new CMKeyStoreProvider());

    try (var stream = Files.newInputStream(file)) {
      ks.load(stream, new char[0]);
    }

    assertEquals(kp0.keyPair().getPrivate(), ks.getKey("k0", new char[0]));
    assertEquals(kp1.keyPair().getPrivate(), ks.getKey("k1", new char[0]));
    assertEquals(c0.certificate(), ks.getCertificate("c0"));
    assertEquals(c1.certificate(), ks.getCertificate("c1"));
    assertEquals(c2.certificate(), ks.getCertificate("c2"));

    assertEquals(null, ks.getKey("nonexistent", new char[0]));
    assertEquals(null, ks.getCertificate("nonexistent"));
    assertEquals(null, ks.getCertificateChain("nonexistent"));

    assertThrows(UnsupportedOperationException.class, () -> {
      ks.setCertificateEntry("x", c0.certificate());
    });
    assertThrows(UnsupportedOperationException.class, () -> {
      ks.setKeyEntry("x", new byte[0], new Certificate[]{c0.certificate()});
    });
    assertThrows(UnsupportedOperationException.class, () -> {
      ks.setKeyEntry(
        "x",
        kp0.keyPair().getPrivate(),
        new char[0],
        new Certificate[]{c0.certificate()}
      );
    });
    assertThrows(UnsupportedOperationException.class, () -> {
      ks.deleteEntry("x");
    });

    for (final var e : List.of("k0", "k1", "c0", "c1", "c2")) {
      assertTrue(ks.containsAlias(e));
    }
    for (final var e : List.of("k0", "k1")) {
      assertTrue(ks.isKeyEntry(e));
    }
    for (final var e : List.of("c0", "c1", "c2")) {
      assertTrue(ks.isCertificateEntry(e));
    }

    assertEquals("c0", ks.getCertificateAlias(c0.certificate()));
    assertEquals("c1", ks.getCertificateAlias(c1.certificate()));
    assertEquals("c2", ks.getCertificateAlias(c2.certificate()));

    assertArrayEquals(
      new Certificate[]{c0.certificate()},
      ks.getCertificateChain("c0")
    );
    assertArrayEquals(
      new Certificate[]{c1.certificate()},
      ks.getCertificateChain("c1")
    );
    assertArrayEquals(
      new Certificate[]{c2.certificate()},
      ks.getCertificateChain("c2")
    );

    assertEquals(
      Set.of("k0", "k1", "c0", "c1", "c2"),
      enumerationToSet(ks.aliases())
    );

    assertEquals(
      fileTime(kp0.secretKeyFile()),
      ks.getCreationDate("k0")
    );
    assertEquals(
      fileTime(kp1.secretKeyFile()),
      ks.getCreationDate("k1")
    );
    assertEquals(
      fileTime(c0.certificateFile()),
      ks.getCreationDate("c0")
    );
    assertEquals(
      fileTime(c1.certificateFile()),
      ks.getCreationDate("c1")
    );
    assertEquals(
      fileTime(c2.certificateFile()),
      ks.getCreationDate("c2")
    );
    assertEquals(
      null,
      ks.getCreationDate("x")
    );
  }

  private static Date fileTime(
    final Path file)
    throws IOException
  {
    final var attr =
      Files.readAttributes(file, BasicFileAttributes.class);
    return Date.from(attr.creationTime().toInstant());
  }

  private static <T> Set<T> enumerationToSet(
    final Enumeration<T> enumeration)
  {
    final var spliterator =
      Spliterators.spliteratorUnknownSize(
        enumeration.asIterator(),
        0
      );

    return StreamSupport.stream(spliterator, false)
      .collect(Collectors.toSet());
  }
}
