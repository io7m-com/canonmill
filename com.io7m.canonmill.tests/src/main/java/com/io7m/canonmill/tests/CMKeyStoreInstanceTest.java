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

package com.io7m.canonmill.tests;

import com.io7m.canonmill.core.internal.CMKeyStoreDescription;
import com.io7m.canonmill.core.internal.CMKeyStoreDescriptionParsers;
import com.io7m.canonmill.core.internal.CMKeyStoreInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Map;

import static com.io7m.canonmill.tests.CMGenerateKeys.generateCertificate;
import static com.io7m.canonmill.tests.CMGenerateKeys.generateKeyPair;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public final class CMKeyStoreInstanceTest
{
  private CMKeyStoreDescriptionParsers descriptions;
  private Path directory;

  @BeforeEach
  public void setup()
    throws IOException
  {
    this.directory =
      CMTestDirectories.createTempDirectory();
  }

  @AfterEach
  public void tearDown()
  {

  }

  @Test
  public void testEmptyNotValid()
    throws Exception
  {
    final var i = CMKeyStoreInstance.empty();
    assertEquals(Map.of(), i.keyEntries());
    assertEquals(Map.of(), i.certEntries());
  }

  @Test
  public void testDescriptionOK()
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

    final var i = CMKeyStoreInstance.create(
      new CMKeyStoreDescription(
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
      )
    );

    assertEquals(2, i.keyEntries().size());
    assertEquals(3, i.certEntries().size());
  }

  @Test
  public void testDescriptionNotCertificate()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);

    final var ex =
      assertThrows(IOException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("k0", kp0.secretKeyFile().getFileName())
            ),
            Map.ofEntries(
              Map.entry("c0", kp0.secretKeyFile().getFileName())
            )
          )
        );
      });

    assertTrue(ex.getMessage().startsWith("Expected an X.509 certificate"));
  }

  @Test
  public void testDescriptionNotPrivateKey()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);
    final var c0 =
      generateCertificate(kp0.keyPair(), this.directory, "c0");

    final var ex =
      assertThrows(IOException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("c0", c0.certificateFile().getFileName())
            ),
            Map.ofEntries(
              Map.entry("c0", c0.certificateFile().getFileName())
            )
          )
        );
      });

    assertTrue(ex.getMessage().startsWith("Expected a private key"));
  }

  @Test
  public void testDescriptionNonexistentCert()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);

    final var ex =
      assertThrows(NoSuchFileException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("k0", kp0.secretKeyFile().getFileName())
            ),
            Map.ofEntries(
              Map.entry("c0", this.directory.resolve("nonexistent"))
            )
          )
        );
      });
  }

  @Test
  public void testDescriptionNonexistentKey()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);
    final var c0 =
      generateCertificate(kp0.keyPair(), this.directory, "c0");

    final var ex =
      assertThrows(NoSuchFileException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("k0", this.directory.resolve("nonexistent"))
            ),
            Map.ofEntries(
              Map.entry("c0", c0.certificateFile())
            )
          )
        );
      });
  }

  @Test
  public void testDescriptionGarbageCert()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);
    final var garbage =
      this.directory.resolve("garbage");

    final var bytes = new byte[1024];
    final var rng = SecureRandom.getInstanceStrong();
    rng.nextBytes(bytes);
    Files.write(garbage, bytes);

    final var ex =
      assertThrows(IOException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("k0", kp0.secretKeyFile().getFileName())
            ),
            Map.ofEntries(
              Map.entry("c0", garbage)
            )
          )
        );
      });
  }

  @Test
  public void testDescriptionGarbageKey()
    throws Exception
  {
    final var kp0 =
      generateKeyPair("k0", this.directory);
    final var c0 =
      generateCertificate(kp0.keyPair(), this.directory, "c0");

    final var garbage =
      this.directory.resolve("garbage");

    final var bytes = new byte[1024];
    final var rng = SecureRandom.getInstanceStrong();
    rng.nextBytes(bytes);
    Files.write(garbage, bytes);

    final var ex =
      assertThrows(IOException.class, () -> {
        CMKeyStoreInstance.create(
          new CMKeyStoreDescription(
            this.directory.toAbsolutePath(),
            Map.ofEntries(
              Map.entry("k0", garbage)
            ),
            Map.ofEntries(
              Map.entry("c0", c0.certificateFile())
            )
          )
        );
      });
  }
}
