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

import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import com.io7m.canonmill.core.CMKeyStoreSchemas;
import com.io7m.canonmill.core.internal.CMKeyStoreDescription;
import com.io7m.canonmill.core.internal.CMKeyStoreDescriptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Map;

import static com.io7m.canonmill.tests.CMGenerateKeys.generateCertificate;
import static com.io7m.canonmill.tests.CMGenerateKeys.generateKeyPair;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public final class CMKeyStoreDescriptionTest
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
  public void testEmptyNotValid()
    throws Exception
  {
    final var stream =
      this.resource("empty-invalid.json");

    assertThrows(IOException.class, () -> {
      this.descriptions.deserialize(stream);
    });
  }

  @Test
  public void testBaseNotAbsolute()
    throws Exception
  {
    final var stream =
      this.resource("base-not-absolute.json");

    assertThrows(ValueInstantiationException.class, () -> {
      this.descriptions.deserialize(stream);
    });
  }

  @Test
  public void testBaseWrongSchema()
    throws Exception
  {
    final var stream =
      this.resource("base-wrong-schema.json");

    assertThrows(ValueInstantiationException.class, () -> {
      this.descriptions.deserialize(stream);
    });
  }

  @Test
  public void testEmpty()
    throws Exception
  {
    final var description =
      this.descriptions.deserialize(this.descriptions.serialize(
        new CMKeyStoreDescription(
          CMKeyStoreSchemas.schemaIdentifierV1(),
          this.directory,
          Map.of(),
          Map.of()
        )
      ));

    assertEquals(Map.of(), description.keys());
    assertEquals(Map.of(), description.certificates());

    this.roundTrip(description);
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

    assertEquals(
      Map.ofEntries(
        Map.entry("k0", kp0.secretKeyFile()),
        Map.entry("k1", kp1.secretKeyFile())
      ),
      description.keys()
    );
    assertEquals(
      Map.ofEntries(
        Map.entry("c0", c0.certificateFile()),
        Map.entry("c1", c1.certificateFile()),
        Map.entry("c2", c2.certificateFile())
      ),
      description.certificates()
    );

    this.roundTrip(description);
  }

  private void roundTrip(
    final CMKeyStoreDescription description)
    throws IOException
  {
    final var result =
      this.descriptions.deserialize(
        this.descriptions.serialize(description)
      );

    assertEquals(description, result);
  }

  private InputStream resource(
    final String name)
    throws IOException
  {
    return CMTestDirectories.resourceStreamOf(
      CMKeyStoreDescriptionTest.class,
      this.directory,
      name
    );
  }
}
