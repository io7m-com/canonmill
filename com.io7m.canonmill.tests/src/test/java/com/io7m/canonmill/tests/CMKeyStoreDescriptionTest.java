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
    final var stream =
      this.resource("empty.json");
    final var description =
      this.descriptions.deserialize(stream);

    assertEquals(Map.of(), description.keys());
    assertEquals(Map.of(), description.certificates());

    this.roundTrip(description);
  }

  @Test
  public void testBasic()
    throws Exception
  {
    final var stream =
      this.resource("basic.json");
    final var description =
      this.descriptions.deserialize(stream);

    final var root =
      FileSystems.getDefault()
        .getRootDirectories()
        .iterator()
        .next();

    final var nonexistent =
      root.resolve("nonexistent");


    assertEquals(
      Map.ofEntries(
        Map.entry("www", nonexistent.resolve("www.sec")),
        Map.entry("mail", nonexistent.resolve("mail.sec"))
      ),
      description.keys()
    );
    assertEquals(
      Map.ofEntries(
        Map.entry("www", nonexistent.resolve("www.crt")),
        Map.entry("mail", nonexistent.resolve("mail.crt")),
        Map.entry("ftp", nonexistent.resolve("ftp.crt"))
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
