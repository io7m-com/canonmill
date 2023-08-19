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


package com.io7m.canonmill.core.internal.v1;

import com.io7m.blackthorne.core.BTElementHandlerConstructorType;
import com.io7m.blackthorne.core.BTElementHandlerType;
import com.io7m.blackthorne.core.BTElementParsingContextType;
import com.io7m.blackthorne.core.BTQualifiedName;
import com.io7m.blackthorne.core.Blackthorne;
import com.io7m.canonmill.core.CMKeyStoreSchemas;
import com.io7m.canonmill.core.internal.CMKeyStoreDescription;
import org.xml.sax.Attributes;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * A parser for v1 keystores.
 */

public final class CM1KeystoreParser
  implements BTElementHandlerType<Object, CMKeyStoreDescription>
{
  private final HashMap<String, Path> keys;
  private final HashMap<String, Path> certificates;
  private Path baseDirectory;

  /**
   * A parser for v1 keystores.
   *
   * @param context The parse context
   */

  public CM1KeystoreParser(
    final BTElementParsingContextType context)
  {
    this.keys =
      new HashMap<>();
    this.certificates =
      new HashMap<>();
  }

  @Override
  public void onElementStart(
    final BTElementParsingContextType context,
    final Attributes attributes)
  {
    this.baseDirectory =
      Paths.get(attributes.getValue("BaseDirectory"))
        .toAbsolutePath();
  }

  private record Key(
    String name,
    Path file)
  {

  }

  private record Certificate(
    String name,
    Path file)
  {

  }

  @Override
  public Map<BTQualifiedName, BTElementHandlerConstructorType<?, ?>>
  onChildHandlersRequested(
    final BTElementParsingContextType context)
  {
    return Map.ofEntries(
      Map.entry(
        element("Key"),
        Blackthorne.forScalarAttribute(
          element("Key"),
          (c, a) -> {
            return new Key(
              a.getValue("Name"),
              Paths.get(a.getValue("File"))
            );
          }
        )
      ),
      Map.entry(
        element("Certificate"),
        Blackthorne.forScalarAttribute(
          element("Certificate"),
          (c, a) -> {
            return new Certificate(
              a.getValue("Name"),
              Paths.get(a.getValue("File"))
            );
          }
        )
      )
    );
  }

  @Override
  public void onChildValueProduced(
    final BTElementParsingContextType context,
    final Object result)
  {
    if (result instanceof final Key key) {
      this.keys.put(key.name, key.file);
      return;
    }
    if (result instanceof final Certificate certificate) {
      this.certificates.put(certificate.name, certificate.file);
      return;
    }

    throw new IllegalStateException(
      "Unrecognized result: %s".formatted(result)
    );
  }

  @Override
  public CMKeyStoreDescription onElementFinished(
    final BTElementParsingContextType context)
  {
    return new CMKeyStoreDescription(
      this.baseDirectory,
      Map.copyOf(this.keys),
      Map.copyOf(this.certificates)
    );
  }

  /**
   * The element with the given name.
   *
   * @param localName The local name
   *
   * @return The qualified name
   */

  public static BTQualifiedName element(
    final String localName)
  {
    return BTQualifiedName.of(
      CMKeyStoreSchemas.schema1().namespace().toString(),
      localName
    );
  }
}
