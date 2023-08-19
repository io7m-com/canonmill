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

import com.io7m.canonmill.core.CMKeyStoreSchemas;
import com.io7m.canonmill.core.internal.CMKeyStoreDescription;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.OutputStream;
import java.util.TreeSet;

/**
 * A serializer for keystores (v1) data.
 */

public final class CM1Serializer
{
  private final XMLOutputFactory outputs;
  private final XMLStreamWriter output;
  private final String ns;

  /**
   * A serializer for keystores (v1) data.
   *
   * @param outputStream The output stream
   *
   * @throws XMLStreamException On errors
   */

  public CM1Serializer(
    final OutputStream outputStream)
    throws XMLStreamException
  {
    this.outputs =
      XMLOutputFactory.newFactory();
    this.output =
      this.outputs.createXMLStreamWriter(outputStream, "UTF-8");
    this.ns =
      CMKeyStoreSchemas.schema1().namespace().toString();
  }

  /**
   * Execute the serializer.
   *
   * @param ks The input keystore
   *
   * @throws XMLStreamException On errors
   */

  public void serialize(
    final CMKeyStoreDescription ks)
    throws XMLStreamException
  {
    this.output.writeStartDocument("UTF-8", "1.0");
    this.serializeKeystore(ks);
    this.output.writeEndDocument();
  }

  private void serializeKeystore(
    final CMKeyStoreDescription ks)
    throws XMLStreamException
  {
    this.output.writeStartElement("Keystore");
    this.output.writeDefaultNamespace(this.ns);

    this.output.writeAttribute(
      "BaseDirectory",
      ks.baseDirectory().toAbsolutePath().toString()
    );

    final var ksKeys =
      ks.keys();
    final var ksCerts =
      ks.certificates();

    final var names = new TreeSet<String>(ksKeys.keySet());
    names.addAll(ksCerts.keySet());

    for (final var name : names) {
      final var key = ksKeys.get(name);
      if (key != null) {
        this.output.writeStartElement("Key");
        this.output.writeAttribute("Name", name);
        this.output.writeAttribute("File", key.getFileName().toString());
        this.output.writeEndElement();
      }
      final var cert = ksCerts.get(name);
      if (cert != null) {
        this.output.writeStartElement("Certificate");
        this.output.writeAttribute("Name", name);
        this.output.writeAttribute("File", cert.getFileName().toString());
        this.output.writeEndElement();
      }
    }

    this.output.writeEndElement();
  }
}
