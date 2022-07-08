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

package com.io7m.canonmill.core.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.module.SimpleDeserializers;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.io7m.dixmont.core.DmJsonRestrictedDeserializers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

import static com.fasterxml.jackson.databind.DeserializationFeature.USE_BIG_INTEGER_FOR_INTS;
import static com.fasterxml.jackson.databind.MapperFeature.SORT_PROPERTIES_ALPHABETICALLY;
import static com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS;

/**
 * Functions to deserialize/serialize messages.
 */

public final class CMKeyStoreDescriptions
{
  private final SimpleDeserializers serializers;
  private final JsonMapper mapper;

  /**
   * Functions to deserialize/serialize messages.
   */

  public CMKeyStoreDescriptions()
  {
    this.serializers =
      DmJsonRestrictedDeserializers.builder()
        .allowClass(CMKeyStoreDescription.class)
        .allowClass(Path.class)
        .allowClass(String.class)
        .allowClassName("java.util.Map<java.lang.String,java.nio.file.Path>")
        .build();

    this.mapper =
      JsonMapper.builder()
        .enable(USE_BIG_INTEGER_FOR_INTS)
        .enable(ORDER_MAP_ENTRIES_BY_KEYS)
        .enable(SORT_PROPERTIES_ALPHABETICALLY)
        .build();

    final var simpleModule = new SimpleModule();
    simpleModule.setDeserializers(this.serializers);
    this.mapper.registerModule(simpleModule);
  }

  /**
   * @return The underlying object mapper
   */

  public ObjectMapper mapper()
  {
    return this.mapper;
  }

  /**
   * Serialize a message.
   *
   * @param message The message
   *
   * @return A serialized message
   *
   * @throws IOException On I/O errors
   */

  public byte[] serialize(
    final CMKeyStoreDescription message)
    throws IOException
  {
    return this.mapper().writeValueAsBytes(message);
  }

  /**
   * Deserialize a message.
   *
   * @param message The message data
   *
   * @return A message
   *
   * @throws IOException On I/O errors
   */

  public CMKeyStoreDescription deserialize(
    final byte[] message)
    throws IOException
  {
    return this.mapper().readValue(message, CMKeyStoreDescription.class);
  }

  /**
   * Deserialize a message.
   *
   * @param stream The input stream
   *
   * @return A message
   *
   * @throws IOException On I/O errors
   */

  public CMKeyStoreDescription deserialize(
    final InputStream stream)
    throws IOException
  {
    return this.mapper().readValue(stream, CMKeyStoreDescription.class);
  }
}
