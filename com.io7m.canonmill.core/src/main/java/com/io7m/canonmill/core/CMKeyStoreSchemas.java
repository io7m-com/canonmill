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

package com.io7m.canonmill.core;

import java.io.InputStream;

/**
 * Access to JSON schemas.
 */

public final class CMKeyStoreSchemas
{
  private static final String SCHEMA_VERSION_URI =
    "https://www.io7m.com/software/canonmill/keystore-1.schema.json";

  private CMKeyStoreSchemas()
  {

  }

  /**
   * @return The schema identifier for format version 1
   */

  public static String schemaIdentifierV1()
  {
    return SCHEMA_VERSION_URI;
  }

  /**
   * @return The schema for format version 1
   */

  public static InputStream schemaV1()
  {
    return CMKeyStoreSchemas.class.getResourceAsStream(
      "/com/io7m/canonmill/core/internal/keystore-1.schema.json"
    );
  }
}
