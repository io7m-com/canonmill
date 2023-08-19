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

import java.nio.file.Path;
import java.security.cert.Certificate;
import java.time.OffsetDateTime;
import java.util.Objects;

/**
 * A keystore entry for a certificate.
 *
 * @param alias        The alias
 * @param file         The file
 * @param certificate  The certificate
 * @param creationTime The creation time
 */

public record CMKeyStoreEntryCertificate(
  String alias,
  Path file,
  Certificate certificate,
  OffsetDateTime creationTime)
  implements CMKeyStoreEntryType
{
  /**
   * A keystore entry for a certificate.
   *
   * @param alias        The alias
   * @param file         The file
   * @param certificate  The certificate
   * @param creationTime The creation time
   */

  public CMKeyStoreEntryCertificate
  {
    Objects.requireNonNull(alias, "alias");
    Objects.requireNonNull(file, "file");
    Objects.requireNonNull(certificate, "certificate");
    Objects.requireNonNull(creationTime, "creationTime");

    if (!file.isAbsolute()) {
      throw new IllegalArgumentException(
        "File '%s' must be an absolute path".formatted(file)
      );
    }
  }
}
