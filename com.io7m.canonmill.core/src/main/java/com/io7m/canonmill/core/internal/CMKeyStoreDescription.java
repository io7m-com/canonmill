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
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A description of a keystore.
 *
 * @param baseDirectory The base directory against which keys and certificates
 *                      are resolved
 * @param keys          The keys
 * @param certificates  The certificates
 */

public record CMKeyStoreDescription(
  Path baseDirectory,
  Map<String, Path> keys,
  Map<String, Path> certificates)
{
  /**
   * A description of a keystore.
   *
   * @param baseDirectory The base directory against which keys and certificates
   *                      are resolved
   * @param keys          The keys
   * @param certificates  The certificates
   */

  public CMKeyStoreDescription
  {
    Objects.requireNonNull(baseDirectory, "baseDirectory");

    if (!baseDirectory.isAbsolute()) {
      throw new IllegalArgumentException(
        "Base directory '%s' must be an absolute path"
          .formatted(baseDirectory)
      );
    }

    keys =
      Objects.requireNonNull(keys, "keys")
        .entrySet()
        .stream()
        .map(e -> resolveMapEntry(baseDirectory, e))
        .collect(Collectors.toUnmodifiableMap(
          Map.Entry::getKey,
          Map.Entry::getValue)
        );

    certificates =
      Objects.requireNonNull(certificates, "certificates")
        .entrySet()
        .stream()
        .map(e -> resolveMapEntry(baseDirectory, e))
        .collect(Collectors.toUnmodifiableMap(
          Map.Entry::getKey,
          Map.Entry::getValue)
        );
  }

  private static Map.Entry<String, Path> resolveMapEntry(
    final Path baseDirectory,
    final Map.Entry<String, Path> e)
  {
    return Map.entry(
      e.getKey(),
      baseDirectory.resolve(e.getValue()).toAbsolutePath()
    );
  }
}
