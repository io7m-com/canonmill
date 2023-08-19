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

import com.io7m.anethum.api.ParsingException;
import com.io7m.anethum.api.SerializationException;
import com.io7m.canonmill.core.CMKeyStoreProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;

/**
 * The main keystore implementation.
 */

public final class CMKeyStore extends KeyStoreSpi
{
  private final CMKeyStoreDescriptionParsers parsers;
  private final CMKeyStoreDescriptionSerializers serializers;
  private volatile CMKeyStoreInstance store;
  private volatile CMKeyStoreDescription description;

  /**
   * The main keystore implementation.
   */

  public CMKeyStore()
  {
    this.parsers =
      new CMKeyStoreDescriptionParsers();
    this.serializers =
      new CMKeyStoreDescriptionSerializers();
    this.store =
      CMKeyStoreInstance.empty();
  }

  private static UnsupportedOperationException readOnly()
  {
    return new UnsupportedOperationException(
      "%s keystores are read-only.".formatted(CMKeyStoreProvider.providerName())
    );
  }

  @Override
  public Key engineGetKey(
    final String alias,
    final char[] password)
  {
    final var e = this.store.keyEntries().get(alias);
    if (e == null) {
      return null;
    }
    return e.privateKey();
  }

  @Override
  public Certificate[] engineGetCertificateChain(
    final String alias)
  {
    final var e = this.store.certEntries().get(alias);
    if (e == null) {
      return null;
    }
    return new Certificate[]{e.certificate()};
  }

  @Override
  public Certificate engineGetCertificate(
    final String alias)
  {
    final var e = this.store.certEntries().get(alias);
    if (e == null) {
      return null;
    }
    return e.certificate();
  }

  @Override
  public Date engineGetCreationDate(
    final String alias)
  {
    final var ek = this.store.keyEntries().get(alias);
    if (ek != null) {
      return Date.from(ek.creationTime().toInstant());
    }
    final var ec = this.store.certEntries().get(alias);
    if (ec != null) {
      return Date.from(ec.creationTime().toInstant());
    }
    return null;
  }

  @Override
  public void engineSetKeyEntry(
    final String alias,
    final Key key,
    final char[] password,
    final Certificate[] chain)
  {
    throw readOnly();
  }

  @Override
  public void engineSetKeyEntry(
    final String alias,
    final byte[] key,
    final Certificate[] chain)
  {
    throw readOnly();
  }

  @Override
  public void engineSetCertificateEntry(
    final String alias,
    final Certificate cert)
  {
    throw readOnly();
  }

  @Override
  public void engineDeleteEntry(
    final String alias)
  {
    throw readOnly();
  }

  @Override
  public Enumeration<String> engineAliases()
  {
    final var s = new HashSet<String>();
    s.addAll(this.store.keyEntries().keySet());
    s.addAll(this.store.certEntries().keySet());
    return Collections.enumeration(s);
  }

  @Override
  public boolean engineContainsAlias(
    final String alias)
  {
    return this.store.certEntries().containsKey(alias)
      || this.store.keyEntries().containsKey(alias);
  }

  @Override
  public int engineSize()
  {
    return this.store.certEntries().size() + this.store.keyEntries().size();
  }

  @Override
  public boolean engineIsKeyEntry(
    final String alias)
  {
    return this.store.keyEntries().containsKey(alias);
  }

  @Override
  public boolean engineIsCertificateEntry(
    final String alias)
  {
    return this.store.certEntries().containsKey(alias);
  }

  @Override
  public String engineGetCertificateAlias(
    final Certificate cert)
  {
    return this.store.certEntries()
      .values()
      .stream()
      .filter(p -> Objects.equals(p.certificate(), cert))
      .findFirst()
      .map(CMKeyStoreEntryCertificate::alias)
      .orElse(null);
  }

  @Override
  public void engineStore(
    final OutputStream stream,
    final char[] password)
    throws IOException
  {
    try {
      this.serializers.serialize(
        URI.create("urn:output"),
        stream,
        this.description
      );
    } catch (final SerializationException e) {
      throw new IOException(e.getMessage(), e);
    }
  }

  @Override
  public void engineLoad(
    final InputStream stream,
    final char[] password)
    throws IOException
  {
    try {
      this.description =
        this.parsers.parse(URI.create("urn:source"), stream);
    } catch (final ParsingException e) {
      throw new IOException(e.getMessage(), e);
    }
    this.store =
      CMKeyStoreInstance.create(this.description);
  }
}
