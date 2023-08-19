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

import com.io7m.canonmill.core.CMKeyStoreProvider;

import java.security.Provider;

/**
 * Directory-based Java keystore (Core)
 */

module com.io7m.canonmill.core
{
  requires static org.osgi.annotation.versioning;
  requires static org.osgi.annotation.bundle;

  requires com.io7m.anethum.api;
  requires com.io7m.blackthorne.core;
  requires com.io7m.blackthorne.jxe;
  requires com.io7m.jcip.annotations;
  requires com.io7m.jdeferthrow.core;
  requires com.io7m.jxe.core;
  requires org.bouncycastle.pkix;
  requires org.bouncycastle.provider;

  provides Provider with CMKeyStoreProvider;

  exports com.io7m.canonmill.core;

  exports com.io7m.canonmill.core.internal
    to com.io7m.canonmill.tests, java.base;
}
