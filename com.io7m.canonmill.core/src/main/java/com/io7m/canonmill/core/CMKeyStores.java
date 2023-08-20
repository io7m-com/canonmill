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


package com.io7m.canonmill.core;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;

/**
 * Convenience methods for keystores.
 */

public final class CMKeyStores
{
  private CMKeyStores()
  {

  }

  /**
   * Create a new keystore using the {@code canonmill} provider.
   *
   * @return A new keystore
   *
   * @throws KeyStoreException       On errors
   * @throws NoSuchProviderException If the {@code canonmill} provider is not loaded.
   */

  public static KeyStore createKeyStore()
    throws KeyStoreException, NoSuchProviderException
  {
    return KeyStore.getInstance(
      CMKeyStoreProvider.keystoreType(),
      CMKeyStoreProvider.providerName()
    );
  }

  /**
   * Create a new keystore using the {@code canonmill provider}.
   *
   * @param provider A specific provider instance
   *
   * @return A new keystore
   *
   * @throws KeyStoreException On errors
   */

  public static KeyStore createKeyStore(
    final CMKeyStoreProvider provider)
    throws KeyStoreException
  {
    Objects.requireNonNull(provider, "provider");

    return KeyStore.getInstance(
      CMKeyStoreProvider.keystoreType(),
      provider
    );
  }

  /**
   * Reload the given keystore from the given file.
   *
   * @param file     The file
   * @param keyStore The keystore
   *
   * @throws CertificateException     On certificate errors
   * @throws IOException              On I/O errors
   * @throws NoSuchAlgorithmException On unsupported algorithms
   */

  public static void reloadKeystoreFromFile(
    final KeyStore keyStore,
    final Path file)
    throws
    CertificateException,
    IOException,
    NoSuchAlgorithmException
  {
    Objects.requireNonNull(keyStore, "keyStore");
    Objects.requireNonNull(file, "file");

    try (var stream = Files.newInputStream(file)) {
      keyStore.load(stream, null);
    }
  }

  /**
   * Create an SSL context using the given keystore and truststore.
   *
   * @param keyStore   The keystore
   * @param trustStore The truststore
   * @param protocol   The protocol (such as "TLSv1.3")
   *
   * @return A new SSL context
   *
   * @throws NoSuchAlgorithmException  On missing algorithms
   * @throws KeyStoreException         On keystore exceptions
   * @throws UnrecoverableKeyException On unrecoverable keys
   * @throws KeyManagementException    On key management errors
   */

  public static SSLContext createSSLContext(
    final KeyStore keyStore,
    final KeyStore trustStore,
    final String protocol)
    throws
    NoSuchAlgorithmException,
    KeyStoreException,
    UnrecoverableKeyException,
    KeyManagementException
  {
    return createSSLContext(
      keyStore,
      trustStore,
      protocol,
      SecureRandom.getInstanceStrong()
    );
  }

  /**
   * Create an SSL context using the given keystore and truststore.
   *
   * @param keyStore   The keystore
   * @param trustStore The truststore
   * @param protocol   The protocol (such as "TLSv1.3")
   * @param random     A secure random instance
   *
   * @return A new SSL context
   *
   * @throws NoSuchAlgorithmException  On missing algorithms
   * @throws KeyStoreException         On keystore exceptions
   * @throws UnrecoverableKeyException On unrecoverable keys
   * @throws KeyManagementException    On key management errors
   */

  public static SSLContext createSSLContext(
    final KeyStore keyStore,
    final KeyStore trustStore,
    final String protocol,
    final SecureRandom random)
    throws
    NoSuchAlgorithmException,
    KeyStoreException,
    UnrecoverableKeyException,
    KeyManagementException
  {
    final var context = SSLContext.getInstance(protocol);
    reloadSSLContext(keyStore, trustStore, context, random);
    return context;
  }

  /**
   * Reload the given SSL context's key manager and trust manager. This,
   * effectively, reloads the keys and certificates in the context.
   *
   * @param keyStore   The keystore
   * @param trustStore The truststore
   * @param random     A secure random instance
   * @param context    The SSL context
   *
   * @throws NoSuchAlgorithmException  On missing algorithms
   * @throws KeyStoreException         On keystore exceptions
   * @throws UnrecoverableKeyException On unrecoverable keys
   * @throws KeyManagementException    On key management errors
   */

  public static void reloadSSLContext(
    final KeyStore keyStore,
    final KeyStore trustStore,
    final SSLContext context,
    final SecureRandom random)
    throws
    NoSuchAlgorithmException,
    UnrecoverableKeyException,
    KeyStoreException,
    KeyManagementException
  {
    final var keyManagerFactory =
      createKeyManagerFactory(keyStore);
    final var trustManagerFactory =
      createTrustManagerFactory(trustStore);

    context.init(
      keyManagerFactory.getKeyManagers(),
      trustManagerFactory.getTrustManagers(),
      random
    );
  }

  /**
   * Reload the given SSL context's key manager and trust manager. This,
   * effectively, reloads the keys and certificates in the context.
   *
   * @param keyStore   The keystore
   * @param trustStore The truststore
   * @param context    The SSL context
   *
   * @throws NoSuchAlgorithmException  On missing algorithms
   * @throws KeyStoreException         On keystore exceptions
   * @throws UnrecoverableKeyException On unrecoverable keys
   * @throws KeyManagementException    On key management errors
   */

  public static void reloadSSLContext(
    final KeyStore keyStore,
    final KeyStore trustStore,
    final SSLContext context)
    throws
    NoSuchAlgorithmException,
    UnrecoverableKeyException,
    KeyStoreException,
    KeyManagementException
  {
    reloadSSLContext(
      keyStore,
      trustStore,
      context,
      SecureRandom.getInstanceStrong());
  }

  private static TrustManagerFactory createTrustManagerFactory(
    final KeyStore trustStore)
    throws NoSuchAlgorithmException, KeyStoreException
  {
    final var trustManagerFactory =
      TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm()
      );

    trustManagerFactory.init(trustStore);
    return trustManagerFactory;
  }

  private static KeyManagerFactory createKeyManagerFactory(
    final KeyStore keyStore)
    throws
    NoSuchAlgorithmException,
    UnrecoverableKeyException,
    KeyStoreException
  {
    final var keyManagerFactory =
      KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

    keyManagerFactory.init(keyStore, null);
    return keyManagerFactory;
  }

  /**
   * Open a {@code canonmill} keystore from the given file.
   *
   * @param file     The file
   * @param provider The specific provider
   *
   * @return A keystore
   *
   * @throws NoSuchAlgorithmException On missing algorithms
   * @throws KeyStoreException        On keystore exceptions
   * @throws CertificateException     On certificate exceptions
   * @throws IOException              On I/O errors
   */

  public static KeyStore openKeyStore(
    final Path file,
    final CMKeyStoreProvider provider)
    throws
    KeyStoreException,
    CertificateException,
    IOException,
    NoSuchAlgorithmException
  {
    final var keystore = createKeyStore(provider);
    reloadKeystoreFromFile(keystore, file);
    return keystore;
  }

  /**
   * Open a {@code canonmill} keystore from the given file.
   *
   * @param file The file
   *
   * @return A keystore
   *
   * @throws NoSuchAlgorithmException On missing algorithms
   * @throws KeyStoreException        On keystore exceptions
   * @throws CertificateException     On certificate exceptions
   * @throws IOException              On I/O errors
   * @throws NoSuchProviderException  If the {@code canonmill} provider is not loaded
   */

  public static KeyStore openKeyStore(
    final Path file)
    throws
    KeyStoreException,
    CertificateException,
    IOException,
    NoSuchAlgorithmException,
    NoSuchProviderException
  {
    final var keystore = createKeyStore();
    reloadKeystoreFromFile(keystore, file);
    return keystore;
  }
}
