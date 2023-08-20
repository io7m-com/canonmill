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


package com.io7m.canonmill.tests;

import com.io7m.canonmill.core.CMKeyStoreProvider;
import com.io7m.canonmill.core.CMKeyStores;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertThrows;

public final class CMExpirationIntegrationTest
{
  private static final Logger LOG =
    LoggerFactory.getLogger(CMExpirationIntegrationTest.class);

  private static final BigInteger CA_CERTIFICATE_SERIAL =
    new BigInteger("1");
  private static final BigInteger SERVER_CERTIFICATE_SERIAL_FIRST =
    new BigInteger("2");
  private static final BigInteger SERVER_CERTIFICATE_SERIAL_SECOND =
    new BigInteger("3");
  private static final BigInteger CLIENT_CERTIFICATE_SERIAL =
    new BigInteger("100");

  private ExecutorService executor;
  private AtomicBoolean done;
  private SSLServerSocket serverSocket;

  @BeforeEach
  public void setup()
  {
    this.executor = Executors.newCachedThreadPool(r -> {
      final var thread = new Thread(r);
      thread.setName("SERVER");
      return thread;
    });
    this.done = new AtomicBoolean(false);
  }

  @AfterEach
  public void tearDown()
  {
    try {
      this.serverSocket.close();
    } catch (final IOException e) {
      LOG.error("", e);
    }
    this.done.set(true);
    this.executor.shutdown();
  }

  @Test
  public void testExpires(
    final @TempDir Path directory)
    throws Exception
  {
    /*
     * Register the necessary providers.
     */

    Security.addProvider(new CMKeyStoreProvider());
    final Provider bcProvider = new BouncyCastleProvider();
    Security.addProvider(bcProvider);

    /*
     * Generate a certificate authority that will be used to sign
     * certificates.
     */

    final var caKeyPair =
      createCAKeyPair();
    final var caCertificate =
      createCACertificate(caKeyPair, "CN=CA", bcProvider);

    /*
     * We will generate several keys and certificates. The first server
     * certificate is set to expire in a very short time so that we can
     * observe the expiration during the test.
     */

    final var timeCreated =
      Instant.now().minusSeconds(60L);
    final var serverExpires0 =
      Instant.now().plusSeconds(5L);
    final var serverExpires1 =
      Instant.now().plusSeconds(86400L);
    final var clientExpires0 =
      Instant.now().plusSeconds(86400L);

    /*
     * Generate two certificates for the server; the first will expire
     * very quickly, and the second will be used to replace the expired
     * certificate later.
     */

    final var serverKeyPair =
      createServerKeyPair();

    final Certificate serverCertificate0 =
      createServerSignedCertificate(
        caKeyPair,
        serverKeyPair,
        timeCreated,
        serverExpires0,
        SERVER_CERTIFICATE_SERIAL_FIRST
      );

    final Certificate serverCertificate1 =
      createServerSignedCertificate(
        caKeyPair,
        serverKeyPair,
        timeCreated,
        serverExpires1,
        SERVER_CERTIFICATE_SERIAL_SECOND
      );

    createServerKeystore(
      directory,
      caCertificate,
      serverKeyPair,
      serverCertificate0
    );

    createServerTruststore(
      directory,
      caCertificate
    );

    /*
     * Generate client certificates.
     */

    final var clientKeyPair =
      createClientKeyPair();

    final Certificate clientCertificate0 =
      createClientSignedCertificate(
        caKeyPair,
        clientKeyPair,
        timeCreated,
        clientExpires0
      );

    createClientKeystore(
      directory,
      caCertificate,
      clientKeyPair,
      clientCertificate0
    );

    createClientTruststore(
      directory,
      caCertificate
    );

    /*
     * Now, create SSL contexts for the client and server.
     */

    final KeyStore serverKeyStore =
      CMKeyStores.openKeyStore(directory.resolve("ServerKeystore.xml"));
    final KeyStore serverTrustStore =
      CMKeyStores.openKeyStore(directory.resolve("ServerTruststore.xml"));

    final var serverContext =
      CMKeyStores.createSSLContext(serverKeyStore, serverTrustStore, "TLSv1.3");

    final KeyStore clientKeyStore =
      CMKeyStores.openKeyStore(directory.resolve("ClientKeystore.xml"));
    final KeyStore clientTrustStore =
      CMKeyStores.openKeyStore(directory.resolve("ClientTruststore.xml"));

    final var clientContext =
      CMKeyStores.createSSLContext(clientKeyStore, clientTrustStore, "TLSv1.3");

    /*
     * Set very short timeouts for sessions. The reason for this is that
     * we want to demonstrate that clients cannot connect to servers that
     * are serving expired certificates - if a client can resume a session,
     * then it will effectively skip the certificate expiration check. By
     * setting a very low timeout, we can ensure that sessions are never
     * resumed, and that fresh sessions are created for each client.
     */

    serverContext.getServerSessionContext()
      .setSessionTimeout(1);
    serverContext.getServerSessionContext()
      .setSessionCacheSize(1);

    clientContext.getClientSessionContext()
      .setSessionCacheSize(1);
    clientContext.getClientSessionContext()
      .setSessionTimeout(1);

    final var serverSockets =
      serverContext.getServerSocketFactory();
    final var clientSockets =
      clientContext.getSocketFactory();

    final var serverAddress =
      new InetSocketAddress(
        InetAddress.getLocalHost(),
        60000
      );

    this.serverSocket =
      (SSLServerSocket) serverSockets.createServerSocket();

    /*
     * Start a server that writes a stream of zeroes to any connected
     * client.
     */

    this.executor.submit(() -> {
      LOG.info("Server: Bind");
      this.serverSocket.bind(serverAddress);
      while (!this.done.get()) {
        LOG.info("Server: Accept");
        final SSLSocket client = (SSLSocket) this.serverSocket.accept();
        LOG.info("Server: Accepted!");
        this.executor.submit(() -> {
          final var output = client.getOutputStream();
          while (!this.done.get()) {
            output.write(0x0);
          }
          return null;
        });
      }
      return null;
    });

    /*
     * Start a client that connects to the server and reads some data.
     * This should always succeed, because the server is serving a
     * certificate that has not yet expired.
     */

    try (var clientSocket = clientSockets.createSocket()) {
      LOG.info("Client: Connect");
      clientSocket.connect(serverAddress);
      LOG.info("Client: Connected!");
      final var input = clientSocket.getInputStream();
      for (int index = 0; index < 10; ++index) {
        input.read();
      }
      LOG.info("Client: Disconnecting");
    }

    LOG.info("Waiting for server certificate to expire...");
    final var toWait =
      Math.max(
        2000L + Duration.between(Instant.now(), serverExpires0)
          .toMillis(),
        0L
      );
    Thread.sleep(toWait);

    /*
     * Start a client that connects to the server and reads some data.
     * This should now fail, because the server certificate has expired.
     */

    LOG.info("Connecting to server with expired certificate...");
    try (var clientSocket = clientSockets.createSocket()) {
      assertThrows(SSLHandshakeException.class, () -> {
        clientSocket.connect(serverAddress);
        clientSocket.getInputStream()
          .read();
      });
    }

    /*
     * Now, write the new non-expired certificate to the server's keystore.
     */

    LOG.info("Updating server certificate...");
    Files.writeString(
      directory.resolve("ServerKeystore")
        .resolve("server.crt"),
      serializeCertificate(serverCertificate1)
    );

    /*
     * Reload the keystore.
     */

    CMKeyStores.reloadKeystoreFromFile(
      serverKeyStore,
      directory.resolve("ServerKeystore.xml")
    );

    /*
     * Reload the server's SSL context.
     */

    CMKeyStores.reloadSSLContext(
      serverKeyStore,
      serverTrustStore,
      serverContext
    );

    Thread.sleep(1_000L);

    /*
     * Now start a new client and connect to the server. This should work
     * correctly, because the server now has an up-to-date non-expired
     * certificate.
     */

    LOG.info("Connecting to server with new certificate...");
    try (SSLSocket clientSocket = (SSLSocket) clientSockets.createSocket()) {
      LOG.info("Client: Connect");
      clientSocket.connect(serverAddress);
      LOG.info("Client: Connected!");

      final var input = clientSocket.getInputStream();
      for (int index = 0; index < 10; ++index) {
        input.read();
      }
      LOG.info("Client: Disconnecting");
    }
  }

  private static void createServerTruststore(
    final Path directory,
    final Certificate caCertificate)
    throws Exception
  {
    LOG.info("Creating server truststore...");

    final var serverTruststoreDirectory =
      directory.resolve("ServerTruststore")
        .toAbsolutePath();

    Files.createDirectories(serverTruststoreDirectory);

    final var serverTruststoreIndex =
      directory.resolve("ServerTruststore.xml");

    Files.writeString(serverTruststoreIndex, """
      <?xml version="1.0" encoding="UTF-8" ?>

      <Keystore xmlns="urn:com.io7m.canonmill.keystore:1"
                BaseDirectory="%s">
        <Certificate Name="ca" File="ca.crt"/>
      </Keystore>
            """.formatted(serverTruststoreDirectory)
    );

    Files.writeString(
      serverTruststoreDirectory.resolve("ca.crt"),
      serializeCertificate(caCertificate)
    );
  }

  private static void createClientTruststore(
    final Path directory,
    final Certificate caCertificate)
    throws Exception
  {
    LOG.info("Creating client truststore...");

    final var clientTruststoreDirectory =
      directory.resolve("ClientTruststore")
        .toAbsolutePath();

    Files.createDirectories(clientTruststoreDirectory);

    final var clientTruststoreIndex =
      directory.resolve("ClientTruststore.xml");

    Files.writeString(clientTruststoreIndex, """
      <?xml version="1.0" encoding="UTF-8" ?>

      <Keystore xmlns="urn:com.io7m.canonmill.keystore:1"
                BaseDirectory="%s">
        <Certificate Name="ca" File="ca.crt"/>
      </Keystore>
            """.formatted(clientTruststoreDirectory)
    );

    Files.writeString(
      clientTruststoreDirectory.resolve("ca.crt"),
      serializeCertificate(caCertificate)
    );
  }

  private static Certificate createClientSignedCertificate(
    final KeyPair caKeyPair,
    final KeyPair clientKeyPair,
    final Instant timeCreated,
    final Instant timeExpires)
    throws Exception
  {
    LOG.info("Generating CSR for client...");
    final var csr = createCSR(clientKeyPair);

    return signCSR(
      caKeyPair,
      clientKeyPair,
      CLIENT_CERTIFICATE_SERIAL,
      timeCreated,
      timeExpires,
      csr
    );
  }

  private static Certificate createServerSignedCertificate(
    final KeyPair caKeyPair,
    final KeyPair serverKeyPair,
    final Instant timeCreated,
    final Instant timeExpires,
    final BigInteger serialNumber)
    throws Exception
  {
    LOG.info("Generating CSR for server...");
    final var csr = createCSR(serverKeyPair);

    return signCSR(
      caKeyPair,
      serverKeyPair,
      serialNumber,
      timeCreated,
      timeExpires,
      csr
    );
  }

  private static X509Certificate signCSR(
    final KeyPair caKeyPair,
    final KeyPair signeeKeyPair,
    final BigInteger serialNumber,
    final Instant timeCreated,
    final Instant timeExpires,
    final PKCS10CertificationRequest csr)
    throws Exception
  {
    LOG.info("Signing CSR...");

    final SubjectPublicKeyInfo keyInfo =
      SubjectPublicKeyInfo.getInstance(signeeKeyPair.getPublic().getEncoded());

    final AlgorithmIdentifier signatureAlgorithm =
      new DefaultSignatureAlgorithmIdentifierFinder()
        .find("SHA256WithRSA");

    final AlgorithmIdentifier digestAlgorithm =
      new DefaultDigestAlgorithmIdentifierFinder()
        .find("SHA-256");

    final X509v3CertificateBuilder certificateBuilder =
      new X509v3CertificateBuilder(
        new X500Name("CN=CA"),
        serialNumber,
        Date.from(timeCreated),
        Date.from(timeExpires),
        csr.getSubject(),
        keyInfo
      );

    final AsymmetricKeyParameter caPrivateKey =
      PrivateKeyFactory.createKey(caKeyPair.getPrivate().getEncoded());

    final ContentSigner signer =
      new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
        .build(caPrivateKey);

    final X509CertificateHolder holder =
      certificateBuilder.build(signer);

    final CertificateFactory cf =
      CertificateFactory.getInstance("X.509", "BC");

    try (var data = new ByteArrayInputStream(holder.getEncoded())) {
      return (X509Certificate) cf.generateCertificate(data);
    }
  }

  private static PKCS10CertificationRequest createCSR(
    final KeyPair keyPair)
    throws Exception
  {
    final AsymmetricKeyParameter privateKeyParam =
      PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
    final AlgorithmIdentifier signatureAlgorithm =
      new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSA");
    final AlgorithmIdentifier digestAlgorithm =
      new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256");
    final ContentSigner signer =
      new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm)
        .build(privateKeyParam);

    final PKCS10CertificationRequestBuilder csrBuilder =
      new JcaPKCS10CertificationRequestBuilder(
        new X500Name("CN=localhost"),
        keyPair.getPublic()
      );
    final ExtensionsGenerator extensionsGenerator =
      new ExtensionsGenerator();

    extensionsGenerator.addExtension(
      Extension.basicConstraints,
      true,
      new BasicConstraints(true)
    );

    extensionsGenerator.addExtension(
      Extension.keyUsage,
      true,
      new KeyUsage(KeyUsage.dataEncipherment)
    );

    csrBuilder.addAttribute(
      PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
      extensionsGenerator.generate()
    );

    return csrBuilder.build(signer);
  }

  private static void createServerKeystore(
    final Path directory,
    final Certificate caCertificate,
    final KeyPair serverKeyPair,
    final Certificate serverCertificate0)
    throws Exception
  {
    LOG.info("Creating server keystore...");

    final var serverKeystoreDirectory =
      directory.resolve("ServerKeystore")
        .toAbsolutePath();

    Files.createDirectories(serverKeystoreDirectory);

    final var serverKeystoreIndex =
      directory.resolve("ServerKeystore.xml");

    Files.writeString(serverKeystoreIndex, """
      <?xml version="1.0" encoding="UTF-8" ?>

      <Keystore xmlns="urn:com.io7m.canonmill.keystore:1"
                BaseDirectory="%s">
        <Key Name="server" File="server.key"/>
        <Certificate Name="server" File="server.crt"/>
        <Certificate Name="ca" File="ca.crt"/>
      </Keystore>
            """.formatted(serverKeystoreDirectory)
    );

    Files.writeString(
      serverKeystoreDirectory.resolve("ca.crt"),
      serializeCertificate(caCertificate)
    );

    Files.writeString(
      serverKeystoreDirectory.resolve("server.key"),
      serializeKey(serverKeyPair)
    );

    Files.writeString(
      serverKeystoreDirectory.resolve("server.crt"),
      serializeCertificate(serverCertificate0)
    );
  }


  private static void createClientKeystore(
    final Path directory,
    final Certificate caCertificate,
    final KeyPair clientKeyPair,
    final Certificate clientCertificate0)
    throws Exception
  {
    LOG.info("Creating client keystore...");

    final var clientKeystoreDirectory =
      directory.resolve("ClientKeystore")
        .toAbsolutePath();

    Files.createDirectories(clientKeystoreDirectory);

    final var clientKeystoreIndex =
      directory.resolve("ClientKeystore.xml");

    Files.writeString(clientKeystoreIndex, """
      <?xml version="1.0" encoding="UTF-8" ?>

      <Keystore xmlns="urn:com.io7m.canonmill.keystore:1"
                BaseDirectory="%s">
        <Key Name="client" File="client.key"/>
        <Certificate Name="client" File="client.crt"/>
        <Certificate Name="ca" File="ca.crt"/>
      </Keystore>
            """.formatted(clientKeystoreDirectory)
    );

    Files.writeString(
      clientKeystoreDirectory.resolve("ca.crt"),
      serializeCertificate(caCertificate)
    );

    Files.writeString(
      clientKeystoreDirectory.resolve("client.key"),
      serializeKey(clientKeyPair)
    );

    Files.writeString(
      clientKeystoreDirectory.resolve("client.crt"),
      serializeCertificate(clientCertificate0)
    );
  }


  private static CharSequence serializeKey(
    final KeyPair serverKeyPair)
    throws IOException
  {
    final var stringWriter = new StringWriter();
    try (var jca = new JcaPEMWriter(stringWriter)) {
      jca.writeObject(serverKeyPair);
      jca.flush();
    }
    return stringWriter.toString();
  }

  private static String serializeCertificate(
    final Certificate certificate)
    throws Exception
  {
    final var stringWriter = new StringWriter();
    try (var jca = new JcaPEMWriter(stringWriter)) {
      jca.writeObject(certificate);
      jca.flush();
    }
    return stringWriter.toString();
  }

  private static KeyPair createCAKeyPair()
    throws Exception
  {
    LOG.info("Creating CA keypair...");

    final var generator =
      KeyPairGenerator.getInstance("RSA");

    generator.initialize(3096);
    return generator.generateKeyPair();
  }

  private static KeyPair createServerKeyPair()
    throws Exception
  {
    LOG.info("Creating Server keypair...");

    final var generator =
      KeyPairGenerator.getInstance("RSA");

    generator.initialize(3096);
    return generator.generateKeyPair();
  }

  private static KeyPair createClientKeyPair()
    throws Exception
  {
    LOG.info("Creating Client keypair...");

    final var generator =
      KeyPairGenerator.getInstance("RSA");

    generator.initialize(3096);
    return generator.generateKeyPair();
  }

  private static Certificate createCACertificate(
    final KeyPair keyPair,
    final String subjectDN,
    final Provider bcProvider)
    throws Exception
  {
    LOG.info("Creating CA certificate...");

    final var now =
      System.currentTimeMillis();
    final var startDate =
      new Date(now);

    final var dnName =
      new X500Name(subjectDN);

    final var calendar = Calendar.getInstance();
    calendar.setTime(startDate);
    calendar.add(Calendar.YEAR, 1);

    final var endDate =
      calendar.getTime();
    final var signatureAlgorithm =
      "SHA256WithRSA";

    final var contentSigner =
      new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

    final var certBuilder =
      new JcaX509v3CertificateBuilder(
        dnName,
        CA_CERTIFICATE_SERIAL,
        startDate,
        endDate,
        dnName,
        keyPair.getPublic()
      );

    final var basicConstraints =
      new BasicConstraints(true);

    certBuilder.addExtension(
      new ASN1ObjectIdentifier("2.5.29.19"),
      true,
      basicConstraints);

    return new JcaX509CertificateConverter()
      .setProvider(bcProvider)
      .getCertificate(certBuilder.build(contentSigner));
  }
}
