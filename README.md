canonmill
===

[![Maven Central](https://img.shields.io/maven-central/v/com.io7m.canonmill/com.io7m.canonmill.svg?style=flat-square)](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22com.io7m.canonmill%22)
[![Maven Central (snapshot)](https://img.shields.io/nexus/s/com.io7m.canonmill/com.io7m.canonmill?server=https%3A%2F%2Fs01.oss.sonatype.org&style=flat-square)](https://s01.oss.sonatype.org/content/repositories/snapshots/com/io7m/canonmill/)
[![Codecov](https://img.shields.io/codecov/c/github/io7m-com/canonmill.svg?style=flat-square)](https://codecov.io/gh/io7m-com/canonmill)
![Java Version](https://img.shields.io/badge/21-java?label=java&color=e6c35c)

![com.io7m.canonmill](./src/site/resources/canonmill.jpg?raw=true)

| JVM | Platform | Status |
|-----|----------|--------|
| OpenJDK (Temurin) Current | Linux | [![Build (OpenJDK (Temurin) Current, Linux)](https://img.shields.io/github/actions/workflow/status/io7m-com/canonmill/main.linux.temurin.current.yml)](https://www.github.com/io7m-com/canonmill/actions?query=workflow%3Amain.linux.temurin.current)|
| OpenJDK (Temurin) LTS | Linux | [![Build (OpenJDK (Temurin) LTS, Linux)](https://img.shields.io/github/actions/workflow/status/io7m-com/canonmill/main.linux.temurin.lts.yml)](https://www.github.com/io7m-com/canonmill/actions?query=workflow%3Amain.linux.temurin.lts)|
| OpenJDK (Temurin) Current | Windows | [![Build (OpenJDK (Temurin) Current, Windows)](https://img.shields.io/github/actions/workflow/status/io7m-com/canonmill/main.windows.temurin.current.yml)](https://www.github.com/io7m-com/canonmill/actions?query=workflow%3Amain.windows.temurin.current)|
| OpenJDK (Temurin) LTS | Windows | [![Build (OpenJDK (Temurin) LTS, Windows)](https://img.shields.io/github/actions/workflow/status/io7m-com/canonmill/main.windows.temurin.lts.yml)](https://www.github.com/io7m-com/canonmill/actions?query=workflow%3Amain.windows.temurin.lts)|

## canonmill

The `canonmill` package provides a
[Keystore](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html)
implementation designed to be less painful from an operational perspective than any of the
`Keystore` implementations currently included in the standard JDK.

## Features

* Exposes a simple directory-based keystore with a single XML file that maps certificate aliases to files. Keys and certificates are expected to be PEM-encoded regular files.
* Implicit compatibility with ACME systems; ACME clients can simply copy certificate files into the directory and, as long as the certificates have an entry in the XML index file, the new certificates will become available as soon as the Keystore is reloaded.
* A small, easily auditable codebase with use of modularity for correctness.
* An extensive automated test suite with high coverage.
* Platform independence. No platform-dependent code is included in any form.
* [OSGi](https://www.osgi.org/)-ready.
* [JPMS](https://en.wikipedia.org/wiki/Java_Platform_Module_System)-ready.
* ISC license.

## Usage

See the [documentation](https://www.io7m.com/software/canonmill/).

