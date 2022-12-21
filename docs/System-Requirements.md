# System Requirements

## HW Requirements

You don't need much more than your Java container of choice requests for the PowerAuth deployment. We suggest following minimal configuration:

- 2x CPU 2.5GHz
- minimum available RAM: 4GB
- sufficient disk space for log storage: 10GB

There are two ways to deploy PowerAuth Server:

- Java container
- Docker

Running PowerAuth server from console using the `java -jar` command is not supported.

## Supported Java Runtime Versions

The following Java runtime versions are supported:
- Java 8 (LTS release)
- Java 11 (LTS release)
- Java 17 (LTS release)

Powerauth Server may run on other Java versions, however we do not perform extensive testing with non-LTS releases.

## Deployment in Java Container

PowerAuth Server primary installation method is running the WAR package in the Java VM environment. This chapter provides detailed system requirements.

It is suggested to deploy PowerAuth in its own Java Servlet Container. PowerAuth Server is currently tested with following container technologies:

- Apache Tomcat 9.x, or
- JBoss Wildfly 9 or newer

PowerAuth supports any JPA2 compatible database, and it is tested with:

- Oracle Database 11g, 12c, 19c, or 21c or
- PostgreSQL 9.5.4 or newer, or
- MySQL 5.5 or newer

Note that MSSQL database is not supported due to unreliable row locking.

When deploying the PowerAuth Server, please follow the specifics of your application server.

Deployment is described in details in a separate documentation:

- [Deploying PowerAuth Server](./Deploying-PowerAuth-Server.md)

### Deployment in Docker

You can also deploy PowerAuth Server in Docker. This is especially convenient for development.

You need following software versions:

- Docker 17.3.1 or newer, and
- Docker Compose 1.11.2 or newer, and
- Unix-based operating system, preferably macOS, or any stable Linux distribution

Deployment is described in a separate documentation:

- [Docker Images for PowerAuth](https://github.com/wultra/powerauth-docker)
