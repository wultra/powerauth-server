# System Requirements

There are two ways to deploy PowerAuth Server:

- Java container
- Docker

### Deployment in Java Environment

PowerAuth Server primary installation method is running the WAR package in the Java VM environment. This chapter provides detailed system requirements.

Following Java version is required:

- JRE 8, and
- Correctly installed Bouncy Castle provider, and
- JCE Unlimited Strength Jurisdiction Policy Files 8

It is suggested to deploy PowerAuth in it's own instance of a Java Servlet Container. PowerAuth Server is currently tested with following container technolgies:

- Apache Tomcat 8 or newer, or
- JBoss Wildfly 9 or newer, or
- IBM WebSphere 8.5.5.10 or newer

PowerAuth supports any JPA2 compatible database and it is tested with:

- Oracle Database 11g or 12c, or
- MySQL 5.5 or newer, or
- PostgreSQL 9.5.4 or newer

Note that MSSQL database is not supported.

When deploying the PowerAuth Server, plese follow the specifics of your application server.

Of course, you can also run the PowerAuth Server without the servler container (as an executable WAR file) - in this case, you need to make sure to place appropriate libraries on Java classpath.

Deployment is described in details in a separate documentation:

- [Deploying PowerAuth Server](./Deploying-PowerAuth-Server.md)

### Deployment in Docker

You can also deploy PowerAuth Server in Docker. This is especially convenient for development.

You need following software versions:

- Docker 17.3.1 or newer, and
- Docker Compose 1.11.2 or newer, and
- Unix-based operating system, preferrably Mac OS, or any stable Linux distribution

Deployment is described in a separate documentation:

- [Docker Images for PowerAuth](https://github.com/wultra/powerauth-docker)

### HW Requirements

You don't need much more than your Java container of choice requests for the PowerAuth deployment. We suggest following minimal configuration:

- 2x CPU 2.5GHz
- minimum available RAM: 2048MB
- sufficient disk space for log storage: 10GB

### Suggested Database Sizing

In order to determine required database sizing, we need to account for two components:

- **base database size** - data related to users and their configuration, generally do not grow rapidly in time
- **expected monthly database growth** - data related to user activity - value grows with every single login, payment, etc.

To compute more exact values, you need to account for following input parameters:

- I - Expected number of installations.
- U - Expected number of monthly active mobile application users.
- D - Expected number of active device per user.
- A - Expected number of active activations per device, including "ghost activations" (residual data after app uninstall).
- O - Expected number of operations per user per month.
- S - Average size of operation related data.
- X - Expected number of extensions (Apple Watch, widgets, ...) per activation.
- C - Expected number of activation changes (activation initialization, blocking, unblocking,
...).

We will be also using value `B` as a "Base unit size for row size" equal to 1kB.

With these values, we can compute expected database size using following formula:

1. In case activation recovery is disabled:
```
SIZE   = SIZE1 + SIZE3 = (I * D * A * B) + (I * D * A * X * B)
       = I * D * A * B * (1 + X)
```

2. In case activation recovery is enabled and recovery postcards are disabled:

```
SIZE   = SIZE1 + SIZE3 + SIZE4A + SIZE5A = (I * D * A * B) + (I * D * A * X * B) + (I * D * A * B) + (I * D * A * 0.5 * B)
       = I * D * A * B * (2.5 + X)
```

3. In case activation recovery is enabled and recovery postcards are enabled:

```
SIZE   = SIZE1 + SIZE3 + SIZE4B + SIZE5B = (I * D * A * B) + (I * D * A * X * B) + (I * D * A * B + I * B) + (I * D * A * 0.5 * B + I * 5 * B)
       = I * D * A * B * (2.5 + X) + I * 6 * B
```

Database size growth can be estimated using following formula:
```
GROWTH = SIZE2
       = U * O * (S + B)
```

#### PowerAuth Server Tables

Specifically, PowerAuth Server tables behave in a following way:

- `pa_activation`
    - this table may grow significantly based mainly on number of users
    - expected row length: `R1 = 1 * B`
    - `SIZE1 = I * D * A * R1 = I * D * A * B`
- `pa_activation_history`
    - this table may grow significantly based mainly on number of users
    - expected row length: `R1 = 1 * B`
    - `SIZE1 = I * D * A * R1 * C = I * D * A * B * C`
- `pa_application`
    - this table is small size and can be neglected in size estimates
    - it contains record for every application you have
    - in most cases, this table contains only one record, for one mobile app
- `pa_application_callback`
    - this table is small size and can be neglected in size estimates
    - it contains record for every application callback (system that is notified about activation status change)
    - since there are not too many systems that need to be notified when activation status changes, this table contains single units of records at most
- `pa_application_version`
    - this table is small size and can be neglected in size estimates
    - it contains record for every application version you have
    - since application releases are performed every 3-6 months, this table contains single units of records at most  (couple for each application from `pa_application`)
- `pa_integration`
    - this table is small size and can be neglected in size estimates
    - it contains record for every application that needs to communicate with PowerAuth Server
    - since there are not too many systems that need to communicate with PowerAuth Server, this table contains single units of records at most
- `pa_master_keypair`
    - this table is small size and can be neglected in size estimates
    - it contains record for every master key pair associated with application
    - since the need for refreshing this master key pair is rare, there usually are at most single units of records in this table (one or two for each application from `pa_application`)
- `pa_signature_audit`
    - this table may grow significantly based mainly on number performed operation and their associated data size
    - operations in this table may be cleared by creation date based on banks requirements for audit data availability, for example: if bank requires to have audit history of 12 months, it may discard records that are older than 12 months
    - expected row length: `R2 = S * B`
    - `SIZE2 = U * O * S * R2 = U * O * (S + B)`
- `pa_token`
    - this table may grow significantly based mainly on number of users and app extensions they use
    - expected row length: `R3 = 1 * B`
    - `SIZE3 = I * D * A * X * R3 = I * D * A * X * B`
- `pa_recovery_code`
    - this table may grow significantly based mainly on number of users, however only in case activation recovery is enabled
    - expected row length: `R4 = 1 * B`
    - in case activation postcards are disabled: `SIZE4A = I * D * A * R4 = I * D * A * B`
    - in case activation postcards are enabled: `SIZE4B = I * D * A * R4 + I * R4 = I * D * A * B + I * B`
- `pa_recovery_puk`
    - this table may grow significantly based mainly on number of users, however only in case activation recovery is enabled
    - expected row length: `R5 = 0.5 * B`
    - in case activation postcards are disabled: `SIZE5A = I * D * A * R5 = I * D * A * 0.5 * B`
    - in case activation postcards are enabled: `SIZE5B = I * D * A * R5 + I * R5 * 10 = I * D * A * 0.5 * B + I * 5 * B`
- `pa_recovery_config`
    - this table is small size and can be neglected in size estimates
    - it contains a single record for every application

#### Example

Assume we have following values:

- I - Expected number of installations: 500 000
- U - Expected number of monthly active mobile application users: 100 000
- D - Expected number of active device per user: 1.5
- A - Expected number of active activations per device: 2
- O - Expected number of operations per user per month: 20 logins + 10 payments => 30
- S - Average size of operation related data: 1KB
- X - Expected number of extensions (Apple Watch, widgets, ...) per activation: 1x Apple Watch Extension => 1
- B - Base unit size - equal to 1kB: OK

Expected growth of the database per month is:

```
SIZE = I * D * A * B * (1 + X)
     = 500 000 * 1.5 * 2 * 1kb * (1 + 1)
     = 3 000 000 kB = 2.86 GB

GROWTH = U * O * (S + B)
       = 100 000 * 30 * (1kb + 1kb)
       = 6 000 000 kB = 5.7 GB
```
