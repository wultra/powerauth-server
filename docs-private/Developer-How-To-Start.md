# Developer - How to Start Guide

## General prerequisites

* _JDK_ version 21.x
* _Maven_ version 3.9.x
* _PostgreSQL_ version 18.x
* _Liquibase_ version 4.33.x


## PowerAuth Java Server

### Build

Build with:

```shell
mvn clean package
```


### Database

* The default DB for development is _PostgreSQL_.
* Database changes are driven by Liquibase.

#### Set up

You have installed and running DB with an admin account.

##### Create a user and a schema

Start a `psql` session with your superuser:

```shell
psql -U $(whoami) -d postgres
```

Then run following commands in the `psql` shell:

```sql
CREATE USER powerauth WITH PASSWORD 'powerauth';
CREATE DATABASE powerauth OWNER powerauth;
```

##### Load the data with Liquibase

This is an example how to invoke Liquibase.
Important and fixed parameter is `changelog-file`.
Others (like URL, username, password) depend on your environment.

To list all undeployed changesets run this `status` command. 

```shell
liquibase --changelog-file=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --url=jdbc:postgresql://localhost:5432/powerauth --username=powerauth status
```

To apply the changesets run this `update` command.

```shell
liquibase --changelog-file=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --url=jdbc:postgresql://localhost:5432/powerauth --username=powerauth update
```
### Configure

#### Database encryption

See the [doc/PowerAuth-Server-2.0.0.md](doc/PowerAuth-Server-2.0.0.md) document for how to create and configure an _Encryption Key_.

#### Local dev env.

You should make a copy of the `application-dev.properties` and do changes specific to your environment (eg. keys, etc.).

### Run

The working directory is `powerauth-java-server`.

#### CLI

```shell
java -jar target/powerauth-java-server-x.y.z.war --spring.profiles.active=dev
```

#### Maven

```shell
mvn spring-boot:run -Dspring-boot.run.arguments="--spring.profiles.active=dev"
```

#### IntelliJ Idea

1. Copy `../.run/PowerAuthServerApplication.run.xml.tmp` to `../.run/PowerAuthServerApplication.run.xml` and modify it
   with sensual values (keys, etc.).
1. Use IntelliJ Idea run the modified configuration at `../.run/PowerAuthServerApplication.run.xml`

### Smoke test

Run following `curl` command:

```shell
curl -v -X POST http://localhost:8080/rest/v4/status
```

You should get response: `200 {"status":"OK"}`

You can check other APIs on:

* http://localhost:8080/swagger-ui/index.html


### Schema Diagram

#### Generate SQL script (optional)


##### PostgreSQL

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/postgresql/generated-postgresql-script.sql updateSQL --url=offline:postgresql
```

##### Oracle

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/oracle/generated-oracle-script.sql updateSQL --url=offline:oracle
```


##### MS SQL

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/mssql/generated-mssql-script.sql updateSQL --url=offline:mssql
```


#### Generate ER diagram
To generate diagram of the database schema, use [SchemaCrawler](https://www.schemacrawler.com/) tool. Unfortunately,
the SchemaCrawler cannot be installed via a package manager for MacOS. You can either use the [docker image](https://www.schemacrawler.com/docker-image.html)
or get the tool from their [releases page](https://github.com/schemacrawler/SchemaCrawler/releases). Note, that
the SchemaCrawler diagram generation depends on `graphviz`, which is available via `brew` package manager.

To install graphviz and download SchemaCrawler run:

```shell
SC_VERSION='16.21.4' && \
brew install graphviz && \
curl -Lo schemacrawler.zip "https://github.com/schemacrawler/SchemaCrawler/releases/download/v${SC_VERSION}/schemacrawler-${SC_VERSION}-distribution.zip" && \
unzip schemacrawler.zip && \
rm schemacrawler.zip && \
mv "schemacrawler-${SC_VERSION}-distribution" schema_crawler
```

There are two config files for the SchemaCrawler, which should be modified.
To modify the configuration, run:

```shell
SC_CONFIG_DIR="./schema_crawler/_schemacrawler/config" && \
SC_CONFIG='
# Hide public. prefix from the table names
schemacrawler.format.show_unqualified_names=true
# Hide SchemaCrawler details
schemacrawler.format.no_schemacrawler_info=true
# Output PNG resolution
schemacrawler.graph.graphviz_opts=-Gsize=7 -Gdpi=300' && \
SC_COLORMAP='
# Set header color for all tables
0099FF=.*' && \
echo "$SC_CONFIG" >> "${SC_CONFIG_DIR}/schemacrawler.config.properties" && \
echo "$SC_COLORMAP" >> "${SC_CONFIG_DIR}/schemacrawler.colormap.properties"
```

Then to generate the schema diagram, run following:

```shell
./schema_crawler/_schemacrawler/bin/schemacrawler.sh \
  --server=postgresql \
  --host=localhost \
  --port=5432 \
  --database=powerauth \
  --schemas=public \
  --user=powerauth \
  --info-level=standard \
  --command=schema \
  --output-format=png \
  --output-file="../docs/images/arch_db_structure.png" \
  --tables='public.pa_(?!cloud|test).*'
```


## PowerAuth Admin Server

### Build

Build with:

```shell
mvn clean package
```

### Run

The working directory is `powerauth-admin`.

#### CLI

```shell
java -jar target/powerauth-admin-x.y.z.war
```

#### Maven

```shell
mvn spring-boot:run
```

#### IntelliJ Idea

* Use IntelliJ Idea to run the configuration at `../.run/PowerAuthAdminApplication.run.xml`

### Smoke test

Run following `curl` command:

```shell
curl -v http://localhost:8080/actuator/health
```

You should get response: `200 {"status":"UP"}`

