# Developer - How to Start Guide


## PowerAuth Java Server


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthServerApplication.run.xml`
- Open [http://localhost:8080/powerauth-java-server/actuator/health](http://localhost:8080/powerauth-java-server/actuator/health) and you should get `{"status":"UP"}`


### Database

Database changes are driven by Liquibase.

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

To generate SQL script run this command.


#### Oracle

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/oracle/generated-oracle-script.sql updateSQL --url=offline:oracle
```


#### MS SQL

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/mssql/generated-mssql-script.sql updateSQL --url=offline:mssql
```


#### PostgreSQL

```shell
liquibase --changeLogFile=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --output-file=./docs/sql/postgresql/generated-postgresql-script.sql updateSQL --url=offline:postgresql
```

### Schema Diagram

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


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthAdminApplication.run.xml`
- Open [http://localhost:8082/powerauth-admin/actuator/health](http://localhost:8082/powerauth-admin/actuator/health) and you should get `{"status":"UP"}`
