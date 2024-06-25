# Developer - How to Start Guide


## PowerAuth Java Server


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthServerApplication.run.xml`
- Open [http://localhost:8080/powerauth-java-server/actuator/health](http://localhost:8080/powerauth-java-server/actuator/health) and you should get `{"status":"UP"}`


### Database

Database changes are driven by Liquibase.

This is an example how to manually check the Liquibase status.
Important and fixed parameter is `changelog-file`.
Others (like URL, username, password) depend on your environment.

```shell
liquibase --changelog-file=./docs/db/changelog/changesets/powerauth-java-server/db.changelog-module.xml --url=jdbc:postgresql://localhost:5432/powerauth --username=powerauth status
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


## PowerAuth Admin Server


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthAdminApplication.run.xml`
- Open [http://localhost:8082/powerauth-admin/actuator/health](http://localhost:8082/powerauth-admin/actuator/health) and you should get `{"status":"UP"}`
