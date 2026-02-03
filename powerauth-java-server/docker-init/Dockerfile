FROM liquibase:4.33.0-alpine

LABEL maintainer="Wultra <hello@wultra.com>"

COPY powerauth-java-server/docker-init/liquibase/data /liquibase/changelog
COPY powerauth-java-server/docker-init/docker-entrypoint.sh /docker-entrypoint.sh

COPY powerauth-java-server/docker/deploy/images-and-libs/mssql*.jar /liquibase/internal/lib/mssql-jdbc.jar

RUN rm /liquibase/internal/lib/snowflake-jdbc.jar

USER liquibase
ENTRYPOINT ["/docker-entrypoint.sh"]
