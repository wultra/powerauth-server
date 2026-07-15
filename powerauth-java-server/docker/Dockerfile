FROM ghcr.io/wultra/wultra-base-images:jre-semeru-25_2

# Prepare environment variables
ENV LOGBACK_CONF=/opt/logback/conf \
    APP_PATH="/app/powerauth-java-server.war" \
    CONTEXT_PATH="/powerauth-java-server"

# Deploy and run applications
COPY ./powerauth-java-server/target/powerauth-java-server*.war "${APP_PATH}"

COPY powerauth-java-server/docker/conf/logback/* $LOGBACK_CONF/