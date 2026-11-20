FROM ghcr.io/wultra/wultra-base-images:jre-semeru-25_7@sha256:30d496462a9fa1ead309d9397f23a27f6deadf235733547e7c24a4040a3f98fa

# Prepare environment variables
ENV LOGBACK_CONF=/opt/logback/conf \
    APP_PATH="/app/powerauth-java-server.war" \
    CONTEXT_PATH="/powerauth-java-server"

# Deploy and run applications
COPY ./powerauth-java-server/target/powerauth-java-server*.war "${APP_PATH}"

COPY powerauth-java-server/docker/conf/logback/* $LOGBACK_CONF/