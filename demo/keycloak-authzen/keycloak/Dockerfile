# Build context: demo/keycloak-authzen/
#
# Stage 1: build the AuthZEN authenticator provider jar.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /build
COPY authenticator/ .
RUN mvn -q -DskipTests package

# Stage 2: Keycloak with the provider and the demo realm baked in.
FROM quay.io/keycloak/keycloak:26.1.0 AS keycloak

# Custom Authenticator provider.
COPY --from=build /build/target/keycloak-authzen-authenticator.jar \
    /opt/keycloak/providers/keycloak-authzen-authenticator.jar

# Demo realm (imported on first start via --import-realm).
COPY realm/authzen-demo-realm.json /opt/keycloak/data/import/authzen-demo-realm.json

# Augment the server with the new provider.
RUN /opt/keycloak/bin/kc.sh build
