# syntax=docker/dockerfile:1

# Build stage
FROM maven:3.9.9-eclipse-temurin-21-alpine AS build
WORKDIR /workspace

# Copy pom first to cache dependencies
COPY pom.xml .
RUN mvn -q -DskipTests dependency:go-offline

# Copy sources and package app
COPY src ./src
RUN mvn -q -DskipTests clean package

# Runtime stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Run as non-root user
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

COPY --from=build /workspace/target/*.jar /app/app.jar

EXPOSE 8080
ENV SERVER_SSL_ENABLED=false
ENV SECURE_CLIENT_IDENTITY_MODE=header
ENV SECURE_CLIENT_IDENTITY_HEADER=X-Device-Id
ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC"
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT:-8080} -jar /app/app.jar"]

