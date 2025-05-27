# 1. Pulling the dependencies
FROM maven:3.8.5-openjdk-17 AS builder
# Change working directory in the container
WORKDIR /opt/app
COPY pom.xml .
COPY src ./src

# compile code in /opt/app
RUN mvn -B -e clean install -DskipTests

# 3. Preparing the runtime environment
FROM openjdk:17-slim

WORKDIR /opt/app

# Start authorization_server
COPY --from=builder /opt/app/target/*.jar sca.jar
COPY src/main/resources/TSA_CC.pem src/main/resources/TSA_CC.pem
EXPOSE 8087
ENTRYPOINT ["java", "-jar", "sca.jar"]