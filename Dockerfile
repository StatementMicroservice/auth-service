FROM openjdk:21-oracle AS Build

WORKDIR /app
COPY target/city-statement-auth-service.jar /app/city-statement-auth-service.jar
EXPOSE 8585

# Set environment variables for MySQL connection
ENV MYSQL_DATABASE=city-statement-auth-service
ENV MYSQL_USER=root
ENV MYSQL_PASSWORD=root
ENV MYSQL_URL=jdbc:mysql://localhost:3306/city-statement-security?useSSL=false&serverTimezone=UTC

ENTRYPOINT ["java","-jar","/app/city-statement-auth-service.jar"]
