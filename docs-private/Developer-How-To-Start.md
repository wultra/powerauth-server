# Developer - How to Start Guide


## PowerAuth Java Server


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthServerApplication.run.xml`
- Open [http://localhost:8080/powerauth-java-server/actuator/health](http://localhost:8080/powerauth-java-server/actuator/health) and you should get `{"status":"UP"}`


## PowerAuth Admin Server


### Standalone Run

- Enable maven profile `standalone`
- Use IntelliJ Idea run configuration at `../.run/PowerAuthAdminApplication.run.xml`
- Open [http://localhost:8082/powerauth-admin/actuator/health](http://localhost:8082/powerauth-admin/actuator/health) and you should get `{"status":"UP"}`
