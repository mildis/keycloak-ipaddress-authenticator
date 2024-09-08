# Keycloak GeoIP Authenticator

This Keycloak extensions allows implementing conditional authentication flows based on the client's estimated location. For example, if you want to show an OTP form only for users connecting from outside known operating countries, you can use this extension to do so.

## Installation
* Copy the MMDB file to the `src/resources` folder and keep the .mmdb extension.
* Then build [build from source](#build-from-source).
* Place the .jar file in the Keycloak `providers` directory and restart Keycloak.

## Build From Source
* Check out the sources
* Run `mvn clean package`
* This will generate the .jar files in the `target` directory.
