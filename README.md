# Keycloak GeoIP Authenticator

This Keycloak extensions allows implementing conditional authentication flows based on the client's estimated location. For example, if you want to show an OTP form only for users connecting from outside known operating countries, you can use this extension to do so.

Supports IPv6 and IPv4. Supports single IP addresses and IP ranges in CIDR as well as netmask notation. Examples: `192.168.1.5`, `a:b:c:d::/64`, `145.251.153.32/255.255.0.0`

## Installation
* Download the `keycloak-geoip-authenticator-{version}-jar-with-dependencies.jar` from the [Releases Tab](https://github.com/evosec/keycloak-ipaddress-authenticator/releases) and verify the checksum. Alternatively you can build [build from source](#build-from-source).
  * You can also use `keycloak-ipaddress-authenticator-{version}.jar`: This jar only contains the compiled code for this extension itself, so you need to add all dependencies manually (see [`pom.xml`](https://github.com/evosec/keycloak-ipaddress-authenticator/blob/master/pom.xml).
* Place the .jar file in the Keycloak Plugins directory and restart Keycloak.

## Build From Source
* Check out the sources
* Run `mvn clean package`
* This will generate the .jar files in the `target` directory.
