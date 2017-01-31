# spring-cas-auth
This is CAS 5.0 Spring integration example with Angular, REST and extra attribute bonus.
CAS setup uses LdapAuthenticationHandler. To get attributes to the client add to cas.properties
```
cas.authn.ldap[0].principalAttributeList=<attr. list>
```
Service definition should allow all attributes you want to see. <br>

To run the application:
```
mvn spring-boot:run
```
