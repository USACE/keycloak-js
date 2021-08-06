#Simple Keycloak JS Client

to use, add the keycloak js class to your project and import it into your auth bundle.
then in the bundler init function, set keycloak up similar to the code below. 

```js
init:store=>{
    keycloak = new Keycloak({
      keycloakUrl:keycloakHost,
      realm:keycloakRealm,
      client:keycloakClient,
      redirectUrl:keycloakRedirect,
      refreshInterval:300,
      sessionEndWarning:600,
      onAuthenticate:(token)=>{
        store.doAuthUpdate(token);
      },
      onError:(err)=>{
        console.log(err);
        store.doAuthUpdate(null);
      },
      onSessionEnding:(remainingTime)=>{
        console.log(remainingTime);
        store.doAppUpdateNotification(true,"warning",`Your session is expiring in ${Math.round(remainingTime/60)} minutes.`)
      }
    });

    keycloak.checkForSession();
  },
```
