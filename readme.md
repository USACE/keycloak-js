#Simple Keycloak JS Client

to use, add the keycloak js class to your project and import it into your auth bundle.
then in the bundler init function, set keycloak up similar to the code below. 

refreshUrl was added to support the use case when a token is requested via CAC, 
then refreshed on the keycloak server's non-cac route to avoid re-entering PIN numbers.

```js
init:store=>{
    keycloak = new Keycloak({
      keycloakUrl:keycloakHost,
      refreshUrl:keycloakRefresh, //omit if refresh should use keycloakHost
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
