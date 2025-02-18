# MTLS_Oauth2

Dans une architecture Spring Boot, on peux sécuriser différents endpoints avec **MTLS** pour les communications **interservices** et **OAuth 2** pour l’authentification des utilisateurs et clients API. Voici comment tu peux organiser cela :

---

## 🔒 **1. Sécuriser certains endpoints avec MTLS**  
### 📌 Objectif :  
MTLS permet d'assurer que seuls des clients authentifiés (autres microservices, API partenaires) peuvent appeler certains endpoints.

### **🔧 Étapes :**  
#### 1️⃣ **Générer les certificats (clé privée + certificat client/serveur)**
Utilise OpenSSL ou une autorité de certification pour créer un keystore et un truststore.

```sh
# Génération du keystore serveur
keytool -genkey -alias server -keyalg RSA -keystore server-keystore.jks -storepass changeit -validity 365

# Génération du truststore (contenant le certificat client)
keytool -import -alias client -file client-cert.pem -keystore truststore.jks -storepass changeit
```

#### 2️⃣ **Configurer Spring Boot pour activer MTLS**
Dans **`application.yml`** :
```yaml
server:
  port: 8443
  ssl:
    key-store: classpath:server-keystore.jks
    key-store-password: changeit
    key-store-type: JKS
    trust-store: classpath:truststore.jks
    trust-store-password: changeit
    trust-store-type: JKS
    client-auth: NEED  # FORCE le client à fournir un certificat
```

#### 3️⃣ **Restreindre les accès à certains endpoints**  
Dans **Spring Security**, utilise un filtre pour appliquer MTLS uniquement sur certains endpoints :

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/internal/**").authenticated() // MTLS obligatoire pour ces endpoints
                .anyRequest().permitAll()
            )
            .requiresChannel(channel -> channel.anyRequest().requiresSecure())
            .sslConfigurer().trustManager(trustManager -> {
                trustManager.trustStore("classpath:truststore.jks", "changeit");
            });

        return http.build();
    }
}
```

---

## 🔑 **2. Sécuriser d'autres endpoints avec OAuth 2**  
### 📌 Objectif :  
OAuth 2 permet d’authentifier les utilisateurs via un **Authorization Server** (Keycloak, Okta, Auth0, Spring Authorization Server...).

### **🔧 Étapes :**  
#### 1️⃣ **Configurer l’Authorization Server**  
Si tu utilises **Keycloak**, crée un realm avec des clients, utilisateurs et rôles.

#### 2️⃣ **Configurer Spring Boot pour OAuth 2**  
Ajoute cette configuration dans **`application.yml`** :
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://your-keycloak.com/realms/myrealm
```

#### 3️⃣ **Restreindre les accès aux endpoints protégés par OAuth 2**
Dans **Spring Security**, protège certains endpoints avec JWT :

```java
@Configuration
@EnableWebSecurity
public class OAuth2SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/user/**").authenticated() // OAuth 2 requis
                .requestMatchers("/api/admin/**").hasRole("ADMIN") // Rôle ADMIN requis
                .anyRequest().permitAll()
            )
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }
}
```

---

## 🛠 **3. Architecture hybride MTLS + OAuth 2**  
### **🌐 Organisation des endpoints**
| Endpoint | Sécurisé avec |
|----------|--------------|
| `/internal/**` | **MTLS** (authentification mutuelle des microservices) |
| `/api/user/**` | **OAuth 2** (JWT des utilisateurs) |
| `/api/admin/**` | **OAuth 2** (JWT avec rôle ADMIN) |

### **📌 Cas d’usage**
- Un **microservice A** appelle un **microservice B** → **MTLS** est requis.
- Un **utilisateur** accède à une API via une **SPA (Angular)** → **OAuth 2 (JWT)** est utilisé.
- Un **admin** accède à une page de gestion → **OAuth 2 avec rôle ADMIN** est requis.

---

### ✅ **Conclusion**
- **MTLS** protège les endpoints critiques accessibles uniquement par d’autres services authentifiés.
- **OAuth 2** protège les endpoints accessibles aux utilisateurs.
- Les deux coexistent et peuvent être activés indépendamment en fonction des besoins.

Besoin d’un exemple plus détaillé avec du code spécifique ? 😊
