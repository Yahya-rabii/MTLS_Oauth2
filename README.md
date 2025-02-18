

---

## 📌 **1. `application.yml` - Configure SSL and OAuth 2**
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
    client-auth: NEED # Enforce MTLS for clients

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://your-keycloak.com/realms/myrealm # Change this to your identity provider
```

---

## 📌 **2. `MTLSFilter.java` - Enforce MTLS for `/internal/**`**
```java
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.security.cert.X509Certificate;

@Component
@Order(1) // Ensures this filter runs first before Spring Security
public class MTLSFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI();

        // Apply MTLS only for "/internal/**" endpoints
        if (requestURI.startsWith("/internal/")) {
            X509Certificate[] certs = (X509Certificate[]) httpRequest.getAttribute("javax.servlet.request.X509Certificate");

            if (certs == null || certs.length == 0) {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Client certificate required for internal API");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
```

---

## 📌 **3. `SecurityConfig.java` - Configure Spring Security for OAuth 2**
```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/internal/**").authenticated() // MTLS is enforced via MTLSFilter
                .requestMatchers("/api/user/**").authenticated() // OAuth2 JWT required
                .requestMatchers("/api/admin/**").hasRole("ADMIN") // OAuth2 + Role required
                .anyRequest().permitAll() // Public endpoints
            )
            .oauth2ResourceServer(oauth2 -> oauth2.jwt()); // Enforce OAuth2 JWT for non-MTLS endpoints

        return http.build();
    }
}
```

---

## 📌 **4. How It Works**
| Endpoint | Security Mechanism | Enforcement |
|----------|-------------------|-------------|
| `/internal/**` | **MTLS (Client Certificate Required)** | Checked in `MTLSFilter` |
| `/api/user/**` | **OAuth 2 (JWT Required)** | Enforced by Spring Security |
| `/api/admin/**` | **OAuth 2 (JWT + Role Required)** | Enforced by Spring Security |
| `/public/**` | **No Security** | Accessible to everyone |

---

## 📌 **5. Generate Keystore & Truststore (MTLS Certificates)**
Use these commands to generate your server keystore and truststore.

```sh
# Generate Server Keystore (for Spring Boot)
keytool -genkey -alias server -keyalg RSA -keystore server-keystore.jks -storepass changeit -validity 365

# Generate Truststore (for Client Certificates)
keytool -import -alias client -file client-cert.pem -keystore truststore.jks -storepass changeit
```

---

## ✅ **Conclusion**
- **MTLS is enforced first via `MTLSFilter`** for `/internal/**`.  
- **OAuth 2 is applied for user/admin APIs** via Spring Security.  
- **Public endpoints remain open**.  

This **cleanly separates** both security mechanisms within the same Spring Boot project.

Would you like to see a **full example with a test client**? 🚀
