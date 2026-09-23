# JWT Validator API

A RESTful service built with Spring Boot and Java 25 that validates incoming JSON Web Tokens (JWTs).

The application parses incoming tokens, checks expiration and issuance timestamps, fetches the public X.509 certificate dynamically from the URL in the `x5u` header claim, and verifies the RSA signature. Throws standard HTTP error codes.

---

## Prerequisites

* Java 25 (or JDK 17+)
* Apache Maven
* Spring Boot 3.2.3
* JJWT (`io.jsonwebtoken` 0.12.5)

---

## How to Run

1. Clone the repository:

```bash
git clone [https://github.com/tmh0n3y/jwt-validator-api.git](https://github.com/tmh0n3y/jwt-validator-api.git)
cd jwt-validator-api
```

2. Start the application using Maven:

```bash
mvn spring-boot:run
```

The server runs on **`http://localhost:8081`** (configured in `src/main/resources/application.properties` to prevent port conflicts).

---

## API Reference

### Endpoint

`GET /auth`

### Headers

| Header | Value | Required |
| :--- | :--- | :--- |
| `Authorization` | `Bearer <token>` | Yes |
| `Accept` | `application/json` | Yes |

---

## Example Usage

Test the endpoint using `curl`:

```bash
curl -i -X GET http://localhost:8081/auth \
  -H "Accept: application/json" \
  -H "Authorization: Bearer <YOUR_JWT_HERE>"
```