package com.example.springsecuritymultitenancy;

import java.time.Duration;

public class CannedData {

    public static final String BEARER_ADMIN = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Im9PZ1pOMDRlaDBZMi1DY1U0RE15TSJ9.eyJpc3MiOiJodHRwczovL2FydGh1ci1kZXYuYXUuYXV0aDAuY29tLyIsInN1YiI6Ik5PV3ZPSTFXUjY2bWJBN2xkWG05RFJRdlR5VDNaZ0x3QGNsaWVudHMiLCJhdWQiOiJodHRwczovL2FydGh1ci1kZXYuY29tLmF1L2FkbWluIiwiaWF0IjoxNjE1ODA5MTc1LCJleHAiOjE2MTU4OTU1NzUsImF6cCI6Ik5PV3ZPSTFXUjY2bWJBN2xkWG05RFJRdlR5VDNaZ0x3Iiwic2NvcGUiOiJyZWFkOmdyZWV0aW5ncyB3cml0ZTpncmVldGluZ3MiLCJndHkiOiJjbGllbnQtY3JlZGVudGlhbHMifQ.j2aoqgByOrLyt-z-CXQajPzsMDCyiMzBHK5cq3tzdYbdrPkfjuHyDpv7NzWD5bmErSzV5B00VN-0-er5NPjm0UW1GVZ6hQIHbpZieXq4rTBI5ExU_bpuRUewKql-lONaG2abrcAboF6AKPEveKYEjc86xodh4vmH9MocDzZIZc3rbpXqNWg8ev2nSlrQcebPyOwSb--s3XisDmGQ1RK9d_Zi9FPBtWSrByTUOfc0aOZeC15DmzVAGAvjySBpLR1C7xpBO6LwAyj0tCK3ISD--LrbjE9-DQhORZQ8_MNDFmwAwvGWk4qFPujHpNx2oti5IY-LmL3jDtcRB3p23DuT6Q";
    public static final String BEARER_USER = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlVhVWlCQnVmM3pfdk83OGNwVlJZQSJ9.eyJpc3MiOiJodHRwczovL2FydGh1ci1kZXYtYWx0LmF1LmF1dGgwLmNvbS8iLCJzdWIiOiJ1akgydUFMZ2duNVQ2WHM0R2h0clQ2OEhTelBTcFh1M0BjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9hcnRodXItZGV2LmNvbS5hdS91c2VyIiwiaWF0IjoxNjE1ODA5MDgxLCJleHAiOjE2MTU4OTU0ODEsImF6cCI6InVqSDJ1QUxnZ241VDZYczRHaHRyVDY4SFN6UFNwWHUzIiwic2NvcGUiOiJyZWFkOmdyZWV0aW5ncyIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.t9g5EWW4j9m4Q04YtZXwYc8hrExANUQW47cVxFQRFpRjMIE38sNf_3N48nR34lBrEs6DZFDK50EfC6EJPDCmjMkJKYLi4tZKT2tjGV7CQ3Y-xwqveVeY2SzpiBsIbOikFe6BuRf0cTrTqcXoQ0wBOlTg7J3-mFRAFjSVL42_dGg9qSMKGu830phgHpxEGbPR8Xs7CoJo0b3Z2FTspL7b9tSOgTUAcr6pilx1-fBHU7PqrwzwldwaGu9INvbfpfefmm9PJVbKWHwn7sHDNZhFt5BHRxViv-6YrF5C-DrWjf_uqM17NvUEnZd3eMhUTLgXuqvzk4nGrJDkpe6bYUlKEw";

    public static MultipleIdps validMultipleIdps() {
        return new MultipleIdps(
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/admin",
                        "https://arthur-dev.au.auth0.com/",
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(15),
                        "https://arthur-dev.au.auth0.com/.well-known/jwks.json"),
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/user",
                        "https://arthur-dev-alt.au.auth0.com/",
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(15),
                        "https://arthur-dev-alt.au.auth0.com/.well-known/jwks.json"));
    }

    public static MultipleIdps randomMultipleIdps() {
        return new MultipleIdps(
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/admin",
                        "https://example.com/",
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(10),
                        "https://example.com/.well-known/jwks.json"),
                new MultipleIdps.OAuth2IdpConfig(
                        "https://arthur-dev.au.auth0.com/user",
                        "https://coco.com/",
                        Duration.ofMinutes(30),
                        Duration.ofMinutes(10),
                        "https://coco.com/.well-known/jwks.json"));
    }
}
