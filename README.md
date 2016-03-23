# auth-test

## Usage

```
lein run
```

## Sample Output

```
GET /clients/:client-id/resources | token:        gibberish_token | params:  {:client-id 2} | result: 401: invalid token
GET /clients/:client-id/resources | token:   client_2_admin_token | params:  {:client-id 2} | result: 200: CLIENT
GET /clients/:client-id/resources | token:  client_2_normal_token | params:  {:client-id 2} | result: 200: CLIENT
GET /clients/:client-id/resources | token:  backend_process_token | params:  {:client-id 2} | result: 200: CLIENT

GET /clients/:client-id/resources | token:        gibberish_token | params:  {:client-id 3} | result: 401: invalid token
GET /clients/:client-id/resources | token:   client_2_admin_token | params:  {:client-id 3} | result: 403: wrong client
GET /clients/:client-id/resources | token:  client_2_normal_token | params:  {:client-id 3} | result: 403: wrong client
GET /clients/:client-id/resources | token:  backend_process_token | params:  {:client-id 3} | result: 200: CLIENT

POST /resource                    | token:        gibberish_token | params:              {} | result: 401: invalid token
POST /resource                    | token:   client_2_admin_token | params:              {} | result: 201: NEW
POST /resource                    | token:  client_2_normal_token | params:              {} | result: 403: roles mismatch
POST /resource                    | token:  backend_process_token | params:              {} | result: 201: NEW

GET /resources                    | token:        gibberish_token | params:              {} | result: 401: invalid token
GET /resources                    | token:   client_2_admin_token | params:              {} | result: 403: roles mismatch
GET /resources                    | token:  client_2_normal_token | params:              {} | result: 403: roles mismatch
GET /resources                    | token:  backend_process_token | params:              {} | result: 200: ALL
```
