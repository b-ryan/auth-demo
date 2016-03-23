(ns auth-test.core
  (:require [buddy.core.keys :as ks]
            [buddy.sign.jws :as jws]
            [clj-time.core :as t]
            [clj-yaml.core :as yaml])
  (:import clojure.lang.ExceptionInfo)
  (:gen-class))

;; creating a private key:
;;
;; openssl genrsa -aes128 -out auth_privkey.pem 2048
;; openssl rsa -pubout -in auth_privkey.pem -out auth_pubkey.pem
;;
;; make the password "password"

(def alg :rs256)
(def priv-key (ks/private-key "auth_privkey.pem" "password"))
(def pub-key (ks/public-key "auth_pubkey.pem"))
(def expiration-time (t/days 3))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TOKEN CREATION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn sign
  [roles {:keys [client-id cross-client-access]}]
  (let [expiration (t/plus (t/now) expiration-time)
        payload {:roles roles
                 :client-id client-id
                 :cross-client-access cross-client-access}]
    (jws/sign payload priv-key {:alg alg :exp expiration})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AUTHENTICATION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- unsign
  "Checks the signature on the token and returns the body of the token when
  the signature is valid. Otherwise returns nil."
  [token]
  (try
    (jws/unsign token pub-key {:alg alg})
    (catch ExceptionInfo e)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; AUTHORIZATION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def policy
  "This could be stored in S3 and re-fetched every X minutes. Doing so will
  allow us to continue using the policy we received at start-up and if the
  fetch from S3 fails, just continue using the old policy until we successfully
  re-fetch."
  (yaml/parse-string (slurp "policy.yaml") false))

(defn roles-intersect?
  [allowed-roles request-roles]
  (seq (clojure.set/intersection (set allowed-roles)
                                 (set request-roles))))

(defn authorized?
  [route unsigned-token]
  (let [service-name "service_1"
        service-policy (get policy service-name)
        allowed-roles (get service-policy route)
        request-roles (get unsigned-token :roles)]
    (when-not allowed-roles
      (throw (ex-info "no permissions defined for route" {:route route})))
    (roles-intersect? allowed-roles request-roles)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; DEMONSTRATION
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def routes
  {"GET /clients/:client-id/resources"
   (fn
     [unsigned-token params]
     (if (or (:cross-client-access unsigned-token)
             (= (:client-id params) (:client-id unsigned-token)))
       "200: CLIENT"
       "403: wrong client"))

   "POST /resource"
   (fn
     [unsigned-token params]
     "201: NEW")

   "GET /resources"
   (fn
     [unsigned-token params]
     "200: ALL")})

(def test-tokens
  {"gibberish_token" "nthaoeunthaeust"
   "client_2_admin_token" (sign #{"admin_user"} {:client-id 2})
   "client_2_normal_token" (sign #{"normal_user"} {:client-id 2})
   "backend_process_token" (sign #{"backend_process"} {:cross-client-access true})})

(defn request
  [route test-token-name params]
  (printf "%-33s | token: %22s | params: %15s | result: %s"
          route
          test-token-name
          params
          (if-let [unsigned-token (unsign (get test-tokens test-token-name))]
            (if (authorized? route unsigned-token)
              ((get routes route) unsigned-token params)
              "403: roles mismatch")
            "401: invalid token"))
  (newline))

(defn -main
  [& args]
  (let [route "GET /clients/:client-id/resources"
        params {:client-id 2}]
    (request route "gibberish_token" params)
    (request route "client_2_admin_token" params)
    (request route "client_2_normal_token" params)
    (request route "backend_process_token" params))

  (newline)

  (let [route "GET /clients/:client-id/resources"
        params {:client-id 3}]
    (request route "gibberish_token" params)
    (request route "client_2_admin_token" params)
    (request route "client_2_normal_token" params)
    (request route "backend_process_token" params)) 

  (newline)

  (let [route "POST /resource"
        params {}]
    (request route "gibberish_token" params)
    (request route "client_2_admin_token" params)
    (request route "client_2_normal_token" params)
    (request route "backend_process_token" params))

  (newline)

  (let [route "GET /resources"
        params {}]
    (request route "gibberish_token" params)
    (request route "client_2_admin_token" params)
    (request route "client_2_normal_token" params)
    (request route "backend_process_token" params))
  )
