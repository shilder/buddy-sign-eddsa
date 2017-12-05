# buddy-sign-eddsa

Library providing EdDSA support for buddy library

## Usage

Library extends `buddy-core` and `buddy-sign` functions to provide
EdDSA JWS signatures.

All heavy lifting is done by https://github.com/str4d/ed25519-java
and https://github.com/funcool/buddy

Library also implements loading of JWK files for Ed25519 curve

## Examples ##

Generating JWS token

```
(require '[buddy.contrib.eddsa :as eddsa])
(require '[buddy.contrib.jwk :as jwk])
(require '[buddy.sign.jws :as jws])

(def key "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",
\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",
\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}")

(let [jwk (jwk/parse-string key)
      payload "Example of Ed25519 signing"
      {:keys [public private]} (jwk/jwk->keypair jwk)
      token (jws/sign payload private {:alg :eddsa
                                       :key private})]
  token)
```

Generate key and save it in file

```
(require '[buddy.contrib.eddsa :as eddsa])
(require '[buddy.contrib.jwk :as jwk])

(let [key (.getPrivate (eddsa/generate-keypair-ed25519))]
  (jwk/write-file key "key.jwk"))
```

Load key from file and sign message

```
(require '[buddy.contrib.eddsa :as eddsa])
(require '[buddy.contrib.jwk :as jwk])
(require '[buddy.core.codecs :as codecs])
(require '[buddy.core.dsa :as dsa])

(let [key (jwk/parse-file "key.jwk")
      {:keys [public private]} (jwk/jwk->keypair key)]
  (codecs/bytes->hex (dsa/sign "Hello" {:alg :eddsa :key private})))
```

JWS Backend setup

```
(buddy.auth.backends/jws
   {:secret  (:public keypair)
    :options {:alg :eddsa}})
```
