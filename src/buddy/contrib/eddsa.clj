(ns buddy.contrib.eddsa
  (:require [buddy.core.dsa :as dsa]
            [buddy.sign.jws :as jws]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.contrib.jwk :as jwk])
  (:import (java.security Security Signature KeyPairGenerator SecureRandom)
           (net.i2p.crypto.eddsa EdDSAPrivateKey EdDSAPublicKey)
           (net.i2p.crypto.eddsa.spec EdDSANamedCurveTable EdDSAPrivateKeySpec EdDSAPublicKeySpec)
           (java.util Arrays)
           (clojure.lang Reflector)
           (java.lang.reflect Method)))

(when (nil? (Security/getProvider "EdDSA"))
  (Security/addProvider (net.i2p.crypto.eddsa.EdDSASecurityProvider.)))

;; append new algorithm
(alter-var-root #'dsa/+algorithms+
                assoc
                :eddsa #(Signature/getInstance "NONEwithEdDSA" "EdDSA"))

(alter-var-root #'jws/+signers-map+
                assoc
                :eddsa {:signer   #(dsa/sign %1 {:alg :eddsa :key %2})
                        :verifier #(dsa/verify %1 %2 {:alg :eddsa :key %3})})

(defn- ^SecureRandom get-secure-random []
  ;; use getInstanceStrong on Java 8 and above
  (if-let [^Method strong (first (Reflector/getMethods SecureRandom 0 "getInstanceStrong" true))]
    (.invoke strong SecureRandom (make-array Object 0))
    ;; Use default constructor on Java 7
    (SecureRandom.)))

;; Actually Ed25519 private key is just 32 random bytes (secure random generator expected)
;; public key is calculated from private key
(defn generate-keypair-ed25519 []
  (let [kg (KeyPairGenerator/getInstance "EdDSA" "EdDSA")]
    (.initialize kg
                 256
                 (get-secure-random))
    (.genKeyPair kg)))

(extend-protocol
  jwk/JCA2JWK
  EdDSAPrivateKey
  (jca->jwk [^EdDSAPrivateKey object]
    {:kty "OKP"
     :crv "Ed25519"
     :d   (-> (.getSeed object)
              (b64/encode true)
              (codecs/bytes->str))
     :x   (-> (.getAbyte object)
              (b64/encode true)
              (codecs/bytes->str))}))

(defmethod jwk/jwkokp->keypair "Ed25519"
  [jwk]
  (let [params (EdDSANamedCurveTable/getByName "Ed25519")
        seedhash (:d jwk)
        priv (EdDSAPrivateKey.
               (EdDSAPrivateKeySpec.
                 ^bytes (b64/decode seedhash)
                 params))
        pub (EdDSAPublicKey.
              (EdDSAPublicKeySpec.
                (.getA priv)
                params))
        ;; public key calculated from private key
        expected (.getAbyte priv)
        ;; public key from file
        actual ^bytes (b64/decode (:x jwk))]
    ;; Check for incorrect public key
    (when-not (Arrays/equals expected actual)
      (throw (ex-info "Public key doesn't match private key"
                      {:expected (codecs/bytes->hex expected)
                       :actual   (codecs/bytes->hex actual)})))
    {:public  pub
     :private priv}))

;; Monkey-patch header encoding for EdDSA header
(in-ns 'buddy.sign.jws)

(defn- encode-header
  [header]
  (-> header
      (update :alg #(if (= % :eddsa) "EdDSA" (str/upper-case (name %))))
      (json/generate-string)
      (b64/encode true)
      (codecs/bytes->str)))

(in-ns 'buddy.contrib.eddsa)
