(ns buddy.contrib.jwk
  "JWK file reading writing and JCA conversions

   Supports only public/private key reading - no symmetric keys support available

   References:

   * https://tools.ietf.org/html/rfc7517
   * https://tools.ietf.org/html/rfc8037
   * https://www.iana.org/assignments/jose/jose.xhtml"
  (:require [clojure.java.io :as io]
            [cheshire.core :as json]
            [buddy.hashers :as hashers]
            [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs])
  (:import (java.io StringReader StringWriter)
           (com.fasterxml.jackson.core JsonGenerator)
           (java.security KeyPair)))

(defn parse-file [path]
  (with-open [r (io/reader path)]
    (json/parse-stream r true)))

(defn parse-string [^String string]
  (let [r (StringReader. string)]
    (json/parse-stream r true)))

(defprotocol JCA2JWK
  (jca->jwk [key] "Encodes JCA key in JWK-compatible format (returns clojure map)"))

(defmulti jwk->keypair
          {:arglists '([jwk])
           :doc      "Converts clojure map representing JWK object to
                      {:public  java.security.PublicKey
                       :private java.security.PrivateKey}"}
          :kty)

;; OKP type - curve specific
(defmulti jwkokp->keypair :crv)

(defmethod jwk->keypair "OKP"
  [object]
  (jwkokp->keypair object))

(defn load-keypair
  "Loads keypair from JWK file.

  Returns
  {:public  java.security.PublicKey
   :private java.security.PrivateKey}"
  [path]
  (jwk->keypair (parse-file path)))

(defn write-file
  "Writes JCA object representing key (PrivateKey or PublicKey) to file"
  [key file]
  (with-open [w (io/writer file)]
    (let [jwk (jca->jwk key)]
      (json/with-writer [w {}]
                        (json/write jwk)))))

(defmulti thumbprint
          {:arglists '([jwk])
           :tag      bytes
           :doc      "Calculates JWK thumbprint"}
          :kty)

;;https://tools.ietf.org/html/rfc8037#appendix-A.3
(defmethod thumbprint "OKP"
  [jwk]
  (let [w (StringWriter.)
        jg ^JsonGenerator (json/create-generator w)]
    (doto jg
      (.writeStartObject)
      (.writeStringField "crv" (:crv jwk))
      (.writeStringField "kty" (:kty jwk))
      (.writeStringField "x" (:x jwk))
      (.writeEndObject)
      (.flush))
    (hash/sha256 (str w))))
