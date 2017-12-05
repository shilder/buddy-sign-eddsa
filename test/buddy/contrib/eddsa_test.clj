(ns buddy.contrib.eddsa-test
  (:require [clojure.test :refer :all]
            [buddy.contrib.jwk :as jwk]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.core.dsa :as dsa]
            [buddy.sign.jws :as jws])
  (:import (net.i2p.crypto.eddsa EdDSAPrivateKey EdDSAPublicKey)))

;; From RFC8037
(def key "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",
\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\",
\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}")

(deftest parse-key
  (let [jwk (jwk/parse-string key)]
    (is (= "Ed25519" (:crv jwk)))))

(deftest key-conversion
  (let [jwk (jwk/parse-string key)
        pair (jwk/jwk->keypair jwk)
        public (:public pair)
        private (:private pair)]

    (is (instance? EdDSAPrivateKey private))
    (is (instance? EdDSAPublicKey public))

    (testing "key roundtrip"
      (is (= "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
          (-> (.getSeed private)
              (b64/encode true)
              (codecs/bytes->str)))

      (is (= "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
          (-> (.getAbyte public)
              (b64/encode true)
              (codecs/bytes->str))))))

(deftest thumbprint-test
  (let [jwk (jwk/parse-string key)
        th (jwk/thumbprint jwk)]
    (is (= "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
           (-> th
               (b64/encode true)
               (codecs/bytes->str))))
    (is (= "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89"
           (codecs/bytes->hex th)))))

(deftest dsa-signing-verification-test
  (let [jwk (jwk/parse-string key)
        ;; Example from RFC
        payload "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
        {:keys [public private]} (jwk/jwk->keypair jwk)
        signature (dsa/sign payload {:alg :eddsa
                                     :key private})]
    (is (= "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
           (codecs/bytes->str (b64/encode signature true))))
    (is (dsa/verify payload signature {:alg :eddsa
                                       :key public}))))

(deftest jws-signing-and-verification-test
  (let [jwk (jwk/parse-string key)
        ;; Example from RFC
        payload "Example of Ed25519 signing"
        {:keys [public private]} (jwk/jwk->keypair jwk)
        token (jws/sign payload private {:alg :eddsa
                                         :key private})]

    (is (= "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
           token))))
