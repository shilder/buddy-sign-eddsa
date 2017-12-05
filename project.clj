(defproject org.clojars.shilder/buddy-sign-eddsa "0.1.0"
  :description "EdDSA support for Buddy library"
  :url "https://github.com/shilder/buddy-sign"
  :license {:name "Apache 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [buddy/buddy-core "1.2.0"]
                 [buddy/buddy-hashers "1.2.0"]
                 [buddy/buddy-sign "2.2.0"]
                 [net.i2p.crypto/eddsa "0.2.0"]])
