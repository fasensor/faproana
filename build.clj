(ns build
  (:require [clojure.tools.build.api :as b]
            [org.corfield.build :as bb]))

(def lib 'ntestoc/proana)

(def version "0.0.3")

(defn uber "uber jar"
  [opts]
  (-> opts
      (assoc :lib lib :main 'ntestoc.proana)
      (bb/clean)
      (bb/uber)))

(defn install "Install the JAR locally."
  [opts]
  (-> opts
      (assoc :lib lib :version version)
      (bb/install)))

