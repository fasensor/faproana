(ns ntestoc.es-utils)

(defn get-hits
  [data]
  (get-in data [:body :hits :hits]))

(defn get-aggs
  [data]
  (get-in data [:body :aggregations]))

