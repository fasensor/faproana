(ns ntestoc.ana-db
  (:require [datalevin.core :as d]
            [ntestoc.utils :refer [remove-nils]]))

(def ana-db-schema { ;; 指定identity, 如果ip相同，后面的写入就是更新(upsert)
                    :ip {:db/unique :db.unique/identity}})

(defn get-conn
  [target]
  (d/get-conn target ana-db-schema))

(defn close
  [conn]
  (d/close conn))

(defn clear-db!
  [conn]
  (d/clear conn))

(defn transact!
  "插入或更新多条数据，如果:ip字段相同则更新"
  [conn datas]
  (->> datas
       (map remove-nils)
       (d/transact! conn)))

(defn get-info-by-id
  [conn id]
  (-> (d/pull (d/db conn) '[*] id)
      (dissoc :db/id)))

(defn get-all-ip-info
  [conn]
  (some->> (d/q '[:find [?e ...]
                  :where
                  [?e :ip]]
                (d/db conn))
           (map #(get-info-by-id conn %))))

(defn get-info-by-ip
  [conn ip]
  (some->> (d/q '[:find ?e
                  :in $ ?ip
                  :where
                  [?e :ip ?ip]]
                (d/db conn)
                ip)
           ffirst
           (get-info-by-id conn)))

(defn q
  [conn query & args]
  (apply d/q query (d/db conn) args))

(defn get-total
  [conn]
  (q conn '[:find (count ?e)
            :where
            [?e :ip]]))

(defn get-rdp-scanners
  [conn]
  (->> (q conn
          '[:find [?e ...]
            :where
            [?e :ip ?ip]
            [?e :tag ?tag]
            [(contains? ?tag "rdp scanner")]])
       (map #(get-info-by-id conn %1))))

(defn get-tcp-breadth
  [conn]
  (->> (q conn '[:find [?e ...]
                 :where
                 [?e :ip ?ip]
                 [?e :tcp_breadth ?tb]])
       (map #(get-info-by-id conn %))))

(defn get-tagged-ip-total
  [conn]
  (q conn '[:find (count ?e)
            :where
            [?e :tag ?tag]]))

(defn get-breadth-ip-total
  [conn]
  (q conn '[:find (count ?e)
            :where
            [?e :breadth ?breadth]]))

(defn get-asn-all
  [conn asn]
  (q conn '[:find ?e ?ip ?tag
            :keys id ip tag
            :in $ ?asn
            :where
            [?e :ip ?ip]
            [?e :tag ?tag]
            [?e :asn ?asn]]
     asn))

(defn get-status
  [conn]
  (some->> (d/q '[:find ?e
                  :where
                  [?e :status]]
                (d/db conn))
           ffirst
           (get-info-by-id conn)))
