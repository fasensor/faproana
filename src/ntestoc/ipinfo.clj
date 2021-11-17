(ns ntestoc.ipinfo
  (:require [netlib.whois :refer [whois-ip]]
            [datalevin.core :as d]
            [netlib.dns :as dns]
            [common.wrap :refer [with-exception-default]]
            [mount.core :refer [defstate]]
            [ntestoc.utils :refer [remove-nils]]
            [netlib.asn :refer [get-asn]]))

(def ipinfo-db-schema { ;; 指定identity, 如果ip相同，后面的写入就是更新(upsert)
                       :ip {:db/unique :db.unique/identity}})

(defstate conn
  :start (d/get-conn ".ipinfo_db" ipinfo-db-schema)
  :stop (d/close conn))

(defn transact!
  "插入或更新多条数据，如果:ip字段相同则更新"
  [datas]
  (->> datas
       (map remove-nils)
       (d/transact! conn)))

(defn get-info-by-id
  [id]
  (-> (d/pull (d/db conn) '[*] id)
      (dissoc :db/id)))

(defn get-info-by-ip
  [ip]
  (some-> (d/q '[:find ?e
                 :in $ ?ip
                 :where
                 [?e :ip ?ip]]
               (d/db conn)
               ip)
          ffirst
          get-info-by-id))

(defn get-ip-info
  [ip]
  (if-let [info (get-info-by-ip ip)]
    (dissoc info :ip)
    (let [asn-info (try
                     (-> (get-asn ip)
                         (select-keys [:asn :org]))
                     (catch Exception _))]
      (when asn-info
        (let [data (assoc asn-info
                          :rdns (dns/rev-lookup ip))]
          (try
            (transact! [(assoc data :ip ip)])
            (catch Exception _))
          data)))))

