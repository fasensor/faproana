(ns ntestoc.rule
  (:require [taoensso.timbre :as log]
            [clojure.core.async :as async]
            [flatland.ordered.map :refer [ordered-map]]
            [ntestoc.config :refer [env]]
            [ntestoc.ipinfo :refer [get-ip-info]]
            [mount.core :refer [defstate]]
            [ntestoc.config :refer [env]]
            [com.climate.claypoole :as cp]
            [ntestoc.db :as db])
  (:use [ntestoc.es-utils]))

(def rules (atom (ordered-map)))

(defstate total-host
  :start (or (:total-fapro-hosts env) 33))

(defn get-rule
  [rule-name]
  (get @rules rule-name))

(defn get-rules
  []
  (map second @rules))

(defn get-visible-rules
  []
  (->> (get-rules)
       (filter (comp not :hidden))))

(defn defrule
  "定义规则
  `hidden`: 是否为可显示的tag 规则， 如果为true，则不显示 （用于内部使用）
  `type`: 规则类型， :ip 为单ip规则, :full 为应用所有数据的规则
  `query`: 规则的查询语句: 如果为:ip类型的规则， query接受一个ip参数，返回查询map
          {:query 查询语句
           :days 数据查询的天数
           :opts 额外查询参数}
          如果是:full类型的规则, query接受一个remote_ip分页aggs配置，返回查询map
  `check-fn`: 规则的测试语句，
              type为:ip, 则check-fn的参数为查询语句的结果,返回为map,则保存此数据， 返回nil或false 表示不匹配此规则

              如果type为:full，check-fn的参数为每次分页的查询结果，
              返回结果为包含此规则的ip列表，每个列表项为{:ip \"1.2.3.4\" :data {:test 1}}
              :date 为包含的附加数据，如果没有:data只应用此规则。
  `days`: 查询的天数，如果type为:ip,则不需要指定
  `highlight`: 是否高亮显示
  `intention`: 意图， good 良好，malicious 恶意, unknown 未知
  `references`: 规则引用的文章
  `cves`: 规则引用的cve
  `category`: 规则类型: :tool 工具 :worm 蠕虫 :actor 角色 :activity 活动
  `description`: 规则的简短描述"
  [rule-name {:keys [category
                     intention
                     description
                     references
                     highlight
                     cves
                     type
                     query
                     hidden
                     check-fn]
              :as rule}]
  (swap! rules assoc rule-name (assoc rule :name rule-name)))

(defn host-count->ten-percent
  [n]
  (int (/ (* 10 (inc n)) total-host)))

(defrule "default ip info"
  {:hidden true
   :description "define default ip info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "remote_ip:%s" ip)
             :opts {:aggs {:hosts {:terms {:field "host.keyword"
                                           :size 200}}
                           :ports {:terms {:field "local_port"
                                           :size 65536}}
                           :protocols {:terms {:field "protocol.keyword"
                                               :size 20000}}}
                    :size 1}})
   :check-fn (fn [data]
               (let [hosts (db/get-aggs-buckets-keys data :hosts)
                     ports (db/get-aggs-buckets-keys data :ports)]
                 {:host hosts
                  :port ports
                  :port_total (count ports)
                  :protocol (db/get-aggs-buckets-keys data :protocols)
                  :breadth (host-count->ten-percent (count hosts))
                  :timestamp (-> (db/get-first-hits-source data)
                                 (get (keyword "@timestamp")))}))})

(defn format-aggs-count
  [buckets]
  (mapv (fn [{:keys [key doc_count]}]
          {:count doc_count
           :value key})
        buckets))

(defn format-aggs
  [agg use-unknown?]
  (let [unknown (:sum_other_doc_count agg)
        data (format-aggs-count (:buckets agg))]
    (cond-> data
      (and use-unknown?
           (pos? unknown)) (conj {:value "unknown"
                                  :count unknown} ))))

(defn get-aggs-buckets-data
  "获取aggs结果"
  ([aggs agg-key] (get-aggs-buckets-data aggs agg-key false))
  ([aggs agg-key use-unknown?]
   (-> (db/get-aggs aggs agg-key)
       (format-aggs use-unknown?))))

(defrule "ip icmp ping"
  {:hidden true
   :description "ip ping info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (message.keyword:\"icmp_ping\")" ip)
             :opts {:size 0
                    :track_total_hits true}})
   :check-fn (fn [data]
               (let [total (db/get-hits-total data)]
                 (when (pos? total)
                   {:ping_times total})))})

(defrule "ip syn info"
  {:hidden true
   :description "ip syn info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (message.keyword:\"tcp_syn\")" ip)
             :opts {:aggs {:hosts {:terms {:field "host.keyword"
                                           :size 200}}
                           :ports {:terms {:field "local_port"
                                           :size 65536}}}}})
   :check-fn (fn [data]
               (let [hosts (get-aggs-buckets-data data :hosts)
                     ports (get-aggs-buckets-data data :ports)]
                 {:syn_host hosts
                  :syn_breadth (host-count->ten-percent (count hosts))
                  :syn_port ports
                  :syn_port_total (count ports)}))})

(defrule "ip tcp conn info"
  {:hidden true
   :description "ip tcp conn info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (message.keyword:\"new conn\")" ip)
             :opts {:aggs {:hosts {:terms {:field "host.keyword"
                                           :size 200}}
                           :protocols {:terms {:field "protocol.keyword"
                                               :size 2000}}
                           :ports {:terms {:field "local_port"
                                           :size 65536}}}}})
   :check-fn (fn [data]
               (let [hosts (get-aggs-buckets-data data :hosts)
                     ports (get-aggs-buckets-data data :ports)]
                 {:tcp_host hosts
                  :tcp_port ports
                  :tcp_port_total (count ports)
                  :tcp_breadth (host-count->ten-percent (count hosts))
                  :tcp_protocol (get-aggs-buckets-data data :protocols)}))})

(defrule "ip udp packet info"
  {:hidden true
   :description "ip udp packet info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (transport.keyword:\"udp\")" ip)
             :opts {:aggs {:hosts {:terms {:field "host.keyword"
                                           :size 200}}
                           :protocols {:terms {:field "protocol.keyword"
                                               :size 2000}}
                           :rports {:terms {:field "remote_port"
                                            :size 65536}}
                           :ports {:terms {:field "local_port"
                                           :size 65536}}}}})
   :check-fn (fn [data]
               (let [hosts (get-aggs-buckets-data data :hosts)
                     ports (get-aggs-buckets-data data :ports)]
                 {:udp_host hosts
                  :udp_port ports
                  :udp_port_total (count ports)
                  :udp_breadth (host-count->ten-percent (count hosts))
                  :udp_rport (get-aggs-buckets-data data :rports)
                  :udp_protocol (get-aggs-buckets-data data :protocols)}))})

(defrule "http request info"
  {:hidden true
   :description "get all http requests info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (base:http) AND (message:request)" ip)
             :opts {:aggs {:uris {:terms {:field "uri.keyword"
                                          :size 20000}}
                           :user_agents {:terms {:field "headers.User-Agent.keyword"
                                                 :size 1000}}}
                    :size 0}})
   :check-fn (fn [data]
               (let [urls (db/get-aggs-buckets-keys data :uris)]
                 (when (seq urls)
                   {:http_url urls
                    :user_agent (db/get-aggs-buckets-keys data :user_agents)})))})

(defn find-http-url
  [s]
  (re-find #"https?:\/\/[^\s]+" s))

(defrule "redis command http info"
  {:hidden true
   :description "get redis command args http url info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (protocol:redis) AND (cmd:set)" ip)
             :opts {:aggs {:args {:terms {:field "args.keyword"
                                          :size 20000}}}
                    :size 0}})
   :check-fn (fn [data]
               (let [urls (->> (db/get-aggs-buckets-keys data :args)
                               (map find-http-url)
                               (filter identity)
                               set)]
                 (when (seq urls)
                   {:redis_url urls})))})

(defrule "mysql query url info"
  {:hidden true
   :description "get mysql query args http url info"
   :type :ip
   :days 1
   :query (fn [ip]
            {:query (format "(remote_ip:%s) AND (protocol:mysql) AND (message.keyword:\"execute query\")" ip)
             :opts {:aggs {:queries {:terms {:field "query.keyword"
                                             :size 20000}}}
                    :size 0}})
   :check-fn (fn [data]
               (let [urls (->> (db/get-aggs-buckets-keys data :queries)
                               (map find-http-url)
                               (filter identity)
                               set)]
                 (when (seq urls)
                   {:mysql_url urls})))})

(defn tcp-syn-query
  ([] (tcp-syn-query 1 "1m"))
  ([days interval]
   (fn [ip]
     {:query (format "(remote_ip:%s) AND (message.keyword:tcp_syn)" ip)
      :days days
      :opts {:aggs {:syn_times {:date_histogram {:field "@timestamp"
                                                 :order {:_count "desc"}
                                                 :fixed_interval interval}
                                :aggs {:top1 {:bucket_sort {:size 1}}}}
                    :hosts {:terms {:field "host.keyword"
                                    :size 200}}
                    :ports {:terms {:field "local_port"
                                    :size 65536}}}
             :size 0}})))

(defn get-first-doc-count
  [data]
  (or (:doc_count (first data))
      0))

(defrule "tcp syn scanner"
  {:category "activity"
   :intention "unknown"
   :description "scan ports on server"
   :query (tcp-syn-query)
   :type :ip
   :check-fn (fn [data]
               (let [syn-max (-> (db/get-aggs-buckets data :syn_times)
                                 get-first-doc-count)]
                 (> syn-max 5)))})

(defrule "massive hosts scanner"
  {:category "activity"
   :intention "unknown"
   :description "massive hosts scanner"
   :type :ip
   :query (tcp-syn-query 5 "1d")
   :check-fn (fn [data]
               (let [hosts (db/get-aggs-buckets-keys data :hosts)]
                 (when (> (count hosts) 3)
                   {:mass_host hosts
                    :mass_port (db/get-aggs-buckets-keys data :ports)})))})

(defrule "spoofable"
  {:hidden true
   :description "check ip spoofable"
   :type :full
   :days 1
   :query (fn [ip-conf]
            {:query "(message.keyword:\"new conn\")"
             :size 0
             :opts {:aggs {:remotes {:terms ip-conf}}
                    :size 0}})
   :check-fn (fn [data]
               (->> (db/get-aggs-buckets-keys data :remotes)
                    (map #(hash-map :ip % :data {:real true}))))})

(def ip-asn-pool (cp/threadpool 20 :name "ip-asn-task"))

(defrule "ip asn info"
  {:hidden true
   :description "get ip asn info"
   :type :full
   :days 1
   :query (fn [ip-conf]
            {:query "*"
             :size 0
             :opts {:aggs {:remotes {:terms ip-conf}}
                    :size 0}})
   :check-fn (fn [data]
               (let [ips (db/get-aggs-buckets-keys data :remotes)
                     get-asn (fn [ip]
                               (when-let [info (get-ip-info ip)]
                                 {:ip ip
                                  :data info}))]
                 (->> (cp/pmap ip-asn-pool
                               get-asn
                               ips)
                      (filter identity))))})

(defn protocol-query
  ([protocol q] (protocol-query protocol q 1 "1m"))
  ([protocol q days interval]
   (fn [ip]
     {:query (format "(remote_ip:%s) AND (protocol.keyword:%s) AND (%s)" ip protocol q)
      :track_total_hits true
      :days days
      :opts {:aggs {:times {:date_histogram {:field "@timestamp"
                                             :order {:_count "desc"}
                                             :fixed_interval interval}
                            :aggs {:top1 {:bucket_sort {:size 1}}}}
                    :hosts {:terms {:field "host.keyword"
                                    :size 200}}
                    :ports {:terms {:field "local_port"
                                    :size 65536}}}
             :size 0}})))

(defrule "rdp scanner"
  {:category "activity"
   :intention "unknown"
   :description "RDP Scanner"
   :type :ip
   :query (protocol-query "rdp" "message.keyword:\"new conn\"" 1 "1m")
   :check-fn (fn [data]
               (let [max-times (-> (db/get-aggs-buckets data :times)
                                   get-first-doc-count)]
                 (when (> max-times 5)
                   {:rdp_host (db/get-aggs-buckets-keys data :hosts)
                    :rdp_port (db/get-aggs-buckets-keys data :ports)})))})

(defn def-brute-force
  [protocol]
  (defrule (format "%s brute force" protocol)
    {:category "activity"
     :intention "unknown"
     :description (format "%s login brute force" protocol)
     :type :ip
     :query (protocol-query protocol "message.keyword:\"login failed\"" 1 "10m")
     :check-fn (fn [data]
                 (let [max-times (-> (db/get-aggs-buckets data :times)
                                     get-first-doc-count)]
                   (when (> max-times 10)
                     {(keyword (format "%s_login_attempts" protocol)) (db/get-hits-total data)})))}))

(def-brute-force "rdp")
(def-brute-force "smb")
(def-brute-force "ssh")
(def-brute-force "mysql")
(def-brute-force "telnet")
(def-brute-force "dcerpc")
(def-brute-force "ftp")
(def-brute-force "smtp")

