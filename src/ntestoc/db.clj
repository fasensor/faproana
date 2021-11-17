(ns ntestoc.db
  (:require [qbits.spandex :as es]
            [cheshire.core :as json]
            [clojure.java.io :as io]
            [clojure.core.async :as async]
            [diehard.core :as dh]
            [mount.core :refer [defstate]]
            [ntestoc.config :refer [env]]
            [java-time :as jt]
            [taoensso.timbre :as log]
            [common.wrap :refer [with-exception-default]]
            [clojure.core.async :as async]))

;; top result number
(defstate top-num
  :start (or (:top-number env) 10))

(defn distinct-by
  "Returns a lazy sequence of the elements of coll, removing any elements that
  return duplicate values when passed to a function f. Returns a transducer
  when no collection is provided."
  ([f]
   (fn [rf]
     (let [seen (volatile! #{})]
       (fn
         ([] (rf))
         ([result] (rf result))
         ([result x]
          (let [fx (f x)]
            (if (contains? @seen fx)
              result
              (do (vswap! seen conj fx)
                  (rf result x)))))))))
  ([f coll]
   (let [step (fn step [xs seen]
                (lazy-seq
                 ((fn [[x :as xs] seen]
                    (when-let [s (seq xs)]
                      (let [fx (f x)]
                        (if (contains? seen fx)
                          (recur (rest s) seen)
                          (cons x (step (rest s) (conj seen fx)))))))
                  xs seen)))]
     (step coll #{}))))


(defstate db
  :start (es/client (:es-host env)))

(defn make-pipeline
  []
  (es/request db {:url "_ingest/pipeline/fapro-remote-ip"
                  :method :put
                  :body {:description "fapro remote_ip process"
                         :processors [{"geoip" {"field" "remote_ip",
                                                "ignore_missing" true,
                                                "target_field" "geoip",
                                                "properties" ["country_name",
                                                              "country_iso_code",
                                                              "region_name"
                                                              "city_name",
                                                              "location"]}},
                                      {"rename" {"field" "geoip.country_name",
                                                 "target_field" "country_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.region_name",
                                                 "target_field" "region_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.country_iso_code",
                                                 "target_field" "country_iso_code",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.city_name",
                                                 "target_field" "city_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.location",
                                                 "target_field" "location",
                                                 "ignore_missing" true
                                                 }},
                                      {"remove" {"field" "geoip",
                                                 "ignore_missing" true
                                                 }}]}}))

(defn make-ana-index
  []
  (log/info :make-ana-index-mapping)
  (es/request db {:url "_ingest/pipeline/fanas-ip"
                  :method :put
                  :body {:description "fanas ip process"
                         :processors [{"geoip" {"field" "ip",
                                                "ignore_missing" true,
                                                "target_field" "geoip",
                                                "properties" ["country_name",
                                                              "country_iso_code",
                                                              "region_name"
                                                              "city_name",
                                                              "location"]}},
                                      {"rename" {"field" "geoip.country_name",
                                                 "target_field" "country_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.region_name",
                                                 "target_field" "region_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.country_iso_code",
                                                 "target_field" "country_iso_code",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.city_name",
                                                 "target_field" "city_name",
                                                 "ignore_missing" true
                                                 }},
                                      {"rename" {"field" "geoip.location",
                                                 "target_field" "location",
                                                 "ignore_missing" true
                                                 }},
                                      {"remove" {"field" "geoip",
                                                 "ignore_missing" true
                                                 }}]}})
  (es/request db {:url "/fanas"
                  :method :put
                  :body {:mappings
                         {:properties
                          {:timestamp {"type" "date"}
                           :ip {"type" "ip"
                                "fields" {"keyword" {"type"
                                                     "keyword"}}}
                           "location" {"type" "geo_point"}
                           :syn_port {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :tcp_port {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :udp_port {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :syn_host {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :udp_host {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :tcp_host {:type "nested"
                                      :properties {:value {:type "keyword"}
                                                   :count {:type "long"} }}
                           :tcp_protocol {:type "nested"
                                          :properties {:value {:type "keyword"}
                                                       :count {:type "long"} }}}}}}))

(defn insert-ana-data
  ([datas] (insert-ana-data datas 0 1000))
  ([datas start batch]
   (let [writed (atom 0)]
     (doseq [ls (partition batch (drop start datas))]
       (dh/with-retry
         {:retry-on Exception
          :on-retry (fn [_ ex]
                      (prn "writed: " @writed ",error:" (es/decode-exception (ex-data ex)) " retrying...")
                      (Thread/sleep 100000))
          :on-success (fn [_]
                        (swap! writed + batch)
                        (prn "writed ok:" @writed))}
         (es/request db {:url "_bulk?"
                         :method :put
                         :headers {"Content-Type" "application/x-ndjson"}
                         :query-string {:pipeline "fanas-ip"}
                         :body (->> ls
                                    (mapcat #(vector {:create {:_index "fanas"}}
                                                     %))
                                    es/chunks->body)}))
       (Thread/sleep 5000)))))

(defn init-db
  []
  (log/info :make-fapro-index)
  (make-pipeline)
  (es/request db {:url "/fapro"
                  :method :put
                  :body {:mappings
                         {:properties
                          {"@timestamp" {"type" "date"}
                           "remote_ip" {"type" "ip"
                                        "fields" {"keyword" {"type"
                                                             "keyword"}}}
                           "location" {"type" "geo_point"}}}}}))

(defn load-data
  ([log-file-path] (load-data log-file-path 0 1000))
  ([log-file-path start-line batch]
   (with-open [rdr (io/reader log-file-path)]
     (let [writed (atom 0)]
       (doseq [ls (partition batch (drop start-line (line-seq rdr)))]
         (dh/with-retry
           {:retry-on Exception
            :on-retry (fn [_ ex]
                        (prn "writed: " @writed ",error:" ex " retrying...")
                        (Thread/sleep 100000))
            :on-success (fn [_] (swap! writed + batch))}
           (es/request db {:url "_bulk?"
                           :method :put
                           :headers {"Content-Type" "application/x-ndjson"}
                           :query-string {:pipeline "fapro-remote-ip"}
                           :body (->> ls
                                      (mapcat #(vector {:create {:_index "fapro"}}
                                                       (let [data (json/decode %)]
                                                         (-> (dissoc data "time")
                                                             (assoc "@timestamp" (get data "time"))))))
                                      es/chunks->body)}))
         (Thread/sleep 5000))))))

(def system-time-zone (str (jt/zone-id)))

(defn format-day
  [date]
  (->> (jt/instant (jt/truncate-to date :days) (jt/zone-id "GMT"))
       (jt/format (jt/formatter :iso-instant))))

(defn make-range
  [end-date days]
  (let [day (-> (jt/local-date (jt/formatter :iso-date) end-date)
                (jt/local-date-time 0 0))
        prev-day (-> (jt/minus day (jt/days days))
                     format-day)
        end-day (format-day day)]
    {"@timestamp"
     {:gte prev-day
      :lte end-day
      :format "strict_date_optional_time"}}))

(defn query-data-chan
  [q end-date days opts]
  (es/scroll-chan db {:url "/fapro/_search"
                  :method :post
                  :body (merge
                         {:query
                          {:bool
                           {:must
                            [{:range (make-range end-date days)}
                             {:query_string {:query q}}
                             ]}}}
                         {:size 10
                          :sort [{"@timestamp" {:order "desc"}}]}
                         opts)}))
(defn query-data
  [q end-date days opts]
  (dh/with-retry
    {:retry-on Exception
     :on-retry (fn [_ ex]
                 (log/warn :query-data q :opts opts :end-date end-date "error:" (es/decode-exception (ex-data ex)) "retrying...")
                 (Thread/sleep 5000))}
    (es/request db {:url "/fapro/_search"
                    :method :post
                    :body (merge
                           {:query
                            {:bool
                             {:must
                              [{:range (make-range end-date days)}
                               {:query_string {:query q}}
                               ]}}}
                           {:size 10
                            :sort [{"@timestamp" {:order "desc"}}]}
                           opts)}))
  )

(defn query-ana
  [q days opts]
  (dh/with-retry
    {:retry-on Exception
     :on-retry (fn [_ ex]
                 (log/error :query-ans "error:" (es/decode-exception (ex-data ex)) "retrying...")
                 (Thread/sleep 5000))}
    (es/request db {:url "/fanas/_search"
                    :method :post
                    :body (merge
                           {:query
                            {:bool
                             {:must
                              [{:range {:timestamp
                                        {:gte (format "now-%dd/d" days)
                                         :lt "now/d"}}}
                               {:query_string {:query q}}
                               ]}}}
                           {:size 10
                            :sort [{"timestamp" {:order "desc"}}]}
                           opts)})))

(defn query-ip-syn-info
  ([ip end-date] (query-ip-syn-info ip end-date nil))
  ([ip end-date {:keys [days interval]
                 :or {days 1
                      interval "1m"}}]
   (query-data (format "(remote_ip:%s) AND (message:tcp_syn)" ip) end-date days
               {:aggs {:syn_times {:date_histogram
                                   {:field "@timestamp"
                                    :order {:_count "desc"}
                                    :fixed_interval interval}}
                       :hosts {:terms {:field "host.keyword"
                                       :size 200}}
                       :ports {:terms {:field "local_port"
                                       :size 65536}}}
                :size 0})))

(defn get-hits-total
  [resp]
  (get-in resp [:body :hits :total :value]))

(defn get-first-hits-source
  [resp]
  (-> (get-in resp [:body :hits :hits])
      first
      :_source))

(defn get-aggs
  [aggs agg-key]
  (get-in aggs [:body :aggregations agg-key]))

(defn get-aggs-buckets
  [aggs agg-key]
  (get-in aggs [:body :aggregations agg-key :buckets]))

(defn get-aggs-buckets-keys
  "获取aggs结果的key列表"
  [aggs agg-key]
  (->> (get-aggs-buckets aggs agg-key)
       (map :key)))

(defn format-aggs-count
  [buckets]
  (mapv (fn [{:keys [key doc_count]}]
          {:Count doc_count
           :Name key})
        buckets))

(defn format-aggs
  [agg use-unknown?]
  (let [unknown (:sum_other_doc_count agg)
        data (format-aggs-count (:buckets agg))]
    (cond-> data
      (and use-unknown?
           (pos? unknown)) (conj {:Name "unknown"
                                  :Count unknown} ))))

(defn get-aggs-buckets-data
  "获取aggs结果"
  ([aggs agg-key] (get-aggs-buckets-data aggs agg-key false))
  ([aggs agg-key use-unknown?]
   (-> (get-aggs aggs agg-key)
       (format-aggs use-unknown?))))

(defn get-hits
  [data]
  (get-in data [:body :hits :hits]))

(defn make-pagination-query-fn
  "构造分页查询
  `num-pages` 分页总数
  `page-query-fn` 分页查询函数，接受一个当前页码的参数 (page-query-fn curr-page)
  "
  [num-pages page-query-fn]
  (let [out-ch (async/chan)]
    (async/go-loop [curr-page 0]
      (if (>= curr-page num-pages)
        (async/close! out-ch)
        (do (when-let [data (with-exception-default nil
                              (page-query-fn curr-page))]
              (async/>! out-ch data))
            (recur (inc curr-page)))))
    out-ch))

(defn get-total-ip
  [date days]
  (-> (query-data "*" date days
                  {:aggs
                   {:ip_count
                    {:cardinality
                     {:field :remote_ip}}}
                   :size 0})
      (get-aggs :ip_count)
      :value))

(def default-page-size 3000)

(defn calc-ips-partition
  ([date days] (calc-ips-partition date days default-page-size))
  ([date days max-part-size]
   (let [ip-total (get-total-ip date days)]
     (int (Math/ceil (/ ip-total max-part-size))))))

(defn make-ip-pagination-query-fn
  "构造根据ip总数分页的查询函数
  `query-fn` 查询函数，接受remote ip terms配置项
  "
  [date days query-fn]
  (let [num-parts (calc-ips-partition date days)
        q-fn (fn [page]
               (query-fn {:field :remote_ip
                          :include {:partition page
                                    :num_partitions num-parts}
                          :size default-page-size}))]
    (make-pagination-query-fn num-parts q-fn)))

(defn all-ip-chan
  [date days]
  (let [out-ch (async/chan)
        partition (calc-ips-partition date days default-page-size)
        query-page-fn (fn [page]
                        (query-data "*" date days
                                    {:aggs
                                     {:remotes
                                      {:terms
                                       {:field :remote_ip
                                        :include {:partition page
                                                  :num_partitions partition}
                                        :size default-page-size}}}
                                     :size 0}))]
    (async/go-loop [curr-page 0]
      (if (>= curr-page partition)
        (async/close! out-ch)
        (let [data (query-page-fn curr-page)
             ips (with-exception-default nil
                   (get-aggs-buckets-keys data :remotes))]
          (doseq [ip ips]
            (async/>! out-ch ip))
          (recur (inc curr-page)))))
    out-ch))

(defn get-top-ip-hosts
  [end-date days]
  (some-> (query-data "message.keyword:\"tcp_syn\""
                      end-date
                      days
                      {:size 0
                       :aggs {:top_ip_hosts
                              {:multi_terms
                               {:terms [{:field :remote_ip}
                                        {:field "host.keyword"}]
                                :size (* 2 top-num)}}}})
          (get-aggs-buckets-data :top_ip_hosts)
          (->> (map #(update % :Name first))
               (distinct-by :Name)
               (take top-num))))

(defn get-aggs-count-by-inner
  [data buckets-key inner-key]
  (->> (get-aggs-buckets data buckets-key)
       (map #(assoc % :doc_count (get-in % [inner-key :value ])))
       (format-aggs-count)))

(defn get-top-ip-ports
  [date days]
  (some-> (query-data "message.keyword:\"tcp_syn\""
                      date
                      days
                      {:size 0
                       :aggs {:top_ip_port_count
                              {:terms
                               {:field :remote_ip
                                :order {:port_count "desc"} ;; 使用order解决
                                :size top-num}
                               :aggs {:port_count
                                      {:cardinality
                                       {:field "local_port"}}}}}})
          (get-aggs-count-by-inner :top_ip_port_count :port_count)))



(def total-host 32)

(defn host-count->ten-percent
  [n]
  (int (/ (* 10 (inc n)) total-host)))

(defn format-ip-breadth
  [breadth-bucket]
  (->> breadth-bucket
       (map #(->> (get-in % [:host_count :value])
                  host-count->ten-percent
                  (assoc % :doc_count)))
       format-aggs-count))

(defn get-top-ip-breadth
  [date days]
  (some-> (query-data "message.keyword:\"tcp_syn\""
                      date
                      days
                      {:size 0
                       :aggs {:top_ip_breadth
                              {:terms
                               {:field :remote_ip
                                :order {:host_count "desc"} ;; 使用order解决
                                :size top-num}
                               :aggs {:host_count
                                      {:cardinality
                                       {:field "host.keyword"}}}}}})
          (get-aggs-buckets :top_ip_breadth)
          format-ip-breadth))

(defn get-top-ip-port
  [date days]
  (let [data (query-data "message.keyword:\"tcp_syn\""
                         date
                         days
                         {:size 0
                          :aggs {:top_ips {:terms {:field :remote_ip
                                                   :size top-num}}
                                 :top_ports {:terms {:field "local_port"
                                                     :size top-num}}
                                 :top_countries {:terms {:field "country_name.keyword"
                                                         :size top-num}}}})]
    data
    {:top_ip  (get-aggs-buckets-data data :top_ips)
     :top_port (get-aggs-buckets-data data :top_ports)
     :top_countrie (get-aggs-buckets-data data :top_countries)}))

(defn get-top-protocol
  [date days]
  (-> (query-data "message.keyword:\"new conn\""
                  date
                  days
                  {:size 0
                   :aggs {:top_protocols {:terms {:field "protocol.keyword"
                                                  :size top-num}}}})
      (get-aggs-buckets-data :top_protocols)))

(defn get-top-info
  "获取所有top信息"
  [date days]
  (assoc (get-top-ip-port date days)
         :top_ip_by_host (get-top-ip-hosts date days)
         :top_ip_by_port (get-top-ip-ports date days)
         :top_ip_scan_breadth (get-top-ip-breadth date days)
         :top_protocol (get-top-protocol date days)))
