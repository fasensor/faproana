(ns ntestoc.proana
  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.core.async :as async]
            [better-cond.core :as better]
            [common.wrap :refer [with-exception-default]]
            [taoensso.timbre :as log]
            [ntestoc.db :as db]
            [clojure.tools.cli :refer [parse-opts]]
            [clojure.set :as set]
            [com.climate.claypoole :as cp]
            [mount.core :refer [defstate]]
            [ntestoc.ana-db :as ip-db]
            [java-time :as jt]
            [ntestoc.rule :as rule]
            [clojure.string :as str]))

(defn exec-ip-rule
  [rule ip end-day]
  (let [q ((:query rule) ip)
        data (with-exception-default nil
               (db/query-data (:query q)
                              end-day
                              (or (:days q) 1)
                              (:opts q)))]
    (when data
      ((:check-fn rule) data))))

(defn exec-full-rule
  [rule end-day]
  (let [chan (db/make-ip-pagination-query-fn end-day (:days rule) (:query rule))
        result-chan (async/chan)]
    (async/go-loop [q (async/<! chan)]
      (if q
        (if-let [data (with-exception-default nil
                        (db/query-data (:query q)
                                       end-day
                                       (or (:days q) (:days rule))
                                       (:opts q)))]
          (let [rs ((:check-fn rule) data)]
            (doseq [r rs]
              (if (and (map? r)
                       (:ip r))
                (async/>! result-chan
                          (assoc r :rule rule))
                (log/error :exec-full-rule (:name rule) "error, :check-fn result item invalid, item:" r)))
            (recur (async/<! chan)))
          (async/close! result-chan))
        (async/close! result-chan)))
    result-chan))

(defn run-ip-rules
  [end-day rules]
  (let [ips (db/all-ip-chan end-day 1)
        result-chan (async/chan)
        pool (cp/threadpool 300 :name "ip-rules-pool")
        run-ip-rule-fn (fn [ip]
                         (log/trace :run-ip-rule "for ip" ip)
                         (cp/upfor pool
                                   [rule rules]
                                   (log/trace :run-ip-rule ip (:name rule))
                                   (let [rule-result (with-exception-default nil
                                                       (exec-ip-rule rule ip end-day))]
                                     (when rule-result
                                       (log/trace :found-ip-rule-match ip (:name rule))
                                       {:ip ip
                                        :rule rule
                                        :data rule-result}))))]
    (async/pipeline
     30
     result-chan
     (comp
      (mapcat run-ip-rule-fn)
      (filter identity))
     ips)
    result-chan))

(defn run-full-rules
  [end-day rules]
  (->> rules
       (map #(exec-full-rule % end-day))
       (async/merge)))

(defn update-ip-data
  [conn data]
  (let [ip (:ip data)
        rule (:rule data)
        info (ip-db/get-info-by-ip conn ip)
        old-tag (or (:tag info) #{})
        new-tag (if (:hidden rule)
                  old-tag
                  (conj old-tag (:name rule)))
        data (if (map? (:data data))
               (:data data)
               {})]
    (try
      (ip-db/transact! conn [(assoc data
                                    :tag new-tag
                                    :ip ip)])
      (catch Exception e
        (log/error :write-ip-data e {:ip ip :data data})))))

(defn update-run-status
  [conn data]
  (with-exception-default nil
    (ip-db/transact! conn [(merge data
                                  {:status :ok
                                   :last-time (java.util.Date.)})])))

(defn get-last-rules
  [conn]
  (let [data (ip-db/get-status conn)]
    {:ip (set (:ip-rules data))
     :full (set (:full-rules data))}))

(defn get-db-name
  [end-day]
  (str "ip_ana_" (str/replace end-day "-" "_")))

(defn run-rules
  [end-day]
  (let [{:keys [ip full]} (group-by :type (rule/get-rules))
        db-name (get-db-name end-day)
        db-conn (ip-db/get-conn db-name)
        prev-rules (get-last-rules db-conn)
        curr-ip-rules (filter #(not ((:ip prev-rules) (:name %))) ip)
        curr-full-rules (filter #(not ((:full prev-rules) (:name %))) full)
        ip-rules-data (run-ip-rules end-day curr-ip-rules)
        full-rules-data (run-full-rules end-day curr-full-rules)
        rules-data (async/merge [ip-rules-data full-rules-data] 1024)
        end-chan (async/chan)]
    (log/info :run-rules
              :db-name db-name
              :prev-rules prev-rules
              :curr-ip-rules (mapv :name curr-ip-rules)
              :curr-full-rules (mapv :name curr-full-rules))
    (async/go-loop []
      (if-let [data (async/<! rules-data)]
        (do
          (log/trace :write-rule-info (:ip data) (get-in data [:rule :name]))
          (with-exception-default nil
            (update-ip-data db-conn data))
          (recur))
        (do (log/info :run-rules :end)
            (update-run-status db-conn
                               {:ip-rules (set (map :name ip))
                                :full-rules (set (map :name full))})
            (ip-db/close db-conn)
            (async/close! end-chan))))
    end-chan))

(defn sync-rule-db
  [end-day]
  (let [db-name (get-db-name end-day)
        db-conn (ip-db/get-conn db-name)
        datas (ip-db/get-all-ip-info db-conn)]
    (log/info :sync-rule-db end-day "total:" (count datas))
    (db/insert-ana-data datas)))

(defn runner
  [start-day end-day]
  (let [start (jt/local-date start-day)
        end (jt/local-date end-day)]
    (async/go-loop [curr-day start]
      (when (jt/before? curr-day end)
        (let [c (str curr-day)
              total (db/get-total-ip c 1)]
          (log/info :runner-for-day c :total-ip total)
          (async/<! (run-rules c))
          (sync-rule-db c)
          (log/info :runner-for-day c "over!"))
        (recur (jt/plus curr-day (jt/days 1)))))))

(comment
  (runner "2021-10-03" "2021-10-14")

  (runner "2021-09-19" "2021-10-15")


  (runner "2021-10-15" "2021-10-18")

  (runner "2021-10-18" "2021-10-19")
  )

;; 关闭elasticsearch 没有认证的警告
(log/merge-config! {:min-level [[#{"ntestoc.*"} :debug]
                                [#{"*"} :warn]]

                    })

(defn usage [options-summary]
  (->> ["This is a FaPro elasticsearch log analysis tool."
        ""
        "Usage: java -jar proana.jar [options] "
        ""
        "Options:"
        options-summary]
       (str/join \newline)))

(defn error-msg [errors]
  (str "The following errors occurred while parsing your command:\n\n"
       (str/join \newline errors)))

(def cli-options
  [["-s" "--start Date" "start date"
    :parse-fn #(str (jt/local-date (jt/formatter :iso-date) %))]
   ["-e" "--end Date" "end date"
    :default (str (jt/local-date))
    :parse-fn #(str (jt/local-date (jt/formatter :iso-date) %))]
  ["-h" "--help"]])


(defn validate-args
  "Validate command line arguments. Either return a map indicating the program
  should exit (with an error message, and optional ok status), or a map
  indicating the action the program should take and the options provided."
  [args]
  (let [{:keys [options arguments errors summary]} (parse-opts args cli-options)]
    (cond
      (:help options) ; help => exit OK with usage summary
      {:exit-message (usage summary) :ok? true}
      errors ; errors => exit with description of errors
      {:exit-message (error-msg errors)}
      :else
      {:options options})))

(defn exit [status msg]
  (println msg)
  (System/exit status))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (let [{:keys [action options exit-message ok?]} (validate-args args)]
    (if exit-message
      (exit (if ok? 0 1) exit-message)
      (do
        (println :start (:start options))
        (mount.core/start)
        (db/make-ana-index)
        (runner (:start options) (:end options))))))
