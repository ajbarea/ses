;; --------------------------------------------------------------------
;; File: port_rules.clp
;; Description: Contains CLIPS rules for evaluating open ports and security posture.
;; --------------------------------------------------------------------

;;; Section: Open Ports Rules ;;;

;; Rule: high-risk-port-open
;; Purpose: Identifies open ports associated with insecure legacy protocols (telnet, ftp, smtp, rdp).
(defrule high-risk-port-open
    "Check for high-risk ports (telnet, ftp, smtp, rdp)"
    (open-port (number ?port&:(or (= ?port 21) (= ?port 23) (= ?port 25) (= ?port 3389))))
    =>
    (assert (finding
        (rule-name "high_risk_port_open")
        (level "warning")
        (description (str-cat "High-risk port " ?port " is open."))
        (details ?port)
        (recommendation "Close unnecessary high-risk ports or restrict access.")
    ))
    (assert (score (value -15) (type penalty)))
)

;; Rule: suspicious-port-combination
;; Purpose: Identifies particularly dangerous combinations of open services with disabled firewalls.
(defrule suspicious-port-combination
    "Check for suspicious combinations of open ports"
    (open-port (number ?port1&:(or (= ?port1 23) (= ?port1 21))))
    (open-port (number ?port2&:(or (= ?port2 139) (= ?port2 445))))
    (firewall (public "OFF"))
    =>
    (assert (finding
        (rule-name "suspicious_port_combination")
        (level "critical")
        (description "Insecure services exposed with firewall disabled.")
        (details ?port1 ?port2)
        (recommendation "Disable unnecessary services and enable firewall.")
    ))
    (assert (score (value -25) (type penalty)))
)

;; Rule: many-ports-open
;; Purpose: Detects unusually large attack surface due to excessive open ports.
(defrule many-ports-open
    "Check if more than 20 ports are open"
    (not (excessive-ports-checked))
    =>
    (bind ?count 0)
    (do-for-all-facts ((?p open-port)) TRUE
        (bind ?count (+ ?count 1))
    )
    
    (if (> ?count 20) then
        (assert (finding
            (rule-name "many_ports_open")
            (level "warning")
            (description (str-cat "Large number of open ports (" ?count "). Threshold is 20."))
            (details ?count)
            (recommendation "Review and close unnecessary ports.")
        ))
        (assert (score (value -10) (type penalty)))
    )
    (assert (excessive-ports-checked))
)