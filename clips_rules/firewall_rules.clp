;; --------------------------------------------------------------------
;; File: firewall_rules.clp
;; Description: Contains CLIPS rules for evaluating Windows Firewall profile statuses.
;; --------------------------------------------------------------------

;;; Section: Firewall Profile Rules ;;;

;; Rule: firewall-all-disabled
;; Purpose: Check if all firewall profiles are disabled.
(defrule firewall-all-disabled
    "Check if all firewall profiles are disabled"
    (firewall (domain "OFF") (private "OFF") (public "OFF"))
    =>
    (assert (finding
        (rule-name "firewall_all_disabled")
        (level "critical")
        (description "All firewall profiles are disabled.")
        (recommendation "Enable Windows Firewall for all profiles immediately.")
    ))
    (assert (score (value -30) (type penalty)))
)

;; Rule: firewall-public-disabled
;; Purpose: Check if public firewall profile is disabled.
(defrule firewall-public-disabled
    "Check if public firewall profile is disabled"
    (firewall (public "OFF"))
    (not (firewall (domain "OFF") (private "OFF") (public "OFF")))
    =>
    (assert (finding
        (rule-name "firewall_public_disabled")
        (level "warning")
        (description "Public firewall profile is disabled.")
        (recommendation "Enable Windows Firewall for the public profile.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: firewall-domain-disabled
;; Purpose: Check if domain firewall profile is disabled.
(defrule firewall-domain-disabled
    "Check if domain firewall profile is disabled"
    (firewall (domain "OFF"))
    (not (firewall (domain "OFF") (private "OFF") (public "OFF")))
    =>
    (assert (finding
        (rule-name "firewall_domain_disabled")
        (level "warning")
        (description "Domain firewall profile is disabled.")
        (recommendation "Enable Windows Firewall for the domain profile.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: firewall-private-disabled
;; Purpose: Check if private firewall profile is disabled.
(defrule firewall-private-disabled
    "Check if private firewall profile is disabled"
    (firewall (private "OFF"))
    (not (firewall (domain "OFF") (private "OFF") (public "OFF")))
    =>
    (assert (finding
        (rule-name "firewall_private_disabled")
        (level "warning")
        (description "Private firewall profile is disabled.")
        (recommendation "Enable Windows Firewall for the private profile.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: firewall-all-enabled
;; Purpose: Check if all firewall profiles are enabled.
(defrule firewall-all-enabled
    "Check if all firewall profiles are enabled"
    (firewall (domain "ON") (private "ON") (public "ON"))
    =>
    (assert (finding
        (rule-name "firewall_all_enabled")
        (level "info")
        (description "All firewall profiles are enabled.")
        (recommendation "Continue monitoring firewall status.")
    ))
    (assert (score (value 5) (type penalty)))
)