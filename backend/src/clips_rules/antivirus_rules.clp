;; --------------------------------------------------------------------
;; File: antivirus_rules.clp
;; Description: Contains CLIPS rules for evaluating antivirus status.
;; --------------------------------------------------------------------

;;; Section: Antivirus Status Rules ;;;

;; Rule: antivirus-disabled
;; Purpose: Identifies systems with completely disabled antivirus protection.
(defrule antivirus-disabled
    "Check if antivirus is disabled"
    (antivirus-info (status "disabled"))
    =>
    (assert (finding
        (rule-name "antivirus_disabled")
        (level "critical")
        (description "Antivirus software is disabled.")
        (recommendation "Enable antivirus software immediately.")
    ))
)

;; Rule: antivirus-definitions-outdated
;; Purpose: Identifies systems with outdated virus definitions that may miss recent threats.
(defrule antivirus-definitions-outdated
    "Check if antivirus definitions are out of date"
    (antivirus-info (definitions "out-of-date"))
    =>
    (assert (finding
        (rule-name "antivirus_definitions_outdated")
        (level "warning")
        (description "Antivirus definitions are out of date.")
        (recommendation "Update antivirus definitions as soon as possible.")
    ))
)

;; Rule: antivirus-real-time-protection-disabled
;; Purpose: Identifies systems where real-time scanning is disabled but antivirus is installed.
(defrule antivirus-real-time-protection-disabled
    "Check if real-time protection is disabled"
    (antivirus-info (real-time-protection "disabled"))
    =>
    (assert (finding
        (rule-name "antivirus_real_time_protection_disabled")
        (level "critical")
        (description "Real-time protection is disabled.")
        (recommendation "Enable real-time protection immediately.")
    ))
)

;; Rule: antivirus-properly-configured
;; Purpose: Rewards systems with properly configured and up-to-date antivirus protection.
(defrule antivirus-properly-configured
    "Check if antivirus is properly configured"
    (antivirus-info (status "enabled") (definitions "up-to-date") (real-time-protection "enabled"))
    =>
    (assert (finding
        (rule-name "antivirus_properly_configured")
        (level "info")
        (description "Antivirus software is properly configured with up-to-date definitions and real-time protection.")
        (recommendation "Continue monitoring antivirus status and keep definitions updated.")
    ))
)
