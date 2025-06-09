;; --------------------------------------------------------------------
;; File: patch_rules.clp
;; Description: Contains CLIPS rules for evaluating system patch status.
;; --------------------------------------------------------------------

;;; Section: Patch Status Rules ;;;

;; Rule: critical-patch-missing
;; Purpose: Identifies systems that are missing security updates and patches.
(defrule critical-patch-missing
    "Check if system patches are missing"
    (patch-status (status "out-of-date"))
    =>
    (assert (finding 
        (rule-name "patch_status")
        (level "critical")
        (description "System patches are not up-to-date.")
        (recommendation "Apply all available Windows security updates immediately.")
    ))
    (assert (score (value -30) (type penalty)))
)

;; Rule: recent-patch-installed
;; Purpose: Confirms that a system has all current security patches installed.
(defrule recent-patch-installed
    "Check if recent patches are installed"
    (patch-status (status "up-to-date") 
                 (hotfixes $?fixes))
    =>
    (assert (finding
        (rule-name "patch_status")
        (level "info")
        (description "System patches are up-to-date.")
        (details $?fixes)
        (recommendation "Continue with regular patch management.")
    ))
)