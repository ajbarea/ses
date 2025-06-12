;; --------------------------------------------------------------------
;; File: firewall_rules.clp
;; Description: Contains CLIPS rules for evaluating Windows Firewall profile statuses.
;; --------------------------------------------------------------------

;;; Section: Firewall Profile Rules ;;;

;; Rule: firewall-all-disabled
;; Purpose: Identifies critical security issue when all firewall profiles are off.
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

;; Rule: smb-port-open
;; Purpose: Detects Windows file sharing (SMB) port 445 being open.
(defrule smb-port-open
    "Check for SMB port 445"
    (open-port (number 445))
    (not (high-risk-smb-detected))
    =>
    (assert (finding
        (rule-name "smb_port_open")
        (level "info")
        (description "SMB port 445 is open, which is common for Windows file sharing.")
        (details 445)
        (recommendation "Ensure this port is not exposed to the internet and is properly firewalled.")
    ))
    (assert (high-risk-smb-detected))
    ;; No score penalty for a standard Windows service
)

;; Rule: smb-port-with-public-firewall-off
;; Purpose: Identifies the high risk scenario of SMB exposed when public firewall is disabled.
(defrule smb-port-with-public-firewall-off
    "Check for SMB port with public firewall off"
    (open-port (number 445))
    (firewall (public "OFF"))
    =>
    (assert (finding
        (rule-name "smb_port_risky")
        (level "warning")
        (description "SMB port 445 is open with public firewall disabled.")
        (details 445)
        (recommendation "Enable public firewall profile and restrict SMB access to trusted networks only.")
    ))
    (assert (score (value -10) (type penalty)))
    (assert (high-risk-smb-detected))
)

;; Rule: firewall-public-disabled
;; Purpose: Identifies when only the public profile is disabled.
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
;; Purpose: Identifies when only the domain profile is disabled.
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
;; Purpose: Identifies when only the private profile is disabled.
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
;; Purpose: Confirms optimal firewall configuration with all profiles enabled.
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
    (assert (score (value 0) (type neutral)))
)