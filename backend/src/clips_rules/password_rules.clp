;; --------------------------------------------------------------------
;; File: password_rules.clp
;; Description: Contains CLIPS rules for evaluating password policy settings.
;; --------------------------------------------------------------------

;;; Section: Password Rules ;;;

;; Rule: password-min-length-weak
;; Purpose: Identifies policies with insufficient minimum password length requirements.
(defrule password-min-length-weak
    "Check for weak minimum password length"
    (password-policy (min-length ?len&:(< ?len 8)))
    =>
    (assert (finding
        (rule-name "password_min_length_weak")
        (level "warning")
        (description (str-cat "Minimum password length is weak (less than 8 characters). Currently: " ?len "."))
        (recommendation "Set minimum password length to at least 8 characters. Consider 12 or more for enhanced security.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: password-min-length-acceptable
;; Purpose: Identifies policies with acceptable but not ideal password length requirements.
(defrule password-min-length-acceptable
    "Check for acceptable minimum password length"
    (password-policy (min-length ?len&:(>= ?len 8)&:(< ?len 12)))
    =>
    (assert (finding
        (rule-name "password_min_length_acceptable")
        (level "info")
        (description (str-cat "Minimum password length is acceptable. Currently: " ?len ". Consider increasing for enhanced security."))
        (recommendation "Consider increasing minimum password length to 12 or more characters.")
    ))
    (assert (score (value 0) (type neutral)))
)

;; Rule: password-min-length-strong
;; Purpose: Identifies policies with strong password length requirements.
(defrule password-min-length-strong
    "Check for strong minimum password length"
    (password-policy (min-length ?len&:(>= ?len 12)))
    =>
    (assert (finding
        (rule-name "password_min_length_strong")
        (level "info")
        (description (str-cat "Minimum password length is strong. Currently: " ?len "."))
        (recommendation "Maintain strong password length requirements.")
    ))
    (assert (score (value 5) (type bonus)))
)

;; Rule: password-complexity-disabled
;; Purpose: Detects when password complexity requirements are not enforced.
(defrule password-complexity-disabled
    "Check if password complexity requirements are disabled"
    (password-policy (complexity "disabled"))
    =>
    (assert (finding
        (rule-name "password_complexity_disabled")
        (level "warning")
        (description "Password complexity requirements (requiring uppercase, lowercase, numbers, symbols) are disabled.")
        (recommendation "Enable password complexity requirements to enforce stronger passwords.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: password-complexity-enabled
;; Purpose: Confirms that password complexity requirements are enabled.
(defrule password-complexity-enabled
    "Check if password complexity requirements are enabled"
    (password-policy (complexity "enabled"))
    =>
    (assert (finding
        (rule-name "password_complexity_enabled")
        (level "info")
        (description "Password complexity requirements are enabled.")
        (recommendation "Ensure password complexity settings align with security best practices.")
    ))
    (assert (score (value 5) (type bonus)))
)

;; Rule: account-lockout-not-defined
;; Purpose: Identifies when account lockout thresholds are not configured.
(defrule account-lockout-not-defined
    "Check if account lockout policy is not defined"
    (password-policy (lockout-threshold not-defined))
    =>
    (assert (finding
        (rule-name "account_lockout_not_defined")
        (level "warning")
        (description "Account lockout policy (e.g., locking account after a certain number of failed attempts) is not defined.")
        (recommendation "Define an account lockout threshold (e.g., 5 failed attempts) and lockout duration.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: account-lockout-defined
;; Purpose: Confirms that account lockout policies are configured.
(defrule account-lockout-defined
    "Check if account lockout policy is defined"
    (password-policy (lockout-threshold ?val&:(neq ?val not-defined)))
    =>
    (assert (finding
        (rule-name "account_lockout_defined")
        (level "info")
        (description (str-cat "Account lockout policy is defined. Threshold: " ?val "."))
        (recommendation "Ensure the lockout threshold and duration are appropriate for your security needs.")
    ))
    (assert (score (value 5) (type bonus)))
)

;; Rule: password-history-disabled
;; Purpose: Identifies when password history requirements are not enforced.
(defrule password-history-disabled
    "Check if password history is not enforced"
    (password-policy (history-size ?size&:(< ?size 1))) ; Assuming 0 means disabled
    =>
    (assert (finding
        (rule-name "password_history_disabled")
        (level "warning")
        (description "Password history is not enforced, allowing immediate reuse of old passwords.")
        (recommendation "Enforce password history (e.g., remember at least the last 5 passwords).")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: password-history-enabled
;; Purpose: Confirms that password history requirements are enforced.
(defrule password-history-enabled
    "Check if password history is enforced"
    (password-policy (history-size ?size&:(>= ?size 1)))
    =>
    (assert (finding
        (rule-name "password_history_enabled")
        (level "info")
        (description (str-cat "Password history is enforced. Remembering last " ?size " passwords."))
        (recommendation "Ensure the password history size is adequate (e.g., 5 or more).")
    ))
    (assert (score (value 5) (type bonus)))
)

;; Rule: max-password-age-disabled
;; Purpose: Identifies when password expiration is not enforced.
(defrule max-password-age-disabled
    "Check if maximum password age is disabled"
    (password-policy (max-age disabled))
    =>
    (assert (finding
        (rule-name "max_password_age_disabled")
        (level "warning")
        (description "Maximum password age is disabled, meaning passwords never expire.")
        (recommendation "Set a maximum password age (e.g., 90 days) to enforce regular password changes.")
    ))
    (assert (score (value -10) (type penalty)))
)

;; Rule: max-password-age-enabled
;; Purpose: Confirms that password expiration is enforced.
(defrule max-password-age-enabled
    "Check if maximum password age is enabled"
    (password-policy (max-age ?days&:(neq ?days disabled)&:(> (integer ?days) 0)))
    =>
    (assert (finding
        (rule-name "max_password_age_enabled")
        (level "info")
        (description (str-cat "Maximum password age is enabled. Passwords expire after " ?days " days."))
        (recommendation "Ensure the maximum password age is appropriate (e.g., 90 days).")
    ))
    (assert (score (value 5) (type bonus)))
)

;; Rule: max-password-age-too-long
;; Purpose: Identifies when password expiration period is excessively long.
(defrule max-password-age-too-long
    "Check if maximum password age is too long"
    (password-policy (max-age ?days&:(neq ?days disabled)&:(> (integer ?days) 365)))
    =>
    (assert (finding
        (rule-name "max_password_age_too_long")
        (level "warning")
        (description (str-cat "Maximum password age may be too long. Passwords expire after " ?days " days."))
        (recommendation "Consider reducing the maximum password age to a shorter period (e.g., 90-180 days).")
    ))
    (assert (score (value -10) (type penalty)))
)
