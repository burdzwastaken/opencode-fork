package opencode.permissions.bash

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default allow := false

# Allow safe read-only commands
allow if {
    is_safe_readonly_command
}

# Allow common development commands
allow if {
    is_development_command
    not is_dangerous_pattern
}

# Allow git commands (with restrictions)
allow if {
    is_git_command
    not is_dangerous_git_operation
}

# Allow package manager commands
allow if {
    is_package_manager_command
    not is_global_install
}

# Deny rules (override allow)
deny contains msg if {
    is_destructive_command
    msg := "Destructive commands (rm -rf, format, etc.) are not allowed"
}

deny contains msg if {
    is_network_exfiltration
    msg := "Network commands that could exfiltrate data are not allowed"
}

deny contains msg if {
    is_privilege_escalation
    msg := "Privilege escalation commands (sudo, su, doas) are not allowed"
}

deny contains msg if {
    modifies_shell_config
    msg := "Modifying shell configuration files is not allowed"
}

deny contains msg if {
    accesses_credentials
    msg := "Accessing credential files is not allowed"
}

deny contains msg if {
    is_git_command
    is_dangerous_git_operation
    msg := "Dangerous git operations (force push, push to main/master, hard reset/clean) are not allowed"
}

# Helper rules
command := input.pattern
tokens := split(command, " ")
first_token := tokens[0]

has_redirect if regex.match(`[<>]`, command)
has_subshell if regex.match(`\$\(|\x60`, command)

# Safe read-only commands
safe_readonly_commands := {
    "ls", "cat", "head", "tail", "less", "more", "wc", "file", "stat",
    "find", "grep", "awk", "sed", "sort", "uniq", "diff", "tree",
    "pwd", "whoami", "hostname", "uname", "date", "cal", "env",
    "which", "whereis", "type", "man", "help", "echo", "printf"
}

is_safe_readonly_command if {
    first_token in safe_readonly_commands
    not has_redirect
    not has_subshell
}

# Development commands
dev_commands := {
    "make", "cargo", "npm", "yarn", "pnpm", "bun", "deno",
    "go", "python", "python3", "pip", "pip3", "poetry",
    "ruby", "gem", "bundle", "rake",
    "mvn", "gradle", "ant",
    "zig", "rustc", "gcc", "clang", "node", "tsc",
    "pytest", "jest", "vitest", "mocha",
    "docker", "docker-compose", "podman"
}

is_development_command if {
    first_token in dev_commands
}

# Git commands
is_git_command if {
    first_token == "git"
}

git_operation := tokens[1] if {
    first_token == "git"
    count(tokens) > 1
}

is_dangerous_git_operation if {
    git_operation == "push"
    contains(command, "--force")
}

is_dangerous_git_operation if {
    git_operation == "push"
    regex.match(`(main|master|prod|release)`, command)
}

is_dangerous_git_operation if {
    git_operation in {"reset", "clean"}
    contains(command, "--hard")
}

# Package managers
package_managers := {"npm", "yarn", "pnpm", "bun", "pip", "pip3", "gem", "cargo"}

is_package_manager_command if {
    first_token in package_managers
}

is_global_install if {
    is_package_manager_command
    regex.match(`(-g|--global|install\s+-g)`, command)
}

# Dangerous patterns
is_destructive_command if {
    regex.match(`rm\s+(-[rf]+\s+)*[/~]`, command)
}

is_destructive_command if {
    regex.match(`(mkfs|dd\s+if=)`, command)
}

is_destructive_command if {
    regex.match(`^\s*format\s+[a-zA-Z]:`, command)
}

is_network_exfiltration if {
    regex.match(`curl.*\|\s*(sh|bash)`, command)
}

is_network_exfiltration if {
    regex.match(`(curl|wget|nc|netcat).*(-d|--data|POST)`, command)
    not is_development_command
}

is_privilege_escalation if {
    first_token in {"sudo", "su", "doas", "pkexec"}
}

modifies_shell_config if {
    regex.match(`(>>?)\s*~/?\.(bash|zsh|profile|rc)`, command)
}

accesses_credentials if {
    regex.match(`(cat|less|head|tail|grep).*\.(ssh|aws|kube|docker)/`, command)
}

accesses_credentials if {
    regex.match(`(cat|less|head|tail|grep).*(credentials|\.env|\.secret|token)`, command)
}

is_dangerous_pattern if is_destructive_command
is_dangerous_pattern if is_network_exfiltration
is_dangerous_pattern if is_privilege_escalation

# Decision output
result := {
    "allow": allow_final,
    "deny": count(deny) > 0,
    "reasons": deny,
    "message": message,
}

allow_final if {
    allow
    count(deny) == 0
}

default allow_final := false

message := concat("; ", deny) if count(deny) > 0
default message := ""
