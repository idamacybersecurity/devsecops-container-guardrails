package main

# A Dockerfile must explicitly switch to a non-root user.
deny contains msg if {
    not non_root_user_defined

    msg := "Dockerfile must specify a non-root USER"
}

non_root_user_defined if {
    some i
    input[i].Cmd == "user"

    user := lower(input[i].Value[0])
    user != "root"
    user != "0"
}

# Explicitly prohibit USER root or USER 0.
deny contains msg if {
    some i
    input[i].Cmd == "user"

    user := lower(input[i].Value[0])
    user == "root"

    msg := "Dockerfile must not use USER root"
}

deny contains msg if {
    some i
    input[i].Cmd == "user"

    input[i].Value[0] == "0"

    msg := "Dockerfile must not use USER 0"
}

# Prohibit mutable latest base-image tags.
deny contains msg if {
    some i
    input[i].Cmd == "from"

    image := lower(input[i].Value[0])
    endswith(image, ":latest")

    msg := sprintf(
        "Dockerfile base image %s must not use the latest tag",
        [input[i].Value[0]],
    )
}