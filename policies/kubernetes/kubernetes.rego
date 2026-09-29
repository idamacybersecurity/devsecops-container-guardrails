package main

# Deployment pods must explicitly run as non-root.
deny contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext.runAsNonRoot

    msg := sprintf(
        "%s: containers must be configured to run as non-root",
        [input.metadata.name],
    )
}

# Every container must use a read-only root filesystem.
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    not container.securityContext.readOnlyRootFilesystem

    msg := sprintf(
        "%s: container %s must set readOnlyRootFilesystem to true",
        [input.metadata.name, container.name],
    )
}

# Container images must not use the mutable :latest tag.
deny contains msg if {
    input.kind == "Deployment"
    some container in input.spec.template.spec.containers
    endswith(container.image, ":latest")

    msg := sprintf(
        "%s: container %s must not use the latest image tag",
        [input.metadata.name, container.name],
    )
}