# ==========================================================================
# The "main" component.
#
# In ESP-IDF, your application is just another COMPONENT named "main" that
# the build system treats specially (it's the one that provides app_main).
# main is now just an orchestrator - all the real logic lives in sibling
# components under components/: storage/, wifi/, dns/, ...
# ==========================================================================
idf_component_register(
    SRCS "pocketdns_main.c"
    INCLUDE_DIRS "."
    REQUIRES storage wifi dns
)
