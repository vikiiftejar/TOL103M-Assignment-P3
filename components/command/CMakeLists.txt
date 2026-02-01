idf_component_register(
  SRCS "command.c"
  INCLUDE_DIRS "include"
  REQUIRES "lownet" "mbedtls" "ping"
  PRIV_REQUIRES "crypt"
)
