project(libecrypt C)

include_directories("${ecrypt_SOURCE_DIR}/include/")

add_library(ecrypt
    blowfish.c
    pbkdf2.c
    rijndael.c
)
