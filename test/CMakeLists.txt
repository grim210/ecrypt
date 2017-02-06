project(libecrypt C)

include_directories("${ecrypt_SOURCE_DIR}/include/")
link_directories("${ecrypt_SOURCE_DIR}")

add_executable(blowfish_test blowfish_test.c)
add_executable(pbkdf2_test pbkdf2_test.c)
add_executable(rijndael_test rijndael_test.c)

target_link_libraries(blowfish_test ecrypt)
target_link_libraries(pbkdf2_test ecrypt)
target_link_libraries(rijndael_test ecrypt)
