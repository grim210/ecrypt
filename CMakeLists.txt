cmake_minimum_required(VERSION 3.0)
project(ecrypt C)

set(ecrypt_VERSION_MAJOR 0)
set(ecrypt_VERSION_MINOR 0)
set(ecrypt_VERSION_PATCH 0)
set(ecrypt_VERSION
    "${ecrypt_VERSION_MAJOR}.${ecrypt_VERSION_MINOR}.${ecrypt_VERSION_PATCH}")

subdirs(src)
subdirs(test)
