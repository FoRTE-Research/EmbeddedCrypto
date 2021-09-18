cmake_minimum_required(VERSION 3.17)
project(gb_aes C)

ADD_LIBRARY( aesLib STATIC
        gladman/aeskey.c gladman/aescrypt.c gladman/aestab.c gladman/aesaux.c gladman/aestst.c)

set(CMAKE_C_STANDARD 99)

add_executable(gladman_aes risc_v_main.c)

TARGET_LINK_LIBRARIES( gladman_aes
        aesLib )