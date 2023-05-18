## erasure code plugins

set(erasure_plugin_dir ${CEPH_INSTALL_PKGLIBDIR}/erasure-code)

set(WITH_JERASURE TRUE CACHE BOOL "Enable JErasure EC library")

if(WITH_JERASURE)
  #jerasure subdir must be before shec so jerasure & neon obj libs are declared
  include_directories(SYSTEM jerasure/jerasure/include)
  include_directories(SYSTEM jerasure/gf-complete/include)
  include_directories(jerasure)

  # legacy jerasure flavors. these are left here for backward compatibility
  # and should be removed in future versions
  set(jerasure_legacy_flavors generic)
  if(HAVE_ARM)
    list(APPEND jerasure_legacy_flavors neon)
  endif()
  if(HAVE_INTEL)
  list(APPEND jerasure_l∑egacy_flavors sse3 sse4)
  endif()
endif(WITH_JERASURE)

if(WITH_JERASURE)
  add_subdirectory(jerasure)
  set(EC_JERASURE_LIB ec_jerasure)
  add_subdirectory(shec) # shec depends on jerasure
  set(EC_SHEC_LIB ec_shec)
  add_subdirectory(lrc) # lrc depends on jerasure
  set(EC_LRC_LIB ec_lrc)
endif(WITH_JERASURE)
add_subdirectory(clay)

if(HAVE_NASM_X64_AVX2 OR HAVE_ARMV8_SIMD)
  set(WITH_EC_ISA_PLUGIN TRUE CACHE BOOL "")
endif()

if(WITH_EC_ISA_PLUGIN)
  add_subdirectory(isa)
  set(EC_ISA_LIB ec_isa)
endif()

add_library(erasure_code STATIC ErasureCodePlugin.cc)
target_link_libraries(erasure_code $<$<PLATFORM_ID:Windows>:dlfcn_win32>
                      ${CMAKE_DL_LIBS})

add_library(erasure_code_objs OBJECT ErasureCode.cc)

add_custom_target(erasure_code_plugins DEPENDS
    ${EC_ISA_LIB}
    ${EC_LRC}
    ${EC_JERASURE}
    ${EC_SHEC}
    ec_clay)
