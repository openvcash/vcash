# Compiler definitions kept in a separate module for neatness

# I believe this makes Vcash 64-bit only, which should be noted somewhere...
list(APPEND _VCASH_DEFINITIONS "-D_FILE_OFFSET_BITS=64")

# Adds compile definitions for the detected compiler
# MSVC compiler
IF(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  # Technically you can get MSVC on non-Windows OS's, so we check here
  IF(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT _WIN32_WINNT)
    # Windows-specific MSVC settings
    # Check if the user has declared their own kernel flag
    # Copy-paste from https://stackoverflow.com/a/40217291
    # Gets correct WinNT kernel version based on system
    macro(get_WIN32_WINNT version)
      if (CMAKE_SYSTEM_VERSION)
          set(ver ${CMAKE_SYSTEM_VERSION})
          string(REGEX MATCH "^([0-9]+).([0-9])" ver ${ver})
          string(REGEX MATCH "^([0-9]+)" verMajor ${ver})
          # Check for Windows 10, b/c we'll need to convert to hex 'A'.
          if ("${verMajor}" MATCHES "10")
              set(verMajor "A")
              string(REGEX REPLACE "^([0-9]+)" ${verMajor} ver ${ver})
          endif ("${verMajor}" MATCHES "10")
          # Remove all remaining '.' characters.
          string(REPLACE "." "" ver ${ver})
          # Prepend each digit with a zero.
          string(REGEX REPLACE "([0-9A-Z])" "0\\1" ver ${ver})
          set(${version} "0x${ver}")
      endif(CMAKE_SYSTEM_VERSION)
    endmacro(get_WIN32_WINNT)
    get_WIN32_WINNT(ver)
    
    # Windows-only definitions | Specifies WinNT kernel to build for
    list(APPEND _VCASH_DEFINITIONS
      "-D_WIN32_WINNT=${ver}"
    )
  ENDIF()

  # Generic MSVC definitions
  list(APPEND _VCASH_DEFINITIONS
    "-D_UNICODE"
    "-DUNICODE"
    "-D_SCL_SECURE_NO_WARNINGS"
    "-D_CRT_SECURE_NO_WARNINGS"
    "-DBOOST_ALL_NO_LIB=1"
    "-DZc:wchar_t" # "If /Zc:wchar_t is on, wchar_t maps to the Microsoft-specific native type __wchar_t"
    "-DZc:forScope" # "Used to implement standard C++ behavior for for loops with Microsoft extensions"
  )

  # "By default, ICF is on if REF is on"
  list(APPEND _VCASH_RELEASE_DEFINITIONS "-DOPT:REF")

  # FIXME implement these ignore codes for MSVC (seems to ignore it for some reason)
  # /ignore:XXXX seems to be proper format, but doesn't actually work
  # 4267 & 4244 to hide "conversion from 'X' to 'Y', possible loss of data"
  # 4005 to hide "'WIN32_LEAN_AND_MEAN': macro redefinition"

# GCC compiler
ELSEIF(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  # 02 optimization required to build on GCC >= v6, otherwise it fails
  list(APPEND _VCASH_RELEASE_DEFINITIONS "-O2")
ENDIF()

# Add our release definitions to the list of definitions to use
IF(CMAKE_BUILD_TYPE STREQUAL "Release" AND _VCASH_RELEASE_DEFINITIONS)
  list(APPEND _VCASH_DEFINITIONS ${_VCASH_RELEASE_DEFINITIONS})
ENDIF()
# Adds our custom compiler definitions | "NDEBUG" is auto-defined by Cmake if building Release
add_definitions(${_VCASH_DEFINITIONS})
