# install_and_export - version 1.0.0
# Author: sum01 <sum01@protonmail.com>
# Git: https://github.com/sum01/cmake-modules
#
# This module can be used to easily install and export any Cmake executable/library created by add_executable() or add_library()
#
# ~~ Usage ~~
# include(install_and_export)
# install_and_export(my_exe_name)
#
# NOTE! When "including" your include/ folder for a lib/exe, you must use generator expressions on the include/ path.
# Example: target_include_directories(my_exe_name PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
#
# More reading: https://cmake.org/cmake/help/latest/prop_tgt/INTERFACE_INCLUDE_DIRECTORIES.html

# Defines standardized defaults for install paths
include(GNUInstallDirs)

macro(install_and_export _INSTALL_EXPORT_TARGET)
  # Gives "Make install" esque operations a location to install to...
  # and creates a .cmake file for other projects to import.
  install(TARGETS ${_INSTALL_EXPORT_TARGET}
    EXPORT "${_INSTALL_EXPORT_TARGET}-targets"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  )

  # "The install(TARGETS) and install(EXPORT) commands work together to install a target and a file to help import it"
  # Installs a cmake file which external projects can import.
  # This will point towards the pre-compiled binary after installation, but be treated as if it had been compiled inside the external project.
  install(EXPORT "${_INSTALL_EXPORT_TARGET}-targets"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${CMAKE_PROJECT_NAME}"
  )

  # "The export command is used to generate a file exporting targets from a project build tree"
  # Creates an import file for external projects which are aware of the build tree.
  # This will not be installed, and is only usefull in certain situations.
  export(TARGETS ${_INSTALL_EXPORT_TARGET}
    FILE "${_INSTALL_EXPORT_TARGET}-exports.cmake"
  )
endmacro()
