logger_build = custom_target(
  'liblogger',
  input: files('logger.go', 'go.mod', 'go.sum'),
  output: ['liblogger.a', 'logger.h'],
  command: [
    find_program('python3'), files('build_logger.py'),
    meson.current_source_dir(), '@OUTPUT0@', '@OUTPUT1@'
  ],
  install: false
)

liblogger_dep = declare_dependency(
  sources: logger_build[1],
  link_args: [logger_build[0].full_path()],
  include_directories: include_directories('.')
)
