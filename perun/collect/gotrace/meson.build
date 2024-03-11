perun_collect_gotrace_dir = perun_collect_dir / 'gotrace'

perun_collect_gotrace_files = files(
    '__init__.py',
    'bpfgen.py',
    'interpret.py',
    'run.py',
    'symbols.py'
)

py3.install_sources(
    perun_collect_gotrace_files,
    subdir: perun_collect_gotrace_dir,
)
