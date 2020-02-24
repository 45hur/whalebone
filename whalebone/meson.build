# C module: whalebone

whalebone_src = files([
  'cache_customlist.c',
  'cache_domains.c',
  'cache_iprange.c',
  'cache_matrix.c',
  'cache_policy.c',
  'crc64.c',
  'file_loader.c',
  'ipranger.c',
  'log.c',
  'program.c',
  'socket_srv.c',
  'util.c',
  'whalebone.c',
])
c_src_lint += whalebone_src

whalebone_mod = shared_module(
  'whalebone',
  whalebone_src,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
