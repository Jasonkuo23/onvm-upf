sources = files(
    'upf_u.c',
    'upf_u_config.c',
    'upf_u_arp.c',
    'upf_u_icmp.c',
    'upf_u_trtcm.c',
    'upf_u_shaper.c',
    'upf_u_nat.c',
    'upf_u_helper.c',
    'upf_u_n3iwf.c'
)

upf_u_link_deps = [
  dependency('yaml-0.1', version: '>=0.2.2', required: true),
]

n3iwf_route_test = executable('upf_u_n3iwf_test',
    files('upf_u_n3iwf.c', 'upf_u_n3iwf_test.c'),
    include_directories: includes,
    dependencies: [onvm_dpdk_dep],
    native: true
)
test('upf-u-n3iwf-route', n3iwf_route_test)
