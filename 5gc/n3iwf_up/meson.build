transport_sources = files('../../../n3iwf-up-client/transport.c')
sources = files(
    'n3iwf_up.c',
    'n3iwf_up_child_sa.c',
    'n3iwf_up_clear.c',
    'n3iwf_up_codec.c',
    'n3iwf_up_control.c',
    'n3iwf_up_downlink.c',
    'n3iwf_up_ipsec.c',
    'n3iwf_up_punt.c',
    'n3iwf_up_session.c',
    'n3iwf_up_wire.c'
) + transport_sources

codec_test = executable('n3iwf_up_codec_test',
    files('n3iwf_up_codec.c', 'n3iwf_up_wire.c', 'n3iwf_up_codec_test.c'),
    native: true
)
test('n3iwf-up-codec', codec_test)

session_test = executable('n3iwf_up_session_test',
    files('n3iwf_up_session.c', 'n3iwf_up_session_test.c'),
    native: true
)
test('n3iwf-up-session', session_test)

child_sa_test = executable('n3iwf_up_child_sa_test',
    files('n3iwf_up_child_sa.c', 'n3iwf_up_session.c',
          'n3iwf_up_child_sa_test.c'),
    native: true
)
test('n3iwf-up-child-sa', child_sa_test)

control_test = executable('n3iwf_up_control_test',
    files('n3iwf_up_wire.c', 'n3iwf_up_session.c', 'n3iwf_up_child_sa.c', 'n3iwf_up_control.c', 'n3iwf_up_control_test.c') + transport_sources,
    dependencies: [onvm_dpdk_dep],
    native: true
)
test('n3iwf-up-control', control_test)

punt_test = executable('n3iwf_up_punt_test',
    files('n3iwf_up_punt.c', 'n3iwf_up_punt_test.c'),
    native: true
)
test('n3iwf-up-punt', punt_test)

clear_test = executable('n3iwf_up_clear_test',
    files(
        'n3iwf_up_clear.c',
        'n3iwf_up_downlink.c',
        'n3iwf_up_codec.c',
        'n3iwf_up_session.c',
        'n3iwf_up_clear_test.c'
    ),
    include_directories: includes,
    dependencies: [onvm_dpdk_dep],
    native: true
)
test('n3iwf-up-clear-path', clear_test)

transport_test = executable('n3dp_transport_test',
    files('../../../n3iwf-up-client/tests/transport_test.c') + transport_sources,
    dependencies: [onvm_dpdk_dep], native: true)
test('n3iwf-up-transport', transport_test)

control_fixture = executable('n3iwf_up_control_fixture',
    files('n3iwf_up_wire.c', 'n3iwf_up_session.c', 'n3iwf_up_child_sa.c',
          'n3iwf_up_control.c', 'n3iwf_up_control_fixture.c') + transport_sources,
    dependencies: [onvm_dpdk_dep], native: true)
