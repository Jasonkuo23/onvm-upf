sources = files(
    'n3iwf_dp.c',
    'n3iwf_dp_child_sa.c',
    'n3iwf_dp_clear.c',
    'n3iwf_dp_codec.c',
    'n3iwf_dp_control.c',
    'n3iwf_dp_downlink.c',
    'n3iwf_dp_punt.c',
    'n3iwf_dp_session.c',
    'n3iwf_dp_wire.c'
)

codec_test = executable('n3iwf_dp_codec_test',
    files('n3iwf_dp_codec.c', 'n3iwf_dp_wire.c', 'n3iwf_dp_codec_test.c'),
    native: true
)
test('n3iwf-dp-codec', codec_test)

session_test = executable('n3iwf_dp_session_test',
    files('n3iwf_dp_session.c', 'n3iwf_dp_session_test.c'),
    native: true
)
test('n3iwf-dp-session', session_test)

child_sa_test = executable('n3iwf_dp_child_sa_test',
    files('n3iwf_dp_child_sa.c', 'n3iwf_dp_child_sa_test.c'),
    native: true
)
test('n3iwf-dp-child-sa', child_sa_test)

control_test = executable('n3iwf_dp_control_test',
    files('n3iwf_dp_wire.c', 'n3iwf_dp_session.c', 'n3iwf_dp_child_sa.c', 'n3iwf_dp_control.c', 'n3iwf_dp_control_test.c'),
    native: true
)
test('n3iwf-dp-control', control_test)

punt_test = executable('n3iwf_dp_punt_test',
    files('n3iwf_dp_punt.c', 'n3iwf_dp_punt_test.c'),
    native: true
)
test('n3iwf-dp-punt', punt_test)

clear_test = executable('n3iwf_dp_clear_test',
    files(
        'n3iwf_dp_clear.c',
        'n3iwf_dp_downlink.c',
        'n3iwf_dp_codec.c',
        'n3iwf_dp_session.c',
        'n3iwf_dp_clear_test.c'
    ),
    include_directories: includes,
    dependencies: [onvm_dpdk_dep],
    native: true
)
test('n3iwf-dp-clear-path', clear_test)
