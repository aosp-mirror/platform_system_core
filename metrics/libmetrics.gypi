{
  'target_defaults': {
    'dependencies': [
      '../../platform2/libchromeos/libchromeos-<(libbase_ver).gyp:libchromeos-<(libbase_ver)',
    ],
    'variables': {
      'deps': [
        'libchrome-<(libbase_ver)',
      ]
    },
    'cflags_cc': [
      '-fno-exceptions',
    ],
  },
  'targets': [
    {
      'target_name': 'libmetrics-<(libbase_ver)',
      'type': 'shared_library',
      'cflags': [
        '-fvisibility=default',
      ],
      'sources': [
        'c_metrics_library.cc',
        'metrics_library.cc',
        'timer.cc',
      ],
    },
  ],
}
